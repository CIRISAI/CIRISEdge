//! Local-state-to-summary computation + diff logic.
//!
//! Edge's `Session` (in [`super::session`]) sits above this surface;
//! callers wiring a live deployment provide a [`StateProvider`] /
//! [`StateApplier`] pair over their `FederationDirectory` and the
//! Session orchestrates rounds.
//!
//! ## Bounded-staleness signal
//!
//! [`StalenessSignal`] is the consumer-facing telemetry surfaced by
//! the Session at the end of each round. Consumers (lens, agent,
//! verify-coord) condition τ_partial on this signal — when staleness
//! is bounded and below the consumer's tolerance, normal R1 quorum
//! applies; when staleness is unknown or above tolerance, the consumer
//! degrades to τ_partial / partition-mode semantics.

use std::collections::{BTreeMap, BTreeSet};

use super::protocol::{EnvelopeKind, EnvelopeRef};
use super::refusal_backoff::RetryDisposition;

/// Snapshot of the envelopes a peer holds locally per
/// [`EnvelopeKind`]. The state machine consumes this to build
/// [`super::protocol::SummaryMessage`]s and to identify which envelopes
/// need to be delivered to the peer.
///
/// Use `BTreeMap` (sorted, deterministic iteration) rather than
/// `HashMap` so the on-wire `SummaryMessage::refs` order is stable
/// across runs — a test that pins exact bytes can be deterministic;
/// in production it makes diff computation predictable for
/// debugging.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LocalState {
    /// Per-kind set of `(envelope_hash, seq)`. Storing seq inside the
    /// map lets the diff logic prefer the higher-seq variant when two
    /// peers have the same content-hash at different seqs (shouldn't
    /// happen — content-hash collisions across seqs would be a
    /// canonical-bytes bug — but the data model has a slot for it).
    pub by_kind: BTreeMap<EnvelopeKind, BTreeMap<[u8; 32], u64>>,
}

impl LocalState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an envelope to local state. Idempotent on (kind,
    /// envelope_hash) — re-inserting updates seq if the new seq is
    /// higher, otherwise no-op.
    pub fn insert(&mut self, kind: EnvelopeKind, envelope_hash: [u8; 32], seq: u64) {
        let entry = self.by_kind.entry(kind).or_default();
        let slot = entry.entry(envelope_hash).or_insert(seq);
        if seq > *slot {
            *slot = seq;
        }
    }

    /// Build a [`super::protocol::SummaryMessage`]-shaped list for
    /// `kind`. Iteration order is BTreeMap-stable.
    pub fn refs_for(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.by_kind
            .get(&kind)
            .map(|inner| {
                inner
                    .iter()
                    .map(|(h, s)| EnvelopeRef {
                        envelope_hash: *h,
                        seq: *s,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Count envelopes for `kind` — useful for staleness telemetry.
    pub fn count(&self, kind: EnvelopeKind) -> usize {
        self.by_kind.get(&kind).map_or(0, BTreeMap::len)
    }
}

/// Trait the live Session calls to read local state. Production
/// adapter (follow-up PR) wraps `FederationDirectory`'s
/// `list_attestations` / `list_federation_keys` / `list_revocations`
/// surfaces.
pub trait StateProvider: Send + Sync {
    /// Snapshot the refs this node OFFERS to the round's peer for `kind` — the
    /// SEND axis. On the Attestation plane this is CIRISEdge#396-send-gated (a
    /// peer outside this node's live `consent:replication` send-set is offered
    /// nothing). Read once per round; callers don't memoize.
    fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef>;

    /// CIRISEdge#414 — the refs this node actually HOLDS for `kind` — the
    /// RECEIVE axis. Used ONLY to compute what the node still LACKS
    /// (`want = remote ∖ local_holdings`) so an inbound round is serviced from
    /// the node's real state, NOT from its (send-gated, possibly empty) offer.
    ///
    /// This split fixes the axis-fusion where the #396 SEND gate darkened the
    /// RECEIVE side: a responder holding `infra:serve` but no consent to SEND to
    /// the initiator must still receive the initiator's offered rows. Holdings
    /// never leave the node — the offer ([`Self::local_refs`]) and delivery
    /// (`fetch_envelope_bytes_for_peer`) stay independently send-gated, so send
    /// fail-secure is unchanged. Defaults to [`Self::local_refs`] for providers
    /// with no peer-gating (every non-Attestation plane, and the test providers).
    fn local_holdings(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.local_refs(kind)
    }

    /// CIRISEdge#544 — should the round's `want` DROP this hash?
    ///
    /// The receive axis' third question, after "what do I offer" and "what do I
    /// hold": *what have I already refused?* `want = remote ∖ holdings` is
    /// otherwise memoryless, so a row a gate will never admit is re-requested
    /// every round at the same cost as a healthy one — the #544 measurement was
    /// 55 re-offers of one `conflicting_version` `Key` row in 30 minutes.
    ///
    /// This gates the ASK ONLY. A peer that pushes the row unsolicited is still
    /// applied on its merits ([`StateApplier::apply_envelope`] never consults
    /// this), so an over-eager `true` can delay a row but can never withhold
    /// one. Implementations MUST decay: a permanently-`true` answer is a plane
    /// going quietly dark, which is the failure this crate spends #423/#425/#433
    /// refusing to allow.
    ///
    /// Defaults to `false` — every provider without a refusal memory (the test
    /// providers, the DST store) keeps the pre-#544 ask-every-round behaviour.
    /// The production `DirectoryStateAdapter` forwards to the ONE shared bridge,
    /// so the verdict is node-wide: the first peer's refusal teaches every
    /// peer's next round.
    fn retry_suppressed(&self, _kind: EnvelopeKind, _envelope_hash: &[u8; 32]) -> bool {
        false
    }

    /// Return the byte-exact signed envelope for the given content
    /// hash, or `None` if the envelope isn't in local state. Called
    /// during the Deliver-message construction step.
    fn fetch_envelope(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> Option<Vec<u8>>;

    /// CIRISEdge#462 — the RECEIVE-axis SERVE reader: the refs this node holds
    /// for `kind` where `subject_key_id` is the data-subject (`list_signed_records`)
    /// or, for the Attestation plane, the sender (`list_attestations_by` — the
    /// subject's own authored testimony, for recovery). Answers an inbound
    /// [`crate::replication::protocol::PullMessage`]: unlike [`Self::local_refs`]
    /// (the whole advertised set) this is SUBJECT-scoped, so it reaches the
    /// `SelfOwn` plane the advertise projection never offers.
    ///
    /// The impl MUST apply the SAME per-record projection gate its advertise path
    /// applies (a Pull can only surface a row the responder would already serve),
    /// and MUST withhold the consent-gated peer-authored scores about the subject
    /// that persist's `consent_gated_claim` classifies (the `capacity:*` family —
    /// the G2 self-revocation-hole carve: a subject pulling a score *about* itself
    /// onto the node where it is the sole writer conflates read-copy with
    /// write-authority). Refs only — the existing
    /// Diff/Deliver flow carries the bytes, re-gated by [`Self::fetch_envelope`].
    ///
    /// Defaults to empty: only the production `DirectoryStateAdapter` (which holds
    /// the persist `FederationDirectory`) can answer a subject pull. Test/in-memory
    /// providers that don't override it simply return no refs — a Pull to them is
    /// a well-formed no-op, never a panic.
    fn subject_refs(&self, _kind: EnvelopeKind, _subject_key_id: &str) -> Vec<EnvelopeRef> {
        Vec::new()
    }

    /// CIRISEdge#474 — the accord-quorum-evidence CURSOR serve reader. Answers an
    /// inbound [`crate::replication::protocol::CursorPullMessage`]: the byte-exact
    /// [`AccordQuorumEvidence`](ciris_persist::federation::accord_carriage::AccordQuorumEvidence)
    /// bundles this node holds with `evidence_at > since`, JSON-serialized ready to
    /// wrap in a [`crate::replication::protocol::DeliverMessage`]. UNLIKE
    /// [`Self::local_refs`] / [`Self::subject_refs`] this returns BYTES, not refs —
    /// the plane has no content-hash index, so there is no Diff/Fetch round-trip;
    /// the responder delivers directly. Bounded by the impl's page limit; the
    /// requester re-pulls from its new high-water next round to drain a backlog.
    ///
    /// Defaults to empty: only the production `DirectoryStateAdapter` (holding the
    /// persist `FederationDirectory`) and the DST store answer it. A cursor pull to
    /// a provider that doesn't override it is a well-formed no-op, never a panic.
    fn accord_evidence_since(
        &self,
        _kind: EnvelopeKind,
        _since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

/// CIRISEdge#425 — the typed result of applying ONE delivered envelope.
///
/// Replaces the old `bool` return of [`StateApplier::apply_envelope`] so a refusal
/// can NEVER be a silent `return false`. Every non-[`Admitted`](ApplyOutcome::Admitted)
/// variant carries a reason, and the SINGLE choke point — `Session::on_deliver` —
/// logs it as it counts the envelope `refused`. This kills the silent-apply
/// subclass BY CONSTRUCTION (`#[must_use]`): a new `apply_*` branch cannot drop the
/// outcome on the floor, so it cannot add a silent refusal — it must yield a reason
/// the loop logs. The failure mode this closes is the #414/#416/#423/#424/#932
/// class: a real refusal quiet enough to look like absence of work (the round
/// still reports a healthy `admitted`/`refused` split, but the *why* was gone).
#[must_use = "an apply outcome carries a refusal reason that on_deliver must log — do not drop it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The envelope was admitted and changed local state — the anti-entropy
    /// progress signal (`Inserted`/`Upgraded` on the Key plane; a fresh `put_*`
    /// elsewhere).
    Admitted,
    /// A byte-identical envelope the node already held. EXPECTED non-progress: the
    /// diff isn't perfect and a re-run / the #927 proactive push re-delivers held
    /// rows all the time, so this is routine — `on_deliver` logs it at DEBUG, never
    /// WARN (WARN-ing every duplicate would drown the genuine refusals). Counts as
    /// non-admitted, exactly like the old `false`.
    Duplicate,
    /// The envelope was well-formed but a GATE refused it — persist's typed
    /// `Error::kind()`, a missing operational provider, a downgrade/ambiguous-owner
    /// rejection, … This is the class that DARKENS carriage: `on_deliver` logs it
    /// at WARN with `reason` (a short, stable, low-cardinality label). NEVER silent.
    ///
    /// CIRISEdge#544 — `retry` is a SECOND required field, for the same structural
    /// reason `reason` is one: #425 made "why" unforgettable by making it
    /// impossible to construct a refusal without it, and "does re-asking help?"
    /// was the next thing every apply branch was silently answering `yes` to.
    /// The receiver's `want` is `remote ∖ holdings` and a refused row is never
    /// stored, so EVERY refusal re-pulled its own bytes next round, forever —
    /// one `conflicting_version` row measured at 55 re-offers in 30 minutes.
    /// A new apply branch must now state the disposition; it cannot default into
    /// the spin. [`RetryDisposition`] documents both directions of getting it
    /// wrong.
    Refused {
        reason: String,
        retry: RetryDisposition,
    },
    /// The delivered bytes failed to deserialize into the plane's record type — a
    /// producer/consumer wire-shape skew, not absence of work. WARN with the error.
    Deserialize(String),
}

impl ApplyOutcome {
    /// Did this outcome admit a NEW envelope (the convergence progress signal that
    /// `on_deliver` counts as `admitted`)?
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, ApplyOutcome::Admitted)
    }

    /// A `Refused` whose verdict is decided by state still in motion — the
    /// CONSERVATIVE constructor, and the right default for any refusal whose
    /// underlying token collapses a recoverable arm together with an
    /// unrecoverable one. Re-asking is bounded by
    /// [`RetryDisposition::Transient`]'s short backoff, so calling a genuinely
    /// terminal refusal transient costs a trickle; calling a recoverable one
    /// terminal would withhold state. Reach for
    /// [`Self::refused_terminal`] only when re-offering the IDENTICAL bytes
    /// cannot change the answer.
    pub fn refused(reason: impl Into<String>) -> Self {
        ApplyOutcome::Refused {
            reason: reason.into(),
            retry: RetryDisposition::Transient,
        }
    }

    /// CIRISEdge#544 — a `Refused` that re-offering the identical bytes cannot
    /// move: a first-seen-wins conflict, a row this build cannot understand, a
    /// plane this node opted out of admitting. The receiver stops ASKING for
    /// these bytes for a long (never infinite) window; it never stops accepting
    /// them if a peer pushes them anyway, and a corrected SUPERSEDING record is
    /// different bytes — a different content hash — so it is unaffected.
    pub fn refused_terminal(reason: impl Into<String>) -> Self {
        ApplyOutcome::Refused {
            reason: reason.into(),
            retry: RetryDisposition::Terminal,
        }
    }

    /// CIRISEdge#544 — what this outcome says about ASKING for the same bytes
    /// again, or `None` when the question does not arise (the row is now held,
    /// so it leaves `want` on its own).
    ///
    /// `Deserialize` is [`RetryDisposition::Terminal`] by nature and not by a
    /// stored field: the wire identity IS the content hash, so re-fetching that
    /// hash returns the same bytes and the same parse failure. The one event
    /// that changes the answer — a build that understands the shape — restarts
    /// the process, which empties the memory anyway.
    #[must_use]
    pub fn retry_disposition(&self) -> Option<RetryDisposition> {
        match self {
            ApplyOutcome::Admitted | ApplyOutcome::Duplicate => None,
            ApplyOutcome::Refused { retry, .. } => Some(*retry),
            ApplyOutcome::Deserialize(_) => Some(RetryDisposition::Terminal),
        }
    }
}

/// Trait the live Session calls to apply received envelopes. Wraps
/// persist's `put_*` admit surface; the impl is responsible for
/// validating the envelope (signature + canonical-bytes hash) before
/// committing to local state. The merge layer in persist is the
/// canonical anti-rollback authority; a duplicate apply hits its R1/Q1
/// dedupe and returns a `Refused` no-op.
///
/// CIRISEdge#370 — `apply_envelope` takes **`&self`** (the third breaking
/// `StateApplier` change; precedent: #425 `ApplyOutcome`, #426 `source_peer`).
/// The old `&mut self` was an adapter-shape artifact, not a safety
/// requirement: the production adapter is a stateless wrapper over
/// `Arc<dyn ReplicationDirectory>` and the real apply underneath
/// (`apply_envelope_bytes`) is `&self` with backend-owned concurrency. The
/// `&mut` forced every coordinator to wrap its applier in an
/// `Arc<Mutex<dyn StateApplier>>` held across a WHOLE message's applies —
/// with `block_on` DB I/O inside — so under N concurrent peers, round
/// servicing serialized (≈ N × batch-apply-time, the sharp collapse past
/// ~40 peers against the 30 s transport timeout). Coordinators now hold a
/// shared `Arc<dyn StateApplier>` directly, no mutex; per-peer rounds apply
/// concurrently down to the store's own serialization. Implementations that
/// record state (test appliers) use interior mutability.
pub trait StateApplier: Send + Sync {
    /// Apply one envelope to local state. The receiver MUST verify the signed
    /// envelope's signature + canonical-bytes hash before admitting. Returns an
    /// [`ApplyOutcome`]: `Admitted` if a NEW envelope changed local state, else a
    /// `Refused`/`Deserialize` carrying WHY — `on_deliver` logs the reason (the
    /// #425 single choke point). Never a silent drop.
    ///
    /// CIRISEdge#426 — `source_peer` is the AUTHENTICATED sender of these bytes
    /// (`InboundFrame::source_key_id`, already E3-gated `Rooted∧owns_key∧hybrid` in
    /// `attribute_and_deliver`), forwarded so a per-peer RECEIVE decision is
    /// expressible at the apply layer — the consent plane used to be send-only
    /// because this identity was dropped before reaching the applier. `None` for
    /// non-peer-attributed applies (tests / self-seed). The receiver is transport-
    /// blind otherwise; this is pass-through metadata, not a protocol input.
    fn apply_envelope(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        source_peer: Option<&str>,
    ) -> ApplyOutcome;
}

/// Compute the diff between two summaries — which hashes the LOCAL
/// peer doesn't have that the REMOTE peer claims to have. This is
/// the input to a `DiffMessage::want` field.
pub fn diff_refs(local: &[EnvelopeRef], remote: &[EnvelopeRef]) -> Vec<[u8; 32]> {
    let local_set: BTreeSet<[u8; 32]> = local.iter().map(|r| r.envelope_hash).collect();
    remote
        .iter()
        .filter(|r| !local_set.contains(&r.envelope_hash))
        .map(|r| r.envelope_hash)
        .collect()
}

/// The freshness signal exposed to consumers per [`EnvelopeKind`].
/// Drives τ_partial / partition-mode semantics in
/// CIRISVerify#48/#49 consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StalenessSignal {
    /// Local state matches the most recent remote summary received
    /// for this kind. Consumers may operate in normal R1 mode.
    InSync,
    /// Local state is missing N envelopes vs the most recent remote
    /// summary. Bounded staleness — consumers can decide whether to
    /// degrade based on N.
    BoundedBy { missing: u64 },
    /// No anti-entropy round has completed for this kind since
    /// process start (or since the local clock was last reset).
    /// Consumers SHOULD treat this as worst-case stale.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    /// Insert + idempotent re-insert + count.
    #[test]
    fn local_state_inserts_and_counts() {
        let mut s = LocalState::new();
        s.insert(EnvelopeKind::Key, h(1), 100);
        s.insert(EnvelopeKind::Key, h(2), 200);
        s.insert(EnvelopeKind::Attestation, h(3), 50);
        assert_eq!(s.count(EnvelopeKind::Key), 2);
        assert_eq!(s.count(EnvelopeKind::Attestation), 1);
        assert_eq!(s.count(EnvelopeKind::Revocation), 0);
        // Re-insert same (kind, hash) at higher seq updates seq.
        s.insert(EnvelopeKind::Key, h(1), 150);
        let refs = s.refs_for(EnvelopeKind::Key);
        let r1 = refs.iter().find(|r| r.envelope_hash == h(1)).unwrap();
        assert_eq!(r1.seq, 150);
        // Re-insert at lower seq is a no-op.
        s.insert(EnvelopeKind::Key, h(1), 120);
        let refs2 = s.refs_for(EnvelopeKind::Key);
        let r1b = refs2.iter().find(|r| r.envelope_hash == h(1)).unwrap();
        assert_eq!(r1b.seq, 150);
    }

    /// `refs_for` returns BTreeMap-sorted output — deterministic
    /// ordering matters for test stability + protocol determinism.
    #[test]
    fn refs_for_is_sorted_by_envelope_hash() {
        let mut s = LocalState::new();
        // Insert in non-sorted order.
        s.insert(EnvelopeKind::Key, h(9), 1);
        s.insert(EnvelopeKind::Key, h(1), 2);
        s.insert(EnvelopeKind::Key, h(5), 3);
        let refs = s.refs_for(EnvelopeKind::Key);
        // BTreeMap stable ordering by key.
        assert_eq!(refs[0].envelope_hash, h(1));
        assert_eq!(refs[1].envelope_hash, h(5));
        assert_eq!(refs[2].envelope_hash, h(9));
    }

    /// Empty kind returns empty refs.
    #[test]
    fn refs_for_empty_kind_returns_empty() {
        let s = LocalState::new();
        assert!(s.refs_for(EnvelopeKind::Community).is_empty());
    }

    /// Diff of disjoint local vs remote — local wants everything.
    #[test]
    fn diff_disjoint_wants_everything() {
        let local: Vec<EnvelopeRef> = vec![];
        let remote = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
        ];
        let want = diff_refs(&local, &remote);
        assert_eq!(want, vec![h(1), h(2)]);
    }

    /// Diff of identical sets — want is empty.
    #[test]
    fn diff_identical_wants_nothing() {
        let local = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
        ];
        let remote = local.clone();
        let want = diff_refs(&local, &remote);
        assert!(want.is_empty());
    }

    /// Partial overlap — want is the remote-minus-local set.
    #[test]
    fn diff_partial_overlap() {
        let local = vec![EnvelopeRef {
            envelope_hash: h(1),
            seq: 1,
        }];
        let remote = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
            EnvelopeRef {
                envelope_hash: h(3),
                seq: 3,
            },
        ];
        let want = diff_refs(&local, &remote);
        assert_eq!(want, vec![h(2), h(3)]);
    }

    /// Local has hashes the remote doesn't — those don't show up in
    /// our wants. The reverse-direction Summary/Diff from the remote
    /// would pick them up.
    #[test]
    fn diff_local_has_extras_ignored() {
        let local = vec![
            EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            },
            EnvelopeRef {
                envelope_hash: h(2),
                seq: 2,
            },
        ];
        let remote = vec![EnvelopeRef {
            envelope_hash: h(1),
            seq: 1,
        }];
        let want = diff_refs(&local, &remote);
        assert!(
            want.is_empty(),
            "local extras shouldn't appear in want list"
        );
    }
}
