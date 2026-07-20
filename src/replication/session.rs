//! Pairwise anti-entropy state machine.
//!
//! A `Session` is one peer's view of one round of anti-entropy with
//! one remote peer. The session does NOT do any networking — it
//! consumes [`crate::replication::protocol::ReplicationMessage`]s and
//! produces them, reading + writing local state via the
//! [`crate::replication::summary::StateProvider`] /
//! [`crate::replication::summary::StateApplier`] traits the caller
//! supplies. The networking glue (binding to a `Transport` instance +
//! scheduling rounds + handling timeouts) is a follow-up PR.
//!
//! ## Round shape
//!
//! Both sides initiate `Summary` in the same round so the diff is
//! bidirectional. Concretely, for each kind:
//!
//! ```text
//!   1. A → B   Summary { kind, my_refs }
//!      A ← B   Summary { kind, my_refs }      (in parallel)
//!   2. A → B   Diff    { kind, want = B-summary − A-local }
//!      A ← B   Diff    { kind, want = A-summary − B-local }
//!   3. A → B   Deliver { kind, envelopes for B.want }
//!      A ← B   Deliver { kind, envelopes for A.want }
//!   4. A.apply(received); B.apply(received) — via StateApplier
//! ```
//!
//! `Session` models ONE direction of this flow. The caller runs two
//! Sessions per peer-pair (initiator + responder roles); the wire
//! messages between them carry the bidirectional traffic.
//!
//! ## Roles
//!
//! [`SessionRole::Initiator`] starts by emitting a Summary. The
//! responder reacts by computing a Diff. Either role can finalize
//! the round when both Diff exchanges have completed and the
//! Delivers have been applied.

use super::protocol::{
    DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, FetchMessage, ReplicationMessage,
    SummaryMessage,
};
use super::summary::{diff_refs, StalenessSignal, StateApplier, StateProvider};

/// What role a session is playing in this round. Initiator emits
/// the first Summary; Responder waits for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// What the session yielded after processing one inbound message
/// (or starting a round). The caller (Transport glue) reads this
/// and decides whether to send the next outbound message, apply
/// envelopes, surface staleness telemetry, or end the round.
#[derive(Debug, PartialEq, Eq)]
pub enum ReplicationOutcome {
    /// The session wants to send these messages out. Order matters —
    /// the caller MUST emit them in order on the underlying
    /// transport.
    Send(Vec<ReplicationMessage>),
    /// CIRISEdge#380 — INITIATOR-FINAL: send these messages, then the round is
    /// COMPLETE without waiting for a reply. Emitted by a proactive-publish
    /// initiator when the peer's last-known Summary shows it already holds our
    /// full publish set (nothing left to push) and we want nothing from it —
    /// there is nothing to wait for. This is what lets a NAT'd initiator's
    /// rounds report `completed` instead of permanently normalizing
    /// `error`/`timed_out` as the signature of working delivery (which poisoned
    /// the #370 round-outcome instrument).
    SendAndComplete {
        msgs: Vec<ReplicationMessage>,
        kind: EnvelopeKind,
    },
    /// The session applied envelopes received from the peer. The
    /// caller can surface a `StalenessSignal` update at this point.
    Applied {
        kind: EnvelopeKind,
        admitted: usize,
        refused: usize,
        staleness: StalenessSignal,
    },
    /// The round is complete for this kind from this side's
    /// perspective. The other direction's round may still be in
    /// flight; the caller tracks that independently.
    RoundComplete { kind: EnvelopeKind },
    /// The peer sent an unexpected message for the current state
    /// (e.g. a Deliver before any Diff was exchanged). NOT a fatal
    /// error — the session resets to idle and the caller can decide
    /// whether to retry or drop the peer.
    UnexpectedMessage,
}

/// One direction of an anti-entropy round. The caller creates one
/// session per `(peer, kind, role)` triple, drives it via `start_round`
/// (initiator) / `on_message` (either role), and reads the
/// `ReplicationOutcome` to decide what to send next.
///
/// ## Lifetime model
///
/// The session is fully **owned** — it carries no borrows. The
/// [`StateProvider`] and [`StateApplier`] are passed as method
/// parameters on each call, so a session can live across multiple
/// calls without lifetime gymnastics. This enables a long-lived
/// session inside [`super::ReplicationCoordinator`] that preserves
/// `diff_want_count` across the Diff and Deliver phases — the
/// documented `Unknown`-staleness gap closes.
///
/// After a round completes (`Applied` outcome), call [`Self::reset`]
/// to clear the per-round state and prepare for the next round with
/// the same peer.
pub struct Session {
    role: SessionRole,
    kind: EnvelopeKind,
    /// What we sent the peer in our most recent Summary — used to
    /// fulfill their Diff against our state.
    last_summary_sent: Option<SummaryMessage>,
    /// Their most recent Summary, recorded so we can compute our
    /// own Diff and track staleness telemetry.
    last_remote_summary: Option<SummaryMessage>,
    /// How many envelopes our most recent outbound Diff asked for.
    /// `None` until the Diff has been sent. Used as the basis for
    /// the post-Apply [`StalenessSignal`] (subtract admitted count
    /// to get residual missing — works regardless of whether the
    /// Provider sees the Applier's writes, since the count is
    /// already known).
    ///
    /// The long-lived session preserves this across the Diff →
    /// Deliver phase boundary, so [`Self::on_deliver`] computes
    /// `BoundedBy { missing }` / `InSync` instead of `Unknown`.
    diff_want_count: Option<usize>,
    /// Whether the round has completed from this side's view.
    completed: bool,
    /// CIRISEdge#927 — initiator-first push. When set (a self-publishing node,
    /// i.e. the runtime was started with a `self_provider` / `key_publish_set`),
    /// an Initiator's [`Self::start_round`] proactively DELIVERS its advertised
    /// publish set right after the Summary, without waiting for the responder's
    /// Diff. This is the only way to reach a carrier-NAT'd peer: the Diff can't
    /// traverse back, so the side that can reach (the initiator) pushes its
    /// key/attestation. Responders never `start_round`, so it's a no-op for them.
    proactive_publish: bool,
    /// CIRISEdge#380 — per-envelope proactive-push ledger: hash → the
    /// `round_counter` value when it was last pushed. Survives [`Self::reset`]
    /// (cross-round knowledge, not round state) so an envelope is not re-pushed
    /// every round; entries refresh after [`PROACTIVE_REFRESH_ROUNDS`] as
    /// insurance for peers whose reverse-path Summary never arrives.
    proactive_sent: std::collections::BTreeMap<[u8; 32], u64>,
    /// CIRISEdge#380 — monotonic count of initiator rounds this session has
    /// started. Basis for the `proactive_sent` refresh window.
    round_counter: u64,
}

/// CIRISEdge#380 — per-round byte budget for the proactive Deliver. The
/// v13.7.0 push was UNBOUNDED (full `local_refs(kind)` every round), which was
/// tolerable for the small `SelfOwn` publish sets it was built for but breaks
/// on the Attestation plane, where persist v18 puts inline trace payloads up
/// to 1 MiB — a mobile would re-blast megabytes every 30 s. The plane now
/// converges over successive rounds instead. A single envelope larger than
/// the whole budget is still pushed (alone) — a budget must bound the batch,
/// never strand an envelope.
pub const PROACTIVE_PUSH_BUDGET_BYTES: usize = 256 * 1024;
/// CIRISEdge#380 — rounds before an already-pushed envelope becomes eligible
/// for an idempotent re-push (insurance when the peer's reverse-path Summary
/// never arrives to confirm receipt). 20 rounds ≈ 10 min at the 30 s cadence.
pub const PROACTIVE_REFRESH_ROUNDS: u64 = 20;

impl Session {
    pub fn new(role: SessionRole, kind: EnvelopeKind) -> Self {
        Self {
            role,
            kind,
            last_summary_sent: None,
            last_remote_summary: None,
            diff_want_count: None,
            completed: false,
            proactive_publish: false,
            proactive_sent: std::collections::BTreeMap::new(),
            round_counter: 0,
        }
    }

    /// CIRISEdge#927 — enable initiator-first proactive publish (see the
    /// `proactive_publish` field). Builder form so `Session::new` stays 2-arg.
    #[must_use]
    pub fn with_proactive_publish(mut self, yes: bool) -> Self {
        self.proactive_publish = yes;
        self
    }

    /// Clear per-round state so the session can drive a new round
    /// with the same peer. Preserves `role` + `kind`. Idempotent —
    /// calling on a fresh session is a no-op.
    ///
    /// CIRISEdge#380 — ALSO preserves the cross-round knowledge: the peer's
    /// `last_remote_summary` (the delta basis for the proactive push + the
    /// initiator-final completion test — it reflects what the peer HOLDS,
    /// which a round boundary doesn't invalidate) and the `proactive_sent`
    /// ledger / `round_counter` (what we already pushed). Clearing those on
    /// every completed round would re-blast the publish set and un-complete
    /// the next round for no reason.
    pub fn reset(&mut self) {
        self.last_summary_sent = None;
        self.diff_want_count = None;
        self.completed = false;
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn kind(&self) -> EnvelopeKind {
        self.kind
    }

    /// Start a round. Only valid for [`SessionRole::Initiator`] —
    /// responders wait for an inbound Summary via [`Self::on_message`].
    pub fn start_round(&mut self, provider: &dyn StateProvider) -> ReplicationOutcome {
        debug_assert!(
            matches!(self.role, SessionRole::Initiator),
            "start_round() is initiator-only"
        );
        let refs = provider.local_refs(self.kind);
        let summary = SummaryMessage {
            kind: self.kind,
            refs: refs.clone(),
        };
        self.last_summary_sent = Some(summary.clone());
        let mut outbound = vec![ReplicationMessage::Summary(summary)];
        // CIRISEdge#927 — initiator-first push. A carrier-NAT'd initiator's round
        // can't complete responder-reply-first: the responder's Diff can't
        // traverse back, so the Deliver is never solicited and the key/attestation
        // never lands (the field's `round_outcomes {error:N}`). A self-publishing
        // node therefore DELIVERS its advertised set proactively, alongside the
        // Summary — the responder applies whatever it lacks (idempotent; a bare
        // Deliver has no phase gate, see `responder_applies_unsolicited_bare_deliver`).
        //
        // CIRISEdge#380 — the push is DELTA-AWARE and BOUNDED (the v13.7.0
        // unbounded full-set push broke on the Attestation plane, where persist
        // v18 puts inline trace payloads up to 1 MiB):
        //  - skip refs the peer's last reverse-path Summary shows it holds;
        //  - skip refs already pushed within `PROACTIVE_REFRESH_ROUNDS`
        //    (idempotent re-push insurance for a peer we never hear from);
        //  - cap the batch at `PROACTIVE_PUSH_BUDGET_BYTES`, oldest-seq first,
        //    spillover converging over subsequent rounds (an envelope larger
        //    than the whole budget still ships, alone).
        if self.proactive_publish {
            self.round_counter += 1;
            let peer_has: std::collections::BTreeSet<[u8; 32]> = self
                .last_remote_summary
                .as_ref()
                .map(|s| s.refs.iter().map(|r| r.envelope_hash).collect())
                .unwrap_or_default();
            let mut candidates: Vec<&EnvelopeRef> = refs
                .iter()
                .filter(|r| !peer_has.contains(&r.envelope_hash))
                .filter(|r| {
                    self.proactive_sent.get(&r.envelope_hash).map_or(
                        true,
                        // `map_or(true, …)` not `is_none_or` — MSRV 1.75.
                        |sent| self.round_counter.saturating_sub(*sent) >= PROACTIVE_REFRESH_ROUNDS,
                    )
                })
                .collect();
            candidates.sort_by_key(|r| r.seq);
            let mut envelopes: Vec<Vec<u8>> = Vec::new();
            let mut budget_used = 0usize;
            for r in candidates {
                let Some(bytes) = provider.fetch_envelope(self.kind, &r.envelope_hash) else {
                    continue;
                };
                if budget_used + bytes.len() > PROACTIVE_PUSH_BUDGET_BYTES && !envelopes.is_empty()
                {
                    // Spillover — the NEXT round carries it (deterministic:
                    // candidates are seq-sorted). Not marked sent.
                    continue;
                }
                budget_used += bytes.len();
                self.proactive_sent
                    .insert(r.envelope_hash, self.round_counter);
                envelopes.push(bytes);
            }
            if envelopes.is_empty() {
                // CIRISEdge#380 — INITIATOR-FINAL completion, strictly gated on
                // CONFIRMED sync: the peer's own last Summary shows it holds our
                // full advertised set (so nothing was pushed), and we lack
                // nothing it advertises. There is nothing on the wire to wait
                // for — the round is complete NOW, and `round_outcomes` reports
                // `completed` instead of normalizing `error`/`timed_out` as the
                // signature of working NAT'd delivery. Pushed-but-unconfirmed
                // rounds do NOT complete (the peer's next reverse-path Summary
                // is the confirmation), so `completed` keeps meaning what it
                // says.
                let peer_holds_all = self.last_remote_summary.is_some()
                    && refs.iter().all(|r| peer_has.contains(&r.envelope_hash));
                let want_nothing = self
                    .last_remote_summary
                    .as_ref()
                    .is_some_and(|remote| diff_refs(&refs, &remote.refs).is_empty());
                if peer_holds_all && want_nothing {
                    self.completed = true;
                    return ReplicationOutcome::SendAndComplete {
                        msgs: outbound,
                        kind: self.kind,
                    };
                }
            } else {
                outbound.push(ReplicationMessage::Deliver(DeliverMessage {
                    kind: self.kind,
                    envelopes,
                }));
            }
        }
        ReplicationOutcome::Send(outbound)
    }

    /// Process an inbound replication message.
    ///
    /// State-machine transitions:
    /// - Inbound Summary → Send Diff (our wants from their summary) +
    ///   record their summary for later staleness comparison. Responder
    ///   also sends our Summary at this point.
    /// - Inbound Diff → Send Deliver (envelopes from our state matching
    ///   their wants).
    /// - Inbound Deliver → Apply envelopes via [`StateApplier`]; mark
    ///   the round complete from our side.
    /// - Inbound Fetch → Same as Diff (responder fulfills the request).
    pub fn on_message(
        &mut self,
        msg: ReplicationMessage,
        provider: &dyn StateProvider,
        applier: &mut dyn StateApplier,
    ) -> ReplicationOutcome {
        match msg {
            ReplicationMessage::Summary(remote_summary) => {
                self.on_summary(&remote_summary, provider)
            }
            ReplicationMessage::Diff(diff) => self.on_diff(&diff, provider),
            ReplicationMessage::Deliver(deliver) => self.on_deliver(&deliver, applier),
            ReplicationMessage::Fetch(fetch) => self.on_fetch(&fetch, provider),
        }
    }

    fn on_summary(
        &mut self,
        remote: &SummaryMessage,
        provider: &dyn StateProvider,
    ) -> ReplicationOutcome {
        if remote.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        self.last_remote_summary = Some(remote.clone());
        let local = provider.local_refs(self.kind);
        let want = diff_refs(&local, &remote.refs);
        let mut outbound = Vec::new();
        // Responder ALSO needs to send its Summary so the
        // initiator's side of the round can progress. We include it
        // before the Diff so the other end sees Summary first
        // (matching the initiator's sequence). For initiators, we
        // already sent our Summary in start_round; skip resending.
        if matches!(self.role, SessionRole::Responder) && self.last_summary_sent.is_none() {
            let my_refs = provider.local_refs(self.kind);
            let my_summary = SummaryMessage {
                kind: self.kind,
                refs: my_refs,
            };
            self.last_summary_sent = Some(my_summary.clone());
            outbound.push(ReplicationMessage::Summary(my_summary));
        }
        self.diff_want_count = Some(want.len());
        outbound.push(ReplicationMessage::Diff(DiffMessage {
            kind: self.kind,
            want,
        }));
        ReplicationOutcome::Send(outbound)
    }

    fn on_diff(&mut self, diff: &DiffMessage, provider: &dyn StateProvider) -> ReplicationOutcome {
        if diff.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        let envelopes: Vec<Vec<u8>> = diff
            .want
            .iter()
            .filter_map(|h| provider.fetch_envelope(self.kind, h))
            .collect();
        ReplicationOutcome::Send(vec![ReplicationMessage::Deliver(DeliverMessage {
            kind: self.kind,
            envelopes,
        })])
    }

    fn on_fetch(
        &mut self,
        fetch: &FetchMessage,
        provider: &dyn StateProvider,
    ) -> ReplicationOutcome {
        // Fetch is structurally identical to Diff on the responder
        // side — both ask "give me these specific envelopes."
        self.on_diff(
            &DiffMessage {
                kind: fetch.kind,
                want: fetch.want.clone(),
            },
            provider,
        )
    }

    fn on_deliver(
        &mut self,
        deliver: &DeliverMessage,
        applier: &mut dyn StateApplier,
    ) -> ReplicationOutcome {
        if deliver.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        let mut admitted = 0usize;
        let mut refused = 0usize;
        for env_bytes in &deliver.envelopes {
            if applier.apply_envelope(self.kind, env_bytes) {
                admitted += 1;
            } else {
                refused += 1;
            }
        }
        // Compute staleness from what we asked for vs what we admitted.
        // This is provider-storage-agnostic (the production wiring will
        // have provider + applier share a FederationDirectory backing,
        // but the test fixture and any in-process orchestrator are
        // free to keep them separate).
        let staleness = match self.diff_want_count {
            None => StalenessSignal::Unknown,
            Some(wanted) => {
                let still_missing = wanted.saturating_sub(admitted);
                if still_missing == 0 {
                    StalenessSignal::InSync
                } else {
                    StalenessSignal::BoundedBy {
                        missing: u64::try_from(still_missing).unwrap_or(u64::MAX),
                    }
                }
            }
        };
        self.completed = true;
        ReplicationOutcome::Applied {
            kind: self.kind,
            admitted,
            refused,
            staleness,
        }
    }

    /// Whether this session has completed its half of the round.
    pub fn is_complete(&self) -> bool {
        self.completed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::summary::{LocalState, StateApplier, StateProvider};
    use std::collections::HashMap;

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    /// Convenience: a `StateProvider` backed by a [`LocalState`] +
    /// a (envelope_hash → bytes) map so the test can fetch byte
    /// payloads back during Diff handling.
    struct TestProvider {
        state: LocalState,
        envelopes: HashMap<[u8; 32], Vec<u8>>,
    }

    impl StateProvider for TestProvider {
        fn local_refs(&self, kind: EnvelopeKind) -> Vec<super::super::protocol::EnvelopeRef> {
            self.state.refs_for(kind)
        }
        fn fetch_envelope(&self, _kind: EnvelopeKind, h: &[u8; 32]) -> Option<Vec<u8>> {
            self.envelopes.get(h).cloned()
        }
    }

    /// An applier that records what it admitted. Maps inbound bytes
    /// back to a hash by indexing the test's known set; in production
    /// the applier validates signatures + canonical-bytes-hash before
    /// admitting.
    struct TestApplier {
        admitted: Vec<Vec<u8>>,
        local_state: LocalState,
        hash_lookup: HashMap<Vec<u8>, [u8; 32]>,
    }

    impl StateApplier for TestApplier {
        fn apply_envelope(&mut self, kind: EnvelopeKind, bytes: &[u8]) -> bool {
            // In production: verify sig + recompute hash. Here we
            // look up the precomputed hash for these bytes.
            if let Some(hash) = self.hash_lookup.get(bytes).copied() {
                let kind_set = self.local_state.by_kind.entry(kind).or_default();
                if kind_set.contains_key(&hash) {
                    return false; // duplicate
                }
                kind_set.insert(hash, 1);
                self.admitted.push(bytes.to_vec());
                true
            } else {
                false
            }
        }
    }

    fn provider_with(envelopes: &[(EnvelopeKind, [u8; 32], Vec<u8>, u64)]) -> TestProvider {
        let mut state = LocalState::new();
        let mut bytes_map = HashMap::new();
        for (k, hash, bytes, seq) in envelopes {
            state.insert(*k, *hash, *seq);
            bytes_map.insert(*hash, bytes.clone());
        }
        TestProvider {
            state,
            envelopes: bytes_map,
        }
    }

    fn applier_for(hash_to_bytes: &[([u8; 32], Vec<u8>)]) -> TestApplier {
        let mut hash_lookup = HashMap::new();
        for (h, b) in hash_to_bytes {
            hash_lookup.insert(b.clone(), *h);
        }
        TestApplier {
            admitted: Vec::new(),
            local_state: LocalState::new(),
            hash_lookup,
        }
    }

    /// Two peers with disjoint state converge in one round.
    #[test]
    fn full_sync_disjoint_state_converges() {
        // Alice has envelopes {1, 2}; Bob has {3, 4}.
        let a_provider = provider_with(&[
            (EnvelopeKind::Key, h(1), b"env_1".to_vec(), 10),
            (EnvelopeKind::Key, h(2), b"env_2".to_vec(), 11),
        ]);
        let b_provider = provider_with(&[
            (EnvelopeKind::Key, h(3), b"env_3".to_vec(), 12),
            (EnvelopeKind::Key, h(4), b"env_4".to_vec(), 13),
        ]);
        let mut a_applier = applier_for(&[(h(3), b"env_3".to_vec()), (h(4), b"env_4".to_vec())]);
        let mut b_applier = applier_for(&[(h(1), b"env_1".to_vec()), (h(2), b"env_2".to_vec())]);

        let mut alice = Session::new(SessionRole::Initiator, EnvelopeKind::Key);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Key);

        // 1. Alice starts → sends Summary.
        let alice_step1 = alice.start_round(&a_provider);
        let alice_summary = match alice_step1 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 2. Bob receives Alice's Summary → emits {Summary, Diff}.
        let bob_step1 = bob.on_message(alice_summary, &b_provider, &mut b_applier);
        let (bob_summary, bob_diff) = match bob_step1 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 2);
                (msgs[0].clone(), msgs[1].clone())
            }
            _ => panic!("expected Send"),
        };

        // 3. Alice receives Bob's Summary → emits Diff. (Then
        //    receives Bob's Diff → emits Deliver.)
        let alice_step2 = alice.on_message(bob_summary, &a_provider, &mut a_applier);
        let alice_diff = match alice_step2 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 4. Bob receives Alice's Diff → emits Deliver(env_1, env_2).
        let bob_step2 = bob.on_message(alice_diff, &b_provider, &mut b_applier);
        let bob_deliver = match bob_step2 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 5. Alice receives Bob's Diff → emits Deliver(env_3, env_4).
        let alice_step3 = alice.on_message(bob_diff, &a_provider, &mut a_applier);
        let alice_deliver = match alice_step3 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 6. Alice applies Bob's Deliver → admitted env_3 + env_4.
        let alice_final = alice.on_message(bob_deliver, &a_provider, &mut a_applier);
        match alice_final {
            ReplicationOutcome::Applied {
                admitted,
                refused,
                staleness,
                ..
            } => {
                assert_eq!(admitted, 2);
                assert_eq!(refused, 0);
                assert_eq!(staleness, StalenessSignal::InSync);
            }
            _ => panic!("expected Applied, got {alice_final:?}"),
        }

        // 7. Bob applies Alice's Deliver → admitted env_1 + env_2.
        let bob_final = bob.on_message(alice_deliver, &b_provider, &mut b_applier);
        match bob_final {
            ReplicationOutcome::Applied {
                admitted,
                refused,
                staleness,
                ..
            } => {
                assert_eq!(admitted, 2);
                assert_eq!(refused, 0);
                assert_eq!(staleness, StalenessSignal::InSync);
            }
            _ => panic!("expected Applied, got {bob_final:?}"),
        }

        // Both sides complete.
        assert!(alice.is_complete());
        assert!(bob.is_complete());
        // Local state of each applier carries the new envelopes.
        assert_eq!(a_applier.admitted.len(), 2);
        assert_eq!(b_applier.admitted.len(), 2);
    }

    /// Partial overlap — peers share some envelopes; only the missing
    /// ones get delivered.
    #[test]
    fn partial_overlap_only_missing_delivered() {
        // Alice has {1, 2, 3}; Bob has {2, 3, 4}. The intersection is
        // {2, 3}; alice wants {4}; bob wants {1}.
        let a_provider = provider_with(&[
            (EnvelopeKind::Attestation, h(1), b"e1".to_vec(), 1),
            (EnvelopeKind::Attestation, h(2), b"e2".to_vec(), 2),
            (EnvelopeKind::Attestation, h(3), b"e3".to_vec(), 3),
        ]);
        let b_provider = provider_with(&[
            (EnvelopeKind::Attestation, h(2), b"e2".to_vec(), 2),
            (EnvelopeKind::Attestation, h(3), b"e3".to_vec(), 3),
            (EnvelopeKind::Attestation, h(4), b"e4".to_vec(), 4),
        ]);
        let mut a_applier = applier_for(&[(h(4), b"e4".to_vec())]);
        let mut b_applier = applier_for(&[(h(1), b"e1".to_vec())]);

        let mut alice = Session::new(SessionRole::Initiator, EnvelopeKind::Attestation);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);

        // Mechanical round-drive (same as full_sync above).
        let m_alice_summary = match alice.start_round(&a_provider) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let (m_bob_summary, m_bob_diff) =
            match bob.on_message(m_alice_summary, &b_provider, &mut b_applier) {
                ReplicationOutcome::Send(m) => (m[0].clone(), m[1].clone()),
                _ => panic!(),
            };
        let m_alice_diff = match alice.on_message(m_bob_summary, &a_provider, &mut a_applier) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let m_bob_deliver = match bob.on_message(m_alice_diff, &b_provider, &mut b_applier) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let m_alice_deliver = match alice.on_message(m_bob_diff, &a_provider, &mut a_applier) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        match alice.on_message(m_bob_deliver, &a_provider, &mut a_applier) {
            ReplicationOutcome::Applied { admitted, .. } => assert_eq!(admitted, 1),
            o => panic!("unexpected: {o:?}"),
        }
        match bob.on_message(m_alice_deliver, &b_provider, &mut b_applier) {
            ReplicationOutcome::Applied { admitted, .. } => assert_eq!(admitted, 1),
            o => panic!("unexpected: {o:?}"),
        }
    }

    /// Idempotent — running the protocol twice changes nothing the
    /// second time (Deliver becomes empty; InSync the whole way).
    #[test]
    fn idempotent_second_run_no_changes() {
        let a_provider = provider_with(&[
            (EnvelopeKind::Key, h(1), b"e1".to_vec(), 1),
            (EnvelopeKind::Key, h(2), b"e2".to_vec(), 2),
        ]);
        let b_provider = provider_with(&[
            (EnvelopeKind::Key, h(1), b"e1".to_vec(), 1),
            (EnvelopeKind::Key, h(2), b"e2".to_vec(), 2),
        ]);
        let mut a_applier = applier_for(&[]);
        let mut b_applier = applier_for(&[]);

        let mut alice = Session::new(SessionRole::Initiator, EnvelopeKind::Key);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Key);

        // Drive round.
        let alice_summary = match alice.start_round(&a_provider) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let (bob_summary_resp, bob_diff_msg) =
            match bob.on_message(alice_summary, &b_provider, &mut b_applier) {
                ReplicationOutcome::Send(m) => (m[0].clone(), m[1].clone()),
                _ => panic!(),
            };
        let alice_diff_msg = match alice.on_message(bob_summary_resp, &a_provider, &mut a_applier) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        // Bob's Deliver from Alice's Diff should be empty (Alice has
        // everything Bob has).
        let bob_deliver_msg = match bob.on_message(alice_diff_msg, &b_provider, &mut b_applier) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        if let ReplicationMessage::Deliver(d) = &bob_deliver_msg {
            assert!(d.envelopes.is_empty(), "bob should deliver nothing");
        }
        // Same for Alice's Deliver from Bob's Diff.
        let alice_deliver_msg = match alice.on_message(bob_diff_msg, &a_provider, &mut a_applier) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        if let ReplicationMessage::Deliver(d) = &alice_deliver_msg {
            assert!(d.envelopes.is_empty(), "alice should deliver nothing");
        }
        // Applied with 0 admitted, InSync staleness.
        match alice.on_message(bob_deliver_msg, &a_provider, &mut a_applier) {
            ReplicationOutcome::Applied {
                admitted,
                staleness,
                ..
            } => {
                assert_eq!(admitted, 0);
                assert_eq!(staleness, StalenessSignal::InSync);
            }
            o => panic!("{o:?}"),
        }
    }

    /// Mismatched-kind message refused with UnexpectedMessage —
    /// defence against a misbehaving peer or a routing bug.
    #[test]
    fn mismatched_kind_refused() {
        let provider = provider_with(&[]);
        let mut applier = applier_for(&[]);
        let mut s = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        let r = s.on_message(
            ReplicationMessage::Diff(DiffMessage {
                kind: EnvelopeKind::Revocation, // ← wrong kind for this session
                want: vec![],
            }),
            &provider,
            &mut applier,
        );
        assert_eq!(r, ReplicationOutcome::UnexpectedMessage);
    }

    /// CIRISEdge#927 / v13.7.0 — a Responder applies an UNSOLICITED bare
    /// `Deliver` (no preceding Summary/Diff). This is the load-bearing invariant
    /// for initiator-first delivery to a carrier-NAT'd peer: the side that can
    /// reach (the initiator) PUSHES its key/attestation, and the responder —
    /// which can neither dial back through NAT nor complete a resource the peer
    /// won't pull — simply APPLIES it. `on_message` dispatches by message TYPE,
    /// not phase, so there is NO Summary→Diff→Deliver gate that would refuse the
    /// push. A regression here would silently re-break the mobile trace.
    #[test]
    fn responder_applies_unsolicited_bare_deliver() {
        let provider = provider_with(&[]);
        let mut applier = applier_for(&[(h(1), b"pushed-key".to_vec())]);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        // No Summary, no Diff — the initiator just pushes its key envelope.
        let r = bob.on_message(
            ReplicationMessage::Deliver(DeliverMessage {
                kind: EnvelopeKind::Key,
                envelopes: vec![b"pushed-key".to_vec()],
            }),
            &provider,
            &mut applier,
        );
        match r {
            ReplicationOutcome::Applied {
                admitted, refused, ..
            } => {
                assert_eq!(admitted, 1, "the pushed key envelope MUST be applied");
                assert_eq!(refused, 0);
            }
            o => panic!("a bare Deliver must be Applied (no phase gate), got {o:?}"),
        }
        assert!(bob.is_complete(), "the bare-Deliver round completes");
    }

    /// CIRISEdge#927 — a self-publishing Initiator's `start_round` PROACTIVELY
    /// delivers its publish set alongside the Summary (initiator-first), so a
    /// carrier-NAT'd peer's key/attestation lands without a return-path Diff.
    /// The plain (non-publishing) initiator stays Summary-only — no unsolicited
    /// dump of a large-state node's contents.
    #[test]
    fn proactive_publish_initiator_delivers_alongside_summary() {
        let provider = provider_with(&[(EnvelopeKind::Key, h(1), b"my-key-env".to_vec(), 1)]);
        let mut m =
            Session::new(SessionRole::Initiator, EnvelopeKind::Key).with_proactive_publish(true);
        match m.start_round(&provider) {
            ReplicationOutcome::Send(msgs) => {
                assert_eq!(msgs.len(), 2, "Summary + proactive Deliver");
                assert!(matches!(msgs[0], ReplicationMessage::Summary(_)));
                match &msgs[1] {
                    ReplicationMessage::Deliver(d) => {
                        assert_eq!(d.kind, EnvelopeKind::Key);
                        assert_eq!(d.envelopes, vec![b"my-key-env".to_vec()]);
                    }
                    o => panic!("expected a proactive Deliver, got {o:?}"),
                }
            }
            o => panic!("expected Send, got {o:?}"),
        }
        // Without the flag: Summary only — the default anti-entropy pull.
        let mut plain = Session::new(SessionRole::Initiator, EnvelopeKind::Key);
        match plain.start_round(&provider) {
            ReplicationOutcome::Send(msgs) => assert_eq!(msgs.len(), 1, "Summary only"),
            o => panic!("expected Send, got {o:?}"),
        }
    }

    // ── CIRISEdge#380 — delta-aware bounded proactive push + initiator-final ──

    /// The peer's last reverse-path Summary is the delta basis: refs it
    /// already holds are NOT re-pushed.
    #[test]
    fn proactive_push_skips_refs_the_peer_summary_holds() {
        let provider = provider_with(&[
            (EnvelopeKind::Attestation, h(1), b"env-a".to_vec(), 1),
            (EnvelopeKind::Attestation, h(2), b"env-b".to_vec(), 2),
        ]);
        let mut applier = applier_for(&[]);
        let mut s = Session::new(SessionRole::Initiator, EnvelopeKind::Attestation)
            .with_proactive_publish(true);
        // The responder's reverse-path Summary arrives first: it holds h(1).
        let _ = s.on_message(
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Attestation,
                refs: vec![EnvelopeRef {
                    envelope_hash: h(1),
                    seq: 1,
                }],
            }),
            &provider,
            &mut applier,
        );
        match s.start_round(&provider) {
            ReplicationOutcome::Send(msgs) => {
                let deliver = msgs.iter().find_map(|m| match m {
                    ReplicationMessage::Deliver(d) => Some(d),
                    _ => None,
                });
                let d = deliver.expect("delta push fires for the ref the peer lacks");
                assert_eq!(d.envelopes, vec![b"env-b".to_vec()], "only h(2) pushed");
            }
            o => panic!("expected Send, got {o:?}"),
        }
    }

    /// An envelope pushed this round is NOT re-pushed next round (sent-cache);
    /// it re-qualifies only after `PROACTIVE_REFRESH_ROUNDS`.
    #[test]
    fn proactive_push_does_not_repush_within_refresh_window() {
        let provider = provider_with(&[(EnvelopeKind::Key, h(1), b"env-a".to_vec(), 1)]);
        let mut s =
            Session::new(SessionRole::Initiator, EnvelopeKind::Key).with_proactive_publish(true);
        match s.start_round(&provider) {
            ReplicationOutcome::Send(msgs) => assert_eq!(msgs.len(), 2, "round 1 pushes"),
            o => panic!("expected Send, got {o:?}"),
        }
        match s.start_round(&provider) {
            ReplicationOutcome::Send(msgs) => {
                assert_eq!(
                    msgs.len(),
                    1,
                    "round 2: Summary only — no re-push (v13.7.0 re-blasted)"
                );
            }
            o => panic!("expected Send, got {o:?}"),
        }
    }

    /// The per-round byte budget bounds the batch; spillover converges on the
    /// next round (oldest seq first), and an envelope bigger than the whole
    /// budget still ships alone.
    #[test]
    fn proactive_push_respects_budget_with_spillover() {
        let big_a = vec![0xAAu8; PROACTIVE_PUSH_BUDGET_BYTES - 1024];
        let big_b = vec![0xBBu8; PROACTIVE_PUSH_BUDGET_BYTES - 1024];
        let oversize = vec![0xCCu8; PROACTIVE_PUSH_BUDGET_BYTES + 4096];
        let provider = provider_with(&[
            (EnvelopeKind::Attestation, h(1), big_a.clone(), 1),
            (EnvelopeKind::Attestation, h(2), big_b.clone(), 2),
            (EnvelopeKind::Attestation, h(3), oversize.clone(), 3),
        ]);
        let mut s = Session::new(SessionRole::Initiator, EnvelopeKind::Attestation)
            .with_proactive_publish(true);
        let round_envelopes = |s: &mut Session| -> Vec<Vec<u8>> {
            match s.start_round(&provider) {
                ReplicationOutcome::Send(msgs) => msgs
                    .into_iter()
                    .find_map(|m| match m {
                        ReplicationMessage::Deliver(d) => Some(d.envelopes),
                        _ => None,
                    })
                    .unwrap_or_default(),
                o => panic!("expected Send, got {o:?}"),
            }
        };
        assert_eq!(
            round_envelopes(&mut s),
            vec![big_a],
            "round 1: seq-1 fits, rest spills"
        );
        assert_eq!(round_envelopes(&mut s), vec![big_b], "round 2: seq-2");
        assert_eq!(
            round_envelopes(&mut s),
            vec![oversize],
            "round 3: the over-budget envelope still ships, alone — a budget \
             bounds the batch, never strands an envelope"
        );
        assert!(
            round_envelopes(&mut s).is_empty(),
            "round 4: everything sent"
        );
    }

    /// INITIATOR-FINAL: when the peer's own Summary confirms it holds our full
    /// set and we want nothing of its, the round completes at send — no wire
    /// wait, and `round_outcomes` reports `completed` (the #370 instrument
    /// stops normalizing error). Pushed-but-unconfirmed rounds do NOT complete.
    #[test]
    fn initiator_final_completes_only_on_confirmed_sync() {
        let provider = provider_with(&[(EnvelopeKind::Key, h(1), b"env-a".to_vec(), 1)]);
        let mut applier = applier_for(&[]);
        let mut s =
            Session::new(SessionRole::Initiator, EnvelopeKind::Key).with_proactive_publish(true);
        // Round 1: never heard the peer → pushes, must NOT complete.
        assert!(
            matches!(s.start_round(&provider), ReplicationOutcome::Send(_)),
            "unconfirmed push stays Send-then-wait"
        );
        // The reverse-path Summary arrives: peer holds h(1) (and nothing more).
        let _ = s.on_message(
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![EnvelopeRef {
                    envelope_hash: h(1),
                    seq: 1,
                }],
            }),
            &provider,
            &mut applier,
        );
        // Round 2: confirmed sync → SendAndComplete.
        match s.start_round(&provider) {
            ReplicationOutcome::SendAndComplete { msgs, kind } => {
                assert_eq!(kind, EnvelopeKind::Key);
                assert_eq!(msgs.len(), 1, "Summary only — nothing to push");
            }
            o => panic!("expected SendAndComplete on confirmed sync, got {o:?}"),
        }
        // reset() (the coordinator's auto-reset on Complete) preserves the
        // cross-round knowledge → the NEXT round completes too.
        s.reset();
        assert!(
            matches!(
                s.start_round(&provider),
                ReplicationOutcome::SendAndComplete { .. }
            ),
            "knowledge survives reset — steady-state stays completed"
        );
    }

    /// A peer whose Summary advertises rows WE lack blocks initiator-final —
    /// the pull half of anti-entropy still matters when it can work.
    #[test]
    fn initiator_final_blocked_when_we_want_their_rows() {
        let provider = provider_with(&[(EnvelopeKind::Key, h(1), b"env-a".to_vec(), 1)]);
        let mut applier = applier_for(&[]);
        let mut s =
            Session::new(SessionRole::Initiator, EnvelopeKind::Key).with_proactive_publish(true);
        let _ = s.on_message(
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![
                    EnvelopeRef {
                        envelope_hash: h(1),
                        seq: 1,
                    },
                    EnvelopeRef {
                        envelope_hash: h(9), // theirs, we lack it
                        seq: 9,
                    },
                ],
            }),
            &provider,
            &mut applier,
        );
        assert!(
            matches!(s.start_round(&provider), ReplicationOutcome::Send(_)),
            "wanting their rows keeps the round open"
        );
    }

    /// Fetch — on-demand envelope retrieval, distinct from anti-
    /// entropy. Responder behavior is the same shape as Diff
    /// (look up envelopes by hash, deliver bytes).
    #[test]
    fn fetch_returns_requested_envelopes() {
        let provider = provider_with(&[
            (EnvelopeKind::Attestation, h(1), b"e1".to_vec(), 1),
            (EnvelopeKind::Attestation, h(2), b"e2".to_vec(), 2),
        ]);
        let mut applier = applier_for(&[]);
        let mut s = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let r = s.on_message(
            ReplicationMessage::Fetch(FetchMessage {
                kind: EnvelopeKind::Attestation,
                want: vec![h(1), h(99)], // h(99) doesn't exist
            }),
            &provider,
            &mut applier,
        );
        match r {
            ReplicationOutcome::Send(msgs) => {
                assert_eq!(msgs.len(), 1);
                if let ReplicationMessage::Deliver(d) = &msgs[0] {
                    assert_eq!(d.envelopes, vec![b"e1".to_vec()]); // only h(1) delivered
                } else {
                    panic!("expected Deliver");
                }
            }
            o => panic!("{o:?}"),
        }
    }

    /// BoundedBy staleness — local applies some but not all of a
    /// remote summary's envelopes (the applier refused some — e.g.
    /// signature validation failed in a hypothetical production
    /// scenario).
    #[test]
    fn bounded_by_staleness_when_some_envelopes_refused() {
        // Bob's summary advertises 3 envelopes; Alice's applier
        // only accepts 1 of them (the other 2 have unknown bytes →
        // refused).
        let a_provider = provider_with(&[]);
        let mut a_applier = applier_for(&[(h(1), b"e1".to_vec())]);
        let mut alice = Session::new(SessionRole::Initiator, EnvelopeKind::Key);
        // Skip the wire dance — drive on_message directly.
        let bob_summary = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![
                super::super::protocol::EnvelopeRef {
                    envelope_hash: h(1),
                    seq: 1,
                },
                super::super::protocol::EnvelopeRef {
                    envelope_hash: h(2),
                    seq: 2,
                },
                super::super::protocol::EnvelopeRef {
                    envelope_hash: h(3),
                    seq: 3,
                },
            ],
        });
        alice.start_round(&a_provider);
        let _ = alice.on_message(bob_summary, &a_provider, &mut a_applier);
        let bob_deliver = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Key,
            envelopes: vec![
                b"e1".to_vec(),         // known, applies
                b"unknown_e2".to_vec(), // applier doesn't know → refuse
                b"unknown_e3".to_vec(),
            ],
        });
        match alice.on_message(bob_deliver, &a_provider, &mut a_applier) {
            ReplicationOutcome::Applied {
                admitted,
                refused,
                staleness,
                ..
            } => {
                assert_eq!(admitted, 1);
                assert_eq!(refused, 2);
                assert_eq!(staleness, StalenessSignal::BoundedBy { missing: 2 });
            }
            o => panic!("{o:?}"),
        }
    }
}
