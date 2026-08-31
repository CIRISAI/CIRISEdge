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
    CursorPullMessage, DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, FetchMessage,
    PullMessage, ReplicationMessage, SummaryMessage,
};
use super::retention::{retention_for, Retention};
use super::summary::{diff_refs, ApplyOutcome, StalenessSignal, StateApplier, StateProvider};

/// What role a session is playing in this round. Initiator emits
/// the first Summary; Responder waits for one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

/// CIRISEdge#414 / CIRISAgent#932 — the maximum RAW envelope bytes a single
/// `Deliver` may carry. A round's diff can want an unbounded number of envelopes;
/// packing them ALL into one `Deliver` produces one frame whose size is unbounded
/// in the peer's holdings (the observed amplification: a busy reverse-path link's
/// oversized Deliver was silently dropped — #932). The transport now fragments any
/// oversized frame onto the packet path, but a frame needing tens of thousands of
/// fragments cannot reassemble under any packet loss (whole-frame retry). Bounding
/// the Deliver here caps the per-round frame — the fragment count per frame stays
/// reassemblable, and the **remainder is carried by the next round's re-diff**
/// (the wanted-but-undelivered hashes stay in `want` because they were never
/// admitted, so the existing periodic anti-entropy round re-requests them). This
/// is semantics-preserving: still ONE `Deliver` per round, and the `BoundedBy`
/// staleness it yields is HONEST (envelopes genuinely remain). A Deliver always
/// carries at least one envelope, so a single envelope larger than the budget is
/// still sent whole (fragmentation carries it; the budget only bounds how many
/// whole envelopes ride together).
///
/// 512 KiB raw → ~1.8 MB JSON-wire → a bounded (not unbounded-in-holdings) frame,
/// while leaving the common small-holdings round a single unfragmented/­lightly-
/// fragmented Deliver. Tuning against real link-loss telemetry is a follow-up; the
/// DST (`replication::sim`) is the harness for it.
pub const MAX_DELIVER_ENVELOPE_BYTES: usize = 512 * 1024;

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
    /// The peer sent a message this session refuses — in practice a message
    /// whose `kind` mismatches this `(peer, kind)` session (the only refusal
    /// the `on_*` arms produce), or a `start_round` on a Responder. NOT a
    /// fatal error, and NOT a state transition: the refusal is
    /// message-typed — the session's round state is left untouched, and only
    /// the coordinator resets the session (its auto-reset on round
    /// Complete). The caller can decide whether to retry or drop the peer.
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
    ///
    /// CIRISEdge#544 — this counts what we ASKED FOR, which is now the wanted
    /// set MINUS the hashes this node has already refused. That is deliberate,
    /// and it makes the signal more honest rather than less: a terminally
    /// refused row is not an envelope still in flight, it is one this node
    /// declined, and counting it kept a single junk row reporting
    /// `BoundedBy { missing: 1 }` forever — permanently degrading every consumer
    /// that conditions τ_partial on this signal, over a row that was never going
    /// to arrive. The refusal itself stays loud at the apply choke.
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
    /// CIRISEdge#474 — set when this Initiator opened a CURSOR round (emitted a
    /// `CursorPull` instead of a Summary). The answering `Deliver` is then a
    /// SOLICITED reply, not an unsolicited push — so [`Self::on_deliver`] applies
    /// it without the per-round unsolicited-WARN, and an empty cursor result still
    /// completes the round cleanly. Per-round state, cleared by [`Self::reset`].
    awaiting_cursor_deliver: bool,
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
            awaiting_cursor_deliver: false,
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
        self.awaiting_cursor_deliver = false;
    }

    pub fn role(&self) -> SessionRole {
        self.role
    }

    pub fn kind(&self) -> EnvelopeKind {
        self.kind
    }

    /// Start a round. Only valid for [`SessionRole::Initiator`] —
    /// responders wait for an inbound Summary via [`Self::on_message`].
    /// A Responder `start_round` is refused with
    /// [`ReplicationOutcome::UnexpectedMessage`] (state untouched).
    pub fn start_round(&mut self, provider: &dyn StateProvider) -> ReplicationOutcome {
        if !matches!(self.role, SessionRole::Initiator) {
            // Release-safe guard (was a `debug_assert!` that compiled OUT of
            // release builds, so a mis-scheduled production Responder would
            // have emitted a bogus Summary-as-initiator instead of refusing).
            // `UnexpectedMessage` is the existing message-typed refusal the
            // coordinator already maps to `DriveStep::Refused` and the
            // scheduler to `RoundEvent::Refused` — the non-fatal shape a
            // scheduler bug deserves; panicking a production node would not be.
            tracing::error!(
                kind = ?self.kind,
                "start_round() called on a Responder session — refused (initiator-only)"
            );
            return ReplicationOutcome::UnexpectedMessage;
        }
        // CIRISEdge#474 — the accord-quorum-evidence plane has no content-hash
        // index, so its round opens with a CURSOR pull, not a Summary. `since:
        // None` pulls all (bounded by the responder's page limit); the receiver's
        // re-tally admit is idempotent on replay, so a stateless-from-None puller
        // is correct — edge's uniform per-round read model. The answering Deliver
        // is marked solicited (`awaiting_cursor_deliver`) so `on_deliver` applies
        // it as a reply, and an evidence-free peer completes the round cleanly.
        if self.kind.is_cursor_served() {
            self.awaiting_cursor_deliver = true;
            return ReplicationOutcome::Send(vec![ReplicationMessage::CursorPull(
                CursorPullMessage {
                    kind: self.kind,
                    since: None,
                },
            )]);
        }
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
        // CIRISEdge#370 — `&dyn` (was `&mut dyn`): appliers are shared,
        // interior-mutable-or-stateless; no exclusive borrow is required to
        // apply, so callers need no wrapping mutex.
        applier: &dyn StateApplier,
        // CIRISEdge#426 — the authenticated sender of this message, forwarded to
        // the apply path so a per-peer RECEIVE decision is expressible. Pure
        // pass-through: only the Deliver arm (the sole write path) consults it.
        source_peer: Option<&str>,
    ) -> ReplicationOutcome {
        match msg {
            ReplicationMessage::Summary(remote_summary) => {
                self.on_summary(&remote_summary, provider, source_peer)
            }
            ReplicationMessage::Diff(diff) => self.on_diff(&diff, provider, source_peer),
            ReplicationMessage::Deliver(deliver) => {
                self.on_deliver(&deliver, provider, applier, source_peer)
            }
            ReplicationMessage::Fetch(fetch) => self.on_fetch(&fetch, provider, source_peer),
            ReplicationMessage::Pull(pull) => self.on_pull(&pull, provider),
            ReplicationMessage::CursorPull(cp) => self.on_cursor_pull(&cp, provider),
        }
    }

    /// CIRISEdge#474 — serve an accord-quorum-evidence CURSOR pull. Unlike
    /// [`Self::on_pull`] (which seeds the content-hash Summary→Diff→Deliver
    /// machinery), this plane has NO content-hash index, so we answer DIRECTLY
    /// with a [`DeliverMessage`] of the serialized bundles past the requester's
    /// `since` watermark — sourced from [`StateProvider::accord_evidence_since`],
    /// which reads persist's cursor-ordered `list_signed_accord_quorum_evidence_since`
    /// and applies the same page limit as every other plane. The requester
    /// re-tallies each bundle on apply (`apply_accord_quorum_evidence`), so serving
    /// from `since` (or the beginning) can only converge — a byte-identical replay
    /// is a `Duplicate`, never a double-count. An empty result is a well-formed
    /// empty `Deliver`: the round still completes (the reply is solicited via the
    /// requester's `awaiting_cursor_deliver`), no timeout, no unsolicited WARN.
    fn on_cursor_pull(
        &mut self,
        pull: &CursorPullMessage,
        provider: &dyn StateProvider,
    ) -> ReplicationOutcome {
        if pull.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        let envelopes = provider.accord_evidence_since(self.kind, pull.since);
        ReplicationOutcome::Send(vec![ReplicationMessage::Deliver(DeliverMessage {
            kind: self.kind,
            envelopes,
        })])
    }

    /// CIRISEdge#462 — serve a subject-scoped RECEIVE-axis pull. The requester
    /// asked "which `kind` records do you hold where `subject_key_id` is the
    /// data-subject or sender?" We answer with an ordinary [`SummaryMessage`] of
    /// the refs we hold for that subject — sourced from
    /// [`StateProvider::subject_refs`], which is projection-gated and withholds
    /// the `capacity:*` scores about the subject (the G2 carve). From here the
    /// EXISTING flow takes over unchanged: the requester's `on_summary` computes
    /// `want = subject_refs ∖ its own holdings`, sends a Diff, and our `on_diff`
    /// serves the bytes through `fetch_envelope` — which RE-APPLIES the full
    /// per-record serve gate, so the Pull widens nothing.
    ///
    /// Reusing Summary here is deliberate: the want-generator the receive axis
    /// needs (`remote ∖ holdings`) is *exactly* what `on_summary` already is; the
    /// Pull's only job is to seed that machinery with a SUBJECT-scoped ref set
    /// instead of the advertise set the `SelfOwn` plane never produces.
    fn on_pull(&mut self, pull: &PullMessage, provider: &dyn StateProvider) -> ReplicationOutcome {
        if pull.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        let refs = provider.subject_refs(self.kind, &pull.subject_key_id);
        let summary = SummaryMessage {
            kind: self.kind,
            refs,
        };
        // Record what we offered so a subsequent Diff for these refs is served
        // (the responder path reads `last_summary_sent` conceptually via
        // `fetch_envelope`; recording it keeps staleness telemetry honest).
        self.last_summary_sent = Some(summary.clone());
        ReplicationOutcome::Send(vec![ReplicationMessage::Summary(summary)])
    }

    fn on_summary(
        &mut self,
        remote: &SummaryMessage,
        provider: &dyn StateProvider,
        // CIRISEdge#552 — the advertising peer. A Summary is where the holder map
        // is learned: knowing a record exists is only actionable alongside who
        // offered it, and this is the one arm that sees both.
        source_peer: Option<&str>,
    ) -> ReplicationOutcome {
        if remote.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        self.last_remote_summary = Some(remote.clone());
        // CIRISEdge#414 — RECEIVE axis: what this node still LACKS is computed
        // from its REAL holdings, not from its (send-gated) offer. Using
        // `local_refs` here fused the #396 SEND gate onto the RECEIVE side — a
        // responder with no consent to send to the initiator saw an empty offer,
        // so `want` became "everything" or the round went dark. `local_holdings`
        // is the node's peer-blind own-state; the offer + delivery stay send-gated.
        let local = provider.local_holdings(self.kind);
        let mut want = diff_refs(&local, &remote.refs);
        // CIRISEdge#544 — the re-offer loop is RECEIVER-PULLED, and this is where
        // the pull is decided. `want` is memoryless: a refused row is never
        // stored, so it is absent from `local_holdings`, so it comes straight
        // back into `want` next round and the peer — doing exactly what we asked
        // — delivers the identical bytes again. Measured on the canonical: one
        // `conflicting_version` Key row, 55 re-offers in 30 minutes, same content
        // hash every time. Dropping the hashes the applier has already refused,
        // for the window its disposition earned, is the whole fix; the sender
        // needs to be told nothing, because it was never the one choosing.
        let before = want.len();
        want.retain(|h| !provider.retry_suppressed(self.kind, h));
        let suppressed = before - want.len();
        if suppressed > 0 {
            // DEBUG, not WARN: the suppression is the CURE, and the refusal that
            // caused it already logged loud at the apply choke with its reason
            // and disposition. A WARN here would re-flood the log this exists to
            // quiet down.
            tracing::debug!(
                kind = ?self.kind,
                suppressed,
                still_wanted = want.len(),
                "want: dropped hashes this node already refused — backing off \
                 instead of re-asking every round (CIRISEdge#544)"
            );
        }
        // ── CIRISEdge#552: HASH-FIRST ────────────────────────────────────────
        // Learn the peer's hashes; ask for no bodies. The node still knows every
        // record exists and who offered it — it simply has not pulled the corpus.
        // That is what keeps a federation-tier identity directory from being an
        // address book: a hash is not a mailing address, and resolving one takes
        // a fetch, which is observable and refusable.
        //
        // `retention_for` is not bypassable by a provider: a `HashFirst` answer
        // for a plane that RETRACTS something still comes back `Bodies`. A node
        // holding the hash of a revocation has not applied it (CIRISEdge#553).
        if retention_for(self.kind, provider.retention(self.kind)) == Retention::HashFirst {
            provider.note_known_hashes(self.kind, &want, source_peer);
            let learned = want.len();
            want.clear();
            if learned > 0 {
                tracing::debug!(
                    kind = ?self.kind,
                    learned,
                    peer = ?source_peer,
                    "hash-first: learned the peer's hashes without pulling bodies \
                     (CIRISEdge#552)"
                );
            }
        }

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

    /// CIRISEdge#414/#932 — pack a byte-BOUNDED prefix of the wanted envelopes,
    /// not the whole (unbounded-in-holdings) set. Fetch in `want` order and stop
    /// once the running raw-byte total would exceed MAX_DELIVER_ENVELOPE_BYTES —
    /// but ALWAYS include at least one envelope (a single envelope larger than
    /// the budget rides whole; the transport fragments it). The undelivered
    /// remainder is NOT lost: those hashes stay in the peer's `want` next round
    /// (never admitted → still missing from its holdings), so the periodic
    /// anti-entropy re-diff carries them, one bounded Deliver per round, until
    /// InSync. This bounds the per-round wire frame so its fragment count stays
    /// reassemblable under packet loss.
    ///
    /// CIRISEdge#429 — returns, alongside the packed envelopes, the hashes that
    /// were advertised-but-UNFETCHABLE (a `want` the provider could not serve).
    /// These are NOT swallowed: the requester asked for something we just claimed
    /// to hold, so an unfetchable want is the single most diagnostic event at this
    /// point (stale wire-index, pruned row, hash skew). Returning the set — rather
    /// than a bare `continue` that vanishes — is the send-side twin of #425's
    /// "never a silent drop" on apply, and lets the caller log each miss LOUD and a
    /// test assert the drop directly instead of inferring it from a byte count. The
    /// budget-`break` remainder is deliberately NOT counted here: that is honest
    /// deferral to the next round, a categorically different thing from unfetchable.
    ///
    /// CIRISEdge#531 DEPTH — "those hashes stay in the peer's `want` next round"
    /// is a claim about the SENDER's advertise set, and the advertise set is now
    /// a per-round PAGE against a per-(peer, plane) watermark. The deferral still
    /// holds, with a bound rather than immediately: a deferred hash is re-offered
    /// when the sender's rolling re-sweep next reaches it, at most
    /// `ceil(corpus / sweep_page_rows)` rounds away — and for any plane smaller
    /// than one page (every plane on a small mesh) it is still the very next
    /// round. The re-sweep is what keeps this sentence true; see
    /// `bridge::PlaneWatermark`.
    fn pack_bounded_deliver(
        &self,
        want: &[[u8; 32]],
        provider: &dyn StateProvider,
    ) -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
        let mut envelopes: Vec<Vec<u8>> = Vec::new();
        let mut dropped: Vec<[u8; 32]> = Vec::new();
        let mut packed_bytes = 0usize;
        for h in want {
            let Some(bytes) = provider.fetch_envelope(self.kind, h) else {
                dropped.push(*h);
                continue;
            };
            // Stop BEFORE exceeding the budget, but never emit an empty Deliver:
            // the first envelope always goes in regardless of its size.
            if !envelopes.is_empty() && packed_bytes + bytes.len() > MAX_DELIVER_ENVELOPE_BYTES {
                break;
            }
            packed_bytes += bytes.len();
            envelopes.push(bytes);
        }
        (envelopes, dropped)
    }

    fn on_diff(
        &mut self,
        diff: &DiffMessage,
        provider: &dyn StateProvider,
        source_peer: Option<&str>,
    ) -> ReplicationOutcome {
        if diff.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        let (envelopes, dropped) = self.pack_bounded_deliver(&diff.want, provider);
        // CIRISEdge#429 — an advertised want we cannot serve must NEVER be inferred
        // from a short byte count. Say so, per-miss and in aggregate. NOT fatal: the
        // round still ships what it could, and the remainder re-diffs next round —
        // but the responder KNOWS it shipped short, so it says so.
        if !dropped.is_empty() {
            let peer = source_peer.unwrap_or("<unattributed>");
            for h in &dropped {
                tracing::warn!(
                    kind = ?self.kind,
                    envelope_hash = %hex::encode(h),
                    peer,
                    "Deliver packing: advertised want is unfetchable — skipped \
                     (#429 advertised-then-unfetchable: stale wire-index / pruned row / hash skew)"
                );
            }
            tracing::warn!(
                kind = ?self.kind,
                wanted = diff.want.len(),
                packed = envelopes.len(),
                dropped = dropped.len(),
                peer,
                "Deliver ships short — the requester's want was only partially served (#429)"
            );
        }
        ReplicationOutcome::Send(vec![ReplicationMessage::Deliver(DeliverMessage {
            kind: self.kind,
            envelopes,
        })])
    }

    fn on_fetch(
        &mut self,
        fetch: &FetchMessage,
        provider: &dyn StateProvider,
        source_peer: Option<&str>,
    ) -> ReplicationOutcome {
        // Fetch is structurally identical to Diff on the responder
        // side — both ask "give me these specific envelopes."
        self.on_diff(
            &DiffMessage {
                kind: fetch.kind,
                want: fetch.want.clone(),
            },
            provider,
            source_peer,
        )
    }

    // CIRISEdge#552 pushed this past the 100-line bound. One scenario — decide
    // retention, then admit — and splitting it would put the hash-first decision
    // in a different function from the apply it guards, which is the coupling
    // worth keeping visible.
    #[allow(clippy::too_many_lines)]
    fn on_deliver(
        &mut self,
        deliver: &DeliverMessage,
        // CIRISEdge#552 — the retention decision lives on the provider, and the
        // apply path needs it: clearing `want` stops us ASKING, and stops
        // nothing from arriving.
        provider: &dyn StateProvider,
        applier: &dyn StateApplier,
        source_peer: Option<&str>,
    ) -> ReplicationOutcome {
        if deliver.kind != self.kind {
            return ReplicationOutcome::UnexpectedMessage;
        }
        // ── CIRISEdge#552: an UNSOLICITED body does not backfill the corpus ──
        //
        // Hash-first empties `want`, so under it this session asks for nothing —
        // which means any Deliver reaching here was not invited by an
        // anti-entropy round. A `#927` proactive publish would otherwise hand the
        // node exactly the bodies it declined to fetch, and the corpus-size and
        // address-book properties would be lost to a peer's generosity rather
        // than to any decision of ours.
        //
        // Keyed on `diff_want_count` — the SOLICITED marker the session already
        // keeps — so an explicit on-demand fetch still applies normally. That is
        // the whole point of hash-first: fetch when something needs the body.
        //
        // `retention_for` keeps the carve-out: a retracting plane is never
        // HashFirst, so a pushed revocation still applies. This deliberately
        // gates the ADMIT, where #544's suppression deliberately does not — the
        // reasons differ. Suppression is about a row we tried and could not
        // admit; hash-first is about a body we chose not to store, and applying
        // it anyway would defeat the choice.
        if self.diff_want_count.is_none()
            && retention_for(self.kind, provider.retention(self.kind)) == Retention::HashFirst
        {
            let learned: Vec<[u8; 32]> = deliver
                .envelopes
                .iter()
                .map(|bytes| {
                    use sha2::{Digest as _, Sha256};
                    let h: [u8; 32] = Sha256::digest(bytes).into();
                    h
                })
                .collect();
            provider.note_known_hashes(self.kind, &learned, source_peer);
            tracing::debug!(
                kind = ?self.kind,
                count = learned.len(),
                peer = ?source_peer,
                "hash-first: an unsolicited Deliver was LEARNED, not applied — \
                 a proactive push must not backfill a corpus this node declined \
                 to fetch (CIRISEdge#552)"
            );
            // `admitted: 0, refused: 0` is the honest pair: nothing was admitted,
            // and nothing was REFUSED either — the bodies were declined, not
            // rejected. The learn is not lost: it is in the known set and in this
            // log line, which is where a "why did my push not land" question gets
            // answered.
            return ReplicationOutcome::Applied {
                kind: self.kind,
                admitted: 0,
                refused: 0,
                staleness: StalenessSignal::InSync,
            };
        }
        // CIRISEdge#426 — distinguish a SOLICITED Deliver (it answers a `Diff` we
        // sent this round — `diff_want_count` is set) from an UNSOLICITED one (a
        // bare push with no in-flight round we invited — the #927 proactive-publish
        // shape AND the Sybil-injection shape). The session used to dispatch on TYPE
        // only and could not tell them apart. We do NOT hard-refuse unsolicited
        // here: #927 legitimately pushes unsolicited bootstrap rows, and the actual
        // Sybil-write vectors are closed by persist v22's put-gates + AV-76 per-peer
        // quota. Instead we make the phase + peer VISIBLE (a bare unsolicited push on
        // a non-bootstrap plane from a peer is the row to watch), and the threaded
        // `source_peer` lets the applier/persist make the per-peer call.
        // CIRISEdge#474 — a cursor round's Deliver answers the `CursorPull` this
        // Initiator sent (no `Diff` phase exists for the index-less accord plane),
        // so `awaiting_cursor_deliver` marks it solicited exactly as `diff_want_count`
        // does for the content-hash planes.
        let solicited = self.diff_want_count.is_some() || self.awaiting_cursor_deliver;
        if !solicited && !deliver.envelopes.is_empty() {
            // CIRISEdge#402/#406 — the bootstrap classification is the SINGLE
            // predicate `EnvelopeKind::is_bootstrap` (ALL-pinned in protocol.rs),
            // never an inline kind list: the local list this replaces had already
            // drifted (it omitted TransportDestination, so a #927 proactive push
            // of the peer's own transport binding was mislabeled a WARN-class
            // unsolicited write). Source-asserted through this call site in
            // `the_unsolicited_deliver_classification_reads_is_bootstrap`.
            let bootstrap_plane = self.kind.is_bootstrap();
            if bootstrap_plane {
                tracing::debug!(
                    kind = ?self.kind,
                    source_peer = source_peer.unwrap_or("<unattributed>"),
                    envelopes = deliver.envelopes.len(),
                    "unsolicited Deliver on a BOOTSTRAP plane — admitted (peer/canonical \
                     seeding; #927 proactive push) (CIRISEdge#426)"
                );
            } else {
                tracing::warn!(
                    kind = ?self.kind,
                    source_peer = source_peer.unwrap_or("<unattributed>"),
                    envelopes = deliver.envelopes.len(),
                    "UNSOLICITED Deliver on a non-bootstrap plane (no in-flight round) — \
                     admitted subject to persist v22 put-gates + AV-76 per-peer quota; the \
                     per-peer receive decision is now expressible via source_peer \
                     (CIRISEdge#426)"
                );
            }
        }
        let mut admitted = 0usize;
        let mut refused = 0usize;
        // CIRISEdge#425 — THE single apply choke point. Every delivered envelope's
        // outcome is counted AND, when it is not `Admitted`, logged with its reason
        // right here. Because `apply_envelope` now yields a `#[must_use]`
        // `ApplyOutcome`, an `apply_*` branch that wanted to `return false` silently
        // cannot — it must produce a reason this loop surfaces. A refusal that
        // withholds carriage can therefore never again read as absence of work; the
        // `refused` count in the `RoundReport` always has a matching WARN saying WHY.
        for env_bytes in &deliver.envelopes {
            match applier.apply_envelope(self.kind, env_bytes, source_peer) {
                ApplyOutcome::Admitted => admitted += 1,
                // Routine non-progress (a re-delivered held row) — quiet by design;
                // WARN-ing every duplicate would drown the genuine refusals.
                ApplyOutcome::Duplicate => {
                    refused += 1;
                    tracing::debug!(
                        kind = ?self.kind,
                        "delivered envelope was a duplicate the node already held (CIRISEdge#425)"
                    );
                }
                // A gate REFUSED a well-formed envelope — the darkens-carriage class.
                // CIRISEdge#544 — the line now carries the RETRY disposition, so a
                // reader can tell "this converges once more state lands" from "this
                // will be refused identically forever" without knowing which persist
                // token maps to which. It is a stable token, never prose.
                ApplyOutcome::Refused { reason, retry } => {
                    refused += 1;
                    tracing::warn!(
                        kind = ?self.kind,
                        reason = %reason,
                        retry = retry.as_str(),
                        "delivered envelope REFUSED — not applied (CIRISEdge#425 apply choke point)"
                    );
                }
                ApplyOutcome::Deserialize(err) => {
                    refused += 1;
                    tracing::warn!(
                        kind = ?self.kind,
                        error = %err,
                        // Terminal by nature: the wire identity is the content hash,
                        // so re-fetching it returns bytes that fail to parse the same
                        // way (CIRISEdge#544).
                        retry = crate::replication::refusal_backoff::RetryDisposition::Terminal
                            .as_str(),
                        "delivered envelope failed to DESERIALIZE — dropped, not applied \
                         (CIRISEdge#425 apply choke point)"
                    );
                }
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
    /// admitting. CIRISEdge#370 — records behind interior mutability
    /// (`std::sync::Mutex`) since `apply_envelope` is now `&self`.
    struct TestApplier {
        admitted: std::sync::Mutex<Vec<Vec<u8>>>,
        local_state: std::sync::Mutex<LocalState>,
        hash_lookup: HashMap<Vec<u8>, [u8; 32]>,
    }

    impl TestApplier {
        fn admitted_count(&self) -> usize {
            self.admitted.lock().unwrap().len()
        }
    }

    impl StateApplier for TestApplier {
        fn apply_envelope(
            &self,
            kind: EnvelopeKind,
            bytes: &[u8],
            _source_peer: Option<&str>,
        ) -> ApplyOutcome {
            // In production: verify sig + recompute hash. Here we
            // look up the precomputed hash for these bytes.
            if let Some(hash) = self.hash_lookup.get(bytes).copied() {
                let mut local_state = self.local_state.lock().unwrap();
                let kind_set = local_state.by_kind.entry(kind).or_default();
                if kind_set.contains_key(&hash) {
                    return ApplyOutcome::Duplicate;
                }
                kind_set.insert(hash, 1);
                self.admitted.lock().unwrap().push(bytes.to_vec());
                ApplyOutcome::Admitted
            } else {
                ApplyOutcome::refused("unknown bytes (test fixture)")
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
            admitted: std::sync::Mutex::new(Vec::new()),
            local_state: std::sync::Mutex::new(LocalState::new()),
            hash_lookup,
        }
    }

    /// CIRISEdge#474 — a provider that answers an accord cursor pull with canned
    /// serialized bundles (the bytes the apply path would `from_slice`). Every
    /// content-hash method is empty: the cursor plane never advertises refs.
    struct CursorProvider {
        bundles: Vec<Vec<u8>>,
    }
    impl StateProvider for CursorProvider {
        fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
            Vec::new()
        }
        fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
        fn accord_evidence_since(
            &self,
            _kind: EnvelopeKind,
            _since: Option<chrono::DateTime<chrono::Utc>>,
        ) -> Vec<Vec<u8>> {
            self.bundles.clone()
        }
    }

    /// CIRISEdge#474 — an Initiator round for the cursor plane opens with a
    /// `CursorPull` (`since: None`), NEVER a Summary: the plane has no content-hash
    /// index, so the Summary/Diff/Fetch flow does not apply to it.
    #[test]
    fn cursor_round_initiator_opens_with_cursor_pull_not_summary() {
        let provider = CursorProvider { bundles: vec![] };
        let mut init = Session::new(SessionRole::Initiator, EnvelopeKind::AccordQuorumEvidence);
        match init.start_round(&provider) {
            ReplicationOutcome::Send(msgs) => {
                assert_eq!(msgs.len(), 1, "one CursorPull, no Summary");
                match &msgs[0] {
                    ReplicationMessage::CursorPull(cp) => {
                        assert_eq!(cp.kind, EnvelopeKind::AccordQuorumEvidence);
                        assert!(cp.since.is_none(), "stateless pull-all (#474)");
                    }
                    other => panic!("expected CursorPull, got {other:?}"),
                }
            }
            other => panic!("expected Send, got {other:?}"),
        }
    }

    /// CIRISEdge#474 — a Responder answers a `CursorPull` DIRECTLY with a `Deliver`
    /// of the provider's bundles (no Summary/Diff round-trip for an index-less plane).
    #[test]
    fn cursor_round_responder_serves_bundles_as_a_deliver() {
        let b1 = b"{\"proposal\":1}".to_vec();
        let b2 = b"{\"proposal\":2}".to_vec();
        let provider = CursorProvider {
            bundles: vec![b1.clone(), b2.clone()],
        };
        let applier = applier_for(&[]);
        let mut resp = Session::new(SessionRole::Responder, EnvelopeKind::AccordQuorumEvidence);
        let pull = ReplicationMessage::CursorPull(CursorPullMessage {
            kind: EnvelopeKind::AccordQuorumEvidence,
            since: None,
        });
        match resp.on_message(pull, &provider, &applier, Some("peer")) {
            ReplicationOutcome::Send(msgs) => {
                assert_eq!(msgs.len(), 1);
                match &msgs[0] {
                    ReplicationMessage::Deliver(d) => {
                        assert_eq!(d.kind, EnvelopeKind::AccordQuorumEvidence);
                        assert_eq!(
                            d.envelopes,
                            vec![b1, b2],
                            "serves the cursor bytes verbatim"
                        );
                    }
                    other => panic!("expected Deliver, got {other:?}"),
                }
            }
            other => panic!("expected Send, got {other:?}"),
        }
    }

    /// CIRISEdge#474 — the full 2-message exchange: Initiator CursorPull → Deliver
    /// → the Initiator applies the delivered bundles (solicited via
    /// `awaiting_cursor_deliver`) and completes.
    #[test]
    fn cursor_round_initiator_applies_delivered_bundles_and_completes() {
        let b1 = b"{\"proposal\":\"a\"}".to_vec();
        let h1 = h(7);
        let provider = CursorProvider {
            bundles: vec![b1.clone()],
        };
        let applier = applier_for(&[(h1, b1.clone())]);
        let mut init = Session::new(SessionRole::Initiator, EnvelopeKind::AccordQuorumEvidence);
        let ReplicationOutcome::Send(open) = init.start_round(&provider) else {
            panic!("expected Send")
        };
        assert!(matches!(open[0], ReplicationMessage::CursorPull(_)));
        let deliver = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::AccordQuorumEvidence,
            envelopes: vec![b1],
        });
        match init.on_message(deliver, &provider, &applier, Some("peer")) {
            ReplicationOutcome::Applied { admitted, .. } => assert_eq!(admitted, 1),
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(applier.admitted_count(), 1);
        assert!(
            init.is_complete(),
            "the cursor round completes after the Deliver"
        );
    }

    /// CIRISEdge#474 — an evidence-free peer answers with an EMPTY Deliver; the
    /// Initiator's round still completes cleanly (no timeout, no unsolicited WARN —
    /// the reply is solicited via `awaiting_cursor_deliver`).
    #[test]
    fn empty_cursor_pull_completes_the_round() {
        let provider = CursorProvider { bundles: vec![] };
        let applier = applier_for(&[]);
        let mut init = Session::new(SessionRole::Initiator, EnvelopeKind::AccordQuorumEvidence);
        let _ = init.start_round(&provider);
        assert!(!init.is_complete());
        let empty = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::AccordQuorumEvidence,
            envelopes: vec![],
        });
        match init.on_message(empty, &provider, &applier, Some("peer")) {
            ReplicationOutcome::Applied {
                admitted, refused, ..
            } => {
                assert_eq!(admitted, 0);
                assert_eq!(refused, 0);
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert!(init.is_complete(), "an empty cursor round still completes");
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
        let a_applier = applier_for(&[(h(3), b"env_3".to_vec()), (h(4), b"env_4".to_vec())]);
        let b_applier = applier_for(&[(h(1), b"env_1".to_vec()), (h(2), b"env_2".to_vec())]);

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
        let bob_step1 = bob.on_message(alice_summary, &b_provider, &b_applier, None);
        let (bob_summary, bob_diff) = match bob_step1 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 2);
                (msgs[0].clone(), msgs[1].clone())
            }
            _ => panic!("expected Send"),
        };

        // 3. Alice receives Bob's Summary → emits Diff. (Then
        //    receives Bob's Diff → emits Deliver.)
        let alice_step2 = alice.on_message(bob_summary, &a_provider, &a_applier, None);
        let alice_diff = match alice_step2 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 4. Bob receives Alice's Diff → emits Deliver(env_1, env_2).
        let bob_step2 = bob.on_message(alice_diff, &b_provider, &b_applier, None);
        let bob_deliver = match bob_step2 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 5. Alice receives Bob's Diff → emits Deliver(env_3, env_4).
        let alice_step3 = alice.on_message(bob_diff, &a_provider, &a_applier, None);
        let alice_deliver = match alice_step3 {
            ReplicationOutcome::Send(ref msgs) => {
                assert_eq!(msgs.len(), 1);
                msgs[0].clone()
            }
            _ => panic!("expected Send"),
        };

        // 6. Alice applies Bob's Deliver → admitted env_3 + env_4.
        let alice_final = alice.on_message(bob_deliver, &a_provider, &a_applier, None);
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
        let bob_final = bob.on_message(alice_deliver, &b_provider, &b_applier, None);
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
        assert_eq!(a_applier.admitted_count(), 2);
        assert_eq!(b_applier.admitted_count(), 2);
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
        let a_applier = applier_for(&[(h(4), b"e4".to_vec())]);
        let b_applier = applier_for(&[(h(1), b"e1".to_vec())]);

        let mut alice = Session::new(SessionRole::Initiator, EnvelopeKind::Attestation);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);

        // Mechanical round-drive (same as full_sync above).
        let m_alice_summary = match alice.start_round(&a_provider) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let (m_bob_summary, m_bob_diff) =
            match bob.on_message(m_alice_summary, &b_provider, &b_applier, None) {
                ReplicationOutcome::Send(m) => (m[0].clone(), m[1].clone()),
                _ => panic!(),
            };
        let m_alice_diff = match alice.on_message(m_bob_summary, &a_provider, &a_applier, None) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let m_bob_deliver = match bob.on_message(m_alice_diff, &b_provider, &b_applier, None) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let m_alice_deliver = match alice.on_message(m_bob_diff, &a_provider, &a_applier, None) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        match alice.on_message(m_bob_deliver, &a_provider, &a_applier, None) {
            ReplicationOutcome::Applied { admitted, .. } => assert_eq!(admitted, 1),
            o => panic!("unexpected: {o:?}"),
        }
        match bob.on_message(m_alice_deliver, &b_provider, &b_applier, None) {
            ReplicationOutcome::Applied { admitted, .. } => assert_eq!(admitted, 1),
            o => panic!("unexpected: {o:?}"),
        }
    }

    /// CIRISEdge#414 — the RECEIVE axis is computed from the node's real
    /// HOLDINGS, not its (send-gated) OFFER. A responder that holds `infra:serve`
    /// but has NO consent to SEND to the initiator advertises nothing (its offer
    /// is empty), yet must still service the round — requesting exactly the rows
    /// it LACKS. Before the split, `want` was computed from the empty offer, which
    /// fused the #396 send gate onto the receive side and darkened the plane.
    #[test]
    fn receive_uses_holdings_not_the_send_gated_offer() {
        // A provider whose OFFER (local_refs) is empty — the responder has no
        // consent to SEND to this peer — but whose real HOLDINGS (local_holdings)
        // contain {A}. The initiator offers {A, B}.
        struct SplitProvider {
            holdings: Vec<super::super::protocol::EnvelopeRef>,
        }
        impl StateProvider for SplitProvider {
            fn local_refs(&self, _kind: EnvelopeKind) -> Vec<super::super::protocol::EnvelopeRef> {
                Vec::new() // send-gated: this node offers NOTHING to the peer
            }
            fn local_holdings(
                &self,
                _kind: EnvelopeKind,
            ) -> Vec<super::super::protocol::EnvelopeRef> {
                self.holdings.clone() // the node's REAL state, peer-blind
            }
            fn fetch_envelope(&self, _k: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
                None
            }
        }
        let provider = SplitProvider {
            holdings: vec![EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            }],
        };
        let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let applier = applier_for(&[]);

        let remote_summary = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Attestation,
            refs: vec![
                EnvelopeRef {
                    envelope_hash: h(1),
                    seq: 1,
                },
                EnvelopeRef {
                    envelope_hash: h(2),
                    seq: 2,
                },
            ],
        });
        let out = match responder.on_message(remote_summary, &provider, &applier, None) {
            ReplicationOutcome::Send(m) => m,
            o => panic!("unexpected: {o:?}"),
        };
        // Outbound = [Summary(EMPTY — the send-gated offer), Diff(want)].
        let (summary, diff) = (out[0].clone(), out[1].clone());
        match summary {
            ReplicationMessage::Summary(s) => assert!(
                s.refs.is_empty(),
                "the responder's OFFER must stay send-gated-empty (#396) even while it receives"
            ),
            o => panic!("expected Summary first: {o:?}"),
        }
        match diff {
            ReplicationMessage::Diff(d) => assert_eq!(
                d.want,
                vec![h(2)],
                "want must be remote ∖ HOLDINGS = only the lacked row {{B}}, NOT all of \
                 remote (which the pre-#414 empty-offer diff would have produced)"
            ),
            o => panic!("expected Diff: {o:?}"),
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
        let a_applier = applier_for(&[]);
        let b_applier = applier_for(&[]);

        let mut alice = Session::new(SessionRole::Initiator, EnvelopeKind::Key);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Key);

        // Drive round.
        let alice_summary = match alice.start_round(&a_provider) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        let (bob_summary_resp, bob_diff_msg) =
            match bob.on_message(alice_summary, &b_provider, &b_applier, None) {
                ReplicationOutcome::Send(m) => (m[0].clone(), m[1].clone()),
                _ => panic!(),
            };
        let alice_diff_msg = match alice.on_message(bob_summary_resp, &a_provider, &a_applier, None)
        {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        // Bob's Deliver from Alice's Diff should be empty (Alice has
        // everything Bob has).
        let bob_deliver_msg = match bob.on_message(alice_diff_msg, &b_provider, &b_applier, None) {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        if let ReplicationMessage::Deliver(d) = &bob_deliver_msg {
            assert!(d.envelopes.is_empty(), "bob should deliver nothing");
        }
        // Same for Alice's Deliver from Bob's Diff.
        let alice_deliver_msg = match alice.on_message(bob_diff_msg, &a_provider, &a_applier, None)
        {
            ReplicationOutcome::Send(m) => m[0].clone(),
            _ => panic!(),
        };
        if let ReplicationMessage::Deliver(d) = &alice_deliver_msg {
            assert!(d.envelopes.is_empty(), "alice should deliver nothing");
        }
        // Applied with 0 admitted, InSync staleness.
        match alice.on_message(bob_deliver_msg, &a_provider, &a_applier, None) {
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
        let applier = applier_for(&[]);
        let mut s = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        let r = s.on_message(
            ReplicationMessage::Diff(DiffMessage {
                kind: EnvelopeKind::Revocation, // ← wrong kind for this session
                want: vec![],
            }),
            &provider,
            &applier,
            None,
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
        let applier = applier_for(&[(h(1), b"pushed-key".to_vec())]);
        let mut bob = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        // No Summary, no Diff — the initiator just pushes its key envelope.
        let r = bob.on_message(
            ReplicationMessage::Deliver(DeliverMessage {
                kind: EnvelopeKind::Key,
                envelopes: vec![b"pushed-key".to_vec()],
            }),
            &provider,
            &applier,
            None,
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
        let applier = applier_for(&[]);
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
            &applier,
            None,
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
        let applier = applier_for(&[]);
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
            &applier,
            None,
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
        let applier = applier_for(&[]);
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
            &applier,
            None,
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
        let applier = applier_for(&[]);
        let mut s = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let r = s.on_message(
            ReplicationMessage::Fetch(FetchMessage {
                kind: EnvelopeKind::Attestation,
                want: vec![h(1), h(99)], // h(99) doesn't exist
            }),
            &provider,
            &applier,
            None,
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
        let a_applier = applier_for(&[(h(1), b"e1".to_vec())]);
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
        let _ = alice.on_message(bob_summary, &a_provider, &a_applier, None);
        let bob_deliver = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Key,
            envelopes: vec![
                b"e1".to_vec(),         // known, applies
                b"unknown_e2".to_vec(), // applier doesn't know → refuse
                b"unknown_e3".to_vec(),
            ],
        });
        match alice.on_message(bob_deliver, &a_provider, &a_applier, None) {
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

    /// CIRISEdge#425 — the apply CHOKE POINT. A stub applier returns a NAMED
    /// `Refused` for every envelope; `on_deliver` must count them ALL as `refused`
    /// (never silently reduce `admitted`) — the reason is what it logs. The
    /// compiler already forbids a silent `return false` (`ApplyOutcome` is
    /// `#[must_use]` with no `bool`); this locks the counting half so a refusal can
    /// never again read as absence of work.
    #[test]
    fn on_deliver_counts_every_refusal_at_the_choke_point() {
        struct RefusingApplier;
        impl StateApplier for RefusingApplier {
            fn apply_envelope(
                &self,
                _k: EnvelopeKind,
                _b: &[u8],
                _source_peer: Option<&str>,
            ) -> ApplyOutcome {
                ApplyOutcome::refused("gate refused this row")
            }
        }
        let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let deliver = DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()],
        };
        match responder.on_deliver(&deliver, &BodiesProvider, &RefusingApplier, Some("peer-x")) {
            ReplicationOutcome::Applied {
                admitted, refused, ..
            } => {
                assert_eq!(admitted, 0, "nothing admitted");
                assert_eq!(refused, 3, "every refused envelope is counted, not dropped");
            }
            o => panic!("expected Applied, got {o:?}"),
        }
    }

    /// CIRISEdge#544 — the re-offer loop is RECEIVER-PULLED, and this is the
    /// pull. A peer advertises two rows the node lacks; the node has already
    /// refused one of them, so its Diff asks for the OTHER one only. Nothing is
    /// sent to the peer to make this happen — the sender was never the one
    /// CIRISEdge#552 — under hash-first retention the round LEARNS the peer's
    /// hashes and asks for no bodies.
    ///
    /// This is the whole mechanism: the node still computes what it lacks (so it
    /// knows the record exists and who has it) but does not pull the corpus.
    #[test]
    fn hash_first_learns_the_hashes_and_asks_for_no_bodies() {
        use std::sync::Mutex;
        struct HashFirstProvider {
            noted: Mutex<Vec<[u8; 32]>>,
            peer: Mutex<Option<String>>,
        }
        impl StateProvider for HashFirstProvider {
            fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
                Vec::new()
            }
            fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
                None
            }
            fn retention(&self, _kind: EnvelopeKind) -> crate::replication::retention::Retention {
                crate::replication::retention::Retention::HashFirst
            }
            fn note_known_hashes(
                &self,
                _kind: EnvelopeKind,
                hashes: &[[u8; 32]],
                peer: Option<&str>,
            ) {
                self.noted.lock().unwrap().extend_from_slice(hashes);
                *self.peer.lock().unwrap() = peer.map(str::to_owned);
            }
        }

        let provider = HashFirstProvider {
            noted: Mutex::new(Vec::new()),
            peer: Mutex::new(None),
        };
        // Key, not Attestation: the Attestation plane carries `withdraws`
        // tombstones and is pinned to Bodies (CIRISEdge#553). Key is an identity
        // plane that cannot retract anything, which is what hash-first is for.
        let mut session = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        let remote = SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![
                EnvelopeRef {
                    envelope_hash: h(1),
                    seq: 1,
                },
                EnvelopeRef {
                    envelope_hash: h(2),
                    seq: 2,
                },
            ],
        };
        let ReplicationOutcome::Send(msgs) = session.on_message(
            ReplicationMessage::Summary(remote),
            &provider,
            &NoApply,
            Some("peer-a"),
        ) else {
            panic!("a summary must produce a round");
        };

        let diff = msgs
            .iter()
            .find_map(|m| match m {
                ReplicationMessage::Diff(d) => Some(d),
                _ => None,
            })
            .expect("the round still sends a Diff");
        assert!(
            diff.want.is_empty(),
            "hash-first asks for NO bodies — got {} wanted",
            diff.want.len()
        );
        assert_eq!(
            provider.noted.lock().unwrap().len(),
            2,
            "both advertised hashes must be LEARNED, or the node cannot later \
             discover the record exists"
        );
        assert_eq!(
            provider.peer.lock().unwrap().as_deref(),
            Some("peer-a"),
            "the advertising peer is the holder to ask — without it the node \
             knows a record exists but not who has it"
        );
    }

    /// CIRISEdge#553 — the carve-out reaches the round, not just the pure
    /// function. A node configured hash-first STILL pulls revocation bodies.
    #[test]
    fn a_hash_first_node_still_pulls_revocation_bodies() {
        struct HashFirstEverywhere;
        impl StateProvider for HashFirstEverywhere {
            fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
                Vec::new()
            }
            fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
                None
            }
            fn retention(&self, _kind: EnvelopeKind) -> crate::replication::retention::Retention {
                crate::replication::retention::Retention::HashFirst
            }
        }

        let mut session = Session::new(SessionRole::Responder, EnvelopeKind::Revocation);
        let remote = SummaryMessage {
            kind: EnvelopeKind::Revocation,
            refs: vec![EnvelopeRef {
                envelope_hash: h(1),
                seq: 1,
            }],
        };
        let ReplicationOutcome::Send(msgs) = session.on_message(
            ReplicationMessage::Summary(remote),
            &HashFirstEverywhere,
            &NoApply,
            Some("peer-a"),
        ) else {
            panic!("a summary must produce a round");
        };

        let diff = msgs
            .iter()
            .find_map(|m| match m {
                ReplicationMessage::Diff(d) => Some(d),
                _ => None,
            })
            .expect("the round still sends a Diff");
        assert_eq!(
            diff.want,
            vec![h(1)],
            "a node holding the HASH of a revocation has not applied it — the \
             body must still be asked for (CIRISEdge#553)"
        );
    }

    /// choosing, which is why the fix needs no wire change.
    #[test]
    fn the_rounds_want_omits_hashes_this_node_has_already_refused() {
        /// A provider holding nothing, that has refused exactly `refused`.
        struct SuppressingProvider {
            refused: [u8; 32],
        }
        impl StateProvider for SuppressingProvider {
            fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
                Vec::new()
            }
            fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
                None
            }
            fn retry_suppressed(&self, _kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> bool {
                *envelope_hash == self.refused
            }
        }

        let provider = SuppressingProvider { refused: h(1) };
        let mut session = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        // The peer advertises BOTH rows — including the one we cannot admit. It
        // has no way to know, and does not need one.
        let remote = SummaryMessage {
            kind: EnvelopeKind::Key,
            refs: vec![
                EnvelopeRef {
                    envelope_hash: h(1),
                    seq: 1,
                },
                EnvelopeRef {
                    envelope_hash: h(2),
                    seq: 2,
                },
            ],
        };
        let ReplicationOutcome::Send(msgs) = session.on_message(
            ReplicationMessage::Summary(remote),
            &provider,
            &NoApply,
            None,
        ) else {
            panic!("a Summary must produce Summary+Diff");
        };
        let diff = msgs
            .iter()
            .find_map(|m| match m {
                ReplicationMessage::Diff(d) => Some(d),
                _ => None,
            })
            .expect("the responder answers with a Diff");
        assert_eq!(
            diff.want,
            vec![h(2)],
            "the refused hash must not be re-requested; without this the row is \
             in `want` every round forever (55 re-offers in 30 min, CIRISEdge#544)"
        );
        assert_eq!(
            session.diff_want_count,
            Some(1),
            "staleness must be computed from what we ACTUALLY asked for, or a \
             suppressed row reads as permanently-missing progress"
        );
    }

    /// A provider with default retention (`Bodies`), for deliver-side tests
    /// that are not about retention at all.
    struct BodiesProvider;
    impl StateProvider for BodiesProvider {
        fn local_refs(&self, _kind: EnvelopeKind) -> Vec<EnvelopeRef> {
            Vec::new()
        }
        fn fetch_envelope(&self, _kind: EnvelopeKind, _h: &[u8; 32]) -> Option<Vec<u8>> {
            None
        }
    }

    /// An applier for want-side tests, which never see a Deliver.
    struct NoApply;
    impl StateApplier for NoApply {
        fn apply_envelope(
            &self,
            _k: EnvelopeKind,
            _b: &[u8],
            _source_peer: Option<&str>,
        ) -> ApplyOutcome {
            ApplyOutcome::refused("no envelope should reach this applier")
        }
    }

    /// CIRISEdge#426 — the authenticated sender must REACH the applier so a
    /// per-peer RECEIVE decision is expressible (it was dropped before the apply
    /// path, which made the consent plane send-only — an admitted peer could write
    /// with no per-peer check because the identity was gone). A recording applier
    /// captures what `on_deliver` hands it: every applied envelope carries the peer.
    #[test]
    fn on_deliver_threads_source_peer_to_the_applier() {
        struct PeerRecordingApplier {
            // CIRISEdge#370 — interior mutability: `apply_envelope` is `&self`.
            seen: std::sync::Mutex<Vec<Option<String>>>,
        }
        impl StateApplier for PeerRecordingApplier {
            fn apply_envelope(
                &self,
                _k: EnvelopeKind,
                _b: &[u8],
                source_peer: Option<&str>,
            ) -> ApplyOutcome {
                self.seen
                    .lock()
                    .unwrap()
                    .push(source_peer.map(str::to_owned));
                ApplyOutcome::Admitted
            }
        }
        let applier = PeerRecordingApplier {
            seen: std::sync::Mutex::new(Vec::new()),
        };
        let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let deliver = DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: vec![b"x".to_vec(), b"y".to_vec()],
        };
        responder.on_deliver(&deliver, &BodiesProvider, &applier, Some("canonical-1"));
        assert_eq!(
            *applier.seen.lock().unwrap(),
            vec![
                Some("canonical-1".to_string()),
                Some("canonical-1".to_string())
            ],
            "each applied envelope carries the authenticated source peer (CIRISEdge#426)"
        );
    }

    /// CIRISEdge#414/#932 — `on_diff` packs a byte-BOUNDED prefix of the wanted
    /// envelopes into one Deliver, never the whole (unbounded-in-holdings) set. The
    /// undelivered remainder stays in the peer's `want` and is carried by the next
    /// round's re-diff. This bounds the per-round wire frame so its fragment count
    /// stays reassemblable under packet loss — the belt to the transport
    /// fragmenter's suspenders.
    #[test]
    fn on_diff_bounds_the_deliver_by_byte_budget() {
        // Eight 100 KiB envelopes = 800 KiB wanted, well over the 512 KiB budget.
        let env_size = 100 * 1024;
        let n = 8u8;
        let mut entries = Vec::new();
        let mut wanted = Vec::new();
        for i in 0..n {
            let hash = h(i + 1);
            entries.push((
                EnvelopeKind::Attestation,
                hash,
                vec![i; env_size],
                u64::from(i) + 1,
            ));
            wanted.push(hash);
        }
        let provider = provider_with(&entries);
        let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let diff = DiffMessage {
            kind: EnvelopeKind::Attestation,
            want: wanted,
        };
        let ReplicationOutcome::Send(msgs) = responder.on_diff(&diff, &provider, None) else {
            panic!("on_diff must Send a Deliver");
        };
        let ReplicationMessage::Deliver(deliver) = &msgs[0] else {
            panic!("expected a Deliver, got {:?}", msgs[0]);
        };
        let packed: usize = deliver.envelopes.iter().map(Vec::len).sum();
        // The budget cut the set — NOT the whole 800 KiB in one frame.
        assert!(
            deliver.envelopes.len() < usize::from(n),
            "budget must cut the set: packed {} of {n}",
            deliver.envelopes.len()
        );
        assert!(
            !deliver.envelopes.is_empty(),
            "a Deliver always carries ≥1 envelope"
        );
        // Exactly five 100 KiB envelopes fit (5 × 100 = 500 KiB < 512 KiB; the 6th
        // would cross), and the packed total never exceeds the budget.
        assert_eq!(
            deliver.envelopes.len(),
            5,
            "five 100 KiB envelopes fit under the 512 KiB budget; the 6th would exceed"
        );
        assert!(
            packed <= MAX_DELIVER_ENVELOPE_BYTES,
            "packed {packed} exceeds the budget {MAX_DELIVER_ENVELOPE_BYTES}"
        );
    }

    /// The always-≥1 rule: a SINGLE envelope larger than the whole budget still
    /// ships whole (the transport fragments it) — the budget bounds how many whole
    /// envelopes ride together, never splits one.
    #[test]
    fn on_diff_ships_a_single_oversize_envelope_whole() {
        let big = MAX_DELIVER_ENVELOPE_BYTES + 4096;
        let hash = h(42);
        let provider = provider_with(&[(EnvelopeKind::Attestation, hash, vec![7u8; big], 1)]);
        let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let diff = DiffMessage {
            kind: EnvelopeKind::Attestation,
            want: vec![hash],
        };
        let ReplicationOutcome::Send(msgs) = responder.on_diff(&diff, &provider, None) else {
            panic!("on_diff must Send a Deliver");
        };
        let ReplicationMessage::Deliver(deliver) = &msgs[0] else {
            panic!("expected a Deliver");
        };
        assert_eq!(
            deliver.envelopes.len(),
            1,
            "the one oversize envelope ships whole"
        );
        assert_eq!(deliver.envelopes[0].len(), big);
    }

    /// CIRISEdge#429 — an advertised `want` the responder cannot fetch is NOT
    /// silently swallowed. `pack_bounded_deliver` RETURNS the unfetchable hash in
    /// its `dropped` set (so the caller logs it loud and this test asserts it
    /// directly — infer nothing from a byte count), and the round still ships what
    /// it COULD: short, not fatal. The send-side twin of #425's "never a silent
    /// drop" on the apply path.
    #[test]
    fn on_diff_surfaces_an_advertised_but_unfetchable_want() {
        let fetchable = h(1);
        let unfetchable = h(2); // deliberately never seeded into the provider
        let provider = provider_with(&[(EnvelopeKind::Attestation, fetchable, vec![9u8; 128], 1)]);
        let mut responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);

        // The helper RETURNS the unfetchable hash rather than vanishing it.
        let (envelopes, dropped) =
            responder.pack_bounded_deliver(&[fetchable, unfetchable], &provider);
        assert_eq!(
            dropped,
            vec![unfetchable],
            "the advertised-but-unfetchable want must be RETURNED, not swallowed"
        );
        assert_eq!(
            envelopes.len(),
            1,
            "the fetchable want still packs — the round ships short, never empty"
        );

        // And on_diff still Sends the (short) Deliver — a drop is loud, never fatal.
        let diff = DiffMessage {
            kind: EnvelopeKind::Attestation,
            want: vec![fetchable, unfetchable],
        };
        let ReplicationOutcome::Send(msgs) = responder.on_diff(&diff, &provider, Some("peer-x"))
        else {
            panic!("a partially-unfetchable Diff must still Send a short Deliver, not fail");
        };
        let ReplicationMessage::Deliver(deliver) = &msgs[0] else {
            panic!("expected a Deliver");
        };
        assert_eq!(
            deliver.envelopes.len(),
            1,
            "ships the one fetchable envelope; the unfetchable want re-diffs next round"
        );
    }

    /// The #429 loud path stays silent on the happy path: a fully-fetchable Diff
    /// records NO drops, so no false-positive "ships short" warn fires.
    #[test]
    fn on_diff_records_no_drop_when_every_want_is_fetchable() {
        let a = h(1);
        let b = h(2);
        let provider = provider_with(&[
            (EnvelopeKind::Attestation, a, vec![1u8; 64], 1),
            (EnvelopeKind::Attestation, b, vec![2u8; 64], 2),
        ]);
        let responder = Session::new(SessionRole::Responder, EnvelopeKind::Attestation);
        let (envelopes, dropped) = responder.pack_bounded_deliver(&[a, b], &provider);
        assert!(dropped.is_empty(), "no unfetchable want → no drop");
        assert_eq!(envelopes.len(), 2, "both fetchable wants pack");
    }

    /// `start_round` on a Responder is REFUSED release-safe (the old guard was
    /// a `debug_assert!` that compiled out of release builds): it returns the
    /// message-typed `UnexpectedMessage`, sends nothing, and leaves the
    /// session's round state untouched — a mis-scheduled `start_round` must
    /// not emit a bogus Summary-as-initiator nor complete anything.
    #[test]
    fn responder_start_round_is_refused_release_safe() {
        let provider = provider_with(&[(EnvelopeKind::Key, h(1), b"e1".to_vec(), 1)]);
        let mut s = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        assert_eq!(
            s.start_round(&provider),
            ReplicationOutcome::UnexpectedMessage,
            "a Responder never opens a round"
        );
        assert!(!s.is_complete(), "the refusal is not a state transition");
        // The session still services its real job afterwards: an inbound
        // Summary produces the ordinary {Summary, Diff} responder step.
        let applier = applier_for(&[]);
        let out = s.on_message(
            ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![],
            }),
            &provider,
            &applier,
            None,
        );
        assert!(
            matches!(out, ReplicationOutcome::Send(ref m) if m.len() == 2),
            "state untouched — the responder round proceeds normally, got {out:?}"
        );
    }

    /// The unsolicited-Deliver bootstrap classification reads
    /// `EnvelopeKind::is_bootstrap` THROUGH THE CALL SITE, never a local
    /// `matches!` (the family_gates.rs model: a source assertion through the
    /// call site so re-inlining the predicate reds the build). The inline list
    /// this locks out had ALREADY drifted once — it omitted
    /// TransportDestination, mislabeling #927 proactive pushes of the peer's
    /// own transport binding at WARN. The membership itself is ALL-pinned in
    /// protocol.rs (`is_bootstrap_is_exactly_the_three_bootstrap_kinds`); this
    /// pins the WIRING, which log-level-only behavior cannot observe.
    #[test]
    fn the_unsolicited_deliver_classification_reads_is_bootstrap() {
        let src = include_str!("session.rs");
        let start = src.find("fn on_deliver").expect("on_deliver exists");
        let end = src[start..]
            .find("pub fn is_complete")
            .expect("is_complete follows on_deliver");
        let body = &src[start..start + end];
        assert!(
            body.contains("let bootstrap_plane = self.kind.is_bootstrap();"),
            "on_deliver must classify via EnvelopeKind::is_bootstrap"
        );
        assert!(
            !body.contains("matches!"),
            "on_deliver must not re-inline a kind list — the inline matches! \
             drifted from is_bootstrap once already (TransportDestination)"
        );
    }
}
