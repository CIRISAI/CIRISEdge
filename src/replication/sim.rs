//! CIRISEdge#414/CIRISAgent#932 — deterministic simulation testing (DST) for the
//! anti-entropy protocol over a size-limited, adversarial transport.
//!
//! The FoundationDB / TigerBeetle lineage applied to edge replication: run the
//! REAL [`Session`] state machines over a single-threaded, seed-driven
//! [`SimWire`] whose fault model injects exactly the cheap-window faults that
//! stall a live mesh — a per-link **MDU** that DROPS any packet larger than it
//! (the #932 fault), packet **loss**, **reorder**, and **duplication** — and
//! assert the liveness + safety invariants across many seeds and payload sizes.
//!
//! The load-bearing methodological rule (learned the hard way in #932): the
//! oracle asserts the **RESPONDER** reaches a terminal applied state, never just
//! the initiator — an initiator completing tells you nothing about whether the
//! payload landed. [`Scenario::run`] returns [`Outcome`] with BOTH sides' applied
//! sets; [`Outcome::converged`] requires both.
//!
//! The transport carries WRAPPED wire frames and fragments them with the SAME
//! [`crate::transport::frame_fragment`] primitive production Reticulum uses, so a
//! green DST is evidence about the real fragmenter, not a mock. Toggling
//! [`SimFaults::fragment`] off reproduces the stall; on proves the fix.
//!
//! Two entry points: [`Scenario::run`] (one seeded scenario, ~µs) and the
//! `proptest`/soak tests below (the permanent CI gate + the high-volume search).

use crate::replication::protocol::{EnvelopeKind, EnvelopeRef};
use crate::replication::session::{ReplicationOutcome, Session, SessionRole};
use crate::replication::summary::{ApplyOutcome, StateApplier, StateProvider};
use crate::replication::{wire_frame, LocalState};
use crate::transport::frame_fragment::{self, fragment, Reassembler, RetransmitBuffer};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

/// CIRISEdge#422 — max fragment-ARQ recovery passes per anti-entropy round before
/// the round is abandoned to the whole-frame re-diff fallback. Each pass re-NAKs
/// whatever is still missing and the sender re-sends ONLY those; a lost NAK or
/// retransmit just costs a pass. Sized so a worst-corner frame (thousands of
/// fragments at 15 %+ loss) recovers IN-round with overwhelming margin — per-pass
/// per-fragment recovery is ~`(1-loss)²` ≈ 0.7, so the chance a fragment survives
/// this many passes un-recovered is ~0; the bound only guarantees termination, it
/// never bites a correct run.
const MAX_ARQ_PASSES: usize = 256;

/// Backstop on packets processed per round (a real stall shows as non-convergence,
/// not a hang). Raised from the pre-ARQ 100 000 because an ARQ round legitimately
/// processes (initial fragments + up to `MAX_ARQ_PASSES` × per-pass NAK/retransmit)
/// packets for a multi-thousand-fragment frame.
const MAX_ROUND_STEPS: usize = 5_000_000;

/// Render an 8-byte `msg_id` as hex for structured logs — CIRISEdge#422: every NAK
/// and retransmit names the frame it is about, so this class is greppable in a live
/// log, never a silent drop (honoring the #423–#429 silent-refusal arc).
fn hex8(id: [u8; 8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(16);
    for b in id {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A tiny deterministic PRNG (SplitMix64) — no external RNG, no clock, so a seed
/// reproduces a scenario bit-for-bit.
#[derive(Clone)]
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A probability check in [0, 1000): `prob` events per 1000.
    fn chance(&mut self, per_mille: u32) -> bool {
        (self.next_u64() % 1000) < u64::from(per_mille)
    }
    fn range(&mut self, lo: usize, hi: usize) -> usize {
        if hi <= lo {
            return lo;
        }
        let span = u64::try_from(hi - lo).unwrap_or(u64::MAX);
        lo + usize::try_from(self.next_u64() % span).unwrap_or(0)
    }
}

/// The adversary's fault parameters for one scenario.
#[derive(Clone, Copy, Debug)]
pub struct SimFaults {
    /// Per-link MDU. A packet strictly larger than this is DROPPED on the wire
    /// (the transport cannot carry it) — the #932 fault.
    pub mdu: usize,
    /// Whether the transport fragments oversized frames to sub-MDU packets (the
    /// FIX). `false` reproduces the stall; `true` proves the fix converges.
    pub fragment: bool,
    /// CIRISEdge#422 — whether the receiver NAKs missing fragment indices and the
    /// sender selectively retransmits them (fragment-level ARQ). `true` recovers a
    /// lossy large frame IN-round, re-sending only the gap; `false` falls back to
    /// pure whole-frame re-diff — the frame still reassembles (the receiver's
    /// reassembler accumulates fragments across rounds), but ONLY by re-sending the
    /// WHOLE frame every round until the last fragment lands: the slow, bandwidth-
    /// wasteful pre-#422 behavior. Independent of [`Self::fragment`]: ARQ needs
    /// fragments to exist, so it is a no-op when `fragment` is `false`.
    pub arq: bool,
    /// Per-packet loss probability, per mille (out of 1000).
    pub loss_per_mille: u32,
    /// Per-packet reorder probability, per mille (delays the packet in the queue).
    pub reorder_per_mille: u32,
    /// Per-packet duplication probability, per mille.
    pub dup_per_mille: u32,
    /// Max anti-entropy rounds to drive before declaring non-convergence — the
    /// protocol re-diffs each round, so transient loss heals across rounds.
    pub max_rounds: usize,
}

impl Default for SimFaults {
    fn default() -> Self {
        Self {
            mdu: 431, // realistic encrypted Reticulum link MDU
            fragment: true,
            arq: true,
            loss_per_mille: 0,
            reorder_per_mille: 0,
            dup_per_mille: 0,
            max_rounds: 8,
        }
    }
}

/// A `StateProvider` + `StateApplier` backed by a `LocalState` and an
/// (envelope_hash → bytes) map, so scenarios control envelope SIZES precisely —
/// the whole point is to make a Deliver exceed the MDU.
struct SimStore {
    state: LocalState,
    bytes: HashMap<[u8; 32], Vec<u8>>,
}
impl SimStore {
    fn new() -> Self {
        Self {
            state: LocalState::new(),
            bytes: HashMap::new(),
        }
    }
    fn insert(&mut self, kind: EnvelopeKind, payload: Vec<u8>, seq: u64) -> [u8; 32] {
        let hash: [u8; 32] = Sha256::digest(&payload).into();
        self.state.insert(kind, hash, seq);
        self.bytes.insert(hash, payload);
        hash
    }
    fn holds(&self, kind: EnvelopeKind, hash: &[u8; 32]) -> bool {
        self.state
            .by_kind
            .get(&kind)
            .is_some_and(|m| m.contains_key(hash))
    }
}
impl StateProvider for SimStore {
    fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.state.refs_for(kind)
    }
    fn fetch_envelope(&self, _kind: EnvelopeKind, h: &[u8; 32]) -> Option<Vec<u8>> {
        self.bytes.get(h).cloned()
    }
}
/// Applier that records admitted envelopes into a shared store (so the same
/// bytes-map serves fetch on the next round — the node now HOLDS what it got).
struct SimApplier<'a> {
    store: &'a mut SimStore,
    /// Maps applied bytes back to their hash (production verifies + rehashes).
    applied: Vec<[u8; 32]>,
}
impl StateApplier for SimApplier<'_> {
    fn apply_envelope(
        &mut self,
        kind: EnvelopeKind,
        bytes: &[u8],
        _source_peer: Option<&str>,
    ) -> ApplyOutcome {
        let hash: [u8; 32] = Sha256::digest(bytes).into();
        if self.store.holds(kind, &hash) {
            return ApplyOutcome::Duplicate;
        }
        let seq = self.store.state.by_kind.get(&kind).map_or(0, BTreeMap::len) as u64 + 1;
        self.store.insert(kind, bytes.to_vec(), seq);
        self.applied.push(hash);
        ApplyOutcome::Admitted
    }
}

/// One node in the pairwise anti-entropy: a `Session`, its store, its inbound
/// fragment reassembler, and (CIRISEdge#422) its sender-side retransmit buffer so a
/// peer's NAK is served by re-sending only the named fragments.
struct SimNode {
    session: Session,
    store: SimStore,
    reasm: Reassembler,
    retx: RetransmitBuffer,
}
impl SimNode {
    fn new(role: SessionRole, kind: EnvelopeKind) -> Self {
        Self {
            session: Session::new(role, kind),
            store: SimStore::new(),
            reasm: Reassembler::new(),
            retx: RetransmitBuffer::new(),
        }
    }
}

/// CIRISEdge#422 — the wire-level instrumentation the oracle asserts on. `max_frame_bytes`
/// preserves the pre-#422 "the payload really exceeded the MDU" evidence; the ARQ
/// counters prove the selective path ENGAGED, and `whole_frame_resends` is the
/// load-bearing invariant: fragment-ARQ must carry a frame IN-round, so a frame's
/// complete fragment set is emitted at most ONCE.
#[derive(Default)]
struct SimMetrics {
    max_frame_bytes: usize,
    naks_sent: usize,
    fragments_retransmitted: usize,
    whole_frame_resends: usize,
    /// `msg_id`s already emitted as a COMPLETE fragment set — a second full emission
    /// of the same id is a whole-frame re-send (what selective ARQ makes needless).
    fully_emitted: std::collections::HashSet<[u8; 8]>,
}

/// A packet on the wire, tagged with its destination (0 = to initiator, 1 = to
/// responder).
struct Packet {
    to: usize,
    bytes: Vec<u8>,
}

/// The result of a scenario — BOTH sides' terminal state, so the oracle can not
/// pass on initiator-only convergence.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub kind: EnvelopeKind,
    pub seed: u64,
    /// Did the initiator reach a terminal applied state (received a Deliver)?
    pub initiator_complete: bool,
    /// Did the RESPONDER reach a terminal applied state? THE load-bearing signal.
    pub responder_complete: bool,
    /// Did each node end holding the union of both nodes' seeded envelopes?
    pub all_envelopes_present_both_sides: bool,
    pub rounds_used: usize,
    /// The largest single wire frame the round produced (asserts the payload
    /// really exceeded the MDU — so a shrunk fixture re-derives the hypothesis).
    pub max_frame_bytes: usize,
    /// CIRISEdge#422 — NAK control packets the receivers emitted (0 ⇒ the selective
    /// path never engaged — no gap to recover).
    pub naks_sent: usize,
    /// CIRISEdge#422 — individual fragments a sender selectively re-sent in answer to
    /// a NAK (a SUBSET of a frame, never the whole frame).
    pub fragments_retransmitted: usize,
    /// CIRISEdge#422 — times a frame's COMPLETE fragment set was re-emitted after its
    /// first send (a whole-frame re-send). The oracle demands this be 0: fragment-ARQ
    /// must carry the frame in-round, so it is never re-fragmented and re-sent whole.
    pub whole_frame_resends: usize,
}
impl Outcome {
    /// Full convergence — the ONLY acceptable terminal state. Requires the
    /// RESPONDER to have completed, not merely the initiator.
    #[must_use]
    pub fn converged(&self) -> bool {
        self.responder_complete && self.initiator_complete && self.all_envelopes_present_both_sides
    }
}

/// A pairwise anti-entropy scenario: the initiator holds `initiator_payloads`,
/// the responder holds `responder_payloads`, both for `kind`, over a wire with
/// `faults`. `run` drives to convergence or `max_rounds` and reports the outcome.
pub struct Scenario {
    pub kind: EnvelopeKind,
    pub seed: u64,
    pub faults: SimFaults,
    pub initiator_payloads: Vec<Vec<u8>>,
    pub responder_payloads: Vec<Vec<u8>>,
}

impl Scenario {
    /// Run the scenario deterministically. Returns the [`Outcome`]; a failing
    /// `seed` reproduces it exactly.
    #[must_use]
    pub fn run(&self) -> Outcome {
        let mut rng = Rng(self.seed ^ 0xD1B5_4A32_D192_ED03);
        // Node 0 = initiator, node 1 = responder. An array (not two named locals)
        // keeps the ARQ index math — `nodes[to]` receives, `nodes[1 - to]` is the
        // peer — a single disjoint borrow, which the NAK/retransmit paths need.
        let mut nodes = [
            SimNode::new(SessionRole::Initiator, self.kind),
            SimNode::new(SessionRole::Responder, self.kind),
        ];
        // Seed each side's holdings. Track the full expected union for the oracle.
        let mut expected: Vec<[u8; 32]> = Vec::new();
        for (i, p) in self.initiator_payloads.iter().enumerate() {
            expected.push(nodes[0].store.insert(self.kind, p.clone(), i as u64 + 1));
        }
        for (i, p) in self.responder_payloads.iter().enumerate() {
            expected.push(nodes[1].store.insert(self.kind, p.clone(), i as u64 + 1));
        }

        let mut metrics = SimMetrics::default();
        let mut wire: Vec<Packet> = Vec::new();
        let mut rounds_used = 0usize;

        for round in 0..self.faults.max_rounds {
            rounds_used = round + 1;
            // Each ROUND is a fresh anti-entropy exchange — mirror the production
            // coordinator, which `reset()`s the session on round completion
            // (`drive_round_step` auto-reset). Without this the responder's
            // `last_summary_sent` guard suppresses its re-Summary after round 0, so
            // the initiator never re-Diffs and the responder's (large, lossy)
            // Deliver is never re-sent — a single lost fragment would then be fatal.
            // reset() preserves cross-round knowledge (the peer's last summary).
            if round > 0 {
                nodes[0].session.reset();
                nodes[1].session.reset();
            }
            // Initiator (node 0) opens the round — its Summary goes TO the
            // responder (node 1). It records its own emitted fragments for ARQ.
            let out = nodes[0].session.start_round(&nodes[0].store);
            self.emit(
                1,
                out,
                &mut wire,
                &mut metrics,
                &mut nodes[0].retx,
                &mut rng,
            );

            // Drive the round: drain the wire to quiescence, then (CIRISEdge#422)
            // run fragment-ARQ recovery passes until nothing is in flight or the
            // pass budget is spent — only THEN fall to the next round's re-diff.
            let mut steps = 0usize;
            let mut arq_pass = 0usize;
            'round: loop {
                while let Some(pkt) = Self::dequeue(&mut wire) {
                    steps += 1;
                    if steps > MAX_ROUND_STEPS {
                        break 'round; // safety — a real stall shows as non-convergence
                    }
                    let to = pkt.to;
                    // A NAK is a TRANSPORT-level control packet (served selectively);
                    // anything else is a fragment/whole frame routed to the session.
                    if frame_fragment::is_nak(&pkt.bytes) {
                        self.serve_nak(&nodes, to, &pkt.bytes, &mut wire, &mut metrics, &mut rng);
                    } else {
                        self.deliver_frame(
                            &mut nodes,
                            to,
                            &pkt.bytes,
                            &mut wire,
                            &mut metrics,
                            &mut rng,
                        );
                    }
                }

                // Wire quiesced. CIRISEdge#422 — try fragment-ARQ before the round
                // ends. `false` when ARQ is off or nothing is in flight.
                if !self.faults.arq {
                    break 'round;
                }
                arq_pass += 1;
                if arq_pass > MAX_ARQ_PASSES {
                    break 'round; // exhausted — the whole-frame re-diff takes over
                }
                if !self.inject_naks(&nodes, &mut wire, &mut metrics, &mut rng) {
                    break 'round; // nothing missing — the round is genuinely done
                }
            }

            if self.both_hold_all(&nodes[0], &nodes[1], &expected) {
                break;
            }
        }

        let all_present = self.both_hold_all(&nodes[0], &nodes[1], &expected);
        Outcome {
            kind: self.kind,
            seed: self.seed,
            initiator_complete: nodes[0].session.is_complete() || all_present,
            responder_complete: nodes[1].session.is_complete() || all_present,
            all_envelopes_present_both_sides: all_present,
            rounds_used,
            max_frame_bytes: metrics.max_frame_bytes,
            naks_sent: metrics.naks_sent,
            fragments_retransmitted: metrics.fragments_retransmitted,
            whole_frame_resends: metrics.whole_frame_resends,
        }
    }

    /// CIRISEdge#422 — serve one inbound NAK. Node `to` is the ORIGINAL SENDER of the
    /// frame; re-send ONLY the requested indices from its retransmit buffer to the
    /// requester (`1 - to`) — never the whole frame, never through the session. A
    /// shortfall (the sender no longer holds a requested index) and a bounded sample
    /// of the served fragments are logged LOUD (this class must never be silent).
    fn serve_nak(
        &self,
        nodes: &[SimNode; 2],
        to: usize,
        bytes: &[u8],
        wire: &mut Vec<Packet>,
        metrics: &mut SimMetrics,
        rng: &mut Rng,
    ) {
        let Some((msg_id, indices)) = frame_fragment::parse_nak(bytes) else {
            return; // malformed NAK — dropped, never acted on
        };
        let requester = 1 - to;
        let frags = nodes[to].retx.retransmit(&msg_id, &indices);
        let served = frags.len();
        if served < indices.len() {
            tracing::warn!(
                msg_id = %hex8(msg_id),
                sender = to,
                requester,
                requested = indices.len(),
                served,
                "CIRISEdge#422 retransmit SHORTFALL — sender cannot serve all NAK'd \
                 fragments; remainder falls to whole-frame re-diff"
            );
        }
        for f in frags.iter().take(8) {
            tracing::debug!(
                msg_id = %hex8(msg_id),
                fragment = frame_fragment::fragment_index(f).unwrap_or_default(),
                sender = to,
                requester,
                "CIRISEdge#422 selective retransmit (sender → requester)"
            );
        }
        metrics.fragments_retransmitted += served;
        for f in frags {
            self.send_packet(wire, requester, f, rng);
        }
    }

    /// Feed one non-NAK packet to node `to`'s reassembler; if it completes a frame,
    /// route it through the session and emit the reply FROM node `to` (recording its
    /// own emitted fragments for later NAK service). A fragment that does not yet
    /// complete a frame is buffered and yields nothing.
    fn deliver_frame(
        &self,
        nodes: &mut [SimNode; 2],
        to: usize,
        bytes: &[u8],
        wire: &mut Vec<Packet>,
        metrics: &mut SimMetrics,
        rng: &mut Rng,
    ) {
        let Some(frame) = nodes[to].reasm.accept(bytes) else {
            return;
        };
        let Ok(Some(msg)) = wire_frame::try_unwrap(&frame) else {
            return;
        };
        // `on_message` reads the PROVIDER (this node's pre-message state) and writes
        // the APPLIER. Snapshot for the provider (so `want` diffs against the state
        // BEFORE this Deliver), then let the applier mutate the real store; the
        // snapshot's borrow ends before the applier's begins.
        let provider_snapshot = SimStore {
            state: store_clone(&nodes[to].store),
            bytes: nodes[to].store.bytes.clone(),
        };
        let outcome = {
            let node = &mut nodes[to];
            let mut applier = SimApplier {
                store: &mut node.store,
                applied: Vec::new(),
            };
            node.session
                .on_message(msg, &provider_snapshot, &mut applier, None)
        };
        self.emit(1 - to, outcome, wire, metrics, &mut nodes[to].retx, rng);
    }

    fn both_hold_all(&self, i: &SimNode, r: &SimNode, expected: &[[u8; 32]]) -> bool {
        expected
            .iter()
            .all(|h| i.store.holds(self.kind, h) && r.store.holds(self.kind, h))
    }

    /// CIRISEdge#422 — one fragment-ARQ recovery pass: for each node holding an
    /// incomplete frame, NAK exactly its missing indices back to the peer (the
    /// sender). Returns whether any NAK was injected (`false` ⇒ nothing in flight ⇒
    /// the round has quiesced). Every NAK is logged LOUD (msg_id + peer + gap size);
    /// this class must NEVER be a silent drop (the #423–#429 silent-refusal arc).
    fn inject_naks(
        &self,
        nodes: &[SimNode; 2],
        wire: &mut Vec<Packet>,
        metrics: &mut SimMetrics,
        rng: &mut Rng,
    ) -> bool {
        let mut injected = false;
        for (recv, node) in nodes.iter().enumerate() {
            let peer = 1 - recv;
            for (msg_id, miss) in node.reasm.missing() {
                let naks = frame_fragment::build_naks(&msg_id, &miss, self.faults.mdu);
                if naks.is_empty() {
                    // MDU too small for even a one-index NAK — the whole-frame re-diff
                    // fallback must cover this frame; make the refusal loud, not silent.
                    tracing::warn!(
                        msg_id = %hex8(msg_id),
                        recv,
                        peer,
                        missing = miss.len(),
                        mdu = self.faults.mdu,
                        "CIRISEdge#422 cannot NAK — MDU too small for a CNAK packet; \
                         falling back to whole-frame re-diff"
                    );
                    continue;
                }
                for &idx in miss.iter().take(8) {
                    tracing::debug!(
                        msg_id = %hex8(msg_id),
                        fragment = idx,
                        recv,
                        peer,
                        "CIRISEdge#422 NAK fragment (receiver → sender)"
                    );
                }
                tracing::warn!(
                    msg_id = %hex8(msg_id),
                    recv,
                    peer,
                    missing = miss.len(),
                    naks = naks.len(),
                    "CIRISEdge#422 selective NAK — missing fragment(s) requested from peer"
                );
                metrics.naks_sent += naks.len();
                for nak in naks {
                    self.send_packet(wire, peer, nak, rng);
                }
                injected = true;
            }
        }
        injected
    }

    /// Wrap each message of an outcome into a wire frame, fragment it (if the fix
    /// is on), and enqueue the packets toward `to` — applying MDU-drop, loss,
    /// reorder, and duplication as the wire's fault model. `sender_retx` is the
    /// EMITTING node's retransmit buffer: a multi-fragment set is recorded there so
    /// a later NAK is served selectively (CIRISEdge#422), and a SECOND full emission
    /// of the same `msg_id` is counted as a whole-frame re-send.
    fn emit(
        &self,
        to: usize,
        outcome: ReplicationOutcome,
        wire: &mut Vec<Packet>,
        metrics: &mut SimMetrics,
        sender_retx: &mut RetransmitBuffer,
        rng: &mut Rng,
    ) {
        let msgs = match outcome {
            ReplicationOutcome::Send(m) => m,
            ReplicationOutcome::SendAndComplete { msgs, .. } => msgs,
            _ => return,
        };
        for m in msgs {
            let frame = wire_frame::wrap_for_kind(&m);
            metrics.max_frame_bytes = metrics.max_frame_bytes.max(frame.len());
            let packets = if self.faults.fragment {
                fragment(&frame, self.faults.mdu).unwrap_or_else(|| vec![frame.clone()])
            } else {
                vec![frame] // no fragmentation — the oversized frame stays whole
            };
            // CIRISEdge#422 — a MULTI-fragment set is retransmittable: cache it for
            // selective NAK service, and count a SECOND full emission of the same
            // msg_id as a whole-frame re-send (the ceiling ARQ exists to avoid). A
            // single unwrapped packet (frame ≤ MDU) has no fragment ARQ.
            if !packets.is_empty() && frame_fragment::is_fragment(&packets[0]) {
                if let Some(msg_id) = frame_fragment::msg_id_of_fragment(&packets[0]) {
                    if !metrics.fully_emitted.insert(msg_id) {
                        metrics.whole_frame_resends += 1;
                        tracing::warn!(
                            msg_id = %hex8(msg_id),
                            to,
                            fragments = packets.len(),
                            "CIRISEdge#422 WHOLE-FRAME RE-SEND — the frame was re-fragmented \
                             and re-emitted in full (fragment-ARQ did not carry it in-round)"
                        );
                    }
                    sender_retx.record(&packets);
                }
            }
            for p in packets {
                self.send_packet(wire, to, p, rng);
            }
        }
    }

    /// Push one already-built packet onto the wire under the fault model: DROP if it
    /// exceeds the MDU (the #932 fault), else drop with `loss`, else enqueue (with
    /// `reorder`) and possibly duplicate. Shared by the initial fragment send, NAK
    /// control packets, AND selective retransmits — so NAKs and retransmits are just
    /// as lossy as data (fragment-ARQ must survive its own losses). The rng-draw
    /// order is byte-identical to the pre-#422 inline path (loss → reorder →
    /// duplication), so a seeded scenario with ARQ idle reproduces exactly.
    fn send_packet(&self, wire: &mut Vec<Packet>, to: usize, p: Vec<u8>, rng: &mut Rng) {
        if p.len() > self.faults.mdu {
            return; // DROPPED — the wire cannot carry a > MDU packet (#932 fault)
        }
        if rng.chance(self.faults.loss_per_mille) {
            return; // lost
        }
        self.enqueue(wire, to, p.clone(), rng);
        if rng.chance(self.faults.dup_per_mille) {
            self.enqueue(wire, to, p, rng);
        }
    }

    fn enqueue(&self, wire: &mut Vec<Packet>, to: usize, bytes: Vec<u8>, rng: &mut Rng) {
        if rng.chance(self.faults.reorder_per_mille) && !wire.is_empty() {
            // Reorder: insert at a random earlier position (delivered later).
            let at = rng.range(0, wire.len());
            wire.insert(at, Packet { to, bytes });
        } else {
            wire.push(Packet { to, bytes });
        }
    }

    fn dequeue(wire: &mut Vec<Packet>) -> Option<Packet> {
        if wire.is_empty() {
            None
        } else {
            Some(wire.remove(0))
        }
    }
}

/// Shallow-clone a `LocalState` (its `by_kind` map). Small — one round's refs.
fn store_clone(store: &SimStore) -> LocalState {
    let mut s = LocalState::new();
    for (k, m) in &store.state.by_kind {
        for (h, seq) in m {
            s.insert(*k, *h, *seq);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fat payload (each envelope ~ this many raw bytes → JSON-expanded ~3–4×).
    // Deterministic byte-pattern fill — the `as u8` truncation IS the intent.
    #[allow(clippy::cast_possible_truncation)]
    fn payloads(n: usize, raw_size: usize, salt: u8) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let base = (i as u8).wrapping_add(salt);
                (0..raw_size).map(|j| base.wrapping_add(j as u8)).collect()
            })
            .collect()
    }

    /// BASELINE — a round with a large payload MUST converge (both sides), AND we
    /// assert the frame really exceeded the MDU, so a shrunk fixture re-derives
    /// the hypothesis rather than silently passing on a small frame.
    #[test]
    fn baseline_large_payload_converges_and_frame_exceeds_mdu() {
        let sc = Scenario {
            kind: EnvelopeKind::Attestation,
            seed: 1,
            faults: SimFaults::default(),              // fragment = true
            initiator_payloads: payloads(6, 5_000, 0), // ~19 KB+ wire Deliver
            responder_payloads: payloads(2, 800, 9),
        };
        let out = sc.run();
        assert!(
            out.max_frame_bytes > 4_000,
            "the Deliver must exceed the MDU by far — got {} bytes (fixture shrank?)",
            out.max_frame_bytes
        );
        assert!(
            out.converged(),
            "large-payload round must converge: {out:?}"
        );
        assert!(
            out.responder_complete,
            "RESPONDER must reach terminal state"
        );
    }

    /// REPRODUCES #932 — with fragmentation OFF, the oversized Deliver is dropped
    /// on the wire and the RESPONDER never completes, exactly the live stall. This
    /// is the failing baseline the fix beats; small control frames still flow.
    #[test]
    fn oversize_deliver_dropped_reproduces_932() {
        let sc = Scenario {
            kind: EnvelopeKind::Attestation,
            seed: 7,
            faults: SimFaults {
                fragment: false, // the pre-fix transport
                ..SimFaults::default()
            },
            initiator_payloads: payloads(6, 5_000, 0),
            responder_payloads: payloads(2, 800, 9),
        };
        let out = sc.run();
        assert!(
            !out.converged(),
            "without fragmentation the oversized Deliver must stall the round (#932): {out:?}"
        );
    }

    /// THE FIX — the same oversized scenario with fragmentation ON converges, and
    /// the responder completes. This is the failing test #932 gives us to beat.
    #[test]
    fn fragmentation_converges_the_oversized_round() {
        let sc = Scenario {
            kind: EnvelopeKind::Attestation,
            seed: 7,
            faults: SimFaults {
                fragment: true,
                ..SimFaults::default()
            },
            initiator_payloads: payloads(6, 5_000, 0),
            responder_payloads: payloads(2, 800, 9),
        };
        let out = sc.run();
        assert!(
            out.converged(),
            "fragmentation must converge the round: {out:?}"
        );
        assert!(out.responder_complete);
    }

    /// A SINGLE envelope larger than the MDU (the 1 MiB inline-trace case) —
    /// chunking-by-envelope cannot help; only fragmentation converges it.
    #[test]
    fn single_oversized_envelope_converges_via_fragmentation() {
        let sc = Scenario {
            kind: EnvelopeKind::Attestation,
            seed: 3,
            faults: SimFaults::default(),
            initiator_payloads: vec![payloads(1, 200_000, 0).pop().unwrap()],
            responder_payloads: vec![],
        };
        let out = sc.run();
        assert!(out.max_frame_bytes > 200_000);
        assert!(
            out.converged(),
            "a single >MDU envelope must fragment + converge: {out:?}"
        );
    }

    /// THE DELIVER BUDGET (CIRISEdge#414/#932) — holdings whose total exceeds
    /// `MAX_DELIVER_ENVELOPE_BYTES` are NOT packed into one unbounded frame; the
    /// Deliver is byte-bounded and the remainder is carried by the next round's
    /// re-diff. Convergence therefore takes MORE than one round (chunk-per-round),
    /// which is the observable signature of the budget engaging. Driven on a
    /// LOSSLESS wire on purpose: this isolates the budget/re-diff MECHANISM from the
    /// whole-frame-retry loss ceiling (a frame needing thousands of fragments will
    /// not reassemble under sustained loss on the pure re-diff path — the separate
    /// limitation now closed by fragment-level ARQ, CIRISEdge#422, exercised by
    /// `fragment_arq_converges_worst_corner_without_whole_frame_resend` below).
    #[test]
    fn oversized_holdings_chunk_across_rounds_via_deliver_budget() {
        use crate::replication::session::MAX_DELIVER_ENVELOPE_BYTES;
        // ~800 KiB of holdings on one side — comfortably over the 512 KiB budget, so
        // the responder MUST split its Deliver across at least two rounds.
        let env = 100 * 1024;
        let n = (MAX_DELIVER_ENVELOPE_BYTES / env) + 3; // 8 envelopes → ~800 KiB
        let sc = Scenario {
            kind: EnvelopeKind::Attestation,
            seed: 11,
            faults: SimFaults {
                mdu: 431,
                fragment: true,
                arq: true,
                loss_per_mille: 0, // isolate the budget mechanism from the loss ceiling
                reorder_per_mille: 40,
                dup_per_mille: 0,
                max_rounds: 24,
            },
            initiator_payloads: payloads(n, env, 0),
            responder_payloads: vec![],
        };
        let out = sc.run();
        assert!(
            out.converged(),
            "budgeted chunking must still converge: {out:?}"
        );
        assert!(
            out.responder_complete,
            "RESPONDER must reach terminal state"
        );
        assert!(
            out.rounds_used > 1,
            "holdings over the budget must chunk across >1 round; got {} — did the budget \
             stop engaging?",
            out.rounds_used
        );
        // No single frame carried the whole unbounded set: the budget caps a Deliver
        // at ~budget + one-envelope slack (raw) → ~4× that JSON-wire. The unbudgeted
        // frame would be ~n × env × 4 ≈ 3.2 MB; the budgeted cap is well under it.
        assert!(
            out.max_frame_bytes < (MAX_DELIVER_ENVELOPE_BYTES + env) * 5,
            "the Deliver frame must be bounded by the budget, got {} bytes",
            out.max_frame_bytes
        );
    }

    /// The worst-corner fault set the module's "whole-frame-retry ceiling" names:
    /// one very large single-envelope frame (thousands of fragments), a TINY MDU,
    /// HIGH per-packet loss, and sustained-busy ⇒ everything on the packet path
    /// (`fragment = true`, no reliable resource path). `arq` selects the two arms.
    fn worst_corner(seed: u64, arq: bool) -> Scenario {
        Scenario {
            kind: EnvelopeKind::Attestation,
            seed,
            faults: SimFaults {
                mdu: 300,            // a tiny link MDU
                fragment: true,      // sustained-busy: every frame rides packets
                arq,                 // the fix under test
                loss_per_mille: 150, // 15 % per-packet loss — high
                reorder_per_mille: 60,
                dup_per_mille: 0,
                max_rounds: 40,
            },
            // ONE ~120 KB raw envelope → ~430 KB JSON-wire → ~1400 fragments at a
            // 300 B MDU. Per round `(1-0.15)^1400 ≈ 10⁻⁹⁹`, so pure whole-frame retry
            // reassembles ONLY by re-sending the entire frame round after round until
            // the last straggler lands (fragments accumulate across rounds) — the
            // slow, wasteful ceiling. Selective retransmit recovers the gap in-round.
            initiator_payloads: vec![payloads(1, 120_000, 0).pop().unwrap()],
            responder_payloads: vec![],
        }
    }

    /// CIRISEdge#422 — the pre-fix behavior, reproduced: the worst corner with ARQ
    /// OFF still converges (the reassembler accumulates fragments across rounds) but
    /// ONLY by RE-SENDING THE WHOLE ~430 KB frame every round until the last fragment
    /// lands — `whole_frame_resends > 0`, and zero NAKs. This is the slow, bandwidth-
    /// wasteful path #422's selective retransmit replaces; the paired oracle below
    /// recovers the SAME corner with `whole_frame_resends == 0`. (The twin of the
    /// #932 fragment on/off pair.)
    #[test]
    fn fragment_arq_worst_corner_retries_whole_frame_without_arq() {
        let sc = worst_corner(0x0422_D15A_B1E0, false);
        let out = sc.run();
        assert!(
            out.converged(),
            "the pre-#422 path still converges by accumulation (reproduce: seed={:#x}): {out:?}",
            out.seed,
        );
        assert!(
            out.whole_frame_resends > 0,
            "without ARQ the WHOLE frame is re-sent each round (the slow path #422 fixes) — \
             expected >0 resends (seed={:#x}): {out:?}",
            out.seed,
        );
        assert_eq!(
            out.naks_sent, 0,
            "ARQ off ⇒ no selective NAKs (seed={:#x}): {out:?}",
            out.seed,
        );
    }

    /// CIRISEdge#422 — THE ORACLE. The SAME worst corner with fragment-ARQ ON
    /// converges (RESPONDER included), the selective path demonstrably ENGAGED
    /// (NAKs + retransmits > 0), and — the load-bearing invariant — the frame's
    /// COMPLETE fragment set is NEVER re-sent (`whole_frame_resends == 0`): recovery
    /// is selective retransmit of the gap, in-round, not a whole-frame gamble across
    /// rounds. Deterministic: the fixed seed reproduces the whole run from one
    /// command, and the assert messages echo it.
    #[test]
    fn fragment_arq_converges_worst_corner_without_whole_frame_resend() {
        let sc = worst_corner(0x0422_D15A_B1E0, true);
        let out = sc.run();
        assert!(
            out.converged(),
            "fragment-ARQ must converge the worst corner (reproduce: seed={:#x}): {out:?}",
            out.seed,
        );
        assert!(
            out.naks_sent > 0 && out.fragments_retransmitted > 0,
            "the selective path must have ENGAGED (naks={} retransmits={}) — else this proves \
             nothing (seed={:#x}): {out:?}",
            out.naks_sent,
            out.fragments_retransmitted,
            out.seed,
        );
        assert_eq!(
            out.whole_frame_resends, 0,
            "the whole frame must NEVER be re-sent — selective retransmit only \
             (seed={:#x}): {out:?}",
            out.seed,
        );
        assert!(
            out.max_frame_bytes > sc.faults.mdu,
            "the frame must exceed the MDU or the corner is not being exercised \
             (seed={:#x}): {out:?}",
            out.seed,
        );
    }

    /// CIRISEdge#422 — a seeded SEARCH over the worst-corner window: large single
    /// frames × tiny MDUs × HIGH-but-recoverable loss must ALWAYS converge via
    /// fragment-ARQ with NO whole-frame re-send. Deterministic (seed-driven, not
    /// `proptest`'s RNG) so any failure prints the exact `seed` for one-command
    /// reproduction, and cheap enough to gate every build. A regression that breaks
    /// in-round selective recovery makes the frame get re-sent whole next round →
    /// `whole_frame_resends > 0` → a reproducible failure here.
    #[test]
    fn fragment_arq_search_high_loss_tiny_mdu_no_whole_resend() {
        let mut rng = Rng(0x0422_5EA5_C0DE_0001);
        for _ in 0..64 {
            let s = rng.next_u64();
            let seed = s;
            let raw = 20_000 + (s % 40_000) as usize; // ~80–240 KB wire: hundreds+ frags
            let mdu = 260 + ((s >> 20) % 300) as usize; // tiny link MDUs
            let loss = 80 + ((s >> 40) % 140) as u32; // 8–22 % loss (high, recoverable)
            let reorder = ((s >> 52) % 120) as u32;
            let sc = Scenario {
                kind: EnvelopeKind::Attestation,
                seed,
                faults: SimFaults {
                    mdu,
                    fragment: true,
                    arq: true,
                    loss_per_mille: loss,
                    reorder_per_mille: reorder,
                    dup_per_mille: 0,
                    max_rounds: 40,
                },
                initiator_payloads: vec![payloads(1, raw, 0).pop().unwrap()],
                responder_payloads: vec![],
            };
            let out = sc.run();
            assert!(
                out.converged(),
                "fragment-ARQ non-convergence (seed={seed:#x} raw={raw} mdu={mdu} loss={loss} \
                 reorder={reorder}): {out:?}",
            );
            assert!(
                out.fragments_retransmitted > 0,
                "high loss must engage selective retransmit (seed={seed:#x}): {out:?}",
            );
            assert_eq!(
                out.whole_frame_resends, 0,
                "selective ARQ must carry the frame in-round — no whole-frame re-send \
                 (seed={seed:#x} raw={raw} mdu={mdu} loss={loss}): {out:?}",
            );
        }
    }

    /// Drive one generated scenario with fragmentation ON and assert the
    /// RESPONDER converges. Shared by the CI proptest gate and the soak runner.
    fn assert_scenario_converges(
        seed: u64,
        num_i: usize,
        num_r: usize,
        raw_size: usize,
        mdu: usize,
        loss: u32,
        reorder: u32,
    ) {
        let sc = Scenario {
            kind: EnvelopeKind::Attestation,
            seed,
            faults: SimFaults {
                mdu,
                fragment: true,
                arq: true,
                loss_per_mille: loss,
                reorder_per_mille: reorder,
                dup_per_mille: loss / 2,
                max_rounds: 40, // ample for transient loss to heal via re-diff
            },
            initiator_payloads: payloads(num_i, raw_size, 1),
            responder_payloads: payloads(num_r, raw_size, 2),
        };
        let out = sc.run();
        assert!(
            out.converged(),
            "NON-CONVERGENCE on {kind:?} after {rounds} rounds (seed={seed} num_i={num_i} \
             num_r={num_r} raw_size={raw_size} mdu={mdu} loss={loss} reorder={reorder}): {out:?}",
            kind = out.kind,
            rounds = out.rounds_used,
        );
        // Guard against a vacuous pass: the scenario must actually have produced a
        // wire frame (a degenerate all-empty payload set would converge trivially
        // without exercising fragmentation). `seed` is echoed so any failure here
        // reproduces exactly.
        assert!(
            out.max_frame_bytes > 0,
            "degenerate scenario produced no wire frame (seed={})",
            out.seed,
        );
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        /// THE PERMANENT CI GATE (CIRISAgent#932): across a broad generated space
        /// of payload sizes (well past the MDU), envelope counts, MDUs, and packet
        /// loss/reorder, EVERY anti-entropy round must converge on the RESPONDER
        /// with fragmentation on. The generator lands in the oversized-frame window
        /// by construction, so a regression that reintroduces a silent-drop window
        /// fails a seed here — which reproduces deterministically. This is the
        /// "can't die to a cheap window issue" guarantee, searched every build.
        #[test]
        fn dst_every_round_converges_across_payloads_and_faults(
            num_i in 0usize..8,
            num_r in 0usize..8,
            raw_size in 1usize..8_000,      // 1 B … well over any link MDU
            mdu in 200usize..2_000,
            loss in 0u32..30,               // up to 3% per-packet loss
            reorder in 0u32..120,           // up to 12% reorder
            seed in proptest::prelude::any::<u64>(),
        ) {
            proptest::prop_assume!(num_i + num_r > 0);
            assert_scenario_converges(seed, num_i, num_r, raw_size, mdu, loss, reorder);
        }
    }

    /// SOAK — the high-volume search, env-gated so it runs pre-release / nightly,
    /// not on every `cargo test`. `CIRIS_DST_SOAK=<n>` runs n deterministic
    /// scenarios (default 50_000) sweeping fat payloads × tiny MDUs × loss/reorder;
    /// any non-convergence prints its exact reproduction seed. Run:
    /// `CIRIS_DST_SOAK=200000 cargo test --lib dst_soak -- --ignored --nocapture`.
    #[test]
    #[ignore = "high-volume soak; run explicitly via CIRIS_DST_SOAK"]
    fn dst_soak() {
        let n: u64 = std::env::var("CIRIS_DST_SOAK")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50_000);
        let mut rng = Rng(0xBA5E_D157_C0DE_F00Du64 ^ n);
        for i in 0..n {
            let s = rng.next_u64();
            let num_i = (s % 8) as usize;
            let num_r = ((s >> 8) % 8) as usize;
            if num_i + num_r == 0 {
                continue;
            }
            let raw_size = 1 + ((s >> 16) % 12_000) as usize; // fat payloads
            let mdu = 200 + ((s >> 32) % 1_800) as usize;
            let loss = ((s >> 48) % 30) as u32;
            let reorder = ((s >> 52) % 120) as u32;
            assert_scenario_converges(s, num_i, num_r, raw_size, mdu, loss, reorder);
            if i % 10_000 == 0 && std::env::var("SIM_DEBUG").is_ok() {
                eprintln!("dst_soak: {i}/{n} scenarios converged");
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // VALUE-EMITTING DUMP (CIRISEdge#430 bench-superset) — the replication-
    // plane half of the honest publishing lane (twin of
    // realtime_av_alm::sim::tests::bench_dump_mesh_metrics). PRINTS each
    // anti-entropy metric's VALUE as a sentinel-prefixed libtest-bencher line
    // so `benchmark-action/github-action-benchmark` trends it per-release.
    // Never asserts.
    //
    // Wire contract with `.github/workflows/bench.yml`: lines are
    //   `SIMBENCH test replication/<name> ... bench: <int> ns/iter (+/- 0)`
    // appended UN-normalized (rounds/ratios are semantic, not wall-time). The
    // `ns/iter` unit is a libtest artifact; the scale is in the name suffix
    // (`_x1000` ⇒ value×1000, `_x100000` ⇒ ratio×100000).
    //
    // Run: cargo test --release --lib bench_dump_replication_metrics -- --nocapture
    #[test]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    fn bench_dump_replication_metrics() {
        fn dump(name: &str, value: i64) {
            println!("SIMBENCH test {name} ... bench: {value} ns/iter (+/- 0)");
        }

        // Build a converging anti-entropy scenario at a fixed operating point:
        // `num_i` initiator envelopes + 2 responder envelopes of `raw_size`,
        // fragmentation ON, `loss`% per-packet loss, ample re-diff budget.
        let scenario = |seed: u64, num_i: usize, raw_size: usize, loss_pct: u32| Scenario {
            kind: EnvelopeKind::Attestation,
            seed,
            faults: SimFaults {
                loss_per_mille: loss_pct * 10,
                reorder_per_mille: 20,
                dup_per_mille: 10,
                max_rounds: 40,         // transient loss heals across re-diffs
                ..SimFaults::default()  // fragment = true, mdu = 431
            },
            initiator_payloads: payloads(num_i, raw_size, 0),
            responder_payloads: payloads(2, 800, 9),
        };

        // ── Lane A — fixed-operating-point replication metrics ───────────

        // Anti-entropy rounds @ fixed loss (replication/summary) — mean
        // rounds-to-converge over 200 seeds at 2 % loss, 6-envelope fat
        // corpus. ×1000 to preserve the fractional mean.
        let rounds: Vec<f64> = (0..200u64)
            .map(|s| scenario(s, 6, 5_000, 2).run().rounds_used as f64)
            .collect();
        dump(
            "replication/antientropy_rounds_loss2pct_mean_x1000",
            (mean(&rounds) * 1_000.0).round() as i64,
        );

        // Reassembly delivery ratio @ fixed loss (replication/wire_frame) —
        // fraction of scenarios that fully converged (both sides hold the
        // union — the fragment-reassembly + re-diff loop delivered every
        // oversized Deliver) at 3 % loss over 200 seeds. ×100000.
        let converged = (0..200u64)
            .filter(|&s| scenario(s, 6, 5_000, 3).run().converged())
            .count();
        dump(
            "replication/reassembly_delivery_ratio_loss3pct_x100000",
            ((converged as f64 / 200.0) * 100_000.0).round() as i64,
        );

        // ── Lane B — convergence-rounds vs corpus size (one name per N) ──

        // rounds-to-converge as the initiator corpus grows (bigger union ⇒
        // larger Deliver ⇒ more fragments ⇒ more re-diff pressure under loss).
        // N = initiator envelope count; fixed 2 % loss, raw_size 3000, mean
        // over 40 seeds, ×1000.
        for &n in &[1usize, 8, 32, 128] {
            let r: Vec<f64> = (0..40u64)
                .map(|s| scenario(s, n, 3_000, 2).run().rounds_used as f64)
                .collect();
            dump(
                &format!("replication/convergence_rounds/N{n}_x1000"),
                (mean(&r) * 1_000.0).round() as i64,
            );
        }
    }

    /// Arithmetic mean of a sample set (0.0 on empty).
    #[allow(clippy::cast_precision_loss)]
    fn mean(xs: &[f64]) -> f64 {
        if xs.is_empty() {
            0.0
        } else {
            xs.iter().sum::<f64>() / xs.len() as f64
        }
    }
}
