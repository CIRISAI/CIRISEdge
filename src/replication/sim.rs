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
use crate::transport::frame_fragment::{fragment, Reassembler};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};

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

/// One node in the pairwise anti-entropy: a `Session`, its store, and its inbound
/// fragment reassembler.
struct SimNode {
    session: Session,
    store: SimStore,
    reasm: Reassembler,
}
impl SimNode {
    fn new(role: SessionRole, kind: EnvelopeKind) -> Self {
        Self {
            session: Session::new(role, kind),
            store: SimStore::new(),
            reasm: Reassembler::new(),
        }
    }
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
        let mut initiator = SimNode::new(SessionRole::Initiator, self.kind);
        let mut responder = SimNode::new(SessionRole::Responder, self.kind);
        // Seed each side's holdings. Track the full expected union for the oracle.
        let mut expected: Vec<[u8; 32]> = Vec::new();
        for (i, p) in self.initiator_payloads.iter().enumerate() {
            expected.push(initiator.store.insert(self.kind, p.clone(), i as u64 + 1));
        }
        for (i, p) in self.responder_payloads.iter().enumerate() {
            expected.push(responder.store.insert(self.kind, p.clone(), i as u64 + 1));
        }

        let mut max_frame_bytes = 0usize;
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
                initiator.session.reset();
                responder.session.reset();
            }
            // Initiator (node 0) opens the round — its Summary goes TO the
            // responder (node 1).
            let out = initiator.session.start_round(&initiator.store);
            self.emit(1, out, &mut wire, &mut max_frame_bytes, &mut rng);

            // Drain the wire to quiescence for this round (bounded step budget).
            let mut steps = 0usize;
            while let Some(pkt) = Self::dequeue(&mut wire) {
                steps += 1;
                if steps > 100_000 {
                    break; // safety — a real stall shows as non-convergence below
                }
                let (node, from) = if pkt.to == 0 {
                    (&mut initiator, 0)
                } else {
                    (&mut responder, 1)
                };
                // Reassemble; a fragment that doesn't complete yields nothing.
                let Some(frame) = node.reasm.accept(&pkt.bytes) else {
                    continue;
                };
                let Ok(Some(msg)) = wire_frame::try_unwrap(&frame) else {
                    continue;
                };
                // Apply against this node's own store. `on_message` reads the
                // PROVIDER (this node's pre-message state) and writes the APPLIER.
                // We take an immutable snapshot for the provider (so `want` diffs
                // against the state BEFORE this Deliver), then let the applier
                // mutate the real store — the snapshot's borrow ends before the
                // applier's mutable borrow begins. The applier commits admitted
                // envelopes into `store` directly (no separate commit step).
                let SimNode { session, store, .. } = node;
                let provider_snapshot = SimStore {
                    state: store_clone(store),
                    bytes: store.bytes.clone(),
                };
                let mut applier = SimApplier {
                    store,
                    applied: Vec::new(),
                };
                let outcome = session.on_message(msg, &provider_snapshot, &mut applier, None);
                self.emit(
                    from_peer(from),
                    outcome,
                    &mut wire,
                    &mut max_frame_bytes,
                    &mut rng,
                );
            }

            if self.both_hold_all(&initiator, &responder, &expected) {
                break;
            }
        }

        let all_present = self.both_hold_all(&initiator, &responder, &expected);
        Outcome {
            kind: self.kind,
            seed: self.seed,
            initiator_complete: initiator.session.is_complete() || all_present,
            responder_complete: responder.session.is_complete() || all_present,
            all_envelopes_present_both_sides: all_present,
            rounds_used,
            max_frame_bytes,
        }
    }

    fn both_hold_all(&self, i: &SimNode, r: &SimNode, expected: &[[u8; 32]]) -> bool {
        expected
            .iter()
            .all(|h| i.store.holds(self.kind, h) && r.store.holds(self.kind, h))
    }

    /// Wrap each message of an outcome into a wire frame, fragment it (if the fix
    /// is on), and enqueue the packets toward `to` — applying MDU-drop, loss,
    /// reorder, and duplication as the wire's fault model.
    fn emit(
        &self,
        to: usize,
        outcome: ReplicationOutcome,
        wire: &mut Vec<Packet>,
        max_frame_bytes: &mut usize,
        rng: &mut Rng,
    ) {
        let msgs = match outcome {
            ReplicationOutcome::Send(m) => m,
            ReplicationOutcome::SendAndComplete { msgs, .. } => msgs,
            _ => return,
        };
        for m in msgs {
            let frame = wire_frame::wrap_for_kind(&m);
            *max_frame_bytes = (*max_frame_bytes).max(frame.len());
            let packets = if self.faults.fragment {
                fragment(&frame, self.faults.mdu).unwrap_or_else(|| vec![frame.clone()])
            } else {
                vec![frame] // no fragmentation — the oversized frame stays whole
            };
            for p in packets {
                // The wire cannot carry a packet larger than the MDU (#932 fault).
                if p.len() > self.faults.mdu {
                    continue; // DROPPED
                }
                if rng.chance(self.faults.loss_per_mille) {
                    continue; // lost
                }
                self.enqueue(wire, to, p.clone(), rng);
                if rng.chance(self.faults.dup_per_mille) {
                    self.enqueue(wire, to, p, rng);
                }
            }
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

fn from_peer(from: usize) -> usize {
    usize::from(from == 0)
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
    /// not reassemble under sustained loss — that is a separate limitation whose fix
    /// is fragment-level ARQ, tracked as a follow-up; see the module notes).
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
