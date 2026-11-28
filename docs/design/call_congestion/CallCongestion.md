# A group call under uplink congestion: the closed model

`CallCongestion.tla` is one closed state model of a call room whose publisher's uplink is capped below its fan-out. It covers edge's ALM fan-out and selector code, leviculum's Channel and its proofs, leg redial, and the publisher's uplink queue. Each fix is a constant switch in the same spec. The model answers three questions: which failures today's code can reach, which switch removes which failure, and what is still missing with every switch on.

- **Files.** `CallCongestion.tla` (the spec), `MCCallCongestion.tla` (sequence-valued constants), `base.cfg.tmpl` (the cfg every scenario is generated from), `run_matrix.py` (the runner), `trace_check.py` (trace conformance).
- **How to run.** `python3 docs/design/call_congestion/run_matrix.py OUTDIR`; one scenario with `--only NAME`. For a counterexample's compact history: `--trace NAME PROPERTY`.
- **The scheduler.** TLC runs through the host scheduler: `GRACE_SCHED_*` + `cargo_guard.sh`, nice 19, idle I/O class, `-Xmx3g`, 2 workers, one run at a time.
- **Prior models.** The conventions are those of leviculum `docs/direct_link/DirectLinkPunch.tla` and `run_matrix.py`. The Channel's hold and learned timeout are those of leviculum `docs/channel/ChannelHold.tla`. That model proves the per-message rules in isolation; this one puts them in the room.

Results: [Results](#results). The table the code should implement: [Decision table](#decision-table).

## The system, as modelled

The room is P (the publisher) and the listeners L (A, B, C at N=4; A, B at N=3). Every listener relays (`relay = true`, the host's member default).

- **Legs.** There is one link per direction. Leg `x>y` is the link x dialled to y. x sends its media (datagrams) and its control (Channel messages) on it. y sends back only the proofs of x's Channel messages. So the proof of a message on `A>P` returns through P's uplink.
- **P's uplink.** It is ONE FIFO, drained at `RCap` units a tick while capped and `RFree` otherwise. Media, control, proofs and closes queue in the order they were handed to it. Nothing is refused locally (the bottleneck is past the process). Every other node's uplink is uncapped. What an uncapped node sends arrives within the same tick, and so does whatever that provokes.
- **Control messages.** These are offers (each node, on every out-leg, every `OfferEvery`; P every `StallOfferEvery` while stalled), subscribe, admit, refuse, shed and unsubscribe.
- **Media.** One batch per tick from P to its children (and to the drained). A relay forwards each new tick of P's media to its own children.

## Scale

At the scale the cfgs use, **1 tick = 100 ms**. The values below are those of `run_matrix.py` BASE. A value marked (s) is scaled down from the code's, to keep the horizon exhaustible; what that hides is listed under each.

| Constant | Model | Code | Note |
|---|---|---|---|
| copy of P's stream | `M` = 3 units/tick | ~190 kbit/s | |
| P's capped uplink | `RCap` = 4 units/tick | 250 kbit/s ≈ 1.3 copies | 3 copies = 2.25× (matrix: 2.3×) |
| uncapped | `RFree` = 40 | - | backlog drains within a few ticks |
| control message / close | 1 unit | ~200 B | proofs cost 0 units (they keep their place in the FIFO) |
| Channel waits | 1,2,2,3,5 ticks at SRTT ≈ 0 | `calculate_timeout`: 100,150,225,337,506 ms | `Wait(k,b)` = b·1.5^(k−1) rounded; base = max(1, ⌈2.5·SRTT⌉) |
| `MaxTries` | 5 | `CHANNEL_MAX_TRIES` = 5 | |
| `HeldCap` | 20 | `CHANNEL_HELD_RETRY_MAX_MS` = 2 s | |
| `Stale` | 100 (40 in the dead-peer runs) | `stale_time_ms` = 2 × keepalive (5 s min) = 10 s | |
| `SrttCap8` | 17 eighths = 2.1 ticks (6 with Stale 40) | `srtt_cap_ms` = 216.7 ms at a 10 s bound | the span at the cap stays within the stale bound |
| `WatchEvery` | 2 | `WATCH_TICK` = 250 ms | 3 is one scenario |
| `StallTicks`, `StallLegs` | 4, 2 | `UPLINK_STALL_MS` = 400, `UPLINK_STALL_LEGS` = 2 | |
| `Latch` | 20 | `UPLINK_STALL_LATCH_MS` = 2 s (calls2 WIP) | |
| `WindowTicks` | 10 | `meter_window_ms` = 1 s | |
| `OfferEvery`, `StallOfferEvery` | 10, 50 | 1 s, 5 s | |
| `RelaySlots` | 1 | a relay's cold-start trial slot (one stream) | it doubles after 2 clean windows in code; held at 1 here |
| `DrainTicks` | 50 | `down_silence_ms` = 5 s | |
| `RxDelayTicks` | 3 | - (proposed: 300 ms of media delay seen by a child) | ReceiverMoves |
| `QTarget` | 5 | - (500 ms) | EndQueueDrained; RFC 8298's target is 50–100 ms, this bound is looser on purpose |
| `Horizon` | 230 (200 for the conformance runs) | - | the cap holds 10..49 unless stated |
| `Dwell` (s) | 20 | `min_dwell_ms` = 10 s | hides: a voluntary move back to P is 5× sooner than in code |
| `CeilingStale` (s) | 20 | `CEILING_STALE_MS` = 60 s | hides: full fan-out returns 30× sooner than in code |
| `DialMin`/`DialMax` | 10/80 | 1 s / 8 s | |
| re-punch time | {10, 30} ticks | 1–3 s (brief) | |
| `Backoff` | 5 | `backoff_base_ms` = 500 ms (×4 after a shed) | |

## Abstractions, and what each can hide

1. **Synchronous ticks, a fixed phase order.** *Known race this hides* (found in code, RM2b): two listeners making late moves toward each other at the same instant. In the model one completes before the other evaluates, so no loop forms. Each tick runs, in order: Channel timers; stale; redial; watch (P, then each listener); the egress window; offers; publish; drain. Delivery from the FIFO is at the end of the tick, and its answers are handled in the same tick.
   - *Sound because* every timer in the code is at least 50 ms (`CHANNEL_HELD_DRAIN_POLL_MS`) and the decisions under test are 100 ms or longer apart.
   - *Hides:* races inside 100 ms. Two examples: a shed and a teardown in the same 100 ms run in phase order; so do a proof and its timer at the same instant (the proof wins, as delivery precedes the next tick's timers).
2. **Uncapped hops take zero time.** On loopback and LAN the RTT is milliseconds, below the 100 ms RTO floor.
   - *Hides:* RTT growth on the listeners' own uplinks (none is capped in the measured runs).
3. **No loss, no reordering.** Only delay. That is the measured case.
   - *Hides:* the loss path of the retry budget. A lost message's retries are exactly the ones modelled; they just never get a late proof.
4. **The Channel window is not modelled; it is never full.** At an RTT below `CHANNEL_RTT_FAST_MS` (180 ms) the window floor is 16 (`update_window_for_rtt`). Control at ~1 Hz per leg never reaches it.
   - *Hides:* `Busy` refusals (the mechanism of F8). It also hides the window's own dynamics: the decrement per timeout, and the give-back of the decrements a spurious retransmit cost.
   - The review's rule is that the give-back is clamped to the window before the loss, so a link that just drained is not re-flooded. That rule is NOT checked here. A model with the window would need it as a state variable per leg, with the clamp as a guard on the give-back.
5. **Link setup is instant.** A redial that is due and whose path is up succeeds in the same tick, with a fresh Channel (SRTT 0, no authenticated inbound).
   - *Hides:* a handshake that itself queues behind P's backlog (F6's "no route to peer" is folded into the re-punch time).
6. **One stream.** Only P publishes, as in `a_capped_publisher_sheds_to_one_child_and_the_rest_are_relayed`. So P relays nothing and has no shares or standbys.
   - *Consequence:* the code's "room eaten by other commitments" cannot arise from state here. It is modelled as a choice instead (abstraction 7).
7. **The room left by a shed (RoomKeepsOne off) is a choice of 0 or 1.** In code the own stream's limit is `committable − reserve − external` (`admission.rs:456`). `external` is everything else this node committed (relayed streams, shares, standbys; `alm.rs:1149`), so the room can be zero.
   - *Sound as* an over-approximation: it allows the measured zero-children outcome (F4) and the one-child outcome.
8. **Selector scoring is abstracted.** It is P first (`direct_first`); otherwise any viable relay, chosen among the first `NPick` in a fixed order. Viable means: offered within `DownSilence` with forwarding and room, both legs up, not backed off, and not a descendant. That is an over-approximation of the scored pick within `PICK_BAND`.
   - *Silence failover is not modelled.* With `idle_aware_silence` a listener that hears nothing on any path treats the stream as idle, not its parent as dead (`selector.rs` tick). So a listener whose only parent went silent waits for a shed notice or a link close. That is exactly what the model does.
   - *Voluntary switches.* The model keeps only the move back to P after the dwell, when P's offer shows room. The 1.2× hysteresis over `hysteresis_hold_windows` is folded into "P has room".
9. **The egress meter is blind on datagram legs** (`path_meter.rs:402`). A window is congested iff the stall verdict holds. The only growth signals are demand (a refused subscribe) and a ceiling gone stale.
10. **Heard counts distinct publish ticks per listener, published WHILE CAPPED** (`[CapAt, min(CapUntil, Horizon − TailTicks)]`), deduplicated like the frame stream (a tick older than the newest one heard is dropped).
    - With a 4 s cap, a 1.4 s gap costs ~35 % of heard. The edge test caps for 30 s. So heard figures are reported both for the 4 s cap and with the cap held (20 s), and the held figure is the one to compare with the test's 70 %.
    - *Hides:* the reorder window's own drops (CIRISEdge#931).
11. **Media granularity.** One FIFO item carries one tick (100 ms, ~3 frames) of P's media for its children. A child's media therefore leaves the queue in tick-sized pieces.
    - At 2.25× those pieces are ~2.25 ticks apart per child, so a silence threshold of 3 ticks can be crossed by lateness alone. Real frames interleave ~75 ms apart.
    - *Hides / distorts:* silence-based rules with thresholds of 300 ms or less. That is why the SilenceFailover result at 300 ms and 2.25× is set aside as an artifact (see Results).
12. **Adversaries.** `ReplayAttack`: after the dead node dies, an on-path party replays a recorded Channel frame (seq 0) and a media tick on every leg from it. They decrypt; the link has no replay protection. `DelayProofs`: an on-path party withholds every proof `DelayVictim` emits during `[AdvFrom, AdvTo)`. Withholding for longer than the retry ladder is, for timing, the same as delaying.
    - *Not modelled:* forging (all frames are authentic) and dropping media.
13. **Liveness on a bounded run.** Time stops at `Horizon`, and the last state stutters. So "eventually" means "by the horizon", and each liveness property is also stated as a terminal-state check with its bound (`End*`).
    - *Hides:* anything after the horizon. Every bound is stated with its property.

## The switches

All switches are FALSE in the baseline, which is the code before any of today's fixes. The pins measured today are:

- `pin-c8699c3d6`: Hold113 on.
- `pin-c75fdeb01`: Hold113 and ReceiptsPerAttempt on.
- `pin-c75fdeb01+edge-wip`: also ShedOnVerdict and RoomKeepsOne, as calls2's uncommitted `alm.rs` does them.

| Switch | What it changes in the model | Code (where it is or will be) |
|---|---|---|
| `ReceiptsPerAttempt` | A proof for any attempt of an outstanding message confirms it. Off: only the latest attempt's receipt exists, and an earlier attempt's proof is dropped unauthenticated. | leviculum c75fdeb01: `ReceiptTracker::register` link_management.rs:198 keeps every attempt (was: replace) |
| `RtoLearnsDelay` | Every valid proof is an RTT sample against the send time of the attempt it names: EWMA 1/8, capped at `SrttCap8`. Off: Karn, a sample only from a first-try message. | leviculum WIP (lev2, uncommitted): `Channel::mark_delivered_attempt` channel/mod.rs ~984, `srtt_cap_ms` ~1054; today Karn at `mark_delivered` channel/mod.rs:887 |
| `Hold113` | At the 5th timeout the leg is held while an authenticated packet arrived after the message's first send, up to `Stale` from that first send. | leviculum 206734977: `poll_with_inbound` channel/mod.rs:1034-1036 |
| `ShedOnVerdict` | Shed at once on the verdict's rise, with the verdict latched `Latch` past its last detection. Off: the verdict only sets a flag, and the next egress window sheds. | calls2 WIP `alm.rs` `set_uplink_stall` / `fold_egress_window`; today `alm.rs:382` (flag) + `alm.rs:1588-1596` (window) |
| `RoomKeepsOne` | A shed keeps exactly one direct child. Off: 0 or 1 (abstraction 7). | calls2 WIP: own room = one + reserve + external; today `alm.rs:1591-1611` + `admission.rs:456` |
| `SlowStart` | P's first room is `InitFanout` (1). After two clean windows since the last congestion and the last widening, it widens by one stream (the probe is the widening; a stall or a late move takes it back). One stream a window at most. Off: the room is the whole room (`PUBLISHER_INITIAL_FANOUT` = 8), and it grows only on demand or when the ceiling goes stale. | missing; today `alm.rs:322-323` |
| `RedialOnPathUp` | A torn leg redials the tick its path is back. Off: on the 1→8 s doubling backoff. | missing on the leg; today `av_call.rs:4276-4283`; the path release is `direct_path.rs:913` |
| `ShedDrains` | A shed child is fed for `DrainTicks` or until it unsubscribes (make-before-break). Off: the stall shed removes it from the ledger and P stops at once. | missing for the stall shed: `admission.rs:905-914` removes without a drain; `shed_all_draining` `admission.rs:396` is the drained form (relay-off, tier 2) |
| `PeerLiveness` | The hold (C3) counts an authenticated packet from the same peer on any leg: the peer's own leg's frames and datagrams, which decrypt under that leg's key, as well as this leg's proofs. | missing in leviculum (#113 option (a)); today the per-link `last_authenticated_inbound_ms` (channel/mod.rs:1034) |
| `ReceiverMoves` | A child of P that is not P's first child, and that sees P's media arrive `RxDelayTicks` (300 ms) or more after it was sent, moves itself to a relay, keeping P until the relay admits. Its unsubscribe says "late" (`unsub_late`). P reads that as congestion: room = its current children, `lastCong` = now, and the probe backoff steps up. Any widening (P6's demand step, or the SlowStart probe) waits 2 windows × 2^fails, fails ≤ 2, stepping down after each widening that held. | missing in edge. The delay is readable: `on_chunk` carries `source_ms` (alm.rs). The rank of P's first child is a wire addition to the Admit. |
| `ProbeBackoff` | Any widening (the demand step P6, the SlowStart probe) waits 2 windows × 2^fails since the last congestion or widening. `fails` counts late moves (N3), at most 2, and steps down after each widening that held. | missing (admission.rs:854-875 widens on demand with no backoff) |
| `HashRank` | P keeps, and the receivers spare, the lowest-ranked child by an order every member computes (hash of stream id and child key: `RankSeq`, deliberately unlike the join order). This replaces "oldest admitted" plus a rank in the Admit. | missing; no wire change |
| `SerialRedial` | While P's verdict holds: one P leg's setup per `SetupGap`; a listener heard through a relay defers its legs with P. | missing (av_call.rs:4253 dials every member at once) |
| `StaggeredSetup`, `SetupUnits` | P's side of a leg's setup costs `SetupUnits` of P's queue (40 ≈ 1 s at the cap: F11), at the start and on every redial. Staggered: one P leg per 3 ticks at the start. | the cost is real today (F11); staggering is missing |
| `ProbeTwoLegs` | Every 200 ms P sends a small control frame on at most two live legs with nothing unproved, so the verdict never waits for an offer (F10). | missing |
| `SilenceFailover`, `SilentTicks` | A child whose primary delivered nothing for 300 / 500 ms moves to a member that offers. | the code's silence suspicion is idle-aware (selector.rs tick); evaluated here as proposed |
| `StallDrain`, `DrainPct` | While the verdict holds, P's copies are 25 / 50 / 75 % of a copy (a base layer, or audio). | `legs_shed_to_base` (C5) exists for other causes; not wired to the stall |
| `FreshEvidence` | Evidence is only a packet that advances state: a Channel frame with a new sequence, a proof for an outstanding receipt, a new media tick. | leviculum review (being built) |
| `ConditionalRto` | The learned SRTT sets the waits of a message only if fresh evidence arrived after its first send; otherwise the cold ladder. | leviculum review (being built) |
| `ReplayAttack`, `DelayProofs` (adversary) | See abstraction 12. | - |
| `CloseLost` (environment) | A LINKCLOSE never reaches the peer, which learns only by the stale bound. | CIRISEdge#1030 |

## Properties

The safety properties are checked at every state. The model folds them into `bad`, which is read at the terminal states.

| Property | Statement |
|---|---|
| `NoSpuriousTeardown` | No leg is torn down `exhausted` (or goes `stale`) while its peer is alive. Every peer here is reachable. |
| `KeepsOneChild` | No shed leaves P with zero direct children when it had any. |
| `NeverTwoParents` | A listener sits in two forwarders' ledgers for at most 2 ticks plus P's queue delay. The parent variable is single-valued by construction. This is the ledger form. |
| `MakeBeforeBreak` (voluntary) | A child P shed, while its leg is up, is still fed by P until it has moved. **It applies to a voluntary shed** (relaying turned off, a window rebalance), where P has headroom to keep feeding. The model has no voluntary shed: relay-off and rebalancing are not modelled, so for every configuration here the property only ever meets stall sheds. Its "violations" in the results are stall sheds and are read as such. |
| `StallShedGap` | A child a STALL shed removed has a parent again within `GapBound` (1.5 s). **Why the split:** a stall shed exists to cut load now. Feeding the shed children until they move is the load that kills the links, and their media was already late. So the obligation is a bounded gap, not continuity. |
| `NoIdleWithOffer` | No listener sits with no parent and nothing pending while a viable member offers, for more than two watch ticks (a refused subscribe costs one watch tick before the next candidate is tried). |
| `NothingWaitsForever` | Every Channel message is proved, or its leg torn, within `Stale + HeldCap + Wait(5, cap)`. |
| `ReparentBound` | At most `MaxReparents` re-parentings per listener: the join, the move to a relay, the move back after a lift, and two per probe. With the probe backoff at most ⌊log₂(H/2W)⌋+1 probes fit in a horizon H, so the bound is 3 + 2·(⌊log₂(H/20)⌋+1) (11 at H = 230). A bound logarithmic in the call's length is what "no oscillation" means here. |
| `EndParented` | At the horizon every live listener has a parent. |
| `EndHeard` | At the horizon every live listener heard at least 70 % of what P published in the window. |
| `EndFullFanOut` | `RecoverBy` ticks after the cap lifts, every live listener's parent is P. `RecoverBy` is stated per configuration: the latch (20) + a window (10) + the dwell (20) + a window (10) + the widenings. With SlowStart and the backoff, the widenings are 2W·4 + 2W·2 = 120; without SlowStart, the ceiling staleness (20). That gives 180 or 80 ticks at N=4. In code scale: about 2 + 1 + 10 + 1 + 8 + 4 ≈ 26 s with SlowStart, and about 60 + 10 + 4 ≈ 74 s without (the real dwell and staleness). |
| `EndQueueDrained` | At the end, P's queue delay is at most `QTarget` (500 ms), unless a widening is less than `Dwell` + 4 windows old (a probe still playing out). |
| `DeadDetected` | After a node dies, every leg toward it is down at the live dialer within `DialerDeadBound`, and every leg from it is down at the live receiver within the stale bound (+2). `DialerDeadBound` is the cold ladder when `ConditionalRto` is on: an offer period + 13 ticks + a watch tick, today's time (#1030). Without it, the ladder at the learned SRTT cap. The scenarios kill the node right after a queueing episode, with SRTT at its cap. |

Terminal outcomes (the `Outcome` probe):

| Outcome | Meaning | Acceptable? |
|---|---|---|
| `FullFanOut` | Everyone on P | yes |
| `Relayed(direct=k)` | k ≥ 1 on P, the rest on relays, everyone heard ≥ 70 % | yes while the cap holds; after a lift only within `RecoverBy` |
| `Starved` | Everyone has a parent, but someone heard < 70 % | no |
| `Stranded` | Someone has no parent at the end | no |
| `Collapsed` | A live peer's leg was torn down `exhausted` | no |

There is no TLC deadlock: `Tick` is enabled until the horizon. A halting state in the protocol sense would show up as `Stranded` (a listener with no candidate and nothing pending), or as a violation of `NothingWaitsForever` (a message waiting forever).

## Results

The final run is in `results/` (`matrix.json`, `matrix.md`, `quality.md`). The tables below are generated from those files: `run_matrix.py OUTDIR --reparse` and `summarise.py OUTDIR`.

- **Reachability, not likelihood.** Every figure is over all reachable behaviours of the scenario: every offer phase of P (10), the listeners' phase, the window phase, the room a shed leaves, the tie-break and the re-punch time.
- **Tick and run length.** A tick is 100 ms. The cap holds 1–5 s (ticks 10–49) unless a row says "cap held"; the horizon is 26 s.

### The findings, in the order they were found

- **R1 — the baseline reproduces F1 and F2 (and F9).** The cap lands at t=10. P's offer of t=13 is retried at 14, 16, 18 and 21. Without per-attempt receipts every proof answers a replaced receipt and is dropped. P's three legs are torn `exhausted` at t=26, 1.6 s after the cap, with P alive. The listeners' legs toward P die at 2.3 s: their proofs leave through P's queue (F9).
  - Over all phases (summarise): the verdict at 0.6 / 1.0 / 1.6 s; the window shed at 1.0 / 1.5 / 2.0 s, with 1.5 / 2.1 / 2.9 s of queue at the shed (F10's 0.9–2.2 s).
  - With setup cost (`baseline-setup`), teardowns add redials whose setups refill the queue (F11): peak queue up to 8.2 s against 3.3 s without. The reachable cycle is teardown → redial → deeper queue → more teardowns.
- **R2 — a late shed cannot save the links by itself.** After a shed to one child, a 1.33-copy uplink drains at only cap − one copy (− control). A backlog past ~1.2 s therefore outlives the retry ladder for seconds.
- **R3 — the #113 hold rarely fires on call legs.** Legs are one-way. The only authenticated inbound on P>A is proofs. At ~1 Hz control, the proof of the previous message has come back before the stuck one is sent, unless the queue is already longer than the offer interval.
- **R4 — the six switches of the brief are not enough** (six-on: Collapsed or Starved). The proofs that RTO learning and the hold need ride the queue they should measure. When the cap lands just after P's offer timer, no sample arrives before the 1.3 s ladder runs out, and the shed notice and the drain ride the same queue.
- **R5 — what the model found missing:**
  1. **PeerLiveness** (leviculum PeerEvidenceHold): evidence from the same peer on any leg.
  2. **ReceiverMoves**: a late child moves itself; its unsubscribe beats P's queue.
  3. **The late departure as a congestion signal.**
  4. **ProbeBackoff**: without it the model oscillates (probe → return → late → leave).
  - With these, every property holds (`all-on`, `cap-stays-all-on`).
- **R6 — SlowStart helps only a call that starts capped.** It costs recovery time after a lift (bounded by the backoff, stated in EndFullFanOut).
- **R7 — the minimum safety set.** PeerLiveness + ShedOnVerdict + RoomKeepsOne + ProbeBackoff + SerialRedial, plus FreshEvidence + ConditionalRto and the receipts and hold already in leviculum, has no spurious teardown and never loses its last child. Its leave-one-outs show which switch carries each property.
  - It misses the stall-shed gap and the quality bound: the shed notice rides P's queue, and after the shed one copy plus control and held retransmits nearly fill the cap.
- **R8 — the stall-shed gap tracks the queue at the shed.** Gap ≈ q_at_shed + the kept child's next offer + a subscribe round trip. On the minimum set that is 1.2 / 2.1 / 3.2 s at 2.25×.
  - SilenceFailover gives nothing. In a FIFO the media queued for a victim before the shed is ahead of its notice, so silence starts when the notice comes out.
  - StallDrain clears the queue faster but does not shorten the gap.
  - ProbeTwoLegs bounds the verdict (0.6 s) and meets the bound at 1.8×, but not at 2.25×.
  - Only ReceiverMoves on the hash rank meets gap < 1.5 s and heard > 70 % at 2.25×, 1.8× and 1.5×.
- **R9 — FreshEvidence requires per-attempt receipts.** Without them, a shed child's leg toward P has no fresh evidence (P sends it no media, P's offers are held to 5 s, retransmits don't count), and the collapse is back (`min-without-receipts`, `cap-stays-min-without-receipts`).
- **R10 — dead-peer detection = the longest gap between this node's Channel messages on the leg + the cold ladder.** With the stall hold-back on P's offers that gap is 5 s, so P's legs to a peer that died during a latched verdict are detected later than the tight bound (`dead-after-queue-min`). The shipping set mostly never latches the verdict and holds the bound.
  - Replay cannot hold a link under FreshEvidence (`replay-dead-B-min`); it can without (`replay-dead-B-min-stale-evidence`).
  - Withholding proofs cannot tear down a link whose peer is visibly alive under PeerLiveness (`delay-proofs-A-ship`); it can without (`delay-proofs-A-no-peer`).
- **R11 — the shipping set** is the minimum set + ReceiverMoves on the hash rank (scope from offers) + DepartureHolds + OwnDownlinkGuard + SlowStart (probe 2, 10 s hold).
  - Heard ≥ 99 % with the cap held at 2.25×, 1.8× and 1.5×; peak queue ≤ 0.6 s; no teardown; no oscillation.
  - Full fan-out after a lift within the stated bound: un-scaled, latch 2 s + window 1 s + the climb from one stream (max(10 s hold, 8 s backoff) + 4 s) + dwell 10 s + window 1 s ≈ 28 s.
- **R12 — RM4 scopes.** Neither variant ever drained P to zero at N=4. Sparing the lowest-ranked MEMBER is safe here only by timing: the first mover's unsubscribe shrinks P's queue before the next one judges. Sparing the lowest-ranked of P's direct children as the members' offers show them (`offer`) is safe by construction, and needs no wire change.
- **R14 — F12: a standby fed a full copy keeps P at two copies after a stall shed.** Standby feeding is `none` / `full` (today's contract, alm.rs:31-32) / `fix` (under a latched verdict a standby gets nothing, a stall shed leaves no standby, a shed never takes the last primary) / `fix2` (`fix`, and a LATE move never leaves P a standby).
  - `full` reproduces F12 in the test configuration: the queue never drains (13–26 s), every state collapses, and P ends with no primary while a standby remains.
  - `fix` restores the test configuration but not the shipping set: a late mover keeps P as its standby, and the verdict rarely latches there.
  - `fix2` restores the shipping set exactly.
  - Cost when the kept child dies mid-stall: `full` reaches 5 % heard and a 19.6 s parent gap; `fix`/`fix2` reach 67 / 82 / 91 % heard and a 1.4 / 2.4 / 6.6 s gap. The tail is D1: P's offers held to 5 s.
- **R15 — F13: a periodic control burst is a congestion source of its own.** The 10 s re-announce reproduces F13's growth: peak 17–39 s, heard 43 %, collapse.
  - Skipping backlogged legs does not help: the first burst lands on a clear uplink, and that one burst (≈ 3 s at the cap) is in front of everything P sends.
  - Expiry alone does not help either.
  - Pacing the parts at 0.5–0.9 s, with expiry and the skip, keeps every leg up with heard 100 % and a peak of 0.9–1.8 s.
  - Rule B1: no periodic burst may add more than about one ladder of queue. Every per-leg periodic control message not modelled (keepalives, CAPS, MTU probes, attendance, identity-link traffic) has the same shape.
- **R16 — F14: a leg must never carry nothing periodic.**
  - Under FreshEvidence + ConditionalRto, a silent listener's leg toward P carries none of its own traffic. When P also holds its control back (latched verdict), P's next message on its leg to that listener has no evidence after its first send and runs the cold ladder into the queue. In the test configuration that collapses 16/112.
  - KeepFresh (≥ 1 fresh message per second on each leg, both sides) removes every teardown.
  - After the kept child is lost, the plain failover (own leg torn ⇒ parent lost) recovers in every state.
  - The literal "no new media on any path ⇒ re-subscribe" rule strands a listener in 80/160. Its mechanism is not fully traced; an orphan relay commitment was tested and ruled out.
- **R17 — the last queue term is control.**
  - **The budget.** With one copy at a 1.33-copy cap, P's other control must stay below about ¼ of the leftover for the queue to drain (B2).
  - **The kill of P's only direct child.** It recovers in 0.6–1.2 s in the shipping configuration: the child fails over on its own torn leg (T1), and a grandchild recovers through it.
  - **UpstreamShed makes recovery slower** (0.4–2.8 s) and is not recommended.
  - **A relay without a parent sends its children nothing**, so D1b must cover relays too.
  - **Moves in flight at the horizon** are not strands; EndParented allows a move begun within the gap bound.
- **R18 — ProbeAfterDrain** (dwell 10 s and ceiling 60 s at the code's values; 2.25×; all phases).
  - **Without it** the lift misses the 35 s come-back bound in 160/160: the stale ceiling reopens only after 60 s.
  - **With it** (`DrainHold` 0.2, 1, 5 or 15 s): the cap lifting gives FullFanOut 160/160, and the cap held gives the capped fan-out (direct = 1, or 2 while a probe is in flight).
  - Every property holds: ParentedThroughout, OneJoinAtATime, ReparentBound, NoSpuriousTeardown, EndQueueDrained; no stall shed in either.
  - **No minimum hold relative to the dwell is needed** for these properties. The hold only adds to the come-back time (bound = latch + window + hold + (n−1)·max(dwell, backoff) + dwell + window).
  - **Without the backoff** (cap held) probes cause stall sheds (up to 2 in 46 s) at the dwell's rate.
  - **Probes are not geometrically rarer** once the backoff (2 windows × 2^fails, fails ≤ 2 = 8 s) is shorter than the dwell (10 s). Then the dwell sets a CONSTANT probe rate under a permanent cap: one probe per ~10 s, each costing one listener two moves, so re-parentings grow linearly with the call's length. Raise the fails cap so that 2W·2^fails can pass the dwell (e.g. ≤ 6 → 128 s) if geometric rarity is wanted.
- **R19 — ADMITs set aside, and the brief parentless spell.**
  - No ignored ADMIT is reachable in the model in any configuration checked (`admits_ignored` = 0 throughout).
  - The brief parentless spell during the cap is reachable (0.3–1.3 s, under the 1.5 s gap bound): it is the stall-shed notice gap (R8).
  - Rules in the code that could set an ADMIT aside and are NOT modelled:
    1. the selector's down hold (`down_hold_ms` 15 s) on a candidate that answers after being marked Down;
    2. the descendant guard reading a stale offer's ancestry (offer loss, RM4b);
    3. a subscribe timeout shorter than the admitting parent's queue delay. In the model a subscribe to a congested P is refused, not admitted, so this never fired.
- **R20 — S3 narrowed, and re-opening after congestion** (no ReceiverMoves so that sheds occur; uncapped headroom 80 units; 2.25×; all phases).
  - **S3.** "Ask after loss" gives FullFanOut 160/160 when the cap lifts, every listener parented throughout, and kill recovery in 0.4 / 0.8 / 1.2 s with heard ≥ 94 %. "Ask after shed" starves 128/160 when the cap lifts (worst listener heard 37 %) and breaks ParentedThroughout with the cap held.
  - **The post-lift over-growth shed (NoShedAfterLift) was NOT reproduced** under either variant. Growth in the model is bounded by the room (≤ N) and by the backoff, so refusals counted as demand never grow P past the uncapped capacity.
  - **Refusal as demand.** With nobody relaying, the first-refusal fast path admits the third child at 0.6 / 1.4 / 1.6 s with every property holding, but it starves 60/160 in the mid-call cap case. The repeat-ask trigger keeps the cap case whole (160/160) but admits the third child only at 1.8 / 2.6 / 3.6 s, parentless up to 3.5 s.
  - **Why the repeat ask arrives late:** a member with no candidate never asks P again in the model. The code's 2 s bridge renewal (or an R3-style ask) is not modelled.
  - **The guard's three conditions changed nothing measurable here.** Demand growth in the model already waits out the backoff and the stall hold. In code, demand growth has no backoff (N4 missing), which is where the guard earns its keep.
  - **Unexplained:** in the kill case EgressOneCopy and NeverDrained fire after the kill (no teardown, every listener parented). Not traced.
- **R21 — SU, the silence drop, the bridge, and the after-kill invariants.**
  - **The tree.** C on P; A and B on C, each the other's standby. P starves C silently for 3 s with the cap on from the start, and A and B lose C by silence at the same watch tick.
  - **Without SU** they promote each other: a loop (LoopFree violated). With SU the loop is impossible.
  - **Both variants first stranded listeners** (48–56/160, parentless up to 18.5 s). The cause is not SU: a silence drop did not unsubscribe the old parent, so P kept the starved C as its only child and refused everyone. With SD:
    - SU off: still loops, no strand;
    - SU on: no loop, every listener parented at the end, parentless up to 1.7 s;
    - SU on + the 2 s bridge: parentless 0.1 / 0.7 / 1.3 s, within the bound.
  - **SU strands no one** once someone re-offers; the 1 Hz offers end every exclusion within a second.
  - **RO (i) with the bridge.** When nobody relays, the third child is in at 0.8 / 1.6 / 2.0 s (parentless up to 1.9 s). In the mid-call cap case the bridge's repeat asks trigger the never-congested fast path before the cap lands, and 34/160 starve. Keeping (i) and the mid-call cap case both needs the fast path to stop once any relay exists, or a start-up phase the cap can't overlap.
  - **The after-kill EgressOneCopy / NeverDrained were model gaps.** The verdict's rise clamped the room only when something was shed, so a later subscribe was admitted under a latched verdict; the window fold in code reads one stream at the rise. And NeverDrained did not exempt the kill. Both are fixed; the kill case now holds them.
- **R22 — the combined re-open rule with several admissions on one uplink.** P relays two other streams' copies from 6 s (the cap lifts at 5 s); 2.25×; dwell 10 s and ceiling 60 s at the code's values; all phases.
  - **Today's paths:** demand set on every refusal and never ageing; the over-committed shed with no verdict; the clean-window raise; fails ≤ 2. The post-lift shed with no cap reproduces: a shed at 17.5 s with no cap, P left with no direct child (KeepsOneChild, NoShedAfterLift, NeverDrained violated). The same configuration without the relayed streams holds them, so the cause is the external commitment, as found in code.
  - **The combined rule holds** NoShedAfterLift, KeepsOneChild, ParentedThroughout and NoSpuriousTeardown.
    - Full fan-out returns at 17.6 / 23.6 / 25.0 s from the start, i.e. 12.6–20 s after the lift. Without the clean-window raise it is 23.4 / 24.6 / 25.0 s.
    - With the raise, OneJoinAtATime fails: it reopens room for several children in one tick.
  - **(6) alone** (no relayed load, no over-commit shed) raises the ceiling to what the drain carried (6 copies, the uncapped capacity) and causes no shed. In the model it cannot over-grow past capacity, because a window can only carry what the uplink drains. It would over-grow only where a drain burst exceeds the sustained rate (a router token bucket), which is not modelled. Its real cost here is the simultaneous rejoin.
  - **Nobody relays, under the combined rule:** the third child is in at 2.2 / 3.0 / 3.6 s, parentless up to 3.5 s. The never-congested two-clean-window path misses the 1.5 s gap bound.
  - **Capped with relays (cap held 46 s):** direct = 1, heard ≥ 99 %, parentless ≤ 1.1 s, no teardown, ≤ 3 stall sheds.
  - **Geometrically rarer probes are NOT demonstrated within 46 s.** The verdict rises (≤ 9) are identical with fails ≤ 2 and fails ≤ 6, and fails reached 3. So the rises in that window are not probe-driven.
  - **The cap held with relayed load could not be checked:** the relayed copies are a fixed load in the model (not shed under a verdict), so the queue grows without bound and TLC ran out of memory.
- **R23 — the ruled fail count.** Reduced configuration: three people, one phase, a cap 0.05 copy below the two-copy step, 260 s.
  - **The model does not reproduce the code's slow-failing step.** Its steps fail in 0.6 s, with ReceiverMoves (the 300 ms lateness) and with the stall verdict alone. The 1→2→1→0 forgiveness cycle (a step forgiven at the dwell because it fails after ~35 s) therefore does not arise. Under a held cap, the old rule and FR then give the same geometric probes: 17, 23, 39, 71 s; ≤ 6 sheds in 260 s; heard ≥ 98 %; parentless ≤ 0.1 s. No oscillation.
  - **The factor in rule (2).** k = 0 (forgive after the backoff alone) gives a constant 17 s probe rate for 260 s (15 sheds, ReparentBound violated). k = 1, 2, 4 are identical here, because the time-to-fail (0.6 s) is far below the backoff. Whether "2 ×" matters, as against any k > 1, depends on steps that fail slower than the dwell, which the model has not produced.
  - **Lift with drain evidence** (backlog 27 units at the lift): FR resets the count, and full fan-out returns at once (0 s).
  - **Lift without drain evidence** (nothing queued): the return inherits the count and takes 6.4–57.4 s depending on where in the backoff the lift lands, for the old rule and FR alike (FR's count is one lower).
  - The step fix (no compounding on unused room) changed nothing visible here.
- **R13 — an overshoot at 1.5×.** With one sample per watch tick, a second child still reads late 200 ms after the first one left, before the queue has drained. So two leave where one would do, and the climb back costs one more widening. The rule should judge on a sustained, non-falling reading (decision row RM2).

## The 45.3 rules (R24–R29)

The 45.3 call-reliability rules as built on `work/45.3` (edge 6392b0a) are each checked by their own small spec in `rules_453/`, not folded into `CallCongestion.tla`. Each spec carries the code lines it models in its header.

- **Files.** `OfferAsLife.tla` and `RelayAdvert.tla` (R29), `SendClock.tla` (R24), `UplinkBacklog.tla` (R25), `StaleAtSender.tla` (R26), `AgeFloor.tla` (R27), `EgressBudget.tla` (R28). `run_rules.py` is the runner and `rows_453.py` holds the R24–R28 scenarios.
- **How to run.** `python3 docs/design/call_congestion/rules_453/run_rules.py OUTDIR --split [--only REGEX]`. `--split` runs each invariant alone, because with `-continue` a state that breaks two invariants is reported under the first only.
- **The scheduler.** The same convention as `run_matrix.py`: `GRACE_SCHED_*` + `cargo_guard.sh` at priority low, nice 19, idle I/O class, `-Xmx2g`, 2 workers, declared peak 3 GB. Grace measured peaks of 0.78–1.7 GB.
- **Tick.** One step is one watch tick (250 ms) unless a row says otherwise. Every timer is an age in ticks, capped, so most specs need no horizon.

In the tables, "states / distinct / depth" are TLC's figures for that run. A failing run's figures are those at the first violation.

### R29 OFFER-AS-LIFE

**Rule.** A child does not charge a parent's silence while that parent's offer is < 2.5 s old, it is forwarding, and its upstream latency is > 800 ms. Excused time is nobody's silence: once the excuse ends, the parent owes chunks under the unchanged silence bound. A relay advertises ≥ its parent's latency + RTT/2, and ≥ the age of the chunks it dropped as stale in the last 2.5 s.

**The model.** One publisher, one relay under test, one child. Life = 10 ticks; down_silence = 20; suspect = 6. The relay is at depth 1, so 9 ticks of silence make it Suspected (`selector.rs:1390`, `peer_state.rs:127-133`), and a Suspected primary is failed over (`selector.rs:1500-1503`). The publisher's backlog runs 0–12 ticks (3 s) and moves at most one tick a tick. Its backlog stamps wait in its own uplink FIFO, so a stamp reaches the relay as old as the backlog it declares. One offer in a row may be lost.

There are four relay kinds:
- **honest:** forwards fresh media and claims late exactly when the publisher's last word is late;
- **liar:** offers every second claiming late, and sends nothing;
- **black hole:** offers on time and sends nothing;
- **gone:** its offers and media stop at some point.

There are three rules for the excuse:
- **current:** `selector.rs:1342-1344`, the relay's own unsigned claim;
- **signed_pubage:** the excuse needs the publisher's signed backlog stamp, relayed unaltered, no older than 2.5 s;
- **signed:** as signed_pubage, but the stamp's age is judged net of the backlog it declares (age − b ≤ 2.5 s).

`gs` means the first-chunk grace (`selector.rs:1382-1389`) also comes from the stamp.

| Run | Checks | States / distinct / depth | Result |
|---|---|---|---|
| liar-ontime-current | LiarFailsOver (◇ failover), publisher never late | 951 / 339 / – | **FAIL** (lasso) |
| liar-ontime-current | LiarHeldTotal (held < down_silence) | 394 / 149 / 21 | **FAIL** |
| liar-late-current | LiarAfterCalm (held ≤ Life + down after the publisher's last real backlog) | 64,721 / 22,675 / 32 | **FAIL** |
| liar-late-current | LiarWithinDown | 223,123 / 72,062 / 56 | pass (vacuous: the liar is never unexcused) |
| liar-ontime-signed | LiarFailsOver | 621 / 227 / 30 | pass |
| liar-ontime-signed | LiarHeldTotal | 394 / 149 / 21 | **FAIL** |
| liar-late-signed | LiarWithinDown, LiarAfterCalm | 106,633 / 38,057 / 37; 121,167 / 41,453 / 38 | **FAIL**, **FAIL** |
| liar-ontime-signed-gs | LiarHeldTotal, LiarFailsOver | 171 / 67 / 10 | pass, pass |
| liar-late-signed-gs | LiarWithinDown, LiarAfterCalm | 140,956 / 47,468 / 44 | pass, pass |
| honest-current | NeverFailsOver, NotChargedAtOnce | 252,837 / 83,463 / 49 | pass |
| honest-signed-gs | NeverFailsOver, NotChargedAtOnce | 252,837 / 83,463 / 49 | pass |
| honest-signed_pubage-gs | NeverFailsOver | 614,349 / 207,717 / 53 | **FAIL** |
| honest-signed_pubage-gs, backlog ≤ 2 s | NeverFailsOver | 539,444 / 179,622 / 53 | pass |
| gone-current / -signed_pubage-gs / -signed-gs | OffersStopBound (≤ 2.5 s + down_silence), NotChargedAtOnce | 14.79 M / 5.24 M / 49; 15.18 M / 5.45 M / 53; 14.79 M / 5.24 M / 49 | pass |
| blackhole-current | BlackHoleBound (on time ⇒ failed over within down_silence), NotChargedAtOnce | 1,134 / 429 / 10 | pass |
| blackhole-signed_pubage-gs / -signed-gs | BlackHoleBound, NotChargedAtOnce | 216,987 / 83,826 / 44; 99,307 / 37,080 / 44 | pass |
| advert-last (R29b, as built) | AdvOverParent, AdvOverDrops, AdvStillLate | see below | see below |

**Counterexamples, in plain words.**
- **The lying relay holds a child forever under the current rule.** The liar offers once a second with `forwarding` set and an upstream latency of 900 ms, and sends no media. Every offer is fresh and claims late, so the excuse holds on every tick and the child's silence stays 0. TLC's lasso repeats one offer period for ever, with the child still attached and no chunk ever arrived.
  - Nothing in the failover path moves it. Failover needs Suspected, Down, depth, membership or eligibility (`selector.rs:1500-1503`). Lateness gives at most Degraded, and that needs a meter window of chunks.
  - The only exit is the voluntary switch (`selector.rs:1646-1698`). It needs a warm standby with at least 2 windows of its own media, room, and a better score held for `hysteresis_hold_windows`. With no such standby, the child is held.
- **Signing the excuse is not enough while the grace is unsigned.** The liar never delivers, so `first_owed` stays true for ever. The grace is `min(offer.upstream_latency_ms, down_silence)` = 5 s, taken from the liar's unsigned claim. A liar whose excuse is grounded is therefore still held 5 s plus the silence bound past it: 29 ticks = 7.25 s when the publisher was never late.
- **Judging a stamp's age raw fails honest relays.** Once the publisher's backlog passes about 2.5 s, every stamp reaches the relay already older than 2.5 s, because it waited in the very queue it reports. No honest relay is excused, and the child fails over a parent that is dropping stale media correctly. Judging age net of the declared backlog removes this: 252,837 states pass.
- **With the fix (signed, net of backlog, grace from the stamp):**
  - A liar on a publisher that was never late is failed over within 12 ticks (3 s) < down_silence.
  - A liar that saved a real late stamp is failed over within down_silence of that stamp expiring, and within Life + down_silence of the publisher's last real backlog.
  - Any relay that holds a real, recent late stamp is excused, honest or not. That is correct: nothing fresh exists then.
- **NotChargedAtOnce holds under every rule.** No failover happens before 9 ticks of silence have passed since both the last chunk and the last excused tick.

**R29b, the advertised latency.** The as-built relay keeps only its LATEST stale drop (`alm.rs:1722-1726`, `stale_seen.insert` overwrites), not the largest drop of the last 2.5 s. So "advertised ≥ every recent drop's age" can fail: a 2.0 s drop followed by a 0.9 s drop advertises 0.9 s. Each recorded drop is already past 800 ms, so the excuse (> 800 ms) still holds (AdvStillLate). Result: see the R29b rows in the R24–R28 table below.

### R24–R28

| Row | Run | Checks | States / distinct / depth | Result |
|---|---|---|---|---|
| R24 SENDCLOCK | sendclock (240 marks, seq mod 16, window 3) | SendClockExact (backlog = oldest unproved message's age from its send, to the tick); NeverOverReads | 295,675 / 98,589 / 9 | pass, pass |
| R24 | sendclock-marks3 | SendClockExact, SendClockBounded, NeverOverReads | 295,675 / 98,589 / 9 | pass |
| R24 | sendclock-seqmod8 (window 3 < 8/2) | SendClockExact, NeverOverReads | 295,675 / 98,589 / 9 | pass |
| R24 | oldest-since (the G8 verdict's own age, `av_call.rs:7071-7081`) | SendClockExact | 33 / 28 / 4 | **FAIL** |
| R25 BACKLOG | backlog-n1 (two-person call) | OwnQueueSeen, OwnStaleSeen | 38 / 20 / 3; 46 / 26 / 3 | **FAIL**, **FAIL** |
| R25 | backlog-n1 | OnePeerIsNotOwn, BackloggedStalled, DrainStalled, NoRelayOfferStalled | 1,153 / 37 / 3 | pass |
| R25 | backlog-n2 | OwnQueueSeen, OwnStaleSeen | 98 / 50 / 3; 106 / 56 / 3 | **FAIL**, **FAIL** |
| R25 | backlog-n2 | OnePeerIsNotOwn, BackloggedStalled, DrainStalled, NoRelayOfferStalled | 324,253 / 1,802 / 14 | pass |
| R25 | backlog-n3 | OwnQueueSeen, OwnStaleSeen | 278 / 140 / 3; 286 / 146 / 3 | **FAIL**, **FAIL** |
| R25 | backlog-n3 | OnePeerIsNotOwn, BackloggedStalled, DrainStalled, NoRelayOfferStalled | 9,401,185 / 9,029 / 14 | pass |
| R25 | backlog-n3-slowkept (only the kept child's peer queues) | DrainEnds (uplink clear for good ⇝ drain ends) | 128,401 / 1,125 / – | **FAIL** (lasso) |
| R26 STALE | stale (C = 2/tick, FIFO 14, stale = > 3 ticks) | ControlNeverHeld; Drains (□◇ backlog ≤ budget) | 278,991 / 27,899 / 19 | pass, pass |
| R26 | none (no STALE rule) | Drains | 70,191 / 17,916 / – | **FAIL** (lasso) |
| R26 | stale-bound3 / -bound5 | ArrivalBound (media arrives ≤ N ticks old) | 14,168 / 3,944 / 8; 106,848 / 11,840 / 11 | **FAIL**, **FAIL** |
| R26 | stale-bound6 / -bound7 | ArrivalBound | 278,991 / 27,899 / 19 | pass |
| R27 AGE | age-current (one stepped chunk allowed, one roll) | NoFalseStale | 16,842 / 1,588 / 4 | **FAIL** |
| R27 | age-current | NoFalseStaleHandout, StaleCaught, NeverForwardStale, HandedFresh | 4,960,512 / 26,343 / 7 | pass |
| R27 | age-current-nostep | NoFalseStale, StaleCaught, HandedFresh | 817,842 / 5,242 / 7 | pass |
| R27 | age-confirm (fix: a new minimum needs a second chunk within FLOOR_NEAR_MS) | NoFalseStale | 16,000 / 4,843 / 4 | **FAIL** |
| R27 | age-confirm | NoFalseStaleHandout, StaleCaught, NeverForwardStale, HandedFresh | 7,825,442 / 37,383 / 7 | pass |
| R27 | age-confirm-nostep | NoFalseStale, StaleCaught, HandedFresh | 1,482,497 / 9,452 / 7 | pass |
| R27 | age-confirm0 (fix, and the epoch's first floor needs its pair too) | all five | 6,101,342 / 28,983 / 7 | pass |
| R27 | age-confirm0-nostep | NoFalseStale, StaleCaught, HandedFresh | 1,526,702 / 9,662 / 6 | pass |
| R28 BUDGET | budget-all (as built) | AudioBeforeVideo, VideoBeforeBulk, WithinRate, QueueBounded | 4,308,761 / 107,719 / 22–23 | pass |
| R28 | budget-all | BulkServed (bulk waiting ⇝ served) | 4,308,761 / 107,719 / 23 | pass |
| R28 | budget-all | BulkWaitBound (≤ 3 ticks), FloorDebtBounded | 2,192,547 / 64,721 / 13; 1,764,764 / 54,731 / 13 | **FAIL**, **FAIL** |
| R28 | budget-all, budget-floor_only | FirstWireWait ≤ 3 ticks | 33,487 / 2,365 / 7; 33,487 / 2,205 / 7 | **FAIL** |
| R28 | firstwait-k4 / -k5 | FirstWireWait ≤ 4 / ≤ 5 ticks | 799,567 / 29,333 / 10; 4,308,761 / 107,719 / 22 | **FAIL**, pass |
| R28 | budget-floor_only (fix: only floor-path bulk debits the floor) | AudioBeforeVideo, VideoBeforeBulk, BulkWaitBound, FloorDebtBounded, WithinRate, QueueBounded, BulkServed | 1,688,041 / 42,201 / 17–18 | pass |
| R28 | budget-nofloor (strict priority, before the CC review) | BulkWaitBound; BulkServed | 140,931 / 8,145 / 9; 438,841 / 17,378 / – | **FAIL**, **FAIL** (lasso) |
| R29b | advert-last (as built) | AdvOverParent, AdvStillLate | 177,154 / 59,051 / 12 | pass |
| R29b | advert-last | AdvOverDrops | 11 / 10 / 4 | **FAIL** |
| R29b | advert-max (the max over 2.5 s) | all three | 177,154 / 59,051 / 12 | pass |

**R24 SENDCLOCK.** The send clock ages the oldest unproved message from its send, to within a tick, and never over-reads. This holds across the sequence wrap and with only 3 marks, as long as the unproved messages fit in less than half the sequence space: the code has 65,536 sequences against a Channel window of a few dozen.
- A first draft without the window constraint let the oldest jump by ≥ half the modulus in one tick, and the wrap comparison then kept a stale mark. That is a modelling artefact at 16 bits.
- The verdict's age (oldest_since) under-reads in 3 states. One message is unproved since tick 1. When the older one is proved, its age restarts at 0. This is why DR moved to the send clock.

**R25 BACKLOG.** One slow peer never reads as this uplink (OnePeerIsNotOwn). Backlogged ⇒ draining ⇒ stalled holds in the same tick, because the drain is folded before `set_uplink_stall` (`av_call.rs:7097-7108`). No relay offer goes out while stalled. Two failures:
- **This uplink's own queue goes unseen while fewer than two legs have something outstanding** (before a drain starts). In a two-person call (n1) it is never seen: `uplink_backlog` returns None for ever (`av_call.rs:4209-4213`). So the drain, STALE (`sends_stale` reads the drain's reading) and the egress budget (`budget.observe(None)` reads clear) never engage. The constant's doc (`alm.rs:386-388`) says a one-child publisher "has nothing to shed". That covers G8, but not STALE or the budget. At n2 and n3 the same happens on any tick where only one leg is outstanding: 3 steps.
- **A drain can outlive the queue that caused it.** Once draining, the kept leg's reading counts alone (`av_call.rs:4209-4211`). A kept child whose own uplink queues makes its proofs return late, so the reading stays ≥ 200 ms and resets the 1 s clear count. The other legs, outstanding only now and then, pull the minimum down for a tick but never for four in a row.
  - The lasso: this uplink is clear for ever, and the kept leg reads 250–500 ms on every tick it is alone. The drain never ends, so media stays withheld.

**R26 STALE.** Control is never held, and with STALE the FIFO keeps returning under the budget. Without STALE, media can hold it above the budget for ever (lasso).
- **STALE does not bound arrival age by itself.** Its reading is the age of the head of the FIFO. A burst handed while the head is young waits behind the queue it builds.
  - The worst case found: media handed at a reading ≤ 3 ticks arrives 6 ticks (1.5 s) old. That is the FIFO's depth over its drain rate.
  - Only the egress budget (R28) keeps that depth short.

**R27 AGE.** Relays never forward a chunk judged stale (NeverForwardStale), and the host is never handed one (HandedFresh, the hand-out re-judgement).
- **The clock-step hole is real.**
  - Under the current floor, one chunk from a publisher clock 2 s ahead lowers the (stream, epoch) floor by 2 s at once (`rxmove.rs:51-58`).
  - Every on-time chunk after it then reads 2 s late and is dropped, on receipt and at hand-out.
  - The drift re-anchor cannot repair it: it needs a sample within 50 ms of the floor, and none comes. The hole lasts until the epoch rolls (3 steps).
- **The proposed fix** is that a new minimum must be confirmed by the next chunk landing within FLOOR_NEAR_MS of it. It closes the mid-epoch hole, but not on the epoch's first chunk: that chunk still sets the floor alone, so a stepped first chunk poisons the epoch (age-confirm, NoFalseStale, 3 steps).
- **confirm0 closes that too.** The epoch's first floor also waits for its pair, and media passes unjudged until then, as before any chunk today. confirm0 passes every property.
- **Take the lower of the pair.** A first draft that set the confirmed floor to the higher of the two missed a chunk 100 ms past the budget once a drift re-anchor added to it (7 steps).
- **Abstractions.** The drift re-anchor is limited to one per epoch here, a 30 s floor age. Unlimited re-anchors creep the floor 50 ms each, which the code allows once per 30 s by design.

**R28 BUDGET.** FIRST is never held by the budget: `take(Control)` is always true. Audio goes before video, and video before main-bucket bulk. What goes besides FIRST stays within R plus the buckets' depth, and the FIFO stays bounded. Three findings:
- **The bulk floor runs into unbounded debt.** Every bulk take debits `floor_tokens`, including one served from the main bucket's room (`egress_budget.rs:228-233`). The floor's refill has no lower clamp.
  - So while there is room, bulk drives the floor into debt. When media later takes the main bucket, bulk waits for that debt to repay at the floor rate (10 % of R).
  - The trace shows bulk waiting ≥ 4 ticks behind video with the floor at −4, still repaying. In the code the debt grows with every second of room-served bulk.
  - Bulk is still served eventually (BulkServed passes, with the model's debt clamped at 8), but the wait is not bounded.
  - floor_only, debiting the floor only for floor-path sends, passes every property. Clamping the debt to one send would also do it.
- **Strict priority starves bulk (the pre-review rule).** budget-nofloor has a lasso where bulk is never served. The floor is what fixes that.
- **FIRST is never queued behind media in edge, but it is at the uplink.** Before the first cut, nothing is held, and the FIFO fills until the backlog reads over 400 ms. The first cut starts from 0.7 of what was handed, which can still exceed the uplink, and the next cut waits up to 1 s.
  - FIRST sent then waits behind up to 5 ticks (1.25 s) of queued media in this model: k4 fails and k5 passes.
  - "Never queued behind media" holds for edge's own hold only.
- **Abstractions.** One unit is 64 kbit/s, so RMin = 2 units. The 8 kbit/s floor minimum rounds up to one unit. The backlog reading is the FIFO's wait, q div C, assumed exact with ≥ 2 legs (R24 and R25 check that separately). FAST-after and lift timers are scaled (8 and 12 ticks).

**R29b.** As built, the advertised latency can be below a stale drop of the last 2.5 s (3 steps: a 1.0 s drop, then a 0.9 s drop). It is still always > 800 ms while any drop is recent, so the excuse is unaffected. Keeping the window's max passes.


## Decision table

Each row is one input a node actually has. It gives the state the row applies in, the action, the model action that does it, and where the code does it, or should. Paths are relative to the worktrees in the brief:

- **lev** = leviculum `Leviculum-punchdiag2` at c75fdeb01 (committed). "lev WIP" is that tree's uncommitted RTO-learning change.
- **edge** = `CIRISEdge-relay` at 5be3874 (committed). "edge WIP" is calls2's uncommitted `alm.rs` / `av_call.rs`.

The status column says one of three things:

- **implemented**: the code does what the model's all-on configuration does;
- **implemented differently**: the code does it, but differently (the difference is stated);
- **missing**: the code does not do it yet.

### The Channel (per leg, at the dialer)

| # | Input | State | Action | Model | Code | Status |
|---|---|---|---|---|---|---|
| C1 | a message's retransmit timer fires, tries < 5 | leg up | retransmit with a new attempt (a new packet, a new receipt); the wait is base·1.5^(tries−1), base = max(2.5·SRTT, 100 ms) | `TimerMsgs` retransmit branch | lev channel/mod.rs:1008-1075 `poll_with_inbound`, :935 `retransmit_due_ms`, :98 `calculate_timeout` | implemented |
| C2 | the timer fires at try 5 | no authenticated inbound since the first send, or the stale bound passed | tear the leg down `ChannelExhausted`; send LINKCLOSE | `TimerMsgs` → `TearDown(…, "exhausted")` | lev channel/mod.rs:1036; link_management.rs:4782-4805 | implemented |
| C3 | the timer fires at try ≥ 5 | an authenticated packet arrived after the first send, and now < first send + stale | hold: retransmit, each wait capped at 2 s | `Held`, the switch `Hold113` | lev channel/mod.rs:1034-1035 | implemented. **The model shows it rarely fires on call legs** (results R3): the only authenticated inbound on P>A is proofs, and at 1 Hz control the proof of the previous message has come back before the stuck one is sent, unless the queue is already longer than the offer interval. |
| C4 | a proof for the LATEST attempt | message outstanding | confirm, record authenticated inbound; a Karn sample only if it was the first try | `RecvProof` (valid, sample = −1 unless tries = 1) | lev link_management.rs:1729-1747, channel/mod.rs:878-934 | implemented |
| C5 | a proof for an EARLIER attempt | message outstanding | confirm it (the earlier copy was queued, not lost); record authenticated inbound; the later retransmits were spurious | `RecvProof` with `ReceiptsPerAttempt` | lev link_management.rs:198 `register` keeps every attempt (c75fdeb01); `confirm_delivery` :281 | implemented (c75fdeb01) |
| C6 | a proof that names its attempt k | message outstanding | an RTT sample = now − send time of attempt k; SRTT ← 7/8·SRTT + 1/8·sample, capped so the 5-try span ≤ the stale bound (RFC 6298 §2, §5; the Eifel/F-RTO detection of RFC 3522 §3.1 / RFC 5682 §2.1 gives the spurious count) | `RecvProof` with `RtoLearnsDelay` | lev WIP channel/mod.rs ~984 `mark_delivered_attempt`, ~1054 `srtt_cap_ms`; link_management.rs `confirm_delivery_attempt` :326 (WIP) | missing (uncommitted WIP) |
| C7 | a proof for a message already confirmed (another attempt's) | - | drop it, unauthenticated (its receipt was cleared on the confirm) | `RecvProof`: no idx | lev `confirm_delivery` clears the sequence's receipts | implemented. **Model note:** this also discards a valid RTT sample and an authenticated-inbound mark. A late duplicate proof is evidence the leg is alive; R5 asks whether it matters. |
| C8 | a first-try proof with a growing RTT | - | today: a Karn sample (EWMA) | `RecvProof` sample when tries = 1 | lev channel/mod.rs:887-899 | implemented |
| C9 | a LINKCLOSE arrives | leg up at the receiver | close it, `peer_closed` | `RecvClose` | lev link close path | implemented, but **#1030: on a direct path it may never arrive** (`CloseLost`) |
| C10 | nothing from the dialer for the stale bound (it is dead, or it tore down and its close was lost) | leg up at the receiver | close it, `stale` | `StaleLegs` | lev link.rs stale check (`stale_time_ms`, 2 × keepalive) | implemented; the bound is ~10 s at a short RTT (31 s measured in #1030 was a channel exhaustion, not stale) |

### The publisher (fan-out controller)

| # | Input | State | Action | Model | Code | Status |
|---|---|---|---|---|---|---|
| P1 | per watch tick, per out-leg: age of the oldest unproved Channel message (age measured from the first watch tick that saw that sequence) | - | the leg is stalled if age ≥ 400 ms; the uplink is stalled if ≥ 2 legs are | `PWatch` (`obs`, `stalled`, `det`) | edge av_call.rs:5788-5815 | implemented. The age is sampled every 250 ms, so the verdict is 0–250 ms late, and it resets when the oldest sequence is confirmed. edge WIP adds "every leg with something unproved is backlogged" (a veto) and the leg's own `min_rtt`. |
| P2 | the stall verdict rises | children > 1 | shed now to one child (LIFO); latch the verdict 2 s past its last detection | `PWatch` with `ShedOnVerdict` | edge WIP `set_uplink_stall` → `fold_egress_window`; today alm.rs:382-386 only sets a flag | implemented in edge WIP (uncommitted) |
| P3 | the egress window closes | the stall flag holds | read the window congested at one stream's room and shed LIFO to the room | `Window` congested branch | edge alm.rs:1588-1636; admission.rs:806-920 | implemented: the room can be zero (F4); edge WIP gives the own stream one + reserve + external |
| P4 | a shed's victims | - | notify each (`Shed{OverCommitted}`) and **keep feeding it until it moved** (make-before-break) | `ShedTo` with `ShedDrains` | admission.rs:905-914 removes the victim from the ledger at once, with no drain; `shed_all_draining` admission.rs:396 is the drained form (relay-off, tier 2) | **missing** for the stall/over-commit shed |
| P5 | the shed notice itself | P's uplink is the congested queue | it rides the same FIFO: it arrives a queue delay later | `SendEach(… "shed")` into the FIFO | edge alm.rs:1622-1634 → the leg's Channel | implemented as the only path. **Model note:** no faster path exists. A kept child could tell the others (it is uncapped). |
| P6 | the egress window closes | no stall, someone was refused since the last window (demand) | room + 1 stream | `Window` clean branch | admission.rs:854-875 (additive increase) | implemented |
| P7 | the egress window closes | no stall for `CEILING_STALE_MS` | forget the ceiling (back to the probe allowance) | `Window`, `CeilingStale` | admission.rs:877-886 | implemented (60 s → 120 s doubling in code; scaled in the model) |
| P8 | call start | - | room = InitFanout (1); widen by P6 as clean windows prove capacity | `Init` room with `SlowStart` | today alm.rs:322-323 `set_probe_streams(min(N−1, 8))` | **missing** |
| P9 | offer timer | stalled | offer only every 5 s (an offer only queues behind the backlog) | `OffersOver` (`StallOfferEvery`) | edge alm.rs:1716-1721 | implemented. **Model note:** fewer messages on P's legs also means fewer proofs, so the #113 hold has less evidence and RTO learning gets fewer samples (R3). |
| P10 | a subscribe from a listener | room > children | admit, and append to the admission order | `PAdmit` | admission.rs `request` | implemented |
| P11 | a subscribe | no room | refuse; set demand | `PAdmit` refuse branch | admission.rs `request` (capacity refusal → demand) | implemented |
| P12 | an unsubscribe | - | drop the child and any drain | `Handle` "unsub" | admission.rs:798 `release` | implemented |
| P13 | a leg of P's goes down | - | release the child (`on_child_link_down`) | `ChildDown` | edge alm.rs:756-767 | implemented |

### The listener (selector)

| # | Input | State | Action | Model | Code | Status |
|---|---|---|---|---|---|---|
| S1 | a Shed from its parent | that parent is its primary | drop it; back the parent off 2 s; remember it drains (to unsubscribe once moved) | `OnShed` | edge alm.rs:1363-1369; selector.rs:540-570 `on_shed` | implemented |
| S2 | its parent's media leg closed (it sees the close) | parent set | fail over | `LWatch1` first branch | selector.rs:515 `on_link_down` (+ the next tick's failover) | implemented |
| S3n | the primary is LOST (its link down, or silence) | - | ask P at once (backoff and P's offered room ignored); P with no primary admits whatever its room | ask P at once after P SHED this node: in the model "ask after shed" starves 128/160 after a lift and leaves listeners parentless past the bound with the cap held; the narrowed rule gives FullFanOut 160/160 | `AskAfterLoss` vs `AskAfterShed`; `PrimarylessAdmit` | edge release 67529ad | implemented (narrowed) |
| SU | this node lost its primary X (link down or silence) | choosing a new primary or promoting its standby | a member whose LAST offer names X as its own upstream is no candidate until a fresh offer after the loss shows another, healthy upstream; if every candidate is excluded, wait (S3n: ask P) | promote a standby that shares the lost upstream: in the model, A and B on a starved C, each the other's standby, promote each other and loop (LoopFree violated without SU, holds with it) | `SUExcluded` in `Viable` and in the promotion; offers carry `up` | selector promotion + offer ancestry | **missing** (ruled) |
| SD | this node drops its parent for SILENCE (nothing new on any path) | - | unsubscribe the old parent as it drops it | keep the old parent's commitment: P keeps a starved child it cannot reach in its ledger, so its room stays full and it is not primary-less, refuses everyone, and listeners strand (model: Stranded 48–56/160, parentless up to 18.5 s, with or without SU) | `SilenceUnsub` | selector silence failover | **missing** |
| BR | a parentless member with nothing pending and no candidate | - | ask P every 2 s (the bridge renewal) | — | `BridgeEvery` | edge bridge renewal | implemented |
| S3 | no parent, nothing pending | a viable candidate: an offer within 5 s with forwarding and room, both legs up, not backed off, not a descendant | subscribe: P first (direct_first), else a relay | `LWatch1` → `Subscribe` | selector.rs:960 tick (join, failover, R3) | implemented differently: the code scores candidates within a 10 % band and adds a join jitter |
| S4 | an Admit | the subscribe is pending to that node | that node is now the parent; unsubscribe the old one; unsubscribe a draining P | `OnAdmit` | selector.rs `on_decision`; alm.rs:1663-1700 (told_publisher, draining_parent) | implemented |
| S5 | a Refuse | the subscribe is pending | back that node off | `Handle` "refuse" | selector.rs `on_decision` | implemented |
| S6 | a subscribe with no answer | pending past `SubTimeout` | give up; back off | `LWatch1` second branch | selector.rs request timeout | implemented differently (the code's timeout is in the selector's link state) |
| S7 | P's offer shows room | on a relay; the dwell has passed | move back to P (make-before-break: keep the relay until P admits) | `LWatch1` voluntary branch | selector.rs:1256-1300 (hysteresis + dwell) | implemented differently (the code compares scores with 1.2× hysteresis) |
| S8 | a parent's silence | no other path delivers either | nothing (the stream is idle, not the parent dead) | not modelled (see abstraction 8) | selector.rs tick `idle_aware` | implemented. **Model note:** a listener shed without a drain hears nothing until the shed notice arrives, a queue delay later. |
| S9 | a relay's offer | - | remember it (candidacy for 5 s) | `Handle` "offer" | alm.rs:1371-1400 | implemented |

### Legs (lifecycle)

| # | Input | State | Action | Model | Code | Status |
|---|---|---|---|---|---|---|
| L1 | a leg torn down at its dialer | - | release the direct path (one free re-punch per base period); schedule the redial | `TearDown` (pathAt, dialAt) | edge direct_path.rs:913 `link_closed`; av_call.rs:3978-3986, :4805-4809 | implemented |
| L2 | a redial is due | the path is not back yet | the dial fails; the backoff doubles 1→8 s | `RedialOver` failure branch | edge av_call.rs:4253-4285 | implemented (F6: 15.5 s to recover) |
| L3 | the path is back (re-punched) | the leg is down | **dial now** | `DialDue` with `RedialOnPathUp` | none | **missing** |
| L4 | a new leg is up | - | a fresh Channel (SRTT unknown) | `RedialOver` success | lev link establish | implemented. **Model note:** the learned delay is lost with the old link: the new leg starts at the 100 ms floor, into a queue that may still be long. |

### Rows the model added (missing in code)

| # | Input | State | Action | Model | Code | Status |
|---|---|---|---|---|---|---|
| N1 | the timer fires at try ≥ 5 | an authenticated packet from the same PEER on any leg arrived after the first send | hold, as C3 | `Held` with `PeerLiveness` (`peerAuth`) | lev: extend `poll_with_inbound`'s `authenticated_inbound_ms` to the peer's newest authenticated time across its links (link_management.rs:4692-4715 passes per-link today) | **missing** |
| N2 | a chunk of P's stream arrives directly from P, `now − source_ms ≥ 300 ms` | this node is P's child and not P's first child; a relay offers room | subscribe to the relay; keep P until it admits; then unsubscribe P with reason "late" | `LWatch1` ReceiverMoves branch, `OnAdmit` (`unsub_late`) | edge alm.rs `on_chunk` (has `source_ms`) → selector; a `late` unsubscribe code in C3 (wire.rs) | **missing** |
| N3 | a "late" unsubscribe | - | drop the child; room = current children; congested now; probe backoff + 1 (max 2) | `Handle` "unsub_late" | admission.rs (a new input beside `on_egress_window`) | **missing** |
| N4 | the egress window closes, no stall | the room may widen (demand, or the SlowStart probe) | widen by at most one stream, and only after 2 windows × 2^fails since the last congestion or widening; a widening after one that held steps fails down | `Window` (`calm`, `probeFails`) | admission.rs:854-875 (demand additive increase has no backoff today) | **missing** |
| N5 | P's first child | - | P tells each child its admission rank (or "first") in the Admit, so only the others move on N2 | `first` read from P's order | wire.rs Admit; selector | **missing** (wire addition) |

### The shipping set for 45.2.0: ReceiverMoves on the hash rank (RM), the review's rules (F)

Each row also states what the code must never do. Code refs are edge at 5be3874 unless marked.

| # | Input | State | Action | Must never | Model | Code | Status |
|---|---|---|---|---|---|---|---|
| RM1 | a chunk of P's stream: its signed `source_ts_ms` vs the local wall clock | any | latency = (wall − source) − floor, where floor = the per-stream minimum offset | use an unsigned or relay-supplied time; **re-anchor the floor while the stream is late** (today the floor is replaced once it is 30 s old: after 30 s of queueing the late signal reads 0) | `Media1` (`rxDelay`; the model has no clock skew) | alm.rs:1086-1112 (`on_chunk`, `min_offset`) | implemented; the floor rule is **missing** |
| RM2 | latency of P's stream delivered directly by P ≥ 300 ms, **sustained** (two readings, not falling: one sample made two children leave at 1.5× where one would do, R13) | primary = P, nothing pending, not spared (RM4), a member other than P offers the stream with room and is not a descendant | subscribe to it; keep P until it admits | move when every source is late (RM6); move when spared; move to a stale offer (> 5 s) or to one without room; move twice in one late episode | `LWatch1` ReceiverMoves branch | beside the selector tick (selector.rs:960) or alm.rs tick C4/C6 | **missing** |
| RM2b | (the target of a late move) | - | ask only the spared direct child of P, or a member at depth ≥ 2 | ask a direct child of P that may itself move: two late movers can ask each other at the same moment, both admit, and they form a loop P's stream reaches neither (found in edge feat/receiver-moves 2ed5236). **The model cannot show this race:** listeners are evaluated in a fixed order within a tick (abstraction 1) | `LWatch1` (the model's `Chain` check only works sequentially) | edge feat/receiver-moves 2ed5236 | implemented there |
| RM2c | (the sustained reading) | a queued child | judge lateness over a COUNT of chunks (e.g. the last N), not a clock window | judge over 250 ms windows: a queued child receives only its share (~13 chunks/s at 3 copies into 1.3), so windows are often empty | not modelled (one reading per watch tick) | edge feat/receiver-moves | implemented there |
| RM4b | (the spare's knowledge) | the relays' periodic offers are lossy (≈25 % of periodic C3 sends failed on loopback; the relay offers went last in each burst) | rotate the send order; spare only on offers fresher than the down-silence | spare on missing offers: two children each believe they are the kept one | not modelled (no offer loss) | edge (order rotated) | implemented there; **model owes an offer-loss action** |
| RM3 | the Admit from the new parent | pending, a late move | switch primary, then unsubscribe P fully (the departure is the congestion signal, RM5) | unsubscribe P before the admit; **keep P as a (fed) warm standby after a late move**: the selector's make-before-break demotes the old primary to standby, and a standby of an opaque or audio stream gets every chunk (alm.rs:31-32), so the load P was shedding stays (F12; the shipping set collapses 144/144 with it) | `OnAdmit` | selector `on_decision`; alm.rs:1180-1200 | **missing** |
| RM4 | the room's members, P's stream id | any | rank = order of hash(stream id ‖ member key). P's stall shed keeps its lowest-ranked direct child. A receiver is spared if it is the lowest-ranked of the members it believes are P's direct children: itself, and every member whose latest offer for the stream shows P as its parent (offers carry depth and ancestry) | let P keep a different child than the receivers spare; leave P with zero direct children; spare on a stale offer | `ShedTo` with `HashRank`; `LWatch1` `spared` (`RankScope`) | admission.rs:905-914 (LIFO today); selector (offer ancestry) | **missing** (no wire change; the scope variants are reported in Results) |
| RM5 | an unsubscribe from a direct child while the stream is live | - | treat it as a late departure (no reason on the wire): drop the child; room = current children; congested now; probe backoff + 1 (max 2) | widen sooner than 2 windows × 2^fails after it | `Handle` "unsub_late" / `DepartureHolds` | alm.rs:1341-1346 → admission.rs (a new congestion input) | **missing** |
| RM6 | latency ≥ 300 ms from P, AND latency ≥ 150 ms from every other source this node hears | - | no move (it is this node's downlink) | move. In a one-publisher room there is no other source, so allow the move: RM2 requires primary = P, so it does not repeat | `OwnDownlinkGuard` | - | **missing** |
| RM7 | P's offer shows room | on a relay, the dwell has passed | move back to P, make-before-break | return while P's offer has no room | `LWatch1` voluntary branch | selector.rs:1256-1300 | implemented |
| SS1 | the live publisher's start | - | room = 2 (probe 2); after a stall, no widening for 10 s, restarting from one stream; then one stream per 2 windows × 2^fails | widen twice in one window | `Window` with `SlowStart`, `InitFanout` = 2, `StallHold` = 100 | committed by the implementer (per the lead) | implemented (not read here) |
| E1 | P's media egress for a stream | the stall verdict is latched, or a late departure is less than a window old | at most ONE copy: the primaries P kept; a standby gets nothing; a stall shed leaves no standby | feed a standby a full copy of an opaque or audio stream under congestion | `Publish` with `StandbyFeed` = "fix2"; `EgressOneCopy` | edge av_call.rs ~4661 (standby feed), alm.rs:31-32 (the contract) | **missing** (the lead's fix + the late-move rule) |
| E2 | a shed | P has any subscriber | keep ≥ 1 primary: a second shed never takes the last primary, whatever standbys the first left | let a standby's commitment eat the one-stream room | `ShedTo` (`room1`); `OnePrimary` | admission.rs:905-914; alm.rs fold | **missing** |
| B1 | a periodic control burst is due (the 10 s binding re-announce: ~10 hybrid-signed parts per leg) | any | send it so that the round never adds more than about one retry ladder (≲ 1 s) of queue at the current capacity: pace the parts across the period (≈ 1 s per part, not REANNOUNCE_PART_GAP = 50 ms); a repeat part is never retransmitted (it gets a deadline, leviculum#94); skip a backlogged leg, a bounded number of rounds. Better: receiver pull instead of a periodic repeat | let one burst put more than the ladder in front of the media and proofs: every listener's leg toward P then sees no fresh evidence and is torn, even with PeerEvidenceHold (F13: the model collapses 156/156); let a held part's retries re-enter the queue at full size | `Reannounce` (`BindEvery`, `BindPace`, `BindExpire`, `BindSkip`) | av_call.rs `reannounce` / `send_binding_paced`; av_chunk_auth.rs:493 `BINDING_REANNOUNCE` | **partly**: the skip exists in calls2's tree (av_call.rs:5290-5310), unbounded; pacing at 1 s and expiry are missing |
| D1b | (both sides of a leg) any node that receives from a peer, **and a relay toward each of its children** | its own leg to that peer | ≥ 1 fresh Channel message per second on it, a SILENT listener included (no own stream to offer) | let a leg carry nothing periodic: under FreshEvidence + ConditionalRto the other side's next message then runs the cold ladder into the queue (F14a) | `OffersOver` with `KeepFresh` (`SilentListener` models the gap) | edge alm.rs offers (1 Hz, own stream only) | **missing** |
| T1 | this node's OWN leg toward its parent is torn | parent set | the parent is lost: fail over (as when the parent's media leg closes) | wait for the parent's media leg to close or go stale (10 s) | `LWatch1` (parent lost on `~up[<<l, parent>>]`) | selector.rs:515 `on_link_down`; its callers in av_call.rs (leg close → alm) | **check** (F14b) |
| T2 | a primary that delivers nothing new while no path delivers | - | re-subscribe ONLY if a viable candidate exists; P directly if P has no primary, whatever its last offer said | drop the parent with nowhere to go: the model's literal rule (`TreeRepair`) strands a listener in 80/160 where the plain failover recovers 160/160 | `TreeRepair` | selector.rs tick (idle-aware silence) | **missing (and the naive form is harmful)** |
| E3 | a new leg, under a latched verdict | the leg has no datagram capability yet | send it no media until it has; media is datagrams only | carry media on the reliable Channel (seen: 140–250 kbit/s with zero datagrams) | not modelled (media is always datagrams here) | edge av dispatcher fallback | **missing** |
| B2 | P's non-media control egress | the verdict is latched | at most about ¼ of (cap − one copy). At a 250 kbit uplink with a ~190 kbit copy that is ≈ 15 kbit/s; everything else waits, except answers and the D1/D1b keep-fresh message | exceed it: at ½ of the leftover the model has teardowns (3–8 %) and a 1.4–2.9 s queue at the end of the cap; at ¾ or more the queue never drains (edge measured 10–60 kbit/s) | `CtrlBg` sweep | edge A/V control (offers, bindings, caps, acks) | **missing** |
| FR | (the probe backoff's fail count) a congestion; a widening that survives; a clean window that carried more than the congestion ceiling; the staleness | - | (1) congestion while the latest change was a widening: fails + 1, recording that step's time-to-fail; (2) fails − 1 only when a widening has survived max(its backoff wait, k × the longest time-to-fail since the last reset); (3) the clean over-carry resets fails and the time-to-fail (the raise itself stays + 1 stream per dwell); (4) so does the staleness; (5) fails ≤ 6; steps = committed + reserve + external + one stream; an over-committed shed counts as a failed probe | forgive a step at the dwell when steps fail slower than the dwell (the code's 1→2→1→0 cycle); with k = 0 the model's probes run at a constant 17 s for 260 s | `FailRule`, `TtfFactor` (k), `StepUp`, `FailBump` | admission.rs N4 | **being built** |
| RO2 | (the combined re-open rule, as built: supersedes RO + PAD) a Capacity refusal; a window; an admission | P's uplink also carries relayed streams | demand only if no verdict is latched, the asker was not shed by this admission within the dwell, and (no congestion-learned ceiling or drained); demand lapses after a dwell. "Drained" means every out-leg queue < 150 ms and nothing outstanding, for 2 clean windows. Then one stream per dwell under N4 (fails ≤ 6, 128 s); the never-congested path is unchanged (two clean windows); staleness 60 s is the backstop. Admission only if it fits beside everything committed (own + relayed); never shed an existing child without a congestion verdict or a named preemption | today's over-committed shed with no verdict (relay admissions grow, the own stream's limit falls): in the model it sheds after the lift and leaves P with no child (KeepsOneChild, NoShedAfterLift violated); let the clean-window raise reopen several children in one tick (OneJoinAtATime violated with it, holds without) | `Reopen`, `OverCommitShed`, `CleanRaise`, `ExtCopies`, `ProbeFailsMax` | admission.rs:974 (demand), ~1064 (clean raise), hard_limit | **being built** |
| RO | (how a publisher re-opens after congestion: PAD + refusal as demand) a Capacity refusal | - | the refusal counts as demand only if no verdict is latched, the asker was not shed by P within the last dwell, and either no ceiling was learned from congestion or the uplink has been drained for the hold. Demand is served under the N4 backoff (one stream per dwell after congestion, PAD), EXCEPT the fast path: a REPEAT ask (the same member refused within 4 s) to a publisher that has never learned congestion is served at the next window | grow while latched, toward a member P just shed, or on an undrained congestion ceiling; serve every first refusal at once (in the model that widens to full fan-out before a mid-call cap and starves 60/160 when it lands) | `DemandGuard` (`counts`, `repeatDemand`); `ProbeAfterDrain` | admission.rs demand (capacity refusal → demand) | **missing** (proposed) |
| PAD | P's uplink measurably drained (no queue, nothing outstanding on its legs) continuously for `DrainHold` | a congestion-learned ceiling holds the room; no stall verdict latched | stop capping the probe by that ceiling: widen one direct child per dwell, each step under the N4 backoff (a stall after a step is a failed probe and doubles the wait); keep the 60 s staleness as a backstop | widen while the verdict is latched; widen more than one child per dwell; let the stale ceiling reopen the whole room at once (the minimum set without it violates OneJoinAtATime: children rejoin together) | `Window` (`ProbeAfterDrain`, `drainedSince`, `DrainHold`); `OneJoinAtATime`, `ParentedThroughout` | edge admission.rs ceiling + CEILING_STALE_MS | **missing** (ruled 11-25) |
| D1 | P's offer timer while the verdict is latched | a leg with nothing unproved | still send something fresh on that leg at ≤ 1 s (the offer, or a small frame) | hold every leg's control to 5 s: dead-peer detection on P's legs then stretches to ≈ 5 s + the cold ladder (R10) | `OffersOver` (`StallOfferEvery`) | alm.rs:1716-1721 | **missing** |
| F1 | a packet on a leg | - | it is evidence of the peer only if it advances state: a Channel frame with a new sequence; a proof for an outstanding receipt; a new chunk | count a replayed frame, a duplicate attempt or a retransmit of an old sequence | `FreshEvidence` (`RecvCtrl`, `RecvProof`, `Media1`) | leviculum (review, being built) | being built |
| F2 | (a coupling) | FreshEvidence is on | per-attempt receipts MUST be on | ship F1 without per-attempt receipts: a shed child's leg toward P then has no fresh evidence, and the collapse is back (Results) | `ReceiptsPerAttempt` | leviculum c75fdeb01 | implemented |
| F3 | a message's timer | no fresh evidence since its first send | the cold ladder (100 ms floor, ≈1.3 s) | use the learned SRTT for a peer that has shown nothing since the message was sent | `ConditionalRto` | leviculum (review, being built) | being built |
| F4 | (an adversary) an on-path party replays recorded frames of a dead peer | - | nothing: replays are not fresh | hold a link on a replay | `ReplayAttack` | - | checked (Results) |
| F5 | (an adversary) an on-path party withholds one node's proofs | the peer is alive and sends fresh traffic | the hold rests on that traffic | tear down a link whose peer is visibly alive; hold one past the stale bound | `DelayProofs` | - | checked (Results) |

### Not in the model, but on this path

| # | Input | Action owed | Code | Status |
|---|---|---|---|---|
| X1 | `publish()` blocked 45–60 ms per call under the cap (retries of refused sends under the publisher lock) | never hold the publisher lock across a settle/ramp retry | edge av_call.rs:2934 (lock), `send_pieces` :3894; dispatcher MEDIA_RAMP / CONTROL_SETTLE / C3_SETTLE (realtime_av_dispatcher.rs:548-556) | missing (F8, calls2 owns it) |
| X2 | a receiver-side delivery report (arrival times per chunk) | would give the publisher a delay signal on datagram legs (RFC 8888-style) without waiting for Channel ages | path_meter.rs:402 "Limit: datagram legs"; CIRISEdge#975 | missing |

## Trace conformance

A recorded run conforms when the model, configured with that run's pins, can reach a terminal state that makes the same observations.

**What a run records.** These are the observables edge already prints:

- the `ciris_edge::link_close` lines, each with its node, direction, plane, peer and reason, timed from the `G8 cap on` line;
- the witness's context line `[G8] capped publisher: …`: first teardown per node, parents, P's children, the ALM counters `shed` and `alm_uplink_stall`, and frames heard.

**What the model prints.** Every terminal state prints `Observed` beside its outcome. `run_matrix.py` writes each distinct observation to `OUTDIR/<scenario>.observed.txt`. The fields:

| Field | What it holds | Edge counterpart |
|---|---|---|
| `first_torn[n]` | the first tick a leg was torn down at node n (exhausted as dialer, stale as receiver) | the witness's `torn_down` (channel_exhausted, timeout, stale) |
| `exhausted` | legs torn by retry exhaustion | `channel_exhausted` |
| `direct`, `relayed` | P's direct children and the listeners on a relay, at the end | — |
| `sheds`, `verdicts` | sheds made and verdict rises | `shed`, `alm_uplink_stall` |
| `heard_pct` | per listener, heard as a percent of what P published | — |

**The check.** `trace_check.py OBSERVED RUN.json` reports CONFORMS with a witness observation, or the nearest observation and the fields that differ. Times match within ±3 ticks, which covers the witness's 100 ms sampler and the model's rounding. `--log EDGE.log` reads `first_torn` and `exhausted` straight from the test's stderr: the link_close lines, minus the cap line's time.

- **A run that does not conform is a finding.** Either the code does something the model does not have, or the run was not the configuration it claims.
- **Why this check and not a TLA+ trace spec.** A full trace spec (each logged event as an action constraint) would need every Channel event to be logged. Edge logs only closes and counters, so the projection check above is the strongest one the logs support.
- **What would make it stronger.** Log leviculum's `channel: max retries exceeded` with seq and tries, plus each leg's last authenticated inbound before its teardown (the instrumentation asked for in leviculum#113). Then per-leg traces could be checked event by event.

**The first two traces** are in `recorded_runs/`; results are in [Results](#results).

- `run1_c8699c3d6.json`: from the leviculum#113 comment of 2026-11-24 01:23Z. Per node, the first teardowns were P 1.82 s, A 2.13 s, B 2.13 s, C 1.72 s. 6 exhausted, P had 0 direct children, all 3 listeners were on relays, shed 0, alm_uplink_stall 1, heard ~21 %.
- `run2_c75fdeb01.json`: only the brief's ranges were available. First teardown at 2.17–2.73 s, the listeners' legs toward P first, P sheds to one child. No per-node file was available to this model (asked calls2; see the report).

**Results of the check** (scenarios `pin-c8699c3d6`, `pin-c75fdeb01`, and `conf-run1` / `conf-run2` with the cap held to the end):

- **Run 2 conforms.** A reachable observation has every listener's first teardown inside 2.17–2.73 s and the listeners' legs toward P torn first (`conf-run2`).
- **Run 1 does not conform.** C's first teardown at 1.72 s is earlier than any listener teardown the model reaches (≥ 2.3 s): a listener's message needs more than the 1.3 s ladder of queue delay, and the queue grows 1.25 s per second. Two candidates:
  - P's uplink carried more than three copies plus control in that run (bindings, attendance re-announces);
  - C's teardown was on a link the model lacks (its identity link through T).
  - Run 1 predates per-link logging, so the lead classed it as under-instrumented rather than a model gap. It stays open until an instrumented run shows the same early teardown.
- **The per-link logs** of the later runs were requested from the calls agent and had not arrived when this was written. `trace_check.py --log` reads them directly once they do.

## References

Each reference below was fetched from rfc-editor.org on 2026-11-23 and read for the claim it is cited for. Where the fetch showed only a summary of a section, not its text, the citation is marked **[summary]**: treat it as less certain. Anything not fetched is marked **unverified**.

| Ref | Section | What it says | Where it applies here |
|---|---|---|---|
| RFC 6298 | §3 | Karn: "RTT samples MUST NOT be made using segments that were retransmitted", except "when the TCP timestamp option is employed" | C4/C8 (today's Karn sample); C6 is the timestamp exception: an attempt-tagged proof is unambiguous |
| RFC 6298 | §2 (2.4), (2.5) | RTO SHOULD be rounded up to 1 s; a maximum MAY be placed, at least 60 s | leviculum's 100 ms floor is far below 2.4, which is why a 1.3 s queue exhausts 5 tries; the SRTT cap (C6) is a maximum in the 2.5 sense, tied to the stale bound |
| RFC 6298 | §5 (5.5) and the note after 5.7 | back off the timer (doubling); a new sample after backoff may collapse RTO back down | leviculum backs off ×1.5 (C1); C6's samples are what lets the timeout follow the queue up and back down |
| RFC 3522 | §3.1, §3.2 step 4 | Eifel: if the first acceptable ACK after a retransmit echoes a timestamp older than the retransmit's, the retransmit was spurious | C5/C6: a proof naming an earlier attempt is that detection |
| RFC 5682 | §2.1 | F-RTO: after an RTO, send new data; if the next ACKs acknowledge data that was not retransmitted, the timeout was spurious | the same detection by other means (C6's spurious count) |
| RFC 7323 | §4.1; App. H **[summary]** | timestamps measure "the RTT of virtually every packet acknowledged"; with timestamps the retransmission ambiguity is removed | why every attempt-tagged proof may be a sample (C6) |
| RFC 9002 | §3, §4.2, §5.1 | QUIC packet numbers never repeat; retransmitted data goes in a new packet with a new number, "removing ambiguity about which packet is acknowledged"; an RTT sample when the largest acknowledged is newly acknowledged | the per-attempt receipt (C5) is exactly a fresh packet number per attempt, so the ACK names the transmission |
| RFC 9002 | §6.2 | a PTO expiration "does not indicate packet loss"; PTO = srtt + max(4·rttvar, granularity) + max_ack_delay, doubling | the Channel tears a link down on timer expiry alone; a timeout is not evidence of a dead peer (NoSpuriousTeardown) |
| RFC 9000 | §12.3, §13.3 **[summary]** | a packet number is never reused; lost frames go in new packets | as above |
| RFC 8085 | §3.1, §3.1.3, §3.1.5 | a UDP application SHOULD control its rate; low-volume traffic SHOULD NOT send more than one datagram per RTT on average; "SHOULD implement a congestion control scheme that provides a prompt reaction to signals indicating congestion", taking into account "both the loss rate and the response time" | the media plane's obligation: P5/P2 (prompt shed) and X2 (a delay signal for datagram legs) |
| RFC 8085 | §3.1.1 | "Latency samples MUST NOT be derived from ambiguous transactions"; timer expiry "MUST be interpreted as an indication of congestion" | C6 removes the ambiguity, so the samples are allowed; P1 reads the Channel's expiries as congestion |
| RFC 8085 | §3.1.10; RFC 8084 §1, §3.1 item 5, §4 req. 6 | a circuit breaker terminates or "significantly reduces" a flow under persistent congestion, over several measurement intervals, and "MUST be constructed so that it does not trigger under light or intermittent congestion" | the Channel's exhaustion teardown acts as a circuit breaker on ONE interval (1.3 s), which is the defect; the shed to one child (P2) is the "significantly reduce" response |
| RFC 8298 | §3.1, §4.1.1.1 | SCReAM: the window grows while qdelay < a target (typically 50–100 ms; QDELAY_TARGET_LO 0.1 s) and decreases otherwise | the kind of signal P1 approximates: P1's 400 ms "unproved" age is a qdelay above target, measured late |
| RFC 8698 | §3, §4.2 | NADA: an aggregate congestion signal from queuing delay (d_fwd − d_base), ECN and loss | as above; a receiver-side report (X2) would give d_queue directly |
| RFC 8888 | §3, §3.1 | per-packet feedback: sequence, arrival time, ECN | X2, the receiver-side delivery report (CIRISEdge#975) |
| RFC 8836 | §2 req. 1, 1.c, 4, 4.a, 10 | as-low-as-possible delay; react to congestion "on the order of a few RTTs … likely within a second"; adapt quickly at the start of a flow, slow-start or history or probing allowed; treat missing feedback as possible overuse | P2 (shed within a second: the model's bound), P8 (slow start), P1 (unproved = missing feedback) |
| RFC 8445 | §2.3; §8.1.1, §7.1.2 **[summary]** | the controlling agent nominates one valid pair | the direct path's nomination (leviculum punch) under L1/L3; the model abstracts the punch to a delay |
| RFC 7675 | §5.1 | consent expires after 30 s without a binding response | a comparison point for C10/#1030: an endpoint stops sending to a silent peer on a bounded clock, never on a timeout alone |
| Chu, Rao, Zhang, "A Case for End System Multicast" (SIGMETRICS 2000) | - | application-layer multicast: end systems form the tree; the overlay adapts to the network | the ALM relay tree (S3, S4); **unverified** (not fetched) |

The model's own conventions follow leviculum `docs/channel/ChannelHold.tla` (the hold and the learned timeout, per message) and `docs/direct_link/DirectLinkPunch.tla` / `run_matrix.py` (the switch-matrix runner).

## What the model does not cover

Each item below is outside the model, or held fixed in it. Every property's "holds" is limited to what is modelled.

- **F8, publish blocking.** It is not modelled at mechanism level, because the Channel window is never full here (abstraction 4). In code it lowers P's media rate, which lowers the load: it cannot cause a teardown in this model's terms. But it starves the capture loop, which is a defect of its own (X1).
- **Loss.** Nothing is lost, so the loss half of the retry budget, FEC and the reorder window (#931) are untouched.
- **More than one publisher, shares and standbys.** Only P publishes (abstraction 6). The room left after a shed is an explicit choice, not derived from P's other commitments.
- **Scoring, jitter, hysteresis.** The selector's score is abstracted to "viable, P first" (abstraction 8). A herding or flapping result that depends on the scores is out of reach. The re-parent bound (`ReparentBound`) covers only the moves the model makes.
- **The relay's own admission growth.** `RelaySlots` is fixed at the cold-start slot. In code it doubles after 2 clean windows. A third listener here may wait for a chain (A → B → C) where the code would let A take both.
- **Link establishment and announces.** These are instant here (abstraction 5). The redial's own queueing, path re-learning and `no route to peer` are folded into the re-punch time.
- **Two of the timers are scaled.** The dwell (10 s → 2 s) and the ceiling staleness (60 s → 2 s) are scaled. So `EndFullFanOut` holds in the model with `RecoverBy` = 4.5 s. In code the same sequence takes about 60 s (stale) + 10 s (dwell) + a window. The bound to state for the code is that sum, not 4.5 s.
- **The listeners' own uplinks, and CPU.** These are uncapped and instant. #996 (the relayed leg losing chunks under CPU contention) is out of scope.
- **Security.** Who may send a shed or an offer is not modelled. Every message here is authentic.
- **The canonical (T in the edge test).** It is not a room member, and it relays nothing on 45.x (`CANONICAL_AV_FALLBACK = false`), so it is not modelled.
- **Standbys** are modelled only as P's (the publisher's): a stall-shed child, or a late mover, keeps P as a warm standby under `StandbyFeed` = full/fix. A relay's standbys are not modelled.
- **Background control** (`CtrlBg`) is load only: it is not a Channel message, so it creates no retries and no evidence.
- **Silent listeners** are modelled by `SilentListener`: no offers to P. A relay always offers to the other listeners, because the model's candidacy needs it.
- **TreeRepair's stranding** (80/160) is not traced to its end.
- **`f13-ship-pace5`** (pacing without expiry) throws a TLC exception that was not diagnosed.
- **What is unverified.**
  - The second recorded run's per-node numbers. Only the brief's ranges were available (see [Trace conformance](#trace-conformance)).
  - The [summary] citations.
  - The ALM paper.
