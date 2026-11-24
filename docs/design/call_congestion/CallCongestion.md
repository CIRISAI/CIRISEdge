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

1. **Synchronous ticks, a fixed phase order.** Each tick runs, in order: Channel timers; stale; redial; watch (P, then each listener); the egress window; offers; publish; drain. Delivery from the FIFO is at the end of the tick, and its answers are handled in the same tick.
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

(filled from run_matrix.py output below)

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
- **What is unverified.**
  - The second recorded run's per-node numbers. Only the brief's ranges were available (see [Trace conformance](#trace-conformance)).
  - The [summary] citations.
  - The ALM paper.
