--------------------------- MODULE CallCongestion ---------------------------
(***************************************************************************)
(* A group call under uplink congestion: one publisher P whose uplink is  *)
(* capped below its fan-out, and the listeners L who hear P directly or   *)
(* through each other (CIRISEdge ALM, docs/AV_ALM_DESIGN.md), over        *)
(* leviculum links whose control rides a reliable Channel (leviculum      *)
(* link/channel/mod.rs) and whose media rides unreliable datagrams.       *)
(*                                                                         *)
(* ONE closed model of the parts that interact under the cap:             *)
(*   (a) P's uplink: one FIFO with a drain rate, carrying media, control, *)
(*       proofs and closes in the order they were handed to it; queue     *)
(*       delay is derived (each item's position over the rate);           *)
(*   (b) the Channel per leg: outstanding messages, every attempt's send  *)
(*       time, per-attempt receipts (a switch), the RTO and its learning  *)
(*       (a switch), the 5-try exhaustion rule, the #113 hold;            *)
(*   (c) P's fan-out controller: children, the stall verdict, the shed,   *)
(*       the room, widening on clean windows, the hold of offers;         *)
(*   (d) each listener's selector: parent = P | a member relay | none;    *)
(*       subscribe / admit / refuse / shed / unsubscribe; failover on a   *)
(*       lost leg; the voluntary move back to P after the dwell;          *)
(*   (e) leg lifecycle: up, torn down (by cause), redial with backoff,    *)
(*       the direct path's release and re-punch.                          *)
(*                                                                         *)
(* Every fix is a CONSTANT switch, not a different spec (see the .md for  *)
(* the table, the abstractions and what each can hide).                   *)
(*                                                                         *)
(* Time is a discrete tick (Tick = 100 ms at the scale the .cfg files     *)
(* use). The system is synchronous: one action, Tick, runs the phases of  *)
(* one tick in a fixed order (deliver what the uplink drained at the end  *)
(* of the last tick is folded into the same tick; see Phase order below). *)
(* Nondeterminism: the offer and window phases (Init), and per tick the   *)
(* room left by a shed (when RoomKeepsOne is off), which relay a listener *)
(* picks among equals, and how long a re-punch takes.                     *)
(*                                                                         *)
(* Code references are in CallCongestion.md, per action.                  *)
(***************************************************************************)
EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    LSeq,               \* the listeners, in a fixed order (strings)
    \* --- the switches (FALSE = the code before the fix) -------------------
    ReceiptsPerAttempt, \* leviculum c75fdeb01: a proof for ANY attempt confirms
    RtoLearnsDelay,     \* every attempt-tagged proof is an RTT sample (RFC 6298 5, 3522)
    Hold113,            \* leviculum 206734977: no teardown while authenticated inbound
    ShedOnVerdict,      \* shed on the stall verdict's rise, latched (not at the window)
    RoomKeepsOne,       \* a shed keeps exactly one direct child (never zero)
    SlowStart,          \* the publisher starts at InitFanout children and widens
    RedialOnPathUp,     \* a dead leg redials when its path is back, not on backoff
    ShedDrains,         \* a shed child keeps media until it moved (make-before-break)
    PeerLiveness,       \* the hold counts authenticated inbound from the PEER on any leg
                        \* (leviculum's PeerEvidenceHold)
    ProbeBackoff,       \* any widening waits 2 windows x 2^fails (fails <= 2)
    HashRank,           \* P keeps, and receivers spare, the lowest-ranked child by a
                        \* rank every member computes (RankSeq), not admission order
    RankSeq,            \* that rank (the order of hash(stream, child key))
    StaggeredSetup,     \* P's legs are set up one per StaggerTicks, not all at once
    StaggerTicks,
    SetupUnits,         \* queue units P's side of one leg's setup costs (0: free)
    SerialRedial,       \* while P's verdict holds: one leg setup at a time; a
                        \* listener heard through a relay defers its legs' redial
    ProbeTwoLegs,       \* P sends a small control frame each ProbeEvery on <= 2 idle legs
    FreshEvidence,      \* evidence = packets that ADVANCE state only (a new Channel
                        \* sequence, a proof for an outstanding receipt, a new chunk)
    ConditionalRto,     \* the learned RTO applies only while there is fresh evidence
                        \* since the message's first send; else the cold ladder
    ReplayAttack,       \* an on-path party replays old frames of DeadNode's after it dies
    DelayProofs,        \* an on-path party withholds the proofs DelayVictim emits
    DelayVictim, AdvFrom, AdvTo,
    OwnDownlinkGuard,   \* RM6: no late move when every source is late (own downlink)
    RankScope,          \* RM4, whom the receivers spare: "member" (the lowest-ranked
                        \* member), "child" (the lowest-ranked of P's direct children,
                        \* exactly), "offer" (the same, as the members' offers show it)
    StallHold,          \* no widening for this long after the last congestion (ticks)
    SilentListener,     \* F14a: a listener sends nothing periodic on its leg to P
    KeepFresh,          \* D1 both sides: P never holds per-leg control past OfferEvery,
                        \* and a listener sends >= 1 fresh message per OfferEvery on its
                        \* leg to every node it receives from
    TreeRepair,         \* F14b: no new media on any path for RepairTicks -> re-subscribe
    AdmitCleanup,       \* an Admit nobody is waiting for is answered by an Unsubscribe
    CtrlBg,             \* P's other A/V control, units per tick (load only)
    NonChildEvery,      \* P offers to members that are not its children this often
    KillAt,             \* P's leg to its first direct child is torn at this tick (0: never)
    UpstreamShed,       \* a relay that loses its parent sheds its children (they fail over)
    RepairTicks,
    BindEvery,          \* F13: P re-announces its stream binding every BindEvery (0: off)
    BindParts,          \* ... as this many Channel messages per leg
    BindSize,           \* ... each this many units (a hybrid-signed part)
    RetxReenter,        \* a retransmit is a new packet: it re-enters the queue
    BindSkip,           \* skip the re-announce on a leg while the verdict holds or the
                        \* leg is backlogged (av_binding_reannounce_held) ...
    BindSkipMax,        \* ... at most this many rounds in a row (the bound)
    BindPace,           \* send one part per leg every BindPace ticks (1: all at once)
    BindExpire,         \* a re-announce part is never retransmitted: at its first
                        \* timeout it expires (it repeats what the peer has)
    StandbyFeed,        \* what a STANDBY child of P gets (an opaque or audio stream):
                        \* "none": no standbys (the model before F12);
                        \* "full": today's contract (alm.rs:31-32): every chunk, a full
                        \*   copy; a stall-shed child stays P's standby; the standby's
                        \*   commitment counts in the one-stream room;
                        \* "fix": nothing to a standby under a latched verdict, a stall
                        \*   shed leaves no standby, a shed never takes the last primary
    SlowNode, SlowTicks,\* a listener whose own downlink adds SlowTicks to everything
    DepartureHolds,     \* RM5: P reads ANY direct child's departure as a late one
    Graceful,           \* DeadNode hangs up (unsubscribes its parent) instead of dying
    SilenceFailover,    \* a child whose primary delivered nothing for SilentTicks moves
    SilentTicks,
    StallDrain,         \* while the verdict holds, P's copies are DrainPct of a copy
    DrainPct,
    ProbeEvery,
    ReceiverMoves,      \* a non-first child that sees P's media late moves itself
    RxDelayTicks,       \* ... at this media delay (ticks)
    QTarget,            \* the queue delay the steady state must get under (ticks)
    GapBound,           \* a stall-shed child has a parent again within this (ticks)
    CloseLost,          \* environment: a LINKCLOSE never reaches the peer (#1030)
    \* --- the uplink --------------------------------------------------------
    M,                  \* media units one child's copy costs per tick
    RCap, RFree,        \* P's drain rate (units/tick) while capped / not
    CtrlSize,           \* units a control message (or close) costs
    CapAt, CapUntil,    \* the cap holds on ticks CapAt .. CapUntil-1
    Horizon,            \* the last tick
    TailTicks,          \* heard is judged on what P published before Horizon-TailTicks
    \* --- the Channel -------------------------------------------------------
    MaxTries,           \* CHANNEL_MAX_TRIES
    Stale,              \* the link's stale bound (ticks)
    HeldCap,            \* CHANNEL_HELD_RETRY_MAX_MS (ticks)
    SrttCap8,           \* srtt_cap_ms, in eighths of a tick
    \* --- edge --------------------------------------------------------------
    WatchEvery,         \* the call's watch tick (ticks)
    StallTicks,         \* UPLINK_STALL_MS
    StallLegs,          \* UPLINK_STALL_LEGS
    Latch,              \* UPLINK_STALL_LATCH_MS (ShedOnVerdict only)
    WindowTicks,        \* the egress meter's window
    OfferEvery,         \* OFFER_EVERY_MS
    StallOfferEvery,    \* STALL_OFFER_EVERY_MS
    InitFanout,         \* SlowStart's first room
    RelaySlots,         \* a relay's room (its cold-start trial slot)
    MaxDepth,           \* max_depth
    DrainTicks,         \* down_silence_ms: how long a drained child is fed
    Dwell,              \* min_dwell_ms (scaled)
    CeilingStale,       \* CEILING_STALE_MS (scaled)
    DownSilence,        \* an offer older than this is forgotten
    SubTimeout,         \* a subscribe with no answer is given up
    Backoff,            \* the selector's backoff after a refuse / loss
    DialMin, DialMax,   \* DIAL_BACKOFF_MIN / _MAX
    PunchTimes,         \* how long a re-punch may take (a set of ticks)
    PPhases, LPhases, WPhases, \* offer phases of P / of listeners, window phases
    NPick,              \* how many equal relays a listener may choose among
    MaxReparents,       \* the bound on re-parentings per listener (join included)
    RecoverBy,          \* ticks after the cap lifts by which full fan-out is back
    DeadNode, DeadAt,   \* a node that dies at DeadAt ("none": nobody)
    TraceOn,            \* keep a compact per-tick history (for traces only)
    Wide                \* each listener its own offer phase and tie-break
                        \* (FALSE: one phase and one tie-break for all)

L == {LSeq[i] : i \in 1..Len(LSeq)}
NL == Len(LSeq)
None == "none"
Nodes == {"P"} \cup L
NodeSeq == <<"P">> \o LSeq
Legs == {<<x, y>> \in Nodes \X Nodes : x /= y}
PLegs == {l \in Legs : l[1] = "P"}

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

Capped(t) == CapAt <= t /\ t < CapUntil
Rate(t) == IF Capped(t) THEN RCap ELSE RFree
\* Heard is judged on what P published WHILE CAPPED (up to TailTicks before the
\* horizon, so it can still arrive); with no cap, on the whole run.
InWin(t) == IF CapAt >= Horizon THEN t <= Horizon - TailTicks
            ELSE CapAt <= t /\ t < CapUntil /\ t <= Horizon - TailTicks
QDelayS(S) == IF S.backlog = 0 THEN 0 ELSE (S.backlog - 1) \div Rate(S.now)

\* 8 x 1.5^(k-1), rounded down: 8, 12, 18, 27, 40, 60, 91, 136, ...
OrdNum(k) == (8 * 3^(k - 1)) \div (2^(k - 1))
\* base RTO in ticks from SRTT in eighths: max(1, ceil(2.5 x srtt))
Base(s8) == Max(1, (5 * s8 + 15) \div 16)
\* calculate_timeout at try k, rounded to the tick; past MaxTries the held
\* wait: min(the backed-off wait, max(HeldCap, the last ordinary wait)).
Ordinary(k, b) == Max(1, (b * OrdNum(k) + 4) \div 8)
Wait(k, b) == IF k <= MaxTries THEN Ordinary(k, b)
              ELSE Min(Ordinary(k, b), Max(HeldCap, Ordinary(MaxTries, b)))

Pay(p) == [p |-> p, fwd |-> FALSE, room |-> FALSE, direct |-> FALSE]
Offer(f, r) == [p |-> "offer", fwd |-> f, room |-> r, direct |-> FALSE]
OfferD(f, r, d) == [p |-> "offer", fwd |-> f, room |-> r, direct |-> d]
NoPay == Pay("none")
Item(k, leg, g, q, a, pay, from, to, t) ==
    [k |-> k, leg |-> leg, gen |-> g, seq |-> q, att |-> a, pay |-> pay,
     from |-> from, to |-> to, t |-> t]
NoObs == [seq |-> -1, since |-> -1]

VARIABLES
    now,
    \* (a) the uplink and the network
    fifo, backlog, net,
    \* (b) legs and Channels (dialer's view, except peerUp)
    up, peerUp, gen, downAt, chan, nextSeq, rxNext, srtt8, lastAuth, peerAuth,
    \* (e) redial
    dialAt, dialBo, pathAt,
    \* (c) the publisher
    children, order, drainTo, shedPend, room, demand, lastCong, lastWiden, probeFails,
    stall, stallSeen, obs, verdicts, sheds, zeroShed, lastOffer, winPhase,
    \* (d) listeners
    relayKids, parent, pendSub, pendAt, boUntil, reparents, lastSwitch,
    shedBy, offerAt, offerFwd, offerRoom, rxDelay, lateMove,
    \* bookkeeping the properties read
    heard, lastHeard, lastFwd, published, torn, dual, maxQd,
    firstVerdictAt, firstShedAt, firstShedQ, fullAt, lastSetupAt,
    shedAtL, maxParentGap, lastNewAt, maxMediaGap, idleCand, lastFromParent, drainClear, capEndQ, slowMoved, offerDirect, zeroRun, maxZeroRun, standbys, maxStallCopies, primaryGapRun, maxPrimaryGap, bindSkips, lastOfferNC, allOkAt, lostAt,
    hist,               \* the compact history (empty unless TraceOn)
    choice,             \* this behaviour's choices, fixed at Init (see Choices)
    bad                 \* the properties this behaviour has violated so far

vars == <<now, fifo, backlog, net, up, peerUp, gen, downAt, chan, nextSeq,
          rxNext, srtt8, lastAuth, peerAuth, rxDelay, probeFails, lateMove, maxQd,
          firstVerdictAt, firstShedAt, firstShedQ, fullAt, lastSetupAt,
          shedAtL, maxParentGap, lastNewAt, maxMediaGap, idleCand, lastFromParent, drainClear, capEndQ, slowMoved, offerDirect, zeroRun, maxZeroRun, standbys, maxStallCopies, primaryGapRun, maxPrimaryGap, bindSkips, lastOfferNC, allOkAt, lostAt, dialAt, dialBo, pathAt, children, order,
          drainTo, shedPend, room, demand, lastCong, lastWiden, stall, stallSeen, obs,
          verdicts, sheds, zeroShed, lastOffer, winPhase, relayKids, parent,
          pendSub, pendAt, boUntil, reparents, lastSwitch, shedBy, offerAt,
          offerFwd, offerRoom, heard, lastHeard, lastFwd, published, torn, dual,
          hist, bad, choice>>

ASSUME /\ NL >= 2 /\ RCap >= 1 /\ RFree >= RCap /\ MaxTries >= 1
       /\ CapAt >= 0 /\ Stale > 0 /\ WatchEvery >= 1

-----------------------------------------------------------------------------
(* The state as one record, so a tick can be written as a pipeline of     *)
(* pure steps S -> S. The choice ch: [keep, pick, punch].                  *)
-----------------------------------------------------------------------------
Rec == [now |-> now, fifo |-> fifo, backlog |-> backlog, net |-> net, up |-> up,
        peerUp |-> peerUp, gen |-> gen, downAt |-> downAt, chan |-> chan,
        nextSeq |-> nextSeq, rxNext |-> rxNext, srtt8 |-> srtt8,
        lastAuth |-> lastAuth, peerAuth |-> peerAuth, rxDelay |-> rxDelay, dialAt |-> dialAt, dialBo |-> dialBo,
        pathAt |-> pathAt, children |-> children, order |-> order,
        drainTo |-> drainTo, shedPend |-> shedPend, room |-> room,
        demand |-> demand, lastCong |-> lastCong, lastWiden |-> lastWiden, probeFails |-> probeFails, lateMove |-> lateMove,
        maxQd |-> maxQd, firstVerdictAt |-> firstVerdictAt, firstShedAt |-> firstShedAt,
        firstShedQ |-> firstShedQ, fullAt |-> fullAt, lastSetupAt |-> lastSetupAt,
        shedAtL |-> shedAtL, maxParentGap |-> maxParentGap, lastNewAt |-> lastNewAt,
        maxMediaGap |-> maxMediaGap, idleCand |-> idleCand, lastFromParent |-> lastFromParent,
        drainClear |-> drainClear, capEndQ |-> capEndQ, slowMoved |-> slowMoved,
        offerDirect |-> offerDirect, zeroRun |-> zeroRun, maxZeroRun |-> maxZeroRun,
        standbys |-> standbys, maxStallCopies |-> maxStallCopies, primaryGapRun |-> primaryGapRun,
        maxPrimaryGap |-> maxPrimaryGap, bindSkips |-> bindSkips, lastOfferNC |-> lastOfferNC,
        allOkAt |-> allOkAt, lostAt |-> lostAt,
        stall |-> stall,
        stallSeen |-> stallSeen, obs |-> obs, verdicts |-> verdicts,
        sheds |-> sheds, zeroShed |-> zeroShed, lastOffer |-> lastOffer,
        winPhase |-> winPhase, relayKids |-> relayKids, parent |-> parent,
        pendSub |-> pendSub, pendAt |-> pendAt, boUntil |-> boUntil,
        reparents |-> reparents, lastSwitch |-> lastSwitch, shedBy |-> shedBy,
        offerAt |-> offerAt, offerFwd |-> offerFwd, offerRoom |-> offerRoom,
        heard |-> heard, lastHeard |-> lastHeard, lastFwd |-> lastFwd,
        published |-> published, torn |-> torn, dual |-> dual, hist |-> hist, bad |-> bad]

Alive(S, n) == ~(n = DeadNode /\ S.now >= DeadAt)

\* (a) Hand an item to node n's uplink: P's is the FIFO (position = units
\* ahead of it plus its own), every other node's is uncapped (net, delivered
\* within the tick).
Emit(S, n, it, size) ==
    IF n = "P"
    THEN LET pos == S.backlog + size
         IN [S EXCEPT !.fifo = Append(@, [pos |-> pos, it |-> it]), !.backlog = pos]
    ELSE [S EXCEPT !.net = Append(@, it)]

\* (b) A new Channel message on leg l (Channel::send -> ReceiptTracker::register).
SizeOf(pay) == IF pay.p = "bind" THEN BindSize ELSE CtrlSize
SendCtrl(S, l, pay) ==
    IF ~S.up[l] \/ ~Alive(S, l[1]) THEN S
    ELSE LET q == S.nextSeq[l]
             S1 == [S EXCEPT !.chan[l] = Append(@, [seq |-> q, first |-> S.now,
                                                   atts |-> <<S.now>>, pay |-> pay]),
                             !.nextSeq[l] = q + 1]
         IN Emit(S1, l[1], Item("ctrl", l, S.gen[l], q, 1, pay, l[1], {}, S.now), SizeOf(pay))

RECURSIVE SendEach(_, _, _)
SendEach(S, set, pay) ==   \* P sends pay to each listener in set
    IF set = {} THEN S
    ELSE LET v == CHOOSE v \in set : TRUE
         IN SendEach(SendCtrl(S, <<"P", v>>, pay), set \ {v}, pay)

RemoveAt(s, i) == SubSeq(s, 1, i - 1) \o SubSeq(s, i + 1, Len(s))

\* The ancestors of x for P's stream (bounded by the depth).
RECURSIVE ChainN(_, _, _)
ChainN(S, x, d) ==
    IF d = 0 \/ x = "P" \/ x = None THEN {}
    ELSE IF S.parent[x] = None THEN {}
    ELSE {S.parent[x]} \cup ChainN(S, S.parent[x], d - 1)
Chain(S, x) == ChainN(S, x, NL + 1)
Depth(S, x) == IF x = "P" THEN 0 ELSE Cardinality(Chain(S, x))

\* (c) The leg to child y went down at its dialer x (on_child_link_down).
ChildDown(S, x, y) ==
    IF x = "P"
    THEN [S EXCEPT !.children = @ \ {y}, !.drainTo[y] = -1, !.shedPend[y] = FALSE,
                   !.standbys = @ \ {y}]
    ELSE [S EXCEPT !.relayKids[x] = @ \ {y}]

\* (e) Leg l torn down at its dialer (check_channel_timeouts TearDownLink).
TearDown(S, l, why, ch) ==
    LET S1 == [S EXCEPT !.up[l] = FALSE, !.chan[l] = <<>>, !.downAt[l] = S.now,
                        !.torn = @ \cup {[leg |-> l, why |-> why, at |-> S.now,
                                          peerAlive |-> Alive(S, l[2])]},
                        !.pathAt[l] = S.now + ch.punch,
                        !.dialBo[l] = DialMin, !.dialAt[l] = S.now + DialMin]
        S2 == IF CloseLost THEN S1
              ELSE Emit(S1, l[1], Item("close", l, S.gen[l], 0, 0, NoPay, l[1], {}, S.now), CtrlSize)
    IN ChildDown(S2, l[1], l[2])

\* (c) The shed: keep the `keep` OLDEST children (LIFO shed), notify the rest.
ShedTo(S, keep) ==
    LET kids == S.children
        ordered == IF HashRank THEN SelectSeq(RankSeq, LAMBDA x : x \in kids)
                   ELSE SelectSeq(S.order, LAMBDA x : x \in kids)
        \* "full": each standby's (full-copy) commitment counts against the
        \* one-stream room first, so the primaries keep what is left
        room1 == IF StandbyFeed = "full" THEN Max(0, keep - Cardinality(S.standbys)) ELSE keep
        kept == {ordered[i] : i \in 1..Min(room1, Len(ordered))}
        victims == kids \ kept
        S1 == [S EXCEPT !.children = kept, !.room = 1,
                        !.standbys = IF StandbyFeed = "full" THEN (@ \cup victims) \ kept
                                     ELSE IF StandbyFeed \in {"fix", "fix2"} THEN {} ELSE @,
                        !.firstShedAt = IF @ < 0 /\ victims /= {} THEN S.now ELSE @,
                        !.firstShedQ = IF @ < 0 /\ victims /= {} THEN QDelayS(S) ELSE @,
                        !.zeroShed = @ \/ (kept = {} /\ kids /= {}),
                        !.sheds = @ + Cardinality(victims),
                        !.drainTo = [v \in L |-> IF v \in victims /\ ShedDrains
                                                 THEN S.now + DrainTicks ELSE @[v]],
                        !.shedPend = [v \in L |-> IF v \in victims THEN TRUE ELSE @[v]],
                        !.shedAtL = [v \in L |-> IF v \in victims THEN S.now ELSE @[v]]]
    IN SendEach(S1, victims, Pay("shed"))

KeepOf(ch) == IF RoomKeepsOne THEN 1 ELSE ch.keep

-----------------------------------------------------------------------------
(* Receiving.                                                              *)
-----------------------------------------------------------------------------
\* Media of P's tick t from s at c (dedup by t; a relay forwards new t).
Media1(S, s, c, t) ==
    IF ~Alive(S, c) \/ ~S.peerUp[<<s, c>>] THEN S
    ELSE LET S0 == [S EXCEPT !.peerAuth[c][s] = IF ~FreshEvidence \/ t > S.lastHeard[c] THEN S.now ELSE @,
                             !.lastFromParent[c] = IF S.parent[c] = s THEN S.now ELSE @,
                             !.rxDelay[c] = IF s = "P" THEN S.now - t + (IF c = SlowNode THEN SlowTicks ELSE 0) ELSE @]
             S1 == IF t > S0.lastHeard[c]
                   THEN [S0 EXCEPT !.lastHeard[c] = t, !.lastNewAt[c] = S.now,
                                   !.heard[c] = IF InWin(t) THEN @ + 1 ELSE @]
                   ELSE S0
             kids == {k \in S1.relayKids[c] : S1.up[<<c, k>>]}
         IN IF kids /= {} /\ t > S1.lastFwd[c]
            THEN [S1 EXCEPT !.lastFwd[c] = t,
                            !.net = Append(@, Item("media", <<c, c>>, 0, 0, 0, NoPay, c, kids, t))]
            ELSE S1

RECURSIVE MediaTo(_, _, _, _)
MediaTo(S, s, set, t) ==
    IF set = {} THEN S
    ELSE LET c == CHOOSE c \in set : TRUE
         IN MediaTo(Media1(S, s, c, t), s, set \ {c}, t)

PAdmit(S, l) ==
    IF l \in S.children THEN SendCtrl(S, <<"P", l>>, Pay("admit"))
    ELSE IF Cardinality(S.children) < S.room
    THEN SendCtrl([S EXCEPT !.children = @ \cup {l}, !.standbys = @ \ {l},
                            !.order = Append(SelectSeq(@, LAMBDA x : x /= l), l),
                            !.drainTo[l] = -1, !.shedPend[l] = FALSE],
                  <<"P", l>>, Pay("admit"))
    ELSE SendCtrl([S EXCEPT !.demand = TRUE], <<"P", l>>, Pay("refuse"))

RelayAdmit(S, x, l) ==
    IF /\ S.parent[x] /= None
       /\ l \notin Chain(S, x)
       /\ Depth(S, x) < MaxDepth
       /\ (l \in S.relayKids[x] \/ Cardinality(S.relayKids[x]) < RelaySlots)
    THEN SendCtrl([S EXCEPT !.relayKids[x] = @ \cup {l}], <<x, l>>, Pay("admit"))
    ELSE SendCtrl(S, <<x, l>>, Pay("refuse"))

OnAdmit(S, l, x) ==
    IF S.pendSub[l] /= x
    THEN IF AdmitCleanup /\ S.parent[l] /= x THEN SendCtrl(S, <<l, x>>, Pay("unsub")) ELSE S
    ELSE LET old == S.parent[l]
             S1 == [S EXCEPT !.parent[l] = x, !.pendSub[l] = None,
                             !.reparents[l] = @ + 1, !.lastSwitch[l] = S.now,
                             !.maxParentGap = IF S.shedAtL[l] >= 0 THEN Max(@, S.now - S.shedAtL[l]) ELSE @,
                             !.shedAtL[l] = -1, !.lastFromParent[l] = S.now,
                             !.shedBy[l] = None, !.lateMove[l] = FALSE]
             \* a move made because P's media came late says so: P reads it
             \* as congestion (ReceiverMoves)
             why == IF S.lateMove[l] /\ old = "P" THEN "unsub_late" ELSE "unsub"
             \* the selector demotes the old primary to a warm standby after a
             \* make-before-break switch (selector.rs module docs): with
             \* standbys modelled, a late mover keeps P as its standby (P hears
             \* the late departure through the role change: "standby_late")
             \* "fix2": a LATE move never keeps P as a standby (it unsubscribes)
             keepsP == StandbyFeed /= "none" /\ old = "P" /\ x /= "P"
                       /\ ~(StandbyFeed = "fix2" /\ S.lateMove[l])
             S2 == IF keepsP THEN SendCtrl(S1, <<l, old>>, Pay(IF S.lateMove[l] THEN "standby_late" ELSE "standby"))
                   ELSE IF old \notin {None, x} THEN SendCtrl(S1, <<l, old>>, Pay(why)) ELSE S1
             \* a publisher that shed this node make-before-break is told once
             \* the replacement is up (alm.rs draining_parent)
             S3 == IF S.shedBy[l] = "P" /\ x /= "P" /\ old /= "P" /\ StandbyFeed /= "full"
                   THEN SendCtrl(S2, <<l, "P">>, Pay("unsub")) ELSE S2
         IN S3

OnShed(S, l, x) ==
    IF S.parent[l] = x
    THEN [S EXCEPT !.parent[l] = None, !.boUntil[l][x] = S.now + 4 * Backoff,
                   !.shedBy[l] = x]
    ELSE [S EXCEPT !.shedBy[l] = IF x = "P" THEN x ELSE @]

Handle(S, pay, s, r) ==
    CASE pay.p = "offer" ->
            IF r = "P" THEN S
            ELSE [S EXCEPT !.offerAt[r][s] = S.now, !.offerFwd[r][s] = pay.fwd,
                           !.offerRoom[r][s] = pay.room, !.offerDirect[r][s] = pay.direct]
      [] pay.p = "sub" -> IF r = "P" THEN PAdmit(S, s) ELSE RelayAdmit(S, r, s)
      [] pay.p = "admit" -> OnAdmit(S, r, s)
      [] pay.p = "refuse" ->
            IF S.pendSub[r] = s
            THEN [S EXCEPT !.pendSub[r] = None, !.boUntil[r][s] = S.now + Backoff]
            ELSE S
      [] pay.p = "shed" -> OnShed(S, r, s)
      [] pay.p = "unsub_late" \/ (pay.p = "unsub" /\ DepartureHolds /\ r = "P" /\ s \in S.children) ->
            LET kids == S.children \ {s}
            IN [S EXCEPT !.children = kids, !.drainTo[s] = -1, !.shedPend[s] = FALSE,
                         !.standbys = @ \ {s},
                         !.room = Max(1, Cardinality(kids)), !.lastCong = S.now,
                         !.probeFails = IF ProbeBackoff THEN Min(@ + 1, 2) ELSE @]
      [] pay.p \in {"standby", "standby_late"} /\ r = "P" ->
            LET kids == S.children \ {s}
                late == pay.p = "standby_late" \/ (DepartureHolds /\ s \in S.children)
            IN [S EXCEPT !.children = kids, !.standbys = @ \cup {s}, !.drainTo[s] = -1,
                         !.shedPend[s] = FALSE,
                         !.room = IF late THEN Max(1, Cardinality(kids)) ELSE @,
                         !.lastCong = IF late THEN S.now ELSE @,
                         !.probeFails = IF late /\ ProbeBackoff THEN Min(@ + 1, 2) ELSE @]
      [] pay.p = "unsub" ->
            IF r = "P"
            THEN [S EXCEPT !.children = @ \ {s}, !.drainTo[s] = -1, !.shedPend[s] = FALSE,
                           !.standbys = @ \ {s}]
            ELSE [S EXCEPT !.relayKids[r] = @ \ {s}]
      [] OTHER -> S

RecvCtrl(S, it) ==
    LET l == it.leg  r == l[2]
    IN IF ~Alive(S, r) \/ ~S.peerUp[l] THEN S
       ELSE LET fresh == ~FreshEvidence \/ it.seq >= S.rxNext[l]
                withheld == DelayProofs /\ r = DelayVictim /\ AdvFrom <= S.now /\ S.now < AdvTo
                S0 == [S EXCEPT !.peerAuth[r][l[1]] = IF fresh THEN S.now ELSE @]
                S1 == IF withheld THEN S0
                      ELSE Emit(S0, r, Item("proof", l, it.gen, it.seq, it.att, NoPay, r, {}, S.now), 0)
            IN IF it.seq >= S1.rxNext[l]
               THEN Handle([S1 EXCEPT !.rxNext[l] = it.seq + 1], it.pay, l[1], r)
               ELSE S1   \* AlreadyDelivered: proved again, handled once

\* (b) A proof at the dialer (ReceiptTracker lookup + Channel::mark_delivered).
\* Without per-attempt receipts only the LATEST attempt's receipt exists:
\* a proof of an earlier attempt is unknown, dropped unauthenticated.
RecvProof(S, it) ==
    LET l == it.leg
        idx == {i \in 1..Len(S.chan[l]) : S.chan[l][i].seq = it.seq}
    IN IF ~Alive(S, l[1]) \/ ~S.up[l] \/ it.gen /= S.gen[l] \/ idx = {} THEN S
       ELSE LET i == CHOOSE i \in idx : TRUE
                m == S.chan[l][i]
                valid == ReceiptsPerAttempt \/ it.att = Len(m.atts)
            IN IF ~valid THEN S
               ELSE LET sample == IF RtoLearnsDelay THEN S.now - m.atts[it.att]
                                  ELSE IF Len(m.atts) = 1 THEN S.now - m.atts[1]
                                  ELSE -1   \* Karn: no sample from a retransmitted message
                        s8 == S.srtt8[l]
                        raw == IF s8 = 0 THEN 8 * sample ELSE s8 - (s8 \div 8) + sample
                        n8 == IF sample <= 0 THEN s8
                              ELSE IF RtoLearnsDelay THEN Min(raw, SrttCap8) ELSE raw
                    IN [S EXCEPT !.chan[l] = RemoveAt(@, i), !.lastAuth[l] = S.now,
                                 !.peerAuth[l[1]][l[2]] = S.now, !.srtt8[l] = n8]

RecvClose(S, it) ==
    LET l == it.leg
    IN IF l \in Legs /\ Alive(S, l[2]) /\ S.peerUp[l] /\ it.gen = S.gen[l]
       THEN [S EXCEPT !.peerUp[l] = FALSE,
                      !.torn = @ \cup {[leg |-> l, why |-> "peer_closed", at |-> S.now,
                                        peerAlive |-> Alive(S, l[1])]}]
       ELSE S

Recv(S, it) ==
    CASE it.k = "media" -> MediaTo(S, it.from, it.to, it.t)
      [] it.k = "ctrl"  -> RecvCtrl(S, it)
      [] it.k = "proof" -> RecvProof(S, it)
      [] it.k = "close" -> RecvClose(S, it)

\* Everything the uncapped nodes send arrives within the tick (and what it
\* provokes, in turn). Bounded: each handler emits a bounded number of items.
RECURSIVE Settle(_, _)
Settle(S, fuel) ==
    IF S.net = <<>> \/ fuel = 0 THEN S
    ELSE Settle(Recv([S EXCEPT !.net = Tail(@)], Head(S.net)), fuel - 1)
Flush(S) == Settle(S, 200)

RECURSIVE RecvAll(_, _)
RecvAll(S, items) ==
    IF items = <<>> THEN S ELSE RecvAll(Flush(Recv(S, Head(items))), Tail(items))

-----------------------------------------------------------------------------
(* The phases of one tick.                                                 *)
-----------------------------------------------------------------------------
\* (b) Channel timers on every live leg (Channel::poll_with_inbound).
\* PeerLiveness: any authenticated packet from the same peer, on any leg
\* (its own leg's frames and datagrams decrypt under that link's key), not
\* only this leg's proofs.
AuthSince(S, l) == IF PeerLiveness THEN S.peerAuth[l[1]][l[2]] ELSE S.lastAuth[l]
Held(S, l, m) == (Hold113 \/ PeerLiveness) /\ AuthSince(S, l) > m.first /\ S.now < m.first + Stale

RECURSIVE TimerMsgs(_, _, _, _)
TimerMsgs(S, l, i, ch) ==
    IF ~S.up[l] \/ i > Len(S.chan[l]) THEN S
    ELSE LET m == S.chan[l][i]
             k == Len(m.atts)
             learned == ~ConditionalRto \/ AuthSince(S, l) > m.first
             due == m.atts[k] + Wait(k, Base(IF learned THEN S.srtt8[l] ELSE 0))
         IN IF S.now < due THEN TimerMsgs(S, l, i + 1, ch)
            ELSE IF BindExpire /\ m.pay.p = "bind"
            THEN TimerMsgs([S EXCEPT !.chan[l] = RemoveAt(@, i)], l, i, ch)
            ELSE IF k >= MaxTries /\ ~Held(S, l, m) THEN TearDown(S, l, "exhausted", ch)
            ELSE LET S1 == [S EXCEPT !.chan[l][i].atts = Append(@, S.now)]
                     S2 == Emit(S1, l[1], Item("ctrl", l, S.gen[l], m.seq, k + 1, m.pay,
                                               l[1], {}, S.now),
                                IF RetxReenter THEN SizeOf(m.pay) ELSE 0)
                 IN TimerMsgs(S2, l, i + 1, ch)

RECURSIVE TimersOver(_, _, _)
TimersOver(S, ls, ch) ==
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             S1 == IF S.up[l] /\ Alive(S, l[1]) THEN TimerMsgs(S, l, 1, ch) ELSE S
         IN TimersOver(S1, ls \ {l}, ch)
Timers(S, ch) == Flush(TimersOver(S, Legs, ch))

\* (e) The peer side of a leg goes stale once its dialer is gone (dead, or
\* torn down with the close lost) for the stale bound.
GoneSince(S, l) == IF ~Alive(S, l[1]) THEN DeadAt ELSE IF ~S.up[l] THEN S.downAt[l] ELSE -1
StaleLegs(S) ==
    LET gone == {l \in Legs : S.peerUp[l] /\ Alive(S, l[2]) /\ GoneSince(S, l) >= 0
                              /\ S.now - GoneSince(S, l) >= Stale}
    IN [S EXCEPT !.peerUp = [l \in Legs |-> IF l \in gone THEN FALSE ELSE @[l]],
                 !.torn = @ \cup {[leg |-> l, why |-> "stale", at |-> S.now,
                                   peerAlive |-> Alive(S, l[1])] : l \in gone}]

\* (e) Redial (reconcile_legs / dial_leg; DirectPathTracker::link_closed).
DialDue(S, l) == IF RedialOnPathUp THEN S.now >= S.dialAt[l] \/ S.now = S.pathAt[l]
                 ELSE S.now >= S.dialAt[l]
InvolvesP(l) == l[1] = "P" \/ l[2] = "P"
\* SerialRedial: while P's verdict holds, one P leg's setup at a time (one per
\* SetupGap), and a listener that hears P through a relay defers its legs
\* with P (it retries on its backoff).
SetupGap == Max(1, SetupUnits \div RCap)
SerialOK(S, l) ==
    ~SerialRedial \/ ~InvolvesP(l) \/ ~S.stall
    \/ (S.now - S.lastSetupAt >= SetupGap
        /\ ~(l[1] \in L /\ S.parent[l[1]] \notin {None, "P"})
        /\ ~(l[2] \in L /\ S.parent[l[2]] \notin {None, "P"}))
\* P's side of a leg's setup (link handshake, PQC transit KEX, hello,
\* bindings) queues on P's uplink.
SetupCost(S, l) ==
    IF SetupUnits > 0 /\ InvolvesP(l)
    THEN Emit([S EXCEPT !.lastSetupAt = S.now], "P",
              Item("close", <<"none", "none">>, -1, 0, 0, NoPay, "P", {}, S.now), SetupUnits)
    ELSE S
RECURSIVE RedialOver(_, _)
RedialOver(S, ls) ==
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             S1 == IF ~S.up[l] /\ Alive(S, l[1]) /\ DialDue(S, l)
                   THEN IF S.now >= S.pathAt[l] /\ Alive(S, l[2]) /\ SerialOK(S, l)
                        THEN SetupCost([S EXCEPT !.up[l] = TRUE, !.peerUp[l] = TRUE, !.gen[l] = @ + 1,
                                       !.chan[l] = <<>>, !.srtt8[l] = 0, !.lastAuth[l] = -1,
                                       !.rxNext[l] = S.nextSeq[l], !.dialBo[l] = DialMin], l)
                        ELSE LET b == Min(2 * S.dialBo[l], DialMax)
                             IN [S EXCEPT !.dialBo[l] = b, !.dialAt[l] = S.now + b]
                   ELSE S
         IN RedialOver(S1, ls \ {l})
Redial(S) == RedialOver(S, Legs)

\* (c) The publisher's watch: the stall verdict (alm_tick), the shed on its
\* rise when ShedOnVerdict.
PWatch(S, ch) ==
    IF ~Alive(S, "P") THEN S
    ELSE LET live == {l \in PLegs : S.up[l]}
             newObs == [l \in Legs |->
                         IF l \in live /\ Len(S.chan[l]) > 0
                         THEN IF S.obs[l].seq = S.chan[l][1].seq THEN S.obs[l]
                              ELSE [seq |-> S.chan[l][1].seq, since |-> S.now]
                         ELSE NoObs]
             stalled == {l \in live : newObs[l].seq >= 0 /\ S.now - newObs[l].since >= StallTicks}
             det == Cardinality(stalled) >= StallLegs
             seen == IF det THEN S.now ELSE S.stallSeen
             st == IF ShedOnVerdict THEN seen >= 0 /\ S.now - seen < Latch ELSE det
             S1 == [S EXCEPT !.obs = newObs, !.stallSeen = seen, !.stall = st,
                             !.verdicts = IF st /\ ~S.stall THEN @ + 1 ELSE @,
                             !.firstVerdictAt = IF @ < 0 /\ st THEN S.now ELSE @]
         IN IF ShedOnVerdict /\ st /\ ~S.stall /\ Cardinality(S1.children) > KeepOf(ch)
            THEN ShedTo(S1, KeepOf(ch)) ELSE S1

\* (d) A listener's selector.
Viable(S, l, x) ==
    /\ x /= l /\ Alive(S, x)
    /\ S.up[<<l, x>>] /\ S.peerUp[<<x, l>>]
    /\ S.now >= S.boUntil[l][x]
    /\ S.offerAt[l][x] >= 0 /\ S.now - S.offerAt[l][x] <= DownSilence
    /\ S.offerFwd[l][x] /\ S.offerRoom[l][x]
    /\ (x = "P" \/ l \notin Chain(S, x))
Cands(S, l) == SelectSeq(NodeSeq, LAMBDA x : x \in Nodes /\ Viable(S, l, x))
Pick(c, k) == IF c[1] = "P" THEN "P" ELSE c[Min(k, Len(c))]
Subscribe(S, l, x) ==
    SendCtrl([S EXCEPT !.pendSub[l] = x, !.pendAt[l] = S.now], <<l, x>>, Pay("sub"))

LWatch1(S, l, k) ==
    IF ~Alive(S, l) THEN S
    ELSE LET lost == S.parent[l] /= None /\ (~S.peerUp[<<S.parent[l], l>>] \/ ~S.up[<<l, S.parent[l]>>])
             S0 == IF lost
                   THEN [S EXCEPT !.boUntil[l][S.parent[l]] = S.now + Backoff,
                                  !.parent[l] = None]
                   ELSE S
             \* UpstreamShed: a relay that lost its parent sheds its children
             \* (Shed{UpstreamLost}), so they fail over on the S1 path
             kids == S0.relayKids[l]
             RECURSIVE ShedKids(_, _)
             ShedKids(T, ks) == IF ks = {} THEN T
                                ELSE LET kd == CHOOSE kx \in ks : TRUE
                                     IN ShedKids(SendCtrl(T, <<l, kd>>, Pay("shed")), ks \ {kd})
             S1 == IF UpstreamShed /\ lost /\ kids /= {}
                   THEN ShedKids([S0 EXCEPT !.relayKids[l] = {}], kids)
                   ELSE S0
             S2 == IF S1.pendSub[l] /= None /\ S1.now - S1.pendAt[l] >= SubTimeout
                   THEN [S1 EXCEPT !.boUntil[l][S1.pendSub[l]] = S1.now + Backoff,
                                   !.pendSub[l] = None]
                   ELSE S1
             \* TreeRepair: nothing new on any path for RepairTicks while the
             \* stream is live (P is publishing): drop the parent and look again
             S2r == IF TreeRepair /\ S2.parent[l] /= None /\ S2.pendSub[l] = None
                        /\ S2.now - S2.lastNewAt[l] >= RepairTicks /\ Alive(S2, "P")
                    THEN [S2 EXCEPT !.boUntil[l][S2.parent[l]] = S2.now + Backoff, !.parent[l] = None]
                    ELSE S2
             c == Cands(S2r, l)
             \* HashRank: the lowest-ranked MEMBER never moves on late media
             \* (computable by everyone); else P's oldest child (the rank rides
             \* the Admit, a wire addition)
             \* who l believes P's direct children are (itself included when
             \* its own parent is P)
             believed == IF RankScope = "child" THEN S2r.children
                         ELSE {x \in L : x = l \/ (S2r.offerDirect[l][x] /\ S2r.now - S2r.offerAt[l][x] <= DownSilence)}
             spared == IF RankScope = "member" THEN RankSeq[1]
                       ELSE LET o == SelectSeq(RankSeq, LAMBDA x : x \in believed)
                            IN IF o = <<>> THEN None ELSE o[1]
             first == IF HashRank THEN spared
                      ELSE LET o == SelectSeq(S2r.order, LAMBDA x : x \in S2r.children)
                           IN IF o = <<>> THEN None ELSE o[1]
             relays == SelectSeq(c, LAMBDA x : x /= "P")
         IN IF S2r.pendSub[l] = None /\ S2r.parent[l] = None /\ c /= <<>>
            THEN Subscribe(S2r, l, Pick(c, k))
            \* ReceiverMoves: P's media reaches this child late, and it is not
            \* P's first child (the one P keeps; the rank rides the Admit):
            \* move to a relay, keeping P until the relay admits.
            ELSE IF /\ ReceiverMoves /\ S2r.pendSub[l] = None /\ S2r.parent[l] = "P"
                    /\ S2r.rxDelay[l] >= RxDelayTicks /\ first /= l /\ relays /= <<>>
                    \* RM6: what another source shows (every other stream this node
                    \* hears carries its own downlink's delay too)
                    /\ ~(OwnDownlinkGuard /\ l = SlowNode /\ 2 * SlowTicks >= RxDelayTicks)
            THEN Subscribe([S2r EXCEPT !.lateMove[l] = TRUE,
                                      !.slowMoved = @ \/ l = SlowNode], l, relays[Min(k, Len(relays))])
            \* SilenceFailover: the primary delivered nothing for SilentTicks
            \* and another member that hears the stream offers: move to it,
            \* keeping the old parent until the new one admits.
            ELSE IF /\ SilenceFailover /\ S2r.pendSub[l] = None /\ S2r.parent[l] /= None
                    /\ S2r.now - S2r.lastFromParent[l] >= SilentTicks
                    /\ SelectSeq(relays, LAMBDA x : x /= S2r.parent[l]) /= <<>>
            THEN LET rs == SelectSeq(relays, LAMBDA x : x /= S2r.parent[l])
                 IN Subscribe(S2r, l, rs[Min(k, Len(rs))])
            ELSE IF /\ S2r.pendSub[l] = None /\ S2r.parent[l] \notin {None, "P"}
                    /\ Viable(S2r, l, "P") /\ S2r.now - S2r.lastSwitch[l] >= Dwell
            THEN Subscribe(S2r, l, "P")
            ELSE S2r

RECURSIVE LWatchOver(_, _, _)
LWatchOver(S, i, ch) ==
    IF i > NL THEN S
    ELSE LWatchOver(Flush(LWatch1(S, LSeq[i], ch.pick[LSeq[i]])), i + 1, ch)

Watch(S, ch) ==
    IF S.now % WatchEvery /= 0 THEN S
    ELSE LWatchOver(Flush(PWatch(S, ch)), 1, ch)

\* (c) The egress window: congested = the stall verdict (the meter is blind
\* on datagram legs); a clean window widens by one on demand; a ceiling
\* gone stale is forgotten.
Window(S, ch) ==
    IF S.now % WindowTicks /= S.winPhase \/ ~Alive(S, "P") THEN S
    ELSE IF S.stall
    THEN LET S1 == [S EXCEPT !.lastCong = S.now, !.room = Min(@, 1)]
         IN IF Cardinality(S1.children) > KeepOf(ch) THEN ShedTo(S1, KeepOf(ch)) ELSE S1
    ELSE LET \* any widening waits out the probe backoff: 2 windows x 2^fails
             \* since the last congestion (a late move is one, ReceiverMoves)
             calm == S.now - Max(S.lastCong, S.lastWiden) >= 2 * WindowTicks * 2^S.probeFails
                     /\ (S.lastCong < 0 \/ S.now - S.lastCong >= StallHold)
             r1 == IF S.demand /\ S.room < NL /\ (calm \/ ~ProbeBackoff) THEN S.room + 1 ELSE S.room
             \* SlowStart: two clean windows since the last congestion and the
             \* last widening prove the room it has; widen by one stream (the
             \* probe is the widening; a stall takes it back).
             probe == SlowStart /\ r1 = S.room /\ r1 < NL   \* one stream a window
                      /\ (IF ProbeBackoff THEN calm
                          ELSE S.now - Max(S.lastCong, S.lastWiden) >= 2 * WindowTicks)
             r2 == IF probe THEN r1 + 1 ELSE r1
             r3 == IF ~SlowStart /\ S.lastCong >= 0 /\ S.now - S.lastCong >= CeilingStale
                   THEN NL ELSE r2
             \* a widening after one that held (no congestion since) steps the
             \* backoff down: the probe that worked is the measurement
             held == S.lastWiden > S.lastCong
         IN [S EXCEPT !.room = r3, !.demand = IF r1 /= S.room THEN FALSE ELSE @,
                      !.lastWiden = IF r3 /= S.room THEN S.now ELSE @,
                      !.probeFails = IF r3 /= S.room /\ held THEN Max(0, @ - 1) ELSE @]

\* F13: P's binding re-announce, every BindEvery on every live leg: BindParts
\* Channel messages of BindSize. BindSkip: a leg is skipped while the verdict
\* holds or its oldest unproved message is older than StallTicks, at most
\* BindSkipMax rounds in a row.
Backlogged(S, l) == Len(S.chan[l]) > 0 /\ S.now - S.chan[l][1].first >= StallTicks
RECURSIVE BindParts1(_, _, _)
BindParts1(S, l, n) == IF n = 0 THEN S ELSE BindParts1(SendCtrl(S, l, Pay("bind")), l, n - 1)
RECURSIVE BindLegs(_, _)
BindLegs(S, ls) ==
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             skip == BindSkip /\ (S.stall \/ Backlogged(S, l)) /\ S.bindSkips[l] < BindSkipMax
             S1 == IF ~S.up[l] THEN S
                   ELSE IF skip THEN [S EXCEPT !.bindSkips[l] = @ + 1]
                   ELSE BindParts1([S EXCEPT !.bindSkips[l] = 0], l, BindParts)
         IN BindLegs(S1, ls \ {l})
\* With BindPace > 1 the round's parts go one per leg every BindPace ticks.
RECURSIVE BindOne(_, _)
BindOne(S, ls) ==
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             skip == BindSkip /\ (S.stall \/ Backlogged(S, l)) /\ S.bindSkips[l] < BindSkipMax
         IN BindOne(IF ~S.up[l] THEN S ELSE IF skip THEN S ELSE SendCtrl(S, l, Pay("bind")), ls \ {l})
Phase(S) == S.now % BindEvery
Reannounce(S) ==
    IF BindEvery = 0 \/ ~Alive(S, "P") \/ S.now = 0 THEN S
    ELSE IF BindPace <= 1 THEN (IF Phase(S) = 0 THEN BindLegs(S, PLegs) ELSE S)
    ELSE IF Phase(S) % BindPace = 0 /\ Phase(S) \div BindPace < BindParts THEN BindOne(S, PLegs)
    ELSE S

\* Offers: every node, on every live out-leg, each OfferEvery (P: each
\* StallOfferEvery while stalled).
OfferPay(S, n) ==
    IF n = "P" THEN Offer(TRUE, Cardinality(S.children) < S.room)
    ELSE OfferD(S.parent[n] /= None, Cardinality(S.relayKids[n]) < RelaySlots, S.parent[n] = "P")
RECURSIVE OfferLegs(_, _, _)
OfferLegs(S, n, ms) ==
    IF ms = {} THEN S
    ELSE LET m == CHOOSE m \in ms : TRUE
         IN OfferLegs(SendCtrl(S, <<n, m>>, OfferPay(S, n)), n, ms \ {m})
RECURSIVE OffersOver(_, _)
OffersOver(S, ns) ==
    IF ns = {} THEN S
    ELSE LET n == CHOOSE n \in ns : TRUE
             every == IF n = "P" /\ S.stall /\ ~KeepFresh THEN StallOfferEvery ELSE OfferEvery
             \* a silent listener offers only to the other listeners (relay
             \* candidacy), nothing to P, unless KeepFresh (it receives from P)
             to == IF n /= "P" /\ SilentListener /\ ~KeepFresh THEN Nodes \ {n, "P"} ELSE Nodes \ {n}
             ncDue == S.now - S.lastOfferNC >= NonChildEvery
             to2 == IF n = "P" /\ ~ncDue THEN {m \in to : m \in S.children} ELSE to
             S1 == IF Alive(S, n) /\ S.now - S.lastOffer[n] >= every
                   THEN OfferLegs([S EXCEPT !.lastOffer[n] = S.now,
                                            !.lastOfferNC = IF n = "P" /\ ncDue THEN S.now ELSE @], n, to2)
                   ELSE S
         IN OffersOver(S1, ns \ {n})
Offers(S) == Flush(Reannounce(OffersOver(S, Nodes)))

\* P publishes one tick of media to its children and the drained.
Publish(S) ==
    IF ~Alive(S, "P") THEN S
    ELSE LET sb == IF StandbyFeed = "full" \/ (StandbyFeed \in {"fix", "fix2"} /\ ~S.stall) THEN S.standbys ELSE {}
             to == {c \in L : (c \in S.children \/ S.drainTo[c] >= S.now \/ c \in sb) /\ S.up[<<"P", c>>]}
             S1 == [S EXCEPT !.published = IF InWin(S.now) THEN @ + 1 ELSE @,
                             !.maxStallCopies = IF S.stall THEN Max(@, Cardinality(to)) ELSE @]
             per == IF StallDrain /\ S.stall THEN Max(1, (M * DrainPct) \div 100) ELSE M
             S1b == IF CtrlBg > 0
                    THEN Emit(S1, "P", Item("close", <<"none", "none">>, -1, 0, 0, NoPay, "P", {}, S.now), CtrlBg)
                    ELSE S1
         IN IF to = {} THEN S1b
            ELSE Emit(S1b, "P", Item("media", <<"P", "P">>, 0, 0, 0, NoPay, "P", to, S.now),
                      per * Cardinality(to))

\* (a) The uplink drains Rate units at the end of the tick; what left it is
\* received (and answered) within the tick.
Drain(S) ==
    LET r == Rate(S.now)
        n == Len(SelectSeq(S.fifo, LAMBDA e : e.pos <= r))
        gone == SubSeq(S.fifo, 1, n)
        rest == [i \in 1..(Len(S.fifo) - n) |-> [S.fifo[n + i] EXCEPT !.pos = @ - r]]
        S1 == [S EXCEPT !.fifo = rest, !.backlog = Max(0, @ - r)]
    IN RecvAll(S1, [i \in 1..n |-> gone[i].it])

\* Bookkeeping: how long a listener has been in two ledgers at once.
InLedger(S, x, l) == IF x = "P" THEN l \in S.children \/ S.drainTo[l] >= S.now
                     ELSE l \in S.relayKids[x]
Max0(X) == IF X = {} THEN 0 ELSE CHOOSE x \in X : \A y \in X : x >= y
\* The stall shed's gap: the longest stretch a live listener goes without a
\* new tick of P's media inside the capped window, and how long a listener
\* sits with no parent, nothing pending, and a viable member offering.
Gaps(S) ==
    [S EXCEPT !.maxMediaGap = IF InWin(S.now) /\ S.now > CapAt
                              THEN Max(@, Max0({S.now - S.lastNewAt[c] : c \in {x \in L : Alive(S, x)}}))
                              ELSE @,
              !.idleCand = [c \in L |->
                  IF Alive(S, c) /\ S.parent[c] = None /\ S.pendSub[c] = None
                     /\ Cands(S, c) /= <<>> THEN @[c] + 1 ELSE 0]]

Dual(S) == [S EXCEPT !.dual = [l \in L |->
                IF Cardinality({x \in Nodes \ {l} : Alive(S, x) /\ InLedger(S, x, l)}) > 1
                THEN @[l] + 1 ELSE 0]]

-----------------------------------------------------------------------------
(* Derived state, for the properties and the traces. Every property is    *)
(* written over the state record S, so the runner can also fold them into *)
(* `bad` (the properties a behaviour has violated so far) and read it at  *)
(* the terminal states without TLC stopping at the first violation.      *)
-----------------------------------------------------------------------------
AliveLS(S) == {c \in L : Alive(S, c)}
DirectS(S) == {c \in AliveLS(S) : S.parent[c] = "P"}
OverS(S) == S.now = Horizon

\* --- Safety ---------------------------------------------------------------
\* No link is torn down while its peer is alive and reachable (every peer
\* here is reachable: only P's uplink is slow, nothing is lost).
NoSpuriousTeardownS(S) == \A t \in S.torn : t.why \in {"exhausted", "stale"} => ~t.peerAlive
\* A publisher with a subscriber keeps a direct child: no shed leaves zero.
KeepsOneChildS(S) == ~S.zeroShed
\* Never two parents: a listener is in two forwarders' ledgers only while a
\* move is in flight (two ticks on uncapped paths, plus P's queue delay when
\* P's admit or shed rides its queue: bounded by the largest delay so far).
NeverTwoParentsS(S) == \A c \in L : S.dual[c] <= 2 + S.maxQd
\* Make-before-break: a child P shed keeps P's media until it has moved.
MakeBeforeBreakS(S) == \A c \in AliveLS(S) : S.shedPend[c] /\ S.up[<<"P", c>>] => S.drainTo[c] >= S.now
\* The stall shed (a split of make-before-break, see the .md): never left
\* without a parent while a viable member offers (beyond one watch tick).
NoIdleWithOfferS(S) == \A c \in L : S.idleCand[c] <= 2 * WatchEvery   \* a refused subscribe costs one watch tick
\* Every child a stall shed removed has a parent again within GapBound of the
\* shed (it learns of the shed only when the notice leaves P's queue).
StallShedGapS(S) == /\ S.maxParentGap <= GapBound
                    /\ \A c \in AliveLS(S) : S.shedAtL[c] >= 0 => S.now - S.shedAtL[c] <= GapBound
\* RM6: a receiver whose own downlink is slow never makes a late move.
OwnSlowStaysS(S) == ~S.slowMoved
\* RM4: after a shed P is never left with no direct child (beyond two watch
\* ticks: a move in flight).
NeverDrainedS(S) == S.maxZeroRun <= 2 * WatchEvery
\* F12: under a latched stall verdict, P's media egress for its stream is at
\* most one copy.
EgressOneCopyS(S) == S.maxStallCopies <= 1
\* F12: while P has any subscriber (a standby counts), it has a primary
\* (beyond two watch ticks).
OnePrimaryS(S) == S.maxPrimaryGap <= 2 * WatchEvery
\* Every Channel message is proved or its link torn within the held bound.
NothingWaitsForeverS(S) ==
    \A l \in {x \in Legs : Alive(S, x[1])} : \A i \in 1..Len(S.chan[l]) :
        S.now - S.chan[l][i].first <= Stale + HeldCap + Wait(MaxTries, Base(SrttCap8))
\* The queue a congested publisher holds gets back under QTarget by the end
\* (a capped uplink must not carry a multi-second backlog for good), unless a
\* widening (a probe) is still playing out: the dwell before a listener takes
\* the new room, and up to four windows for the verdict, the shed and the drain.
EndQueueDrainedS(S) == (OverS(S) /\ S.now - S.lastWiden >= Dwell + 4 * WindowTicks) => QDelayS(S) <= QTarget
\* No oscillation: re-parentings per listener are bounded (the join counts).
ReparentBoundS(S) == \A c \in L : S.reparents[c] <= MaxReparents

\* --- At the horizon (the terminal states) ---------------------------------
\* (a move begun within GapBound of the end is in flight, not a strand)
EndParentedS(S) == OverS(S) => \A c \in AliveLS(S) :
                       S.parent[c] /= None \/ (S.lostAt[c] >= 0 /\ S.now - S.lostAt[c] <= GapBound)
EndHeardS(S) == OverS(S) => \A c \in AliveLS(S) : 10 * S.heard[c] >= 7 * S.published
\* RecoverBy is stated per configuration (run_matrix.py): with SlowStart one
\* stream per two clean windows plus the dwell; without, the ceiling's
\* staleness plus the dwell; plus two windows for the verdict to clear.
EndFullFanOutS(S) == (OverS(S) /\ CapUntil + RecoverBy <= Horizon) =>
                        \A c \in AliveLS(S) : S.parent[c] = "P"
\* A dead peer is still detected: every link toward it is down at the live
\* dialer, and every link from it at the live receiver, within the bound
\* the code already has (an offer period + the retry span at the learned
\* cap, twice; the stale bound for the receiver side).
DeadBound == OfferEvery + 2 * Wait(MaxTries, Base(SrttCap8)) + 13 * Base(SrttCap8) + Stale
\* With ConditionalRto the dialer side is the cold ladder: one offer period
\* for a message to be outstanding, its 5 cold waits (13 ticks), a watch tick.
ColdSpan == Ordinary(1, 1) + Ordinary(2, 1) + Ordinary(3, 1) + Ordinary(4, 1) + Ordinary(5, 1)
DialerDeadBound == IF ConditionalRto THEN Max(OfferEvery, NonChildEvery) + ColdSpan + 2
                   ELSE OfferEvery + 2 * Wait(MaxTries, Base(SrttCap8)) + 13 * Base(SrttCap8) + 2
DeadDetectedS(S) ==
    /\ (DeadNode /= None /\ S.now >= DeadAt + DialerDeadBound) =>
          \A l \in Legs : l[2] = DeadNode /\ Alive(S, l[1]) => ~S.up[l]
    /\ (DeadNode /= None /\ S.now >= DeadAt + Stale + 2) =>
          \A l \in Legs : l[1] = DeadNode => ~S.peerUp[l]

Bad(S) ==
    {n \in {"NoSpuriousTeardown", "KeepsOneChild", "NeverTwoParents", "MakeBeforeBreak",
            "NothingWaitsForever", "ReparentBound", "EndParented", "EndHeard",
            "EndFullFanOut", "DeadDetected", "EndQueueDrained",
            "NoIdleWithOffer", "StallShedGap", "OwnSlowStays", "NeverDrained", "EgressOneCopy", "OnePrimary"} :
        CASE n = "NoSpuriousTeardown" -> ~NoSpuriousTeardownS(S)
          [] n = "KeepsOneChild" -> ~KeepsOneChildS(S)
          [] n = "NeverTwoParents" -> ~NeverTwoParentsS(S)
          [] n = "MakeBeforeBreak" -> ~MakeBeforeBreakS(S)
          [] n = "NothingWaitsForever" -> ~NothingWaitsForeverS(S)
          [] n = "ReparentBound" -> ~ReparentBoundS(S)
          [] n = "EndParented" -> ~EndParentedS(S)
          [] n = "EndHeard" -> ~EndHeardS(S)
          [] n = "EndFullFanOut" -> ~EndFullFanOutS(S)
          [] n = "DeadDetected" -> ~DeadDetectedS(S)
          [] n = "EndQueueDrained" -> ~EndQueueDrainedS(S)
          [] n = "NoIdleWithOffer" -> ~NoIdleWithOfferS(S)
          [] n = "StallShedGap" -> ~StallShedGapS(S)
          [] n = "OwnSlowStays" -> ~OwnSlowStaysS(S)
          [] n = "NeverDrained" -> ~NeverDrainedS(S)
          [] n = "EgressOneCopy" -> ~EgressOneCopyS(S)
          [] n = "OnePrimary" -> ~OnePrimaryS(S)}

-----------------------------------------------------------------------------
LegName(l) == l[1] \o ">" \o l[2]
Snap(S, T0) ==
    [t |-> S.now, qdelay |-> IF S.backlog = 0 THEN 0 ELSE (S.backlog - 1) \div Rate(S.now),
     backlog |-> S.backlog, P_children |-> S.children, room |-> S.room, stall |-> S.stall,
     parents |-> S.parent, pending |-> S.pendSub, relays |-> S.relayKids,
     down |-> {LegName(l) : l \in {x \in Legs : ~S.up[x]}},
     oldest |-> {<<LegName(l), S.chan[l][1].pay.p, S.chan[l][1].first, Len(S.chan[l][1].atts)>> :
                  l \in {x \in Legs : S.chan[x] /= <<>>}},
     srtt8 |-> {<<LegName(l), S.srtt8[l]>> : l \in {x \in Legs : S.srtt8[x] > 0}},
     heard |-> S.heard, published |-> S.published,
     torn_now |-> {<<LegName(r.leg), r.why>> : r \in S.torn \ T0}]

\* The call's own legs set up at the start (P's side queues): all at tick 0,
\* or one P leg per StaggerTicks (StaggeredSetup). Order: P's legs, then the
\* listeners' legs toward P.
StartLegs == [i \in 1..(2 * NL) |-> IF i <= NL THEN <<"P", LSeq[i]>> ELSE <<LSeq[i - NL], "P">>]
RECURSIVE SetupAll(_, _)
SetupAll(S, i) == IF i > 2 * NL THEN S ELSE SetupAll(SetupCost(S, StartLegs[i]), i + 1)
StartSetup(S) ==
    IF SetupUnits = 0 THEN S
    ELSE IF ~StaggeredSetup THEN (IF S.now = 0 THEN SetupAll(S, 1) ELSE S)
    ELSE IF S.now % StaggerTicks = 0 /\ S.now \div StaggerTicks < 2 * NL
         THEN SetupCost(S, StartLegs[S.now \div StaggerTicks + 1]) ELSE S

\* ProbeTwoLegs: a small control frame every ProbeEvery on at most two of P's
\* live legs with nothing unproved, so the verdict never waits for an offer.
ProbeLegs(S) ==
    LET idle == SelectSeq([i \in 1..NL |-> <<"P", LSeq[i]>>],
                          LAMBDA l : S.up[l] /\ S.chan[l] = <<>>)
        n == Min(2, Len(idle))
        RECURSIVE Go(_, _)
        Go(T, i) == IF i > n THEN T ELSE Go(SendCtrl(T, idle[i], Pay("probe")), i + 1)
    IN IF ProbeTwoLegs /\ Alive(S, "P") /\ S.now % ProbeEvery = 0 THEN Go(S, 1) ELSE S

\* ReplayAttack: after DeadNode dies, an on-path party replays a frame it
\* recorded: its first Channel message (seq 0) and its first media tick, on
\* every leg from it. They decrypt (no replay protection on the link), so
\* only FreshEvidence keeps them from counting as the peer being alive.
RECURSIVE ReplayTo(_, _)
ReplayTo(S, ms) ==
    IF ms = {} THEN S
    ELSE LET x == CHOOSE x \in ms : TRUE
             l == <<DeadNode, x>>
             S1 == Recv(S, Item("ctrl", l, S.gen[l], 0, 1, Offer(TRUE, TRUE), DeadNode, {}, 0))
             S2 == IF x \in L THEN Recv(S1, Item("media", <<DeadNode, DeadNode>>, 0, 0, 0, NoPay,
                                                  DeadNode, {x}, 0)) ELSE S1
         IN ReplayTo(S2, ms \ {x})
RECURSIVE CloseOut(_, _)
CloseOut(S, ls) ==   \* the leaver's own legs: closed at its side, LINKCLOSE sent
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             S1 == IF S.up[l]
                   THEN Emit([S EXCEPT !.up[l] = FALSE, !.chan[l] = <<>>, !.downAt[l] = S.now], l[1],
                             Item("close", l, S.gen[l], 0, 0, NoPay, l[1], {}, S.now), CtrlSize)
                   ELSE S
         IN CloseOut(S1, ls \ {l})
\* the legs toward the leaver: their dialers see the close of the leaver's
\* session (the links are torn at both ends when a call is left)
RECURSIVE CloseIn(_, _)
CloseIn(S, ls) ==
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             S1 == IF S.up[l]
                   THEN ChildDown([S EXCEPT !.up[l] = FALSE, !.chan[l] = <<>>, !.downAt[l] = S.now,
                                            !.peerUp[l] = FALSE, !.dialAt[l] = S.now + 100000], l[1], l[2])
                   ELSE S
         IN CloseIn(S1, ls \ {l})
Kill(S, ch) ==
    IF KillAt = 0 \/ S.now /= KillAt \/ S.children = {} THEN S
    ELSE LET o == SelectSeq(S.order, LAMBDA x : x \in S.children)
             c == IF o = <<>> THEN CHOOSE x \in S.children : TRUE ELSE o[1]
         IN Flush(TearDown(S, <<"P", c>>, "killed", ch))
Hangup(S) == IF Graceful /\ DeadNode \in L /\ S.now = DeadAt - 1
             THEN LET S1 == IF S.parent[DeadNode] /= None
                            THEN SendCtrl(S, <<DeadNode, S.parent[DeadNode]>>, Pay("unsub")) ELSE S
                  IN Flush(CloseIn(Flush(CloseOut(Flush(S1), {l \in Legs : l[1] = DeadNode})),
                                   {l \in Legs : l[2] = DeadNode}))
             ELSE S
Replays(S) == IF ReplayAttack /\ DeadNode /= None /\ S.now > DeadAt
              THEN Flush(ReplayTo(S, Nodes \ {DeadNode})) ELSE S

Step(S, ch) ==
    LET S1 == Timers(Flush(ProbeLegs(StartSetup(Replays(Hangup(Kill(S, ch)))))), ch)
        S2 == Flush(StaleLegs(S1))
        S3 == Redial(S2)
        S4 == Watch(S3, ch)
        S5 == Flush(Window(S4, ch))
        S6 == Offers(S5)
        S7 == Flush(Publish(S6))
        S8 == Drain(S7)
        S9 == Gaps(Dual(S8))
        S10 == IF TraceOn THEN [S9 EXCEPT !.hist = Append(@, Snap(S9, S.torn))] ELSE S9
        S11 == [S10 EXCEPT !.now = @ + 1, !.maxQd = Max(@, QDelayS(S10)),
                           !.capEndQ = IF S10.now = Min(CapUntil, Horizon) - 1 THEN QDelayS(S10) ELSE @,
                           !.drainClear = IF @ < 0 /\ S10.firstShedAt >= 0 /\ QDelayS(S10) <= QTarget
                                          THEN S10.now ELSE @,
                           !.fullAt = IF @ < 0 /\ \A c \in {x \in L : Alive(S10, x)} : S10.parent[c] = "P" THEN S10.now ELSE @,

                           !.lostAt = [c \in L |-> IF S10.parent[c] = None
                                                    THEN (IF S.parent[c] /= None \/ @[c] < 0 THEN S10.now ELSE @[c])
                                                    ELSE -1],
                           !.allOkAt = IF @ < 0 /\ KillAt > 0 /\ S10.now > KillAt
                                          /\ S10.children /= {}
                                          /\ \A c \in {x \in L : Alive(S10, x)} : S10.parent[c] /= None
                                       THEN S10.now ELSE @,
                           !.primaryGapRun = IF S10.children = {} /\ S10.standbys /= {} /\ Alive(S10, "P")
                                             THEN @ + 1 ELSE 0,
                           !.maxPrimaryGap = Max(@, IF S10.children = {} /\ S10.standbys /= {} /\ Alive(S10, "P")
                                                    THEN S10.primaryGapRun + 1 ELSE 0),
                           !.zeroRun = IF S10.firstShedAt >= 0 /\ Alive(S10, "P") /\ S10.children = {}
                                       THEN @ + 1 ELSE 0,
                           !.maxZeroRun = Max(@, IF S10.firstShedAt >= 0 /\ Alive(S10, "P") /\ S10.children = {}
                                                 THEN S10.zeroRun + 1 ELSE 0)]
    IN [S11 EXCEPT !.bad = @ \cup Bad(S11)]

\* The environment's and the code's free choices, ONE per behaviour (fixed
\* at Init, so Next is deterministic and TLC evaluates each tick once): the
\* room a shed leaves when RoomKeepsOne is off, each listener's tie-break
\* among equal relays, how long a re-punch takes. Sound for what is checked:
\* every per-run combination is explored; what it hides is a run in which
\* the same choice comes out differently at two moments (e.g. one shed
\* leaves one child and a later one zero).
Choices == [keep : IF RoomKeepsOne THEN {1} ELSE {0, 1},
            pick : IF Wide THEN [L -> 1..NPick] ELSE {[c \in L |-> k] : k \in 1..NPick},
            punch : PunchTimes]

-----------------------------------------------------------------------------
Init ==
    /\ now = 0
    /\ fifo = <<>> /\ backlog = 0 /\ net = <<>>
    /\ up = [l \in Legs |-> TRUE] /\ peerUp = [l \in Legs |-> TRUE]
    /\ gen = [l \in Legs |-> 0] /\ downAt = [l \in Legs |-> -1]
    /\ chan = [l \in Legs |-> <<>>] /\ nextSeq = [l \in Legs |-> 0]
    /\ rxNext = [l \in Legs |-> 0] /\ srtt8 = [l \in Legs |-> 0]
    /\ lastAuth = [l \in Legs |-> -1]
    /\ peerAuth = [x \in Nodes |-> [y \in Nodes |-> -1]]
    /\ rxDelay = [c \in L |-> 0] /\ probeFails = 0 /\ lateMove = [c \in L |-> FALSE]
    /\ maxQd = 0 /\ firstVerdictAt = -1 /\ firstShedAt = -1 /\ firstShedQ = -1
    /\ fullAt = -1 /\ lastSetupAt = -100
    /\ shedAtL = [c \in L |-> -1] /\ maxParentGap = 0 /\ lastNewAt = [c \in L |-> 0]
    /\ maxMediaGap = 0 /\ idleCand = [c \in L |-> 0]
    /\ lastFromParent = [c \in L |-> 0] /\ drainClear = -1 /\ capEndQ = -1 /\ slowMoved = FALSE
    /\ offerDirect = [c \in L |-> [n \in Nodes |-> FALSE]] /\ zeroRun = 0 /\ maxZeroRun = 0
    /\ standbys = {} /\ maxStallCopies = 0 /\ primaryGapRun = 0 /\ maxPrimaryGap = 0
    /\ bindSkips = [l \in Legs |-> 0] /\ lastOfferNC = -100 /\ allOkAt = -1 /\ lostAt = [c \in L |-> -1]
    /\ dialAt = [l \in Legs |-> 0] /\ dialBo = [l \in Legs |-> DialMin]
    /\ pathAt = [l \in Legs |-> 0]
    /\ children = {} /\ order = <<>> /\ drainTo = [c \in L |-> -1]
    /\ shedPend = [c \in L |-> FALSE]
    /\ room = IF SlowStart THEN InitFanout ELSE NL
    /\ demand = FALSE /\ lastCong = -1 /\ lastWiden = 0 /\ stall = FALSE /\ stallSeen = -1
    /\ obs = [l \in Legs |-> NoObs] /\ verdicts = 0 /\ sheds = 0 /\ zeroShed = FALSE
    /\ \E pp \in PPhases,
          lp \in IF Wide THEN [L -> LPhases] ELSE {[c \in L |-> x] : x \in LPhases} :
          lastOffer = [n \in Nodes |-> (IF n = "P" THEN pp ELSE lp[n]) - OfferEvery]
    /\ winPhase \in WPhases
    /\ relayKids = [c \in L |-> {}] /\ parent = [c \in L |-> None]
    /\ pendSub = [c \in L |-> None] /\ pendAt = [c \in L |-> -1]
    /\ boUntil = [c \in L |-> [n \in Nodes |-> 0]]
    /\ reparents = [c \in L |-> 0] /\ lastSwitch = [c \in L |-> 0]
    /\ shedBy = [c \in L |-> None]
    \* the call is joined: every listener heard P's offer (direct first)
    /\ offerAt = [c \in L |-> [n \in Nodes |-> IF n = "P" THEN 0 ELSE -1]]
    /\ offerFwd = [c \in L |-> [n \in Nodes |-> n = "P"]]
    /\ offerRoom = [c \in L |-> [n \in Nodes |-> n = "P"]]
    /\ heard = [c \in L |-> 0] /\ lastHeard = [c \in L |-> -1]
    /\ lastFwd = [c \in L |-> -1] /\ published = 0
    /\ torn = {} /\ dual = [c \in L |-> 0]
    /\ hist = <<>> /\ bad = {}
    /\ choice \in Choices

Assign(S) ==
    /\ now' = S.now /\ fifo' = S.fifo /\ backlog' = S.backlog /\ net' = S.net
    /\ up' = S.up /\ peerUp' = S.peerUp /\ gen' = S.gen /\ downAt' = S.downAt
    /\ chan' = S.chan /\ nextSeq' = S.nextSeq /\ rxNext' = S.rxNext
    /\ srtt8' = S.srtt8 /\ lastAuth' = S.lastAuth /\ peerAuth' = S.peerAuth
    /\ rxDelay' = S.rxDelay /\ probeFails' = S.probeFails /\ lateMove' = S.lateMove
    /\ maxQd' = S.maxQd /\ firstVerdictAt' = S.firstVerdictAt
    /\ firstShedAt' = S.firstShedAt /\ firstShedQ' = S.firstShedQ
    /\ fullAt' = S.fullAt /\ lastSetupAt' = S.lastSetupAt
    /\ shedAtL' = S.shedAtL /\ maxParentGap' = S.maxParentGap /\ lastNewAt' = S.lastNewAt
    /\ maxMediaGap' = S.maxMediaGap /\ idleCand' = S.idleCand
    /\ lastFromParent' = S.lastFromParent /\ drainClear' = S.drainClear /\ capEndQ' = S.capEndQ /\ slowMoved' = S.slowMoved
    /\ offerDirect' = S.offerDirect /\ zeroRun' = S.zeroRun /\ maxZeroRun' = S.maxZeroRun
    /\ standbys' = S.standbys /\ maxStallCopies' = S.maxStallCopies
    /\ primaryGapRun' = S.primaryGapRun /\ maxPrimaryGap' = S.maxPrimaryGap /\ bindSkips' = S.bindSkips
    /\ lastOfferNC' = S.lastOfferNC /\ allOkAt' = S.allOkAt /\ lostAt' = S.lostAt /\ dialAt' = S.dialAt
    /\ dialBo' = S.dialBo /\ pathAt' = S.pathAt /\ children' = S.children
    /\ order' = S.order /\ drainTo' = S.drainTo /\ shedPend' = S.shedPend
    /\ room' = S.room /\ demand' = S.demand /\ lastCong' = S.lastCong /\ lastWiden' = S.lastWiden
    /\ stall' = S.stall /\ stallSeen' = S.stallSeen /\ obs' = S.obs
    /\ verdicts' = S.verdicts /\ sheds' = S.sheds /\ zeroShed' = S.zeroShed
    /\ lastOffer' = S.lastOffer /\ winPhase' = S.winPhase
    /\ relayKids' = S.relayKids /\ parent' = S.parent /\ pendSub' = S.pendSub
    /\ pendAt' = S.pendAt /\ boUntil' = S.boUntil /\ reparents' = S.reparents
    /\ lastSwitch' = S.lastSwitch /\ shedBy' = S.shedBy /\ offerAt' = S.offerAt
    /\ offerFwd' = S.offerFwd /\ offerRoom' = S.offerRoom /\ heard' = S.heard
    /\ lastHeard' = S.lastHeard /\ lastFwd' = S.lastFwd
    /\ published' = S.published /\ torn' = S.torn /\ dual' = S.dual
    /\ hist' = S.hist /\ bad' = S.bad

Tick == now < Horizon /\ Assign(Step(Rec, choice)) /\ UNCHANGED choice

Next == Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Tick)

-----------------------------------------------------------------------------
\* The same properties as state invariants (for cfg INVARIANTS).
QueueDelay == QDelayS(Rec)
AliveL == AliveLS(Rec)
Direct == DirectS(Rec)
Over == OverS(Rec)
NoSpuriousTeardown == NoSpuriousTeardownS(Rec)
KeepsOneChild == KeepsOneChildS(Rec)
NeverTwoParents == NeverTwoParentsS(Rec)
MakeBeforeBreak == MakeBeforeBreakS(Rec)
NothingWaitsForever == NothingWaitsForeverS(Rec)
ReparentBound == ReparentBoundS(Rec)
EndParented == EndParentedS(Rec)
EndHeard == EndHeardS(Rec)
EndFullFanOut == EndFullFanOutS(Rec)
DeadDetected == DeadDetectedS(Rec)
EndQueueDrained == EndQueueDrainedS(Rec)

TypeOK == /\ now \in 0..Horizon /\ backlog \in Nat
          /\ children \subseteq L /\ parent \in [L -> Nodes \cup {None}]

-----------------------------------------------------------------------------
(* Liveness (under WF(Tick), on the bounded run: the last state stutters). *)
-----------------------------------------------------------------------------
EventuallyParented == <>[](\A c \in AliveL : parent[c] /= None)
EventuallyNothingOutstanding == \A l \in Legs : <>(chan[l] = <<>> \/ ~up[l] \/ Over)

-----------------------------------------------------------------------------
(* The terminal states: the outcome and what the behaviour violated.      *)
-----------------------------------------------------------------------------
Outcome ==
    LET k == {t \in torn : t.why = "exhausted" /\ t.peerAlive}
    IN IF k /= {} THEN "Collapsed"
       ELSE IF \E c \in AliveL : parent[c] = None /\ ~(lostAt[c] >= 0 /\ now - lostAt[c] <= GapBound)
            THEN "Stranded"
       ELSE IF \E c \in AliveL : 10 * heard[c] < 7 * published THEN "Starved"
       ELSE IF Direct = AliveL THEN "FullFanOut"
       ELSE "Relayed(direct=" \o ToString(Cardinality(Direct)) \o ")"
\* What a recorded run can be compared with (trace_check.py): per node, the
\* first tick a leg was torn down AT that node with a cause edge's
\* `torn_down` counts (exhausted at the dialer, stale at the receiver; -1:
\* none); the exhausted count; P's direct children and the listeners on a
\* relay at the end; P's sheds and stall verdicts; heard per listener in
\* percent of what P published.
FirstTorn(n) ==
    LET ts == {t.at : t \in {r \in torn : (r.why = "exhausted" /\ r.leg[1] = n)
                                         \/ (r.why = "stale" /\ r.leg[2] = n)}}
    IN IF ts = {} THEN -1 ELSE CHOOSE x \in ts : \A y \in ts : x <= y
Observed ==
    [first_torn |-> [n \in Nodes |-> FirstTorn(n)],
     exhausted |-> Cardinality({r \in torn : r.why = "exhausted"}),
     direct |-> Cardinality(Direct),
     relayed |-> Cardinality({c \in AliveL : parent[c] \notin {None, "P"}}),
     sheds |-> sheds, verdicts |-> verdicts, qdelay |-> QueueDelay, max_qdelay |-> maxQd,
     first_verdict |-> firstVerdictAt, first_shed |-> firstShedAt, q_at_shed |-> firstShedQ,
     full_at |-> fullAt, parent_gap |-> maxParentGap, media_gap |-> maxMediaGap,
     drain_clear |-> drainClear, cap_end_q |-> capEndQ, zero_direct |-> maxZeroRun,
     all_ok_after_kill |-> IF allOkAt >= 0 THEN allOkAt - KillAt ELSE IF KillAt > 0 THEN 9999 ELSE -1, stall_copies |-> maxStallCopies, primary_gap |-> maxPrimaryGap, verdict_rises |-> verdicts,
     heard_pct |-> [c \in L |-> IF published = 0 THEN 100 ELSE (100 * heard[c]) \div published]]
\* One line per terminal state: the outcome, the violated set, what is observed.
RecordOutcome == Over => PrintT(<<"OUTCOME", Outcome, bad, Observed>>)

\* Traced variants: a violation prints the compact history (TraceOn).
Dump == PrintT(<<"TRACE", hist>>) /\ FALSE
T_NoSpuriousTeardown == NoSpuriousTeardown \/ Dump
T_KeepsOneChild == KeepsOneChild \/ Dump
T_NeverTwoParents == NeverTwoParents \/ Dump
T_MakeBeforeBreak == MakeBeforeBreak \/ Dump
T_NothingWaitsForever == NothingWaitsForever \/ Dump
T_ReparentBound == ReparentBound \/ Dump
T_EndParented == EndParented \/ Dump
T_EndHeard == EndHeard \/ Dump
T_EndFullFanOut == EndFullFanOut \/ Dump
T_DeadDetected == DeadDetected \/ Dump
T_EndQueueDrained == EndQueueDrained \/ Dump
NoIdleWithOffer == NoIdleWithOfferS(Rec)
StallShedGap == StallShedGapS(Rec)
T_NoIdleWithOffer == NoIdleWithOffer \/ Dump
T_StallShedGap == StallShedGap \/ Dump
EgressOneCopy == EgressOneCopyS(Rec)
OnePrimary == OnePrimaryS(Rec)
T_EgressOneCopy == EgressOneCopy \/ Dump
T_OnePrimary == OnePrimary \/ Dump
=============================================================================
