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
    TraceOn             \* keep a compact per-tick history (for traces only)

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
InWin(t) == CapAt <= t /\ t <= Horizon - TailTicks

\* 8 x 1.5^(k-1), rounded down: 8, 12, 18, 27, 40, 60, 91, 136, ...
OrdNum(k) == (8 * 3^(k - 1)) \div (2^(k - 1))
\* base RTO in ticks from SRTT in eighths: max(1, ceil(2.5 x srtt))
Base(s8) == Max(1, (5 * s8 + 15) \div 16)
\* calculate_timeout at try k, rounded to the tick; past MaxTries the held
\* wait: min(the backed-off wait, max(HeldCap, the last ordinary wait)).
Ordinary(k, b) == Max(1, (b * OrdNum(k) + 4) \div 8)
Wait(k, b) == IF k <= MaxTries THEN Ordinary(k, b)
              ELSE Min(Ordinary(k, b), Max(HeldCap, Ordinary(MaxTries, b)))

Pay(p) == [p |-> p, fwd |-> FALSE, room |-> FALSE]
Offer(f, r) == [p |-> "offer", fwd |-> f, room |-> r]
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
    up, peerUp, gen, downAt, chan, nextSeq, rxNext, srtt8, lastAuth,
    \* (e) redial
    dialAt, dialBo, pathAt,
    \* (c) the publisher
    children, order, drainTo, shedPend, room, demand, lastCong,
    stall, stallSeen, obs, verdicts, sheds, zeroShed, lastOffer, winPhase,
    \* (d) listeners
    relayKids, parent, pendSub, pendAt, boUntil, reparents, lastSwitch,
    shedBy, offerAt, offerFwd, offerRoom,
    \* bookkeeping the properties read
    heard, lastHeard, lastFwd, published, torn, dual,
    hist                \* the compact history (empty unless TraceOn)

vars == <<now, fifo, backlog, net, up, peerUp, gen, downAt, chan, nextSeq,
          rxNext, srtt8, lastAuth, dialAt, dialBo, pathAt, children, order,
          drainTo, shedPend, room, demand, lastCong, stall, stallSeen, obs,
          verdicts, sheds, zeroShed, lastOffer, winPhase, relayKids, parent,
          pendSub, pendAt, boUntil, reparents, lastSwitch, shedBy, offerAt,
          offerFwd, offerRoom, heard, lastHeard, lastFwd, published, torn, dual,
          hist>>

ASSUME /\ NL >= 2 /\ RCap >= 1 /\ RFree >= RCap /\ MaxTries >= 1
       /\ CapAt >= 0 /\ Horizon > CapAt /\ Stale > 0 /\ WatchEvery >= 1

-----------------------------------------------------------------------------
(* The state as one record, so a tick can be written as a pipeline of     *)
(* pure steps S -> S. The choice ch: [keep, pick, punch].                  *)
-----------------------------------------------------------------------------
Rec == [now |-> now, fifo |-> fifo, backlog |-> backlog, net |-> net, up |-> up,
        peerUp |-> peerUp, gen |-> gen, downAt |-> downAt, chan |-> chan,
        nextSeq |-> nextSeq, rxNext |-> rxNext, srtt8 |-> srtt8,
        lastAuth |-> lastAuth, dialAt |-> dialAt, dialBo |-> dialBo,
        pathAt |-> pathAt, children |-> children, order |-> order,
        drainTo |-> drainTo, shedPend |-> shedPend, room |-> room,
        demand |-> demand, lastCong |-> lastCong, stall |-> stall,
        stallSeen |-> stallSeen, obs |-> obs, verdicts |-> verdicts,
        sheds |-> sheds, zeroShed |-> zeroShed, lastOffer |-> lastOffer,
        winPhase |-> winPhase, relayKids |-> relayKids, parent |-> parent,
        pendSub |-> pendSub, pendAt |-> pendAt, boUntil |-> boUntil,
        reparents |-> reparents, lastSwitch |-> lastSwitch, shedBy |-> shedBy,
        offerAt |-> offerAt, offerFwd |-> offerFwd, offerRoom |-> offerRoom,
        heard |-> heard, lastHeard |-> lastHeard, lastFwd |-> lastFwd,
        published |-> published, torn |-> torn, dual |-> dual, hist |-> hist]

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
SendCtrl(S, l, pay) ==
    IF ~S.up[l] \/ ~Alive(S, l[1]) THEN S
    ELSE LET q == S.nextSeq[l]
             S1 == [S EXCEPT !.chan[l] = Append(@, [seq |-> q, first |-> S.now,
                                                   atts |-> <<S.now>>, pay |-> pay]),
                             !.nextSeq[l] = q + 1]
         IN Emit(S1, l[1], Item("ctrl", l, S.gen[l], q, 1, pay, l[1], {}, S.now), CtrlSize)

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
    THEN [S EXCEPT !.children = @ \ {y}, !.drainTo[y] = -1, !.shedPend[y] = FALSE]
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
        ordered == SelectSeq(S.order, LAMBDA x : x \in kids)
        kept == {ordered[i] : i \in 1..Min(keep, Len(ordered))}
        victims == kids \ kept
        S1 == [S EXCEPT !.children = kept, !.room = 1,
                        !.zeroShed = @ \/ (kept = {} /\ kids /= {}),
                        !.sheds = @ + Cardinality(victims),
                        !.drainTo = [v \in L |-> IF v \in victims /\ ShedDrains
                                                 THEN S.now + DrainTicks ELSE @[v]],
                        !.shedPend = [v \in L |-> IF v \in victims THEN TRUE ELSE @[v]]]
    IN SendEach(S1, victims, Pay("shed"))

KeepOf(ch) == IF RoomKeepsOne THEN 1 ELSE ch.keep

-----------------------------------------------------------------------------
(* Receiving.                                                              *)
-----------------------------------------------------------------------------
\* Media of P's tick t from s at c (dedup by t; a relay forwards new t).
Media1(S, s, c, t) ==
    IF ~Alive(S, c) \/ ~S.peerUp[<<s, c>>] THEN S
    ELSE LET S1 == IF t > S.lastHeard[c]
                   THEN [S EXCEPT !.lastHeard[c] = t,
                                  !.heard[c] = IF InWin(t) THEN @ + 1 ELSE @]
                   ELSE S
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
    THEN SendCtrl([S EXCEPT !.children = @ \cup {l},
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
    IF S.pendSub[l] /= x THEN S
    ELSE LET old == S.parent[l]
             S1 == [S EXCEPT !.parent[l] = x, !.pendSub[l] = None,
                             !.reparents[l] = @ + 1, !.lastSwitch[l] = S.now,
                             !.shedBy[l] = None]
             S2 == IF old \notin {None, x} THEN SendCtrl(S1, <<l, old>>, Pay("unsub")) ELSE S1
             \* a publisher that shed this node make-before-break is told once
             \* the replacement is up (alm.rs draining_parent)
             S3 == IF S.shedBy[l] = "P" /\ x /= "P" /\ old /= "P"
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
                           !.offerRoom[r][s] = pay.room]
      [] pay.p = "sub" -> IF r = "P" THEN PAdmit(S, s) ELSE RelayAdmit(S, r, s)
      [] pay.p = "admit" -> OnAdmit(S, r, s)
      [] pay.p = "refuse" ->
            IF S.pendSub[r] = s
            THEN [S EXCEPT !.pendSub[r] = None, !.boUntil[r][s] = S.now + Backoff]
            ELSE S
      [] pay.p = "shed" -> OnShed(S, r, s)
      [] pay.p = "unsub" ->
            IF r = "P"
            THEN [S EXCEPT !.children = @ \ {s}, !.drainTo[s] = -1, !.shedPend[s] = FALSE]
            ELSE [S EXCEPT !.relayKids[r] = @ \ {s}]
      [] OTHER -> S

RecvCtrl(S, it) ==
    LET l == it.leg  r == l[2]
    IN IF ~Alive(S, r) \/ ~S.peerUp[l] THEN S
       ELSE LET S1 == Emit(S, r, Item("proof", l, it.gen, it.seq, it.att, NoPay, r, {}, S.now), 0)
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
                                 !.srtt8[l] = n8]

RecvClose(S, it) ==
    LET l == it.leg
    IN IF Alive(S, l[2]) /\ S.peerUp[l] /\ it.gen = S.gen[l]
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
Held(S, l, m) == Hold113 /\ S.lastAuth[l] > m.first /\ S.now < m.first + Stale

RECURSIVE TimerMsgs(_, _, _, _)
TimerMsgs(S, l, i, ch) ==
    IF ~S.up[l] \/ i > Len(S.chan[l]) THEN S
    ELSE LET m == S.chan[l][i]
             k == Len(m.atts)
             due == m.atts[k] + Wait(k, Base(S.srtt8[l]))
         IN IF S.now < due THEN TimerMsgs(S, l, i + 1, ch)
            ELSE IF k >= MaxTries /\ ~Held(S, l, m) THEN TearDown(S, l, "exhausted", ch)
            ELSE LET S1 == [S EXCEPT !.chan[l][i].atts = Append(@, S.now)]
                     S2 == Emit(S1, l[1], Item("ctrl", l, S.gen[l], m.seq, k + 1, m.pay,
                                               l[1], {}, S.now), CtrlSize)
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
RECURSIVE RedialOver(_, _)
RedialOver(S, ls) ==
    IF ls = {} THEN S
    ELSE LET l == CHOOSE l \in ls : TRUE
             S1 == IF ~S.up[l] /\ Alive(S, l[1]) /\ DialDue(S, l)
                   THEN IF S.now >= S.pathAt[l] /\ Alive(S, l[2])
                        THEN [S EXCEPT !.up[l] = TRUE, !.peerUp[l] = TRUE, !.gen[l] = @ + 1,
                                       !.chan[l] = <<>>, !.srtt8[l] = 0, !.lastAuth[l] = -1,
                                       !.rxNext[l] = S.nextSeq[l], !.dialBo[l] = DialMin]
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
                             !.verdicts = IF st /\ ~S.stall THEN @ + 1 ELSE @]
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
    ELSE LET S1 == IF S.parent[l] /= None /\ ~S.peerUp[<<S.parent[l], l>>]
                   THEN [S EXCEPT !.boUntil[l][S.parent[l]] = S.now + Backoff,
                                  !.parent[l] = None]
                   ELSE S
             S2 == IF S1.pendSub[l] /= None /\ S1.now - S1.pendAt[l] >= SubTimeout
                   THEN [S1 EXCEPT !.boUntil[l][S1.pendSub[l]] = S1.now + Backoff,
                                   !.pendSub[l] = None]
                   ELSE S1
             c == Cands(S2, l)
         IN IF S2.pendSub[l] = None /\ S2.parent[l] = None /\ c /= <<>>
            THEN Subscribe(S2, l, Pick(c, k))
            ELSE IF /\ S2.pendSub[l] = None /\ S2.parent[l] \notin {None, "P"}
                    /\ Viable(S2, l, "P") /\ S2.now - S2.lastSwitch[l] >= Dwell
            THEN Subscribe(S2, l, "P")
            ELSE S2

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
    ELSE LET r1 == IF S.demand /\ S.room < NL THEN S.room + 1 ELSE S.room
             r2 == IF ~SlowStart /\ S.lastCong >= 0 /\ S.now - S.lastCong >= CeilingStale
                   THEN NL ELSE r1
         IN [S EXCEPT !.room = r2, !.demand = IF r1 /= S.room THEN FALSE ELSE @]

\* Offers: every node, on every live out-leg, each OfferEvery (P: each
\* StallOfferEvery while stalled).
OfferPay(S, n) ==
    IF n = "P" THEN Offer(TRUE, Cardinality(S.children) < S.room)
    ELSE Offer(S.parent[n] /= None, Cardinality(S.relayKids[n]) < RelaySlots)
RECURSIVE OfferLegs(_, _, _)
OfferLegs(S, n, ms) ==
    IF ms = {} THEN S
    ELSE LET m == CHOOSE m \in ms : TRUE
         IN OfferLegs(SendCtrl(S, <<n, m>>, OfferPay(S, n)), n, ms \ {m})
RECURSIVE OffersOver(_, _)
OffersOver(S, ns) ==
    IF ns = {} THEN S
    ELSE LET n == CHOOSE n \in ns : TRUE
             every == IF n = "P" /\ S.stall THEN StallOfferEvery ELSE OfferEvery
             S1 == IF Alive(S, n) /\ S.now - S.lastOffer[n] >= every
                   THEN OfferLegs([S EXCEPT !.lastOffer[n] = S.now], n, Nodes \ {n})
                   ELSE S
         IN OffersOver(S1, ns \ {n})
Offers(S) == Flush(OffersOver(S, Nodes))

\* P publishes one tick of media to its children and the drained.
Publish(S) ==
    IF ~Alive(S, "P") THEN S
    ELSE LET to == {c \in L : (c \in S.children \/ S.drainTo[c] >= S.now) /\ S.up[<<"P", c>>]}
             S1 == [S EXCEPT !.published = IF InWin(S.now) THEN @ + 1 ELSE @]
         IN IF to = {} THEN S1
            ELSE Emit(S1, "P", Item("media", <<"P", "P">>, 0, 0, 0, NoPay, "P", to, S.now),
                      M * Cardinality(to))

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
Dual(S) == [S EXCEPT !.dual = [l \in L |->
                IF Cardinality({x \in Nodes \ {l} : InLedger(S, x, l)}) > 1
                THEN @[l] + 1 ELSE 0]]

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

Step(S, ch) ==
    LET S1 == Timers(S, ch)
        S2 == Flush(StaleLegs(S1))
        S3 == Redial(S2)
        S4 == Watch(S3, ch)
        S5 == Flush(Window(S4, ch))
        S6 == Offers(S5)
        S7 == Flush(Publish(S6))
        S8 == Drain(S7)
        S9 == Dual(S8)
        S10 == IF TraceOn THEN [S9 EXCEPT !.hist = Append(@, Snap(S9, S.torn))] ELSE S9
    IN [S10 EXCEPT !.now = @ + 1]

Choices == [keep : IF RoomKeepsOne THEN {1} ELSE {0, 1},
            pick : [L -> 1..NPick],
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
    /\ dialAt = [l \in Legs |-> 0] /\ dialBo = [l \in Legs |-> DialMin]
    /\ pathAt = [l \in Legs |-> 0]
    /\ children = {} /\ order = <<>> /\ drainTo = [c \in L |-> -1]
    /\ shedPend = [c \in L |-> FALSE]
    /\ room = IF SlowStart THEN InitFanout ELSE NL
    /\ demand = FALSE /\ lastCong = -1 /\ stall = FALSE /\ stallSeen = -1
    /\ obs = [l \in Legs |-> NoObs] /\ verdicts = 0 /\ sheds = 0 /\ zeroShed = FALSE
    /\ \E pp \in PPhases, lp \in [L -> LPhases] :
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
    /\ hist = <<>>

Assign(S) ==
    /\ now' = S.now /\ fifo' = S.fifo /\ backlog' = S.backlog /\ net' = S.net
    /\ up' = S.up /\ peerUp' = S.peerUp /\ gen' = S.gen /\ downAt' = S.downAt
    /\ chan' = S.chan /\ nextSeq' = S.nextSeq /\ rxNext' = S.rxNext
    /\ srtt8' = S.srtt8 /\ lastAuth' = S.lastAuth /\ dialAt' = S.dialAt
    /\ dialBo' = S.dialBo /\ pathAt' = S.pathAt /\ children' = S.children
    /\ order' = S.order /\ drainTo' = S.drainTo /\ shedPend' = S.shedPend
    /\ room' = S.room /\ demand' = S.demand /\ lastCong' = S.lastCong
    /\ stall' = S.stall /\ stallSeen' = S.stallSeen /\ obs' = S.obs
    /\ verdicts' = S.verdicts /\ sheds' = S.sheds /\ zeroShed' = S.zeroShed
    /\ lastOffer' = S.lastOffer /\ winPhase' = S.winPhase
    /\ relayKids' = S.relayKids /\ parent' = S.parent /\ pendSub' = S.pendSub
    /\ pendAt' = S.pendAt /\ boUntil' = S.boUntil /\ reparents' = S.reparents
    /\ lastSwitch' = S.lastSwitch /\ shedBy' = S.shedBy /\ offerAt' = S.offerAt
    /\ offerFwd' = S.offerFwd /\ offerRoom' = S.offerRoom /\ heard' = S.heard
    /\ lastHeard' = S.lastHeard /\ lastFwd' = S.lastFwd
    /\ published' = S.published /\ torn' = S.torn /\ dual' = S.dual
    /\ hist' = S.hist

Tick == now < Horizon /\ \E ch \in Choices : Assign(Step(Rec, ch))

Next == Tick

Spec == Init /\ [][Next]_vars /\ WF_vars(Tick)

-----------------------------------------------------------------------------
(* Derived state, for the properties and the traces.                       *)
-----------------------------------------------------------------------------
QueueDelay == IF backlog = 0 THEN 0 ELSE (backlog - 1) \div Rate(now)
AliveL == {c \in L : Alive(Rec, c)}
Direct == {c \in AliveL : parent[c] = "P"}
Relayed == {c \in AliveL : parent[c] \notin {None, "P"}}
Over == now = Horizon

-----------------------------------------------------------------------------
(* Safety.                                                                 *)
-----------------------------------------------------------------------------
\* No link is torn down while its peer is alive and reachable (every peer
\* here is reachable: only P's uplink is slow, nothing is lost).
NoSpuriousTeardown == \A t \in torn : t.why \in {"exhausted", "stale"} => ~t.peerAlive

\* A publisher with a subscriber keeps a direct child: no shed leaves zero.
KeepsOneChild == ~zeroShed

\* Never two parents: a listener is in two forwarders' ledgers only while a
\* move is in flight (one tick on an uncapped path, plus the queue delay
\* when the old parent is P).
NeverTwoParents == \A c \in L : dual[c] <= 2 + QueueDelay

\* Make-before-break: a child P shed keeps P's media until it has moved.
MakeBeforeBreak == \A c \in AliveL : shedPend[c] /\ up[<<"P", c>>] => drainTo[c] >= now

\* Every Channel message is proved or its link torn within the held bound.
NothingWaitsForever ==
    \A l \in Legs : \A i \in 1..Len(chan[l]) :
        now - chan[l][i].first <= Stale + HeldCap + Wait(MaxTries, Base(SrttCap8))

\* No oscillation: re-parentings per listener are bounded (the join counts).
ReparentBound == \A c \in L : reparents[c] <= MaxReparents

TypeOK == /\ now \in 0..Horizon /\ backlog \in Nat
          /\ children \subseteq L /\ parent \in [L -> Nodes \cup {None}]

-----------------------------------------------------------------------------
(* At the horizon (the system's terminal states).                          *)
-----------------------------------------------------------------------------
\* Every live listener has a parent at the end.
EndParented == Over => \A c \in AliveL : parent[c] /= None
\* Every live listener heard >= 70 % of what P published in the window.
EndHeard == Over => \A c \in AliveL : 10 * heard[c] >= 7 * published
\* After the cap lifts, full fan-out is back within RecoverBy.
EndFullFanOut == (Over /\ CapUntil + RecoverBy <= Horizon) =>
                    \A c \in AliveL : parent[c] = "P"
\* A dead peer is still detected: every link to or from it is down at
\* the live end within the existing bound (one offer period + the retry
\* span learned at the cap; the stale bound for the peer side).
DeadBound == OfferEvery + 2 * Wait(MaxTries, Base(SrttCap8)) + 13 * Base(SrttCap8) + Stale
DeadDetected ==
    (DeadNode /= None /\ now >= DeadAt + DeadBound) =>
        \A l \in Legs : (l[2] = DeadNode => ~up[l]) /\ (l[1] = DeadNode => ~peerUp[l])

-----------------------------------------------------------------------------
(* Liveness (under WF(Tick), on the bounded run: the last state stutters). *)
-----------------------------------------------------------------------------
EventuallyParented == <>[](\A c \in AliveL : parent[c] /= None)
EventuallyNothingOutstanding == \A l \in Legs : <>(chan[l] = <<>> \/ ~up[l] \/ Over)

-----------------------------------------------------------------------------
(* Outcome of a terminal state, for the runner (one line per state).      *)
-----------------------------------------------------------------------------
Outcome ==
    LET k == {t \in torn : t.why = "exhausted" /\ t.peerAlive}
    IN IF k /= {} THEN "Collapsed"
       ELSE IF \E c \in AliveL : parent[c] = None THEN "Stranded"
       ELSE IF \E c \in AliveL : 10 * heard[c] < 7 * published THEN "Starved"
       ELSE IF Direct = AliveL THEN "FullFanOut"
       ELSE "OneChildRelayed(" \o ToString(Cardinality(Direct)) \o ")"
RecordOutcome == Over => PrintT(<<"OUTCOME", Outcome>>)

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
=============================================================================
