--------------------------- MODULE UplinkBacklog ---------------------------
(* Row R25 BACKLOG (45.3 rows DR + G8): the uplink backlog is the LEAST
   send-clock age over every leg with something outstanding, with at least
   two such legs (once draining, the kept leg alone counts); backlogged =>
   stalled; no relay offers while stalled.

   Code (CIRISEdge work/45.3):
     av_call.rs:4187-4219  uplink_backlog: ages per leg (past min_rtt);
                           reading = min if len >= UPLINK_STALL_LEGS (2), or
                           draining and len >= 1; else None
     alm.rs:438-466        UplinkDrain: enter at >= 400 ms, leave after the
                           reading stays < 200 ms for 1 s
     av_call.rs:7097-7108  the drain is folded first, then
                           set_uplink_stall(detected), and
     alm.rs:698-715        set_uplink_stall: detected || drain.active();
                           latched UPLINK_STALL_LATCH_MS = 2 s
     alm.rs:2372           relay offers: relay_capable && forwarding &&
                           !uplink_stall
     alm.rs:627-629        STALE: sends_stale = drain.backlog_ms > 800

   A leg's age is a round trip: this node's uplink queue Q plus the peer's
   own queue P[i] (its proofs wait there). One step = one watch tick
   (250 ms): enter = 2 ticks (>= 400 ms), leave = < 1 tick (< 200 ms),
   clear = 4 ticks, latch = 8 ticks, stale = >= 4 ticks (> 800 ms).
   Leg 1 is the kept child.                                                  *)
EXTENDS Naturals, FiniteSets

CONSTANTS
    N,          \* legs (members this node sends its stream to)
    QMax, PMax, \* the largest own / peer queue, ticks
    SlowOnly,   \* "any" | "kept": which peers may queue (P > 0)
    Enter, Leave, Clear, Latch, StaleT

VARIABLES Q, P, outs, reading, drain, clear, stallAge, relayOffer, calm

vars == <<Q, P, outs, reading, drain, clear, stallAge, relayOffer, calm>>
Legs == 1..N
None == 99
MinOf(S) == CHOOSE x \in S : \A y \in S : x <= y
Stalled == stallAge < Latch

TypeOK == /\ Q \in 0..QMax /\ P \in [Legs -> 0..PMax] /\ outs \in SUBSET Legs
          /\ drain \in BOOLEAN /\ clear \in 0..Clear /\ stallAge \in 0..Latch

Init == /\ Q = 0 /\ P = [i \in Legs |-> 0] /\ outs = {} /\ reading = None
        /\ drain = FALSE /\ clear = 0 /\ stallAge = Latch /\ relayOffer = FALSE
        /\ calm = FALSE

Tick ==
    \E q \in 0..QMax, p \in [Legs -> 0..PMax], o \in SUBSET Legs, c \in BOOLEAN :
      /\ (calm => c) /\ (c => q = 0)               \* once calm, own queue stays empty
      /\ \A i \in Legs : (SlowOnly = "kept" /\ i /= 1) => p[i] = 0
      /\ LET ages == {q + p[i] : i \in o}
             r    == IF Cardinality(o) >= 2 \/ (drain /\ o /= {}) THEN MinOf(ages) ELSE None
             rv   == IF r = None THEN 0 ELSE r
             \* UplinkDrain.observe
             d2   == IF ~drain THEN rv >= Enter
                     ELSE ~(rv < Leave /\ clear >= Clear)   \* clear since >= 1 s
             cl2  == IF drain /\ d2 /\ rv < Leave THEN clear + 1 ELSE 0
             \* the G8 verdict is any other detection; here: none of its own
             det  == d2
             sa2  == IF det THEN 0 ELSE IF stallAge < Latch THEN stallAge + 1 ELSE Latch
         IN /\ Q' = q /\ P' = p /\ outs' = o /\ reading' = r
            /\ drain' = d2 /\ clear' = IF cl2 > Clear THEN Clear ELSE cl2
            /\ stallAge' = sa2
            /\ relayOffer' = (sa2 >= Latch)        \* forwarding, relay-capable
            /\ calm' = c

Spec == Init /\ [][Tick]_vars /\ WF_vars(Tick)

\* One slow peer is that peer, not this uplink.
OnePeerIsNotOwn ==
    (Q = 0 /\ Cardinality({i \in outs : P[i] > 0}) <= 1 /\ Cardinality(outs) >= 2)
        => reading = 0
\* This uplink's own queue is seen, whenever any leg has something outstanding.
OwnQueueSeen == (Q >= Enter /\ outs /= {}) => (reading /= None /\ reading >= Enter)
\* ... and STALE engages on it.
OwnStaleSeen == (Q >= StaleT /\ outs /= {}) => (reading /= None /\ reading >= StaleT)
\* Backlogged => stalled, in the same tick.
BackloggedStalled == (reading /= None /\ reading >= Enter) => (drain /\ Stalled)
DrainStalled == drain => Stalled
\* No relay offers while stalled.
NoRelayOfferStalled == relayOffer => ~Stalled
\* Once this uplink is clear for good, the drain ends.
DrainEnds == calm ~> ~drain
=============================================================================
