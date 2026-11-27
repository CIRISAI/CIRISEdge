--------------------------- MODULE StaleAtSender ---------------------------
(* Row R26 STALE (45.3): while the uplink backlog reads over the receivers'
   media budget (MEDIA_STALE_BUDGET, 800 ms), the sender hands the uplink no
   media (audio included); control is never held.

   Code (CIRISEdge work/45.3):
     alm.rs:424-427   stale_at_sender(b) = b > 800
     alm.rs:627-629   sends_stale(): the drain's last backlog reading
     av_call.rs:4235-4240  media_held_back(): every media chunk, own or
                      relayed; control never comes here

   The uplink is one FIFO past the process, drained C units a tick (one tick
   = 250 ms). The reading is the send-clock age of the oldest unproved
   message (R24 exact, the ack's return not counted), read once a tick,
   before that tick's sends. Ages are in ticks; "stale" = arrival age >
   StaleT ticks (800 ms -> 3).                                               *)
EXTENDS Naturals, Sequences

CONSTANTS C, MMax, CtlMax, LMax, StaleT, Bound, Rule   \* Rule: "stale" | "none"

VARIABLES q, maxArr, ctlLost, stalePhase

vars == <<q, maxArr, ctlLost, stalePhase>>
\* q: the FIFO, each entry <<age, kind>>, head first
Reading == IF q = <<>> THEN 0 ELSE q[1][1]
Ages == 0..(LMax + 2)

TypeOK == Len(q) <= LMax

Init == q = <<>> /\ maxArr = 0 /\ ctlLost = FALSE /\ stalePhase = FALSE

RECURSIVE MaxMediaAge(_)
MaxMediaAge(s) == IF s = <<>> THEN 0
                  ELSE LET r == MaxMediaAge(Tail(s)) IN
                       IF s[1][2] = "m" /\ s[1][1] > r THEN s[1][1] ELSE r

Tick ==
    \E m \in 0..MMax, k \in 0..CtlMax :
      LET held   == Rule = "stale" /\ Reading > StaleT
          mSent  == IF held THEN 0 ELSE m
          \* this tick's sends join the tail (age 0); control first
          new    == [i \in 1..(k + mSent) |-> <<0, IF i <= k THEN "c" ELSE "m">>]
          room   == LMax - Len(q)
          take   == IF k + mSent <= room THEN new ELSE SubSeq(new, 1, room)
          q1     == q \o take
          \* C units leave (delivered at their age + 1), the rest age a tick
          out    == IF Len(q1) <= C THEN q1 ELSE SubSeq(q1, 1, C)
          rest   == IF Len(q1) <= C THEN <<>> ELSE SubSeq(q1, C + 1, Len(q1))
          arr    == MaxMediaAge(out)
      IN /\ q' = [i \in 1..Len(rest) |-> <<rest[i][1] + 1, rest[i][2]>>]
         /\ maxArr' = IF arr > maxArr THEN arr ELSE maxArr
         /\ ctlLost' = (ctlLost \/ k > room)
         /\ stalePhase' = held

Spec == Init /\ [][Tick]_vars /\ WF_vars(Tick)

\* Media handed to the uplink arrives at most Bound ticks old.
ArrivalBound == maxArr <= Bound
\* Control is never held by STALE (only a full FIFO, outside edge, drops it).
ControlNeverHeld == ~ctlLost
\* The queue drains: the backlog keeps returning under the budget.
Drains == []<>(Reading <= StaleT)
=============================================================================
