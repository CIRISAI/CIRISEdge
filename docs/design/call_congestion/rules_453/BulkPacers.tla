----------------------------- MODULE BulkPacers -----------------------------
(* R33 BULK-PACERS (45.3): two pacers in series for identity-plane bulk.

   Edge (CIRISEdge squash/45.3, with nat-reach's floor-debit fix 7df1d9a7):
     reticulum.rs:8872-8899  wait_egress: a BULK envelope waits on the budget,
                             wire = bytes + bytes/7 + 64
     egress_budget.rs        wait_bulk: one FIFO for every bulk send (a tokio
                             mutex), the head taken when the main bucket has
                             120 ms of R left OR the floor bucket is not in
                             debt; the floor (max(0.1 R, 8 kbit/s)) is debited
                             only for floor-path sends (the fix)
   Leviculum v0.34.0+ciris.5 (leviculum-std/src/egress.rs):
     Resource transfer is class Bulk, the lowest tier; Announce and Bulk share
     a floor credit of share/(100-share) of every high-class byte sent (10 %)
     plus 4 kbit/s while low is queued (refill 658-677, on_sent 745-754, run
     840-870); the rate is set above edge's (1.1 R); one Resource at a time per
     link (TransferInProgress), so an envelope on a busy lane waits for the
     lane (edge's lane lease, reticulum.rs:3240-3256).

   The worst case for bulk: media keeps edge's main bucket and leviculum's
   high tiers full (edge bulk goes only by its floor; leviculum serves low
   only by floor credit). One step = 250 ms; 1 unit = 1 kbit.
   Ten envelopes are queued ahead of one chat row (Order = "fifo", as built);
   the envelopes go to Lanes distinct links (1 = all to one peer).
   Order = "chatfirst": a chat row is not queued behind bulk transfers
   (its own FIFO, served first by the same floor).                        *)
EXTENDS Naturals, Sequences

CONSTANTS RSet,      \* edge's rate R, units/tick (64 = 256 kbit/s)
          SSet,      \* an envelope's wire size, units (75 = an 8 KB envelope)
          Chat,      \* the chat row's wire size, units
          NEnv, Lanes, Order, Bound, Ann   \* Ann: announce units per tick at leviculum

VARIABLES r, s, t, edgeQ, ftok, levQ, credit, chatAt, envAt

vars == <<r, s, t, edgeQ, ftok, levQ, credit, chatAt, envAt>>
Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b
F == Max(r \div 10, 2)                  \* edge floor, units/tick (8 kbit/s = 2)
FCap == Max((F * 2) \div 5, 1)          \* its 100 ms bucket
\* leviculum's floor credit per tick: 10/90 of the high bytes it sends (it
\* sends about R of media, its rate being 1.1 R) plus 4 kbit/s (1 unit)
LCredit == (r \div 9) + 1

\* an item: <<kind, size, link>>
Init == /\ r \in RSet /\ s \in SSet /\ t = 0
        /\ edgeQ = [i \in 1..(NEnv + 1) |->
                      IF i <= NEnv THEN <<"env", s, ((i - 1) % Lanes) + 1>>
                      ELSE <<"chat", Chat, 1>>]
        /\ ftok = 0 /\ levQ = <<>>
        /\ credit = 0 /\ chatAt = 0 /\ envAt = 0

\* the head edge would serve next, by Order
Pick == IF Order = "chatfirst" /\ \E i \in 1..Len(edgeQ) : edgeQ[i][1] = "chat"
        THEN CHOOSE i \in 1..Len(edgeQ) : edgeQ[i][1] = "chat"
        ELSE 1
Remove(q, i) == [j \in 1..(Len(q) - 1) |-> IF j < i THEN q[j] ELSE q[j + 1]]

Tick ==
  /\ chatAt = 0 /\ t < 400
  /\ LET f1   == Min(ftok + F, FCap)
         go   == Len(edgeQ) > 0 /\ f1 >= 0
         h    == Pick
         item == edgeQ[h]
         eQ2  == IF go THEN Remove(edgeQ, h) ELSE edgeQ
         f2   == IF go THEN f1 - item[2] ELSE f1
         lQ1  == IF go THEN Append(levQ, item) ELSE levQ
         \* leviculum: the floor credit serves its low queue oldest first, one
         \* transfer at a time (serial: one Resource per link, the worst case
         \* Lanes = 1); announces take their share of the credit first
         cr1  == credit + LCredit
         cr2  == IF cr1 > Ann THEN cr1 - Ann ELSE 0
         hd   == IF Len(lQ1) > 0 THEN 1 ELSE 0
         sent == IF hd = 0 THEN 0 ELSE Min(cr2, lQ1[1][2])
         done == hd = 1 /\ sent = lQ1[1][2]
         lQ2  == IF hd = 0 THEN lQ1
                 ELSE IF done THEN Tail(lQ1)
                 ELSE [lQ1 EXCEPT ![1] = <<lQ1[1][1], lQ1[1][2] - sent, lQ1[1][3]>>]
     IN /\ t' = t + 1
        /\ edgeQ' = eQ2 /\ ftok' = f2
        /\ levQ' = lQ2
        /\ credit' = IF hd = 0 THEN Min(cr2, 6) ELSE cr2 - sent
        /\ chatAt' = IF done /\ lQ1[1][1] = "chat" THEN t + 1 ELSE chatAt
        /\ envAt' = IF done /\ lQ1[1][1] = "env" THEN t + 1 ELSE envAt
        /\ UNCHANGED <<r, s>>

Spec == Init /\ [][Tick]_vars

TypeOK == r \in RSet
\* the chat row arrives within Bound ticks of being queued
ChatWithin == (chatAt = 0 /\ t > Bound) => FALSE
ChatArrives == chatAt > 0 \/ t < 400
=============================================================================
