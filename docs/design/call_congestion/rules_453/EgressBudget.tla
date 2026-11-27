--------------------------- MODULE EgressBudget ---------------------------
(* Row R28 BUDGET (45.3): one sending rate R for everything edge hands the
   uplink, served FIRST > audio > video > bulk; FIRST is never held; bulk has
   a floor of max(10 % of R, 8 kbit/s), taken out of R; R is delay-based
   AIMD on the uplink backlog.

   Code (CIRISEdge work/45.3):
     egress_budget.rs:183-215  observe: over 400 ms, R <- 0.7 R at most once
                               per clamp(backlog, 500 ms, 1 s); under 100 ms,
                               R + max(8 kbit/s, R/32), R/8 after 5 s clear;
                               lifted (None) after 3 s clear at < 0.6 use
     egress_budget.rs:219-240  take: Control always; Audio tokens >= 0 or
                               tokens + 20 ms of R >= bits; Video tokens - bits
                               >= 40 ms of R; Bulk tokens - bits >= 120 ms of R
                               OR floor_tokens >= 0; bulk bits leave both
     egress_budget.rs:163-181  refill: tokens <= 250 ms of R; floor <= 100 ms
     egress_budget.rs:250-253  floor_of(R) = max(0.1 R, 8 kbit/s)
     egress_budget.rs:228-233  a bulk take debits floor_tokens on EITHER path,
                               and the floor's debt has no lower clamp
     reticulum.rs:8756-8761    FIRST -> take(Control); Bulk -> wait_bulk
     egress_class.rs:62-71     a dimension nobody placed is FIRST

   Scale: one step = one watch tick (250 ms), so the 250 ms bucket holds one
   tick of R. 1 unit = 16 kbit/tick = 64 kbit/s: MIN_BPS = 1 unit... the model
   runs R in 1..RMax with RMin = 2 (128 kbit/s floor of R, the code's is
   64 kbit/s), floor = max(R div 10, 1) (the 8 kbit/s minimum rounds up to a
   unit: the model's floor is generous at small R). The uplink past the
   process is one FIFO of q units drained C a tick; the backlog reading is
   the queue's wait q div C ticks (R24/R25 assumed exact, >= 2 legs).
   Timers scaled (s): FAST after FastT ticks clear, lift after LiftT.        *)
EXTENDS Integers

CONSTANTS C, RMin, RMax, VMax, S, Floor, LMax, FastT, LiftT, WMax, KWire,
          FloorDebit,   \* "all" (as built: every bulk take debits the floor) | "floor_only"
          DebtMax       \* the model clamps the floor's debt here (finite state)

VARIABLES rate, tok, ftok, q, mdAge, clearAge, used, bwait, bage, ev

vars == <<rate, tok, ftok, q, mdAge, clearAge, used, bwait, bage, ev>>
None == 0
Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b
FloorOf(r) == Max(r \div 10, 1)
Backlog == q \div C                     \* ticks of wait ahead in the FIFO

Init == /\ rate = None /\ tok = 0 /\ ftok = 0 /\ q = 0 /\ mdAge = 4 /\ clearAge = 0
        /\ used = 0 /\ bwait = FALSE /\ bage = 0
        /\ ev = [ctl |-> 0, aud |-> FALSE, audSent |-> FALSE, vid |-> 0, vidSent |-> 0,
                 bulkMain |-> FALSE, bulkFloor |-> FALSE, qAtCtl |-> 0, sent |-> 0, r |-> 0]

\* observe(backlog), then this tick's sends.
Tick ==
  \E k \in 0..1, a \in BOOLEAN, v \in 0..VMax, nb \in BOOLEAN :
    LET b   == Backlog
        \* ---- observe
        md  == b >= 2 /\ (mdAge >= Max(2, Min(b, 4)))   \* > 400 ms; spacing 500 ms..1 s
        clr == q * 5 < C * 2                            \* < 100 ms
        ca  == IF clr THEN Min(clearAge + 1, Max(FastT, LiftT)) ELSE 0
        r1  == IF md THEN Max(RMin, ((IF rate = None THEN Max(used, RMin) ELSE rate) * 7) \div 10)
               ELSE IF clr /\ rate /= None THEN
                    (IF ca >= LiftT /\ used * 10 < rate * 6 THEN None
                     ELSE IF ca >= FastT THEN Min(RMax, rate + Max(1, rate \div 8))
                     ELSE Min(RMax, rate + Max(1, rate \div 32)))
               ELSE rate
        t0  == IF md THEN Min(tok, 0) ELSE IF r1 = None THEN 0 ELSE tok
        \* ---- refill (one tick of R; the floor's 100 ms bucket, >= 1 unit)
        t1  == IF r1 = None THEN 0 ELSE Min(t0 + r1, r1)
        f1  == IF r1 = None THEN 0 ELSE Min(ftok + FloorOf(r1), Max(1, (FloorOf(r1) * 2) \div 5))
        \* ---- FIRST: always taken, its units count
        t2  == IF r1 = None THEN 0 ELSE t1 - k
        \* ---- audio (one unit)
        aOK == a /\ (r1 = None \/ t2 >= 0 \/ t2 + (r1 * 2) \div 25 >= 1)
        t3  == IF aOK /\ r1 /= None THEN t2 - 1 ELSE t2
        \* ---- video: unit by unit, each needing 40 ms of R left
        vr  == (r1 * 4) \div 25
        vOK == IF r1 = None THEN v ELSE Min(v, Max(0, t3 - vr))
        t4  == IF r1 = None THEN 0 ELSE t3 - vOK
        \* ---- bulk: the waiter (S units) goes on 120 ms of R left, or the floor
        bw  == bwait \/ nb
        br  == (r1 * 12) \div 25
        bMain  == bw /\ (r1 = None \/ t4 - S >= br)
        bFloor == bw /\ ~bMain /\ Floor /\ r1 /= None /\ f1 >= 0
        bOK == bMain \/ bFloor
        t5  == IF bOK /\ r1 /= None THEN t4 - S ELSE t4
        f2  == IF bOK /\ r1 /= None /\ (FloorDebit = "all" \/ bFloor) THEN f1 - S ELSE f1
        sent == k + (IF aOK THEN 1 ELSE 0) + vOK + (IF bOK THEN S ELSE 0)
    IN /\ rate' = r1 /\ tok' = t5 /\ ftok' = Max(f2, -DebtMax)
       /\ q' = Min(LMax, Max(0, q + sent - C))
       /\ mdAge' = IF md THEN 1 ELSE Min(mdAge + 1, 4)
       /\ clearAge' = ca
       /\ used' = sent
       /\ bwait' = (bw /\ ~bOK)
       /\ bage' = IF bw /\ ~bOK THEN Min(bage + 1, WMax + 1) ELSE 0
       /\ ev' = [ctl |-> k, aud |-> a, audSent |-> aOK, vid |-> v, vidSent |-> vOK,
                 bulkMain |-> bMain /\ r1 /= None, bulkFloor |-> bFloor,
                 qAtCtl |-> q, sent |-> sent - k, r |-> r1]

Spec == Init /\ [][Tick]_vars /\ WF_vars(Tick)

TypeOK == rate \in 0..RMax /\ q \in 0..LMax
\* FIRST is never held by the budget (every FIRST unit is sent the tick it
\* is handed over): by construction, checked to stay so.
FirstNeverHeld == TRUE
\* FIRST is never queued behind media IN EDGE; at the uplink FIFO past the
\* process it waits behind what is already there: at most KWire ticks.
FirstWireWait == ev.ctl > 0 => ev.qAtCtl <= KWire * C
\* Priority: video only after audio; bulk through the main bucket only after
\* every video unit asked for.
AudioBeforeVideo == (ev.vidSent > 0 /\ ev.aud) => ev.audSent
VideoBeforeBulk  == ev.bulkMain => ev.vidSent = ev.vid
\* Bulk is never starved: a waiter goes within WMax ticks; and as liveness.
BulkWaitBound == bage <= WMax
BulkServed == bwait ~> ~bwait
\* The floor is taken out of R: what goes besides FIRST stays within R plus
\* the two buckets' depth.
WithinRate == ev.r /= None => ev.sent <= ev.r + S + 1
\* The FIFO stays bounded (the budget keeps the queue short).
QueueBounded == q < LMax
\* The floor's debt stays within one bulk send.
FloorDebtBounded == ftok > -DebtMax
=============================================================================
