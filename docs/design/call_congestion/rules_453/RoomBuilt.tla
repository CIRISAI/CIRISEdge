------------------------------ MODULE RoomBuilt ------------------------------
(* R32 ROOM-BUILT (45.3, composed, the rules as built after R31):
     (1) a stale chunk is not an arrival: it never resets the carrier's silence;
     (2) stale chunks alone excuse for at most STALE_ONLY_EXCUSE_MS = 5 s per
         run, the run counted from the first witness after a lapse
         (selector.rs on_stale_witness: a new run when the last witness is
         more than OFFER_IS_LIFE_MS old); past that only a stamp declaring
         > 800 ms excuses; a delivered chunk ends the run;
     (3) each stale chunk usable once by seq, <= 6 s late; one per stream per
         offer period is forwarded (alm.rs note_stale_end_to_end);
     (4) P stamps from word > 300 ms (the first-chunk grace = the stamp's
         declared backlog); the excuse needs a declared backlog > 800 ms.
   Code: CIRISEdge-453 working tree on e356535f: selector.rs 1405-1440
   (excuse), 552-562 (witness run), 585 (a chunk ends the run), 1926
   (STALE_ONLY_EXCUSE_MS); alm.rs 56 (STALE_WITNESS_CAP_MS), 1825-1855.

   One step = 250 ms. P's FIFO q grows g a tick while P hands it media under
   the cap and drains a tick a tick while STALE holds media back; P's
   estimate lags `lag` ticks while it grows and reads `u` low while it
   drains. R is P's kept child (depth 0). C starts as P's direct child and
   MOVES to R the first tick a chunk of P reaches it 300 ms late or more
   (ReceiverMoves RM2), subscribing to R at depth 1 then.

   Liar = TRUE: the manufactured-stale relay. P is never backlogged (no
   cap). R holds fresh chunks and forwards them to C as stale witnesses (one
   per offer period at most, each new by seq and <= 6 s late) whenever it
   likes, and delivers nothing. C is subscribed to R from tick 0 at depth D. *)
EXTENDS Naturals, FiniteSets

CONSTANTS Liar, CapEnd, H, USet, LSet, GSet, ThrS, DSet,
          RunSet, PauseSet,  \* the liar's pattern: witness for runLen ticks, pause pauseLen
          LapseRestarts      \* as built: a witness after a 2.5 s lapse starts a new 5 s run
                             \* (selector.rs:554-559); FALSE: only a delivered chunk does

Budget == 3        \* > 800 ms
Life == 10         \* 2.5 s
StaleOnly == 20    \* 5 s
Win == 13          \* 3.3 s
CapW == 24         \* 6 s
DownS == 20

VARIABLES t, q, est, hist, qh, pend,
          rLast, rEx, rStamp, rStaleAt, rStaleSince, rAttached,
          moved, subAt, cLast, cEx, cStamp, cStaleAt, cStaleSince, cAttached,
          wSentAt, firstW, gotR, u, lag, g, phP, phR, dep, runLen, pauseLen

vars == <<t, q, est, hist, qh, pend, rLast, rEx, rStamp, rStaleAt, rStaleSince, rAttached,
          moved, subAt, cLast, cEx, cStamp, cStaleAt, cStaleSince, cAttached,
          wSentAt, firstW, gotR, u, lag, g, phP, phR, dep, runLen, pauseLen>>
N == 999
NoSt == [heard |-> N, sent |-> 0, d |-> 0]
Max(a, b) == IF a > b THEN a ELSE b
MaxSet(S) == IF S = {} THEN 0 ELSE CHOOSE x \in S : \A y \in S : x >= y
Within(x, k) == x /= N /\ t - x <= k
Fresh(st) == st.heard /= N /\ (t - st.sent) - st.d <= Life
Susp(d) == (6 * (2 + d) + 1) \div 2

Init == /\ t = 0 /\ q = 0 /\ est = 0 /\ hist = [i \in 0..(Win - 1) |-> 0]
        /\ qh = [i \in 0..4 |-> 0] /\ pend = {}
        /\ rLast = 0 /\ rEx = N /\ rStamp = NoSt /\ rStaleAt = N /\ rStaleSince = N
        /\ rAttached = TRUE
        /\ moved = Liar /\ subAt = 0 /\ cLast = 0 /\ cEx = N /\ cStamp = NoSt
        /\ cStaleAt = N /\ cStaleSince = N /\ cAttached = TRUE /\ wSentAt = N /\ firstW = N
        /\ gotR = FALSE
        /\ u \in USet /\ lag \in LSet /\ g \in GSet /\ phP \in 0..3 /\ phR \in 0..3
        /\ dep \in (IF Liar THEN DSet ELSE {1})
        /\ runLen \in RunSet /\ pauseLen \in PauseSet

Tick ==
 /\ t < H
 /\ LET lw == Liar /\ (t % (runLen + pauseLen)) < runLen   \* the liar's witness pattern
      capped  == t < CapEnd
      media   == est <= Budget
      wmax    == Max(est, MaxSet({hist[i] : i \in 0..(Win - 1)}))
      stampP  == (t % 4 = phP) /\ wmax >= ThrS
      sendC   == IF media THEN {[at |-> t + q, kind |-> "c", sent |-> t, d |-> 0]} ELSE {}
      sendS   == IF stampP THEN {[at |-> t + q, kind |-> "s", sent |-> t, d |-> wmax]} ELSE {}
      pend1   == pend \cup sendC \cup sendS
      arr     == {x \in pend1 : x.at = t}
      chA     == {x \in arr : x.kind = "c"}
      stA     == {x \in arr : x.kind = "s"}
      q2      == IF capped THEN (IF media THEN q + g ELSE IF q > 0 THEN q - 1 ELSE 0)
                 ELSE (IF q > 4 THEN q - 4 ELSE 0)
      qh2     == [i \in 0..4 |-> IF i = 0 THEN q2 ELSE qh[i - 1]]
      e2      == IF q2 >= q THEN qh2[lag] ELSE (IF q2 > u THEN q2 - u ELSE 0)
      freshA  == {x \in chA : t - x.sent <= Budget}
      staleA  == {x \in chA : t - x.sent > Budget /\ t - x.sent <= CapW}
      \* ---- R's view of P (depth 0): stale chunks are witnesses, not arrivals
      rl2     == IF freshA /= {} THEN t ELSE rLast
      rSt2    == IF stA = {} THEN rStamp
                 ELSE LET s == CHOOSE x \in stA : TRUE IN [heard |-> t, sent |-> s.sent, d |-> s.d]
      rSA2    == IF staleA /= {} THEN t ELSE rStaleAt
      rSS2    == IF freshA /= {} THEN N
                 ELSE IF staleA /= {} /\ (rStaleSince = N \/ (LapseRestarts /\ ~Within(rStaleAt, Life))) THEN t
                 ELSE rStaleSince
      rStamped == Fresh(rSt2) /\ rSt2.d > Budget
      rExc    == rStamped \/ (Within(rSA2, Life) /\ Within(rSS2, StaleOnly))
      rEx2    == IF rExc THEN t ELSE rEx
      rFail   == rAttached /\ ~rExc /\ t - Max(rl2, IF rEx2 = N THEN 0 ELSE rEx2) >= Susp(0)
      rAlive  == rAttached /\ ~rFail
      \* ---- C: moves to R when P reads 300 ms late (as P's direct child)
      late    == ~Liar /\ \E x \in chA : t - x.sent >= 2
      mv2     == moved \/ late
      sub2    == IF ~moved /\ mv2 THEN t ELSE subAt
      \* what R gives C: fresh chunks (a child), a witness (once a period,
      \* to a child), stamps with its 1 s offers (to every member)
      toC     == mv2 /\ rAlive
      cGetsC  == toC /\ ~Liar /\ freshA /= {}
      witOK   == wSentAt = N \/ t - wSentAt >= 4
      cGetsW  == toC /\ witOK /\ (IF Liar THEN lw ELSE staleA /= {})
      offR    == rAlive /\ (t % 4 = phR) /\ rSt2.heard /= N /\ t - rSt2.heard <= Life
      cSt2    == IF offR THEN [heard |-> t, sent |-> rSt2.sent, d |-> rSt2.d] ELSE cStamp
      cl2     == IF cGetsC THEN t ELSE cLast
      cSA2    == IF cGetsW THEN t ELSE cStaleAt
      cSS2    == IF cGetsC THEN N
                 ELSE IF cGetsW /\ (cStaleSince = N \/ (LapseRestarts /\ ~Within(cStaleAt, Life))) THEN t
                 ELSE cStaleSince
      cStamped == Fresh(cSt2) /\ cSt2.d > Budget
      cExc    == rAlive /\ (cStamped \/ (Within(cSA2, Life) /\ Within(cSS2, StaleOnly)))
      cEx2    == IF cExc /\ mv2 THEN t ELSE cEx
      gotR2   == (gotR /\ moved) \/ cGetsC
      firstOw == mv2 /\ ~gotR2
      grace   == IF firstOw /\ Fresh(cSt2) THEN (IF cSt2.d > DownS THEN DownS ELSE cSt2.d) ELSE 0
      lastC   == Max(Max(IF gotR2 THEN cl2 ELSE 0, sub2), IF cEx2 = N THEN 0 ELSE cEx2)
      silC    == IF t - lastC > grace THEN t - lastC - grace ELSE 0
      cFail   == mv2 /\ cAttached /\ ~cExc /\ (silC >= Susp(dep) \/ ~rAlive)
  IN /\ t' = t + 1 /\ q' = q2 /\ est' = e2 /\ qh' = qh2
     /\ hist' = [i \in 0..(Win - 1) |-> IF i = 0 THEN est ELSE hist[i - 1]]
     /\ pend' = pend1 \ arr
     /\ rLast' = rl2 /\ rEx' = rEx2 /\ rStamp' = rSt2 /\ rStaleAt' = rSA2
     /\ rStaleSince' = rSS2 /\ rAttached' = rAlive
     /\ moved' = mv2 /\ subAt' = sub2 /\ cLast' = cl2 /\ cEx' = cEx2 /\ cStamp' = cSt2
     /\ cStaleAt' = cSA2 /\ cStaleSince' = cSS2 /\ cAttached' = (cAttached /\ ~cFail)
     /\ wSentAt' = IF cGetsW THEN t ELSE wSentAt
     /\ firstW' = IF cGetsW /\ firstW = N THEN t ELSE firstW
     /\ gotR' = gotR2
     /\ UNCHANGED <<u, lag, g, phP, phR, dep, runLen, pauseLen>>

Spec == Init /\ [][Tick]_vars

TypeOK == q \in Nat
\* (c) the honest move to the relay: C keeps R; R keeps P.
MovedKeepsRelay == (~Liar /\ moved) => cAttached
RelayKeepsP == ~Liar => rAttached
\* (b) the manufactured-stale liar as the only candidate: failed over within
\* 5 s + down_silence of its first witness (or of the subscription).
LiarOnlyBound == (Liar /\ cAttached) => t <= (IF firstW = N THEN 0 ELSE firstW) + StaleOnly + DownS
\* the liar is never held past the horizon (a liar pattern that escapes)
LiarGone == (Liar /\ t >= H - 1) => ~cAttached
=============================================================================
