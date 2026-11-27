----------------------------- MODULE AgeFloor -----------------------------
(* Row R27 AGE (45.3): media age is measured end to end, above a per-(stream,
   epoch) floor (the least wall - source_ts seen); a chunk past the budget is
   dropped, never relayed, and judged again at hand-out to the host.

   Code (CIRISEdge work/45.3):
     av_call.rs:146-161  is_stale_end_to_end: latency above the AGE floor >
                         MEDIA_STALE_BUDGET (800 ms)
     alm.rs:1553-1567    the floor is keyed (stream, epoch); a roll keeps the
                         epoch before and starts a new one
     rxmove.rs:51-58     LatencyFloor.sample: a LOWER offset replaces the floor
                         at once; a sample within FLOOR_NEAR_MS (50 ms) of a
                         floor older than FLOOR_REANCHOR_MS (30 s) re-anchors
     av_call.rs:5953-5960  stale on receipt: dropped, never forwarded
     av_call.rs:6663-6680  hand-out: latency_now (wall now - source - floor)
                         judged again; stale frames are not handed out

   Units of 50 ms: Budget = 16 (800 ms), Near = 1 (50 ms), Step = 40 (a
   publisher clock 2 s ahead for one chunk: its offset reads 2 s low).
   d = a chunk's true lateness above the path's fastest delivery; the
   floor's true value is 0. w = its wait in the reorder window / for its
   other fragments before hand-out.

   Floor = "current"  : rxmove.rs:51-58 as built.
   Floor = "confirm"  : the proposed fix: a lower offset becomes the floor
                        only when a second chunk lands within Near of it;
                        the epoch's first chunk still sets the floor alone.
   Floor = "confirm0" : as confirm, and the first floor of an epoch also
                        needs its second chunk (until then: no floor, media
                        passes, as before the first chunk today).          *)
EXTENDS Integers

CONSTANTS Floor, Budget, Near, Step, DMax, WMax, MaxSteps, Rolls,
          MaxReanchor   \* drift re-anchors per epoch (one per 30 s in the code)

VARIABLES floor, cand, steps, lastStep, rolls, anchored, ev, rean, prevOn

vars == <<floor, cand, steps, lastStep, rolls, anchored, ev, rean, prevOn>>
None == -1000
\* ev: the last chunk's verdicts, for the properties
\*   <<d, step, latency, staleRx, forwarded, handed, w>>
\*   (before the first chunk, and after a roll, the empty event: handed)
\* anchored: the epoch has seen TWO consecutive on-time chunks (d = 0, not
\* stepped), so every rule here has the true floor (confirm needs the pair)
Empty == <<0, FALSE, 0, FALSE, FALSE, TRUE, 0>>

Init == /\ floor = None /\ cand = None /\ steps = 0 /\ lastStep = FALSE
        /\ rolls = 0 /\ anchored = FALSE /\ rean = 0 /\ prevOn = FALSE
        /\ ev = Empty

Lat(off, f) == IF f = None THEN None ELSE IF off - f > 0 THEN off - f ELSE 0
Stale(l) == l /= None /\ l > Budget

\* One chunk of the current epoch arrives.
Chunk ==
    \E d \in 0..DMax, st \in BOOLEAN, w \in 0..WMax, old \in BOOLEAN :
      /\ st => (steps < MaxSteps /\ ~lastStep)      \* the step is one chunk
      /\ old => rean < MaxReanchor   \* a re-anchor needs a 30 s old floor
      /\ LET off == IF st THEN d - Step ELSE d
             \* the floor after this sample. confirm / confirm0: a lower
             \* offset is a candidate; the NEXT chunk confirms it when it
             \* lands within Near of it (and below the floor too), and the
             \* floor takes the lower of the two. (Taking the higher, as first
             \* drafted, left the floor up to Near high, and one drift re-anchor
             \* on top missed a chunk 2 x Near past the budget: TLC, 7 states.)
             near    == cand /= None /\ off - cand <= Near /\ cand - off <= Near
             lower   == floor = None \/ off < floor
             lo      == IF off < cand THEN off ELSE cand
             reanch  == floor /= None /\ old /\ off >= floor /\ off - floor <= Near
             f2 == CASE Floor = "current" ->
                          IF lower \/ reanch THEN off ELSE floor
                     [] Floor = "confirm" /\ floor = None -> off
                     [] OTHER ->
                          IF lower /\ near THEN lo
                          ELSE IF reanch THEN off ELSE floor
             c2 == IF Floor = "current" THEN None
                   ELSE IF lower /\ ~near /\ ~(Floor = "confirm" /\ floor = None)
                        THEN off ELSE None
             l   == Lat(off, f2)
             srx == Stale(l)
             \* hand-out: judged again after waiting w
             lh  == IF l = None THEN None ELSE l + w
             hnd == ~srx /\ ~Stale(lh)
         IN /\ floor' = f2 /\ cand' = c2
            /\ steps' = IF st THEN steps + 1 ELSE steps
            /\ lastStep' = st
            /\ prevOn' = (~st /\ d = 0)
            /\ anchored' = (anchored \/ (prevOn /\ ~st /\ d = 0))
            /\ ev' = <<d, st, l, srx, ~srx, hnd, w>>
            /\ rean' = IF reanch /\ f2 = off /\ ~lower THEN rean + 1 ELSE rean
            /\ UNCHANGED rolls

\* The room's epoch rolls: the floor starts again with the new epoch.
Roll ==
    /\ rolls < Rolls
    /\ rolls' = rolls + 1
    /\ floor' = None /\ cand' = None /\ anchored' = FALSE /\ lastStep' = FALSE /\ rean' = 0
    /\ prevOn' = FALSE /\ ev' = Empty
    /\ UNCHANGED steps

Next == Chunk \/ Roll
Spec == Init /\ [][Next]_vars

D == ev[1]
StepC == ev[2]
L == ev[3]
StaleRx == ev[4]
Fwd == ev[5]
Handed == ev[6]
Wt == ev[7]

TypeOK == TRUE
\* An on-time chunk (not the stepped one) is never dropped as stale.
NoFalseStale == (~StepC /\ D <= Budget) => ~StaleRx
\* ... nor at hand-out, when its wait keeps it in budget.
NoFalseStaleHandout == (~StepC /\ D + Wt <= Budget) => (StaleRx \/ Handed)
\* Once the epoch has seen an on-time chunk, a chunk more than Near past the
\* budget is caught (dropped on receipt).
StaleCaught == (anchored /\ ~StepC /\ D > Budget + Near) => StaleRx
\* A relay never forwards a chunk it judged stale.
NeverForwardStale == Fwd => ~StaleRx
\* The host is never handed a chunk truly past the budget (once anchored).
HandedFresh == (anchored /\ ~StepC /\ Handed) => D + Wt <= Budget + Near
=============================================================================
