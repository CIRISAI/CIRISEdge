---------------------------- MODULE RelayAdvert ----------------------------
(* Row R29 OFFER-AS-LIFE, its second clause: a relay's advertised upstream
   latency is >= its parent's + RTT/2, and >= the age of every chunk it
   dropped as stale in the last OFFER_IS_LIFE_MS (2.5 s).

   Code (CIRISEdge work/45.3):
     selector.rs:429      upstream_view latency = max(e2e meter,
                          parent's upstream_latency_ms + rtt/2)
     alm.rs:1722-1726     note_stale_end_to_end: stale_seen.insert(stream,
                          (now, latency)): the LATEST drop replaces the last
     alm.rs:1733-1750     sync_upstream: advertised = max(view, stale_seen's
                          latency while it is <= 2.5 s old)

   Keep = "last" (as built) | "max" (the max over the window).
   Units: one step = 250 ms; ages in 100 ms (StaleB = 8 = 800 ms). The
   window holds the drops of the last Life steps.                          *)
EXTENDS Naturals, Sequences

CONSTANTS Keep, Life, AMax, StaleB, Parent, HalfRtt

VARIABLES win, seen, adv

vars == <<win, seen, adv>>
\* win: the ages of the drops in the last Life steps (0 = none that step)
\* seen: <<steps since, age>> as stale_seen holds it

Init == win = [i \in 1..Life |-> 0] /\ seen = <<Life + 1, 0>> /\ adv = Parent + HalfRtt

Min2(a, b) == IF a < b THEN a ELSE b
MaxSeq(s) == LET R == {s[i] : i \in DOMAIN s} IN CHOOSE x \in R : \A y \in R : x >= y

Tick ==
    \E drop \in {0} \cup ((StaleB + 1)..AMax) :
      LET w2 == Append(Tail(win), drop)
          s1 == IF drop > 0 THEN <<1, drop>>
                ELSE <<Min2(seen[1] + 1, Life + 1), seen[2]>>
          \* "last": the newest drop, while <= Life steps old; "max": the
          \* largest drop of the window
          st == IF Keep = "max" THEN MaxSeq(w2)
                ELSE IF s1[1] <= Life THEN s1[2] ELSE 0
          v  == Parent + HalfRtt
      IN /\ win' = w2 /\ seen' = s1
         /\ adv' = IF st > v THEN st ELSE v


Spec == Init /\ [][Tick]_vars

TypeOK == TRUE
AdvOverParent == adv >= Parent + HalfRtt
AdvOverDrops  == adv >= MaxSeq(win)
\* What the excuse reads: still past the stale budget while any drop is recent.
AdvStillLate  == MaxSeq(win) > StaleB => adv > StaleB
=============================================================================
