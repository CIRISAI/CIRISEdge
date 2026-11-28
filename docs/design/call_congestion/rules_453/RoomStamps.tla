----------------------------- MODULE RoomStamps -----------------------------
(* R31 ROOM-STAMPS (45.3, composed): the publisher's real FIFO, its own
   estimate of it, the signed backlog stamp riding that FIFO, a relay that
   drops stale chunks and re-forwards the latest stamp it verified, and that
   relay's child, which excuses the relay's silence only on a fresh stamp.

   Code (CIRISEdge-453 e356535f + working edits):
     alm.rs own_queue_word_ms      word = max(leg queue gauges, send clock)
     av_call.rs:4224-4260          stamp_own_backlog: stamp while
                                   max(word over 2.5 s + 0.8 s) > 800 ms,
                                   declaring that max
     av_call.rs:4235-4240 (STALE)  media held back while the send clock > 800
     av_call.rs:5953 (AGE)         the relay drops chunks > 800 ms end to end
     alm.rs offers loop            the relay re-sends the latest stamp it
                                   verified with each offer (1 s) while it
                                   heard it <= 2.5 s ago
     selector.rs excuse            fresh = (now - seen) + net_at_seen <= 2.5 s,
                                   declared > 800 ms, parent forwarding
     selector.rs:1390, peer_state  silence * 2 / (2 + depth) >= 1.5 s:
                                   Suspected, failed over

   One step = 250 ms; horizon H. The cap holds from tick 0 to CapEnd: while
   P hands the uplink media its queue grows a tick a tick (2x overload),
   while it holds media back (STALE) the queue drains a tick a tick; after
   the lift it drains 4 a tick. P's ESTIMATE of its queue reads it exactly
   while it grows and up to U ticks LOW while it drains (the send clock's
   oldest message is proved; the legs carry little): STALE and the stamp
   read the estimate, the relay's AGE reads the truth.

   Rule = "e356"  : as built (signed stamps only).
   Rule = "c1545" : 1545ee18, the relay's own advertised latency (its stale
                    drops in the last 2.5 s) excuses it.
   Rule = "stale" : proposed: a STALE CHUNK IS A STAMP. The relay forwards
                    each offer period one publisher-signed chunk it dropped
                    as stale (seq above the child's highest, so each is
                    usable once); a child excuses the relay while it holds
                    one heard <= 2.5 s ago whose age is <= ChunkCap.
   Rule = "both"  : "stale" and the signed stamp.                          *)
EXTENDS Naturals, FiniteSets

CONSTANTS Rule, USet, LSet, GSet, CapEnd, H, Liar, ChunkCap,
          NCSet,       \* the stalled offer interval to a non-child (ticks): 4, or 8..14
          SelfStamp    \* proposed: P stamps while it withholds from anyone (stalled),
                       \* and its stamps go to its standbys every offer period

Budget == 3        \* > 800 ms: 4 ticks and over (ages in whole ticks)
Life == 10         \* 2.5 s
Win == 13          \* 3.3 s
SuspR == 6         \* the relay's view of P (depth 0): 1.5 s
SuspC == 9         \* the child's view of the relay (depth 1): 2.25 s

VARIABLES t, q, est, hist,     \* tick, true queue (ticks), P's estimate, est history
          pend,                \* items in P's FIFO: [at, kind, sent, d]
          rStamp,              \* the relay's latest verified stamp: [heard, sent, d] or none
          rStale,              \* the relay's latest stale chunk: [heard, sent] or none
          rDrops,              \* the relay's last stale drop tick (or -1 as 999)
          cLast, cEx, cStamp, cStale,   \* the child: last chunk, last excused, stamp, stale chunk
          rLastP, rEx,         \* the relay's view of P: last arrival, last excused
          cAttached, rAttached,
          u, phP, phR,         \* chosen once: P's under-read, the offer phases
          lag, g, qh,          \* the estimate's lag while the queue grows; the
                               \* growth a tick while media goes; q's history
          drainOn, clearN, stallAge,  \* P's drain (DR) and stall latch (G8)
          sLast, sEx, sStamp, sOffer, sAttached, nc, lastNC
                               \* L2, a listener that moved to the relay and keeps P
                               \* as its STANDBY (the come-back needs it kept)

vars == <<t, q, est, hist, pend, rStamp, rStale, rDrops, cLast, cEx, cStamp, cStale,
          rLastP, rEx, cAttached, rAttached, u, phP, phR, lag, g, qh,
          drainOn, clearN, stallAge, sLast, sEx, sStamp, sOffer, sAttached, nc, lastNC>>
None == [heard |-> 999, sent |-> 0, d |-> 0]
Max(a, b) == IF a > b THEN a ELSE b
MaxSet(S) == IF S = {} THEN 0 ELSE CHOOSE x \in S : \A y \in S : x >= y

Init == /\ t = 0 /\ q = 0 /\ est = 0 /\ hist = [i \in 0..(Win - 1) |-> 0]
        /\ pend = {} /\ rStamp = None /\ rStale = None /\ rDrops = 999
        /\ cLast = 0 /\ cEx = 999 /\ cStamp = None /\ cStale = None
        /\ rLastP = 0 /\ rEx = 999 /\ cAttached = TRUE /\ rAttached = TRUE
        /\ u \in USet /\ phP \in 0..3 /\ phR \in 0..3
        /\ lag \in LSet /\ g \in GSet /\ qh = [i \in 0..4 |-> 0]
        /\ drainOn = FALSE /\ clearN = 0 /\ stallAge = 99
        /\ sLast = 0 /\ sEx = 999 /\ sStamp = None /\ sOffer = [heard |-> 999, w |-> 0]
        /\ sAttached = TRUE /\ nc \in NCSet /\ lastNC = 0

Since(x) == IF x = 999 THEN 999 ELSE t - x
Fresh(st) == st.heard /= 999 /\ (t - st.sent) - st.d <= Life
StaleOK(sc) == sc.heard /= 999 /\ t - sc.heard <= Life /\ t - sc.sent <= ChunkCap

Tick ==
  /\ t < H
  /\ LET capped  == t < CapEnd
         media   == est <= Budget                    \* STALE reads the estimate
         wmax    == Max(est, MaxSet({hist[i] : i \in 0..(Win - 1)}))
         stalled == drainOn \/ stallAge < 8          \* G8: latched 2 s past detection
         stampP  == (t % 4 = phP) /\ (wmax > Budget \/ (SelfStamp /\ stalled))
         dDecl   == IF wmax > Budget THEN wmax ELSE Budget + 1
         sendC   == IF media THEN {[at |-> t + q, kind |-> "c", sent |-> t, d |-> 0]} ELSE {}
         sendS   == IF stampP THEN {[at |-> t + q, kind |-> "s", sent |-> t, d |-> dDecl]} ELSE {}
         \* to L2 (P's standby): base/audio while media goes and P is not
         \* stalled (stalled, standbys get nothing: alm.rs `Role::Standby =>
         \* self.uplink_stall`); offers (+ stamp) each period, or under the
         \* stall at the non-child interval unless SelfStamp keeps 1 s
         ivl     == IF stalled /\ ~SelfStamp THEN nc ELSE 4
         offS    == (t % 4 = phP) /\ (t - lastNC >= ivl \/ lastNC = 0)
         sendB   == IF media /\ ~stalled THEN {[at |-> t + q, kind |-> "b", sent |-> t, d |-> 0]} ELSE {}
         sendO   == IF offS THEN {[at |-> t + q, kind |-> "o", sent |-> t, d |-> est]} ELSE {}
         sendS2  == IF offS /\ stampP THEN {[at |-> t + q, kind |-> "s2", sent |-> t, d |-> dDecl]} ELSE {}
         pend1   == pend \cup sendC \cup sendS \cup sendB \cup sendO \cup sendS2
         arr     == {x \in pend1 : x.at = t}
         chunksA == {x \in arr : x.kind = "c"}
         stampsA == {x \in arr : x.kind = "s"}
         \* the queue: grows a tick while capped and media goes, drains otherwise
         q2      == IF capped THEN (IF media THEN q + g ELSE IF q > 0 THEN q - 1 ELSE 0)
                    ELSE (IF q > 4 THEN q - 4 ELSE 0)
         \* P's estimate: `lag` ticks behind while the queue grows (the send
         \* clock ages its oldest message from its send; the gauges sample),
         \* up to u ticks low while it drains
         qh2     == [i \in 0..4 |-> IF i = 0 THEN q2 ELSE qh[i - 1]]
         e2      == IF q2 >= q THEN qh2[lag] ELSE (IF q2 > u THEN q2 - u ELSE 0)
         \* the relay: every chunk from P counts for its view of P; a chunk
         \* more than Budget old end to end is dropped, else forwarded
         fresh   == {x \in chunksA : t - x.sent <= Budget}
         staleA  == {x \in chunksA : t - x.sent > Budget}
         newSt   == IF stampsA = {} THEN rStamp
                    ELSE LET s == CHOOSE x \in stampsA : TRUE
                         IN [heard |-> t, sent |-> s.sent, d |-> s.d]
         newSc   == IF staleA = {} THEN rStale
                    ELSE LET s == CHOOSE x \in staleA : \A y \in staleA : x.sent >= y.sent
                         IN [heard |-> t, sent |-> s.sent, d |-> 0]
         rl2     == IF chunksA /= {} THEN t ELSE rLastP
         \* the relay excuses P on P's own stamp (both rules read it)
         rExc    == Fresh(newSt) /\ newSt.d > Budget
         rEx2    == IF rExc THEN t ELSE rEx
         rSil    == t - Max(rl2, IF rEx2 = 999 THEN 0 ELSE rEx2)
         rFail   == rAttached /\ ~rExc /\ rSil >= SuspR
         rAlive  == rAttached /\ ~rFail                \* forwarding
         \* the relay's offer to its child, with what it forwards
         offerR  == rAlive /\ (t % 4 = phR)
         fwdSt   == offerR /\ newSt.heard /= 999 /\ t - newSt.heard <= Life
         \* a stale chunk counts once: only one newer than the child holds
         fwdSc   == offerR /\ newSc.heard /= 999 /\ Rule \in {"stale", "both"}
                    /\ (cStale.heard = 999 \/ newSc.sent > cStale.sent)
         cSt2    == IF fwdSt THEN [heard |-> t, sent |-> newSt.sent, d |-> newSt.d]
                    ELSE cStamp
         cSc2    == IF fwdSc THEN [heard |-> t, sent |-> newSc.sent, d |-> 0] ELSE cStale
         drops2  == IF staleA /= {} THEN t ELSE rDrops
         \* the child: chunks the relay forwarded (none from a liar)
         cl2     == IF fresh /= {} /\ rAlive /\ ~Liar THEN t ELSE cLast
         \* c1545: the relay's own advertised latency; a liar claims it always
         c15     == IF Liar THEN rAlive
                    ELSE (rAlive /\ drops2 /= 999 /\ t - drops2 <= Life)
         cExc    == CASE Rule = "c1545" -> c15
                      [] Rule = "e356"  -> rAlive /\ Fresh(cSt2) /\ cSt2.d > Budget
                      [] Rule = "stale" -> rAlive /\ StaleOK(cSc2)
                      [] OTHER          -> rAlive /\ ((Fresh(cSt2) /\ cSt2.d > Budget)
                                                      \/ StaleOK(cSc2))
         cEx2    == IF cExc THEN t ELSE cEx
         cSil    == t - Max(cl2, IF cEx2 = 999 THEN 0 ELSE cEx2)
         cFail   == cAttached /\ ~cExc /\ cSil >= SuspC
         \* L2's view of its standby P (depth 0)
         bA      == {x \in arr : x.kind = "b"}
         oA      == {x \in arr : x.kind = "o"}
         s2A     == {x \in arr : x.kind = "s2"}
         sl2     == IF bA /= {} THEN t ELSE sLast
         sSt2    == IF s2A = {} THEN sStamp
                    ELSE LET x == CHOOSE y \in s2A : TRUE IN [heard |-> t, sent |-> x.sent, d |-> x.d]
         sOf2    == IF oA = {} THEN sOffer
                    ELSE LET x == CHOOSE y \in oA : TRUE IN [heard |-> t, w |-> x.d]
         sExc    == IF Rule = "c1545" THEN sOf2.heard /= 999 /\ t - sOf2.heard <= Life /\ sOf2.w > Budget
                    ELSE Fresh(sSt2) /\ sSt2.d > Budget
         sEx2    == IF sExc THEN t ELSE sEx
         sSil    == t - Max(sl2, IF sEx2 = 999 THEN 0 ELSE sEx2)
         \* a standby is dropped at Down (selector.rs, keep a warm standby: Down),
         \* down_silence 5 s at depth 0
         sFail   == sAttached /\ ~sExc /\ sSil >= 20
         \* P's drain: enter at >= 400 ms, leave after < 200 ms for 1 s
         dOn2    == IF ~drainOn THEN est >= 2 ELSE ~(est < 1 /\ clearN >= 4)
         clr2    == IF drainOn /\ dOn2 /\ est < 1 THEN clearN + 1 ELSE 0
     IN /\ t' = t + 1 /\ q' = q2 /\ est' = e2
        /\ hist' = [i \in 0..(Win - 1) |-> IF i = 0 THEN est ELSE hist[i - 1]]
        /\ pend' = pend1 \ arr
        /\ rStamp' = newSt /\ rStale' = newSc /\ rDrops' = drops2
        /\ rLastP' = rl2 /\ rEx' = rEx2 /\ rAttached' = rAlive
        /\ cLast' = cl2 /\ cEx' = cEx2 /\ cStamp' = cSt2 /\ cStale' = cSc2
        /\ cAttached' = (cAttached /\ ~cFail)
        /\ qh' = qh2
        /\ drainOn' = dOn2 /\ clearN' = (IF clr2 > 4 THEN 4 ELSE clr2)
        /\ stallAge' = IF dOn2 THEN 0 ELSE IF stallAge < 99 THEN stallAge + 1 ELSE 99
        /\ sLast' = sl2 /\ sEx' = sEx2 /\ sStamp' = sSt2 /\ sOffer' = sOf2
        /\ sAttached' = (sAttached /\ ~sFail)
        /\ lastNC' = IF offS THEN t ELSE lastNC
        /\ UNCHANGED nc
        /\ UNCHANGED <<u, phP, phR, lag, g>>

Spec == Init /\ [][Tick]_vars

TypeOK == q \in Nat
\* The honest relay is never failed over while P's backlog drains, and the
\* relay keeps P.
ChildKeepsRelay == ~Liar => cAttached
RelayKeepsP == rAttached
\* A liar (forwards real stamps and stale chunks it heard, sends no media)
\* is failed over within down_silence (20 ticks) of P's queue clearing.
LiarBounded == (Liar /\ t >= CapEnd + 48 /\ q = 0) => ~cAttached
\* The moved listener keeps P as its standby (the come-back to P needs it).
StandbyKept == sAttached
=============================================================================
