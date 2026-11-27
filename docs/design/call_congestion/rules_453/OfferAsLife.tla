---------------------------- MODULE OfferAsLife ----------------------------
(* Row R29 OFFER-AS-LIFE (45.3): a child does not charge a parent's media
   silence while that parent's offer is fresh (< OFFER_IS_LIFE_MS), forwarding,
   and says its upstream is later than STALE_UPSTREAM_MS.

   One publisher P, one relay R (the parent under test), one child C.
   One tick = 250 ms (the selector's WATCH_TICK). Every timer is an AGE in
   ticks, capped at Cap, so the state space is finite without a clock.

   Code (CIRISEdge work/45.3):
     selector.rs:1342-1344  excused = offer.forwarding
                              /\ offer.upstream_latency_ms > STALE_UPSTREAM_MS
                              /\ now - offer_at_ms <= OFFER_IS_LIFE_MS
     selector.rs:1345-1347  excused_at_ms := now while excused and subscribed
     selector.rs:1361-1364  silent = 0 while excused, else counted from
                            max(last chunk, subscribed, excused_at)
     selector.rs:1376-1389  before a subscription's first chunk, the offer's
                            upstream_latency_ms (<= down_silence) is owed too
     selector.rs:1390       silent * 2 / (2 + depth)
     peer_state.rs:127-133  >= suspect (1.5 s) Suspected, >= down (5 s) Down
     selector.rs:1500-1503  a Suspected or Down primary is failed over
     selector.rs:1828,1831  OFFER_IS_LIFE_MS = 2500, STALE_UPSTREAM_MS = 800

   Rule = "current"      : the code above (the relay's own claim).
   Rule = "signed_pubage": the excuse needs the publisher's signed backlog
                           stamp, relayed unaltered, late (b > budget) and no
                           older than Life by the publisher's clock.
   Rule = "signed"       : as signed_pubage, but the stamp's age is judged
                           NET of the backlog it declares (age - b <= Life):
                           a stamp that waited in the very queue it reports
                           is not stale for having waited there.
   GraceSigned           : the first-chunk grace (selector.rs:1382-1389) is
                           taken from the stamp's backlog, not the relay's
                           unsigned upstream_latency_ms.                    *)
EXTENDS Naturals

CONSTANTS
    Kind,          \* "honest" | "liar" | "blackhole" | "gone"
    Rule,          \* "current" | "signed_pubage" | "signed"
    GraceSigned,   \* BOOLEAN
    PubLate,       \* BOOLEAN: may the publisher's backlog pass the budget at all
    LoseOne,       \* BOOLEAN: may an offer be lost (never two in a row)
    OfferEvery,    \* 4   (1 s)
    Life,          \* 10  (OFFER_IS_LIFE_MS 2.5 s)
    StaleB,        \* 4   (backlog >= 1 s is past the 800 ms budget)
    BMax,          \* the publisher's largest backlog, ticks
    Depth,         \* the relay's offered depth (1 = child of the publisher)
    Suspect,       \* 6   (suspect_silence_ms 1.5 s)
    DownSilence,   \* 20  (down_silence_ms 5 s)
    Cap            \* age cap

VARIABLES
    phase,      \* tick mod OfferEvery; offers and stamps move at phase 0
    b,          \* the publisher's uplink backlog (send clock), ticks
    relStAge,   \* the stamp the relay holds: its age (Cap = none) ...
    relStB,     \* ... and the backlog it declares
    gone,       \* Kind = "gone": the relay's offers and media have stopped
    goneAge,    \* ticks since they stopped
    lostLast,   \* the previous offer was lost
    offAge,     \* ticks since the child's last offer from R (Cap = none)
    offLate,    \* that offer's claim: upstream_latency_ms > 800
    offStAge,   \* the stamp that offer carried: its age now (Cap = none) ...
    offStB,     \* ... and its declared backlog
    rxAge,      \* ticks since the last chunk (or the subscription)
    everRx,     \* a chunk has arrived since the subscription
    exAge,      \* ticks since the child last excused R (Cap = never)
    calmAge,    \* ticks since the publisher's backlog was last past budget
                \* (or since the subscription)
    attached,   \* R is still C's primary
    failRx,     \* at failover: rxAge, exAge (Cap+1 = no failover yet)
    failEx

vars == <<phase, b, relStAge, relStB, gone, goneAge, lostLast, offAge, offLate,
          offStAge, offStB, rxAge, everRx, exAge, calmAge, attached, failRx, failEx>>

Min(x, y) == IF x < y THEN x ELSE y
Inc(x) == Min(x + 1, Cap)
Ages == 0..Cap
\* silence ticks at which the child goes Suspected: s * 2 \div (2 + D) >= Suspect
SuspTicks == (Suspect * (2 + Depth) + 1) \div 2

TypeOK ==
    /\ phase \in 0..(OfferEvery - 1) /\ b \in 0..BMax
    /\ relStAge \in Ages /\ relStB \in 0..BMax
    /\ gone \in BOOLEAN /\ goneAge \in Ages /\ lostLast \in BOOLEAN
    /\ offAge \in Ages /\ offLate \in BOOLEAN /\ offStAge \in Ages /\ offStB \in 0..BMax
    /\ rxAge \in Ages /\ everRx \in BOOLEAN /\ exAge \in Ages /\ calmAge \in Ages
    /\ attached \in BOOLEAN /\ failRx \in 0..(Cap + 1) /\ failEx \in 0..(Cap + 1)

\* The child has just subscribed to R (R is admitted, its first offer seen,
\* nothing delivered yet); the publisher is on time.
Init ==
    /\ phase = 0 /\ b = 0
    /\ relStAge = 0 /\ relStB = 0
    /\ gone = FALSE /\ goneAge = 0 /\ lostLast = FALSE
    /\ offAge = 0 /\ offLate = (Kind = "liar") /\ offStAge = 0 /\ offStB = 0
    /\ rxAge = 0 /\ everRx = FALSE /\ exAge = Cap /\ calmAge = 0
    /\ attached = TRUE /\ failRx = Cap + 1 /\ failEx = Cap + 1

\* The relay's offer content. An honest relay's advertised upstream latency
\* is >= its parent's + RTT/2 (selector.rs:429) and >= its recent stale drops
\* (alm.rs:1733-1750): late exactly when the publisher's latest word is late.
\* The liar always claims late; the black hole always claims on time.
Claim(sb) == CASE Kind = "liar"      -> TRUE
               [] Kind = "blackhole" -> FALSE
               [] OTHER              -> sb >= StaleB

\* Is R excused this tick, given the child's view after this tick's offer.
StampOK(sa, sb) ==
    /\ sa < Cap /\ sb >= StaleB
    /\ CASE Rule = "signed_pubage" -> sa <= Life
         [] Rule = "signed"        -> sa <= Life + sb
         [] OTHER                  -> TRUE
Excused(oa, ol, sa, sb) ==
    /\ oa <= Life                      \* the offer is fresh (forwarding: always)
    /\ IF Rule = "current" THEN ol ELSE StampOK(sa, sb)

\* The first-chunk grace, ticks: the offer's upstream latency, <= down_silence.
\* The liar names any figure it likes, so it names down_silence.
Grace(ol, sb, ev) ==
    IF ev THEN 0
    ELSE IF GraceSigned /\ Rule /= "current"
         THEN Min(sb, DownSilence)
         ELSE CASE Kind = "liar"      -> DownSilence
                [] Kind = "blackhole" -> 0
                [] OTHER              -> Min(sb, DownSilence)

Tick ==
    /\ attached
    /\ \E nb \in {x \in 0..BMax : x + 1 >= b /\ x <= b + 1 /\ (PubLate \/ x < StaleB)},
          ng \in IF Kind = "gone" /\ ~gone THEN BOOLEAN ELSE {gone},
          lose \in IF LoseOne /\ ~lostLast /\ phase = 0 THEN BOOLEAN ELSE {FALSE} :
        LET at0     == phase = 0
            \* the relay's stamp: aged, then this period's arrives (it waited
            \* nb ticks in the publisher's uplink FIFO, so it is nb old). The
            \* liar keeps the freshest LATE stamp it ever saw and replays it.
            agedA   == Inc(relStAge)
            keepNew == at0 /\ (Kind /= "liar" \/ nb >= StaleB)
            rA      == IF keepNew THEN nb ELSE agedA
            rB      == IF keepNew THEN nb ELSE relStB
            \* media: a publisher past the budget sends none (STALE); an
            \* honest relay forwards what is fresh; liar and black hole none.
            chunk   == /\ Kind \in {"honest", "gone"} /\ ~ng /\ nb < StaleB
            offered == at0 /\ ~ng /\ ~lose
            oA      == IF offered THEN 0 ELSE Inc(offAge)
            oL      == IF offered THEN Claim(rB) ELSE offLate
            sA      == IF offered THEN rA ELSE Inc(offStAge)
            sB      == IF offered THEN rB ELSE offStB
            ex      == Excused(oA, oL, sA, sB)
            rx      == IF chunk THEN 0 ELSE Inc(rxAge)
            ev      == everRx \/ chunk
            exA     == IF ex THEN 0 ELSE Inc(exAge)
            since   == Min(rx, exA)
            g       == Grace(oL, sB, ev)
            fail    == ~ex /\ since >= g /\ (since - g) >= SuspTicks
        IN /\ phase' = (phase + 1) % OfferEvery
           /\ b' = nb
           /\ relStAge' = rA /\ relStB' = rB
           /\ gone' = ng
           /\ goneAge' = IF ng THEN (IF gone THEN Inc(goneAge) ELSE 0) ELSE 0
           /\ lostLast' = IF at0 THEN lose ELSE lostLast
           /\ offAge' = oA /\ offLate' = oL /\ offStAge' = sA /\ offStB' = sB
           /\ rxAge' = rx /\ everRx' = ev /\ exAge' = exA
           /\ calmAge' = IF nb >= StaleB THEN 0 ELSE Inc(calmAge)
           /\ attached' = ~fail
           /\ failRx' = IF fail THEN rx ELSE failRx
           /\ failEx' = IF fail THEN exA ELSE failEx

Spec == Init /\ [][Tick]_vars /\ WF_vars(Tick)

\* ---------------------------------------------------------------- properties
\* The liar's hold. Liveness: the liar is eventually failed over. (Run with
\* PubLate = FALSE: the publisher is never late, so no excuse is earned.)
LiarFailsOver == <>(~attached)
\* Safety: a liar is held at most DownSilence ticks past its last excuse, and,
\* when the publisher never ran late, at most DownSilence ticks in all.
LiarWithinDown == attached => exAge < DownSilence \/ exAge = Cap
LiarHeldTotal  == attached => rxAge < DownSilence
\* And measured against the publisher: held at most Life + DownSilence
\* ticks after the publisher's backlog was last past the budget (or after
\* the subscription). The last late stamp reached the relay then, at most
\* BMax old, and passes `signed` for Life more ticks.
LiarAfterCalm  == attached => calmAge <= Life + DownSilence

\* Honest cases.
NeverFailsOver  == attached                    \* honest: late offers + silence
OffersStopBound == (gone /\ attached) => goneAge <= Life + DownSilence
\* An on-time black hole (the publisher on time for Life + DownSilence) is
\* failed over within DownSilence. (Under `signed` a black hole holding a
\* real late stamp is excused like an honest relay: nothing fresh exists.)
BlackHoleBound  == attached => (rxAge < DownSilence \/ calmAge <= Life + DownSilence)

\* Excused time is nobody's silence: no failover sooner than SuspTicks of
\* silence counted after the excuse (and after the last chunk).
NotChargedAtOnce == failEx <= Cap => Min(failRx, failEx) >= SuspTicks
=============================================================================
