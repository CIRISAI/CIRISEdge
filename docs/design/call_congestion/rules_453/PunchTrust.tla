----------------------------- MODULE PunchTrust -----------------------------
(* Row R30 PUNCH-TRUST (45.3, edge policy layer): one address predicate
     P(s) = s not anonymous /\ s sees standing for the other side
   (a shared room or a named contact), read on BOTH sides for every
   proposal, every answer and each link's escalation; re-read on every
   standing change and on a 5 s cadence; a link whose peer no longer passes
   is retired to its relayed path, and leviculum's background retry runs
   only while this node proposes and is not anonymous.

   Leviculum is abstract here (its own model, DirectLinkPunch.tla, owns the
   punch): a gate value per side read at the punch's planning points, a
   background-retry table, retire_direct_link.

   Code = "fixed" (CIRISEdge 3d0c95c, work/45.3-nat):
     reticulum.rs:15932-15944  may_show_address: may_reveal_address() and
                               direct_standing (room or contact)
     reticulum.rs:15860-15879  dispatch_proposal: refused unless P; sets the
                               link's escalation to true before the session
     reticulum.rs:20751-20787  the answer: not anonymous, standing,
                               accepts_direct; escalation := the answer
     direct_path.rs:490,658    IdentifiedOnly asks the host, under the same
                               predicate
     reticulum.rs:10907-10979  reconcile_direct_standing: per link, gate :=
                               P when changed; not P and direct: retire; a
                               loss (gate was true) or a change of want
                               (proposes and not anonymous) toggles the
                               retry off (and back on if wanted)
     reticulum.rs:12154        DIRECT_STANDING_RECHECK = 5 s
     reticulum.rs:12714-12726  the re-read: on notify_standing, the 5 s tick,
                               the scope table's generation
     reticulum.rs:8972-8976, 28864, 28876; direct_path.rs:1553,1621
                               notify_standing callers: onion_refresh (the
                               host's tier switch, device state), scoped
                               destination install / retire, contacts
     leviculum direct_link.rs:608-616  set_direct_link_retry(false): every
                               retry's due time cleared, the ENTRIES kept
     leviculum direct_link.rs:684-705  a failed session re-arms its entry
                               unless retry is off
     leviculum direct_link.rs:1519-1540  retire: entry removed
   Code = "asbuilt" (6392b0a): no reconcile, no per-link escalation (the
     default rule, leviculum direct_link.rs:580-596: the initiator always
     escalates; under IdentifiedOnly the responder never does; under
     AskHost the responder does once it accepted); IdentifiedOnly accepts any
     identified peer (direct_path.rs:630); retry on iff proposing, for ever
     (reticulum.rs:4269-4270); no retire on a standing loss.

   One step of Tick = 1 s. A proposes (the link's initiator), B answers.
   SilentTier: A's Anonymous Tier may switch on WITHOUT a notify (its
   availability follows its relays' liveness, onion/runtime.rs:185-187);
   only the 5 s cadence sees it.                                           *)
EXTENDS Naturals

CONSTANTS Code, Accept,      \* "fixed"|"asbuilt"; "room"|"identified"
          Contacts,          \* contacts may be named (one-way) at all
          Anon,              \* A's tier may switch on at all
          SilentTier,        \* ... without a notify
          DirectNotify,      \* proposed fix: a link going direct is a standing event
          FailNotify,        \* proposed fix: DirectLinkFailed re-runs the reconcile,
                             \* and a non-passing link's retry is cleared every
                             \* pass (level-triggered), not only on the loss
          TierNotify,        \* proposed fix: every may_reveal_address change notifies
          Period, Cap

VARIABLES room, conA, conB, anonA,       \* the truth each side reads
          seenA, seenB,                  \* what each side's reconcile last read: P
          notA, notB, phase,             \* pending notifies; the 5 s cadence
          gateA, gateB,                  \* the escalation leviculum holds per side
          retryOff, retry,               \* A's leviculum: "none"|"idle"|"armed"|"ready"
          session, direct,               \* A->B: "none"|"run"; on the direct path
          lossAge,                       \* ticks since P(A) /\ P(B) last held
          ev,                            \* the last step's event, for the properties
          recA, recB                     \* re-read in this second's cadence slot

vars == <<room, conA, conB, anonA, seenA, seenB, notA, notB, phase, gateA, gateB,
          retryOff, retry, session, direct, lossAge, ev, recA, recB>>

PA == ~anonA /\ (room \/ conA)           \* A's predicate for B
PB == room \/ conB                       \* B's predicate for A (B never anonymous here)
Both == PA /\ PB
Inc(x) == IF x < Cap THEN x + 1 ELSE x
Fixed == Code = "fixed"
\* What B answers a proposal with.
BAccepts == IF Fixed THEN PB
            ELSE IF Accept = "identified" THEN TRUE ELSE PB
\* The as-built default gate (no host decision).
DefGateA == TRUE
DefGateB == Accept = "room"              \* AskHost: the responder, once it accepted

Init == /\ room = TRUE /\ conA = FALSE /\ conB = FALSE /\ anonA = FALSE
        /\ seenA = TRUE /\ seenB = TRUE /\ notA = FALSE /\ notB = FALSE /\ phase = 0
        /\ gateA = IF Fixed THEN TRUE ELSE DefGateA
        /\ gateB = IF Fixed THEN TRUE ELSE DefGateB
        /\ retryOff = FALSE /\ retry = "none" /\ session = "none" /\ direct = FALSE
        /\ lossAge = 0 /\ ev = "none" /\ recA = TRUE /\ recB = TRUE

Keep == UNCHANGED <<seenA, seenB, gateA, gateB, retryOff, retry, session, direct, phase, recA, recB>>

\* ---- the environment
LeaveRoom == /\ room /\ room' = FALSE /\ notA' = Fixed /\ notB' = Fixed
             /\ UNCHANGED <<conA, conB, anonA>> /\ Keep
JoinRoom  == /\ ~room /\ room' = TRUE /\ notA' = Fixed /\ notB' = Fixed
             /\ UNCHANGED <<conA, conB, anonA>> /\ Keep
FlipConA  == /\ Contacts /\ conA' = ~conA /\ notA' = Fixed /\ UNCHANGED <<notB, room, conB, anonA>> /\ Keep
FlipConB  == /\ Contacts /\ conB' = ~conB /\ notB' = Fixed /\ UNCHANGED <<notA, room, conA, anonA>> /\ Keep
FlipAnon  == /\ Anon
             /\ \E silent \in (IF SilentTier THEN BOOLEAN ELSE {FALSE}) :
                  /\ anonA' = ~anonA
                  /\ notA' = (Fixed /\ (notA \/ ~silent \/ TierNotify))
             /\ UNCHANGED <<notB, room, conA, conB>> /\ Keep
Env == (LeaveRoom \/ JoinRoom \/ FlipConA \/ FlipConB \/ FlipAnon)
       /\ lossAge' = (IF Both' THEN 0 ELSE lossAge) /\ ev' = "env"

\* ---- A proposes (edge's own call; its callers and dispatch read P)
Propose ==
    /\ session = "none" /\ ~direct /\ PA
    /\ session' = "run" /\ retry' = "idle"
    /\ gateA' = IF Fixed THEN TRUE ELSE gateA
    /\ ev' = "propose"
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, seenB, notA, notB, phase, gateB,
                   retryOff, direct, lossAge, recA, recB>>

\* ---- leviculum's background retry fires (edge is not asked)
RetryFires ==
    /\ retry = "ready" /\ ~retryOff /\ session = "none" /\ ~direct
    /\ session' = "run" /\ retry' = "idle"
    /\ ev' = "retry"
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, seenB, notA, notB, phase, gateA, gateB,
                   retryOff, direct, lossAge, recA, recB>>

\* ---- the punch, at a planning point: escalates when A's gate says so
Escalate ==
    /\ session = "run" /\ gateA
    /\ ev' = "escalate"
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, seenB, notA, notB, phase, gateA, gateB,
                   retryOff, retry, session, direct, lossAge, recA, recB>>
\* the session ends: direct when B accepts (B answers at the request)
Succeed ==
    /\ session = "run" /\ BAccepts
    /\ session' = "none" /\ direct' = TRUE
    /\ gateB' = IF Fixed THEN TRUE ELSE gateB      \* B's answer sets its gate
    /\ retry' = IF retry = "none" THEN "none" ELSE "idle"
    /\ ev' = "direct"
    \* 3d0c95c: going direct is not among the standing events
    \* (reticulum.rs:12856-12868: LinkEstablished / Identified / Closed)
    /\ notA' = (notA \/ (Fixed /\ DirectNotify))
    /\ notB' = (notB \/ (Fixed /\ DirectNotify))
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, seenB, phase, gateA,
                   retryOff, lossAge, recA, recB>>
Fail ==
    /\ session = "run"
    /\ session' = "none"
    /\ gateB' = IF Fixed /\ ~BAccepts THEN FALSE ELSE gateB
    /\ retry' = IF ~retryOff /\ retry /= "none" THEN "armed" ELSE retry
    /\ ev' = "fail"
    /\ notA' = (notA \/ (Fixed /\ FailNotify))
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, seenB, notB, phase, gateA,
                   retryOff, direct, lossAge, recA, recB>>

\* ---- the re-read (fixed only), per side: on a notify or the 5 s cadence
ReconcileA ==
    /\ Fixed /\ (notA \/ (phase = 0 /\ ~recA))
    /\ recA' = TRUE
    /\ LET lost == gateA /\ ~PA
           want == ~anonA                         \* proposes /\ not anonymous
           tog  == lost \/ (retryOff = want)
                   \/ (FailNotify /\ ~PA /\ retry \in {"armed", "ready"})
       IN /\ gateA' = PA /\ seenA' = PA /\ notA' = FALSE
          /\ direct' = (direct /\ PA)
          /\ retry' = CASE direct /\ ~PA -> "none"          \* retired: entry removed
                        [] tog /\ retry \in {"armed", "ready"} -> "idle"
                        [] OTHER -> retry
          /\ retryOff' = IF tog THEN ~want ELSE retryOff
    /\ ev' = "reconcileA"
    /\ UNCHANGED <<room, conA, conB, anonA, seenB, notB, phase, gateB, session, lossAge, recB>>
ReconcileB ==
    /\ Fixed /\ (notB \/ (phase = 0 /\ ~recB))
    /\ recB' = TRUE
    /\ gateB' = PB /\ seenB' = PB /\ notB' = FALSE
    /\ direct' = (direct /\ PB)
    /\ ev' = "reconcileB"
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, notA, phase, gateA, retryOff, retry,
                   session, lossAge, recA>>

\* ---- time: one second; a due retry becomes ready. The event loop serves a
\* notify, and the cadence's slot, before the second ends.
Tick ==
    /\ Fixed => (~notA /\ ~notB /\ recA /\ recB)
    /\ phase' = (phase + 1) % Period
    /\ recA' = (phase' /= 0) /\ recB' = (phase' /= 0)
    /\ retry' = IF retry = "armed" THEN "ready" ELSE retry
    /\ lossAge' = IF Both THEN 0 ELSE Inc(lossAge)
    /\ ev' = "tick"
    /\ UNCHANGED <<room, conA, conB, anonA, seenA, seenB, notA, notB, gateA, gateB,
                   retryOff, session, direct>>

Next == Env \/ Propose \/ RetryFires \/ Escalate \/ Succeed \/ Fail
        \/ ReconcileA \/ ReconcileB \/ Tick
Spec == Init /\ [][Next]_vars

TypeOK == retry \in {"none", "idle", "armed", "ready"} /\ lossAge \in 0..Cap

\* ---- properties
\* The gates are equal after a re-read: both sides re-read since the last
\* change (no notify pending) and the predicate is the same on both.
GatesEqual == (Fixed /\ ~notA /\ ~notB /\ seenA = PA /\ seenB = PB /\ PA = PB)
                  => gateA = gateB
\* Stronger, the shape of the requirement: whenever both re-read, equal.
GatesEqualAlways == (~notA /\ ~notB /\ (~Fixed \/ (seenA = PA /\ seenB = PB)))
                        => gateA = gateB
\* No direct path outlives one re-read period past the loss of standing.
DirectBound == direct => (Both \/ lossAge <= Period)
\* ... settled: excusing a notify the event loop has not served yet.
DirectSettled == direct => (Both \/ lossAge <= Period \/ notA \/ notB)
\* No escalation while P(A) is false.
NoEscalationWhileFalse == ev = "escalate" => PA
\* No proposal (edge's or leviculum's retry) while A is anonymous.
NoProposalWhileAnonymous == ev \in {"propose", "retry"} => ~anonA
\* Leviculum's background retry stops once P(A) is false.
RetryStops == ev = "retry" => PA
\* The same three, SETTLED: excusing only the race between a change and the
\* event loop serving its notify (leviculum's tick runs in its own task, so
\* that window exists whatever edge does). What fails here is structural.
EscalationSettled == ev = "escalate" => (PA \/ notA)
ProposalSettled   == ev \in {"propose", "retry"} => (~anonA \/ notA)
RetrySettled      == ev = "retry" => (PA \/ notA)
=============================================================================
