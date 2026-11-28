----------------------------- MODULE ShedMovers -----------------------------
(* R34 SHED-MOVERS (45.3): does P's over-commit shed pick the relay its late
   children just moved to?

   Code (CIRISEdge-453 release/45.3.0, b5097907):
     alm.rs:2773  movers read P's direct children FROM OFFERS
                  (direct_children_by_offer: a member whose fresh offer of
                  P's stream shows P as parent at depth 1 — only a relay that
                  is relay-capable, forwarding and not stalled offers it)
     alm.rs:2783-2792, rxmove.rs:193-217  a mover is any but the lowest-
                  ranked of those; it may move only to the lowest-ranked one
                  (the spared) or to a member not among them
     admission.rs:1325-1372  P sheds over its LEDGER: standbys first, then
                  primaries by the same hash rank, highest first; a root never
                  sheds its last primary
   Members X, R, L1, L2 are P's direct primaries, each with a rank (a
   permutation). Vis[m]: m's offers show P as its parent (it relays). The
   movers are the visible non-lowest; they move to the lowest visible (the
   spared). While their unsubscribes are in flight P's ledger may still hold
   them (Gone: they have left it). P sheds down to K primaries.            *)
EXTENDS Naturals, FiniteSets

CONSTANTS Rule   \* "asbuilt" | "keepSpared" | "moversFirst" | "keepChosen"

Members == {"X", "R", "L1", "L2"}

VARIABLES rank, vis, gone, k, done, shed, target, movers

vars == <<rank, vis, gone, k, done, shed, target, movers>>

Perms == {f \in [Members -> 1..4] : \A a, b \in Members : a /= b => f[a] /= f[b]}
Lowest(S) == CHOOSE m \in S : \A n \in S : rank[m] <= rank[n]
Highest(S) == CHOOSE m \in S : \A n \in S : rank[m] >= rank[n]

Init == /\ rank \in Perms
        /\ vis \in [Members -> BOOLEAN]
        /\ k \in {1, 2}
        /\ done = FALSE /\ shed = {}
        /\ LET dirs == {m \in Members : vis[m]}
           IN /\ Cardinality(dirs) >= 2
              /\ target = Lowest(dirs)
              /\ movers = dirs \ {target}
        /\ gone \in SUBSET movers   \* movers whose unsubscribe P has applied

\* P's over-commit shed, once: down to k primaries, never its last.
Shed ==
  /\ ~done
  /\ LET ledger == Members \ gone
         \* the order P sheds in, as a sequence of choices
         RECURSIVE Go(_)
         Go(L) == IF Cardinality(L) <= k \/ Cardinality(L) <= 1 THEN Members \ L
                  ELSE LET pool == CASE Rule = "asbuilt"     -> L
                                     [] Rule = "moversFirst" ->
                                          IF L \cap movers /= {} THEN L \cap movers ELSE L
                                     [] Rule = "keepSpared"  ->
                                          \* the spared (lowest VISIBLE primary) goes last
                                          IF L \ {Lowest({m \in L : vis[m]} \cup {target})} /= {}
                                          THEN L \ {Lowest({m \in L : vis[m]} \cup {target})}
                                          ELSE L
                                     [] OTHER                -> \* keepChosen
                                          IF L \ {target} /= {} THEN L \ {target} ELSE L
                       IN Go(L \ {Highest(pool)})
     IN shed' = Go(ledger) \ gone
  /\ done' = TRUE
  /\ UNCHANGED <<rank, vis, gone, k, target, movers>>

Spec == Init /\ [][Shed]_vars

TypeOK == done \in BOOLEAN
\* The relay the movers chose is never shed.
MoversParented == done => target \notin shed
=============================================================================
