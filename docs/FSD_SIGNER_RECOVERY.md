# FSD — Signer-Key Recovery under Hash-First Retention

**Status:** design, for CIRISEdge#552
**Supersedes:** three failed in-code attempts on PR #556 (see §3)

## 1. The problem

Under `Retention::HashFirst` a node converges the hash set for the directory
planes and does not fetch their bodies. A delivered row on any plane is then
refused **transiently** when its signer's `Key` body is absent, because persist's
shared ingest gate resolves the signer's registered pubkeys via
`lookup_public_key` before it verifies anything.

Ordinary anti-entropy cannot repair this. Hash-first is precisely the decision
*not* to fetch bodies, so the `Key` body never arrives on its own, the #544
backoff re-offers the row forever, and a row whose signer is unknown is
permanently unadmittable. When that row is a **revocation**, the result is a kill
order that never lands.

The node must therefore be able to ask a peer for one specific `Key` body,
**by identifier**, and receive it.

## 2. What is available

`PullMessage { kind, subject_key_id }` is the only verb that names a record by
identifier; every other read is content-hash-addressed, and a node cannot compute
the hash of a record it does not hold.

Its responder rule (`bridge::subject_holdings`) answers:

* a requester authenticated **as** the subject — the data-subject access path; and
* on the four unconditionally-`public` planes, a request for **the responding
  node's own record**, which is exactly what the `self_own` advertise projection
  already hands every peer.

A **third-party** subject is refused, and that refusal is load-bearing:
`subject_holdings_inner` performs an arbitrary lookup against the responder's
whole local directory, so answering it would turn a body-holding server into an
address-book oracle for records it never advertised.

**Consequence for this design:** the only fetchable signer is *the peer that
delivered the row*, asking for *its own* key. That is not a limitation of the
recovery mechanism; it is the entitlement boundary, and the mechanism must not
try to exceed it.

## 3. Why three previous attempts failed

All three failed on the same fact, stated here so a fourth does not repeat it:

> **An Initiator reads inbound messages only inside the drive loop, and the drive
> loop's first step (`drive_round_step(None)`) OPENS by sending a Summary.**

| attempt | shape | failure |
|---|---|---|
| 1 | send Pull, then `run_one_round` | Two exchanges outstanding. Both answer with a Summary and there is no request correlation, so the **scheduled** Summary could be consumed as the Pull's reply — putting the peer's whole Key page into `pending_bodies` and fetching every body on a node that had just chosen not to. |
| 2 | batch up to 32 Pulls per round | The on-demand exemption is a **round counter**, not a per-request ledger. The batch outran its own exemption and later replies were suppressed as ordinary hash-first traffic, after the names had already been dequeued. |
| 3 | send Pull, then `continue` the tick | Defers *receiving* rather than driving. The next tick's `run_one_round` sends its Summary **first** and then dequeues the stale Pull reply — the same overlap, one tick later. |

The lesson: the Pull's reply must be consumed by a loop that **did not also send a
Summary**.

## 4. Design

### D1 — A recovery exchange is a ROUND TYPE, not a message inserted into a round

`run_one_round` is exactly two things: an initiating step, then a
send-and-wait loop. Recovery reuses the second and omits the first.

```
run_one_round          = drive_exchange_to_completion(initiating_step)
run_one_recovery_round = send Pull; drive_exchange_to_completion(SendThenWait(∅))
```

`SendThenWait(∅)` sends nothing and waits, so the reply the loop consumes can only
be the Pull's. No new wire verb, no request ID, no protocol version event.

### D2 — Correlation by construction: one exchange outstanding per coordinator

Each `(peer, kind)` coordinator has one sequential scheduler task. A recovery
round **replaces** the ordinary round on its tick, so at no point are two
exchanges outstanding on one coordinator. This is what makes the absence of
request IDs safe, and it is the same property the rest of the protocol already
relies on — the session is a sequential per-peer state machine.

### D3 — A recovery round replaces its tick

Cost: one cadence tick per recovered key, and only on a tick where a name is
actually queued. Bounded by D4: at most one name per peer exists, so recovery
can displace at most one ordinary round per peer before it is done.

### D4 — Queue only what a Pull can satisfy: the delivering peer's own key

From §2, a third-party signer is not fetchable by identifier. Queueing one would
schedule a request guaranteed to return empty while consuming a recovery slot and
a tick.

This bounds the queue **at its root**, which matters for more than tidiness: a
peer can enqueue exactly one name — its own — so an attacker delivering rows that
name thousands of unique nonexistent signers has nothing to enqueue, and cannot
crowd out another peer's revocation recovery. Policing the queue after the fact
(caps, fair-share eviction) left that vector open; this closes it.

### D5 — An expectation is REQUEST state, not ROUND state

`pending_bodies` is the set of hashes this node explicitly asked for, and it is
the only thing that lets those bytes past the hash-first gate. Today
`Session::reset` clears the whole set once `pull_exempt_rounds` reaches zero, so:

* a `start_fetch` expectation, which sets no exemption, is discarded by the very
  next reset; and
* an expectation whose body arrived and was refused **transiently** is discarded
  even though the node still wants it.

Each expectation therefore carries its **own** time-to-live in rounds, decremented
on reset and dropped at zero. An expectation outlives the round that created it,
and a transient refusal refreshes it rather than consuming it.

### D6 — Failure is silent-safe, never silent-lossy

A recovery round that times out, is refused, or returns an empty Summary leaves
the row transiently refused and **visible**. The name is not re-queued by the
recovery path itself: the row that named it re-notes it on its next offer, so the
retry rides #544's existing backoff instead of a second, unbounded timer.

## 5. Naming

Every name states which of the two round types it belongs to.

| name | meaning |
|---|---|
| `drive_exchange_to_completion` | the shared send-and-wait loop, given its first step |
| `run_one_round` | anti-entropy: initiate, then drive |
| `run_one_recovery_round` | recovery: send the Pull, then drive **without initiating** |
| `ReplicationCoordinator::send_recovery_pull` | take this peer's queued name and Pull it; `None` when nothing is queued |
| `StateProvider::take_missing_signer_for(peer)` | take the one name `peer` can answer for |
| `Session::expect_body_for_rounds` | record an expectation with its own TTL |
| `RoundEvent::RecoveryCompleted` | a recovery round finished, distinct on the instrument |

## 6. Invariants (each has a test)

1. **A recovery round sends no Summary.** Otherwise the reply is ambiguous again.
2. **At most one exchange outstanding per coordinator.**
3. **Only a peer's own key is ever queued** — a third-party signer is never enqueued.
4. **An expectation survives a round reset** until its own TTL expires.
5. **A transiently-refused requested body stays expected.**
6. **A third-party subject Pull is refused by the responder** (the anti-oracle rule).
7. **Recovery never runs under `Retention::Bodies`** — there the Key body replicates on its own.

## 7. Out of scope

* **Third-party signer resolution.** Needs a separately authorized, rate-limited
  resolver; the entitlement question is not answered by this design.
* **Contact resolution of an unheld third-party identifier.** Same reason;
  `contact::request_key_body` returns `false` and says so rather than promising a
  fetch that cannot happen.
* **A production path from `KnownHashes` to `Fetch`.** The holder map is recorded
  but no runtime consumer selects a holder and issues a point fetch yet.
