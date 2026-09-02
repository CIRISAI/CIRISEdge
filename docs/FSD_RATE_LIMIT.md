# FSD — One Rate Limiter

**Status:** design, for the DRY consolidation of every keyed limiter in edge.
**Supersedes:** three independent implementations (`log_throttle::LogThrottle`,
`invite_gate::InviteGate`, `replication::refusal_backoff::RefusalBackoff`) plus
two hand-rolled bounded maps (`KnownHashes`, the missing-signer queue).

## 1. Why one module

Five places in edge answer the same question — *may this keyed thing proceed
right now?* — and each answered it differently. The divergence was not
cosmetic; every one of them shipped a bug the others had already solved:

| implementation | bug it shipped | already solved in |
|---|---|---|
| `KnownHashes` | unbounded until capped; then evicted the *quiet* peer's entries under flood | — (fixed by fair eviction) |
| missing-signer queue | flat cap let one peer starve every other peer's recovery | `KnownHashes`, one commit earlier |
| `InviteGate` | unbounded map under identity rotation; then O(cap) scan per rejected invite | `LogThrottle` (bounded from the start) |
| `RefusalBackoff` | — (the reference implementation for backoff) | |
| `LogThrottle` | — (the reference implementation for bounded keys) | |

The lesson is the ordinary one: a limiter is mostly edge cases, and five copies
means fixing each edge case five times, late, in production. One module, one
set of edge cases, one place to fix them.

## 2. The superset

Every existing limiter is this module with different settings:

| caller | key | quota | window | classes | backoff |
|---|---|---|---|---|---|
| log throttle | log-site + subject | N per window | fixed | — | no |
| invite gate | sender fedID | 1 stranger / 8 contact | 24 h | stranger, contact | no |
| refusal backoff | (kind, envelope hash) | 1 | grows per consecutive refusal | transient, terminal | yes |
| **identifier lookup** (new) | requesting peer | N per window | fixed | — | optional |

So the superset is: **a keyed, bounded, clock-injected limiter whose quota and
window are chosen per key CLASS, with optional exponential backoff on
consecutive denial.**

### D1 — The clock is the caller's

Every method takes `now`. The module never reads a clock, which is what makes
abuse behaviour testable at all: a 24-hour refill and a 6-hour backoff cap
cannot be exercised against a real clock. This is already true of
`InviteGate::admit` and `RefusalBackoff::record_at`; it becomes universal.

### D2 — Bounded keys, with FAIR eviction

Every key space here is attacker-chosen: sender IDs rotate, envelope hashes are
manufactured, peer IDs are cheap. A cap alone is not enough — the question is
*whose* entry is dropped when the cap is reached, and the naive answers are all
wrong:

* **Evict the oldest** → the flooder's fresh entries survive, the honest quiet
  peer's are dropped. Exactly the `KnownHashes` bug.
* **Refuse the newest** → the flooder, already resident, keeps its budget and
  the honest newcomer is locked out. Exactly the missing-signer bug.

The rule that survives both: **charge eviction to the largest source.** Under
contention no single source holds much more than its share; uncontended, one
source may use the whole map. A source may never evict on its own behalf.

Before evicting anything, **release the free entries**: a key whose window has
fully refilled is state-equivalent to a key never seen, so forgetting it
changes no verdict. That release must be **O(1)-gated** — track the earliest
possible release time and skip the scan when nothing can yet expire, or an
attacker forces a full scan per rejected request and the memory bound becomes a
CPU one. (The `InviteGate` bug, twice.)

### D3 — Never tell the limited party when to retry

A `Deny` carries a reason **for the operator**. It does not carry a retry-after,
and callers must not derive one for the limited party. Telling a spammer the
refill interval is telling them the optimal send rate. This is `InviteGate`'s
existing rule, promoted to the module so no future caller re-derives it wrongly.

Backoff windows are likewise internal: the limiter knows when it will next
allow, and does not say.

### D4 — Classes carry the tier, promotion is explicit

A key's class selects its quota. `InviteGate`'s stranger/contact split is the
model: an established contact must not be throttled like a stranger, because
throttling replies is how an anti-spam control breaks the conversations it
exists to protect.

Promotion is a separate, explicit call and is **permanent for the key's
lifetime in the map**. It is also the one piece of state that cannot be
reconstructed from traffic, so a promoted key is **never evicted** by D2 — the
map may drop what it can rebuild, never what it cannot.

### D5 — Suppression is counted and surfaced

A denied event is not silently dropped: the count of denials since the last
allow rides on the next `Allow`. That is `LogThrottle`'s `suppressed_prev`, and
it generalises — a limiter that hides the flood it absorbed leaves an operator
unable to see the attack. A floor on log volume is right; a metric that
under-counts is a metric that lies.

### D6 — Advisory vs enforcing is the CALLER's decision

The module returns a verdict. Whether a denial drops the work, defers it, or
merely logs is the caller's, because the consequences differ: dropping a log
line is free, dropping a federation record is data loss. Nothing in this module
may drop anything itself.

## 3. What this must NOT become

* **Not an admission gate.** Refusing to *admit* correctly-signed federation
  state on a rate heuristic is the silent-state-withholding class
  (CIRISEdge#425). Rate limiting belongs on *serving*, *presenting*, and
  *asking* — never on carriage of state already received.
* **Not a privacy control.** Limiting identifier lookups raises the cost of
  bulk harvesting on a plane that is public by construction. It is friction,
  and it must never be described as confidentiality (CC 1.13.3.1's bounding
  non-goals).

## 4. The abuse cases this must handle, each with a test

These are the reasons the module exists. Every row is a test in
`rate_limit::tests`, named for the scenario.

| # | scenario | required behaviour |
|---|---|---|
| A1 | one key floods | denied after its quota; other keys unaffected |
| A2 | **identity rotation** — every request a fresh key | map stays bounded; honest keys keep their budget |
| A3 | rotation *inside* the window, nothing releasable | denial is **O(1)** — no scan per request |
| A4 | flooder + quiet honest key, map at cap | the honest key's entry SURVIVES; the flooder's is evicted |
| A5 | a promoted key under a flood | never evicted, never throttled as a stranger |
| A6 | quota refills after the window | a long-quiet key is judged fresh, not on ancient history |
| A7 | consecutive denials with backoff | window grows, capped; a single allow resets it |
| A8 | log flood | denials counted and surfaced on the next allow |
| A9 | clock goes backwards | no panic, no permanent lockout, no free permits |
| A10 | two classes, same key space | each judged by its own quota |
| A11 | cap reached with only promoted keys | new key refused; no promoted key is evicted |

## 5. Migration

One caller at a time, each keeping its public surface so no consumer changes:

1. `LogThrottle` — quota, no classes, no backoff. `suppressed_prev` maps to D5.
2. `InviteGate` — two classes + promotion + fair release. `InviteVerdict` and
   `RefuseReason` stay; the body becomes a call into the limiter.
3. `RefusalBackoff` — one permit, backoff window per disposition class.
   `RetryDisposition` becomes the class.
4. **Identifier lookup** (new, the reason this is happening now): per-requesting-
   peer quota on `subject_holdings`. Option 1 concentrates bodies at canonicals,
   so a canonical answering by name is the one place bulk harvesting is
   possible, one named subject at a time — and rate limiting is what makes that
   bound real rather than nominal.

Each migration keeps its existing tests green as the acceptance criterion: the
old tests were written against real bugs, so they are the regression suite.
