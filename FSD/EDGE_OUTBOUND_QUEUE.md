# FSD: edge_outbound_queue — Durable substrate for `send_durable()`

**Status:** Substrate landed in CIRISPersist v0.4.0 (issue #16 closed
2026-05-03). CIRISEdge consumes from `ciris-persist >= 0.4.0`. Spec
frozen; persist threat-model closures: AV-40 (queue disk exhaustion)
and AV-41 (spoofed in_reply_to ACK matching).
**Owner spec:** CIRISEdge (this repo, per OQ-05 — edge owns the
wire-format and the contract; persist implements the substrate).
**Implementer:** CIRISPersist (table + Engine FFI surface).
**Companion:** [`CIRIS_EDGE.md`](CIRIS_EDGE.md) §3.2 (public API),
[`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) OQ-09 (closure rationale),
[`../docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md) AV-12 / AV-13.

---

## 1. Purpose

CIRISEdge OQ-09 ships two outbound channels:

- `send()` — ephemeral. Caller-owned retry. Failure visible.
- `send_durable()` — must eventually land across edge restart.
  Edge-owned retry. Caller gets a `DurableHandle` to observe outcome.

Delivery class lives on the message type:
`AccordEventsBatch::DELIVERY = Ephemeral`,
`BuildManifestPublication::DELIVERY = Durable`. The durable channel
needs a persistent substrate; this document specifies it.

The substrate is a single Postgres table in the `cirislens` schema
(matching `federation_keys`'s namespace) plus a small Engine FFI
surface for enqueue, claim-and-dispatch, ACK matching, and operator
inspection.

## 2. State machine

Five states; transitions explicit:

```
                            ┌──────────────────────────────────┐
                            │                                  │
                  [enqueue] │                                  │
                            ▼                                  │
                       ┌─────────┐                             │
                       │ pending │◄──────────────────┐         │
                       └────┬────┘                   │         │
                  [claim]   │                        │         │
                            ▼                        │         │
                       ┌─────────┐                   │         │
                       │ sending │                   │         │
                       └────┬────┘                   │         │
                            │                        │         │
       (transport failure)  │  (transport delivered) │         │
       (or claim expired)   │                        │         │
                  ┌─────────┴──────────┐             │         │
                  ▼                    ▼             │         │
              (retry)         requires_ack ?         │         │
                  │                    │             │         │
                  │       no ──────────┼──┐ yes      │         │
                  │                    │  │          │         │
                  │                    ▼  ▼          │         │
                  │            ┌───────────┐  ┌──────────────┐ │
                  │            │ delivered │  │ awaiting_ack │ │
                  │            └───────────┘  └───────┬──────┘ │
                  │                                   │        │
                  │      (ack envelope arrives)       │        │
                  │            ┌──────────────────────┘        │
                  │            ▼                               │
                  │      ┌───────────┐                         │
                  │      │ delivered │                         │
                  │      └───────────┘                         │
                  │                                            │
                  │      (ack timeout)                         │
                  │            └────────────────────────────►──┘
                  │
                  └─► (attempt_count >= max_attempts)
                  └─► (enqueued_at + ttl < now)
                  └─► (operator cancel)
                              │
                              ▼
                      ┌────────────┐
                      │ abandoned  │
                      │ (+ reason) │
                      └────────────┘
```

`replay_detected` reject from receiver routes to `delivered` (idempotent
recovery — the receiver already has the message; persist's AV-9 dedup
makes a duplicate delivery harmless on the receiver side).

## 3. Schema

```sql
CREATE TABLE IF NOT EXISTS cirislens.edge_outbound_queue (
    queue_id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identity
    sender_key_id              TEXT NOT NULL,
    destination_key_id         TEXT NOT NULL,

    -- Message (signed envelope, byte-exact, ready to ship)
    message_type               TEXT NOT NULL,
    edge_schema_version        TEXT NOT NULL,
    envelope_bytes             BYTEA NOT NULL,
    body_sha256                BYTEA NOT NULL,
    body_size_bytes            INTEGER NOT NULL,

    -- Lifecycle
    status                     TEXT NOT NULL,
    enqueued_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_attempt_after         TIMESTAMPTZ NOT NULL,
    last_attempt_at            TIMESTAMPTZ,
    transport_delivered_at     TIMESTAMPTZ,
    delivered_at               TIMESTAMPTZ,
    abandoned_at               TIMESTAMPTZ,
    abandoned_reason           TEXT,

    -- Retry policy (copied from message-type policy at enqueue time;
    -- per-row so policy changes don't retroactively break in-flight rows)
    attempt_count              INTEGER NOT NULL DEFAULT 0,
    max_attempts               INTEGER NOT NULL,
    ttl_seconds                BIGINT  NOT NULL,
    last_error_class           TEXT,
    last_error_detail          TEXT,
    last_transport             TEXT,

    -- ACK (only meaningful when requires_ack = TRUE)
    requires_ack               BOOLEAN NOT NULL,
    ack_timeout_seconds        BIGINT,
    ack_envelope_bytes         BYTEA,
    ack_received_at            TIMESTAMPTZ,

    -- Concurrency claim (multi-instance dispatch per OQ-06)
    claimed_until              TIMESTAMPTZ,
    claimed_by                 TEXT,

    -- FK constraints
    CONSTRAINT sender_key_must_exist
        FOREIGN KEY (sender_key_id)
        REFERENCES cirislens.federation_keys(key_id),
    CONSTRAINT destination_key_must_exist
        FOREIGN KEY (destination_key_id)
        REFERENCES cirislens.federation_keys(key_id),

    -- Domain checks
    CONSTRAINT status_must_be_known
        CHECK (status IN ('pending', 'sending', 'awaiting_ack', 'delivered', 'abandoned')),
    CONSTRAINT abandoned_reason_must_be_known
        CHECK (abandoned_reason IS NULL
               OR abandoned_reason IN ('max_attempts', 'ttl_expired', 'operator_cancel')),
    CONSTRAINT body_size_bounded
        CHECK (body_size_bytes BETWEEN 1 AND 8388608),     -- AV-13: 8 MiB cap
    CONSTRAINT body_sha256_correct_length
        CHECK (octet_length(body_sha256) = 32),
    CONSTRAINT max_attempts_positive
        CHECK (max_attempts > 0),
    CONSTRAINT ttl_seconds_positive
        CHECK (ttl_seconds > 0),
    CONSTRAINT ack_timeout_required_when_requires_ack
        CHECK ((NOT requires_ack)
               OR (ack_timeout_seconds IS NOT NULL AND ack_timeout_seconds > 0)),

    -- State-shape invariants
    CONSTRAINT delivered_implies_delivered_at
        CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CONSTRAINT abandoned_implies_abandoned_at
        CHECK ((status = 'abandoned')
               = (abandoned_at IS NOT NULL AND abandoned_reason IS NOT NULL)),
    CONSTRAINT ack_envelope_implies_ack_received
        CHECK ((ack_envelope_bytes IS NOT NULL) = (ack_received_at IS NOT NULL)),
    CONSTRAINT ack_received_implies_requires_ack
        CHECK (ack_received_at IS NULL OR requires_ack = TRUE)
);

-- Hot dispatch path: workers pull pending rows whose timer has fired
CREATE INDEX edge_outbound_queue_pending_dispatch
    ON cirislens.edge_outbound_queue (next_attempt_after)
    WHERE status = 'pending';

-- ACK-timeout sweep: rows that transport-delivered but never got ACK
CREATE INDEX edge_outbound_queue_awaiting_ack_sweep
    ON cirislens.edge_outbound_queue (transport_delivered_at)
    WHERE status = 'awaiting_ack';

-- ACK matching: incoming ACK envelope's in_reply_to_sha256 → original
CREATE INDEX edge_outbound_queue_body_sha256_awaiting
    ON cirislens.edge_outbound_queue (body_sha256)
    WHERE status = 'awaiting_ack';

-- Operator queries: "all pending to peer X", "queue depth per dest"
CREATE INDEX edge_outbound_queue_destination
    ON cirislens.edge_outbound_queue (destination_key_id, status);

-- Operator queries: "oldest non-terminal", "status histogram"
CREATE INDEX edge_outbound_queue_status_enqueued
    ON cirislens.edge_outbound_queue (status, enqueued_at);

-- Claim-expiry sweep: workers that crashed with status='sending'
CREATE INDEX edge_outbound_queue_claimed_until_sweep
    ON cirislens.edge_outbound_queue (claimed_until)
    WHERE status = 'sending';
```

Schema lives at `cirislens.edge_outbound_queue` (matching
`federation_keys`'s namespace). Migration: next available number in
`migrations/postgres/lens/` (likely V005__edge_outbound_queue.sql).
Schema is **experimental during edge v0.1.x** per the same
v0.4.0-stabilization contract `federation_keys` uses.

## 4. Engine surface

```rust
// ─── Sender side (called by edge.send_durable) ─────────────────────
fn enqueue_outbound(
    &self,
    sender_key_id: &str,
    destination_key_id: &str,
    message_type: &str,
    edge_schema_version: &str,
    envelope_bytes: &[u8],
    body_sha256: &[u8; 32],
    body_size_bytes: i32,
    requires_ack: bool,
    ack_timeout_seconds: Option<i64>,
    max_attempts: i32,
    ttl_seconds: i64,
    initial_next_attempt_after: TimestampTz,
) -> Result<QueueId, OutboundError>;

// ─── Dispatch loop (called by edge's background tokio task) ────────
//
// Atomic claim: SELECT FOR UPDATE SKIP LOCKED + UPDATE to status='sending'
// with claimed_until=now()+claim_duration, claimed_by=worker_id.
// Returns up to batch_size rows whose next_attempt_after <= now()
// AND status='pending'. Disjoint batches across concurrent workers.
fn claim_pending_outbound(
    &self,
    batch_size: i64,
    claim_duration_seconds: i64,
    claimed_by: &str,
) -> Result<Vec<OutboundRow>, OutboundError>;

// On transport success — !requires_ack: status='delivered'.
//                       requires_ack:  status='awaiting_ack',
//                                      transport_delivered_at=now().
fn mark_transport_delivered(
    &self,
    queue_id: QueueId,
    transport: &str,
) -> Result<(), OutboundError>;

// On transport failure — increment attempt_count, schedule next_attempt_after,
// status returns to 'pending'. If attempt_count >= max_attempts:
// status='abandoned', abandoned_reason='max_attempts'.
fn mark_transport_failed(
    &self,
    queue_id: QueueId,
    error_class: &str,
    error_detail: &str,
    transport: &str,
    next_attempt_after: TimestampTz,
) -> Result<OutboundFailureOutcome, OutboundError>;
// OutboundFailureOutcome: { Retrying { attempt: i32 } | Abandoned }

// Sender-visible reject 'replay_detected' from receiver maps to delivered.
fn mark_replay_resolved(&self, queue_id: QueueId) -> Result<(), OutboundError>;

// ─── ACK side (called by edge's inbound dispatch on a verified envelope
//     whose envelope.in_reply_to matches a row's body_sha256) ────────
fn match_ack_to_outbound(
    &self,
    in_reply_to_sha256: &[u8; 32],
) -> Result<Option<OutboundRow>, OutboundError>;

fn mark_ack_received(
    &self,
    queue_id: QueueId,
    ack_envelope_bytes: &[u8],
) -> Result<(), OutboundError>;
// status='delivered', ack_received_at=now(), delivered_at=now().

// ─── Background sweeps ─────────────────────────────────────────────
// awaiting_ack rows where transport_delivered_at + ack_timeout < now()
// → pending (re-attempt). Returns count of rows swept.
fn sweep_ack_timeouts(&self) -> Result<i64, OutboundError>;

// Non-terminal rows where enqueued_at + ttl_seconds < now()
// → abandoned, abandoned_reason='ttl_expired'. Returns count.
fn sweep_ttl_expired(&self) -> Result<i64, OutboundError>;

// 'sending' rows whose claim expired (worker crashed mid-attempt)
// → pending. Returns count.
fn sweep_expired_claims(&self) -> Result<i64, OutboundError>;

// ─── Inspection (for DurableHandle) ────────────────────────────────
fn outbound_status(&self, queue_id: QueueId) -> Result<OutboundStatus, OutboundError>;

// OutboundStatus: full row state — status, attempt_count, last_error_*,
// delivered_at, abandoned_at/reason, ack_envelope_bytes if available.

// ─── Operator surface ──────────────────────────────────────────────
fn list_outbound(
    &self,
    filter: OutboundFilter,    // by status, destination, age, etc.
    limit: i64,
) -> Result<Vec<OutboundRow>, OutboundError>;

fn cancel_outbound(&self, queue_id: QueueId) -> Result<(), OutboundError>;
// Non-terminal → abandoned, abandoned_reason='operator_cancel'.

fn replay_abandoned(&self, queue_id: QueueId) -> Result<(), OutboundError>;
// abandoned → pending; resets attempt_count to 0; clears abandoned_*.
// Operator confirmation gated at the API layer above Engine.
```

PyO3 surface mirrors the above so the Python lens can construct
`DurableHandle` objects during the alongside-window cutover.

## 5. Wire-format implications

`EdgeEnvelope` (FSD/CIRIS_EDGE.md §3.4) gains one optional field:

```rust
/// 32-byte body_sha256 of the original envelope this is a response to.
/// Set on response/ACK envelopes; None on first-touch envelopes.
/// Used by the sender's edge_outbound_queue to match ACKs to originals
/// (CIRISPersist#16 / OQ-09 closure). Receiver populates from the
/// inbound envelope's body_sha256 when invoking the handler's response.
#[serde(default, skip_serializing_if = "Option::is_none")]
pub in_reply_to: Option<[u8; 32]>,
```

The field is part of canonical bytes and signed. An attacker cannot
forge an ACK without the destination peer's key (AV-1 closure
applies). Mismatched `in_reply_to` (ACK envelope claims to reply to
a `body_sha256` we never sent) → no row matches; ACK is dropped with
typed log; not a security issue.

## 6. Threat-model touchpoints

| AV | Touchpoint | Mitigation |
|---|---|---|
| AV-2 | Compromised sender key inserts forged-but-correctly-signed durable rows | Out of scope; same as elsewhere — closure is hardware-backed key storage upstream (CIRISVerify) |
| AV-9 | Re-verify on retry would self-verify | Dispatch loop does NOT re-verify on retry (envelope already verified at enqueue); ACK envelopes go through normal verify pipeline before `mark_ack_received` is called |
| AV-12 / **persist AV-40** | Adversary inflates queue (disk exhaustion) | Schema CHECK constraints (`body_size_bytes BETWEEN 1 AND 8388608`, `ttl_seconds > 0`, `max_attempts > 0`); operational discipline (`sweep_ttl_expired` cadence + ops dashboard alert on `oldest-pending-age`); FK constraint on sender/destination_key_id chains to persist's federation_keys trust boundary |
| AV-13 | Body-size flood | `body_size_bytes BETWEEN 1 AND 8388608` CHECK constraint enforces 8 MiB cap on enqueue |
| **persist AV-41** | Spoofed `in_reply_to` to mark a row delivered prematurely | ACK envelopes go through persist's normal verify pipeline (AV-1 unknown-key gate + AV-39 verify_hybrid via persist) before `mark_ack_received` is called; bound-signature pattern (persist AV-33) closes Ed25519-alone forgery branch |

## 7. Operator surface

### Telemetry (OTLP, surfaced by edge from Engine)

- `edge_outbound_queue_depth{status,destination_key_id}` — gauge
- `edge_outbound_queue_oldest_pending_age_seconds{status}` — gauge,
  alarm at threshold (configurable; default 300s)
- `edge_outbound_queue_abandoned_total{abandoned_reason}` — counter
- `edge_outbound_queue_attempts_total{status,last_error_class}` — counter
- `edge_outbound_queue_acks_received_total{message_type}` — counter
- `edge_outbound_queue_acks_timed_out_total{message_type}` — counter

### Alarms (operator's choice; suggested defaults)

- `abandoned{abandoned_reason='max_attempts'}` increment → page (an
  exhausted-retry message is operator-actionable)
- `oldest_pending_age{status='pending'} > 600s` → page (something is
  stuck)
- `oldest_pending_age{status='awaiting_ack'} > 1800s` → warn (slow
  receiver)

### Operator commands

- `cancel_outbound(queue_id)` — non-terminal → abandoned/operator_cancel
- `replay_abandoned(queue_id)` — abandoned → pending; resets attempt_count

## 8. Phase 1 message types using `Delivery::Durable`

At v0.1.0 of edge, the message types declaring `DELIVERY = Durable`:

- `BuildManifestPublication` (registry adoption — Phase 2 cutover):
  `requires_ack=true`, `max_attempts=100`, `ttl_seconds=604800` (7d),
  `ack_timeout_seconds=300`.
- `DSARRequest` / `DSARResponse` (DSAR handler chain):
  `requires_ack=true`, `max_attempts=20`, `ttl_seconds=86400` (24h),
  `ack_timeout_seconds=600`.
- `AttestationGossip` (federation directory):
  `requires_ack=false`, `max_attempts=10`, `ttl_seconds=3600` (1h).
- `PublicKeyRegistration` (federation directory):
  `requires_ack=true`, `max_attempts=50`, `ttl_seconds=259200` (3d),
  `ack_timeout_seconds=300`.

`AccordEventsBatch` and heartbeats stay `DELIVERY = Ephemeral`
(`send()` channel; persist's AV-9 dedup is the recovery mechanism).

## 9. Why this shape

- **One table**, not split-into-archive: keep it simple at Phase 1
  scale; vacuum/archive cold rows offline if scale demands.
- **FK on both sender_key_id and destination_key_id**: every durable
  row has identifiable provenance and target; operator queries
  ("all pending to peer X") cleanly join to `federation_keys`.
- **Per-row policy** (max_attempts, ttl_seconds, ack_timeout_seconds):
  message-type policy changes don't retroactively break in-flight
  rows.
- **Optimistic claim with `claimed_until`**: multi-instance dispatch
  (per OQ-06) without inter-worker locks; expired claims auto-revert.
- **Five states with explicit transitions**: every state has explicit
  shape invariants enforced at the CHECK level; no implicit-from-column
  state.
- **`abandoned_reason` instead of separate `dlq` state**: same
  primitive, less state surface; reason is an attribute, not a status.
- **`replay_detected` → delivered**: idempotent recovery against
  receiver's replay window expiring before our ACK arrives.
- **`in_reply_to` on the wire**: ACK matching uses content-derived
  `body_sha256`, not sender-local IDs; both sides naturally agree.

## 10. What this does NOT specify

- **Backoff schedule:** the formula (exponential, jittered) lives in
  edge's dispatch-loop code, not in persist. Persist stores the
  scheduled `next_attempt_after`; edge computes it.
- **Worker identity (`claimed_by`):** edge supplies its worker
  identifier (a key_id, a hostname+pid, whatever); persist stores
  verbatim for forensics. No format prescribed.
- **Per-message-type policy registration:** the message-type's
  `Delivery::Durable { requires_ack, max_attempts, ttl_seconds,
  ack_timeout_seconds }` is declared in edge's message-type
  definitions, not in persist. Persist only stores the policy values
  per-row at enqueue.
