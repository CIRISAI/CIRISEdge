# FSD: Replication Wire Format v1 — anti-entropy gossip for federation envelopes

**Status:** Proposed — lands as part of CIRISEdge#65 layer (c-2) production wiring
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-06-09
**Repo:** `~/CIRISEdge` (this document is the spec; code lands in this repo)
**Anchors:** Path to CIRIS 2.0 — this wire format is the **first version-stable
contract** for cross-region anti-entropy gossip. Every replication round shipped
from v1.5.0 forward speaks this wire; protocol breakages going forward bump
`WIRE_PROTOCOL_VERSION`.
**Risk:** Wire-stable. Mistakes bake in at the protocol-version level and cost
a fleet-wide rolling-upgrade tolerance window to escape. Hence: ratify before
shipping; expand the kind taxonomy now to match persist's surface 1:1.

**Companion documents:**
- [`CIRIS_EDGE.md`](CIRIS_EDGE.md) — overall edge mission
- [`../MISSION.md`](../MISSION.md) §3 (canonicalization isn't edge's to define)
- [`CIRISRegistry#58`](https://github.com/CIRISAI/CIRISRegistry/issues/58) — "remove Spock" epic ("Edge owns propagation")
- [`CIRISPersist src/federation/types.rs`](https://github.com/CIRISAI/CIRISPersist/blob/main/src/federation/types.rs) — record shapes
- CEG 0.15 §0.9 canonicalization rules + §0.9.2.1 determinism rules

---

## 1. Why this exists

Cross-region convergence in the CIRIS federation today is split:

- **Trust data** (keys / attestations / revocations / families /
  communities / identity_occurrences) — replicated CEG-natively via
  point-to-point signed envelopes. Eventual consistency depends on
  every region eventually sending to every other.
- **Cross-region DB state** — replicated via Postgres Spock multi-
  master, which trusts the DB layer. A compromised node's injected
  rows replicate silently.

CIRISRegistry#58 ("[Epic] Remove Spock") collapses these into a
**single CEG-native replication mechanism**: every cross-region state
change is a signed CEG envelope, propagated via edge's anti-entropy
gossip, applied with persist's R1/Q1 quorum-merge + anti-rollback.

The decision boundary per #58:
- **Persist owns** the federation directory + quorum-merge (V058 +
  generalization to operational data).
- **Edge owns propagation** — the anti-entropy protocol shape, gossip
  cadence, peer-set discovery, wire frame.
- **Registry is consumer** — defines operational-data envelope shapes
  (orgs/users/licenses/partners) where they don't already exist.

This FSD specifies edge's propagation contract: **what bytes go on
the wire**, **how envelopes are identified**, **what protocol messages
the two peers exchange**.

The shape implementations partially landed in #69 (protocol types) →
#70 (coordinator) → #71 (directory trait + adapters) → #72 (wire-frame
prefix) → #73 (long-lived Session) → #75 (scheduler glue). This FSD
locks the **v1 wire-stable shape** and adds the missing piece —
layer (c-2) production wiring via a `FederationDirectoryReplicationBridge`
that bridges replication's [`ReplicationDirectory`] trait onto persist's
existing [`FederationDirectory`] + `ReadEngine` surfaces.

## 2. Scope

In:

- Envelope identity (`envelope_hash`) and wire-byte format
  (`envelope_bytes`) for every kind of federation envelope
- Replication kind taxonomy (`EnvelopeKind`) — expanded from the
  4-variant pre-v1 shape to a **9-variant v1 shape** aligned 1:1
  with persist's `FederationDirectory` put_* surface
- Wire-protocol version marker; advancement rules
- Bridge implementation surface (`FederationDirectoryReplicationBridge`)
- Hash → bytes cache strategy (persist surface gap; edge mitigation)
- PyO3 init shape for operator config + runtime registration

Out:

- The R1/Q1 quorum-merge semantics (substrate-side; persist owns)
- Operational-data CEG envelope shapes (Registry owns)
- Streaming/multicast (CEG 0.15 §10.5 — separate axis; CIRISEdge#66)
- Cross-region peer-set discovery (operator config)

## 3. Decision authority — what's locked, what's open

The 5 design questions surfaced during layer (c-2) investigation
resolve as follows. Citations are by direction (CEG / persist /
edge MISSION).

### 3.1 envelope_hash semantics — LOCKED (CEG + persist)

The federation envelope identity is **`original_content_hash`**:
sha256 over the canonical bytes of the inner `*_envelope` JSON
value carried inside each `Signed*Record`.

Every persist federation record type (`KeyRecord`, `Attestation`,
`Revocation`, `IdentityOccurrence`, `Family`, `Community`, the V067
membership-revocation triple from v4.8.0) carries the same shape:
- A `*_envelope: serde_json::Value` field — the inner CEG envelope
- An `original_content_hash: String` field — hex sha256 of canonical
  bytes of that envelope
- Embedded scrub signatures (Ed25519 classical + ML-DSA-65 hybrid)
- A server-computed `persist_row_hash: String` over the full record

We use `original_content_hash` (the **content** identity), not
`persist_row_hash` (the **row** identity). Justification:

- `original_content_hash` is deterministic across nodes; same content
  claim → same hash regardless of which node observed it. That's the
  property anti-entropy summary↔diff convergence requires.
- v4.7.0 `register_public_key` typed return (Registered /
  AlreadyRegistered / RotationCollision) defines persist's stance:
  same `key_id` + same pubkey → idempotent; same `key_id` + different
  pubkey → rotation collision. Content identity is the dedup boundary.
- CEG §0.9.2.1 (canonical-bytes determinism rules) locks the
  canonicalization that makes `original_content_hash` reproducible
  cross-impl.

### 3.2 envelope_bytes wire format — LOCKED (edge MISSION + persist)

The bytes shipped over the replication wire are **canonical(Signed*Record)**
serialized via persist's `PythonJsonDumpsCanonicalizer` (the V1Python
canonicalizer today; flips to JCS at the 2.9.6 substrate triple via
persist v4.6.0's signed-epoch version gate).

Edge does **not** define canonicalization rules. Quoting `MISSION.md`
§3: *"`sign_envelope` calls `ciris_persist::canonicalize_envelope_for_signing`;
edge re-implements no canonicalization rule. Canonical bytes are not
edge's to define."* Layer (c-2) calls persist's canonicalizer directly.

The wire bytes include the embedded scrub signatures + the
server-computed `persist_row_hash` field — the **full record** as
persist would re-canonicalize it after `put_*` admit. This means:

- A peer receiving an envelope deserializes the Signed*Record,
  forwards to the appropriate `put_*` admit on its local persist,
  and the admit's scrub-signature verification runs against the
  embedded signatures.
- `persist_row_hash` is server-computed on receive too — the receiver's
  persist recomputes it. Edge does not preserve the sender's
  `persist_row_hash` semantically; it just rides along in the wire
  bytes and is recomputed downstream.

The shipped canonicalizer (V1Python) flips to JCS by persist v4.6.0's
`produce_canon_version()` returning `CanonVersion::V2Jcs` (gated by
the signed-epoch version, NOT by a caller flag). When that flip
happens, replication wire bytes auto-flip too — edge calls persist's
canonicalizer at runtime; no edge-side coordination needed.

### 3.3 EnvelopeKind taxonomy — DECISION: expand 4→9

This was the genuinely open question. We resolve it by aligning the
replication kind discriminator **1:1 with persist's `FederationDirectory`
put_* surface**. Nine variants:

| `EnvelopeKind` variant      | Persist put_* method                          | Wire tag         |
|-----------------------------|------------------------------------------------|------------------|
| `Key`                       | `put_public_key(SignedKeyRecord)`             | `"key"`          |
| `Attestation`               | `put_attestation(SignedAttestation)`          | `"attestation"`  |
| `Revocation`                | `put_revocation(SignedRevocation)`            | `"revocation"`   |
| `IdentityOccurrence`        | `put_identity_occurrence(SignedIdentityOccurrence)` | `"identity_occurrence"` |
| `Family`                    | `put_family(SignedFamily)`                    | `"family"`       |
| `Community`                 | `put_community(SignedCommunity)`              | `"community"`    |
| `IdentityOccurrenceRevocation` | `put_identity_occurrence_revocation(SignedIdentityOccurrenceRevocation)` | `"identity_occurrence_revocation"` |
| `FamilyMembershipRevocation`   | `put_family_membership_revocation(SignedFamilyMembershipRevocation)`   | `"family_membership_revocation"` |
| `CommunityMembershipRevocation` | `put_community_membership_revocation(SignedCommunityMembershipRevocation)` | `"community_membership_revocation"` |

The wire tag is the `serde(rename = "snake_case")` form. Tagged via
`#[serde(tag = "kind")]` at the message layer (Summary / Diff /
Fetch / Deliver each carry their kind on the wire).

Justification:

- **1:1 with persist** means `apply_envelope_bytes` dispatches via
  a simple match on `EnvelopeKind` — no JSON shape sniffing, no
  schema inference. Each branch deserializes the matching Signed*Record
  and calls the matching put_*.
- **Forward-secrecy revocations** (the V067 triple from persist v4.8.0)
  are first-class kinds — they propagate via federation gossip just
  like the membership puts they revoke, so the wire surface must
  carry them.
- **No lumped Community sub-kind** means we don't need a wire-frame
  discriminator and don't need to invent CEG-spec extensions.

We accept the **wire-format break from the pre-v1 4-variant shape**.
This is acceptable because:
- No production fleet runs the pre-v1 shape yet — the protocol PRs
  shipped to develop, not to a tagged production replication run.
- v1 stays stable from this version forward; advancing requires
  bumping `WIRE_PROTOCOL_VERSION` (§3.5).

### 3.4 anti-entropy wire shape — LOCKED (edge-defined, already shipped)

The Summary / Diff / Fetch / Deliver four-message shape (#69) plus
the CRPL wire-frame prefix (#72) plus the long-lived Session (#73)
plus the scheduler (#75) constitute the v1 anti-entropy protocol.
CEG defers to edge per #58.

### 3.5 WIRE_PROTOCOL_VERSION

Replication protocol version is carried in the wire-frame:

```text
  ┌────┬────┬──────────────────────────────────────────────┐
  │MAG │VER │  ReplicationMessage::to_bytes() — JSON       │
  │ 4B │ 1B │                                              │
  └────┴────┴──────────────────────────────────────────────┘
```

- `MAG` is `b"CRPL"` (4 bytes; see #72)
- `VER` is `0x01` for v1 (1 byte; **new in this FSD**)

A receiver with no `VER` byte support (the pre-v1 in-development
shape) MUST be replaced before any production peer ships replication.
Going forward, the version byte gates dispatch:

```rust
match version {
    0x01 => parse_v1(body),
    _    => Err(ProtocolError::UnknownVersion(version)),
}
```

Future versions:
- `0x02` — when CEG-native operational-data envelopes (orgs / users /
  licenses / partners per #58 Phase 2) land and need new
  `EnvelopeKind`s. Currently expected for CIRIS 2.0.
- `0x03+` — reserve.

The single-byte version field gives us 255 future versions before
needing a multi-byte version extension. Plenty.

### 3.6 Layer (c-2) production wiring — DECIDED

Layer (c-2) ships a **`FederationDirectoryReplicationBridge`** that
implements `ReplicationDirectory` over `Arc<dyn FederationDirectory> +
Arc<dyn ReadEngine>`:

- **`list_envelope_refs(kind)`** — pages through the matching
  `ReadEngine::list_*` bulk method (the v4.0+ §I federation
  observability bulk primitives in `src/ceg/list/federation.rs`),
  collecting `(envelope_hash, seq)` pairs. The `seq` is the bulk
  cursor's natural ordering field (`valid_from` for keys,
  `asserted_at` for attestations, `revoked_at` for revocations,
  etc.); we project to a `u64` via Unix ms.

- **`fetch_envelope_bytes(kind, hash)`** — looks up the bytes by
  content hash. **Substrate gap**: persist has no
  `lookup_*_by_content_hash` point-read. v1 mitigation: an
  in-memory `HashMap<(EnvelopeKind, [u8; 32]), Vec<u8>>` cache
  populated as a side effect of `list_envelope_refs`. The cache is
  bounded (LRU, 4096 entries by default — operator-tunable) and
  keyed on the `(kind, hash)` pair. Cache miss = "I don't have this
  envelope" semantically (the responder side returns empty bytes
  for that hash; the requester re-attempts next round).
  - Follow-up persist issue to file: `lookup_signed_key_record_by_hash`
    and friends. v1 ships without; the cache + bulk-list shape is
    sufficient for federations up to ~10k envelopes per kind
    (validated by sizing the cache to match steady-state envelope
    count + round cadence).

- **`apply_envelope_bytes(kind, bytes)`** — deserializes the matching
  `Signed*Record` (one match arm per kind), routes to the matching
  persist `put_*` admit. Persist runs scrub-signature verification +
  R1/Q1 monotonicity; edge returns `bool` for "admitted vs refused"
  (matching the existing `StateApplier::apply_envelope` shape — #71).

### 3.7 PyO3 init shape

`init_edge_runtime` gains two replication parameters:

```python
init_edge_runtime(
    engine,                                # existing
    transports=...,                         # existing
    replication_peers: list[tuple[str, str]] = None,  # NEW
    replication_cadence_seconds: int = 30,  # NEW (matches scheduler default)
)
```

`replication_peers` is a list of `(peer_key_id, kind_str)` pairs.
Each entry constructs a `ReplicationCoordinator` (Initiator role,
because the operator chose to peer with this remote for this kind),
registers it with the application-side `ReplicationRegistry` (for
inbound dispatch), and adds it to the `ReplicationScheduler`'s
Initiator set.

The Responder side is symmetric: when an unknown remote peer sends
a Summary, the registry auto-creates a Responder coordinator on
first contact (subject to operator allowlist policy — out of scope
here; operator policy lives at the transport layer per existing
blackhole_rules surface).

Runtime hot-add via `PyEdge.register_replication_peer(peer_key_id, kind_str)`
gives operators flexibility post-init.

## 4. Acceptance criteria

- [ ] 9-variant `EnvelopeKind` shipped; serde tags match §3.3 table
- [ ] `WIRE_PROTOCOL_VERSION = 0x01` byte added to wire frame; wrap/try_unwrap updated
- [ ] `FederationDirectoryReplicationBridge` implements `ReplicationDirectory`
  over `Arc<dyn FederationDirectory> + Arc<dyn ReadEngine>`
- [ ] In-memory hash→bytes cache (LRU, 4096 default capacity) populated
  from bulk-list responses
- [ ] All 9 kinds round-trip via `apply_envelope_bytes` → persist `put_*`
  → list_envelope_refs (in-memory sqlite test)
- [ ] PyO3 init accepts `replication_peers` + `replication_cadence_seconds`;
  `PyEdge.register_replication_peer` hot-add works
- [ ] `try_unwrap_replication_frame` rejects unknown version bytes with
  `ProtocolError::UnknownVersion(u8)`
- [ ] FSD anchored as `~/CIRISEdge/FSD/REPLICATION_WIRE_FORMAT_V1.md`
  (this document); cross-linked from `CIRIS_EDGE.md` and `replication/mod.rs`

## 5. Path to CIRIS 2.0

Per #58, the operational-data envelope shape (orgs / users / licenses /
partners) is the **one genuinely new design lift** for Spock removal.
That lift introduces new `EnvelopeKind`s — naturally a wire-protocol
version bump (`0x01` → `0x02`).

This FSD anchors v1 so the path is clear:

1. **CIRIS 1.x replication line** — v1 wire (`VER = 0x01`),
   nine `EnvelopeKind`s, federation directory + R1/Q1 quorum-merge
   for trust data. Operational-data still on Spock multi-master.
2. **CIRIS 2.0 cut** — Spock fully removed. Operational-data envelopes
   defined by Registry (per #58 Phase 2). Wire bumps to `VER = 0x02`
   adding `EnvelopeKind::Org`, `User`, `License`, `Partner` (or
   whatever Registry names them). Edge tolerates both v1 and v2
   wire during the rolling-upgrade window via the version byte.
3. **Post-2.0** — Spock-free federation; one CEG-native replication
   mechanism; single auditable cryptographic-provenance trail across
   every cross-region state change.

The wire-version byte at the frame layer (§3.5) is the load-bearing
detail. Without it, the v1 → v2 transition would require a coordinated
fleet-wide flag day. With it, individual peers can upgrade
independently and the framing dispatch tells them what they're
receiving.

## 6. Non-goals (explicit, with linked tracking)

- **Operational-data envelope shapes** — CIRISRegistry#58 Phase 2;
  not edge's design.
- **Streaming chunked content (CEG §10.5)** — separate axis;
  CIRISPersist#142 + CIRISEdge#66 (relay/multicast for large-N).
- **Adaptive byte-range scheduling** — CIRISEdge#55 / CIRISPersist#145.
- **`lookup_*_by_content_hash` on persist** — substrate follow-up;
  v1 mitigates via in-memory cache (§3.6).
- **Cross-region peer-set discovery cadence** — operator config;
  not protocol.
- **Telemetry beyond the existing `StalenessSignal` +
  `RoundEvent`** — metrics counters land in a follow-up; the
  `tracing` spans the scheduler emits give the v1 observability
  surface.

## 7. Threat model considerations

The v1 wire surface adds **no new cryptographic primitives** — it's
plumbing. The security envelope is unchanged:

- **AV-9** (hybrid Ed25519 + ML-DSA-65 scrub signatures) — enforced
  at persist's put_* admit. Layer (c-2)'s `apply_envelope_bytes`
  delegates to the admit; no edge-side verify bypass.
- **AV-13** (signed envelopes only — refuse unsigned) — same.
- **R1/Q1 anti-rollback monotonicity** — persist V058 / v4.8.0
  forward-secrecy; replication just streams envelopes, persist
  decides admit/refuse.
- **Frame magic prefix** + **version byte** — these are routing
  metadata, NOT integrity primitives. A peer that lies about its
  version causes its envelope to be rejected at parse; the embedded
  scrub signatures remain the integrity floor.

New attack surface from replication itself:

- **Amplification** — a peer requesting many envelope_hashes triggers
  large `DeliverMessage`s. Mitigation: round_timeout + scheduler
  cadence bound total throughput per peer. Operator can tune.
- **Cache poisoning** — the in-memory hash→bytes cache trusts the
  bulk-list response from persist. Persist's response is authoritative
  (it's reading its own local DB), so this is moot.
- **Replay** — replication doesn't have a freshness window; persist's
  monotonicity gates handle duplicate-application. Subject to the
  same anti-rollback guarantees as the put_* surfaces.

No new TM entries; the existing AV-9/AV-13/V058 set covers v1
replication wire.
