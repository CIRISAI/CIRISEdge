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
- CEG §0.9 canonicalization rules + §0.9.2.1 determinism rules (anchors
  stable through CEG 0.15 → 0.17)

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
  4-variant pre-v1 shape to a **10-variant v1 shape** aligned 1:1
  with persist's `FederationDirectory` put_* surface
- Wire-protocol version marker; advancement rules
- Bridge implementation surface (`FederationDirectoryReplicationBridge`)
- Hash → bytes cache strategy (persist surface gap; edge mitigation)
- PyO3 init shape for operator config + runtime registration

Out:

- The R1/Q1 quorum-merge semantics (substrate-side; persist owns)
- Operational-data CEG envelope shapes (Registry owns)
- Streaming/multicast (CEG §10.5 — separate axis; CIRISEdge#66)
- Cross-region peer-set discovery (operator config)

## 3. Decision authority — what's locked, what's open

The 5 design questions surfaced during layer (c-2) investigation
resolve as follows. Citations are by direction (CEG / persist /
edge MISSION).

### 3.1 envelope_hash semantics — **AMENDED v1: `persist_row_hash` uniformly**

**Original lock (preserved for history):** spec-owner review chose
`original_content_hash` as the envelope identity for v1.

**v1 implementation discovery (layer (c-2) wiring):** only **3 of the
10** `Signed*Record` inner types carry `original_content_hash` —
`KeyRecord`, `Attestation`, `Revocation` (the legacy shape with an
inner `*_envelope: Value` field). The 7 newer types
(`IdentityOccurrence`, `Family`, `Community`, the three V067
membership-revocations from v4.8.0, `LocationProof` from v4.10.0)
carry only `persist_row_hash`. The CEG 0.7+ record shapes store
their typed Rust fields directly without an inner JSON envelope
field, so there is no `original_content_hash` to compute.

**Decision (v1 amendment):** the v1 wire uses `persist_row_hash`
**uniformly** across all 10 kinds as `EnvelopeRef::envelope_hash`.

Justification:

- **Uniform** — no per-kind special-casing. A single match arm in
  the bridge handles every kind's hash extraction.
- **Deterministic across nodes** — persist's `compute_persist_row_hash`
  is sha256 over canonical(record minus `persist_row_hash` itself);
  same content + same scrub-signing inputs on every peer → same hash.
- **Stronger convergence than `original_content_hash`** — full-record
  identity (includes embedded scrub signatures). Same byte-identical
  record on every peer or no convergence. Ed25519 and ML-DSA-65 are
  deterministic (FIPS 204 final), so same signer + same payload →
  same signature → same `persist_row_hash`. The "different witnesses
  → same envelope" ambiguity that motivated picking
  `original_content_hash` doesn't apply when the wire identity binds
  to the full Signed*Record.
- **Still satisfies the v4.7.0 `register_public_key` idempotency
  story** — same `key_id` + same pubkey + same scrub-signatures →
  same `persist_row_hash` → idempotent dedup. A rotation collision
  (same key_id, different pubkey) yields a different
  `persist_row_hash`, surfacing at admit-time.

The original-lock anchor at `original_content_hash` was the right
answer for the 3 legacy record types but doesn't generalize. The
amendment chooses the answer that does. Tracked in the bridge's
module docs (`src/replication/bridge.rs`) alongside the
implementation.

### 3.2 envelope_bytes wire format — LOCKED (edge MISSION + persist)

The bytes shipped over the replication wire are **canonical(Signed*Record)**
serialized via persist's `PythonJsonDumpsCanonicalizer` (the V1Python
canonicalizer today; flips to JCS at the 2.9.6 substrate triple via
persist v4.6.0's signed-epoch version gate).

Edge does **not** define canonicalization rules. Quoting `MISSION.md`
§3: *"`sign_envelope` calls `ciris_persist::canonicalize_envelope_for_signing`;
edge re-implements no canonicalization rule. Canonical bytes are not
edge's to define."* Layer (c-2) calls persist's canonicalizer directly.

#### 3.2.1 Canonicalization status post-persist-v4.15.0

**Persist v4.15.0 LANDED the JCS canonicalization flip** (2026-06-09,
the 2.9.6 substrate triple cutover, CEG 1.0 §0.9 conformance milestone,
CIRISPersist#171/#176). `produce_canon_version()` flipped V1Python →
V2Jcs. The transitional caveat originally documented here is partially
resolved + a new architectural finding now anchors here.

**What flipped (relevant to edge):**
- The 3 legacy types' `original_content_hash` field (KeyRecord,
  Attestation, Revocation — the shape with an inner `*_envelope:
  Value` field) is now sha256 over **JCS-canonical** bytes. For
  records signed with schema version ≥ "3.0.0", the hash is
  CEG-§0.9-conformant and reproducible by non-persist
  implementations.
- Records signed pre-flip (schema "2.7.x") stay V1Python-canonical;
  the signed-epoch version-gate in `canon_version_for_trace_schema`
  dispatches the right canonicalizer per record. The discriminator
  is inside the signed bytes — downgrade-safe (FSD §6).

**What did NOT flip (persist's design intent):**
- **`persist_row_hash` STAYS V1Python forever.** Persist explicitly
  documents this in its v4.15.0 release notes: *"Internal
  `persist_row_hash` + audit `canonical_bytes_for_entry` — never
  cross the federation boundary; stay Python-compat per FSD OQ-2."*
- The carve-out reflects persist's stated boundary model: `persist_row_hash`
  is a per-node integrity invariant, not a cross-federation
  identity. Flipping it would invalidate every existing persisted
  row's recomputable hash — a substrate-wide rewrite cost that
  persist's design avoided.

**Architectural finding (anchored here for the record):**

Edge's v1 wire DOES cross `persist_row_hash` over the federation
boundary as `EnvelopeRef::envelope_hash` per the v1.6.0 §3.1
amendment. This is **contrary to persist's stated intent** but
operationally sound:

- `persist_row_hash` is deterministic (`compute_persist_row_hash` is
  sha256 over canonical(record minus `persist_row_hash` itself); same
  bytes in, same bytes out, on every node)
- Same scrub-signed record produces same `persist_row_hash` on every
  peer (Ed25519 + ML-DSA-65 deterministic per FIPS 204 final)
- The V1Python canonicalizer used inside `compute_persist_row_hash`
  is a fixed, version-stable function — not subject to the
  `produce_canon_version()` gate that flipped to JCS

The trade-off: a **non-persist CEG implementation cannot reproduce
edge's envelope_hash for the 7 newer types**, because it would have
to implement persist's V1Python canonicalization (which persist
considers internal). Concretely:

- All-persist federations: full interop. ✓
- Non-persist CEG implementations: must implement persist-compat
  V1Python canonicalization OR a future wire-protocol-version bump
  (v2) introduces a CEG-conformant hash basis.

The path to non-persist CEG interop for replication is therefore
**deferred to a v2 wire-protocol-version cycle**, when CIRISRegistry#58
Phase 2's operational-data envelopes drive a `WIRE_PROTOCOL_VERSION
= 0x02` cut anyway. v2 would settle on a CEG-§0.9-conformant
envelope-identity scheme for all kinds (likely: sha256 of
JCS-canonical(Signed*Record), edge-defined). The version byte
mechanism (§3.5) makes the v1→v2 transition peer-by-peer; no
flag-day required.

**v1 stays unchanged** — `persist_row_hash` uniformly, all-persist
federations only. Documented as an explicit interop boundary, not a
silent caveat. **The deferred path resolves in §3.2.2.**

#### 3.2.2 v2 envelope_hash basis — LOCKED (CEG 1.0-RC2)

**Resolution of the §3.2.1 deferred-interop path.** CEG 1.0-RC2
(`v-ceg-1.0-rc2`, commit `b21fe84`) closed blocker A as **JCS**
(RFC 8785 — not TupleHash128); CEG 1.0-RC1 (`v-ceg-1.0-rc1`, commit
`8872bfe`) shipped the canonical-bytes redesign. CIRISRegistry#70
review (Edge ✅ · Verify ✅ · Persist ✅) locked the v2 wire surface
in the same RC2 cut.

**v2 `envelope_hash` = `sha256(JCS(Signed*Record))`**, uniformly
across all v2-emitting kinds. Edge-defined; reproducible by any
CEG-§0.9-conformant implementation; non-persist CEG implementers
gain full interop with v2-capable peers.

The architectural shift from v1:

- **v1**: `envelope_hash = persist_row_hash` (V1Python, persist-internal).
  All-persist federations only; an explicit interop boundary per §3.2.1.
- **v2**: `envelope_hash = sha256(JCS(Signed*Record))` (CEG-§0.9-conformant,
  edge-defined). Any CEG implementation reproduces it.

Per §3.5, peer-by-peer transition: v2-capable peers exchange v2
envelopes with v2-capable peers and v1 envelopes with v1-only peers.
The version byte negotiates; no flag-day.

**`PartnerRecord` admission depends on JCS basis.** Per the Verify
review catch locked in RC2 §5.6.8.13: M distinct stewards must sign
**byte-identical JCS canonical bytes** for the M-of-N steward quorum
to admit. The §0.9.2.1 rule 1 set-semantics declaration on
`capabilities_granted[]` / `capabilities_denied[]` /
unordered-list-inside-`constraints` (lexicographic sort) is what
makes M-of-N convergence possible — without it, two stewards
emitting the same grant in different field order produce different
canonical bytes and the quorum silently fails to admit. Edge's v2
wire surfaces these arrays via the same JCS pass that produces
`envelope_hash`; consistency by construction.

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

### 3.3 EnvelopeKind taxonomy — DECISION: expand 4→10

This was the genuinely open question. We resolve it by aligning the
replication kind discriminator **1:1 with persist's `FederationDirectory`
put_* surface**. **Ten variants** as of persist v4.10.0:

| `EnvelopeKind` variant      | Persist put_* method                          | Wire tag                          | Substrate ship |
|-----------------------------|------------------------------------------------|-----------------------------------|----------------|
| `Key`                       | `put_public_key(SignedKeyRecord)`             | `"key"`                           | v1.0+ |
| `Attestation`               | `put_attestation(SignedAttestation)`          | `"attestation"`                   | v1.0+ |
| `Revocation`                | `put_revocation(SignedRevocation)`            | `"revocation"`                    | v1.0+ |
| `IdentityOccurrence`        | `put_identity_occurrence(SignedIdentityOccurrence)` | `"identity_occurrence"`     | CEG 0.7 |
| `Family`                    | `put_family(SignedFamily)`                    | `"family"`                        | CEG 0.7 |
| `Community`                 | `put_community(SignedCommunity)`              | `"community"`                     | CEG 0.8 |
| `IdentityOccurrenceRevocation` | `put_identity_occurrence_revocation(SignedIdentityOccurrenceRevocation)` | `"identity_occurrence_revocation"` | v4.8.0 (#161) |
| `FamilyMembershipRevocation`   | `put_family_membership_revocation(SignedFamilyMembershipRevocation)`   | `"family_membership_revocation"`   | v4.8.0 (#161) |
| `CommunityMembershipRevocation` | `put_community_membership_revocation(SignedCommunityMembershipRevocation)` | `"community_membership_revocation"` | v4.8.0 (#161) |
| `LocationProof`             | `put_location_proof(SignedLocationProof)`     | `"location_proof"`                | v4.10.0 (#154) |

The wire tag is the `serde(rename = "snake_case")` form. Tagged via
`#[serde(tag = "kind")]` at the message layer (Summary / Diff /
Fetch / Deliver each carry their kind on the wire).

The 10th variant `LocationProof` is the CEG 0.8 §0.8.1 normative
privacy primitive — a geographic claim bounded to H3 resolution ≤ 7,
enforced at the substrate (CIRISPersist v4.10.0, V068
`federation_location_proofs` + `validate_location_cell`). The
substrate's resolution-≤-7 rejection IS the privacy enforcement; a
producer can't over-share precise location even if client UI gating
fails.

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

- [ ] 10-variant `EnvelopeKind` shipped; serde tags match §3.3 table
- [ ] `WIRE_PROTOCOL_VERSION = 0x01` byte added to wire frame; wrap/try_unwrap updated
- [ ] `FederationDirectoryReplicationBridge` implements `ReplicationDirectory`
  over `Arc<dyn FederationDirectory> + Arc<dyn ReadEngine>`
- [ ] In-memory hash→bytes cache (LRU, 4096 default capacity) populated
  from bulk-list responses
- [ ] All 10 kinds round-trip via `apply_envelope_bytes` → persist `put_*`
  → list_envelope_refs (in-memory sqlite test)
- [ ] Federation-tier-only invariant (§7.1) enforced + tested: a
  §10.1.4-invisible private IdentityOccurrence/Family/Community MUST
  NOT appear in `list_envelope_refs`; a federation-present record
  MUST appear; a local-tier (pre-promotion) attestation MUST NOT
  appear in `list_envelope_refs(Attestation)`
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
   ten `EnvelopeKind`s, federation directory + R1/Q1 quorum-merge
   for trust data. Operational-data still on Spock multi-master.
2. **CIRIS 2.0 cut** — Spock fully removed. Operational-data envelopes
   defined by Registry (per #58 Phase 2). Wire bumps to `VER = 0x02`
   adding **three** new `EnvelopeKind`s (per §5.2 below — locked at
   RC2, narrower than the four originally anticipated). Edge tolerates
   both v1 and v2 wire during the rolling-upgrade window via the
   version byte.
3. **Post-2.0** — Spock-free federation; one CEG-native replication
   mechanism; single auditable cryptographic-provenance trail across
   every cross-region state change.

The wire-version byte at the frame layer (§3.5) is the load-bearing
detail. Without it, the v1 → v2 transition would require a coordinated
fleet-wide flag day. With it, individual peers can upgrade
independently and the framing dispatch tells them what they're
receiving.

### 5.2 v2 EnvelopeKind additions — LOCKED (CEG 1.0-RC2 §5.6.8.13)

CIRISRegistry#70 specified the operational-data envelope shape;
three-sided federation review (Edge ✅ · Verify ✅ · Persist ✅)
locked decisions; CEG 1.0-RC2 codified at §5.6.8.13. The v2
`EnvelopeKind` additions are **three**, not the four originally
forecast:

| v2 `EnvelopeKind` | wire token | merge intent (§10.1.6) | rationale |
|---|---|---|---|
| `Organization` | `organization` | `lww_skew_bounded` | public org identity federates; PII (`tax_id`, contacts, `metadata`) stays region-local |
| `OrgMembership` | `org_membership` | `lww_skew_bounded` + `withdrawal_forward_only` | authz binding (`user_id`/`org_id`/`role`) federates; **User PII never federates** |
| `PartnerRecord` | `partner_record` | `monotonic_quorum` (V058-generalized) | combines old `License`+`Partner`; M-of-N steward quorum + monotonic-fail-secure (more-restrictive wins) |

**`User` is explicitly dropped from the wire.** The original §5
forecast anticipated four kinds (`Org`/`User`/`License`/`Partner`);
the federate-the-trust/authz-minimal-projection principle keeps PII
per-region — only the `OrgMembership` role binding crosses. The old
`License`+`Partner` pair collapses into the existing combined
`PartnerRecord` shape (already hybrid-signed today; CEG-native just
means it propagates by envelope instead of Spock).

**Wire tokens are normative** — snake_case per the §3.3 v1
convention; the CEG cut names them explicitly so no implementation
re-derives. Per §3.2.2, all three v2 kinds use
`envelope_hash = sha256(JCS(Signed*Record))`.

**Edge's v2 implementation scope — SHIPPED at v2.0.0:**

1. ✅ Added `Organization`, `OrgMembership`, `PartnerRecord` to
   `EnvelopeKind` (appended for `Ord`/`Hash` stability on
   `LocalState`'s `BTreeMap<EnvelopeKind, …>` keys).
2. ✅ Implemented v2 `envelope_hash` per §3.2.2 (JCS-conformant) —
   `bridge::v2_envelope_hash` calls
   `ciris_verify_core::jcs::canonicalize` then sha256.
3. ✅ Wire-version negotiation extended — `WIRE_PROTOCOL_VERSION_V2 = 0x02`
   in `wire_frame.rs`; `try_unwrap` accepts both `0x01` and `0x02`;
   `wrap_for_kind` selects per-message version via
   `EnvelopeKind::min_wire_version` (v2 kinds emit at `0x02`, v1 kinds
   stay at `0x01`); `Coordinator::send_message` calls `wrap_for_kind`.
4. ✅ `Bridge::apply_envelope_bytes` extended with `apply_organization` /
   `apply_org_membership` / `apply_partner_record` — each dispatches
   to persist v5.1.1's `put_organization` / `put_org_membership` /
   `put_partner_record` with the operator-supplied `OperationalProviders`
   (key_directory + root_stewards + steward_roster).
5. ✅ No new coordinator code — merge policy stays persist-side
   (`lww_skew_bounded` + `withdrawal_forward_only` + `monotonic_quorum`
   per §10.1.6, dispatched declaratively, never inferred).
6. ✅ `OperationalProviders` bundle in `BridgeConfig` — optional;
   when unset (`v1-only` bridge construction via `new` / `with_config`),
   all 3 operational `apply_*` fail-close to `false` without touching
   persist. Operators opt into v2 admission via
   `with_operational` / `with_config_and_operational`.

**Substrate prerequisites — SATISFIED:**

- ✅ **`ciris-persist` v5.1.1** ships `put_organization` /
  `put_org_membership` / `put_partner_record` admit surfaces + the
  two §10.1.6 merge dispatchers (`resolve_lww` for organization /
  org_membership; `resolve_monotonic_quorum` for partner_record) +
  V058-generalized `verify_coord` for `license_id` + skew-bound LWW
  precedence + stable-id grouping.
- ✅ **`ciris-verify` v5.1.0** ships `ciris_verify_core::operational_admit`
  (the role-chain resolver applied to operational subject_kinds via
  `resolve_role_authority` + `verify_founder_quorum` for partner_record
  admission) + `ciris_verify_core::jcs::canonicalize` (the JCS basis
  v2 envelope_hash invokes).
- ⏳ **CIRISConformance#9** M-of-N identical-bytes vector set — pending
  (the Verify-raised catch from RC2 review). Persist + verify own the
  fixture generation; edge consumes the vectors via conformance tests.

**v2.0.0 known limitation — `partner_record` is admit-only.**

`PartnerRecord`'s row shape (per CIRISPersist v5.1.0's
`federation::operational::PartnerRecord`) does NOT carry the M-of-N
steward signatures inline — they live in the
`SignedPartnerRecord` write wrapper. Persist v5.1.0's
`list_partner_records_since` returns rows only (no companion
`list_signed_partner_records_since`). Edge's
`Bridge::list_partner_records` therefore returns empty — the Initiator
side does NOT advertise `partner_record` envelopes via anti-entropy
enumeration. The Responder side admits peer-pushed
`SignedPartnerRecord` bytes correctly (the sender ships the M-of-N
signatures inline; verify v5.1.0's `verify_partner_record_quorum`
admits on receipt). The fully bidirectional path lights up when persist
ships `list_signed_partner_records_since` (a v5.2 follow-up filed
upstream). Organization + OrgMembership are fully bidirectional at
v2.0.0 because their row shapes carry the single-signer Ed25519 +
ML-DSA-65 signatures inline.

### 5.3 v2 → v3 (and beyond)

CEG 1.0-RC2 declares the **design surface complete** — #70 was the
one scheduled addition; RC2→1.0 changes are found defects, not
design additions. Edge's v3+ surface area is therefore expected to
be either (a) optimization-driven (e.g., O(log N) MLS rekey tree
when the relay/multicast 1.x cycle drives it — currently CIRISEdge#66)
or (b) reactive to defect-driven CEG amendments. No further forecast
EnvelopeKinds expected.

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

### 7.1 Federation-tier-only invariant (CEG §10.1.4 / §10.1.5)

**Normative invariant:** Replication carries only federation-PRESENT
`Signed*Record` envelopes — never local-only or pre-promotion content.
The line that must hold: *federation directory = federation-present
records only; the private at-rest tier is a separate local store.*

Two enforcement mechanisms, by kind:

- **`Attestation`** — safe by construction. CEG §10.1.5 defines local-
  tier attestations as **deferred-signature** (producer-only-visible);
  promotion is the act of hybrid-signing `JCS(envelope)`. A local-tier
  attestation has **no `SignedAttestation` form** until promoted, so
  it is **structurally ineligible** to appear in
  `list_envelope_refs(Attestation)`. The wire format enforces this by
  type — no new gate required.

- **`IdentityOccurrence` / `Family` / `Community`** — signed forms
  exist for both private (CEG §10.1.4 structurally-invisible) and
  federation-present records. The structural guarantee that protects
  attestations does **NOT** extend here. Layer (c-2) MUST enforce an
  **explicit scope gate**: the bridge reads only the federation
  directory (`federation_identity_occurrences` / `federation_families`
  / `federation_communities`); CEG §10.1.4-invisible private records
  live in a separate local-only store that `list_envelope_refs`
  MUST NOT read.

A **cross-region self** (CEG §8.1.12.7 Self-at-login — app+agent
occurrences sharing a Self DEK across regions) is precisely the case
that exercises this gate. Three things legitimately cross regions
for a cross-region self, all safe:
1. The `IdentityOccurrence` directory envelope — **cleartext
   provenance** (occurrence id, pubkey, `transport_destination`,
   `cohort_scope`), federation-PRESENT by intent. This is how the
   federation resolves "these instances are one self" and how peers
   reach them.
2. The shared **Self DEK** — as a wrapped key-grant
   (`wrap_algorithm: v2`), ciphertext, only the target instance
   unwraps.
3. The **encrypted content** — DEK-encrypted, via content-fetch,
   never via this directory stream.

A §10.1.4-invisible *private* self (federation-absent) MUST NOT
cross. That is the line.

**Layer (c-2) acceptance tests (Finding 1 fence):**

1. A §10.1.4-invisible IdentityOccurrence / Family / Community
   record (private at-rest tier) MUST NOT appear in
   `list_envelope_refs(IdentityOccurrence | Family | Community)`.
2. A federation-present occurrence (declared `cohort_scope: federation`
   + transport binding) MUST appear in `list_envelope_refs`.
3. A local-tier (pre-promotion) attestation MUST NOT appear in
   `list_envelope_refs(Attestation)` — structurally true today;
   pin as a regression test.

Substrate confirmation required (persist side): `list_attestations`
/ `list_identity_occurrences` / `list_families` / `list_communities`
in the `ReadEngine` bulk surface read ONLY federation-tier promoted
rows, never a local-tier / pre-promotion store. Almost certainly
true today; the test fences the invariant against future refactors.

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
