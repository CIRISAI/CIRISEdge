# CEG RC1 Bifurcation — Edge-Court Record

**Status:** Decisions locked 2026-06-01. CEG normative text lands in
CIRISRegistry (`FSD/CEG/`, v0.9 → 0.10). This document is the
**Edge-side** record: the resolutions Edge owns, grounded in the Edge
tree, plus the corrected source anchors for the cross-cutting clauses
so the 0.10 text does not propagate citations that don't resolve.

CEG = **The CIRIS Epistemic Grammar** (a federation attestation
grammar), not a streaming layer. §3 defines exactly five primitives:
`scores`, `delegates_to`, `supersedes`, `withdraws`, `recants`.
`holds_bytes` / `key_grant` are §10 endpoint constructs;
`live_stream` / chunk-DAG / multicast are **net-new §10 surface**, not
grammar primitives.

---

## 1. The bifurcation

RC1 splits cleanly along whether the substrate primitives exist today:

| Half | Rides | RC1 status |
|------|-------|------------|
| **Observer-share / directed delivery** (single Contribution → subscriber-community; no `stream_id`) | community roster (#153/#154) + `key_grant` wrap (CEG §5.6.8.4) — **both exist** | **Ships at RC1** |
| **Media / streaming multicast** (chunk-DAG, per-`(stream_id, epoch)` keys) | streaming primitives that are **0-occurrence in every tree** | **Spec now, impl `pending-#142`** |

Greenfield confirmed: `transport_epoch`, `stream_id`,
`put_blob_chunk`, `seal_stream`, `ChunkDag`, `live_stream`,
`has_chunk` → **0 occurrences** in the Edge tree. The design is
defined natively, not retrofitted.

CEG 0.10 absorbs #44 (CEG 0.5 `live_stream`) as new §10 endpoint text.

---

## 2. Dependency map (what gates what)

- **`#142`** (streaming primitives: chunk table, `put_blob_chunk`,
  `seal_stream`) gates the **streaming half only** — not directed
  delivery.
- **`#34`** (witness consistency-proof / anti-equivocation) gates the
  **accountable** stream tier only. §10.3 today carries
  consistency-proof *fields* but not the proof *machinery*; #34 is
  described upstream as post-v2.0.0 polish, so accountable streams are
  `pending-#34`. **Best-effort** streams (producer-root only) do not
  need #34 and can land first.

---

## 3. Edge-court resolutions (E1–E4)

Full rationale in [`OPEN_QUESTIONS.md`](OPEN_QUESTIONS.md) OQ-14–OQ-17.

- **E1 — encryption layering (OQ-14):** two independent layers.
  Transit = Reticulum link encryption / TLS (hop-by-hop). Content =
  producer-applied epoch-DEK cascade. **Edge ships ciphertext it
  cannot read**; the transit wrap never replaces the cascade. Anchor:
  `THREAT_MODEL.md` AV-15 ("Edge does NOT add a third encryption
  layer"), `multimedia.rs` (`ExternalRefWithAcl`).
- **E2 — RC1 multicast = pull-only (OQ-15):** producer seals →
  `holds_bytes` directory → subscribers pull. Already implemented:
  `ContentFetch`/`ContentBody`/`ContentMiss` (#42, §10.1.1).
  Relay/fan-out tree → 1.x.
- **E3 — live-delivery ownership = `entitled ∧ reachable` (OQ-16):**
  Persist owns durable entitlement; Edge owns transport-reachability
  (`reachability.rs`, #29, node-local). Presence rides #29 — node-
  local, TTL'd, never an attestation, never replicated.
- **E4 — durable entitlement over the existing path (OQ-17):** roster
  + epoch-key grants propagate as `DELIVERY = Durable`
  `federation_attestations` over `send_federation` / `send_durable` →
  `cirislens.edge_outbound_queue`. No net-new Edge transport.

---

## 4. Invariants to bake into the 0.10 text (P1–P4)

- **P2 — node-local / never-logged:** live-delivery + presence +
  heartbeat are node-local, TTL'd, **never** minted as `holds_bytes`
  or any attestation, never replicated, never logged. Precedent: the
  `cohort_scope` discipline (`cohort_scope.rs`, #48-A: "self/family-
  scope content never emits `holds_bytes`, never crosses to inter-host
  paths"). Write as an invariant, not a default.
- **P4 — fail-honest on evicted epochs:** catch-up returns
  `ContentMiss` for epochs evicted below the chunk-retention horizon
  even when the grant still exists. No silent gap. Anchor:
  MISSION fail-loud doctrine ("CIRISEdge fails **loud**: it never
  drops … silently", AV-42; `ContentFetch`/`ContentBody`/`ContentMiss`
  #21). Retention windows are operator/Lens-core knobs, not substrate
  constants — precedent: `EdgeConfig::holds_bytes_ttl_seconds`
  (configurable; 24h is the spec-pinned default, CEG §10.1.2).

---

## 5. Corrected source anchors

The discussion thread cited several anchors that do not resolve. Use
the corrected anchors below in the 0.10 text:

| Thread cited | Reality | Use instead |
|--------------|---------|-------------|
| `§10.1.5` (streaming/Merkle clause) | §10 has no §10.1.5; no Merkle/chunk/stream language anywhere in §10 | Net-new §10 endpoint subsection (TBD number) |
| `MISSION:66` / `MISSION:148` ("evidence that can't replicate…") | Those lines are peer-separability / outbound-queue | MISSION fail-loud doctrine (l.182/197/414) |
| `validated-not-adjudicated (MISSION §1.4)` | "adjudicated" does not appear in MISSION; §1.4 is the apophatic bound | CEG validate/adjudicate language (not MISSION §1.4) |
| `Policy E (locality-scaled)` | No "Policy E" exists; policies are K/L/M (§8.1.11–13) | CEG **§8.1.5 locality-scaled-quorum** (+ §8.1.5.1 sub-quorum fallback) |
| `cohort_scope::suppresses_holds_bytes` (v3.9.2) | No such symbol; mechanism is producer-side refusal | `cohort_scope.rs` (v0.19.1, #48-A) |
| `transit-key / #857` | 0 occurrences in Edge | `THREAT_MODEL.md` AV-15 (Reticulum/TLS) |
| `#46/#43` (fan-out deferral) | #46 = canonical bootstrap-peer hard-remove | net-new; no Edge issue yet |
| `#41` (durable cutover) | not in Edge tree | OQ-04 + OQ-09 (`edge_outbound_queue`) |

**Per-stream transparency log — note for §10.3:** the V1 design
("a stream is its own log, `log_id = stream_id`") is **net-new §10.3
surface**, not verbatim reuse. §10.3 today is a **single global** log
with no `log_id` dimension. The RFC-6962 STH/cosign math
(`SignedTreeHead::cosign`, `count_valid_witnesses`,
`witness_quorum_met`, consistency-proof fields — all real in §10.3,
Verify v2.12.0+) is reusable; the log-identity dimension must be
**added**. `delivery_receipt:{stream_id}` is a new §7 reserved prefix.

**Persist confirmations still owed** (not verifiable from the Edge
tree): `rotation_chain` shape (P1 hinge — 0 occurrences in Edge) and
the `KEY_GRANT_V1_INFO` versioned-context nonce pattern (V2). Pin both
on the record before they enter normative text.
