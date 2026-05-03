# Open Questions — CIRISEdge

Design forks that need owner input before Phase 1 implementation
starts. Each question states the choice, the trade-off, and the
**lens-side default** as a starting point — not a binding answer.
Answers land here as they're resolved; resolved questions move to a
"Closed" section at the bottom with the rationale captured.

This document is intentionally a **decision register**, not an issue
tracker. Questions that get clear yes/no answers move to `CLOSED`.
Questions that need an `INTEGRATION_*.md` doc to resolve get tagged
`→ defer to integration spec`.

---

## OQ-13: Test infrastructure for multi-medium transports

**Question:** How does edge test LoRa, packet-radio, serial transports
in CI without physical hardware?

**Options:**
- **A — Sim-only:** Each transport ships with a sim crate that
  emulates the medium's characteristics (latency, packet loss,
  bandwidth). CI runs sim-only.
- **B — Sim + opt-in hardware:** Sim runs in CI; physical hardware
  testing is gated on dedicated runners (Raspberry Pi with LoRa hat,
  USB serial dongle). Pre-merge gate is sim; post-merge nightly
  exercises hardware.
- **C — Hardware required:** No CI sims; physical runners only.

**Lens-side default:** B. Sim catches the wire-correctness issues;
hardware catches the operational issues (power, RF interference,
driver versions). Both are real; sim is cheaper to run on every PR;
hardware nightly catches the stuff sims don't model.

**Status:** OPEN — Phase 3 concern; not blocking Phase 1. Reopen at
Phase 3 kickoff once the first multi-medium transport PR is in flight.

---

## CLOSED

Resolutions captured during the 2026-05-03 design pass. Each entry
summarizes the question and the rationale that landed; the full
options/trade-offs treatment is preserved in this file's git history.

### OQ-01: Library vs sidecar — RESOLVED A (library) — 2026-05-03

Edge ships as a Rust crate each peer links into its own runtime.
Persist owns the seeds; edge holds the `Engine` handle and calls into
persist for every sign/verify. A sidecar would reintroduce the
key-leak surface (sidecar process holds Reticulum identity) at a new
layer — exactly the inversion `CIRISPersist#10` rejected at the
cold-path PQC level. Multi-language reach is handled by PyO3 bindings
(lens already uses them for `ciris-persist`); agent + registry are
headed Rust anyway. Closes the FFI-boundary discipline behind AV-17.

### OQ-02: HTTP fallback — RESOLVED B (HTTP fallback) — 2026-05-03

Reticulum is canonical; HTTP/HTTPS ships alongside as a documented
fallback transport. Wire format is identical across transports
(signed envelope is transport-agnostic). Per-peer config decides the
default. Reticulum-only at Phase 1 is operationally prohibitive
(every cloud deployment would need a Reticulum daemon); HTTP-default
fails the M-1 pluralism axis. B threads the needle. AV-15 closure:
Reticulum native link encryption + TLS at deployment edge for HTTP;
edge does not add a third encryption layer.

### OQ-03: Wire-format scope — RESOLVED A (federation-only) — 2026-05-03

Edge carries signed federation messages (traces, key registrations,
manifest publications, federation gossip). OTLP traces stay on the
existing otelcol → Tempo/Mimir path. The two trace surfaces serve
different purposes — signed-CIRIS is federation evidence, OTLP is
operator observability — and conflating them would break lens's
Grafana investment for marginal "one trace surface" value. OTLP also
has no per-message signature today; verify-via-persist would be a
no-op on it.

### OQ-04: Migration path — RESOLVED B (alongside-window) — 2026-05-03

Lens-side cutover runs edge alongside the existing FastAPI route for
~1 minor; traffic mirrors to both; once clean shadow comparison
passes, FastAPI route deletes. Mirrors the persist v0.2.x cutover
precedent (Phase 1 wired idle, Phase 2a delegated, Phase 2b retired
legacy). Bridge has the playbook from v0.2.x. Same shape used for
agent + registry adoption in Phase 2.

### OQ-05: Spec authority — RESOLVED A (edge-owned) — 2026-05-03

Wire-format spec lives at `~/CIRISEdge/FSD/WIRE_FORMAT.md`; downstream
peers (`CIRISAgent`, `CIRISLens`, `CIRISRegistry`) pin against tagged
commits. Same precedent CIRISAgent set with
`TRACE_WIRE_FORMAT.md @ v2.7.9-stable` and persist set with
`PUBLIC_SCHEMA_CONTRACT.md`. AV-7's strict version allowlist requires
a single source of truth.

### OQ-06: Multi-worker concurrency — RESOLVED B (multi-instance) — 2026-05-03

Each worker (uvicorn worker, spawned edge instance) gets its own
`key_id` registered under the host's shared `identity_ref` in
persist's `federation_keys`. Persist's composite index
`(identity_type, identity_ref)` is **designed** for many-keys-per-
identity — that's not an exception, it's the schema's intended shape.
Mirrors `CIRISAgent.AuthenticationService`'s `rotate_keys` pattern:
one `wa_id`, many keys over time, `active_only=True` filters the live
set. Each worker has its own Reticulum link state (destination =
`sha256(pubkey)[..16]` per worker key); persist's advisory-lock-on-init
handles boot serialization; persist's AV-9 dedup is the authoritative
cross-worker catch.

Side benefit: clean key rotation falls out of the same pattern (mint
new `key_id` under same `identity_ref`, run both during overlap,
expire old via `valid_until`). No schema change needed; persist's
directory already supports it.

### OQ-07: Reticulum-rs vs Leviculum vs both — RESOLVED C (both via Transport trait) — 2026-05-03

`Transport` trait abstracts both Rust Reticulum implementations.
Phase 1 ships reticulum-rs only; Leviculum (or any future Rust impl)
gains a `Transport` enum entry once AV-25 byte-equivalence regression
passes. Optionality is mission-aligned per PoB §3.2 ("fork-survivable
Rust implementations"); the Transport trait is designed for C-shape
from day one even though only one impl exists at v0.1.0. If one fork
dies, the other carries the federation forward.

### OQ-08: Replay window size — RESOLVED 5min Phase 1, configurable Phase 2 — 2026-05-03

Phase 1 default: 5-minute window; bounded LRU at 100K entries.
Sustained replay-flood adversary must produce 333 messages/sec just
to win the eviction race against legitimate traffic — and pay verify
cost on every one (cost-asymmetric per PoB §2.1). Phase 2 makes the
window per-peer-configurable for deployments with different
network-reliability/threat-model trade-offs. Persist's AV-9 dedup
tuple catches application-layer replay regardless. Captured in TM
AV-3 / AV-12.

### OQ-09: Outbound queue / retry policy — RESOLVED A + C only, delivery-class on message type — 2026-05-03

**Two channels, no middle ground.** B (bounded in-memory retry) was
the hedge — convenience without commitment — and a federation
primitive shouldn't ship that as a first-class option.

- **A — `send()`** for ephemeral messages. Caller-owned retry;
  failure is visible. Returns `EdgeError::Unreachable` on transport
  failure; no hidden retry behind the caller's back. Use cases: trace
  batches, heartbeats — anything where "next batch supersedes" or
  persist's AV-9 dedup recovers from drop.
- **C — `send_durable()`** for messages that must eventually land
  across restarts. Edge-owned persistent queue
  (`cirislens.edge_outbound_queue`). Caller gets a `DurableHandle`
  to observe outcome (poll, await, dlq inspect). Use cases:
  manifest publications, DSAR responses, key registrations,
  attestation gossip — rare, high-value, must-land messages.

**Delivery-class lives on the message type, not the call site:**
`AccordEventsBatch::DELIVERY = Ephemeral`,
`BuildManifestPublication::DELIVERY = Durable`. Caller can't
accidentally pick wrong; threat model gets it cheaper because the
durable-queue surface only exists for message types that declared
they need it (AV-12 / AV-13 gates can be type-specific). Spec for
each message type names its contract; `register_handler` rejects
mismatches at compile time via the `Delivery` associated type.

**Persist dependency: SATISFIED in v0.4.0 (CIRISPersist#16 closed
2026-05-03).** `cirislens.edge_outbound_queue` + Engine surface
(`enqueue_outbound`, `claim_pending_outbound`,
`mark_transport_delivered`, `mark_transport_failed`,
`mark_replay_resolved`, `match_ack_to_outbound`,
`mark_ack_received`, sweeps, operator commands) are the substrate.
CIRISPersist threat-model AV-40 (queue disk exhaustion) and AV-41
(spoofed in_reply_to ACK matching) closed. Spec lives at
[`FSD/EDGE_OUTBOUND_QUEUE.md`](EDGE_OUTBOUND_QUEUE.md).

### OQ-10: Operator-UI HTTP integration — RESOLVED A (out of scope) — 2026-05-03

Edge handles federation peer ↔ peer traffic only. Operator UX
(Grafana proxy, OAuth, admin pages) stays on whatever HTTP stack each
peer composes for itself (FastAPI/Caddy at the lens). Mounting
auth-pluggable middleware would drag OAuth into the federation
transport spec — exactly the multiplexing of concerns FSD §11 + TM §1
already exclude.

### OQ-11: PQC verify timeline — RESOLVED day-1 hybrid (Ed25519 + ML-DSA-65) — 2026-05-03

Hybrid PQC is in prod across the federation: CIRISVerify v1.9.0 ships
`MlDsa65SoftwareSigner` + `PqcSigner` trait; CIRISPersist v0.2.0+
`federation_keys` carries `pubkey_ml_dsa_65_base64` +
`scrub_signature_pqc` + `pqc_completed_at`; the "hot Ed25519 + cold
ML-DSA kickoff" writer contract is operational. **Edge ships hybrid
verify in v0.1.0, not deferred.**

Edge inherits persist's eventual-consistency trust model. Three
configurable consumer policies, picked per peer:
- **Strict-hybrid:** reject any envelope whose sender's
  `federation_keys` row is hybrid-pending (`pqc_completed_at IS NULL`).
- **Soft-hybrid + freshness:** accept hybrid-pending rows within a
  freshness window (e.g. 30s after write); reject older ones.
- **Ed25519-fallback:** accept Ed25519-only verification (lowest-
  assurance default for environments where PQC reach is incomplete).

**Persist dependency: SATISFIED in v0.3.6 (CIRISPersist#14 closed
2026-05-03), bumped to v0.4.0 floor for the federation substrate
cut.** Two variants ship:

- `Engine.verify_hybrid(canonical_bytes, ed25519_sig, ml_dsa_65_sig,
  ed25519_pubkey, ml_dsa_65_pubkey, policy, soft_freshness_window,
  row_age) -> VerifyOutcome` — raw-pubkey form.
- `Engine.verify_hybrid_via_directory(canonical_bytes,
  signature_key_id, ed25519_sig, ml_dsa_65_sig, policy,
  soft_freshness_window, row_age) -> VerifyOutcome` — combines
  `lookup_public_key` + verify in one call. **Edge's per-message hot
  path uses this variant.**

Edge MUST NOT call `ciris-crypto::HybridVerifier` directly — that
violates the verify-via-persist single-source-of-truth
(CIRISPersist#7 closure). Phase 1 implementation pin:
`ciris-persist >= 0.4.0`.

### OQ-12: Build-manifest signing — RESOLVED A (yes, hybrid signed) — 2026-05-03

Per-release `EdgeExtras` JSON with hybrid (Ed25519 + ML-DSA-65)
signature via `ciris-build-sign`, registered with CIRISRegistry,
round-trip verified at release publication. Same pattern lens +
persist + verify use today. AV-24 closure. No "library exemption" —
every signed primitive in the federation publishes its own
provenance, including the runner binary that ships alongside the
library.
