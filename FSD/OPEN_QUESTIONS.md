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

## OQ-01: Library vs sidecar

**Question:** Does `ciris-edge` ship as a Rust library each peer links
into its own runtime, or as a separate binary/sidecar process that
peers talk to over IPC?

**Options:**
- **A — Library:** Edge is a Rust crate. Each peer (`cirislens-api`,
  `ciris-agent`, `ciris-registry`) links it directly alongside
  `ciris-persist`. One process per peer; FFI boundary stays inside
  persist.
- **B — Sidecar:** Edge runs as a separate process. Peers talk to it
  over a Unix socket / gRPC / shared memory. Edge owns the Reticulum
  identity locally and exposes a sign-and-send API.

**Trade-offs:**

| Dimension | Library | Sidecar |
|---|---|---|
| FFI-boundary discipline | Same as today (persist owns seeds; edge holds Engine handle) | Re-litigated (sidecar holds Reticulum identity; new key-leak surface) |
| Deployment complexity | One process per peer | Two processes per peer; new sidecar lifecycle to manage |
| Multi-language reach | Rust-native; non-Rust peers (Python lens for now) need PyO3 bindings | Language-agnostic via local socket; any peer can talk to it |
| Process isolation | Edge fault crashes the host | Edge fault is contained; host can detect and reconnect |
| Memory footprint | Shared with host | Separate; multiplies per peer |
| Testing | Unit-test against in-memory persist | Integration-test against running sidecar |

**Lens-side default:** Library. The whole point of persist's FFI
boundary is "keys never cross process memory." A sidecar re-introduces
the boundary problem (sidecar process holds Reticulum identity) at a
new layer, and CIRISPersist#10 just argued this exact pattern down at
the cold-path PQC level. Multi-language reach is a real concern but
PyO3 bindings (which lens already uses for `ciris-persist`) handle the
Python case; the agent and registry are headed to Rust anyway.

**Status:** OPEN — waiting on confirmation from agent + registry teams.

---

## OQ-02: HTTP fallback for federation transport

**Question:** Does `ciris-edge` ship an HTTP/HTTPS transport alongside
Reticulum, or is the federation Reticulum-only?

**Options:**
- **A — Reticulum-only:** Federation traffic uses Reticulum exclusively.
  Deployments without Reticulum reach (cloud-only, restrictive
  networks, environments where you can't run a daemon) can't
  participate.
- **B — HTTP fallback:** Both transports ship. Reticulum is canonical;
  HTTP is documented fallback. Per-peer config decides the default.
  Wire format is identical across transports (signed envelope is
  transport-agnostic).
- **C — HTTP shim:** HTTP is the default; Reticulum is opt-in. Same
  shape as B but with the polarity flipped.

**Trade-offs:**

| Dimension | Reticulum-only | HTTP fallback | HTTP shim |
|---|---|---|---|
| Pluralism (M-1) | Strong on the edge (LoRa, off-grid) | Strong both directions | Weak on the edge |
| Cloud deployability | Requires Reticulum daemon in cloud env (doable, not standard) | Works out of the box | Works out of the box |
| Spec surface | One transport to spec | Two | Two |
| Test matrix | One transport to test | Two | Two |
| Migration cost from current Python edge | High (every peer needs Reticulum at deploy day) | Low (peers cut over at their pace) | Low |
| Adversary-resistance | Reticulum's mesh routing is harder to censor | HTTP can be MITM'd at the cert authority | HTTP can be MITM'd |

**Lens-side default:** B (HTTP fallback). The mission demands
pluralism (LoRa, off-grid, adversary-controlled networks) — that's
not negotiable. But Reticulum-only at Phase 1 is operationally
prohibitive — every cloud deployment would need to set up Reticulum
just to participate. HTTP fallback during Phase 1-2 lets the federation
exist now; Phase 3 productionizes the multi-medium transports for the
deployments that need them.

**Status:** OPEN — depends on whether agent + registry teams want to
commit to Reticulum at deploy day or want the fallback option.

---

## OQ-03: Wire-format scope — federation messages only, or also OTLP?

**Question:** Does `ciris-edge` carry only signed federation messages
(traces, key registrations, manifest publications, federation gossip),
or does it also handle OTLP trace ingestion (currently a separate
collector at the lens)?

**Options:**
- **A — Federation-only:** Edge carries signed federation messages.
  OTLP traces (the OpenTelemetry-shaped data agents emit for
  metrics/observability) stay on a separate ingestion path
  (otelcol → Tempo / Mimir / Loki, the Grafana stack lens runs today).
- **B — Edge subsumes OTLP:** Edge becomes the universal trace ingest.
  OTLP shapes get packaged into edge envelopes; the otelcol collector
  goes away.

**Trade-offs:**

| Dimension | Federation-only | Edge subsumes OTLP |
|---|---|---|
| Spec scope | Tight (CIRIS messages) | Wide (CIRIS + OTLP) |
| Existing tool reuse | Grafana ecosystem keeps working | Need adapters for Tempo/Mimir |
| Deduplication of "trace" concept | Two trace surfaces (signed CIRIS + OTLP) | One trace surface |
| Migration cost | None (OTLP path untouched) | High (lens's Grafana dashboards rebind) |

**Lens-side default:** A (federation-only). OTLP has its own ecosystem
(otelcol, Tempo, Mimir) that's mature and well-served by Grafana. The
two trace surfaces serve different purposes — signed-CIRIS is
federation evidence; OTLP is operator observability. Conflating them
multiplexes concerns and breaks the existing Grafana investment.

**Status:** OPEN — but lens has a strong default here.

---

## OQ-04: Migration path from existing Python edge

**Question:** Does the cutover from current Python edge (lens FastAPI,
agent httpx, registry HTTPS) to `ciris-edge` happen as a flag-day, or
in an alongside-window with both running concurrently?

**Options:**
- **A — Flag-day:** Phase 2a-style flag flip.
  `CIRISLENS_USE_EDGE=true` switches all federation traffic to edge at
  once. Old Python paths retire immediately.
- **B — Alongside-window:** Edge runs alongside Python edge for ~1
  minor. Traffic mirrors to both; lens compares results; once the
  comparison is clean for the soak window, Python edge retires.
- **C — Per-message-type:** Different message types cut over at
  different cadences. AccordEventsBatch first; PublicKeyRegistration
  second; etc.

**Trade-offs:**

| Dimension | Flag-day | Alongside-window | Per-message-type |
|---|---|---|---|
| Risk | High (atomic cutover) | Low (gradual) | Medium |
| Complexity | Low (one flag) | High (mirror, compare, drift detection) | Highest (per-type config) |
| Operator surface | One change | Two paths to monitor | N paths |
| Bug discovery | At cutover | Pre-cutover via shadow comparison | Phased |

**Lens-side default:** B (alongside-window). Same playbook
CIRISPersist used for the v0.2.x substrate cutover (Phase 1 wired idle,
Phase 2a delegated, Phase 2b retired legacy). It worked then; same
shape now. Lens's `accord_api.py` keeps the FastAPI route during
Phase 1; edge's HTTP transport handles the same shape; Phase 1 ends
with the FastAPI route deleted.

**Status:** OPEN — depends on bridge's appetite for shadow-comparison
ops (which they did fine at v0.2.x).

---

## OQ-05: Versioning and spec authority

**Question:** Where does the edge wire-format spec live, and how do
downstream peers pin against it?

**Options:**
- **A — In `~/CIRISEdge/FSD/WIRE_FORMAT.md`:** Spec lives in the
  `ciris-edge` repo. Downstream peers (`CIRISAgent`, `CIRISLens`,
  `CIRISRegistry`) pin against tagged commits. Same precedent
  CIRISAgent set with `TRACE_WIRE_FORMAT.md @ v2.7.9-stable`.
- **B — In `~/CIRISAgent/FSD/`:** Spec lives in the agent repo
  alongside TRACE_WIRE_FORMAT.md. Edge pins against an agent tag.
- **C — In a separate `CIRISFederationSpec` repo:** Neutral spec home;
  every peer pins against it.

**Trade-offs:**

| Dimension | Edge-owned | Agent-owned | Separate spec repo |
|---|---|---|---|
| Spec authority | Clear (edge owns its wire) | Awkward (transport spec in agent repo) | Neutral but bureaucratic |
| Tag coordination | One repo per concern | Two repos to update | Three repos to update |
| Drift surface | Low | Medium (cross-repo dependency) | Low |

**Lens-side default:** A (edge-owned). The spec for the network wire
naturally lives with the network primitive. Same pattern persist owns
its `PUBLIC_SCHEMA_CONTRACT.md` for the substrate's column contract,
and CIRISAgent owns `TRACE_WIRE_FORMAT.md` for the trace shape. Edge
owns the envelope shape and the message-type discriminators; downstream
peers pin against `ciris-edge @ vX.Y.Z`.

**Status:** OPEN — but lens has a strong default; mostly need agent +
registry buy-in.

---

## OQ-06: Multi-worker concurrency model

**Question:** Lens runs multi-worker uvicorn today. How does
`ciris-edge` handle multi-worker hosts?

**Options:**
- **A — Single edge instance per host:** One edge process per host,
  fanning out to multiple worker tasks for handler dispatch. Reticulum
  identity is the host's; workers share it.
- **B — Multi-instance with persist serialization:** Each uvicorn
  worker constructs its own `Edge`. Persist's existing
  advisory-lock-on-init handles multi-worker boot; identity is the
  same across workers (single steward seed); each instance owns its
  own transport sessions.
- **C — Edge as separate process (sidecar):** See OQ-01.

**Trade-offs:**

| Dimension | Single edge / fanout | Multi-instance | Sidecar |
|---|---|---|---|
| Reticulum sessions | One per host (clean) | N per host (each instance has its own session) | One per host |
| Multi-worker safety | Edge handles its own concurrency | Persist handles it (already proven) | Sidecar handles it |
| Failure domain | Edge crash takes down host federation | Per-worker crash; host stays up | Edge crash isolated |
| Inbound message dedup | Single-instance dedup window | Need cross-worker dedup (persist's AV-9 covers it) | Single-instance dedup |

**Lens-side default:** B (multi-instance with persist serialization).
Persist already handles multi-worker boot via advisory lock; that
discipline generalizes. Reticulum sessions per-worker is more
expensive but clean — each worker has its own link state, no shared
mutable state between workers, persist's dedup catches duplicates.

**Status:** OPEN — depends on what reticulum-rs's session model
supports cleanly. Worth empirical testing with the chosen reticulum
crate before committing.

---

## OQ-07: Reticulum-rs vs Leviculum

**Question:** Which Rust Reticulum implementation does edge link
against?

**Options:**
- **A — Beechat's `Reticulum-rs`:** The original Rust port; closer to
  upstream Python Reticulum protocol semantics; smaller community.
- **B — Lew_Palm's `Leviculum`:** Independent Rust implementation;
  larger community uptake; some protocol divergence from upstream.
- **C — Both via a `Transport` trait:** Edge's transport layer
  abstracts over either implementation; downstream peers pick at build
  time.

**Trade-offs:**

| Dimension | Reticulum-rs | Leviculum | Both |
|---|---|---|---|
| Protocol fidelity to upstream | Higher | Lower | Either |
| Community uptake | Smaller | Larger | Composable |
| Maintenance burden | One impl to track | One impl to track | Two impls |
| Cross-impl byte-equivalence test | Trivially passes (one impl) | Trivially passes | Becomes a real test (PoB §3.2 mentions both) |

**Lens-side default:** C (both via Transport trait). PoB §3.2
explicitly names both as "fork-survivable Rust implementations" — the
mission-aligned move is to keep both viable. The Transport trait
abstracts the difference; integration tests assert byte-equivalent
round-trip across both. If one fork dies, the other carries the
federation forward.

**Status:** OPEN — needs empirical evaluation of both crates' API
ergonomics + test coverage.

---

## OQ-08: Replay protection window size

**Question:** How wide is edge's `(signing_key_id, nonce)` replay-
protection window?

**Options:**
- **A — Short (e.g. 60 seconds):** Tight window; replay attacks must
  fire within it. Lower memory cost; risk of false-rejecting
  legitimate retries during network blips.
- **B — Medium (e.g. 5 minutes):** Mid-ground. Enough slack for
  retry-on-network-blip; bounded memory.
- **C — Long (e.g. 1 hour):** Wide window catches most replay
  scenarios. Higher memory cost; lower false-reject rate.
- **D — Per-peer-configurable:** Operators decide based on their
  network reliability + threat model.

**Lens-side default:** B (5 minutes) for Phase 1, with D
(per-peer-configurable) as the Phase 2 evolution. Persist's AV-9
dedup catches application-layer replay regardless; edge's window is
defense-in-depth at the wire.

**Status:** OPEN — needs threat-model write-up to ground the choice.

---

## OQ-09: Outbound queue / retry policy

**Question:** When `edge.send(dest, msg)` fails (transport unavailable,
destination unreachable), what does edge do?

**Options:**
- **A — Fail fast:** Return `EdgeError::Unreachable` immediately.
  Caller decides whether to retry.
- **B — Bounded queue with retry:** Edge maintains a per-destination
  outbound queue; retries with exponential backoff up to some limit.
  Caller sees success on enqueue.
- **C — Persistent queue:** Edge writes outbound to persist (a new
  table) and retries from there; survives process restart.

**Trade-offs:**

| Dimension | Fail fast | Bounded retry | Persistent |
|---|---|---|---|
| Caller complexity | High (callers implement retry) | Low | Low |
| Memory cost | None | Bounded | Disk |
| Restart survival | Caller's responsibility | Lost on restart | Survives |
| Failure surface | Caller-visible | Edge-internal | Persist-visible |

**Lens-side default:** B (bounded retry) for Phase 1, with C
(persistent) as a future option. Most federation traffic is
high-frequency and short-lived; persistent queues are overkill for the
common case. For build-manifest publication (low-frequency, important
to land), C makes sense — but those are also the messages where
caller-implemented retry is fine.

**Status:** OPEN.

---

## OQ-10: Operator-UI HTTP integration

**Question:** Edge handles federation peer ↔ peer traffic. Lens (and
maybe other peers) also serves operator-UI HTTP (Grafana proxy, OAuth,
admin pages). Does edge offer any integration with that, or is it
strictly out of scope?

**Options:**
- **A — Strictly out of scope:** Edge is federation-only. Operator-UI
  HTTP stays on a separate FastAPI/Caddy stack each peer composes for
  itself.
- **B — Edge offers an "operator transport" alongside federation:**
  Same HTTP transport that handles federation fallback also serves
  operator UIs, with auth-pluggable middleware.
- **C — Edge offers an HTTP listener bindable to non-federation
  routes:** Hosts can mount their FastAPI app on the same listener
  edge uses for HTTP federation fallback.

**Trade-offs:**

| Dimension | Out of scope | Operator transport | Bindable listener |
|---|---|---|---|
| Spec scope | Tight | Wide (auth concerns enter edge) | Medium |
| Operator UX | Two listeners per host | One listener | One listener |
| Auth concerns | Stay out of edge | Enter edge | Stay out of edge (host-mounted) |

**Lens-side default:** A (strictly out of scope). Operator UX is a
different concern than federation transport. Lens already runs Caddy
+ FastAPI for the operator surface; that's well-served. Edge mounting
auth-pluggable middleware would multiplex concerns and pull OAuth /
session-management into the federation transport spec — a bad trade.

**Status:** OPEN — but lens has a very strong default.

---

## OQ-11: PQC verify timeline

**Question:** Edge's wire envelope reserves `signature_pqc` for ML-DSA-
65 hybrid signatures. When does edge actually *verify* the PQC
component (vs accept-but-not-verify)?

**Options:**
- **A — Phase 1: accept, never verify:** Edge accepts PQC sigs in the
  envelope but never validates. Same posture as persist v0.3.x for the
  cold-path-signed federation_keys rows.
- **B — Phase 1: verify when present:** Edge runs PQC verify whenever
  `signature_pqc` is non-null. Persist's verifier path needs to expose
  the primitive.
- **C — Phase 2+: hard-PQC required:** Edge requires PQC verify on
  every message. Quantum-threat-flip-day posture.

**Trade-offs:**
- A matches persist's current state (no PQC verifier in the substrate
  yet).
- B requires persist to ship PQC verify in `Engine` first; couples
  edge's release to persist's roadmap.
- C is the future end-state, gated on quantum threat materializing.

**Lens-side default:** A for Phase 1; B once persist exposes
`Engine.verify_pqc(canonical, classical_sig, pqc_sig, public_key)`;
C as Phase 4+ when policy flips.

**Status:** OPEN — coordination point with persist roadmap.

---

## OQ-12: Build-manifest signing for `ciris-edge` releases

**Question:** Does `ciris-edge` publish its own signed build manifest
to CIRISRegistry on every release?

**Options:**
- **A — Yes, same pattern lens uses:** `EdgeExtras` JSON, hybrid sig
  via `ciris-build-sign`, registered with CIRISRegistry, round-trip
  verified.
- **B — No, edge is "library-only" and doesn't ship a runnable
  artifact:** Persist's wheel + the consuming peer's binary are what
  get signed; edge as a library is a transitive dependency.

**Lens-side default:** A. Every signed primitive in the federation
publishes its own provenance — there's no "library exemption." Edge
ships a runner binary alongside the library (`cargo install
ciris-edge`); that runner has a signed manifest.

**Status:** OPEN — easy yes, just confirming.

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

**Status:** OPEN — Phase 3 concern; not blocking Phase 1.

---

## CLOSED

(Empty until questions get resolved.)
