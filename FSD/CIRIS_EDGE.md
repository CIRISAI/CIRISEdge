# FSD: CIRISEdge — Reticulum-native federation transport for the CIRIS stack

**Status:** Proposed
**Author:** Eric Moore (CIRIS Team) with Claude Opus 4.7
**Created:** 2026-05-03
**Repo:** `~/CIRISEdge` (this document is the spec; code lands in this repo)
**Risk:** Architectural. Replaces the Python edge across the federation
(lens HTTP ingest, agent HTTPS emission, registry HTTPS publication)
with a single Rust crate. No flag-day required: HTTP fallback shipped
in Phase 1 means each peer cuts over at its own pace.

---

## 1. Why this exists

The CIRIS architecture has three peers that each currently maintain
their own network edge:

- **CIRISAgent** ships signed traces over HTTPS to a hard-coded lens
  endpoint. A Python `httpx` call wrapped in retry logic. The agent's
  network identity is "wherever it can reach the lens"; there's no
  cryptographic addressing, no mesh routing, no off-grid story.
- **CIRISLens** receives traces via FastAPI on `POST /api/v1/accord/events`,
  verifies in-process via `engine.receive_and_persist`, runs PII scrub,
  writes to `trace_events` + `trace_llm_calls`. The endpoint is HTTPS
  through Cloudflare, fronted by Caddy, gated behind OAuth for the
  operator surface. ~500 lines of Python wrap what is fundamentally
  "verify a signature, hand bytes to persist."
- **CIRISRegistry** accepts build-manifest publications via HTTPS,
  responds to directory queries the same way. Same shape: thin Python
  wrapper over a verify-and-store loop.

The Proof-of-Benefit Federation FSD
(`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.2) names the
architectural collapse:

> Reticulum / Reticulum-rs — Cryptography-routed mesh networking stack.
> Destination = hash of identity public key — **addressing IS identity.**
> Multi-medium (TCP, LoRa, packet radio, serial). The Rust forks
> (Beechat's Reticulum-rs, Lew_Palm's Leviculum) are the proposed
> transport.

PoB §3.1 separately argues that CIRISLens and CIRISNode are *functions
any peer can run on data the peer already has*, not authorities — they
fold into the agent. With Reticulum as the transport and persist as the
substrate, each CIRIS peer becomes:

```
host application code
    │ registers handlers
    ▼
ciris-edge       ←── Reticulum link sessions (TCP / LoRa / serial / I²P)
    │ verify via persist
    ▼
ciris-persist    ←── steward identity, federation_keys, trace storage
    │ canonical bytes, sign / verify
    ▼
disk / OS
```

Each peer is the same shape: edge handles wire I/O, persist handles
substrate, host code handles peer-specific logic. No more three
parallel HTTP shims with three different retry policies and three
different cert-management stories.

**The Python edge is the last big gap.** Persist is Rust. The agent's
internal pipeline is heading Rust per CIRISPersist#10's architectural
inversion lesson (byte-stable crypto belongs in the substrate). The
federation transport must follow.

## 2. Scope

This FSD specifies a Rust crate, **`ciris-edge`**, that replaces the
network edge across every CIRIS peer. Delivered in three phases, each
independently shippable:

| Phase | What lands | Risk |
|---|---|---|
| **Phase 1** (immediate) | Crate skeleton with HTTP transport + Reticulum transport behind a feature flag. Ed25519 verify via persist. Typed handler dispatch. Lens-side cutover from FastAPI to embedded `ciris-edge` runner. Agent + registry stay on HTTPS, can opt into Reticulum at their pace. | Low — alongside-window with the existing Python edge. |
| **Phase 2** (federation-wide cutover) | Agent + registry adopt `ciris-edge`. HTTPS becomes a fallback per peer (operator-configurable). Build-manifest publication moves to Reticulum-native. | Medium — touches every peer; coordinated cutover by tag pin. |
| **Phase 3** (multi-medium reach) | LoRa, packet-radio, and serial transports productionized. Off-grid CIRIS deployments become tractable. | Higher — new transports = new operational surface; gated on community uptake. |
| **Out of scope** | Operator-facing HTTP (Grafana, OAuth, admin UI). Those stay on a separate FastAPI/Caddy stack at each peer that wants them. Edge is for federation peer ↔ peer traffic. |

The phases are differentiated by **transport scope and migration risk**,
not by architectural separation:

- **Phase 1** delivers the crate and proves the boundary at one peer (lens).
- **Phase 2** generalizes to the other peers; the boundary doesn't change.
- **Phase 3** adds transport variants; the boundary still doesn't change.

We commit to all three phases; we sequence them so each one stands on
its own; the crate's API surface is designed from Phase 1 to support
Phase 3 without future rewrites.

## 3. Phase 1 — Crate skeleton + lens cutover

**Outcome:** `cirislens-api`'s `POST /api/v1/accord/events` route stops
being a FastAPI endpoint and becomes a `ciris-edge` runner registered
to handle the `AccordEventsBatch` message type. The Python lens layer
keeps the operator-UI HTTP stack (Grafana proxy, OAuth, admin) but
loses the federation-traffic responsibility.

### 3.1 Crate shape

```
ciris-edge/
├── Cargo.toml              ← deps: ciris-persist, reticulum-rs, tokio,
│                              tracing, opentelemetry
├── MISSION.md              ← M-1 alignment per module (this companion doc)
├── README.md               ← short pointer; mission and FSD live next to it
├── FSD/
│   ├── CIRIS_EDGE.md       ← this file
│   ├── WIRE_FORMAT.md      ← message taxonomy + signed-bytes spec (Phase 1)
│   ├── OPEN_QUESTIONS.md   ← unresolved design forks (deferred to Phase 1+)
│   ├── INTEGRATION_LENS.md ← how lens plugs in (mirror of persist's pattern)
│   ├── INTEGRATION_AGENT.md
│   └── INTEGRATION_REGISTRY.md
├── src/
│   ├── lib.rs              ← public API surface
│   ├── transport/
│   │   ├── mod.rs          ← `Transport` trait
│   │   ├── reticulum.rs    ← Reticulum link sessions, addressing, link state
│   │   └── http.rs         ← HTTPS fallback for non-Reticulum networks
│   ├── verify.rs           ← thin wrapper around persist's lookup_public_key
│   │                          + Ed25519 verify; reject codes typed
│   ├── identity.rs         ← Reticulum identity ↔ persist steward seed;
│   │                          edge.start(persist_engine) wires them
│   ├── handler.rs          ← register_handler, dispatch, error mapping
│   ├── observability.rs    ← OTLP metrics, structured log hooks
│   └── messages/
│       ├── mod.rs          ← shared envelope + signed-bytes canonicalization
│       ├── accord.rs       ← AccordEventsBatch, PublicKeyRegistration, DSARRequest
│       ├── manifest.rs     ← BuildManifestPublication, ManifestQuery
│       └── federation.rs   ← FederationKeyDirectoryQuery, AttestationGossip
├── examples/
│   ├── echo_peer/          ← minimal: signs + sends + receives one message
│   └── lens_handler_set/   ← reference for what lens registers
└── tests/
    ├── wire_correctness/   ← round-trip byte equivalence
    ├── verify_enforcement/ ← reject-before-handler property tests
    ├── identity_boundary/  ← heap scan during sign
    ├── transport_matrix/   ← TCP × LoRa-sim × serial-sim cross-tests
    └── backpressure/       ← persist saturation; sender-visible backpressure
```

### 3.2 Public API surface

The host (lens / agent / registry) interacts with edge through a small
surface:

```rust
use ciris_edge::{Edge, EdgeConfig, EdgeError, Handler, Transport};
use ciris_persist::Engine;

// Construction. Edge takes the persist Engine (which holds steward
// identity + federation_keys directory) and a transport stack.
let edge = Edge::builder()
    .persist(persist_engine)                  // ciris-persist::Engine
    .transport(Transport::Reticulum(reticulum_config))
    .transport(Transport::Http(http_config))  // fallback; optional
    .observability(otlp_config)
    .build()?;

// Typed handler registration. One per message type the host handles.
edge.register_handler::<AccordEventsBatch, _>(|msg, ctx| async move {
    // msg is the parsed, verified payload; ctx carries
    //   - sender's signing_key_id (already resolved to identity_ref)
    //   - body_sha256 (forensic join key)
    //   - transport identifier (which network medium it arrived on)
    persist_engine.receive_and_persist(msg.canonical_bytes()).await?;
    Ok(AccordEventsResponse { accepted: msg.events.len() as u32 })
})?;

// Outbound: host sends a signed message to a destination.
let dest = edge.resolve_destination("registry-steward").await?;
edge.send::<BuildManifestPublication>(dest, manifest).await?;

// Run loop. Spawns the transport listeners + dispatch loop.
edge.run().await?;
```

### 3.3 Verify-via-persist contract

Every inbound message walks this path before reaching the handler:

```
1. Transport receives raw bytes + sender Reticulum destination
2. Edge parses the wire envelope (typed Rust struct via serde)
3. Edge extracts (signing_key_id, signature, canonical_bytes)
4. Edge calls persist.engine.lookup_public_key(signing_key_id)
   ─ if None: reject `unknown_key` (typed wire error code)
5. Edge verifies signature with the public key
   ─ if fail: reject `signature_mismatch`
6. Edge checks message-type-specific schema constraints
   ─ if fail: reject `schema_invalid`
7. Edge dispatches to the registered handler with the parsed struct
8. Handler returns Result<Response, EdgeError>
9. Edge serializes the response, signs with edge's steward identity
   via persist.engine.steward_sign(canonical), sends via transport
```

Steps 4 and 9 cross the FFI boundary into persist. Edge's process never
holds key bytes; persist owns the seeds, edge holds the `Engine` handle.

### 3.4 Wire-format envelope

The Phase 1 wire envelope (full spec in `FSD/WIRE_FORMAT.md`):

```rust
#[derive(Serialize, Deserialize)]
pub struct EdgeEnvelope {
    /// Wire format version; pinned by edge release tag.
    pub edge_schema_version: SchemaVersion,
    /// Sender's federation_keys.key_id (matches signing_key_id).
    pub signing_key_id: String,
    /// Recipient's federation_keys.key_id; lets the peer reject
    /// misrouted messages before parsing the body.
    pub destination_key_id: String,
    /// Discriminator for the body union (AccordEventsBatch,
    /// BuildManifestPublication, etc.).
    pub message_type: MessageType,
    /// Per-message timestamp; used in replay-protection windowing.
    pub sent_at: DateTime<Utc>,
    /// Random per-message nonce; replay-protection.
    pub nonce: [u8; 16],
    /// Canonical bytes (PythonJsonDumpsCanonicalizer-shaped) of the
    /// body; preserved verbatim for signature verification.
    pub body: serde_json::value::RawValue,
    /// Ed25519 signature over canonical(envelope-without-signature).
    pub signature: String,  // base64
    /// ML-DSA-65 PQC signature (base64). Required when sender's
    /// `federation_keys` row has `pubkey_ml_dsa_65_base64` populated
    /// (hybrid-complete); MAY be None when the row is hybrid-pending
    /// (`pqc_completed_at IS NULL`). Consumer-side acceptance policy
    /// (strict-hybrid / soft-hybrid+freshness / Ed25519-fallback) is
    /// per-peer config. Verify always calls
    /// `Engine.verify_hybrid()` — never `ciris-crypto` directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_pqc: Option<String>,
    /// 32-byte body_sha256 of the original envelope this is a
    /// response/ACK to. Set on response envelopes; None on first-touch
    /// envelopes. Used by the sender's edge_outbound_queue to match
    /// ACKs to originals (FSD/EDGE_OUTBOUND_QUEUE.md). Part of canonical
    /// bytes; signed and verified along with everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<[u8; 32]>,
}
```

Canonical bytes for verify use persist's
`Engine.canonicalize_envelope()` — never re-implemented in edge
(CIRISPersist#7 lesson). Replay protection: edge maintains a sliding
window of recently-seen `(signing_key_id, nonce)` pairs; persist's
existing dedup-key tuple covers application-layer replay detection.

### 3.5 Phase 1 lens cutover plan

```
1. Edge crate ships v0.1.0 with HTTP transport (Reticulum gated on a
   `reticulum` feature flag, default off until Phase 2).
2. Lens links edge alongside the existing FastAPI. The
   /api/v1/accord/events route forwards verified bytes to
   edge.dispatch() via an in-process channel. Lens runs both paths in
   shadow for ~1 minor.
3. Lens's CIRISLENS_USE_EDGE=true flag flips. New traffic goes through
   edge; legacy FastAPI route stays as fallback for one minor.
4. Lens drops the /api/v1/accord/events FastAPI route. Operator-UI
   HTTP (Grafana, OAuth, admin) keeps its FastAPI stack.
5. Same flag-flip pattern Phase 2a established for the persist
   substrate cutover. Bridge-controlled redeploy; ~10 min wall time.
```

## 4. Phase 2 — Agent + registry adoption

**Outcome:** Agent's `httpx` lens-shipping code path is replaced by
`edge.send::<AccordEventsBatch>(lens_destination, batch)`. Registry's
HTTPS publication endpoint is replaced by an `edge.register_handler`
for `BuildManifestPublication`. HTTPS becomes a fallback per peer.

The agent and registry adoption work mirrors the lens cutover with two
changes:

- Both peers gain a Reticulum identity at startup (derived from their
  steward seed via persist; same FFI boundary).
- HTTP fallback is per-peer-configurable: deployments without
  Reticulum reach (cloud-only, restrictive networks) keep HTTPS as
  primary; deployments with Reticulum reach (mobile, off-grid, mesh)
  flip to Reticulum primary.

Coordinated tag pin across CIRISAgent / CIRISRegistry / CIRISLens at
the same edge release. Same coordination pattern CIRISPersist v0.3.3
+ CIRISAgent e714ff3c4 used.

## 5. Phase 3 — Multi-medium reach

LoRa, packet-radio, serial, I²P transports productionized. The
`Transport` trait abstracts them; each transport is a separate Cargo
feature. `cargo build --features transport-lora` produces a runner
that can deploy to a Raspberry Pi with a LoRa hat.

Phase 3 is gated on community uptake — we don't ship transports
nobody's deploying. Phase 1 and 2 prove the substrate; Phase 3
proves the *pluralism* M-1 actually demands.

## 6. Module mission alignment (per MDD)

Per MDD methodology, every module has a sentence at the top of its
file naming what it serves:

| Module | One-sentence mission |
|---|---|
| `transport/` | "Carry signed bytes between sovereign peers over the network media that exist in the world." |
| `verify/` | "Ensure no application code touches a byte that hasn't been verified against persist's federation directory." |
| `identity/` | "Bind the peer's network address to its persist-managed cryptographic identity, with the seed never crossing the FFI boundary." |
| `handler/` | "Dispatch verified messages to the right host code through typed contracts that prevent mission-violating behaviors." |
| `observability/` | "Make every wire event auditable by any peer, in real time, without forensic archaeology." |

Full per-module rationale lives in `~/CIRISEdge/MISSION.md`.

## 7. Anti-patterns (call them out in PR review)

1. **Edge holding pubkey caches.** Verify is `lookup_public_key`
   per-message. If profiling shows lookup is hot, optimize persist's
   lookup, not edge's caching.
2. **Per-peer special cases in `handler/`.** Peers compose around edge,
   not into it. A handler trait variant that's "this is just for the
   lens" is the bug.
3. **HTTP-only transport configs being convenient.** Reticulum is the
   canonical wire; HTTP is documented fallback. Test matrix asserts
   Reticulum works in CI even when the deployment hosts use HTTP.
4. **Untyped message bodies.** No `&[u8]` past parse; no
   `serde_json::Value` in handler signatures. Every message has a
   concrete struct.
5. **Caller canonicalization.** `Engine.canonicalize_envelope()` only.
   Re-implementing the PythonJsonDumpsCanonicalizer rules in edge is
   exactly the CIRISPersist#7 trap.
6. **Silent reject paths.** Every wire reject produces a typed error
   code visible to the sender. "Drop and log" doesn't count as a
   federation primitive.

## 8. Test categories

Mirroring the MDD test taxonomy:

| Category | What a passing test asserts |
|---|---|
| **Wire correctness** | Round-tripped bytes are byte-equivalent at the destination, across all configured transports. |
| **Verify enforcement** | A handler is never invoked for a message that fails any of the verify pipeline's seven steps. |
| **Identity boundary** | Edge's heap contains no seed-shaped bytes during or after a sign operation (property test). |
| **Transport matrix** | The same message round-trips successfully over TCP, simulated LoRa, simulated serial. |
| **Backpressure** | When persist's queue is saturated, senders observe edge-applied backpressure rather than silent message loss. |
| **Replay protection** | A message replayed within the dedup window rejects with `replay_detected`; outside the window, it passes verify but persist's AV-9 dedup catches it. |
| **Forensic completeness** | A replayed-from-logs scenario reconstructs the message + verify outcome from structured-log output alone. |
| **Spec drift** | A message at an unrecognized `edge_schema_version` rejects with typed `UnsupportedSchemaVersion`; never falls through to a handler. |

## 9. Build-manifest provenance for `ciris-edge` itself

Every signed primitive in the federation publishes its own provenance.
`ciris-edge` follows the same pattern lens uses today
(`scripts/emit_lens_extras.py` + `.github/workflows/docker-publish.yml`):

- Per-release `EdgeExtras` JSON (FSD content hash, wire-format spec
  hash, transport feature matrix, persist version pin).
- Hybrid Ed25519 + ML-DSA-65 signature via `ciris-build-sign`
  (transitively installed when persist's wheel is in the build env).
- Registered with CIRISRegistry on every release.
- Round-trip verified before the release tarball publishes.

## 10. Open questions

Decisions that need owner input before Phase 1 implementation starts.
Tracked in `FSD/OPEN_QUESTIONS.md` — don't restate here.

## 11. Out-of-scope (and why)

| Excluded | Why |
|---|---|
| Operator-facing HTTP (Grafana, OAuth, admin UI) | Different concern (operator UX vs federation transport). Stays on FastAPI/Caddy at each peer. |
| OTLP trace ingestion | Has its own ecosystem (otelcol, Tempo, etc.). Lens ingests OTLP via the existing collector; edge handles signed federation messages. |
| Transport-level encryption | Reticulum provides it natively; HTTP fallback uses TLS. Edge doesn't add a third encryption layer. |
| Authentication beyond signature | Federation auth IS signature verification against the federation directory. OAuth, OIDC, mTLS are operator-UI concerns, not federation concerns. |
| Inter-message orchestration | Edge is a transport. Workflow / saga / multi-message coordination is host-code responsibility. |

## 12. References

- Mission: `~/CIRISEdge/MISSION.md` — M-1 alignment per module.
- Open questions: `FSD/OPEN_QUESTIONS.md` — decisions that need owner input.
- MDD methodology: `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`.
- Reticulum-rs proposal: `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.2.
- Architectural collapse argument (lens + node fold into agent):
  `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.1.
- Persist substrate (wire-format authority + key management):
  `~/CIRISPersist/MISSION.md`, `~/CIRISPersist/FSD/CIRIS_PERSIST.md`.
- Wire-format precedent (drift-resistant single-source-of-truth):
  `~/CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ v2.7.9-stable`.
