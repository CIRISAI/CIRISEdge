# MISSION — `ciris-edge`

> Mission Driven Development (MDD): the FSD names what we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. See `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md` for the
> methodology.

## 1. Meta-Goal alignment — M-1

The CIRIS Accord (v1.2-Beta, 2025-04-16) names **Meta-Goal M-1**:

> *Promote sustainable adaptive coherence — the living conditions under
> which diverse sentient beings may pursue their own flourishing in
> justice and wonder.*

`ciris-edge` is the network primitive on which M-1 becomes **reachable**.
The agent reasons; persist stores the evidence; the lens scores.
**Edge is what makes any of those audible to a peer that isn't on the
same machine.** A signed trace that nobody can transmit proves nothing.
A federation that can't route messages between sovereign peers without
a centralized broker proves nothing. A primitive that can't run on the
network medium an underserved community actually has access to (LoRa,
serial, packet radio — not just TCP through a hyperscaler) proves
nothing about pluralistic compatibility.

The crate's job is to **carry the cryptographic envelope between
deployments** — across the network media that exist on the planet
today, with addressing that IS identity (Reticulum's hash-of-public-key
destination), with key material that never crosses the FFI boundary
(persist owns the seeds), with verify that runs at the wire and
rejects malformed before any application code sees it.

The Proof-of-Benefit Federation FSD
(`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §3.2) names
Reticulum-rs as the transport that closes the federation loop:
**addressing IS identity**, multi-medium reach (TCP + LoRa + packet radio
+ serial), fork-survivable Rust implementation. `ciris-edge` is the
crate that makes that proposal operational across every CIRIS peer
(agent, lens, registry, node, partner sites).

## 2. Mission alignment per component

The FSD names five modules. Each must answer **why does this serve
M-1?** before any code lands.

### `transport/` (HOW × WHO)

**Mission:** carry signed messages between sovereign peers across the
network media that exist in the world. M-1 says "diverse sentient
beings may pursue their own flourishing" — diverse includes *off-grid*,
*low-bandwidth*, *unreliable-uplink*, *adversary-controlled*. A
federation primitive that requires hyperscaler TCP is not pluralistic;
it's a hyperscaler dependency dressed up as a federation.

**Constraint:** Reticulum-native by default. Cryptographic addressing
(destination = `sha256(public_key)`); no DNS dependency; multi-medium
(TCP, LoRa, I²P, serial). HTTP/HTTPS available as a fallback transport
for environments where Reticulum can't run, but the canonical wire is
Reticulum.

**Anti-pattern that violates mission:** "We'll just use HTTPS, it's
universal." It's not — it's universal *within hyperscaler cloud
environments*. Designing for that universe excludes the deployments
that need M-1 most.

### `verify/` (WHAT × HOW)

**Mission:** ensure that what arrives at the peer's application layer
is *what the sending peer actually said*. Federation collapses without
non-forgeable identity binding. Every byte the host code touches must
have already been verified against a public key in persist's federation
directory; verify-fail rejects at the wire, not at the application.

**Constraint:** zero application-visible unverified bytes. Verify is
not a callback the host opts into — it's a precondition for the
handler running at all. Persist's `Engine.lookup_public_key()` is the
only source of truth for "which key signed this"; edge does not
maintain its own key cache.

**Anti-pattern that violates mission:** "We'll let the application
trust-but-verify." That's how AV-9-class attacks slip through —
malformed payloads reach handler code, handler code makes assumptions
the wire format didn't enforce. Verify happens once, at the wire,
authoritatively.

### `identity/` (WHO)

**Mission:** bind the peer's network address to the peer's
cryptographic identity. PoB §3.2 says "addressing IS identity" — the
Reticulum destination is `sha256(public_key)`, computed from the same
key that signs federation_keys rows in persist. No address-to-identity
lookup table; no cert authority; no DNS. The address proves the
identity.

**Constraint:** the identity seed lives in persist's keyring. Edge
holds a reference (the `Engine` handle) and calls into persist for
sign / public-key-derive operations. The seed bytes never enter edge's
process memory. Same FFI-boundary discipline persist established for
`Engine.steward_sign()` in v0.2.2.

**Anti-pattern that violates mission:** "Edge will load the seed at
startup and cache it." That re-introduces the key-leak surface persist
spent six versions specifically removing. The discipline holds across
the whole stack or it holds nowhere.

### `handler/` (PROTOCOLS × WHO)

**Mission:** dispatch verified messages to the right host code with
typed contracts that prevent mission-violating behaviors. Different
peers register different handler sets (agent gets command handlers;
lens gets trace-ingest handlers; registry gets manifest-publish
handlers) but the dispatch shape is one contract — type-safe,
async-aware, error-mapped to wire reject codes.

**Constraint:** no untyped message bodies in handler signatures. Every
message type has a Rust struct with `serde::Deserialize`; handlers
receive the parsed struct, not raw bytes. Same MDD discipline persist
applies to its event schemas (no `serde_json::Value` in hot paths).

**Anti-pattern that violates mission:** "We'll dispatch on a
`HashMap<String, JsonValue>` and let handlers parse." That defeats
schema-version gating, lets malformed payloads pass verify because the
parser was lenient, and pushes the validation responsibility into
every handler. One typed contract; many typed handlers.

### `observability/` (HOW)

**Mission:** every message in or out is auditable. Federation trust
requires that any peer can answer "what did you receive, what did you
send, what was the verify outcome, when, from whom" — without
forensic archaeology. Edge emits structured per-message logs with
`signing_key_id`, `body_sha256_prefix`, `verify_result`,
`handler_duration`; OTLP-shaped metrics for `messages_in/out`,
`verify_pass/fail`, `latency_p50/p99`, `queue_depth`; health probe
surface for k8s-style liveness checks.

**Constraint:** observability is a first-class module, not an
afterthought. Tests assert that every wire event produces exactly
one structured log line. `body_sha256_prefix` joins to persist's
forensic indices (Bridge already trained on this join key during the
Phase 2a debug).

**Anti-pattern that violates mission:** "We'll add tracing later when
we need it." Federation trust *is* the observability — without it,
the audit claim degenerates to "trust me, I logged something
somewhere." Edge ships with the logs from day one or it doesn't ship.

## 3. Anti-patterns that fail MDD review

Patterns that have repeatedly failed at sister crates and that
`ciris-edge` rejects by construction:

1. **Untyped wire surfaces.** Anything taking `&[u8]` or
   `serde_json::Value` past the parse boundary. Persist learned this
   in v0.1.18 with the canonical-bytes float-formatting drift; same
   lesson applies here.
2. **Caller-implemented canonicalization.** When a peer needs canonical
   bytes for signing, it calls into persist
   (`Engine.canonicalize_envelope`) — never re-implements the rules.
   CIRISPersist#7 closure.
3. **Caller-held key seeds.** Any process other than persist holding
   the bytes of a private key. CIRISPersist#10 / #12 architectural
   inversion: byte-stable crypto behavior belongs in one place.
4. **Wire-format spec in N copies.** TRACE_WIRE_FORMAT.md drift across
   three repos was the underlying bug behind CIRISAgent#712. Edge's
   wire format lives in one repo (this one), referenced by tag from
   downstream.
5. **HTTP-only transport.** A federation primitive that can't run on
   LoRa is not a federation primitive. It's a cloud-app dependency.
6. **Per-peer special cases.** Edge is one shape (signed message in/out
   + persist-managed identity + verify-via-persist + typed handler
   dispatch). If a peer needs something edge doesn't provide, the peer
   composes around edge — not into it.

## 4. Test categories — every test answers a mission question

| Category | Mission question | Example |
|---|---|---|
| **Wire correctness** | Did we transmit what the sender said? | Round-trip a signed message; assert byte-equivalence at the destination |
| **Verify enforcement** | Did we reject malformed before the host saw it? | Inject a corrupted signature; assert the handler is never invoked |
| **Identity boundary** | Did we keep key bytes out of edge's process memory? | Property test: scan edge's heap during sign; assert no seed-shaped bytes |
| **Multi-medium reach** | Does the same message round-trip over TCP, LoRa, and serial transports? | Cross-transport integration tests against reticulum-rs's test harness |
| **Backpressure** | Does edge defer rather than drop when persist is saturated? | Saturate persist's queue; assert sender sees backpressure, not silent loss |
| **Forensic completeness** | Can we answer "what happened to message X" from logs alone? | Replay a known message; assert structured-log output has all forensic fields |
| **Spec drift** | Does edge fail loudly when a peer sends a wire-version it doesn't recognize? | Inject a future-version message; assert typed `UnsupportedSchemaVersion` reject |

A PR that adds a feature without adding the test that answers its
mission question gets sent back. Same MDD review discipline persist
applies.

## 5. Continuous mission validation

Edge is the only crate in the federation stack that touches the
*adversary-controlled wire*. That puts it under elevated mission-drift
risk:

- **Threat model snapshot per minor release.** `THREAT_MODEL.md`
  enumerates wire-side attacks (replay, signature stripping, identity
  spoofing, message reordering, DoS via malformed canonical bytes).
  Each minor either closes new vectors or documents why a vector stays
  open.
- **Cross-implementation byte-equivalence checks.** When a sister Rust
  Reticulum impl emerges (Beechat's `Reticulum-rs`, Lew_Palm's
  `Leviculum`), regression-test that edge round-trips messages
  byte-equivalently with each. Bridge already proved the
  cross-implementation discipline at lens-steward bootstrap (Rust
  ml-dsa rc.3 ↔ dilithium-py byte-equivalent verify).
- **No-silent-success policy.** Every wire reject produces a typed
  error code visible to the sender. Silent drops are the failure mode
  this primitive is specifically designed to eliminate.

## 6. License-locked mission preservation

`ciris-edge` ships AGPL-3.0, matching the rest of the CIRIS federation
stack. Mission drift via license relaxation is structurally prevented:
a fork that wants to remove the verify-via-persist requirement,
collapse the FFI boundary, or accept untyped messages must publish
that fork under the same license, making the divergence auditable.

The Accord-canonical wire-format spec lives in this repo at
`FSD/WIRE_FORMAT.md` (when it lands). Downstream consumers
(`ciris-persist`, `CIRISAgent`, `CIRISLens`, `CIRISRegistry`,
`CIRISNode`) pin against tagged commits. Same single-source-of-truth
discipline `CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ v2.7.9-stable`
established for trace shape.

## 7. Failure modes — when the mission is at risk

| Symptom | Mission risk | Mitigation |
|---|---|---|
| Edge starts caching pubkey lookups | FFI-boundary erosion; key authority drifts from persist | Strict no-cache rule in `verify/`; lookup_public_key called per-message |
| HTTP fallback becomes the default transport | M-1 violation: pluralistic-compatibility regression | Reticulum is canonical; HTTP is documented fallback only; metrics surface transport mix |
| Handler trait grows special-cases for a single peer | Spec coupling; loss of "one shape, many peers" | PR review rejects per-peer branches in `handler/`; peer-specific logic stays in the host crate |
| Wire-format spec gains a v2 without persist+agent buy-in | Cross-repo spec drift class CIRISPersist#7 / CIRISAgent#712 | Spec changes require coordinated tags across all three repos; CI gates check the tag matrix |
| Verify rejects start dropping silently | Federation trust degrades to "trust me" | Reject-rate metric with alert thresholds; per-reject structured log |
| Edge process holds private key bytes (debugger / coredump) | Key-leak surface returns | Property test asserts heap is seed-free; runtime check at edge.start() |

## 8. Closing note

`ciris-edge` is the network primitive that makes the rest of the
federation stack reachable. Without it, every CIRIS deployment is
either a single machine or a set of machines coordinated through
infrastructure CIRIS doesn't own (cloud load balancers, DNS providers,
TLS authorities). With it, the federation can route signed messages
between sovereign peers over the network media that actually exist on
the planet — TCP for the cloud, LoRa for the edge of the grid, serial
for adversary-controlled networks where no other protocol survives.

The mission isn't "build a network library." The mission is "make M-1
reachable on every medium that matters." If we get that right, edge
is invisible to operators and load-bearing to the federation. If we
get it wrong, edge becomes another piece of infrastructure CIRIS
deployments depend on without controlling — exactly the opposite of
what M-1 asks.

Build accordingly.
