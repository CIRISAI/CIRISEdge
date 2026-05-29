# CIRISEdge Threat Model

**Status:** v0.17.x production-grade — Reticulum + HTTPS transports both
shipped at production grade (HTTPS promoted from "fallback" to
fully-equivalent transport at v0.13.0 CIRISEdge#23 Track B);
authenticated `PeerResolver` cold-start (AV-42, v0.4.0); UniFFI binding
surface (v0.13.0 CIRISEdge#36 GO); 6-capsule cohabitation handoff with
`local_signer` for the Reticulum transport identity (v0.16.1 main-line
cherry-pick of v0.13.1 patch line, CIRISEdge#43); ~210 tests across the
verify / replay / authenticated-resolution / links / routing / peer-mgmt
/ SAS surfaces. Prior baseline: v0.0 spec-only scaffold at `3fc4ab0`.
Updated each minor release.
**Audience:** federation peers integrating against `ciris-edge`, security
reviewers, downstream substrate consumers (`CIRISLens`, `CIRISAgent`,
`CIRISRegistry`).
**Companion:** [`MISSION.md`](../MISSION.md), [`FSD/CIRIS_EDGE.md`](../FSD/CIRIS_EDGE.md),
[`FSD/OPEN_QUESTIONS.md`](../FSD/OPEN_QUESTIONS.md).
**Inspired by:** [`CIRISVerify/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md)
(structural template), [`CIRISProxy/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISProxy/blob/main/docs/THREAT_MODEL.md)
(transport-class adjacency), [`CIRISPersist/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/THREAT_MODEL.md)
(verify-and-persist substrate).
**Federation primitives addressed:** N1 (cryptographic addressing) and N2
(multi-medium transport) — the two primitives the federation meta threat
model (`FEDERATION_THREAT_MODEL.md` §5) lists as unfilled. CIRISEdge is
the substrate that fills both.

---

## 1. Scope

### What CIRISEdge Protects

CIRISEdge is the federation transport substrate. It carries cryptographic
envelopes between sovereign peers across whatever network media exist
(TCP, LoRa, packet radio, serial, I²P, HTTP fallback). Per MISSION.md §2
it protects:

- **Wire-edge integrity**: no application code touches a byte that hasn't
  been verified against `persist.engine.lookup_public_key()`. Verify is a
  precondition for handler dispatch, not an opt-in.
- **Cryptographic addressing**: per PoB §3.2, the Reticulum destination
  is `sha256(public_key)[..16]` — the address IS the identity. No DNS,
  no certificate authority, no out-of-band binding. Forging an address
  requires forging the underlying public key.
- **FFI boundary discipline**: the steward seed lives in `ciris-persist`'s
  keyring; edge holds the `Engine` handle and calls into persist for
  every sign / verify operation. The seed bytes never enter edge's
  process memory. Same discipline persist established in v0.2.2 for
  `Engine.steward_sign()` (CIRISPersist#10).
- **Verify-via-persist contract**: edge does not maintain its own
  public-key cache or canonicalization implementation. Persist's
  `lookup_public_key()` and `canonicalize_envelope()` are the single
  sources of truth. Re-implementing either in edge is the
  CIRISPersist#7 trap.
- **Replay protection within a bounded window**: edge maintains a
  sliding window (5 min in Phase 1 per `OPEN_QUESTIONS.md` OQ-08) of
  recently-seen `(signing_key_id, nonce)` pairs. Beyond the window,
  persist's dedup tuple `(agent_id_hash, trace_id, thought_id,
  event_type, attempt_index, ts)` (CIRISPersist AV-9 closure) catches
  application-layer replay.
- **Typed handler dispatch**: no `&[u8]` or `serde_json::Value` past
  the parse boundary. Every message type has a Rust struct with
  `serde::Deserialize`; handlers receive parsed structs, not raw bytes.
- **Wire-event auditability**: every message in or out emits exactly
  one structured log line with `signing_key_id`, `body_sha256_prefix`,
  `verify_result`, `handler_duration`. Forensic completeness is a test
  category, not an afterthought.
- **Multi-medium reach**: the same wire envelope round-trips
  byte-equivalent across all configured transports. M-1 demands the
  primitive runs on the network media that exist on the planet, not
  just the ones convenient for hyperscaler deployments.

### What CIRISEdge Does NOT Protect

- **Compromised steward keys** (AV-2 class — persist's threat model
  owns; the verifier cannot distinguish stolen-key from legitimate).
  Detection is statistical via N_eff drift over time (PoB §2.4 + §5.6,
  RATCHET).
- **Federation directory poisoning**. The `accord_public_keys` /
  `federation_keys` directory is persist's responsibility. Edge calls
  into it; if it's owned, edge's verify is meaningless.
- **Build-time supply chain compromise**. CIRISVerify owns build
  attestation; edge's release tarball is signed via `ciris-build-sign`
  hybrid (Ed25519 + ML-DSA-65) and registered with CIRISRegistry, but
  the upstream attestation infrastructure is CIRISVerify's threat model.
- **Application-layer authorization**. Edge dispatches verified
  messages to typed handlers; whether the host application *should*
  process a given message under the application's policy is host-code
  responsibility.
- **TLS termination on HTTP fallback**. The HTTP fallback transport
  (Phase 1, gated on Reticulum non-availability) uses TLS provided by
  the deployment-edge proxy (nginx, ALB). Misconfigured TLS is a
  deployment concern, not edge's.
- **Operator UI surfaces**. Grafana, OAuth, admin console — explicitly
  out of scope per FSD §2. Each peer keeps its own operator-UI HTTP
  stack.
- **Quantum compromise of Ed25519 *under Ed25519-fallback consumer
  policy*.** Edge ships hybrid Ed25519 + ML-DSA-65 verify in v0.1.0
  (OQ-11 closure: hybrid PQC is already in prod across CIRISVerify
  v1.9.0 + CIRISPersist v0.2.0+). Three consumer policies are
  selectable per peer: strict-hybrid, soft-hybrid+freshness, and
  Ed25519-fallback. Quantum residual exists only under Ed25519-fallback;
  strict-hybrid eliminates it modulo persist's eventual-consistency
  trust contract for hybrid-pending rows.
- **Reticulum-rs / Leviculum implementation bugs**. The transport-impl
  threat model is the upstream crate's; edge wraps the trait.
  Cross-implementation byte-equivalence is a regression test category
  (MISSION.md §5).

---

## 2. Adversary Model

### Adversary Capabilities

The adversary is assumed to have:

- **Full source-code access** (AGPL-3.0, public).
- **Ability to mint arbitrary Ed25519 keypairs** and sign bytes.
- **Network access to all configured transports**: arbitrary bytes to
  the HTTP endpoint, Reticulum link establishment with arbitrary
  identities, simulated LoRa / serial / I²P link establishment.
- **Ability to run their own peers** on the federation and request
  federation_keys registration.
- **Replay capability**: capture any in-transit message and re-send.
- **Active MITM** on HTTP fallback if TLS is misconfigured at the
  deployment edge.
- **Side-channel observation**: response timing, transport-level error
  codes, structured-log output if exposed.
- **Ability to read public CI artifacts**: every published Cargo
  release, the dep tree, the deny.toml, the Dockerfile.
- **Compute resources sufficient for classical cryptography** but not
  for breaking Ed25519 within polynomial time.
- **Ability to submit malformed canonical bytes** at any wire entry
  point.
- **Slow-medium privilege**: on LoRa / serial / I²P, transport-level
  jitter and asymmetric latency give the adversary additional timing
  observation surface compared to TCP.

### Adversary Limitations

The adversary is assumed NOT to have:

- **The ability to break Ed25519** within polynomial time on classical
  hardware. (PoB §6 acknowledges quantum risk; `signature_pqc` field
  reserved.)
- **Compromised the federation directory** (`federation_keys` /
  `accord_public_keys` in persist). Edge's verify is gated on this
  directory; if it's owned, the threat model breaks at persist's layer.
- **Compromised persist's keyring** (the steward seed). Same FFI
  boundary discipline persist established in v0.2.2.
- **Compromised the deployment hardware** running edge (process memory
  inspection, debugger attachment, coredump capture).
- **Quantum compute** capable of breaking Ed25519 today (tracked in §9
  Residual Risks; PoB §6 hybrid-PQC is Phase 2+).
- **Broken sha256** to forge cryptographic addresses.
- **Physical access to LoRa / serial hardware** at the edge deployment
  (transport-physical-layer attacks are out of scope for this crate).

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│ Adversary-controlled wire (TCP / LoRa / packet radio / serial /     │
│ I²P / HTTP fallback)                                                │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ raw bytes
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ciris-edge process (host: lens / agent / registry binary)           │
│                                                                     │
│   ┌──────────────────────────────────────────────────────┐          │
│   │ transport/                                            │          │
│   │   Trust boundary 1: untrusted bytes enter            │          │
│   │   Reticulum link state OR HTTPS request body         │          │
│   └─────────────────────────┬────────────────────────────┘          │
│                             ▼                                        │
│   ┌──────────────────────────────────────────────────────┐          │
│   │ verify/                                               │          │
│   │   Trust boundary 2: typed envelope deserialize       │          │
│   │   ┌──────────────────────────────────────────┐       │          │
│   │   │ FFI boundary: edge ↔ ciris-persist       │       │          │
│   │   │ - lookup_public_key(signing_key_id)      │       │          │
│   │   │ - canonicalize_envelope()                │       │          │
│   │   │ - steward_sign() for outbound            │       │          │
│   │   │ Seed bytes NEVER cross this boundary     │       │          │
│   │   └──────────────────────────────────────────┘       │          │
│   │   Ed25519 verify_strict(canonical, sig, pubkey)      │          │
│   └─────────────────────────┬────────────────────────────┘          │
│                             ▼                                        │
│   ┌──────────────────────────────────────────────────────┐          │
│   │ handler/                                              │          │
│   │   Trust boundary 3: typed dispatch                   │          │
│   │   No unverified bytes past this line — invariant    │          │
│   │   asserted by verify_enforcement test category       │          │
│   └─────────────────────────┬────────────────────────────┘          │
└─────────────────────────────┼────────────────────────────────────────┘
                              ▼
                     Host application code
                     (peer-specific reasoning, persistence, scoring)
```

**Explicit non-boundary**: edge's process and persist's `Engine` share
heap. Persist's `Engine` is constructed in the host process and passed
to edge by reference. The seed-bytes-don't-cross-FFI invariant is
maintained by persist's API surface (the seed is held in OS-keyring,
never returned across the boundary — see CIRISPersist v0.1.3+ AV-25
closure). Edge tests assert this invariant by heap-scan property tests
(MISSION.md §4 "Identity boundary").

---

## 4. Attack Vectors

Thirty-one vectors organized by adversary goal (twenty-four
pre-Phase-1 vectors AV-1..AV-25; AV-42 added at v0.4.0;
AV-43..AV-47 added at v0.17.1 — these document architectural surfaces
that landed across v0.13.0 → v0.17.0; plus the canonical-peer
invariant documented as a forward-looking threat-modeling anchor for
the v0.18.0 wire-up of CIRISEdge#46). Each lists the attack, the
primary mitigation, secondary mitigation, and residual risk.

### 4.1 Identity / Forgery — adversary wants their bytes counted

#### AV-1: Forged message from attacker-minted key

**Attack**: Attacker generates a fresh Ed25519 keypair, signs a synthetic
`EdgeEnvelope`, sends to a peer's edge listener via any transport.

**Mitigation**: `verify/` calls `persist.engine.lookup_public_key(
signing_key_id)` before signature verification (FSD §3.3 step 4).
Unknown `signing_key_id` → typed `unknown_key` reject → handler is
never invoked. Same gate as `CIRISPersist/THREAT_MODEL.md §3.1 AV-1`.

**Secondary**: persist's federation_keys directory is the load-bearing
admission policy. Edge does not implement its own admission gate —
that's intentional, single-source-of-truth.

**Residual**: an attacker who registers a key id (via the federation's
`accord/agents/register` flow) earns the same gate as any peer. PoB
§2.1 cost-asymmetry is the federation-level mitigation.

#### AV-2: Forged message from compromised legitimate key

**Attack**: Attacker exfiltrates a peer's signing seed (out-of-band
secrets-manager compromise), signs a malicious `EdgeEnvelope` under
that peer's identity.

**Mitigation**: **Out of CIRISEdge's protection scope.** The verifier
cannot distinguish stolen-key from legitimate. Same residual as
CIRISPersist AV-2 — closure is statistical via N_eff drift (PoB §2.4)
and architectural via Phase 2 peer-replicate audit-chain validation.

**Residual**: undetectable at edge ingest until peer-replicate lands.
The peer's own CIRISVerify hardware-backed key storage is the
upstream mitigation; edge holds no keys to compromise locally
(MISSION.md §3 anti-pattern 3).

#### AV-3: Replay within edge's sliding window

**Attack**: Network MITM (or re-submission attack at the API) captures
a valid signed envelope and replays it within the 5-minute window.

**Mitigation**: edge maintains a bounded LRU of `(signing_key_id,
nonce)` pairs seen in the last `replay_window_secs` (5 min default per
OQ-08, configurable Phase 2). Replayed within window → typed
`replay_detected` reject → handler is never invoked.

**Secondary**: TLS at the deployment edge (HTTP fallback only)
prevents in-flight capture; not edge's responsibility. Reticulum's
native link encryption covers the canonical transport.

**Residual**: the LRU is process-local. A replay against a *second*
edge instance of the same peer (multi-replica deployment) lands once
per replica until persist's AV-9 dedup catches it at the application
layer. Per OQ-06 (multi-worker concurrency), multi-instance replay
detection requires either a shared replay-window store (Redis-class)
or accepting per-instance redundancy with persist as the authoritative
dedup. Phase 1 default: per-instance + persist as authoritative.

#### AV-4: Replay outside edge's sliding window

**Attack**: Adversary captures a valid signed envelope, waits >5
minutes, replays.

**Mitigation**: edge's window has expired the entry; the replay passes
edge's verify. **Persist's AV-9 dedup tuple catches it at the
application layer** — the message produces zero-row insert because
`(agent_id_hash, trace_id, thought_id, event_type, attempt_index, ts)`
already exists. Edge's responsibility is bounded; persist's is the
authoritative dedup.

**Residual**: a replay against a *different* peer (federation replication)
lands once by design — that's what trace replication is supposed to do
(PoB §5.1). Per-peer dedup is each peer's local guarantee.

#### AV-5: Canonicalization mismatch

**Attack**: Adversary exploits a byte-difference between what the
sender canonicalizes and what edge canonicalizes for verify.

**Mitigation**: edge does NOT implement canonicalization. Every verify
calls `persist.engine.canonicalize_envelope(envelope)` — same code
path the sender used to compute the bytes it signed. Single source of
truth (CIRISPersist#7 closure; same AV closure pattern as
CIRISPersist/THREAT_MODEL.md §3.1 AV-4).

**Secondary**: Ed25519 collision and preimage resistance bound the
"produce different bytes that verify" branch to 2^128 work — practically
infeasible.

**Residual**: float-formatting drift across host platforms (CIRISPersist
AV-4 residual). Edge inherits the same exposure and the same closure
path — a future change to persist's canonicalizer rolls out via persist
version pin in edge's `Cargo.toml`.

#### AV-6: Reticulum destination spoofing

**Attack**: Adversary attempts to claim a Reticulum destination
matching an honest peer's `sha256(public_key)[..16]`.

**Mitigation**: **Structurally impossible without breaking either
sha256 or Ed25519.** The Reticulum destination is derived from the
public key bytes; an adversary cannot produce a destination matching
honest peer X's destination without holding X's keypair. PoB §3.2
"addressing IS identity" closure.

**Residual**: 64-bit collision-resistance on the truncated destination
(CIRISPersist AV-9 residual — same trade-off, same federation-scale
acceptance). 2^64 grinding cost for targeted DOS via address collision
is the residual; 2^32 birthday for any collision pair across federation
populations up to ~4B peers.

### 4.2 Authentication / Authorization — adversary wants verified bytes to reach the wrong handler

#### AV-7: Schema-version downgrade

**Attack**: Adversary sends an envelope with a known-vulnerable
`edge_schema_version` to exploit a bug fixed in a later version.

**Mitigation**: `SUPPORTED_VERSIONS` is a strict allowlist, mirrored
from CIRISPersist v0.1.2 AV-12 closure. Out-of-set versions hit typed
`unsupported_schema_version` reject. There is no "best-effort" or
"downgrade-and-try" branch.

**Residual**: when two versions are simultaneously in the allowlist
(rolling-deploy window), per-version payload gates must be
independently typed-deserialize-strict. Track at every spec bump.

#### AV-8: Misrouted message acceptance

**Attack**: Adversary sends a valid signed envelope to peer X with
`destination_key_id` set to peer Y. The sender's signature verifies;
the envelope is "authentic" but addressed to a different peer.

**Mitigation**: edge checks `envelope.destination_key_id ==
self.steward_key_id` BEFORE deserializing the body. Mismatch →
typed `misrouted` reject; the body is never parsed.

**Secondary**: at scale, misrouted messages indicate either an
operational bug at the sender or a deliberate confusion attack;
metrics (`messages_in_misrouted` counter) surface the rate.

**Residual**: a peer running multiple steward identities (multi-tenant
deployment) needs to validate against all of its own identities; this
is the host's responsibility via `Engine.is_local_identity()`.

#### AV-9: Handler dispatch on unverified bytes

**Attack**: Adversary exploits a code path where `dispatch()` is
called before the verify pipeline completes (race condition,
exception-handling flaw, future refactor that shortcuts verify).

**Mitigation**: structural — the verify pipeline is a
linear seven-step path (FSD §3.3); `dispatch()` is private to the
verify module's success path. The `handler/` module's public API takes
already-typed-and-verified `(msg, ctx)`; there is no surface for an
unverified path.

**Secondary**: `verify_enforcement` test category (MISSION.md §4)
asserts at the property-test level that no handler is invoked for any
message that fails any of the seven verify steps. Fuzzing covers the
exception-handling boundary.

**Residual**: a future contributor adds a "fast path" that bypasses
verify under some condition. PR review + the verify_enforcement test
category catch this; the test passes only if zero unverified
invocations occur over N>=1M fuzz runs.

### 4.3 Denial of Service — adversary wants edge unable to receive evidence

#### AV-10: Wire-flooding (transport-level)

**Attack**: Adversary floods a transport endpoint (HTTP POST flood,
Reticulum link establishment flood, simulated LoRa frame flood) to
saturate edge's accept loop.

**Mitigation in v0.1.0**: per-transport rate caps on inbound link
establishment. HTTP transport: deployment-edge rate limit (nginx /
ALB) is the primary; edge applies an in-process per-source-IP token
bucket as defense-in-depth. Reticulum: link-establishment quota per
remote identity. LoRa / serial: physical-layer bandwidth is itself a
rate cap, plus per-link quota.

**Secondary**: bounded inbound queue (`DEFAULT_QUEUE_DEPTH`, OQ-09).
On saturation: 429 + Retry-After to HTTP, equivalent typed reject for
Reticulum.

**Residual**: a sufficiently distributed attacker bypasses per-source
rate limits. Federation-level admission policy (PoB §5.6 acceptance
policy) is the upstream mitigation.

#### AV-11: Verify-path saturation

**Attack**: Adversary submits high-rate valid-but-cheap messages that
each force a `lookup_public_key` round-trip into persist, saturating
persist's queue.

**Mitigation**: `lookup_public_key` is a hot path; persist's
implementation must be cheap (in-memory + worker-local cache, falling
back to DB; CIRISPersist AV-1 mitigation). Edge applies a per-source
verify-rate cap as defense-in-depth.

**Secondary**: if persist's verify path saturates, edge's bounded
queue applies backpressure to senders (429 + Retry-After).

**Residual**: pre-Phase-1 implementation; track measured throughput
against attack-rate hypothesis. If verify-path saturation becomes
observed, persist's lookup_public_key gets a circuit-breaker; edge's
backpressure becomes the operational signal.

#### AV-12: Replay-window memory growth

**Attack**: Adversary submits high-rate distinct-nonce messages to
inflate edge's `(signing_key_id, nonce)` LRU.

**Mitigation**: LRU is bounded with explicit eviction policy. Default
size: 100K entries (Phase 1; configurable). Beyond capacity, oldest
entries evict; entries past the window expire regardless of capacity.

**Residual**: with eviction, an old entry can re-enter the window via
explicit replay if the window is shorter than time-to-eviction. OQ-08
sets the window at 5min; eviction at 100K entries means the attacker
must sustain 100K/5min = 333 messages/sec just to win the eviction
race against legitimate traffic — plus pay verify cost on every one.
Cost-asymmetric.

#### AV-13: Body-size flood

**Attack**: Adversary submits arbitrarily large message bodies to
exhaust edge's parse-buffer memory.

**Mitigation in v0.1.0**: explicit `MAX_BODY_BYTES` ceiling (default
8 MiB matching CIRISPersist AV-7 closure). HTTP transport: applied at
the axum extractor layer (`DefaultBodyLimit::max(8 * 1024 * 1024)`).
Reticulum: link-frame size limits applied by the transport crate;
`MAX_BODY_BYTES` enforced after reassembly, before parse.

**Secondary**: deployment-edge proxy on HTTP fallback caps body size
upstream of edge.

**Residual**: until the limit is enforced symmetrically across all
transports, body-size flood is a defense-in-depth gap on novel
transports. Track at every new-transport PR.

#### AV-14: Malformed canonical bytes triggering parse amplification

**Attack**: Adversary submits an envelope whose `body` is deeply
nested JSON (`[[[[...]]]]` 10000 deep) or contains a single key with a
1GB string value, exhausting `serde_json::Value` deserialization.

**Mitigation**: typed envelope deserialization rejects depth-bombs at
the `EdgeEnvelope` boundary. Per-message-type body deserialize is
strict — no `serde_json::Value` in handler signatures (MISSION.md §3
anti-pattern 1). Body is `serde_json::value::RawValue` only at the
envelope layer; canonicalization preserves bytes verbatim, parse is
type-strict at the message-type boundary.

**Secondary**: recursion-depth guard (`MAX_DATA_DEPTH=32`, mirroring
CIRISPersist AV-6 closure) on any `RawValue` body parse path.

**Residual**: an attacker with a registered, accepted public key who
submits inflated-but-syntactically-valid bodies pays the cost-asymmetry
PoB §2.1 names.

### 4.4 Confidentiality / Privacy — adversary wants content text exposed

#### AV-15: Transport plaintext leakage

**Attack**: Network-adjacent adversary reads in-transit envelope
bodies on a misconfigured transport.

**Mitigation**: Reticulum provides native link-layer encryption
(canonical transport). HTTP fallback uses TLS at the deployment-edge
proxy. Edge does NOT add a third encryption layer (FSD §11
out-of-scope).

**Residual**: HTTP fallback with no TLS at the deployment edge is a
deployment misconfiguration that exposes envelope bodies. Edge MAY
emit a startup warning if HTTP transport is configured without an
upstream TLS termination indication, but ultimately TLS posture is
the operator's job. LoRa / serial / I²P: native encryption per
Reticulum's link layer.

#### AV-16: Side-channel timing on verify

**Attack**: Adversary measures response time to distinguish "unknown
key" vs "known key + wrong signature" vs "known key + right signature
+ wrong canonical bytes" — gleaning information about the federation
directory or canonicalization state.

**Mitigation in v0.1.0**: Ed25519 `verify_strict` is constant-time
over the signature/key path. **However**:
- The `lookup_public_key` short-circuits on unknown-key (returns
  before signature math runs). Timing leaks key-membership.
- Canonicalization byte length differs per payload — observable.
- LoRa / serial mediums have intrinsic per-frame timing observability.

**Recommended for v0.2.x**: constant-response-time wrapper that sleeps
to a P99 budget on the rejection path. Not free operationally; track
as research-grade hardening.

**Residual**: a network-adjacent attacker can probably enumerate
`signing_key_id`s via timing oracle. Per CIRISPersist AV-16 residual,
the federation primitive treats `signing_key_id` as public anyway —
directory enumeration is not a high-impact leak. The slow-medium
amplification (LoRa) makes the channel noisier but no more
information-theoretic leak.

#### AV-17: Heap leak of seed bytes

**Attack**: Process memory exfiltration (debugger attach, coredump
capture, `/proc/<pid>/mem` access on Linux) reveals key-seed bytes
loaded into edge's heap.

**Mitigation**: **Edge does not load seed bytes.** All sign / verify
operations call into `persist.engine`, which holds the seed in
OS-keyring (CIRISPersist v0.1.3+ AV-25 closure). The seed bytes never
cross the FFI boundary into edge's process memory.

**Test category**: `identity_boundary` test (MISSION.md §4) — property
test that scans edge's heap during sign and asserts no seed-shaped
bytes are present.

**Residual**: a future contributor adds caching that copies seed
bytes into edge's heap. The test category catches this; the heap
scan property test passes only if no seed-shaped patterns are found
across N>=1000 sign operations.

**v0.16.0 wire-form note (CIRISEdge#38 + D26, FSD-002 §3.4):** the
canonical wire string for this invariant is now
`key_boundary:{scope}:no_seed_in_heap` where `{scope}` is one of
`process` / `tenant:{tenant_id}` / `channel:{channel_id}` /
`cohort:{cohort_id}` / `data_class:{class}`. **The AV-17 invariant
itself is unchanged at v0.16.0 — edge's process never holds a seed,
period, scope-irrespective.** The scope slot is a *wire-form
primitive* so consumers can express per-tenant / per-channel /
per-cohort / per-data-class isolation contracts that future
verify-time enforcement (binding signatures to a scope) will check.
The legacy v0.15.x string `key_boundary:no_seed_in_heap` parses as
the `process` scope for backward compatibility; existing v0.15.x
envelopes round-trip byte-equal at v0.16.0 with the
`key_boundary_scope` envelope field omitted (default `None`). See
`src/key_boundary.rs` for the typed `KeyBoundaryScope` enum + the
wire-string codec; v0.16.1+ owns scope-binding enforcement.

**v0.16.0 testimonial_witness wire-form note (CIRISEdge#37, FSD-002
§3.6.3 v1.4 + §5.14):** the `EdgeEnvelope` now carries an optional
`testimonial_witness: Option<TestimonialWitness>` field
(`{kind, payload, issuer_key_id, issued_at}`). It is a
**preservation primitive** — edge propagates the value verbatim
across federation forwarding and signs it as part of canonical
envelope bytes; edge does NOT interpret the opaque `payload` (that
lives at the joint-correlation tier in `ciris-lens-core` and the
ratchet-conscience evaluators). The field is `Option`-wrapped with
`#[serde(default, skip_serializing_if = "Option::is_none")]` so
existing v0.15.x envelopes round-trip byte-equal; witness-bearing
envelopes from v0.16.0+ producers are visible to v0.16.0+ consumers
and ignored by pre-v0.16.0 deserializers. No new AV vector is
introduced at v0.16.0 — the field is forwarded data, not a privilege
boundary; verification of the witness against its `issuer_key_id` is
the consumer's responsibility (the same discipline edge already
applies to `accord_signatures`, FSD-002 §4.5).

### 4.5 Multi-medium specific — N2 primitive surface

#### AV-18: Cross-medium replay

**Attack**: Adversary captures an envelope from TCP and replays it
over LoRa (or vice versa), exploiting per-transport replay-window
isolation.

**Mitigation**: edge's replay window is keyed on `(signing_key_id,
nonce)` — transport-agnostic. A replay across mediums is the same
`(signing_key_id, nonce)` and is caught by the same window.

**Residual**: a sufficiently old replay (>5min) bypasses edge's
window per AV-4; persist's AV-9 dedup tuple catches application-layer
replay at the substrate. Cross-medium does not change the residual.

#### AV-19: Slow-medium timing-amplification

**Attack**: On LoRa or serial transports, transport-layer latency
gives adversary observable timing on internal verify operations
(verify takes longer per medium quantum than over TCP).

**Mitigation**: same as AV-16 — `verify_strict` is constant-time per
operation; transport-medium-asymmetry doesn't change the per-operation
timing surface, but does amplify per-message timing observation.

**Residual**: research-grade. LoRa / serial transports SHOULD apply
per-medium pacing on the response path so per-message latency is
medium-bandwidth-bounded rather than verify-time-bounded. Track for
Phase 3 productionization.

#### AV-20: I²P endpoint enumeration

**Attack**: Adversary enumerates the federation's I²P endpoints via
exposed routing.

**Mitigation**: I²P endpoints are public-key hashes (same as Reticulum
addresses). Enumerating them is enumerating the federation directory,
which is a public artifact (the directory is distributed by design).
Not a leak.

### 4.6 Operational / FFI boundary — adversary wants edge to drift from the discipline

#### AV-21: Lookup-cache emergence

**Attack surface (operational, not adversarial)**: future contributor
adds a public-key cache to `verify/` to reduce per-message
`lookup_public_key` cost.

**Mitigation**: PR review + MISSION.md §3 anti-pattern 1 explicit
("Caller-implemented canonicalization" generalizes — same invariant
applies to lookup). The discipline is "if profiling shows lookup is
hot, optimize persist's lookup, not edge's caching" (FSD §7
anti-pattern 1).

**Residual**: discipline-only. If lookup latency becomes a real
bottleneck, persist's `lookup_public_key` gets a worker-local cache
*inside persist*; edge stays cache-free.

#### AV-22: Per-peer special-case in handler trait

**Attack surface (architectural)**: a contributor adds a handler-trait
variant that's special-cased for one peer ("this is just for the
lens"), defeating "one shape, many peers."

**Mitigation**: PR review (FSD §7 anti-pattern 2). Peers compose
around edge, not into it. Peer-specific logic stays in the host crate.

**Residual**: catches at review time; no runtime detector.

#### AV-23: Caller-side canonicalization drift

**Attack surface (architectural)**: a contributor implements
canonicalization in edge to avoid the FFI round-trip into persist.

**Mitigation**: MISSION.md §3 anti-pattern 2 + FSD §7 anti-pattern 5.
Same closure path as CIRISPersist#7. PR review catches.

**Residual**: canonicalization byte-equivalence test (every PR runs
edge's `canonical_payload_value` against persist's
`canonicalize_envelope` for a test fixture set). Drift between the
two is the AV-5 attack vector — both directions need to stay in sync,
and the test asserts they do.

### 4.7 Supply chain — adversary wants malicious edge binaries

#### AV-24: Edge build-manifest forgery

**Attack**: Adversary publishes a malicious `ciris-edge` release tarball
with a forged or stolen build-signing key.

**Mitigation**: hybrid (Ed25519 + ML-DSA-65) signature via
`ciris-build-sign` per CIRISVerify v1.8 build-attestation (CIRISVerify
THREAT_MODEL.md §3.3). Per-release `EdgeExtras` JSON registered with
CIRISRegistry. Round-trip verified at release publication.

**Secondary**: AGPL-3.0 license-locked mission preservation per
MISSION.md §6 — a fork that publishes under a different license is
auditable.

**Residual**: a compromised maintainer's signing key (AV-2 class
applied to the edge release pipeline). Mitigation is upstream
(CIRISVerify hardware-backed key storage for release signing); not
edge's local concern at runtime.

#### AV-25: Reticulum-rs vs Leviculum implementation drift

**Attack surface (architectural)**: a malicious or buggy alternative
Reticulum implementation (Leviculum or future fork) produces
byte-different envelope encoding from Reticulum-rs, breaking
cross-implementation interop.

**Mitigation**: cross-implementation byte-equivalence regression
tests (MISSION.md §5). Bridge-trained discipline from lens-steward
bootstrap (Rust ml-dsa rc.3 ↔ dilithium-py byte-equivalent verify).
A new Reticulum impl gains an entry in edge's `Transport` enum only
after byte-equivalence passes.

**Residual**: until a sister Rust Reticulum impl actually ships, this
is a forward-looking concern. Phase 1 ships with reticulum-rs only.

#### AV-42: Spoofed transport-identity ↔ federation-key binding

**Attack**: a Reticulum destination is a *dedicated dual-key transport
identity* (`hash(x25519 ‖ ed25519)`), separate from the federation
Ed25519 signing key — the federation seed never enters Leviculum
(AV-17). The transport therefore needs a binding "Reticulum
destination X belongs to federation key Y". v0.3.1's announce-driven
discovery recorded `key_id → destination` straight off the announce
app-data: trust-on-first-use. A Reticulum announce is signed, so it
proves the announcer controls *that transport identity* — it does
**not** prove the transport identity legitimately belongs to `key_id`.
An adversary announces a federation `key_id` it does not own, paired
with an adversary-controlled destination; a sender calling
`send(key_id, ..)` routes the envelope to the adversary. The envelope
is still signed by the sender's federation key (the adversary cannot
forge a response the real recipient would accept), but Reticulum link
encryption means the adversary *receives + decrypts* the envelope
bytes, and legitimate delivery is denied — misrouting / DoS.

**Mitigation**: the authenticated cold-start path (CIRISEdge#15 /
CIRISVerify#28 Phase 3, v0.4.0). Each announce carries an
`AnnounceAttestation` in its app-data — a federation-key signature
over `{transport_identity_pubkey, federation_key_id, epoch}`
(`src/transport/attestation.rs`). The `PeerResolver` cold-start path
in `src/transport/reticulum.rs` is a **two-step root + verify**:

1. **Root the federation key** — `root_binding(directory, key_id,
   claimed_ed25519_pubkey)` (CIRISPersist v1.12.0
   `federation::rooting`) confirms the `key_id` resolves to a
   `federation_keys` directory row, the claimed pubkey matches it,
   and the recursive-provenance chain verifies up to a steward
   bootstrap. A spoofed `key_id` fails here with `PubkeyMismatch`
   (the adversary's pubkey ≠ the directory row) or `UnknownKeyId`.
   A `DirectoryError` is treated as retryable — a transient substrate
   fault, not a verdict — so the peer is not blacklisted; the seven
   structural/crypto rejections are terminal AV-42 events.
2. **Verify the attestation signature** over
   `{transport_identity_pubkey, key_id, epoch}` against the
   now-directory-confirmed Ed25519 pubkey (never the wire claim). An
   announcer that does not hold `key_id`'s federation seed cannot
   forge this signature.

The consumer `HybridPolicy` is then applied to the rooted provenance
chain (`Strict` rejects any hybrid-pending link). Only an announce
that clears all three is recorded as a rooted resolution; `send`
routes only to rooted peers. This replaces trust-on-first-use
entirely — there is no provisional-trust state.

**Test**: `tests/reticulum_av42.rs` is the acceptance gate — a
spoofed announce (wrong `key_id` → `root_binding` rejection; tampered
/ adversary-signed attestation → signature mismatch) is rejected.
`tests/reticulum_loopback.rs` covers the legitimate-rooted-resolution
end-to-end path.

**Residual**: a transport identity is routing-only and never a
`federation_keys`-class row (CIRISPersist Finding G) — it is outside
the recursive-provenance chain and is not itself rooted; the binding
is authenticated solely by the announce attestation. A federation key
whose seed is compromised (AV-2 class) can attest an
adversary-controlled transport identity — that residual is the AV-2
stolen-key surface, not AV-42, and closes upstream (peer-replicate
audit chain). The `epoch` field gives transport-identity rotation a
monotonic supersede signal; revocation of a stale binding before its
epoch bumps is a v0.2.x freshness concern.

### 4.8 Cohabitation / FFI cohab discipline — v0.13.0 → v0.17.0 surfaces

#### AV-43: Federation transport identity 32-byte vs 65-byte hybrid

**Attack surface (architectural)**: when edge cohabits with a host
process's already-bootstrapped persist `Engine` (the CIRIS 3.0
cohabitation lane — agent + edge + lens in one Python process), the
hardware-rooted 65-byte hybrid `keyring_signer_capsule` (P-256 +
ML-DSA hybrid under `hardware_hsm_only`) is the correct primitive for
**hot-path scrub envelope signing** — that is the forensic-grade
identity the federation expects on outbound envelopes. But the
Reticulum transport's Curve25519-derived DH key-exchange needs a
**32-byte Ed25519 private key** to mint the dual-key transport
identity. A naive cohab implementation could either (a) try to drive
Reticulum's transport-identity construction from the 65-byte hybrid
signer (Reticulum can't consume it; the transport never establishes)
or (b) reach back into the cohabiting engine and copy the local-signer
seed across the FFI boundary into edge's heap — breaking AV-17.

**Mitigation**: v0.13.1 (patch line) + v0.16.1 (main line cherry-pick
per CIRISEdge#43) close this with `init_edge_runtime`'s **Step 3.5**
dual-capsule extraction. After persist v3.1.1 (CIRISPersist#119), the
cohab engine exposes a second signer capsule alongside the first:
`local_signer_capsule` wraps an `Arc<dyn ciris_keyring::LocalSigner>`
constructed from the engine's `local_key_path` 32-byte Ed25519 seed.
`init_edge_runtime` extracts the capsule via the same
`extract_capsule` helper (`src/ffi/pyo3.rs::extract_capsule`) it uses
for the other four cohab capsules, then wraps the resulting
`Arc<dyn LocalSigner>` in persist's `LocalSignerHardwareAdapter` — an
adapter that implements `Arc<dyn HardwareSigner>` so the Reticulum
transport can consume it through the same trait surface it always
has. **AV-17 holds: neither seed crosses the FFI boundary** — both
signers arrive as opaque `Arc<dyn Trait>` pointers wrapped in
`PyCapsule`s; edge's heap holds the trait objects, not the seed
bytes. Two capsules, two roles, one cohabiting engine: the
hardware-rooted hybrid drives scrub envelope signing on the hot path,
the local Ed25519 drives Reticulum's transport identity.

**Test**: the cohabitation init path is exercised through the
PyCapsule extraction smoke tests in `src/ffi/pyo3.rs` (cf. line ~2936
where the error-message contract for the four mandatory capsules is
pinned, and line ~3007 where the runtime-handle-capsule fallback is
checked). For v3.1.1-pre engines that don't expose `local_signer_capsule`
yet, the `LocalSignerCapsuleAttempt::NotPresent` branch falls back to
the legacy seed-file path (`src/identity.rs::LocalSigner::from_seed_dir`)
predating persist v2.12.0 / #112; AV-17's heap-scan property test
covers both paths uniformly because the invariant is "no seed bytes in
edge's heap during sign", scope-irrespective.

**Residual**: a future contributor wires Reticulum's transport
identity through `keyring_signer_capsule` directly (bypassing the
adapter), or copies the local seed across the FFI rather than holding
the capsule. PR review catches the first (the type doesn't compile —
Reticulum's transport-identity constructor expects 32 bytes, not 65);
the AV-17 heap-scan property test catches the second.

#### AV-44: testimonial_witness preservation invariant

**Attack surface (architectural + integrity)**: at v0.16.0 the
`EdgeEnvelope` carries an optional
`testimonial_witness: Option<TestimonialWitness>` field
(`{kind, payload, issuer_key_id, issued_at}`) propagated verbatim from
the joint-correlation tier (lens-core detectors, ratchet-conscience
evaluators, registry attesters). The threat is **silent witness drop
or re-interpretation by edge** along the forwarding path — either
would break the M-1 Fidelity & Transparency audit chain (the chain
requires every witness a downstream evaluator might need to be
visible end-to-end) and would silently substitute edge's reading of
the payload for the policy tier's signed claim, breaking Respect
for Autonomy ("the policy tier owns its own meaning").

**Mitigation**: the field is `Option`-wrapped with
`#[serde(default, skip_serializing_if = "Option::is_none")]` so
v0.15.x envelopes round-trip byte-equal at v0.16.0+ (no spurious
`"testimonial_witness": null` appears in serialized JSON when the
field is `None`). Canonical bytes derive through
`ciris_persist::canonicalize_envelope_for_signing` — the single
source of canonicalization (CIRISPersist#7) — so the witness bytes
participate in the signature exactly as the issuer wrote them.
**Edge does not interpret the opaque `payload`** — the payload is
the issuer's bytes, signed by the issuer's key; verification of the
witness against its `issuer_key_id` is the consumer's responsibility,
the same discipline edge already applies to `accord_signatures`
(FSD-002 §4.5).

**Test**: `tests/testimonial_witness_round_trip.rs` pins the
preservation contract: v0.15.x backward-compat (key absent when
`None`); witness round-trips byte-equal when `Some`; canonical bytes
differ between present-vs-absent witness (i.e. the field is in the
signed bytes); multi-issuer witnesses round-trip byte-equal; the
"one witness per envelope" type-level invariant (the field is
`Option<TestimonialWitness>`, not `Vec`).

**Residual**: a future contributor adds an "edge-side witness sniff"
helper that parses the opaque `payload` to make a routing decision.
That would break the Respect-for-Autonomy framing of §10. PR review
catches; the discipline is "if you need to read a witness, you are
not edge — the witness is for the policy tier."

#### AV-45: key_boundary {scope} binding-deferred

**Attack surface (architectural)**: v0.16.0 ships the wire form
`key_boundary:{scope}:no_seed_in_heap` where `{scope}` is one of
`process` / `tenant:{tenant_id}` / `channel:{channel_id}` /
`cohort:{cohort_id}` / `data_class:{class}` (typed via
`src/key_boundary.rs::KeyBoundaryScope`). **Signature-to-scope binding
enforcement** — the verify-time check that a signature was produced
under a key actually scoped per the envelope's declared scope — is
v0.16.1+ scope and explicitly NOT closed at v0.16.0 / v0.17.0.
The threat is **scope-spoofing**: an envelope claims
`key_boundary:tenant:foo:no_seed_in_heap` but is signed by a
process-wide key (or by a key scoped to a different tenant). A
consumer naively trusting the declared scope would mis-attribute the
claim to a key-boundary it was not actually signed under.

**Mitigation (v0.16.0 / v0.17.0)**: the wire form exists so
downstream consumers can express their scoping contracts on the wire
without a wire break; future enforcement (a verify-time check that
binds signatures to a scope) will check the declaration against the
substrate's scope-keyed signing-key resolution. **AV-17 itself is
unchanged at v0.16.0 / v0.17.0 — edge's process never holds a seed,
scope-irrespective** (the heap-scan property test covers the
process-wide invariant, which holds for every scope). Consumers
should treat the `key_boundary_scope` field as a *declared* contract,
not an *enforced* one, until v0.16.1+ binding enforcement lands.
Legacy v0.15.x envelopes carrying the bare
`key_boundary:no_seed_in_heap` string parse as the
`KeyBoundaryScope::Process` variant for backward compatibility
(`src/key_boundary.rs::LEGACY_NO_SEED_IN_HEAP`).

**Residual**: scope-spoofing is detectable only by the consumer's
own scope-binding check until edge enforces it. **Document this as a
known deferred-enforcement scope** so multi-tenant / per-cohort
deployments do not assume the wire field is enforced at v0.16.0 /
v0.17.0. The deferred enforcement is intentional — landing the wire
form first lets downstream substrate consumers (CIRISLens,
CIRISAgent) start emitting scoped envelopes and gather migration
signal before the binding semantics solidify.

**v0.19.1 addendum (CIRISEdge#48-A)**: partial closure. The
`cohort_scope` side of the locality scope family — a sibling slot
to `key_boundary_scope` per CIRISNodeCore SCHEMA §3.2 / FSD
`FEDERATION_SCALING_MODEL.md` — is now STRUCTURALLY enforced at
both the producer side (refusal at `Edge::send_*` outbound enqueue:
`SelfOnly` / `Family` / `Cohort` MUST NOT cross federation-class /
mandatory-class hops, and point-to-point delivery refuses when the
recipient is not authorized for the declared scope) and the
consumer side (symmetric check at `dispatch_inbound`: an inbound
envelope whose claimed `SelfOnly` / `Family` scope doesn't match the
sender's directory-recorded scope is REJECTED with a moderation-
signal event on the EventBus). Default enforcement posture is
[`CohortScopeEnforcement::Strict`] per wire-format invariant; the
`WarnOnly` and `Off` modes exist as operator migration gradients
(`Off` is explicitly testing/dev only). The producer-side refusal
returns typed [`EdgeError::CohortScopeRefused{Federation,Mandatory,Recipient}`]
variants; the consumer-side refusal emits a `cohort_scope_violation`
resource event so lens-core can downweight the sender. See
[`src/cohort_scope.rs`] + the consumer-side hook in
`src/edge.rs::dispatch_inbound`. The full
`key_boundary_scope`-to-signature binding (signature was actually
produced under the declared key-boundary scope) remains deferred —
that would require a verify-time per-key scope-resolution surface in
persist's federation directory (no v3.2.0 read accessor exists), and
is intentionally larger work than #48-A's wire-format locality
dividend.

**v0.19.6 addendum (CIRISEdge#48-A completion)**: AV-45 closure
progress narrowed further. The v0.19.1 in-process `cohort_membership`
HashMap registry (the "edge-only enforcement, no persist
coordination" workaround) is REMOVED at v0.19.6. The source of truth
for per-peer cohort_scope is now persist's
`federation_peer_metadata.policy_blob.cohort_scope` field, read at
the consumer-side check via
`FederationDirectory::peer_metadata_for(key_id)` (CIRISPersist#127,
v3.4.1). Operators declare per-peer scope via
`Engine::update_peer_policy(key_id, json!({"cohort_scope": <scope>}))`
where `<scope>` is the wire-form `CohortScope` JSON (`{"kind":
"public" | "self" | "family"}` or `{"kind": "cohort", "cohort_id":
"..."}`). The substrate-tier directory becomes the
single-source-of-truth across cohabitation peers (the host engine
and every sibling cdylib see the same scope per peer); the v0.19.1
edge-side mirror is gone. The previously-deferred consumer-side
`Cohort{id}` arm (v0.19.1 §"Public and Cohort{id} are NOT
short-circuited here at v0.19.1") is enabled at v0.19.6 — the same
persist lookup drives `SelfOnly` / `Family` / `Cohort{id}`. The
v0.19.6 closure progression table:

  - v0.16.0 — `key_boundary:{scope}` wire form lands (declared, not
    enforced);
  - v0.19.1 — `cohort_scope` producer + consumer enforcement against
    in-process registry (partial — no Cohort{id}, no persist
    coordination);
  - v0.19.6 — `cohort_scope` enforcement against persist's federated
    peer_metadata (full — `SelfOnly` + `Family` + `Cohort{id}`,
    operator-declared via `update_peer_policy`, edge consumes via
    `peer_metadata_for`);
  - PENDING — `key_boundary_scope`-to-signature binding (signature
    was actually produced under the declared key-boundary scope) —
    would need a CIRIS 3.0 wire extension or a verify-time per-key
    scope-resolution surface; intentionally larger work than the
    wire-format locality dividend.

#### AV-46: peer-mgmt TrustClass = operator opinion, not attestation

**Attack surface (architectural / semantic)**: v0.15.1 wired the
peer-mgmt mutation surface (`src/ffi/uniffi_impl.rs::peer_add` /
`peer_remove` / `peer_set_alias` / `peer_set_trust` / `peer_set_notes`
/ `peer_set_policy`) against persist v3.1.0's `FederationDirectory`
mutation methods (CIRISPersist#117). The typed `TrustClass` enum
(`Untrusted` / `Trusted` / `Restricted` / `Blocked`) carries the
operator's view of the peer. The threat is **confusing operator
opinion with federation attestation**: a downstream consumer reading
`TrustClass::Blocked` on a peer-info row might infer that the
federation has attested-against this peer (revocation, fraud finding,
etc.) when in fact the operator simply chose to refuse traffic from
that peer on this Edge instance. The reverse confusion is worse —
treating an operator's `Trusted` flip as if it were a federation
attestation would let a single compromised operator effectively
"vouch" for an adversary peer to the rest of the substrate.

**Mitigation**: **operator opinion lives in
`federation_peer_metadata` — a sibling table to `federation_keys`,
per CIRISPersist#117 — NOT folded into the directory itself.** The
schema separation is the load-bearing invariant: federation directory
rows carry the federation's attested view (crypto identities, trust
statements signed by the federation); operator metadata rows carry
the per-instance operator opinion (alias, trust class, notes,
policy). Edge surfaces both in `EdgePeerInfo`, but the structural
separation makes "this is an operator opinion" textually obvious at
every call site. Trust-state mutations **bypass §6.1
chain-honesty by design** — they are a local-policy primitive, not a
wire-attested claim. The framing aligns with CIRIS Accord §I
Respect-for-Autonomy: an operator's right to refuse traffic is theirs;
that refusal does not propagate as an attestation against the peer.

**Test**: `tests/peer_mutation_ffi.rs` exercises the mutation surface
through the UniFFI free-function shape — `peer_add` → `peer_get`
round-trips the typed `EdgePeerTrust`; `peer_set_trust` flips persist
through `edge_trust_to_persist` (`src/ffi/uniffi_impl.rs:248`); the
post-mutation `peer_list` view reflects the operator opinion.

**Residual**: a downstream consumer reads `peer_get(handle).trust`
and infers a federation attestation. Documentation is the mitigation
— the `EdgePeerTrust` doc comment names this explicitly. The
structural separation in persist's schema (sibling table, not folded
column) makes the inversion expensive to do accidentally.

#### AV-47: UniFFI pre-init invariant

**Attack surface (cross-language correctness)**: every UniFFI FFI
free function in `src/ffi/uniffi_impl.rs` /
`src/ffi/uniffi_impl_links.rs` / `src/ffi/uniffi_impl_routing.rs`
dispatches through the global `install_edge_handle` registry slot
(`src/ffi/uniffi_impl.rs::install_edge_handle`, a
`OnceLock<RwLock<Weak<Edge>>>`). The threat is **a cross-language
consumer (Python, Kotlin, Swift) calling an FFI free function before
`init_edge_runtime` has populated the slot, or after the Edge has
been torn down**. The naive failure mode is a panic (UniFFI surfaces
panics as language-level exceptions on most targets, but Swift's
binding contract requires `Result`-shaped errors, not panics);
returning garbage data (e.g. an empty `Vec`) is worse because the
consumer would silently treat "no Edge installed yet" as "Edge is up
but has no state".

**Mitigation**: every FFI free function checks slot population via
`current_edge()` (`src/ffi/uniffi_impl.rs:79`) and returns typed
`EdgeBindingsError::NotInitialized` if the slot is empty, OR typed
`EdgeBindingsError::Unsupported` if the slot is populated but the
specific FFI surface is unavailable (e.g. an FFI free function whose
backing trait method is `NotImplemented` on the current persist
version). **No FFI free function panics, returns garbage, or
silently does nothing** — every entry point is `Result`-typed with
the same `EdgeBindingsError` discriminant set across the crate. The
`Weak<Edge>` design also handles teardown gracefully: after the
strong `Arc<Edge>` is dropped, `Weak::upgrade()` returns `None` and
the FFI surfaces flip back to `NotInitialized`.

**Test**: `tests/routing_ffi.rs::uniffi_path_table_unsupported_without_init`
and `tests/links_ffi.rs::uniffi_link_list_unsupported_without_init`
pin the invariant for the routing and links surfaces. Analogous
pre-init smoke tests cover the peer-mgmt surface; the assertion is
"no `install_edge_handle` call → FFI returns typed
`NotInitialized` / `Unsupported`, never panics, never returns garbage
data."

**Residual**: a contributor adds a new FFI free function and forgets
the `current_edge()?` gate. PR review + the per-surface pre-init
smoke test pattern catches this; the discipline is "every UniFFI
free function gates on `current_edge()` first."

#### AV-48: Trust short-circuit at dispatch_inbound

**Attack surface (architectural)**: a peer with high N (volume of
verified envelopes) but low T (trust score relative to the
federation's accumulated evidence) can saturate the inbound handler
pipeline of every peer that subscribes to its emissions. Without a
trust gate at the dispatch layer, the AV-9 invariant (no dispatch on
unverified bytes) is necessary but not sufficient: verification
gates *identity* (the envelope was produced by the claimed key) and
*integrity* (canonical bytes match the signature); it does NOT gate
*reputation* (whether this signing identity is one the federation
has reason to trust at the current handler-dispatch threshold). A
peer whose key is in `federation_keys` and whose envelopes verify
cleanly can still flood inbound dispatch with malformed-claim
payloads, scope-spoofed envelopes (see AV-45), or signed-but-
adversarial content — and persist's evidence corpus already has the
attestation graph that lets the substrate compute "this key has low
trust." Edge needs the fast-path consumer of that signal.

**Mitigation (v0.19.6 CIRISEdge#48-B)**: edge consumes persist's
`TrustScoring` trait (CIRISPersist#123, v3.4.0) at
`dispatch_inbound`. After signature verify (the substrate gate
stays first; verify still runs so persist's scoring surface sees
the corpus) and BEFORE handler dispatch, the dispatcher resolves
the verified `signing_key_id`'s trust score and DROPS the envelope
when the score falls below
[`EdgeConfig::trust_threshold`]. The drop fires a typed
`EventKind::TrustShortCircuited` moderation signal on the EventBus
(resource channel — same fan-in as `cohort_scope_violation`), so
lens-core can downweight the offender's emission cadence at the
policy tier. The dropped envelope ALSO bumps the
`EdgeMetrics::inbound_dropped_low_trust` counter so operators can
observe the drop rate.

Configuration knobs:

  - `trust_threshold: f64` — floor below which the dispatcher drops.
    Default `0.0` (bootstrap-permissive — the code path skips the
    scoring resolver entirely at `≤ 0.0`, matching persist's
    `AdmissionGate::check` discipline). Operators raise this as the
    federation's trust corpus stabilizes (e.g. `0.5` after the
    first quarter of attestation aggregation).
  - `trust_short_circuit_enabled: bool` — explicit on/off override
    independent of the threshold value (default `true`; flip to
    `false` for migration / dev paths that want to disable the
    check without zeroing the threshold).
  - `Arc<dyn TrustScoring>` wired via `EdgeBuilder::trust_scoring()`.
    `None` (the default) structurally disables the short-circuit
    — same effect as `threshold = 0.0`. The cohabitation pyo3 init
    path currently leaves this `None` (deferred to v0.20.0 RC1
    pending an `AdmissionGate::scoring_arc()` accessor in a
    persist v3.5.1+ cut; persist v3.5.0 exposes the install side
    `Engine::set_admission_gate` but no read accessor on the gate
    itself).

The effective check is the AND of all three predicates; any one
disabled means no drop fires. This belt-and-suspenders shape
prevents a misconfigured deployment from silently rejecting all
traffic — if the operator forgets to wire the scorer, the
short-circuit stays off rather than failing closed.

**Threat that AV-48 does NOT close**: a peer with high N AND high T
remains a high-volume verified emitter; edge still verifies their
envelopes and dispatches them. The trust gate is a *reputation*
filter, not a *volume* filter — the per-transport rate caps (AV-10)
and bounded inbound queue (AV-13 family) are the volume gates.
AV-48 is the substrate's pre-dispatch defense against
*signed-but-untrusted* emissions; it composes with the rate gates,
not as a replacement.

**Threat that AV-48 INTENTIONALLY leaves observable**: signature
verification still runs on every inbound envelope even when the
sender will be dropped. This is by design — persist's `TrustScoring`
computes its scores over the signed-evidence corpus (CEG §10.1.2),
so the corpus needs to see the envelopes. A future cut could
short-circuit even verify for a known-blocked sender (the
`BlackholeRules` family already supports this at the
*transport-identity* layer per AV-46); the trust short-circuit gates
*dispatch*, not *verify*, because the scoring substrate needs
the verify-side evidence to converge.

**Test**: `tests/trust_short_circuit.rs` pins the behavioral
contract — 9 tests covering (a) below-threshold drop, (b)
above-threshold dispatch, (c) at-threshold dispatch (boundary —
the condition is `score < threshold`, strict `<`), (d) `0.0`
threshold short-circuits the scoring call entirely, (e) `enabled =
false` overrides any positive threshold, (f) moderation signal
event semantics (kind + peer_key_id + measurement +
resource_kind tag), (g) metrics counter increments, (h) absent
scorer structurally disables, (i) typed error variant carries
key_id + score + threshold + issue tag.

**Residual**: the cohabitation pyo3 init path currently leaves
`trust_scoring = None`, so production cohabitation deployments
fall back to the bootstrap-permissive default until persist
exposes the `AdmissionGate::scoring_arc()` (or
`Engine::trust_scoring_capsule()`) accessor needed to auto-derive
the scorer from the engine's installed admission gate. Operators
deploying outside the cohabitation path (e.g. sovereign Pi /
mobile / standalone hosts using `EdgeBuilder` directly) can wire
the scorer via `EdgeBuilder::trust_scoring()` immediately at
v0.19.6.

### 4.9 Forward-looking invariants (anchored at v0.17.1 for v0.18.x wire-up)

#### Canonical-peer invariant (CIRISEdge#46 — scheduled v0.18.0)

**Attack surface (operational)**: bootstrap peers — the canonical
CIRIS infrastructure roster (`agents.ciris.ai`, the steward bootstrap
nodes, the registry peers) — are how a fresh Edge discovers the
federation at all. The threat is **an operator silently dropping a
canonical CIRIS infrastructure peer and losing federation reach** —
either by accident (an over-aggressive `peer_remove` cleanup script)
or by an adversary with operator-tier access who wants to isolate a
victim Edge from the wider federation while still letting it run.
A naive peer-mutation surface (the v0.15.1 shape) would let
`peer_remove(handle, hard=true)` permanently delete the
`agents.ciris.ai` row from the local `federation_peer_metadata`
table; the operator might never notice the deletion until federation
traffic dries up.

**Mitigation (scheduled v0.18.0)**: the v0.18.0 cut introduces three
linked invariants:

1. **Bootstrap peers re-seeded on every Edge start.** A canonical
   roster (the federation's published infrastructure list, ratified
   via the same CIRISRegistry channel as the substrate version pins)
   is reconciled into `federation_peer_metadata` at startup. Missing
   canonical peers are re-inserted with default `Untrusted` trust
   state; existing rows keep their operator-set trust state untouched.
2. **Operator trust state survives restarts.** An operator who has
   flipped `agents.ciris.ai` to `Blocked` will see it remain `Blocked`
   across restarts — the reconcile pass preserves
   `federation_peer_metadata.trust_class` for existing rows. The
   operator-autonomy framing of AV-46 holds: the user can refuse
   trust.
3. **Hard-remove is rejected for canonical peers.**
   `peer_remove(handle, hard=true)` against a canonical peer returns
   typed `EdgeBindingsError::CannotRemoveCanonicalPeer` (the exact
   error name lands at v0.18.0; the discriminant is reserved here
   for the contract). The operator can refuse trust but cannot lose
   knowledge — canonical peers are infrastructure-class. The
   `EdgePeerInfo` row gains a `canonical: bool` field so the consumer
   can render the "this peer is infrastructure, you may refuse trust
   but cannot remove" UX semantic.

The split aligns with Reticulum's structural distinction between
propagation nodes (the infrastructure roster — fixed, infra-class)
and peers (operator-controlled trust relationships — mutable).
Documenting the invariant at v0.17.1 (ahead of the v0.18.0 wire-up)
primes the threat model: downstream substrate consumers
(CIRISLens, CIRISAgent, CIRISRegistry) can pin against the contract
shape before the wiring ships, and v0.18.0's acceptance tests can be
written against the documented invariant rather than reverse-engineered
from the implementation.

**Test (scheduled)**: v0.18.0 acceptance suite must pin
(a) canonical-peer reseed on fresh start; (b) operator-flipped trust
state preserved across restart; (c) `peer_remove(canonical,
hard=true)` returns typed `CannotRemoveCanonicalPeer`;
(d) `EdgePeerInfo.canonical` is `true` for bootstrap peers, `false`
for operator-added peers.

**Residual**: an operator who blocks every canonical peer locally
loses federation reach — by design. The mitigation is **knowledge
without trust**: the operator sees the canonical peers in
`peer_list`, knows what they are (`canonical: true`), and can choose
to refuse traffic; they cannot accidentally forget the peers exist.
A wholly air-gapped deployment (no federation reach by design) is a
distinct deployment mode, not a canonical-peer concern.

---

## 5. Mitigation Matrix

| AV | Attack | Severity | Primary Mitigation | Secondary | Status | Fix tracker |
|---|---|---|---|---|---|---|
| AV-1 | Forged from attacker key | — | `lookup_public_key` directory gate | N_eff drift detection (RATCHET) | ✓ Mitigated (architectural; persist owns directory) | — |
| AV-2 | Forged from compromised key | — | Out of scope at write time | Phase 2 peer-replicate audit chain | ⚠ Phase 2 closes | persist FSD §4.5 |
| AV-3 | Replay within window | P1 | `(signing_key_id, nonce)` LRU, 5-min window | Per-instance + persist AV-9 | ⚠ Phase 1 baseline | impl |
| AV-4 | Replay outside window | — | Persist AV-9 dedup | TLS at deploy edge | ✓ Mitigated (architectural) | — |
| AV-5 | Canonicalization mismatch | — | `Engine.canonicalize_envelope` only; no edge re-impl | Cross-impl byte-equivalence test | ✓ Mitigated (CIRISPersist#7 closure) | — |
| AV-6 | Reticulum destination spoofing | — | Structural (sha256 + Ed25519 collision-resistance) | — | ✓ Mitigated | — |
| AV-7 | Schema-version downgrade | P1 | Strict allowlist | Per-version payload gates | ⚠ Track at every spec bump | — |
| AV-8 | Misrouted-message acceptance | P2 | `destination_key_id` check before parse | Metric on misroute rate | ⚠ Track | — |
| AV-9 | Dispatch on unverified bytes | **P0** | Structural (private dispatch surface) | `verify_enforcement` test category | ⚠ Pre-Phase-1; impl + test must land together | impl |
| AV-10 | Transport-level flooding | P1 | Per-transport rate caps | Bounded inbound queue, backpressure | ⚠ Phase 1 design | impl |
| AV-11 | Verify-path saturation | P1 | Cheap `lookup_public_key`; per-source verify-rate cap | Backpressure | ⚠ Phase 1 design | impl |
| AV-12 | Replay-window mem growth | P2 | Bounded LRU + window expiry | Cost-asymmetric attack | ⚠ Phase 1 design | impl |
| AV-13 | Body-size flood | P0 | `MAX_BODY_BYTES` (8 MiB) at extractor | Deploy-edge body-size cap | ⚠ Phase 1 design | impl |
| AV-14 | Parse amplification | P0 | Typed envelope; `MAX_DATA_DEPTH=32` | Bounded queue | ⚠ Phase 1 design | impl |
| AV-15 | Transport plaintext | P1 | Reticulum link encryption / TLS on HTTP | Startup warning if HTTP w/o TLS indication | ⚠ Phase 1 design | impl |
| AV-16 | Side-channel timing | P3 | Ed25519 verify_strict (constant-time) | Future: constant-response-time wrapper | ⚠ Track v0.2.x | — |
| AV-17 | Heap leak of seed bytes | **P0** | FFI boundary discipline (persist owns seed) | `identity_boundary` heap-scan test | ⚠ Pre-Phase-1; test must land with code | impl |
| AV-18 | Cross-medium replay | — | Transport-agnostic `(key, nonce)` window | Persist AV-9 catch | ✓ Mitigated by design | — |
| AV-19 | Slow-medium timing-amp | P3 | Per-medium pacing on response path | — | ⚠ Phase 3 hardening | — |
| AV-20 | I²P endpoint enum | — | Public by design | — | ✓ Not a leak | — |
| AV-21 | Lookup cache emergence | P3 | PR review + MISSION.md anti-pattern | — | ⚠ Discipline-only | — |
| AV-22 | Per-peer special-case | P3 | PR review | — | ⚠ Discipline-only | — |
| AV-23 | Caller canonicalization drift | P3 | PR review + byte-equivalence test | — | ⚠ Discipline + CI | — |
| AV-24 | Build-manifest forgery | P1 | Hybrid Ed25519 + ML-DSA-65 release sig | AGPL license-lock | ⚠ Same as lens, persist | — |
| AV-25 | Cross-Reticulum-impl drift | P2 | Byte-equivalence regression test | — | ⚠ Forward-looking (Leviculum) | — |
| AV-42 | Spoofed transport-identity ↔ federation-key binding | P1 | Two-step root + attestation-verify cold-start path (`root_binding` + announce attestation) | Consumer `HybridPolicy` over the rooted chain | ✓ Mitigated (CIRISEdge#15, v0.4.0) | `tests/reticulum_av42.rs` |
| AV-43 | 32-byte vs 65-byte hybrid transport identity confusion in cohab | P1 | Step 3.5 dual-capsule extraction in `init_edge_runtime`; `LocalSignerHardwareAdapter` wraps `local_signer_capsule` for the Reticulum transport identity | AV-17 heap-scan property test (both signers cross FFI as opaque `Arc<dyn Trait>`) | ✓ Mitigated (CIRISEdge#43, v0.13.1 patch / v0.16.1 main cherry-pick) | `src/ffi/pyo3.rs::extract_capsule` smoke tests |
| AV-44 | testimonial_witness silent drop / re-interpretation | P1 | `#[serde(default, skip_serializing_if = "Option::is_none")]`; canonical bytes via `ciris_persist::canonicalize_envelope_for_signing`; edge does not interpret `payload` | Consumer verifies witness against `issuer_key_id` (same discipline as `accord_signatures`) | ✓ Mitigated (v0.16.0 CIRISEdge#37) | `tests/testimonial_witness_round_trip.rs` |
| AV-45 | key_boundary scope-spoofing (declared ≠ actually-signed-under) | P2 | Wire form only at v0.16.0 / v0.17.0; documented as declared-not-enforced | AV-17 process-wide invariant unchanged (scope-irrespective heap-scan) | ⚠ Deferred enforcement (v0.16.1+ binding scope) | `src/key_boundary.rs` (wire codec only) |
| AV-46 | Operator opinion confused with federation attestation | P3 | Schema separation: `federation_peer_metadata` sibling table per CIRISPersist#117 (not folded into `federation_keys`); `EdgePeerTrust` doc explicit | Documentation; Accord §I operator-autonomy framing | ✓ Mitigated structurally (v0.15.1) | `tests/peer_mutation_ffi.rs` |
| AV-47 | UniFFI free-function called pre-init / post-teardown | P1 | `OnceLock<RwLock<Weak<Edge>>>` slot + per-surface `current_edge()?` gate; typed `EdgeBindingsError::{NotInitialized,Unsupported}` | `Weak::upgrade` returns `None` on teardown → flips back to `NotInitialized` | ✓ Mitigated (v0.13.0+ UniFFI scaffolding pattern) | `tests/routing_ffi.rs::uniffi_path_table_unsupported_without_init`, `tests/links_ffi.rs::uniffi_link_list_unsupported_without_init` |
| AV-48 | High-N low-T signed envelope flood at dispatch_inbound | P1 | `Arc<dyn TrustScoring>` consumer at dispatch_inbound (CIRISPersist#123); drop below `trust_threshold` + emit `EventKind::TrustShortCircuited`; `inbound_dropped_low_trust` counter; default `0.0` bootstrap-permissive | Per-transport rate caps (AV-10); bounded inbound queue (AV-13 family) cover the *volume* axis | ✓ Mitigated (v0.19.6 CIRISEdge#48-B) | `tests/trust_short_circuit.rs` |
| Canonical-peer | Operator silently drops canonical CIRIS infra peer | P1 | Bootstrap reseed on every start; `peer_remove(canonical, hard=true)` → typed `CannotRemoveCanonicalPeer`; `EdgePeerInfo.canonical: bool` | Operator trust-state flip preserved across restart (refuse trust without forgetting peer) | ⚠ Scheduled v0.18.0 (CIRISEdge#46) | tests scheduled v0.18.0 acceptance |

**Pre-Phase-1 P0 must-have bundle**: AV-9 + AV-13 + AV-14 + AV-17 +
hybrid verify (OQ-11 closure). The first four are the structural
invariants that, if not in place at Phase 1 v0.1.0, break the
threat-model claim. Hybrid verify is the v0.1.0 PQC posture: edge
calls `Engine.verify_hybrid()` on every inbound message whose sender's
`federation_keys` row carries `pubkey_ml_dsa_65_base64`; consumer
policy (strict / soft+freshness / fallback) is per-peer config.
Pre-Phase-1 coordination: persist exposes the verify_hybrid FFI
surface; the underlying primitive already exists in `ciris-crypto`.

---

## 6. Security Levels by Deployment Tier

| Tier | Transport | FFI shape | Threat model |
|---|---|---|---|
| **Server-class peer** (production lens / agent / registry) | TCP via Reticulum primary; HTTPS fallback | edge ↔ persist via Rust API | Full §4 model applies. TLS at edge required for HTTP fallback. |
| **Standalone Rust binary** (Phase 2+) | Reticulum primary; HTTPS optional | edge ↔ persist same-process | Same as above; FastAPI / Python shim absent. |
| **Pi-class sovereign** (Phase 3) | Reticulum over LoRa / serial / TCP | edge ↔ persist embedded | Reduced attack surface (typically not internet-exposed). LoRa AV-19 timing-amp residual. |
| **Mobile bundled** (Phase 3 stretch) | Reticulum over Bluetooth-LE / TCP-when-online | edge ↔ persist via swift-bridge or jni | Apple/Android sandbox + secure enclave. Threat model dominated by upstream agent's CIRISVerify hardware-attestation tier. |
| **MCU no_std relay** (Phase 3 stretch) | Reticulum verify-only over serial / packet radio | edge verify-only; no persist | Out of full HTTP-ingest scope; verify-only relay. AV-1 + AV-3 + AV-7 still apply. |

**Critical invariant**: all tiers run the same `verify/` pipeline, the
same `transport/` trait, the same `Engine` FFI boundary. A finding in
one tier's implementation is presumed to apply to the same surface in
others unless explicitly excepted.

---

## 7. Security Assumptions

The system depends on these assumptions; if violated, the threat model
breaks.

1. **Persist's federation directory is sound.** `lookup_public_key`
   returns truthful answers; the directory is not compromised. Edge's
   AV-1 closure depends entirely on this.
2. **Persist's keyring is sound.** The steward seed lives in OS-keyring
   (CIRISPersist v0.1.3+ AV-25). Edge holds no keys; if persist's
   keyring is compromised, AV-2 applies — out of edge's scope.
3. **`Engine.canonicalize_envelope` is byte-deterministic** across host
   platforms and version bumps. Drift at this layer triggers AV-5.
4. **Reticulum's cryptographic addressing holds**: sha256 collision-
   resistance + Ed25519 unforgeability. Both are classical-cryptography
   assumptions; quantum compromise is tracked in §9 Residual.
5. **TLS at the deployment edge** for HTTP fallback. Plaintext HTTP
   exposes envelope bodies (AV-15).
6. **Clock accuracy** is within ~5 minutes of real time across all
   peers. Skew degrades AV-3 replay-window mitigation.
7. **Wire-format spec stability**: peers and edge agree on
   `EdgeEnvelope` canonicalization (FSD §3.4). Drift between peers is
   AV-5; drift between edge versions on the same peer is the
   schema-version-bump review trigger.
8. **Deployment hardware integrity**: edge's host process is not
   compromised at root. Process memory inspection, debugger attach,
   coredump access are out of scope.
9. **Build-pipeline integrity**: edge's release tarball is signed via
   the same hybrid (Ed25519 + ML-DSA-65) chain CIRISVerify v1.8
   defined; the build-signing key is hardware-protected per
   CIRISVerify's tier. AV-24 closure depends.
10. **Persist exposes hybrid verify + outbound-queue substrates.**
    `Engine.verify_hybrid_via_directory()` (per-message hot path)
    and `Engine.verify_hybrid()` (raw-pubkey form) for inbound;
    `cirislens.edge_outbound_queue` table + the OQ-09 Engine surface
    (`enqueue_outbound`, `claim_pending_outbound`, ACK matching,
    sweeps) for outbound `send_durable()`. **Available in
    CIRISPersist v0.4.0+ (CIRISPersist#14 + #16 closed 2026-05-03).**
    Phase 1 pin: `ciris-persist >= 0.4.0`. Persist threat-model
    closures: AV-39 (verify pipeline), AV-40 (queue disk exhaustion),
    AV-41 (spoofed in_reply_to ACK matching). Edge MUST NOT call
    `ciris-crypto` directly — that breaks the verify-via-persist
    single-source-of-truth (CIRISPersist#7).

Critical: **Assumption 1 is load-bearing.** Edge's entire verify
guarantee reduces to "lookup_public_key returns truthful answers."
Persist's federation directory is the federation's single point of
trust at this layer, and persist's threat model is the upstream
authority.

---

## 8. Fail-Secure Degradation

All failures degrade to MORE restrictive modes, never less.

| Failure | Current behavior (target Phase 1) | Should be |
|---|---|---|
| Envelope schema parse failure | Typed `schema_invalid` reject; handler not invoked | ✓ Correct |
| Unsupported `edge_schema_version` | Typed `unsupported_schema_version` reject | ✓ Correct |
| Signature verification failure | Typed `signature_mismatch` reject; handler not invoked | ✓ Correct |
| Unknown signing key | Typed `unknown_key` reject | ✓ Correct |
| Misrouted message (`destination_key_id` mismatch) | Typed `misrouted` reject; body never parsed | ✓ Correct |
| Replay within window | Typed `replay_detected` reject | ✓ Correct |
| Persist `lookup_public_key` errors out | Typed `verify_unavailable` reject; surface as 503-equivalent | ✓ Correct (no fallback acceptance) |
| Body > `MAX_BODY_BYTES` | Typed `body_too_large` reject; transport-level 413 if HTTP | ✓ Correct |
| Inbound queue full | 429 + Retry-After (HTTP) / equivalent typed reject | ✓ Correct |
| Handler returns error | Wire-formatted error response signed and returned to sender | ✓ Correct |
| Handler panics | Edge-level panic-handler returns typed `handler_panicked`; process stays up | ✓ Correct |
| Edge process panics (verify path) | Process exits; orchestrator restart; no silent recovery | ✓ Correct |
| Reticulum link establishment fails | Transport falls back to next configured transport (HTTP if available); per-transport metric records the failure | ⚠ Phase 1 design |
| Transport encryption negotiation fails | Connection rejected; no plaintext fallback within a single transport | ✓ Correct |

Critical invariant: **`signature_verified=false` envelopes do not reach
handlers.** The verify pipeline asserts this true unconditionally;
unverified bytes never produce a handler invocation. Storing or
processing unverified envelopes would corrupt the federation's PoB §2.4
measurement.

---

## 9. Residual Risks

Risks edge mitigates but cannot fully eliminate.

1. **Compromised peer signing key** (AV-2). Edge accepts
   forged-but-correctly-signed envelopes. Closure: agent-side key
   storage hardening (CIRISVerify), Phase 2 peer-replicate, federation
   N_eff drift detection (RATCHET).
2. **Quantum compromise of Ed25519 under Ed25519-fallback policy.**
   Edge ships hybrid Ed25519 + ML-DSA-65 verify in v0.1.0 (OQ-11
   closure). Strict-hybrid policy eliminates the residual against
   hybrid-complete rows; against hybrid-pending rows, the residual is
   bounded by the consumer's chosen policy (soft-hybrid+freshness or
   strict-hybrid both give explicit control). Ed25519-fallback retains
   the residual by design — it's the deployment-tier choice for
   environments where PQC reach is incomplete (older agents, transport
   bandwidth caps).
3. **Cross-implementation drift** when Leviculum or other Reticulum
   forks emerge. Mitigation is regression test (AV-25); residual is
   any drift not caught by the test fixture set.
4. **Persist directory compromise** (Assumption 1). Out of edge's
   scope; persist's threat model is authoritative.
5. **Same-host attacker reading persist's keyring file** (CIRISPersist
   AV-25 residual on `SoftwareSigner` fallback). Closure: hardware-
   backed keyring (TPM / Secure Enclave / StrongBox) per
   CIRISPersist's tier classification. Edge inherits whatever tier
   persist runs at.
6. **Side-channel timing leakage of directory membership** (AV-16).
   Low-impact (key ids are public) but trackable; LoRa/serial timing
   amplification (AV-19) makes the channel slower-but-not-more-leaky.
7. **All federation peers compromised simultaneously** (PoB §5.1
   residual). Per Accord NEW-04, no detector is complete. Topological
   cost-asymmetry over time is the federation-level response.
8. **DNS bootstrap poisoning for HTTP fallback** (the HTTP transport
   resolves a hostname; DNS spoof points to attacker). Mitigation:
   Reticulum is canonical; HTTP fallback is for environments where
   Reticulum can't run, and those environments inherit DNS as part of
   their existing trust model. Track at HTTP-transport documentation.

---

## 10. Posture Summary

```
PRE-PHASE-1 P0 MUST-HAVE BUNDLE — must land with v0.1.0
  ⚠ AV-9   Structural verify-pipeline gating (no unverified bytes past handler boundary)
  ⚠ AV-13  MAX_BODY_BYTES = 8 MiB at all transport entry points
  ⚠ AV-14  Typed envelope deserialize + MAX_DATA_DEPTH=32
  ⚠ AV-17  FFI boundary heap-scan property test
  ⚠ OQ-11  Hybrid verify via Engine.verify_hybrid_via_directory (CIRISPersist v0.4.0+; #14 closed)

V0.4.0 SHIPPED (CIRISEdge#15 / CIRISVerify#28 Phase 3)
  ✓ AV-42  Authenticated transport-identity ↔ federation-key binding
           (two-step root_binding + announce-attestation verify;
           replaces v0.3.1 trust-on-first-use on the PeerResolver
           cold-start path)

V0.13.0 → V0.17.0 SHIPPED (cohab + UniFFI + wire-compliance surfaces)
  ✓ AV-43  Federation transport identity 32-byte vs 65-byte hybrid
           split (Step 3.5 dual-capsule extraction +
           LocalSignerHardwareAdapter; CIRISEdge#43, v0.13.1 patch /
           v0.16.1 main cherry-pick)
  ✓ AV-44  testimonial_witness preservation invariant
           (Option-wrapped wire field; canonical bytes via persist;
           CIRISEdge#37, v0.16.0)
  ✓ AV-46  Schema-level separation of operator opinion from federation
           attestation (peer-mgmt mutation surface against
           federation_peer_metadata sibling table; CIRISEdge#26 +
           CIRISPersist#117, v0.15.1)
  ✓ AV-47  UniFFI pre-init invariant (every FFI free function gates
           on current_edge() → typed NotInitialized / Unsupported;
           CIRISEdge#36 GO, v0.13.0)

V0.17.1 DOCUMENTED, ENFORCEMENT SCHEDULED LATER
  ⚠ AV-45  key_boundary scope-binding enforcement deferred to v0.16.1+
           (wire form ships at v0.16.0; declared-not-enforced); v0.19.6
           narrows the residual to "key_boundary_scope-to-signature
           binding" only — the cohort_scope half is now persist-backed
           and structurally enforced
  ⚠ Canonical-peer invariant scheduled v0.18.0 (CIRISEdge#46) —
           bootstrap reseed + typed CannotRemoveCanonicalPeer +
           EdgePeerInfo.canonical field

V0.19.6 SHIPPED (CIRISEdge#48-A completion + #48-B)
  ✓ AV-48  Trust short-circuit at dispatch_inbound — persist
           TrustScoring consumer drops verified envelopes whose
           signing_key_id scores below EdgeConfig::trust_threshold;
           moderation signal on EventBus; inbound_dropped_low_trust
           metric (CIRISPersist#123 / CIRISEdge#48-B)
  ✓ AV-45 partial — cohort_scope source-of-truth moves from
           in-process registry (v0.19.1 workaround) to persist's
           federation_peer_metadata.policy_blob.cohort_scope via
           peer_metadata_for (CIRISPersist#127). Cohort{id}
           consumer-side check enabled (v0.19.1 deferred arm closes).
           key_boundary_scope-to-signature binding REMAINS deferred.

PHASE-1 P1 BUNDLE — must land for production cutover
  ⚠ AV-3   Replay LRU with 5-min window
  ⚠ AV-5   Cross-impl byte-equivalence test for canonicalize_envelope
  ⚠ AV-7   Strict version allowlist
  ⚠ AV-10  Per-transport rate caps + bounded queue
  ⚠ AV-11  Cheap lookup_public_key + per-source verify-rate cap
  ⚠ AV-15  TLS startup warning on HTTP-without-TLS
  ⚠ AV-24  Hybrid release signature via ciris-build-sign

PHASE-2-CLOSES (architecturally deferred)
  ⚠ AV-2   Stolen-key forgery (peer-replicate audit chain in persist)
  ⚠ AV-25  Cross-Reticulum-impl drift (when sister impl emerges)

V0.2.X TRACK (low blast radius)
  ⚠ AV-8, AV-12, AV-16, AV-21, AV-22, AV-23

PHASE-3 (multi-medium hardening)
  ⚠ AV-19  Slow-medium timing-amplification (LoRa / serial pacing)

ARCHITECTURALLY MITIGATED (no further action required)
  ✓ AV-1   Forged from attacker key (lookup_public_key gate)
  ✓ AV-4   Replay outside window (persist AV-9 catches)
  ✓ AV-6   Reticulum destination spoofing (structural)
  ✓ AV-18  Cross-medium replay (transport-agnostic window)
  ✓ AV-20  I²P endpoint enumeration (public by design)
```

**Bottom line**: edge is a thin verify-and-dispatch substrate. The
threat-model story reduces to five invariants:

1. No unverified bytes reach handlers (AV-9).
2. No untyped bytes pass parse (AV-14).
3. No seed bytes enter edge's heap (AV-17).
4. No body exceeds the size cap (AV-13).
5. Hybrid (Ed25519 + ML-DSA-65) verify is the day-1 posture, with
   consumer policy (strict / soft+freshness / fallback) selecting
   acceptance against hybrid-pending rows (OQ-11).

If those five hold at v0.1.0, the rest of the threat model is
architecturally consistent with the federation meta. The pre-Phase-1
implementation work is exactly: land those five invariants with the
tests that assert them, then build outward.

Federation-primitive contribution: edge fills the N1 (cryptographic
addressing) and N2 (multi-medium transport) gaps that
`FEDERATION_THREAT_MODEL.md` §5 explicitly lists as unfilled.
Submitting this threat model upstream closes those rows in the
federation's per-primitive coverage table.

---

## 11. Update Cadence

This document is updated:
- On every minor release: comprehensive review.
- On every published security advisory affecting deps (reticulum-rs,
  tokio, axum, serde): addendum in §4 + `cargo audit` re-run.
- On every wire-format schema-version bump: AV-5 / AV-7 review against
  the new shape, byte-equivalence test against persist's
  `canonicalize_envelope`.
- On every new transport landing in `transport/`: AV-10 / AV-13 / AV-15
  / AV-19 review for the new medium's specific surface.
- On every cross-trinity boundary change (CIRISPersist flips the
  Engine surface, CIRISVerify flips keyring API, CIRISAgent flips
  trace wire format): trust-boundary review + interaction matrix
  update.

Last updated: 2026-05-29 (v0.19.6 — last feature cut before RC1.
AV-48 added (trust short-circuit at dispatch_inbound, mitigated
v0.19.6 CIRISEdge#48-B via CIRISPersist#123 TrustScoring trait);
AV-45 closure narrowed (cohort_scope side now persist-backed via
peer_metadata_for / CIRISPersist#127; only key_boundary_scope-to-
signature binding remains deferred). Mitigation Matrix gains
AV-48 row. v0.19.6 closure progression for AV-45 documented in
the AV-45 § addendum. Prior baselines: 2026-05-29 v0.17.1
docs-only cut (AV-43/44/45/46/47 added + canonical-peer
invariant); 2026-05-22 v0.4.0 AV-42 mitigated; 2026-05-03 v0.0
scaffold.)
