# CIRISEdge Threat Model

**Line:** **v44.x** (the long-term support line), written against **v44.1.0**
(`Cargo.toml:3`, base `release/44.1.0` at `1175e65`). Regenerated per release
line, not per minor; a minor that changes a vector below amends it in place.

**Pins this document describes** (read from `Cargo.toml` and `pyproject.toml`):

| Dependency | Pin | Source |
|---|---|---|
| `ciris-persist` | tag `v61.0.4` (61.0.5 expected on this line) | `Cargo.toml:454` |
| `ciris-keyring` / `ciris-crypto` / `ciris-verify-core` (CIRISVerify) | tag `v22.0.0` | `Cargo.toml:478-488` |
| `leviculum-core` / `-std` / `-lxmf` | tag `v0.34.0+ciris.1` | `Cargo.toml:952-963` |
| Python wheel floor | `ciris-persist>=61.0.4,<62` | `pyproject.toml:123` |
| Constitution text | CC 1.0-rc17 (namespace manifests vendored at rc15, `ace6b74`) | `docs/RELEASE_NOTES.md` (v44.0.0); `src/cc_namespace.rs:31` |
| Wire vocabulary | `WIRE_VOCABULARY.md` **v1.0.2**, sha256 `38bd4847…` | `src/lib.rs:159-169`; `CIRISConstitution/manifests/WIRE_VOCABULARY.md` |

**Audience:** federation peers integrating against `ciris-edge`, security
reviewers, downstream substrate consumers (`CIRISServer`, `CIRISAgent`,
`CIRISLens`, `CIRISRegistry`).
**Companion:** [`MISSION.md`](../MISSION.md), [`FSD/CIRIS_EDGE.md`](../FSD/CIRIS_EDGE.md),
[`FSD/CIRIS_EDGE_TRANSPORT.md`](../FSD/CIRIS_EDGE_TRANSPORT.md),
[`FSD/PRIVACY_MODES.md`](../FSD/PRIVACY_MODES.md),
[`FSD/ONION_ROUTING.md`](../FSD/ONION_ROUTING.md),
[`docs/LIGHTNET_DARKNET.md`](LIGHTNET_DARKNET.md).
**Normative source:** the CIRIS Constitution (CC), above all Part 5
(transport) and CC 1.13.3 (what the substrate does and does not buy). Where
this document and the CC disagree, the CC is right and this document is the
bug. CC 1.13.3.3 is the canonical adversary-class table; §2 below does not
restate it.
**Inspired by:** [`CIRISVerify/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/THREAT_MODEL.md)
(structural template), [`CIRISPersist/docs/THREAT_MODEL.md`](https://github.com/CIRISAI/CIRISPersist/blob/main/docs/THREAT_MODEL.md)
(verify-and-persist substrate).

**How to read the sources.** Every claim added or re-checked for 44.x names
where it comes from: a CC section (`CC 5.4.3`), an FSD or doc, or a
`file:line` at `1175e65`. Line numbers drift; the symbol named beside them
is the stable anchor.

**How to read the older text.** §4.1–§4.9 (AV-1 … AV-52 and the
canonical-peer invariant) are the vectors as first written, each dated by
the version it names; §1–§3 keep their v1.0 structure. Statements in them
found untrue at 44.1 have been removed or corrected in place, saying so
where the correction matters; the rest were not re-derived line by line
for this regeneration and are dated, not current. **§0, §4.10 and §5–§11
are the 44.x surface** and govern where an older entry reads otherwise.

---

## 0. The 44.x line at a glance

What changed in the threat surface since the v1.0.0 document, in one place.

- **Every byte on an RNS link is under a hybrid transit seal** (CC 5.3.3.5
  E1, enforced at once, no advisory mode: `src/transport/link_seal.rs:1-16`).
  The RNS link layer underneath is classical and is not relied on for
  post-quantum confidentiality (CC 5.3.3.5 E1 rule 2). AV-53.
- **Producers sign hybrid.** Ed25519 + ML-DSA-65 is mandatory at admission
  (CC 5.3.2.4.3.1). The consumer `HybridPolicy` defaults to `Strict`
  (`src/edge.rs:579`); see §9 R-4 for the fallback setting that remains.
- **Three meshes, and the shaping rules of CC 5.4.3 rc17**: a shaped row
  mesh, an unshaped bulk plane, and an unshaped A/V plane. A shaped link is
  one hop; a node holds at most eight; past eight a link runs unshaped unless
  the node is shaped-only or Anonymous-Tier; "off" means "does not offer",
  never "refuses"; a message over 64 KiB never crosses a shaped link. AV-54,
  AV-55.
- **What moves to a peer** (CC 5.2): a row moves when requested, or required,
  and appropriate, never because it is federation-tier. AV-56.
- **Relay forwarding never closes on the service tier**; the host sheds
  load through graduated, leased levers that refuse nothing. AV-57.
- **The Anonymous Tier is wired and dormant** (`src/onion/mod.rs:1-8`):
  off by default, and unavailable on every node because no layer reaches
  three relays. Its replay set is bounded by CIRISEdge#955 (landing in
  44.1). AV-58, AV-59.
- **The residuals the CC states are stated here** (§9), with the scope of
  what has been measured and what has not.

---

## 1. Scope

### What CIRISEdge Protects

CIRISEdge is the federation transport substrate. It carries cryptographic
envelopes between sovereign peers across whatever network media exist
(Reticulum over TCP, UDP, LoRa/RNode and local interfaces; packet radio;
HTTPS). Per MISSION.md §2 it protects:

- **Wire-edge integrity**: no application code touches a byte that hasn't
  been attributed to a `Rooted ∧ owns_key` federation identity and
  verified through persist's directory. Verify is a precondition for
  handler dispatch, not an opt-in.
- **Link confidentiality, post-quantum**: every byte on an RNS link rides
  a hybrid X25519 + ML-KEM-768 transit seal bound to the link and to a
  pair authenticated to the dialled identity (CC 5.3.3.5 E1; AV-53).
- **Structural invisibility**: `self` / `family` content emits no holding
  claim outside its cohort, and group-scoped destinations are never
  announced (CC 5.2, CC 5.4.6). This buys content-holding confidentiality
  only (§9 R-C1).
- **Cryptographic addressing**: the Reticulum destination is a hash of
  the node's dedicated transport identity, a second keypair distinct
  from its federation key; the two are bound only by the node's signed
  route row (AV-42, AV-53). No DNS, no certificate authority.
- **Signer boundary**: the federation signing seed is held behind the
  keyring signer (`Arc<dyn HardwareSigner>`); edge's code calls it and
  never reads the seed. Transport secrets (the RNS identity, the transit
  KEX seed, per-link keys) are edge's and live in its process, zeroized on
  drop (`src/transport/transit_kex_custody.rs:1-30`; AV-17).
- **Verify-via-persist contract**: edge does not maintain its own
  public-key cache or canonicalization implementation. Persist's
  `lookup_public_key()` and `canonicalize_envelope()` are the single
  sources of truth. Re-implementing either in edge is the
  CIRISPersist#7 trap.
- **Replay protection within a bounded window**: edge maintains a
  sliding window (5 min default per `OPEN_QUESTIONS.md` OQ-08) of
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
- **TLS termination on HTTPS**. The HTTPS transport uses TLS (mTLS or
  bearer, `docs/HTTPS_DEPLOYMENT.md`) configured by the deployment; the
  E1 seal is a Reticulum rule and does not cover HTTPS. Misconfigured TLS
  is a deployment concern, not edge's.
- **Operator UI surfaces**. Grafana, OAuth, admin console — explicitly
  out of scope per FSD §2. Each peer keeps its own operator-UI HTTP
  stack.
- **What the Constitution names as non-goals**: relationship existence,
  the communication graph, traffic analysis outside a shaped link,
  unobservability against a global passive adversary, post-compromise
  security for streams (CC 1.13.3.1). §9 states each.
- **Post-quantum metadata on the RNS layer**. The RNS link request,
  announce and path request are classical; the PQ guarantee is carried
  by the seal, content keys and hybrid signatures above them
  (CC 5.3.3.5 E1 rules 2-3; §9 R-4).
- **leviculum implementation bugs**. Edge's RNS is leviculum
  (`CIRISAI/leviculum` `v0.34.0+ciris.1`); a bug there is edge's
  exposure, tracked upstream (§9 R-11).

---

## 2. Adversary Model

### Adversary Capabilities

The adversary is assumed to have:

- **Full source-code access** (AGPL-3.0, public).
- **Ability to mint arbitrary keypairs**, classical or hybrid, and sign
  bytes; a swarm of fresh keys costs nothing (CC 1.13.3.3).
- **Network access to all configured transports**: arbitrary bytes to
  the HTTPS endpoint, Reticulum link establishment with arbitrary
  identities, LoRa / serial link establishment.
- **Ability to run their own peers** on the federation and request
  federation_keys registration.
- **Replay capability**: capture any in-transit message and re-send.
- **Active MITM** on HTTPS if TLS is misconfigured at the deployment
  edge; on-path position as a Reticulum forwarder.
- **Record now, decrypt later**: capture of every link today against a
  future quantum computer (CC 5.3.3.5 E1 rule 2).
- **Side-channel observation**: response timing, transport-level error
  codes, structured-log output if exposed.
- **Ability to read public CI artifacts**: every published Cargo
  release, the dep tree, the deny.toml, the Dockerfile.
- **Compute resources sufficient for classical cryptography**; quantum
  compute is assumed eventually, against recorded traffic.
- **Ability to submit malformed canonical bytes** at any wire entry
  point.
- **Slow-medium privilege**: on LoRa / serial, transport-level
  jitter and asymmetric latency give the adversary additional timing
  observation surface compared to TCP.

### Adversary Limitations

The adversary is assumed NOT to have:

- **The ability to break both halves of a hybrid** (Ed25519 and
  ML-DSA-65; X25519 and ML-KEM-768) at once.
- **Compromised the federation directory** (`federation_keys` /
  `accord_public_keys` in persist). Edge's verify is gated on this
  directory; if it's owned, the threat model breaks at persist's layer.
- **Compromised persist's keyring** (the steward seed). Same FFI
  boundary discipline persist established in v0.2.2.
- **Compromised the deployment hardware** running edge (process memory
  inspection, debugger attachment, coredump capture).
- **Broken sha256** to forge cryptographic addresses.
- **Physical access to LoRa / serial hardware** at the edge deployment
  (transport-physical-layer attacks are out of scope for this crate).

---

## 3. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│ Adversary-controlled wire (TCP / UDP / LoRa / packet radio /        │
│ serial / HTTPS)                                                     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ raw bytes
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ciris-edge process (host: lens / agent / registry binary)           │
│                                                                     │
│   ┌──────────────────────────────────────────────────────┐          │
│   │ transport/                                            │          │
│   │   Trust boundary 1: untrusted bytes enter            │          │
│   │   RNS link: E1 seal first (AV-53) OR HTTPS body      │          │
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
│   │   │ Signing seed stays behind the signer     │       │          │
│   │   └──────────────────────────────────────────┘       │          │
│   │   attribution + hybrid Ed25519/ML-DSA-65 verify      │          │
│   └─────────────────────────┬────────────────────────────┘          │
│                             ▼                                        │
│   ┌──────────────────────────────────────────────────────┐          │
│   │ handler/                                              │          │
│   │   Trust boundary 3: typed dispatch                   │          │
│   │   No unverified bytes past this line — invariant    │          │
│   │   held by the private dispatch path (AV-9)           │          │
│   └─────────────────────────┬────────────────────────────┘          │
└─────────────────────────────┼────────────────────────────────────────┘
                              ▼
                     Host application code
                     (peer-specific reasoning, persistence, scoring)
```

**Explicit non-boundary**: edge's process and persist's `Engine` share
heap. Persist's `Engine` is constructed in the host process and passed
to edge by reference. The signing seed is held by the keyring signer and
never returned across its API; under `SoftwareOnly` custody it is on disk
and, once loaded, in the same process's memory (§9 R-10). The heap-scan
property test earlier versions of this document named was never built:
the invariant is the signer API's, not a test's.

---

## 4. Attack Vectors

Vectors organized by adversary goal: AV-1..AV-25 (pre-Phase-1),
AV-42 (v0.4.0), AV-43..AV-49 (v0.13 → v1.0), AV-50 and AV-52 (v4.0,
v5.0), the canonical-peer invariant, and **AV-53..AV-59, the 44.x surface
(§4.10)**. Each lists the attack, the mitigation and the residual. See
the note at the top of this document on how the older entries are dated.

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

**Secondary**: on Reticulum, the E1 transit seal (AV-53) keeps an
on-path forwarder from capturing envelope bytes at all; on HTTPS, TLS at
the deployment edge does.

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

**v8.0.0 CC 0.7 note (WIRE_VOCABULARY.md §3.3; v1.0.1 when written, unchanged in v1.0.2):** for a Tier-2
opaque `payload` (`OpaqueRequest` / `OpaqueResponse` / `OpaqueEvent`),
**edge canonicalizes nothing** — the `payload` is opaque bytes edge
carries verbatim, so the AV-5 canonicalization-mismatch surface does
not apply to the inner payload. The outer `EdgeEnvelope` still
canonicalizes through persist as above (the envelope signature is
transport-tier); any inner canonicalization or inner signature over
the `payload` is the **app's** responsibility, and any mismatch there
is the app's threat model, not edge's.

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

**v8.0.0 CC 0.7 note (WIRE_VOCABULARY.md §3.3; v1.0.1 when written, unchanged in v1.0.2):** a verified
Tier-2 `OpaqueRequest` whose `kind: u32` has no registered handler is
**not** silently dropped. The handler replies
`OpaqueResponse { kind: <echo>, status: 501, payload: b"unknown kind" }`
— a typed, sender-visible reject. This upholds the fail-loud stance
(MISSION §1.6, §6 anti-pattern 7): an unknown `kind` is a mechanically-
visible refusal to the sender, never a swallowed byte. Edge reasons
about the envelope and the `kind` discriminant only; the opaque
`payload` remains uninterpreted whether or not a handler exists.

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

**Secondary**: deployment-edge proxy on HTTPS caps body size
upstream of edge.

**Residual**: until the limit is enforced symmetrically across all
transports, body-size flood is a defense-in-depth gap on novel
transports. Track at every new-transport PR.

**v8.0.0 CC 0.7 note (WIRE_VOCABULARY.md §3.3; v1.0.1 when written, unchanged in v1.0.2):** the
`MAX_BODY_BYTES` cap applies to the Tier-2 opaque `payload` on
`OpaqueRequest` / `OpaqueResponse` / `OpaqueEvent` exactly as it does
to any Tier-1 body. Edge treats `payload` as opaque bytes and enforces
the ceiling before handing it to a handler; a migrant `kind` cannot buy
a larger parse buffer by riding the opaque tier.

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

**Mitigation (44.x)**: on Reticulum, every edge frame rides the E1
hybrid transit seal over the RNS link's own (classical) encryption, with
no plaintext edge frame in either direction and no classical-only lane
(CC 5.3.3.5 E1; `src/transport/link_seal.rs:1-16`; AV-53). Earlier
versions of this entry said edge adds no encryption layer of its own;
that stopped being true with the seal. On HTTPS, TLS at the deployment
edge.

**Residual**: HTTPS with no TLS at the deployment edge is a deployment
misconfiguration that exposes envelope bodies. On RNS, link setup and
the pre-seal route row are visible (the row is public by construction,
E1 rule 9).

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

**Mitigation**: **edge's code does not read the federation signing
seed.** Signing goes through the keyring signer (`Arc<dyn
HardwareSigner>`, `src/identity.rs`), which never returns the seed.
Hardware-backed custody keeps it off the host; `SoftwareOnly` custody
keeps it on disk and in the process once loaded (§9 R-10).

**What edge does hold** (44.x): its RNS transport identity, the static
transit KEX root seed (`src/transport/transit_kex_custody.rs`, zeroized
on drop, never logged), per-link seal keys, and, when the Anonymous Tier
runs, its hop secret (`src/onion/hop_key.rs`). A process-memory attacker
who takes these can impersonate the node's transport and open its links;
it cannot sign as its federation identity.

**Test category**: the `identity_boundary` heap-scan property test this
entry once named was never built; `tests/key_boundary_scope.rs` tests the
wire string only.

**Residual**: a future contributor adds caching that copies seed bytes
into edge's heap. PR review is the only gate.

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

**Not applicable at 44.x**: no I²P transport is built (the module is
commented out, `src/transport/mod.rs:314`). Reticulum destinations of
announced nodes are public by design (CC 5.4.6); group-scoped
destinations are never announced.

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

#### AV-25: RNS implementation drift (leviculum)

**Attack surface (architectural)**: edge's Reticulum is leviculum, pinned
to the `CIRISAI/leviculum` fork (`v0.34.0+ciris.1`, `Cargo.toml:952-963`).
A divergence from Python RNS, or a bug in the fork, breaks interop or
loses frames.

**Mitigation**: the fork tracks `teranos/leviculum` upstream
(`Cargo.toml`, the leviculum pin comment); edge uses leviculum's
reliability primitives at the pin rather than re-implementing them;
`tests/leviculum_interface_diversity.rs` covers the interface kinds. E1
makes Python-RNS interop for edge frames moot: a peer that does not run
the seal is outside the mesh (CC 5.3.3.5 E1 rule 11).

**Residual**: a leviculum bug is edge's exposure until fixed upstream.
Pre-0.34 peers keep edge's upgrade guard (`docs/RELEASE_NOTES.md`
v44.1.0). The earlier statement that edge ships on reticulum-rs is no
longer true.

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

**44.x note**: the binding is now a verified-only superseding route
table (`route_supersession_decision`, `src/transport/reticulum.rs`;
`tests/route_table_e2e.rs`), and the E1 seal resolves a pair only from a Rooted
binding, the node's own hybrid-signed route row, or a pairing pin, never a
bare announce (CC 5.3.3.5 E1 rule 3; AV-53). The announce attestation is
still signed Ed25519 only (`src/transport/reticulum.rs:21274-21280`); see
§9 R-4.

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
predating persist v2.12.0 / #112. (That seed-file path is gone at
44.x; no `from_seed_dir` remains in `src/identity.rs`.)

**Residual**: a future contributor wires Reticulum's transport
identity through `keyring_signer_capsule` directly (bypassing the
adapter), or copies the local seed across the FFI rather than holding
the capsule. PR review catches the first (the type doesn't compile —
Reticulum's transport-identity constructor expects 32 bytes, not 65);
PR review is the only gate for the second (the AV-17 heap-scan test
was never built).

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
scope-irrespective** (a structural property of the signer API; no
heap-scan test exists). Consumers
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
    `None` (the default) structurally disables the short-circuit —
    same effect as `threshold = 0.0`. **v0.20.0 RC1
    (CIRISEdge#51 / CIRISPersist#129)**: the cohabitation pyo3 init
    path now auto-derives the scorer via
    `extract_trust_scoring(engine)` (`src/ffi/pyo3.rs`), which
    consumes persist v3.5.1+'s `Engine::trust_scoring_capsule`
    (name tag `ciris_persist::trust_scoring`, wrapped type
    `Arc<dyn TrustScoring>`). When no `AdmissionGate` has been
    installed (the typed `ValueError("trust_scoring_unavailable")`),
    the cohab path falls back to `None` (bootstrap-permissive) and
    logs an info breadcrumb naming the install path
    (`Engine::set_admission_gate`).

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

**v0.20.0 RC1 closure** (CIRISEdge#51 / CIRISPersist#129): the
v0.19.6 cohabitation-deferral residual is removed. Persist v3.5.1
shipped the 7th cohabitation capsule
(`Engine::trust_scoring_capsule`, name tag
`ciris_persist::trust_scoring`); edge consumes it via
`src/ffi/pyo3.rs::extract_trust_scoring`. The cohab pyo3 init now
auto-derives the `Arc<dyn TrustScoring>` from the engine's
installed `AdmissionGate` (the same Arc that
`Engine::set_admission_gate(...)` installs) and falls back to the
bootstrap-permissive `None` posture (matching the operator
sentinel `trust_threshold = 0.0`) when no gate is installed. The
typed `TrustScoringCapsuleError::Other` variant preserves the
v0.13.0 "loud fail on unexpected capsule shape" contract; missing
methods and typed unavailability fall back with structured warn /
info logs. Operators deploying outside the cohabitation path
(sovereign Pi / mobile / standalone hosts using `EdgeBuilder`
directly) continue to wire the scorer via
`EdgeBuilder::trust_scoring()` — unchanged from v0.19.6.

**v0.20.0 RC1 recursion-depth wiring** (CIRISEdge#51,
`EdgeConfig::trust_recursion_depth` + `AgentMode::
default_trust_recursion_depth`): the resolver call now passes the
operator-configured depth (CEWP L0 = 0, L1 = 1) instead of v0.19.6's
hardcoded `0`. Persist's `TrustScoring::trust_score(_,
recursion_depth: u8)` walks `delegates_to` edges per the BFS in
`crate::federation::topology::build_delegation_graph`; depth = 0
yields strict direct attestations, depth = 1 yields friend-of-
friends. The L0/L1 tier is documented as a security boundary
below (§4.9 CEWP L0/L1 tier model).

#### CEWP L0/L1 tier model — recursion depth as blast-radius bound, disk budget as capacity-gated admission contract (v0.20.0 RC1, CIRISEdge#51)

**Architectural framing**: CIRIS 3.0 is the **CIRIS Epistemic Web
Platform (CEWP)** per FSD `FEDERATION_SCALING_MODEL.md` +
`CIRISNodeCore/FSD/CEWP.md`. The federation scales across
deployments with **distinct storage + trust tiers** — a sovereign Pi
(L0 / Proxy) is not a curated bootstrap host (L1 / Server); a
hyperscaler-detached client is neither. v0.20.0 RC1 promotes
`AgentMode` from the v0.18.0 "listener bind + outbound queue cap"
posture-only knobs to the full L0/L1 tier vocabulary:

| Mode     | CEWP tier | Disk budget   | Trust recursion |
|----------|-----------|---------------|-----------------|
| Client   | n/a       | 0             | 0               |
| Proxy    | L0        | 256 GB        | 0 (strict)      |
| Server   | L1        | 1 TB          | 1 (FoF)         |

**`trust_recursion_depth` as security boundary**: the depth threads
into persist's `TrustScoring::trust_score(key_id, recursion_depth)`
(CIRISPersist#123) which walks `delegates_to` attestation edges per
the BFS in `crate::federation::topology::build_delegation_graph`.
**Higher depth = wider attestation graph = larger blast radius if
a single attester is compromised**. Strict depth = 0 (L0) only
counts attestations directly targeting the key; depth = 1 (L1)
walks one `delegates_to` hop and counts the attester's attesters as
well. The L0/L1 default is a **conservative bound** — the spec's
"distinct CEWP tiers" framing maps directly onto attestation-graph
distance. Operators may override per deployment via
`init_edge_runtime`'s `trust_recursion_depth` kwarg (e.g. a curated
bootstrap host may pin depth = 0 even though L1 default is 1, when
the operator wants direct-trust strictness regardless of tier).

**`disk_budget_bytes` as capacity-gated admission contract**: edge
**does not enforce** the budget — persist or the host consults
`Edge::disk_budget_bytes()` (`src/edge.rs`) at admission time. The
edge surface exposes the budget as a contract: a peer declaring
itself an L1 server agrees to host up to 1 TB of evidence; a peer
declaring itself an L0 proxy agrees to 256 GB. The substrate that
admits content rows checks `disk_budget_bytes` against current
table size before write — capacity-gated admission per persist's
`AdmissionGate` discipline. Without the per-tier contract,
federation peers cannot reason about who can hold what, and the
N_eff measurement that CIRIS's Proof-of-Benefit substrate computes
(`PROOF_OF_BENEFIT_FEDERATION.md` §2.4) becomes opaque to capacity
constraints.

**Threat that the L0/L1 model intentionally leaves open**: a peer
declaring itself L1 but actually only having 32 GB of storage is
not detectable from the edge tier alone. The discrepancy surfaces
at persist's first admission failure (a row is too large to admit
under the actual capacity); the operator gets a typed error from
persist + an opportunity to either reduce the budget declaration
or expand storage. Edge advertises the contract; persist enforces
it; the **declaration-vs-reality gap is a persist responsibility,
not an edge one**. The apophatic bound §1.4 "Not a storage layer"
holds.

**Threat that the L0/L1 model architecturally closes**: a peer
declaring itself L1 but pinning depth = 5 to inflate its trust
score is blocked at the persist tier — persist's `TrustScoring`
admits the depth as an argument but persist's `AdmissionGate`
discipline can cap the effective depth per-deployment. Edge is the
contract-surface; persist is the policy-enforcement-surface. L2+
tiers (depth ≥ 2, multi-TB) are deferred to a post-v1.0 cut — the
v1.0 GA contract is L0/L1 only.

**Test**: `tests/agent_mode_init.rs` (12 tests covering the
default-budget + recursion-depth matrix per mode + operator-
override semantics) and `tests/trust_recursion_depth_wired.rs` (5
tests pinning the
`EdgeConfig::trust_recursion_depth → dispatch_inbound →
TrustScoring::trust_score` byte-equivalence flow via a recording
scorer).

**Residual**: `disk_budget_bytes` is advisory at edge — operators
must use persist's `Engine::set_capacity_budget` (post-v1.0
follow-up; documented contract not yet shipped) to get
persist-tier enforcement. Until persist v3.7+, an L0 proxy that
exceeds 256 GB will see persist admit rows past the declared budget
with no edge-side rejection; the operator sees the discrepancy via
the standard persist row-count + disk-usage observability surface,
not via a typed disk-budget rejection (a future
`DiskBudgetExceeded` shape; reserved name not yet taken). The wire
contract (the field exists and is byte-equivalent across peers) is
locked at v0.20.0 RC1; enforcement is a persist follow-up.

#### AV-49 — Multimedia tier transport semantics (v0.20.1, CIRISEdge#52)

**AV-49 — Multimedia tier transport semantics**:
- takedown_notice fast-path bypasses standard rate-limiting for TVEC/GIFCT-CIP/NCMEC (legal-compliance basis)
- Edge does not fetch external bytes; consumer's client fetches directly from external_uri (avoiding edge-as-MitM concerns + bandwidth amplification)
- L1-as-CDN-edge opt-in is operator choice; opt-out is the default
- BlobBody::External bytes are NOT scrubbed by edge (scrub primitive is for inline_text_pipeline only); external content is the publisher's responsibility

**Implementation surfaces (CIRISEdge#52, v0.20.1)**:

- `src/multimedia.rs` — typed `FastPathLegalBasis` (TVEC, GIFCT-CIP,
  NCMEC) + `ContributionSubjectKind` (TakedownNotice, KeyGrant) +
  `ContributionDispatchProbe` (best-effort body-field projection) +
  `ExternalRefWithAcl` (wire-form for the BlobBody::External pointer)
  + `cdn_edge_prefetch_stub` (L1-CDN-edge async entry point).
- `src/edge.rs::dispatch_inbound` — Contribution sub-dispatch arm
  fires `edge.dispatch.takedown_fast_path` on a fast-path
  legal_basis match, `edge.dispatch.key_grant` on KeyGrant, and
  `tokio::spawn`s `cdn_edge_prefetch_stub` on Server-mode +
  l1_cdn_edge_enabled + external blob_body_kind.
- `src/edge.rs::validate_content_body` — short-circuits the AV-13
  + SHA-256 integrity gate when the body's `kind == "external"`
  discriminator is set; edge does NOT re-hash external bytes (they
  are not held at edge to hash).
- `EdgeConfig::{l1_cdn_edge_enabled, l1_cdn_edge_external_uri_base}` —
  L1-as-CDN-edge opt-in. Default `false / None`. Operator-set per
  deployment; Client + Proxy modes IGNORE the flag (Spec §2.7
  restricts CDN-edge to L1/Server).

**Threat that AV-49 INTENTIONALLY closes**: a malicious peer
attempting to coerce edge into bandwidth amplification by sending
`BlobBody::External` envelopes that point at attacker-controlled
URIs — edge structurally does NOT fetch external bytes, so the
attacker cannot induce edge-side egress regardless of how many
Contribution envelopes they ship. The consumer's client decides
whether to fetch, and the consumer's client side is where the
fetch policy lives.

**Threat that AV-49 INTENTIONALLY leaves observable**: a TakedownNotice
carrying a forged `legal_basis: tvec` to inflate dispatch priority.
The fast-path arm is an OBSERVABILITY emission (`tracing::info!` +
ResourceEvent on the event bus) — it does NOT grant the sender any
authority edge would not otherwise extend; the substrate's existing
ModerationEvent + Slashing path is the corrective if the
legal_basis claim is later disputed. The fast-path is a routing
hint, not an admission grant.

**Threat that AV-49 does NOT close**: a Server-mode L1 operator who
opts in to L1-as-CDN-edge and then prefetches malicious bytes from
an attacker-controlled `external_uri` (post-v1.0 follow-up; the
v0.20.1 stub does NOT actually fetch). When the full prefetch
implementation lands, the operator's L1-CDN-edge will be subject to
the publisher's signed ACL (carried in `ExternalRefWithAcl::acl_signature`)
+ the SHA-256 verification step (`external_sha256_hex`); a
mismatched fetch MUST be discarded (the operator's own substrate
admission gates remain authoritative). The wire shape locks the
contract; the full enforcement lands when the prefetch ships.

**Test**: `tests/multimedia_tier.rs` — 22 tests covering the
fast-path legal_basis vocabulary, the Contribution sub-dispatch
routing matrix, BlobBody::External vs inline bytes, the
L1-as-CDN-edge gate matrix (mode × enabled × URI base), and the
cohort_scope preservation (Strict enforcement still applies BEFORE
the multimedia sub-dispatch arm executes — defence-in-depth).
Plus 10 in-module unit tests pinning the wire-string codec for
the typed enums.

**Residual**: the L1-as-CDN-edge prefetch is a STUB at v0.20.1 —
`cdn_edge_prefetch_stub` logs the trigger via `tracing::info!`
but does NOT perform the HTTP GET. The wire shape is locked here;
the full implementation (reqwest-driven fetch + SHA verification +
operator-base re-publish + filing the holding claim, a
`custody:ack:v1` `here` row since v55) is a post-v1.0
cut. Operators who flip `l1_cdn_edge_enabled = true` at v0.20.1
see the trigger fire in observability but no bytes move — the
operator-side opt-in surface is locked; the bytes-fetching wire
follows when persist's external-content admission lands.

#### AV-50 — Path-independence threat surface (v4.0 CEWP-1.0 seal)

**AV-50 — Path-independence violation in holonomic substrate**: the
v4.0 substrate exposes a load-bearing invariant — **two peers given
byte-equal input snapshots produce byte-equal outputs** across all
four holonomic primitives (swarm rarity, WholenessWitness,
deterministic ALM topology, recursive trust bootstrap). The threat is
**substrate-implementation divergence**: a peer running a non-
conformant implementation (different scoring constants, different
canonicalization, different Merkle layout, different tie-break order)
produces a different output from the same input. The federation
fragments into split-brain partitions sharing the wire but
disagreeing about state.

**Implementation surfaces (v3.10.0, locked at v1)**:

- `src/holonomic/swarm_rarity.rs` — `FountainHoldingClaim` canonical
  field order: `(peer_id, content_id, symbol_ids, observed_at_unix_ms,
  claim_version)`; `compute_rarity_score` deterministic by holding-
  claim count and lex-min tie-break.

- `src/holonomic/wholeness_witness.rs` — `WholenessWitness` canonical
  field order: `(peer_id, epoch_id, merkle_root, leaf_count,
  claim_namespaces, observed_at_unix_ms, witness_version)`;
  `claim_namespaces` lex-sorted; `merkle_root` lowercase 64-char hex;
  empty-input sentinel `SHA-256("WW-v1-empty") = 2280d27f...49563464f`;
  Merkle construction: single-hash leaf domain + CT-style duplicate-
  last on odd-count layers.

- `src/holonomic/deterministic_topology.rs` — `compute_alm_topology`
  v1 wire-determinism constants LOCKED: `TOPOLOGY_VERSION=1`,
  `MAX_USEFUL_RTT_MS=5000`, `MAX_TRUST_CHAIN_DEPTH=4`,
  `WEIGHT_CAPACITY=50`, `WEIGHT_TRUST=30`, `WEIGHT_REACHABILITY=20`,
  `CAPACITY_NORMALIZER_MILLIBPS=10_000_000`. Integer (u64) scoring
  only — NO floats; floats are non-deterministic across architectures.
  Tie-break: parent lex-min when scores tie; child iteration order:
  child lex-min.

- `src/holonomic/recursive_trust_bootstrap.rs` — 16-byte domain
  separator `CIRIS-CLAIM-v1` on `SignedClaim` canonical bytes
  (distinct from `CIRISALM-CAPv2` used by `SignedRelayCapacity`);
  prevents replay across claim types. Chain walked backwards
  (newest first; first anchor wins); trust distance =
  `anchor_distance + chain.len() - chain_index_of_anchor`.

**Mitigation**: cross-implementation conformance is enforced via
CIRISRegistry CEG 1.1 normative absorption ([CIRISRegistry#85](https://github.com/CIRISAI/CIRISRegistry/issues/85))
— §B (bootstrap), §T (topology), §W (witness), §R (rarity) ratify
byte-exact input → output test vectors. Any implementation claiming
CEWP-1.0 conformance MUST reproduce the vectors bit-exactly.

**Residual risk**: an attacker running a deliberately-non-conformant
implementation cannot bypass admission (admission verifies hybrid
PQC signatures + chain-to-root) but CAN cause local view drift on
peers that trust their topology calculations. Mitigation:
`WholenessWitness` epoch cross-comparison surfaces `Divergent`
state, which gates reconciliation — divergent peers MUST reconcile
before participating in subsequent rounds, blocking drift from
propagating.

**Test**: holonomic test suite (45 tests) covers (a) determinism
under input permutation, (b) canonical-bytes locked field order,
(c) Merkle determinism property, (d) chain-walk backwards property,
(e) tie-break invariants. CEG 1.1 §B/§T/§W/§R conformance vectors
make these properties cross-repo verifiable.

#### AV-52 — Constitutional-discipline adversary surface (v5.0; CC 0.1.5)

**AV-52 — Adversary tries to inject a privileged-principal shortcut
or content-policy in violation of the Constitution's discipline**:
the **CIRIS Constitution** (CC 0.1.5; woven CIRIS Accord 1.3-RC2 +
CEG 1.0-RC29) places normative constraints on what the substrate is
allowed to *be*. These are not policy constraints on the operator —
they are structural invariants of the wire. An adversary attempts
to subvert one of:

1. **CC 1.13.1 Ubuntu commitment #5 — Recursive Golden Rule**: try
   to land a code path that admits a "trusted bootstrap peer" via a
   shortcut not available to ordinary peers. The substrate's
   `recursive_trust_bootstrap` MUST walk the same chain rules
   regardless of signer identity; founder-quorum applies only to
   *infrastructure roots* as a structural property, never as a
   "this signer is special" bypass.

2. **CC 1.13.5 operational-language gate** (safety ≠ censorship):
   try to add a refusal code or admission filter whose *meaning*
   encodes preferences-about-content rather than a mechanically-
   checkable substrate property. The discipline is that
   `EjectionVerdict` variants name mechanism (revocation, capacity
   pressure, tier-aggregation), never content classes. A patch that
   introduces a content-keyed refusal MUST fail review on this
   ground.

3. **CC 1.13.4 substrate-stores-never-adjudicates**: try to make a
   `should_eject_above_target` / `recursive_trust_bootstrap` / §19
   primitive consult an agency-tier policy (a "decision" surface).
   These are mechanical-degradation operators. Adding agency to them
   is a Constitutional violation regardless of operational benefit.

4. **§19.1 WW-2 / Constitution privacy**: try to land a Merkle leaf
   walk that includes anonymous-tier or `cohort_scope: self` rows.
   This re-attributes structurally-deniable content to a stable
   `peer_id` — a violation of the Ubuntu privacy substrate that the
   Constitution enforces. The producer-side filter
   `filter_witness_leaves` is the gate.

5. **§19.7 N5 / consent override**: try to make rarity weight
   resurrect revoked content (the §19.3 N5 inversion). Any code
   path where `ConsentState::Revoked` does not produce
   `EjectionVerdict::EjectHardDelete` is a Constitutional violation
   regardless of how it's spelled.

6. **CC 5.3.2.4.3.1 PQC-mandatory**: try to land a non-hybrid
   signing path or a verifier that accepts an empty/invalid
   ML-DSA-65 half on a federation-tier object. v9.0.0 G1+G2 made
   this a BREAKING change at persist's store gate; edge's producer
   side must NEVER emit a federation-tier object lacking the bound
   hybrid pair.

7. **CC 5.6.8.10 TRUST≠MEMBERSHIP confusion**: try to make a
   chain-walk return a membership verdict from
   `recursive_trust_bootstrap`. Pre-v4.1.0 this was the F-1
   CRITICAL — admission was conflated with trust-graph reachability.
   The fix (v4.1.0 PR #146) was `AdmitTrustServe` only; membership
   admission requires the destination's separate §5.6.8.10
   owner-binding gate. A regression here re-opens the Constitutional
   gap.

**Implementation invariants (v5.0)**:

- Every refusal variant in `holonomic::recursive_trust_bootstrap::AdmissionRefusal`
  names a substrate property (`ChainExhausted`, `SignatureInvalid`,
  `ChainTooLong`, `BudgetExceeded`, `TrustGraphCycle`,
  `AggregateWeightCapExceeded`, `OwnerBindingMissing`). None encodes
  content preferences.
- Every `EjectionVerdict` variant names mechanism (`EjectHardDelete`,
  `EjectToTier`, `EjectAggregatedTierOnly { tier }`, `Keep`). None
  encodes content classes.
- §19.1 `WholenessWitness::filter_witness_leaves` is structurally
  required to be called before `compute_merkle_root` in every
  producer path that emits a witness.
- `swarm_rarity::should_eject_above_target` short-circuits on
  `ConsentState::Revoked` → `EjectHardDelete` regardless of holder
  count or rarity score. Compile-time `const _: () = assert!(...)`
  guards in `fountain_defaults` pin the §R-policy invariants.
- The PQC-mandatory signing discipline is enforced at the producer
  layer (every signed object carries the bound hybrid pair) AND at
  the persist v9.0.0+ ingest gate (verify-before-persist).

**Residual risk**:

- The Constitution is a living document (CC 0.1.5; future versions
  may add invariants). The substrate's compile-time / wire-locked
  invariants harden against *current* Constitutional adversaries;
  future Constitutional amendments may require substrate updates
  to maintain conformance. The CEG normative absorption process
  (CIRISRegistry#85 / #89 family) is the formal channel.
- Operator-tier policy above the substrate can still encode
  content preferences; the substrate's job is to ensure those
  preferences don't leak *into* the wire shape. An operator who
  configures their policy layer to refuse certain content classes
  doesn't violate the Constitution (CC 1.13.5 explicitly allows
  this at the policy layer); the substrate's MUST is that the
  refusal not be wire-observable as a content-keyed mechanism.

**Test**: structural — every `AdmissionRefusal` and `EjectionVerdict`
variant is documented as mechanism-only; PR review must reject any
content-keyed addition. The compile-time invariants in
`fountain_defaults`, the `WW-PREIMAGE-v1` domain separator + bound-
hybrid signing tests, and the §19 + §19.7 conformance vector round-
trip all serve as continuous Constitutional-discipline regression
guards.

### 4.9 Invariants anchored at v0.17.1 (shipped from v0.18.0)

#### Canonical-peer invariant (CIRISEdge#46 — shipped; `tests/canonical_peer.rs`)

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

### 4.10 The 44.x surface — transit seal, three meshes, what moves, relay load, the Anonymous Tier

Each vector here was derived for 44.1 from the CC text and the code at
`1175e65`. The witness column names the test that fails if the mitigation
stops holding.

#### AV-53 — Reading or redirecting traffic on an RNS link (CC 5.3.3.5 E1)

**Attack**: a forwarder, an on-path observer, or a harvest-now-decrypt-later
recorder reads frames on an RNS link; or a dialler is steered to an
adversary's transit pair so the adversary can open what it seals.

**Mitigation**: every byte edge sends over an RNS link is under a hybrid
(X25519 + ML-KEM-768) transit seal bound to the link's id, run once per link
as its first frame, covering Channel messages, Resources, requests and
responses in both directions (CC 5.3.3.5 E1 rules 3-4;
`src/transport/link_seal.rs:1-16`). There is no advisory mode and no
classical-only lane: a peer that does not run the seal gets nothing (E1
rule 11). The dialler resolves a pair **authenticated to the node it means
to reach** before it dials: a Rooted binding, else the node's own
hybrid-signed route row, else a pairing pin, never a bare announce (E1
rule 3; `LinkSeals::resolve_pair`). With none, the pre-seal route fetch asks
the dialled node for its own signed row and checks signer and subject equal
the dialled key before storing anything (E1 rules 5-7;
`src/transport/route_fetch.rs`). A responder delivers nothing upward until
the handshake completes, refuses a first frame that is neither a handshake
nor a route request, answers at most one route request per link, and runs
the per-link, per-sender and node-wide receiver rates before parsing (E1
rules 8-9; `ReceiverOrder`, `src/transport/link_keying.rs`). Links still
keying are capped node-wide and the oldest is refused by name, never the
newest (`AWAITING_LINKS_MAX`, `link_seal.rs` module head). Decapsulation runs
off the event loop in a bounded pool (CIRISEdge#947).

**Witness**: `tests/link_seal_e1.rs`, `tests/sealed_cut_bundle_e1.rs`,
`tests/offline_route_e1.rs`.

**Residual**: the handshake authenticates the responder only; the
initiator's id is a claim, held to the link's attribution on every frame,
and an unattributed initiator may carry only the first-contact plane
(`link_seal.rs`, "The claim and the first-contact carve-out"). The RNS layer
under the seal (link request, announce, path request) is classical (E1
rule 2); see §9 R-4. The KEM-authenticated handshake of the v62 edition is
planned, not shipped (CC 5.3.3.5, "The handshake of the v62 edition").

#### AV-54 — Inferring traffic from a shaped link, or defeating shaping (CC 5.4.3 rc17)

**Attack**: an observer of a link infers when and how much real traffic it
carries; or an adversary arranges for a link that should be shaped to run
unshaped, through a forwarder, or below its class.

**Mitigation** (CC 5.4.3, "Link shaping" and "A shaped link is one hop"):

- Shaping is a per-link property negotiated after the E1 handshake, under its
  keys: constant-size sealed frames on a Poisson timer, cover filling what
  real traffic leaves, at the lower of the two ends' budget classes
  (`src/transport/link_shaping.rs`, `SHAP` offer).
- **A shaped link is one direct hop.** A link a forwarder carries is never
  offered shaping and answers `off`; a shaped link that falls back onto a
  forwarder closes (`CLM-shaped-link-one-hop`; `link_is_forwarded`,
  `src/transport/reticulum.rs:534`; commit `79bd7fd`).
- **Off means not offered.** The setting says only whether a node offers
  shaping by default. A node with shaping off still gives a shaped link to a
  peer that asks, at its own device class, and drops it ten minutes after the
  last real frame, cover not counting (`CLM-shaping-offered-never-refused`;
  `DEFAULT_ASKED_IDLE_TTL`, `link_shaping.rs:1918`). Fleet defaults: on for
  `server` (and `seat`↔`seat`), off for `home`, `phone-wifi`,
  `phone-cellular` (`FLEET_DEFAULTS`, `link_shaping.rs:388`).
- **The bound.** At most eight shaped links, each at the full rate of its
  class (`NODE_CAP_LINKS`, `link_shaping.rs:495`); a `seat` link sits outside
  the eight. Past eight, a node set to shaped-only or to the Anonymous Tier
  refuses the ninth shaping peer with up to three referrals
  (`MAX_REFERRALS`, `src/transport/shaping_referral.rs:52`); every other node
  runs the ninth link **unshaped**. A shaped link is never run below its class
  (`CLM-shaped-link-bound-refuse`, CIRISEdge#952; `link_shaping.rs:309-333`).
- **Scoped and A/V links are never shaped**, whatever the policy
  (`LinkShapers::offer_off_for`, `link_shaping.rs:2978`); A/V is unshaped
  only (CC 5.4.3 item 4).

**Witness**: `tests/link_shaping_e1.rs`, `tests/direct_links_805.rs`,
`tests/poisson_emission_e2e.rs`.

**Residual** (stated by the CC, CC 5.4.3 item 5): link setup is observable;
a node with any unshaped link can be told from one that shapes every link;
shaping hides timing and volume inside a shaped link, not which links exist;
an adversary that drops or delays frames is outside the claim, and edge does
no defensive dropping (`docs/RELEASE_NOTES.md`, v44.0.0 "Known limits";
`FSD/TRANSPORT_TIERS_MODEL.md` §9.4). The link past the bound is the
**accepted leak**: an observer learns the node is at its bound
(`link_shaping.rs:328-333`). Displacement of a lower-class shaped peer is
not built (CIRISEdge#939): a higher-class newcomer at a full node is
refused, not given a slot (`link_shaping.rs:318-319`). The ρ/W/byte-budget
defaults come from a model on the production scheduler over a virtual clock,
not from a live mesh (CC 5.4.3, "Why these values").

#### AV-55 — Bulk or large content on the shaped plane (CC 5.4.3 rc17, "Two planes")

**Attack**: a large message rides a shaped link, starving the rows that
share it or exposing its size by the time it holds the link; or a failed bulk
dial silently falls back onto shaped frames.

**Mitigation**: one constant decides. A message over 64 KiB is bulk whatever
its type (`SHAPED_ROW_MAX_BYTES`, `link_shaping.rs:462`; `is_bulk_payload`),
and content/blob chunk bodies and their fetches are bulk by kind
(`BULK_MESSAGE_TYPES`, `link_shaping.rs:448`). A bulk send to a peer no
unshaped link reaches is refused by name, `link_shaping_bulk_refused`
(`src/observability.rs:1273`), and retried on the dispatcher's schedule; the
fragment fallback that carried bulk on shaped frames was removed (commit
`cafb90d`).

**Witness**: `the_row_limit_is_one_constant` (`link_shaping.rs:3887`),
`tests/link_shaping_e1.rs`.

**Residual / not yet as the CC says**: CC 5.4.3 rc17 puts chat and files on a
shaped link only when one end is shaped-only. At 44.1 a row of 64 KiB or less
rides whatever shaped link exists between the pair; chat and small-attachment
routing is 44.2 work (commit `cafb90d`; `FSD/PRIVACY_MODES.md` §2.3). The
CC's named refusal for a shaped-only node fetching a large file ("This file
is too large to access over shaped links") is not emitted; the code refuses as
`link_shaping_bulk_refused`. A NAT'd peer reachable only over the link it
dialled waits for an unshaped link.

#### AV-56 — A peer becomes a mirror of a corpus it has no business holding (CC 5.2)

**Attack**: a single `consent:replication` grant, or federation tier alone,
causes a node to offer a peer every federation row it holds, oldest first:
a privacy over-reach (the peer learns rows nobody asked to move to it) and a
load lever (11,662 rows / 42 MB to one new contact, `docs/RELEASE_NOTES.md`
v44.1.0).

**Mitigation**: a row moves when it is **requested, or required, and
appropriate**, never because it is federation-tier (CC 5.2, "What moves to a
peer"; `CLM-moves-requested-required-appropriate`). Two seats on the active
roster keep the anti-entropy walk. Every other peer gets the required read
first (live grants naming it, rows to it or its person, its own rows, this
node's allegiance rows), then only what is required or appropriate and live
(`unasked_offer`, `src/replication/bridge.rs:10911`). A grant moves the
class it names and nothing else. The served set is pinned by
`SERVE_ADVERTISE_POLICY_HASH` = `14aedf25…` (`docs/RELEASE_NOTES.md`
v44.1.0), which CIRISServer must mirror.

**Witness**: `src/replication/bridge/tests/moves_5_2.rs`.

**Residual**: a third party's `membership:proposal:v1` older than the 60 s
margin waits for the history read (one page a minute) until persist offers a
read by subject (`docs/RELEASE_NOTES.md` v44.1.0). The fetch twin and the
subject Pull still move any row on request, a superseded row included, which
is what CC 5.2 means by "requested". This is a load and over-reach bound,
not a confidentiality boundary: what a peer may receive at all is still
decided by the audience gates (CC 5.3.2.4, `may_receive`).

#### AV-57 — Starving first contact by closing a relay (CC 5.4.6; `FSD/CIRIS_MESH.md` §7.2, §7.7)

**Attack**: an adversary (or ordinary load) pushes a canonical into a high
service tier; if the tier closes forwarding, every NAT'd node that can only
be reached through it loses first contact, and each refused dial is retried
(v44.0 turned one refused dial into 48 retries).

**Mitigation**: **the service tier never closes forwarding**
(`src/transport/relay_tier.rs:36-40`). What bounds a relay is a configured
link bound and the link table cap, fixed process bounds, plus its C2
forward admission (`ForwardAdmission`, `relay_tier.rs`). Load is shed through
the host's levers (`src/load_levers.rs:1-23`): `walk`, `page` and `bulk`
each move one step at a time (`RAISE_STEP` 10 s, `RELEASE_STEP` 30 s), each
step halves a cost and none refuses anything, and every pull is a **lease**
(`LEASE_MAX` 300 s) that walks back to 0 when the host stops renewing.
Forwarding, subject Pulls, announces and owed rounds are outside every
lever. Edge implements the gauges and levers; the host decides when to pull
them.

**Witness**: `tests/relay_roster_752.rs`, `src/load_levers.rs` unit tests.

**Residual**: forwarding remains admitted up to the process bounds, so a
relay under a forward flood degrades at those bounds rather than by tier.
`ForwardAdmissionConfig` has no PyO3 kwarg (`docs/RELEASE_NOTES.md` v44.0.0
"Known limits"), so a Python-only host cannot set it.

#### AV-58 — Onion replay and relay-state exhaustion (CC 5.4.6; CIRISEdge#955)

**Attack**: hop public keys are published, so anyone can mint valid onion
packets with distinct KEM ciphertexts; replaying one makes a relay forward it
twice, and minting many grows the relay's replay memory.

**Mitigation**: the relay accepts in a fixed order: the link is shaped, before
any cryptography (`onion_unshaped_link`); the packet peels under the current
or previous hop key; its period is this one or the last
(`onion_period_mismatch`); its encapsulation is new within two periods
(`onion_replay`); a forward fits the hold bound (`onion_hold_deferred`)
(`src/onion/relay.rs:6-13`). The replay tag is `SHA3-256("ciris-onion/v1/replay"
‖ ct)` (`src/onion/packet.rs:111-112`).

**Status at `1175e65`**: the replay set rotates by period but has no
ceiling (`ReplaySet`, `relay.rs:86-110`). CIRISEdge#955, landing in 44.1,
bounds it by the admitted rate per period and refuses by name past the bound,
never evicting silently (CC 5.3.3.5 E1 rule 9: a hold is bounded and refuses
on overflow by name). Until it lands, the bound is the shaped rate per link
times the number of shaped links, which the eight-link bound caps. The tier
is dormant (AV-59), so no production relay holds a replay set today.

#### AV-59 — The Anonymous Tier: what it is at 44.x, and the identity rule (CC 5.4.6)

**Status**: wired and **dormant** (`src/onion/mod.rs:1-8`;
`FSD/ONION_ROUTING.md`, "v44 status"). It runs only when the operator opts
in (`OnionPolicy::enabled`, default off) **and** every layer has three relays
dealt and answering; the canonical bundle seats too few relays, so every node
answers `onion_tier_not_opted_in` or `onion_tier_unavailable_floor`. The CC
has not pinned the packet layout, key-derivation label or AEAD (CC 5.4.6,
"The Anonymous Tier"); edge's `outfox-xwing-v1` codec is a submission
(`docs/onion_packet_wire.md`). The transit pair stands in for the onion hop
key until CIRISPersist#1181 (`src/onion/hop_key.rs`). The rendezvous row and
mailbox (CIRISPersist#1149), the fold reader that builds relay candidates,
the pseudonym's persist gate, and an over-the-wire RNS loopback are owed
(`FSD/ONION_ROUTING.md`, "Still owed").

**What holds today**: an onion packet never rides an unshaped link (AV-58);
a node in the tier starts no call and no stream (`onion_anonymous_no_media`,
`src/onion/tokens.rs:59`; CC 5.4.3 "Two planes"); layer links are shaped and
count within the eight (`FSD/ONION_ROUTING.md`).

**The identity rule (CC 5.4.6)**: an anonymous node is a separate, dedicated
identity with no row linking it to any announced identity of the person; it
**proxies nothing and relays nothing** under that identity, and a node that
activated the tier holds that identity alone, because a public route at the
same address would hand its guard the name behind it. **Not enforced in code
at 44.1**: `relay_offering` (`src/onion/policy.rs:72-74`) does not read
`OnionPolicy::enabled`, so an opted-in node whose relay offering is on would
still report free shaped slots and be named in referrals (a proxy under
CC 5.4.6). The tier is dormant, so this is latent; it must close before the
tier can activate. See §9 R-7.

**Residual** (CC 5.4.6 item 8, stated for when the tier runs): a relay can
count packets to one rendezvous per period; relays do not mix at today's
load; a phone that sleeps can be narrowed by a room insider together with an
observer of when it is online. The tier carries no delivery acknowledgement:
a publisher learns nothing of whether its packet arrived.

---

## 5. Mitigation Matrix

Status is at 44.1 (`1175e65`). "Built" means the mitigation is in the code and
named; "as written" means the entry's own version is the last time it was
checked and this regeneration did not re-derive it.

| AV | Attack | Mitigation at 44.1 | Status | Witness |
|---|---|---|---|---|
| AV-1 | Forged from attacker key | Attribution at ingest (`Rooted ∧ owns_key`) before any handler; persist directory gate | Built | `tests/reticulum_av42.rs`, `tests/rooting_chain_walk.rs` |
| AV-2 | Forged from compromised key | Out of edge's scope; statistical (N_eff drift) and key rotation/revocation | Residual (§9 R-1) | — |
| AV-3 | Replay within window | `(signing_key_id, nonce)` window, 5 min default (`src/verify.rs:1388-1408`) | Built; process-local | — |
| AV-4 | Replay outside window | Persist dedup / idempotent admission | As written | — |
| AV-5 | Canonicalization mismatch | Canonical bytes via persist only | As written | — |
| AV-6 | RNS destination spoofing | Destination derived from the transport identity; binding to the federation key is AV-42/AV-53 | Built | `tests/reticulum_av42.rs` |
| AV-7 | Schema-version downgrade | Strict allowlist, typed `unsupported_schema_version` (`src/verify.rs`) | Built | — |
| AV-8 | Misrouted acceptance | `VerifyError::Misrouted` before body parse (`src/verify.rs:1466`) | Built | — |
| AV-9 | Dispatch on unverified bytes | Structural (private dispatch path) | Built; the named `verify_enforcement` fuzz category was never built | — |
| AV-10 | Transport flooding | Receiver order: per-link, per-sender, node-wide rates before parse (CC 5.3.3.5 E1 rule 9) | Built | `tests/link_seal_e1.rs` |
| AV-11 | Verify-path saturation | Rates as AV-10; keying off the event loop in a bounded pool (#947) | Built | — |
| AV-12 | Replay-window memory | Bounded window + expiry (`ReplayWindow::new(.., max_replay_entries)`) | Built | — |
| AV-13 | Body-size flood | `MAX_BODY_BYTES` 8 MiB (`src/transport/frame_fragment.rs:139`; HTTPS `src/transport/http.rs:155`) | Built | — |
| AV-14 | Parse amplification | Typed envelope; `MAX_DATA_DEPTH` (`src/verify.rs`) | Built | — |
| AV-15 | Transport plaintext | E1 hybrid transit seal on every RNS link; TLS at the deployment edge for HTTPS | Built (RNS); deployment (HTTPS) | `tests/link_seal_e1.rs` |
| AV-16 | Verify timing side channel | None beyond constant-time primitives | Residual (key ids are public) | — |
| AV-17 | Seed bytes in edge's heap | Federation signing seed held behind `Arc<dyn HardwareSigner>`; edge code never reads it. Transport secrets (RNS identity, transit KEX seed, link keys) ARE in process, zeroized on drop | Built; the heap-scan property test was never built | `tests/key_boundary_scope.rs` (wire form only) |
| AV-18 | Cross-medium replay | Transport-agnostic window | As written | — |
| AV-19 | Slow-medium timing | None | Residual | — |
| AV-20 | I²P endpoint enumeration | Not applicable: no I²P transport is built | — | — |
| AV-21–23 | Discipline drifts | PR review | Discipline-only | — |
| AV-24 | Build-manifest forgery | Hybrid release signature | As written | — |
| AV-25 | RNS implementation drift | Edge runs leviculum (CIRISAI fork, `v0.34.0+ciris.1`); Python-RNS interop is leviculum's | Residual (§9 R-11) | `tests/leviculum_interface_diversity.rs` |
| AV-42 | Transport-identity ↔ federation-key spoof | Authenticated superseding route table; seal binds an authenticated pair (AV-53) | Built | `tests/reticulum_av42.rs`, `tests/route_table_e2e.rs` |
| AV-43–49 | Cohabitation / FFI / trust short-circuit / multimedia | As in each entry | As written (v0.13–v1.0) | per entry |
| AV-50, AV-52 | Path independence; constitutional discipline | As in each entry | As written (v4.0, v5.0) | per entry |
| Canonical-peer | Operator drops a canonical peer | Typed `CannotRemoveCanonicalPeer` (`src/edge.rs`) | Built | `tests/canonical_peer.rs` |
| AV-53 | Reading/redirecting RNS link traffic | E1 seal, authenticated pair, pre-seal route fetch, receiver order | Built | `tests/link_seal_e1.rs` |
| AV-54 | Shaped-link inference / defeat | One hop; off = not offered; eight-link bound; scoped and A/V never shaped | Built; displacement (#939) not built | `tests/link_shaping_e1.rs`, `tests/direct_links_805.rs` |
| AV-55 | Bulk on the shaped plane | 64 KiB row limit; bulk by kind; named refusal, no fallback | Built; rc17 chat/file routing is 44.2 | `tests/link_shaping_e1.rs` |
| AV-56 | Peer as mirror | Requested / required / appropriate (CC 5.2) | Built | `moves_5_2.rs` |
| AV-57 | Closing a relay on tier | Tier never closes forwarding; leased graduated levers | Built | `tests/relay_roster_752.rs` |
| AV-58 | Onion replay / replay memory | Ordered relay acceptance; replay set bounded by #955 | Ordered acceptance built; bound landing in 44.1 | `src/onion/relay.rs` tests |
| AV-59 | Anonymous Tier identity rule | Tier dormant; no-media built; identity rule not enforced | Dormant; gap (§9 R-7) | — |

---

## 6. Security Levels by Deployment Tier

| Tier | Transport | FFI shape | Notes |
|---|---|---|---|
| **Serve seat / canonical** | Reticulum over TCP; HTTPS | Rust host (CIRISServer links the crate) | Shaping on by default; `seat`↔`seat` links outside the eight (AV-54). Relay is mandatory for a serve node (CC 1.13.3.1 operator guidance). Takes host-pulled levers (AV-57). |
| **Home / agent node** | Reticulum over TCP / UDP / Auto; HTTPS | PyO3 wheel | Shaping off by default, offered on request (AV-54). |
| **Phone** | Reticulum over TCP when online | UniFFI (Android floor API 24) | Relays only while charging on an unmetered network (CC 5.4.6). Suspend / resume are host verbs (`Edge::suspend`, `Edge::resume`, `src/edge.rs:5018-5057`). |
| **Radio** | Reticulum over RNode (LoRa); packet radio (`transport-packet-radio`) | as host | The shaped frame is the link's MDU, ~400 B at the Reticulum base MTU (CC 5.4.3). |

**Critical invariant**: all tiers run the same attribution, seal, shaping and
serve gates. A finding in one tier's implementation is presumed to apply to
the same surface in others unless excepted.

---

## 7. Security Assumptions

If any of these is violated, the threat model breaks.

1. **Persist's directory and admission are sound.** Attribution, rooting,
   key and route admission are persist's doors; edge consults them.
2. **The signer is sound.** The federation seed lives behind the keyring
   signer. Its custody class (hardware-backed, or `SoftwareOnly` with the
   seed on disk) is the deployment's, and a same-host attacker on a
   `SoftwareOnly` node reads it (§9 R-10).
3. **Canonical bytes are deterministic** across hosts and versions (AV-5).
4. **The hybrid primitives hold**: at least one of Ed25519 / ML-DSA-65 for
   signatures and one of X25519 / ML-KEM-768 for key agreement (CC 5.1,
   CC 5.3.3.5 E1). SHA-256 / SHA3-256 collision resistance.
5. **TLS at the deployment edge for HTTPS.** E1 is a Reticulum rule; the
   HTTPS transport's confidentiality is the deployment's TLS.
6. **Clocks within ~5 minutes** across peers (AV-3); onion periods assume
   the same global clock (CC 5.4.6 item 7).
7. **The wire vocabulary pin matches the CC artifact** (`WIRE_VOCABULARY.md`
   v1.0.2, `src/lib.rs:169`; test `wire_vocabulary_hash_pinned`).
8. **The host is not compromised at root** (process memory, debugger,
   coredump are out of scope).
9. **The host pulls the levers it is meant to pull.** With no host pulling,
   every lever sits at 0 and the node serves its whole role
   (`src/load_levers.rs:3-5`); load policy is the host's, not edge's.

---

## 8. Fail-Secure Degradation

All failures degrade to more restrictive modes, never less.

| Failure | Behaviour at 44.1 |
|---|---|
| Envelope schema / version / signature / key failure | Typed reject; no handler invoked |
| Unattributable inbound frame | Dropped before any serve gate (CC 5.4.6 bootstrap carve-out excepted: Key, IdentityOccurrence, TransportDestination) |
| Peer does not run the E1 seal | Gets nothing; link refused by name (`SealRefusal`) |
| No authenticated pair for the dialled node | Pre-seal route fetch; else no dial, never a bare-announce pair |
| First frame neither handshake nor route request | Link dropped |
| Keying hold over its bound | Refused by name, never trimmed |
| Peer cannot meet a shaping offer | Declines the link rather than run half-shaped (CC 5.4.3 item 2) |
| Ninth shaping peer at a shaped-only / Anonymous-Tier node | Refused with up to three referrals |
| Bulk with no unshaped link | `link_shaping_bulk_refused`, retried on schedule; never shaped frames |
| Shaped frame over the Channel limit | Dropped by name (`link_shaping_frame_too_large`), link stays up |
| Onion packet on an unshaped link | `onion_unshaped_link`, before any cryptography |
| Tier not opted in / layer under three relays | `onion_tier_not_opted_in` / `onion_tier_unavailable_floor` |
| Host stops renewing a lever | Lever walks back to 0; node serves its whole role |
| Handler panics | Typed `handler_panicked`; process stays up |

Critical invariant: **unattributed or unverified bytes do not reach handlers.**

---

## 9. Residual Risks

What edge does not defend against at 44.x. The first group is the
Constitution's own statement of what the substrate does not buy; edge
inherits it and must not represent otherwise.

**Stated by the Constitution (CC 1.13.3.1, CC 5.2 scope note, CC 5.4.3 item 5,
CC 5.4.6):**

- **R-C1 Relationship existence, communication graph, metadata.** Group
  existence, rough size and churn are observable; announce and path request
  expose who is reachable where; cohort scope hides content, not contact
  (CC 1.13.3.1). Structural invisibility buys content-holding confidentiality
  only (CC 5.2, Scope).
- **R-C2 Traffic analysis.** Outside a shaped link, stream existence, group
  size, churn, bursts and bitrate class leak without decrypting a byte
  (CC 1.13.3.1). Shaping hides timing and volume inside a shaped link only,
  never which links exist, and a node with any unshaped link is
  distinguishable (CC 5.4.3 item 5). Scoped and A/V links are never shaped
  (AV-54).
- **R-C3 A global passive adversary at federation scope.** Not defeated by
  base CEG/RET; the Anonymous Tier is the opt-in answer, and it is dormant
  (CC 1.13.3.1; AV-59).
- **R-C4 Post-compromise security for streams.** Forward-only; a compromised
  current member is not self-healed (CC 1.13.3.1).
- **R-C5 First contact under a flood.** A swarm of minted keys can fill the
  node-wide stranger budget; an honest stranger's chance falls to about the
  budget over the flood's rate, and nothing keeps it up (CC 5.4.6, "What this
  does not promise").
- **R-C6 Relays do not mix at today's load; a phone that sleeps** can be
  narrowed by a room insider with an observer of its online times (CC 5.4.6
  item 8). Applies when the tier runs.
- **R-C7 Insiders.** An honest-but-curious member sees in-scope content and
  co-members; a malicious member can leak what it was entitled to; a
  compromised substrate node reads every attestation row it holds
  (CC 1.13.3.3).
- **R-C8 The growth tax.** Consent-gated replication has not been shown to
  coexist with mass adoption (CC 8.3.1 R11). AV-56 lowers the per-contact
  cost; it does not answer the bet.

**Edge's own residuals at 44.1:**

- **R-1 Compromised signing key** (AV-2): the verifier cannot tell a stolen
  key from its owner.
- **R-2 Persist directory compromise**: out of edge's scope (§7.1).
- **R-3 No defensive dropping.** Shaped frames ride the leviculum Channel, so
  a dropped frame becomes a delay and nothing at the shaping layer detects it
  (`docs/RELEASE_NOTES.md` v44.0.0 "Known limits").
- **R-4 Post-quantum metadata.** The RNS link layer (link request, announce,
  path request) is classical and not relied on for post-quantum
  confidentiality (CC 5.3.3.5 E1 rule 2); content keys, record signatures and
  the per-link seal carry the PQ guarantee (E1 rule 3). A recorder of today's
  links who later breaks X25519 recovers RNS link framing and the
  unsealed pre-seal route row (a public row, E1 rule 9), and learns which
  transport identities linked when, not what crossed the seal. Announce
  app-data's attestation is signed Ed25519 only
  (`src/transport/reticulum.rs:21274-21280`); E1 rule 3 keeps a bare announce
  from authenticating a transit pair, so a forged announce can misdirect a
  path, not open a seal. **Needs a CC or code answer**: the consumer
  `HybridPolicy::Ed25519Fallback` setting remains selectable
  (`src/ffi/pyo3.rs:5613`) and accepts an Ed25519-rooted provenance chain on
  the announce path (`hybrid_policy_accepts`, `reticulum.rs:21265-21272`);
  the default is `Strict` (`src/edge.rs:579`), and CC 5.3.2.4.3.1 / E1 rule 11
  admit no classical-only accommodation.
- **R-5 Deniability.** The link's identification frame is a signature; the
  KEM-authenticated handshake that removes the transferable proof is the
  planned v62 edition (CC 5.3.3.5).
- **R-6 A/V.** A/V across real NATs is unproven; A/V through the canonical
  is not end to end (one-hop legs) (`docs/RELEASE_NOTES.md` v44.0.0 "Known
  limits"). The ALM tree reads an epoch roll as total loss and lets a member
  claim depth 0 (CIRISEdge#945, open).
- **R-7 The Anonymous Tier is dormant and incomplete.** Packet not pinned by
  the CC; hop key is a stand-in (CIRISPersist#1181); no rendezvous or mailbox
  (CIRISPersist#1149); no over-the-wire loopback; **no delivery feedback**
  (a publisher cannot learn whether a packet arrived); the CC 5.4.6
  identity rule (an anonymous node proxies and relays nothing) is not
  enforced by `relay_offering` (AV-59). Replay memory is unbounded at
  `1175e65` and bounded by CIRISEdge#955 (AV-58). None of this is reachable
  while the tier is dormant; all of it must close before activation.
- **R-8 Shaping not yet as rc17 says.** Chat and small attachments ride any
  shaped link at 44.1 (rc17: only when one end is shaped-only); displacement
  is not built (#939); the named large-file refusal string is not emitted
  (AV-54, AV-55).
- **R-9 Replay window is process-local** (AV-3): a replay against a second
  instance of the same peer lands once per instance until persist dedups.
- **R-10 Same-host read of a `SoftwareOnly` seed.** Hardware-backed custody
  closes it; edge inherits the class the deployment runs.
- **R-11 leviculum.** Edge's RNS is a fork (`CIRISAI/leviculum`
  `v0.34.0+ciris.1`); a bug there is edge's exposure. Pre-0.34 peers keep
  edge's upgrade guard (`docs/RELEASE_NOTES.md` v44.1.0).
- **R-12 DNS for HTTPS.** The HTTPS transport inherits DNS.
- **R-13 Timing side channels on verify** (AV-16, AV-19).

### 9.1 What is measured, and what is not

"Measured" here means a test or harness demonstrates it; the scope of each
measurement is the claim's scope, and nothing larger.

| Claim | Measured by | Scope of the measurement | Not measured |
|---|---|---|---|
| Group plane: non-member cannot fetch, relay holds no group address, rotation without frame loss, address retirement | `bench-mesh/` legs (`docs/LIGHTNET_DARKNET.md`) | One host, docker containers: K=1 relay, M ∈ {1, 2, 4}, at most 7 nodes (8 at K=2) (`docs/LIGHTNET_DARKNET.md:155-156`; `bench-mesh/README.md:108-109`). Committed baselines are from v18.6.0–v18.8.0 (2026-08) | Any real NAT, WAN latency, radio, or more than 8 nodes. **The weekly lane (`.github/workflows/bench-mesh.yml`) has not passed since 2026-10-12**: the scheduled runs of 2026-10-19, 10-26 and 11-02 failed, so no acceptance sweep is recorded green on the 44.x line |
| E1 seal, route fetch, receiver order | `tests/link_seal_e1.rs`, `tests/offline_route_e1.rs` | Loopback leviculum nodes in one process | Python-RNS peers |
| Shaping: one hop, bound, off-not-offered, bulk refusal | `tests/link_shaping_e1.rs`, `tests/direct_links_805.rs` | Loopback, often at raised test rates | Live-mesh ρ/W behaviour (the CC's defaults are model-derived, CC 5.4.3) |
| Direct links and first contact across NAT | The cross-NAT harness (`docs/RELEASE_NOTES.md` v44.0.0; `FSD/CIRIS_MESH.md` §1) | Individual runs, not a scheduled gate | A/V across real NATs (R-6) |
| CC 5.2 moves | `moves_5_2.rs` | Unit, against a fixture store | Fleet-scale offer volume |
| Relay never closes on tier; levers | `tests/relay_roster_752.rs`, lever unit tests | Loopback / paused clock | A canonical under real forward flood |
| Onion packet codec | KATs (`src/onion/packet.rs`, `docs/onion_packet_wire.md`) | Codec only | Any onion delivery over a wire |

---

## 10. Posture Summary (44.x)

```
BUILT AND WITNESSED AT 44.1
  ✓ AV-53  E1 hybrid transit seal on every RNS link, enforced at once
  ✓ AV-54  Shaping per CC 5.4.3 rc17: one hop, off = not offered,
           eight-link bound (refuse only on shaped-only / anonymous),
           scoped and A/V never shaped
  ✓ AV-55  64 KiB row limit; bulk refused by name, never on shaped frames
  ✓ AV-56  CC 5.2 what moves to a peer
  ✓ AV-57  Tier never closes forwarding; graduated, leased host levers
  ✓ AV-1/6/42  Attribution and authenticated route binding before any handler
  ✓ AV-7/8/9/13/14  Strict version, misroute, typed parse, size and depth caps

LANDING IN 44.1
  ⧗ AV-58  Onion replay set bounded by admitted rate × period (#955)

DORMANT (must close before the Anonymous Tier activates)
  ○ AV-59  Identity rule not enforced; hop key stand-in (persist#1181);
           rendezvous/mailbox (persist#1149); packet not pinned by the CC;
           no delivery feedback; no over-the-wire loopback

KNOWN GAPS AGAINST CC rc17
  ⚠ Chat / small-attachment shaped routing (44.2)
  ⚠ Shaped-link displacement (#939)
  ⚠ HybridPolicy::Ed25519Fallback still selectable (§9 R-4)

UNMEASURED ON THIS LINE
  ⚠ No green acceptance sweep on 44.x (§9.1)
  ⚠ A/V across real NATs
```

**Bottom line**: at 44.x edge's contract is that every inbound byte is
attributed before a handler sees it, every RNS byte rides a hybrid seal,
shaped links are one hop and never diluted, a peer is offered only what it
asked for, needs, or is the audience of, and the relay a NAT'd node depends
on never closes on load. What it does not buy is the CC's list in §9, stated
there in the CC's own terms. Prior posture blocks (v0.1 → v1.0.0 GA) are in
this file's git history.

---

## 11. Update Cadence

This document is regenerated:

- **Per release line** (44.x, 45.x, …): pins, §0, §4.10, §5, §9 and §10
  re-derived from the code and the CC, with sources marked.
- **On a minor that changes a vector**: the vector amended in place, its
  witness named.
- **On a CC cut that touches Part 5 or CC 1.13.3**: §9's stated residuals
  re-read against the new text.
- **On a pin move** (persist, CIRISVerify, leviculum, `WIRE_VOCABULARY.md`):
  the pins table and any vector that names the old version.
- **When an acceptance sweep runs**: §9.1 updated with its scope, date and
  verdict, including a NOT MEASURED or a red.

Last regenerated: 2026-11-08, for the 44.x line at v44.1.0 (`1175e65`),
CIRISEdge#956. Previous baseline: 2026-05-30, v1.0.0 GA.
