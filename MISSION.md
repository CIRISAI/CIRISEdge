# MISSION — CIRISEdge

> Mission Driven Development (MDD): the FSD names *what* we build; this
> document names *why*, against the CIRIS Accord's objective ethical
> framework. Every component, every test, every PR cites against this
> file. Methodology: `~/CIRISAgent/FSD/MISSION_DRIVEN_DEVELOPMENT.md`
> and the overview at [ciris.ai/mdd](https://ciris.ai/mdd).

**Version**: 1.1
**Status**: Active — refreshed against `main` at v0.17.x (v1.0-prep docs cut)
**Date**: 2026-05-29

This is the reverse-engineered MDD charter for CIRISEdge: it maps the
four pillars — Mission (WHY) / Protocols (WHO) / Schemas (WHAT) / Logic
(HOW) — onto the code as it stands. Every claim is anchored to a file
path or constant; a reviewer should be able to grep from any sentence to
its implementation in under a minute. When the code drifts from the
doc, **the doc is wrong** — update it.

---

## 1. MISSION (WHY)

### 1.1 The Meta-Goal

The cornerstone, verbatim from the CIRIS Accord §VII (`~/CIRISAgent/ACCORD.md`):

> **Meta-Goal M-1** — Promote sustainable adaptive coherence: the living
> conditions under which diverse sentient beings may pursue their own
> flourishing in justice and wonder.

Every architectural decision in this repo is checked against M-1. The
Accord renders M-1 into six operationally-testable principles —
Beneficence, Non-maleficence, Integrity, Fidelity & Transparency,
Respect for Autonomy, Justice. CIRISEdge most directly serves
**Respect for Autonomy** ("honour the rights of agents to self-
determination") and **Justice** ("distribute benefits and burdens
equitably"): sovereign peers reaching each other over network media
*they* control — no broker, no DNS authority, no hyperscaler — is
autonomy rendered as transport; a LoRa or packet-radio deployment
being a first-class federation peer rather than a degraded tier is
Justice rendered as reach.

### 1.2 The cosmological floor — why a peer-to-peer wire is load-bearing

The vision beneath M-1 ([ciris.ai/vision](https://ciris.ai/vision)) is
**the corridor**: at every scale where coordination matters, healthy
systems sit in a band between over-rigidity (forced uniformity) and
fragmentation (no coherent cooperation). The corridor is governed by
one identity — `k_eff(k, ρ) = k / (1 + ρ(k−1))` — effective independent
dimensions collapse as correlation `ρ` rises. The federation's
Sybil-resistance (Proof of Benefit,
`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` §2.4) is an **N_eff
measurement** over the signed-evidence corpus; **N_eff is k_eff**.

CIRISEdge's place in that cosmology, rendered honestly:

- N_eff is only real if the peers being counted are **genuinely
  independent**. A federation of "distinct" peers that can only reach
  each other through a shared broker — a cloud load balancer, a DNS
  provider, a TLS authority — is not `k` independent dimensions. It is
  `k` deployments correlated through one chokepoint: `ρ → 1`,
  `k_eff → 1`. The broker is the correlation.
- **CIRISEdge is what keeps the peers separable.** Cryptographic
  addressing (the destination *is* the key, no name authority),
  multi-medium reach (TCP where it exists, LoRa / serial where it does
  not), peer-to-peer routing with no router-of-record — these are not
  features, they are what makes "two independent peers" a *physically
  true* statement rather than a diagram.
- A federation that cannot route a signed message between two sovereign
  peers without infrastructure CIRIS does not own has not failed to
  scale — it has failed to be *distributed at all*. Its N_eff is a
  fiction the broker could collapse at will.

The agent reasons; CIRISVerify makes it evidence; CIRISPersist makes
the evidence last; CIRISLens scores it — **CIRISEdge is what makes any
of it *audible to a peer that is not on the same machine*.** A signed
trace nobody can transmit between sovereign peers proves nothing.

### 1.3 What CIRISEdge is

One embeddable Rust crate that is every CIRIS peer's network edge: the
signed-envelope-in / signed-envelope-out boundary, verify-at-the-wire,
typed handler dispatch, and a durable outbound queue — over Reticulum
(the canonical wire) or HTTP (the documented fallback). A node links it
as a library (`crate-type = ["cdylib", "rlib"]`, `Cargo.toml`) and gets
one transport surface instead of three hand-rolled HTTP shims across
agent / lens / registry. Constructed via `Edge::builder()`
(`src/edge.rs`, `EdgeBuilder`); driven by `Edge::run` (`src/edge.rs`).

It is the **federation's transport primitive, one layer below the
substrate**: edge does not reason, score, store, or root identity — it
*carries the cryptographic envelope between deployments* and rejects
the malformed before any application code is reached.

### 1.4 Apophatic bound — what CIRISEdge will not be

CIRIS is partly defined by structural refusal. CIRISEdge's refusals are
sharp and load-bearing:

- **Not a verifier; never rolls its own crypto.** Edge calls CIRISVerify
  for every signing and verification primitive — `ciris-keyring`'s
  `HardwareSigner` / `PqcSigner` for outbound signing
  (`src/identity.rs`), `ciris-persist`'s `verify_hybrid_via_directory`
  for inbound (`src/verify.rs`). Edge takes ZERO direct deps on
  `ed25519` / `ml-dsa` / `sha2`-as-a-signer primitive crates for
  authentication. It re-implements no canonicalization: canonical bytes
  come from `ciris_persist::canonicalize_envelope_for_signing`
  (`src/identity.rs::sign_envelope`) — CIRISPersist#7 closure.
- **Not a key custodian.** The federation Ed25519/ML-DSA seed lives
  behind `ciris_keyring`'s `Arc<dyn HardwareSigner>` and **never enters
  edge's process memory** — `LocalSigner` (`src/identity.rs`) holds the
  signer trait object, not seed bytes. AV-17 (`docs/THREAT_MODEL.md`)
  is a heap-scan property test, not a hope.
- **Not a broker; not a router-of-record.** Edge is a peer-to-peer
  transport. It does not centralize routing, does not become the
  chokepoint §1.2 names. Peers compose *around* edge, never *into* it
  (`MISSION.md` §6 anti-pattern 6). If edge is doing its job it is
  invisible to operators and load-bearing to the federation.
- **Not a storage layer.** Edge carries envelopes; CIRISPersist stores
  them. The durable outbound queue is *persist's* `edge_outbound_queue`
  table — edge runs the dispatcher loop over it (`src/outbound.rs`,
  `run_dispatcher`) through the `OutboundHandle` adapter, and owns no
  table of its own.
- **Not a trust oracle.** Edge authenticates *origin* — verify-at-the-
  wire, and cold-start binding-rooting via `root_binding`
  (`src/transport/reticulum.rs`). It never *confers* trust. The
  federation-wide invariant inherited from CIRISVerify#27/#28: every
  primitive authenticates origin; none authorizes. A rooted peer is a
  *known* peer, not a *trusted* one.
- **Not HTTP-first.** Reticulum is the canonical wire
  (`src/transport/reticulum.rs`); HTTP (`src/transport/http.rs`) is the
  documented fallback for Reticulum-unreachable cloud environments,
  surfaced in the transport-mix metric — never the default.

### 1.5 Multi-medium reach is not a tier

A federation primitive that can only run on hyperscaler TCP is not
pluralistic — it is a cloud dependency dressed as a federation. Edge's
`Transport` trait (`src/transport/mod.rs`) is medium-agnostic by
construction: the same signed `EdgeEnvelope` round-trips over Reticulum
(TCP, and — Phase 3 — LoRa / serial / I²P) and over HTTP, with no
medium-specific type in the public API. A solar-powered LoRa Pi at the
edge of the grid is a **first-class federation peer**, not a degraded
mode. This is load-bearing for **Justice**: the deployments that need
M-1 most are precisely the ones a TCP-only design excludes. OQ-13
(`FSD/OPEN_QUESTIONS.md`) keeps the multi-medium transports as declared
feature gates so the contract is stable before the implementations
land.

### 1.6 Fail-loud is a mission stance

Edge is the only crate in the stack that touches the
**adversary-controlled wire**. Where CIRISVerify fails *secure* and
CIRISPersist fails *honest*, CIRISEdge fails **loud**: it never drops a
message silently.

- **No application-visible unverified bytes.** Verify is a precondition
  for dispatch, not a callback the host opts into — `VerifyPipeline`
  (`src/verify.rs`) runs before any handler, and a verify-fail means
  the handler is never invoked.
- **Every wire reject is a typed code.** `VerifyError`, `HandlerError`,
  `TransportError`, `EdgeError`, `AttestationError`, `RootingRejection`
  (`thiserror` throughout) — a rejected message produces a structured,
  sender-visible reason. A silent drop is the exact failure mode edge
  exists to eliminate; it is a mission violation, not a tuning issue.
- **No-TOFU.** The Reticulum `PeerResolver` (`src/transport/reticulum.rs`)
  drops an announce it cannot root rather than provisionally trusting
  it. With no rooting directory configured, announce discovery is
  *off* — fail-honest, never "accept anything" (AV-42).

---

## 2. PROTOCOLS (WHO)

The contract surface. Implementations may change; these change only
with deliberate cross-repo coordination.

- **The `Transport` trait** (`src/transport/mod.rs`) — the sealed
  medium abstraction: `id`, `send(destination_key_id, envelope_bytes)`,
  `listen(sink)`. `ReticulumTransport` (`src/transport/reticulum.rs`)
  and `HttpTransport` (`src/transport/http.rs`) implement it
  identically; edge holds `Vec<Arc<dyn Transport>>` — multiple media
  active at once is the multi-medium reach §1.5 demands.
- **The `Message` / `Handler` typed contract** (`src/handler.rs`) —
  every wire message is a Rust struct with `serde::Deserialize` + a
  `MessageType` discriminant + a `Delivery` class; handlers receive the
  parsed struct, never raw bytes. `InlineTextMessage` marks the bodies
  the outbound pipeline scans. Different peers register different
  handler sets; the dispatch shape is one contract.
- **The `EdgeEnvelope` wire format** (`src/messages/mod.rs`) — the
  signed envelope every peer emits and verifies. Its shape is the
  cross-repo contract; a change is a coordinated `SchemaVersion` break
  (§3), never a casual edit.
- **The content-fetch transport primitive** (`src/messages/mod.rs`:
  `ContentFetch` / `ContentBody` / `ContentMiss`) — CIRISEdge#21
  v0.8.0 content-addressable byte fetch over the federation wire. Not
  a new architectural tier; just three typed message bodies that ride
  the existing `Delivery::Ephemeral` class. The integrity primitive is
  `sha256(bytes) == claimed_sha256` re-checked on receipt; trust rides
  the attestation that named the SHA (out-of-band).
- **The `AnnounceAttestation` binding contract** (`src/transport/attestation.rs`)
  — the federation-key-signed transport-identity ↔ federation-key
  binding carried in the Reticulum announce. CIRISEdge#15 / CIRISVerify#28
  Phase 3. Field names + canonical encoding are the contract.
- **The persist adapter traits** — `VerifyDirectory` and
  `RootingDirectory` (`src/verify.rs`) erase `ciris-persist`'s
  `FederationDirectory` (RPIT `async fn in trait`, not dyn-compatible)
  behind object-safe traits; `OutboundHandle` (`src/outbound.rs`) erases
  `OutboundQueue`. Edge composes against persist's substrate through
  these, never against backend types.
- **The CIRISVerify / CIRISPersist primitives edge consumes as
  contracts** — `verify_hybrid_via_directory`, `root_binding`,
  `canonicalize_envelope_for_signing`, `body_sha256` (CIRISPersist
  v1.12.0); `HardwareSigner` / `PqcSigner` (`ciris-keyring` v2.8.0).
  Edge calls the authority; it never re-implements it.
- **The Leviculum stack** — the Reticulum transport is built on
  `reticulum-core` + `reticulum-std`, consumed from the
  `CIRISAI/leviculum` fork (`Cargo.toml`; OQ-07 closure — Beechat's
  reticulum-rs was spiked and rejected for a broken link data path).
- **PyO3 / FFI shell** (`src/ffi/pyo3.rs`) — a thin translation layer
  over the public Rust API; the `Edge` class registration lands in a
  later minor. `crate-type = ["cdylib", "rlib"]` so one wheel serves
  Python while `cargo` consumers get the `rlib`.
- **UniFFI binding surface** (`udl/ciris_edge.udl`, v0.13.0
  CIRISEdge#36 GO) — a single UDL drives auto-generated Python,
  Kotlin, and Swift bindings via `uniffi::generate_scaffolding` in
  `build.rs`. The spike's GO carve-out keeps the load-bearing
  cohabitation primitives on PyO3 (`init_edge_runtime` PyCapsule
  cohabitation, Tier 2 GIL-drainer callbacks, AsyncIterator event
  stream, QR import/export with `Bound<PyAny>` complexity); every
  other read/CRUD surface — transport mgmt (#25), peer mgmt (#26),
  identity reads (#31), observability snapshot reads (#28), links
  FFI (#32), routing FFI (#33) — moves under UniFFI so the same UDL
  produces Python + Kotlin Multiplatform + Swift bindings from one
  source. Free-function shape registered via `install_edge_handle`
  (`src/ffi/uniffi_impl.rs::install_edge_handle`); pre-init callers
  receive typed `EdgeBindingsError::NotInitialized` rather than
  panics or garbage data (AV-47).
- **The 6-capsule cohabitation surface** (`src/ffi/pyo3.rs::extract_capsule`)
  — when edge cohabits with an already-bootstrapped persist `Engine`
  in the same Python process, the engine hands edge five (now six,
  with persist v3.1.1's `local_signer_capsule`) opaque `PyCapsule`
  pointers: `federation_directory_capsule`, `outbound_queue_capsule`,
  `keyring_signer_capsule`, `runtime_handle_capsule`, and
  `local_signer_capsule`. The sixth slot (`blob_storage_capsule`)
  is the contract shape reserved for the v0.18.x content-fetch
  durability cohabitation. "Each capsule one job" is the architectural
  primitive: the hot-path **hardware-rooted scrub envelope signer**
  arrives through `keyring_signer_capsule` (P-256 + ML-DSA hybrid
  under `hardware_hsm_only`) while the **32-byte Ed25519 Reticulum
  transport identity** arrives through `local_signer_capsule`
  (LocalSigner over a `local_key_path` seed). Two capsules, two
  signing identities, one cohabiting engine — the split is what makes
  AV-43 closure structural rather than a runtime check.
- **Verify-4 FederationKeyset hybrid pubkey separation**
  (`src/identity.rs::EdgeFederationKeyMetadata::pubkey_ml_dsa_65_base64`,
  `src/verify.rs::AccordHolderKey::pubkey_ed25519`) — CIRISVerify v4.0
  formalizes the federation key's transport (Ed25519) and PQC
  (ML-DSA-65) components as distinct first-class fields. Edge reads
  `pubkey_ed25519_base64` for the §6.1 attestation cold-start root +
  `AccordHolderKey` accord-holder enumeration, and
  `pubkey_ml_dsa_65_base64` (when present on the federation row) for
  the hybrid verify second leg via `verify_hybrid_via_directory`. The
  field separation is what makes consumer `HybridPolicy` selectable
  per-peer: strict-hybrid rejects rows with `pubkey_ml_dsa_65_base64 =
  None`; soft-hybrid+freshness accepts pending rows within a freshness
  budget; Ed25519-fallback honors the row even when the PQC half is
  absent.

## 3. SCHEMAS (WHAT)

**Canonical bytes are the mission-load-bearing schemas.** A signature
proves nothing if edge canonicalizes differently from the signer;
ambiguity is how a buggy peer or a Sybil claims something a peer never
said.

- **`EdgeEnvelope`** (`src/messages/mod.rs`) — the signed wire
  envelope: `signing_key_id`, `destination_key_id`, `message_type`,
  `nonce`, `sent_at`, the typed body, and the hybrid Ed25519 + ML-DSA-65
  signatures. The body rides as `serde_json::value::RawValue` — bytes
  preserved verbatim so the signature covers exactly what the verifier
  checks, never a re-serialization (AV-5; FSD §3.4).
- **Canonical bytes are not edge's to define.** `sign_envelope`
  (`src/identity.rs`) calls `ciris_persist::canonicalize_envelope_for_signing`;
  edge re-implements no canonicalization rule. CIRISPersist#7 closure.
- **`SchemaVersion`** (`src/messages/mod.rs`) — a strict allowlist.
  An unrecognized wire version is a typed reject
  (`VerifyError`, AV-7), never a lenient parse.
- **The `AnnounceAttestation` canonical encoding**
  (`src/transport/attestation.rs::AttestationPayload::canonical_bytes`)
  — domain-separated, length-prefixed, **injective**: the field
  boundaries cannot be confused, so a signature over one
  `(transport_pubkey, key_id, epoch)` triple can never be replayed as
  another. An injectivity test guards it.
- **`MessageType`** (`src/messages/mod.rs`) — the body discriminator;
  dispatch is keyed on it, and `Delivery` (`src/handler.rs`) lives on
  the type, not the call site, so a caller cannot pick the wrong
  delivery class (OQ-09).

**The mandate:** an `EdgeEnvelope`, `SchemaVersion`, or attestation
encoding change is a coordinated, versioned wire break — never a casual
edit. The wire-format spec lives in this repo (`FSD/CIRIS_EDGE.md`);
downstream consumers pin against tagged commits.

## 4. LOGIC (HOW)

- **The verify pipeline** (`src/verify.rs::VerifyPipeline::verify`) —
  `bytes → body-size cap (AV-13) → typed deserialize, depth-capped
  (AV-14) → schema-version allowlist (AV-7) → destination check (AV-8)
  → replay window (AV-3) → hybrid verify via persist's directory
  (AV-1 + AV-9 + AV-39)`. Cheap constant-time rejects come first; the
  cryptographic check is last. No byte reaches a handler before this
  completes.
- **The replay window** (`src/verify.rs`) — a bounded LRU over
  `(signing_key_id, nonce)`, time- and capacity-bounded (AV-3 / AV-12;
  OQ-08). `check_and_record` is the on-wire replay gate; persist's
  dedup catches application-layer replay beyond the window.
- **The cold-start `PeerResolver` path** (`src/transport/reticulum.rs`)
  — on an inbound announce: parse the `AnnounceAttestation` → root the
  federation key via `root_binding` against persist's `federation_keys`
  directory → verify the attestation signature against the directory-
  confirmed pubkey → apply `HybridPolicy` over the provenance chain →
  record the rooted `key_id → transport_identity` resolution. Replaces
  trust-on-first-use (AV-42).
- **Outbound signing** (`src/identity.rs`) — `build_envelope` assembles
  the typed body; `sign_envelope` canonicalizes and signs Ed25519
  (mandatory) + ML-DSA-65 (when the signer is hybrid-complete).
- **`send` / `send_durable` / `send_inline`** (`src/edge.rs`) —
  ephemeral send is caller-retry; durable send enqueues to persist's
  `edge_outbound_queue`; `send_inline` runs the transit-touch pipeline
  (Classify + Scrub + EncryptAndStore) over `InlineTextMessage` bodies
  before signing — the cleartext never crosses the wire.
- **The durable dispatcher** (`src/outbound.rs::run_dispatcher`,
  `run_sweeps`) — edge-owned retry/backoff over persist's queue rows;
  ACK matching by `body_sha256` (`in_reply_to`).
- **The Reticulum transport** (`src/transport/reticulum.rs`) — Leviculum
  `ReticulumNode`; envelopes ride as Reticulum Resources over Links
  (they exceed the single-packet MDU); the local Reticulum identity is
  a dedicated routing-tier identity, distinct from the federation
  signing key (persist Finding G — transport identities are
  routing-only, never rooted as trust anchors).
- **Build-manifest provenance** (`src/manifest.rs`, `src/bin/emit_edge_extras.rs`)
  — every release emits hybrid-signed `EdgeExtras`, round-trip-verified
  against CIRISRegistry before publish (OQ-12).

## 5. Test categories — every test answers a mission question

Per MDD §"Testing Standards": tests verify *mission-aligned outcomes*,
not just "no error returned."

| Category | Mission question | Examples |
|---|---|---|
| **Wire correctness** | Did we transmit what the sender said? | `reticulum_loopback` — a signed `EdgeEnvelope` round-trips byte-exact |
| **Verify enforcement** | Did we reject the malformed before a handler saw it? | corrupted signature → handler never invoked; backend sees nothing |
| **Replay rejection** | Is the on-wire replay window sound? | `verify::tests::replay_window_*` — within-window replay detected, capacity evicts oldest |
| **Authenticated resolution** | Can a peer spoof a federation key_id? | `reticulum_av42` — pubkey-mismatch / unknown-key / swapped-transport / tampered-sig announces all rejected |
| **Identity boundary** | Did key bytes stay out of edge's memory? | AV-17 heap-scan property test asserts no seed-shaped bytes during sign |
| **Multi-medium reach** | Does the same envelope round-trip on every medium? | the loopback test runs on Linux and darwin; LoRa/serial join per Phase 3 |
| **Spec drift** | Does edge fail loud on an unknown wire version? | future-`SchemaVersion` message → typed allowlist reject |

A PR that adds a feature without the test answering its mission
question is not done. Test absence is mission drift.

## 6. Anti-patterns that fail MDD review

Rejected on mission grounds, not style:

1. **Untyped wire surfaces.** `&[u8]` or `serde_json::Value` past the
   parse boundary. Every message is a typed struct; the parser is the
   schema gate.
2. **Caller-implemented canonicalization.** Canonical bytes come from
   `ciris_persist::canonicalize_envelope_for_signing` — never
   re-implemented (CIRISPersist#7).
3. **Edge holding raw key seed bytes.** The federation seed stays
   behind `ciris-keyring`'s `HardwareSigner`; edge holds the trait
   object, never the seed (AV-17).
4. **Crypto implemented outside the CIRISVerify authority.** A direct
   `ed25519` / `ml-dsa` signing-primitive dependency. Edge calls
   ciris-keyring / ciris-crypto; it never rolls its own.
5. **HTTP-only / HTTP-default transport.** A federation primitive that
   cannot run on LoRa is a cloud dependency (§1.5). Reticulum is
   canonical; HTTP is fallback.
6. **Per-peer special cases in `handler/`.** Edge is one shape. A peer
   that needs more composes around edge — a per-peer branch in the
   dispatch path fails review.
7. **A silent drop.** Every wire reject is a typed, sender-visible code
   (§1.6). A swallowed error is a mission violation.
8. **Trust-on-first-use.** Recording an unrooted announce as a usable
   peer. The `PeerResolver` roots or drops (AV-42).
9. **A test that asserts only "no error returned."** Tests verify
   mission outcomes — the right signature *rejected*, the right spoof
   *detected* (§5).

## 7. Failure modes — when the mission is at risk

| Symptom | Mission risk | Mitigation |
|---|---|---|
| HTTP fallback becomes the default transport | Pluralistic-compatibility regression — edge becomes a cloud dependency | Reticulum canonical; transport-mix metric surfaces drift (§1.5) |
| Edge process holds private-key bytes (coredump / debugger) | Key-leak surface returns | AV-17 heap-scan property test; `LocalSigner` holds only the signer trait object |
| Verify rejects start dropping silently | Federation trust degrades to "trust me" | Typed reject per failure; per-reject structured log; reject-rate metric (§1.6) |
| `PeerResolver` accepts an unrooted announce | AV-42 — a Sybil intercepts `send(key_id, ..)` | `root_binding` + attestation-verify two-step; `reticulum_av42` gate |
| Handler trait grows a per-peer branch | "One shape, many peers" erodes into spec coupling | PR review rejects per-peer branches; peer logic stays in the host crate |
| `EdgeEnvelope` / attestation encoding edited without a version break | Cross-repo wire drift (CIRISPersist#7 / CIRISAgent#712 class) | Coordinated `SchemaVersion` tags; injectivity test on the attestation encoding |
| Edge re-implements a canonicalization or crypto rule | Byte-stable behavior drifts from the authority | `cargo deny` + review: no direct signing-primitive deps; persist owns canonical bytes |

## 8. Constant alignment — the review heuristic

When CIRISEdge code crosses a reviewer's eyes, they ask:

1. **Verify ordering** — does any byte reach a handler before
   `VerifyPipeline` cleared it? Verify is a precondition, not a
   callback.
2. **Crypto authority** — is every signing/verifying primitive behind
   CIRISVerify (ciris-keyring / ciris-crypto) and every canonicalization
   behind CIRISPersist? A new direct primitive dep is a red flag.
3. **Key boundary** — does the federation seed stay behind
   `HardwareSigner`? Edge never holds seed bytes (AV-17).
4. **Fail-loud** — under any new failure mode, is the reject a typed,
   sender-visible code, never a silent drop? (§1.6)
5. **Multi-medium** — does this stay medium-agnostic? A medium-specific
   type in the public API fails review on Justice grounds (§1.5).
6. **Origin vs trust** — does this keep authenticating-origin separate
   from conferring-trust? A rooted peer is *known*, not *trusted*.

## 9. Federation context

CIRISEdge does not stand alone. The authoritative federation map is
`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md`.

- **CIRISAgent** reasons and emits signed traces. **CIRISVerify** is the
  identity/integrity root that makes them evidence. **CIRISPersist**
  carries that evidence durably. **CIRISLens** scores it and runs the
  Coherence Ratchet. **CIRISNodeCore** runs federation consensus.
  **CIRISEdge** is the wire between every pair of them — signed
  envelope in/out, verify-at-the-wire, typed dispatch, durable
  outbound.
- Edge consumes CIRISVerify for signing primitives (`ciris-keyring` /
  `ciris-crypto`) and CIRISPersist for the federation directory,
  canonical bytes, cold-start rooting (`root_binding`), and the
  `edge_outbound_queue` substrate. It is a *consumer* of both
  authorities, never a re-implementer.
- **CIRIS 3.0 critical path:** `CIRISVerify#27 → CIRISPersist rooting →
  CIRISEdge resolver → fleet enforcement`. The authenticated
  `PeerResolver` (CIRISEdge#15, shipped v0.4.0) is the CIRISEdge node —
  past it, the 3.0 blocker is fleet enforcement, not edge.
- The Reticulum stack is Leviculum, consumed from the
  `CIRISAI/leviculum` fork — a CIRIS-maintained fork that strips
  upstream's dead integ-harness submodules so the repo resolves as a
  cargo git dependency.

## 10. License-locked mission preservation

CIRISEdge is **AGPL-3.0-or-later** (`Cargo.toml`), matching the rest of
the federation stack. This is a mission decision, not a licensing one:
edge is the crate on the adversary-controlled wire — anyone reasoning
about whether a CIRIS-derived deployment preserves M-1 must be able to
audit every line of the transport. A fork that wants to remove
verify-at-the-wire, collapse the key boundary, accept untyped messages,
or reintroduce trust-on-first-use must publish that fork under the same
license, making the divergence auditable. The Accord acknowledges no
detector is complete; the only counterweight is **legibility under
audit**. AGPL makes that structurally enforceable, not socially
expected.

The v0.16.0 wire-compliance fields anchor here. `testimonial_witness`
(CIRISEdge#37, FSD-002 §3.6.3 v1.4 + §5.14) is a **preservation
primitive**: edge propagates whatever the joint-correlation tier
(lens-core detectors, ratchet-conscience evaluators, registry
attesters) signs into the envelope, verbatim, and signs the bytes
under its forwarding key — but it does NOT interpret the payload.
That asymmetry is M-1 rendered as architecture: the wire surface
must carry every witness a future detector class will need to make
visible (Fidelity & Transparency — the audit chain must never
silently drop attestation traffic), and the wire crate must never
silently re-interpret what a higher tier has signed (Respect for
Autonomy — the policy tier owns its own meaning, edge is reach not
gate). `key_boundary:{scope}` (CIRISEdge#38 + D26, FSD-002 §3.4)
extends edge's load-bearing AV-17 invariant (no seed bytes in edge's
heap; see `docs/THREAT_MODEL.md` §AV-17) with a wire-form scope slot
— `process` (the v0.15.x default), `tenant`, `channel`, `cohort`,
`data_class` — so a multi-tenant or per-cohort deployment can express
its key isolation contract on the wire without a wire break. The
v0.16.0 cut lands the slot's wire shape only; future enforcement
(binding signatures to a scope at verify time) is a v0.16.1+ scope
and intentionally does not touch the substrate today. Together these
fields make CIRISEdge legibly compliant with the CIRIS 3.0 protocol
surface, in the AGPL letter as well as the apophatic spirit of §1.4.

## 11. Architectural surfaces shipped v0.5.0 → v0.17.x

The v0.4.0 reverse-engineering pass anchored the v1.0-prep architecture
floor — verify pipeline, durable outbound, Reticulum + HTTP transports,
authenticated `PeerResolver` cold-start (AV-42). The minors between
v0.4.0 and v0.17.0 added six load-bearing surfaces that the v1.0 doc
contract must name explicitly. Each is anchored to its primary
implementation file:

- **Link lifecycle primitive** (v0.14.0 CIRISEdge#32,
  `src/transport/reticulum.rs::link_open` / `link_teardown` /
  `link_request`; `src/events.rs::LinkEvent`) — Reticulum's Link
  becomes an operator-visible lifecycle: `link_open(dest_hash)` →
  `LinkEstablished` event → typed `LinkId` returned → `link_request`
  / `link_teardown` over the established link → `LinkDropped` event on
  close. Links carry encrypted Curve25519-derived DH keys per
  connection (Reticulum-native, not edge-defined); they are
  **security-relevant because traffic over a Link is encrypted under
  a per-connection key derived from both endpoints' transport
  identities** — Reticulum's `LinkEstablished` is the point past which
  bytes are no longer wire-readable to a passive adversary. Edge
  exposes the lifecycle through `EdgeLinkInfo` + `EdgeLinkState`
  (`src/ffi/uniffi_types.rs`) so operators can see which peers
  currently have a live link, when it established, and tear stale
  links down.
- **Routing-table FFI primitives** (v0.15.0 CIRISEdge#33,
  `src/ffi/uniffi_impl_routing.rs`) — six routing surfaces exposed
  for operator visibility + policy: `routing_path_table` /
  `routing_path_to` / `routing_path_request` / `routing_path_drop` /
  `routing_path_drop_via` (Reticulum's announced-paths view);
  `routing_blackhole_list` / `_add` / `_remove` /
  `_prune_expired` (operator deny-list, per-Reticulum-identity);
  `routing_rate_table` (per-source rate-limit decay view);
  `routing_tunnels` / `routing_transport_uptime` /
  `routing_transport_id`; `routing_announce_table` (in-flight
  announces); `routing_reverse_table` (reverse path-resolution
  cache). The blackhole surface is the architecturally-interesting
  one: it is **local operator policy, not federation attestation**
  — see AV-46. v0.16.1 (CIRISEdge#33 follow-up + CIRISPersist#120)
  flipped blackhole storage from in-memory
  `Arc<RwLock<HashMap<Vec<u8>, BlackholeRecord>>>` to durable
  persist-backed `Arc<dyn BlackholeRules>` over the V052
  `cirislens.blackhole_rules` table; operator-set rules now survive
  process restarts.
- **Peer-mgmt mutation surface** (v0.15.1 CIRISEdge#26,
  `src/ffi/uniffi_impl.rs::peer_add` / `peer_remove` /
  `peer_set_alias` / `peer_set_trust` / `peer_set_notes` /
  `peer_set_policy`) — six peer-CRUD methods wiring persist v3.1.0's
  `FederationDirectory` mutation surface (CIRISPersist#117). The
  typed `EdgePeerTrust` enum (`Untrusted` / `Trusted` / `Restricted`
  / `Blocked`) mirrors persist's `TrustClass`. **TrustClass is
  operator opinion, not federation attestation** — a peer marked
  `Blocked` locally is not being attested-against by the federation;
  see AV-46. The opinion lives in persist's `federation_peer_metadata`
  sibling table (per CIRISPersist#117 — not folded into
  `federation_keys`), preserving the "federation directory is about
  identity, operator metadata is about policy" separation.
- **testimonial_witness preservation primitive** (v0.16.0
  CIRISEdge#37, FSD-002 §3.6.3 v1.4, `src/messages/mod.rs::
  TestimonialWitness`; round-trip pinned by
  `tests/testimonial_witness_round_trip.rs`) — `EdgeEnvelope` now
  carries an optional `testimonial_witness: Option<TestimonialWitness>`
  field. Edge forwards the value verbatim across federation forwarding
  and signs it as part of canonical envelope bytes; edge does **not**
  interpret the opaque `payload`. The asymmetry is M-1 rendered as
  architecture and is treated in detail in §10 above + AV-44 below.
- **key_boundary `{scope}` slot** (v0.16.0 CIRISEdge#38,
  `src/key_boundary.rs::KeyBoundaryScope`) — wire-form scope slot
  extending the AV-17 invariant string. Wire form:
  `key_boundary:{process|tenant|channel|cohort|data_class}:no_seed_in_heap`.
  The AV-17 process-level invariant (no seed in edge's heap) is
  **unchanged at v0.16.0 — scope-irrespective**. The slot is wire-form
  only at v0.16.0 / v0.17.0; signature-to-scope binding enforcement
  is v0.16.1+ scope. Treated in detail in §10 above + AV-45 below.
- **SAS deterministic UX helper** (v0.17.0 CIRISEdge#47,
  `src/sas.rs::peer_sas_words` / `peer_sas_digits`) — a deterministic,
  order-independent representation of `(local_pub, peer_pub,
  CIRIS_SAS_PROTOCOL_CONSTANT)` that two operators can verbally
  confirm out-of-band to verify they share the same peer identity
  (MITM-resistant elevation from `EdgePeerTrust::Untrusted` to
  `Trusted`). The recipe is `H(sorted(local_pub ‖ peer_pub) ‖
  CIRIS_SAS_PROTOCOL_CONSTANT)` with the protocol constant locked as
  `ciris-edge::peer-sas::v1\0` (`src/sas.rs::CIRIS_SAS_PROTOCOL_CONSTANT`,
  pinned by `tests::peer_sas_protocol_constant_locked`). BIP39 English
  wordlist; default 5 words ≈ 55 bits, default 6 digits ≈ 20 bits —
  consumer picks the tier their UX channel supports. The order-
  independence (`sort_unstable` before hashing) guarantees both peers
  compute the same SAS regardless of who is "local" — critical for an
  out-of-band verbal-confirmation UX.
- **Canonical-peer invariant** (CIRISEdge#46, scheduled v0.18.0 —
  anchored here as a v0.17.1 documented requirement so v1.0-prep
  consumers can rely on the contract shape). Bootstrap peers (the
  canonical CIRIS infrastructure roster — e.g. `agents.ciris.ai`) are
  re-seeded into `federation_peer_metadata` on every Edge start; the
  operator can flip their trust state (`Untrusted` / `Blocked`) and
  that flip survives restarts; the operator **cannot** permanently
  remove a canonical peer — `peer_remove(handle, hard=true)` on a
  canonical peer returns typed `CANNOT_REMOVE_CANONICAL_PEER` and
  `EdgePeerInfo` gains a `canonical: bool` field. This aligns with
  Reticulum's structural distinction between propagation nodes (the
  infrastructure roster) and peers (operator-controlled trust
  relationships). The wiring lands at v0.18.0; the invariant is
  documented now (and threat-modeled in §AV-canonical-peer below) so
  downstream substrate consumers can pin against the contract before
  the wire-up ships.

## 12. How to maintain this document

A working document, not a release artifact. Update it whenever:

- A module in `src/` is added or its contract changes
- A transport is added (`Transport` impl) or the medium set changes
- The `EdgeEnvelope` / `SchemaVersion` / attestation encoding in §3
  changes shape
- A trait in §2 is added or its contract changes
- An `OQ-*` resolution or a `THREAT_MODEL.md` `AV-*` verdict changes
- The apophatic bound or an invariant in §1 is touched
- The Accord is amended

If a future reviewer running `git blame` would want a line to cite a
real file or constant and it doesn't, fix it. If the doc drifts from
the code, the apophatic test has failed — the doc is wrong, not the
code.

---

**Cross-references**

- [ciris.ai/vision](https://ciris.ai/vision) — the corridor / consent cosmology
- [ciris.ai/mdd](https://ciris.ai/mdd) — Mission Driven Development methodology
- `~/CIRISAgent/ACCORD.md` — Meta-Goal M-1 + the six principles (canonical)
- `~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md` — the federation primitive + N_eff
- `FSD/CIRIS_EDGE.md` — full functional spec
- `FSD/EDGE_OUTBOUND_QUEUE.md` — the durable-send substrate contract
- `FSD/OPEN_QUESTIONS.md` — the OQ decision register
- `docs/THREAT_MODEL.md` — adversary model + AV-* attack vectors
- `README.md` — crate status + the consume-from-Rust surface
