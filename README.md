# `ciris-edge`

Reticulum-native federation transport for the CIRIS stack. Replaces
the Python edge across CIRISLens (FastAPI), CIRISAgent (httpx),
CIRISRegistry (HTTPS) with a single Rust crate that does signed
message in/out, verify-via-persist, and typed handler dispatch.

**Status:** v0.2.0 — Phase 1 substrate live. Verify pipeline (hybrid
Ed25519 + ML-DSA-65 via persist's directory lookup), durable outbound
queue + dispatcher, typed handler dispatch, HTTP transport, outbound
inline-text pipeline integration (Classify + Scrub + EncryptAndStore
via `ciris-persist` v1.1.2), and a sovereign-mode convenience
constructor (`EdgeBuilder::from_keyring_seed_dir`) for Reticulum-style
adoption with no persist Engine in-process. PyO3 surface (`Edge`
class registration + `init_edge_runtime`) lands in v0.3.x; reticulum
+ multi-medium transports follow per Phase 3 of the FSD.

## Read in this order

1. **[`MISSION.md`](MISSION.md)** — the WHY. Mission Driven Development
   alignment to CIRIS Accord Meta-Goal M-1; per-module mission
   statements; anti-patterns that violate the mission; failure modes.

2. **[`FSD/CIRIS_EDGE.md`](FSD/CIRIS_EDGE.md)** — the WHAT. Architecture
   spec, three-phase delivery plan, crate shape, public API surface,
   verify-via-persist contract, wire-format envelope, test categories.

3. **[`FSD/OPEN_QUESTIONS.md`](FSD/OPEN_QUESTIONS.md)** — the HOW.
   Thirteen design forks needing owner input before Phase 1 starts.
   Each question states the choice, the trade-off, and a lens-side
   default; resolutions land at the bottom in `CLOSED`.

## TL;DR

The CIRIS architecture has three peers (agent, lens, registry) each
maintaining their own network edge. Three parallel HTTP shims, three
retry policies, three cert-management stories. The Proof-of-Benefit
Federation FSD ([`~/CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md`](../CIRISAgent/FSD/PROOF_OF_BENEFIT_FEDERATION.md)
§3.2) names Reticulum-rs as the transport that closes the federation
loop: addressing IS identity, multi-medium reach, fork-survivable Rust.

`ciris-edge` is the crate that operationalizes that proposal. Each
peer becomes:

```
host application code
    │ registers handlers
    ▼
ciris-edge       ←── Reticulum link sessions (TCP / LoRa / serial / I²P)
    │ verify via persist
    ▼
ciris-persist    ←── steward identity, federation_keys, trace storage
```

One shape, many peers. Library, not sidecar. Verify happens at the
wire, before any handler sees a byte. Key seeds never cross the FFI
boundary. HTTP fallback ships in Phase 1 so cloud deployments can
participate today; Reticulum is canonical and Phase 3 productionizes
LoRa + serial + I²P for the deployments that need M-1 most.

## Phases

| Phase | Outcome |
|---|---|
| **1** (immediate) | Crate skeleton; HTTP transport + Reticulum behind a feature flag; Ed25519 verify via persist; typed handler dispatch; lens cuts over from FastAPI to embedded edge runner |
| **2** | Agent + registry adopt edge; HTTPS becomes per-peer fallback |
| **3** | LoRa, packet-radio, serial transports productionized; off-grid CIRIS deployments tractable |

## Sister repos

- [`CIRISAgent`](../CIRISAgent) — agent reasoning loop; emits signed
  traces. Wire-format spec lives at `FSD/TRACE_WIRE_FORMAT.md`.
- [`CIRISPersist`](../CIRISPersist) — substrate. Owns the federation
  keys directory, steward identity, canonical-bytes canonicalization,
  trace storage. Edge calls into persist for sign + verify.
- [`CIRISLens`](../CIRISLens) — analytical observatory. First peer to
  adopt edge in Phase 1 (cuts over from FastAPI ingest).
- [`CIRISRegistry`](../CIRISRegistry) — identity / build / license /
  revocation directory. Adopts edge in Phase 2.
- [`CIRISVerify`](../CIRISVerify) — cryptographic primitives library.
  Edge depends transitively via persist.

## License

AGPL-3.0, matching the rest of the CIRIS federation stack. License-
locked mission preservation per [`MISSION.md`](MISSION.md) §6.
