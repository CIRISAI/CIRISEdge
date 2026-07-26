# `ciris-edge`

**The transport and replication layer of the CIRIS Epistemic Web
([CEWP](https://ciris.ai/cewp)).** A single Rust crate that moves the 14 signed
envelope kinds of the CEG grammar between federation peers over any medium —
Reticulum mesh, HTTPS, packet radio — decides *who is allowed to learn a claim
exists*, and attributes every inbound byte to a cryptographic identity **before
any handler sees it**.

Edge is the operational realization of
**[Constitution Part 5 — Transport & Substrate](../CIRISConstitution/constitution/part_5_transport_substrate.md)**,
built on two disciplines: **fail-secure** (a missing key or unresolved consent
resolves to *less* access, never a silent downgrade) and **integrity through
structure** (privacy and authenticity are properties the wire format *cannot
violate*, not promises an operator makes). Its design thesis, from
[contextual integrity](https://ciris.ai/contextual-integrity/):
**"the strongest flow rule is one the network cannot express breaking."**

> **📖 The protocol spec: [`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)** —
> the 14 EnvelopeKinds, the cohort/namespace projections, the anti-entropy state
> machine, the transport attribution pipeline, the serve/consent gates, and the
> CEG-vs-OSI layering, with diagrams and code anchors. Start there.

## What edge does

```
host application code
    │ registers handlers                    ┌─ Reticulum mesh (TCP / LoRa / serial / I²P)
    ▼                                        │
ciris-edge  ──── anti-entropy replication ───┼─ HTTPS (bearer / mTLS)
    │ attribute at the wire · serve by consent │
    ▼                                        └─ packet radio
ciris-persist  ──── keys · attestations · trace · admission
```

One shape, many peers. **Library, not sidecar.** Verify happens at the wire,
before any handler sees a byte. Key seeds never cross the FFI boundary. Every
transport is a projection of one `Transport` trait; Reticulum is canonical, HTTPS
is the production fallback so cloud deployments participate today.

## Read in this order

1. **[`MISSION.md`](MISSION.md)** — the WHY. Mission-Driven Development alignment to
   CIRIS Accord Meta-Goal M-1; per-module missions; anti-patterns; failure modes.
2. **[`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)** — the protocol.
   State machines, the 14 kinds, namespaces, attribution, consent-routing, CEG↔OSI.
3. **[`FSD/CIRIS_EDGE.md`](FSD/CIRIS_EDGE.md)** — the architecture spec, crate shape,
   public API surface, verify-via-persist contract, test categories.

## The shape of the protocol (one-paragraph tour)

Every claim is one of **14 signed [`EnvelopeKind`s](FSD/CIRIS_EDGE_TRANSPORT.md#2-the-14-envelopekinds)**,
each its own anti-entropy stream. A claim's **`cohort_scope`** (`self` → `family`
→ `community` → `affiliations` → `species` → `biosphere` → `federation`) resolves
to a **projection** — `SelfOwn` (publish-your-own, *structurally invisible* — no
directory advertisement), `Cohort` (roster hold-and-forward), or `Global`
(commons + anti-rollback tombstones). Peers reconcile per `(peer, kind)` via a
bidirectional **Summary → Diff → Deliver** round. Every inbound frame is
**attributed** at ingest to a `Rooted ∧ owns_key` federation identity (a fresh
peer bootstraps via a narrow, self-authenticating `{Key, IdentityOccurrence,
TransportDestination}` carve-out); an unattributable frame is dropped before any
serve gate is consulted. Only the `Attestation` plane is **consent-gated** — a
consentable claim flows to a peer only if the producer's consent grant includes
it, the recipient holds `infra:serve`, and it satisfies any `recipient_capability`
restriction. The recipient axis *cannot exceed* the transmission principle,
by construction.

## Status

**v14.x** — production CEG-native transport. Reticulum + HTTPS + packet-radio
transports; the anti-entropy replication engine; the `#393` two-item attribution
gate (Rooted∧owns_key + hybrid transport binding); the `#402` bootstrap carve-out;
the `#396` consent-resolved fan-out + serve gates; hybrid Ed25519 + ML-DSA-65
throughout; PyO3 + UniFFI mobile surfaces. Pinned in lockstep to `ciris-persist`
(Registry-of-Record admission) via drift-witnessed policy hashes.

## Sister repos

- [`CIRISConstitution`](../CIRISConstitution) — the canonical CEG spec (Part 5 is
  edge's transport substrate; Part 2 the grammar; Part 3 the namespace).
- [`CIRISPersist`](../CIRISPersist) — substrate: federation keys, attestations,
  trace storage, admission (the `put_*` surface edge replicates onto).
- [`CIRISVerify`](../CIRISVerify) — hybrid crypto primitives (Ed25519 + ML-DSA-65,
  X-Wing), consumed transitively via persist.
- [`CIRISAgent`](../CIRISAgent) — reasoning loop; emits signed traces edge replicates.
- [`CIRISRegistry`](../CIRISRegistry) · [`CIRISLens`](../CIRISLens) — identity/build
  directory · analytical observatory; federation peers.

## License

AGPL-3.0, matching the CIRIS stack. License-locked mission preservation per
[`MISSION.md`](MISSION.md) §6.
