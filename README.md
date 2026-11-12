# `ciris-edge`

**The transport and replication layer of the CIRIS Epistemic Web
([CEWP](https://ciris.ai/cewp)).** A single Rust crate that moves the 15 signed
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
> the 15 EnvelopeKinds, the cohort/namespace projections, the anti-entropy state
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
   State machines, the 15 kinds, namespaces, attribution, consent-routing, CEG↔OSI.
3. **[`FSD/CIRIS_EDGE.md`](FSD/CIRIS_EDGE.md)** — the architecture spec, crate shape,
   public API surface, verify-via-persist contract, test categories.

## The shape of the protocol (one-paragraph tour)

Every claim is one of **15 signed [`EnvelopeKind`s](FSD/CIRIS_EDGE_TRANSPORT.md#2-the-15-envelopekinds)**,
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

## The two-plane hybrid

Edge realizes the **lightnet/darknet split** of
[CC 5.4.6](../CIRISConstitution/constitution/part_5_transport_substrate.md): a
**public identity plane** (announced, rooted, attributable — no anonymity
claim) and a **derived group plane** (per-group destinations derived from
directory state members already hold — never announced, so group *existence*
is structurally invisible to outsiders). Derivation replaces discovery;
determinism replaces coordination. What that buys — private *manageable*
groups, decentralized video over member-relays, and the posited
occurrence-invisible ballot — and the measurement status of each claim, is in
**[`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)**. The proofs run as
the multi-container acceptance bench (**[`bench-mesh/`](bench-mesh/README.md)**,
real video + real blobs through real relays, in CI).

## Status

**v45.0.0.** Pins `ciris-persist` v61.2.2 (exact, Python too), CIRISVerify v22.2.0 and
leviculum v0.34.0+ciris.3 (`Cargo.toml`); MSRV 1.92; CC 1.0-rc17;
wire vocabulary v1.0.3 (since v44.1.2). Release notes: [`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md);
threat model and its stated residuals: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**Measured, and its scope.** The multi-container acceptance sweep
([`bench-mesh/`](bench-mesh/README.md); labels and evidence in
[`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)) delivered real
encrypted video and files through a relay that can neither read them nor learn
the group exists, with mid-stream joins, key rotation without frame loss,
address retirement and outsider refusal. Its scope is one host, one relay, up
to four subscribers (seven containers), and its committed baselines are from
v18.6–v18.8; the weekly lane has not passed since 2026-10-12, so no sweep is
recorded green on 44.x. Real NATs, WAN latency, radio and larger meshes are
not measured by it, and A/V across real NATs is unproven
([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §9.1).

Under the hood: production CEG-native transport with a hybrid transit seal on
every Reticulum link (CC 5.3.3.5 E1); per-link traffic shaping under CC 5.4.3
(one hop, eight links, bulk and A/V unshaped); the CC 5.2 rule for what moves
to a peer; scope-native addressing end to end (`#499`); the A/V mesh spine;
Reticulum + HTTPS + packet-radio transports; the anti-entropy replication
engine; the `#393` two-item attribution gate; MLS cohorts (TreeKEM, X-Wing)
with scope-derived addressing and seal/retirement; mandatory hybrid Ed25519 +
ML-DSA-65 on every producer; PyO3 + UniFFI mobile surfaces (Android floor:
API 24). The Anonymous Tier is wired and dormant. Pinned in lockstep to
`ciris-persist` via drift-witnessed policy hashes.

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
