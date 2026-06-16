# Roadmap: v3.8.0 → v4.0 — three cuts to the holonomic federation

Aggressive, low-number-discipline scaffolding from v3.8.0 (shipping now) through v4.0 (CEWP-1.0 holonomic federation seal). Three cuts total; no v3.99.x climb.

## Design principle

| Property | What ships | Cut |
|---|---|---|
| **Substrate** | Wire-format primitives, transport, AEAD, key agreement | v3.8.0 (shipping) |
| **Holographic** | Any fragment reconstructs the whole at proportional fidelity | v3.9.0 |
| **Federation-wide holographic** | The swarm collectively retains optimal coverage | v3.10.0 (part 1) |
| **Holonomic** | The federation reconstitutes itself from any sufficient fragment | v3.10.0 (parts 2-4) |
| **CEWP-1.0** | Production seal | v4.0 |

## v3.8.0 — substrate (✅ shipping now)

PR #131. ALM mesh + MDC sub-stream commitments + MLS X-Wing rekey + multi-parent dedup + layer-policy fan-out + 374 lib tests + 4 benches + FSD + SOTA validation + recommended-stack lock-in.

The user-facing claim: **the substrate is ready for everything that follows.**

## v3.9.0 — holographic mesh becomes actual video

**Issue**: [CIRISEdge#133](https://github.com/CIRISAI/CIRISEdge/issues/133)

The cut that turns the substrate from infrastructure into product. Real codec + real fountain coding + real round-trip with empirical numbers.

| Component | Crate | Role |
|---|---|---|
| Video encoder | `rav1e` | Pure Rust AV1 encoder; lowest RAM footprint of the AV1 family |
| Video decoder | `dav1d` | Production AV1 decoder; deployed in every browser |
| Audio codec | `opus` (libopus 1.6) | 5–26.5ms algorithmic delay; WebRTC / Discord / Mumble standard |
| Fountain wrap | `raptorq` | RFC 6330 RaptorQ; deployed in 3GPP MBMS + DVB-H since 2012 |

New module `src/transport/realtime_av_codec/` with feature gates (`codec-av1`, `codec-opus`, `codec-fountain`, `codec-default`). End-to-end bench `benches/holographic_mesh_e2e.rs` validates the full chain: real frame → encode → fountain-wrap → ALM mesh routing → multi-parent dedup → fountain-decode → AV1-decode → reconstructed frame.

Composes with CIRISPersist#227 (storage) — substrate publishes `ChunkLayer.quality`; persist evicts; reconstruction stays at consumer side.

## v3.10.0 — the holonomic substrate (four interlocking pieces, one cut)

The architectural keystone. Four issues that compose into one coherent holonomic federation upgrade:

### Part 1: Swarm-coordinated rarest-shard retention ([CIRISEdge#134](https://github.com/CIRISAI/CIRISEdge/issues/134))

The swarm collectively retains the rarest fountain symbols at every resolution. Each node's local eviction is informed by what the swarm holds. BitTorrent rarest-first applied to retention (not download); novel composition vs Tahoe-LAFS / Storj / Filecoin / IPFS Cluster — no published prior art.

### Part 2: WholenessWitness ([CIRISEdge#135](https://github.com/CIRISAI/CIRISEdge/issues/135))

Bohm's implicit order made explicit. Every peer periodically publishes a signed Merkle root over its CEG claim state. Other peers cross-compare; differences become reconciliation work. The architectural keystone — every other holonomic upgrade verifies against the witness chain.

### Part 3: Deterministic ALM topology (CIRISEdge#NEW)

Today the ALM tree depends on which RelayCapacity ads a planner saw in what order — path-dependent. v3.10.0 makes it a **pure deterministic function** of (current capacity advertisements, current trust graph, current reachability snapshot). Every peer with the same input arrives at the same tree without leader / consensus. Composes with WholenessWitness — the inputs to the topology function are themselves witness leaves.

### Part 4: Recursive trust bootstrap (CIRISEdge#NEW)

Today bootstrap depends on a known set of trust roots. v3.10.0: a new peer can bootstrap from **any** signed CEG claim that chains to a trust root in its own trust graph. No special "first peer" assumption; any peer's witness suffices. Composes with WholenessWitness — bootstrap = "follow the witness chain until you find a trust-rooted claim."

### Why these four bundle as one cut

They interlock:
- WholenessWitness needs CEG claims to Merkle-root over (Part 1 produces FountainHoldingClaim; Parts 3-4 produce trust + topology claims)
- Deterministic ALM (Part 3) consumes WholenessWitness inputs
- Recursive trust bootstrap (Part 4) consumes WholenessWitness chains
- Swarm rarity (Part 1) gives rarity computation more confidence when paired with WholenessWitness

Shipping them separately means each cut has a stub for the others. Shipping together = clean composition + real end-to-end holonomic test.

## v4.0 — CEWP-1.0 holonomic federation seal

The production seal. Cross-repo locked. The "we did it" release.

- All four holonomic substrate pieces integrated and stable
- End-to-end demonstration: federation surviving / reconstituting from a sufficient fragment
- Persist v8.0.0 layer-aware eviction stable
- Verify family stable at the corresponding hybrid-PQ floor
- CIRISRegistry CEG 1.1 published with the `witness:`, `holding_claim:`, `compress_request:`, `holonomic_topology:` namespaces ratified
- Documentation: MISSION.md updated with the holonomic-federation framing; THREAT_MODEL.md updated with the path-independence threat surface

## What v4.0 does NOT contain (filed for later)

- Holonomic MLS snapshots — persist + verify cross-repo work; can ship at v4.x
- Privacy-preserving witness disclosure (ZK claim-membership) — research-grade, deferred
- Cross-witness BFT proofs against Byzantine peers — solvable independently once basic protocol ships
- Compression of older witnesses into longer-cadence epigraph hashes — operational nicety, deferred

## Version-number discipline

Three cuts to v4.0. No v3.20.x death march. Each cut is ambitious; each is shippable.

| Cut | What ships | Time horizon |
|---|---|---|
| v3.8.0 | substrate | shipping now |
| v3.9.0 | actual working holographic mesh (codec wiring) | next |
| v3.10.0 | holonomic substrate (4 pieces bundled) | next-after-next |
| v4.0 | CEWP-1.0 holonomic federation seal | the cut after that |

## Composition with siblings

| Repo | Cut | Compose-point |
|---|---|---|
| CIRISPersist | v8.0.0 (#227) — layer-aware eviction | `ChunkLayer.quality` priority byte |
| CIRISPersist | v8.x — wholeness_witnesses table + retention | WholenessWitness storage |
| CIRISVerify | (TBD) — holonomic MLS snapshots | exporter_secret as witness leaf |
| CIRISRegistry | CEG 1.1 — witness:/holding_claim: namespaces | the wire format for all of the above |

## The reason this matters

CIRIS's Mission says diverse sentient beings may pursue their own flourishing. A holographic substrate gives graceful degradation under loss. A holonomic substrate gives the federation a stronger property: **graceful reconstitution from any sufficient fragment**.

Every node can leave; come back years later; bootstrap from any claim chain; reach the same federation view as everyone else. No central authority needed. No special bootstrap peers. No path-dependence to recover. The federation as a whole is path-independent — which means it can survive arbitrary partial loss + arbitrary partial reconstitution + arbitrary onboarding of new sovereign beings.

This is the deepest expression of M-1. v4.0 ships it.

## Cross-repo: CEG normative absorption ([CIRISRegistry#85](https://github.com/CIRISAI/CIRISRegistry/issues/85))

**Filed as the gate to v4.0 on the spec side.** Without this, v4.0 cannot ship as "the holonomic federation seal" because the federation isn't actually interoperable across implementations — two implementations of WholenessWitness produce different Merkle roots from the same claim set; two AlmJoinPlanners arrive at different topologies from the same inputs; two retention_priority implementations evict different symbols. The substrate works; the *federation* fragments.

CEG 1.1 must absorb the following as normative by v4.0:

- **§N** realtime A/V chunk wire-format (incl. codec_id namespace from #84)
- **§M** ALM substrate envelopes (RelayCapacity, SignedRelayCapacity, SubStreamCommitment, planner algorithm)
- **§P** fountain content/manifest (FountainManifestV1, FountainSymbolV1, retention_priority encoding, eviction tier table)
- **§Q** codec wiring contract (raptorq + rav1e/dav1d/opus mapping)
- **§R** swarm-coordinated rarest-shard retention (FountainCompressRequest, FountainHoldingClaim, rarity scoring)
- **§W** WholenessWitness (canonical bytes, Merkle tree construction, reconciliation)
- **§T** deterministic ALM topology (pure function specification)
- **§B** recursive trust bootstrap (admission rule)

Each section includes **conformance test vectors** — input → expected output byte-for-byte. Migration paths from informative to normative are non-breaking; existing v3.6+ wires interop with v4.0 wires.

## What this means for the cuts

Every edge cut from v3.8.0 onward should be paired with a CIRISRegistry CEG normative addition request. The pattern:

1. Edge ships a substrate piece as informative implementation
2. Empirical validation via benches + tests
3. CIRISRegistry promotes to normative § via CEG 1.1 spec absorption
4. Conformance test vectors locked
5. v4.0 ships when all of the above are stable cross-repo

**Without normative status, the substrate is non-interoperable. With it, the federation can have multiple implementations that genuinely federate.**
