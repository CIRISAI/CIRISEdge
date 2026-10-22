# Edge's mesh configuration and holonomic capabilities, as they stand in code

For the steward, 2026-10-22, read from edge v43.1.1 / release 43.2 (`release/43.2.0` a8d1572) and the
onion branch. **MEASURED** = a number produced by code on this host or pinned by a test; **MODELLED** =
arithmetic over stated assumptions; **SHIPPED** = compiled into the wheel the fleet runs
(`transport-http transport-reticulum pyo3 lxmf`) and reachable from a production path; **BUILT, NOT WIRED** =
code and tests exist but no production path calls it; **FEATURE-GATED** = compiled only with a cargo feature
the wheel does not enable. Every claim names its symbol.

---

## 1. Mesh configuration

A node's mesh configuration is five things from four authorities. The fold decides membership and reach;
the owner decides what the node offers; the steward relieves (never expands) through a signed plane; the
fleet default is a constant in edge.

### 1.1 What the owner sets (host-supplied, local choices)

The single door is `src/ffi/pyo3.rs#init_edge_runtime` (42 keyword arguments) over
`src/transport/reticulum.rs#ReticulumTransportConfig` and `src/edge.rs#EdgeConfig` /
`src/edge.rs#EdgeBuilder`. Grouped:

| Group | Knobs (owner) | Where |
|---|---|---|
| Reachability | `listen_addr`, `bootstrap_peers`, `announce_interval_seconds`, typed `interfaces`, `enable_transport` (RNS transport-node mode), `transit` + IFAC trio (`ifac_netname/passphrase/size`), `local_instance_name/role` (shared rnsd) | `ReticulumTransportConfig` fields; `with_scoped_transit`, `with_transport_node` |
| Identity | `identity_path`, `local_epoch`, `use_node_identity`, `node_identity_dir`, `node_keystore_alias`, `agent_occurrence_key_id` | `ReticulumTransportConfig`; CIRISEdge#541 |
| Posture | `hybrid_policy`, `transport_binding_enforcement` (`src/transport/attestation.rs#TransportBindingEnforcement`: Advisory / WarnOnly / Enforce), `require_local_signer`, `bundle_save_gate` (`src/bundle_gate.rs#BundleSaveGateMode`, Off default), `own_build_bundle` | `EdgeConfig`, `bundle_gate` |
| Canonicals | `canonical_bootstrap_peers` (augments the baked set), `baked_canonical_dials` (default on outside a test trust root: `src/edge.rs#baked_canonical_dials_allowed`) | `src/edge.rs#baked_canonical_genesis_ids` reads persist's baked bundle |
| Shaping (43.2) | `shaping_class`, `shaping_rho`, `shaping_window_seconds`, `shaping_node_cap_bytes_per_s`, `require_shaped_links` | `src/transport/link_shaping.rs#ShapingPolicy`; `ReticulumTransportConfig::with_shaping` |
| Direct links (A/V) | `src/transport/direct_path.rs#DirectLinksConfig { facilitator, serve_facilitator, accept: RoomPeers \| Off }` | Rust builder only today |
| Budgets | `disk_budget_bytes`, `trust_recursion_depth`, `max_body_bytes`, `max_content_body_bytes`, `replay_window_seconds`, `event_channel_capacity`, `reachability_window_seconds` | `EdgeConfig` |
| Replication | the peer set (`src/ffi/pyo3.rs#set_peers` → `src/replication/runtime.rs#ReplicationRuntime::set_peers`), the self-publish set, scheduler cadence and round timeout (`ReplicationRuntimeConfig`), `disable_bundle_bootstrap_peers` (43.2, #881) | the HOST computes the peer set from consent and hands it in; edge adds the bundle's seats on the bootstrap planes |

### 1.2 What the fold decides (not configurable)

- **Who may be spoken to and served:** attribution (`#393` items 1–2: `owns_key` ∧ a hybrid-verified
  `transport_destination` for the `(peer, dest)`), the #659 Rooted floor (`src/replication/bridge.rs#audience_withholds`,
  narrowed in 43.2 by #882), persist's consent send-set and `may_receive`. Owner config cannot widen any of these.
- **The transit pair and now the hop key:** from the node's own hybrid-signed route row
  (`src/transport/transit_kex_peer.rs#PeerTransitResolver::resolve_authenticated`; the bundle seeds the seats'
  rows, CC 5.3.4). The 43.2 pre-seal route fetch (`src/transport/route_fetch.rs`) fetches it when not held.
- **Serve seats and the bundle:** `canonical_genesis_bundle().serve_nodes` and the v4 bundle's
  `serve_transport_destinations` (persist); edge's `baked_canonical_genesis_ids` is a read-only projection.
- **Shaping agreement per link:** `src/transport/link_shaping.rs#agree` — the conservative resolution of two offers,
  computed identically at both ends.
- **The onion layer deal (designed, 43.2+1):** `src/transport/onion_layers.rs#deal_layers`, a pure function of
  the fold (witnessed over T0–T19).

### 1.3 What the steward relieves (the mesh-config plane)

`src/replication/mesh_config.rs#MeshConfigReader` reads persist's `mesh_config` plane
(`resolve_mesh_config`: per-root most-restrictive fold, CC 4.2.1 rules 1–2) once per round (TTL 30 s) and
yields `MeshConfigRelief`: a relief **never expands** flow beyond the owner's baseline. Edge consumes eight
keys: `antientropy.round_secs`, `antientropy.page_limit`, `feature.trace_replication`, `feature.av_streams`,
`redundancy.k_repair_symbols`, `redundancy.min_viable_symbols`, `redundancy.target_holders`,
`redundancy.min_viable_holders`. The first four are wired (`ReplicationRuntime` at `runtime.rs:404`); the four
redundancy keys land on `src/swarm/runtime.rs#SwarmRuntimeConfig::with_mesh_relief`, which is only reached if
a swarm runtime is installed (§2.2: it is not, in production). SHIPPED for the first four; BUILT, NOT WIRED for
the redundancy four.

### 1.4 The fleet defaults (constants in edge)

Shaping: `ShapingPolicy::for_class` (ρ 0.5; W 600 s, 3600 s phone-cellular; 7000/2800/1400/350 B/s; node cap
8 links' worth; off). Link pool: `reticulum.rs#DEFAULT_LINK_POOL_IDLE_BOUND` 120 s,
`DEFAULT_LINK_POOL_IDLE_CAP` 4 idle links per destination, `MAX_CONCURRENT_DIALS_PER_DEST` 4,
`CHANNEL_FIRST_MAX_FRAGMENTS` 8. Replication cadence 30 s. Fountain: §2.1. Onion (designed): c = 2, floor 3,
μ 2 s, period 3600 s.

### 1.5 Relay roles today

| Role | What it is | Status |
|---|---|---|
| Row relay | any node re-serves rows it holds on the planes its audience rules allow; 43.1.1 added relaying other nodes' own signed route rows (`bridge.rs#relayable_signed_route`) | SHIPPED |
| RNS transport node | `enable_transport`: forwards Reticulum packets for non-local destinations | SHIPPED, owner opt-in |
| A/V relay leg | `src/transport/realtime_av_relay.rs#RelayNode`, relay legs in the A/V spine (#805) | SHIPPED on the live node for calls; local parent choice (`AlmJoinPlanner`) |
| Onion relay | hop key + default-on relaying (CC 5.4.6) | DESIGNED (FSD/ONION_ROUTING.md), not built |

No relay role today hides anything: every link is sealed and attributed to its two endpoints (CC 5.3.3.5 E1).

---

## 2. Holonomic capabilities

The holonomic substrate (`src/holonomic/`) is a set of **pure, deterministic functions over shared snapshots**:
same input bytes ⇒ same output on every peer, no coordinator. What exists, piece by piece:

### 2.1 Fountain coding and the swarm (CC 6.1.5, 6.1.2)

| Piece | Symbol | Status | What it buys |
|---|---|---|---|
| Default tuple N=20, K=6, min_viable=5, target_holders=30 | `src/holonomic/fountain_defaults.rs#recommended_policy`, compile-time asserts at lines 181–199 (`total = N+K`, `0 < min_viable < N`, `target_holders ≥ total`, `K/N ≥ 20 %`) | SHIPPED as constants | the producer-silent policy CC 6.1.5.1 restates |
| Survival floor | `fountain_defaults.rs#distinct_symbol_availability`, `#recommended_reconstruction_probability` | MEASURED by test (`repair_headroom_knee_at_k_6`) and the Monte-Carlo bench: P(reconstruct) 0.999926 at q=0.95, **0.995039 at q=0.90**, 0.957 at 0.85, 0.845 at 0.80, under spread-duplicate placement (22 singly-held + 4 doubly-held symbols, 26 distinct) | content survives the loss of a third of its holders at typical wifi availability; below q≈0.85 the floor is recovered by rarity repair, not by FEC |
| RaptorQ codec | `src/transport/realtime_av_codec/fountain.rs` (crate `raptorq`) | **FEATURE-GATED** (`codec-fountain`, via `codec-default`); the wheel's features (`pyo3`, `transport-reticulum`, `lxmf`, `transport-http`) do not enable it | the A/V layered codec's per-layer fountain wrap; no general content path fountain-codes today |
| Content transfer today | persist v52 DAG chunks + `src/blob_swarm` multi-peer byte-range swarm download (BitTorrent pattern over `list_holders`) | SHIPPED | parallel fetch and holder diversity; **plain chunks, not RaptorQ symbols** |
| Swarm rarity scorer, ejection verdicts | `src/holonomic/swarm_rarity.rs#compute_rarity_score`, `#should_eject_above_target`, `EjectionVerdict::{Keep, EjectToTier, …}`, `src/swarm/diversity.rs` (RTT-diverse ejection) | BUILT, witnessed; the verdict names match CC 6.1.2 | retention biased to the rarest symbols; over-target copies step down a tier |
| Swarm runtime (publish claims, observe, converge, evict to tier / hard-delete on revocation, `RepairNeeded`) | `src/swarm/runtime.rs#FountainSwarmRuntime`, installed by `src/edge.rs#install_swarm_runtime`; inbound claims routed at `edge.rs:7310` | **BUILT, NOT WIRED**: nothing in `pyo3.rs` or `edge.rs` calls `install_swarm_runtime`; the Server has no entry point for it | when installed: convergence toward 30 holders, rarity-driven eviction, revocation-driven descent |
| Scope-aware holding claims | `src/swarm/scope.rs` (#499): claims for self/family content stay in the cohort | BUILT with the runtime | CC 6.1.5 "no second who-holds-what directory" |
| Converged view (read side) | `src/holonomic/converged_view.rs` | BUILT, NOT WIRED | what the cohort says it holds |
| Noise floor / aggregation pyramid | `src/holonomic/aggregation.rs` (`AggregationMetaV1`, `first_repeated_source_id`, used by `pyo3.rs:8726`), `multiplicity.rs` (R9 content-similarity) | SHIPPED for the producer side of N→1 aggregation (used by the Server's aggregation door) | forever-memory below the floor; the erasure certificate's honesty |
| Consent decay scheduler | `src/holonomic/consent_decay.rs` | BUILT; wiring through `PersistHandle` is the host's | revocation as descent |

**Reconstitution from any sufficient fragment set** is therefore: MEASURED at the symbol-availability layer
(the table), real in the A/V codec when the feature is on, and **modelled only** for general content, because
general content is not fountain-coded in the shipped path and the swarm converger is not installed.
**Survival under node loss, partition, churn** today rests on replication (every holder of a row re-serves
it; anti-entropy heals partitions) and on the blob swarm's holder diversity — not on fountain coding.

### 2.2 Witness chains and deterministic topology (CC 6.1.1, 6.1.6, 6.1.8)

| Piece | Symbol | Status |
|---|---|---|
| WholenessWitness (signed Merkle roots over claim state), the federation/cohort chain split (#175) | `src/holonomic/wholeness_witness.rs`, `witness_chain_split.rs`; `unique_merkle_root` (43.0: a repeated leaf refused before hashing, CC 6.1.1) | BUILT and unit-witnessed; **no production path publishes a witness root** (`lib.rs` re-exports only) |
| Deterministic ALM topology | `src/holonomic/deterministic_topology.rs#compute_alm_topology_verified` over `(capacity_ads, trust_grants, reachability_observations, locality, snapshot_epoch_id)`, integer-only scoring (weights 50/30/20), N8 hybrid-verified `SignedRelayCapacity`, depth ≈ ⌈log_k N⌉ | BUILT, conformance-vectored (`field_conformance.rs:1270`); **the live A/V path uses the local `AlmJoinPlanner::plan` / `plan_parent_gated`** (`realtime_av_runtime.rs:924/954`), not the deterministic tree |
| Recursive trust bootstrap | `src/holonomic/recursive_trust_bootstrap.rs` | BUILT; admission in production is persist's rooting (`persist_root_binding`), not this walk |

So the one holonomic function running in production is the aggregation producer; the one deterministic
structure the mesh actually relies on at runtime is the fold itself (persist's rooting, send sets, the
bundle), which is where 43.2's shaping agreement and the designed layer deal also sit.

---

## 3. What the two bear on the onion tier

### 3.1 Could a holonomic structure replace or strengthen the three-layer deal?

- **The ALM relay tree (CC 6.1.6) is the wrong shape and the right precedent.** It is a *tree* rooted at a
  publisher, scored by capacity, trust and reachability, for one-to-many fan-out; an onion route is a *path*
  through three independent layers whose members must not know who the publisher is. Reusing the tree would
  put the publisher at the root by construction. What transfers is the precedent: a pure, integer-only,
  permutation-invariant function over verified inputs (N8) with conformance vectors. `deal_layers` already
  follows it (H over a domain tag, seats first, no floats, no map order). **Real:** the method. **New work:**
  none for the deal; vectors for it when the CC registers the claim.
- **Member-relay fan-out** (the member-only ALM of CC 6.1.6's informative position) is cohort-scoped by
  design; the onion tier is federation-scope and must *not* be member-only (that would announce the cohort).
  Not applicable.
- **Deriving layer capacity from the swarm's holding set instead of seats.** The idea: let a layer's cap scale
  with how many *verified holders* the fountain swarm sees, so a thick holding swarm means thick layers. Two
  problems. First, the holding set is not a trust signal: a holding claim proves possession of symbols (N6),
  not that the holder is not a Sybil; a swarm of strangers can hold symbols as cheaply as it can relay. The
  cap exists to bound the *hostile share* of a layer, and only seats carry the standing that bounds it
  (vetted, in the bundle, under a charter). Second, the holding set is not in the fold the way seats are: the
  swarm runtime is not installed, claims are cohort-scoped for self/family content, and `converged_view`
  is per-node and TTL-pruned, so two nodes would deal different layers. **Verdict:** holonomics cannot
  replace seats in the cap without re-opening the Sybil bound; what it *could* do is give the client a
  measured "how many relays are actually alive and answering" number (N6 possession challenges) to decide
  availability honestly. That is new work and does not change the cap.
- **A better lever that is already in the fold:** the cap could count **owner-bound, Rooted-under-a-bundle-root
  identities with standing** (e.g. a steward-conferred `infra:relay` role on the accord plane) as "seat-like"
  for the cap's denominator. That keeps the bound where trust is conferred and lets the steward grow layers
  by conferring, not by hoping. New work: one role token in the accord family and a one-line change in
  `deal_layers`' denominator. This is the recommendation if "few seats make small layers" must move.

### 3.2 Could the rendezvous mailbox be fountain-coded across seats?

Yes in principle, and it is the right long-term shape; today it is new work on top of pieces that are not
wired. A mailbox packet (15,200 B) RaptorQ-coded N=20, K=6 across three layer-3 seats with spread-duplicate
placement would survive the loss of any one seat (MODELLED from §2.1's floor at q≈1 for seats) and remove the
single rendezvous node from the receiver's route row. What it costs: the receiver's route blob would need
three final hops (three slots more, or one slot naming a seat set), the storage node set becomes visible to
the last relay, and a fetch collects from ≥ 20-of-26 symbol holders instead of one. What is **real** today:
the codec (feature-gated), the symbol-level survival math, persist's fountain store and eviction surfaces.
What is **new**: the codec in the wheel, a mailbox symbol placement rule (deterministic over the seat set,
`deal_layers` style), the multi-seat fetch, and the CC text (the row currently names one
`rendezvous_node_key_id`). Edge's recommendation: ship v1 with one seat per rendezvous row (seats do not
churn: §d of the onion model) and keep "mailbox as fountain symbols across seats" as the v2 item once the
swarm runtime is installed for anything else.

### 3.3 Shaping and the fountain swarm

If the swarm runtime is ever installed, its holding claims and symbol fetches are ordinary identity-plane
rows and ride shaped links like everything else; the onion tier's relays would then also be symbol holders,
which is fine (relays are already any node) and does not change the deal.

---

## 4. Where the CC text and the code disagree

1. **CC 1.13.3.1 and 6.1.5 speak of a running fountain/anonymous substrate; edge ships the constants and the
   codec behind a feature.** The wheel does not enable `codec-fountain`; no production path fountain-codes
   general content; `FountainSwarmRuntime` is never installed. The survival table is true of the model, not of
   a deployed swarm. CC should say the fountain layer is *specified and feature-gated* until an edge release
   installs the runtime and enables the codec.
2. **CC 6.1.6 "every peer computes the same tree":** the live A/V path uses the local `AlmJoinPlanner`
   (edge-internal, as the PIN line allows), not `compute_alm_topology`. The deterministic function exists and
   is vectored; it is not what a call uses today. Not a contradiction of the PIN line, but a reader would assume
   otherwise.
3. **CC 6.1.1 / witness chains:** `WholenessWitness` is built and tested; nothing publishes a witness root in
   production. The CC's "every other piece verifies against witness chains" describes the design, not the fleet.
4. **CC 4.2.1 / mesh_config:** the four `redundancy.*` relief keys have a consumer in edge only when the swarm
   runtime is installed; today they resolve and are dropped. The other four keys are live.
5. **CC 5.4.3 item 1 says shaping is "agreed in the transit key-exchange handshake (the CTKX frame)".** In
   43.2 the offer is the link's first *sealed* frame after CTKX (the CTKX body is ciris-crypto's fixed
   `TransitHandshake`); the two offers resolve identically at both ends. Same property, one frame later; the
   text should say "immediately after the handshake, under its keys".
6. **CC 6.1.5.1 says edge asserts `target_holders ≥ total` "at compile time":** true (`fountain_defaults.rs:192`),
   and edge additionally asserts `K/N ≥ 20 %` (line 199), which CC does not mention. Minor.
7. **Nothing in CC names the 43.2 route fetch's rate numbers (32 per 10 s) or the link-pool constants:** by
   design (implementation values), recorded here so the formal model does not assume CC fixes them.

---

## 5. What the steward needs for the onion cap and the formal model

- The cap bounds a layer to (1 + c) × its seats; capacity grows with seats or with whatever the cap's
  denominator counts. Holonomics does not supply a trust-bearing denominator; a conferred relay standing on
  the accord plane would (§3.1). Keep c = 2; decide whether to add a conferred standing to the denominator.
- Model the deal as it is coded: `deal_layers(candidates, period, c)` with the five-leg membership predicate
  and H = SHA-256(domain ‖ key_id ‖ BE64(period)); the Rust witness and the Python script agree on T0–T19.
- Treat fountain survival numbers as a property of the model and the A/V codec, not of general content, until
  the swarm runtime is installed; treat the rendezvous mailbox as single-seat in v1.
- Shaping is the live prerequisite and is off by default; the formal model's "shaped layer links" leg is a
  real gate in 43.2 code (`link_shaping.rs`, `require_shaped_links`).
