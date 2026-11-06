# The holonomic view — "size of the room, length of the shelf"

For the steward, 2026-10-22. Companion to `docs/MESH_AND_HOLONOMICS_2026-10-22.md`. Labels as before:
**SHIPPED** (in the wheel, on a production path), **BUILT** (code + tests, no production path),
**DESIGNED** (FSD/CC text only), **MEASURED** (a number code produced or a test pins), **MODELLED**
(arithmetic over assumptions). The steward's frame is adopted: RaptorQ is the **durability tier**, an opt-in
per item in a family or community; the holonomic view is **measurement that feeds policy**. The phrase
"size of the room, length of the shelf" appears in no repository text; this document gives it its first
written definition from the pieces that exist.

---

## 1. The concept as designed

### 1.1 The two quantities

- **The size of the room** is what a node believes exists: the corpus, per scope and per plane, as a
  count of items and a root over their identities. It is a statement about the *whole*, held by a part.
  Design sources: CC 6.1 ("each part contains a projection of the whole"); CC 6.1.1 WholenessWitness ("a
  peer's hybrid-signed Merkle root over a scoped projection of the claims it holds", with `leaf_count` and
  `claim_namespaces`); the NodeCore scaling model's thesis that identity-aware storage lets every node know
  *whose* bytes it holds and for whom (`CIRISNodeCore/FSD/FEDERATION_SCALING_MODEL.md` §9).
- **The length of the shelf** is how deeply each item is held: holders per item, symbols per holder, the
  node's own share, and the gap to the target. Design sources: CC 6.1.5 (`FountainHoldingClaim` as the
  symbol-level who-holds-what, N6 possession-challengeable; `target_holders` H = 30; `min_viable`);
  `src/holonomic/fountain_defaults.rs` (the C₁/C₂/C₃ derivation of H; the survival table).
- **What a node cannot see**, by design: self/family holdings outside its cohort (WW-2, WW-3, #499 scoped
  claims); anonymous-tier content (SR-2/3: exempt from claims and from reconstitution); any identity behind
  the counts on a public surface (`converged_view` returns numbers only); and anything a peer has not
  claimed in the last TTL (silence is "unknown", never zero).

### 1.2 How a node computes its view (designed)

Three instruments, each a pure fold over signed inputs:

1. **The witness root** (`src/holonomic/wholeness_witness.rs#WholenessWitness`): lex-sorted, deduplicated
   leaves (the canonical bytes of the signed claims in the named namespaces), SHA-256 Merkle with odd-node
   duplication, `b"WW-v1-empty"` sentinel; fields `peer_id, epoch_id, merkle_root, leaf_count,
   claim_namespaces, observed_at_unix_ms, witness_version`, hybrid-signed. It attests **"this is the whole
   I hold in these namespaces at this epoch, and how many pieces it has"**. Two peers compare roots
   (`compare_witnesses` → `Identical | Divergent | EpochBehind`); divergence *triggers* reconciliation and
   never decides it (CC 6.1.1 "the witness sees, the quorum-merge rules"). The federation chain
   (`witness_chain_split.rs#FederationWitness`) adds a **rate-smoothed activity counter** with cover leaves,
   so the federation learns *that* non-federation activity exists at a constant tick, never how much —
   the room's size is told at federation scope only to the resolution the privacy model allows.
2. **The holding claim fold** (`src/holonomic/converged_view.rs#fold_observations` over
   `FountainHoldingClaim`s): per cohort, the distinct peers, distinct contents, live `(content, peer)`
   claims, symbols claimed, and the age of the newest and oldest claim. The length of the shelf per item is
   the per-content holder count inside `src/swarm/runtime.rs#ObservedClaims` (a per-content map of
   per-peer claims with `HoldingClaimVerification`: `PossessionVerified` weight 2, `SignatureOnly` 1,
   `Unverified` 0 — `swarm_rarity.rs#HOLDING_WEIGHT_*`), which `compute_rarity_score` turns into a
   retention priority and `should_eject_above_target` into an `EjectionVerdict`.
3. **The replication round** (`src/replication/protocol.rs#SummaryMessage { kind, refs }`): every
   anti-entropy round an initiator receives, per plane, the peer's page of envelope references and answers
   with a `Diff` of what it lacks. This is the row-level shelf: what *this peer* holds that I do not, plane
   by plane, bounded by `antientropy.page_limit`.

### 1.3 How views converge (designed)

Same inputs ⇒ same output: the witness root is order-independent (sort inside the function), the claim fold
is a pure arithmetic over a set, the rarity verdict is integer-only. Convergence across nodes is therefore
convergence of *inputs* — replication carries the rows, claims are published to the cohort on a cadence, and
witness roots are compared — not agreement of planners. Where inputs differ, the witness says so
(`Divergent`) and the quorum-merge (CC 5.3.2.3) decides. The onion layer deal (`onion_layers.rs#deal_layers`)
and the shaping agreement (`link_shaping.rs#agree`) follow the same rule: pure over the fold, never over
arrival order.

---

## 2. The state today

| Quantity | Grain | Where | Exposed to host | Published to peers | Status |
|---|---|---|---|---|---|
| Rows held per plane | per plane, per node | persist (the directory); edge sweeps it per round (`bridge.rs` advertise sweep, page-bounded) | the Server reads persist directly for its own store counts ("748 identities, 101,631 trace_events, as seen by this node") | **yes**: `SummaryMessage` per round, per plane, to consent peers; row-level | SHIPPED, MEASURED (the advertise ledger counts `listed / withheld / offered` per round) |
| What a peer holds that I lack | per plane, per peer, per round | `Diff` / `Deliver` in `src/replication/coordinator.rs`; the #882-narrowed audience gate decides what is shown | metrics only (`advertise`, `withholds_by_reason`) | yes (the Diff) | SHIPPED |
| Cohort holding counts (peers, contents, claims, symbols, freshness) | per cohort, counts only | `src/holonomic/converged_view.rs#ConvergedView`, armed at `edge.rs:4122/5012`, fed at `edge.rs:7299` from verified inbound claims | `Edge::swarm_convergence()` (Rust); **no PyO3 wrapper, the Server does not read it** | — | SHIPPED as a tap; **always "cold start / converged to nothing" in the fleet**, because no node publishes claims (next row) |
| Holding claims (`FountainHoldingClaim`) | per content, per holder, symbol ids | `src/swarm/runtime.rs#FountainSwarmRuntime` publisher; `ObservedClaims` map | — | would be: cohort-scoped (`swarm/scope.rs`) | **BUILT, NOT WIRED**: `Edge::install_swarm_runtime` has no caller in edge or PyO3; no claim is ever published |
| Per-item holder depth, rarity, ejection verdict | per content | `ObservedClaims`, `compute_rarity_score`, `should_eject_above_target`, `swarm/diversity.rs` | — | — | BUILT; the verdict names (`Keep / EjectToTier / …`) match CC 6.1.2 |
| Possession challenge (N6) | per claim | `HoldingClaimVerification::PossessionVerified` is a *weight*; no challenger exists | — | — | DESIGNED only: claims would count `SignatureOnly` (weight 1), never `PossessionVerified` |
| Witness root | per namespace set, per epoch | `WholenessWitness` + `witness_chain_split` | — | — | BUILT, unit-witnessed; **nothing publishes or compares a root in production** |
| Fountain symbols held | per content | persist's fountain store (`list_held_fountain_content`, `evict_fountain_content_to_tier`, `_hard_delete`); the RaptorQ codec `realtime_av_codec/fountain.rs` | — | — | persist surfaces SHIPPED; codec **FEATURE-GATED** (`codec-fountain`, not in the wheel); correct for a per-item durability tier that no producer has yet opted into |
| Survival floor | the tuple (N=20, K=6, min_viable=5, H=30) | `fountain_defaults.rs` | constants | — | SHIPPED constants; MEASURED by test and bench: P(reconstruct) 0.9999 at q=0.95, 0.995 at q=0.90, 0.957 at 0.85, 0.845 at 0.80 under spread-duplicate placement |
| Noise floor / aggregation | per aggregate | `holonomic/aggregation.rs` (used by `pyo3.rs:8726`), `multiplicity.rs` | yes (the Server's aggregation door) | yes (the aggregate rows) | SHIPPED |
| Relay liveness (for the onion tier) | per relay, per period | not yet; see §4 | — | — | DESIGNED |

In one sentence: **the room is known at the row level, by replication, and that view is live; the shelf
(holders per item) is designed, built and tested, and nobody in the fleet publishes it yet, because the
durability tier it serves has no opted-in items.**

---

## 3. Policy: view → mesh_config → behaviour

### 3.1 What was meant

Persist's `mesh_config` plane (CC 4.2.1; `ciris_persist::federation::mesh_config`) is the one door through
which the fold sets policy: accord-authored, TTL'd rows, resolved per root most-restrictively, **relieve
never expand**. Every key names a consumer and a knob (persist's registry test enforces it). The four
redundancy keys name consumer `repair_planner`: `redundancy.k_repair_symbols` → `k_repair` (owner default
20), `redundancy.min_viable_symbols` → `min_viable_symbols` (20), `redundancy.target_holders` →
`target_holders` (64), `redundancy.min_viable_holders` → `min_viable` (64). Their edge consumer is
`SwarmRuntimeConfig::with_mesh_relief`, which `min`s each relief into the running converger's config on its
tick (`src/swarm/runtime.rs:271`): a root can tell the fleet "hold fewer copies of this corpus" (the #570
headline "20 copies → 10") or raise the holder floor that triggers `RepairNeeded`, and no root can make a
node hold *more* than its owner configured.

The intended loop, from the design: **measure** (holding claims → `ObservedClaims` / `ConvergedView`; witness
roots → divergence) → **judge** (rarity vs `target_holders`; `min_viable` → `RepairNeeded`; divergence →
reconcile) → **act locally** (`EjectToTier`, hard-delete on revocation, fetch repair) → **steer globally**
(a root reads the measurements, writes a `mesh_config` relief, every node narrows). The view sets policy
only through the plane, so no node's measurement ever widens anyone's behaviour.

### 3.2 What is wired today

- `antientropy.round_secs`, `antientropy.page_limit`, `feature.trace_replication`, `feature.av_streams`:
  SHIPPED (`MeshConfigReader`, TTL 30 s, `ReplicationRuntime` at `runtime.rs:404`). These steer the **room's
  replication**: how often and how much of the shelf is compared.
- The four redundancy keys: resolved by the reader, **consumed by nothing** in the fleet (no swarm runtime).
- Shaping (CC 5.4.3) and the onion tier (CC 5.4.6) have **no mesh_config keys**: ρ, W, the class budgets, the
  node cap, `c`, μ are owner/steward settings in edge config today, not relievable from the plane.
- `RepairNeeded` is emitted (when a runtime runs) and consumed by nothing: the repair fetch off the blob
  swarm is a "downstream cut" that never came.

### 3.3 Closing the loop — what it would take

1. **Install the swarm runtime and publish claims** on an opt-in basis: the host calls
   `Edge::install_swarm_runtime` (needs a PyO3 wrapper) for nodes that hold durability-tier items; claims stay
   cohort-scoped (#499). Cost: one FFI function, one Server toggle, the publisher's cadence on shaped links.
2. **Expose the view**: a PyO3 wrapper for `Edge::swarm_convergence()` (counts only) so the Server's mesh
   status reports the converged cohort view beside its own store counts, with `null` for "unknown".
3. **Close `RepairNeeded`**: wire the event to the blob swarm's fetch for the under-held content (the
   designed "downstream cut"), bounded by the owner's disk budget.
4. **Possession challenges (N6)**: a symbol request/answer so claims can reach `PossessionVerified`; without
   it rarity runs on `SignatureOnly` weight and a liar can lower a peer's retention priority at most by one
   weight unit — acceptable for v1, state it.
5. **Shaping and onion keys in the plane** (CC change + persist registry + edge consumer): `shaping.rho`,
   `shaping.window_secs`, `shaping.node_cap_bytes_per_s`, `onion.cap_factor`, `onion.mix_mean_delay_ms`,
   each with a consumer in edge, all relieve-never-expand (a root may lower a budget or shorten a window,
   never raise one). This is the "view sets policy" the steward describes, done the way the plane already
   works.
6. **Witness roots**: publish `FederationWitness` on the constant tick and compare on receipt; the first
   consumer is reconciliation telemetry (how far apart two nodes' rooms are), not a merge decision.

---

## 4. The onion tier's honest liveness count

The layer deal is a function of the fold: it says who *should* be in each layer this period. It cannot say
who *is answering*. The fold's inputs for a relay (a live announced row, a hop key, no opt-out, an owner
binding under a bundle root) are all slow facts; a phone that went to sleep ten minutes ago still satisfies
every one. The client's "available / unavailable" answer therefore needs a second, measured input beside
the deal:

- **A relay-liveness quantity, holonomic in shape**: for each dealt relay, the age of the newest *verified*
  evidence that it answers — a completed shaped-link handshake to it, a route answer, a forwarded onion
  packet acknowledged by the next hop, or (the natural generalisation of N6) a **possession-style
  challenge**: a tiny onion packet the node sends through the relay to itself and times. Folded like
  `ConvergedView`: per layer, `relays_dealt`, `relays_answering_within(W)`, `newest_evidence_age`, counts only.
- **A crowd quantity**: how much shaped traffic the node's own hop-1 candidates carry is not observable
  without being the relay; what the node *can* count is its own shaped-link set and, from the deal, how many
  publishers could choose the same hop 1 (the layer size). The honest crowd figure for the client is the
  model's: the layer size per layer, and "small" below ten.
- **Should it be the availability answer?** Yes, as a conjunction: `available = floor holds on the deal ∧
  answering ≥ 3 per layer within the period`. The deal stays authoritative for *who*; liveness decides
  *whether now*. It is per-node and may differ between nodes (one node's view of liveness is its own), which
  is exactly the property the deal must not have and the availability answer may. New work: the liveness
  fold (`src/transport/onion_liveness.rs`, ~200 lines on the `ConvergedView` pattern) and the client copy.

---

## 5. What CC 6.1 and 1.13.3 should say

1. **The durability tier is opt-in per item.** 6.1.5: "A producer MAY place an item in the durability tier
   (fountain-coded, swarm-retained toward `target_holders`); general content travels and is retained by
   replication and holder diversity." Today's text reads as if every item is fountain-coded and swarm-held.
2. **Status.** 6.1 / 1.13.3.1: "The durability tier's codec and swarm converger are specified, built and
   conformance-vectored; a release that installs the converger and enables the codec names the first opted-in
   kinds." Today's text implies they run.
3. **The holonomic view is measurement feeding policy.** A new sentence in 6.1 (or 4.2.1): "The holonomic
   view — witness roots, holding claims, replication summaries — is how a node measures how much there is to
   know and how deeply it is held; it changes behaviour only through the `mesh_config` plane, relieve-never-
   expand, so no measurement widens any node's flow." Then list the keys that exist and mark the
   redundancy four as "consumer installed with the durability tier".
4. **Witness roots.** 6.1.1 should say the root is published on the federation chain's constant tick and
   compared on receipt *once a release wires it*, and that `leaf_count` is the room's size per namespace to
   the privacy model's resolution (the rate-smoothed counter at federation scope).
5. **The onion tier's availability.** 5.4.6 item 4 could add one clause: "Availability for a period is the
   floor on the deal and, per node, a measured liveness of at least three answering relays per layer; the
   deal is fold-determined, liveness is the node's own."
6. **N6 today.** 6.1.5 N6 is stated as MUST; code counts unverified-possession claims at weight 1 and has
   no challenger. Either stage N6 as the durability tier's first-release requirement or state the weight
   rule as the interim.
