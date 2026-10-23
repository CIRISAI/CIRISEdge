# The mesh census — edge's proposal as main consumer

For the steward and the CC, 2026-10-22. Answers the CC's five questions after the ruling that the holonomic
view is rebuilt as the **census**: each node keeps its **inventory** (local), publishes anonymous **census
returns** (counts only), the CC 6.1.2 N→1 aggregation tier folds returns into the **mesh census**, and
`mesh_config` reads the census. Row shape is to be agreed with persist; CC registers names and rules.
Labels: **SHIPPED**, **BUILT** (code + tests, no production path), **NEW** (needs code).

Three design rules run through every section:

1. **The census never decides anything by itself.** It is measurement. Behaviour changes only through
   `mesh_config`, relieve-never-expand, signed by the accord authority as today.
2. **A return is coarse and an individual return is never published.** Only composites that pass the
   dominance gate and a minimum source count leave the aggregator.
3. **Recovery wants more work, and the plane cannot grant more work.** Every census-driven action that
   *increases* a node's effort (a catch-up round, a repair fetch) is an owner-local default triggered by a
   measured condition, never a `mesh_config` key. The plane only narrows.

---

## 1. The questions edge needs answered

| # | Question | Composite it reads | Decision it drives | Cadence |
|---|---|---|---|---|
| Q1 | How many nodes are live, by budget class? | node count per budget class (server / home / phone-wifi / phone-cellular / off) | Shaping defaults per class (ρ, W) and the node cap (CC 5.4.3); whether the rc10 table still fits the fleet's mix | hourly composite, daily trend |
| Q2 | How fast does the fleet churn? | nodes present this period and absent last period, and the reverse, as fractions | Onion route lifetime and the one-hour period (CC 5.4.6); anti-entropy cadence relief; the liveness window | daily |
| Q3 | How many relays can each onion layer draw on? | seat-like and ordinary relay counts, hop keys published, liveness-answering count (the liveness fold's per-node result, bucketed) | The onion availability answer's "your set is small" copy; the cap factor c; whether μ (mix delay) can relax | per onion period (1 h) |
| Q4 | How deeply is each class of item held? | holder-depth histogram per item class and scope class (bucketed: 1, 2–3, 4–7, 8–15, ≥16 holders) | Repair targets and the durability floor (`redundancy.*` keys); the chunk-replication target holder count that replaced RaptorQ | daily |
| Q5 | How much traffic does each plane carry, per class? | bytes per plane per budget-class window, bucketed; shaped-link counts; real versus cover share | Budget classes and λ; the cover share; whether a class budget is set too low (constant saturation) or too high (mostly cover) | hourly |
| Q6 | Is the mesh partitioned, and when did it heal? | fleet size per region bucket and per aggregator, compared with the last stable composite | Trigger owner-local catch-up rounds and repair on heal (rule 3); hold back narrowing reliefs while a partition is suspected | each period, plus on change |
| Q7 | How big is the room per plane? | rows held per plane, bucketed (the advertise sweep's `listed` count) | Anti-entropy page limit relief; expected round cost; the replication budget the shaped links must carry | daily |

Q6 needs one rule of its own: a sudden fall in the composite's source count (for example more than a third
between periods, with no fall in any single aggregator's share) reads as a partition, not as churn. During
it, no relief that narrows replication is applied, and on recovery each node runs its own catch-up.

---

## 2. What a node may return

### 2.1 Granularity

Every count in a return is **bucketed on a log₂ scale** (0, 1, 2–3, 4–7, …) and reported as the bucket
index, never the exact value. Dimensions a count may be split by:

- **Scope class**: self, family, community, federation, as classes. Never which cohort, room or group.
- **Plane**: the envelope kind or the CC plane name (identity, replication, A/V, chat, blob).
- **Budget class**: the node's own declared class.
- **Region bucket**: optional, self-declared, at most continent-sized. A node that declares none is counted
  under "undeclared". A region bucket is published in a composite only when it passes the gate in §2.3.

### 2.2 What may appear where

| Count | In a return | In a published composite |
|---|---|---|
| Node present this period, budget class | yes | yes (count per class) |
| Seen last period (churn bit) | yes | yes (fraction) |
| Relay standing, hop key published, opted out | yes | yes (counts per layer class) |
| Liveness: answering relays per layer, as this node measured | yes, bucketed | yes (median and spread) |
| Holder depth per item class and scope class | yes, as a bucketed histogram | yes, federation and community classes only |
| Holder depth at self or family scope | yes, as one coarse histogram, no item class | **aggregate only**: folded into a fleet-wide "private-scope held deeply enough" fraction, never split |
| Rows held per plane | yes, bucketed | yes |
| Bytes per plane per class window | yes, bucketed | yes |
| Shaped links, live links, pooled lanes | yes, bucketed | yes |

### 2.3 The withholding gate

A composite cell is published only when **both** hold:

1. **k-anonymity floor**: at least `k = 10` distinct returns contributed to the cell.
2. **Dominance gate** (CC 6.1.2.1.2): no source supplies more than half of the cell's mass, checked by
   `passes_dominance_gate` over the signed `n_eff`. Edge already re-exports both from verify.

A cell that fails is merged upward (region into "all regions", item class into "all items") and retried. A
cell that still fails is withheld and published as "below the floor". The reader sees "unknown", never a
small exact number.

### 2.4 What a node must never return

- Any identity: its own key id, a peer's key id, a transport identity, a destination hash, an IP address.
- Any per-item fact at a private scope: which items, how many copies of a given item, which room.
- Exact small counts. A raw count of 1 or 2 is identifying, and bucketing removes it.
- Timing finer than the period. A return is stamped with its period number only.
- The membership of any cohort, even as a count, below the community scope class.

---

## 3. The rows

### 3.1 Names

- `census:return:v1` — one per node per period. **Not replicated.** It travels to exactly one aggregator
  and is deleted at the end of the next period.
- `census:composite:{class}:v1` — one per aggregator per period per composite class (`fleet`, `relay`,
  `holdings`, `traffic`, `room`). Published at federation scope. Carrier: `AggregationMetaV1` at
  version 3 (signed `n_eff` and mass commitment), with the bucketed cells as the body. Retention: the 19.7
  descent applies, so old composites fold into coarser tiers rather than being deleted.

### 3.2 Who aggregates

**Seats.** They are announced, accountable, already the rendezvous for the onion tier, and their count is
public. Each node sends its return to exactly one seat per period, chosen by
`H(return_token ‖ period) mod seats`. Composites from different seats are then disjoint and can be summed
without double counting. That is the correlated-source discount solved by construction instead of estimated.
Any node may also fold the composites it receives into its own fleet estimate. That estimate is local and is
never published as a composite.

### 3.3 The anonymity boundary, stated honestly

The seat that receives a return learns that a node sent it. There are two ways to handle this:

- **v1: signed returns, a trusted fold.** The return rides the node's identity link to the seat, sealed under
  E1 and hybrid-signed by the node. Sybil resistance comes from rooted standing, one return per node per
  period. The seat sees one node's coarse, bucketed counts and nothing else, and it must not retain or
  forward returns. This is the same trust a seat already carries for routes and mailboxes. The residual risk
  is a seat that logs returns. It would learn bucketed facts about nodes it can already see on the wire.
- **v2: blinded return tokens.** The seat issues each rooted node one blinded token per period. The node
  submits its return with the unblinded token over an onion route, and the seat can check the token without
  linking it to the node. This removes the residual, but it needs a post-quantum blind or anonymous
  credential scheme. That is open research for the hybrid-signature line, so v2 is named and not scheduled.

### 3.4 How a reader verifies a composite without learning its sources

- **The commitment is over return tokens, not node ids.** A return token is `H(node_secret ‖ period)`. It is
  fresh each period, so tokens cannot be linked across periods, and a node id cannot be tested against the
  commitment.
- **Any reader** checks the seat's hybrid signature and the dominance gate over the signed `n_eff`. It also
  checks that the cells sum to the mass commitment.
- **A contributing node** can ask its seat for the Merkle path of its own token, and so prove its return was
  counted. Nobody else learns the token list.
- **Seats cross-check each other.** The sum of the seats' source counts should track the directory's count
  of live announced nodes, bucketed. A seat whose share departs sharply from its expected `1/seats` fraction
  is visible to every reader.

---

## 4. The loop

### 4.1 Keys the census may set or relieve

All keys relieve-never-expand. The census proposes, the accord authority signs, edge consumes.

| Key | Consumer | Census input | Example relief |
|---|---|---|---|
| `shaping.rho` | `link_shaping.rs` | Q5 traffic, Q1 class mix | lower ρ when a class runs mostly cover |
| `shaping.window_secs` | `link_shaping.rs` | Q2 churn | shorten W for a class whose links live shorter than W |
| `shaping.node_cap_bytes_per_s` | `link_shaping.rs` | Q5 saturation | lower the cap where it is never reached |
| `onion.cap_factor` | `onion_layers.rs` | Q3 relay counts | lower c when seat-like relays dominate the deal |
| `onion.mix_mean_delay_ms` | the onion relay (NEW) | Q3, Q5 | shorten μ when layers are large |
| `antientropy.round_secs`, `antientropy.page_limit` | `ReplicationRuntime` (SHIPPED) | Q7 room size, Q2 churn | slower rounds for a stable, small room |
| `redundancy.target_holders`, `redundancy.min_viable_holders` | the repair planner | Q4 holder depth | fewer target holders where depth is already high |

### 4.2 From a measured value to a relief

- **The policy function is pure and published**: `relief = f(composite, current_config)`. It is versioned
  beside the key registry so every node can recompute what the authority should have signed.
- **Bound**: each key keeps its registry bounds. A relief can never cross the owner's configured value.
- **Hysteresis**: a relief changes only when the composite has been outside the current band for two
  consecutive periods, and it moves one band at a time. A relief is never applied while Q6 reads as a
  partition.
- **Who signs**: the accord authority signs the `mesh_config` row, as today. A seat's composite is
  evidence, not authority.
- **Rollback**: the row's TTL is the rollback. If the authority stops renewing a relief, nodes return to
  their owner defaults.

### 4.3 How this composes with CIRISEdge#886 and the five plane keys

The six loop-closing steps on #886 become:

1. **Install the swarm runtime and publish claims.** It stays the durability tier's own step, and it feeds
   Q4's holder depth for opted-in items.
2. **Expose the view.** This becomes the node's inventory, plus the census return built from it.
3. **Close `RepairNeeded`.** Repair stays owner-local (rule 3). Census Q4 says where repair is worth it.
4. **Possession challenges.** These are unchanged. They raise the weight of the holder-depth input.
5. **Shaping and onion keys in the plane.** These are the five plane keys, listed above with their census
   inputs.
6. **Witness roots.** `leaf_count` becomes Q7's local input, and the root comparison stays a
   reconciliation trigger.

---

## 5. What a first return can carry today

| Census field | Source in edge today | Status |
|---|---|---|
| Rows held per plane | the advertise ledger's `listed` count per round (`bridge.rs` sweep) | SHIPPED, MEASURED |
| Live links, pooled lanes, sealed links | the link pool and seal counters in `Edge::metrics()` | SHIPPED |
| Shaped links and class | the `link_shaping` metrics dict (43.2) | SHIPPED in 43.2, off by default |
| Peers this node can route to (its own fleet estimate) | the route table and directory counts per identity type | SHIPPED |
| Relay standing, hop key, opt-out | the announced row and the deal's inputs (`onion_layers.rs`) | BUILT |
| Answering relays per layer | `onion_liveness.rs#LivenessFold` | BUILT, not wired |
| Cohort holdings | `ConvergedView` | SHIPPED as a tap, but empty in the fleet because no node publishes claims |
| Holder depth per item | `ObservedClaims` | BUILT, needs the swarm runtime |
| Bytes per plane per class window | none | NEW: a per-plane byte counter on the shaped and unshaped send paths |
| Churn bit | none | NEW: one persisted "present last period" flag |
| Budget class, region bucket | the shaping config (class); region is NEW and optional | partly SHIPPED |
| The return itself, bucketing, seat choice, token | none | NEW |

So a first `census:return:v1` can ship with Q1, Q3 (without liveness), Q5 (links only) and Q7 from
counters that already exist. Q2 needs the churn bit, Q4 needs the swarm runtime, and Q5's byte counts need
one new counter.

---

## 6. Open points for the CC and persist

1. Confirm the term (census, inventory, return, composite) before persist names rows.
2. Persist: `census:return:v1` must be a non-replicated row class with a one-period TTL, readable only by the
   receiving seat. A new placement class may be needed, because no existing plane is "deliver to one seat
   and expire".
3. CC: the k floor (10) and the region rule are proposals and want the steward's number.
4. CC 6.2's surviving pieces (the effective-count definition and the correlated-source discount) sit beside
   the dominance gate. The seat choice in §3.2 makes the discount zero by construction for census composites.
   CC should say so, so readers do not apply the discount twice.
