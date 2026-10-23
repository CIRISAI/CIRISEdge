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
| Q3 | How many relays can each onion layer draw on? | seat-like and ordinary relay counts and hop keys published, as classes per coarse region (all inputs of the public deal) | The onion availability answer's "your set is small" copy; the cap factor c; whether μ (mix delay) can relax | per onion period (1 h) |
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
| Liveness: answering relays per layer | **never** (the fold stays local; only its verdict is shown, to the node's own user) | no |
| Onion use: routes built, packets sent or relayed, onion bytes | **never** | no |
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
| Answering relays per layer | `onion_liveness.rs#LivenessFold` | BUILT; stays local by rule (section 8), never in a return |
| Cohort holdings | `ConvergedView` | SHIPPED as a tap, but empty in the fleet because no node publishes claims |
| Holder depth per item | `ObservedClaims` | BUILT, needs the swarm runtime |
| Bytes per plane per class window | none | NEW: a per-plane byte counter on the shaped and unshaped send paths |
| Churn bit | none | NEW: one persisted "present last period" flag |
| Budget class, region bucket | the shaping config (class); region is NEW and optional | partly SHIPPED |
| The return itself, bucketing, seat choice, token | none | NEW |

So a first `census:return:v1` can ship with Q1, Q3, Q5 (links only) and Q7 from
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

---

## 7. Threat model (AV rows)

Numbers in this section come from `docs/models/census_threat_model.py` (seeded, deterministic). Rows are
numbered after the onion FSD's last row, AV-89.

**Eligibility, used by every row.** One return per node per period, from a node whose owner binding chains
to a bundle root (rooted standing). Vote and base counts count **owners**, not nodes. Mesh-config counts
count nodes, with at most 8 nodes counted per owner.

#### AV-90: Census stuffer (Sybil returns move a relief, a default, a cap or a vote base)

**Attack**: an adversary controls s eligible nodes and returns the largest bucket in every field, to raise
a composite and move a relief, a shaping default, a relay cap, or the expected-active base of a vote.

**Mitigation**:
- **Per-field clamp.** Every field has a bucket ceiling, so one return contributes a bounded amount.
- **Robust fold for per-node quantities.** Composites of per-node quantities (rows held, bytes, links) publish
  the median bucket and the 10% trimmed mean, never a sum or plain mean. Modelled, 1,000 returns, honest
  median about 2,000 rows:

  | Sybil fraction | sum or mean moves | trimmed mean moves | median moves |
  |---|---|---|---|
  | 1% | +198% | +4.5% | 0 |
  | 5% | +989% | +22% | 0 |
  | 9% | +1,780% | +51% | one bucket (2×) |
  | 20% | +3,955% | +3,692% | one bucket (2×) |

  The median of log2 buckets moves at most one bucket below 20% Sybils in this model. The trimmed mean is
  sound only while the Sybil fraction is below the trim fraction, so reliefs read the median.
- **Counts are owner-bound.** Fleet and base counts can rise only by the number of eligible owners the
  adversary holds. The dominance gate (6.1.2.1.2) refuses a composite where one owner supplies more than
  half the mass.
- **Hysteresis.** A relief moves one band, only after two consecutive periods out of band (section 4.2).

**What it does not bound**: an adversary holding a real share of rooted owners moves counts by that share.
That is the federation's admission cost (PoB), not a census property. The census also cannot detect a
Sybil that reports plausible values. It bounds influence, it does not detect lies.

#### AV-91: Deanonymiser (small counts, sparse cells, differencing)

**Attack**: read a cell with few members (one region, one class), or difference two consecutive composites
to see one node join, leave or change.

**Mitigation**:
- **k floor**: a cell with fewer than 10 returns is merged upward, then withheld as "below the floor".
- **Coarse regions**: continent-sized at most, self-declared, and published only when the k floor holds.
- **No deltas**: composites publish levels, never changes. Every published value is also **rounded to a grid
  of max(k, two significant figures)**. Modelled: one join into a cell changes the published value with
  probability 0.10 for cells of 10 to 100 returns, and 0.01 at 1,000, against 1.00 for exact values. A
  change that does show says only that some node in a k-sized cell changed.
- **Bucketed returns**: a return never carries an exact small count.

**Residual**: an observer who controls all but one node in a cell can still infer the last one. The k floor
counts distinct owners, so this needs at least 9 colluding owners in that cell.

#### AV-92: Coerced operator or subpoena against an aggregator or the directory

**Attack**: compel a seat to hand over what it holds, or compel the directory.

**Mitigation**:
- A composite reveals nothing about any one node beyond the k-floored, rounded cells.
- A seat holds returns for one period, then MUST delete them. A seat compelled at the right moment yields
  the current period's returns: bucketed counts, by scope **class**, never by cohort, room or item.
- The directory holds no census data at all. Composites carry per-period tokens, never node ids.

**Residual (v1)**: the seat sees which node sent which return during the period. Section 3.3 states the
boundary, and v2's blinded tokens remove it.

#### AV-93: Global passive adversary correlating return timing with traffic

**Attack**: watch when a node sends its return and how big it is, and correlate that with other traffic.

**Mitigation**:
- **Fixed size**: every return is padded to one fixed size, the same for every node and period.
- **Fixed cadence**: one return per period at an offset derived from `H(return_token ‖ period)`, so the
  timing is uniform and carries no information from the node's activity.
- **On a shaped link**, the return replaces a cover frame and is invisible to the GPA.
- **On an unshaped link** (shaping is off by default), the GPA sees one fixed-size frame per period from
  every participating node. That reveals participation, which is everyone's, and nothing more.

#### AV-94: Withholding adversary shrinks a denominator

**Attack**: suppress returns (drop them in transit, or silence its own nodes) so a count, or a vote base
derived from the census, falls.

**Mitigation**:
- **The base ratchet.** A census-derived base may fall at most 10% per period, and never below its
  floor. The floor is the standing roster for communities at or below the small-community size (CC 4.5.13
  keeps its current rule there), and otherwise the larger of the roster's rooted-active members and 50% of
  the last stable composite. Modelled: silencing 30% of returns lowers the base by 30% and no further.
  Silencing 50% or 90% needs at least 7 periods to halve the base, in plain view as a sustained decline.
- **Q6 freeze.** A fall of more than a third in one period reads as a partition. The base and every
  narrowing relief freeze until two stable periods follow.
- **Absence forfeits, but cannot shrink the base below the floor.** CC 4.5.13's rule stands, and the floor
  is what silencing cannot reach.

#### AV-95: Poisoned aggregator

**Attack**: a seat publishes a composite that misstates its returns, drops some, or invents some.

**Mitigation**:
- **Only seats aggregate.** They are announced, accountable, and their number is public.
- **Readers check** the hybrid signature, the dominance gate over the signed `n_eff`, and that cells sum to
  the mass commitment.
- **Contributors check inclusion.** A node asks its seat for its token's Merkle path. A missing path is
  evidence against the seat.
- **Seats check each other.** Seat choice is `H(token ‖ period) mod seats`, so each seat should carry about
  1/seats of the returns. A seat whose share departs from that, period after period, is visible to every
  reader.

**What it does not bound**: a seat can invent returns from tokens it made up, up to the share it is expected
to carry. The cross-check against the directory's bucketed count of live announced nodes bounds this to the
rounding grid. v2's blind-issued tokens remove it, because a seat cannot mint a token it did not issue to a
node.

---

## 8. The anonymous tier

The census must never expose who uses or relays the tier.

- **No return carries onion use.** There is no field for routes built, onion packets sent, relayed or
  received, or onion bytes, and onion traffic is never a plane in Q5. Shaped links report link counts only.
  A shaped link's rate is constant by construction, so its bytes say nothing anyway.
- **Relay counts are classes.** Relay standing, hop-key publication and opt-out are returned as counts per
  class (seat-like, ordinary) per coarse region, under the k floor.
- **A relay's own return reveals nothing new.** Being in a layer is decided by the public fold over public
  inputs (the announced row, the hop key, the opt-out). Counting relays therefore publishes nothing a reader
  could not compute from the deal. What a relay carries is never returned. Counting onion **users** must
  not happen, in any form.
- **Liveness stays local.** The per-node liveness fold never enters a return. Only its availability verdict
  is shown, to the node's own user.
- **The client's answer reads the composite.** The onion availability answer and the "your set is small"
  copy read the census relay composite and the node's own local liveness, never another node's return.

---

## 9. Voting

CC 4.5.13 counts a governance change against "the standing roster at or below the small-community size and
the expected-active count above it". Nothing supplies the expected-active count today. The census is its
source, under four constraints.

1. **A community's expected-active count is a member-only composite.**
   - Each member's period return carries one extra cell for each community it belongs to: the bit "active
     this period". The cell is sealed under the community's MLS epoch key and rides the community's
     member-only witness chain, not the federation census.
   - Expected-active means a member who returned active in at least one of the last 4 periods, counted per
     owner.
   - Every member folds the same returns with the same deterministic algorithm id, so the count is byte-equal
     at every member. An outsider never holds the sealed cells and cannot compute or see it.
2. **A tally is the same instrument.** Ballots are a member-only composite folded the same way, counted per
   owner. The dominance gate refuses any tally where one owner supplies more than half the mass, so one
   source can never be the majority by itself.
3. **The base cannot be withheld below its floor.** The base is the expected-active count under AV-94's
   ratchet. The floor is the standing roster at or below the small-community size, and above it the larger of
   the roster's rooted-active members and 50% of the last stable count. Silencing members lowers the base by
   at most 10% per period, and a sudden fall freezes it.
4. **A ballot's occurrence stays invisible.** Every member's community cell is emitted every period, at the
   fixed size, whether or not a ballot is open. An open ballot fills a field that is otherwise padding. An
   outsider sees the same sealed, fixed-size cell on the same cadence either way. Returns are counts on the
   cadence, never events.

**What persist's `reverse_quorum` and `verify_coord` ballot surfaces need from the census**:

- a reader for a community's expected-active count at a given period, with the period's ratchet floor;
- the deterministic fold's algorithm id and the period number, so a `MergeBallot` binds the base it was
  counted against;
- the member-only cell's wire shape, sealed under the community epoch key, with the active bit, the ballot
  field and the padding to fixed size;
- the dominance-gate verdict over owners for both the base and the tally.

The census does not replace persist's quorum math. It supplies the one input that is missing, the base, and
carries the tally in a shape outsiders cannot see.
