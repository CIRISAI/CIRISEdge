# Range fingerprints: anti-entropy that costs nothing when two peers agree

Status: DESIGN, for the 45.1.x LTS line (Eric's ruling: build it now, not as a
later major). No code is changed by this document. Every claim about existing
behaviour cites the file and line at `origin/main` b84073e (45.1.9). Evidence
marks follow `FSD/EVENT_PATH_MODEL.md`: **[read]** is read in the code or the
text, **[inf]** is inferred from numbers, **[new]** is proposed here.

## 0. The recommendation in one page

- **Protocol.** Range-based set reconciliation in the Negentropy style: an
  additive fingerprint (sum of the 32-byte envelope hashes mod 2^256, plus the
  count, hashed and truncated to 16 bytes) over **hash-prefix ranges** of each
  plane, fan-out 16. The order is the envelope hash itself, not a cursor
  (§2.1). The **sender** sends fingerprints of exactly the rows it would offer
  today. The **receiver** answers each range `match`, `split` or `list`, and
  never sends a fingerprint, a count or an id of its own (§2.3). Ids are listed
  only for small or mostly-missing ranges, in the existing `refs` field, so
  `Diff`, `want`, `Deliver`, salvage and the serve gate are unchanged.
- **Wire.** Two optional, flattened `rf` members, one on `Summary` and one on
  `Diff`, following the #937 `status` and #1014 `withheld` precedent. No
  `WIRE_PROTOCOL_VERSION` change, no new verb (§2.5).
- **Where the fingerprints come from.** In memory, in edge, with no persist
  API: the sender from the key-plane memo's listing and the holdings index's
  route records, rebuilt once per memo generation; the receiver from the
  holdings index, tagged by session plane. An in-sync round costs one root
  comparison and **zero store reads** (§3).
- **The audience.** Both sides fingerprint only rows the other side is in the
  audience of. The sender's set is its offer to that peer, exactly. The
  receiver's set is what it would not want, restricted to what it may serve
  that sender. Safety (a match never hides a row the receiver would want) holds
  for any receiver set inside "would not want"; the restriction is what makes
  the protocol leak nothing a listing would not (§2.4, §4).
- **Scope for 45.1.x.** The five bootstrap planes: `Key`,
  `IdentityOccurrence`, `TransportDestination`, `Revocation`,
  `IdentityOccurrenceRevocation`. They carry 201.1M of the canonical's 201.7M
  listed refs in 42 h (§1.4). The `Attestation` plane keeps its watermark and
  re-sweep in 45.1.x; its range fingerprints are phase 2 and need one CC answer
  first (§4.4, §7).
- **Compatibility.** Capability is learned in band from the `rf` members. A
  peer that never answers one stays on the legacy listing, paced by
  **`BridgeConfig::legacy_resweep_every` (env `CIRIS_EDGE_LEGACY_RESWEEP_SECS`,
  default 3600 s, `0` = unpaced)** (§6).
- **Effect on canonical-1.** About 30.7 GB of the 42 h's 63.8 GB tx is Summary
  JSON on these planes. In sync, the same rounds cost about 62 MB (ceiling
  0.5 GB) (§1.4, §10.2).

## 1. The problem, from the code

### 1.1 What each plane lists today

| Plane | Listing source | Watermark? | Per peer? | Hash on the wire | `seq` |
|---|---|---|---|---|---|
| `Key` | `list_key_record_rows(None)` over the publish set, `src/replication/bridge.rs:6906` → `key_plane_listing`, `bridge.rs:8193` | **no**: the whole publish set every Summary | no: the `_ =>` arm of `list_envelope_refs_for_peer`, `bridge.rs:5296` | `content_hash_of(row)` = persist `attestation_wire_hash`, `bridge.rs:16007-16012` | `asserted_at` ms, `bridge.rs:8159` |
| `IdentityOccurrence` | `list_occurrence_rows(Some(subjects))`, `bridge.rs:8520` | **no** | yes: the #682 withheld subjects removed, `bridge.rs:8507-8516` | as `Key` | as `Key` |
| `TransportDestination` | `list_transport_destinations_page`, `bridge.rs:8584` (a `sweep_paged` over `list_signed_transport_destinations_since`) | yes: head + rolling re-sweep | yes (#682), `bridge.rs:8522-8524` | sha256 of the `SignedTransportDestination` JSON | epoch, else `asserted_at` |
| `Revocation`, `IdentityOccurrenceRevocation` | `list_revocation_rows` / `list_occurrence_withdrawal_rows`, `bridge.rs:13907`, `13925`, over `Projection::Global` | no | no | as `Key` | as `Key` |
| `Attestation` | `list_attestations`, `bridge.rs:12421`: required read, head page, re-sweep page | yes | yes, per row (consent, trace, audience, quarantine, walk class) | content hash of the bare row | |

Every hash is the persist index's own content hash, so both sides compute it
identically: the holdings index already relies on that ("The hash is
`sha256(serde_json::to_vec(row))` … proved by test per envelope kind",
`src/replication/holdings_index.rs` module docs) **[read]**. The row hashed
includes `scrub_signature_classical` and `scrub_signature_pqc`
(persist `src/federation/types.rs:1640-1644`) **[read]**, which matters for
§2.8.

### 1.2 Two ways a plane is re-listed when nothing changed

1. **The key planes have no watermark at all.** `Key` and `IdentityOccurrence`
   list the whole publish set on every Summary (`bridge.rs:6895-6907`). The
   #930/#971 memo and listing cache made that free in store reads
   (`key_plane_memo.rs` module docs, `bridge.rs:8199-8222`), not on the wire.
2. **The watermarked planes re-sweep forever.** Once `caught_up`, every round's
   spare page budget is a backfill page (`SweepCursors::after_head`,
   `bridge.rs:2017-2050`), and `after_backfill` wraps to the beginning on a
   short page (`bridge.rs:2135-2148`). `DEFAULT_SWEEP_PAGE_ROWS` = 1024
   (`bridge.rs:1139`) sets the period; its own docs call it the "ROLLING
   RE-SWEEP period" (`bridge.rs:1120-1128`). A peer with no walk reads a page of
   history every `DEFAULT_HISTORY_PAGE_EVERY` = 1 min (`bridge.rs:1094`) and that
   wraps too (`history_read`, `bridge.rs:2281`).

**Both roles list.** A responder answers a round-opening Summary with its own
full Summary (`src/replication/session.rs:921-931`). So every peer's round
toward the canonical costs the canonical one listing, whatever the canonical's
own cadence is.

### 1.3 Why the re-listing exists: what it does that must survive

The re-sweep is a door-stop, not waste by design (`PlaneWatermark` docs,
`bridge.rs:1658-1700`). It covers, and range fingerprints must cover:

1. a row the peer refused **transiently** and will admit later (AV-45
   `retry_after_roster`; the receiver never reports it, `bridge.rs:1660-1667`);
2. a row the peer wanted that did not fit the round's Deliver budget
   (`MAX_DELIVER_ENVELOPE_BYTES` 512 KiB, `session.rs:94`, remainder "carried by
   the next round's re-diff", `session.rs:81`);
3. a row lost with a dropped frame;
4. the ageing of `known_hashes` on conferred servers, which is refreshed only
   by re-advertisement (`src/replication/known_hashes.rs` "Ageing");
5. the removal receipt ledger's protocol-native acks, booked from a peer's
   Summary (`coordinator.rs:1110`, `observability.rs:4722`);
6. the proactive push's delta basis, the peer's last Summary
   (`session.rs:492-496`).

### 1.4 The canonical's 42 h, in bytes

A ref on the wire is JSON (`protocol.rs:30-37`), and `[u8; 32]` serialises as
an array of 32 decimal numbers, so **[inf]**:

```text
ref  = {"envelope_hash":[ 32 numbers ],"seq":N},
     = 18 + (32 x 2.57 digits + 31 commas = 113) + 8 + 13 (ms seq) + 2  ~ 154 B
TD ref (epoch seq, 1-3 digits)                                         ~ 142 B
want = one hash in a Diff's list                                       ~ 114 B
```

| Counter (canonical-1, 45.1.7, 42 h) | Count | App-layer bytes |
|---|---|---|
| `summary_refs_out` key | 102.2M | 15.7 GB |
| `summary_refs_out` identity_occurrence | 79.3M | 12.2 GB |
| `summary_refs_out` transport_destination | 19.6M | 2.8 GB |
| `summary_refs_out` all other planes | 0.6M | 0.1 GB |
| **Summary tx subtotal** | 201.7M | **30.8 GB** of 63.8 GB tx |
| `deliver_bytes_out` | | 9.05 GB |
| `summary_refs_in` | 22.65M | 3.5 GB rx |
| `diff_want_in` | 26.0M | 3.0 GB rx |

`summary_refs_out` counts refs, not bytes (`coordinator.rs:1457-1465`); the
byte figures are the derivation above. The 24 GB of tx not explained by
Summaries and Deliver bodies is framing, the E1 seal, resource control,
retransmits and announces: CIRISEdge#1025 (`feat/1025-transport-bytes`,
`src/wire_bytes.rs`) is the ledger that will split it.

102.2M / 33k ≈ 3,100 full key listings in 42 h, ≈ 74 an hour over about 17
concurrent links, ≈ one per link every 14 minutes, and ≈ 23 per identity over
135 identities **[inf]**. At the 30 s cadence that is far fewer than one per
round, so most Key rounds toward the canonical do not end in a full listing
being sent; why is not established here (a 5 MB Summary on a contact-lane link,
§5.10, is a candidate). Range fingerprints remove the listing either way.

`diff_want_in` / `deliver_rows_out` = 26.0M / 0.68M ≈ 38 **[read]** counters,
**[inf]** cause: a peer that lacks thousands of rows wants all of them on every
listing and receives one 512 KiB Deliver's worth, so the same hashes are wanted
again and again. §5.4 addresses it.

## 2. The protocol

### 2.1 The order: the envelope hash

Range reconciliation needs an order both sides agree on.

- `(admitted_at, id)`, the cursor order every `list_*_since` uses, is
  **node-local**: persist documents `admitted_at` as "THIS node's serve position
  on the row (node-local, never hashed)" (persist `types.rs:4335-4339`). Two
  nodes put the same row at different positions. Unusable.
- `(asserted_at, hash)`, Negentropy's own order, is shared, but `asserted_at`
  is chosen by the signer: skewed clocks, back-dated rows and ties all land in
  one range, and new rows do not cluster at the end anyway once the head
  listing (§5.1) carries them.
- **The envelope hash** is shared, uniform, needs no second key, and makes a
  fixed hex-prefix tree balanced by construction. persist already scans its
  wire index in this order cheaply: `list_wire_hashes_since(kind,
  after_content_hash, limit)`, an index-only page (persist
  `src/store/sqlite.rs:6266`, CIRISPersist#780) **[read]**, which an audit can
  use (§3.5).

**[new] Ranges are hex prefixes of the envelope hash**, fan-out 16: the root
`""`, then `"0"`…`"f"`, then `"00"`…`"ff"`, and so on. A node is named by its
prefix string.

### 2.2 The fingerprint: Negentropy-style sums, not a Merkle tree

| | Additive (Negentropy, NIP-77) | Merkle prefix tree |
|---|---|---|
| Union of disjoint sets | sum of their fingerprints | recompute |
| Remove one row (withdrawal, per-peer exception) | subtract its hash | recompute the leaf and its path |
| Per-peer projection = shared set ± a few rows | O(exceptions) from the shared tree | a per-peer tree, or per-peer leaf recomputation |
| Cost in sync | one 16 B root | one root |
| Cost with k sparse differences | O(k · depth · 16) node fingerprints + O(k · leaf) refs | the same |
| Rounds | depth + 1 | depth + 1 |
| Collision resistance | generalized birthday (Wagner) is the known weakness of a plain sum; mitigated below | cryptographic |
| Prior art | Negentropy, deployed in Nostr relays | many |

**Pick the additive fingerprint.** The decisive row is the per-peer one:
`IdentityOccurrence` and `TransportDestination` are one shared set minus a
peer's #682 withheld subjects (`bridge.rs:8507-8516`), and the phase-2
Attestation projection is a union of audience classes (§4.4). Both are sums and
differences of shared sums; with a Merkle tree each would be a per-peer tree.

```text
v(x)        = x read as a little-endian 256-bit integer     x = envelope hash
fp(S, p)    = trunc16( SHA-256( "ciris-rf-v1" || plane || p ||
                                LE256( sum v(x) mod 2^256 ) || u32be(|S|) ) )
```

The outer hash binds the plane and the prefix, so a fingerprint of one range
cannot stand for another. SHA-256 is the hash every envelope hash already is.
The wire names the construction (`"a":1`), so a stronger one (§2.8) is a new
value, not a new message.

### 2.3 Who says what: the sender fingerprints, the receiver only answers

Each direction of a pair is reconciled separately, exactly as today each side
offers its own Summary.

- The **sender** A sends nodes `(prefix, count, fp)` over its set S_A (§2.4),
  plus ids (`refs`) for ranges it lists.
- The **receiver** B computes `fp(T_B, prefix)` for each node and answers per
  node: `match` (equal), `split` (differ: send me the 16 children), or `list`
  (differ, and B holds at most half of A's count: send me the ids). B never
  sends a fingerprint, a count or an id of its own.
- A lists a node outright, without being asked, when its own count is at most
  `RF_LEAF_ROWS` = 16 **[new]**.

What B reveals per node is one of three answers about its own set; what A
reveals is the fingerprint of rows it would list to B anyway. Neither ever
reveals more than a legacy listing does (§2.4).

### 2.4 The two sets, and the safety rule

- **S_A** = exactly the refs A's legacy listing would offer B this round
  (§3.1). Not a superset: a superset would let B test whether A holds a row B
  may not be offered.
- **T_B** = `settled_B ∩ servable_B→A − excluded_B(A)`, where
  - `settled_B` = what B **would not want** if offered: the holdings-index
    hashes of the plane's family (`holdings_index.rs`), the #1252
    held-equivalent refs (`wire_ref.rs:128`), the refusals still in backoff
    (`retry_suppressed`, `bridge.rs:5891`, #544), and on a `HashFirst` plane the
    `known_hashes` (#552);
  - `servable_B→A` = rows B's own serve gate would serve A
    (`fetch_envelope_bytes_for_peer`, `bridge.rs:5705`): every row on the
    public key planes, and on `IdentityOccurrence` / `TransportDestination`
    every row except an unannounced node's to a peer that is not its owner's
    (#682, `identity_row_withholds`, `bridge.rs:14947`);
  - `excluded_B(A)` = rows B has seen A not offer (§3.2), learned only from A's
    own listings.

**Safety.** If `fp(S_A, p) = fp(T_B, p)` then, up to a fingerprint collision,
`S_A ∩ p = T_B ∩ p ⊆ settled_B`: B would not have wanted any row A would have
listed there. So a match never suppresses a row today's listing would have
delivered. This needs only `T_B ⊆ settled_B`; every other choice in T_B (the
plane tags, the exclusions, a hash with no known family) moves efficiency,
never correctness. That is deliberate: every rule in §3.2 that cannot be exact
leans toward a smaller T_B, which costs a listing, not a row.

**Disclosure.** Everything A fingerprints, A would list to B. Everything B's
answer depends on, B may serve A. A sender that crafts fingerprints to probe
B learns, at most, whether B holds exactly some set of rows A is in the audience
of. For the bootstrap planes those rows are federation-public (the holder
directory of the Commons, CC 5.2's table) or rows B would serve A. §7 asks CC
to confirm this reading before the Attestation plane (§4.4).

### 2.5 Wire shape

Additive members on the two existing messages (`protocol.rs:651`,
`protocol.rs:690`), flattened and skipped when absent, as `status`
(`protocol.rs:668`) and `withheld` (`protocol.rs:701`) are. A pre-RF peer
ignores them: no `deny_unknown_fields` on this path (`protocol.rs:662-667`,
pinned by `summary_status_is_flat_optional_and_tolerant_937`).

```text
Summary (RF sender, in sync):
{"type":"summary","kind":"identity_occurrence","refs":[],
 "rf":{"v":1,"a":1,"n":[["",33012,"<32 hex>"]]}}                        ~ 121 B

Summary (after a split of "3f"): one packed record per split parent
 "rf":{"v":1,"a":1,"c":[["3f",[c0..c15],"<16 x 32 hex>"]]}               ~ 700 B / split

Diff (RF receiver):
{"type":"diff","kind":"identity_occurrence","want":[],
 "rf":{"v":1,"m":[""],"s":[],"l":[]}}                                    ~ 75 B
```

- `refs` carries the head rows (§5.1) and the listed ranges' ids, as
  `EnvelopeRef` exactly, so `local_want`, the Diff, the Fetch, the Deliver and
  the #1020 salvage of a late reply's refs (`coordinator.rs:654-718`) are
  untouched.
- `rf.m` / `rf.s` / `rf.l` name the prefixes answered `match` / `split` /
  `list`. `rf.u: true` is "unable this round" (§3.4) and makes the sender send
  the legacy listing next round.
- An RF marker with no nodes (`"rf":{"v":1}`) on a legacy Summary or Diff says
  "I answer RF" (§6.1).

### 2.6 The round: one step of the descent per round, advanced by the answer

**[new] `RangeFrontier`**, per `(peer, plane)`, pure state like
`SweepCursors` (`bridge.rs:1963`): no directory, no clock, no I/O.

- The frontier is the set of nodes to send this round: the root when empty,
  else the children of last answers' `split`s and the ranges answered `list`.
- **It moves only on an answer.** A Summary that is lost, timed out or shed in
  the reply lane leaves the frontier where it was, and the next round sends the
  same nodes. Listing is not delivery (#1020), and here nothing ever moved on
  the listing, so the rewind machinery (`round_ended`, `rewind_to`,
  `listing_delivered`, `bridge.rs:2063-2124`) has nothing to undo on an RF
  plane.
- Answers are idempotent set operations keyed by prefix: `split p` on a node
  already split is a no-op, and a late or duplicate answer costs at most one
  extra node. The initiator's and the responder's answers fold into the same
  frontier, as the two roles share one `SweepCursors` key today
  (`bridge.rs:2059-2062`).
- A listed range stays on the frontier as a node until it answers `match`. That
  is what carries deferred Deliver remainders, transient refusals and lost
  frames (§1.3 items 1-3).
- Bounds: at most `RF_MAX_SPLITS_PER_SUMMARY` = 16 packed splits (~11 KB) and at
  most the effective page (`sweep_page_rows`, the host's page lever) of listed
  refs per Summary; the rest waits a round. LRU-capped like
  `MAX_TRACKED_SWEEP_CURSORS` (`bridge.rs:1986`); an evicted frontier restarts
  at the root, which costs one descent, never a row.

One RTT per round, exactly as today, so the Session state machine and the #634
round shape (`session.rs:458-470`) do not change. Descending several levels in
one round is a later option (§11).

### 2.7 Costs

For a plane of n rows, fan-out 16, leaf threshold 16:

| Case | Bytes per round per direction | Rounds | Store reads |
|---|---|---|---|
| In sync | ~121 B Summary + ~75 B Diff | 1 | 0 (§3.4) |
| One missing row, n = 33k | ~2.1 KB of splits over 3 levels + ~1.2 KB leaf listing ≈ 3.3 KB in all | 4 (root, 16, 256, leaf) | 0 |
| k sparse missing rows | ≈ k × 3.3 KB less shared upper levels | 4 | 0 |
| First contact or k ≥ n/2 | B answers `list` at the root: the plane is listed a page per round, **once** | n / page | as today |
| Today, any case | n × 154 B (Key: 33k → 5.1 MB) | 1 | 0 to n |

The crossover where RF bytes reach a listing's is about k ≈ 1,500 sparse
differences on a 33k plane; B's `list` rule (half missing) caps RF at about
twice the minimum there.

### 2.8 Lying peers and collisions

- **B lies `match`.** B loses rows it would have been offered. That is B's loss
  only.
- **B lies `split`/`list` forever.** A lists, bounded by the page per round:
  never more than today's listing.
- **A lies.** A can make B answer `split`, then must list to make progress, and
  every listed row is gated by the serve gate and every delivered row by
  admission. A cannot inject a row or learn anything §2.4 does not allow.
- **A third party forges a collision.** A plain modular sum is open to
  Wagner's generalized-birthday attack: with many chosen elements, a k-sum
  equal to a target is cheap **in hash evaluations**. Here each element is the
  hash of an admitted row whose bytes include its hybrid signatures (§1.1), so
  each candidate costs an ML-DSA-65 signature, not a hash. A useful attack
  needs on the order of 2^31 signed candidates and 2^16 admitted rows from
  attacker keys, placed in one prefix range of A and kept off B (or the
  reverse) against both sides' anti-entropy, past `PeerBurst` and admission,
  with counts balanced. The prize is one delayed backstop for one row toward
  one peer; the head listing, the kicks and every Pull still carry it.
  **Recommendation: ship the sum (`"a":1`)** and keep `"a":2` reserved for an
  elliptic-curve multiset hash over ristretto255 (collision resistance rests on
  discrete log, still additive and incremental, at the cost of one hash-to-group
  per row at insert; `curve25519-dalek` is already in the tree through
  `ed25519-dalek`). Decision 1 in §11.

## 3. Where fingerprints come from

### 3.1 The sender's trees

**[new] `RangeTree`**, per session plane: 4,096 leaf buckets (three hex digits)
each holding a 256-bit sum and a count, and the plane's hashes sorted for the
listing of a range. A node at depth ≤ 3 sums buckets; a deeper node scans its
bucket (about 8 rows at 33k).

| Plane | Built from | Rebuilt when |
|---|---|---|
| `Key`, `Revocation`, `IdentityOccurrenceRevocation` (peer-invariant) | the plane's complete listing from `key_plane_listing` (`bridge.rs:8193`): the listing cache when it hits (`bridge.rs:8204-8222`), else the listing just built | the memo's generation moves (`key_plane_memo.rs:575`); "generation moves on every change to what the memo would answer" (`key_plane_memo.rs:357-362`) |
| `IdentityOccurrence` | the shared listing over the publish set, minus, per peer, the refs of its #682 withheld subjects (memo lookups) | as above; the per-peer patch is cached against `(generation, withheld set)` |
| `TransportDestination` | the holdings index's route records (`holdings_index.rs:325`, which already keep each route's subject "so the stranger view … can later filter by owner"), filtered by the listing's predicate: subject in the publish set, or `relayable_signed_route` (`bridge.rs:8572`), stored as one bit per record at feed time; minus the peer's #682 subjects | each route feed delta |

**The tree is the listing.** The set the tree sums is the set
`list_envelope_refs_for_peer` would have returned: a subject the memo's read
budget left unread (`KEY_PLANE_READ_BUDGET` 256, `key_plane_memo.rs:296`) is
absent from both. So S_A equals today's offer by construction.

Rebuilding is one pass over the listing (33k additions, well under a
millisecond) and happens at most once per memo generation, which moves at most
once per feed probe (`FEED_PROBE_SPACING` 5 s, `store_feed.rs:86`) plus the
TTL epoch (`MEMO_TTL` 10 min, `key_plane_memo.rs:97`). Incremental add and
subtract is a later optimisation.

### 3.2 The receiver's settled sets

The receiver needs `settled_B` per **session plane**, but the holdings index
covers the whole Attestation index, shared by six session planes
(`holdings_index.rs` "What the set is"). **[new]** The index records each hash's
session plane when the feed or the warm-up names its row (the family of a
key-plane row is `key_plane_rows::key_plane_row_of_bytes`, as
`fetch_envelope_bytes` already uses at `bridge.rs:5230-5233`). An entry seeded
by hash alone (the retired-carrier class, `holdings_index.rs` "Which rows a
delta adds") has no plane and is in no T_B. A hash with no known plane that A
lists on plane k and B holds is tagged k when B sees the listing.

The corrections are applied per comparison over small sets:

- **plus** the refusals in backoff. A refused row is in T_B for exactly its
  window, so a match keeps it unasked, as `on_summary`'s
  `want.retain(!retry_suppressed)` does today (`session.rs:844-852`). When the
  window ends it leaves T_B, the range differs, and A lists it: the row is
  re-asked about a descent after its window, instead of when the re-sweep
  happens past it (`FSD/EVENT_PATH_MODEL.md` §1.2: "The row waits for an offer,
  not for its window", up to 25 min at 52k rows).
- **plus** the held-equivalent refs (#1252), which `holdings_want` already
  filters out of a want (`bridge.rs:5389`).
- **plus**, on a `HashFirst` plane, the known hashes. They then age out on
  their eviction cutoff, the range differs, and they are re-learned with their
  holder: the refresh the re-sweep gave them (§1.3 item 4), on the cutoff's
  period.
- **minus** the rows B may not serve A (§2.4).
- **minus `excluded_B(A)`**: when A lists a range, every row of `T_B` in that
  range that A did not list is a row A does not offer B; B records it and drops
  it from T_B toward A. It leaves the set when A lists it. Capped per
  `(peer, plane)` (1,024) and node-wide (65,536, ~2 MiB); an evicted exclusion
  costs one more listing of its range. Without it, a row B holds that A
  withholds (a subject-Pulled row, CC 5.2 "the rest waits on a pull") would
  make one range differ forever.

### 3.3 Withdrawals, revocations, replacements

A row leaving a set is a subtraction: no tombstone of the tree's own.

- **A revocation or withdrawal is a new row** on its plane (`key:revocation:v1`,
  a `withdraws`), added to the sender's tree when the memo's feed sees it; the
  revoked key's own `key:record:v1` row leaves the Key listing when the memo's
  dirt drops it (`key_plane_memo.rs` "When an answer goes stale"), and the next
  rebuild subtracts it.
- **A replacement by record** (a PQC completion, a re-seal, a superseding
  route) removes the old hash and adds the new one, as the holdings index does
  (`holdings_index.rs` "Replacement by record"). Two hashes of difference until
  both sides have the new row.
- **A purge or erasure** reaches the holdings index only at its audit
  (`DEFAULT_AUDIT_EVERY` 1 min, `holdings_index.rs:222`); until then B keeps
  the hash in `settled_B`. That is the right direction: a match over a purged
  row means nobody offers it, and "erasure requires that this node NOT
  re-acquire the row" (`holdings_index.rs` "Removes are skipped on purpose").

### 3.4 Bounds

| | Memory | CPU in sync | Store reads in sync |
|---|---|---|---|
| Sender trees, 5 planes | 4,096 × 36 B buckets + n × 32 B sorted hashes per plane: about 4 MiB at canonical sizes | none: the root is cached per `(peer, plane, generation)` | none: the listing cache hits |
| Sender per peer | a frontier (usually the root) and a head position: under 1 KiB per `(peer, plane)`, 2 KiB at the split cap | none | none |
| Receiver | per plane 4,096 buckets + the sorted hashes: about 4 MiB beside the holdings index | one root sum plus the corrections in the root's range | none: the index answers; a clean feed is not probed within `FEED_PROBE_SPACING` |
| Exclusions | at most 65,536 × 32 B ≈ 2 MiB | | |

**Fail to the old behaviour, never to a wrong answer.** If the receiver's plane
is not `Ready` (holdings index unbooted, booting or suspect,
`holdings_index.rs` "Failing to the old behaviour"), it answers `"u": true`
and the sender lists that peer the legacy way next round. If the sender's
listing failed or its tree is not built, it sends a legacy Summary.

### 3.5 Why not a persist API

A persist range fingerprint would sum the raw wire index. The sender's set is
not the raw index: it is the publish set (`self_own_subjects`,
`bridge.rs:7994`, the host's per-kind answer) minus #682 per peer, an edge-side
projection. So the sender's tree must be edge's either way, and the receiver's
already has the index in memory. persist's hash-ordered index page
(`list_wire_hashes_since`, §2.1) is enough to audit a tree against the store if
we want one; it is no prerequisite. An optional persist ask, not a dependency:
per-kind bucket sums kept transactionally beside `signed_wire_index`, which
would let the receiver's audit read 4,096 sums instead of draining the index.

## 4. The audience

### 4.1 The rule

CC 5.2: "A row is served to a node in its audience and to no other", and for
`self` and `family` content an outsider learns "nothing, not even that the
content exists" (`~/CIRISConstitution/constitution/part_5_transport_substrate.md:103-111`).
Range fingerprints add no new disclosure if both sides fingerprint only inside
the other's audience (§2.4). Per side:

- the sender, its exact offer, so nothing beyond what it lists;
- the receiver, its would-not-want set inside what it would serve the sender.

### 4.2 The bootstrap planes (45.1.x)

- `Key`, `Revocation`, `IdentityOccurrenceRevocation`: peer-invariant listings
  over public rows (the `Key` plane is "a #402 bootstrap plane, served public",
  `bridge.rs:5230-5233`; the revocation planes enumerate `Projection::Global`).
  One shared tree; no per-peer exceptions.
- `IdentityOccurrence`, `TransportDestination`: one shared tree minus the
  peer's #682 subjects: "an unannounced node's occurrence and route go only to
  its owner's own nodes" (`bridge.rs:5282-5285`). The exception set is
  `identity_rows_withheld_from` (`bridge.rs:15182`), the same function the
  listing applies, so the sender's fingerprint excludes exactly what its
  listing would.
- The receiver applies the same rule in the other direction: B leaves out of
  T_B an unannounced node's row unless A is one of that node's owner's nodes.

### 4.3 What the per-peer work costs

`identity_rows_withheld_from` walks the whole subject set per call, one
`identity_row_withholds` each (`bridge.rs:15182-15194`). Today that runs every
listing. Under range fingerprints its answer is cached against
`(peer, memo generation, owner-binding generation)`, so an idle round does not
run it.

### 4.4 The Attestation plane (phase 2, not 45.1.x)

The Attestation offer is per row and live: the namespace projection, the
consent send set (re-resolved every round, the 10 s memo of #400/#1022,
`CONSENT_SEND_SET_MEMO_TTL`, `bridge.rs:3430`), the trace consent gate, the
audience gate, quarantine, and three walk classes (`UnaskedOffer`,
`bridge.rs:2419-2430`; `no_walk`, `bridge.rs:12562-12568`). Recomputing that
per peer per round would cost what today's walk costs, so phase 2 decomposes it:

- **classes**: each row carries a label computable from the row alone (the
  projection from its dimension, `cohort_scope` and type; the group it is
  placed in). A peer's offer is a union of classes (the commons; each group it
  is in; rows about it), and its fingerprint is the sum of class trees;
- **volatile rows**: a row whose verdict for this peer also depends on live
  state (a consent grant, a trace consent, an author's quarantine, the trace
  pause) is never fingerprinted. Its bucket is always listed, through today's
  gates. Exact and leak-free, at the price of listing those buckets;
- the class trees are invalidated by the inputs the advertise already watches
  (`check_advertise_inputs`, `bridge.rs:4386`; `AdvertiseFingerprint`,
  `bridge.rs:1796`) and never outlive the send set's TTL.

The Attestation plane is 0.6M of the 201.7M listed refs (§1.4). It stays on
the watermark in 45.1.x, where §6.3's pacing is not applied to RF-capable
peers.

## 5. Interaction with what exists

### 5.1 New rows still move in the next round

- **Watermarked planes** (`TransportDestination`): the head page stays as it
  is (`sweep_head`, `bridge.rs:4444`; `after_head`), in `refs`, beside the
  nodes. Only the backfill page is replaced by the frontier. The head
  position's #1020 rewind stays for the head.
- **Key planes** (no watermark today): **[new]** a per-plane ring of the last
  4,096 hashes added to the tree, each with a local sequence number; the
  Summary's `refs` carries the ring entries past the peer's position, and the
  position moves when the round's answer arrives. A peer whose position fell
  off the ring gets no head rows that round; the descent finds them.

A propagation kick (`scheduler.rs:466`, `Propagate`) therefore still delivers a
new key or revocation in one round, as the full listing does now.

### 5.2 Subject Pulls and #881's required-set Pull

A Pull is answered by a plain Summary of the subject's refs
(`summary.rs` `subject_pull_answer`; `protocol.rs` "A PullMessage"), and its
answer is byte-identical in shape to an anti-entropy Summary (`session.rs`
comment on the Pull exemption). So:

- a Pull's answer never carries `rf` and is never read as a downgrade (§6.1);
- the bundle path (`BUNDLE_PULL_PLANES`, `runtime.rs:1143`; one ordinary round
  on `BUNDLE_ROUND_PLANES` = `Revocation`, `runtime.rs:1170`) is unchanged. Its
  Revocation round gets range fingerprints like any other.

### 5.3 The Diff, `withheld`, refusals

`want` is computed from `refs` exactly as today (`session.rs:828`). Leaf
listings are small, so #1014's `withheld` (offers ≤ `MAX_WITHHELD` = 64,
`protocol.rs:708`) is named on nearly every RF round that lists, which is what
the wrap courier needs. The refusal backoff (#544) is in T_B (§3.2), so a
refused row is not even listed during its window.

### 5.4 Deliver, budget deferral, and the repeated wants

A listed range stays on the frontier until it answers `match` (§2.6), so a
Deliver remainder is listed again next round inside that range only. A peer
that lacks 30k rows then wants at most one page per round instead of all 30k on
every listing: `diff_want_in` falls to the rows actually listed. If the
remaining want-to-deliver gap still dominates, **want carry-over** (the sender
keeps the peer's last unanswered wants, bounded and short-lived, and delivers
from them before listing again) is the next step; it is a separate change with
its own counter (§11, decision 7).

### 5.5 #1020: salvage and rewind

- A late reply's refs are still salvaged (`salvage_late_reply`,
  `coordinator.rs:654`) and merged into the next responder Summary
  (`merge_salvaged`, `coordinator.rs:721`). A late reply's `rf` answers are
  stale and dropped: the frontier re-sends.
- The listing marks and rewinds (`listing_mark`, `coordinator.rs:1171`;
  `rewind_to`, `bridge.rs:2100`) remain for head listings and for legacy peers.
  RF state needs none (§2.6).

### 5.6 The proactive push and the "peer lacks nothing" count

The initiator's push skips refs the peer's last Summary showed it holds
(`session.rs:492-496`). An RF Summary's `refs` is not the peer's holdings, so
**[new]** the push consults the last RF answer to our own offer instead: a root
`match` means the peer holds everything we would push. `peer_lacks_nothing`
(`coordinator.rs:298`) counts root matches as it counts empty Diffs.

### 5.7 The removal receipt ledger (#441)

An ack is booked today when a peer's Summary lists a removal row
(`coordinator.rs:1110-1120`). Under RF a `match` over range p proves the peer
holds every removal row of S_A in p, so the sender books those, once per
`(peer, plane, generation)`. That is a stronger ack than a listing: a listing
says the peer's offer contains the row; a match says the peer holds all of
ours.

### 5.8 Known hashes on conferred servers (#552)

As §3.2: in T_B on a `HashFirst` plane, refreshed by re-listing after their
cutoff. The holder map's freshness becomes the eviction cutoff, not the
re-sweep wrap; `known_hashes.rs` "Eviction" already takes the cutoff from the
caller.

### 5.9 First contact

Two RF peers never full-list each other. A new peer answers `list` at the root
(it holds less than half), and A lists the plane a page per round, once; then
the frontier returns to the root and stays there. The bootstrap planes'
attribution path (#393/#402) sees the same rows in the same order of rounds as
on a legacy first walk.

### 5.10 The shaped and onion tiers

Every verb on the five bootstrap planes rides the shaped **contact** lane
(`CONTACT_ENVELOPE_KINDS`, `src/transport/link_shaping.rs:643-649`), and CC
5.4.3 shapes all maintenance traffic. A 5 MB Key Summary is about 3,700
1,400-byte frames on a rate-limited lane; an in-sync RF exchange is one frame
each way. Nothing in the shaping or onion wire changes; replication frames are
sealed application frames to both.

### 5.11 The staleness signal

A root `match` is `StalenessSignal::InSync` (`summary.rs:765`) with
evidence: today InSync is inferred from an empty want against a page, which
cannot see past the page.

## 6. Compatibility

### 6.1 Capability, in band

- **Where.** Not CTKX: it negotiates a link's shaping (`ShapingOffer`,
  `link_shaping.rs:1042`), runs before the seal, and is per link, while
  replication capability is per peer and must survive link churn. Not the v3
  preamble: its reserved `FLAGS` bits are refused when set
  (`wire_frame.rs:173`, `wire_frame.rs:343`), so an old peer would drop the
  frame. Not the bundle: it names seats, not versions. **In the `rf` members
  themselves**, which old peers ignore (§2.5).
- **Learning.** A node that answers RF puts the marker on its anti-entropy
  Summaries and Diffs. A node with the sender on sends RF Summaries to a peer
  whose marker it has seen.
- **Speculation.** To a peer with no known capability, the sender sends an RF
  Summary with the root. An old peer reads the head refs and diffs them,
  harmlessly; its Diff carries no `rf` answer, and the sender marks it legacy at
  once. The cost is one round of an incomplete offer to an old peer, against a
  full listing once per new pair otherwise (5 MB on the Key plane). Decision 3
  in §11.
- **Downgrade.** A Diff answering an RF Summary without an `rf` answer marks the
  peer legacy (a peer restarted onto an old build). A Pull's answer is never
  read this way (§5.2).
- **Kept in memory**, per peer, refreshed by every RF message, capped and
  LRU-evicted with the frontiers. A restart re-learns in one round.

### 6.2 The fleet as it is

Long-soak peers are deliberately old, among them edge v18.7.0 and Datum.
A pre-v26 peer speaks only v1/v2 legacy frames with no round id
(`wire_frame.rs:115`, `wire_frame.rs:199`); it is never sent an RF Summary at all, because it
never opens a v3 round. Every other old peer is detected as in §6.1.

### 6.3 Pacing the legacy re-listing

**[new] `BridgeConfig::legacy_resweep_every`, env
`CIRIS_EDGE_LEGACY_RESWEEP_SECS`, default 3600 s, `0` = unpaced (the 45.1.9
behaviour). Read once at runtime assembly; an unparseable value is ignored with
a WARN, as `ADVERTISE_SWEEP_PERMITS_ENV` is.** Toward a `(peer, plane)` marked
legacy, with range fingerprints on:

- **Watermarked planes:** a re-sweep cycle may start no sooner than this long
  after the previous cycle started. `after_head` returns no backfill page while
  `backfill` is at the beginning and the cycle is not due; the head page runs
  every round. The same bound applies to a no-walk peer's history pages, which
  wrap today too.
- **Key planes:** the full listing at most once per interval; in between, the
  head ring's rows (§5.1) only.
- The cycle start time joins `ResweepCycle` (`bridge.rs:1818`), injected as
  `now` so `SweepCursors` stays pure.

What an old peer loses: a transiently refused row or a lost Deliver remainder
is re-offered at the next cycle, at most an hour later, instead of within the
current wrap. That sits inside the refusal ladder's own tail (terminal at the
8th refusal, 20 min to hours, `FSD/EVENT_PATH_MODEL.md` §1.1-1.2). At the
measured rate of one full key listing per link every ~14 min (§1.4), the
default cuts a legacy peer's key-plane listings about 4×. Decision 4 in §11.

The knob is local "less of its own optional work", which CC 4.2.1.4 lets a
node do without any row; it is not a mesh-config key.

## 7. What the Constitution says, and what to ask it

**Findings [read]:**

- The replication wire is edge's: "The Summary / Diff / Fetch / Deliver
  four-message shape … constitute the v1 anti-entropy protocol. CEG defers to
  edge per #58" (`FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4).
  `manifests/WIRE_VOCABULARY.md` names `EdgeEnvelope` message types and no
  `CRPL` verb. Adding `rf` needs no CC wire change.
- CC 5.2 "What moves to a peer": a row moves when requested, or required, and
  appropriate; "an automatic diff is not a request"; "Anti-entropy over the
  commons is what serve seats do among themselves"; "What is offered unasked is
  the live state" (`part_5_transport_substrate.md:131-139`). Range fingerprints
  change how an offer is proven complete, not what is offered: S_A is today's
  offer (§2.4).
- CC 5.2's audience table and "structural invisibility"
  (`part_5_transport_substrate.md:103-127`) bound what a fingerprint may cover
  (§4).
- CC 6.1.5: "Every anti-entropy round carries what a node holds and lacks, per
  plane; the noise-floor aggregation producer (CC 6.1.2.1) runs over those
  rounds" (`part_6_the_coherence_mathematics.md:218`). Under RF an in-sync
  round carries a fingerprint, not the list.
- CC 6.1.5.3: "Anti-entropy is standard at every tier … by pull anti-entropy"
  (`part_6_the_coherence_mathematics.md:302`). Unchanged: rounds still run on
  every plane at every tier.
- CC 5.4.3 item 4: maintenance traffic is shaped
  (`part_5_transport_substrate.md:954`). §5.10.

**Questions for CC:**

1. **Is a range fingerprint, or a receiver's match answer, a holding claim
   under CC 5.2?** This design treats it as a statement made only to a node in
   the audience of every row it covers (§2.4). That is harmless for the
   Commons-public bootstrap planes. It needs a ruling before phase 2 puts
   `community`, `family` and `self` rows under fingerprints, in particular for
   "nothing of the content, of the roster or of who holds it".
2. **CC 6.1.5, "carries what a node holds and lacks".** May a round carry it as
   a fingerprint over ranges, with ids only where the ranges differ? Is there a
   normative consumer that needs the per-row list each round? Edge's own
   consumers (the holder map, the removal ledger, the proactive push) are
   covered in §5.6-5.8. Suggested text: "carries, or proves by range
   fingerprint, what a node holds and lacks".
3. **CC 5.2, "an automatic diff is not a request".** Confirm that a receiver's
   `list` answer for a range is not a request in this sense: it widens nothing,
   because the sender still lists only what it would offer unasked.
4. **The fingerprint construction as a pinned rule.** The replication wire is
   edge's, so CC need not pin it. Say whether CC wants the `"a":1` sum
   construction stated, or the `"a":2` collision-resistant one required, given
   §2.8's cost analysis.

## 8. Telemetry

All closed label sets; no peer id, key id or address is ever a label.

| Name | Kind | Labels | Says |
|---|---|---|---|
| `replication_io` `rf_nodes_out`, `rf_nodes_in` | counter | plane | fingerprint nodes sent and answered |
| `replication_io` `rf_split`, `rf_list`, `rf_match` | counter | plane, `sent`/`answered` | the descent |
| `replication_io` `rf_refs_listed_out` | counter | plane | ids listed by RF; with `summary_refs_out`, the head/RF/legacy split |
| `replication_io` `summary_bytes_out`, `summary_bytes_in`, `diff_bytes_in`, `diff_bytes_out` | counter | plane | app-layer JSON bytes, beside the ref counts |
| `rf_rounds` | counter | plane, outcome = `in_sync` / `descending` / `listing` / `unable` / `legacy` | the **in-sync ratio** = `in_sync / (in_sync + descending + listing)` per plane |
| `rf_peers` | gauge | `capable`, `legacy`, `unknown` | the fleet's capability |
| `rf_frontier_nodes` | gauge | plane | open descent across all peers |
| `rf_exclusions` | gauge | plane | §3.2's exclusions held |
| `rf_tree_rebuilds`, `rf_tree_build_ms` | counter | plane | sender rebuilds and their cost |
| `rf_receiver_unable` | counter | plane, reason = `unbooted` / `booting` / `suspect` | §3.4's fallbacks |
| `legacy_resweep_paced` | counter | plane | backfill pages and key listings skipped by §6.3 |

The byte truth comes from #1025's ledger, `(transport, plane)` cells with
`other` as interface truth minus everything attributed (`src/wire_bytes.rs`,
branch `feat/1025-transport-bytes`). The `summary_bytes_*` labels say how much
of its replication cell is Summaries; the drop in that cell after the canary is
the number that proves this design.

## 9. Witness plan

**Pure state machines** (unit, `cargo test --lib`, no fixture):

1. `RangeTree`: the fingerprint of every prefix equals the fingerprint
   recomputed from the elements, after any random sequence of insert, remove
   and replace (a differential against a `BTreeSet` model, as
   `holdings_index_971_tests` does); union and subtraction of trees equal the
   tree of the union and difference.
2. `RangeFrontier`: in sync, every Summary is the root alone; with k planted
   differences the frontier lists exactly the differing leaves within
   depth + 1 answers; a lost answer leaves the frontier unchanged; a duplicate
   or stale answer costs at most one node; eviction restarts at the root; the
   split and listing caps hold.
3. The receiver's set: for random inputs `T_B ⊆ settled_B` always (the safety
   rule as a property); an exclusion is learned from a listing and dropped when
   the row is listed; a backoff's expiry makes its range differ in the next
   comparison.
4. Wire: the `rf` members round-trip, are omitted when absent (a legacy
   Summary's bytes are unchanged), and are ignored by a pre-RF struct, in the
   form of `summary_status_is_flat_optional_and_tolerant_937`.
5. Lies: a receiver answering `split` on every node never makes a Summary list
   more than the page; a sender's arbitrary fingerprints never make the
   receiver emit a want for a hash it was not listed.

**Two real nodes** (integration, real sqlite directories and the loopback
transport, as `key_plane_v59_tests::NodeA`):

6. **In-sync cost is O(planes).** Seed 4,096 key rows on both, converge, then
   run 20 rounds: `summary_refs_out` 0 and `summary_bytes_out` under 256 B per
   `(plane, round, role)`, and zero subject reads (the #1019x attribution
   labels).
7. **k differences cost O(k log n).** Remove k ∈ {1, 8, 64} rows from B: B
   converges, the refs listed are at most k × 16, and the rounds at most 5.
8. **A transient refusal is re-asked after its window**, not after a wrap: B
   refuses a row once (a refusal fixture), and the row is listed again the
   first comparison after the backoff window and admitted.
9. **Mixed pair.** A node with the sender on, against a node with the switch
   off and against a frozen pre-RF Diff fixture: the peer is marked legacy in
   one round; it receives the legacy listing; its second full cycle does not
   start before `legacy_resweep_every` (injected clock).
10. **The audience.** An unannounced node X owned by O, and a peer P that is not
    O's: A's fingerprint toward P equals the sum over P's visible rows exactly;
    no listing to P names X's rows; and on the receiver side, adding X's rows
    to B leaves B's answers to A unchanged when A is not O's node.

**Gates** (per the repo's rules): run every integration suite the change can
reach, the source-scan suites (`log_citations` and its siblings), the wide
clippy lane with `RUSTFLAGS=-D warnings` over the four feature sets, and the
DST (`src/replication/sim.rs`) with frame loss on an RF pair, filtered runs
only on this host.

## 10. Rollout

### 10.1 The sequence

Each step ships alone, in order; each depends on the one before.

| Step | Ships | Switch | Default |
|---|---|---|---|
| A (45.1.10) | the byte labels of §8 (`summary_bytes_*`, `diff_bytes_*`); the receiver half: plane tags in the holdings index, `settled_B`, the `rf` answers, the marker | `CIRIS_EDGE_RANGE_FINGERPRINTS_ANSWER` | **on**: it answers only when asked and costs only memory |
| B (45.1.11) | the sender half on the five bootstrap planes: trees, frontier, head ring, capability, §5.6-5.8's adjustments, §6.3's pacing toward legacy peers | `CIRIS_EDGE_RANGE_FINGERPRINTS` | **off**; on for the canary on canonical-1 |
| C (45.1.12) | the sender default flipped, on the canary's numbers; want carry-over if `diff_want_in` still dominates | as B | on |
| Phase 2 (a later minor) | the Attestation plane (§4.4), after CC question 1 | its own switch | off |

The receiver half ships first because the canonical can only save bytes toward
peers that answer, and phones update on the agent's release train.

### 10.2 What the canonical's numbers should do

Against the 42 h of §1.4, with every peer on step A and the canonical on B:

```text
Summary tx on the five bootstrap planes, today          ~ 30.7 GB
RF in sync: per pair 3 planes x 2 roles x 120/h x 42 h  = 30,240 Summaries
            x 121 B                                     ~ 3.7 MB per pair
            x 17 concurrent links                       ~ 62 MB
            ceiling: x 135 identities, always on        ~ 0.5 GB
plus genuine differences, ~3.3 KB each, and first contacts listed once
```

- `summary_refs_out` on `key`, `identity_occurrence` and `transport_destination`
  falls from 201.1M to the head rows plus the rows of differing ranges.
- Namespace tx falls by at least the 30 GB of Summary JSON (≥ 47% of 63.8 GB).
  If the 24 GB of unattributed tx scales with frames, by up to about 77% of the
  attributable bytes. #1025 decides which.
- `diff_want_in` falls from 26.0M toward the rows listed per round (§5.4); rx
  loses most of `summary_refs_in`'s 3.5 GB as peers' own offers go RF.
- Toward peers that stay legacy: key-plane listings about 4× fewer at the
  default pacing (§6.3).
- The in-sync ratio (§8) should sit near 1 on the five planes once first
  contacts are done; a ratio that does not is a finding, either a persistent
  difference (exclusions at cap) or a peer that cannot answer.

## 11. Open decisions for Eric

1. **The fingerprint.** The `"a":1` modular sum, shipping now (recommended, with
   §2.8's cost argument), or the `"a":2` ristretto multiset hash from day one.
2. **The order.** The envelope hash (recommended) or `(asserted_at, hash)`.
3. **Unknown peers.** Speculative RF on first contact (recommended: one round of
   incomplete offer to an old peer) or a legacy listing with the marker first
   (one full listing per new pair).
4. **`legacy_resweep_every`.** 1 h (recommended) or longer for the long-soak
   peers. It applies only toward legacy peers; the Attestation re-sweep toward
   RF peers is unchanged in 45.1.x.
5. **One step per round or several.** Across rounds (recommended for 45.1.x: no
   Session change, a missed row is found in 4 rounds) or several levels inside
   one round (fewer rounds, a change to the #634 round shape).
6. **The receiver's restriction to "servable to the sender".** Recommended as
   designed; the alternative, all holdings, is simpler but leaks on the #682
   rows.
7. **Want carry-over** in step C, or only if the canary still shows
   `diff_want_in` ≫ `deliver_rows_out`.
8. **The Attestation plane.** Phase 2 after CC rules on question 1, or keep it
   on the paced re-sweep for the life of the LTS.
