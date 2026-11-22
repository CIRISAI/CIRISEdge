# Range fingerprints: anti-entropy that costs nothing when two peers agree

Status: DESIGN, for the 45.1.x LTS line (Eric's ruling: build it now, not as a
later major). No code is changed by this document. Every claim about existing
behaviour cites the file and line at `origin/main` b84073e (45.1.9). Evidence
marks follow `FSD/EVENT_PATH_MODEL.md`: **[read]** is read in the code or the
text, **[inf]** is inferred from numbers, **[new]** is proposed here.

## 0. The recommendation in one page

- **Protocol.** Range-based set reconciliation in the Negentropy style: a
  **salted** additive fingerprint over **hash-prefix ranges** of each plane,
  fan-out 16. The fingerprint is Σ SHA-256(tag‖salt‖id) mod 2^256, with the
  count, hashed and truncated to 16 bytes. The salt is 32 fresh random bytes
  per link session, carried only inside the sealed link. The order is the envelope hash itself, not a cursor
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
- **Scope: all of it on the LTS.** First the five bootstrap planes: `Key`,
  `IdentityOccurrence`, `TransportDestination`, `Revocation`,
  `IdentityOccurrenceRevocation`. They carry 201.1M of the canonical's 201.7M
  listed refs in 42 h (§1.4). Then the `Attestation` plane, also on 45.1.x
  (Eric, 2026-11-22). Its audience classes and volatile buckets are designed in
  full in §4.4. CC has ruled that it may go ahead (§7). It ships behind its own
  switch in step D and is turned on in step E.
- **Compatibility.** Capability is learned in band from the `rf` members. A
  peer that never answers one stays on the legacy listing, paced by
  **`BridgeConfig::legacy_resweep_every` (env `CIRIS_EDGE_LEGACY_RESWEEP_SECS`,
  default 3600 s, `0` = unpaced)** (§6).
- **Encoding.** Under the same capability, refs, wants and Deliver bodies travel
  in compact form, base64url. Today a ref is ~154 B and a Deliver body ~3.5× its
  raw size, because every byte is a JSON number. The bodies are the other half
  of the canonical's tx (§12).
- **Effect on canonical-1.** Of the 42 h's 63.8 GB tx, about 30.7 GB is Summary
  JSON on the bootstrap planes and about 31.7 GB is Deliver bodies as JSON
  number arrays (§1.4). In sync, range fingerprints cut the first to about
  89 MB (ceiling 0.7 GB). Compact bodies cut the second to about 12 GB toward
  capable peers (§10.2, §12).
- **CC has ruled** (2026-11-22, §7): a fingerprint is a compressed ref list,
  not a holding claim; the Attestation plane is allowed, mixed-audience ranges
  included, so long as each fingerprint covers only rows that peer may
  receive. No CC text changes. The construction and its known-answer vectors
  are in `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2, which CC cites.
- **Named requirements** R1-R9 (§13) carry CC's conditions and the hardening:
  - the audience filter goes before the sum and the count;
  - fingerprints are per peer;
  - a match feed keeps holder counts whole on both sides;
  - the salted sum, with a fresh per-link-session salt of 32 bytes.
- **Decisions** are recorded in §11.1. The open question for the
  implementation to measure is in §11.2.

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
| **Summary tx subtotal** | 201.7M | **30.8 GB** |
| `deliver_bytes_out` (raw envelope bytes) | | 9.05 GB raw → **~31.7 GB on the wire** |
| **Accounted tx** | | **~62.5 GB of 63.8 GB** |
| `summary_refs_in` | 22.65M | 3.5 GB rx |
| `diff_want_in` | 26.0M | 3.0 GB rx |

`summary_refs_out` counts refs, not bytes (`coordinator.rs:1457-1465`).
`deliver_bytes_out` counts the raw envelope bytes, "the JSON frame around them
is not counted" (`observability.rs:2298`).
`DeliverMessage::envelopes` is a `Vec<Vec<u8>>` (`protocol.rs:787`), which
serde_json writes as an array of decimal numbers, one per byte. The code's own
figure is "512 KiB raw → ~1.8 MB JSON-wire" (`session.rs:90`), so a body is
about 3.5× its raw size on the wire **[read]**. So 9.05 GB raw is ≈ 31.7 GB on
the wire **[inf]**. The two together, about 62.5 GB, leave about 1.3 GB of the
63.8 GB tx for framing, the E1 seal, resource control, retransmits and
announces. CIRISEdge#1025 (`feat/1025-transport-bytes`, `src/wire_bytes.rs`) is
the ledger that will confirm the split. Range fingerprints address the first
half and compact encoding the second (§12).

102.2M / 33k ≈ 3,100 full key listings in 42 h, ≈ 74 an hour over about 17
concurrent links, ≈ one per link every 14 minutes, and ≈ 23 per identity over
135 identities **[inf]**. At the 30 s cadence that is far fewer than one per
round, so most Key rounds toward the canonical do not end in a full listing
being sent. Why is not established: §11.2 makes it a measurement the
implementation owes. Range fingerprints remove the listing either way.

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
| Per-peer projection = shared set ± a few rows | O(exceptions) over a shared membership index (the salted sums are per link session, §3.4) | a per-peer tree, or per-peer leaf recomputation |
| Cost in sync | one 16 B root | one root |
| Cost with k sparse differences | O(k · depth · 16) node fingerprints + O(k · leaf) refs | the same |
| Rounds | depth + 1 | depth + 1 |
| Collision resistance | a plain sum falls to generalized birthday (Wagner); the salted sum below takes the elements out of any third party's reach | cryptographic |
| Prior art | Negentropy, deployed in Nostr relays | many |

**Pick the additive fingerprint.** The decisive row is the per-peer one.
`IdentityOccurrence` and `TransportDestination` are one shared set minus a
peer's #682 withheld subjects (`bridge.rs:8507-8516`), and the Attestation
projection is a union of audience classes (§4.4). With a sum, each peer's set
is assembled from shared membership with a few additions and subtractions;
with a Merkle tree, each would be a per-peer tree. The sum is over **exactly
that peer's set** before anything is hashed (R1, R2).

```text
e(x)      = SHA-256( "CIRIS-RF-v1/elem" || salt || x )   as LE 256-bit     x = envelope hash
sum       = Σ_{x ∈ S_A(P), x in p} e(x) mod 2^256
count     = |{x ∈ S_A(P) : x in p}|
fp(S, p)  = SHA-256( "CIRIS-RF-v1/node" || u8 len || plane || u8 len || p
                     || LE256(sum) || u64_be(count) )[0..16]
```

The normative bytes and six known-answer vectors are in
`FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2 (R9).
- The outer hash binds the plane and the prefix, so a fingerprint of one range
  cannot stand for another.
- The salt makes every element a value only the two ends of the link can
  compute (§2.8).
- SHA-256 is the hash every envelope hash already is.
- The wire names the construction, `"a":1`, so a stronger one (`"a":2`,
  ristretto255, reserved) is a new value, not a new message.

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
directory of the Commons, CC 5.2's table) or rows B would serve A. CC
confirmed the reading on 2026-11-22: a fingerprint is a compressed ref list,
not a holding claim, provided it covers only rows the peer may receive (§7,
R1).

### 2.5 Wire shape

Additive members on the two existing messages (`protocol.rs:651`,
`protocol.rs:690`), flattened and skipped when absent, as `status`
(`protocol.rs:668`) and `withheld` (`protocol.rs:701`) are. A pre-RF peer
ignores them: no `deny_unknown_fields` on this path (`protocol.rs:662-667`,
pinned by `summary_status_is_flat_optional_and_tolerant_937`).

```text
Summary (RF sender, in sync):
{"type":"summary","kind":"identity_occurrence","refs":[],
 "rf":{"v":1,"a":1,"salt":"<43 b64url>","n":[["",33012,"<32 hex>"]]}}  ~ 173 B

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
  "I answer RF" (§6.1). `"e":1` in it says "I decode the compact encoding"
  (§12.3).

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
- **The salt and the frontier are separate.** The receiver answers each
  Summary with the salt that Summary carries (R6). The frontier is prefixes
  only, so it does not depend on the salt. A round that rides another pooled
  link, with that link session's own salt, continues the same descent.
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
| In sync | ~173 B Summary (the salt included) + ~75 B Diff | 1 | 0 (§3.4) |
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
- **A third party forges a collision.** CC flagged it, and it is real for an
  unsalted sum. A peer connected to both A and B can mint rows whose hashes sum,
  with the counts balanced, to a target (Wagner's generalized birthday is cheap
  in hash evaluations), and so make the A–B range match while B lacks a row. The
  hybrid signature inside each row's hash makes each candidate costly, but it
  does not make the attack impossible.
- **The salted sum closes it.** Each element is `e(x) = SHA-256(tag‖salt‖x)`.
  The salt is drawn fresh by the sender for each link session, and it is known
  only to the two ends of that sealed link (R5, R6).
  - A third party cannot compute any `e(x)` on the A–B link, so it cannot
    prepare a set in advance.
  - A row it mints lands at a value it cannot predict.
  - A random collision of the 128-bit truncation is 2^-128 per comparison.
  - The only parties who know the salt are A and B. Either can already lie
    (above) and hurt only itself.
- **Why per link session and not per round.** A per-round salt would make the
  sender re-hash its whole offer every round, and the receiver its whole set.
  §3.4 has the arithmetic: per link session the same safety costs one hash pass
  per link-up per plane, plus the delta per memo generation.
- `"a":1` is this salted sum (decision 1, as hardened 2026-11-22). `"a":2`
  stays reserved for a ristretto255 multiset hash.

## 3. Where fingerprints come from

### 3.1 The sender's trees

The sender keeps two kinds of structure.

**[new] `RangeIndex`**, one per session plane, shared across peers. It is
**membership only**: the plane's hashes sorted into 4,096 leaf buckets (three
hex digits), each hash with the labels the per-peer filter reads (the subject
on the identity planes, §4.4.2's labels on the Attestation plane). It holds no
sum, no count and no fingerprint, so nothing salted or peer-specific is ever
shared (R2).

**[new] `LinkSums`**, one per `(link session, plane)`. A link session belongs
to exactly one peer.
- It holds 256 level-2 buckets of salted sum and count, over exactly that
  peer's set: `RangeIndex` filtered by the peer's audience before summing (R1).
- A node at depth ≤ 2 adds buckets.
- A deeper node hashes the members of its level-2 bucket in that peer's set,
  about 130 at 33k rows.

| Plane | Built from | Rebuilt when |
|---|---|---|
| `Key`, `Revocation`, `IdentityOccurrenceRevocation` (peer-invariant membership) | the plane's complete listing from `key_plane_listing` (`bridge.rs:8193`): the listing cache when it hits (`bridge.rs:8204-8222`), else the listing just built | the memo's generation moves (`key_plane_memo.rs:575`); "generation moves on every change to what the memo would answer" (`key_plane_memo.rs:357-362`) |
| `IdentityOccurrence` | the shared listing over the publish set, minus, per peer, the refs of its #682 withheld subjects (memo lookups) | as above; the per-peer patch is cached against `(generation, withheld set)` |
| `TransportDestination` | the holdings index's route records (`holdings_index.rs:325`, which already keep each route's subject "so the stranger view … can later filter by owner"), filtered by the listing's predicate: subject in the publish set, or `relayable_signed_route` (`bridge.rs:8572`), stored as one bit per record at feed time; minus the peer's #682 subjects | each route feed delta |

**The tree is the listing.** The set the tree sums is the set
`list_envelope_refs_for_peer` would have returned: a subject the memo's read
budget left unread (`KEY_PLANE_READ_BUDGET` 256, `key_plane_memo.rs:296`) is
absent from both. So S_A equals today's offer by construction.

The `RangeIndex` is rebuilt once per memo generation: one unsalted pass, at
most once per feed probe (`FEED_PROBE_SPACING` 5 s, `store_feed.rs:86`) plus the
TTL epoch (`MEMO_TTL` 10 min, `key_plane_memo.rs:97`). Each live `LinkSums` is
then updated **incrementally** by the generation's delta: hash the rows added
and removed with that link's salt, and add or subtract them. A full salted
pass happens only when a link session starts (§3.4).

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
| Sender `RangeIndex`, all planes | n × (32 B + labels) per plane: about 4 MiB at canonical sizes, plus §4.4.7 for Attestation | none | none: the listing cache hits |
| Sender `LinkSums` | 256 × 40 B ≈ 10 KiB per `(link session, plane)`: 17 links × 6 planes ≈ 1 MiB; 135 peers × 2 pooled links × 6 ≈ 16 MiB worst | none: the root is cached per `(link session, plane, generation)` | none |
| Sender per peer | a frontier (usually the root) and a head position: under 1 KiB per `(peer, plane)`, 2 KiB at the split cap | none | none |
| Receiver | a `RangeIndex` over its settled set per plane (≈ 4 MiB), and `LinkSums` per `(peer's salt, plane)`, rebuilt when a new salt arrives | one root compare plus the corrections in the root's range, salted the same way | none: the index answers; a clean feed is not probed within `FEED_PROBE_SPACING` |
| Exclusions | at most 65,536 × 32 B ≈ 2 MiB | | |

**The CPU cost of the salt.** One element costs one SHA-256 over 80 bytes:
two compressions, about 0.2 µs with SHA extensions and ≈ 0.5 µs without (the
conservative figure used here). The canonical's offer, all six planes at
today's sizes, is about 140k rows:
- Key 33k;
- IdentityOccurrence ≤ 33k;
- TransportDestination ~18k;
- Revocation and IdentityOccurrenceRevocation ≤ 7.2k each;
- Attestation 42.5k.

| Salt scope | When the full salted pass runs | Canonical cost |
|---|---|---|
| **per link session (R5)** | once per link-up per plane, on the link's first RF Summary; then O(delta) per memo generation | ≈ 70 ms per link-up as sender, ≈ 70 ms as receiver over its own holdings. At one link-up every 10 s: ≈ 1.4% of a core. At one a second (a churn storm): ≈ 14%. Deltas: 10 new rows × 17 links = 170 hashes ≈ 85 µs per generation |
| per round | every round, per link, per role | 17 links × 2 roles × 70 ms per 30 s ≈ 8% of a core for the sender alone, ≈ 16% with the receiver, and ≈ 120% if all 135 peers were linked at once |

The per-link salt is cheaper than the per-round one by the number of rounds a
link carries: a link that lives ten minutes carries twenty. Link churn
(CIRISEdge#532) is the variable that sets the real figure. Step A's telemetry
counts link-up rebuilds and their milliseconds (`rf_linksums_built`, §8). A
link-up does not wait for the pass: until a `LinkSums` exists, that link's
round sends a legacy Summary (§3.4 fallback).

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
  Membership is shared and has no per-peer exceptions; the salted sums are
  still per link session, so per peer (R2).
- `IdentityOccurrence`, `TransportDestination`: shared membership minus the
  peer's #682 subjects, filtered before the per-link salted sum (R1): "an unannounced node's occurrence and route go only to
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

### 4.4 The Attestation plane (on the LTS; CC ruled 2026-11-22)

Built in full on 45.1.x behind its own switch (§10.1, step D) and turned on in
step E. CC's ruling on question 1 allows it on the condition R1 and R2 carry:
each fingerprint covers only rows that peer may receive (§7, §4.4.8).

The Attestation offer is per row and partly live. Recomputing it per peer per
round would cost what the walk costs today. So the design splits every input
the gates read by the scope it belongs to:

- **node** inputs: one value for every peer;
- **peer** inputs: one value per peer per round;
- **class** inputs: one value per placement, shared by every peer;
- **(row, peer)** inputs: the volatile ones.

Each kind of input is then cached in the one place where the listing would
read it.

#### 4.4.1 The gate stack, input by input

The advertise is `offer_rows` (`bridge.rs:12917`), behind the round's peer
resolution in `list_attestations` (`bridge.rs:12421`). In order:

| # | Gate (line) | Reads | Scope | Today's freshness | Under RF |
|---|---|---|---|---|---|
| 1 | peer resolution, `resolve_attestation_recipient` (11680) | is the peer in the consent send set | peer | 10 s memo, `CONSENT_SEND_SET_MEMO_TTL` (3430), every round (#400, #1022) | unchanged, every round. Unresolved means an empty offer: no node is sent, as nothing is listed today (`bridge.rs:12463-12466`) |
| 2 | walk class, `unasked_offer` (13307) | seat or not, owner's node or not, reach | peer | every round | unchanged; it picks the class family (§4.4.3) |
| 3 | required read, `required_rows` (13352) | invitations naming the peer, its groups' rows | peer | every round, bounded (`REQUIRED_READ_PAGE`, `SUBJECT_READ_BUDGET`) | §4.4.5 |
| 4 | `attestation_is_advertised` (9715) | projection; for `SelfOwn`, attester ∈ self set | row + node | per row read | row label `proj` + node self set, invalidated by `check_advertise_inputs` (4386) |
| 5 | #738 `receipted_by_peer` (3756) | the peer receipted the file | (row, peer) | per row read | **ignored**: the peer holds the row, so it is in T_B and the range matches. The superset this allows is a row the peer holds, so nothing leaks |
| 6 | trace pause, `trace_plane_paused` (4791) | mesh-config relief | node | per sweep | class flag `serve`: paused drops those classes |
| 7 | reach half, `audience_reach_half` / `reach_withholds` (11281) | the peer's reach × the row's audience | peer × class | per row | class-level given the peer's reach |
| 8 | `author_quarantine_withholds` (10799) | the author's standing | node, per author | per-sweep memo | exception set: subtract the quarantined authors' rows |
| 9 | `accord_relay_withholds` (4181) | persist's taking verb on the whole row | row | per row | **volatile** (§4.4.4) |
| 10 | serve capability, `peer_has_serve_capability` (10309) | the peer's `infra:serve` | peer | per-sweep memo | peer bit; gates class flag `serve` |
| 11 | `recipient_capability_withholds` (10452) | `Capability(t)`: is the peer a token holder; `Subject`: the data subject's grant | peer × token; (row, peer) | per-sweep grant cache | `Capability(t)`: peer bit per token. `Subject`: **volatile** |
| 12 | `audience_withholds` (11431): persist `may_receive` (persist v61.4.3 `replication_audience.rs:710`), the Rooted floor and its exemptions | the row's placement audience; is the peer Rooted; is the row self-authored, cohort-delivered or addressed to the peer | class + peer + row flags | per-sweep memo | class membership (§4.4.3), peer bit `rooted`, row flags |
| 13 | `trace_recipient_withholds` (10589) | the trace subject's egress grant naming the peer | (row, peer) | per-round memo | **volatile** |
| 14 | `moves_unasked` (13719) and `retired_of` (13844), for `RequiredOrAppropriate` only | appropriate, required, a public group the peer is in, allegiance facts, superseded | class + row flags + (row, peer) | per row | class family "appropriate" (§4.4.3), row flag `retired` kept by the feed; `placed_in_a_group_of` and `attestation_is_allegiance_fact` are **volatile** |

#### 4.4.2 Row labels

Each row is labelled once, when the store feed or the warm-up first names it
(the same drain that feeds the holdings index and the key-plane memos,
`store_feed.rs`). The labels are computed from the row alone and interned:

- `proj`: `Global` | `Cohort` | `SelfOwn` | `Capability(t)` | `Subject`, by
  `attestation_projection` (`bridge.rs:10225`);
- `place`, the placement: `commons` (species, biosphere, federation),
  `self(owner)`, `family(f)`, `community(c)`, `affiliation(c)`, or
  `group_plane(g)` for a roster or membership row (`is_group_plane_row`). A
  row whose audience is unreadable (`audience_of_view`, `bridge.rs:10972`, an
  `Err`) gets `malformed`, which no peer's offer includes, as the gate
  withholds it;
- `origin` = `attesting_key_id`; `names` = `attested_key_id` ∪
  `subject_key_ids` ∪ the `for_key_id` a grant is for. These are `may_receive`'s
  origin and refers-to arms (persist v61.4.3 `replication_audience.rs:697-709`);
- flags: `serve` (`trace:*`, `attestation_requires_serve`, `bridge.rs:10182`);
  `accord`; `tombstone` (`withdraws`, `recants`); `charter`; `appointment`;
  `retired` (superseded, set and cleared by the feed when a `supersedes` naming
  it lands or is withdrawn); `volatile` (§4.4.4).

That is about 64 B a row interned, ≈ 2.7 MiB at the canonical's 42,520
Attestation-index rows (`holdings_index.rs` module docs).

#### 4.4.3 Classes, and each peer's offer as a sum of them

A **class** is the set of non-volatile rows sharing `(place, proj, flags)`.
Each class is **membership**: its rows' hashes in the plane's `RangeIndex`
buckets (§3.1). That is dense for the commons class, which is most of the
plane, and sparse for every other class. A class holds no sum.

**The audience of a placement** comes from persist's resolver,
`audience_nodes(cohort_scope, target)` (persist v61.4.3 `replication_audience.rs:591`):
`Everyone` for the commons and a public group, otherwise the exact node set.
It is **peer-independent**, so it is memoized per placement, not per peer. It
is dropped when the feed brings a row that can change it:
- a roster or membership row of that group;
- a `consent:replication` grant, which carries the per-node allow list
  (CC 3.3.7, persist `replication_audience.rs` module docs);
- an `identity:occurrence:v1` row, for its `device_class`;
- a charter, for `is_public_group`.

What the cursor cannot see is bounded by `MEMO_TTL`, as for the key-plane memo
(`key_plane_memo.rs:97` and "What the cursor cannot see").

**A peer's classes.** For a peer P, with its peer bits:
- `rooted`: the serve floor;
- `serve`: its `infra:serve` capability;
- its capability tokens;
- its reach;
- its principals (`principals_with_self`).

C(P) by walk class:

| Walk class (`UnaskedOffer`) | C(P) |
|---|---|
| `Commons` (two seats) | every class whose placement audience contains P, the commons and public groups included, under the reach and floor bits |
| `ByReach` (the owner's own nodes) | the same, under P's reach |
| `RequiredOrAppropriate` (a contact) | only the classes `moves_unasked` passes: `Global` and `Capability(t)` projections; placements whose audience contains P (`Reason::Cohort`); origin or names in P's principals (`Origin`, `RefersTo`); group-plane rows; tombstones; charters; appointments. Minus `retired` rows (live state only: "a superseded row moves on request", CC 5.2) |

Then:

```text
S_A(P) = Σ_{c ∈ C(P), bits pass} tree_c
       − rows of quarantined authors in those classes
       + volatile rows whose cached verdict for P is yes
```

A peer's `LinkSums` (§3.1) is the salted sum and count, bucket by bucket, of
exactly S_A(P) as computed above, with that link's salt (R1, R2). Its 256
buckets are about 10 KiB a link session, and deeper nodes hash the members of
S_A(P) in the bucket. The subtractions in the formula act on membership, or on
salted values under the same salt. Either way the `(sum, count)` that enter
the outer hash are bit-identical to summing the filtered set, and witness 15
checks every sent node against that filter-first reference.

Membership is shared across peers; sums never are. A peer's `LinkSums` is
recomputed (the members changed, re-hashed with the same salt) only when one
of its inputs moves:
- one of its classes;
- a placement audience it is in or leaves;
- its peer bits;
- the quarantine set;
- the node's self set.

The rebuild is O(rows P sees outside the commons). An idle round does no
rebuild and no store read.

#### 4.4.4 Volatile rows

A row is **volatile** when its verdict for a given peer needs a read about
that row and that peer, not just its labels. The cases, from §4.4.1:
- the `Subject` grant (gate 11);
- the trace recipient's consent (gate 13);
- the accord relay (gate 9);
- for contacts, `placed_in_a_group_of` and `attestation_is_allegiance_fact`
  (gate 14);
- the first-contact membership carve (`first_contact_membership_serves`,
  inside gate 12).

Volatile rows are not in any class tree. Per peer, the sender keeps a verdict
for each volatile row it has judged: a bitset over the plane's volatile-row
index, `n_volatile` bits a peer. Each verdict is from the real gate, run as
the listing runs it. It is valid until the first of:
1. dirt: the feed brings a row that can change it (a consent grant, a
   `withdraws` or `recants`, a quarantine marker, an accord row);
2. `valid_until`: the earliest `expires_at` or `bounded_until` among the
   inputs it read. This is the #659 rule that no verdict outlives a
   `withdraws`, a halt or persist's `bounded_until` (`summary.rs` `FetchBatch`
   docs);
3. `RF_VOLATILE_TTL` = `MEMO_TTL` (10 min). Today a history row is judged
   once per re-sweep cycle (up to 25 min at 52k rows, `bridge.rs:1120-1128`),
   so this is fresher than the listing it replaces.

**Volatile buckets.** A round re-reads at most `RF_GATE_BUDGET` = 256
volatile verdicts per `(peer, round)`, absent ones before expired ones, as the
key-plane read budget does (`key_plane_memo.rs:296`). A leaf bucket holding a
volatile row with no valid verdict is **pending** for that peer:
- **Not fingerprinted.** The sender sends no node that covers a pending
  bucket. In place of the root it sends the largest nodes made only of fresh
  buckets: the "maximal fresh cover", at most `RF_MAX_SPLITS_PER_SUMMARY`
  records. So the root is sent only when the plane is fresh for that peer.
- **Not listed** without the real gate. A pending bucket waits for its
  verdicts. Once they are read, it is fingerprinted like any other bucket, and
  a listing of it always re-runs the gates.
- **Bounded.** In steady state no verdict expires except by TTL, so the
  re-reads come to `n_volatile / (TTL / cadence)` a round, spread. With no
  dirt and no TTL due, a round does zero gate reads.

A verdict can go stale without the feed seeing it, for a change that is
neither a row nor an expiry. Until the TTL, the fingerprint may then include a
row the live gate would now refuse. That is the stated 2 × `MEMO_TTL` residual
the LTS already accepts for the key-plane memo (`key_plane_memo.rs`, "The
stated bound is two `MEMO_TTL`s"). It never moves a row: every listing
re-runs the gates, and the Fetch twin re-gates every byte.

#### 4.4.5 Required rows

"What is required moves before any walk" (CC 5.2). `required_rows` stays as
it is. Its rows are listed in `refs`, at the head of the Summary, on every
round until a `match` covers their range after they were listed; after that
they are ordinary fingerprinted rows. The read itself is memoized per peer
against the feed. It is re-read when a row naming one of the peer's principals,
or placed in one of its groups (`REQUIRED_GROUPS`, `bridge.rs:2443`), lands.
A grant that is new to the peer therefore still moves in the next round, and
an idle round reads nothing.

#### 4.4.6 The receiver, on the Attestation plane

`T_B = settled_B ∩ servable_B→A − excluded_B(A)`. Here `servable_B→A` comes
from B's own copy of the same machinery, at the serve-gate level:
`may_receive` by class, with the Rooted floor. It is never the walk level.
Two rules make it sound without B evaluating volatile gates for A:

- **Under-approximation is always allowed.** A smaller T_B costs listings,
  never rows or disclosure (§2.4). So B leaves every volatile row out of T_B
  by default.
- **Learned inclusions.** A row that A listed to B is a row A holds, and "a
  node holds a row only when it is in that audience" (CC 5.2,
  `part_5_transport_substrate.md:103`). So B may count it in T_B toward A
  without disclosing anything. B keeps these inclusions per `(peer, plane)`,
  capped like the exclusions (§3.2). They stop a volatile row B holds from
  making a range differ forever.

#### 4.4.7 Bounds

| | Memory | Idle round |
|---|---|---|
| Labels | ≈ 64 B a row: ≈ 2.7 MiB | none |
| Class membership | in the plane's `RangeIndex`: 32 B a row plus labels | none |
| Placement audiences | one node set per placement | none: dirt-driven |
| Per peer | `LinkSums` ≈ 10 KiB per link session; volatile bitset `n_volatile` bits; inclusions and exclusions ≤ 1,024 each | root compare |
| Gate reads | ≤ `RF_GATE_BUDGET` per (peer, round), only on dirt or TTL | zero |

#### 4.4.8 CC question 1, ruled

CC ruled that a fingerprint is a compressed ref list, not a holding claim
(§7). Mixed-audience ranges are allowed on one condition: each fingerprint
covers only rows that peer may receive. This section's construction meets the
condition in three ways:
- S_A(P) is built from P's classes and P's own volatile verdicts only (R1);
- the sum and count are over that set before hashing;
- no fingerprint, sum or cache is shared with another peer (R2).

The fallback this section used to describe, making `self` and `family`
placements volatile by rule, is not needed. Step E needs no further ruling.

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

### 5.7 The match feed: holders from matched ranges, on both sides (R3)

CC's condition (c): any consumer that reads "peer P holds id x" from rounds must
still count P as a holder of every id in a range that **matched**, on both
sides. Otherwise rarity reads low for exactly the best-replicated rows, the
ones that never get listed again.

**Where holders are read from ref lists today [read]:**

| Consumer | Reads | Site |
|---|---|---|
| the removal receipt ledger (#441) | every hash of a peer's Summary on a removal kind, as "the peer's own statement of holdings" | `coordinator.rs:1110-1120` → `observability.rs:4722` (`removal_ack_from_summary`) |
| the known-hash holder map (#552) | the hashes a peer's Summary offered that this node lacks, with the peer as holder | `session.rs:903` → `bridge.rs:5168-5194` (`note_known_hashes`, `last_advertised_by`) |
| the proactive push's delta basis | the peer's last Summary as what it holds | `session.rs:493`, `session.rs:554` |
| `peer_lacks_nothing` | an empty Diff | `coordinator.rs:1077-1079` |

The noise-floor and rarity machinery itself does **not** read replication
refs today:
- its holder counts come from signed `FountainHoldingClaim` envelopes
  (`swarm/runtime.rs:467` `upsert`, `:503` `distinct_holders`, `:531`
  `weighted_holder_equivalents`);
- the read side is a tap on the same claim plane (`holonomic/converged_view.rs`
  module docs);
- the `AggregationMetaV1` producer (`holonomic/aggregation.rs`) is
  verify-shaped and fed by them.

So range fingerprints cannot lower today's rarity counts. The match feed below
is what keeps that true for the four consumers above, and for any producer that
later reads holders from rounds.

**[new] The match feed.** One event, emitted by each side when a range
matches:

```text
RangeMatched { peer, plane, role: Sender | Receiver, link_session, prefix,
               ids: lazy iterator over this side's own set ∩ prefix }
```

- **Sender side.** A receives `match` for prefix p. Then B holds every id of
  S_A(B) ∩ p, so each id is booked with B as a holder.
- **Receiver side.** B answers `match` for prefix p. Then A offers, and so
  holds, every id of T_B(A) ∩ p, so each id is booked with A as a holder.
- **Once per change.** The feed fires for `(peer, plane, prefix)` only when the
  matched set's generation differs from the last one it fired for. A root that
  matches round after round costs nothing after the first match. The
  iteration is O(|set ∩ p|) once per change.
- **Consumers:**
  - the removal ledger books acks from both roles: a match is a stronger ack
    than a listing, because a listing says the peer offers the row and a match
    says it holds all of ours;
  - the holder map refreshes `last_advertised` for its known hashes in p, so
    on a `HashFirst` plane the holder map stays as fresh as the matches, not
    the eviction cutoff (§5.8);
  - the proactive push reads "root matched" (§5.6);
  - `peer_lacks_nothing` counts root matches;
  - a future rounds-reading rarity producer subscribes to the same event.
- **Witness 14** (§9) pins that, for the same pair and the same sets, every
  consumer's count equals the count the legacy listing produces.

### 5.8 Known hashes on conferred servers (#552)

In T_B on a `HashFirst` plane (§3.2). The match feed (§5.7) refreshes each
known hash's holder on every new match of its range, so the holder map ages
only when the peer's set changes. If a known hash does age out, it leaves T_B,
its range differs, and the listing re-teaches it with its holder.

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

**Questions put to CC, and its rulings (2026-11-22).** No CC text changes.

| # | Question | Ruling | What it puts in this design |
|---|---|---|---|
| 1 | Is a range fingerprint, or a match answer, a holding claim under CC 5.2? | **No.** A fingerprint is a compressed ref list. The Attestation plane is allowed, mixed-audience ranges included, provided each fingerprint covers **only rows that peer may receive** | §4.4 is enabled on that condition, as R1 and R2 (§13). §4.4.8's fallback is not needed |
| 2 | CC 6.1.5, "carries what a node holds and lacks": may it be a fingerprint? | **Yes.** CC 6.1.5 fixes what a round conveys, not its encoding. Any consumer that reads holders from rounds must still see every id of a matched range, on both sides | the match feed, R3 (§5.7) |
| 3 | Is a `list` answer a request under "an automatic diff is not a request"? | **No.** It is a step of the automatic diff | none: the sender lists only its unasked offer (§2.4) |
| 4 | Should CC pin the construction? | **It is edge's wire, not `WIRE_VOCABULARY`.** The construction and known-answer vectors go in `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4, which CC cites | §3.4.2 of the FSD, R9 |

**Hardening CC asked for, and took.** The unsalted sum lets a peer connected to
both A and B mint rows of equal sum and count and suppress a row on the A–B
link. The fix is the salted sum Σ H(salt‖id), with the salt per link session:
- drawn by the sender at link establishment;
- fresh and random for every session, re-established ones included;
- never derived from anything stable;
- 32 bytes;
- carried only inside the sealed link.

A per-link-session `LinkSums` is cached for the link's life (CC agreed). This
is R4-R6, and it stays `"a":1`; ristretto255 remains `"a":2`.

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
| `replication_io` `deliver_wire_bytes_out`, `deliver_wire_bytes_in` | counter | plane, encoding = `json` / `b64` | Deliver bytes as encoded on the wire, beside the raw `deliver_bytes_*` (§12.3) |
| `rf_round_outcome_by_size` | counter | plane, role, outcome, size band | §11.2's measurement: does a large Summary's round complete |
| `rf_attestation_pending_buckets` | gauge | walk class | §4.4.4's buckets waiting for verdicts, all peers |
| `rf_attestation_gate_reads` | counter | cause = `absent` / `dirt` / `ttl` | volatile verdicts re-read, by why (the #1019x attribution shape) |
| `rf_linksums_built`, `rf_linksums_build_ms` | counter | plane, role = `sender` / `receiver` | full salted passes at link-session start, and their cost (§3.4) |
| `rf_linksums_delta_hashes` | counter | plane | salted hashes spent on memo-generation deltas |
| `rf_match_feed_ids` | counter | plane, role, consumer | ids delivered to each match-feed consumer (§5.7) |
| `rf_attestation_class_rebuilds` | counter | cause = `class` / `audience` / `peer_bits` / `quarantine` / `self_set` | per-peer array rebuilds (§4.4.3) |

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

**The Attestation plane** (§4.4; real directories, as the audience suites
`membership_first_contact_756` and the #761 S1 suites are):

11. **Classes equal the walk.** For each walk class (`Commons`, `ByReach`,
    `RequiredOrAppropriate`), over a corpus covering every placement, every
    projection, every flag and a quarantined author: the set S_A(P) built from
    classes equals the set the 45.1.9 `offer_rows` would offer P over the whole
    plane. A differential at every step of a random sequence of feed events:
    roster changes, grants, occurrences, supersessions, quarantine, the trace
    pause.
12. **Volatile rows never leak and never go stale past the bound.** A trace row
    whose consent is withdrawn is out of S_A(P) at the first comparison after
    the `withdraws` is fed. An expiring grant is out at its `expires_at`. A
    bucket with an unread verdict is never covered by a sent node.
    `RF_GATE_BUDGET` bounds gate reads per round. An idle round reads nothing.
    Every fingerprint over a mixed-audience range sums only rows the peer may
    receive (R1).

**The encoding** (§12):

13. Compact `rh`, `wh`, `xh` and `eb` decode to the same struct as the JSON
    form, byte-exact for bodies. A compact member is never sent to a peer that
    has not advertised `"e":1`. A compact Deliver of consent grants is classed
    `contact` by the shaper and by #1025's frame classifier, as its JSON twin
    is.

**The named requirements** (§13):

14. **The match feed equals the listing (R3).** For the same pair and sets, run
    once with the legacy listing and once with RF, and compare:
    - the removal ledger's acks per peer;
    - the holder map's entries and holders;
    - the proactive push's skips;
    - `peer_lacks_nothing`.

    Each must equal the legacy run on both sides once the ranges match, and the
    feed must fire once per change, not once per round.
15. **Filter first (R1, R2).** For every node a sender emits, its `(sum,
    count)` equals a reference computed by filtering the peer's set first and
    salting second. Two peers with different audiences over the same plane and
    the same salt get different fingerprints whenever their sets differ. No
    `LinkSums` is ever read for a peer other than its own.
16. **Fresh salts (R5).**
    - Two link sessions of the same pair draw different salts. So does a link
      torn down and re-established between the same two nodes, within one
      process and across a restart.
    - The salt is 32 bytes.
    - It is not equal to any value derivable from the pair's keys, key ids,
      link id, link hash or round ids. The test computes the obvious
      derivations (hashes and HKDFs of each) and asserts none matches.
    - A source scan asserts the salt is produced only by a call to the OS
      CSPRNG.
17. **Never outside the seal (R6).** A frame carrying `rf.salt` is never
    written by an unsealed path. On a transport without confidentiality the
    sender sends a legacy Summary. The salt appears in no log line, metric
    label, persisted row or FFI return (a source scan, as `log_citations`
    does).
18. **Known answers (R9).** The implementation reproduces the six vectors of
    `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2, byte for byte.

**Gates** (per the repo's rules): run every integration suite the change can
reach, the source-scan suites (`log_citations` and its siblings), the wide
clippy lane with `RUSTFLAGS=-D warnings` over the four feature sets, and the
DST (`src/replication/sim.rs`) with frame loss on an RF pair, filtered runs
only on this host.

## 10. Rollout

### 10.1 The sequence

Each step ships alone. A comes before B and C. D needs A's receiver plumbing
and B's index, `LinkSums` and frontier. E needs D's canary. R1-R9 (§13) are in
force from the first step that sends or answers a fingerprint: A for answers,
B for sends.

| Step | Ships | Switch | Default |
|---|---|---|---|
| A (45.1.10) | the byte labels of §8 (`summary_bytes_*`, `diff_bytes_*`, `deliver_wire_bytes_*`); §11.2's measurement; the receiver half on the bootstrap planes: plane tags in the holdings index, `settled_B`, the `rf` answers, the marker; **decoding** of the compact encoding (§12), advertised as `"e":1` | `CIRIS_EDGE_RANGE_FINGERPRINTS_ANSWER` | **on**: it answers only when asked and costs only memory |
| B (45.1.11) | the sender half on the five bootstrap planes: trees, frontier, head ring, capability, §5.6-5.8's adjustments, §6.3's pacing toward legacy peers; **encoding** of compact refs, wants and bodies toward peers that advertised `"e":1` | `CIRIS_EDGE_RANGE_FINGERPRINTS`; `CIRIS_EDGE_COMPACT_WIRE` for §12 | **off**; on for the canary on canonical-1 |
| C (45.1.12) | the sender and encoding defaults flipped, on the canary's numbers; want carry-over only if the canary shows `diff_want_in` ≫ `deliver_rows_out` (decision 7) | as B | on |
| D (45.1.13) | the Attestation plane, both halves (§4.4): row labels, class membership, placement audiences, volatile verdicts and pending buckets, the required-row memo, learned inclusions | `CIRIS_EDGE_RANGE_FINGERPRINTS_ATTESTATION` | off; on for the canary |
| E (45.1.14) | D's switch on. CC has ruled (§7), so no fallback applies | as D | on |

The receiver half ships first because the canonical can only save bytes toward
peers that answer, and phones update on the agent's release train. For the
same reason compact decoding ships in A and encoding in B.

### 10.2 What the canonical's numbers should do

Against the 42 h of §1.4, with every peer on step A and the canonical on B:

```text
Summary tx on the five bootstrap planes, today          ~ 30.7 GB
RF in sync: per pair 3 planes x 2 roles x 120/h x 42 h  = 30,240 Summaries
            x 173 B (salt included)                     ~ 5.2 MB per pair
            x 17 concurrent links                       ~ 89 MB
            ceiling: x 135 identities, always on        ~ 0.7 GB
plus genuine differences, ~3.3 KB each, and first contacts listed once

Deliver bodies on the wire, today (9.05 GB raw x ~3.5)  ~ 31.7 GB
compact bodies (base64url, x 1.33)                      ~ 12.0 GB

tx, today                                               63.8 GB
tx after steps B and C, every peer capable              ~ 13-14 GB  (about -79%)
```

- `summary_refs_out` on `key`, `identity_occurrence` and `transport_destination`
  falls from 201.1M to the head rows plus the rows of differing ranges.
- Range fingerprints alone remove about 30.7 GB (≈ 48% of tx). Compact bodies
  remove about 19.7 GB more toward capable peers (≈ 31%). Peers that stay legacy
  keep today's body encoding. #1025's ledger confirms both against interface
  truth.
- `diff_want_in` falls from 26.0M toward the rows listed per round (§5.4). On
  rx, most of `summary_refs_in`'s 3.5 GB goes as peers' own offers go RF, and
  wants shrink 2.7× in compact form.
- Toward peers that stay legacy: key-plane listings about 4× fewer at the
  default pacing (§6.3).
- The in-sync ratio (§8) should sit near 1 on the five planes once first
  contacts are done. A ratio that does not is a finding: either a persistent
  difference (exclusions at cap) or a peer that cannot answer.
- Step E adds the Attestation plane's 0.6M refs and, more importantly, ends its
  per-round walk reads toward peers in sync.

## 11. Decisions and open questions

### 11.1 Decided (2026-11-22)

| # | Question | Decision | By |
|---|---|---|---|
| 1 | The fingerprint | The modular sum now, as `"a":1`; `"a":2` reserved for the ristretto255 multiset hash (§2.8) | Eric |
| 2 | The order | The envelope hash (§2.1) | team lead, on the recommendation |
| 3 | Unknown peers | Speculative RF: an unknown peer gets an RF Summary, and one that answers without `rf` is marked legacy at once (§6.1). This covers the `rf` nodes only, never the compact encoding (§12.3) | Eric |
| 4 | `legacy_resweep_every` | 1 h default; `0` = unpaced (§6.3) | Eric |
| 5 | Descent | One step per round; the #634 round shape is kept (§2.6) | team lead |
| 6 | The receiver's set | Restricted to what it may serve the sender (§2.4, §3.2, §4.4.6) | team lead |
| 7 | Want carry-over | Only on canary evidence that `diff_want_in` ≫ `deliver_rows_out` persists (§5.4, step C) | team lead |
| 8 | The Attestation plane | On the LTS: built in step D, switched on in step E (§4.4, §10.1) | Eric |
| 9 | CC questions 1-4 | Ruled 2026-11-22; no CC text change (§7) | CC |
| 10 | Collision hardening | The salted sum Σ H(salt‖id), one salt per link session: 32 random bytes, fresh per session, never derived, carried only in the sealed link; `LinkSums` cached for the link's life. Stays `"a":1` (§2.2, §2.8, R4-R6) | CC, taken by the team lead |
| 11 | Where the construction lives | `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2, with known-answer vectors; CC cites it (R9) | CC |

### 11.2 For the implementation to measure: does a full key listing ever arrive?

**Found, not chased.** On canonical-1 only about one full key listing per link
per ~14 minutes reaches the counters (§1.4), against a 30 s cadence, so most
Key rounds toward the canonical do not end in a listing being sent. A 5 MB Key
Summary is about 3,700 shaped frames on the rate-limited contact lane
(`CONTACT_ENVELOPE_KINDS`, `link_shaping.rs:643-649`). The candidate cause is
that such a Summary does not cross within the round's step timeout, so the
round times out, is abandoned, and backs off. If so, today's key plane is not
only expensive but **not converging**, and range fingerprints fix delivery as
well as cost. Step A measures it before step B ships. Per plane and per role
it books:

- the round outcome (`completed`, `timed_out`, `error`, `abandoned`) against the
  size band of the Summary that round sent (`<16 KiB`, `<256 KiB`, `<1 MiB`,
  `≥1 MiB`), as one counter with closed labels;
- the contact lane's queue depth and drops at the moment a bootstrap-plane
  Summary is enqueued, from the shaper's existing gauges;
- #1025's `replication` cell on the contact lane against the
  `summary_bytes_out` booked for the same planes. If the two diverge, the
  listing was built and counted but never fully sent.

The answer goes into this section before B's canary, so the canary can tell
"RF fixed convergence" apart from "RF saved bytes".

## 12. The ref and body encoding

### 12.1 What a byte costs today

The replication wire is JSON (`protocol.rs:30-37`), and every 32-byte hash and
every body is a `Vec<u8>` or `[u8; 32]`, which serde_json writes as an array of
decimal numbers:

| Item | Wire form today | Size |
|---|---|---|
| a ref (`EnvelopeRef`, `protocol.rs:638`) | `{"envelope_hash":[32 numbers],"seq":N}` | ~154 B (§1.4) |
| a want or a withheld hash (`protocol.rs:690-704`) | 32 numbers | ~114 B |
| a Deliver body (`protocol.rs:787`) | one number per byte | ~3.5× raw (`session.rs:90`) |

Range fingerprints remove most refs and wants, but three things still pay
these prices:
- first contact (a plane listed once);
- the rows of differing ranges;
- every Deliver body.

The bodies are the bigger half of the canonical's tx (§1.4: ~31.7 GB of 63.8).

### 12.2 The options

| Encoding | Hash | Body | Change | Verdict |
|---|---|---|---|---|
| today: JSON number arrays | 113 chars | 3.5× | none | |
| hex strings | 64 chars (2.4× smaller ref) | 2.0× | additive JSON members | simple, but half the gain of base64 |
| **base64url, hashes packed into one string** | **~43 chars** (3.6× smaller ref) | **1.33×** | additive JSON members | **recommended** |
| bodies as raw JSON (`RawValue`) | n/a | 1.0× | additive member | byte-exact only for a JSON body. A body is a signed envelope whose bytes must not change, and the coming CBOR/COSE signed object (CIRISPersist#1205) is not JSON. Left as a later option |
| a binary codec (CBOR frame) | 32 B | 1.0× | a new frame version | the largest gain and the largest change; it belongs with #1205, not in an LTS point release |

**`seq` is dropped in the compact form.** No receiver reads a peer's `seq`:
- `diff_refs` and the holdings index compare hashes only (`summary.rs:738`,
  `holdings_index.rs:635`);
- the proactive push sorts its **own** refs by `seq` (`session.rs:508`);
- the key-plane memo reads its own (`key_plane_memo.rs:734`).

A compact ref is therefore its 32 bytes.

### 12.3 Wire and compatibility

Additive members, decoded into the existing fields on parse. So `local_want`,
salvage, the serve gate, `is_owner_binding_push` (`protocol.rs:808`), and
every consumer of `refs`, `want` and `envelopes` see the struct they see
today:

```text
Summary  "rh":"<base64url of n x 32 bytes>"      beside "refs":[] (both may be present; merged)
Diff     "wh":"<base64url>"  "xh":"<base64url>"  for want and withheld
Deliver  "eb":["<base64url body>", ...]          beside "envelopes":[]
```

- **Capability.** A node that decodes the compact form says so in its marker:
  `"rf":{"v":1,"e":1}`. It ships in step A, ahead of any sender.
- **No speculation for the encoding.** Unlike the `rf` nodes (decision 3), a
  compact member is sent only to a peer that advertised `"e":1`. An old peer
  would read an empty `refs` and an empty Deliver: harmless for `refs`, but an
  empty Deliver would drop bodies. Legacy and unknown peers keep today's form
  in full.
- **No version change.** Frames stay v3. The members are additive, and an old
  peer ignores them, as it ignores `status` and `withheld` (§2.5).
- **Raw-frame readers.** Two places read replication frames without the full
  decode:
  - the shaper's lane classifier, `is_contact_replication_frame`
    (`link_shaping.rs:668`), which also classifies an Attestation Deliver by its
    bodies;
  - #1025's frame classifier (`wire_bytes.rs`, `classify_link_frame`).
  Both must call the same decode for `eb`. Otherwise a compact Deliver of
  consent grants would be classed `sync` instead of `contact`. Witness 13
  (§9) pins this.
- **Counters.** `deliver_bytes_*` keep counting raw envelope bytes, so their
  history stays comparable. A new `deliver_wire_bytes_*` label counts the
  encoded form (§8).

### 12.4 What it saves

```text
per ref       154 B -> ~45 B      (first contact, listed ranges)
per want      114 B -> ~43 B
per body      3.5 x raw -> 1.33 x raw
canonical-1 Deliver tx, 42 h: ~31.7 GB -> ~12.0 GB toward capable peers
a first-contact Key listing, 33k refs: ~5.1 MB -> ~1.4 MB
```

Base64 costs one pass over the bytes on each side, negligible beside the JSON
number formatting it replaces.

## 13. Named requirements

Each is a MUST, and each has a witness in §9.

- **R1. The audience filter comes before the sum and the count.** Every
  fingerprint a node sends is computed over exactly the set of rows that peer
  may receive on that plane in that range: S_A(P) for a sender, T_B(A) for a
  receiver. The filter is applied before the sum and before the count, and the
  count is in the preimage. A construction that subtracts exceptions from a
  shared base is allowed only on two conditions: the exceptions are a subset of
  the base, and they are salted with the same link salt. Then the `(sum,
  count)` entering the outer hash are bit-identical to filtering first. Never
  filter, truncate or correct after hashing. Witness 15.
- **R2. Fingerprints are per peer.** No sum, count, fingerprint or cached root
  is shared between peers or reused across peers whose audiences differ. What
  may be shared is unsalted membership only (`RangeIndex`, class membership,
  placement audiences, §3.1, §4.4.3), which is never sent. Every salted value
  belongs to one link session, and a link session belongs to one peer.
  Witness 15.
- **R3. A match counts holders, on both sides.** When a range matches, the
  sender counts the receiver as a holder of every id of its own set in the
  range, and the receiver counts the sender as a holder of every id of its own
  set in the range. Both are booked through the match feed (§5.7), to every
  consumer that reads holders from rounds, once per change of the matched set.
  Witness 14.
- **R4. The salted sum.** `"a":1` is `e(x) = SHA-256("CIRIS-RF-v1/elem" ‖ salt
  ‖ x)`, summed mod 2^256 with the count and closed by the node hash of
  `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2. An unsalted sum is never sent.
  Witness 18.
- **R5. The salt is fresh, random, per link session, 32 bytes.**
  - The sender draws the salt from the OS CSPRNG when a link session is
    established: every new session, a re-established one included, and every
    process start.
  - It is never derived from anything stable: no key, key id, node id, link id,
    link hash, round id, counter or clock.
  - It is 32 bytes (CC's floor is 16).
  - A link session's `LinkSums` may be cached for that session's life and are
    discarded with it.
  - On HTTPS, where there is no link, a session is the transport's connection
    session with the peer, with a new salt on each new session and at least
    hourly.

  Witness 16.
- **R6. The salt never leaves the sealed link.**
  - It travels only in RF Summaries on that link: the first of the session and
    every one after, so a lost first frame cannot strand the receiver.
  - It travels only on a transport that is confidential end to end: the E1
    per-link seal (`src/transport/link_seal.rs`, AES-256-GCM per direction) or
    HTTPS.
  - Where neither holds, the node sends no RF Summary.
  - The salt is never logged, put in a metric, persisted, or returned across
    the FFI.

  Witness 17.
- **R7. The receiver's set stays inside "would not want" and inside what it may
  serve the sender** (§2.4, decision 6). Safety needs the first; no disclosure
  needs the second. Witnesses 3 and 10.
- **R8. Fail to the legacy listing, never to a wrong answer.** If an input is
  not ready, the node sends or answers the legacy way and never fingerprints:
  a holdings index not `Ready`, no `LinkSums` yet, or a volatile verdict
  unread (§3.4, §4.4.4). Witnesses 2, 6 and 12.
- **R9. The bytes are the FSD's.** The construction and its known-answer
  vectors live in `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2. Any change is a
  new `"a"` value, never an edit of `"a":1`. Witness 18.
