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
  per peer session, sent only over a confidential transport (§6.4). The order
  is the envelope hash itself, not a cursor (§2.1).
- **Who sends what.**
  - The **sender** sends fingerprints of the rows it would offer today, the
    root in every Summary (§2.4).
  - The **receiver** compares them against its **listed mirror**: the ids
    that sender has listed to it, intersected with what it would not want. It
    answers each range `match`, `split` or `list`.
  - The receiver never sends a fingerprint, count or id of its own. Its
    split/list choice is one bit about its count over ids the sender listed
    (§2.3).
  - Ids are listed only for small or mostly-missing ranges, in the existing
    `refs` field. `Diff`, `want`, `Deliver`, salvage and the serve gate are
    unchanged.
  - Answers are bound to the Summary they answer (§2.6).
- **Wire.** One nested, optional, leniently parsed `rf` member on each of
  `Summary` and `Diff`, declared after `kind`. No `WIRE_PROTOCOL_VERSION`
  change, no new verb (§2.5).
- **Where the fingerprints come from.** In memory, in edge, with no persist
  API: the sender from the key-plane memo's listing and the holdings index's
  route records. Membership is shared; the salted sums are per peer
  (`PeerSums`). The receiver works from the holdings index and its mirror. An
  in-sync round costs one root comparison and **zero store reads** (§3).
- **The audience.**
  - The sender's set is its offer to that peer. Rows with an unread verdict
    are denied until read.
  - The receiver's set holds only ids the sender listed, so only rows the
    sender may receive.
  - A match never hides a row the sender offers, and nothing is revealed that
    a legacy listing and Diff do not reveal (§2.4, §4).
- **Scope: all of it on the LTS.** First the five bootstrap planes: `Key`,
  `IdentityOccurrence`, `TransportDestination`, `Revocation`,
  `IdentityOccurrenceRevocation`. They carry 201.1M of the canonical's 201.7M
  listed refs in 42 h (§1.4). Then the `Attestation` plane, also on 45.1.x
  (Eric, 2026-11-22). Its audience classes and volatile rows are designed in
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
- **Effect on canonical-1.** Of the 42 h's 63.8 GB tx, Summary JSON on the
  bootstrap planes is about 25-31 GB and Deliver bodies as JSON number arrays
  about 25-32 GB. The accounting does not close, which suggests some counted
  bytes never left (§1.4, §11.2). In sync, range fingerprints cut the first to about
  95 MB (ceiling 0.75 GB). Compact bodies cut the second to about 12 GB toward
  capable peers (§10.2, §12).
- **CC has ruled** (2026-11-22, §7): a fingerprint is a compressed ref list,
  not a holding claim; the Attestation plane is allowed, mixed-audience ranges
  included, so long as each fingerprint covers only rows that peer may
  receive. No CC text changes. The construction and its known-answer vectors
  are in `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2, which CC cites.
- **Named requirements** R1-R16 (§13) carry CC's conditions, the hardening
  and the independent review's fixes:
  - the audience filter goes before the sum and the count;
  - fingerprints are per peer, by type;
  - a match feed books what a match proves, on both sides;
  - the salted sum, with a fresh 32-byte per-peer-session salt;
  - answers bound to their Summary, and the root in every Summary;
  - completion, staleness and pacing that read a two-way root match;
  - salt-churn limits.
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
the wire **[inf]**.

**The accounting does not close, and that is itself a finding** (review,
plausible item 6). The two figures together are about 62.5 GB at the
application layer, before any framing, and `push_bytes_out` is not even in
them. If 63.8 GB is interface truth, that leaves about 1.3 GB, and that is too
little for what every frame pays:
- RNS packet headers and link tokens (tens of bytes a packet on a ~400-byte
  MDU);
- the E1 seal (25 B a frame: version, counter and tag);
- Resource control and retransmits;
- announces.

Edge does not compress: leviculum's bz2 Resource compression is a cargo
feature edge does not enable, and E1-sealed bytes would not compress anyway.
Two explanations are open, and they may both hold:
1. the 3.5× body factor and the ~154 B ref are averages that overstate this
   corpus;
2. bytes are **counted but never reach the interface**. `summary_refs_out` is
   booked when `transport.send` returns `Ok` (`coordinator.rs:1314-1330`), which
   is when the frame is handed down, not when it leaves.

The second is §11.2's hypothesis. So these figures are ranges, not a closed
sum: Summary JSON ≈ 25-31 GB and Deliver ≈ 25-32 GB of the tx. CIRISEdge#1025
(`feat/1025-transport-bytes`, `src/wire_bytes.rs`), with interface truth per
transport, will settle it. Either way, range fingerprints address the Summary
share and compact encoding the Deliver share (§12).

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
| Per-peer projection = shared set ± a few rows | O(exceptions) over a shared membership index (the salted sums are per peer session, §3.4) | a per-peer tree, or per-peer leaf recomputation |
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

- The **sender** A sends nodes `(prefix, count, fp)` over its set S_A(B)
  (§2.4). Every Summary includes the root (R11). A also sends ids (`refs`): the
  head rows (§5.1), and the ranges it lists completely, which it names in `lc`.
- **Fingerprints exclude this Summary's own listed ids, on both sides.** Every
  node's sum and count are computed over the set minus the ids this Summary
  carries in `refs`. The sender subtracts them from S_A, and the receiver
  subtracts them from T_B. Those ids are compared one by one through the Diff
  instead. So a head row B lacks does not make the root differ, and a churning
  plane still matches (review finding 11).
- The **receiver** B computes `fp(T_B(A), prefix)` for each node and answers
  per node:
  - `match`: equal.
  - `list`: differ, and either A's count is at most `RF_LIST_ROWS` = 16, or B's
    count is at most half of A's and A's count is at most one page.
  - `split`: differ otherwise. A range larger than a page is always split,
    never listed (finding 3).
- B never sends a fingerprint, a count or an id of its own. **What its answers
  do reveal:** the choice between `split` and `list` is one bit about B's
  count in that range. The count is over T_B(A), which contains only ids A
  itself listed to B (§2.4), so that bit is a fact about A's own listed rows.
  Today's Diff already tells A, id by id, which of its listed rows B lacks.
- A lists a range without being asked only when it holds at most
  `RF_UNASKED_LIST_ROWS` = 2 rows. Otherwise it waits for a `list` answer
  (finding 11).

### 2.4 The two sets, and the safety rule

- **S_A(B)**, the sender's set, is the legacy offer to B, with two changes and
  no others:
  - minus any row whose verdict for B is not yet read. Such a row is **denied**
    until its gate runs, within `RF_GATE_BUDGET` per round (§4.4.4, finding 4).
    That delays it the way the legacy page delays a row it has not reached; it
    never hides the row;
  - plus, optionally, rows B is **known to hold**. The one instance is the #738
    receipted-file gate, ignored under RF (§4.4.1 row 5): a superset made only
    of rows B holds changes no match and discloses nothing.
- **T_B(A)**, the receiver's set, is `settled_B ∩ M_B(A)`:
  - **`M_B(A)`, the listed mirror**, is the set of ids A has listed to B on that
    plane, kept per `(peer, plane)` (§3.2). An id enters when A lists it, as a
    head row or in any listed range. An id leaves when A lists a range
    completely (`lc`) without it, which is A saying it no longer offers that id
    to B;
  - **`settled_B`** is what B would not want: its holdings, plus the #1252
    held-equivalent refs, plus refusals still in backoff (#544), plus the known
    hashes on a `HashFirst` plane (#552). On the removal planes (`Revocation`,
    `IdentityOccurrenceRevocation`) it is the holdings only (R13, finding 5).

**Safety.** Write L for this Summary's listed ids. If
`fp(S_A − L, p) = fp(T_B − L, p)` then, up to a collision,
`(S_A − L) ∩ p = (T_B − L) ∩ p ⊆ settled_B`, and every id of L is compared by
the Diff. So a match never suppresses a row the sender currently offers. The
proof needs only `T_B ⊆ settled_B`.

**Convergence when B holds more than A offers (finding 1).** That is the
normal case on the bootstrap planes: a phone offers a handful of rows and holds
33k. Because T_B counts only ids A listed, B's extra holdings are never in it.
Once A has listed a range completely, B's mirror of that range equals S_A ∩ p.
If B holds all of it, the range matches. Nothing has to be excluded, evicted or
re-learned, so a range does not re-open on its own. The owner's-node case is
the same rule on every plane (finding 1b). The canonical offers O's phone the
rows of O's unannounced desktop X; they are in the phone's mirror because the
canonical listed them, so the range matches.

**Disclosure.** Each side reveals no more than a legacy listing and Diff do.
- The sender fingerprints only rows it would list to B.
- The receiver's answers are functions of `settled_B ∩ M_B(A)`: per id, they
  depend only on whether B would want an id that A itself listed. That is
  exactly what today's Diff reveals, because the receive diff is peer-blind
  (`local_want` over the peer-blind holdings, `session.rs:820-828`, #414).
- The one bit of §2.3 is about the same ids.
- A `HashFirst` node's known hashes and B's refusals enter T_B only if A
  listed them, so the answers open no oracle on rows A never named (finding 6).

CC ruled on 2026-11-22: a fingerprint is a compressed ref list, not a holding
claim, provided it covers only rows the peer may receive (§7, R1).

### 2.5 Wire shape

Additive members on the two existing messages (`protocol.rs:651`,
`protocol.rs:690`). `rf` is a **nested** optional member, omitted when absent,
like `withheld` (a plain `#[serde(default, skip_serializing_if =
"Vec::is_empty")]` member, `protocol.rs:701-702`). It is not flattened like
`status` (`protocol.rs:668`), which would put `v`, `a` and `salt` at top level
(finding 14).

- **Lenient parsing.** `rf` is parsed leniently: as a JSON value first, then
  into its type. A shape this build does not understand reads as no `rf` and
  is counted (`rf_parse_failed`). A later change to `rf`'s inner types can
  therefore never fail the Summary that carries it.
- **Old peers ignore it.** There is no `deny_unknown_fields` on this path
  (`protocol.rs:662-667`, pinned by
  `summary_status_is_flat_optional_and_tolerant_937`).
- **Field order.** `rf` is declared after `kind`, so `kind` stays within the
  first 256 bytes the shaper's lane classifier reads (`link_shaping.rs:680-684`).

```text
Summary (RF sender, in sync):
{"type":"summary","kind":"identity_occurrence","refs":[],
 "rf":{"v":1,"a":1,"salt":"<43 b64url>","sid":118,"n":[["",33012,"<32 hex>"]]}}   ~ 185 B

after a split of "3f": the root again, plus one packed record per split parent
 "rf":{…,"n":[["",33012,"…"]],"c":[["3f",[c0..c15],"<16 x 32 hex>"]]}           + ~610 B / split

a complete listing of "3f2a": its ids in refs (or compact "rh", §12), named in lc
 "rf":{…,"lc":["3f2a"]}

Diff (RF receiver):
{"type":"diff","kind":"identity_occurrence","want":[],
 "rf":{"v":1,"sid":118,"m":[""],"s":[],"l":[]}}                                   ~ 85 B
unable this round:  "rf":{"v":1,"sid":118,"u":"unbooted"|"salt"|"cap"|"busy"}
```

- `sid` numbers the sender's RF Summaries per `(peer, plane)`, across both
  roles. Every answer echoes it (§2.6, finding 7).
- A marker with no nodes (`"rf":{"v":1}`) on a legacy Summary or Diff says "I
  answer RF". `"e":1` in it says "I decode the compact encoding" (§12.3).

### 2.6 The round: one step of the descent per round, bound to its Summary

**[new] `RangeFrontier`**, per `(peer, plane)`, is pure state like
`SweepCursors` (`bridge.rs:1963`): no directory, no clock, no I/O.

- **Every Summary sends the root** (R11, finding 8). It also sends the
  children of the nodes last answered `split`, and the complete listings of the
  ranges last answered `list`. A leaf that can never match (a #429 unfetchable
  row, a want that never lands) therefore cannot hide the rest of the plane: a
  change anywhere else still makes the root differ, and the descent toward it
  starts.
- **It moves only on an answer.** A Summary that is lost, timed out or shed
  leaves the frontier where it was. Nothing moves on a listing, so the #1020
  rewinds (`round_ended`, `rewind_to`, `listing_delivered`,
  `bridge.rs:2063-2124`) have nothing to undo on an RF plane.
- **Answers are bound to their Summary** (R10, finding 7):
  - The sender keeps the last `RF_SNAPSHOTS` = 4 Summaries per `(peer, plane)`,
    each recorded as `sid → {prefix → fp as sent}`.
  - An answer whose `sid` is not among them is dropped
    (`rf_answers_stale`).
  - A `match p` is applied only if the sender's current `fp(p)` still equals
    the fingerprint sent. Under the salt, equal fingerprints mean the same set,
    so a match is never applied to rows added since. Otherwise it is stale: p
    stays on the frontier.
  - `split` and `list` are applied in `sid` order. An older one never undoes a
    newer one.
  - The initiator's and responder's Summaries share the `sid` sequence, so the
    two roles fold into one frontier without overtaking each other.
- **A listed range stays on the frontier** as a node until it answers `match`.
  That carries deferred Deliver remainders, transient refusals and lost frames
  (§1.3 items 1-3).
- **A leaf that keeps failing is parked.** If a leaf has been listed
  `RF_LEAF_RETRIES` = 4 times with the same wants and still does not match, it
  is parked with exponential backoff (to 1 h). That covers an unfetchable
  #429 row or a refusal loop. The root still covers it, and any change to it
  un-parks it.
- **Bounds.** At most `RF_MAX_SPLITS_PER_SUMMARY` = 16 packed splits (~10 KB)
  and at most the effective page (`sweep_page_rows` under the host's page
  lever) of listed refs per Summary; the rest waits a round. Frontiers are
  LRU-capped like `MAX_TRACKED_SWEEP_CURSORS` (`bridge.rs:1986`). An evicted
  frontier restarts at the root, which costs one descent, never a row.
- **The salt and the frontier are separate.** The frontier is prefixes only.
  The receiver answers each Summary with the salt that Summary carries (§6.4).

One RTT per round, exactly as today. The Session state machine and the #634
round shape (`session.rs:458-470`) do not change. The one gate that depended on
a full listing, the #380 initiator-final completion, is re-keyed in §5.6.

### 2.7 Costs

For a plane of n = 33k rows, fan-out 16, `RF_LIST_ROWS` 16: a level-3 range
holds about 8 rows, so a difference is listed at level 3 on a `list` answer.
Split records are ~610 B; a listed ref is 154 B as JSON, ~45 B compact (§12).

| k random differences | RF, whole descent, JSON refs | RF, compact refs | One legacy listing (JSON / compact) |
|---|---|---|---|
| in sync | ~185 B Summary + ~85 B Diff per round | same | 5.1 MB / 1.5 MB **every listing** |
| 1 | 3.2 KB over 5 rounds | 2.4 KB | |
| 10 | 24 KB | 15 KB | |
| 100 | 184 KB | 97 KB | |
| 1,000 | 1.26 MB | 0.49 MB | |
| 10,000 | 4.8 MB | 1.5 MB | 5.1 MB / 1.5 MB |

The descent's cost is paid **once per difference**. A legacy listing's cost is
paid on every listing, whether or not anything changed. The crossover for a
single descent is near k ≈ n/3, and there B's `list` rule (it holds at most half)
turns the descent into a paged listing, so RF never costs much more than one
legacy listing.

**First contact, and a receiver restart.** The mirror (§3.2) is in memory, so a
new pair, or a receiver after a restart, has an empty `M_B(A)`. Its root
differs, the two top levels split (they are larger than a page), and A then
lists the plane one page per round, once. That is the legacy first walk, and
it is paid once per receiver restart, not once per listing. For a phone that
restarts, the canonical lists its whole offer once: ≈ 140k refs, ≈ 6.3 MB
compact. Persisting the mirror would remove that cost; it is left for after
the LTS (§11.3).

### 2.8 Lying peers and collisions

- **B lies `match`.** B loses rows it would have been offered, and that is B's
  loss only. B also gets booked as a holder by the match feed (§5.7). On the
  removal planes that booking is a distinct, weaker class, never a delivery
  ack (R13).
- **B lies `split`/`list` forever.** A lists, at most a page per round: never
  more than today's listing.
- **B churns its salt or its answers to burn A's CPU.** Bounded by §6.4.
- **A lies.** A can make B answer `split` and must then list to make progress.
  Every listed row is gated by the serve gate, and every delivered row by
  admission, so A cannot inject a row. A can also churn the salt to burn B's
  CPU: §6.4's first-salt rule, rebuild token bucket and node cap bound it.
- **A third party forges a collision.** CC flagged it, and it is real for an
  unsalted sum. A peer connected to both A and B can mint rows whose hashes sum,
  with the counts balanced, to a target (Wagner's generalized birthday is cheap
  in hash evaluations). That would make an A–B range match while B lacks a row.
- **The salted sum closes it.** Each element is `e(x) = SHA-256(tag‖salt‖x)`.
  The salt is 32 fresh random bytes per peer session, sent only inside a
  confidential transport (§6.4, R5-R6).
  - A third party cannot compute any `e(x)` toward that peer, so it cannot
    prepare a set.
  - A row it mints lands at a value it cannot predict.
  - A random collision of the 128-bit truncation is 2^-128 per comparison.
  - Only A and B know the salt, and either can already lie (above).
- `"a":1` is this salted sum. `"a":2` stays reserved for a ristretto255
  multiset hash.

## 3. Where fingerprints come from

### 3.1 The sender's trees

The sender keeps two kinds of structure.

**[new] `RangeIndex`**, one per session plane, shared across peers. It is
**membership only**: the plane's hashes sorted into 4,096 leaf buckets (three
hex digits), each hash with the labels the per-peer filter reads (the subject
on the identity planes, §4.4.2's labels on the Attestation plane). It holds no
sum, no count and no fingerprint, so nothing salted or peer-specific is ever
shared (R2).

**[new] `PeerSums`**, one per `(peer, plane, salt)` (§6.4), owned by one peer
(R2).
- It holds 256 level-2 buckets of salted sum and count, over exactly that
  peer's set: `RangeIndex` filtered by the peer's audience before summing (R1).
- A node at depth ≤ 2 adds buckets.
- A deeper node hashes the members of its level-2 bucket in that peer's set,
  about 130 at 33k rows.

| Plane | Built from | Rebuilt when |
|---|---|---|
| `Key`, `Revocation`, `IdentityOccurrenceRevocation` (peer-invariant membership) | the plane's complete listing from `key_plane_listing` (`bridge.rs:8193`): the listing cache when it hits (`bridge.rs:8204-8222`), else the listing just built | the memo's generation moves (`key_plane_memo.rs:575`); "generation moves on every change to what the memo would answer" (`key_plane_memo.rs:357-362`) |
| `IdentityOccurrence` | the shared listing over the publish set, minus, per peer, the refs of its #682 withheld subjects (memo lookups) | as above; the per-peer patch is cached against `(generation, withheld set)` |
| `TransportDestination` | the holdings index's route records (`holdings_index.rs:325`, which already keep each route's subject "so the stranger view … can later filter by owner"), filtered by the listing's predicate: subject in the publish set, or `relayable_signed_route` (`bridge.rs:8572`). Only the row-intrinsic bit (`relayable`) is stored at feed time; "subject in the publish set" is evaluated when the index is rebuilt, against the current publish set, so it cannot go stale. Then minus the peer's #682 subjects | each route feed delta, and every publish-set change (which moves the generation through `check_advertise_inputs`, `bridge.rs:4386`) |

**The tree is the listing.** The set the tree sums is the set
`list_envelope_refs_for_peer` would have returned: a subject the memo's read
budget left unread (`KEY_PLANE_READ_BUDGET` 256, `key_plane_memo.rs:296`) is
absent from both. So S_A equals today's offer by construction.

The `RangeIndex` is rebuilt once per memo generation: one unsalted pass, at
most once per feed probe (`FEED_PROBE_SPACING` 5 s, `store_feed.rs:86`) plus the
TTL epoch (`MEMO_TTL` 10 min, `key_plane_memo.rs:97`). Each live `PeerSums`
is then updated **incrementally** by the generation's delta: the rows added and
removed are hashed with that peer's salt and added or subtracted. A full salted
pass happens only when a new salt is drawn (§3.4, §6.4).

### 3.2 The receiver: settled set and listed mirror

**`M_B(A)`, the listed mirror.** It is per `(peer, plane)` and lives in
memory.

- **Representation.** A sorted set of 8-byte id prefixes, bucketed like the
  `RangeIndex`. A truncated id that matches a settled id A never listed only
  enlarges T_B by an id B holds: that costs efficiency, never safety, and it
  happens with probability about n²/2^64.
- **An id enters** when it is in any RF Summary's `refs` from A: a head row or
  a listed range.
- **A range is replaced** when A lists it completely and names it in `lc`:
  the mirror's ids in that range become exactly the ids listed. Ids A has
  stopped offering leave this way.
- **Capped.** A hostile peer could list made-up ids to grow the mirror, so it
  is capped per `(peer, plane)` at 262,144 ids (2 MiB) and node-wide at
  32 MiB. A peer at the cap gets `"u":"cap"` on that plane, and the pair goes
  legacy; this is counted in `rf_mirror_capped`. Nothing is evicted, so no
  range re-opens because of an eviction.
- **Sizes.** A phone's mirror of the canonical is the canonical's whole offer,
  ≈ 140k × 8 B ≈ 1.1 MiB. The canonical's mirror of a phone is the phone's
  handful of own rows. A seat's mirror of another seat is ≈ 1.1 MiB. Restart
  semantics are in §2.7.

**`settled_B`** comes from the holdings index (`holdings_index.rs`), plus the
small sets of §2.4: held-equivalent refs (`wire_ref.rs:128`), refusals in
backoff (`retry_suppressed`, `bridge.rs:5891`), and `HashFirst` known hashes.
Because T_B is `settled_B ∩ M_B(A)`, no per-plane tagging of the holdings index
is needed. A hash A listed on plane k is the same row wherever B holds it,
because hashes are content hashes. The earlier per-plane tags, and the rule
tagging an untagged hash with A's plane, are gone (review, plausible item 2).

**Effects that carry over from today:**
- **A refusal in backoff** is in T_B while its window runs, so a match keeps it
  unasked, as `want.retain(!retry_suppressed)` does today
  (`session.rs:844-852`). When the window ends it leaves T_B, the range
  differs, and A lists it. The row is re-asked about one descent after its
  window, instead of when the re-sweep next passes it (`FSD/EVENT_PATH_MODEL.md`
  §1.2: "The row waits for an offer, not for its window").
- **A `HashFirst` known hash** is in T_B only once A has listed it to B
  (finding 6). Today's `HashFirst` Diff clears `want` (`session.rs:899-907`),
  and the mirror rule keeps that: A learns nothing about B's known hashes
  beyond its own listed ids.
- **On the removal planes** `settled_B` is the holdings only (R13): a refused
  or merely known revocation never matches as if held.

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

**Memory.** Typical is the canonical with ~17 active peers; worst is 135
peers, four of them seats with full mirrors, every cap reached.

| Structure | Typical | Worst |
|---|---|---|
| `RangeIndex`, all planes (membership + labels, §3.1, §4.4.2) | ≈ 7 MiB | ≈ 7 MiB |
| `PeerSums` (256 × 40 B ≈ 10 KiB per `(peer, plane)`, §3.1) | ≈ 1 MiB | 135 × 6 × 10 KiB ≈ 8 MiB |
| Frontiers + `RF_SNAPSHOTS` (≈ 2 KiB per `(peer, plane)` at the split cap) | < 0.5 MiB | ≈ 1.6 MiB |
| Receiver mirrors `M_B(A)` (8 B an id) | ≈ 1 MiB | 4 seats × 6 planes × 33k × 8 B + 131 phones' own rows ≈ 7 MiB |
| Receiver `PeerSums` over `settled ∩ M` | < 0.5 MiB | ≈ 8 MiB |
| Attestation volatile bitsets (§4.4.4) | < 0.1 MiB | 135 × ~2.5 KiB ≈ 0.3 MiB |
| Compact/receiver caches, misc | | ≈ 8 MiB |
| **Total** | **≈ 10 MiB** | **≈ 40 MiB** |

**CPU and store reads in sync.**
- An in-sync round is one root compare per `(peer, plane)` per direction. Every
  sum is cached until its inputs move.
- Store reads: none. The listing cache hits (§3.1); the holdings index answers,
  and a clean feed is not probed within `FEED_PROBE_SPACING`.

**The CPU cost of the salt.** One element costs one SHA-256 over 80 bytes: two
compressions, about 0.2 µs with SHA extensions and ≈ 0.5 µs without (the
conservative figure used here). The canonical's offer across all six planes at
today's sizes is about 140k rows:
- Key 33k;
- IdentityOccurrence ≤ 33k;
- TransportDestination ~18k;
- Revocation and IdentityOccurrenceRevocation ≤ 7.2k each;
- Attestation 42.5k.

A receiver's pass is over `settled ∩ M_B(A)`, which is only as large as what
that peer listed to it.

| Salt scope | When the full salted pass runs | Canonical cost |
|---|---|---|
| **per peer session (R5, recommended)** | sender: once per new salt per peer, i.e. at session start, on reconnect, and at least hourly, then O(delta) per memo generation. Receiver: once per salt it accepts (§6.4) | sender ≈ 70 ms per salt per peer, so at the hourly floor 135 peers × 70 ms / 3,600 s ≈ 0.3% of a core, plus reconnects. Receiver: tiny for phones (their own rows), ≈ 70 ms per seat peer per salt. Deltas: 10 new rows × 17 peers = 170 hashes ≈ 85 µs per generation |
| per round | every round, per peer, per role | 17 peers × 2 roles × 70 ms per 30 s ≈ 8% of a core for the sender alone, ≈ 16% with the receiver, and over 100% if all 135 peers were active |

The per-session salt is cheaper by the number of rounds a session carries:
twenty for a ten-minute session, 120 for the hourly floor. Counters
`rf_peersums_built` and `rf_peersums_build_ms` (§8) measure the real rate. A
round never waits for a build: until a peer's sums exist, that round sends a
legacy Summary (R8).

**Fail to the old behaviour, never to a wrong answer** (R8).
- The receiver answers `"u"`, and the sender lists that peer the legacy way
  next round, when the holdings index for the plane is not `Ready` (unbooted,
  booting or suspect, `holdings_index.rs` "Failing to the old behaviour"), or
  when a salt or cap rule refuses (§6.4).
- The sender sends a legacy Summary when its listing failed or the peer's sums
  are not yet built.

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
  still per peer session, so per peer (R2).
- `IdentityOccurrence`, `TransportDestination`: shared membership minus the
  peer's #682 subjects, filtered before the per-peer salted sum (R1): "an unannounced node's occurrence and route go only to
  its owner's own nodes" (`bridge.rs:5282-5285`). The exception set is
  `identity_rows_withheld_from` (`bridge.rs:15182`), the same function the
  listing applies, so the sender's fingerprint excludes exactly what its
  listing would.
- The receiver needs no rule of its own. T_B(A) is `settled_B ∩ M_B(A)`, so an
  unannounced node's row is in it only if A listed it to B, and A lists it only
  where #682 lets it. That covers the owner's-node case (finding 1b): the
  canonical lists O's desktop rows to O's phone, and the phone's mirror counts
  them.

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
| 5 | #738 `receipted_by_peer` (3756) | the peer receipted the file | (row, peer) | per row read | **ignored**: an instance of §2.4's rule that S_A may be the legacy offer plus rows B is known to hold. The peer receipted the row, so it is in T_B, and the range matches |
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

A peer's `PeerSums` (§3.1) is the salted sum and count, bucket by bucket, of
exactly S_A(P) as computed above, with that link's salt (R1, R2). Its 256
buckets are about 10 KiB a peer, and deeper nodes hash the members of
S_A(P) in the bucket. The subtractions in the formula act on membership, or on
salted values under the same salt. Either way the `(sum, count)` that enter
the outer hash are bit-identical to summing the filtered set, and witness 15
checks every sent node against that filter-first reference.

Membership is shared across peers; sums never are. A peer's `PeerSums` is
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

**An unread verdict denies (review finding 4).** A round re-reads at most
`RF_GATE_BUDGET` = 256 volatile verdicts per `(peer, round)`, absent ones before
expired ones, as the key-plane read budget does (`key_plane_memo.rs:296`). A
volatile row with no valid verdict is treated as **denied** for that peer: it is
left out of S_A(P) and out of every fingerprint, exactly as if its gate had
refused.
- **The root is always sent** (R11). There is no pending bucket and no "fresh
  cover". The earlier draft's cover revealed that a volatile row existed in a
  three-hex-digit bucket, and when one arrived, even a row the peer would be
  refused, which CC 5.2 does not allow.
- **What a denial costs.** Delay only. Once the verdict is read and is yes, the
  row joins S_A(P), the range differs, and the descent lists it through the
  real gates. That is the legacy page's delay for a row the walk has not yet
  reached (§2.4).
- **Bounded.** In steady state a verdict expires only by its TTL, so the
  re-reads come to about `n_volatile / (TTL / cadence)` a round, spread. With
  no dirt and no TTL due, a round does zero gate reads.

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

The rule of every plane: `T_B(A) = settled_B ∩ M_B(A)` (§2.4, §3.2). B
evaluates no gate for A. The mirror holds only rows A listed to B. A holds every
row it lists, and "a node holds a row only when it is in that audience" (CC 5.2,
`part_5_transport_substrate.md:103`). So T_B covers only rows A may receive,
which is CC's condition, by construction. This replaces the earlier draft's
"servable" computation, its exclusions and its learned inclusions.

A row B holds in a group A is not in never enters `M_B(A)`, because A never
lists it. It therefore cannot make a range differ, and B's answers do not
depend on it. Witness 19 checks both.

#### 4.4.7 Bounds

| | Memory | Idle round |
|---|---|---|
| Labels | ≈ 64 B a row: ≈ 2.7 MiB | none |
| Class membership | in the plane's `RangeIndex`: 32 B a row plus labels | none |
| Placement audiences | one node set per placement | none: dirt-driven |
| Per peer | `PeerSums` ≈ 10 KiB per plane; volatile bitset `n_volatile` bits; the mirror `M_B(A)` (§3.2) | root compare |
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
  (`merge_salvaged`, `coordinator.rs:721`).
- A late reply's `rf` answers are **not** dropped wholesale. They are applied
  under §2.6's binding: by `sid`, and for a `match` only when the node's
  fingerprint is unchanged. That is what keeps a NAT'd initiator's descent
  moving when its replies arrive after the round ended (§5.6).
- The listing marks and rewinds (`listing_mark`, `coordinator.rs:1171`;
  `rewind_to`, `bridge.rs:2100`) remain for head listings and for legacy peers.
  RF state needs none (§2.6).

### 5.6 The #380 initiator-final gate, the proactive push, and "peer lacks nothing"

**The gate as it stands.** A proactive-publish initiator completes its round
early (`SendAndComplete`) when two things hold, both read from
`last_remote_summary` (`session.rs:553-565`):
- `peer_holds_all`: the peer's last Summary lists every ref we would push;
- `want_nothing`: `diff_refs(refs, remote.refs)` is empty.

**Why it breaks under RF (finding 2).** An RF Summary's `refs` are head rows
only, so both tests are nearly always true. A phone would complete every round
at once. The canonical's `Summary_R` and `Diff_R` would then arrive after the
round, and the descent would stall.

**[new] For an RF peer the gate reads the descent instead:**
- `peer_holds_all` holds only if our last RF Summary's root was answered
  `match` at our **current** generation (§2.6 binding);
- `want_nothing` holds only if we answered `match` on the peer's root at the
  peer's latest `sid`.

Both directions must be root-matched. Otherwise the round waits for the reply
as any round does. For a legacy peer the gate is unchanged. The proactive
push's candidates likewise skip our refs only after a root match, not on the
strength of `last_remote_summary`.

**`peer_lacks_nothing`** (`coordinator.rs:1077-1079`) counts root matches for
an RF peer, never an empty Diff. Under RF an empty Diff only means "nothing
listed this round was wanted".

### 5.7 The match feed: holders from matched ranges, on both sides (R3)

CC's condition: any consumer that reads "peer P holds id x" from rounds must
still count P as a holder of every id in a range that **matched**, on both
sides. Otherwise rarity reads low for exactly the best-replicated rows. The
reviewer's correction is that **a match is not a holding**: T_B contains
refusals in backoff, held-equivalents and known hashes. So the feed carries
what a match does prove, and labels it as such.

**Where holders are read from ref lists today [read]:**

| Consumer | Reads | Site |
|---|---|---|
| the removal receipt ledger (#441) | every hash of a peer's Summary on a removal kind, as "the peer's own statement of holdings" | `coordinator.rs:1110-1120` → `observability.rs:4722` |
| the known-hash holder map (#552) | the hashes a peer offered that this node lacks, with the peer as holder | `session.rs:903` → `bridge.rs:5168-5194` |
| the proactive push | the peer's last Summary | `session.rs:493`, `session.rs:553-565` |
| `peer_lacks_nothing` | an empty Diff | `coordinator.rs:1077-1079` |

The noise-floor and rarity machinery does **not** read replication refs
today:
- holder counts come from signed `FountainHoldingClaim` envelopes
  (`swarm/runtime.rs:467` `upsert`, `:503` `distinct_holders`, `:531`
  `weighted_holder_equivalents`);
- the read side taps that claim plane (`holonomic/converged_view.rs`);
- the `AggregationMetaV1` producer (`holonomic/aggregation.rs`) is fed by it.

So range fingerprints cannot lower today's rarity counts. The feed keeps that
true for the four consumers above, and for any producer that later reads
holders from rounds.

**[new] The event**, emitted by each side when it applies or gives a `match`:

```text
RangeMatched { peer, plane, side: Sender | Receiver, sid, prefix,
               generation,   // the set's generation at the compared snapshot
               ids }         // the compared snapshot's ids in the range, lazily
```

- **Sender side.** A applies `match p` (bound as in §2.6: same `sid`, same
  fingerprint). Then B would not want any id of S_A ∩ p: B holds them, or holds
  them as equivalents, or is refusing them for now.
- **Receiver side.** B answers `match p`. Then A offers every id of T_B ∩ p,
  and A holds what it offers.
- **Booked over the compared snapshot only.** The ids are those compared:
  - on the sender, S_A ∩ p at the sent `sid`, which is the current set because
    the fingerprint is unchanged;
  - on the receiver, T_B ∩ p computed and booked in one step when it answers.

  No id added since is booked (finding 7).
- **Once per change.** The feed fires for `(peer, plane, prefix)` only when the
  matched generation differs from the last one booked. A root matching round
  after round costs nothing after the first.
- **What each consumer may conclude:**
  - **Removal ledger (R13).** On the removal planes T_B is the holdings only
    (§3.2), so a match means "holds". It is booked as `acked_by_match`, a class
    distinct from the Summary ack, over ids A had listed to B before. A lying B
    can therefore claim only rows it was shown, as with a listing today.
  - **Holder map.** A refreshes `last_advertised` for its known hashes in p
    whose holder is A, on the receiver side. B is a holder, or refuses, so the
    sender side books nothing here.
  - **Future rarity producers.** They receive `side`, and use only `Receiver`
    events (the sender holds what it offers), or `Sender` events on planes
    where T_B is holdings only. That is the same evidence a listing gives
    today, never more.
  - **The push and `peer_lacks_nothing`** read root matches (§5.6).

### 5.8 Known hashes on conferred servers (#552)

On a `HashFirst` plane a known hash is in T_B once A has listed it (§2.4). The
match feed refreshes its holder when A's range matches, so the holder map ages
only when A's set changes. A known hash that does age out leaves T_B, its range
differs, and the next listing re-teaches it with its holder.

### 5.9 First contact

Two RF peers full-list each other once, as a legacy first walk does, and
never again. A new peer's mirror is empty, so the root differs. The two top
levels are larger than a page, so they are split (R14). Their level-2 children
are answered `list`, because the peer holds at most half, and A lists them a
page per round. The frontier then returns to the root and stays there. A
receiver restart costs the same once (§2.7). The bootstrap planes'
attribution path (#393/#402) sees the same rows in the same order of rounds as
on a legacy first walk.

### 5.10 The shaped and onion tiers

Every verb on the five bootstrap planes rides the shaped **contact** lane
(`CONTACT_ENVELOPE_KINDS`, `src/transport/link_shaping.rs:643-649`), and CC
5.4.3 shapes all maintenance traffic. A 5 MB Key Summary is about 3,700
1,400-byte frames on a rate-limited lane; an in-sync RF exchange is one frame
each way. Nothing in the shaping or onion wire changes; replication frames are
sealed application frames to both.

### 5.11 Staleness and first sync (finding 9)

**Today.**
- `StalenessSignal::InSync` comes from the round's want count: a round that
  wanted nothing, or admitted all it wanted, is in sync
  (`session.rs:1452-1462`).
- `first_sync` marks itself done on the first idle in-sync round
  (`coordinator.rs:1362-1367`).

Under RF both would read "in sync" in the middle of a descent: a split round
lists nothing, so it wants nothing.

**[new]** For an RF peer:
- `InSync` holds only when the root matched in **both** directions at current
  generations (§5.6's test);
- a descending round reports `BoundedBy` with `missing` = the open frontier
  nodes' count difference, or `Unknown` when that is not known;
- `first_sync` completes only at the first two-way root match.

The signal is then stronger than today's: a match proves the whole plane, not
one page.

## 6. Compatibility

### 6.1 Capability, in band

- **Where.** Not CTKX: it negotiates a link's shaping (`ShapingOffer`,
  `link_shaping.rs:1042`) and runs before the seal, per link. Not the v3
  preamble: its reserved `FLAGS` bits are refused when set
  (`wire_frame.rs:173`, `wire_frame.rs:343`). Not the bundle, which names
  seats, not versions. **In the `rf` members themselves**, which old peers
  ignore (§2.5).
- **Learning.** A node that answers RF puts the marker on its anti-entropy
  Summaries and Diffs. A node with the sender on sends RF Summaries to a peer
  whose marker it has seen in the current peer session (§6.4).
- **Speculation (decision 3).** To a peer with no known capability, the sender
  sends an RF Summary with the root. An old peer reads the head refs and diffs
  them, harmlessly. Its Diff carries no `rf` answer, and the sender marks it
  legacy at once. The compact encoding is never sent speculatively (§12.3).
- **Downgrade.** A Diff that answers an RF Summary without an `rf` answer marks
  the peer legacy, as when a peer restarts onto an old build. A Pull's answer
  is never read this way (§5.2).
- **Kept in memory**, per peer, for the current peer session (§6.4). A restart
  on either side re-learns it in one round.

### 6.2 The fleet as it is

Long-soak peers are deliberately old, among them edge v18.7.0 and Datum.
A pre-v26 peer speaks only v1/v2 legacy frames with no round id
(`wire_frame.rs:115`, `wire_frame.rs:199`); it is never sent an RF Summary at all, because it
never opens a v3 round. Every other old peer is detected as in §6.1.

### 6.3 Pacing the legacy re-listing

**[new] `BridgeConfig::legacy_resweep_every`, env
`CIRIS_EDGE_LEGACY_RESWEEP_SECS`, default 3600 s, `0` = unpaced (the 45.1.9
behaviour).** Read once at runtime assembly; an unparseable value is ignored
with a WARN, as `ADVERTISE_SWEEP_PERMITS_ENV` is.

**When it paces (finding 10).** Toward a `(peer, plane)` marked legacy, with
range fingerprints on, pacing applies only once that pair has gone **quiet**:
the last complete re-listing cycle produced **no** wants and left **no**
deferred Deliver remainder. Until then the pair is unpaced. This matters
because a legacy peer short of rows gets its remainder only from the next
re-listing (`session.rs:76-81`). Pacing a peer still catching up would hand it
one 512 KiB Deliver per hour per plane. Any want or remainder in a cycle
clears the quiet state.

When the pair is quiet:
- **Watermarked planes:** a re-sweep cycle may start no sooner than this long
  after the previous cycle started. `after_head` returns no backfill page while
  `backfill` is at the beginning and the cycle is not due. The head page runs
  every round. A no-walk peer's history pages, which wrap too, get the same
  bound.
- **Key planes:** the full listing at most once per interval. In between, only
  the head ring's rows (§5.1).
- The cycle start time joins `ResweepCycle` (`bridge.rs:1818`), injected as
  `now`, so `SweepCursors` stays pure.

**What a quiet old peer loses.** A row it refuses transiently, or a frame it
loses, is re-offered at the next cycle, at most an hour later. A peer that is
catching up loses nothing. At the measured rate of one full key listing per
link every ~14 minutes (§1.4), the default cuts a quiet legacy peer's key-plane
listings about 4×.

The knob is local "less of its own optional work", which CC 4.2.1.4 lets a
node do without any row. It is not a mesh-config key.

### 6.4 The salt: per peer session, and its limits (findings 12, 13)

**Why not per link session (finding 13).** `src/replication` has no link
identity: the Session builds a message, and the transport picks the link
afterwards, a pooled or reverse-path one. A per-link salt therefore cannot be
written where `rf` is built, and R6 could not be enforced there.

**[new] The salt is per peer session** (recommended; the team lead is
confirming with CC):
- It is drawn by the sender as 32 bytes from the OS CSPRNG. Each `(peer,
  sending process)` holds one salt, drawn fresh:
  - at process start;
  - when the peer reconnects, meaning the transport reports a live link to the
    peer after a period with none (the same evidence that clears the #794
    no-route backoff, `scheduler.rs` module docs, "A peer with no route
    backs off");
  - at least once an hour.
- It is never derived from anything stable: no key, key id, link id, link
  hash, round id, counter or clock.
- It rides in every RF Summary of the session.

**R6 is enforced where `rf` is built.** RF Summaries are built only for a peer
the transport reports as confidential end to end, through a new
`Transport::confidential_to(peer) -> bool`:
- **Reticulum: always.** "There is never a plaintext edge frame in either
  direction" (`src/transport/link_seal.rs` module docs, E1 enforced at once).
  Every pooled or reverse-path link is sealed, so it does not matter which link
  the transport picks.
- **HTTP: only when the peer's target is `https`.** The HTTP transport allows
  TLS-terminating front ends (`src/transport/http.rs:19-32`), so plain-HTTP
  peers get legacy Summaries.

**Limits a hostile peer cannot get past (finding 12):**
- **The first salt wins.** A receiver accepts one salt per peer session. A new
  salt is accepted only if `RF_SALT_MIN_AGE` = 10 min has passed since the last
  one accepted, or the receiver itself saw the peer reconnect. Otherwise it
  answers `"u":"salt"` and the round goes legacy.
- **A rebuild token bucket**, per peer: 3 rebuilds, refilled at one per 20 min.
  It is joined by a node-wide cap of 2 concurrent rebuilds; beyond either,
  `"u":"busy"`.
- **A node cap per Summary.** A receiver evaluates at most 64 nodes and 16
  split records per Summary. Anything beyond is answered `"u":"cap"`. Honest
  senders stay under it (§2.6).
- **Counted:** `rf_salt_changes_received`, `rf_rebuilds_refused`,
  `rf_answers_cap`.

The reply lane's byte budget (`reply_lane.rs`) does not need to change. The
cost a peer can impose is now bounded by the token bucket, not by how many
frames it sends.

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
link. The fix is the salted sum Σ H(salt‖id). CC asked for the salt to be
per link session, drawn fresh and random for every session (re-established ones
included), never derived from anything stable, 32 bytes, and carried only
inside the sealed link. CC agreed to caching for the link's life.

The independent review (finding 13) showed that a per-link salt cannot be
written where `rf` is built: the replication layer has no link identity. This
revision therefore makes the salt **per peer session** (§6.4) and keeps every
other property:
- 32 bytes from the OS CSPRNG;
- fresh at process start, on the peer's reconnect, and at least hourly;
- never derived from anything stable;
- sent only where `Transport::confidential_to(peer)` holds: every Reticulum
  frame is E1-sealed; on HTTP, only `https` targets.

**The team lead is confirming this change with CC.** It is R4-R6, and it stays
`"a":1`; ristretto255 remains `"a":2`.

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
| `rf_mirror_ids` | gauge | plane | ids held in all receiver mirrors `M_B(A)` (§3.2) |
| `rf_mirror_capped` | counter | plane | pairs sent legacy because a mirror reached its cap (§3.2). It replaces the review's "exclusions evicted" counter: the mirror evicts nothing |
| `rf_answers_stale` | counter | plane, reason = `sid_unknown` / `fp_changed` / `out_of_order` | answers dropped by §2.6's binding |
| `rf_salt_changes_received`, `rf_rebuilds_refused`, `rf_answers_cap` | counter | plane | §6.4's limits |
| `rf_parse_failed` | counter | message | `rf` members this build could not read (§2.5) |
| `rf_leaf_parked` | counter | plane | leaves parked after `RF_LEAF_RETRIES` (§2.6) |
| `replication_io` `summary_refs_built`, `summary_bytes_built` | counter | plane | Summaries as built, booked before `transport.send` (§11.2, finding 15) |
| `rf_tree_rebuilds`, `rf_tree_build_ms` | counter | plane | sender rebuilds and their cost |
| `rf_receiver_unable` | counter | plane, reason = `unbooted` / `booting` / `suspect` | §3.4's fallbacks |
| `legacy_resweep_paced` | counter | plane | backfill pages and key listings skipped by §6.3 |
| `replication_io` `deliver_wire_bytes_out`, `deliver_wire_bytes_in` | counter | plane, encoding = `json` / `b64` | Deliver bytes as encoded on the wire, beside the raw `deliver_bytes_*` (§12.3) |
| `rf_round_outcome_by_size` | counter | plane, role, outcome, size band | §11.2's measurement: does a large Summary's round complete |
| `rf_attestation_denied_unread` | gauge | walk class | volatile rows currently denied for want of a verdict, all peers (§4.4.4) |
| `rf_attestation_gate_reads` | counter | cause = `absent` / `dirt` / `ttl` | volatile verdicts re-read, by why (the #1019x attribution shape) |
| `rf_peersums_built`, `rf_peersums_build_ms` | counter | plane, role = `sender` / `receiver` | full salted passes on each new salt, and their cost (§3.4) |
| `rf_peersums_delta_hashes` | counter | plane | salted hashes spent on memo-generation deltas |
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
2. `RangeFrontier`: in sync, every Summary is the root alone, and every
   Summary carries the root; with k planted
   differences the frontier lists exactly the differing leaves within
   depth + 1 answers; a lost answer leaves the frontier unchanged; a duplicate
   or stale answer costs at most one node; eviction restarts at the root; the
   split and listing caps hold.
3. The receiver's set: for random inputs `T_B ⊆ settled_B` always (the safety
   rule as a property). `M_B(A)` gains every id A lists and is replaced by a
   complete listing. A backoff's expiry makes its range differ in the next
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
    the `withdraws` is fed. An expiring grant is out at its `expires_at`. A row
    with an unread verdict is in no fingerprint, and the Summary's nodes are
    identical whether or not such a row exists (no cover, no bucket signal).
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
    the same salt get different fingerprints whenever their sets differ. The
    type-level guarantee of R2: `PeerSums` yields only a `PeerFingerprint`
    carrying its peer, and the Summary builder refuses one for another peer.
    A unit test pins that refusal, and a compile-fail test pins that no
    accessor returns a bare sum.
16. **Fresh salts (R5).**
    - Two peer sessions of the same pair draw different salts: the peer
      disconnects and reconnects, the hourly rotation fires, and the process
      restarts. Two different peers never share a salt.
    - The salt is 32 bytes.
    - It is not equal to any value derivable from the pair's keys, key ids,
      link id, link hash or round ids. The test computes the obvious
      derivations (hashes and HKDFs of each) and asserts none matches.
    - A source scan asserts the salt is produced only by a call to the OS
      CSPRNG.
17. **Never outside a confidential transport (R6).** `confidential_to` is
    true for every Reticulum peer and false for an `http://` peer. Toward an
    `http://` peer no Summary carries `rf`. The Reticulum send path seals every
    frame, which the E1 suite already witnesses. The salt appears in no log line, metric
    label, persisted row or FFI return (a source scan, as `log_citations`
    does).
18. **Known answers (R9).** The implementation reproduces the six vectors of
    `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2, byte for byte.

**From the independent review of 6f49541** (each witness seeds the case that
broke, never identical sets on both sides):

19. **Asymmetric sets converge (finding 1, 1b).**
    - Case 1. A offers 50 rows and B holds those 50 plus 30,000 more, on `Key`
      and on `Revocation`. Case 2 is the reverse.
    - Case 3. The canonical offers O's phone the IO and TD rows of O's
      unannounced desktop.
    - In every case: the root matches within depth + 2 rounds and stays matched
      for 50 idle rounds with zero listed refs. B's mirror is never larger than
      what A listed.
    - The same on the Attestation plane, where B holds rows of groups A is not
      in. B's answers are unchanged by them: receiver-side R1 and R7.
20. **Legacy fallbacks (R8).** `"u"` makes the next round toward that peer a
    legacy Summary. No `PeerSums` yet (a fresh salt, a build pending) gives a
    legacy Summary at once, without waiting. An unread volatile verdict leaves
    its row out of S_A(P), and the root is still sent.
21. **Stale answers (finding 7).** Interleave initiator and responder Summaries.
    Deliver an old `match p` after a newer `split p`, and a `match` for a node
    whose set has gained a row since. Neither drops p, and neither books the
    new row in the match feed. Each is counted in `rf_answers_stale`.
22. **One stuck leaf hides nothing (finding 8).** Plant an unfetchable #429 row
    in one leaf, then add a row elsewhere. The new row is listed and delivered
    within depth + 2 rounds. The stuck leaf parks after `RF_LEAF_RETRIES`.
23. **The #380 gate (finding 2).** A proactive-publish initiator toward an RF
    responder never returns `SendAndComplete` before a two-way root match. Its
    descent completes even when every `Summary_R` arrives after the round
    ended.
24. **Staleness and first sync (finding 9).** While descending, no round
    reports `InSync`, and `first_sync` is not done. Both turn at the first
    two-way root match.
25. **Paging (finding 3, 11).** A `list` answer for a range larger than a page
    produces its children, never a listing. A split's 16 children are sent as
    fingerprints, and only children of two rows or fewer are listed unasked.
    Planting one difference in 33k rows lists at most 16 refs.
26. **Pacing throughput (finding 10).** A legacy peer that is 30,000 rows short
    receives them at the unpaced rate (one Deliver budget per round). Pacing
    starts only after a quiet cycle.
27. **Salt churn (finding 12).** A peer that sends a new salt in every Summary
    gets `"u":"salt"` after the first. It costs the receiver at most 3 rebuilds
    plus one per 20 min, and never more than 2 at once node-wide. Summaries
    over the node cap get `"u":"cap"`.
28. **The measurement (finding 15).** A Summary built and then refused by
    `transport.send` is booked in `summary_bytes_built` and not in
    `summary_bytes_out`.

**Gates** (per the repo's rules): run every integration suite the change can
reach, the source-scan suites (`log_citations` and its siblings), the wide
clippy lane with `RUSTFLAGS=-D warnings` over the four feature sets, and the
DST (`src/replication/sim.rs`) with frame loss on an RF pair, filtered runs
only on this host.

## 10. Rollout

### 10.1 The sequence

Each step ships alone. A comes before B and C. D needs A's receiver plumbing
and B's index, `PeerSums` and frontier. E needs D's canary. R1-R16 (§13) are in
force from the first step that sends or answers a fingerprint: A for answers,
B for sends.

| Step | Ships | Switch | Default |
|---|---|---|---|
| A (45.1.10) | the byte labels of §8 (`summary_bytes_*`, `diff_bytes_*`, `deliver_wire_bytes_*`); §11.2's measurement; the receiver half on the bootstrap planes: plane tags in the holdings index, `settled_B`, the `rf` answers, the marker; **decoding** of the compact encoding (§12), advertised as `"e":1` | `CIRIS_EDGE_RANGE_FINGERPRINTS_ANSWER` | **on**: it answers only when asked and costs only memory |
| B (45.1.11) | the sender half on the five bootstrap planes: trees, frontier, head ring, capability, §5.6-5.8's adjustments, §6.3's pacing toward legacy peers; **encoding** of compact refs, wants and bodies toward peers that advertised `"e":1` | `CIRIS_EDGE_RANGE_FINGERPRINTS`; `CIRIS_EDGE_COMPACT_WIRE` for §12 | **off**; on for the canary on canonical-1 |
| C (45.1.12) | the sender and encoding defaults flipped, on the canary's numbers; want carry-over only if the canary shows `diff_want_in` ≫ `deliver_rows_out` (decision 7) | as B | on |
| D (45.1.13) | the Attestation plane, both halves (§4.4): row labels, class membership, placement audiences, volatile verdicts (an unread verdict denies), the required-row memo, learned inclusions | `CIRIS_EDGE_RANGE_FINGERPRINTS_ATTESTATION` | off; on for the canary |
| E (45.1.14) | D's switch on. CC has ruled (§7), so no fallback applies | as D | on |

The receiver half ships first because the canonical can only save bytes toward
peers that answer, and phones update on the agent's release train. For the
same reason compact decoding ships in A and encoding in B.

### 10.2 What the canonical's numbers should do

Against the 42 h of §1.4, with every peer on step A and the canonical on B:

```text
Summary tx on the five bootstrap planes, today          ~ 25-31 GB (§1.4)
RF in sync: per pair 3 planes x 2 roles x 120/h x 42 h  = 30,240 Summaries
            x 185 B (salt and sid included)             ~ 5.6 MB per pair
            x 17 concurrent links                       ~ 95 MB
            ceiling: x 135 identities, always on        ~ 0.75 GB
plus each difference once (§2.7: 2.4 KB compact for an isolated one),
plus one paged listing per receiver restart (~6.3 MB per phone, §2.7)

Deliver bodies on the wire, today (9.05 GB raw x ~2.8-3.5)  ~ 25-32 GB
compact bodies (base64url, x 1.33)                          ~ 12.0 GB

tx, today                                               63.8 GB
tx after steps B and C, every peer capable              ~ 13-20 GB  (about -70% to -80%)
```

- `summary_refs_out` on `key`, `identity_occurrence` and `transport_destination`
  falls from 201.1M to the head rows plus the rows of differing ranges.
- Range fingerprints alone remove most of the Summary share, about 25-31 GB
  (≈ 40-48% of tx). Compact bodies remove another ≈ 13-20 GB toward capable
  peers. The ranges are §1.4's: the accounting does not close until #1025
  measures interface truth. Peers that stay legacy
  keep today's body encoding. #1025's ledger confirms both against interface
  truth.
- `diff_want_in` falls from 26.0M toward the rows listed per round (§5.4). On
  rx, most of `summary_refs_in`'s 3.5 GB goes as peers' own offers go RF, and
  wants shrink 2.7× in compact form.
- Toward peers that stay legacy: key-plane listings about 4× fewer at the
  default pacing (§6.3).
- The in-sync ratio (§8) should sit near 1 on the five planes once first
  contacts are done. A ratio that does not is a finding: either a persistent
  difference (a parked leaf, `rf_leaf_parked`) or a peer that cannot answer.
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
| 10 | Collision hardening | The salted sum Σ H(salt‖id), 32 random bytes, fresh, never derived. CC asked for it per link session; after review finding 13 it is per peer session, sent only over confidential transports, with `PeerSums` cached for the session (§6.4). Stays `"a":1` (§2.2, §2.8, R4-R6) | CC, taken by the team lead; the per-peer scope is being confirmed with CC |
| 12 | Review of 6f49541 | All 15 confirmed findings fixed in this revision; each plausible item addressed in §11.3 | reviewer, team lead |
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
- the Summary as **built**, booked when it is built, before `transport.send`
  (`summary_refs_built`, `summary_bytes_built`). Today `summary_refs_out` is
  booked only after `transport.send` returns `Ok` (`coordinator.rs:1314-1330`,
  `book_served` → `book_io`), so a listing built and never sent is invisible
  (review finding 15);
- #1025's `replication` cell on the contact lane, as interface truth. The
  three numbers (built, handed to the transport, crossed the interface) are
  compared per plane. Where they diverge, the listing was built or handed
  down and never fully sent.

The answer goes into this section before B's canary, so the canary can tell
"RF fixed convergence" apart from "RF saved bytes".

### 11.3 The review's plausible items, and what is left for after the LTS

| Item (review of 6f49541) | Disposition |
|---|---|
| `"e":1` remembered across a peer's restart | **Adopted:** `e` lasts one peer session, and proactive pushes are always JSON (§12.3) |
| Tagging untagged hashes with A's plane | **Removed:** T_B is `settled ∩ M_B(A)`, and content hashes need no plane tag (§3.2) |
| "A listed it, so A holds it" is a claim | **Stated:** the baseline is today's peer-blind receive diff (`session.rs:820-828`, #414). RF reveals per id only what a Diff reveals about ids A listed (§2.4) |
| The "half" rule is a count oracle | **Stated:** one bit per range about T_B, which contains only ids A listed. Harmless now that finding 6 is fixed (§2.3) |
| The TD publish-set bit goes stale | **Adopted:** only row-intrinsic bits are stored at feed time; publish-set membership is evaluated at each index rebuild (§3.1) |
| The 1.3 GB residual is too small for framing | **Adopted:** §1.4 now gives ranges and names "counted but never sent" as an open explanation, for #1025 to settle |
| Memory, typical and worst | **Stated:** ≈ 10 MiB typical, ≈ 40 MiB worst (§3.4) |
| More known-answer vectors | **Adopted:** V2 wraps mod 2^256; V7 and V9 use 3- and 8-character prefixes; V8 is a non-root range with count 0 (FSD §3.4.2) |

**After the LTS.** Persisting the receiver's mirror `M_B(A)` would remove the
one full listing a receiver restart costs (§2.7). It stays in memory for 45.1.x,
because a mis-persisted mirror can only cost efficiency, never correctness, and
persistence is a store-schema change.

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
- **No speculation for the encoding, and `e` lasts one peer session.** Unlike
  the `rf` nodes (decision 3), a compact member is sent only to a peer that
  advertised `"e":1` **in the current peer session** (§6.4), on a message
  received in that session. A peer that restarted on an old build therefore
  never receives a compact Deliver on the strength of an `e` it advertised
  before the restart. **A proactive push is always sent in the JSON form.** It
  goes out before any message from the peer in this round, and
  `proactive_sent` would otherwise stop re-pushing for
  `PROACTIVE_REFRESH_ROUNDS` (`session.rs:337`) a body the peer never
  read. (Review, plausible item 1.) An old peer
  would read an empty `refs` and an empty Deliver: harmless for `refs`, but an
  empty Deliver would drop bodies. Legacy and unknown peers keep today's form
  in full.
- **No version change.** Frames stay v3. The members are additive and
  leniently parsed, and an old peer ignores them, as it ignores `status` and
  `withheld` (§2.5).
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

Each is a MUST. Each has a witness in §9.

- **R1. The audience filter comes before the sum and the count.**
  - **Sender.** Every fingerprint is computed over exactly S_A(P) (§2.4) minus
    this Summary's listed ids, in that range. The filter is applied before the
    sum and before the count, and the count is in the preimage. Subtracting
    exceptions from a shared base is allowed only when the exceptions are a
    subset of the base and salted with the same salt; then the `(sum, count)`
    are bit-identical to filtering first.
  - **Receiver.** It sums exactly `settled_B ∩ M_B(A)` minus the listed ids.
  - Never filter, truncate or correct after hashing. Witnesses 15 and 19.
- **R2. Fingerprints are per peer, by type.**
  - No sum, count, fingerprint or cached root is shared between peers, or
    reused across peers whose audiences differ.
  - What may be shared is unsalted membership only (`RangeIndex`, class
    membership, placement audiences), and it is never sent.
  - Every salted value lives in a `PeerSums` owned by one `(peer, plane,
    salt)`. The only way to obtain a fingerprint is a method on that value
    returning a `PeerFingerprint` that carries its peer. The Summary builder
    accepts a `PeerFingerprint` only for the Summary's own peer, a check in the
    one constructor.
  - Witness 15.
- **R3. A match feeds holders on both sides, as what it proves.** On a match,
  each side emits `RangeMatched` over the compared snapshot's ids (§5.7). It is
  emitted once per change of the matched set. Consumers book it as a match,
  never as a Summary listing. Witness 14.
- **R4. The salted sum.** `"a":1` is `e(x) = SHA-256("CIRIS-RF-v1/elem" ‖ salt
  ‖ x)`, summed mod 2^256, with the count, closed by the node hash of
  `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2. An unsalted sum is never sent.
  Witness 18.
- **R5. The salt is 32 bytes, random, fresh per peer session, never derived.**
  - It is drawn from the OS CSPRNG at process start, on the peer's reconnect,
    and at least hourly (§6.4).
  - It is never derived from a key, key id, node id, link id, link hash, round
    id, counter or clock.
  - It is never reused across peers: each peer gets its own draw.
  - The team lead is confirming with CC that per peer session, rather than per
    link session, meets CC's rule, since the replication layer has no link
    identity (§6.4).
  - Witness 16.
- **R6. The salt is sent only where the transport is confidential.**
  - An RF Summary is built only when `Transport::confidential_to(peer)` holds:
    always on Reticulum, where every frame is E1-sealed, and only on `https`
    targets over HTTP (§6.4).
  - The salt is never logged, put in a metric, persisted, or returned across
    the FFI.
  - Witness 17.
- **R7. The receiver's set is `settled_B ∩ M_B(A)`.** It holds only ids A
  listed (the disclosure rule) and only ids B would not want (the safety rule).
  Witnesses 3, 10 and 19.
- **R8. Fail to the legacy listing, never to a wrong answer.** If an input is
  not ready, the node sends or answers the legacy way and never fingerprints:
  - a holdings index not `Ready` (`"u"`);
  - no `PeerSums` yet;
  - a salt or cap refusal.

  An unread volatile verdict is a denial (§4.4.4).
  Witnesses 2, 6, 12 and 20.
- **R9. The bytes are the FSD's.** The construction and its known-answer
  vectors live in `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2. A change is a new
  `"a"` value, never an edit of `"a":1`. Witness 18.
- **R10. Answers are bound to their Summary** (§2.6).
  - Each answer echoes the Summary's `sid`.
  - A `match` applies only if the node's fingerprint is unchanged since it was
    sent.
  - `split` and `list` answers apply in `sid` order.
  - Witness 21.
- **R11. Every RF Summary carries the root.** Witness 22.
- **R12. The early-completion, staleness and first-sync signals read a two-way
  root match**, never an empty want (§5.6, §5.11). Witnesses 23 and 24.
- **R13. Removal planes.** On `Revocation` and `IdentityOccurrenceRevocation`,
  `settled_B` is the holdings only, and a match is booked as `acked_by_match`
  over ids A had listed to B (§5.7). Witness 14.
- **R14. Never list a range larger than a page; list unasked only at two rows
  or fewer** (§2.3). Witness 25.
- **R15. Legacy pacing starts only once a pair is quiet** (§6.3). Witness 26.
- **R16. The salt-change and rebuild limits of §6.4.** Witness 27.
