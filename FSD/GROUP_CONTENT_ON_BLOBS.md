# FSD: Group Content on Blobs — CIRISEdge

**Status:** **LOCKED** — every open question answered on CIRISPersist#836.
Not implemented; CIRISEdge#586 is the first consumer, and the design is
deliberately not chat's.

**Substrate:** CIRISPersist **v44.1.0** (`FSD/BLOB_ENCRYPTION_AT_REST.md`
§11–§12, §12.9–§12.10, I41–I42), CIRISVerify v15.1.0
(`aes_gcm::{encrypt_aad, decrypt_aad}`).

---

## 1. What this is

One content pattern for **every group-scoped blob edge will ever write** —
a chat message, an attached file, a video, a log bundle, an A/V recording.
Not a chat design that others might later borrow.

The reason to write it once is that the parts that are easy to get wrong are
identical for all of them, and they fail the same way: **silently, months
later, on a read.** A blob whose associated data was built differently on
the write path than the read path does not fail at write. It fails when
someone opens a two-year-old video, and by then the writer that produced it
has shipped.

So this document fixes three things that every content type must answer the
same way:

1. **Which scope** the content is written at, and where membership comes from.
2. **Which shape** — one sealed body, or a sealed chunk DAG.
3. **What the AAD preimage is**, exactly, byte for byte.

Everything else — media type, retention, who may see it — is per-content-type
policy layered on top, and is explicitly *not* fixed here.

---

## 2. What this replaces, and why

Chat today seals its own bodies: `body_key` is HKDF from a `RoomKey`, the
ciphertext goes in `FIELD_BODY`, and a `FIELD_SEALED` header says how it
opens. That was correct when it shipped (v19.0.0) — persist had no encrypted
blob tier, and a room needed confidentiality that the substrate could not
give it.

Three things have changed:

- **persist v43 gave content a cohort-keyed DEK cascade**, so encrypted
  storage is a substrate property rather than an application one.
- **persist v44 (#831) gave the doors caller-supplied AAD**, which is the
  piece that makes an application-level seal genuinely unnecessary rather
  than merely redundant — see §5.
- **Membership is a community roster.** Chat's parallel MLS group is a second
  answer to a question the federation already answers, and two membership
  systems that can disagree will.

The cost of keeping a private seal is not just duplication. Content sealed
under a key persist cannot derive is content persist cannot **recall** — an
epoch destroy sweeps the DEK, and bytes sealed outside that cascade survive
it. A right-to-be-forgotten guarantee that a layer above can silently opt out
of is not a guarantee.

---

## 3. Scope and membership — the roster is the answer

| cohort scope | tier persist resolves | membership source |
|---|---|---|
| `self` | `InvisibleEncrypted` | the node's owner ([[single-owner boundary]]) |
| `family` | `InvisibleEncrypted` | operator-declared family cohort |
| `community` | **`CommunityDek`** | the community roster |
| `affiliations` | `CommunityDek` | affiliation roster |
| `species` / `biosphere` / `federation` | `Plaintext` | commons — public by design |

**Group content means `community` (or `affiliations`), and therefore
`CommunityDek`.** That tier is *mandatory* on persist's side — the shared
epoch DEK is community content's sole confidentiality boundary — and it is
the only tier whose membership is a roster rather than a single owner.

Two rules follow, and both are load-bearing:

- **Edge never invents membership.** The subscriber set for an epoch DEK is
  the roster, resolved through persist. Edge's job is to name the
  `community_key_id`; persist's job is to say who is in it right now.
- **Edge never picks the tier.** It names the `cohort_scope`; the door
  resolves the tier and writes it on the row. §11.1 of persist's FSD is
  explicit that the row is the authority on its own tier, and the reader
  dispatches on the row's column — never on anything the writer asserted.

A two-party room is not a special case. `pair_community_key_id(a, b)` already
derives a stable community id from two federation ids in sorted order; that
id is a `community_key_id` like any other, and the roster machinery treats it
like any other. The 2-party derivation exists so a pair needs no roster
ceremony — not so it can take a different code path.

---

## 4. Shape — one axis, two doors

The only question is whether the content needs **random access or live
append**. Not size, and not media type.

| | whole blob | chunk DAG |
|---|---|---|
| write | `put_blob_scoped(scope, community, plaintext, media_type, aad)` | `put_blob_chunk_scoped(scope, community, stream_id, seq, plaintext, epoch, aad)` then `seal_stream_scoped(…, aad)` |
| read | `read_blob_as(sha, viewer, aad)` | `read_blob_as` for all of it, `read_blob_range_as(sha, viewer, start, end, aad)` for a range |
| live | — | `stream_chunks(stream_id)` |
| use for | chat messages, small files, log bundles read whole | video, audio, large files, logs tailed live |

**Choose the DAG when a reader will want part of it, or when a writer will
append to it while readers are reading.** A 4 KB chat message in a DAG is
waste; a 2 GB video as a whole blob is unreadable, because seek means
downloading and opening all of it.

Notes that are easy to get wrong:

- **Chunk sizes in a v2 manifest are PLAINTEXT**, while each chunk row stores
  `size + AT_REST_ENVELOPE_OVERHEAD` bytes. A plaintext range maps to a chunk
  set by prefix sum over those sizes. Edge's swarm scheduler already checks
  `total_size == Σ sizes` and that check stays correct precisely because both
  sides are plaintext.
- **Relays carry what they cannot read.** Chunks are content-addressed by
  their *ciphertext* sha, so transfer, dedup, and edge's hash verifier are
  unchanged from the plaintext case. A relay never needs the DEK.
- **`External` chunks are not available under an encrypted tier**, and no
  nested DAGs. If content cannot be inlined or chunked, it cannot be group
  content today.

---

## 5. The AAD contract — the part that must not be improvised

Associated data is folded into the GCM tag and **never stored**. Its purpose
is narrow and worth stating precisely: it makes a **ciphertext lifted onto a
different row fail to open**. Without it, a blob is opened by whoever holds
the DEK, and every member of a community holds the DEK — so any member could
move another member's ciphertext under their own row and have it open there.

Three properties of persist's implementation drive everything below:

1. **persist derives nothing.** The `aad` is passed verbatim to every
   `seal`/`open`, including every chunk of a DAG and the manifest. The
   preimage is entirely edge's to define.
2. **`Some(b"")` ≡ `None`.** An empty AAD is byte-identical to no AAD. An
   empty preimage is not a weak binding; it is *no* binding.
3. **`Some(aad)` at a plaintext tier is refused**, not ignored. Commons
   content must pass `None`.

### 5.1 The preimage — LOCKED

```
caller_aad = "ciris.edge.blob.aad.v1" ‖ 0x00
           ‖ lp(author_key_id)
           ‖ lp(asserted_at)          // STORED form — see §5.2
           ‖ lp(field)
```

where `lp(x)` = `be_u32(len(x)) ‖ x`.

- **domain string + `0x00`** — never confusable with another protocol's
  preimage, and the NUL means the version can never run into the first field.
- **`author_key_id`** — a member cannot re-attribute another member's content
  to themselves. The substitution CIRISPersist#830 named.
- **`asserted_at`** — a ciphertext cannot be replayed onto a different row by
  the same author.
- **`field`** — two blobs in one row (a message body and its attachment)
  cannot be swapped for each other.

**Length-prefixing is not decoration.** Plain concatenation makes
`("ab","c")` and `("a","bc")` the same preimage. persist frames this same
preimage the same way for the same reason (§5.5).

### 5.1.1 Why `community_key_id` and `epoch` are NOT in it

An earlier draft included both. **CIRISPersist#836 Q1 answered that they come
out**, and the reasoning is worth keeping because it is not obvious.

They are already bound *cryptographically by the blob itself*: the DEK is per
`(community, epoch)` and the blob row records both, so putting them in the
AAD adds no binding the ciphertext does not already have — it only adds two
more ways for a legitimate operation to break a read.

And they are exactly the two members a legitimate **cross-community
widening** changes.

### 5.1.2 Widening — the premise of the old open question was wrong

That draft asserted `widen_audience` breaks an AAD over
`(author, asserted_at)` because the widened row carries a different instant.
**It does not.** A widening carries `asserted_at` **verbatim** —
`check_widening` compares it like any other body member and `build_widening`
sets it from the prior — and the placement's own instant is the separate
signed member `widened_at` (persist v40.0.0). So a reader rebuilding the AAD
from a widened row computes the same preimage as from the original.

The rule that follows:

- **Widening within one community's DEK is a no-op on the blob.** Same sha,
  same AAD, nothing to do.
- **Widening to commons, or to a community the DEK does not cover, is a
  re-seal.** A `CommunityDek` ciphertext has no business under another tier
  or another DEK. The widened row references the *new* sha — with the *same*
  `(author, asserted_at, field)` AAD, because those did not change.

Blob-bearing rows are widenable. The draft's "must not be widened" rule is
withdrawn.

### 5.2 The reconstruction rule, and the trap under it

> **The AAD is built from the values as STORED, never from the values as
> submitted.**

persist truncates `asserted_at` to the substrate time resolution *before
writing the column*. A writer that seals under `Utc::now()` and a reader that
rebuilds from the row's column are using different bytes, and the read fails
as a crypto error with nothing obviously wrong anywhere.

So the write path MUST truncate first, seal second — using the same
truncation persist applies — and the read path rebuilds from the row. A test
that writes and reads in one process with an already-truncated timestamp
**will not catch this**; the witness has to use a timestamp with sub-resolution
precision.

### 5.3 What must never enter the preimage

Anything a later, legitimate operation rewrites:

- **Signatures and `additional_scrubs`.** `promote_attestation` re-signs with
  the node and clears `additional_scrubs`; an AAD over either would make
  every promoted row unreadable.
- **The row's own hash or id.** Circular: the blob must be sealed before the
  row that carries its sha exists.
- **Anything from the transport or the reader.** The AAD must be identical
  for every authorized reader on every node.

### 5.4 DAG binding — persist frames the preimage and binds position

**As of persist v44.1.0 (#838) this is enforced by the substrate**, not left
to the reader's good behaviour. The preimage in §5.1 is the *caller's* half;
persist wraps it:

```
chunk_aad = "ciris-persist:chunk:v1" ‖ u64_be(len(caller_aad)) ‖ caller_aad
                                     ‖ u64_be(len(stream_id))  ‖ stream_id
                                     ‖ u64_be(seq)
```

Two consequences for this design:

- **A chunk moved to another index does not open.** The gap the v44.0.0 draft
  recorded — one `aad` for every chunk, so intra-DAG reordering was invisible
  to the crypto — is closed.
- **Edge's preimage goes in unchanged, and is length-delimited from the
  position bytes**, so it cannot collide with them. Edge never constructs
  `chunk_aad` itself; it passes `caller_aad` and persist frames it.

The sealed v2 manifest carries `stream_id` and each chunk's `seq`, which is
what a reader needs to rebuild a chunk's AAD.

**Hand-assembling chunks is out of contract — permanently, not "not yet".**
persist was explicit on this: the manifest stays the contract and
`read_blob_range_as` stays the in-contract assembly; #838 makes the contract
enforce itself rather than merely stating it. A sealed stream chunk also no
longer opens by its sha alone — the door is
`read_stream_chunk_as(stream_id, seq, viewer_key_id, aad)`.

### 5.5 `stream_id` — the caller's to make unique, the substrate's to defend

Since persist v44.1.0 (#837) a stream **belongs to its first append**:
`federation_streams` records `(cohort_scope, community_key_id, owner_key_id)`
and every later append is compared against it. An append naming a different
cohort or community is refused **at that chunk**, storing nothing.

- **Derivation:** `<writer derived key id>-<ULID or 128-bit random>`. A
  content hash is not available before the content exists, which is why the
  id cannot be derived from what it names.
- **Uniqueness is still edge's to guarantee**; what the substrate guarantees
  is that a collision is *refused at the second chunk* rather than silently
  interleaving two writers' chunks until the seal catches it.
- **The `MAX_CHUNKS_PER_EPOCH` budget is safe by construction** — a foreign
  writer cannot append at all, so no member can spend another's budget by
  guessing an id.

## 6. Lifecycle — what an epoch does to content

Rotation and recall are the reason this lives in the substrate, so a design
that ignores them has not used the substrate.

- **Rotation is not recall.** Bumping an epoch changes what *new* content
  seals under. Existing content stays readable under its bound epoch, which
  is why `community_dek_bind_blob_epoch` exists and why the epoch is in the
  AAD.
- **Destroying an epoch is recall, and its reach is narrower than it sounds.**
  persist's §11.4 is explicit and this design must not overstate it:
  `destroyed` means *persist's* copies of the key material are gone and
  persist will never serve that content again. The destroy precondition is
  **node-local** — "no object sealed under this epoch" means *on this node*,
  because persist cannot know what peers hold. And a recipient who already
  recovered the DEK from a delivered wrap keeps it; no key-management scheme
  can undo that.

  Recall of copies that already travelled is the **tombstone plane's** job
  (§10.6), not destroy's. That plane reaches every holder because
  `Tombstone` / `MonotonicSupersede` project at their plane's
  `tombstone_ceiling` regardless of scope — but only if that ceiling is at
  least as wide as shards can travel. persist calls that "a gate, not a
  convention", and edge is the side that fountains the shards.

  **The decided value: `Global` for `CommunityDek` blob shards until
  CIRISEdge#581 lands, then `Cohort`.** `Cohort` is the right ceiling *once
  shards stay in the cohort* — and today they do not, because edge has a
  serve gate and no store gate, so the converger can push a shard to a node
  outside the community. A `Cohort`-ceiling tombstone does not reach that
  node, and the violation is silent. persist exposes `crypto_tier` on every
  blob row and every `holds_bytes` announcement, so the ceiling choice keys
  off the tier without a new primitive.

  This makes #581 a **prerequisite for narrowing the ceiling**, not only for
  claiming recall — the wide ceiling is the interim cost of not having it.

  **Status:** the gate itself now exists
  ([`blob_swarm::store_gate`](../src/blob_swarm/store_gate.rs)) and is wired
  into the swarm's fetch path ahead of any byte transfer. It is UNARMED by
  default and says so once per process, because arming it changes what a
  running deployment accepts. Narrowing the ceiling to `Cohort` waits on the
  gate being armed in the field AND on the converger's push path being
  covered, not merely on the gate compiling.

  What a private application seal opts out of is therefore not "recall" in
  the absolute — it is *persist's* half of it, which is the half that is
  actually enforceable.
- **Eviction retracts what it announced.** A swept blob answers `Evicted` to
  an authorized reader — "swept", not "never ours". Edge's serve path maps
  that to a miss on the wire (CIRISEdge#587), because the peer's correct
  action is to fetch elsewhere either way.
- **Rotation reaches only as far as edge's store gate**, which does not exist
  yet (CIRISEdge#581). Until it does, edge can accept content it should not
  retain, and no amount of correct sealing fixes that. #581 is a prerequisite
  for claiming the recall guarantee end-to-end, not an optimization.

---

## 7. What the row carries

The row stops carrying content and starts carrying a **pointer plus the
binding inputs** — everything a reader needs to rebuild the AAD, and nothing
that reveals the content.

| member | why |
|---|---|
| `community_key_id` | which community to read as; NOT an AAD input (§5.1.1) |
| `content_sha256` | the at-rest sha to read |
| `content_field` | which field this blob is; **AAD input** |
| `media_type` | so a reader knows what it got before opening it |
| `stream_id` | present iff chunked — the DAG's stream (§5.5) |

`author_key_id` and `asserted_at` are already envelope members and are the
other two **AAD inputs**; they are not duplicated.

The **epoch is deliberately absent**. It is recorded on the blob row's own
binding, it is not an AAD input, and carrying it on the referencing row would
create a second copy that a rotation can make stale. A reader asks the blob,
not the pointer.

Whether the content is chunked is answered by `stream_id`'s presence rather
than by a separate boolean — one fact, one member, no way for the two to
disagree.

`FIELD_BODY` / `FIELD_SEALED` / `SEAL_ALG` and the `RoomKey` body-key
derivation are **retired** by this design, not kept as a fallback. A fallback
that can still open content is a second confidentiality boundary, and
[[fallbacks-mask-gates]] is the recorded lesson: removing one is what exposes
the gates that were only ever green because the fallback caught them.

---

## 8. Migration

Ordered so that each step is independently reversible until the last one.

1. **Read-new-write-old.** Teach readers to resolve a blob pointer, while
   writers still seal inline. No behaviour change; proves the read path.
2. **Write-new for new rooms only.** New content goes to blobs; existing rooms
   are untouched. The two shapes coexist, distinguished by which members the
   row carries.
3. **Backfill.** Existing sealed bodies are opened under the room key and
   re-written as blobs, one community at a time, under the epoch current at
   backfill time.
4. **Retire the inline seal.** Delete `body_key`, `seal_body`, `open_body`,
   and the room-key derivation. Only now does the fallback go.

Step 3 is the only irreversible one and the only one that needs the room key
at all — which is the point: after it, the room key has no readers.

---

## 9. Invariants

Each one falsifiable through a door a consumer holds, per persist's §11.10
discipline.

| # | invariant |
|---|---|
| **G1** | A ciphertext moved to a row with a different `author_key_id`, `asserted_at`, or `field` does not open. |
| **G1b** | A ciphertext survives a widening: a row widened within its community's DEK opens the SAME blob, and a widening that crosses the DEK re-seals and references the new sha. |
| **G1c** | A sealed chunk moved to another `seq` does not open (persist's frame, #838) — asserted at edge's boundary so a substrate regression is caught here rather than inferred. |
| **G2** | The AAD preimage is never empty, and the write path refuses to seal with an empty one rather than silently sealing unbound. |
| **G3** | A row written with a sub-resolution `asserted_at` reads back correctly — i.e. the writer truncated before sealing. |
| **G4** | Commons-tier content passes `None`, and passing `Some` is refused at the door rather than sealing something unreadable. |
| **G5** | A relay that holds neither DEK nor grant can still transfer and verify every chunk, and can open none of them. |
| **G6** | Destroying an epoch makes content sealed under it unopenable **through every persist read door on this node**, with no path that bypasses it. Deliberately not "unopenable everywhere": that is the tombstone plane's reach, not this one's, and asserting it here would be the precondition-that-cannot-be-checked persist's §11.4 warns about. |
| **G7** | A range read returns the plaintext range requested, never a ciphertext substring. |
| **G8** | Two blobs in one row cannot be exchanged for one another. |

**G3 needs a witness with sub-resolution precision.** A test using an
already-truncated timestamp passes whether or not the writer truncates, which
makes it a green test on the wrong input — the [[test-field-provenance]]
failure, and the one most likely to be written by accident here.

---

## 10. Resolved questions

All four blocking questions were answered on **CIRISPersist#836**; two became
persist work and shipped in **v44.1.0**.

| # | question | resolution |
|---|---|---|
| Q1 | AAD vs `widen_audience` | **Premise was wrong.** A widening carries `asserted_at` verbatim; `widened_at` is a separate member. `(author, asserted_at, field)` is stable across every widening. Community and epoch come OUT (§5.1.1, §5.1.2). |
| Q2 | `stream_id` namespace | **Shipped, #837.** A stream belongs to its first append; collisions refuse at the second chunk. Uniqueness stays edge's; derivation is `<writer key id>-<ULID>` (§5.5). |
| Q3 | per-chunk binding | **Shipped, #838.** persist frames the caller AAD with `(stream_id, seq)`. Hand-assembly is out of contract permanently, not "not yet" (§5.4). |
| Q4 | tombstone ceiling width | **Edge's, and unchanged.** `Global` for `CommunityDek` shards until CIRISEdge#581 lands the store gate, then `Cohort` (§6). |
| — | backfill epoch | Answered from source before filing: not expressible; current-at-backfill only. |
| — | reach of a destroy | Answered from source: node-local, and travelled copies are the tombstone plane's. |

### 10.1 Edge's own, answered here

- **`field` in the AAD when a row carries one blob.** Kept unconditionally so
  there is one preimage rather than two.
- **Does the A/V path write through these doors?** Live frames are
  point-to-point under a transit key and are *not* at-rest content; the
  recording is. The boundary is: anything that outlives the session goes
  through these doors, anything that does not stays on the transit path.

### 10.2 One standing offer, not taken

persist offered to make it an I-level gate at `serve_blob*` — refusing to
serve a `CommunityDek` shard to a peer whose declared ceiling is narrower
than the tier requires. Not taken **yet**, and the reason is that it would
be persist enforcing a value only edge can compute; the honest place for it
is CIRISEdge#581, which is where the copy set is known. If #581's store gate
turns out not to reach the converger's push path, revisit it.
