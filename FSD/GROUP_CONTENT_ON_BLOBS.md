# FSD: Group Content on Blobs — CIRISEdge

**Status:** DESIGN — on paper, not implemented. CIRISEdge#586 is the first
consumer; the design is deliberately not chat's.

**Substrate:** CIRISPersist v44.0.0 (`FSD/BLOB_ENCRYPTION_AT_REST.md` §11–§12),
CIRISVerify v15.1.0 (`aes_gcm::{encrypt_aad, decrypt_aad}`).

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

### 5.1 The preimage

```
AAD = "ciris.edge.blob.aad.v1" ‖ 0x00
    ‖ lp(community_key_id)
    ‖ lp(author_key_id)
    ‖ lp(asserted_at)           // STORED form — see §5.2
    ‖ be_u64(epoch)
    ‖ lp(field)
```

where `lp(x)` = `be_u32(len(x)) ‖ x`.

Each element earns its place:

- **domain string + `0x00`** — this preimage is never confusable with another
  protocol's, and the NUL means the version can never run into the first
  field.
- **`community_key_id`** — a ciphertext cannot move between communities.
- **`author_key_id`** — a member cannot re-attribute another member's content
  to themselves. This is the substitution #830 named.
- **`asserted_at`** — a ciphertext cannot be replayed onto a later row by the
  same author in the same community.
- **`epoch`** — binds to the DEK generation, so a ciphertext cannot be
  carried across a rotation and presented as current.
- **`field`** — two blobs in one row (a message body and its attachment)
  cannot be swapped for each other.

**Length-prefixing is not decoration.** Plain concatenation makes
`("ab","c")` and `("a","bc")` the same preimage, which would let a crafted
`community_key_id` absorb the author's. Every variable-length element is
length-prefixed for that reason alone.

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

### 5.4 DAG binding, stated honestly

persist passes the **same** `aad` to every chunk and to the manifest. It does
*not* derive a per-chunk `(manifest_sha, index)` binding — that was
considered and deferred, because the manifest sha does not exist at
chunk-write time.

The consequence, stated rather than glossed: **within one DAG, a chunk can be
moved to another index and still open.** Across DAGs it cannot, because the
AAD differs. Reordering within a sealed DAG is detected by the manifest —
the chunk shas are listed in order and the manifest is itself sealed — so the
gap is closed at the manifest layer, not the chunk layer. Edge must therefore
**never trust a chunk it opened without checking the manifest's order**, and
`read_blob_range_as` is the door that does that. Hand-assembling chunks is
out of contract.

---

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
  convention", and edge is the side that fountains the shards. See open
  question 4.

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
| `community_key_id` | which community; AAD input |
| `content_sha256` | the at-rest sha to read |
| `content_field` | which field this blob is; AAD input |
| `epoch` | the bound DEK generation; AAD input |
| `media_type` | so a reader knows what it got before opening it |
| `chunked` | whether to expect a DAG (range reads available) |

`author_key_id` and `asserted_at` are already envelope members and are not
duplicated.

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
| **G1** | A ciphertext moved to a row with a different `author_key_id`, `asserted_at`, `community_key_id`, `epoch`, or `field` does not open. |
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

## 10. Open questions

Questions 2, 4 and 5 are filed as **CIRISPersist#836** and block locking this
design. Questions 1 and 6 are edge's own and are answered inline.

1. **Does `field` need to be in the AAD when a row carries exactly one blob?**
   It costs nothing and closes G8 by construction. Kept unconditionally so
   there is one preimage rather than two.
2. **What is the `stream_id` for a live A/V recording**, and who guarantees
   its uniqueness across a community? The DAG doors key on it, and edge has
   no allocator for it today.
3. ~~Backfill under which epoch~~ — **answered by the source, not open.** The
   community cascade re-seals under the CURRENT epoch when the epoch moves
   under a write and returns `EpochNotCurrent` only after exhausting retries,
   so sealing under a historical epoch is not expressible. Backfill uses
   current-at-backfill because nothing else is available.

   The consequence is worth stating rather than discovering: a message
   authored under epoch 3 and backfilled under epoch 12 becomes recallable
   only by destroying epoch 12 — which also reaches everything else sealed
   under 12. Backfill therefore **coarsens recall granularity**, and doing it
   one community at a time (§8 step 3) is what keeps that blast radius
   legible.
4. **Is edge's `FountainContent` tombstone ceiling wide enough for
   `CommunityDek` blobs?** §10.6 makes ceiling width a gate: narrower than
   the copy set and a retraction "silently un-revokes". Edge fountains the
   shards, so edge is where this is checkable — and nothing checks it today.

5. **An AAD over `(author, asserted_at)` does not survive `widen_audience`.**
   Widening writes a NEW row that supersedes and leaves the prior, so the
   widened row carries a different `asserted_at` — and a reader rebuilding
   the AAD from *it* gets a different preimage and the blob does not open.

   Three possible resolutions, and this design cannot pick one alone:
   crossing a tier boundary always re-writes the content (likely correct for
   `community` → commons, since the tier changes anyway); the AAD binds to
   the ORIGINATING row's identity, carried forward as an explicit envelope
   member on every superseding row; or widening within one tier is simply not
   supported for blob-bearing rows. **Until this is settled, blob-bearing
   rows must not be widened.**

6. **Does the A/V path (`realtime_av_*`) write through these doors**, or does
   it keep its own transit sealing for live frames and only use blobs for the
   recording? Live frames are point-to-point under a transit key and are not
   at-rest content; the recording plainly is. Stated here because the
   boundary between them is currently implicit.
