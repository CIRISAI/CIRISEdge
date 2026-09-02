# FSD — Replication DX: one verb, two axes

**Status:** **adopted — this is edge's replication DX.** Implemented in
`replication::attestation_bind` (`share`, `publish`, `keep_local`, `With`) and
pinned by `tests/chat_message_federates.rs`.

**This surface is an OPTION, not a gate.** A row authored directly at
`tier: federation` with the intended `cohort_scope` replicates exactly as well —
that is the substrate's native path and nothing here changes it. This API exists
because the two-axis model is easy to get wrong (the author did, twice in one
afternoon, see below), so it names the audience in a type, refuses the two
silent misconfigurations, and leaves the substrate untouched. Callers who
already author correctly at federation tier lose nothing by ignoring it.

Written after an arc in which the author conflated
`tier` and `cohort_scope` twice in one afternoon — once silently (a row
authored `tier: federation` made `promote_attestation` a no-op that returned
`Ok(false)`), once loudly (a private chat message stamped `cohort_scope:
federation`, which is *publishing*, not sending).

Both mistakes were available because the word **`federation` names a value in
both vocabularies and means something different in each**. That is the design
problem this document exists to fix.

---

## 1. The two axes

They are orthogonal, and every replication decision is a point in their
product.

### Tier — *is it on the wire at all?*

| tier | meaning |
|---|---|
| `local` | producer-only-authority, **signature-deferred**, self-visible-only. **Never replicates.** |
| `federation` | **hybrid-signed**, federation-visible. The promotion target. |

Two values, closed, enforced by a schema `CHECK` on the SQL backends. The
closure is load-bearing beyond tidiness: `verify_federation_tier_ingest`
exempts every tier that is not *exactly* `federation` from signature
verification, so an unknown tier was a **signature-exempt** tier.

The advertise surface reads `list_attestations_since`, which is
**federation-tier only** (the E5 invariant). So:

> **`tier` is the on/off switch for the wire.** A `local` row is not "slow to
> replicate"; it is not replicating, ever.

### Cohort — *who, once it is on the wire?*

Seven values, widening `self → family → community → affiliations → species →
biosphere → federation`, with two further properties that are themselves
orthogonal to each other:

| cohort | at rest | can a non-member tell it exists? |
|---|---|---|
| `self` | encrypted (opt-in) | **no** |
| `family` | encrypted, per-write DEK wrapped per member (opt-in) | **no** |
| `community` | encrypted, shared per-community DEK (**mandatory**) | yes |
| `affiliations` | encrypted, shared DEK | yes |
| `species` | **plaintext** | yes |
| `biosphere` | **plaintext** | yes |
| `federation` | **plaintext** (Commons) | yes |

The grouping is not arbitrary. CC 4.4.3.2.1 draws the line at one question —
**"does it have a bounded membership roster?"** — yes → encrypt, no →
plaintext. A community is a stream its members subscribe to cryptographically
(one DEK, wrapped per member, re-wrapped on membership change), and that DEK is
its **sole** confidentiality boundary because community content *federates*.
The tier name IS the guarantee: "a persecuted community is protected by *being
a community*, not by remembering a flag." Commons (`species` / `biosphere` /
`federation`) has no roster, so there is nothing to wrap to.

Two traps live in that table:

1. **`species` and `biosphere` narrow the audience but do not protect the
   bytes.** `crypto_tier` is *negative-default* (CIRISPersist#188): only
   self/family and community/affiliations encrypt, and everything else —
   including unknown future scopes — falls through to plaintext. A `community`
   whose `cohort_subkind` is `infrastructure` is plaintext too, so even
   "community ⇒ encrypted" cannot be hardcoded.
2. **Only `self` and `family` are structurally invisible.** The `holds_bytes`
   row *is* the discovery surface, so declining to emit it is the privacy
   primitive. Community content is deliberately NOT suppressed (CEG 0.8
   §8.1.13.3): communities can be large and per-member byte-level invisibility
   is infeasible. So a community gives **cohort-filtered visibility**. "Only
   members can read it" is true; "nobody can tell it exists" is true only of
   self and family.

### The product, stated plainly

| tier × cohort | what happens |
|---|---|
| `local` × anything | stays on this node. Nothing crosses a wire. |
| `federation` × `self` | **replicates to the owner's OWN device set.** A node has exactly one owner (CIRISConstitution#23), and recipient admission resolves through `owner_of`, so "self" spans your devices — not one machine. |
| `federation` × `family` | replicates to the family cohort; emits no `holds_bytes`. |
| `federation` × `community` | replicates to the room; discoverable, encrypted under the room DEK. |
| `federation` × `affiliations` | replicates to the organisations you are attached to; discoverable, encrypted under a shared DEK — the same tier as `community` (CC 4.4.3.2.1 groups them). |
| `federation` × `species` / `biosphere` | replicates to a narrower AUDIENCE than the whole federation — **but plaintext**, with a discoverable `holds_bytes`. Commons tier. |
| `federation` × `federation` | **published.** World-readable, plaintext. |

**So promotion to federation tier is not a technical step — it is the act of
SHARING.** The only questions are *with whom* (cohort) and *on what terms*.
That is the API this document proposes.

---

## 2. What is wrong with today's API

```rust
// What a caller writes today:
let row = chat_message_attestation(..).await?;          // tier: local, cohort: self
directory.put_attestation(SignedAttestation { attestation: row.clone() }).await?;
share_encrypted_privately(&*dir, &row, EncryptedCohort::Community, &signer).await?;
```

Three problems:

1. **The tier is invisible.** Nothing in the call says "this is what puts it on
   the wire". A producer that authored `tier: federation` gets `Ok(false)` from
   the promotion and no error — the row simply never moves, silently.
2. **`share_*` is three functions** (`share_encrypted_privately`,
   `share_clear_privately`, `share_publicly`) because the crypto posture had to
   be lifted into the *name* to stop `species` reading as "private". That is
   the right instinct implemented in the wrong place: the posture is a
   *property of the cohort*, so it should be readable from the cohort value.
3. **Terms are absent.** Contextual integrity's fifth parameter — the
   transmission principle — has nowhere to go in the call.

---

## 3. Proposed DX

### One verb

```rust
// Share, with an audience. The verb is the same every time; the variable is
// WHO. (Terms ride on the row at authorship — see §3 "Honest scoping".)
share(&*dir, &row, With::MyDevices,    &signer).await?;
share(&*dir, &row, With::MyFamily,     &signer).await?;
share(&*dir, &row, With::Community,    &signer).await?;   // the room id is IN the row

// Publishing is a different verb, because it is a different act.
publish(&*dir, &row, &signer).await?;

// And the explicit non-share, so "I did not share it" is something you can
// write rather than something you achieve by not calling anything.
keep_local(&row)?;
```

`With::Community` takes no room argument on purpose: `cohort_scope` is the
single string `community`, and WHICH community is a signed envelope member
(`community_id`) the producer already wrote. A parameter here would be one the
substrate never reads.

`With` carries the audience; the type answers the two questions callers get
wrong, from the value rather than the function name:

```rust
With::Community.is_encrypted_at_rest()      // true  (shared room DEK)
With::Community.is_structurally_invisible() // FALSE (holds_bytes IS emitted)
With::MyFamily.is_structurally_invisible()  // true
With::Species.is_encrypted_at_rest()        // FALSE — narrower audience, plaintext bytes
```

Both delegate to persist (`crypto_tier`, `suppresses_holds_bytes`) rather than
restating the grouping, so an API that promises encryption the substrate does
not apply is a test failure, not a doc bug.

### The five flow parameters, mapped

ciris.ai/contextual-integrity embeds five parameters in the wire. A caller
should be able to see all five in the call or the row, and never have to infer
one:

| parameter | wire | where the caller sees it |
|---|---|---|
| data subject | `subject_key_ids` | the producer, for a self-declaration; set by the producer helper |
| sender | `attesting_key_id` | the signing node |
| recipient | `cohort_scope` + `subject_key_ids` + `delivery_mode` | **`With::…`** |
| information type | `dimension` | the producer helper (`chat:message:v1`) |
| transmission principle | `consent:scope` | **`Terms::…`** |

**Both paths present the same picture.** `share` and `publish` compute a
[`Flow`] — all five parameters read from the row through persist's canonical
envelope names and edge's typed `delivery_mode` reader — BEFORE anything
moves, log it as `CROSSING THE WIRE — type=… sender=… subject=… recipient={…}
principle={…}`, and return it in the `Crossing`. A row authored directly at
federation tier never passes through `share`, so `describe_flow(row)` presents
the identical `Flow` for that path. A row with no `dimension` is refused on
both: information type is the strict admission test, and without a namespace
no consent grant can cover it.

The federation crossing is the moment edge picks a row up and offers it to
peers, so it is the one moment all five must be present and correct — and the
one moment a consumer should be able to SEE all five without inferring any.

`Terms` is the piece with no home today. Proposed surface, smallest first:

```rust
Terms::default()                    // share, no declared limit
Terms::retain_for(Days(90))         // a deletion window the producer commits to
Terms::no_analysis()                // may be read, not mined
Terms::no_training()
```

### Honest scoping of `Terms`

**`Terms` cannot ride on the promotion call as things stand, and this FSD does
not pretend otherwise.** The promotion reseal carries the envelope, its hash,
both signature halves, the re-signer and a timestamp — not `expires_at`, and no
consent-scope member. Retention is a property of the row at **authorship**.

So the phasing is:

* **Phase 1 (buildable now).** `share`/`publish`/`keep_local` + `With`. Terms
  accepted only where the substrate already reads them: producer helpers take
  `Terms` and stamp `expires_at`. `share(.., Terms::retain_for(..))` on an
  already-authored row REFUSES rather than silently ignoring — a parameter that
  does nothing is worse than one that is absent.
* **Phase 2 (needs persist).** A consent-scope member inside the promotion
  reseal, so terms can be attached or narrowed at share time. This is a
  substrate ask, filed against persist, not something edge can fake.

That split is the point: an API that accepts `Terms` and drops them would be a
governance object that looks authoritative and grants nothing — the same shape
CIRISServer's non-vacuous-prefix guard exists to refuse.

---

## 4. What this makes impossible

* **Publishing by accident.** `publish` is its own verb. No enum variant
  reaches the world-readable tier.
* **A silently-unshared row.** `share` on a `tier: federation` row currently
  returns `Ok(false)`. That arm is **constitutionally correct and must stay**:
  CC 5.3.2.4.2 makes promotion idempotent ("promoting a `federation` row returns
  it unchanged"). So the fix is in the DX layer, not the substrate: `share`
  distinguishes *already shared at this cohort* (fine, idempotent) from *authored
  already-promoted so there was never anything to move* (an authoring bug, named
  as such) — by reading the row's tier and cohort before calling the primitive.
* **"Private" meaning four different things.** The caller reads
  `is_encrypted_at_rest()` and `is_structurally_invisible()` off the audience,
  and the two never collapse into one word.
* **Third-party placement.** A `family`/`community` placement must name no
  party but its own producer (CIRISPersist#592 / AV-84) — a placement is a
  producer's self-declaration about its *own* content. `share` enforces this at
  the call rather than surfacing persist's refusal at the door.

## 5. Migration

`share_encrypted_privately` / `share_clear_privately` / `share_publicly` stay
as-is. They are already correct; they are simply lower-level than most callers
need, and their names encode in prose what `With` encodes in a type. `share`
and `publish` are built on the same `promote_to_scope` they are, so there is
one promotion path, not two.

## 6. Open questions

1. Does `delivery_mode` belong in `Terms` or in `With`? It is the third
   recipient mechanism (active receivers), so `With` is the honest home — but
   it is also selective fail-secure machinery, and most callers should never
   set it.
2. Should `keep_local` exist at all, given a row is authored `local` already?
   Argued yes: an explicit no-op documents intent at the call site, and gives
   an audit surface a missing call cannot. **But it must refuse one class of
   row.** Local-tier eligibility is decided by *revocation authority*, not by
   whether `subject_key_ids` is empty (CC 5.3.2.4.1 / 5.3.2.2): a producer may
   name a subject and stay local, but a row where **another subject holds
   revocation authority** — a subject-side `consent:state:revoked`, or a
   `withdraws` under CC 2.4.1.1 rule 2/3 — is federation-tier *by
   classification*. It may transit local while in flight but MUST NOT rest
   there; the substrate drives it to promotion within a 24 h SLA and flags
   `hard_case:consent_revocation_promotion_overdue` otherwise. `keep_local` on
   such a row is therefore an error, not a choice.
3. `species` / `biosphere` have no encrypted counterpart. If they are meant to
   carry anything sensitive, that is a substrate gap worth filing rather than
   papering over in the API.

---

## 7. Cross-check against CIRISConstitution (rc4.6)

Every load-bearing claim above was checked against the constitution and
against persist's code, not restated from memory. Where they agree it is
noted; where they diverge it is flagged rather than smoothed over.

### Confirmed

| claim in this FSD | constitution |
|---|---|
| promotion IS sharing | CC 5.3.2.4.2: "**promotion *is* the federation-emit moment**" — the tiered-scope promotion and `holds_bytes` emission fire at that instant, exactly as for any federation write |
| `local` never crosses a wire — and is stricter than that | CC 5.3.2.4.3 tier table: `local` is readable by **only the producing occurrence**; "every other caller — even an authorized family/community peer — sees nothing". The read-gate is *orthogonal* to `cohort_scope` and composes with it (threat entries AV-59 / AV-60 / AV-61) |
| `tier = federation ⟹ hybrid signature present`, both halves verified | CC 5.3.2.4.3 invariant + 5.3.2.4.3.1: immediate, no phased cutover, no `require_hybrid: false` posture. A key without a PQC half is confined to local tier until it has one |
| `self` = the owner's own devices, not one machine | CC 1.13.3.4: "the `self` cohort is one owner's own devices, so its boundary is well-defined only because ownership is **single-valued**" (CC 3.2). For `self`, *outsider* means "any node not owner-bound to my owner" |
| publishing is the opt-in, not the default | CC 1.13.3.4: "**federation (public-commons) scope is the opt-in**, not anonymity" — a deliberate correction of opt-in-anonymity designs, because opt-in fails the non-savvy vulnerable |
| the encrypted / clear grouping | CC 4.4.3.2.1 table: self/family (per-write DEK, no discovery) · Community = `community` + `affiliations` (community DEK, **mandatory**, `holds_bytes` with cleartext provenance) · Commons = `species` + `biosphere` + `federation` (plaintext, anyone) |
| only self/family are structurally invisible; it is unconditional; at-rest crypto is defense-in-depth and may default off | CC 5.2, "Two layers, not one" |
| group-scoped destinations do not announce | CC 5.3 (transport): a destination whose `cohort_scope` is below federation — `self`, `family`, `community`, `affiliations` — MUST NOT emit a Reticulum announce, directed or broadcast; only Commons scopes and the `infrastructure` opt-out may. Edge's `announce_suppression.rs` is that rule |
| the lightnet / darknet split | CC 5.3 adopts the name from edge's `docs/LIGHTNET_DARKNET.md`: identity plane public (lightnet), group plane derived (darknet) |
| what none of this buys | CC 1.13.3.1 non-goals: cohort scope hides *content*, not *contact*. No communication-graph privacy, no traffic-analysis resistance, no unobservability against a global passive adversary at federation scope. This FSD makes none of those claims and must never be read as making them |

### Vocabulary drift — flagged, not fixed here

1. **`global` is not a wire value.** CC 4.4.3.3.1 and the CC 8 worked example
   widen a scope to `"global"`. persist's closed `cohort_scope::ALL` has no such
   value; the widest tier is `federation`, which CC 1.13.3.4 glosses as
   "federation (public-commons)". Treat `global` as worked-example prose. A
   caller who types it is refused by `cohort_scope::is_valid`, which is the
   right outcome, but the constitution text should say `federation` too.

2. **Two promotion patterns in the constitution; persist implements one.**
   CC 4.4.3.3.1 describes cohort widening as a **`supersedes`** chained off
   the original — `references_attestation_id`, `differs_in: ["cohort_scope"]`,
   content hash preserved, lineage walkable. CC 5.3.2.4.2 describes
   `local → federation` promotion as an **in-place** tier flip with a fresh
   hybrid signature and explicitly *no* "was-promoted" marker in the signed
   bytes. persist's `promote_attestation` is the second: it re-stamps the
   envelope for the new placement (`RowMirror::restamp_for_scope`), sets
   `promoted_at`, and UPDATEs in place. Nothing emits a `supersedes` row.
   **Open question for the author**: is the CC 4.4.3.3.1 lineage-walkable form
   still intended for cohort widening (in which case edge's `share` should emit
   it *alongside* the tier flip), or has 5.3.2.4.2 superseded it? This FSD
   does not guess.

3. **`witness_relation`.** CC 5.3.2.4.1 requires `witness_relation: self` for
   every local-tier write and CC 3.3.7 requires it on a consent grant. It is
   not an envelope member on persist's `Attestation` — persist treats it
   structurally (the producing occurrence is `attesting_key_id`, which must
   exist in `federation_keys`, and a self-attestation is `attested_key_id`
   defaulting to the attester). So edge's producers are conformant by
   construction, but they do not *say* so anywhere a reader could check. Worth
   a one-line assertion in each producer.

---

## 8. How persist enforces this — the gates, by name

The FSD's claims are only worth making because the substrate refuses the
alternatives. Every one of these was hit, by name, while building the chat
flow — which is the strongest evidence that they are live.

| gate | what it refuses | discipline |
|---|---|---|
| `check_row_column_binding` | a typed column (`asserted_at`, `attestation_id`, `attesting_key_id`, `cohort_scope`, …) that is not bound into the SIGNED envelope's row mirror — CIRISPersist#598 / #643 | pure fn of the row, no I/O, no crypto — AV-76 **tier 1**, same order on all three backends. This is what refused the first two mesh runs |
| `verify_federation_tier_ingest` | any federation-tier row whose hybrid signature does not verify over `ceg_produce_canonicalize(envelope)` with `SHA-256(canonical) == original_content_hash`; `HybridPolicy::Strict` — a classical-only row is refused as hybrid-pending | CC 5.3.2.4.3.1. Refused the classical-only owner binding |
| `check_promotion_admission` | a promotion whose reseal was not verified — re-runs `check_row_column_binding` over the row **as it will be stored**, so a caller that skipped the re-stamp is refused at the primitive | verify-before-mutation (AV-9), evaluated before the state lock. One promotion primitive since v31 (#649) — "the door beside the door" was removed on purpose |
| `check_promotion_cohort_standing` | a `family` / `community` placement naming any party but its own producer — CIRISPersist#592 / AV-84 | a placement is a producer's self-declaration about its OWN content; a claim about a third party belongs at a belonging-tier. Refused the recipient-named chat row |
| promote's idempotency arm | nothing — `tier == federation ⟹ Ok(false)`, unchanged | CC 5.3.2.4.2. The DX surfaces it; the substrate must not error |
| `check_single_node_owner_admission` | a second owner binding on a node that already has a live one | CC 3.2 single-owner; in every `put_attestation`, verify-before-mutation, so a rejected second owner leaves no trace. What makes `self` a well-defined boundary at all |
| `check_node_agency_admission` | an `agency:*` scope on a node-role key | CC 1.13.5 — "no agency for infra" is cryptographic, not policy |
| the put door's `cohort_scope` check | a `community`-scoped row from **any** signer — only a promotion may place one, and it re-signs | why a message is authored `self` and promoted, never authored at the room |
| `cohort_scope::crypto_tier` | nothing — it *classifies*, negative-default (#188): only self/family and community/affiliations encrypt; everything else, including unknown future scopes, is plaintext | this FSD's `EncryptedCohort` / `ClearCohort` are pinned to it by test, not restated |
| `cohort_scope::suppresses_holds_bytes` | emitting the discovery row for `self` / `family` | CC 5.2 — the privacy primitive itself |
| closed tier vocabulary | any `tier` other than `local` / `federation` | v38.2.0 (#761): an unknown tier was a **signature-exempt** tier, so the doors now refuse unknown tiers on every backend as a pure tier-1 check |

Two things the table makes visible that a prose spec cannot: every gate is
**tier 1** where it can be (pure, no I/O, identical on all backends) and runs
**before mutation** — so a refused row leaves no trace, and a peer that
reconstructs the same decision reaches the same verdict. That is what lets
edge's DX be thin: it names the audience and signs the bytes, and the
substrate makes the inappropriate flow inexpressible rather than merely
discouraged.
