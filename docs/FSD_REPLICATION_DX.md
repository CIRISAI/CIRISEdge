# FSD — Replication DX: one verb, two axes

**Status:** **adopted — this is edge's replication DX, as shipped in
v19.0.0 over CIRISPersist v39.0.0.** Implemented in
`replication::attestation_bind` (`share`, `publish`, `keep_local`, `With`,
`Signers`, `custody_for`) and pinned by `tests/chat_message_federates.rs`
(16 tests, real sqlite substrate).

**History, 2026-09-02.** The first cut of this surface (`v18.15.0`, never
tagged) was built over persist's `promote_attestation`, which re-signed the
row with the NODE's key and cleared `additional_scrubs` — so
`share(row, With::Community)` destroyed the actor's signature, and a row
attested by anyone but the node was refused at every peer while promotion
returned `Ok`. Persist's review of this document found it (the sender row in
§3 had recorded the defect as the design), persist's
`FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md` replaced the one primitive
with two operations, and v19.0.0 re-based onto them: `enter_mesh` (same
bytes; the actor's signature stays the base scrub, the node may only APPEND a
co-scrub) and `widen_audience` (a `supersedes` the ACTOR signs at the wider
audience). Edge's five-axis `Flow` was deleted for persist's nine-axis
`ContextualIntegrity`, which is verified at the crossing and refused by axis
name. The vocabulary (`With`, `publish` as its own verb, `keep_local`) stands;
the signature of every verb changed (§0).

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

## 0. The surface, as built — `ciris_edge::replication::attestation_bind`

For a reader who wants the API before the argument. Everything below is
implemented and pinned by `tests/chat_message_federates.rs` (16 tests) and
`tests/rooting_chain_walk.rs`; nothing here is proposed.

```rust
// The verbs. A share is TWO substrate operations: enter_mesh over the row's
// own bytes, then — when `With` is wider than the row's own audience — a
// supersedes the ACTOR signs at the wider one. Idempotent on both.
pub async fn share(dir, row, With, CrossingBasis, Signers)   -> Result<Crossing, String>
pub async fn publish(dir, row, CrossingBasis, Signers)       -> Result<Crossing, String>
pub fn keep_local(row)                                       -> Result<(), String>

// The keys a crossing may sign with: the NODE (custody) and, when in hand,
// the ACTOR (the attester). `custody_for` decides which signs, from the row.
pub struct Signers<'a> { node: &'a LocalSigner, actor: Option<&'a LocalSigner> }
pub async fn custody_for(row, Signers) -> Result<Option<TierPromotionCustody>, String>

// The audience — every non-public cohort, in widening order. `family` and
// `community` NAME their cohort (a placement is a membership claim, AV-45).
pub enum With { MyDevices, MyFamily { family_key_id }, Community { community_key_id },
                Affiliations, Species, Biosphere }
impl With { fn audience() -> Audience; fn cohort_scope(); fn is_encrypted_at_rest();
            fn is_structurally_invisible(); }

// What crossed, and how — both verb outcomes verbatim, because a widening
// is two rows; the nine axes as persist verified them; where edge routes it.
pub struct Crossing { shared: Shared, ci: ContextualIntegrity, routes_to: RoutesTo,
                      discoverable: bool, entered: MeshCrossingOutcome,
                      widened: Option<MeshCrossingOutcome> }
pub enum Shared { Placed { attestation_id }, AlreadyThere { attestation_id },
                  AwaitingActor { attestation_id, age_ms } }
pub enum RoutesTo { OwnerNodes, FamilyNodes {..}, CommunityMembers {..}, Affiliations,
                    Species, Biosphere, Everyone }

// The pure plan both verbs run first (public so it is testable without a directory)
pub fn share_plan(row, &Audience) -> Result<SharePlan, String>
pub enum SharePlan { AlreadyThere, Enter, EnterThenWiden(Audience), Widen(Audience) }

// Persist's types, re-exported — ONE vocabulary, not two
pub use ciris_persist::federation::{Audience, ContextualIntegrity, CrossingBasis, Custody,
    DataSubject, DeliveryMode, Lifecycle, ContentRef, MeshCrossing, MeshCrossingOutcome,
    Replicates, RevocationAuthority, TierPromotionCustody};
pub use ciris_persist::federation::crossing::describe as describe_crossing; // the direct path
pub use ciris_persist::federation::admission::{render_signed_instant,         // CC 2.6.2 `.sssZ`
                                               truncate_to_substrate_resolution};

// Thin wrappers whose NAMES say what the bytes do
pub async fn share_encrypted_privately(dir, row, EncryptedCohort, CrossingBasis, Signers)
pub async fn share_clear_privately(dir, row, ClearCohort, CrossingBasis, Signers)
pub async fn share_publicly(dir, row, CrossingBasis, Signers)
```

There is one crossing path in edge: `share_plan` → `custody_for` →
`FederationDirectory::enter_mesh` → (`crossing::build_widening` →
`stamp_and_canonicalize` → the actor signs → `assemble` →
`FederationDirectory::widen_audience`). Edge never re-signs a row; it offers
the actor's signature or appends the node's co-scrub, and persist verifies
every signature it admits at that door.

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

## 2. What the previous API got wrong

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

## 3. The DX, as built

### One verb

```rust
// Share, with an audience. The verb is the same every time; the variable is
// WHO. The basis is the transmission-principle axis, stated at the call.
let keys = Signers { node: &node, actor: Some(&alice) };
share(&*dir, &row, With::MyDevices,                              ProducerAuthority, keys).await?;
share(&*dir, &row, With::MyFamily { family_key_id: fam },        ProducerAuthority, keys).await?;
share(&*dir, &row, With::Community { community_key_id: room },   ProducerAuthority, keys).await?;

// Publishing is a different verb, because it is a different act.
publish(&*dir, &row, ProducerAuthority, keys).await?;

// And the explicit non-share, so "I did not share it" is something you can
// write rather than something you achieve by not calling anything.
keep_local(&row)?;
```

`With::Community` NAMES the room. A cohort placement is a membership claim
about ONE cohort, proven at the put door against the id the row carries
(AV-45), and persist's widening writes that id into the new row under the
canonical alias `community_key_id` — so a targeted audience without its id is
not an audience. (The first cut of this surface took no id and read it off the
row; persist's review corrected it.)

`With` carries the audience; the type answers the two questions callers get
wrong, from the value rather than the function name:

```rust
With::Community { .. }.is_encrypted_at_rest()      // true  (shared room DEK)
With::Community { .. }.is_structurally_invisible() // FALSE (holds_bytes IS emitted)
With::MyFamily { .. }.is_structurally_invisible()  // true  — replicated to the family's nodes, never advertised
With::Species.is_encrypted_at_rest()               // FALSE — narrower audience, plaintext bytes
```

Both delegate to persist (`crypto_tier`, `Audience::discoverable`) rather than
restating the grouping, so an API that promises encryption the substrate does
not apply is a test failure, not a doc bug.

### The nine axes, at the crossing

CC 4.5.1.1 ratifies a closed vocabulary of nine contextual-integrity axes.
The federation crossing is the moment edge picks a row up and offers it to
peers, so it is the one moment all nine must be present and correct — and
persist now makes that structural: both verbs take a `ContextualIntegrity`
with every axis required, cross-check each against the row, and refuse a
mismatch **by the name of the axis** (`ContextualIntegrityMismatch`). Edge
derives it from the row (`describe_crossing`, persist's own), passes it, and
returns it in `Crossing.ci` as applied:

| axis | wire | as edge states it |
|---|---|---|
| `sender` | `attesting_key_id` | **the actor** — the AgentID, or the human's FedID. MUST equal `attesting_key_id`; persist refuses otherwise. The node is **custody** (`scrub_key_id` / a co-scrub), never the sender: a node-only key cannot carry agency. |
| `data_subject` | `subject_key_ids` | `Nobody`, or exactly the row's subjects |
| `recipient_see` | `cohort_scope` (+ the cohort id) | **`With::…`** → `Audience` |
| `recipient_revoke` | `subject_key_ids` (CC 2.4.1.1) | `ProducerOnly`, or the subjects — stated back so the caller SEES the authority conferred |
| `recipient_receive` | `delivery_mode` | `BestEffort` / `Mandatory` |
| `information_type` | `dimension` → family | the producer helper (`chat:message:v1`) |
| `transmission_principle` | the crossing CALL | **`CrossingBasis`**: `ProducerAuthority`, or `ConsentGrant { attestation_id }` naming the live egress grant that covers this dimension at this audience — validated against the stored grant; never a reseal member (that would change the bytes the actor signed) |
| `temporal_lifecycle` | `asserted_at` / `expires_at` (signed) | the row's own instants, stated back |
| `content` | `original_content_hash` | the hash the crossing commits to; REUSED by a widening (CC 8.1.5) |

A row with no `dimension` is refused before anything moves (`share_plan`):
information type is the strict admission test, and without a namespace no
consent grant can cover it. A row authored directly at federation tier never
passes through `share`; `describe_crossing(row, audience, basis)` presents the
identical nine axes for that path.

### The two operations — as built

Persist's review resolved §6/§9.6b: the constitution's two promotion patterns
are **two different operations**, and persist had conflated them. v39.0.0
ships them; v19.0.0 composes them.

| operation | what it is | who signs | rows after |
|---|---|---|---|
| `enter_mesh` | `local → federation` over the SAME bytes, at the row's OWN audience (CC 5.3.2.4.2) | the actor's signature, made at write or now (`ActorSigned`); or the actor's write-time signature preserved + the node's co-scrub APPENDED with `cosigned_at` (`NodeCoScrub`) | one row, tier flipped, `cohort_scope` untouched — so `(local, self)` becomes `(federation, self)`: replicated to the owner's own nodes by consent fan-out, never advertised |
| `widen_audience` | a strictly wider audience (CC 4.4.3.3.1) | the actor, as a `supersedes` row chained off the original (`references_attestation_id`, `differs_in: ["cohort_scope"]`, body reused member by member) | **two rows**: the original untouched at its audience, the new one at the wider audience, lineage walkable |

**v40.0.0 (CIRISPersist#801) — a widening carries the CLAIM's instant.**
v39.0.0 re-minted `asserted_at` on the `supersedes` row, so the widening — the
only row a peer ever receives, since a `self` row is structurally
undiscoverable (CC 5.2) — asserted its *placement* time and the claim's own
instant was unrecoverable off-node. It is now carried verbatim off the prior,
and the placement records its own signed `widened_at`. Callers pass ONE `now`
to `build_widening` and `stamp_and_canonicalize`. Edge's chat seal binds the
claim instant because of this guarantee (`chat::RoomKey::body_key`).

`share` is `share_plan` → `enter_mesh` → `widen_audience`, and passes the
**actor's** signer (`Signers.actor`) alongside the node's. Who signs is
decided from the row by `custody_for` (the table on `Signers`); there is no
delegated widening — a node cannot author a `supersedes` on an actor's behalf
(CC 4.4; subsidiarity) — so a widening with only the node in hand returns
`Shared::AwaitingActor`, typed, with the original already in the mesh.

**The consequence callers notice:** `share(self-row, With::Community { .. })`
leaves TWO federation rows — the original still replicates to your own
devices, the `supersedes` to the room — and `Shared::Placed` carries the
**new** row's id, because that is the one a peer receives. CC 8.1.5's worked
example is this two-row shape. Readers that key on `attestation_type` must
fold `supersedes` (`chat::messages_in_room` does: a widening IS the claim at
the wider audience, and the prior it references is dropped when both are
present).

**Sign at write.** Edge's producers sign at write (the chat producer signs
with the author's key; the A/V rows are born federation-tier), because an
unsigned row has nothing to co-scrub: persist's `NoActorSignature` closes the
co-scrub path to it, and a key rotation strands it forever
(`CustodyIsNotTheActor`). Deferral (CC 5.3.2.2) is reserved for
ceremony-bound keys — a FedID on hardware signs at the crossing, which for
chat is the send. §6 item 5 has the argument.

### Transmission principle — built, not Phase 2

Persist's answer to §9.1 is better than the ask: the principle rides the
**crossing call** (`ContextualIntegrity.transmission_principle` on
`enter_mesh` / `widen_audience`, edge's `CrossingBasis` argument to `share`)
and is validated against the consent grant already on the row. A reseal member
would change the signed bytes — the exact thing that would invalidate the
actor's local signature and foreclose the co-scrub path — so it stays off the
preimage. The paragraphs below are retained as the record of the original ask.

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
  producer's self-declaration about its *own* content. **`share` does NOT
  pre-check this**; persist's `check_promotion_cohort_standing` refuses it at
  the promote door and `share` surfaces that refusal verbatim (it names both
  the offending party and the rule). A pre-check in edge would be a second copy
  of a gate persist already runs at both doors — see §8 — so it is deliberately
  left where it is.

**Added in v19.0.0 — what the substrate change made NEWLY possible, and what
edge closed the same day.** Persist v39 admits `(federation, self)` at the
crossing, so for the first time a `self`-scoped row exists on the wire.
Edge's advertise projection for `SelfOwn` was producer-keyed and peer-blind —
right for the publish-own planes it was built for, silent about who may
RECEIVE a self row — and the first v19 mesh run showed the owner's `self`
copy of a chat message on another person's node. `bridge.rs#audience_withholds`
(advertise + fetch twin) now makes these impossible:

* a `self` row reaching a node whose principal is not the row's principal
  (CIRISConstitution#23: the owner's own node set, resolved through persist's
  `admission_identity_for_writer`);
* a `family` / `community` row reaching a node that is neither a member nor a
  member's node (persist's `list_*_for_member`);
* a `family` / `community` row that names no cohort, or a peer whose principal
  cannot be resolved, being served at all (fail-closed, booked).

Witnessed by `self_scoped_attestation_is_served_only_to_the_owners_own_nodes`
and `community_scoped_attestation_is_served_only_to_a_members_node` on a real
memory backend, and by the harness receiver, which now fails the leg on a
leaked `self` copy rather than accepting any row with the right body.


## 5. Migration

`share_encrypted_privately` / `share_clear_privately` / `share_publicly` stay,
thin over `share` / `publish`: their names encode in prose what `With` encodes
in a type. There is one crossing path, not two.

**From v18.x (never tagged) to v19.0.0**, every verb's signature changed:
`share(dir, row, With, &node_signer)` → `share(dir, row, With, CrossingBasis,
Signers { node, actor })`; `With::MyFamily` / `With::Community` gained their
cohort id; `Flow` / `describe_flow` / `already_promoted_verdict` /
`promote_to_scope` are gone (`ContextualIntegrity` / `describe_crossing` /
`share_plan` / nothing); `Shared` variants carry the id on the wire and
`AwaitingActor` is new; `chat_message_attestation` takes the AUTHOR's signer
and no node id; `messages_in_room` lists by the humans who speak. A consumer
that counted rows after a share now sees two.

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

### Answered against persist's FSD (`CIRISPersist/FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md`, 2026-09-02)

4. **Delegated widening (persist OQ-1) — no.** A node may not `widen_audience`
   an actor's claim on the actor's behalf. Subsidiarity (CC part_3 §308:
   "decisions belong at the smallest scale competent to make them") — the
   actor who authored the claim is that scale; the node is custody, and
   `check_node_agency_admission` makes the refusal cryptographic. The widening
   waits for the actor.

5. **Should an actor sign at local write by default (persist OQ-2) — edge's
   answer: yes for software-held actor keys (AgentID); at the crossing for
   ceremony-bound keys (FedID on hardware).** A per-key-class default, not a
   global one. Persist's own FSD decides it:
   - **§5.1 W4** — `NodeCoScrub` over an empty-sentinel base is
     `NoActorSignature`. The co-scrub path, the only thing in the FSD that
     *preserves* anything, is closed to a row that carries no signature. A
     deferred row's only road to the wire is the actor present at the
     crossing; otherwise §5.4 parks it as `promotion_awaiting_actor`. Forever.
   - **§5.1 W5** — `reseal.scrub_key_id != row.attesting_key_id` is
     `CustodyIsNotTheActor`. Key rotation makes "actor gone" *routine*: a row
     deferred under AgentID-v1 and promoted after rotation to v2 has no signer
     that can ever sign it as v1. Signed at write, v1's signature over the
     identical bytes stands and the node co-scrubs.
   - **§4.5's own guarantee** ("`asserted_at` is signed, so the path cannot be
     chosen by editing a column") is empty for a deferred row: its
     `asserted_at` is an unsigned stamped column until the very promotion the
     rule governs. The guarantee holds exactly for rows signed at write.
   - **§1.2, measured** — most local rows are empty-sentinel today. Without a
     sign-at-write default the FSD fixes transit revocations and custody
     attribution on *immediate* promotion, and leaves "share later" exactly as
     stranded as it is now. Requirement 1 ("human- and agent-signed rows …")
     presupposes the rows are signed.
   - **The carve-out is the human.** A FedID on a device where each signature
     may cost a presence ceremony signs at the crossing — for chat the crossing
     *is* the send, so the ceremony coincides with intent — and a human row
     never signed, whose human is absent, correctly stays local: it is a draft
     nobody committed. That is deferral-as-consent, not
     deferral-as-optimisation.
   - **Cost** (CC 5.3.2.2's "cardinality win"): for a cohabited agent the
     hybrid sign rides an in-process, prompt-free signer on a path that already
     canonicalises and fsyncs. Measure before deferring; if a class of row
     measurably matters, it is the class that will never leave the producer's
     signer's reach (self-witnessed telemetry), never a claim.
   - **Correction to persist's OQ-2 disposition** ("for human-authored rows
     where FedID lives on another device, the row falls to the co-scrub path or
     waits"): the first half is false under its own W4 — an unsigned row has
     nothing to co-scrub. It waits. The co-scrub path exists only for rows
     signed at write. That *is* the answer to OQ-2.
   - **Edge's practice already agrees**: every edge producer signs at write
     (A/V rows are born federation-tier; the chat producer moves from
     node-attester to actor-attester at the re-base). `share*` takes the
     actor's signer: present → `ActorSigned`; absent and the row is signed →
     `NodeCoScrub`; absent and unsigned → a typed `Shared::AwaitingActor`,
     never a silent stay-local. "Reachable" in persist §5.4 means "the caller
     handed over the signer" — there is no oracle, and the layer that holds
     the key is the layer that decides.

6. **Two corrections to persist §5.6, from edge's side of the wire.**
   - `visible_to_edge: InvisibleByScope` for `self` / `family` is a mislabel.
     `federation/self` **replicates** — to the owner's own node set
     (`CohortScope::SelfOnly`, `src/edge.rs:2777`; the single-owner boundary),
     and `family` to the family's nodes, by consent fan-out over resolved
     recipients rather than by `holds_bytes` discovery. CC 5.2 makes them
     *undiscoverable*, not un-replicated. Persist can state what the row **is**
     (`discoverable: bool`); only edge can state where it goes
     (`routes_to: OwnerNodes | Family | Community | Everyone`). Rename the
     variant `Replicates { kinds, discoverable: false }`, or drop the field and
     let edge's `Crossing` carry it.
   - **One type, persist's.** `ContextualIntegrity` (nine axes, required,
     refused by axis name) subsumes edge's five-axis `Flow`; edge deletes
     `Flow`, re-exports `ContextualIntegrity` + `FederationCrossing`, and keeps
     `With` (the audience vocabulary → `Audience`) and `Shared`. The output is
     the input as applied, plus what edge does with it.

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
   **Answered (persist FSD, v39.0.0)**: both — they are two operations. Edge's
   `share` emits the tier flip (`enter_mesh`, in place, same bytes) and then
   the lineage-walkable `supersedes` (`widen_audience`). This FSD originally
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

---

## 9. Asks of persist — what building this surfaced

Each item is something edge worked around, with the evidence. None blocks
edge; all would remove a footgun for the next consumer.

1. **`Terms` on the promotion reseal (Phase 2, §3).** *Disposition: answered differently — on the crossing call, validated against the row's grant; see §3, Transmission principle.* `AttestationReseal`
   carries envelope · hash · both signature halves · re-signer · timestamp — no
   consent-scope member and no `expires_at`. So the transmission principle
   cannot be attached or narrowed at *share* time; edge refuses a `Terms`
   argument rather than accept one that does nothing. A consent-scope member
   in the reseal (or a `RowMirror::restamp_for_scope` variant that takes one)
   is the substrate change that lets the fifth CI parameter be set at the
   crossing, where the CI page says it belongs.

2. **A typed "already federation" promote outcome.** *Disposition: shipped — `MeshCrossingOutcome::{Crossed, AlreadyInMesh, AlreadyWidened, AwaitingActor}`; edge folds it into `Shared`.* `promote_attestation`
   returns `Ok(false)` for a row already at `tier: federation` — correct and
   idempotent by CC 5.3.2.4.2, but indistinguishable from "placed nothing for
   another reason" without reading the row's tier first. Edge does that read
   (`already_promoted_verdict`). A `Promoted::AlreadyFederation` variant would
   let every consumer tell the two apart without the pre-read.

3. **`effective_accord_holder_records()` is a footgun under
   `CIRIS_TESTING_MODE`.** *Disposition: real, separate — persist will file it.* It falls back to the *real* baked HUMANITY_ACCORD
   roster when the test anchor is not fully armed, so a harness that set three
   of the six `CIRIS_TEST_TRUST_ROOT*` vars seeds production's constitutional
   holders into a throwaway directory and looks green. Edge now calls
   `test_anchor_genesis_records()` and hard-errors on `None`. Suggest:
   `effective_*` refuses (or warns loudly) when `CIRIS_TESTING_MODE` is set
   but the anchor does not resolve, instead of silently falling back.

4. **`crypto_tier` is negative-default for UNKNOWN scopes.** *Disposition: real, separate — persist will file it (closed-enum match, build error on omission).* CIRISPersist#188:
   only self/family and community/affiliations encrypt; any scope the dispatch
   does not recognise is plaintext. That is the safe default for the closed
   set today, but it means a future scope added to `cohort_scope::ALL` without
   a `crypto_tier` arm ships in the clear. A compile-time exhaustiveness pin
   (match on the closed enum rather than a string) would make that a build
   error. Edge pins its own grouping to `crypto_tier` by test so it cannot
   drift, but only persist can make the substrate itself fail closed.

5. **A typed transient-membership refusal for AV-45.** *Disposition: real, separate — persist will file it (#737's class: absence vs deliberate).* When a
   `community`-scoped row arrives before the recipient holds the `Community`
   row, the put door refuses it (correctly) and edge's re-offer carries it
   later — measured at 11 refusals and ~5 s on `ladder.send_message`. The
   refusal arrives as a generic `Error::InvalidArgument` string, so edge cannot
   distinguish "back off, the roster has not landed" from "this will never
   admit". A typed variant would let edge back off on the first and stop on
   the second.

6. **Constitution vocabulary drift, for whoever owns rc4.7.** *Disposition: (a) the constitution's, agreed; (b) answered by persist's FSD — two operations, not one; see §3, The re-base.* (a) `global`
   appears as a widened scope in CC 4.4.3.3.1 and the CC 8 worked example; the
   wire value is `federation` (`cohort_scope::ALL` has no `global`, and
   `is_valid` refuses it). (b) CC 4.4.3.3.1 describes promotion as a
   `supersedes` chain with walkable lineage; CC 5.3.2.4.2 describes it as an
   in-place tier flip with no marker in the signed bytes. persist implements
   the second. If the lineage-walkable form is still intended for cohort
   widening, edge's `share` should emit it alongside — but that is a decision
   for the constitution's author, not a guess for edge to make.

7. **Verify, not persist:** `test_trust_root_override` WARNs "TEST TRUST ROOT
   active" on every anchor lookup — 449 lines per node per mesh run — with no
   once-guard. Correct to warn; wrong to warn per call.

8. **CC 2.6.2 date-time canonicalization — a SHARED non-conformance.** The
   canonical form is `YYYY-MM-DDTHH:MM:SS.sssZ`: literal `Z` (the `+00:00`
   offset form MUST NOT be used), exactly three fractional digits, and
   consumers MUST reject any other form when verifying a signature. Persist
   emits `+00:00` at microsecond precision (persist's finding); **edge does
   too** — the binder's signed `asserted_at` and the chat producer both use
   chrono's `to_rfc3339()` — and persist admits it, so nothing rejected it.
   Edge's fix is not cosmetic: the signed `asserted_at` must agree with the
   typed column at the instant level (CIRISPersist#598 refuses a divergence),
   so it is millisecond truncation **and** `Z`, in the binder, every producer,
   and the typed column together. **Done in v19.0.0**: edge's binder, the
   chat producer and the A/V producer render through persist's
   `render_signed_instant` (`.sssZ`, millisecond floor) and truncate the column
   through `truncate_to_substrate_resolution`; edge's own `truncate_to_micros`
   is gone. Persist's ingest check stays microsecond-tolerant for pre-v39 rows
   (§11 item 3 of its FSD). One consequence that reaches further than
   promotion: a consumer that windows on a raw `Utc::now()` can drop a row
   stamped "at" that instant by up to 1 ms — truncate the bound the way the
   producer truncates the row.
