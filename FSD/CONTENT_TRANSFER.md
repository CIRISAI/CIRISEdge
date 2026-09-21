# FSD: Content transfer at every cohort — rows, keys, bytes, addressing: the state table under the link-state table

**Status:** Normative for edge; proposed to persist and server. Community and commons rows are
DONE (edge v29.1.0 / persist v46.1.0, proven on CIRISServer#612's ladder 2026-09-21). Self and
family rows are the open work (CIRISPersist#884 / CIRISEdge#646).
**Author:** Eric Moore (CIRIS Team) with Claude Fable 5.1
**Created:** 2026-09-22
**Owner spec:** CIRISEdge (the integrating side, as for `CIRIS_EDGE_TRANSPORT.md`); persist owns
the substrate rules it cites, the Constitution owns the rulings.
**Companions:**
- [`CIRIS_EDGE_TRANSPORT.md`](CIRIS_EDGE_TRANSPORT.md) §5.3 / §5.4.1 (link state) / §5.4.2
  (round layer) — the two tables this one sits under
- [`REPLICATION_ROUND_CORRELATION.md`](REPLICATION_ROUND_CORRELATION.md) — the round a row rides
- [`GROUP_CONTENT_ON_BLOBS.md`](GROUP_CONTENT_ON_BLOBS.md) — the community seal, the AAD, the
  roster; this document does not restate it
- persist `FSD/BLOB_REPLICATION.md` (holder plane), `FSD/SELF_FAMILY_DEK_CASCADE.md` (keys),
  `FSD/EPOCH_MINTER.md` (the minter), `FSD/MEDIA_SOURCE.md` (size, renditions)
- CIRISServer#615 (the client's create / read / enumerate contract)

---

## 0. Why this exists

The community path was proven on 2026-09-21 after **four host gaps found one ladder run each**
(CIRISEdge#634 registry role, #636 key identity, #640 lifecycle drive, #640 chunk source, then
persist#873 principal, #876 minter, #878 pointer, #884 discovery). Every one of them was "the issue
one level up" from the previous run's symptom, and every one was findable from the rules that already
existed — there was no table that named the rungs, so each was discovered by running to it.

`CIRIS_EDGE_TRANSPORT.md` §5.4.1 ended that for attribution: every link state is a row, every row
names what it may cause and the test that proves it. §5.4.2 did the same for the round beneath an
attributed row. **This document is the third table: what a round carries, at every cohort, from the
producer's write to the reader's open — with the rung named, the owner named, the refusal named, and
the witness named.** Its purpose is that the next ladder run says *which rung* is red, never *that
something* is.

It also states the one thing no document stated: how self and family content reaches the owner's
other devices. The Constitution ruled it (§1); nobody wrote the join; the community arc's method
would have found it in five runs. Here it is in one table.

## 1. The fixed points — what the Constitution rules, per cohort

These do not move. Every row in §4 and §5 traces to one of them.

| # | ruling | consequence for transfer |
|---|---|---|
| **CC 5.2** | *"When a Contribution carries `cohort_scope: self` OR `family`, the substrate MUST NOT emit a corresponding `holds_bytes:sha256:{prefix}` directory attestation … MUST NOT propagate C beyond the self-collective / family scope via any other directory or discovery surface."* Headed **UNCONDITIONAL**. | No holder claim for self/family **at any audience** — the prohibition is on the attestation type, not its scope. No substitute discovery surface either. |
| **CC 5.2** (same sentence) | *"the content's bytes are delivered to admitted members of the relevant self-collective (CC 3.3.6) or family (CC 3.3.4) via the at-rest encryption flow, NOT via the public holder-discovery directory."* | Self/family bytes move by **delivery**, not discovery. The mechanism is named. |
| **CC 1.13.3.2** | *"a non-member cannot discover that the bytes exist via the substrate and cannot fetch them … the bytes are delivered only to admitted members via the at-rest key cascade. That is the whole of what omission buys."* | Content-holding confidentiality only; link metadata is out of scope, so fetching from a known node over an encrypted link is inside the ruling. |
| **CC 3.3.6** | `identity_occurrence` *"is what makes 'this is me, on another device' a cryptographic fact"*; without it *"`cohort_scope: self` content cannot reach the user's other devices."* | The self-collective is knowable without a roster or a grant. |
| **CC 8.1.12.4** | *"New occurrence / new family-member admission triggers retroactive `key_grant` emission for all extant `cohort_scope: self\|family` content (the 'I bought a new phone' case)."* | A new device must be granted the past, not only the future. |
| **CC 3.2** | A node has exactly one owner. | An owner "consenting" to their own node is a category error; the self-collective's membership is not a grant. |
| **CC 4.4.3.2.1** | Three crypto tiers: self/family per-write DEK (invisibility is the floor, encryption defence-in-depth); community shared epoch DEK (**sole** boundary, federates); commons plaintext. | The tier is a fact about the bytes; the pointer carries it (§3). |
| **CC 4.4.3.3.1 / 8.1.5** | Widening is a `supersedes`, strictly wider, actor-signed. | A row reaches a community only as its widening; the authored `self` row never leaves the owner's nodes (`chat_two_person_community.rs`). |
| **CC 5.3.2 / 5.3.2.1** | `ContentFetch` / `ContentBody` / `ContentMiss`; holder discovery via `holds_bytes:sha256:*`, 24 h TTL, at most 2 holders in parallel, `ContentMiss` ⇒ `withdraws`. | The **community / commons** byte path. Not self/family. |
| **CC 5.3.2.5 / 3.3.13** | Every blob carries `size`; every consumer checks it before hashing; the multimedia Source struct. | persist v45 puts `size` on the holder claim; the reader bounds the fetch by it. |
| **CC 5.3.2.6** | Render tier from verified, sniffed bytes. | The reader's job after adopt; out of scope here beyond "verify-then-sniff". |
| **CC 5.4.6** | Scoped destinations are derived per member and never announced; one hop. | Addressing for any non-public cohort is the derived address; the serve gate keys on arrival scope. |
| **CC 3.1.9.1** | `holds_bytes:sha256:{prefix}`: *"Substrate auto-emission per `federation_blobs.put_blob` … full SHA lives in `evidence_refs[]`."* | The citation, not the pointer, is what the substrate indexes (§3, CIRISEdge#646). |

## 2. Where this table sits — three tables, one frame

```
  CIRIS_EDGE_TRANSPORT §5.4.1   link state × frame kind      "may this link cause this?"
            │ Rooted ∧ owns_key (or Advisory for bootstrap kinds)
            ▼
  CIRIS_EDGE_TRANSPORT §5.4.2   round metadata × role         "which coordinator, which round?"
            │ RoutedToResponder / RoutedToInitiator
            ▼
  THIS DOCUMENT §5              cohort × rung                 "does this row, key, byte reach
                                                               the party entitled to it, and
                                                               if not, which rung says why?"
```

Nothing below is reachable except through an attributed link and a correlated round; nothing above
knows what a row means. A ladder run reads the three tables top-down: `bound` is §5.4.1/§5.4.2,
`sent` is §5 rung R1–R2, `arrived` is §5 rung R3–R8.

## 3. The objects, named once

The community arc's defects were all one object standing in for another (§0). These are the objects,
what each is authoritative for, and where it lives. A rung that reads one for another's job is wrong
by construction.

| object | authoritative for | never for | code |
|---|---|---|---|
| **Row** (the referencing attestation) | who may hold — `cohort_scope`, `attesting_key_id`, `subject_key_ids`; the access grant (`is_audience`) | the key plane | `Attestation`; persist `hold.rs::is_audience` |
| **Citation** (`evidence_refs[sha]`) | the relation *this row is about these bytes*; what persist indexes (`attestations_binding_content`, `envelope_binds_content`) | how to open | CIRISEdge#646 `chat::cite_evidence`; every producer MUST cite |
| **Pointer** (`BlobPointer` under a named field) | the key plane — `tier`, `community_key_id`, `epoch`, `content_field`; how to open | the audience (a pointer never widens a cohort — persist#878) | `group_content::BlobPointer`; `BlobMeaning::project`; persist `BlobProvenance::from_attestation` |
| **Key-grant set** | who can decrypt; its signer is the **minter** = the node that sealed the bytes = a holder by construction | discovery for community (that is the claim) | persist `key_grant:*`, `Engine::apply_replicated_key_grant`; `FSD/EPOCH_MINTER.md` |
| **Holder claim** (`holds_bytes:sha256:*`) | possession, at community / affiliations / commons only; 24 h TTL | meaning (`PossessionIsNotMeaning`); self/family (CC 5.2) | persist `put_blob_scoped`; edge `store_gate::announce_is_possible` |
| **Occurrence** (`identity_occurrence`) | the self-collective: every device/agent of one identity; the recipient set for self content | consent (CC 3.2) | persist `list_identity_occurrences_active`; edge `contact::resolve` → `nodes` |
| **Roster** (community / family record) | the recipient set for community / family content | the key plane | persist `resolve_community().members`, `list_families_for_member_active` |
| **Scope-address group** | the derived per-member addresses a cohort's bytes move over (CC 5.4.6) | trust | `ScopeAddressTable`, `ScopeLifecycle`, `cohort_addressing::snapshot_for_nodes` |
| **Send set** | which peers a plane's rows are offered to | audience (a peer in the send set is still gated by the row) | persist `consent_peers_by_principals`; edge bridge `resolved_peer_set` |

Two rules that follow and are already load-bearing (persist#878, v46.1.0): **`cohort_scope` from the
row, always; `tier` / `community_key_id` / `epoch` from the pointer; the floor binds the two.** And
**`minter_key_id` is named or derived from the admitted set, never inferred from the row's author.**

## 4. The transfer rule per cohort — one table

| | **self** | **family** | **community / affiliations** | **commons** (species / biosphere / federation) |
|---|---|---|---|---|
| tier (CC 4.4.3.2.1) | per-write DEK, `InvisibleEncrypted` | per-write DEK, `InvisibleEncrypted` | shared epoch DEK, `CommunityDek` | `Plaintext` |
| row projection (persist `namespace`) | `SelfOwn` | `SelfOwn` | `Cohort` | `Cohort` / `Global` (trust root) |
| **rows reach** | the identity's active occurrences — **implicit** (CC 3.3.6 / 3.2), no grant | the family members' occurrences — implicit per member | consent peers ∩ roster; the room sees the **widening** (CC 4.4.3.3.1) | consent peers (allowlisted senders, `SenderStanding::Allowlisted`) |
| keys reach | every occurrence, wrapped at write; **retroactively on new occurrence** (CC 8.1.12.4) | every member's occurrence, wrapped at write; retroactively on new member | roster, via the epoch cascade + `key_grant` set | none |
| **holder discovery** | **none** (CC 5.2) | **none** (CC 5.2) | `holds_bytes` at community visibility, 24 h TTL (CC 5.3.2.1) | `holds_bytes`, plaintext provenance |
| **holder set** | **known by construction**: the epoch's minter (the sealing device), then the identity's other occurrences | the minter (the author's device), then the family's other nodes (opportunistic) | `list_holders` (+ `list_holders_sized`, v45) | `list_holders` |
| byte movement | **delivery**: addressed fetch from the minter; push-on-write optional | delivery, as self | discovery + swarm pull (`BlobPuller`, up to 2 holders) | discovery + swarm pull |
| addressing (CC 5.4.6) | `SelfOnly` group of the identity's occurrences — the **self room** (§6.3) | `Family` group of the family's nodes | `Cohort` group from the room's MLS exporter (`cohort_addressing`) | federation address |
| serve gate (edge `admit_blob_serve`) | arrival `SelfOnly` ∧ requester `OwnNode` | arrival `Family` ∧ requester member | arrival same `Cohort` group; `chunk_scope` answered | any arrival |
| adopt gate (persist `would_hold`) | `is_audience` self arm: principal equality | family arm: roster | community arm: active member of the named community | commons: allowlist |
| announce after adopt | never (`LocalOnly`) | never | `Announce` — the adopter becomes a holder | `Announce` |
| revocation reach (`withdraws`) | the occurrences | the family | every holder, via the claim index + the register | every holder |

The right-hand two columns are proven. The left-hand two are the design in §6; every cell there
is a rung in §5 with a witness named and, today, absent.

## 5. The rung table — cohort × rung, owner, refusal, witness

Rung numbering is shared across cohorts so a ladder can print `R5 red` and mean the same thing
everywhere. A rung's **owner** is the repo whose code decides it; its **refusal** is the name the
log and the counter carry when it fails; its **witness** is the test that proves it. "—" in the
witness column is the work.

### 5.1 Community / affiliations — DONE, the reference row set

| rung | what must be true | owner | refusal by name | witness |
|---|---|---|---|---|
| **R0** producer writes | seal under the room's epoch DEK; pointer + citation on the row; row authored at `self` | edge `chat_message_attestation_in` | `readable_by_nobody` | `chat_message_federates::every_encrypted_cohort_actually_encrypts_and_every_clear_one_does_not`, `a_chat_message_cites_its_blob_in_evidence_refs_and_keeps_the_pointer` |
| **R1** row widened to the room | `share(.., With::Community, ProducerAuthority)` — the supersedes the room receives | host (server `share_in_room`; harness) | `AudienceNotWider`, `CustodyIsNotTheActor` | `chat_two_person_community.rs` (the widen), `chat_message_federates::the_share_plan_is_decided_before_any_directory_and_refuses_a_narrowing` |
| **R2** row reaches a member's node | consent peer ∩ roster; round completes (§5.4.2) | edge replication | `RecipientNotInSendSet`, `ReplyDropped{…}` | `runtime.rs::mutual_initiators_634`, ladder `sent` |
| **R3** key reaches the member | `key_grant` set admitted, wraps projected to the member's occurrences | persist `apply_replicated_key_grant`; host wires `SealedContentWiring` | `key_grant set … projected as grants` (INFO) / `NotGranted` | `blob_federation_e2e::a_far_node_opens_once_the_key_grant_and_the_bytes_both_arrive`; `chat_harness_dx` (config shape) |
| **R4** holder discovered | `holds_bytes` at community visibility, indexed with the row (v44.8.1) | persist `put_blob_scoped` | `NoHolders` | persist I113/I113c; `blob_federation_e2e::holds_bytes_says_possession_and_never_meaning` |
| **R5** holder addressed | the room installed in the scope table (nodes, not persons); route to the derived address | host drives `ScopeLifecycle` with `snapshot_for_nodes` | `blob_group_not_installed` / `blob_holder_not_in_group` / `blob_holder_sealed_out` (`blob_route_refusals`) | `scope.rs::a_group_that_was_never_installed_is_named_as_such_not_as_a_membership_refusal`, `cohort_addressing::a_community_of_persons_installs_as_its_nodes` |
| **R6** holder serves | arrival on the matching group; `chunk_scope` answered (`answers_scope`) | edge `admit_blob_serve`; host wires a scope-answering source | `blob_serve_scope_undeterminable` / `…arrival_scope_insufficient` / `…group_mismatch` (`blob_serve_refusals`); build refuses the unwired state | `scope.rs::a_scoped_blob_is_served_to_a_peer_arriving_on_the_matching_address`, `edge.rs::scope_native_gate_640` |
| **R7** bytes adopted | sha verified, size bounded; provenance from the row + pointer, minter derived; `is_audience` community arm | persist `adopt_sealed_blob`; edge `pull.rs::adopt_sealed` | `StoreFailed(NotPartyTo)`, `size ≠ stored length` (AV-89) | persist I121–I135; `pull.rs::a_pointer_only_chat_row_keeps_the_pointers_tier_and_community`, `the_minter_is_never_transcribed_from_the_author` |
| **R8** reader opens | wrap for the viewer's occurrence, AAD rebuilt from the row | edge `group_content` | `Body::Unopened { reason }` | `blob_federation_e2e::a_far_node_opens_once_the_key_grant_and_the_bytes_both_arrive`; ladder `arrived` / `hamburger` |
| **R9** withdraw reaches holders | `withdraws` re-verified against the held row; bytes evicted, refused `Withdrawn` | edge `revocation`, persist `delete_blob` | `Revoked` / `Withdrawn` | `blob_federation_e2e::a_withdraws_revokes_the_bytes_on_a_holder_and_an_unauthorized_one_is_inert`, `revocation.rs::a_blob_is_revoked_only_when_every_known_reference_is_withdrawn` |

### 5.2 Commons — DONE (differs from community only at R3 and R7)

R3 is empty (no key). R7 is `put_blob` at plaintext tier with the allowlist as the sender gate
(`store_gate::commons_content_needs_the_allowlist_and_nothing_else_substitutes`). R8 is
`blob_federation_e2e::a_commons_blob_opens_on_any_node_because_no_key_is_involved`. Everything else
is the community row.

### 5.3 Self — the open row set (CIRISPersist#884 / CIRISEdge#646)

| rung | what must be true | owner | refusal by name | witness |
|---|---|---|---|---|
| **R0** producer writes | seal under a per-write DEK wrapped to **every active occurrence**; pointer + citation; **no holder claim** (I52) | persist `put_blob_scoped` (self branch) | `readable_by_nobody` | persist I52 ✓; `store_gate::an_invisible_scope_cannot_be_announced_however_the_operator_asks` ✓ |
| **R1** — | no widening: the authored row IS the row | — | — | — |
| **R2** row reaches every occurrence | the identity's active occurrences are **implicit** send-set peers for `SelfOwn` planes — no grant (CC 3.3.6 / 3.2) | **persist** `consent_peers_by_principals` (§6.1) | `RecipientNotInSendSet` (today: silent — the row never leaves) | — *(persist: "a self row authored on A is held on B with no grant between them")* |
| **R3** key reaches every occurrence | the set travels with the row (`key_grant:*` at self ⇒ `SelfOwn`); **retroactive on new occurrence** (CC 8.1.12.4) | persist cascade (write ✓); persist retroactive (§6.5) | `NotGranted` | write: cascade tests ✓; retroactive: — *(persist: "a device admitted after the write opens the write")* |
| **R4** holder known | **no discovery.** Holder = the epoch's minter from the admitted set; fallback = the identity's other occurrences | edge `pull_one_inner` source rule (§6.2); persist `minter_of(identity, epoch)` read | `NoOtherOccurrence` (terminal, honest) — never `NoHolders` for these scopes | — *(edge: "a self row's pull asks the minter, never list_holders")* |
| **R5** holder addressed | the **self room** installed: `SelfOnly` group, members = the identity's occurrences (§6.3) | edge `self_addressing::snapshot`; host drives install / advance on occurrence change | `blob_group_not_installed { scope: self }` | — *(edge: "two occurrences of one identity derive each other's self addresses")* |
| **R6** holder serves | arrival on the self group ∧ requester `OwnNode` (principal equality) | edge `admit_blob_serve` ✓ + `SenderStanding::OwnNode` ✓ | `blob_serve_arrival_scope_insufficient` | `scope.rs` serve tests cover the gate shape ✓; self-specific: — |
| **R7** bytes adopted | `is_audience` self arm (principal equality, after #873) ✓; adopt `LocalOnly` (never announce) ✓ | persist `would_hold` / `adopt_sealed_blob` | `NotPartyTo` (correct for a non-owner) | persist I135 ✓ (a self row keeps self; a non-owner is `NotPartyTo`) |
| **R8** reader opens | wrap for **this device's** occurrence | edge `group_content` ✓ | `Body::Unopened` | — *(e2e: "the owner's second device opens what the first wrote")* |
| **R9** withdraw reaches occurrences | the row plane carries it (`SelfOwn`); register evicts locally | edge `revocation` ✓ | `Revoked` | — |
| **R10** the drive lists it | every self row held on any occurrence, with **row-held / bytes-absent** as a first-class state | server `GET /v1/drive` over the row plane (CIRISServer#615 §3) | `not_fetched` shown as "on another device" | — |

Rungs R2 and R3-retroactive are prerequisites for everything beneath them; a ladder that reaches R4
with R2 red is testing the wrong thing.

### 5.4 Family — self's row set, one column wider

Same rungs. R2's recipient set is the family members' occurrences (`list_families_for_member_active`
→ per-member occurrences); R3 is wrapped per member and retroactive on **new member**; R4's minter is
the author's device, with the family's other nodes as opportunistic fallback — a node that has adopted
may serve a fetch addressed to it, and nothing points anyone at it, which is the property (persist's
reading on #884, agreed); R5 is a `Family` group of the family's nodes; R6/R7 use the family arms;
R10 is the family's row plane. Open question §12.1.

## 6. The self/family design — five parts

### 6.1 The self-collective is implicit in the send set (persist)

For every `SelfOwn`-projected plane, the send set of key `k` is
`consent_peers_by_principals(k) ∪ { every active occurrence of principal_of(k) }`, and for family
planes additionally the occurrences of every active member. No grant is authored or read for this
set: CC 3.2 makes an owner's consent to their own node a category error, CC 3.3.6 makes membership a
cryptographic fact. Edge consumes it through the existing `resolved_peer_set`; nothing on edge
changes at this rung except that the rows arrive.

**Today** the set is explicit grants only, the server authors none between an owner's nodes, and
persist#884's own report could find no witness of a self row on a second device. This is the rung
under every other rung, and it is the one persist's reading on #884 assumed rather than measured.

### 6.2 The holder is known by construction — the source rule (edge; one persist read)

`pull_one_inner` branches on `meaning.scope()`:

```
Cohort | Public   → holders = list_holders(sha)                  (unchanged; R4 community)
SelfOnly | Family → holders = [ minter(identity|family, epoch) ]  // the sealing device
                            ++ other active occurrences / member nodes (opportunistic)
                    list_holders is NEVER consulted; NoHolders is not a possible outcome
                    empty → NoOtherOccurrence (terminal, refused by name)
```

The minter is the `key_grant` set's signer (persist#876, `FSD/EPOCH_MINTER.md`): it sealed the
bytes, so it holds them. A puller that admitted the set already knows it; the persist read
`minter_of(scope_key, epoch)` makes the join explicit rather than a convention. The row's **sender**
is not the holder by construction — device B re-advertises A's rows to C (edge advertises a row
whose attester is in its self-publish set, and the owner's fed-id is in it on every device), so C's
sender may be row-held / bytes-absent. Sender-as-holder is a first-hop coincidence; minter-as-holder
is the invariant. (Correction to persist's reading on #884.)

The fetch itself is `fetch_blob_scoped_with_disposition(sha, manifest, holders, meaning)`, which
already takes a caller-supplied holder list and routes each through `BlobScopeRouter` — so R5's
derived address is used exactly as for community. Retries are meaningful (a device coming online),
unlike today's structural `NoHolders`.

**Push-on-write is an optimisation, not the floor.** The sealing device MAY deliver bytes to
occurrences that are online at write time (the #927 initiator-first shape; persist's proposed
`deliverables_for_occurrence(occ)` read names what to push). Device B is offline at write time in
the ordinary case, so pull-from-minter remains the primary path; push means B usually holds the bytes
before it asks.

### 6.3 Addressing: the self room (edge)

The serve gate requires a self-scoped blob to arrive on a `SelfOnly` derived address
(`allows_recipient_scope(SelfOnly, SelfOnly)` only), the scope table already accepts `SelfOnly`
groups, and nothing installs one. The addressing root is a **per-identity MLS group whose members
are the identity's active occurrences** — the self room — with `self_addressing::snapshot(identity,
lens)` as the twin of `cohort_addressing::snapshot_for_nodes`, installed on first occurrence,
advanced on occurrence admission / revocation, sealed on the convergence cadence. Family: a
`Family` group of the members' nodes, same twin.

This reuses the CC 5.4.6 substrate — derived addresses are transport privacy for *any* non-public
cohort — without being the community approach: no holder claim, no swarm discovery, no community
roster; the roster IS the occurrence list. The alternative (fetch over the federation address, gated
by `OwnNode` standing only) is simpler and exposes "this node fetched *something* from that node" to
link observers; CC 1.13.3 says invisibility does not buy that metadata anyway, so it is admissible —
but the self room is the design that keeps one serve gate for every cohort. Open question §12.2.

### 6.4 Family (persist ruling on #884 Q2, agreed)

Each member's node receives the row by fan-out; the holder by construction is the author's device
(the minter); other family nodes that adopted may serve a fetch addressed to them but nothing points
anyone at them. "Any member's device may serve any other's" holds only opportunistically, which is
what CC 5.2 permits: no advertisement, ever.

### 6.5 Retroactive re-grant on a new occurrence (persist)

CC 8.1.12.4 is explicit and it is not implemented (`at_rest_cascade.rs`, `self_at_login.rs`: no
backfill path). On admission of a new `identity_occurrence` (or family member), persist emits
`key_grant` wraps for every extant self (family) blob the identity (family) holds, addressed to the
new occurrence's content-KEM keys. Without it §6.1–6.3 deliver every file except the ones that
existed before the new device did.

### 6.6 The new-device flow, end to end (the ladder stage `mine_on_b`)

```
A writes  (R0)  seal → DEK wrapped to {A, B} → row(self, pointer, citation) → key_grant set (minter=A)
A → B     (R2)  row + set ride SelfOwn to B (implicit peer)          ← today: never leaves A
B         (R3)  admits the set; wrap for B's occurrence projected
B         (R4)  pull: scope=self → holders=[A (minter)]; list_holders untouched
B         (R5)  self room installed on both → route to A's derived self address
A         (R6)  arrival=SelfOnly ∧ requester principal == owner → serve
B         (R7)  sha+size verified → adopt LocalOnly (is_audience self arm)
B         (R8)  open with B's wrap
C joins   (R3') persist re-grants extant content to C (retroactive); C runs R4–R8 against A or B
```

## 7. Invariants — and the mutant each must kill

1. **No `holds_bytes` for self/family at any audience.** persist I52 stays as written; edge
   `announce_is_possible(SelfOnly | Family) == false` stays, and (CIRISEdge#646 ask 1) asks the
   substrate's predicate rather than restating it. *Mutant:* a claim emitted at `self` scope → I52 red.
2. **Audience from the row, never the pointer.** persist#878 I135. *Mutant:* "scope from the pointer"
   → a non-owner becomes party to a `self` row → I135 red.
3. **Key plane from the pointer, never the row's scope.** persist#878 I132–I134; edge
   `pull.rs::a_pointer_only_chat_row_keeps_the_pointers_tier_and_community`.
4. **Minter named or derived, never the author.** persist#876 I126–I130; edge
   `pull.rs::the_minter_is_never_transcribed_from_the_author`.
5. **Every producer cites.** A row that references bytes carries them in `evidence_refs`
   (CIRISEdge#646). *Mutant:* drop the citation → persist's index cannot find the row → revocation's
   known set incomplete → `revocation.rs::a_blob_is_revoked_only_when_every_known_reference_is_withdrawn` red.
6. **For self/family, `list_holders` is never consulted and `NoHolders` is not a possible outcome.**
   *Mutant:* fall through to `list_holders` → the new witness (`a self row's pull asks the minter,
   never list_holders`) red.
7. **The half-wired host state is unconstructible** (v27.0.0): `SealedContentWiring`,
   `answers_scope`; the self room adds nothing new here — its installer is a lifecycle drive like the
   room's, and a scope-native node without it refuses at R5 by name, never silently.
8. **A refusal is the branch, never a disjunction** (CIRISEdge#433, #640): every rung above names its
   own refusal; two rungs never share one.

## 8. Observability — what a run must be able to say

| counter / line | rung | exists |
|---|---|---|
| `bootstrap_door_outcomes`, `link_before_binding` | §5.4.1 | ✓ v26.1.0 |
| `replication_routed_to_{responder,initiator}_total`, `replication_reply_dropped_total` | §5.4.2 | ✓ v26.0.0 |
| `key_grant set admitted — wraps … projected as grants` | R3 | ✓ (persist INFO) |
| `pull … outcome=` (`NoHolders` / `NoOtherOccurrence` / `FetchFailed` / `StoreFailed` / `Stored`) | R4–R7 | ✓; `NoOtherOccurrence` — |
| **`blob_pull_sources`** by scope kind × source (`list_holders` / `minter` / `occurrence_fallback` / `pushed`) | R4 | — (new; the one line that proves self never touched the directory) |
| `blob_route_refusals` (`blob_group_not_installed` / `…not_in_group` / `…sealed_out`) | R5 | ✓ v26.2.0 |
| `blob_serve_refusals` | R6 | ✓ v27.0.0 |
| `scope lifecycle INSTALLED / ADVANCED` (scope, group, epoch, members) | R5 | ✓ v26.2.0; self room: — |
| `chat: body opened` / `Body::Unopened { reason }` | R8 | ✓ |
| ladder stages: `bound`, `sent`, `arrived`, `hamburger` | community | ✓ (server); **`mine_on_b`** for self — |

The ladder's merged narrative (CIRISServer#612) already prints R2–R8 for community in time order;
the self row set adds `mine_on_b` = "a self row written on A opened on B", with the rung named on red.

## 9. The DX contract at every cohort — what a host wires, what is automatic

| | host MUST wire | automatic once wired |
|---|---|---|
| **all** | `ReplicationRuntimeConfig::local_key_id`; `sealed_content: SealedContentWiring { engine, pull_sink, revocations }`; a `BlobChunkSource` with `answers_scope() -> true` if scope-native; `kick()` after publishing | rounds, propagation kicks, key-grant projection, pull on admitted rows, revocation eviction |
| **community** | the widen (`share(.., With::Community, ..)`); `ScopeLifecycle::install` on `Keyed` with `snapshot_for_nodes`, `advance` on epoch change, `seal_due` on a cadence | holder claim, discovery, swarm pull, serve, adopt, announce |
| **self / family** | nothing new in the config; the self room drive (`self_addressing::snapshot` → `install`, `advance` on occurrence change) — or accept the federation-address fallback (§12.2) | implicit send set (persist), minter-as-holder fetch, `LocalOnly` adopt, retroactive re-grant (persist) |
| **commons** | the allowlist (`SenderStanding::Allowlisted`) | everything else |
| **client** (CIRISServer#615) | create: descriptor + bytes with `size`; read: verify → sniff → policy; enumerate: `GET /v1/drive` over the row plane, cursor `since`, row-held/bytes-absent as a state | — |

## 10. Sequencing

1. **persist**: §6.1 implicit send set → §6.5 retroactive re-grant → `minter_of` read (§6.2). The first
   two are prerequisites for any self row or key to exist on device B; nothing on edge can be
   witnessed end to end before them.
2. **edge**: §6.2 source rule (buildable now against a stubbed holder read; switches to persist's when it
   lands) → §6.3 self room (independent of persist) → `blob_pull_sources` counter → `announce_is_possible`
   asks the substrate (#646 ask 1).
3. **server**: the self room drive beside the chat room drive; the `mine_on_b` ladder stage; the drive read.
4. **mixed fleet**: a pre-cut device is simply an occurrence that never asks; nothing it holds changes
   meaning. No wire change in any of the above.

## 11. Acceptance

Every "—" in §5.3 / §5.4 / §8 becomes a named test on the owning side before the rung is called green,
and the ladder prints `mine_on_b` with the rung named on red. The community row set (§5.1) is the
template: it is green because each rung has a witness, not because a run passed.

## 12. Genuinely open

1. **Family serve-from-non-author.** Persist's reading (no advertisement; opportunistic serve only) is
   CC-conformant; whether a family member's node should *prefer* a nearer member that adopted, without a
   claim, is a policy question for the Constitution (locality dividend vs. "nothing points anyone at it").
2. **Self room vs federation-address fallback** (§6.3). Both are CC-admissible; the self room keeps one
   serve gate for every cohort and is recommended; the fallback is a smaller first cut.
3. **Push-on-write scope.** Whether the sealing device pushes to *every* online occurrence or only
   those on a live link is a cost question, not a correctness one.
