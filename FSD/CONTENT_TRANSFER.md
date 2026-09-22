# FSD: Content transfer at every cohort — rows, keys, bytes, addressing: the state table under the link-state table

**Status:** Normative for edge; proposed to persist and server. Community and commons rows are
DONE (edge v29.1.0 / persist v46.1.0, proven on CIRISServer#612's ladder 2026-09-21). Self and
family rows are the open work (CIRISPersist#884 / CIRISEdge#646).
**Author:** Eric Moore (CIRIS Team) with Claude Fable 5.1
**Created:** 2026-09-22 · **Revised:** 2026-09-22 (PR #647 review: nine findings, each verified
against code and CC before the text moved — see the §13 changelog)
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

Nothing below is reachable except through an attributed link (§5.4.1); nothing above knows what
a row means. **Only rows and keys ride correlated rounds (§5.4.2).** Bytes do not: R5–R8 move as
ephemeral envelopes (`ContentFetch` / `ContentBody`, `BlobChunkRequest` / `BlobChunk*`) that the
registry classifies `NotAReplicationFrame` and hands to ordinary envelope dispatch
(`edge.rs`, `replication::RouteDisposition::NotReplication`) — no coordinator, no round, no
`RoutedTo*` outcome. So the frame is a fork, not a stack:

```
  §5.4.1 link ──► §5.4.2 round ──► R0–R4 (rows, keys, who holds)      ← replication planes
             └──────────────────► R5–R8 (address, serve, adopt, open)  ← envelope dispatch
```

A ladder run reads it that way: `bound` is §5.4.1 (and §5.4.2 for the row round), `sent` is R1–R2,
`arrived` is R3–R4 for the row and key and R5–R8 for the bytes. A byte-fetch failure is never a
§5.4.2 finding — a round-drop counter reading zero while a fetch fails is the expected shape, not a
contradiction.

## 3. The objects, named once

The community arc's defects were all one object standing in for another (§0). These are the objects,
what each is authoritative for, and where it lives. A rung that reads one for another's job is wrong
by construction.

| object | authoritative for | never for | code |
|---|---|---|---|
| **Row** (the referencing attestation) | who may hold — `cohort_scope`, `attesting_key_id`, `subject_key_ids`; the access grant (`is_audience`) | the key plane | `Attestation`; persist `hold.rs::is_audience` |
| **Citation** (`evidence_refs[sha]`) | the relation *this row is about these bytes*; what persist indexes (`attestations_binding_content`, `envelope_binds_content`) | how to open | CIRISEdge#646 `chat::cite_evidence`; every producer MUST cite |
| **Pointer** (`BlobPointer` under a named field) | the key plane — `tier`, `community_key_id`, `epoch`, `content_field`; how to open | the audience (a pointer never widens a cohort — persist#878) | `group_content::BlobPointer`; `BlobMeaning::project`; persist `BlobProvenance::from_attestation` |
| **Key-grant set** | who can decrypt. Two axes (persist `key_grant.rs`): **epoch** `(community, minter, epoch)` — the signer is the **minter**, named or derived, never the author; **content** `(sha, cohort_scope, owner)` for self/family — admission REQUIRES the signer to equal the blob row's `author_key_id` (`key_grant.rs` §12), so on this axis the minter *is* the author, by rule, and the row already names it | discovery for community (that is the claim); a minter read keyed by epoch for self/family (a self/family pointer has `epoch: None` — `BlobPointer::epoch` is `CommunityDek` only) | persist `key_grant:*`, `Engine::apply_replicated_key_grant`; `FSD/EPOCH_MINTER.md` |
| **Holder claim** (`holds_bytes:sha256:*`) | possession, at community / affiliations / commons only; 24 h TTL | meaning (`PossessionIsNotMeaning`); self/family (CC 5.2) | persist `put_blob_scoped`; edge `store_gate::announce_is_possible` |
| **Occurrence** (`identity_occurrence`) | the self-collective: every device/agent of one identity; a **content-KEM / grant target** (CC 3.3.6.1); its `transport_destination` (CC 3.3.6) is the signed binding to the NODE that hosts it | consent (CC 3.2); **a peer** — an occurrence is not a replication endpoint; node-class and device-class occurrences exist, and under `use_node_identity` (CIRISEdge#541) the actor/engine key is an occurrence while peers see the NODE key | persist `list_identity_occurrences_active`; edge `contact::resolve` → `Subject.nodes` |
| **Node** (the advertised identity) | what a round is run against and a fetch is addressed to; the key a `TransportBinding` (#636) proves on a link; the member of every scope-address group; `Edge::advertised_key_id` | authorship (stored rows are the actor's) | CC 4.4.3.2.4.1(b) `resolve_member_transport`: occurrence → `transport_destination` → destination; edge `contact::resolve`, `cohort_addressing::snapshot_for_nodes` |
| **Roster** (community / family record) | the recipient set for community / family content | the key plane | persist `resolve_community().members`, `list_families_for_member_active` |
| **Scope-address group** | the derived per-member addresses a cohort's bytes move over (CC 5.4.6) | trust | `ScopeAddressTable`, `ScopeLifecycle`, `cohort_addressing::snapshot_for_nodes` |
| **Send set** | which **nodes** a plane's rows are offered to (persist's `consent_peers_by_principals` returns node key ids) | audience (a peer in the send set is still gated by the row); occurrence keys (a set containing a device-class occurrence runs rounds against a key with no destination and may omit the node that hosts it) | persist `consent_peers_by_principals`; edge bridge `resolved_peer_set` |

Two rules that follow and are already load-bearing (persist#878, v46.1.0): **`cohort_scope` from the
row, always; `tier` / `community_key_id` / `epoch` from the pointer; the floor binds the two.** And
**`minter_key_id` is named or derived from the admitted set, never inferred from the row's author.**

## 4. The transfer rule per cohort — one table

| | **self** | **family** | **community / affiliations** | **commons** (species / biosphere / federation) |
|---|---|---|---|---|
| tier (CC 4.4.3.2.1) | per-write DEK, `InvisibleEncrypted` | per-write DEK, `InvisibleEncrypted` | shared epoch DEK, `CommunityDek` | `Plaintext` |
| row projection (persist `namespace`) | `SelfOwn` | `SelfOwn` | `Cohort` | `Cohort` / `Global` (trust root) |
| **rows reach** | the **nodes** hosting the identity's active occurrences — **implicit** (CC 3.3.6 / 3.2), no grant | the nodes hosting the family members' occurrences — implicit per member | consent peers ∩ roster; the room sees the **widening** (CC 4.4.3.3.1) | consent peers (`consent_peers_by_principals`); the allowlist gates the STORE, not the send |
| keys reach | every occurrence, wrapped at write; **retroactively on new occurrence** (CC 8.1.12.4) | every member's occurrence, wrapped at write; retroactively on new member | roster, via the epoch cascade + `key_grant` set | none |
| **holder discovery** | **none** (CC 5.2) | **none** (CC 5.2) | `holds_bytes` at community visibility, 24 h TTL (CC 5.3.2.1) | `holds_bytes`, plaintext provenance |
| **holder set** | **known by construction**: the author's nodes (`contact::resolve(author_key_id).nodes` — the sealing node is among them; on the content axis author = minter by admission rule) | the author's nodes, as self; the family's other nodes only opportunistically | `list_holders` (+ `list_holders_sized`, v45) | `list_holders` |
| byte movement | **delivery**: addressed fetch from the minter; push-on-write optional | delivery, as self | discovery + swarm pull (`BlobPuller`, up to 2 holders) | discovery + swarm pull |
| addressing (CC 5.4.6) | `SelfOnly` group whose members are the identity's **nodes** — the **self room**, a per-identity MLS group with a specified bootstrap (§6.3); group id = the identity (`identity_key_id`, CC 3.3.6) | `Family` group of the members' nodes; group id = `family_id` (CC 5.2) | `Cohort` group from the room's MLS exporter (`cohort_addressing`) | federation address (no group, no table) |
| serve gate (edge `admit_blob_serve`) | arrival `SelfOnly` (same group) ∧ requester `OwnNode` | arrival `Family` (same group) ∧ requester member | arrival same `Cohort` group; `chunk_scope` answered | any arrival (`allows_recipient_scope(Public, _)`) |
| adopt gate (persist `would_hold`) | `is_audience` self arm: principal equality | family arm: roster | community arm: active member of the named community | commons: allowlist |
| announce after adopt | never (`LocalOnly`) | never | `Announce` — the adopter becomes a holder | `Announce` |
| revocation reach (`withdraws`) | the identity's nodes — the row is a **tombstone** and projects at the Attestation plane's ceiling, never `SelfOwn` (transport FSD §3.2; persist `tombstone_ceiling`) | the family's nodes, same projection | every holder, via the claim index + the register | every holder |

The right-hand two columns are proven. The left-hand two are the design in §6; every cell there
is a rung in §5 with a witness named and, today, absent. The commons column is not "community
minus a key": it has no room, no widening, no scope group and no serve-side scope duty, which is
why §5.2 gives it its own rows.

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

### 5.2 Commons (species / biosphere / federation) — DONE, its own row set

Plaintext tier, no room, no scope group: the bytes ride the federation address and the store gate
is the allowlist. Inheriting the community rows would demand a widening (R1) and a lifecycle drive
(R5) the path does not have, and would hide the refusals it does have.

| rung | what must be true | owner | refusal by name | witness |
|---|---|---|---|---|
| **R0** producer writes | `put_blob` at `Plaintext`; pointer + citation; **holder claim emitted** at global visibility | persist `put_blob` | — | persist plaintext-tier tests ✓ |
| **R1** — | no widening: a commons row is authored at its scope | — | — | — |
| **R2** row reaches peers | send set = `consent_peers_by_principals` (nodes); projection `Cohort` / `Global` (trust root) | persist projection; edge bridge `resolved_peer_set` | `RecipientNotInSendSet` | bridge send-set tests ✓ |
| **R3** — | no key | — | — | — |
| **R4** holder known | `list_holders(sha)` from the claim index | edge `pull_one_inner`; persist `list_holders` | `NoHolders` | `blob_federation_e2e` commons leg ✓ |
| **R5** holder addressed | `ContentScope::Federation` ⇒ the holder's **federation address**; the router never consults the table | edge `BlobScopeRouter::route` (`Federation => federation()`) | — (unroutable only if the holder is undiscovered: `NotYetDiscovered`) | `scope.rs::public_content_rides_the_federation_address` ✓ |
| **R6** holder serves | `allows_recipient_scope(Public, _) == true`: any arrival | edge `admit_blob_serve` | — | `scope.rs` serve tests ✓ |
| **R7** bytes adopted | sha+size verified; **store gate = the allowlist** (`SenderStanding::Allowlisted`, nothing substitutes); `is_audience` commons arm = everyone | edge `store_gate`; persist `would_hold` | `SenderNotAllowlisted` | `store_gate::commons_content_needs_the_allowlist_and_nothing_else_substitutes` ✓ |
| **R8** reader opens | plaintext | — | — | `blob_federation_e2e::a_commons_blob_opens_on_any_node_because_no_key_is_involved` ✓ |
| **R9** withdraw reaches holders | tombstone at the plane's ceiling (`Global` for a trust root); every holder evicts | edge `revocation` | `Revoked` | `revocation.rs` ✓ |
| **R10** listed | the row plane | server | — | — |

### 5.3 Self — the open row set (CIRISPersist#884 / CIRISEdge#646)

| rung | what must be true | owner | refusal by name | witness |
|---|---|---|---|---|
| **R0** producer writes | seal under a per-write DEK wrapped to **every active occurrence**; pointer (`tier: InvisibleEncrypted`, `epoch: None`) + citation; **no holder claim** (I52). The row names its author; the self group id is a **function of the author** (§6.2), not a field | persist `put_blob_scoped` (self branch) | `readable_by_nobody` | persist I52 ✓; `store_gate::an_invisible_scope_cannot_be_announced_however_the_operator_asks` ✓ |
| **R1** — | no widening: the authored row IS the row | — | — | — |
| **R2** row reaches every node of the identity | the **nodes hosting** the identity's active occurrences are **implicit** send-set members for `SelfOwn` planes — no grant (CC 3.3.6 / 3.2); occurrence → node by CC 4.4.3.2.4.1(b) | **persist** `send_set_for(k, self)` (v46.3.0); edge `ResolvedPeerSet::widened_by_self_collective` + `Reach` (v29.3.0) | `RecipientNotInSendSet` (names the axis: `peer reached by the self_collective axis, which carries no federation rows`) | persist I137–I140 ✓; edge `bridge::the_owners_second_node_is_a_recipient_with_no_grant_between_them` ✓, `resolved_state::a_reach_admits_exactly_the_scopes…` ✓ |
| **R3** key reaches every occurrence | the content-axis set travels with the row (`key_grant:*` at self ⇒ `SelfOwn`); **retroactive on new occurrence** (CC 8.1.12.4) | persist cascade (write ✓); persist retroactive (§6.5) | `NotGranted` | write: cascade tests ✓; retroactive: — *(persist: "a device admitted after the write opens the write")* |
| **R4** holder known | **no discovery, no minter read.** Holders = `contact::resolve(row.author_key_id).nodes` — the author's nodes; the sealing node is among them, and on the content axis the minter *is* the author (admission rule) | edge `pull_one_inner` source rule (§6.2) | `NoOtherNode` (terminal, honest) — never `NoHolders` for these scopes | — *(edge: "a self row's pull asks the author's nodes, never list_holders")* |
| **R5** holder addressed | `BlobMeaning::project` yields `Group { SelfOnly, group_id = identity }` (today: `GroupWithoutId`); the **self room** installed: members = the identity's nodes (§6.3) | edge `meaning.rs` self arm; `self_addressing::snapshot`; host drives install / advance / refresh | `blob_group_not_installed { scope: self }` | — *(edge: "two nodes of one identity derive each other's self addresses"; "a self row projects its identity as the group id")* |
| **R6** holder serves | arrival on the self group ∧ requester `OwnNode` (principal equality) | edge `admit_blob_serve` ✓ + `SenderStanding::OwnNode` ✓ | `blob_serve_arrival_scope_insufficient` | `scope.rs` serve tests cover the gate shape ✓; self-specific: — |
| **R7** bytes adopted | `is_audience` self arm (principal equality, after #873) ✓; adopt `LocalOnly` (never announce) ✓ | persist `would_hold` / `adopt_sealed_blob` | `NotPartyTo` (correct for a non-owner) | persist I135 ✓ (a self row keeps self; a non-owner is `NotPartyTo`) |
| **R8** reader opens | wrap for **this device's** occurrence | edge `group_content` ✓ | `Body::Unopened` | — *(e2e: "the owner's second device opens what the first wrote")* |
| **R9** withdraw reaches the nodes | `withdraws` is a **tombstone**: it projects at the Attestation plane's ceiling (`Global` / `Cohort` / `Capability` / `Subject` — never `SelfOwn`; transport FSD §3.2, persist `tombstone_ceiling`), so a withdrawal authored on B for A's row is relayed, not suppressed; the audience gate at admission stays the self arm; the register evicts locally | persist projection; edge `revocation` ✓ | `Revoked` | — *(edge: "a withdraws for a self row projects at the ceiling and evicts on every node of the identity")* |
| **R10** the drive lists it | every self row held on any node, with **row-held / bytes-absent** as a first-class state | server `GET /v1/drive` over the row plane (CIRISServer#615 §3) | `not_fetched` shown as "on another device" | — |

Rungs R2 and R3-retroactive are prerequisites for everything beneath them; a ladder that reaches R4
with R2 red is testing the wrong thing.

### 5.4 Family — self's row set with membership in place of principal equality

The predicates differ at every rung that says "the owner": family membership is a roster fact
(`list_families_for_member_active`), principal equality is a directory fact. A self witness cannot
prove a family branch — each row below names its own.

| rung | what differs from §5.3 | owner | refusal by name | witness |
|---|---|---|---|---|
| **R0** producer writes | DEK wrapped to every active occurrence of **every member**; the row carries **`family_id`** (CC 5.2 `C.family_id`) — the group id for R5 | persist `put_blob_scoped` (family branch) | `readable_by_nobody` | persist family cascade ✓ |
| **R2** row reaches every member's nodes | send set ∪= the nodes hosting each active member's occurrences (implicit) | persist §6.1 | `RecipientNotInSendSet` | — *(persist: "a family row authored by A is held on member B's node with no grant")* |
| **R3** key reaches every member | wrapped per member at write; **retroactive on new member** (CC 8.1.12.4) | persist §6.5 | `NotGranted` | — *(persist: "a member admitted after the write opens the write")* |
| **R4** holder known | the author's nodes (as self); a member's node that adopted may serve but **nothing points at it** (§6.4) | edge §6.2 | `NoOtherNode` | — *(edge: "a family row's pull asks the author's nodes, never list_holders")* |
| **R5** holder addressed | `BlobMeaning::project` yields `Group { Family, group_id = family_id }`; the **family group** installed: members = the nodes of every active member | edge `meaning.rs` family arm; `family_addressing::snapshot`; host drives on roster change | `blob_group_not_installed { scope: family }` | — *(edge: "two members' nodes derive each other's family addresses"; "a family row projects its family_id as the group id")* |
| **R6** holder serves | arrival on the family group ∧ requester is an active member's node (`SenderStanding::MemberOfJoinedGroup` at family) | edge `admit_blob_serve` | `blob_serve_arrival_scope_insufficient` | — *(edge: "a member's node is served on the family address; a non-member's node is refused by name")* |
| **R7** bytes adopted | `is_audience` family arm (`author_is_local_or_family`); adopt `LocalOnly` | persist | `NotPartyTo` | — *(persist: "a family row adopts on a member's node and is `NotPartyTo` on a non-member's")* |
| **R8** reader opens | wrap for this device's occurrence, as a member | edge `group_content` | `Body::Unopened` | — *(e2e: "a member's device opens what another member wrote")* |
| **R9** withdraw | tombstone ceiling projection, as self; evicts on every member's node | persist; edge | `Revoked` | — |
| **R10** listed | the family's row plane | server | — | — |

Open question §12.1 (serve-from-non-author preference) stands.

## 6. The self/family design — five parts

### 6.1 The self-collective is implicit in the send set (persist) — in nodes

For every `SelfOwn`-projected plane, the send set of key `k` is
`consent_peers_by_principals(k) ∪ nodes(occurrences(principal_of(k)))`, and for family planes
additionally `nodes(occurrences(m))` for every active member `m`. **The union is of nodes, not
occurrences**: an occurrence is a KEM target (CC 3.3.6.1), and the runtime hosts device-class
occurrences with no destination and, under `use_node_identity` (#541), an actor occurrence whose
node is a different key. The occurrence → node step is CC 4.4.3.2.4.1(b) — the occurrence's signed
`transport_destination` — which is the resolution `contact::resolve` and `snapshot_for_nodes`
already perform for community members; persist's send set is already in node key ids. Persist
v46.3.0 ships it as `send_set_for(k, cohort_scope)`, the union taken over the **nodes hosting** each
occurrence (`nodes_owned_by` over `principals_of(k)`), never the occurrence keys. Edge v29.3.0
consumes it in the one minting door: `ResolvedPeerSet` is widened by the `self` and `family` sets and
each recipient carries its `Reach` (`Consent` / `SelfCollective` / `Family`), which the per-row
audience gate checks before the principal walk — so a family member's node is in the set for
`family` rows and for nothing wider, exactly persist's per-scope rule. No grant is authored or read
for this set: CC 3.2 makes an owner's consent to their own node a category error,
CC 3.3.6 makes membership a cryptographic fact. Edge consumes it through the existing
`resolved_peer_set`; nothing on edge changes at this rung except that the rows arrive.

**Before v46.3.0 / v29.3.0** the set was explicit grants only, the server authored none between an
owner's nodes, and persist#884's own report could find no witness of a self row on a second device.
This was the rung under every other rung, and the one persist's reading on #884 assumed rather than
measured. Persist v46.3.0 also closed the defect under §6.2's premise: the content-axis set is signed
by the sealing NODE while the adopted row names the PERSON, so `signer == author` retired every set on
a second device — now `speaks_for(signer, author)` (shared principal), and `is_audience`'s self arm
compares principals.

### 6.2 The holder is known by construction — the source rule (edge; no new persist read)

Two facts make the holder a function of the row:

1. **On the content axis the minter is the author.** Persist admits a self/family `key_grant` set
   only if its signer equals the blob row's `author_key_id` (`key_grant.rs` §12). The epoch-axis rule
   — minter named or derived, never the author — is about community, where several members mint;
   here there is one sealer and the row names it. A `minter_of(scope, epoch)` read is not callable
   for these tiers anyway: `BlobPointer::epoch` is `None` outside `CommunityDek`.
2. **The author is an occurrence; the holder is a node.** The sealing node is the one hosting the
   author occurrence, reached by CC 4.4.3.2.4.1(b). Every node of the same identity is a self-room
   member and a legitimate fetch target, so the resolution `contact::resolve(author_key_id).nodes`
   (owner → nodes) is both sufficient and bounded: the sealing node is in it, the rest are the
   opportunistic fallback.

`pull_one_inner` branches on `meaning.scope()`:

```
Federation        → holders = list_holders(sha)                        (unchanged; §5.2 R4)
Cohort            → holders = list_holders(sha)                        (unchanged; §5.1 R4)
SelfOnly | Family → holders = contact::resolve(row.author_key_id).nodes  // the author's nodes,
                    ordered with the node whose TransportBinding holds the author occurrence's
                    transport_destination first; list_holders is NEVER consulted; NoHolders is not
                    a possible outcome; empty → NoOtherNode (terminal, refused by name)
```

The row's **sender** is not the holder by construction — device B re-advertises A's rows to C, so
C's sender may be row-held / bytes-absent. Sender-as-holder is a first-hop coincidence;
author's-nodes-as-holders is the invariant. (Correction to persist's reading on #884.)

**The group id is a function of the row, never a new field.** `BlobMeaning::project` maps `self` and
`family` to `ContentScope::Group` and today refuses both as `GroupWithoutId` because it looks for a
community id. The rule: **self** → `identity_key_id` of the author's self-collective (CC 3.3.6; the
principal `#873` already resolves — the projector takes it from the lens the puller holds);
**family** → the row's `family_id` (CC 5.2 names it on the Contribution; persist confirms the
envelope carrier, §12.2). The installer (§6.3) names its group by the same function of the same
directory fact, which is what makes "the projected id matches the installed id" true by construction
rather than by a write-time field kept in sync.

The fetch itself is `fetch_blob_scoped_with_disposition(sha, manifest, holders, meaning)`, which
already takes a caller-supplied holder list and routes each through `BlobScopeRouter` — so R5's
derived address is used exactly as for community. Retries are meaningful (a device coming online),
so the pull sink's re-ask keeps its cadence.

### 6.3 Addressing: the self room (edge) — and how it is bootstrapped

CC 5.4.6 lists `self` among the group-scoped tiers whose destinations are "resolved DETERMINISTICALLY
from (cached directory entry + per-group HKDF) — every member derives the same destination", using
"the same group-and-epoch-bound key schedule the substrate already uses" — the MLS exporter. So the
self room is a **per-identity MLS group** (`CohortGroup`), not a derivation from the occurrence list:
an occurrence roster alone yields no shared secret, and two nodes that each `create` would derive
different secrets and address each other at destinations nobody registered. The fetch-over-
federation-address alternative the first draft left open is closed by this reading — it is not the
CC 5.4.6 construction for a group-scoped tier.

**Members are nodes** (the lifecycle listens on `own_key_id`, the node key): the self room's roster is
`nodes(occurrences(identity))`, exactly §6.1's set. **Group id** = `self:<identity_key_id>`.

**Bootstrap — everything rides the row plane, which needs no self room.** KeyPackage, Welcome and
Commit are `SelfOwn` rows (the community rooms already carry them as rows: `chat::KEY_PACKAGE_DIMENSION`,
`WELCOME_DIMENSION`); they reach every node of the identity by R2 over ordinary federation-addressed
links (the lightnet facts CC 1.13.3.1 concedes). Only the bytes (R5–R8) need the room.

```
creator      the canonical-first node of the identity (lowest node key_id among the nodes hosting
             active occurrences, CC 4.4.3.2.4.1(a) ordering) that holds no self-room state creates
             the group; every other node publishes a KeyPackage row and WAITS. A CreationClaim
             (at_ms, creator_key_id) rides the first Commit; a node that created and then admits a
             Welcome for the same group id with an earlier claim abandons its own group and joins
             (the #604 CommitClaim rule, applied one level up)
new node B   B announces its occurrence → B publishes KeyPackage(self) → any member (the creator,
             or whichever member admits the KeyPackage first) commits Add(B): Commit row +
             Welcome row, the Welcome HPKE-wrapped under B's occurrence X-Wing key (CC 5.4.4)
             → B admits the Welcome → CohortGroup::join → self_addressing::snapshot → install
             → the epoch advanced on every member → advance (make-before-break, seal on cadence)
concurrent   two members commit at once → #604 convergent merge (earliest claimed_at, lowest
             committer key_id), rollback within the retention window — nothing new
late member  a node whose occurrence announce reached this node AFTER the room was installed at
             the same epoch → ScopeLifecycle::refresh_members (CIRISEdge#648): admit it without
             rotating and without a window in which anyone is unaddressed
revocation   IdentityOccurrenceRevocation → any member commits Remove → epoch advances → advance;
             the removed node's addresses seal out on cadence
creator lost the group lives in every member; there is no creator role after creation. An identity
             whose every node lost state is a single-node identity again and the rule above recreates
```

`self_addressing::snapshot(identity, lens)` is the twin of `cohort_addressing::snapshot_for_nodes`:
it reads the identity's active occurrences, resolves them to nodes, and hands the lifecycle a
`ScopeGroupSnapshot` from the self room's `destination_secret`. **Family** is the same shape with the
roster from `list_families_for_member_active` and group id `family:<family_id>`; the creator rule
orders over the members' nodes.

This reuses the CC 5.4.6 substrate — derived addresses are transport privacy for *any* non-public
cohort — without being the community approach: no holder claim, no swarm discovery, no community
roster, no widening; the roster IS the occurrence list, and the room's only job is the address.

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
B joins   (R2)  B's occurrence announced; B's KeyPackage row reaches A; A commits Add(B): Commit +
                Welcome rows reach B (SelfOwn, implicit send set, federation-addressed links)
B         (R5)  B joins the self room from the Welcome → install; A advances (epoch moved)
B         (R3') persist re-grants extant content to B (retroactive, §6.5)
A writes  (R0)  seal → DEK wrapped to {A, B} → row(self, pointer, citation) → content-axis key_grant set (signer = A)
A → B     (R2)  row + set ride SelfOwn to B                                     ← today: never leaves A
B         (R3)  admits the set; wrap for B's occurrence projected
B         (R4)  pull: scope=self → holders = nodes(owner(A)) = [A, B]; list_holders untouched
B         (R5)  project → Group { SelfOnly, self:<identity> } → route to A's derived self address
A         (R6)  arrival = self room ∧ requester principal == owner → serve
B         (R7)  sha+size verified → adopt LocalOnly (is_audience self arm)
B         (R8)  open with B's wrap
C joins         as B; C runs R4–R8 against A or B — both are the author's nodes
```

## 7. Invariants — and the mutant each must kill

1. **No `holds_bytes` for self/family at any audience.** persist I52 stays as written; edge
   `announce_is_possible(SelfOnly | Family) == false` stays, and (CIRISEdge#646 ask 1) asks the
   substrate's predicate rather than restating it. *Mutant:* a claim emitted at `self` scope → I52 red.
2. **Audience from the row, never the pointer.** persist#878 I135. *Mutant:* "scope from the pointer"
   → a non-owner becomes party to a `self` row → I135 red.
3. **Key plane from the pointer, never the row's scope.** persist#878 I132–I134; edge
   `pull.rs::a_pointer_only_chat_row_keeps_the_pointers_tier_and_community`.
4. **Minter named or derived, never the author — on the epoch axis.** persist#876 I126–I130; edge
   `pull.rs::the_minter_is_never_transcribed_from_the_author`. On the content axis (self/family) the
   signer MUST equal the author (persist `key_grant.rs` §12) — the two rules are one rule read from
   each axis, and a self/family holder lookup keyed by epoch is unconstructible (`epoch: None`).
5. **Every producer cites.** A row that references bytes carries them in `evidence_refs`
   (CIRISEdge#646). *Mutant:* drop the citation → persist's index cannot find the row → revocation's
   known set incomplete → `revocation.rs::a_blob_is_revoked_only_when_every_known_reference_is_withdrawn` red.
6. **For self/family, `list_holders` is never consulted and `NoHolders` is not a possible outcome.**
   *Mutant:* fall through to `list_holders` → the new witness (`a self row's pull asks the author's
   nodes, never list_holders`) red.
7. **The half-wired host state is unconstructible** (v27.0.0): `SealedContentWiring`,
   `answers_scope`; the self room adds nothing new here — its installer is a lifecycle drive like the
   room's, and a scope-native node without it refuses at R5 by name, never silently.
8. **A refusal is the branch, never a disjunction** (CIRISEdge#433, #640): every rung above names its
   own refusal; two rungs never share one.
9. **Rounds carry rows and keys; bytes never enter a round.** *Mutant:* route a `BlobChunk*` through
   the registry → `NotAReplicationFrame` is the only admissible outcome; a ladder attributing a fetch
   failure to §5.4.2 is reading the wrong table.
10. **A send set, a scope group and a holder list contain nodes, never occurrences.** *Mutant:* union
    the occurrence keys into `resolved_peer_set` → a round against a device-class occurrence
    (`NotYetDiscovered` forever) — the witness "a self row reaches the NODE hosting a device-class
    occurrence" red.
11. **One self room per identity.** Two nodes of one identity never hold two groups under one id past
    one convergence window. *Mutant:* both create → the later CreationClaim never abandons → B's fetch
    routes to an address A never registered → `mine_on_b` red at R5 with `blob_group_not_installed`
    on A's side reading healthy: exactly the CIRISEdge#646 shape this document exists to prevent.

## 8. Observability — what a run must be able to say

| counter / line | rung | exists |
|---|---|---|
| `bootstrap_door_outcomes`, `link_before_binding` | §5.4.1 | ✓ v26.1.0 |
| `replication_routed_to_{responder,initiator}_total`, `replication_reply_dropped_total` | §5.4.2 | ✓ v26.0.0 |
| `key_grant set admitted — wraps … projected as grants` | R3 | ✓ (persist INFO) |
| `pull … outcome=` (`NoHolders` / `NoOtherOccurrence` / `FetchFailed` / `StoreFailed` / `Stored`) | R4–R7 | ✓; `NoOtherOccurrence` — |
| **`blob_pull_sources`** by scope kind × source (`list_holders` / `author_nodes` / `pushed`) | R4 | — (new; the one line that proves self never touched the directory) |
| `blob_route_refusals` (`blob_group_not_installed` / `…not_in_group` / `…sealed_out`) | R5 | ✓ v26.2.0 |
| `blob_serve_refusals` | R6 | ✓ v27.0.0 |
| `scope lifecycle INSTALLED / ADVANCED / REFRESHED` (scope, group, epoch, members, added/removed) | R5 | ✓ v26.2.0 / v29.2.0 (#648); self room: — |
| `self room CREATED / JOINED / ABANDONED(claim)` (identity, creator, claim) | R5 | — |
| `blob meaning projected` with `group_id` provenance (`identity` / `family_id` / `community`) | R5 | — |
| `chat: body opened` / `Body::Unopened { reason }` | R8 | ✓ |
| ladder stages: `bound`, `sent`, `arrived`, `hamburger` | community | ✓ (server); **`mine_on_b`** for self — |

The ladder's merged narrative (CIRISServer#612) already prints R2–R8 for community in time order;
the self row set adds `mine_on_b` = "a self row written on A opened on B", with the rung named on red.

## 9. The DX contract at every cohort — what a host wires, what is automatic

| | host MUST wire | automatic once wired |
|---|---|---|
| **all** | `ReplicationRuntimeConfig::local_key_id`; `sealed_content: SealedContentWiring { engine, pull_sink, revocations }`; a `BlobChunkSource` with `answers_scope() -> true` if scope-native; `kick()` after publishing | rounds, propagation kicks, key-grant projection, pull on admitted rows, revocation eviction |
| **community** | the widen (`share(.., With::Community, ..)`); `ScopeLifecycle::install` on `Keyed` with `snapshot_for_nodes`, `advance` on epoch change, `seal_due` on a cadence | holder claim, discovery, swarm pull, serve, adopt, announce |
| **self / family** | nothing new in the config; the self-room drive beside the chat-room drive: `self_addressing::snapshot` → `install` on join, `advance` on every Commit, `refresh_members` (#648) when an occurrence resolves late, `seal_due` on the cadence; publish the KeyPackage row on first start | the creator rule, Welcome/Commit rows, the implicit send set (persist), author's-nodes fetch, `LocalOnly` adopt, retroactive re-grant (persist) |
| **commons** | the allowlist (`SenderStanding::Allowlisted`) | everything else |
| **client** (CIRISServer#615) | create: descriptor + bytes with `size`; read: verify → sniff → policy; enumerate: `GET /v1/drive` over the row plane, cursor `since`, row-held/bytes-absent as a state | — |

## 10. Sequencing

1. **persist**: §6.1 implicit send set (in nodes) → §6.5 retroactive re-grant → confirm the `family_id`
   carrier (§12.2). The first two are prerequisites for any self row or key to exist on device B;
   nothing on edge can be witnessed end to end before them. No `minter_of` read is asked for.
2. **edge**: `BlobMeaning::project` group-id rule (§6.2; unblocks R5 for both tiers) → §6.2 source
   rule (buildable now: `contact::resolve` exists) → §6.3 self room: creator rule + CreationClaim,
   KeyPackage/Welcome/Commit as `SelfOwn` rows, `self_addressing::snapshot` → `blob_pull_sources`
   counter → `announce_is_possible` asks the substrate (#646 ask 1). `refresh_members` (#648) lands
   first and independently.
3. **server**: the self-room drive beside the chat-room drive (§9); the `mine_on_b` ladder stage; the
   drive read.
4. **mixed fleet**: a pre-cut device is simply an occurrence that never asks; nothing it holds changes
   meaning. No wire change in any of the above.

## 11. Acceptance

Every "—" in §5.2 / §5.3 / §5.4 / §8 becomes a named test on the owning side before the rung is
called green — the family witnesses in §5.4 are their own, exercised with a **second member**, since
membership and principal equality are different predicates — and the ladder prints `mine_on_b` with
the rung named on red. The community row set (§5.1) is the
template: it is green because each rung has a witness, not because a run passed.

## 12. Genuinely open

1. **Family serve-from-non-author.** Persist's reading (no advertisement; opportunistic serve only) is
   CC-conformant; whether a family member's node should *prefer* a nearer member that adopted, without a
   claim, is a policy question for the Constitution (locality dividend vs. "nothing points anyone at it").
2. **The `family_id` carrier.** CC 5.2 names `C.family_id` on a family Contribution; persist's family
   audience arm is membership-based (`author_is_local_or_family`) and does not read it. The projector
   needs the field name on the envelope — a persist confirmation, not a design question.
3. **Push-on-write scope.** Whether the sealing device pushes to *every* online node or only those on a
   live link is a cost question, not a correctness one.

## 13. Changelog

- **2026-09-22 (PR #647 review).** Nine findings, each checked against code and CC before the text
  moved: §2 is a fork (bytes ride envelope dispatch, never a round); §3 gains Node and the two key-grant
  axes; §5.2 has its own rows; §5.3 R4 drops the `minter_of(scope, epoch)` read (`epoch: None` at the
  invisible tier; content-axis signer = author by admission) for the author's nodes; R5 states the
  group-id rule (`GroupWithoutId` today); R9 states the tombstone-ceiling projection; §5.4 has its own
  witnesses; §6.1 unions nodes, not occurrences; §6.3 specifies the self room's MLS bootstrap
  (creator rule, KeyPackage/Welcome/Commit as `SelfOwn` rows, #604 merge, #648 refresh) and closes the
  federation-address alternative on CC 5.4.6's reading; invariants 9–11 added.
