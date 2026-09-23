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
| byte movement | **delivery**: addressed fetch from the author's nodes; push-on-write optional | delivery, as self | discovery + swarm pull (`BlobPuller`, up to 2 holders) | discovery + swarm pull |
| **file shape** (§6.7) | inline ≤ 1 MiB (CC 2.6.1.3), else a sealed **chunk DAG** (CC 5.3.3.1) — **the DAG door is not built: CIRISPersist#821 Q1/Q2, CIRISEdge#633** | same | same | same |
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
| **R10** listed | the room's file rows, by `community_key_id` | **blocked on CIRISPersist#893** (§6.8.1): the §4.3 gate's community arm cannot match a row AV-84 admits | `DriveGateUnavailable` — refused by name, never silently empty | — |

### 5.3 Self — the open row set (CIRISPersist#884 / CIRISEdge#646)

| rung | what must be true | owner | refusal by name | witness |
|---|---|---|---|---|
| **R0** producer writes | seal under a per-write DEK wrapped to **every active occurrence**; pointer (`tier: InvisibleEncrypted`, `epoch: None`) + citation; **no holder claim** (I52). The row names its author; the self group id is a **function of the author** (§6.2), not a field | persist `put_blob_scoped` (self branch) | `readable_by_nobody` | persist I52 ✓; `store_gate::an_invisible_scope_cannot_be_announced_however_the_operator_asks` ✓ |
| **R1** — | no widening: the authored row IS the row | — | — | — |
| **R2** row reaches every node of the identity | the **nodes hosting** the identity's active occurrences are **implicit** send-set members for `SelfOwn` planes — no grant (CC 3.3.6 / 3.2); occurrence → node by CC 4.4.3.2.4.1(b) | **persist** `send_set_for(k, self)` (v46.3.0); edge `ResolvedPeerSet::widened_by_self_collective` + `Reach` (v29.3.0) | `RecipientNotInSendSet` (names the axis: `peer reached by the self_collective axis, which carries no federation rows`) | persist I137–I140 ✓; edge `bridge::the_owners_second_node_is_a_recipient_with_no_grant_between_them` ✓, `resolved_state::a_reach_admits_exactly_the_scopes…` ✓ |
| **R3** key reaches every occurrence | the content-axis set travels with the row (`key_grant:*` at self ⇒ `SelfOwn`); **retroactive on new occurrence** (CC 8.1.12.4) | persist cascade (write ✓); persist retroactive (§6.5) | `NotGranted` | write: cascade tests ✓; retroactive: — *(persist: "a device admitted after the write opens the write")* |
| **R4** holder known | **no discovery, no minter read.** Holders = `contact::resolve(row.author_key_id).nodes` — the author's nodes; the sealing node is among them, and on the content axis the minter *is* the author (admission rule). The source follows the **key plane's tier** (`InvisibleEncrypted` ⇒ author's nodes; else the claim index) | edge `pull_one_inner` source rule (§6.2) ✓ v29.4.0; counter `blob_pull_sources{self:author_nodes}` | `NoOtherNode { retrying }` — never `NoHolders` for these tiers | `blob_federation_e2e::a_self_rows_pull_asks_the_authors_nodes_and_never_the_claim_index` ✓ (alice's phone pulls alice's file: source = author's nodes, `OwnNode` clears the gate, the router refuses R5 by name) |
| **R5** holder addressed | `BlobMeaning::project` yields `Group { SelfOnly, group_id = identity }` ✓ v29.4.0 (the pointer's group slot carries the OWNER at `self` — persist's own convention; else the author's identity the puller resolved); the **self room** installed: members = the identity's nodes (§6.3) | edge `meaning.rs` self arm ✓; `self_addressing::snapshot` —; host drives install / advance / refresh | `blob_group_not_installed { scope: self }` / `NO scope address table` | projector: `meaning::facets_646::a_self_row_without_a_community_projects_the_authors_identity_as_its_group` ✓; room: — *(edge: "two nodes of one identity derive each other's self addresses")* |
| **R6** holder serves | arrival on the self group ∧ requester `OwnNode` (principal equality) | edge `admit_blob_serve` ✓ + `SenderStanding::OwnNode` ✓ | `blob_serve_arrival_scope_insufficient` | `scope.rs` serve tests cover the gate shape ✓; self-specific: — |
| **R7** bytes adopted | `is_audience` self arm (principal equality, after #873) ✓; adopt `LocalOnly` (never announce) ✓ | persist `would_hold` / `adopt_sealed_blob` | `NotPartyTo` (correct for a non-owner) | persist I135 ✓ (a self row keeps self; a non-owner is `NotPartyTo`) |
| **R8** reader opens | wrap for **this device's** occurrence | edge `group_content` ✓ | `Body::Unopened` | — *(e2e: "the owner's second device opens what the first wrote")* |
| **R9** withdraw reaches the nodes | `withdraws` is a **tombstone**: it projects at the Attestation plane's ceiling (`Global` / `Cohort` / `Capability` / `Subject` — never `SelfOwn`; transport FSD §3.2, persist `tombstone_ceiling`), so a withdrawal authored on B for A's row is relayed, not suppressed; the audience gate at admission stays the self arm; the register evicts locally | persist projection; edge `revocation` ✓ | `Revoked` | — *(edge: "a withdraws for a self row projects at the ceiling and evicts on every node of the identity")* |
| **R10** the drive lists it | every self file row held on any node, with **row-held / bytes-absent** as a first-class state | edge `files::in_room` ✓ v29.6.0 — persist's **gated** query (`cohort_scope` + `dimension_exact` on `Engine::list_attestations`, §4.3 composed after the filter); server `GET /v1/drive` over it (CIRISServer#615 §3) | `not_fetched` shown as "on another device" (`UnopenedReason`) | edge: `a_self_rows_pull_asks…` reads the drive back through the gated door ✓; server: — |

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
| **R5** holder addressed | `BlobMeaning::project` yields `Group { Family, group_id = family_key_id }` ✓ v29.4.0 (read through persist's `envelope_cohort_target`, four aliases, disagreement refused `GroupIdAmbiguous` — CIRISPersist#887); the **family group** installed: members = the nodes of every active member | edge `meaning.rs` family arm ✓; `family_addressing::snapshot` —; host drives on roster change | `blob_group_not_installed { scope: family }` | projector: `meaning::facets_646::a_family_row_reads_family_key_id_through_persists_cohort_target_reader` ✓; group: — |
| **R6** holder serves | arrival on the family group ∧ requester is an active member's node (`SenderStanding::MemberOfJoinedGroup` at family) | edge `admit_blob_serve` | `blob_serve_arrival_scope_insufficient` | — *(edge: "a member's node is served on the family address; a non-member's node is refused by name")* |
| **R7** bytes adopted | `is_audience` family arm (`author_is_local_or_family`); adopt `LocalOnly` | persist | `NotPartyTo` | — *(persist: "a family row adopts on a member's node and is `NotPartyTo` on a non-member's")* |
| **R8** reader opens | wrap for this device's occurrence, as a member | edge `group_content` | `Body::Unopened` | — *(e2e: "a member's device opens what another member wrote")* |
| **R9** withdraw | tombstone ceiling projection, as self; evicts on every member's node | persist; edge | `Revoked` | — |
| **R10** listed | the family's file rows, by `family_key_id` | **blocked on CIRISPersist#893** (§6.8.1): the §4.3 gate's family arm cannot match a row AV-84 admits | `DriveGateUnavailable` — refused by name, never silently empty | — |

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

`pull_one_inner` branches on the **key plane's tier** (shipped v29.4.0):

```
Plaintext | CommunityDek → holders = list_holders(sha)                     (unchanged; §5.1/§5.2 R4)
InvisibleEncrypted       → holders = contact::resolve(row.author_key_id).nodes \ {self}
                           // the author's nodes; list_holders is NEVER consulted; NoHolders is not
                           // a possible outcome; none resolved / directory not converged →
                           // NoOtherNode { retrying } (a device coming online is a retry)
```
Counter `blob_pull_sources{scope:source}` (`self:author_nodes` … `federation:claim_index`) is the
line a run greps to prove a self pull never touched the directory.

The row's **sender** is not the holder by construction — device B re-advertises A's rows to C, so
C's sender may be row-held / bytes-absent. Sender-as-holder is a first-hop coincidence;
author's-nodes-as-holders is the invariant. (Correction to persist's reading on #884.)

**The group id is a function of the row, never a new field** (shipped v29.4.0). `BlobMeaning::project`
reads it in order: the pointer's group slot — which at `self` carries the **owner's** key id and at
`family` the family's, by persist's own `put_blob_scoped` convention — then the envelope's cohort
target through persist's `envelope_cohort_target` (four aliases, first non-empty, a disagreement
refused `GroupIdAmbiguous`; `family_key_id` is the canonical member, CIRISPersist#887), then for a
`self` row the author's identity the puller resolved (`project_with(row, sha, identity)`). The
installer (§6.3) names its group by the same function of the same directory fact, which is what
makes "the projected id matches the installed id" true by construction.

**Two facets, one meaning** (v29.4.0). `BlobMeaning::scope()` is the row's **placement**; `key_plane()`
is the pointer's group (persist#878). They differ on one shape: the owner's own copy of a room
message — placed `self`, sealed under the room's DEK. Holder source, route and the store gate's
**trust** axis follow the key plane (a room member hands over the room's bytes); audience, adopt
disposition and announce follow the placement. Routing that copy to a `self` table keyed by the room
would ask for a group nobody installs; routing it to the room asks the members who hold it.

The fetch itself is `fetch_blob_scoped_with_disposition(sha, manifest, holders, meaning)`, which
already takes a caller-supplied holder list and routes each through `BlobScopeRouter` — so R5's
derived address is used exactly as for community. Retries are meaningful (a device coming online),
so the pull sink's re-ask keeps its cadence.

### 6.3 Addressing: the self room (edge) — and how it is bootstrapped

CC 5.4.6 lists `self` among the group-scoped tiers whose destinations are "resolved DETERMINISTICALLY
from (cached directory entry + per-group HKDF) — every member derives the same destination", using
"the same group-and-epoch-bound key schedule the substrate already uses" — the MLS exporter. So the
self room is an ordinary `CohortGroup` whose members are the identity's **nodes**; nothing about it is
new machinery. The fetch-over-federation-address alternative the first draft left open is closed by
this reading — it is not the CC 5.4.6 construction for a group-scoped tier.

**Naming (shipped v29.5.0).** Every question about a room's identity is asked of one type,
`scope_room::ScopeRoom` — `Community{community_key_id}` / `SelfCollective{identity_key_id}` /
`Family{family_key_id}` — which answers: the cohort `scope()`, the `content_group_id()` a row and
pointer carry, the `table_group_id()` the lifecycle installs under, the `cohort_target_field()` a row
places itself with (`community_key_id` / `family_key_id` / none), the `row_scope_token()`, and the
`widen_to()` audience. Before it, the first three were spelled in three files and a disagreement was
silent on both sides of the wire (CIRISEdge#616/#619). **The table's key is the pair
`(CohortScope, group_id)`**, so the scope already discriminates: a community keeps its `cohort:`
namespace (installed under it today), and self and family take the bare id. An earlier draft of this
section said `self:<identity_key_id>`; the pair is the key, so a prefix would buy a migration and
nothing else.

**Members are nodes**; the roster is the DIRECTORY's answer (`self_room::roster` → `nodes_owned_by`,
the same walk the send set's node half uses), and the MLS tree is the state this node has converged
to. The difference between them is the work.

**Nobody creates it.** A community room is created by a person inviting another; a self room must
appear the moment an identity has a second device, with no human act — and if two devices each
create one they derive different secrets and address each other at destinations nobody registered.
So the rule is edge's, as a pure total function (`self_room::decide`, shipped v29.5.0), and the IO is
the host's — the same split `ScopeLifecycle`'s verbs already use, which is what keeps two hosts from
disagreeing about who creates:

| this node's state | decision | the host does |
|---|---|---|
| not in the directory's roster | `NotInRoster` | fix the owner binding; never derive |
| roster is just me | `SoleDevice` | nothing; it ends when a second device announces |
| no room, I am canonical-first (lowest key id) | `Create` | `CohortGroup::create`, stamp the `CommitClaim` |
| no room, someone else is first (or a rival room is known) | `PublishKeyPackage` | publish a KeyPackage row at `self` |
| hold the room, directory has devices the tree lacks | `Add(nodes)` | `add_member` per published KeyPackage → Commit + Welcome rows |
| hold the room, tree has devices the directory dropped | `Remove(nodes)` | `remove_member` → the epoch advances, forward-securing what follows |
| hold the room, a rival claim wins | `Abandon{in_favour_of}` | drop it and join the winner's |
| converged | `Idle` | `seal_due` on the cadence |

**Concurrent creation is settled, not prevented.** In an unconverged directory B cannot see A, so B
believes it is first and a second room appears. Preventing that needs a coordination round the
substrate has no way to run; settling it needs only a total order, which `CommitClaim` already is
(earliest `asserted_at`, ties on the lowest committer key id — the CIRISEdge#604 rule one level up,
applied to creation itself). Both nodes abandon the same room from either arrival order.

**The bootstrap needs no room.** KeyPackage, Welcome and Commit are ordinary `self`-placed rows, so
they reach the identity's other nodes over the row plane — which since v29.3.0 carries a `self` row
to the owner's own nodes with no grant between them (R2). Only the BYTES need the room, so there is
no chicken-and-egg. Welcome is HPKE-wrapped under the invitee's X-Wing key (CC 5.4.4).

`self_room::snapshot(group, identity)` is the twin of `cohort_addressing::snapshot`, differing only
in the key; there is no person-to-node walk and so no `unresolved` set, because the tree already
holds nodes. **Family** is the same shape with the roster from `list_families_for_member_active`
(§6.4).

This reuses the CC 5.4.6 substrate — derived addresses are transport privacy for *any* non-public
cohort — without being the community approach: no holder claim, no swarm discovery, no community
roster, no widening of the room itself; the roster IS the occurrence list, and the room's only job is
the address.

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

### 6.9 Local vs crossed — which `self` rows replicate, and which never leave

Two columns both get called "self" and they answer different questions. Conflating them is how a
row can be *correct here and invisible everywhere else*, so:

| | `tier = local` | `tier = federation` |
|---|---|---|
| **`cohort_scope = self`** | the **authored** row — this node's private working copy. **Never leaves, ever.** | the **crossed** row — replicates to the owner's other nodes |

- **`cohort_scope`** says *who may hold it*: the self-collective, and nobody else (CC 5.2, the
  audience gate, the adopt gate).
- **`tier`** says *whether it is in the stream at all*. Persist's **E5 invariant** excludes local-tier
  rows from the federation stream structurally — `list_attestations_since` is
  `… AND tier = 'federation'`, with persist's own test pinning that a local row never appears.

So: **a `self` row replicates iff it has crossed.** Every edge content producer authors at
`(self, local)` — `chat_row`, `files::file_row` — and the crossing (`attestation_bind::share` with
[`With::MyDevices`](crate) for a self room) mints the federation-tier row that others receive. This
is *not* a self-only rule: a community message is authored at `(self, local)` too and crosses to
`(community, federation)` — the self room's only difference is that its crossing target is the
owner's own devices rather than a room (CC 4.4.3.3.1's two-row widening, one code path).

Three consequences worth stating, because each was a silent failure waiting to happen:

1. **Skipping the crossing is not "a local-only file", it is a lost file.** It replicates nowhere and
   it does not appear in this node's own drive, since [§6.8]'s listing reads the federation stream.
   `files::publish` therefore always crosses, and reports `PublishedFile::crossed = false` with a WARN
   when the crossing PARKS awaiting an actor signature — authored, reaching nobody, recoverable.
2. **The drive lists crossed files only.** That is the honest set: an uncrossed row is one this node
   has not yet published to its own collective. A UI wanting "drafts" wants a different read.
3. **Every device re-advertises the collective's rows, not just the author's.** The `SelfOwn`
   advertise gate admits a row whose attester is in this node's publish set, and the owner's
   federation id is in that set on *every* device — so B re-offers A's crossed self rows to C. The
   collective converges rather than star-routing through whichever device happened to write the file,
   which is also why "the sender is a holder" is a first-hop coincidence and never the source rule
   (§6.2).

### 6.7 The shape of a file — inline, or a sealed chunk DAG (persist#821, edge#633)

Everything above moves a blob as **one object**. That is the whole story up to a size and no further,
and the boundary is not a tuning knob:

- **≤ 1 MiB** the bytes can ride inside the signed envelope. CC 2.6.1.3 bounds an envelope's canonical
  bytes at exactly that, and persist's `DEFAULT_INLINE_BYTES_CAP` is the same number for the same
  reason — the signed thing is the sized thing.
- **Above it** the content must be a **sealed chunk DAG** (CC 5.3.3.1: SFrame-conformant per-chunk
  AEAD, `(stream_id, counter)` nonce, ≤ 2²⁴ chunks per epoch), read by range, with a manifest pinning
  the chunk shas and the total size.

**Shape is chosen by access pattern, not by size** (`GROUP_CONTENT_ON_BLOBS.md` §4): a reader wanting
part of it, or a writer appending while readers read, is a DAG whatever it weighs. Size only decides
inline-vs-blob at the envelope bound. And RaptorQ is **not** on this axis at all — fountain coding is
a retention-class mechanism (CC 6.1.5, durability and graceful degradation per `ChunkLayer`) and the
scope-privacy wire profile's fragment unit (CC 5.4.2, see CIRISEdge#651), never a "large file"
strategy. Self and family content is excluded from fountain retention by CC 6.1.5's inheritance of
the CC 5.2 suppression anyway: no `FountainHoldingClaim` exists for it, and a 2–5-device collective
cannot place the 26 distinct symbols the shipped tuple's feasibility floor needs.

**Not built — and not blocked** (corrected 2026-09-22 against the pinned tree). `files::publish`
refuses anything over the bound by name, `FileError::TooLargeForInline { size, cap }`. An earlier
draft of this section said that refusal was waiting on **CIRISPersist#821 Q1/Q2**. It is not: Q1
shipped in persist v44.5.0 (`serve_blob_range_to_peer` — the ranged serve with the same proxy-shedding
and quarantine gates as the whole-blob path), Q2 is settled, and the **scoped chunk DAG shipped whole**
(persist #832/#838). At the version edge pins today, v46.3.1, every door exists as an `Engine` call:

| door | what it does |
|---|---|
| `put_blob_chunk_scoped(scope, stream_id, seq, plaintext, epoch, community_key_id, aad)` | append one segment to a live stream, sealed where the tier requires — the chunk twin of `put_blob_scoped` |
| `seal_stream_scoped(scope, stream_id, community_key_id, media_type, aad)` | seal the live stream into a `chunk_dag` at that cohort |
| `read_blob_range_as(sha, viewer, start, end, aad)` | the ranged read; the whole-read door refuses above 64 MiB and names this one |
| `read_stream_chunk_as(stream_id, seq, viewer, aad)` | one chunk by position |
| `adopt_sealed_chunk` | the receiver's adopt, gated by `would_hold` + the §4.3 adopt path |

Per-chunk AEAD with position-bound AAD (`ChunkManifest` v2), `MAX_CHUNKS_PER_EPOCH = 2²⁴` as the
nonce-safety cap. **Edge wires none of them**, which is the whole of the gap: the write path above the
bound is `put_blob_chunk_scoped` × N → `seal_stream_scoped`, and the read path is `read_blob_range_as`.
That is **CIRISEdge#633**, unblocked on the current pin, and it is the difference between "self files
replicate" and "files". A drive that cannot hold a video is a notes app.

(Persist will ship a PyO3 binding for `adopt_sealed_chunk` in v46.4.0. Edge does not need it — edge
calls the `Engine` door in Rust — but a **Python** consumer adopting a chunk DAG does.)

### 6.8 The drive read is a gated query (CIRISPersist#891 — shipped v46.4.0, adopted v29.6.0)

R10 is a query: *this room's file rows, resumable*. Until persist v46.4.0 the only door edge had was
`list_attestations_since`, so the room-and-dimension predicate ran client-side and the limit bounded
the wrong set — ask for 50 and filter afterwards and you get however many of that global page happened
to be this room's files, which on a busy node is none, and the later pages are invisible **permanently**
rather than merely late.

**The door was never missing; the axis was.** `list_attestations` has been filtered, cursor-paged and
§4.3-gated since persist v4.0; what it lacked was a `cohort_scope` axis on `AttestationFilter`
(CIRISEdge#352's verdict). v46.4.0 adds it — the column was already indexed for exactly this query
(V056, a partial index on non-`federation` scopes) — and edge v29.6.0 consumes it:

```rust
files::in_room(engine, &room, caller_occurrence_key_id, limit)
// → AttestationFilter { cohort_scope, dimension_exact: FILE_DIMENSION }
//   on Engine::list_attestations, newest-first, cursor-paged
```

Two properties come from the substrate rather than from edge remembering:

- **The limit bounds the answer, not the plane**, because the selection is server-side.
- **The caller is gated in one spelling.** Persist composes §4.3 *after* the filter, so a filter naming
  a room the caller is not in returns nothing — the filter can never widen an audience (persist's
  I142). The host precondition v29.5.0 carried is gone.

**Why the ungated cursor was the wrong door, in persist's words:** `list_attestations_since` is the
**replication** cursor and composes no visibility predicate — correct for replication, where the
audience question is answered by the send set and the per-row gates, and wrong for a reader's. Giving
*it* a filter would have dressed the ungated door as a reader's, so persist shipped the axis on the
gated door instead. Edge had been reading through the ungated one, which on a shared device let a
caller naming another person's identity enumerate their file rows.

Persist's ruling on the question edge asked — *should a local drive read carry the gate at all, since
the reader is the owner?* — is **yes**: the gate is about who is asking, not where the bytes are, and
"the reader is the owner" is a deployment assumption the shared device breaks.

#### 6.8.1 Targeted rooms are refused until CIRISPersist#893

The `self` arm of the gate compares by principal and is witnessed. The **`community` and `family`
arms cannot match any row edge can write**, and the reason is a contradiction between two rules that
are each correct alone (CIRISPersist#893):

- **AV-84 (write):** a targeted-cohort placement is a producer self-declaration, so a `community` /
  `family` row MUST name its own **producer** in `attested_key_id`; naming the room is refused.
- **§4.3 (read):** a row is admitted iff its **target** is in the caller's admitted set — and the
  target column passed on `federation_attestations` is `attested_key_id`.

`attested_key_id` is the producer; `community_key_ids` holds room keys; the intersection is empty by
construction. So no member can read their own room's rows through this door.

`files::in_room` therefore **refuses** a targeted room by name
(`FileError::DriveGateUnavailable`) rather than returning the empty list the gate produces — a
silently empty drive is indistinguishable from a room with no files — and rather than falling back to
the ungated cursor, because a function that takes a caller must not hand back rows it did not gate.

**Edge's ruling on the fix** (posted on #893): give the read gate the envelope's cohort target, as a
generated column over the value the write gate already validated. The argument is that **the correct
predicate is already shipped twice and both spellings key on the ROW's community** — persist's own
hold path (`is_audience_of`: `community_key_id.is_some_and(|c| member_communities.contains(c))`) and
edge's serve gate (`Audience::Community { community_key_id }` → `c.communities.contains(..)`). The
§4.3 gate is the one asking a different question. The alternative of admitting on "the caller shares
a room with the producer" is a **transitive widening** — a member of any one of my rooms would see
rows from all of them — and would put the local read door in contradiction with both shipped
spellings at once.

## 7. Invariants — and the mutant each must kill## 7. Invariants — and the mutant each must kill

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
| **`blob_pull_sources`** `scope:source` (`author_nodes` / `claim_index`) | R4 | ✓ v29.4.0 (metrics snapshot + PyO3 dict) |
| `blob_route_refusals` (`blob_group_not_installed` / `…not_in_group` / `…sealed_out`) | R5 | ✓ v26.2.0 |
| `blob_serve_refusals` | R6 | ✓ v27.0.0 |
| `scope lifecycle INSTALLED / ADVANCED / REFRESHED` (scope, group, epoch, members, added/removed) | R5 | ✓ v26.2.0 / v29.2.0 (#648); self room: — |
| `self room CREATED / JOINED / ABANDONED(claim)` (identity, creator, claim) | R5 | — (the host logs what `self_room::decide` named; the decision itself is a pure value) |
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
| **self / family** | tick `self_room::decide` and perform the action it names (§6.3's table); `self_room::snapshot` → `install` on join, `advance` on every Commit, `refresh_members` (#648) when an occurrence resolves late, `seal_due` on the cadence | the creator rule ITSELF (`decide` is edge's), the implicit send set (persist), author's-nodes fetch, `LocalOnly` adopt, retroactive re-grant (persist) |
| **files, every cohort** | `files::publish(dir, store, signers, &FileWrite { room, bytes, media_type, filename, asserted_at })` — one call, ≤ 1 MiB until §6.7 | the seal at the room's tier, persist's group slot, the citing row, the cohort target field, and the crossing to the room's audience; every refusal typed (`FileError::{TooLargeForInline, ReadableByNobody, Seal, Author, Cross, Row}`). Read: `files::in_room` (the drive — a bounded walk until §6.8) + `FileRow::open` → bytes or `UnopenedReason` (`NotFetched` = "on another device") |
| **commons** | the allowlist (`SenderStanding::Allowlisted`) | everything else |
| **client** (CIRISServer#615) | create: descriptor + bytes with `size`; read: verify → sniff → policy; enumerate: `GET /v1/drive` over the row plane, cursor `since`, row-held/bytes-absent as a state | — |

## 10. Sequencing

1. **persist — done**: §6.1 the implicit send set in nodes (`send_set_for`, v46.3.0), §6.5 the
   retroactive re-grant exposed (`rekey_self_occurrence_add_json`), `speaks_for` so a node-signed
   content set is not retired as "not the author" on every second device (v46.3.0), the `family_key_id`
   carrier confirmed (CIRISPersist#887), and the read-side self gate (v46.3.1). **Nothing here blocks
   self row or self byte replication.**
2. **persist — both asks shipped in v46.4.0**, adopted by edge v29.6.0: the §6.8 `cohort_scope` axis
   on the gated reader door (**CIRISPersist#891**), and `adopt_sealed_chunk_json` (**#821**, which
   edge does not itself need — it calls the `Engine` door in Rust; a Python consumer adopting a chunk
   DAG does). **One persist item remains and it is a ruling, not a build: CIRISPersist#893** — the
   §4.3 gate's targeted arms are unsatisfiable with AV-84, so a community or family drive is refused
   by name until it lands (§6.8.1). Edge's ruling is posted there.
3. **edge — done**: the projector's group-id rule and the two facets (§6.2, v29.4.0); the source rule
   and `blob_pull_sources` (§6.2); `announce_is_possible` asks the substrate (#646 ask 1); `ScopeRoom`,
   `self_room::{roster, snapshot, decide}` and the file door (§6.3/§9, v29.5.0); `refresh_members`
   (#648, v29.2.0).
4. **edge — open**: the §6.7 DAG door (**CIRISEdge#633 — unblocked on the current pin**, every persist
   door exists; this is edge's unbuilt work, not a dependency), then the §6.8 gated reader door when
   v46.4.0 lands; the CC 5.4 wire profile (CIRISEdge#651), orthogonal to all of the above.
5. **server — open, and it is the whole remaining path**: drive `self_room::decide` and perform the
   action it names (§6.3's table) beside the chat-room drive; the `mine_on_b` ladder stage, red by
   design at first; `GET /v1/drive` over `files::in_room`. Bytes do not move end to end until (5),
   whatever else is green.
6. **mixed fleet**: a pre-cut device is simply an occurrence that never asks; nothing it holds changes
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
2. **CLOSED (CIRISPersist#887).** The `family_id` carrier: a family row carries `family_key_id` in the
   signed envelope, written by the widen door and read through `admission::envelope_cohort_target`
   (four aliases, first non-empty, a disagreement refused). Recorded here because the projector's
   family arm is built on it (§6.2).
3. **Push-on-write scope.** Whether the sealing device pushes to *every* online node or only those on a
   live link is a cost question, not a correctness one.

## 13. Changelog

- **2026-09-22 (v29.5.0 review).** Six findings on PR #654, all real, all fixed with witnesses:
  removal before addition in `decide` (an `Add` waits on another node's KeyPackage while a `Remove`
  does not, so the old order held a REVOKED device in the tree); `publish` refuses a seal readable by
  nobody; the drive read pages to its limit (the directory limits the global plane before the room
  filter, so later pages were invisible permanently); a self listing matches its identity (every
  self-scoped row otherwise put one person's file metadata in another's drive);
  `LadderStall::is_self_resolving` so a terminal stall stops consuming the retry ledger; and
  `PullOutcome::AuthorUnresolved` so a self row that outruns its author's directory records is
  retried rather than refused forever. The two persist asks are now written into §6.7 (the chunk-DAG
  door, CIRISPersist#821 / CIRISEdge#633) and §6.8 (the listing filter), with §10 restructured to
  separate what persist has DONE from the two things it still owes.
- **2026-09-22 (v29.5.0, CIRISEdge#646 §6.3 + the file door).** `ScopeRoom` — one type answering every
  question about a room's identity, replacing three spellings; the self room specified as an ordinary
  `CohortGroup` with `self_room::{roster, snapshot, decide}` (the creator rule pure and total, the IO
  the host's); `files::publish` / `files::in_room` / `FileRow::open` — one door for a file at any
  cohort, which the R4 witness now uses end to end instead of a hand-rolled producer. The group-id
  namespace question is settled above. Open in #646: the host-side drive.
- **2026-09-22 (v29.4.0, CIRISEdge#646 §6.2 cut).** R4 source rule + R5 projector rule shipped with
  witnesses; the two-facet rule (`scope()` placement / `key_plane()` pointer) written into §6.2; the
  group-id order corrected to persist's convention (the pointer's slot carries the owner at `self`,
  the family at `family`); `family_key_id` per CIRISPersist#887; `announce_is_possible` asks the
  substrate (#646 ask 1). Open in #646: §6.3 the self room.
- **2026-09-22 (PR #647 review).** Nine findings, each checked against code and CC before the text
  moved: §2 is a fork (bytes ride envelope dispatch, never a round); §3 gains Node and the two key-grant
  axes; §5.2 has its own rows; §5.3 R4 drops the `minter_of(scope, epoch)` read (`epoch: None` at the
  invisible tier; content-axis signer = author by admission) for the author's nodes; R5 states the
  group-id rule (`GroupWithoutId` today); R9 states the tombstone-ceiling projection; §5.4 has its own
  witnesses; §6.1 unions nodes, not occurrences; §6.3 specifies the self room's MLS bootstrap
  (creator rule, KeyPackage/Welcome/Commit as `SelfOwn` rows, #604 merge, #648 refresh) and closes the
  federation-address alternative on CC 5.4.6's reading; invariants 9–11 added.
