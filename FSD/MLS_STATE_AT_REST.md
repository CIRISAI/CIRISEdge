# FSD — MLS state at rest: what survives a restart, under whose key, and how a device gets back in

**Status:** normative for edge (CIRISEdge#676; persist half = CIRISPersist#911, shipped v49.0.0).
**Hosts affected:** CIRISServer#630 (self-room state in memory → a restarted device can never
rejoin) and #623 (a restarted holder is not listening on its rooms' derived addresses).
**Sources:** CC 5.4 (the per-room MLS group is the addressing root; 5.4.3 rebind on Add/Remove;
5.4.6 destinations are derived, never announced), CC 4.2.2 (hardware custody), persist
`FSD/BLOB_ENCRYPTION_AT_REST.md` §11.7 (one sealed seed; re-derive, never mint),
`FSD/CONTENT_TRANSFER.md` §6.3 (the self-room rule), `FSD/FIRST_CONTACT.md` (rows cross before
trust; the bootstrap needs no room).

The ownership rule this document is written under: **protocol and MLS semantics are edge's;
sealed storage and its single key root are persist's; hosts wire paths and lifecycle.** A host that
re-implements rejoin drifts from every other host, so the rejoin rule and the boot entry point live
here and are pure or host-driven, never host-written.

---

## 0. What is already durable, and what was not

Edge's cohort groups (`mls::cohort_group`, since #499) persist by **snapshotting openmls's storage
map into the sealed KV on every commit** and restoring it with `MlsGroup::load` on open
(`ScopeStateProvider::group_state_put/get`, namespace `mls/<community_id>/group_state`, a
byte-deterministic versioned blob). That *is* the `StorageProvider` realisation: openmls 0.8.1's
libcrux `Provider` fixes its storage to a private `openmls_memory_storage::MemoryStorage`, so a
per-method `openmls_traits::storage::StorageProvider` over the KV would require edge's own
`OpenMlsProvider` composing libcrux's crypto with a KV-backed storage — ~60 generic methods, every
one a synchronous KV round-trip on the hot path — for the same durability the snapshot gives with
one sealed write per commit. **Decision: the snapshot stays the mechanism.** The "DEFERRED to
v6.1.0" language in `scope_state.rs` is retired; revisit only if openmls lets a provider's storage
be injected.

What was **not** durable, and is after this cut:

| State | Before | After |
|---|---|---|
| Group state, ratchet tree, epoch secrets, own leaf, signer | snapshot in the sealed KV — durable **iff the host opened the KV on disk**; the self-room drive opened it **in memory** keyed by the room id (CIRISServer#630) | the host opens it through `mls::scope_state::open_mls_state(path)` (§2); an in-memory store is an explicit, named choice (`ScopeStateProvider::ephemeral()`), never a room-id passphrase |
| A published KeyPackage's private material (`CohortKeyMaterial`) while its Welcome is in flight | in memory only — a restart between `PublishKeyPackage` and the Welcome lost the ability to consume it | persisted under `mls/<room>/pending_join` (§3); restored by `CohortGroups::restore_key_material`, consumed and cleared by `join` |
| Per-member add instants (needed to recognise a re-published KeyPackage as a restart) | not recorded | `mls/<room>/member_joins` (§4) |
| Which rooms this node holds (to re-address at boot) | not enumerable — one namespace per room, no index | `mls/__rooms__/index` (§5) |
| Which addresses to listen on | rebuilt only when a local op revisited the room (CIRISServer#623) | one boot entry point re-installs every persisted room (§5) |

---

## 1. Key root, the two custody kinds, and the one refusal (persist v50.0.0 #920, CIRISEdge#694)

- **The key is persist's, and it follows the content master.** `Engine::open_mls_state(path)`
  derives the store key by HKDF (CIRISVerify) under `MLS_STATE_CONTEXT = "mls-state-at-rest-v1"`
  from **the root the persisted `federation_content_master` row names**: the hardware-sealed seed
  (`key_kind='hardware'`) or the persisted **software** content master (`key_kind='software'`,
  `BLOB_ENCRYPTION_AT_REST.md` §4.3/§10.2 — "a software fallback that is honest about being
  software"). The MLS store is content at rest; there is no seed file and no third root. **The row
  wins**: a store created on a software host keeps opening after a TPM appears. A node with no row
  yet gets one on first open, exactly as its first encrypted blob write would create it.
- **Two custody kinds, both durable on disk.** The opener returns `MlsStateCustody { kind:
  Hardware | Software, descriptor }` beside the store; edge logs the kind by name and returns it.
  A host with no TPM / Keystore / Secure Enclave (every CI runner) opens **on disk** as `Software`
  — a custody *class*, not a failure (CC 4.2.2.1; verify reports `HardwareType::SoftwareOnly` the
  same way). A v32.1.0 store keyed from the hardware seed under a software row opens through
  persist's compat arm and is reported `Hardware` with a `legacy-v49-…` descriptor, not re-keyed.
- **One refusal: §11.7.** `KVError::HardwareCustodyUnavailable` now means only that the row says
  hardware and the seed is unreachable (or the compat arm's hardware key is unreachable); nothing
  is written and nothing is minted. Edge surfaces it by name as
  `MlsStateUnavailable::HardwareCustodyUnavailable(detail)` and **opens nothing**; that is the
  only case a host falls back to `ScopeStateProvider::ephemeral()` (in memory, a restart loses
  group state, stated as such) or an operator passphrase (`XChaChaKvStore::open(path,
  passphrase)`, FSD §7.8 phone-class tier). **Edge refuses to derive a passphrase from anything** —
  not a room id, not a key id, not a path. A wrong-keyed store on a host with no hardware storage is
  `WrongPassphrase` → `MlsStateUnavailable::Store`.
- **Async; the engine does the blocking.** `mls::scope_state::open_mls_state(engine, path)` awaits
  persist's `Engine::open_mls_state` (it reads the content-master row); hosts call edge's wrapper.

---

## 2. Host wiring contract

```text
open   : mls::scope_state::open_mls_state(&engine, path).await
           -> Ok((ScopeStateProvider, MlsStateCustody))       durable ON DISK; log custody.kind
                                                              (hardware | software) by name
           -> Err(MlsStateUnavailable::HardwareCustodyUnavailable(detail))   §11.7 only: §1's fallback
           -> Err(MlsStateUnavailable::Store(KVError))        wrong key / tamper / backend: do not
                                                              silently fall back — a store that
                                                              fails to open is a store to inspect
path   : one file per node, under the node's state dir (e.g. <state_dir>/mls-state.kv).
         One store houses every room the node is in (namespaced per room); never one file per room.
boot   : mls::boot::readdress_persisted_rooms(&store, &groups, &lifecycle, &lens, classify).await
         ONCE, after the transport and ScopeLifecycle are armed (#499) and before the first
         round; returns a ReaddressReport the host logs. Idempotent: a second call re-installs the
         same snapshots (the lifecycle's install is a superseding write).
drive  : self_room::decide_with_republished(own, roster, held, rival, republished) each tick
         (decide(..) with an empty republished slice is unchanged for callers that do not yet
         compute it). republished = self_room::republished_members(...) — see §4.
outbox : at boot, for every opened group: group.unplaced_commits().await -> Vec<CohortCommit>
         (oldest epoch first) — place each Commit, and its Welcome to each of
         commit.welcome_recipients() (welcome_attestation_in), exactly as a fresh one, then
         group.mark_placed(&commit).await -> MarkPlaced::{Removed, NotOwed, Superseded}. After
         every placement in normal operation, too: a CohortCommit is in the outbox from the moment
         it exists until mark_placed (§4.3). The ack names THE commit (placement_id), not the
         epoch.
welcome: chat::welcome_for_row(dir, from, room, recipient) -> Option<PlacedWelcome{bytes, epoch,
         asserted_at}> — the row's instant, so a restarted creator can tell whether a member in
         its tree was welcomed FOR ITS CURRENT ADD (asserted_at >= member_added_at). welcome_for
         (bytes, epoch) is unchanged.
lineage: group.creation_claim().await -> Option<CommitClaim> — the claim the group was CREATED
         under (creator + instant), persisted with the group; survives the creator's removal.
         None on a group this node JOINED (a joiner never saw the creation; the host keeps its
         own record if it needs one).
```

What the host must NOT do: open the store per room; derive a passphrase; catch
`HardwareCustodyUnavailable` and retry with a different derivation; write group secrets anywhere
else.

---

## 3. Pending join material

A node that answered `PublishKeyPackage` holds `CohortKeyMaterial { provider, signer, key_id }`:
the private leaf and signature key its published KeyPackage commits to. The Welcome, when it comes,
can be consumed only with that material. It is persisted as
`mls/<room>/pending_join` = versioned blob `{ storage snapshot (the same codec as group state),
signer public key, key_id }`; restored with `restore_storage` +
`SignatureKeyPair::read(storage, pk, ED25519)`. `CohortGroups::stash_key_material(room, &m)` writes
it; `CohortGroups::restore_key_material(room)` reads it; `CohortGroups::join` **deletes it** on a
successful join (the room state supersedes it), and `evict`/abandon deletes it too. A stash for a
room that later goes to a different creator is simply overwritten by the next `PublishKeyPackage`.

---

## 4. Rejoin after restart — the rule

Two restart shapes, one rule:

- **State survived** (durable store): the node reopens its groups, its epoch and addresses are
  re-derived (§5); nothing to rejoin. This is the common case and it costs no round trip.
- **State lost** (a device restored from backup, a wiped store, an ephemeral store): the node's
  leaf is still in every surviving member's tree, so `decide` sees no missing member and never
  Welcomes it (CIRISServer#630). The restarted node **publishes a fresh KeyPackage** — that is its
  only move and it already does it (`PublishKeyPackage`; a lost-state creator lands there too,
  because the survivors' Commit rows give it a `rival` claim it cannot beat). The surviving
  members must read that fresh KeyPackage as what it is: **a member of the tree re-publishing a
  KeyPackage after it was added is a restart signal.** Nothing else produces that row.

**`SelfRoomAction::Rejoin(Vec<String>)`**: tree members whose latest self-placed KeyPackage row
is newer than their recorded add instant (§4.1). The holder performs **remove, then add with the
fresh KeyPackage** — two commits, the same order the existing removal-first rule mandates, so a
stale leaf never survives a tick it could have been evicted in. `Rejoin` ranks **after `Abandon`
and after `Remove`** (a departed device is not rejoined) and **before `Add`**.

**§4.1 The signal is decidable locally.** `CohortGroup` records `member_joins: room → {member →
added_at}` (the commit claim's instant for adds this node makes; the apply instant for remote
commits; the creator at creation; every member at Welcome time on the joiner). It is persisted
beside the group state and restored with it. `self_room::republished_members(directory, room,
group)` returns the members with a KeyPackage row `asserted_at > added_at + SKEW` (SKEW = 5 s,
the substrate's timestamp resolution plus clock slop; a KeyPackage published *before* the add is
the one the add consumed and is never a restart signal). Pure over rows the node already holds.

**§4.2 What is re-derived vs re-fetched vs re-requested.**

| Thing | On restart with state | On restart without state |
|---|---|---|
| epoch, exporter secret, addresses | re-derived from the snapshot (`MlsGroup::load`) | re-requested: fresh KeyPackage → `Rejoin` at a holder → Welcome |
| the room's roster | re-fetched from the directory (`nodes_owned_by` / `active_*_members`) — never trusted from the tree alone | same |
| pending Welcome material | restored from `pending_join` | minted anew (the old KeyPackage's Welcome, if it ever comes, is unconsumable and ignored) |
| commit claims / epoch ledger | persisted in the ledger slot beside every snapshot, before the head moves (bounded retention) | re-requested with the group |
| creation claim | persisted in the ledger at genesis; never pruned | unknown (a re-created group has a new one) |
| unplaced Commits / Welcomes | the outbox (§4.3): handed back by `unplaced_commits()` | lost with the group; the room's members see a stale holder and `decide` repairs |

**§4.3 Genesis, lineage and the outbox (CIRISEdge#695, #696, #697).**

*Who owns what (confirmed against persist v50, `FSD/SECOND_DEVICE.md` §2):* the MLS group state,
epoch secrets, scope addresses and Commit/Welcome production are **edge's**; persist owns the DEK
cascade, the #916 device re-wrap, the MLS-state store (storage only, §1) and roster standing. The
items below are therefore edge's to make durable.

- **Upgrade backfill (groups persisted before this cut have no join map).** `load` of a group
  with no `member_joins` slot backfills every current tree member and persists the map, choosing
  each instant by what it is USED for:
  - **Another member** — the instant feeds the Rejoin signal (a KeyPackage published *after* it
    is a restart). An early instant would make the KeyPackage the add consumed look newer than
    the add: a spurious Rejoin, evicting a healthy device. So: the exact add instant when the
    ledger still holds this node's `Add` intent for that member (its claim's instant); otherwise
    **the load instant** — every KeyPackage already placed predates it, so none is misread as a
    restart, and restarts after the upgrade are detected. The cost is stated: a member that lost
    state *and* republished before the upgrade is not detected by this signal; its next
    republish is.
  - **This node itself** — never a Rejoin candidate (`decide` excludes own); the instant feeds
    the host's creation-claim fallback, where EARLIER is the safe direction (a late instant loses
    a creation contest it should win). So: the earliest instant the durable state proves — the
    smallest claim in the ledger (the group existed before its first commit) — else the load
    instant.
  - A backfill that cannot be written is logged and kept in memory; the next commit persists it.

- **Genesis persists what a commit persists.** `create` and `join` write the snapshot, the ledger
  and the member-join map, and only then the head — the same slot order as `persist_and_seal`.
  Before this a group that never committed reloaded with no join instants (#695): a creator alone
  in its room had nothing for `member_added_at(own)` to answer.
- **Lineage.** The ledger carries `creation: Option<CommitClaim>` — set once, at `create`, to
  `(created_at, creator)`; never pruned, never rewritten by a rollback. A self room's creation
  contest is decided by that claim; before this it could only be inferred from `member_joins`,
  which drops a removed member (#696).
- **The outbox.** `add_member` / `remove_member` / `rotate` make their epoch durable BEFORE the
  host places the Commit. A crash (or a failed placement) in that window used to leave the group
  at N+1 with the Commit bytes gone: the members stay at N, every later Commit is one they cannot
  apply, and the room forks with nothing reporting it (#697). Now `persist_and_seal` writes the
  sealed Commit, Welcome and claim into the ledger's `outbox` **in the same write as the claim,
  before the head moves**; `unplaced_commits()` returns them, oldest first; `mark_placed(epoch)`
  removes one (a ledger-only write; the head does not move). A remote commit this node merely
  applied has nothing to place and is never in the outbox.
  - **The ack names the commit, not the epoch.** `mark_placed(&CohortCommit)` removes the entry
    only if its `placement_id` (sha256 of the Commit bytes) matches: after a lost contest the
    same epoch can hold a DIFFERENT re-proposed commit, and a late ack for the discarded one must
    not delete the re-proposal's recovery entry. A mismatch is `MarkPlaced::Superseded` (no
    delete); no entry is `MarkPlaced::NotOwed`.
  - **Durable before forgotten.** `mark_placed` writes the ledger without the entry first and
    only then drops it in memory; a failed write leaves the entry owed on the handle, so a retry
    writes again rather than reporting success over a debt the store still holds.
  - **The Welcome's recipients travel with it.** Each entry carries the key ids its Welcome
    admits (`welcome_recipients()`), so a recovered Add can be placed with
    `welcome_attestation_in` even after its `CommitIntent` has aged out of the ledger.
  - **Never ahead of the head.** A crash between the ledger write and the head move leaves an
    outbox entry for an epoch the group never reached; `load` drops every entry above the head,
    so a host is never handed a Commit its own group does not hold.
  - **A lost contest drops its commits.** A rollback (CC 3 convergent merge) discards this node's
    commits above the fork point; their outbox entries go with them, and the re-proposals enter
    the outbox as new commits.
  - **Not pruned by retention.** An unplaced Commit is owed until placed; the retention window
    bounds snapshots, not debts. Entries are a few KB (the Welcome carries the ratchet tree).

---

## 5. One boot entry point

`mls::boot::readdress_persisted_rooms(store, groups, lifecycle, lens, classify) -> ReaddressReport`:

1. `store.persisted_room_ids()` — the index namespace `mls/__rooms__/index` (key = room id),
   written by `group_state_put`, removed by `group_state_delete`. One scan; no cross-namespace
   enumeration exists in the KV and none is invented.
2. For each id: `groups.open(id)` (restores the snapshot); `classify(id) -> Option<ScopeRoom>` — the
   **host's** naming, because the KV does not know a self room from a chat room. The default
   classifier edge ships: `chat:pair:v1:*` / `chat:room:v1:*` → `Community`; `family:*` → `Family`;
   an id the lens resolves to a `user` identity → `SelfCollective`; else skipped by name.
3. Snapshot: `self_room::snapshot(group, identity)` for a self room; `cohort_addressing::snapshot`
   otherwise (members → nodes through the lens; unresolved members are reported, not fatal).
4. `lifecycle.install(&room.scope(), &snapshot)`; `SelfNotInRoster` and every other refusal is a
   `skipped(reason)` row, never a panic — a node re-addressing a room it has left must not stop
   the rest.
5. Report `{ installed: [(room, epoch, members)], skipped: [(room, reason)] }`.

The roster the addresses are installed for is **persist's fold** (through the lens), not the MLS
tree's — the tree may be behind; `decide` closes the gap on the next tick.

---

## 6. Threat check

| Threat | Answer |
|---|---|
| State file copied off the device | Every row is XChaCha20-Poly1305 under a key HKDF-derived from the hardware-sealed seed; without the seed the file is noise. The index and pending material live in the same store under the same key. |
| State file rolled back to an older snapshot | The node reloads an older epoch. Its next commit is at a stale epoch: peers refuse it by epoch (openmls) and the claim contest keeps the winner (`apply_remote_commit_claimed`, #604); the node's own `apply_remote_commit` of the peers' newer commits brings it forward. It cannot decrypt content sealed at epochs it missed (forward secrecy holds); nothing it sends is accepted at the wrong epoch. |
| Cross-room key reuse | Namespaces are `mls/<room>/<kind>`; the pending material is per room; the exporter secret is per group (CC 5.4.1); an identity's groups never share leaf material. |
| A forged "re-published KeyPackage" to force a Rejoin (evict-and-readd a victim) | The row is self-placed and hybrid-signed by the member itself (persist admission); only the member can publish it. A Rejoin re-adds the same member under its own fresh key — the attacker gains nothing and the victim loses one epoch of continuity. |
| `HardwareCustodyUnavailable` used to downgrade to a weak key | Edge opens nothing on that error; the only fallbacks are an explicit ephemeral store or an operator passphrase the host supplies — never derived by edge. |
| Two rooms for one identity after a lost-state creator re-creates | Pre-existing design (`decide`): the claims are totally ordered; the later room is abandoned and its member rejoins the winner. Durable state makes this the exception, not the rule. |

---

## 7. Invariants and witnesses

| # | Invariant | Witness |
|---|---|---|
| S1 | A group written through one `ScopeStateProvider` is readable through a **fresh** provider over the same store bytes (restart), at the same epoch with the same exporter secret. | `cohort_group` (existing) + `boot::a_restarted_node_readdresses_every_persisted_room` |
| S2 | `open_mls_state(engine, path)` on a host with no hardware storage opens the store **on disk** under the persisted software content master, reports the custody kind by name, and re-opens it with the same kind and the same contents; the in-memory fallback is reachable only through persist's §11.7 refusal. | `scope_state::a_tpm_less_host_opens_the_store_on_disk_as_software` (runs on every CI runner — none has a TPM) |
| S3 | Pending join material survives a restart: stash → fresh `CohortGroups` over the same store → `restore_key_material` → `join(welcome)` succeeds; the stash is cleared after the join. | `cohort_group::pending_join_material_survives_a_restart_and_is_consumed_once` |
| S4 | `decide` answers `Rejoin(m)` iff `m` is in the tree and re-published; `Remove` and `Abandon` rank above it; `Add` below it. | `self_room::a_re_published_key_package_from_a_tree_member_is_a_rejoin` and the ordering tests |
| S5 | `republished_members` is computed from rows the node holds and the persisted add instants; a KeyPackage older than the add is never a signal. | `self_room::republished_is_only_a_key_package_newer_than_the_add` |
| S6 | Boot re-address installs every persisted room's addresses into the lifecycle and reports each skip by name; it is idempotent. | `boot::a_restarted_node_readdresses_every_persisted_room`, `boot::readdress_is_idempotent` |
| S7 | Tampered store bytes are refused at read (`AuthFailure`), never decoded as state. | `scope_state::a_tampered_row_is_refused_not_decoded` |
| S8 | Edge derives no passphrase: `ephemeral()` is random per open; no code path passes a room id, key id or path to `XChaChaKvStore::open`. | grep pin `no_room_id_is_a_passphrase` (source gate) |
| S9 | A group that never committed reloads with the creator's join instant (`member_added_at(own)` is `Some`), on `create` and on `join`. | `cohort_group::a_genesis_group_reloads_with_its_join_map` |
| S10 | The creation claim persists with the group and survives the creator's removal; a joined group reports `None`. | `cohort_group::the_creation_claim_survives_a_reload_and_the_creators_removal` |
| S11 | A Commit that was durable but never placed is handed back after a restart, byte-identical (Commit, Welcome, claim); `mark_placed` removes it and the removal is durable; remote applies never enter the outbox. | `cohort_group::an_unplaced_commit_survives_a_restart_until_marked_placed` |
| S12 | The outbox is never ahead of the head: an entry for an epoch the head did not reach is dropped at load. | `cohort_group::an_outbox_entry_above_the_head_is_dropped_at_load` |
| S13 | `welcome_for_row` returns the row's `asserted_at` beside the bytes and epoch. | `tests/chat_message_federates.rs` (the handshake witness reads `welcome_for_row` and asserts the row's `asserted_at`) |
| S14 | A late `mark_placed` for a discarded commit does not delete the re-proposal that holds the same epoch after a lost contest (`Superseded`, entry kept). | `cohort_group::a_stale_ack_after_a_rollback_does_not_delete_the_reproposal` |
| S15 | A `mark_placed` whose ledger write fails leaves the debt owed on the handle; a retry writes; a restart does not replay an acked commit. | `cohort_group::a_failed_ack_write_keeps_the_debt_and_a_retry_clears_it` |
| S16 | A recovered Add carries its Welcome's recipient key id after a restart, with the intent pruned. | `cohort_group::a_recovered_add_names_its_welcome_recipient` |
| S17 | A group persisted with no join map loads with every member backfilled (creator = earliest proven instant; others = exact add claim or the load instant), persists it, and an already-placed KeyPackage is not read as a restart. | `cohort_group::a_pre_upgrade_group_backfills_its_join_map_without_a_spurious_rejoin` |

---

## 8. Owed

- The server's rungs: a restart rung in the self-files and chat ladders (CIRISServer#630) — with
  state (no traffic) and without state (`Rejoin` observed at the holder).
- A per-method `StorageProvider` if openmls exposes storage injection (then the snapshot becomes
  a cache and the store the truth per write). Not now.
- Rekeying the store when the hardware seed rotates: persist's §11.7 governs; edge reopens.
