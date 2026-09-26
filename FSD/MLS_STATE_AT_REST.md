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

## 1. Key root and degraded posture

- **The key is persist's.** `XChaChaKvStore::open_mls_state(path)` derives the store key by HKDF
  (CIRISVerify) from persist's one hardware-sealed seed under `MLS_STATE_CONTEXT =
  "mls-state-at-rest-v1"` — the same root as the secrets master and the content-at-rest master, so
  every host gets the same custody and there is still one seed to seal. Only the first open of an
  empty store may seal a seed; a store in use re-derives and never mints (§11.7).
- **No seed ⇒ `KVError::HardwareCustodyUnavailable`** (no TPM / Keystore / Secure Enclave, a
  build without `secrets`, `CIRIS_DATA_DIR` unset, or a seed gone missing under a store in use).
  Edge surfaces it by name as `MlsStateUnavailable::HardwareCustodyUnavailable(detail)` and
  **opens nothing**. The host chooses: keep MLS state in memory (`ScopeStateProvider::ephemeral()`
  — today's behaviour, a restart loses group state, stated as such), or open with
  `XChaChaKvStore::open(path, passphrase)` where the passphrase is the **operator's** (FSD §7.8
  phone-class tier). **Edge refuses to derive a passphrase from anything** — not a room id, not a
  key id, not a path. A room id is public; a key sealed under it is a key sealed under nothing.
- **Sync and blocking.** The opener touches the TPM and the filesystem; edge runs it under
  `tokio::task::spawn_blocking`. Hosts call the async wrapper, never persist's opener directly.

---

## 2. Host wiring contract

```text
open   : mls::scope_state::open_mls_state(path).await
           -> Ok(ScopeStateProvider)                          durable, hardware-rooted
           -> Err(MlsStateUnavailable::HardwareCustodyUnavailable(detail))   choose §1's posture
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
| commit claims / epoch ledger | rebuilt as commits arrive (bounded retention; not persisted) | same |

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
| S2 | `open_mls_state` on a host with no sealed seed returns `MlsStateUnavailable::HardwareCustodyUnavailable` by name and opens nothing; no file is created with a derived key. | `scope_state::no_hardware_seed_is_the_named_degraded_posture` (runs on every CI runner — none has a TPM) |
| S3 | Pending join material survives a restart: stash → fresh `CohortGroups` over the same store → `restore_key_material` → `join(welcome)` succeeds; the stash is cleared after the join. | `cohort_group::pending_join_material_survives_a_restart_and_is_consumed_once` |
| S4 | `decide` answers `Rejoin(m)` iff `m` is in the tree and re-published; `Remove` and `Abandon` rank above it; `Add` below it. | `self_room::a_re_published_key_package_from_a_tree_member_is_a_rejoin` and the ordering tests |
| S5 | `republished_members` is computed from rows the node holds and the persisted add instants; a KeyPackage older than the add is never a signal. | `self_room::republished_is_only_a_key_package_newer_than_the_add` |
| S6 | Boot re-address installs every persisted room's addresses into the lifecycle and reports each skip by name; it is idempotent. | `boot::a_restarted_node_readdresses_every_persisted_room`, `boot::readdress_is_idempotent` |
| S7 | Tampered store bytes are refused at read (`AuthFailure`), never decoded as state. | `scope_state::a_tampered_row_is_refused_not_decoded` |
| S8 | Edge derives no passphrase: `ephemeral()` is random per open; no code path passes a room id, key id or path to `XChaChaKvStore::open`. | grep pin `no_room_id_is_a_passphrase` (source gate) |

---

## 8. Owed

- The server's rungs: a restart rung in the self-files and chat ladders (CIRISServer#630) — with
  state (no traffic) and without state (`Rejoin` observed at the holder).
- A per-method `StorageProvider` if openmls exposes storage injection (then the snapshot becomes
  a cache and the store the truth per write). Not now.
- Rekeying the store when the hardware seed rotates: persist's §11.7 governs; edge reopens.
