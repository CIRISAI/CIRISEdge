# FSD: The host call API — a call is a room's stream set (CIRISEdge#805 items 5–6)

**Status:** DESIGN. Written ahead of items 1–3 so the program keeps moving; it must not LAND
before them (#846 one seal, CIRISPersist#981 one DEK, #805 item 3 live-into-the-DAG). Every type
named below exists on `local/805-1-one-seal` unless it is marked **new**. Open questions for
persist, verify and the CC are in §10; nothing there is guessed in the body.

**Inputs:** `CIRISEdge#805` (items 5–6), `docs/AV_ALM_DESIGN.md`, `FSD/CONTENT_TRANSFER.md`,
the spine (`src/transport/av_spine.rs`, #813), the room (`src/chat.rs`, `src/mls/cohort_group.rs`),
membership consent (`src/membership.rs`, `src/community_roster.rs`, CIRISPersist#955), persist v55
(`register_stream_epoch_dek`, `stream_sth`), the CC 5.1 key ruling of 2026-10-12.

---

## 1. What exists, and the one thing that is wrong for a room call

| Piece | Where | State |
|---|---|---|
| Call lifecycle: `open` / `join` / `subscribe` / `publish` / `heal` / `seal_due` | `transport::av_spine::AvSpine` | built (#813), on the live node |
| Media roles | `realtime_av_runtime::{AvPublisher, AvRelay, AvSubscriber}` | built |
| Seal, one place | `realtime_av::{seal_av_inner, open_av_chunk, seal_av_terminator}` → persist `stream_seal` | #846 (part 2 waits on persist v55.1) |
| Chunk-size budget | `AvSpine::chunk_plaintext_budget()` | #720 |
| Per-subscriber layer policy | `realtime_av::ReceiverLayerPolicy`, `AvSpine::subscribe(.., policy, ..)` | built |
| The room | `community_key_id` (`chat::ROOM_COMMUNITY_PREFIX` / `PAIR_COMMUNITY_PREFIX`), its MLS group `mls::CohortGroup` (via `mls::CohortGroups::open`) | built |
| Who is in the room | persist's active roster; `CohortGroup::member_key_ids` | built |
| Nobody joins without consent | `membership::{propose, reply, widen_on_acceptance}` (#955) | built |
| Room rows, delivered not discovered | `chat::chat_message_attestation_in` (community DEK body) | built |
| Stream STH producer + gate | persist `federation::stream_sth::produce_stream_sth`, `BlobStorage::put_stream_sth` | built (persist) |

**What is wrong for a room call:** the media key. `AvPublisher::create` → `AvSession::create`
mints a **new MLS group per stream** (`realtime_av_mls::MlsSession`) and derives the epoch DEK
from that group's exporter (`ciris-realtime-av-epoch-dek-seed-v1`). A room already HAS an MLS group
(`CohortGroup`, ciphersuite `0x004D`, the room's addressing root). #805 rules "the call's MLS group
is the room's": a call must not stand up a second group whose roster can drift from the room's.
(The mesh harness already keys its bench calls from the room group, `edge_node.rs::epoch_keys`
over `CohortGroup::record_secret`, but with a bench-only HKDF label; §10 V1.)

## 2. The model

- **A call is a set of streams in one room.** CC streams have a single sender
  (`register_stream_epoch_dek`: "the writer is this Engine's signer (the stream's single sender)"),
  so each participant that publishes owns ONE stream of the call. `CallId` (**new**) names the
  call; each publisher's `StreamId` is derived from it (§3.1).
- **The room is the control plane.** The call's admission is the room's membership; the call's
  key epochs are the room's MLS epochs; its signalling is room rows (§7).
- **Live and stored differ only by subscriber offset** (#805): the live chunk IS the stored chunk
  (#846); a kept call's chunks are written into the stream asynchronously (item 3).

## 3. Binding a call to its room

### 3.1 Identifiers

- `CallId([u8; 32])` (**new**) = the content hash of the call's genesis row (the ring row, §7),
  so a call is named by a signed room row and two members never disagree about it.
- Per-publisher `StreamId` = `SHA-256("ciris-edge:call-stream:v1" ‖ CallId ‖ utf8(publisher
  key_id))`. The persist / STREAM-nonce label is `realtime_av::stream_label(stream_id)` (lowercase
  hex), as #846 fixes; a kept stream's persist stream is named by that hex.

### 3.2 The MLS group IS the room's

- Opening a call opens the room's group: `CohortGroups::open(community_key_id)` → `CohortGroup`.
  No `AvSession::create` for a room call.
- **The call DEK for `(stream, room epoch)`** is an MLS exporter secret of the ROOM group under an
  A/V label with the stream bound in the exporter context. The label and context are verify's
  (`cohort_group.rs`: labels are a cross-impl wire fact, owned by CIRISVerify); §10 V1. Until verify
  rules, nothing here derives a DEK.
- **The call's epoch is the room's MLS epoch** (`CohortGroup::epoch`). A call never commits on its
  own: an epoch moves only on a room commit — `CohortGroup::add_member*` / `remove_member*` /
  `rotate*` — and every live call in the room rolls with it (new DEK; `chunk_seq` back to 0 per
  #846 part 1; the old epoch's terminator sealed with `seal_av_terminator`).
- **Addressing**: `AvSpine::open` installs addresses from the session's `destination_secret`. For a
  room call that secret is the room group's (`CohortGroup::destination_secret`), so the spine's
  `ScopeLifecycle` and the room's installed addresses (`mls::boot::readdress_persisted_rooms`) are
  one table. Whether A/V links take the room's addresses or an A/V-labelled derivation of them is
  §10 V2.

### 3.3 Who may join

- **Joining a call is presence, not admission.** Any ACTIVE member of the room may join any call
  in it: active in persist's roster (its `_active` view; a raw roster read admits revoked and
  pending members) AND a member of the room's MLS group
  (`CohortGroup::member_key_ids`). The two agree by construction after the room's own join.
- **A non-member joins the ROOM first**, through #955 and nothing else:
  `membership::propose` → the invitee's `membership::reply` (accept) →
  `membership::widen_on_acceptance` (or a `MembershipWidener` on the bridge) → the room group's
  `CohortGroup::add_member` commit. A call never has a door of its own around that.
- `AvSpine::join(Joiner, now)` today admits to the per-stream MLS group. For a room call it
  becomes "the room admitted this member and the room epoch moved": the spine's re-address +
  relay-window move run on the ROOM commit, not on a call verb (§9 sequencing).

## 4. The Rust surface (**new** unless named)

```rust
/// Open a call in `room` and start publishing this node's stream in it.
Edge::open_call(&self, room: &str /* community_key_id */, opts: CallOptions) -> Result<Call, CallError>;
/// Join a call that a ring row (§7) named.
Edge::join_call(&self, room: &str, call: CallId, opts: CallOptions) -> Result<Call, CallError>;

pub struct CallOptions {
    /// Item 2's `transport::av_keep::AvKeep` — `Unkept` (default) | `Kept`. Caller-supplied until
    /// CIRISPersist#1068 ships the row-borne keep decision (`history_on_join` / recorded); then
    /// `open_call` reads it from the room and this field goes.
    pub keep: AvKeep,
    pub relay: bool,                       // this node relays for others (AvSpine::open relay_node)
    pub default_policy: ReceiverLayerPolicy,
}

impl Call {
    pub fn id(&self) -> CallId;
    pub fn room(&self) -> &str;
    pub fn epoch(&self) -> Epoch;                                  // AvSpine::epoch
    /// The largest frame plaintext every downstream link carries (#720,
    /// AvSpine::chunk_plaintext_budget). A codec cuts to this.
    pub fn chunk_plaintext_budget(&self) -> Option<usize>;
    /// Seal ONCE and fan out (AvSpine::publish_chunk). Refuses a frame over the
    /// budget BEFORE sealing; a link-level ChunkTooLarge is a leg outcome.
    pub async fn publish(&mut self, frame: Frame) -> Result<PublishReport, CallError>;
    /// Reconstructed frames from every other publisher, in chunk order per stream.
    pub fn frames(&mut self) -> FrameStream;                       // impl Stream<Item = ReceivedFrame>
    /// Per-subscriber layer policy (AvSpine::subscribe(.., policy, ..)).
    pub fn set_layer_policy(&mut self, subscriber: &str, policy: ReceiverLayerPolicy) -> Result<(), CallError>;
    /// Hang up: final terminator, final STH, the hang-up row (§7).
    pub async fn leave(self) -> Result<CallSummary, CallError>;
    pub fn state(&self) -> CallState;                              // Live | Degraded(StrandedEpoch) | Ended(EndCause)
    /// Typed call events (§5, §8): `KeepRefused`, `EpochRolled`, `MemberJoined/Left`, `Stranded`.
    pub fn events(&mut self) -> CallEventStream;                   // impl Stream<Item = CallEvent>
}

pub struct Frame { pub codec_id: u8, pub layer: ChunkLayer, pub bytes: Vec<u8> }
pub struct ReceivedFrame { pub publisher: String, pub stream: StreamId, pub epoch: Epoch,
                           pub chunk_seq: ChunkSeq, pub codec_id: u8, pub layer: ChunkLayer, pub bytes: Vec<u8> }
```

**The publisher underneath is item 2's `KeptAvPublisher<R: StreamDekRegistrar>`, never the bare
`AvPublisher`.** `Call` owns the spine; the spine owns the `KeptAvPublisher`, so every epoch move
(create, `admit_joiner`, `advance_epoch`) passes through the keep layer and a kept call cannot move
an epoch without registering it.

`publish` maps onto `AvSpine::publish_chunk` (one inner seal per chunk, `RelayNode::forward` + the
publisher's direct links, `LegOutcome` per leg); `frames` reads the A/V sink's arrivals through
`AvSubscriber` / `open_av_chunk`; `set_layer_policy` is `AvSpine::subscribe` with the policy. The
spine's `seal_deadline()` is the one timer an idle call's host loop waits on (unchanged).

**PyO3 twin** (`ciris_edge.PyEdge`): `open_call(room, keep="unkept", relay=False)`,
`join_call(room, call_id, ...)` → `PyCall` with `id()`, `epoch()`, `chunk_plaintext_budget()`,
`publish(bytes, codec_id=CODEC_OPAQUE, layer=(0,0,0))`, `frames()` (an async iterator on the
edge-owned executor, the `run_async` pattern), `set_layer_policy(subscriber, (s,t,q))`, `leave()`,
`state()`, `events()` (an async iterator). Every Rust verb has a Python twin; the PyO3 parity test
walks the list.

## 5. Keys — unkept vs kept (CC 5.1, ruled 2026-10-12)

| | Unkept call (default) | Kept call (`Recorded` / `HistoryOnJoinFull`) |
|---|---|---|
| DEK | room MLS exporter (§3.2), in memory, zeroized at the roll | the same exporter secret |
| persist DEK door | **never touched** | `register_stream_epoch_dek(cohort_scope, room, stream_label, epoch, &dek, …, None)` once per epoch, BEFORE that epoch's first chunk |
| key grants | none (forward secrecy: an unkept call wraps to nobody) | persist wraps to the stream's audience, `key_grant:stream:v1` |
| seal | `seal_av_inner` (persist's pure seal, #846) | same bytes; item 3 writes them into the stream |
| bytes at rest | ciphertext only (§10 P1: which door) | the stream's chunks |

- **The keep layer is item 2's** (`transport::av_keep`, CIRISEdge `local/805-2-one-dek`):
  `KeptAvPublisher<R: StreamDekRegistrar>` wraps `AvPublisher`; its async `create`, `admit_joiner`
  and `advance_epoch` register each epoch's exporter DEK when the call is `AvKeep::Kept` and return
  `KeepOutcome { NotKept, Registered, AlreadyRegisteredHere, Refused }`. The call API consumes the
  outcome; it never calls `register_stream_epoch_dek` itself.
- **A refused keep does not end the call.** On `KeepOutcome::Refused` the call stays live and goes
  UNKEPT from that epoch; epochs registered before it stay kept, so the recording is PARTIAL. Item 2
  signals it today as the resource-bus event `av_keep_refused`; the call API surfaces it as the typed
  `CallEvent::KeepRefused { epoch, reason }`, and `CallSummary` names the kept epoch range.
- **Edge rolls the epoch; persist never does after a supply.** A retryable
  `BlobError::StreamEpochRotationRequired { reason, .. }` on a kept chunk is the signal: `reason:
  Removal` names a recipient who left (the room's `remove_member` commit must exist), `reason: Cap`
  means only the terminator's counter slot is left. A roll with no roster change is an MLS
  SELF-UPDATE commit through `advance_epoch` (openmls refuses an empty batch). Edge registers the
  next epoch (through the keep layer) and resends; nothing was stored.
- **A second registration with a DIFFERENT DEK** is persist's `StreamEpochDekConflict` from v55.1
  (CIRISPersist#1069); `AlreadyRegisteredHere` is the same-DEK idempotent case.
- `register_stream_epoch_dek` closes the open epoch with its terminator (persist-side); the live
  side seals the same terminator with `seal_av_terminator` (counter = the epoch's chunk count, last
  set, #846).
- **Where the keep decision comes from:** the caller (`CallOptions::keep`) until CIRISPersist#1068
  ships the row-borne decision (`history_on_join` / recorded, v55.1 or v56); then the room's row.
  Who may set it is still §10 C1.
- **The room-group binding (§3.2) sits UNDER the keep layer.** `KeptAvPublisher` registers whatever
  exporter DEK its `AvPublisher`'s session yields; moving that session from a per-stream
  `AvSession` group to the room's `CohortGroup` changes the DEK's source, not the keep layer's
  contract. Under §3.2 the self-update commit above is a ROOM commit (§10 C2).

## 6. STHs — every live stream, kept or not

- Cadence: a publisher produces an STH over its stream every **K = 64 chunks or T = 2 s**,
  whichever comes first (CC 5.3.3.3), and on `leave`.
- Producer: `stream_sth::produce_stream_sth(local, stream_label, chunk_shas, tree_size, now)` under
  the node's full hybrid signer (the same one call `receipts::stream_sth_for_file` makes), published
  through `BlobStorage::put_stream_sth`, whose gate recomputes the root from the chunk hashes the
  store holds.
- **That gate needs the chunks in the store.** A kept stream's chunks are there (item 3). An unkept
  stream's are there only if its ciphertext is stored (§10 P1); and how a live STH reaches the
  participants (on a row, like a file's `stream_sth` claim, or another plane) is §10 P3.

## 7. Signalling as room rows (item 6)

- Four row dimensions in the room (**new**; names are §10 C3): `chat:call:ring:v1`
  (`call_id` genesis, media kinds, retention, ring expiry), `chat:call:accept:v1`,
  `chat:call:decline:v1`, `chat:call:hangup:v1` (final epoch, final `tree_size`).
- Placement: `community` at the room, built exactly like a chat message
  (`chat::chat_message_attestation_in`: the body is a blob under the room's community DEK, the row
  carries the pointer). Audience: S1, the room's members' devices (`may_receive`). **Delivered to
  the room, never discovered.**
- `CallId` = the ring row's content hash (§3.1). Accept = `join_call`. Decline is final for that
  ring for that member. Hang-up is per participant; the call ends when the last publisher hangs up
  or the ring expires unanswered.
- **Presence comes from the D6 reachable set** (`reachability::ReachabilityTracker`, the
  `RealtimeFanout::plan` filter), read locally. It is never attested, never a row, never on the
  wire: a "who is reachable now" view is this node's measurement, not a claim.

## 8. Failure modes and typed errors

`CallError` (**new**), every arm named and witnessed:

| Arm | When | Witness |
|---|---|---|
| `NotARoomMember { key_id }` | join/open by a key not active in the room's roster or group | a non-member's `join_call` is refused by name; no MLS commit, no address install |
| `ConsentMissing` | a room join attempted without a held #955 acceptance (surfaced from `MembershipError::Refused`) | widen without acceptance → refused, never retried as transient |
| `RoomGroupUnavailable(MlsStateUnavailable)` | the room's MLS state cannot be opened (custody, `mls::MlsStateUnavailable`) | a node with no scope state cannot open a call; nothing is sent |
| `FrameTooLarge { bytes, budget }` | `publish` with `bytes > chunk_plaintext_budget()` | refused BEFORE the seal: no `chunk_seq` consumed, no nonce used |
| `NoBudget` | no downstream link reports a Channel limit yet | `publish` before any link is up refuses rather than guessing a size |
| `Congested` (per leg, in `PublishReport`) | link backpressure (`AvDispatcherError::Congested`) | a frame is dropped for that leg, never queued; other legs deliver |
| `EpochRollFailed(..)` | a kept chunk got `StreamEpochRotationRequired` and the room commit or the next registration failed | the call goes `Degraded`, never seals under a stale epoch |
| `CallEvent::KeepRefused { epoch, reason }` (an EVENT, not an error) | the keep layer returned `KeepOutcome::Refused` (`stream_not_authored`, `InvalidArgument`, from v55.1 `StreamEpochDekConflict`) | the call stays live and unkept from that epoch; earlier epochs stay readable through the key-grant plane |
| `SthRefused(BlobError)` | `put_stream_sth`'s gate refused (root mismatch, too few chunks) | a tampered STH never publishes |
| `Stranded(StrandedEpoch)` | the room commit landed but the spine's re-address failed | `state()` is `Degraded`; publish serves what is live (#813's semantics) |
| `CallEnded(EndCause)` | `Revoked` (this member left the room), `RingExpired`, `HungUp` | a revoked member's `publish` refuses; the room's next epoch excludes it |

Inbound failures are NOT call errors: a chunk that does not open (`RealtimeAvError::InnerSeal`,
`ChunkSeqMismatch`, `WireTooShort`) is dropped and counted on the A/V plane, and the call carries on.

## 9. Acceptance criteria — and the witness for each

| # | Criterion | Witness |
|---|---|---|
| A1 | The call key is the room's: two members derive the same call DEK for `(stream, epoch)` without exchanging it; a non-member cannot | two `CohortGroup` members over a loopback room; a third key outside the group fails |
| A2 | Join is membership: a non-member and a member without consent are refused by name | `NotARoomMember`, `ConsentMissing` |
| A3 | A room roster change rolls every live call: new DEK, `chunk_seq` 0, the old epoch's terminator, and a removed member cannot open post-roll chunks | the departed member's last DEK fails on the first new-epoch chunk |
| A4 | Unkept: zero `register_stream_epoch_dek` calls and zero `key_grant:stream:v1` rows; the exporter secret is never persisted | a counting persist double + a scope-state scan |
| A5 | Kept: each epoch registered before its first chunk; a member NOT in the live call opens the call through the key-grant plane | item 2's witness, over the room |
| A6 | `StreamEpochRotationRequired` (both reasons) rolls and resends with no chunk lost | a forced `Removal` and a forced `Cap` |
| A7 | `publish` cuts to the budget: at budget delivered, one over `FrameTooLarge` with no nonce consumed | #720's exact-budget test, through `Call` |
| A8 | `frames()` yields every other publisher's frames byte-identical, in chunk order per stream; per-subscriber layer policy drops above-policy layers at the relay | a 3-member loopback call with an SVC stream |
| A9 | STH every 64 chunks or 2 s and on leave; each accepted by `put_stream_sth` | a 200-chunk call: STHs at 64, 128, 192 and the leave |
| A10 | Ring / accept / decline / hang-up reach the room's members only; no row anywhere carries reachability | an outsider node receives none of the four rows |
| A11 | PyO3 parity: every `Call` verb has its Python twin | the parity test walks the verb list |
| A12 | A keep refused mid-call: the call continues, `CallEvent::KeepRefused` fires once, epochs before it stay openable via key grants and epochs after it are never registered | a registrar double refusing epoch 3 of a kept call |

Each criterion carries a fail-before: A1 (DEK from the per-stream `AvSession` group → a non-member
in that group opens), A3 (no roll on removal → the departed member opens), A4 (a register on an
unkept call → the counter is nonzero), A7 (the pre-seal check removed → a nonce is consumed by a
refused frame).

## 10. Open questions — for persist, verify and the CC (not guessed here)

**Verify**
- **V1.** The A/V DEK label and exporter context for a call keyed from the ROOM group: may the room
  group export under the A/V DEK-seed label (`cohort_group.rs` anticipated "a future deployment that
  points both at one group"), and is the stream bound in the exporter context or by a KDF step after
  it? The bench's HKDF over `record_secret` is not a production derivation.
- **V2.** A/V link addressing for a room call: the room's derived addresses, or an A/V-labelled
  derivation of the room's destination secret (so call links and room replication links are
  distinguishable)?

**Persist**
- **P1.** An unkept call stores "ciphertext only": through which door? `put_blob_chunk_scoped`
  takes plaintext and seals with a registered DEK (not allowed: an unkept call never registers);
  `adopt_sealed_chunk` is the holder path for another author's stream. Is there (or will there be) an
  author door for pre-sealed chunks of one's own unkept stream, so `put_stream_sth`'s gate can see
  its chunk hashes? Or is an unkept call's STH produced without storing its chunks?
- **P2.** `register_stream_epoch_dek`'s final v55 signature. At `8c2d88f7` it takes `keep: bool`;
  the 2026-10-12 ruling makes "registered" mean "kept". Item 2's `StreamDekRegistrar` hides the
  call shape from this API, but confirm `keep` is removed and `aad` is `None` for a call (so it
  matches #846's `AV_CHUNK_CALLER_AAD`).
- **P3.** How a live stream's STH reaches participants: on a row (a file carries `stream_sth` on its
  row), on the hang-up row, or replicated another way?
- **P4.** Item 3 writes a kept call's chunks: the store must seal them in the v2 form
  (CIRISPersist#1067 says supplied epochs seal V2) with `caller_aad = None`, so the stored bytes ARE
  the live bytes. Confirm the store door that takes them.
- **P5.** One stream per publisher: `register_stream_epoch_dek` names the writer as the stream's
  single sender. Confirm a call's N publishers are N streams under one room, each its own
  `stream_not_authored` gate.

**The CC**
- **C1.** Who may make a call kept (recorded / `history_on_join: full`): the opener, any
  participant, or only with every participant's consent? Can retention change mid-call? (The
  decision's CARRIER is CIRISPersist#1068's row; this is the rule for setting it.)
- **C2.** A call rolls the whole room's epoch (a room commit). Acceptable for a room with traffic
  besides the call, or does the CC want a call sub-epoch (exporter context only, no commit) for the
  `Cap` case?
- **C3.** The signalling dimension names (`chat:call:*:v1` proposed) and whether their bodies are
  community-encrypted like chat messages (proposed: yes; the row's existence and time still leak).
- **C4.** Presence is local D6 reachability only, never attested (proposed): confirm nothing in the
  CC asks for a presence row.

## 11. Sequencing

1. #846 part 2 (persist v55.1) — the one seal.
2. CIRISPersist#981 / item 2 — one DEK; answers P2, P4.
3. Item 3 — live chunks into the stream, STHs; answers P1, P3.
4. V1 / V2 from verify; C1–C4 from the CC.
5. This API (item 5) and the signalling rows (item 6), behind those.

## 12. Changelog

- 2026-10-12 — first draft (CIRISEdge#805 items 5–6).
- 2026-10-12 — the call API builds on item 2's `KeptAvPublisher` / `AvKeep` / `KeepOutcome`; a
  refused keep is the typed `CallEvent::KeepRefused` (partial recording), rotation without a roster
  change is a self-update commit, `StreamEpochDekConflict` (#1069) named, keep comes from the row
  once CIRISPersist#1068 ships.
