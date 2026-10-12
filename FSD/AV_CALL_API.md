# FSD: The host call API — a call is a room's stream set (CIRISEdge#805 items 5–6)

**Status:** DESIGN. Written ahead of items 1–3 so the program keeps moving; it must not LAND
before them (#846 one seal, CIRISPersist#981 one DEK, #805 item 3 live-into-the-DAG). Every type
named below exists on `local/805-1-one-seal` unless it is marked **new**. Open questions for
persist, verify and the CC are in §10; nothing there is guessed in the body. The CC answered
C1–C5 and V1 on 2026-10-12, and ruled CIRISConstitution#169 (CC rc8, a93974e): one DEK per
stream per epoch, and keep changed mid-stream. Edge vendors CC rc7 today; rc8 is vendored when
persist vendors it.

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
  so each participant that publishes owns ONE stream of the call. **The CC has no call object:**
  a call is the room's set of live streams. `CallId` (**new**) is an API handle only (§3.1), never
  on the wire as a row of its own and never key input.
- **The room is the control plane.** The call's admission is the room's membership; the call's
  key epochs are the room's MLS epochs; its signalling is the room's EXISTING membership rows, with
  no new wire (§7).
- **Live and stored differ only by subscriber offset** (#805): the live chunk IS the stored chunk
  (#846); a kept call's chunks are written into the stream asynchronously (item 3).

## 3. Binding a call to its room

### 3.1 Identifiers

- `CallId([u8; 32])` (**new**, `transport::av_call_key::CallId`) is a signalling and API handle:
  `SHA-256("ciris-edge:call:v1" ‖ utf8(community_key_id))` of the room the call lives in (an
  ad-hoc call's room is its ephemeral community, §7). There is no call row to hash (C3), so a room
  has at most one call: its live streams. `CallId` is never key input (§3.2).
- Per-publisher `StreamId` = `SHA-256("ciris-edge:call-stream:v2" ‖ utf8(room community_key_id)
  ‖ utf8(publisher NODE key_id) ‖ join_nonce)`, where `join_nonce` is 32 bytes from the OS CSPRNG,
  minted on every `join_call` / `ring` and never persisted. The stream's writer is a NODE key
  (persist, P5): one person publishing from two devices is two streams. The persist label is
  `realtime_av::stream_label(stream_id)` = `av-` + lowercase hex (persist refuses a bare 64-hex
  stream id, reserved for an inline blob's one-leaf log, #953); a kept stream's persist stream is
  named by that label.
- **Invariant: a call never reuses a `stream_id`, including after a crash or a rejoin.** The
  derivation guarantees it: every open or join mints a fresh `join_nonce`, so a publisher that
  crashes and rejoins, or leaves and rejoins, gets a new stream, never its old one. A derivation
  with no fresh input would not: the stream DEK (§3.2) and the STREAM nonce are both functions of
  `(stream_id, epoch, chunk_seq)`, so a rejoin inside the same room epoch would restart `chunk_seq`
  at 0 under the same key, which is nonce reuse. Nothing is persisted to remember "streams already
  used", so a lost store cannot break the invariant. Every stream is born V2 (#1067): there is no
  V1 prefix to carry across a rejoin. Witness (later, with item 5's code): a publisher that drops
  its `Call` without `leave` and rejoins the same room in the same epoch gets a different
  `stream_id`, and no `(dek, nonce)` pair appears twice across the two streams.

### 3.2 The MLS group IS the room's

- Opening a call opens the room's group: `CohortGroups::open(community_key_id)` → `CohortGroup`.
  No `AvSession::create` for a room call.
- **The DEK for `(stream, room epoch)`** is `transport::av_call_key::stream_epoch_dek(room_group,
  stream_id, epoch)` (CIRISEdge `local/805-5-call-key`):

  ```text
  seed = MLS-Exporter(L, context = EMPTY, 32)                    (the ROOM group)
  dek  = HKDF-SHA256(ikm = seed, salt = EMPTY, info = L ‖ stream_id_utf8 ‖ u64_be(epoch))
  ```

  `stream_id_utf8` is `stream_label(stream_id)` (`av-` + 64 lowercase hex chars, the same string
  persist and the STREAM nonce bind); no length prefixes. The
  exporter context stays EMPTY, as verify requires; the stream is bound by the KDF step after it.
  `CallId` is not an input. A DEK is derived only at the room group's CURRENT epoch
  (`StreamKeyError::EpochNotCurrent` otherwise).
- **Normative: CC 5.1 (rc8, CIRISConstitution#169).** `L` = `STREAM_DEK_LABEL` =
  `"ciris-stream-dek/v1"`; ONE label serves both the exporter call and the info tag. A
  `key_grant:stream:v1` wraps this per-stream DEK and opens exactly one stream; the exporter secret
  is never wrapped, so one participant's kept stream never opens another's unkept stream in the
  same epoch. Conformance is CIRISVerify#308's KAT set: when verify lands its `stream_dek` fn and
  vectors, `stream_epoch_dek` calls it and runs them (a TODO in the code); that graduates the claim.
- **The call's epoch is the room's MLS epoch** (`CohortGroup::epoch`, C2), with no call sub-epoch.
  A call never commits on its own: an epoch moves only on a room commit. **Every Add and every
  Remove rotates** (`CohortGroup::add_member*` / `remove_member*`): an Add rotates the DEK too, and
  the CC table that says otherwise is an erratum. At the cap, ANY member may commit an Update
  (`rotate*`). Every live stream in the room rolls with the commit: a new DEK, `chunk_seq` back to
  0 (#846 part 1), and the old epoch's terminator sealed with `seal_av_terminator`.
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
/// Start publishing this node's stream in `room`'s call (an in-room call needs no ring, §7).
/// Opening and joining are one verb: the room's call is its live streams.
Edge::join_call(&self, room: &str /* community_key_id */, opts: CallOptions) -> Result<Call, CallError>;
/// An ad-hoc call: mint an ephemeral community with a short `valid_until` and ring each invitee
/// with `membership:proposal:v1` (§7). This node joins it like any room.
Edge::ring(&self, invitees: &[&str], valid_until: Timestamp, opts: CallOptions) -> Result<Call, CallError>;

pub struct CallOptions {
    /// Item 2's `transport::av_keep::AvKeep` — `Unkept` (default) | `Kept`, for THIS node's stream
    /// only (C1: keep is per stream, set by its producer). Caller-supplied until
    /// CIRISPersist#1068 ships the row-borne decision (the producer's `history_on_join` on its
    /// stream's genesis); then it is read from that row and this field goes.
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
    /// Hang up: final terminator and final in-band STH; for an ad-hoc call, the forward-only
    /// withdraw (§7).
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

**PyO3 twin** (`ciris_edge.PyEdge`): `join_call(room, keep="unkept", relay=False)`,
`ring(invitees, valid_until, ...)` → `PyCall` with `id()`, `epoch()`, `chunk_plaintext_budget()`,
`publish(bytes, codec_id=CODEC_OPAQUE, layer=(0,0,0))`, `frames()` (an async iterator on the
edge-owned executor, the `run_async` pattern), `set_layer_policy(subscriber, (s,t,q))`, `leave()`,
`state()`, `events()` (an async iterator). Every Rust verb has a Python twin; the PyO3 parity test
walks the list.

## 5. Keys — unkept vs kept, per STREAM (CC 5.1, ruled 2026-10-12; C1)

Keep is a property of a STREAM, set by its producer, not of the call: one participant's stream can
be kept while another's in the same call is not. **"Recorded" is not a field** (CC 5.1, rc8): a
stream is kept when its genesis carries `history_on_join: full` or when `key_grant:stream:v1` wraps
exist for it, and the recording is the after-the-fact CC 3.3.13 blob. No row or option names
"recorded".

| | Unkept stream (default) | Kept stream (genesis `history_on_join: full`, or existing `key_grant:stream:v1` wraps) |
|---|---|---|
| DEK | `stream_epoch_dek` (§3.2), in memory, zeroized at the roll | the same DEK |
| persist DEK door | **never touched** | `register_stream_epoch_dek(cohort_scope, room, stream_label, epoch, &dek, …, None)` once per epoch, BEFORE that epoch's first chunk |
| key grants | none (forward secrecy: an unkept call wraps to nobody) | persist wraps to the stream's audience, `key_grant:stream:v1` |
| seal | `seal_av_inner` (persist's pure seal, #846) | the same bytes |
| bytes at rest | the live ciphertext, ADOPTED by its author: `adopt_sealed_chunk(s)` under `for_stream_keyed_chunk` provenance, no DEK row (persist P1, BELIEVED; witnessed in persist's final head). How long it is kept is edge's choice: the reconnect horizon, CC 5.3.3.4 | the live ciphertext, ADOPTED by its author into the supplied epoch (item 3, below) |

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
- **Item 3 is "the author adopts its live ciphertext"** (persist P4, CIRISPersist#1067 v55.1): a
  supplied epoch is V2 (no form argument), and stored == live bytes because the author ADOPTS the
  exact chunks it sealed live into the supplied epoch. Never a re-seal through
  `put_blob_chunk_scoped`. STH leaf order (#1067): `(epoch, counter)`, each epoch's terminator its
  last leaf; streams are born V2. Still open on #1067: the counter bookkeeping for adopted chunks.
- `register_stream_epoch_dek`'s `aad` seals the terminator persist writes, so it MUST equal the
  chunks' caller AAD: `None`, i.e. #846's `AV_CHUNK_CALLER_AAD` (persist P2; the final v55 has no
  `keep` argument). It closes the open epoch with that terminator (persist-side); the live
  side seals the same terminator with `seal_av_terminator` (counter = the epoch's chunk count, last
  set, #846).
- **Where the keep decision comes from (C1):** the PRODUCER of each stream, through its own
  `history_on_join` on the stream's genesis. Until CIRISPersist#1068 ships that row (v55.1 or v56),
  the producer's caller supplies it (`CallOptions::keep`). No other participant sets it, and there
  is no call-wide keep.
- **Keep changed mid-stream (normative, CC 5.1 rc8):** turning keep ON wraps the CURRENT and later
  epochs only. Earlier epochs' DEKs were never wrapped and are gone, so the keep layer registers
  the current epoch at once and every epoch after. Turning it OFF is forward-only: the keep layer
  stops registering from the next epoch, and wraps already issued are not unmade (a `withdraws` on
  a `key_grant` is refused). A refused keep (`CallEvent::KeepRefused`, below) has the same shape as
  OFF.
- **The room-group binding (§3.2) sits UNDER the keep layer.** `KeptAvPublisher` registers whatever
  DEK its `AvPublisher`'s session yields; moving that session from a per-stream `AvSession` group
  to `stream_epoch_dek` over the room's `CohortGroup` changes the DEK's source, not the keep
  layer's contract. Under §3.2 the self-update commit above is a ROOM Update commit, which any
  member may make (C2).

## 6. STHs — every live stream, kept or not

- Cadence: a publisher produces an STH over its stream every **K = 64 chunks or T = 2 s**,
  whichever comes first (CC 5.3.3.3), and on `leave`.
- Producer: `stream_sth::produce_stream_sth(local, stream_label, chunk_shas, tree_size, now)` under
  the node's full hybrid signer (the same one call `receipts::stream_sth_for_file` makes). It works
  over IN-MEMORY leaf hashes with nothing stored (persist P1), so a live STH never waits on the
  store.
- **Carrier (C5):** live STHs ride IN-BAND, best-effort, on edge's own wire to the call's
  participants. That is conformant to CC 5.3.3.3; a lost live STH is not a failure.
- **A kept stream's roots ride its recording,** in the manifest and recording blob, as CC 3.3.13
  `evidence_refs`. Nothing writes an STH row: no replicated carrier exists, and none is wanted.
  Before the roots go into the manifest, edge recomputes them from the chunks it ADOPTED and refuses
  a `tree_size` larger than what it holds (the check `put_stream_sth` does, without its row).

## 7. Signalling — the room's existing rows, no new wire (item 6, C3)

There is no `chat:call:*` dimension and no call row of any kind. Signalling reuses what exists:

- **An in-room call needs no ring.** Every member of the room already may join; `join_call(room)`
  starts this node's stream, and the others see it arrive. "Accept" is joining, and "decline" is
  not joining.
- **An ad-hoc call is an ephemeral community** with a short `valid_until`, built like any room
  (`community_key_id`, its `CohortGroup`), through #955 and nothing else:

  | Call step | Row (existing) |
  |---|---|
  | ring | `membership:proposal:v1` from the caller to each invitee (`membership::propose`) |
  | accept | `membership:acceptance:v1` (`membership::reply`), then `widen_on_acceptance` and the group's Add commit; the Add rotates (§3.2) |
  | decline | `membership:decline:v1` (`membership::reply`) |
  | hang up | forward-only withdraws: the leaver's membership is withdrawn going forward; what was delivered stays delivered |

  The call ends when the community's `valid_until` passes or its last member hangs up.
- **An in-room hang-up writes nothing:** the stream's final terminator and in-band STH end it
  (§6). The leaver stays a member of the room.
- Delivery is the membership rows' own: to the invitee and the community, never discovered.
- **Presence comes from the D6 reachable set** (`reachability::ReachabilityTracker`, the
  `RealtimeFanout::plan` filter), read locally. It is never attested, never a row, never on the
  wire (C4, confirmed): a "who is reachable now" view is this node's measurement, not a claim.

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
| `RecordingRootMismatch { tree_size, held }` | a kept stream's manifest roots do not recompute from the adopted chunks, or name more chunks than are held (§6) | a tampered root never reaches `evidence_refs` |
| `Stranded(StrandedEpoch)` | the room commit landed but the spine's re-address failed | `state()` is `Degraded`; publish serves what is live (#813's semantics) |
| `CallEnded(EndCause)` | `Revoked` (this member left the room), `Expired` (an ad-hoc community's `valid_until` passed), `HungUp` | a revoked member's `publish` refuses; the room's next epoch excludes it |

Inbound failures are NOT call errors: a chunk that does not open (`RealtimeAvError::InnerSeal`,
`ChunkSeqMismatch`, `WireTooShort`) is dropped and counted on the A/V plane, and the call carries on.

## 9. Acceptance criteria — and the witness for each

| # | Criterion | Witness |
|---|---|---|
| A1 | The call key is the room's: two members derive the same DEK for `(stream, epoch)` without exchanging it; a non-member cannot; two streams in one epoch get different DEKs | `av_call_key` tests (`local/805-5-call-key`), then two `CohortGroup` members over a loopback room with a third key outside the group |
| A2 | Join is membership: a non-member and a member without consent are refused by name | `NotARoomMember`, `ConsentMissing` |
| A3 | Every Add and every Remove rolls every live stream: new DEK, `chunk_seq` 0, the old epoch's terminator; a removed member cannot open post-roll chunks, and an added member cannot open pre-Add chunks | the departed member's last DEK fails on the first new-epoch chunk; the joiner's first DEK fails on the last pre-Add chunk |
| A4 | Unkept: zero `register_stream_epoch_dek` calls and zero `key_grant:stream:v1` rows; the exporter secret is never persisted | a counting persist double + a scope-state scan |
| A5 | Kept: each epoch registered before its first chunk; a member NOT in the live call opens the call through the key-grant plane | item 2's witness, over the room |
| A6 | `StreamEpochRotationRequired` (both reasons) rolls and resends with no chunk lost | a forced `Removal` and a forced `Cap` |
| A7 | `publish` cuts to the budget: at budget delivered, one over `FrameTooLarge` with no nonce consumed | #720's exact-budget test, through `Call` |
| A8 | `frames()` yields every other publisher's frames byte-identical, in chunk order per stream; per-subscriber layer policy drops above-policy layers at the relay | a 3-member loopback call with an SVC stream |
| A9 | In-band STH every 64 chunks or 2 s and on leave; a kept stream's manifest carries its roots in `evidence_refs`; no STH row is written | a 200-chunk call: STHs at 64, 128, 192 and the leave; a `stream_sth` row count of 0 |
| A10 | Signalling adds no wire: ring / accept / decline / hang-up are the existing membership rows, and no row anywhere carries reachability | an ad-hoc call's rows are all `membership:*:v1`; an outsider receives none of them |
| A11 | PyO3 parity: every `Call` verb has its Python twin | the parity test walks the verb list |
| A12 | A keep refused mid-call: the call continues, `CallEvent::KeepRefused` fires once, epochs before it stay openable via key grants and epochs after it are never registered | a registrar double refusing epoch 3 of a kept call |

Each criterion carries a fail-before: A1 (the stream dropped from the KDF info →
`the_dek_is_per_stream` RED; the epoch check removed → the old-epoch test RED; both run on
`local/805-5-call-key`), A3 (no roll on removal → the departed member opens; no roll on Add → the
joiner opens pre-Add chunks), A4 (a register on an
unkept call → the counter is nonzero), A7 (the pre-seal check removed → a nonce is consumed by a
refused frame).

## 10. Open questions — for persist, verify and the CC (not guessed here)

**Verify**
- **V1 (RULED, CC 5.1 rc8, CIRISConstitution#169).** One DEK per `(stream_id, epoch)` under the
  room group's exporter, label `"ciris-stream-dek/v1"` (§3.2). KATs come from CIRISVerify#308.
- **V2.** A/V link addressing for a room call: the room's derived addresses, or an A/V-labelled
  derivation of the room's destination secret (so call links and room replication links are
  distinguishable)? V1 is ruled, so this is open for verify.

**Persist**
- **P1 (answered, BELIEVED).** An unkept call's author stores its ciphertext with
  `adopt_sealed_chunk(s)` under `for_stream_keyed_chunk` provenance, no DEK row (the holders' door);
  persist is witnessing it in its final head. STHs: `produce_stream_sth` over in-memory leaves;
  `put_stream_sth` only over adopted chunks (§6).
- **P2 (answered).** The final v55 `register_stream_epoch_dek` has no `keep`; its `aad` seals the
  terminator persist writes, so it is `None`, equal to the chunks' caller AAD.
- **P3 (answered).** No replicated STH carrier; `stream_sth` rows are node-local. Live STHs ride
  edge's wire; the durable question is C5.
- **P4 (answered, CIRISPersist#1067 v55.1).** No form argument; a supplied epoch is V2; stored ==
  live by the author ADOPTING its live ciphertext. Leaf order `(epoch, counter)`, each epoch's
  terminator last; streams are born V2. OPEN on #1067: adopted-chunk counter bookkeeping.
- **P5 (answered).** One stream per publisher; the writer is a NODE key (two devices, two
  streams).

**The CC (answered 2026-10-12)**
- **C1.** Keep is per STREAM, set by its producer's own `history_on_join` on the stream's genesis
  (§5). Mid-stream (#169, rc8): ON wraps the current and later epochs; OFF is forward-only.
  "Recorded" is not a field.
- **C2.** The call epoch is the room's MLS epoch. Any member may commit an Update at the cap, and
  there is no sub-epoch. Every Add and every Remove rotates (the CC table that exempts Add is an
  erratum) (§3.2).
- **C3.** No `chat:call:*`. An ad-hoc call is an ephemeral community with a short `valid_until`;
  ring, accept and decline are `membership:proposal|acceptance|decline:v1`; hang-up is forward-only
  withdraws; an in-room call needs no ring (§7).
- **C4.** No presence row (confirmed).
- **C5.** Best-effort in-band live STHs are conformant. A kept stream's roots ride the manifest and
  recording blob (CC 3.3.13 `evidence_refs`), with no STH row (§6).
- **#169 (ruled, rc8):** one DEK per stream per epoch (V1), and keep changed mid-stream (C1).

## 11. Sequencing

1. #846 part 2 (persist v55.1) — the one seal.
2. CIRISPersist#981 / item 2 — one DEK (`KeptAvPublisher`, `local/805-2-one-dek`).
3. Item 3 — **the author adopts its live ciphertext** (`adopt_sealed_chunk(s)`): into the supplied
   epoch when kept, under `for_stream_keyed_chunk` with no DEK row when unkept; live STHs from
   in-memory leaves, `put_stream_sth` over adopted chunks. Waits on #1067's counter bookkeeping
   (the leaf order is settled).
4. CIRISVerify#308's `stream_dek` fn and KATs (#169 is ruled), and V2 from verify. C1–C5 are
   answered.
5. This API (item 5) and the signalling rows (item 6), behind those.

## 12. Changelog

- 2026-10-12 — first draft (CIRISEdge#805 items 5–6).
- 2026-10-12 — persist's P1–P5 answers: an author ADOPTS its own live ciphertext (unkept: no DEK
  row; kept: into the supplied V2 epoch), live STHs from in-memory leaves and `put_stream_sth` only
  over adopted chunks, no replicated STH carrier (C5 added), register `aad` = `None`, one stream per
  publisher NODE.
- 2026-10-12 — the call API builds on item 2's `KeptAvPublisher` / `AvKeep` / `KeepOutcome`; a
  refused keep is the typed `CallEvent::KeepRefused` (partial recording), rotation without a roster
  change is a self-update commit, `StreamEpochDekConflict` (#1069) named, keep comes from the row
  once CIRISPersist#1068 ships.
- 2026-10-12 — #1067: the STH leaf order is `(epoch, counter)` with each epoch's terminator last,
  and streams are born V2. A call never reuses a `stream_id` (crash or rejoin): `StreamId` gains a
  fresh per-join `join_nonce` and drops `CallId`; the witness lands with item 5's code.
- 2026-10-12 — the CC's answers to C1–C5 and V1. Keep is per stream, set by its producer. The call
  epoch is the room's, with no sub-epoch; every Add and every Remove rotates; any member may make
  the Update at the cap. Signalling reuses the membership rows: no `chat:call:*`, an ad-hoc call is
  an ephemeral community, and an in-room call needs no ring (`open_call` folds into `join_call`;
  `ring` added). No presence row. Live STHs are in-band; a kept stream's roots ride `evidence_refs`
  with no STH row (`SthRefused` → `RecordingRootMismatch`). The DEK is `stream_epoch_dek` (code on
  `local/805-5-call-key`): a per-stream binding under a PENDING label, a proposed deviation awaiting
  CIRISConstitution#169. `CallId` is an API handle only, never key input.
- 2026-10-12 — CIRISConstitution#169 RULED (CC rc8, a93974e): the per-stream DEK is normative,
  `L` = `"ciris-stream-dek/v1"` for both the exporter and the info tag (`STREAM_DEK_LABEL`),
  and a `key_grant:stream:v1` opens one stream. Keep changed mid-stream: ON wraps the current and
  later epochs, OFF is forward-only. "Recorded" is not a field (`history_on_join: full` or existing
  wraps; the recording is the CC 3.3.13 blob). verify#308's `stream_dek` and KATs replace edge's
  derivation when they land.
- 2026-10-12 — the stream label is `av-` + lowercase hex, not the bare hex: persist's chunk door
  refuses a bare 64-hex stream id (reserved for an inline blob's one-leaf log, #953). One spelling
  (`realtime_av::stream_label`) feeds the persist stream id, the STREAM nonce (#846) and the
  per-stream DEK's info.
