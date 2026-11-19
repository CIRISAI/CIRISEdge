# Changelog

Full notes for every release are in [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

## 45.1.7 — 2026-11-19

**PATCH. Per-leg call telemetry, chat reactions and flat threads, a facilitator for agent nodes,
and persist v61.4.2.** Pins: persist **v61.4.2** by tag (`ciris-persist==61.4.2`; was v61.4.1),
CIRISVerify v22.2.0, leviculum v0.34.0+ciris.3. No migration. Two new clear chat members and one
new chat dimension (below); a peer before 45.1.7 stores and replicates them as ordinary `chat:`
rows and shows a reply as a plain message.

### Changed

- **persist v61.4.2** (tag v61.4.2, commit 213a1c86): wire-compatible with 61.4.1,
  `DIRECTORY_ABI_VERSION` stays 13. The capsule proxy now routes 34 `FederationDirectory` methods
  that read `Unsupported` through it before, `list_live_consent_grants_by` among them, so an agent node's capability gate
  no longer reads "no grants" through the capsule. `DirectoryOp` / `DirectoryOpResult` variants
  are appended; edge matches neither exhaustively.

### Added

- **`call_legs`: one row per live call leg, as `ciris.edge.call.*` series**, for the call
  screen's "?" panel. A row is a member, one stream and one media kind (`audio`, `video`,
  `share`), sent (this node's own stream on its leg to the member) or received (the member's
  stream as it reaches this node). Every series carries `ciris.room.id`, `ciris.call.id`,
  `ciris.call.member`, `ciris.call.stream_id` and `ciris.media.kind`:
  - `ciris.edge.call.path` (gauge, 1): `path` `direct` or `relayed`; `relay.key_id`, the member
    relay that is the stream's ALM primary parent (empty when none; a transport forwarder is
    `relayed` with an empty key); `transport`, the carrier (`datagram` or `channel`); `punched`;
    `nat.local_type` and `nat.peer_type`, always `unknown` on 45.1.x (leviculum 0.34 has no NAT
    classification); `direction`.
  - `ciris.edge.call.rtt` (ms, the leg link's srtt) and `ciris.edge.call.bitrate` (bit/s,
    `direction` send or recv, re-measured at most once a second).
  - Receive rows only: `ciris.edge.call.frames_lost` (gaps in `frame_seq`),
    `ciris.edge.call.frames_skipped` (chunks the reorder window gave up on),
    `ciris.edge.call.jitter` (ms, RFC 3550 against the signed source timestamp) and
    `ciris.edge.call.reorder_window` (the most chunks the window held in the last second).
  - `ciris.edge.call.codec` (gauge, 1): `codec`, the binding's registered token for the class,
    else the class's name; never a peer-chosen string.
  - Each instrument is its own `TELEMETRY_CATALOGUE` row (field `call_legs`, label
    `ciris.call.member` as `LabelValues::CallLeg`, operator-only; `Unit::BitsPerSecond` is new),
    so a host renders OTLP from the catalogue. The host reads them from
    `Edge::metrics().snapshot()`: `EdgeMetricsBundle::call_legs` (`Vec<CallLegSeries>`: name,
    kind, UCUM unit, attributes, value) and `call_legs_overflow`. Python:
    `metrics_snapshot()["call_legs"]`. The flat form (UniFFI) carries the series count.
  - **Bounded:** rows are read from each live call's state when the bundle is read (a `Weak`
    registry), so a leg's series are gone in the first snapshot after the leg or its call ends; at
    most 64 rows (`CALL_LEG_ROWS_MAX`), `call_legs_overflow` counting the rest. No address, IP or
    port is ever an attribute.
  - **Off the hot path:** send bytes ride each leg's congestion entry under the lock
    `note_leg_outcomes` already holds; the receive side lives in the reorder loop's own maps and
    is published once a second (the loop wakes to publish).
- **Flat reply threads** (`FSD/CHAT_REACTIONS_AND_THREADS.md` §2 in CIRISServer, settled by CC).
  `chat::chat_message_reply_in` writes an ordinary `chat:message:v1` with one more clear member,
  `replies_to_attestation_id`, the thread's ROOT; nothing is written to the root. It refuses
  `chat.thread_in_thread` (naming the root as `root_attestation_id`) and
  `chat.reply_target_not_in_room` as `ChatComposeError::Refused(ChatRefusal)`. A revision keeps
  the root. `ChatMessage::replies_to` carries it, and `messages_in_room` files a stray nested
  reply under its target's root: a reader never opens a thread in a thread. A reply carries a
  file as a message does (`file: Option<&Attestation>`, refused `chat.file_not_in_room` when the
  file is not in the room), and is revised, withdrawn, recanted and reported as a message.
- **Emoji reactions.** `chat::chat_reaction_in` writes `chat:reaction:v1`: clear
  `community_key_id` and `target_attestation_id`, the emoji sealed under the room's DEK exactly as
  a body is. One emoji sequence of at most 32 bytes (`chat::is_one_emoji`, over the Unicode emoji
  property tables: flags, keycaps, modifiers, tag runs, ZWJ sequences), else `chat.not_an_emoji`.
  Taken back by the author's `chat_message_withdraw_in`, which now also takes the author's own
  reaction (a reaction is never revised or recanted). `chat::reactions_for(room, targets)` reads
  them opened, keeping the earliest per (person, target, emoji, byte for byte) and at most 20
  emoji per person per target; `chat::open_reaction` opens one row. Reactions are not messages:
  `messages_in_room` never returns one.
- **Conformance features:** `chat::FEATURE_REACTIONS` (`chat:reactions`),
  `chat::FEATURE_THREADS` (`chat:threads`) and `chat::CHAT_FEATURES` name them for the host's
  features list; edge advertises none itself.

### Fixed

- **An agent node with no named facilitator proposes direct links through its first bootstrap
  peer.** Field: the server's fold harness, where calls never formed legs on agent-style (PyO3)
  nodes. The PyO3 init took the facilitator from the host or the genesis bundle only, and the
  bundle's is gated off under a test trust root (#661), so nothing proposed and members two hops
  apart through the seat never got a leg (a derived A/V address answers a one-hop neighbour only).
  `DirectLinksConfig::resolve_facilitator`: the host-named one, else the bundle's where allowed,
  else the operator's first bootstrap peer (taken before any canonical is seeded, so the #661 gate
  holds), logged once at INFO with its source (`FacilitatorSource`). The server's compose already
  defaulted to the first bootstrap peer. `edge_node` is unchanged.
- **A call leg born on a punched interface reads punched.** `ReticulumTransport::av_link_path`
  (behind `Call::leg_info` and the `call_legs` path series) asked leviculum's
  `direct_link_interface`, which names only a link MOVED onto a punched interface. A call leg
  dialled once the identity link moved is sent on the punched interface from its first packet
  and was never moved, so E4's legs read `Interface` / `punched=false`. A link now reads
  `DirectUdp` when it was moved onto a punched interface or its interface index is one a direct
  path rides (`DirectPathTracker::punched_interfaces`); the link list is read only while a direct
  path is up. Found by the E4 telemetry witness, red before the fix.
- **A link forwarded through a punched peer reads relayed** (Codex on #1016). A punched interface
  is one socket to one peer (leviculum `interfaces/direct_udp.rs`), but when that peer is a
  transport node a link to a third destination through it leaves on the same interface; the
  born-on check now also requires the link not be forwarded (`born_on_punched`).
- **A release or skip at a reorder deadline is published** (Codex on #1016). Only arrivals marked
  the receive side for its once-a-second publish, so a deadline's release or skip after the last
  arrival left bitrate, skipped, depth and lost stale until the next packet. `RxPublish` marks a
  publish on any release, skip or framing-gate move; an idle call publishes nothing.
- **`ciris.edge.call.bitrate` counts one layer both ways** (Codex on #1016): each chunk's
  plaintext payload. The send side counted the wire form (overhead and trailer included).

### Privacy

- `call_legs` is the third field that names peers (`ciris.call.member`, and `relay.key_id`),
  after `peer_reachability_ratio` and `recent_withholds`: a named exception by Eric's decision
  (2026-11-19), operator-only and served to the owner session only, live calls only, 64 rows at
  most. The catalogue test pins `LabelValues::CallLeg` to the `call_legs` field alone;
  `docs/TELEMETRY_CATALOGUE.md` says why.
- A reaction's emoji is sealed: which emoji someone chose is as private as what they wrote.

### Witnessed

- The roster-relay call (`alm_mesh_stage2`): C's receive row for B's stream is `relayed` with A
  as `relay.key_id`, every instrument present with the common attributes; A's row for B is
  `direct`, unpunched; B's send row to A has a rate; every series is gone after the calls drop.
  E4 (`av_call_nat_805`): A's send and receive rows to B read `direct`, `punched`, `datagram`;
  both nodes' series are gone after leave. No attribute value of any witnessed series parses as an
  IP or socket address. Unit: the 64-row cap and its overflow count, one catalogue row per
  instrument.
- Chat (`chat_message_federates`): a reply round trip; a reply carrying a file, whose edit keeps
  its root and its file and whose recant leaves the root; a reply to a reply refused naming the root;
  a stray nested reply filed under the root; a reaction opened, deduplicated to the earliest and
  taken back by withdraw; text that is not one emoji refused; and a reaction made on bob's node
  crossing to alice's, who opens the emoji (a non-member opens nothing). Unit: emoji sequence
  shapes.
- The facilitator: an unnamed facilitator under a test trust root resolves to the first bootstrap
  peer without reading the bundle; host and bundle still come first; `off` resolves nothing.
- Each witness was run red, with its fix undone, before green.

## 45.1.6 — 2026-11-18

**PATCH. A call starts on every agent install, and a wrap a member refused before their roster
landed reaches them once it has.** Pins unchanged: persist **v61.4.1** by tag
(`ciris-persist==61.4.1`), CIRISVerify v22.2.0, leviculum v0.34.0+ciris.3. No migration. One
additive wire member (`Diff.withheld`, below); a peer before 45.1.6 ignores it.

### Fixed

- **A split home's call is signed by the node.** Field: ciris-agent 2.22.1 + server 0.5.249 (edge
  45.1.4). `POST /v1/chat/<room>/call` returned 503 `call.plumbing`: "the signer that binds this
  stream's chunk keys is ciris-agent-bootstrap-…, not the publisher ciris-node-bootstrap-…". Every
  agent install is a split home: the Edge signs as the agent (the actor), while its transport, its
  stream's publisher and its room leaf are the node. `join_call_as` handed the call the Edge's
  engine signer as the stream's chunk-key binder and as the node's co-scrub on the call row, and
  `Call::join` refused it. Standalone harness nodes have one key, so every witness passed.
  - **`Edge::node_signer()`** is the signer of THIS NODE, the one whose key is the transport's
    occurrence. It is the host's (`EdgeBuilder::node_signer`, `Edge::set_node_signer`; refused
    when its key is not the occurrence, set once), else the transport's own signer when that is
    the node (`ReticulumTransport::node_signer`), else the Edge's signer. A single-key node is
    unchanged, and an agent install needs no host change: its transport already holds the node's
    signer. The pyo3 init also hands the node identity it resolves under `use_node_identity` to
    the builder.
  - `join_call_as` binds the stream (and so its Ready/Caps, rebinds and leave) and co-scrubs the
    call row with the node signer. The attendee, when the host names none, stays the Edge's
    signer: the actor (#541).
  - Same class: `send_mandatory`'s and the federation fan-out's self-loopback filters compared
    peers with the actor only. A split home is also the node it advertises.
- **The wrap courier books what the recipient did, and carries a refused wrap again
  (CIRISEdge#1014).** Field (server harness, four-person star room, 45.1.5): dave never got bob's
  key_grant, `not_granted: 1` for 6 min, while bob booked `wrap_courier_sent 2 / admitted 2`.
  dave's responder recorded the round `admitted: 0, refused: 1` (persist: not yet an active member)
  and dave's roster landed 1.7 s later. The courier read a round's end as admission (the report it
  read was its own apply of dave's empty Deliver) and dropped dave. dave's #1148 release re-asks
  only its own peers, which in a star room do not include the minter.
  - A row is now settled by the recipient's next answer: asked for again, or named in its Diff's
    new `withheld` (rows it refused and backs off from), the delivery was refused, and the row is
    retried on the existing backoff (10 s doubling to 5 min, given up after 6). Neither asked for
    nor withheld, the recipient holds it. A delivered row is confirmed by a round 2 s later.
  - **`Diff.withheld`** is sent only for an offer of at most 64 refs, capped at 64 hashes, and
    omitted when empty, so an ordinary round's Diff is byte-identical. A recipient before 45.1.6
    names nothing withheld; a row it refused and still backs off from reads as held there.
  - **Booked truthfully:** `wrap_courier_sent` counts rows the recipient asked for and was
    delivered; each delivery is later booked once, `admitted` or `refused` (or `gave_up`).

### Tested

- `a_split_home_joins_its_rooms_call_as_the_node` (`scoped_body_identity_link_718`): A's Edge
  signs as an agent while its transport is the node, as the pyo3 path and the server compose it.
  Red at 45.1.5 with the field's error. Green here: A joins, and B accepts A's frames (under a
  binding verified against A's node key), publisher A's node.
- Guards (`edge`): a source scan holds that `join_call_as` binds and co-scrubs with the node
  signer and uses the Edge's signer only as the attendee fallback; the node signer is set once
  and falls back to the Edge's signer.
- `a_wrap_refused_before_the_roster_lands_is_carried_again_1014` (`late_device_768_tests`): B's
  wrap reaches A before A's roster, A refuses, the roster lands 1.7 s later. Red at 45.1.5 (sent 2
  / admitted 2, never granted). Green here: A admits within 60 s, B books the refusal before the
  admission, and sent == refused + admitted with nothing given up. Units: a row settled by the
  answer, the round recording the answer, a responder naming what it withholds (and nothing for
  a large offer).

### Audit: what edge signs as "this node"

| Site | Role | 45.1.6 |
| --- | --- | --- |
| `join_call_as` stream binder (`CallDeps::signer`: binding, Ready/Caps, rebind, leave, chunk seal) | node | node signer |
| `join_call_as` call-row co-scrub (`PersistCallRecord::node`) | node | node signer |
| `join_call_as` attendee fallback | actor (#541) | unchanged |
| `send_mandatory` / federation self-loopback filters | node identity | actor or advertised id |
| Envelope signing, enqueue sender, delivery and refusal attestations | actor (#541, v18.15) | unchanged |
| Transport routes, announces, transit pair | node | already the transport's own signer |
| Direct-link proposals | node | channel signals on the node's identity link; no edge signature |
| File holds, custody claims and co-scrubs (`attestation_bind::Signers`) | node | host-supplied `Signers { node, actor }`, no edge-side default |
| Key-grant emitter | minter | persist's engine signer |
| Wrap courier | minter | carries rows, signs nothing; scans by the runtime's `local_key_id` |
| Touch claims (pyo3 `produce_*_touch`) | attester's own | unchanged |

### Known, not fixed in this line

- **CIRISEdge#1000:** a responder step still has no deadline of its own.
- **CIRISEdge#996:** `direct_links_805`'s relay-leg test loses A/V chunks under CPU contention.
- **CIRISEdge#1002:** an initiator round's opening step runs outside the round timeout.
- **CIRISEdge#1009:** `av_call_nat_805`'s punched-interface room call failed once, with the link
  seal held during keying.
- **CIRISEdge#1010:** a fresh A/V leg drops its first frames, and the rotation leg blames the
  rotation for them.
- **CIRISEdge#1012:** mesh6: a member's message body bytes are never fetched (`not_fetched`).
- **Owner keys reach a six-node room in about 600 s:** to be re-measured.

## 45.1.5 — 2026-11-16

**PATCH. A member's messages in a star room open for everyone: a minter carries its key-grant
wraps to members that are not its peers; and `not_in_audience` follows persist's retry rule.**
Pins unchanged: persist **v61.4.1** by tag (`ciris-persist==61.4.1`), CIRISVerify v22.2.0,
leviculum v0.34.0+ciris.3. No wire change, no call-shape change, no migration. Found in the
server's star6 harness on 45.1.4 (0/3): a newcomer read the founder's messages but never a
second writer's.

### Fixed

- **A minter carries its wraps to a room member that is not its peer.** A member who writes
  mints its own epoch and wraps it to each member device. persist serves a wrap to its recipient
  only, so no member can relay it, and a host's replication peers are its consent peers. In a star
  room the members are contacts of the founder but not of each other. A non-founder's wraps
  therefore never left its node, and the newcomer read its messages `not_granted` for good. This
  was not the #1006 ordering class: the founder's wrap and person row were refused, released and
  admitted within about 100 ms in every run.
  - **The wrap courier** (`replication::wrap_courier`) runs one task per sealing runtime. It is
    woken by the host's kicks (the room seat kicks after granting) and runs once at start. It
    reads this node's own key-grant rows newest first until a page holds nothing new. Each wrap
    whose recipient has no Attestation initiator here is carried in one ordinary
    Summary/Diff/Deliver round on a coordinator of its own. That coordinator is registered only
    while the recipient's initiator slot is empty, and the round goes over whatever route
    reaches the recipient. No new wire message.
  - **Scope.** Only rows this node signed, addressed to that recipient, each passing persist's
    own `may_receive`. The round offers exactly those refs and wants nothing back. A recipient
    that is, or becomes, a peer is left to its ordinary round.
  - **Bounded.** One round per recipient at a time. Retries double from 10 s to 5 min, and the
    courier gives up after 6 attempts. It holds at most 256 recipients and carries at most 64
    rows per round. Nothing is read between wakes.
  - **Booked** in `replication_io`: `attestation:wrap_courier_{sent,admitted,refused,gave_up}`,
    counted in rows. `admitted` means the round ended in sync. Never addresses.
- **`not_in_audience` follows persist's retry rule.** persist marks it retryable; edge overrode
  it to terminal on both the general and the key-grant door. It is now transient and indexed on
  its audience gate as an ordinary row, the #1006 shape. The #1148 releases still forget it at
  once, and the #858 cap still moves a never-released one to the terminal schedule.

### Tested

- `a_minters_wrap_reaches_a_member_that_is_not_its_peer_star6` (`late_device_768_tests`): two
  real substrates and runtimes joined only by a pair transport. Node B mints an epoch wrapped
  to member A, and the two are not peers. Red at 45.1.4: B sent no frames in 20 s. Green here:
  - A admits B's wrap after B's host kicks;
  - every row B delivered is one of A's own wraps;
  - B books sent == admitted, with nothing refused or given up.
- `a_not_in_audience_refusal_is_transient_and_indexed_on_its_gate_star6` (`replication::bridge`):
  red at 45.1.4 (terminal), green here. The #1148 witnesses now assert the transient window and
  the cap fall in place of the terminal park. Courier units cover the backoff bound and a round
  that offers only what it carries.

### Known, not fixed in this line

- **CIRISEdge#1000:** a responder step still has no deadline of its own.
- **CIRISEdge#996:** `direct_links_805`'s relay-leg test loses A/V chunks under CPU contention.
- **CIRISEdge#1002:** an initiator round's opening step runs outside the round timeout.
- **CIRISEdge#1009:** `av_call_nat_805`'s punched-interface room call failed once, with the link
  seal held during keying.
- **mesh6 `not_fetched`:** a message body's bytes not fetched in one six-person mesh run, a
  different class from star6's (blob fetch). To be filed.
- **Owner keys reach a six-node room in about 600 s:** to be re-measured after #1005.

## 45.1.4 — 2026-11-15

**PATCH. A new node is no longer locked out of a seat, its own Key is no longer starved by
recovery rounds, and a member's row that beats their acceptance lands (CIRISEdge#1004, #1005,
#1006).** Pins unchanged: persist **v61.4.1** by tag (`ciris-persist==61.4.1`), CIRISVerify
v22.2.0, leviculum v0.34.0+ciris.3. No wire change, no call-shape change, no migration. All three
were found in the server's harness and QA runs against 45.1.3.

### Fixed

- **A new node that returns on a second transport identity is not locked out (CIRISEdge#1004,
  seat side).** A brand-new node announced on transport identity A and was bound Advisory, with no
  Key row at the seat yet. When the same key came back on identity B at the same epoch (a wiped
  `data/edge`, or a stray process that shared the key), the seat read B as a stale re-announce:
  at equal epoch only an owner may move a route, and with no Key row the seat's directory could
  not confirm ownership. Every link from B missed attribution and was torn down inside the E1
  hold before the #402 carve-out could land B's Key row, so the lockout never cleared.
  - **The fix.** On `UnknownKeyId` the seat now accepts the announce's own ownership proof: the
    key id's fingerprint is the claimed pubkey's and the attestation self-verifies under it. This
    is the #636 proof Stage 1 already binds every first-seen peer on. B then reroutes as the owner
    (the #336 owner reroute), its links are attributed, and its Key row lands.
  - **Why this is the smallest change.** Supersession rules are unchanged. Only the input that was
    missing on `UnknownKeyId` is supplied, and it is used only over a resident entry that is not
    Rooted, so a Rooted route still moves only on the directory's verdict (CRITICAL-1, #337).
  - **Spoofing.** The proof needs the federation private key. An attacker who knows only the key
    id cannot produce it, so it cannot evict anything it could not evict before. It also loses the
    lockout it had: a spoofer that announced first under a new node's key id is now superseded
    by the real node.
  - **A stale announce from another identity no longer keeps the resident alive.** The
    IgnoreStale arm refreshed the resident's LRU stamp whatever identity announced. It now does so
    only for the resident's own transport key (#530's liveness ordering is otherwise unchanged).
- **A recovery round no longer costs a peer its ordinary round (CIRISEdge#1005, node side).** A
  signer-recovery round replaced the tick's ordinary round, and only the ordinary round's Summary
  offers the node's own rows. A host that re-queues a contact's missing key every pass, toward a
  seat that cannot answer it yet, turned every tick into a recovery round. The node's own Key never
  went, so the seat never met the node it would have needed to answer the Pull (62 recovery rounds
  in 297 s, no ordinary Key round).
  - **The fix.** The ordinary round now follows the recovery round in the same tick. The recovery
    round is closed before the ordinary one opens its own round, so one exchange is still
    outstanding at a time, and a late Pull reply is dropped at the registry (#634).
  - **The cost.** At most one `round_timeout` (10 s) more on a tick where a name is queued,
    against the 30 s cadence, and a tick that overruns is skipped, never bursted. The alternative,
    a guaranteed ordinary round every N ticks, would still delay a fresh node's own Key by N
    cadences.
  - **Booked apart.** A recovery round no longer books `note_round_complete`, which logged "first
    sync complete: moved nothing" for a node whose own rows had never been offered. It is counted
    as `replication_io` `<kind>:recovery_rounds` / `recovery_rounds_completed`.
    `FSD_SIGNER_RECOVERY` D2/D3 updated.
- **A member's row that arrives before their membership lands once the membership does
  (CIRISEdge#1006).** In a star room (members not all contacts of each other), a newcomer that
  already held the roster received a member's chat row before that member's acceptance. persist
  refused it `NoCommunityMembership`. Edge classified that TERMINAL (30 min doubling to 6 h), and
  nothing cleared the refusal when the membership landed seconds later, so the row was never
  asked for again and its body never fetched.
  - **Transient again.** `not_a_community_member` and `not_a_family_member` are transient. Persist
    cannot tell "removed" from "not caught up yet", and in a growing room it is the latter. Their
    log line no longer says TERMINAL. A member who really was removed is still bounded: after
    `TRANSIENT_CAP_HITS_BEFORE_TERMINAL` (3) windows at the cap the row falls to the terminal
    schedule (#858, the #544 storm bound).
  - **Released by the roster event.** These two classes and `retry_after_roster` are now indexed on
    their group's audience gate (`audience:group:<group>`, from the row's signed cohort target). Any
    event that lands the roster releases them at once and kicks the offering peer, reusing the
    #1148 release paths:
    - a first roster, a roster supersede or a widening admitted through the replication choke;
    - the widener's local widening (`release_audience`);
    - a `RosterLanded` row reported through `note_local_writes_since`.
  - **Not parked.** They stay ordinary transient rows, so a roster that arrives by some other path
    still converges on the transient window. They do not wait out a terminal park.
  - Both community and family planes. No persist-facing contract changes.

### Tested

- `a_new_node_back_on_a_second_identity_reaches_the_seat_1004` (`canonical_nat_clients_971`,
  real Reticulum on loopback): a seat with no Key row for the client; identity A is bound, then
  suspended; identity B, same key and epoch, runs its bootstrap rounds. Red at 45.1.3: after
  2 min the seat's route still named A, B had no attributed link and no Key row. Green here.
- `a_requeued_recovery_name_does_not_starve_the_own_key_round` (`replication::scheduler`): a
  recovery name re-queued every pass toward a seat that answers it empty. Red at 45.1.3 (499
  recovery asks in 5 s, 0 of 2 own rows at the seat). Green here.
- `a_members_row_ahead_of_their_acceptance_lands_once_it_does_1006` and
  `a_locally_landed_roster_clears_a_members_refused_row_1006` (`replication::bridge`): a star
  room of three, the member's row before the member's widening, through the choke and through
  `note_local_writes_since`. Both red at 45.1.3 and green here. Unit witnesses cover the
  widening, a roster supersede, the family plane, the first roster (`retry_after_roster`), and
  that an indexed row still falls to the terminal schedule at the cap.

### Known, not fixed in this line

- **CIRISEdge#1000:** a responder step still has no deadline of its own.
- **CIRISEdge#996:** `direct_links_805`'s relay-leg test loses A/V chunks under CPU contention.
  A/V relay is off on the server for this LTS.
- **CIRISEdge#1002:** an initiator round's opening step runs outside the round timeout.
- **Owner keys reach a six-node room in about 600 s, against about 75 s for three.** #1005 may
  have been its cause (a node's own Key starved by recovery rounds until its queue drained); to
  be re-measured on 45.1.4 before it is attributed to the key-plane memo's revalidation.

## 45.1.3 — 2026-11-14

**PATCH. A node's replication responder no longer wedges (CIRISEdge#998).** Pins unchanged:
persist **v61.4.1** by tag (`ciris-persist==61.4.1`), CIRISVerify v22.2.0, leviculum
v0.34.0+ciris.3. No wire change, no call-shape change, no migration. Found in the server's
six-person `big_room` runs: one node's responders all sat in one step for minutes (354 s on Dave
at 45.1.2, 372 s and 483 s on 45.1.0's nroom6b and nroom6c) while its initiator kept running, so
nothing toward that node crossed, including owner bindings and invitations.

### Fixed

- **A task holding a sweep permit no longer asks for a second one (CIRISEdge#998).** The node-wide
  sweep gate (two permits by default) is not re-entrant. A stranger's announced-testimony Pull
  (#907, `subject_pull_answer` arm 4) held its permit across the whole holdings walk, and each row
  of that walk resolves its recipient through the consent memo, which takes a second permit when
  the memo is empty or expired. Two concurrent stranger Pulls then held both permits and waited
  for each other forever.
  - **Why it froze every plane, not one.** Every other permit taker parked behind them. The store
    feed's catch-up waits for a page permit while holding the node-wide feed mutex, and the
    key-plane listing holds its memo lock across that catch-up, so every responder on every plane
    ended up waiting. Responder steps have no deadline; initiators time out at 10 s, which is why
    the node still looked alive from outside.
  - **The fix.** The announced-testimony permit is now taken inside the holdings walk, around the
    paged store read only, and released before the per-row recipient resolution.
  - **The class, audited.** A call graph from every permit site in the bridge (all 19, plus the
    paged-read closures and the offer path by hand) found this one holder able to reach another
    acquire. No permit holder reaches the feed mutex or a memo lock, so no lock-then-permit order
    can invert.
- **A peer added after start counts into the host's metrics.** Every replication coordinator
  built after `ReplicationRuntime::start` was built with no metrics bag. That covers peers added
  by `set_peers` / `register_peer`, homed peers, the bundle seats' Pull and their revocation
  rounds. Only `start`'s initial peers and the responder factory carried one. This predates 45.1.
  A server-composed node starts with no peers, so before 45.1.3 every initiator on it was
  unmetered. Its initiator-side counters read zero:
  - `replication_envelopes_served_total` from pushes;
  - `replication_io` push, summary, diff and pull rows;
  - `first_sync_complete`;
  - `peer_activity.wire`.

  So 45.1.0's seat-load counters were partly dark on the seat. It showed most after 45.1's
  seat-load changes moved a node's rows from its responders' answers (metered) onto its own push
  (unmetered). `replication_envelopes_served_total` keeps its meaning: rows sent on the
  replication plane, pushed or delivered, each row once, when the transport took the frame. It was
  never meant to count the 45.0.x double delivery of a pushed row. `replication_io` remains the
  per-direction detail.
- **A debug guard against re-entry.** In debug builds the sweep gate records which task holds a
  permit and where it was taken. A task that holds one and asks for another panics under test and
  logs an error naming both sites in other debug builds. Release builds carry none of it.

### Tested

- `a_strangers_announced_testimony_pull_never_waits_on_a_second_permit_998`
  (`replication::bridge`): two permits, two concurrent stranger Pulls and the subject's own
  Key-plane Pull, with an expired consent memo. Red at 45.1.2 on the first of 50 attempts (one
  permit and one Pull hangs outright); green here.
- `a_task_holding_a_sweep_permit_cannot_ask_for_another_998` (`sweep_width_tests`): the guard
  fires on a nested acquire. Both witnesses are red under their own mutation.
- `a_peer_added_after_start_counts_into_the_hosts_bag` (`replication::runtime`): a runtime
  started with no peers, a peer added by `set_peers`, its push and a later Deliver read through
  the host's own `EdgeMetrics`: served = push rows = rows sent, each once. Red (0, 0) with the
  bag dropped from `build_peer_coordinator`. `every_production_coordinator_is_built_with_metrics`
  guards the class by source scan.
- The full integration gate runs in debug, so the guard was live across all of it.
- **Field confirmation:** with the gate off (`CIRIS_EDGE_ADVERTISE_SWEEP_PERMITS=0` on every
  node), four six-person `big_room` runs on 45.1.2 + persist 61.4.1 passed 4 of 4 with no
  `stepping` drops on any node, against 2 wedged runs of 3 at the default permits.
- **Production:** the seat itself showed only stalls of up to 4.5 s (the Attestation plane, agent
  CI peers, 2026-11-13); the minutes-long wedge was seen in the six-node harness.

### Known, not fixed in this line

- **CIRISEdge#1000:** a responder step still has no deadline of its own. With the deadlock gone
  nothing known holds one for long, but a bound is filed for after this line.
- **CIRISEdge#996:** `direct_links_805`'s relay-leg test loses A/V chunks under CPU contention
  (present at v45.1.0). A/V relay is off on the server for this LTS.
- **Owner keys reach a six-node room in about 600 s, against about 75 s for three:** a staircase
  whose span is the key-plane memo's 10-minute revalidation on the seat; after the persist v62
  refactor.
- **CIRISEdge#1002:** an initiator round's opening step (building its Summary and push) runs
  outside the round timeout, so a stuck opening step never ends its round. Filed for after this
  line.

## 45.1.2 — 2026-11-14

**PATCH. Rooms of three or more read their history.** Pins: persist **v61.4.1** by tag (`tag =
"v61.4.1"`, commit 32e19ede; Python too: `ciris-persist==61.4.1`), CIRISVerify v22.2.0, leviculum
v0.34.0+ciris.3. Found by the server's `big_room` harness on 0.5.247: a newcomer in a three-person
room read one history message `not_fetched` and another `seal_mismatch` until teardown, and a
second run of identical code passed. Three causes, two in edge and one in persist; all three fixed.

### Consumer notes

- **The persist requirement is `ciris-persist==61.4.1`.** Capsules are named for the persist
  build, so a 61.4.0 wheel is refused at `init_edge_runtime` with `capsule_version_skew`. No
  migration and no call-shape change.
- **New counters.** `blob_pull_refusals[park_register_full]` counts a parked pull dropped from the
  full park register (it is then no longer woken); `link_seal[link_seal_route_fetch_backed_off]`
  counts a dial refused inside a route-fetch backoff.

### Fixed

- **A body sealed before the newcomer held its author's key now opens (persist v61.4.1,
  CIRISPersist#1271).** Edge adopts a pulled body with no named minter, and persist chose the
  epoch's minter as the lone one granting this node, without asking whether it acts for the
  body's author. On Carol's node Bob's epoch-0 grant arrived first, Alice's body was bound to Bob,
  and the repair for stranded bindings never moved it (Bob holds a grant): every read was
  `seal_mismatch`. 61.4.1 filters the lone candidate by acts-for-author, rebinds a stranded
  binding only onto a minter that acts for the author, and heals a body that does not open on read.
- **A one-chunk blob with two routable holders is no longer struck out by its own fetch.** The
  edge holds one waiter per `(blob, chunk)`; the swarm's endgame (always on for a one-chunk blob)
  sent a duplicate to the second holder, which replaced the first holder's wait, and each closed
  wait ("channel closed before response") was an error strike. Both holders were retired within
  milliseconds (20 dispatches in 45 ms on Carol). The endgame now skips a chunk already waiting
  under any holder, and a replaced wait is neither an answer nor a strike (bounded: past
  `error_strike_limit` supersessions of one chunk it is a strike again).
- **A pull with nobody to fetch from parks instead of being dropped.** A pull that ended with its
  room's group not yet installed in the scope address table, with no holder, with every holder
  unreachable, or with its retry ladder spent (5 attempts, about 75 s) was dropped, and nothing
  re-offered the row. It now parks and is woken by the scope address table installing its group,
  or by an admitted holder claim (`custody:ack` `here`) for its blob.
  - The scope wake reads a generation counter the table bumps on every write that can make an
    address appear (install, refresh, install-next, activate-next), rather than hooking the scope
    lifecycle's verbs: `ScopeLifecycle` is built by the host, so this needs no host change, and it
    also covers hosts that drive the table directly. A woken pull records the generation, so one
    that fails again against an unchanged table is not re-pulled every tick.
  - The park register is shared with the key-wake parks: at most `retry_capacity` entries (256 by
    default), the oldest dropped with a WARN and counted (`park_register_full`).
- **Consecutive failed route fetches back their destination off (CIRISEdge#993).** A dial with no
  transit pair fetches the peer's route row first; when that failed, every caller dialled again
  on its own schedule, and the outbound drain retries each queued row separately, so N rows toward
  such a peer were N redials (about 1,700 link up/down a minute per node in the loopback control
  scenario; the behaviour predates v45.0.2). The first failure toward a destination is free: one
  immediate retry is kept, the CC 5.3.3.5 E1 / CIRISEdge#964 contract that the dialler cannot see
  a responder's request cap reopen or its own replaced PQC commitment. From the second
  consecutive failure a pairless dial is refused before any link opens, for 5 s doubling to
  5 min; bounded at 4096 destinations. A successful fetch clears it, a verified announce from the
  peer clears it (the peer may have minted its row), and a dial that holds a pair (a replicated
  route row) never consults it.

### Tested

- `a_newcomer_opens_a_body_whose_authors_grant_arrived_after_it_1271` (tests/blob_federation_e2e.rs):
  three members; Bob's grant first; Alice's body through edge's own pull, offered by both holders;
  Alice's grant after the body; the body opens. Red on v45.1.1 (Rust identical to v45.1.0) with
  persist 61.4.0 (`SealMismatch`), green here. The two-holder fetch itself is witnessed at the swarm
  (`a_chunk_with_two_holders_is_asked_once_and_lands`, red with the old endgame filter); the whole
  path end to end is the server's `big_room`.
- Every fix has a witness red under its own mutation: the superseded wait, the scope wake (no
  generation bump), the holder wake, the drop counter, the backoff and its announce reset.

### Known, not fixed in this line

- **CIRISEdge#996:** `direct_links_805`'s relay-leg test loses A/V chunks under CPU contention
  (5 in 10 interleaved runs, the same at v45.1.0 and here). A/V relay is off on the server for this
  LTS.
- **Owner keys reach a six-node room in about 600 s, against about 75 s for three:** the keys land
  as a staircase whose span is exactly the key-plane memo's 10-minute revalidation on the seat.
  The memo work waits for after the persist v62 refactor.
- **CIRISEdge#998:** in six-node runs one node's replication responder can wedge for minutes,
  every driver stuck in one step while its initiator keeps running (present at v45.1.0). Rows
  toward that node, including owner bindings and invitations, do not cross until it clears. Under
  investigation; it is the next fix on this line.

## 45.1.1 — 2026-11-14

**PATCH. The pin form only.** Persist is pinned by its tag, `tag = "v61.4.0"`, instead of by
`rev = "0568ebf3…"`. It is the same commit and the same tree, so nothing a host runs changes. A
consumer that pins persist by tag beside edge now resolves one persist source, and a release gate
that reads `?tag=` from `Cargo.lock` passes. Code, pins and behaviour are otherwise identical to
45.1.0, and every 45.1.0 note applies.

## 45.1.0 — 2026-11-13

**MINOR. The long-term support line** for a mesh of at most 100 nodes, until the persist v62
refactor lands. Pins: persist **v61.4.0** (tag 0568ebf3, exact, Python too: `ciris-persist==61.4.0`),
CIRISVerify v22.2.0, leviculum v0.34.0+ciris.3. After this tag the line takes bug fixes only.

### Consumer notes

- **The persist requirement is `ciris-persist==61.4.0`.** Capsules are named for the persist
  build; a 61.2.x or 61.3.0 wheel is refused at `init_edge_runtime` with `capsule_version_skew`.
  Persist 61.3.0 and 61.4.0 add migrations V214 (`federation_cosign_pending`,
  `federation_cosign_signatures`, `federation_cosign_aliases`) and V215 (the alias table indexed
  by the held row); they run at the first open.
- **Init refuses a persist that lacks the ops capsules.** Every store view edge holds (verify,
  rooting, blackhole, edge-detection, the outbound queue) is built from persist's
  `directory_ops_capsule` / `outbound_queue_ops_capsule`; the raw `outbound_queue_capsule` is no
  longer read and `runtime_handle_capsule` is checked for presence only, never unwrapped.
- **The responder's completion line reads `refused: N, duplicate: D, rejected: R`.** `refused`
  keeps its old meaning (refusals and duplicates) for this release, because hosts parse it;
  `rejected` is the real refusals. `RoundReport` and the applied outcomes gain `duplicate`.
- **New counters (seat load).** All in `metrics_snapshot()` and docs/TELEMETRY_CATALOGUE.md:
  `advertise.rows.<class>.<outcome>`, `responder_rounds_total.<kind>:opened_<message>`,
  `replication_io.<kind>:<label>` (rows and bytes per plane, in and out) with
  `first_sync_complete`, `peer_activity.initiator.<class>.<outcome>`,
  `peer_activity.link_up.<class>` / `link_down.<class>.<cause>`, `peer_activity.wire.{v3,legacy}`,
  `persist_reads.<door>:<caller>.<reads|rows|bytes>`, `holdings_index.<plane>.duplicate_from_index`,
  `holdings_index.held_equivalent.forgotten`, and `decision_row_unheard_total` gains
  `cosign_pending` and `cosign_signature`.
- **`persist_reads` is complete only in a single binary.** In a host that links edge and persist
  into one binary (ciris-server) every store read is counted under edge's site label. Across two
  Python wheels, edge's snapshot reads the counters of edge's own copy of persist: it shows only
  the reads counted on edge's side of the capsule (the typed attestation query, under its label,
  e.g. `attestation_query:edge.first_contact`); reads counted inside persist's wheel stay in the
  wheel's counters, unlabelled, until CIRISPersist#1270.
- **No seat CPU saving is claimed.** Production windows on 2026-11-13 could not separate any
  planned fix's CPU effect from zero; seat CPU follows link count. This release ships the counters
  that measure it; measurement follows.

### Fixed

- **Two-wheel hang (CIRISEdge#988).** With persist and edge installed as two Python wheels, each
  `.so` links its own `parking_lot`, which keeps parked threads in a per-binary table. Edge ran its
  own compiled copy of persist's store code on the wheel's backend (a concrete `SqliteBackend`
  lifted from `outbound_queue_capsule`), so a waiter one binary parked on the SQLite writer was
  never woken by the other's unlock: the first `dispatch_inbound_bytes` hung for good, in either
  direction. Every store call now runs inside persist's library through the ops proxy
  (CIRISPersist#1227, #1244). `tests/no_concrete_persist_in_binding.rs` holds the binding to zero
  concrete persist references; tools/two_wheel_lock_witness.sh and
  tools/scenarios/cohab_store_lock_contention.py drive the two wheels side by side.
  Measured (store-lock witness; 8-wide reproduction):

  | build | witness | reproduction |
  |---|---|---|
  | v45.0.2 + persist 61.2.3 (before) | 12 of 12 runs failed | 9 of 320 runs hung |
  | this branch, local wheels (edge 1eaa021, persist 61.4.0 from 4ca2a28b) | 80 of 80 passed | 0 of 320 hung |
  | edge bcfdaff + persist 61.4.0 tag-CI wheel (sha256 4e507375…5f9c) | 20 of 20 passed | 0 of 80 hung |

  A two-node Reticulum scenario over the two wheels (tools/scenarios/cohab_reticulum_two_node.py)
  passed 20 of 20, with the rooting writes and the blackhole read on send traced through the proxy.
- **Persist trust reads no longer fail open through the proxy (CIRISPersist#1268).** At 61.4.0 the
  halt, withdrawal, audience, hardware-policy, key-grant, purge, roster and cosign-alias reads are
  ops; none answers a trait default through the capsule.
- **A read persist answers with its timeout fallback is never kept.** `node_key_id`,
  `hardware_attestation_policy` and `withdraws_delegation_depth` block one host round trip through
  the proxy (30 s bound, fail-closed). Edge latches the first real answer and never latches the
  fallback (`NODE_KEY_ID_UNAVAILABLE`, the refuse-all policy, depth 0); a node key registered after
  init is read when it lands (CIRISPersist#1269 is the v62 fix on persist's side).
- **An unheard `cosign_pending` decision row was counted as `membership_proposal`.** The kind list
  now carries both cosign kinds; a test checks every kind lands in its own slot.

### Changed: persist #1252 (quorum rooms widen and remove inside the mesh)

- **Cosign rows are decision rows.** `cosign:pending:` and `cosign:signature:` reach the room's
  members as `DecisionRowKind::CosignPending` / `CosignSignature`, scoped by the held row, keyed
  by the quorum key.
- **One act, one ref.** An attestation's content hash is persist's wire hash; holdings are written
  under the act's ref and remembered under the plain ref too, so an act offered under another
  ref (a 61.2 peer's old hash) is wanted once and then answered as held (`HeldEquivalent`).
- **A `withdraws` that arrives before its target parks on the row** (`row:<attestation_id>`) and
  is released when the target lands, by replication, as a duplicate, or by a local write.

### Changed: replication on the seat

- **A Duplicate of a ref the holdings set lacks is remembered as held** (Attestation plane), so it
  is not wanted again every round; an audit that finds a held hash gone forgets the remembered refs.
- **Bytes a Ready holdings index holds are a Duplicate without a persist call**: long-lived peers
  that re-push rows the seat withholds from them cost a hash lookup.
- **An initiator does not deliver twice in one round**: the Diff that rode beside our own push no
  longer asks for what we pushed, so a fresh node's first round applies each row once.

### Paths the two-wheel fix covers, and two it does not exercise at wheel level

Every store view runs through the ops proxy. Two paths are routed but not driven by a wheel-level
test: the edge-detection writer (`put_edge_detection_event`) is unreachable from the Python binding,
because the probe observer is off with no switch there (the route stays for single-binary hosts,
which can enable it); and the sealed link, so nothing past the handshake (frames, replication):
two fresh loopback nodes hold no signed route row of their own with a transit pair, so every
pre-seal route fetch is answered `route_unavailable` and no link seals. The 20 two-wheel Reticulum
runs above gave both nodes one all-zero transport identity, so neither rooted the other; with a
transport identity each (the mixed runs below), each node roots the other.

### Mixed versions

- **In the release suite** (lib tests, on the merged head), the named mixed-version leg ran 9
  tests: `an_act_offered_under_another_ref_is_wanted_once_1252` (three idle diffs against a 61.2
  peer's old refs read no store page), `cosign_rows_are_decision_rows_on_their_room_1252`,
  `a_cosigned_row_is_held_under_its_act_ref_1252`,
  `a_withdraws_waits_for_its_target_and_lands_after_it_1252`,
  `a_stale_route_is_fetched_once_not_every_round_971`,
  `a_route_leaving_the_index_ends_every_stale_mark_971`,
  `the_mark_past_the_cap_evicts_the_oldest_once_971`,
  `a_duplicate_of_an_unheld_ref_is_not_wanted_again_seat_load` and
  `a_re_pushed_held_row_costs_no_persist_call_seat_load`. The transport tests that answer as an
  old peer (`answer_off_like_an_old_peer_for_test`, `set_old_peer_for_test`) ran in the lib groups,
  not in that leg.
- **Against the released v45.0.2** (tools/scenarios/cohab_reticulum_two_node.py, two processes on
  loopback, 5 runs): node A the v45.0.2 release wheel (sha256 cc1b9e89…61ef7, checked against the
  release's SHA256SUMS) on persist 61.2.3, node B this release on the persist 61.4.0 tag-CI wheel;
  the control ran both nodes on this release (5 runs). Both nodes started in every run. B rooted A
  and opened outbound links in 5 of 5; A reported in 3 runs and rooted B and opened outbound links
  in 2 of them (in the third it rooted nothing and opened no link). No link sealed in either set
  (above), so no frame crossed and no replication round ran: the scenario cannot drive replication
  between fresh nodes, and no rows were applied, duplicated or refused. The v45.0.2 node failed in
  every mixed run: its persist reader stalled (exit 3) in 2, and in the other 3 its edge answered
  nothing during the quiet minute while B's route requests to it timed out
  (`link_seal_refused_route_timeout`, 6–8 in each of those 3 runs, the one refusal class B showed
  that the control did not). With both nodes on v45.0.2 (5 runs) a node stalled or hung in 5 of 5.
  No node of this release failed in any run. That is v45.0.2's own two-wheel hang (CIRISEdge#988),
  not an interaction between the versions; single-binary hosts (ciris-server) are not exposed to
  it.

### Deliberately out (designs kept for after the v62 refactor)

The held-inert store (rows refused for a missing key or binding), the shared first-contact history
page, the key-plane memo rebuild fix, the push filter (F3), and the narrowed first-contact read
(needs CIRISPersist#1270 `by_types`).

### Not run locally

- `libcrux_cross_version_822` (0 run, 4 ignored): a cross-build witness for CIRISEdge#822 whose
  four stages need fixtures from a build against the OTHER lock. It runs only when the file is built
  twice (pre-#822 lock and fork) and the stages run `--ignored` in order over one `CIRIS_822_DIR`.
  Nothing here touches openmls or libcrux.
- The Android PyO3 variant (needs CI's libpython stub link) and iOS (no Apple toolchain); CI
  builds both at the tag.

### Also

- deny ignores three more hickory DNSSEC-validation advisories (RUSTSEC-2026-0530/0531/0532), on
  the same grounds as v45.0.2's.
- A guard (`tools/gen_kept_directory.py --check`, `--check-doubles`, run by
  `tests/kept_directory_current.rs`) fails a persist bump that adds a trait method the kept
  directory or a test double does not delegate.

## 45.0.2 — 2026-11-12

**PATCH.** Pins: persist **v61.2.3** (9873c0f4), CIRISVerify v22.2.0, leviculum v0.34.0+ciris.3.
v45.0.0 and v45.0.1 are tagged and have no release assets; this is the first v45 that does.

### Consumer notes

- **BREAKING for Python hosts: the persist requirement is `ciris-persist==61.2.3`.** Capsules are
  named for the persist build (`ciris_persist::<capsule>@61.2.3`); a 61.2.2 wheel is refused at
  `init_edge_runtime` with `capsule_version_skew`.
- **macOS opens a file-backed store with the reader pool on again (CIRISPersist#1261).** Persist
  found the cause: Apple's system SQLite will not let a read-only connection create the
  `-wal`/`-shm` files, and since CIRISPersist#1246 a reader's first access happens inside the
  pool's open. 61.2.3 fixes it. v45.0.1's zero-reader default is removed on macOS. It stays on
  iOS, where nobody has opened a file-backed 61.2.3 store; `CIRIS_PERSIST_SQLITE_READERS` still
  overrides it.

### Why v45.0.1 has no assets

Its macOS test lane hit the step's 30 minute limit three times. The step built and tested inside
one budget; at v45 the tests alone take about 43 minutes on that runner. The build now has its own
step and the test step has 75 minutes. No test deadline changed.

## 45.0.1 — 2026-11-11

**PATCH.** Pins unchanged (persist v61.2.2, CIRISVerify v22.2.0, leviculum v0.34.0+ciris.3). v45.0.0
is tagged (a54c6a2) but has no release: its macOS lane failed, and the release job needs it. A host
that consumes edge by tag may stay on v45.0.0 if it applies the same default itself (CIRISServer
does); this version is the first v45 with release assets.

### Consumer notes

- **On macOS and iOS a file-backed store opens with no reader pool unless the operator set
  `CIRIS_PERSIST_SQLITE_READERS` (CIRISPersist#1261).** At persist 61.2.2 a file-backed
  `SqliteBackend::open` fails on macOS with `sqlite open readers: unable to open database file`.
  On a macos-15 runner `CIRIS_PERSIST_SQLITE_READERS=0` clears it; the memory-map knob, the temp
  directory and the open-file limit do not; persist 61.0.5 opened the same stores. The cause is
  not established. `EdgeBuilder::from_keyring_seed_dir` (the one place edge opens its own store)
  now goes through `store_open::open_federation_sqlite`: on an Apple target with the env var
  unset it opens with zero readers, so reads use the writer connection, the model persist ran
  before the pool. The cost is concurrency only. One WARN at open names the env var. An
  operator's value wins; every other platform, and every in-memory store, is unchanged. A host
  that opens the store itself and hands edge a capsule must apply the same default itself. iOS
  is presumed affected and has not been tested. To be removed when the persist pin carries the
  fix.

## 45.0.0 — 2026-11-10

**MAJOR.** Pins: persist v61.2.2 (712575df; CIRISPersist#1246 SQLite mmap and cache_size), CIRISVerify
v22.2.0 (rusqlite 0.41.1 / libsqlite3-sys 0.39.1, RUSTSEC-2026-0459 cleared), leviculum
v0.34.0+ciris.3 (#102 A/V media on unordered datagrams, #104 probed MTU, a Channel send's sequence
and its delivery proof). MSRV 1.92; toolchain 1.97.0.

### Consumer notes

- **Room calls carry video (the call series; AV_ALM_DESIGN).**
  - Frames larger than one chunk (keyframes, P-frames) are split before sealing and reassembled
    whole by receivers: at most 4096 fragments and 1 MiB per frame, reassembled per (stream,
    layer); a partial frame is never handed out. `Call::publish` no longer refuses ordinary video
    frames; a frame over 1 MiB, or over the budget on an unframed stream, still raises
    `frame_too_large`.
  - A host declares its codecs at join (`codecs=["h264","opus"]`); the registered tokens are `av1`,
    `h264` and `opus`.
  - Screen sharing is a second stream: `add_stream(codecs)` returns its `stream_id`,
    `publish_on(stream_id, ...)` sends on it and `end_stream(stream_id)` ends it (signing end = 3,
    never a leave). A sharing phone can background its camera with
    `end_stream(stream_id(), "backgrounded")`. At most 3 own streams at once.
  - **BREAKING for hosts that map call events by kind:** new `stream_added` (`stream_kind` 0 media,
    1 share), `stream_ended` (cause `ended` / `left` / `backgrounded`) and `stream_replaced`;
    `attendee_left` now fires only on a member's last stream with a leave, or on lost / removed.
  - New on `Call`: `leave(cause=)`, `replace_stream(codecs=)`, `leg_info()` (path, MDU and frame
    budget per leg); `request_layers(stream, (s, t, q))` exists behind a lever that is off by
    default.
  - The ALM relay controller measures its uplink from delivered bytes (AV_ALM_DESIGN §5.1) and
    raises a learned ceiling by one stream per clean window, so relay-on rooms no longer
    over-commit at media start.
  - Wire: every stream signs a v2 key binding (codec map, kind, framing, replaces, end 0-3,
    final_seq); v1 is still sent for older peers. A v44 publisher's video reached only through a
    relay is held, then dropped, at v45 receivers (counted `av_frame_framing_unknown`); its audio
    plays.
- **A keyframe burst no longer overruns a busy receiver.** leviculum's data-plane event channel
  defaulted to 128 events and sheds an arriving link datagram while 96 are queued unread; a 30 KB
  keyframe is 127 datagrams sent back to back, so a receiver whose event loop was busy for a few
  milliseconds lost the burst's tail (`av_datagram_shed_sink`) and, with no repair in v45, the
  whole keyframe. Edge now runs the channel at 1024 (`DATA_CHANNEL_CAPACITY`), 768 slots before a
  datagram is shed. Env `CIRIS_EDGE_RETICULUM_DATA_CHANNEL_CAPACITY` overrides it, clamped like the
  control channel's; the value is logged at start. Witness
  `a_keyframe_reaches_a_loaded_receiver_whole` (the receiver's loop slowed to 2 ms per datagram):
  at 128 it sheds 32 and loses the keyframe, at 1024 nothing is shed. A receiver slower than that
  for longer still sheds; publisher pacing and resend are 45.1.
- **leviculum v0.34.0+ciris.3:** `LinkHandle::try_send_seq` (and `NodeCore::send_on_link_seq`)
  returns the Channel sequence a message went out under, and the new `LinkSeqStats` (via
  `ReticulumNode::link_seq_stats`: `last_sent_sequence`, `oldest_unacked_sequence`,
  `delivered_through(seq)`) proves that message and everything before it were delivered; edge uses
  it for the leave / replace / end_stream bindings. `LinkStats` is unchanged, there is no wire
  change, and the `send_on_link` error mapping is unchanged.
- **BREAKING: the Python persist requirement is exact, `ciris-persist==61.2.2`.** Every raw-layout
  capsule is named for the persist build that laid it out (`ciris_persist::<capsule>@61.2.2`,
  CIRISPersist#1242), and edge asks for the name its own build compiled
  (`capsule_names::checked_pointer`), so any other wheel is refused at `init_edge_runtime` with a
  `TypeError` led by `capsule_version_skew`. A server pins the same version.
- **BREAKING: hybrid-required is the only verifier policy (CIRISEdge#957, CIRISPersist#1233, CC
  5.3.2.4.3.1).** `init_edge_runtime(hybrid_policy=...)` accepts `"strict"` only; anything else
  raises `ValueError("verify_policy_violation: ...")`. `EdgeBuilder::build` and
  `ReticulumTransport::new` refuse a non-`Strict` policy. New `VerifyError::PolicyViolation`, metric
  class `verify_policy_violation`.
- **BREAKING: `membership::WidenOutcome` gains `NeedsCosign`.** A widening one voice short of the
  room's protocol (persist's `roster_consensus_insufficient`) is
  `Ok(WidenOutcome::NeedsCosign { scope, group_key_id, member_key_id, role, proposal_id })`, no
  longer an `Err`. An exhaustive match adds the arm. The have/need counts wait on persist
  (CIRISPersist#1250).
- **`Edge::arm_room_groups` (CIRISEdge#970).** An Edge built with no room groups (every
  `init_edge_runtime` host) takes them once on the running Edge; a second arm, or an arm on an Edge
  the builder gave groups, is refused with `EdgeError::Config`. Calls on agent-hosted nodes were
  refused `Plumbing("join_call needs the room groups ...")` before.
- **A late joiner is offered its groups' history (CIRISEdge#968).** Gauges
  `group_backfill_rows_read_total`, `group_backfill_rows_kept_total`,
  `group_backfill_completed_total`; one page a round per peer under the `page` lever.
- **The outbound queue rides `outbound_queue_ops_capsule` (CIRISEdge#960),** and every handle copied
  out of a capsule holds that capsule for as long as it is used.
- **`set_av_datagrams_enabled(bool)` (leviculum#102):** node-wide, default on; gauge
  `av_datagrams_enabled`.
- **A host that writes to the store behind edge must follow the write with a kick
  (`round_now`/`round_now_all`) or `note_local_write(s)`, or its rows reach peers up to 5 s later;
  use `note_local_write(s)` where decision-row events matter (CIRISEdge#971).** Such a write is
  listed on the key planes only once the serve-cursor feed's last probe is `FEED_PROBE_SPACING`
  (5 s) old; before v45 it was on the next listing. For a withdrawal or a revocation that is up to
  5 s more before a peer is offered it. 5 s is the worst case, a TTL revalidation included. A kick
  or `note_local_write(s)` marks the feed dirty (`invalidate_send_set_memos`), so the next listing
  carries the row as before.

- **The receive diff no longer drains persist's content-hash index per Summary (CIRISEdge#971).**
  The Attestation index (six session planes: Attestation, KeyGrant, Key, Revocation,
  IdentityOccurrence, IdentityOccurrenceRevocation) and the TransportDestination index are kept as
  in-memory sets equal to `signed_wire_index`: seeded by one boot drain, fed by a write-through on
  every admitted apply and by persist's serve cursors (`list_attestations_since`, shared with the
  CIRISEdge#930 key-plane memos, and `list_signed_transport_destinations_since`), and reconciled to
  a full drain every 60 s. Before the boot drain completes, while a cursor probe fails, or after an
  audit finds more drift than max(16, size/1000), a plane answers from the drain as before.
  `ReplicationDirectory::holdings_want` and `StateProvider::local_want` are new defaulted trait
  methods; an implementor that does not override them gets the old diff over `list_holdings`.
  - **Lever:** `BridgeConfig::holdings_index` (default `true`), env `CIRIS_EDGE_HOLDINGS_INDEX=0`
    (or `off`, `false`) to turn it off. Audit cadence `BridgeConfig::holdings_audit_every`, env
    `CIRIS_EDGE_HOLDINGS_AUDIT_SECS`.
  - **Gauges:** `holdings_index.<plane>.{answers_set, answers_drain, fallback_unbooted,
    fallback_suspect, boots, audits, drain_failures, drain_ms, drift_missing, drift_extra,
    suspect_audits, write_through, feed_inserts, duplicate_unheld, feed_probes, feed_coalesced,
    feed_failures}` and `holdings_index_gauge.<plane>.{size, status, source, last_drain_ms}` plus
    `holdings_index_gauge.enabled`, with `<plane>` one of `attestation`, `transport_destination`.
  - **Key-plane ledger:** `key_plane_sweep.key_plane_probe_reads` now counts the shared cursor
    probe, which a holdings ask also runs, and the memos no longer each keep a cursor.
  - **An idle round reads nothing.** Sequential asks of a cursor are spaced: a clean feed probed
    less than 5 s ago (`BridgeConfig::feed_probe_spacing`, `Duration::ZERO` restores a probe per
    ask) is not probed again unless a door edge sees marked it dirty: an admitted apply, a host
    kick, `note_local_write(s)` or a released signer. A host write that reaches none of those is
    seen within the spacing (a `Duplicate`, or a key-plane offer one round late). Counted under
    `key_plane_sweep.{key_plane_probes_spaced, key_plane_feed_dirty_marks}`. This changes the
    CIRISEdge#930 guarantee: a store write that bypasses every edge door is in the next listing
    only once the spacing has passed.
  - **The index warms in the background.** `ReplicationRuntime::start` spawns the warm-up: it
    places both serve cursors, walks each plane's served log from its head on its own cursor
    (on the canonical about 86 Attestation pages and 37 route pages of 500 rows), then runs the
    boot drain. Until a plane is Ready its asks take the pre-v45 drain; no round waits on the
    walk. New: `holdings_index.<plane>.{warm_rows, warm_failures}`,
    `holdings_index_gauge.<plane>.ready_after_ms`, `sweep_permits.holdings_warm`.
- **Where the seat's sweep permits and send-set reads go (CIRISEdge#971).** New family
  `sweep_permits.<site>` (`holdings_index`, `holdings_rows`, `plane_page`, `accord_evidence`,
  `subject_pull`, `announced_testimony`, `key_plane_subject`, `feed_attestation`, `feed_route`,
  `send_set`, `advertise_page`, `advertise_required`, `other`) splits
  `sweep_permit_wait_seconds.count` by the call site that took the permit. `advertise` gains
  `advertise_send_set_dropped_live` (a door dropped a consent memo still inside its 10 s TTL) and
  `advertise_send_set_expired` (a round found it past the TTL). `key_plane_sweep` gains the memo
  rebuild causes `key_plane_rebuilds_first`, `key_plane_rebuilds_ttl`, `key_plane_forgotten`,
  plus `key_plane_inbox_overflows` and `key_plane_plane_dirt`.
- **A route older than the one held is fetched once per terminal window, not every round
  (CIRISEdge#971).** The stale arm of the route apply still reports `Duplicate`, and now also marks
  the bytes in a memory of their own (4,096 marks, front-drop, terminal schedule 30 min doubling to
  6 h), which `remember_outcome` does not clear. The round's `want` drops a marked hash; a newer
  route is a new hash and is wanted as before. On the canonical, 10,710 of 24,949 routes served in
  one process lifetime were these.
  Counted on their own, not in `retry_suppressions`: `holdings_index.stale_route.{marked,
  suppressed, evicted, cleared}` and the gauge `holdings_index_gauge.stale_route.size`. Every mark
  is dropped when an audit finds a route hash gone from the index (`cleared`); no persist door
  removes a route's index entry today, so this is a backstop.
- **Behaviour change: a row refused by several gates is booked under the first one
  (CIRISEdge#971).** The Attestation advertise now asks the audience gate's reach half (from
  memory) before the gates that read the store: author quarantine, the accord relay, the serve
  capability and the producer's recipient capability. The offered set is unchanged (a row the
  reach refuses was refused at the audience gate anyway). What moves: a row both a reach and an
  earlier gate refuse is booked `recipient_not_in_send_set` where it used to be booked
  `quarantined_author`, `serve_capability_missing`, `serve_capability_not_rooted` or a relay
  reason, and the quarantine WARN is no longer emitted for rows the reach refuses. All of these sit
  in one Policy class for CIRISServer's operator surface. For a first-contact peer the advertise
  now reads no consent grant and no quarantine marker for refused rows, and the peer's owner
  (`owner_of`) is read once per round instead of once per consent-grant row.
- **A first-contact peer's own rows are read only in the shapes its reach can carry
  (CIRISEdge#971).** The required read used to take a page of every row the peer authored; for a
  first-contact peer it now takes only its consent grants, group-plane rows and membership ceremony
  rows, the only peer-authored shapes that reach admits. The offer is unchanged; the refused rows
  are no longer read.
- **Every edge store read names its caller (CIRISEdge#971, CIRISPersist#1235).** 26 call sites run
  under a persist caller scope (`edge.advertise.{required, groups, history, unasked, gate}`,
  `edge.gate.{quarantine, capability, owner_of_peer}`, `edge.fetch.gate`, `edge.pull.serveable`,
  `edge.subject_pull`, `edge.key_plane`, `edge.feed`, `edge.identity_plane`, `edge.holdings`,
  `edge.send_set`, `edge.owner_binding`, `edge.apply`, `edge.transport.attribution`,
  `edge.first_contact`, `edge.membership`, `edge.chat`, `edge.av_call`, `edge.blob.durability`,
  and for the bundle-seat reads #971 adds, `edge.bundle.seats` (the serve nodes' key-record check)
  and `edge.transport.carriable` (the round-start transit-pair read)), so persist's
  `observe::snapshot().callers` splits the read rate by site. The innermost scope wins. A label
  counts only where persist books the door: today persist counts the attestation-row doors and
  not `lookup_public_key`, so `edge.bundle.seats` does not appear in `snapshot().callers` yet
  (asked on CIRISPersist#1249), and whether the transit-pair read behind
  `edge.transport.carriable` passes a counted door is untraced. A read outside every scope books
  as persist's `unattributed`. These are 26 of persist's 32 caller labels; a host that adds more
  than 6 of its own sees the rest under `other`.
- **Naming a shaping class is no longer the shaping opt-in (CIRISEdge#969, CC 5.4.3).**
  `init_edge_runtime(shaping_class="home" | "phone-wifi" | "phone-cellular")` used to shape every
  identity link while seeding the device with no opt-in, so the policy and the device disagreed.
  The class now names the device and the policy is its fleet default: layer links only, unless the
  new kwargs `shaping_opt_in` (`home`, `phone-wifi`) or `shaping_opt_in_cellular`
  (`phone-cellular`) are `True`. `"server"` is unchanged (every identity link). No current PyO3
  host passes these classes; one that relied on the class alone must add `shaping_opt_in=True`.
- **`shaping_set_device_state` keeps an opt-in the call leaves out (CIRISEdge#969).** Its
  `shaping_opt_in` / `shaping_opt_in_cellular` now default to `None` (keep the current choice);
  pass `True` or `False` to change one. A call that moved only the class or the network used to
  clear the person's opt-in. The UniFFI record states both opt-ins explicitly and is unchanged.

- **Behaviour change: the bundle's serve nodes are bootstrap peers by
  default** (CIRISEdge#971, #881; Eric's ruling). From v43.2.0 to v44.1.2
  `ReplicationRuntimeConfig::enable_bundle_bootstrap_peers` was opt-in and no
  host set it, so an unclaimed device that consent named to no seat rounded
  with nobody, and the seat held it Advisory and pairless for good. It is
  replaced by `disable_bundle_bootstrap_peers` (opt-out). Every v45 node that
  takes the default asks each baked serve node its directory holds for the
  required set by subject Pull (bundle-seat mode, below). Once that seat holds
  the node's key and route, the node also keeps an ordinary Revocation round
  with it. A serve node joins only if this node's own
  directory holds its key record. Only persist's Engine boot seed writes those
  records, and it skips them under a test trust root, so tests, harnesses and
  scratch directories add none. A record that lands after start joins at the
  next `set_peers` (latched: zero reads once held). The pyo3
  `start_replication(bundle_bootstrap_peers=…)` kwarg keeps its name and now
  defaults to `True`. A host opts out with `disable_bundle_bootstrap_peers:
  true`. A node that opens no replication round to anyone says so at start,
  naming each skipped serve node and why (WARN, `tracked: CIRISEdge#971`).
- **Bundle-seat mode: the required set by subject Pull, never a whole-plane
  diff** (CIRISEdge#971, CC 5.2). Toward a bundle seat the host does not name
  as a consent peer, a device runs no Summary round on Key,
  IdentityOccurrence, TransportDestination or IdentityOccurrenceRevocation.
  Instead it asks by subject Pull, at most every 30 s:
  - At first contact, at once, then every 15 to 45 s (30 s, jittered per
    device), up to six times, until the seat holds its key and route: about
    itself (offering only the rows of its own the seat's answer lacks) and
    about the seat. If six tries pass without that, the timer below takes
    over, counted as `first_contact_gave_up`, with one WARN per process.
  - On a timer drawn per device from 5 to 15 min (`BUNDLE_PULL_INTERVAL`
    10 min, jittered): the same, plus about its owner once claimed, on Key,
    IdentityOccurrence and IdentityOccurrenceRevocation. The owner Pull is
    the only lookup the seat charges.
  - On a host kick (`round_now`, `round_now_all`): about itself and the
    seat.
  - On a local write of its own on one of those four planes: about itself,
    on that plane only.

  The seat never builds its whole offer for the device (about 2,690
  announced keys on canonical-1; about 0.7 GB/day per phone on Key alone as
  a 30 s diff). The IdentityOccurrenceRevocation legs and the Revocation
  round wait until the seat holds the device's key and route: before that,
  the seat drops frames of those kinds from a sender it cannot attribute.
  Key-level Revocation then keeps an ordinary round, a small
  `Projection::Global` offer. A v44 seat serves all of it: the self and seat
  subjects are uncharged, and the device's own rows ride an unsolicited
  Deliver (a v44 seat admits one on IdentityOccurrenceRevocation with a
  WARN). An owned node's route is not asked of a seat (CC
  CLM-route-handed-by-owner, CIRISEdge#972). The Pull coordinators are never
  scheduled, so `set_peers` does not remove them.
- **Behaviour change for a host that opted in on v43.2.0 to v44.1.2**
  (`enable_bundle_bootstrap_peers: true`). Such a host got five-plane
  Summary rounds every 30 s toward each bundle seat. It now gets the subject
  Pulls above and one Revocation round, which starts only after the seat holds
  its key and route. A host that counted those rounds' outcomes per plane
  now sees one plane per seat.
  `round_now` toward a bundle seat it does not name also runs that seat's
  self and seat Pulls.
- **No automated path names a third party to a seat the node has no consent
  relationship with** (CIRISEdge#971, CC 5.4.6). Signer recovery toward a
  bundle seat the host does not name asks only for a signer of a row that
  seat delivered, or for the seat's own key. A key a person is waiting on
  (#904) and an unrouted repair name stay queued for a consent peer. The
  rule is read at the moment of asking, so it follows the host's peer set
  (`names_only_required_subjects`).
- **Behaviour change: a node with no owner-binding here that is another
  identity's occurrence is no longer listed to strangers** (CIRISEdge#971,
  CC 5.4.6 "never listed"). Until now the #682 reach gate read "no owner
  held" as "its own trust subject" and served the node's
  `IdentityOccurrence` and `TransportDestination` rows to every peer. That
  also covered a person's device whose owner-binding was released, had
  lapsed, or had never reached the holder. Now:
  - No other identity holds the key as its occurrence (a canonical, a bare
    server): every peer, as before.
  - The key is not node-type (a split-home agent key, a user key): every
    peer, as before.
  - A node held as the occurrence of an identity `X`: only the node itself,
    `X`, `nodes_owned_by(X)` and `X`'s active occurrences. Anyone else is
    booked the new withhold token `identity_row_occurrence_unowned`. A read
    error fails closed to the node itself (`identity_row_announce_unresolved`).

  The rule holds on the advertise, the direct-fetch twin and the subject
  Pull. `Key` rows are not gated. At canonical-1 (2026-11-10) 384 node keys
  match, all `ciris-node-bootstrap-*` under test-alias owners; no real home
  is among them. Cost: one occurrence read per unowned subject per 30 s
  memo, and one key-record read when the subject is another identity's
  occurrence.

  Two departures from the letter of CC 5.4.6, recorded in the code
  (`bridge.rs::unowned_reach`): the active-occurrence clause (the text names
  a live owner-binding; an occurrence the identity signed is served so a
  device whose binding has not arrived still reaches its own person), and
  agent-type keys stay open (CIRISEdge#897: closing them cuts the content
  keys a roster wraps per occurrence).
- **The public `InboundRouter` re-asks a peer whose reply it dropped
  unattributed** (CIRISEdge#971, #968). `InboundRouter::try_route` now makes
  the same `note_unattributed_drop` / `note_attributed` pair as the Edge's
  own router, so a host that routes frames itself gets the round again as
  soon as the peer attributes. The first round still runs to its 15 s
  timeout (CIRISEdge#977).
- **Replication sends to a peer no rule can reach are refused before any path
  seek** (CIRISEdge#971). With no live link, no path and no authenticated
  transit pair, CC 5.3.3.5 E1 forbids the dial, so the 3 s seek and its path
  request broadcast could only end "never dialled". The send is refused at
  once, and the round toward that peer is not started, before its advertise
  sweep. Both are booked `no_route` as before; only the duration drops. One
  count differs, on a peer's FIRST rounds only: the first refusal is now
  instant, so it puts the peer into its shared no-route backoff (#794) before
  every plane's first tick has run. A plane whose first tick lands after it
  is skipped and books no outcome, as every later tick toward an unroutable
  peer already was. Steady-state counts are unchanged.
- **New gauges.** `replication_reach{carried_on_inbound_link, dialled,
  skipped_undialable, round_skipped_undialable, path_seek_found,
  path_seek_not_found, path_request_sent}`,
  `initiator_peers{host, bundle, homed}`, and
  `bundle_pull{cycle_first_contact, cycle_timer, cycle_kick, cycle_write,
  first_contact_gave_up,
  pull_self, pull_seat, pull_owner, held_back, answer_self, answer_seat,
  answer_owner, answer_other, answer_throttled}`. The answer counters cover
  no-consent seats only. A non-zero `answer_other` means the host itself is
  looking people up at a seat (`pull_subject_testimony`); bundle-seat mode
  never does.

## 44.1.2 — 2026-11-09

**`FountainHoldingClaim` is no longer a wire kind** (CIRISEdge#959, CC wire vocabulary v1.0.3, rc17
a08db38). Holding on the chunk plane is a sealed-chunk custody fact carried as rows and
acknowledgements (CC 5.3.3.2.4, CC 6.1.5.1). Nothing in production emitted the kind: no edge host
installs the swarm runtime, and server's shipped wheel never did.
- **Hash:** `WIRE_VOCABULARY_HASH` = `e0ffb58b0f15938c186f6a4eaa0fbf7393a8a10b9d18378e56b658c25f85a2b6`.
- **Rejected at decode:** `MessageType::FountainHoldingClaim` is `#[serde(skip_deserializing)]`, so
  an envelope naming it fails the typed decode (verify step 2) as an unknown kind, before replay,
  signature or dispatch. That is the vocabulary's "a decoder MUST reject it".
- **Dropped by name:** the refusal is `VerifyError::SchemaInvalid` led by the token
  `retired_wire_kind` (`verify::RETIRED_WIRE_KIND_REASON`), a throttled warn
  `edge.verify.retired_wire_kind_dropped`, and the counter `verify::retired_wire_kind_drops()`. It
  still counts under `verify_failures_total{schema_invalid}`. `messages::RETIRED_WIRE_KINDS` and
  `messages::retired_wire_kind` name it.
- **No fold:** the dispatch arm that fed verified claims into the converged view and an installed
  swarm runtime (CIRISEdge#184/#545/#763) is gone. `Edge::swarm_convergence` and
  `converged_claim_view` stay; an armed view now reads converged-to-nothing.
- **Rust types stay on 44.x:** the variant still serializes, and `FountainHoldingClaim`,
  `HOLDING_CLAIM_DOMAIN`, `FountainSwarmRuntime` and the `codec-fountain` feature are unchanged, so
  server's in-process benchmark builds as before. They are removed on the next line that may break,
  once server 0.5.246 is off them.
- **Tests:** `tests/retired_wire_kind_959.rs` drives a hybrid-signed claim from a directoried peer
  through the receive path (`a_received_fountain_holding_claim_is_dropped_by_name_959`, and its twin
  with a runtime installed). Restoring the fold fails both. `swarm_converger_e2e`'s discriminator
  test now witnesses the rejection; its envelope round trip and
  `https_round_trip_fountain_holding_claim` are retired, since they witnessed only the retired kind.
- **Evidence:** a supporting `CLM-policy-versioning` (CC 2.6.4) row, `src/verify.rs#VerifyPipeline::verify`.

**The Python persist requirement is `ciris-persist>=61.0.5,<61.1`** (was `<62`). Edge 44.1.x is built
against persist 61.0.5, and some capsules (`BackendDispatch`, `TrustScoring`, the local signer) read
persist's Rust layout directly with no ABI check. Persist 61.1.0 adds trait methods, so a pip pairing
with it could misdispatch. The Rust pin is unchanged.

## 44.1.1 — 2026-11-09

**The shaped frame is 1,400 bytes** (CIRISEdge#963, CC 5.4.3 rc17 a3dd97a). Every shaped link's
frame is 1,400 B before the E1 seal, header included, or the channel payload MDU where that is
smaller (`SHAPED_FRAME_BYTES`, `shaped_frame`). It is one constant: not per class, not negotiated.
A 44.x peer offering 16,272 agrees at 1,400 because `agree` takes the smaller. The byte rate is
unchanged, so λ rises about 11×. The mean frame gap is 0.2 s at `server`, 0.5 s at `home`, 1.0 s
at `phone-wifi` and 4 s at `phone-cellular`, against 2.3 / 5.8 / 11.6 / 47 s before.
- **Contact time:** first contact relayed through a canonical (seven exchanges, server class)
  moves from p50 65.6 s to 5.5 s.
- **ρ:** the real share holds better. At equal load it falls from 0.20 to 0.11, and the worst
  budget window goes from 0.54–0.67 to 0.50–0.53.
- **Stated costs:** these now include the transport's per-packet header and proof. That is about
  15% at this frame, so `server` is 20.9 GB a month per link each way.
- **Row wait:** sized in bytes. A 64 KiB row may take up to the p99 of its 48 frames, so it now
  converges on `phone-cellular`.
- **Queue cap:** one window's real budget in bytes.
- **Round waits:** cover a reply's frames, and are never shorter than 44.1.0's.
- **Onion packets:** a packet crosses as 12 fragments and arrives intact
  (`an_onion_packet_crosses_a_1400_byte_shaped_link_in_fragments_and_arrives_intact`).

**Contact rows leave first** (CIRISEdge#962). A shaped link's queue has two lanes, and the next
real frame takes contact first.
- **Contact:** key and identity rows, routes, revocations, consent grants, owner bindings, and
  every withdrawal or recant.
- **Sync:** everything else.
- **No starvation:** while both lanes hold rows, at least one real frame in four carries sync
  (`CONTACT_RUN_MAX`).
- **Wire:** unchanged.

**A code's PQC commitment binds the key record a dial fetches** (CIRISEdge#964, CC 5.3.3.5
item 6). `contact::resolve_contact_with_commitment` and `contact::discover_with_commitment`
take an optional commitment: 64 lowercase hex, sha256 of the raw ML-DSA-65 key (CC 2.6.8). A v3
code's own commitment is held as well, and the latest well-formed commitment for a key wins.
- **Mismatch:** a route-fetched or held key record whose ML-DSA-65 key misses the commitment is
  refused by name (`link_seal_refused_route_answer_pqc_commitment`,
  `self_signed_row_pqc_commitment_mismatch`). The check is CIRISVerify's
  `fedcode::verify_pulled_ml_dsa_65_pubkey`.
- **No commitment:** behaviour is unchanged. The fail-closed half is the v62 handshake's.

**A direct-link proposal that arrives before its room is held for it.** On every OS, a peer that
proposed a direct link a moment before the other side's call installed its group was refused by
policy. It then waited out leviculum's 60 s proposal cooldown with no direct leg. The request from
a known room peer is now held for up to 4 s while the call comes up (`direct_link_request_held`).

RUSTSEC-2026-0459 (CVE-2026-119375; bundled SQLite before 3.54.0, a crafted `-wal` beside a database
file can return uninitialized page-cache memory) is ignored in `deny.toml` with its justification.
It is local only, and edge opens only the node's own store. The fix, `rusqlite` 0.41, is pinned
through persist, verify and refinery (tracked: CIRISEdge#966).

Test instruments on macOS:
- the establish-budget witness uses a spent budget, not a 1 ms race;
- the suspend suite reads the kernel's TCP table there and fails loudly when it cannot (it had
  read `/proc`, which macOS lacks);
- a fresh A/V leg's first frames wait out backpressure.

## 44.1.0 — 2026-11-08

The onion relay's replay set is a bounded hold (CIRISEdge#955, CC 5.3.3.5 E1 rule 9). It holds at
most `REPLAY_BOUND` = 62,134 tags a period: the `seat` rate on the node cap's eight shaped links,
264,000 B/s, over the 3,600 s period, divided by the 15,296-byte packet. With the last period's tags
that is under 8.3 MiB. Past the bound a new packet is refused as `onion_replay_set_full`, counted
like the other onion refusals; no held tag is evicted, and a replay of a held tag is still
`onion_replay`. The bound is fixed, not a lever. A source witness pins that an onion frame reaches
`accept_inbound` only on a link that keyed behind `ReceiverOrder::admit`, and `accept_inbound`'s
`link_shaped` is documented as the transport's own shaping state.

A node that turned on the Anonymous Tier no longer offers relay (CC 5.4.6 rc17,
`CLM-referred-peer-is-proxy`): `relay_offering` is false while `OnionPolicy::enabled` holds, so it
reports no free shaped slots and is never referred as a proxy. It still relays onion packets.

The process loads one tokio and one sqlite: on a PyO3 host, edge's calls run inside a runtime edge
owns, so edge's copy of persist code never reaches a runtime persist's .so built (a linux + postgres
SIGSEGV), and a source-built edge on Linux binds persist's bundled sqlite (CIRISEdge#50).

The weekly bench mesh's A/V legs ride direct links, as production's do: the harness configures direct
links with the relay as facilitator, cuts the stream to the leg's budget, paces it, and dials a late
joiner beside the stream. No leg's assertion changed.

The threat model and README are regenerated for the 44.x line (CIRISEdge#956).

A call in a room whose MLS leaves are persons is joined through their nodes. The server mints room
keys as the owner, so no node was a leaf and `join_call` refused every node as `NotARoomMember`. A
call's members are now the room's leaves with each person replaced by the nodes it owns, by
persist's owner binding (`nodes_owned_by`/`owner_of`, `CallDeps::owners`); the join, inbound links,
stream key bindings, ALM and the roll all read that set. A node whose owner is not a leaf, or that
acts for an attendee it is not bound to, is refused; removing a person ends their nodes' part at the
next epoch. Rooms whose leaves are nodes work as before.

A call's addresses no longer equal its room's. They were derived from the room's own destination
secret for the same members at the same epoch, so a node that had installed the room's addresses
refused the call as `address collision … reused exporter_secret?`. A call now derives them from
`call_destination_secret` (HKDF over the room's destination secret with `ciris-edge:call-destination:v1`
and the call's group id). Every member of a call must run this release: a call address changed.


What moves to a peer (CC 5.2): a row moves when it is requested, or required, and appropriate, never
because it is federation-tier. Two serve seats keep the commons walk; every other peer starts with
what is required, and of the walk is offered only what is required or appropriate and live. The rest
waits on the peer's pull. `SERVE_ADVERTISE_POLICY_HASH` is 14aedf25…; `advertise_awaits_request` is
new.

Adopts leviculum 0.34.0+ciris.1. The Resource window is `ByMedium`, radio included. Direct-link
`Glare`, `InterfaceLost`, `HeldTooLong` and `PeerFellBack` have retries and labels, and a frame over
the Channel limit is named, not a dead link. The load tier leaves forwarding alone and the host gets
leased shed levers. Every node can shape on a direct link, a shaped link is one direct hop, eight
shaped links do not stop new connections, and a failed bulk dial refuses by name.

A peer that is neither a seat nor its owner's no longer walks the plane: it reads new rows from the
tip, and history at one full page a minute. This node's own invitations and their answers are required
reads. `chat::pair_proposal_for` reads the room's index; `membership::pending_proposal_in` is new.
A third party's invitation relayed here, of any age, is in the invitee's first offer: the required
read takes the `membership:proposal:v1` rows naming each of the peer's principals by persist's
subject read (`list_attestations_naming_by_dimension`, persist 61.0.5 #1225, pinned by rev
3a9456bf until the tag), newest first from the head each round, at most 256 rows a round, and every
row still crosses the serve gate. Before, it waited on the history page, up to 52 minutes on 52k rows.

**Server must:** mirror the policy hash; take the `no_route` outcome and `RoundEvent::NoRoute`; set
`ReplicationRuntimeConfig::recognised_seats` from `Edge::recognised_seats()` on a Rust host; build its
shaping policy with `ShapingPolicy::for_device`; pull the leased levers (`pull_shed_lever`).

Every step of a late subject Pull gets the late window, so a Deliver behind a late Summary is kept.
The retired-plane line logs at debug at the hot-add door. Test fixes and the 44.0.0 notes date.
`anti-entropy round ended` carries `outcome` and `error`; a failing round says why at INFO, once per
(peer, kind) in five minutes.
`replication_round_outcomes_total` gains `no_route`. A new peer's first Attestation round waits for
the peer to confirm the bootstrap planes, at most five seconds, so a contact no longer loses a round
timeout to attribution.
A round lost after listing puts the watermark back, at most three times running, so its rows are in
the next round and not the re-sweep.
On a PyO3 host a blob serve no longer holds the inbound loop: replication is routed in place, other
frames run on their own task, and two chunk serves run at once.

## 44.0.0 — 2026-11-06

Long-term support line. Pins persist 61.0.4, verify 22.0.0, leviculum 0.33.0+ciris.1. Coordinated
cut: a v43.x peer cannot interoperate.

- **Changed:** a group's record and roster are rows; every call runs the ALM controller; A/V chunks
  name their publisher; direct links propose by default; shaping is on for the `server` class;
  sharing traces is its own consent, per recipient.
- **Added:** suspend and resume; the load ladder; cosigned room roster changes and decision rows; the
  seat class, the eight-link bound and referrals; a typed shaping status and shed levers; the
  telemetry catalogue; the Anonymous Tier, dormant.
- **Fixed:** decapsulation and a responder's first frames left the event path (#947); replies have
  their own lane (#943); ALM meter and depth-0 claims (#945 items 1-3); stall guard (#926); key-plane
  memo (#930); late joiners ask for a path; a refused dial is jittered; standing survives a restart;
  a publisher keeps one stream under any measured ceiling, a ceiling goes stale, and the periodic
  binding re-announce no longer reads as congestion (#945); no Resource starts on a link mid-upgrade
  (`direct_link_upgrade_guarded`, `direct_link_failed_held`); the reaper leaves a punched link under a
  live call; a peer with no dial candidate backs off and replication frames are no longer queued;
  `replication_envelopes_served_total` counts at the send; persisted standing is one bounded,
  change-driven pass (`persisted_standing`).
- **Breaking:** `SERVE_ADVERTISE_POLICY_HASH` is `83099f47…`; `ApplyOutcome::Refused` gains `class`;
  `ReticulumTransportConfig`, `CallDeps` and `EdgeDeviceState` gain required fields; `Transport`
  gains `attach_load_ladder`, with a default; `TransportError` gains `NoDialCandidate`;
  `RootingDirectory::live_reticulum_bindings`, candidate-only, is four methods.
- **Unmet:** #945 item 4, E4, E5, #939, #940, #935, leviculum#97, #98, persist #1198, #1201, #1202;
  a relay with no floor can wait 30-240 s after a real shed; A/V is unproven across real NATs; the
  onion tier is not live.
