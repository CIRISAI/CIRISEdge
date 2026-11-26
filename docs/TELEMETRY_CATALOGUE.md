# Edge telemetry catalogue

What a running node can say about itself, and which number answers which
question. The catalogue in code is `crate::telemetry::TELEMETRY_CATALOGUE`, one
row per bundle field; the table at the end of this page is that list.

Nothing here leaves the node. Edge has no `metrics` facade, no recorder and no
exporter. The host reads the bundle (`metrics_snapshot()` in Python, the flat
`EdgeMetricsSnapshot` in UniFFI, `Edge::metrics().snapshot()` in Rust) and
decides what to do with it.

## Reading a snapshot

- **A series that is missing is not 0.** Every closed label is present at zero
  from the first snapshot. Absent means this build does not have the series; 0
  means it did not happen. Families marked `Tokens` in the catalogue are sparse:
  their keys are compile-time or persist tokens, not a closed list here.
- **An age of `-1` means never or not running.** `load_pressure_report_age_seconds`
  at `-1` says the host never reported. A tier of 0 next to it is not a calm
  reading, it is no reading. A parked node's loops read `-1`, not a growing age.
- **A key with a `:` refines the key before it.** `link_shaping_home_elsewhere`
  is the total of `:given` and `:received`. Sum one or the other.
- **Check the side of the wire.** A counter says what happened on this node. See
  [Which side](#which-side-of-the-wire).
- **Histograms** are cumulative `le` buckets, a count and a sum in seconds. In
  the flat form: `name.<label>.bucket.<le>`, `name.<label>.count`, and the gauge
  `name.<label>.sum`. `refusal_attempts` counts refusals, so its sum is refusals.

## Exposure

Each field is `public-safe` or `operator-only`, and the server enforces that.
One field is public: `node_alive`. It is 1 when the event loop and the ladder
both turned in the last 60 seconds. That is too coarse for traffic to move it.
Everything else needs the owner or loopback, including the counters that were
on the unauthenticated route: a 1 Hz poller of `envelopes_sent_total` reads a
shaped node's real activity directly, which is what shaping hides.

`loop_last_progress_age_seconds` is operator-only for the same reason: a
dispatcher busy with a batch turns late.

## Shaping's numbers

Shaping exists to hide real activity, so real frames and row wait are not live
counters. They wait in a per-class window and are published once per window W
(600 s, 3600 s for `phone-cellular`), rounded down to a multiple of 16 frames,
and only for a class holding at least three links. With fewer, an aggregate is
one peer's series, so the window is dropped, not carried, and
`shaping_windows_withheld{class}` counts it.

- `link_shaping` does not carry raw real frames. `shaping_frames_real_windowed`
  does, by class. `link_shaping_frames_cover` is safe alone because cover is
  load-independent.
- `shaping_row_wait_seconds` uses coarse buckets for the same reason.
- `ShapingStatus.links` and `.peers`, `load_ledger.transit[]`, the C7 tail and
  referral peers are not in the bundle. They name who talks to whom.

## Per-leg call series (v45.1.7)

`call_legs` is the one field whose labels name rooms and members
(`ciris.call.member` is a peer key): a named third exception to "no peer in a
label", after `peer_reachability_ratio` and `recent_withholds`, by Eric's
decision (2026-11-19), because the call screen's "?" panel needs to say which
leg is slow and why. It has one catalogue row per instrument, all of field
`call_legs`, and it is bounded three ways. It is operator-only, and the
server serves it to the owner session only, never on a public surface. It is live only: rows are read from each live
call's state when the bundle is read, so a leg's series are gone in the first
snapshot after the leg or its call ends. It is capped at 64 rows (a member, a
stream and a media kind each), with `call_legs_overflow` counting the rest.
No address, IP or port is ever an attribute. Every series carries
`ciris.room.id`, `ciris.call.id`, `ciris.call.member`, `ciris.call.stream_id`
and `ciris.media.kind` (`audio`, `video` or `share`):

| Instrument | Kind | Unit | Own attributes |
|---|---|---|---|
| `ciris.edge.call.path` | gauge (1) | 1 | `path` (`direct`, `relayed`), `relay.key_id` (empty unless a member relay forwards it), `transport` (`datagram`, `channel`), `punched`, `nat.local_type`, `nat.peer_type` (`unknown` on 45.1.x), `direction` |
| `ciris.edge.call.rtt` | gauge | ms | `direction` |
| `ciris.edge.call.bitrate` | gauge | bit/s | `direction` (`send`, `recv`); counts each chunk's plaintext payload both ways, never the wire form |
| `ciris.edge.call.frames_lost` | counter | {frame} | receive rows only |
| `ciris.edge.call.frames_skipped` | counter | {chunk} | receive rows only |
| `ciris.edge.call.jitter` | gauge | ms | receive rows only |
| `ciris.edge.call.reorder_window` | gauge | {chunk} | receive rows only |
| `ciris.edge.call.codec` | gauge (1) | 1 | `codec`, `direction` |

A send row is this node's own stream to one member's leg. A receive row is
one member's stream as it reaches this node: `relayed` with `relay.key_id`
when a member relay is its ALM primary parent, and `relayed` with an empty
key when a transport forwarder carries the link.

Log lines that name peers or rooms stay local: `edge.alm.decision` at DEBUG,
referral lines, `direct link` lines, `room` in `CALL JOINED` and `CALL LEFT`. The
`shaped frame sent` TRACE line must never be enabled in production.

## The questions

### Where do this node's bytes go?

`transport_wire_bytes_in_total` and `transport_wire_bytes_out_total`
(CIRISEdge#1025) say, for every byte an interface carried, which medium and
which plane it was for. Keys are `transport:plane`, and both label sets are
closed:

- **transport** (11): `tcp`, `udp`, `udp-direct` (a punched direct link),
  `i2p`, `lora`, `serial`, `ble`, `auto`, `local`, `http`, `other`.
- **plane** (11): `application`, `replication`, `resource`, `av`, `announce`,
  `path`, `link_control`, `relay`, `direct_link`, `shaped`, `other`.

That is at most 121 keys per direction, plus each family's total. A transport
that carried nothing is absent. A transport that carried anything lists all 11
planes, so a 0 there is a plane that moved nothing. No address, port, link,
interface name or peer is ever a key.

How a key gets its bytes:

- **Interface truth.** leviculum's I/O tasks count every byte read from or
  written to a socket, HDLC framing and IFAC included. The node tick (1 s), and
  every snapshot, folds those per-interface totals in by transport. Each
  interface's last reading is kept, so a TCP client that disconnects keeps its
  bytes up to the last fold. The bytes it moved after that fold and before it
  went are lost, at most one second of one connection, until leviculum exposes
  retired-interface totals (CIRISAI/leviculum#111).
- **Edge's attribution.** Every frame edge seals or opens on a Reticulum link
  (CC 5.3.3.5 E1) is counted once, at the seal, with one atomic add, by its
  lane and its tag:

| Plane | Rule |
|---|---|
| `application` | an envelope or any untagged Channel frame; link requests and responses |
| `replication` | `CRPL`, the `CFRG` fragments of a `CRPL` frame, and a Resource carrying one |
| `resource` | a Resource whose payload has no tag of its own (an envelope, a file) |
| `av` | the datagram lane, any frame on an A/V link, and `CHLO` / `CSKB` / `CALM` |
| `announce` | `CANN` and `CBND` link frames |
| `link_control` | `CTKX` (transit KEX), `CTKR` / `CTKA` (pre-seal route fetch), `SHAP` / `SHRF` / `SHCP`, `CNAK` |
| `relay` | `CONP` onion layers |
| `shaped` | `SHPF`: every frame on a shaped link, real and cover alike |
| `path`, `direct_link` | nothing yet: they wait for leviculum's per-packet hook (CIRISAI/leviculum#111) |
| `other` | interface truth minus every plane above |

  HTTP's `application` is the envelope bytes `Edge::send` and
  `dispatch_inbound` count. A link on a punched interface is `udp-direct`. Any
  other link is counted under the node's one configured interface kind, or
  under `other` when the node has several kinds.

**Reading `other`.** A transport's planes sum to what its interfaces carried, so
`other` is everything leviculum moved that edge never handed it, and everything
it wrapped around edge's frames: relayed packets, RNS announces and path
requests, link requests, proofs and keepalives, Resource advertisements, parts
and retransmits, packet headers, link tokens and HDLC framing. About a fifth of
a small frame is that wrapping (CC 5.4.3 rc17 puts it at 107 B of header and
token plus an 83 B proof per packet). An `other` far above that is the
finding. Until leviculum exposes a per-packet hook (CIRISAI/leviculum#111),
the planes it would split
out (`path`, `link_control` beyond edge's own frames, `relay` beyond onion,
`direct_link`) stay inside `other`.

**`shaped` is not split on purpose.** Real frames against cover is the activity
shaping hides (see [Shaping's numbers](#shapings-numbers)). A shaped link sends
at its class rate whatever it carries: 33,000 B/s each way on a seat link,
7,000 B/s at `server`, and about 1.15 times that on the wire. So `shaped` grows
with the number of shaped links, not with load.

`transport_bytes_in_total` and `transport_bytes_out_total` keep their old
meaning: application envelope bytes by edge transport id (`http`,
`reticulum-rs`). They were never the wire, so a seat whose wire is all
replication and shaping can read `{}` there.

### How many links and peers does this node carry? (CIRISEdge#1025)

Four families size a seat. None names a peer, link, address or port, and every
one is bounded.

- **`links_active`**: the established Reticulum links now, keyed
  `transport:direction`. The transport tokens are the wire-bytes ones, less
  `http` (10), and the direction is `inbound` (a peer opened it) or `outbound`
  (this node dialled it), so 20 keys, every one present from the first
  snapshot. A link counts under the node's one configured interface kind (or
  `other` when it has several) until it moves onto a punched interface, then
  under `udp-direct`, and back if it falls back. The same record backs
  `inbound_links` / `outbound_links`, so the 20 keys sum to them. Memory: 20
  integers per transport instance.
- **`distinct_peers_1h`** and **`distinct_peers_24h`**: how many distinct
  peers had an authenticated link to this node in the last hour and the last
  day. A peer counts once however many links it holds, and it is counted again
  in each five-minute bucket its link stays up. The estimator is a HyperLogLog
  of 2^12 registers per bucket: 12 five-minute buckets for the hour (so the
  window is the last 55 to 60 minutes) and 24 hourly buckets for the day,
  merged by register max on read. Standard error is 1.04/sqrt(4096), about
  1.6 % (±4.9 % at 3σ); below about 10,000 peers the linear-counting branch is
  within a peer or two of exact. The input is SHA-256 of a 32-byte salt drawn
  from the OS at start and the peer's key id; the key id is never kept, and
  neither the salt nor any register is exported. Memory: 36 × 4 KiB = 144 KiB.
  A peer is authenticated when edge attributes the link: the dialled node, by
  the transit pair the link was keyed to, or the identified dialler, by its
  proven Reticulum identity and binding.
- **`top_peers_by_bytes`**: the 10 peers that moved the most wire bytes with
  this node since it started, heaviest first, each as `peer` (16 hex digits of
  the same salted hash), `bytes_in`, `bytes_out` and `error_bytes`. A
  Space-Saving sketch of 64 counters (about 2 KiB) feeds it from the E1 seal's
  attribution: every frame sealed or opened on an attributed link adds to that
  link's tally (one atomic add), and the node tick drains the tallies into the
  sketch. Any peer above 1/64 of all peer-attributed bytes is in the sketch,
  and an entry is over-ranked by at most its `error_bytes`; `bytes_in` and
  `bytes_out` are lower bounds. The hash means nothing outside this process:
  a restart draws a new salt and two nodes never share one, so an entry can be
  followed between scrapes of one process and nowhere else. This is the
  per-peer sketch WORKLOAD_ATTRIBUTION A8 asks for, so it is not a label: the
  bundle (and the PyO3 dict) carry the list, and the flat (UniFFI / OTLP) form
  carries only the entry count and `top_peers_by_bytes.<rank>.bytes_in` /
  `.bytes_out` / `.error_bytes` for ranks 0 to 9, without the hash. Bytes
  leviculum moved that edge never handed it (`other` in the wire family) are
  not in it.
- **`link_duration_seconds`**: each established link's life, from its
  `LinkEstablished` to its close, keyed `class:cause`. `cause` is the close
  cause the direction counters use (`idle_expired`, `pool_idle_expired`,
  `pool_full`, `local_teardown`, `normal`, `peer_closed`, `timeout`, `stale`,
  `invalid_proof`, `channel_exhausted`, `blackholed`, `other`, `vanished`);
  `class` is the `peer_activity` class an inbound link came up under (a peer
  identified to this node), `dialled` for a link this node opened
  (`peer_activity` classes only identified inbound links), or `unidentified`
  for an inbound link no peer identified on. Buckets are 1 s, 5 s, 30 s,
  2 min, 10 min, 1 h, 6 h and `+Inf`. A label set nothing closed under is
  absent, so at most 8 × 13 = 104 label sets (about 8 KiB). A link
  recovered after a lost `LinkEstablished` (`recovered_links_total`) is timed
  from its recovery.

`first_contact:peer_closed` filling the 1 s and 5 s buckets while
`distinct_peers_24h` stays small is the churn #1025 found: few identities,
many short links.

### Why didn't this peer connect?

Read this on the node that was dialled, then on the dialler.

1. `seal_keyer_workers{configured}`: 0 means the keyer was never reached.
2. `link_seal_refused_handshake_node_rate:{standing,stranger,unidentified}`,
   `..._sender_rate:*` and `link_seal_refused_decap_saturated:{standing,stranger}`
   say which budget refused it. A peer the directory binds has standing from
   its first handshake after a restart, so a burst of `:stranger` then is first
   contacts, or peers off the roster.
3. `seal_keyer_queued{standing,stranger}` against 1024 and 256, and
   `seal_keying_duration_seconds` by standing, say whether the queue or the
   crypto is the wait.
4. `seal_awaiting_links`, `seal_awaiting_bytes` and
   `link_seal_refused_awaiting_cap`: half-open links at the cap.
   `link_seal_refused_stranger_cap`: the oldest keyed link with no standing,
   closed at 512. It re-dials. A rate of these is a flood or a very busy door.
5. `seal_held_bytes` and `link_seal_refused_keying_hold`: frames that arrived
   during keying.
6. `link_shaping_home_elsewhere:given` on the dialled node means it refused at
   its bound. `:received` on the dialler means a peer refused it.
   `shaping_free_slots` is what it had left.
7. `link_seal_refused_no_pair` on the dialler is the visible harm of a peer
   whose `transport_signer_id_mismatch` is 1.
8. `first_contact_duration_seconds{answered,timeout,failed}` is the requester's
   whole wait. A bimodal shape under a flood is the keyer's rate window.

`link_seal_keyer_panicked` above 0 is a bug. `link_seal_keying_skipped_stale`
counts handshakes whose link closed in the queue: they cost no crypto.

### Why is this canonical's event loop slow?

1. `event_handler_duration_seconds{event}` is the answer. It covers every arm of
   the loop, timers too, because a slow announce tick holds the frames behind it
   the same as a slow frame. Compare `sum / count` for the mean and the top
   buckets for the tail. `keying_applied` includes the frames that waited on a
   keying and replayed.
2. `edge.event_loop.slow` is the throttled WARN for one event past 250 ms.
3. `leviculum_events_queued{plane}` against `leviculum_events_capacity{plane}`
   is the backlog. `leviculum_events_dropped{plane}` rising means this loop did
   not drain in time; a dropped control event is a lost link edge.
4. `leviculum_shed_packets` rising is the per-peer breaker doing its job.
5. `loop_last_progress_age_seconds{event}` past a few seconds means one handler
   has not returned. It beats once a second from a timer arm, so it tracks the
   loop and not the traffic.
6. `replication_inbound_wait_seconds{kind}` and
   `replication_reply_wait_seconds{kind}` separate the event loop from a
   responder lane. `replication_reply_queued{sum,max}`: `max` near 8 is one
   reverse-dead peer. `reply_shed` and `reply_expired` are in
   `responder_rounds_total`. So is `reply_shed_node`: a frame that reads bodies
   unanswered at the node-wide 64 MiB bound, its own lane having room.

### Why did this call fail over?

1. `alm_active_calls` and `alm_c3_peers`: 0 explains a silent ALM.
2. `alm_failover_gap_seconds{cause}`, from when the old primary was last heard
   to the new parent's first chunk: what the listener lost. `link_down` is a
   link gone or silent, `health` a member or eligibility change, `depth` an
   offered depth past the bound.
3. `alm_failover` counts failure-driven changes, `alm_switch` make-before-break.
   They are told from the C7 log, so they match a replay.
4. `alm_epoch_resync`, `alm_loop_detected` and `alm_over_claim` are in `av_plane`.
5. `call_setup_duration_seconds{first_frame,ended}`.
6. The `edge.call.ended` INFO line carries the C7 hash, record count and counts,
   with no room and no peers. `edge.alm.failover` is INFO with no peer;
   `edge.alm.decision` is DEBUG with the peer.
7. `Call.alm_log()` in Python returns the hash, the count and the tail while the
   call lives. The tail names peers: it is for the owner's session only.

### Why is this call at another epoch than its room?

1. A call runs at its room group's stored head (45.3). Each watch tick (250 ms)
   reads the head slot; when another handle on the same store moved it (the
   host's chat driver holds its own), the call's handle reloads and the call
   rolls. `av_call_room_followed_store` in `av_plane` counts those reloads.
2. `av_call_roll_failed` in `av_plane` counts every tick a roll failed. The
   WARN line "the roll to the room's epoch failed" names the cause once, and
   again every 30 s while the same cause stands.
3. A "CALL ROLLED" INFO line follows each roll, with the epochs.
4. `av_call_room_refresh_failed` in `av_plane` counts each open of a room
   whose cached handle could not follow the store's head (a store fault, a
   snapshot that will not load). The cached handle is handed out as it was;
   the WARN line "the cached handle could not follow the store's head" names
   the cause once, and again every 30 s while it stands.

### What tier is this node in, and who put it there?

1. `load_tier` (0, 1, 2) and `load_host_pressure` (0, 1, 2).
2. `load_pressure_report_age_seconds`: `-1` means the host never reported, so
   tier 0 means nothing. A large age means the host stopped.
3. `load_tier_changes_total{to:cause}`: `host:*`, `edge:transit_pps`,
   `edge:relay_commit`, `edge:av_queue_age`, or `cooldown` for a step down.
4. Did shedding work: `load_shed:shaped` and
   `load_refuse:admit_closed` in `link_shaping`, then `load_tier` falling.

The tier reaches the shapers on a one-second tick, so edge needs no host read to
act on its own signals, and the cooldowns run on that tick. A host verdict not
renewed in 30 s lapses to normal. The tier does not close forwarding.

### What is a relay refusing, and what has the host shed?

1. `forward_refusals_total{load_refuse:capacity}` against `forward_admitted_total`:
   the only refusal left is a configured link bound, and each move of it is an
   INFO line, `forward admission refused link requests`, with `delta`, `reason`,
   `tier` and `cause`. Non-zero with no bound configured is a bug.
2. `forward_links_live`, `forward_packets_per_second`, `forward_bits_per_second`.
3. `load_lever_level{walk,page,bulk}`, and `load_lever_lease_seconds`: a level
   above 0 with a lease of 0 means the host stopped renewing and the lever is
   walking home.
4. `load_lever_changes_total{lever:cause}`, and the INFO line `load lever moved`.
   `lease_expired` with a live server means its renewal is too slow.

### Is shaped traffic within budget, by class?

1. `shaping_enabled` and `shaping_links{counted,seat}`: 0 explains a silent
   family. `shaping_seat_roster_age_seconds`: a retired seat keeps its class
   until a read works. `-1` means none has.
2. `shaping_row_wait_seconds{class}` once per W.
3. `link_shaping_row_left_timeout` and `link_shaping_row_retracted`: rows past
   their budget and rows taken back. `link_shaping_bodies_stranded`: bodies a
   closing link took with it. All of them retry.
4. `link_shaping_queue_deferred`, `link_shaping_over_cap`,
   `link_shaping_bulk_refused`.
5. `shaping_frames_real_windowed{class}` over W against the class's real budget.
6. `shaping_windows_withheld{class}` rising means the class is under three links
   and the two above are not being published. That is not the same as no traffic.

### Why hasn't a new member seen the room's history?

1. `group_backfill_rows_read_total` rising while `group_backfill_rows_kept_total`
   stays flat: the join backfill (CIRISEdge#968) is reading history families
   that hold nothing of the joined groups. Its pace is one page a round per
   peer under the `page` lever.
2. `group_backfill_completed_total` counts backfills that reached the end. A
   kept row is still subject to every serve gate; a withheld one is booked in
   the advertise round summary like any other.

### Why hasn't this governance row landed?

1. `decision_row_subscribers`: 0 means nobody is listening, and
   `decision_row_unheard_total{kind}` counts rows that found nobody. They still
   rest on `decision_rows_since`.
2. `apply_refusals_by_class`, `attestation_apply_refusals_by_reason` and
   `key_apply_refusals_by_reason` say which gate refused it.
3. `apply_refusals{moved_to_terminal}`: a row moved from the transient schedule
   to the terminal one, at the eighth refusal if nothing moved. It then waits 30
   minutes doubling to 6 hours, so a rolling upgrade can leave a row re-asked
   long after it ended. `edge.refusal.terminal` is the throttled INFO line.
4. `apply_refusals{refused_then_admitted:<class>}`: it did land.
   `refusal_attempts{transient,terminal}` says what it cost.
5. `retry_suppressions`: asks the memory held back. `rows_parked_on_signer`,
   `parked_on_signer_len` and `signer_releases`: rows waiting on a key.
6. `wake_first_round_duration_seconds`: on a phone, the time from resume to the
   first completed round.

### Which memo is reading the store, and why? (v45.1.9)

1. `memo_reads{<memo>.<reason>}`: each lookup through the owner, announce,
   own-set, key-plane and accord relay memos. `hit` answered from memory;
   `miss`, `ttl` and `invalidated` are reads, by cause: never filled, expired,
   or dropped by an event while live. A rising `invalidated` names the event
   path (a host kick, an ownership or revocation row, a delta row on a key
   plane); a rising `ttl` is the cadence; a rising `miss` is a working set
   that grows or churns. `owner.joined` waited on another caller's read.
2. The consent send set: `advertise_send_set_lookup_{hit,joined}`, then
   `advertise_send_set_read_miss`, `advertise_send_set_expired` and
   `advertise_send_set_read_invalidated`, which sum to the reads.
3. `structure_sizes{<structure>}`: how big what those paths walk is. The last
   send set's three widths, each memo's entries, `sweep_cursors.tracked`
   against 8192, `refusal_memory.parked_signers`, and each key plane's
   `store_feed.inbox.*` against 4096. Every gauge is set where the structure
   changes, so a scrape reads the last change, never a recount.

## Which side of the wire

| Series | Sits on | Cannot tell you |
|---|---|---|
| `link_shaping_home_elsewhere:given` | the refuser | that peers home elsewhere |
| `link_shaping_home_elsewhere:received` | the refused | anything about this node's room |
| `link_seal_refused_*` | the side that refused | that the sender knows |
| `transport_signer_id_mismatch` | this node's own wiring | that peers can key to it |
| `replication_reply_wait_seconds` | the responder | the reverse path's cause |
| `replication_envelopes_served_total` | the sender | that the peer admitted the row |

`transport_signer_id_mismatch` stays a gauge. It is set once at construction
and read back on every refresh. A node at 1 logs one ERROR and carries on, and
its peers see `link_seal_refused_no_pair`. The server needs a standing token for
it on top of the field: a node's own 0 says nothing about peers failing to key
to it, and a 1 is not visible from anywhere else.

`replication_envelopes_served_total` counts the rows this node sent a peer on
the replication plane, pushed or delivered, each row once, when the transport
took the frame. Per-direction detail (push, deliver, summary, diff, pull) is in
`replication_io`. Before 45.1.3 a peer added after start (every initiator on a
server-composed node) counted into neither.

Range fingerprints, step A (`docs/design/RANGE_FINGERPRINTS.md` §8) adds to
`replication_io`:

- the frame bytes of what crossed, preamble and JSON included:
  `summary_bytes_{out,in}`, `diff_bytes_{out,in}` and
  `deliver_wire_bytes_{out,in}`. These sit beside `deliver_bytes_*`, which
  stay the raw envelope bytes;
- `summary_refs_built` and `summary_bytes_built`, booked when a Summary is
  built, before the send. With the sent twins, these show a listing that was
  built but never handed down (§11.2);
- the receiver half's counters: `rf_nodes_in` (fingerprint nodes received,
  split children included), the answers `rf_match`, `rf_split` and `rf_list`,
  `rf_not_understood` (an `rf` member this build could not read, answered
  with the plain marker), and `rf_unable` for every `u` answer, with its
  reason in one of `rf_receiver_unbooted`, `rf_salt_refused`,
  `rf_answers_cap`, `rf_mirror_capped`, `rf_rebuilds_refused` (`busy`) and
  `rf_transport_refused`. `rf_salt_changes_received` counts salts accepted,
  `rf_peersums_built` the full salted passes over a mirror, `rf_seeded` the
  ids the restart seed added, `rf_match_feed_ids` the known hashes a matched
  range re-heard from their holder, and `rf_settled_from_peer` the wanted
  ids that entered a mirror on admission.

`holdings_index_gauge` gains `rf_mirror_ids` (the ids held in every
receiver mirror together), `rf_pending_ids` (the ids asked for and not yet
seen admitted) and `rf_parse_failed` (the `rf` members this process could not
parse or read since it started). No label carries a peer, a salt or an
address.

## Log events

| Target | Level | Carries |
|---|---|---|
| `edge.event_loop.slow` | WARN, throttled | event, ms |
| `edge.alm.decision` | DEBUG | kind, peer, value, reason |
| `edge.alm.failover` | INFO | reason, health state |
| `edge.call.ended` | INFO | cause, C7 hash, counts |
| `edge.refusal.terminal` | INFO, throttled | kind, class, next ask |
| `edge.shaping.seat_lost` | INFO | link |
| `edge.direct_link.posture` | INFO, at listen | proposing, facilitator |

## Every field

| Field | Name | Kind | Unit | Exposure |
|---|---|---|---|---|
| `envelopes_sent_total` | `ciris.edge.envelopes.sent` | counter | count | operator-only |
| `envelopes_received_total` | `ciris.edge.envelopes.received` | counter | count | operator-only |
| `send_failures_total` | `ciris.edge.send.failures` | counter | count | operator-only |
| `verify_failures_total` | `ciris.edge.verify.failures` | counter | count | operator-only |
| `durable_enqueued_total` | `ciris.edge.durable.enqueued` | counter | count | operator-only |
| `transport_bytes_in_total` | `ciris.edge.transport.bytes.in` | counter | bytes | operator-only |
| `transport_bytes_out_total` | `ciris.edge.transport.bytes.out` | counter | bytes | operator-only |
| `transport_wire_bytes_in_total` | `ciris.edge.transport.wire.bytes.in` | counter | bytes | operator-only |
| `transport_wire_bytes_out_total` | `ciris.edge.transport.wire.bytes.out` | counter | bytes | operator-only |
| `links_active` | `ciris.edge.links.active` | gauge | count | operator-only |
| `distinct_peers_1h` | `ciris.edge.peers.distinct.1h` | gauge | count | operator-only |
| `distinct_peers_24h` | `ciris.edge.peers.distinct.24h` | gauge | count | operator-only |
| `top_peers_by_bytes` | `ciris.edge.peers.top_by_bytes` | gauge | bytes | operator-only |
| `link_duration_seconds` | `ciris.edge.link.duration` | histogram | seconds | operator-only |
| `peer_reachability_ratio` | `ciris.edge.peer.reachability` | gauge | ratio | operator-only |
| `inbound_dropped_low_trust` | `ciris.edge.inbound.dropped_low_trust` | counter | count | operator-only |
| `replication_round_outcomes_total` | `ciris.edge.round.outcomes` | counter | count | operator-only |
| `replication_inbound_backpressure_drops` | `ciris.edge.replication.inbound.backpressure_drops` | counter | count | operator-only |
| `replication_inbound_backpressure_drops_by_role` | `ciris.edge.replication.inbound.backpressure_drops_by_role` | counter | count | operator-only |
| `blob_route_refusals` | `ciris.edge.blob.route_refusals` | counter | count | operator-only |
| `blob_serve_refusals` | `ciris.edge.blob.serve_refusals` | counter | count | operator-only |
| `blob_serve_legacy_dag_walks` | `ciris.edge.blob.serve_legacy_dag_walks` | counter | count | operator-only |
| `blob_scoped_carriers` | `ciris.edge.blob.scoped_carriers` | counter | count | operator-only |
| `blob_pull_sources` | `ciris.edge.blob.pull_sources` | counter | count | operator-only |
| `blob_pull_refusals` | `ciris.edge.blob.pull_refusals` | counter | count | operator-only |
| `blob_dag_phases` | `ciris.edge.blob.dag.phases` | counter | nanoseconds | operator-only |
| `blob_dag_chunks` | `ciris.edge.blob.dag.chunks` | counter | count | operator-only |
| `durability_custody` | `ciris.edge.durability.custody` | counter | count | operator-only |
| `delivery_receipts` | `ciris.edge.delivery.receipts` | counter | count | operator-only |
| `bootstrap_door_outcomes` | `ciris.edge.bootstrap_door.outcomes` | counter | count | operator-only |
| `transport_inbound_drops` | `ciris.edge.transport.inbound_drops` | counter | count | operator-only |
| `first_contact_outcomes` | `ciris.edge.first_contact.outcomes` | counter | count | operator-only |
| `av_plane` | `ciris.edge.av.plane` | counter | count | operator-only |
| `link_seal` | `ciris.edge.link_seal` | counter | count | operator-only |
| `link_shaping` | `ciris.edge.link_shaping` | counter | count | operator-only |
| `direct_link` | `ciris.edge.direct_link` | counter | count | operator-only |
| `peer_binding` | `ciris.edge.peer_binding` | counter | count | operator-only |
| `key_plane_sweep` | `ciris.edge.key_plane.sweep` | counter | count | operator-only |
| `sweep_permits` | `ciris.edge.sweep_permits` | counter | count | operator-only |
| `holdings_index` | `ciris.edge.holdings_index` | counter | count | operator-only |
| `holdings_index_gauge` | `ciris.edge.holdings_index.gauge` | gauge | count | operator-only |
| `persisted_standing` | `ciris.edge.persisted_standing` | counter | count | operator-only |
| `link_stall` | `ciris.edge.link_stall` | counter | count | operator-only |
| `direct_link_upgrade_guarded` | `ciris.edge.direct_link.upgrade_guarded` | counter | count | operator-only |
| `advertise` | `ciris.edge.advertise` | counter | count | operator-only |
| `replication_reach` | `ciris.edge.replication.reach` | counter | count | operator-only |
| `bundle_pull` | `ciris.edge.replication.bundle_pull` | counter | count | operator-only |
| `initiator_peers` | `ciris.edge.replication.initiator_peers` | gauge | count | operator-only |
| `memo_reads` | `ciris.edge.memo.reads` | counter | count | operator-only |
| `structure_sizes` | `ciris.edge.structure.sizes` | gauge | count | operator-only |
| `direct_links_active` | `ciris.edge.direct_links.active` | gauge | count | operator-only |
| `replication_routed_to_responder_total` | `ciris.edge.replication.routed.responder` | counter | count | operator-only |
| `replication_routed_to_initiator_total` | `ciris.edge.replication.routed.initiator` | counter | count | operator-only |
| `replication_reply_dropped_total` | `ciris.edge.replication.reply_dropped` | counter | count | operator-only |
| `announce_intake_evictions` | `ciris.edge.announce.intake_evictions` | counter | count | operator-only |
| `transport_packets_dropped` | `ciris.edge.transport.packets_dropped` | counter | count | operator-only |
| `known_destination_evictions` | `ciris.edge.known_destination.evictions` | gauge | count | operator-only |
| `transport_signer_id_mismatch` | `ciris.edge.transport.signer_id_mismatch` | gauge | count | operator-only |
| `link_pool_links` | `ciris.edge.link_pool.links` | gauge | count | operator-only |
| `link_pool_max_per_destination` | `ciris.edge.link_pool.max_per_destination` | gauge | count | operator-only |
| `link_pool_closed_by_reason` | `ciris.edge.link_pool.closed` | counter | count | operator-only |
| `inbound_links` | `ciris.edge.links.inbound` | gauge | count | operator-only |
| `outbound_links` | `ciris.edge.links.outbound` | gauge | count | operator-only |
| `inbound_link_closed_by_reason` | `ciris.edge.links.inbound.closed` | counter | count | operator-only |
| `outbound_link_closed_by_reason` | `ciris.edge.links.outbound.closed` | counter | count | operator-only |
| `link_before_binding` | `ciris.edge.link.before_binding` | counter | count | operator-only |
| `announce_queue_drop_first_seen` | `ciris.edge.announce.queue_drop_first_seen` | counter | count | operator-only |
| `channel_first_skipped_over_cap` | `ciris.edge.channel_first.skipped_over_cap` | counter | count | operator-only |
| `announce_to_binding_ms_last` | `ciris.edge.announce.to_binding_last` | gauge | milliseconds | operator-only |
| `withholds_by_reason` | `ciris.edge.withholds` | counter | count | operator-only |
| `recent_withholds` | `ciris.edge.withholds.recent` | gauge | count | operator-only |
| `replication_envelopes_served_total` | `ciris.edge.replication.envelopes_served` | counter | count | operator-only |
| `apply_refusals_by_kind` | `ciris.edge.apply_refusals.by_kind` | counter | count | operator-only |
| `key_apply_refusals_by_reason` | `ciris.edge.apply_refusals.key` | counter | count | operator-only |
| `attestation_apply_refusals_by_reason` | `ciris.edge.apply_refusals.attestation` | counter | count | operator-only |
| `apply_refusals_by_class` | `ciris.edge.apply_refusals.by_class` | counter | count | operator-only |
| `envelope_kind_retired_refusals` | `ciris.edge.apply_refusals.kind_retired` | counter | count | operator-only |
| `rows_parked_on_signer` | `ciris.edge.rows.parked_on_signer` | counter | count | operator-only |
| `signer_releases` | `ciris.edge.rows.signer_releases` | counter | count | operator-only |
| `retry_suppressions` | `ciris.edge.retry.suppressions` | counter | count | operator-only |
| `signer_park_evictions` | `ciris.edge.rows.signer_park_evictions` | counter | count | operator-only |
| `refusal_memory_len` | `ciris.edge.refusal_memory.len` | gauge | count | operator-only |
| `refusal_memory_capacity` | `ciris.edge.refusal_memory.capacity` | gauge | count | operator-only |
| `parked_on_signer_len` | `ciris.edge.rows.parked_on_signer.len` | gauge | count | operator-only |
| `parked_on_signer_capacity` | `ciris.edge.rows.parked_on_signer.capacity` | gauge | count | operator-only |
| `replication_applied_total` | `ciris.edge.replication.applied` | counter | count | operator-only |
| `replication_duplicate_total` | `ciris.edge.replication.duplicate` | counter | count | operator-only |
| `removal_delivery` | `ciris.edge.removal.delivery` | gauge | count | operator-only |
| `replication_round_duration_seconds` | `ciris.edge.round.duration` | histogram | seconds | operator-only |
| `sweep_permit_wait_seconds` | `ciris.edge.sweep.permit_wait` | histogram | seconds | operator-only |
| `responder_rounds_total` | `ciris.edge.responder.rounds` | counter | count | operator-only |
| `peer_activity` | `ciris.edge.peer.activity` | counter | count | operator-only |
| `persist_reads` | `ciris.edge.persist.reads` | counter | count | operator-only |
| `replication_io` | `ciris.edge.replication.io` | counter | count | operator-only |
| `responder_link_up_seconds` | `ciris.edge.responder.link_up` | histogram | seconds | operator-only |
| `responder_link_up_total` | `ciris.edge.responder.link_up.outcomes` | counter | count | operator-only |
| `recovered_links_total` | `ciris.edge.links.recovered` | counter | count | operator-only |
| `unclaimed_ship_refused_total` | `ciris.edge.links.unclaimed_ship_refused` | counter | count | operator-only |
| `event_handler_duration_seconds` | `ciris.edge.event.handler.duration` | histogram | seconds | operator-only |
| `seal_keying_duration_seconds` | `ciris.edge.seal.keying.duration` | histogram | seconds | operator-only |
| `replication_inbound_wait_seconds` | `ciris.edge.replication.inbound.wait` | histogram | seconds | operator-only |
| `replication_reply_wait_seconds` | `ciris.edge.replication.reply.wait` | histogram | seconds | operator-only |
| `shaping_row_wait_seconds` | `ciris.edge.shaping.row.wait` | histogram | seconds | operator-only |
| `alm_failover_gap_seconds` | `ciris.edge.alm.failover.gap` | histogram | seconds | operator-only |
| `call_setup_duration_seconds` | `ciris.edge.call.setup.duration` | histogram | seconds | operator-only |
| `first_contact_duration_seconds` | `ciris.edge.first_contact.duration` | histogram | seconds | operator-only |
| `refusal_attempts` | `ciris.edge.refusal.attempts` | histogram | count | operator-only |
| `wake_first_round_duration_seconds` | `ciris.edge.wake.first_round.duration` | histogram | seconds | operator-only |
| `seal_keyer_queued` | `ciris.edge.seal.keyer.queued` | gauge | count | operator-only |
| `seal_keyer_workers` | `ciris.edge.seal.keyer.workers` | gauge | count | operator-only |
| `seal_awaiting_links` | `ciris.edge.seal.awaiting.links` | gauge | count | operator-only |
| `seal_awaiting_bytes` | `ciris.edge.seal.awaiting.bytes` | gauge | bytes | operator-only |
| `seal_held_bytes` | `ciris.edge.seal.held.bytes` | gauge | bytes | operator-only |
| `replication_reply_queued` | `ciris.edge.replication.reply.queued` | gauge | count | operator-only |
| `load_tier` | `ciris.edge.load.tier` | gauge | count | operator-only |
| `load_host_pressure` | `ciris.edge.load.host_pressure` | gauge | count | operator-only |
| `load_pressure_report_age_seconds` | `ciris.edge.load.pressure_report_age` | gauge | seconds | operator-only |
| `load_tier_changes_total` | `ciris.edge.load.tier_changes` | counter | count | operator-only |
| `load_lever_level` | `ciris.edge.load.lever.level` | gauge | count | operator-only |
| `load_lever_lease_seconds` | `ciris.edge.load.lever.lease` | gauge | seconds | operator-only |
| `load_lever_changes_total` | `ciris.edge.load.lever.changes` | counter | count | operator-only |
| `forward_links_live` | `ciris.edge.forward.links` | gauge | count | operator-only |
| `forward_admitted_total` | `ciris.edge.forward.admitted` | counter | count | operator-only |
| `forward_refusals_total` | `ciris.edge.forward.refused` | counter | count | operator-only |
| `forward_packets_per_second` | `ciris.edge.forward.packets` | gauge | count | operator-only |
| `forward_bits_per_second` | `ciris.edge.forward.bits` | gauge | count | operator-only |
| `shaping_enabled` | `ciris.edge.shaping.enabled` | gauge | count | operator-only |
| `av_datagrams_enabled` | `ciris.edge.av.datagrams.enabled` | gauge | count | operator-only |
| `shaping_links` | `ciris.edge.shaping.links` | gauge | count | operator-only |
| `shaping_free_slots` | `ciris.edge.shaping.free_slots` | gauge | count | operator-only |
| `shaping_seat_roster_age_seconds` | `ciris.edge.shaping.seat_roster.age` | gauge | seconds | operator-only |
| `shaping_frames_real_windowed` | `ciris.edge.shaping.frames_real` | counter | count | operator-only |
| `shaping_windows_withheld` | `ciris.edge.shaping.windows_withheld` | counter | count | operator-only |
| `leviculum_events_queued` | `ciris.edge.leviculum.events.queued` | gauge | count | operator-only |
| `leviculum_events_capacity` | `ciris.edge.leviculum.events.capacity` | gauge | count | operator-only |
| `leviculum_events_dropped` | `ciris.edge.leviculum.events.dropped` | counter | count | operator-only |
| `leviculum_shed_packets` | `ciris.edge.leviculum.shed.packets` | counter | count | operator-only |
| `direct_link_proposing` | `ciris.edge.direct_link.proposing` | gauge | count | operator-only |
| `alm_active_calls` | `ciris.edge.alm.active_calls` | gauge | count | operator-only |
| `alm_c3_peers` | `ciris.edge.alm.c3_peers` | gauge | count | operator-only |
| `decision_row_unheard_total` | `ciris.edge.decision_row.unheard` | counter | count | operator-only |
| `decision_row_subscribers` | `ciris.edge.decision_row.subscribers` | gauge | count | operator-only |
| `group_backfill_rows_read_total` | `ciris.edge.group_backfill.rows_read` | counter | count | operator-only |
| `group_backfill_rows_kept_total` | `ciris.edge.group_backfill.rows_kept` | counter | count | operator-only |
| `group_backfill_completed_total` | `ciris.edge.group_backfill.completed` | counter | count | operator-only |
| `apply_refusals` | `ciris.edge.apply_refusals` | counter | count | operator-only |
| `loop_last_progress_age_seconds` | `ciris.edge.loop.last_progress_age` | gauge | seconds | operator-only |
| `call_legs` | `ciris.edge.call.path` | gauge | count | operator-only |
| `call_legs` | `ciris.edge.call.rtt` | gauge | milliseconds | operator-only |
| `call_legs` | `ciris.edge.call.bitrate` | gauge | bits/s | operator-only |
| `call_legs` | `ciris.edge.call.frames_lost` | counter | count | operator-only |
| `call_legs` | `ciris.edge.call.frames_skipped` | counter | count | operator-only |
| `call_legs` | `ciris.edge.call.jitter` | gauge | milliseconds | operator-only |
| `call_legs` | `ciris.edge.call.reorder_window` | gauge | count | operator-only |
| `call_legs` | `ciris.edge.call.codec` | gauge | count | operator-only |
| `call_legs_overflow` | `ciris.edge.call.legs_overflow` | gauge | count | operator-only |
| `node_alive` | `ciris.edge.node.alive` | gauge | count | public-safe |
