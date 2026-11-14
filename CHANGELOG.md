# Changelog

Full notes for every release are in [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

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
