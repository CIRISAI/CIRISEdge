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

Log lines that name peers or rooms stay local: `edge.alm.decision` at DEBUG,
referral lines, `direct link` lines, `room` in `CALL JOINED` and `CALL LEFT`. The
`shaped frame sent` TRACE line must never be enabled in production.

## The six questions

### Why didn't this peer connect?

Read this on the node that was dialled, then on the dialler.

1. `seal_keyer_workers{configured}`: 0 means the keyer was never reached.
2. `link_seal_refused_handshake_node_rate:{standing,stranger,unidentified}`,
   `..._sender_rate:*` and `link_seal_refused_decap_saturated:{standing,stranger}`
   say which budget refused it. A burst of `:stranger` right after a restart is
   expected.
3. `seal_keyer_queued{standing,stranger}` against 64 and 32, and
   `seal_keying_duration_seconds` by standing, say whether the queue or the
   crypto is the wait.
4. `seal_awaiting_links`, `seal_awaiting_bytes` and
   `link_seal_refused_awaiting_cap`: half-open links at the cap.
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
   `responder_rounds_total`.

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

### What tier is this node in, and who put it there?

1. `load_tier` (0, 1, 2) and `load_host_pressure` (0, 1, 2).
2. `load_pressure_report_age_seconds`: `-1` means the host never reported, so
   tier 0 means nothing. A large age means the host stopped.
3. `load_tier_changes_total{to:cause}`: `host:*`, `edge:transit_pps`,
   `edge:relay_commit`, `edge:av_queue_age`, or `cooldown` for a step down.
4. Did shedding work: `load_shed:shaped`, `load_shed:bulk` and
   `load_refuse:admit_closed` in `link_shaping`, then `load_tier` falling.

The tier reaches the shapers and forward admission on a one-second tick, so edge
needs no host read to act on its own signals, and the cooldowns run on that tick.

### Is shaped traffic within budget, by class?

1. `shaping_enabled` and `shaping_links{counted,seat}`: 0 explains a silent
   family. `shaping_seat_roster_age_seconds`: a retired seat keeps its class
   until a read works. `-1` means none has.
2. `shaping_row_wait_seconds{class}` once per W.
3. `link_shaping_row_left_timeout` and `link_shaping_row_retracted`: rows past
   their budget and rows taken back. `link_shaping_bodies_stranded`: bodies a
   closing link took with it. All of them retry.
4. `link_shaping_queue_deferred`, `link_shaping_over_cap`,
   `link_shaping_bulk_refused`, `link_shaping_bulk_fallback:{ok,failed}`.
5. `shaping_frames_real_windowed{class}` over W against the class's real budget.
6. `shaping_windows_withheld{class}` rising means the class is under three links
   and the two above are not being published. That is not the same as no traffic.

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

## Which side of the wire

| Series | Sits on | Cannot tell you |
|---|---|---|
| `link_shaping_home_elsewhere:given` | the refuser | that peers home elsewhere |
| `link_shaping_home_elsewhere:received` | the refused | anything about this node's room |
| `link_seal_refused_*` | the side that refused | that the sender knows |
| `transport_signer_id_mismatch` | this node's own wiring | that peers can key to it |
| `replication_reply_wait_seconds` | the responder | the reverse path's cause |

`transport_signer_id_mismatch` stays a gauge. It is set once at construction
and read back on every refresh. A node at 1 logs one ERROR and carries on, and
its peers see `link_seal_refused_no_pair`. The server needs a standing token for
it on top of the field: a node's own 0 says nothing about peers failing to key
to it, and a 1 is not visible from anywhere else.

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
| `link_stall` | `ciris.edge.link_stall` | counter | count | operator-only |
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
| `shaping_enabled` | `ciris.edge.shaping.enabled` | gauge | count | operator-only |
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
| `apply_refusals` | `ciris.edge.apply_refusals` | counter | count | operator-only |
| `loop_last_progress_age_seconds` | `ciris.edge.loop.last_progress_age` | gauge | seconds | operator-only |
| `node_alive` | `ciris.edge.node.alive` | gauge | count | public-safe |
