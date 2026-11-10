# Changelog

Full notes for every release are in [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

## 45.0.0 — 2026-11-10

**MAJOR.** Pins: persist v61.2.2 (712575df; CIRISPersist#1246 SQLite mmap and cache_size), CIRISVerify
v22.2.0 (rusqlite 0.41.1 / libsqlite3-sys 0.39.1, RUSTSEC-2026-0459 cleared), leviculum
v0.34.0+ciris.2 (#102 A/V media on unordered datagrams, #104 probed MTU). MSRV 1.92; toolchain 1.97.0.

### Consumer notes

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
- **Replication sends to a peer no rule can reach are refused before any path
  seek** (CIRISEdge#971). With no live link, no path and no authenticated
  transit pair, CC 5.3.3.5 E1 forbids the dial, so the 3 s seek and its path
  request broadcast could only end "never dialled". The send is refused at
  once, and the round toward that peer is not started, before its advertise
  sweep. Both are booked `no_route` as before, so outcome counts stay
  comparable; only the duration drops.
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
