# Changelog

Full notes for every release are in [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

## Unreleased

The onion relay's replay set is a bounded hold (CIRISEdge#955, CC 5.3.3.5 E1 rule 9). It holds at
most `REPLAY_BOUND` = 62,134 tags a period: the `seat` rate on the node cap's eight shaped links,
264,000 B/s, over the 3,600 s period, divided by the 15,296-byte packet. With the last period's tags
that is under 8.3 MiB. Past the bound a new packet is refused as `onion_replay_set_full`, counted
like the other onion refusals; no held tag is evicted, and a replay of a held tag is still
`onion_replay`. The bound is fixed, not a lever. A source witness pins that an onion frame reaches
`accept_inbound` only on a link that keyed behind `ReceiverOrder::admit`, and `accept_inbound`'s
`link_shaped` is documented as the transport's own shaping state.

## 44.1.0 — 2026-11-07

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
