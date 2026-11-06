# Changelog

Full notes for every release are in [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md).

## 44.1.0 — 2026-11-06

What moves to a peer (CC 5.2): a row moves when it is requested, or required, and appropriate, never
because it is federation-tier. Two serve seats keep the commons walk; every other peer starts with
what is required, and of the walk is offered only what is required or appropriate and live. The rest
waits on the peer's pull. `SERVE_ADVERTISE_POLICY_HASH` is 14aedf25…; `advertise_awaits_request` is
new.

Every step of a late subject Pull gets the late window, so a Deliver behind a late Summary is kept.
The retired-plane line logs at debug at the hot-add door. Test fixes and the 44.0.0 notes date.
`anti-entropy round ended` carries `outcome` and `error`; a failing round says why at INFO, once per
(peer, kind) in five minutes.
`replication_round_outcomes_total` gains `no_route`. A new peer's first Attestation round waits for
the peer to confirm the bootstrap planes, at most five seconds, so a contact no longer loses a round
timeout to attribution.
A round lost after listing puts the watermark back, at most three times running, so its rows are in
the next round and not the re-sweep.

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
