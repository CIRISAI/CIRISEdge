# Edge 45.2.0 — call paths and peer relay: the frozen token set (for hosts)

Every token in this file is **frozen for 45.x**. Later releases only add tokens; none is renamed or removed in 45.x. A host must accept a token it doesn't know, and show it as the generic case.

**Show** means the client explains it to a person (it needs copy). **Diag** means it goes to the "?" panel, logs or support only.

## Host defaults (the host decides, edge does not)

- `CallOptions::relay: bool` is unchanged. The server passes `true` for member nodes and `false` for canonicals and for a client on a metered or mobile network.
- Edge adds one rule of its own: **a serve seat never relays call media, audio included**, whatever `relay` says. The lever is `av_call::CANONICAL_AV_FALLBACK = false` on 45.x.

## Calls (Rust `Call`, Python `Call`)

| Item | Meaning |
|---|---|
| `Call::set_relay(on: bool)` (async) / `Call.set_relay(on)` | Start or stop relaying others' streams live. Off sheds every child make-before-break (they keep media until they move). A serve seat stays off. Fires `RelayStatus` at once. |
| `Call::relay_status() -> (bool, u16)` / `Call.relay_status()` | `(relaying, relaying_for)` now. |
| `Call::relayed_to() -> Vec<RelayedTo>` | What this node forwarded, per child node: `child`, `bytes`, `chunks`, `streams`. Diag. |
| `RELAY_WAIT` (6 s) | How long a member with no direct path waits for a member relay before `MediaPathFailed` fires. |

## Call events

| Event (`kind` on the Python dict) | Fields | Show / Diag | When |
|---|---|---|---|
| `relay_status` (`CallEvent::RelayStatus`) | `relaying: bool`, `relaying_for: u16` | **Show** ("relaying for N people") | On change, once a value has held one 250 ms tick, and at once on `set_relay`. `relaying_for` counts distinct child **nodes**; the host maps nodes to people. |
| `media_path_restored` (`CallEvent::MediaPathRestored`) | `member`, `via: PathKind`, `through: Option<key id>` | **Show** (`via = peer_relay`: "through {person of `through`}"; any other `via`: "direct") | A direct leg came up after a `media_path_failed`. Or the member's primary stream is first heard through another member. Re-fired whenever `via` or `through` changes, a move back to the publisher included. |
| `media_path_failed` (`CallEvent::MediaPathFailed`) | `member`, `cause`, `retryable`, `retry_after_s`, `detail`, `tried`, `local_nat`, `peer_nat`, `relay` | **Show** (`cause`; `relay` as a secondary line) | Only when there is neither a direct leg nor a member relay: at once in a two-person call, else after `RELAY_WAIT` with no member relaying. Once per cause. |

`tried` is a list of `{kind: PathKind, outcome: PathOutcome, attempts, elapsed_ms, knocks_sent, sockets}`. `local_nat` and `peer_nat.report` are `NatReport` dicts: `mapping`, `allocation`, `filtering`, `port_preserving`, `router_mapping`, `family`, `evidence`, `legacy_class`, `measured_at` (ms). `peer_nat` also has `source`. All of these are Diag. `legacy_class` may appear in the "?" panel.

## `MediaPathCause` (`cause`): the user-facing causes. The client needs copy for exactly these

| Token | Meaning | retryable |
|---|---|---|
| `both_nats_random` | Both networks assign ports at random, so a direct path can't be aimed. | no |
| `punch_no_answer` | The direct-path attempt ran and nothing came back. | yes |
| `punch_one_way` | It got through one way only. | yes |
| `nat_undetermined` | The attempt ended before either network's behaviour was known. | yes |
| `no_facilitator` | This device has no meeting point (facilitator) for a direct path, or it didn't answer. | yes |
| `refused_by_peer_policy` | The other person's device doesn't take direct paths from this one. | no |
| `peer_unsupported` | The other device can't take part in a direct path. | no |
| `budget_refused` | The harder techniques the networks need were held back for now. | yes (`retry_after_s`) |
| `not_trusted` | This device doesn't reveal its address to that peer. | no |
| `no_member_could_relay` | No direct path, and no one else in the call could relay it. `detail` still says why direct failed. | yes |
| `anonymous_no_direct` | This device is in anonymous mode, which never makes direct paths (they reveal the address). | no (while anonymous) |
| `other` | Anything else; `detail` names it. | yes |

## `RelayStanding` (`relay` on `media_path_failed`), Show as a secondary line

| Token | Meaning |
|---|---|
| `peer_relay_in_use` | Another member relays it (never on a failure; reserved). |
| `none_available` | No member offered to relay it. |
| `refused_by_policy` | Only a server offered, and servers never relay calls. |

## `PathDetail` (`detail`), Diag

`proposing_off`, `facilitator_unresolved`, `peer_untrusted`, `escalation_gated`, `probe_failed`, `peer_reject_unsupported`, `peer_reject_policy`, `both_random`, `escalation_budget`, `peer_punch_failed`, `heard_not_acked`, `punch_silent`, `peer_timeout`, `proposal_unanswered`, `peer_busy`, `glare`, `peer_holding`, `peer_reject_unknown`, `interface_lost`, `held_too_long`, `peer_fell_back`, `no_link`, `backing_off`, `yielded`, `propose_refused`, `path_stands`.

Each names the one code branch that decided the cause (see `media_path.rs` for its line).

## `PathKind` (`via`, `tried[].kind`)

| Token | Meaning | Show / Diag |
|---|---|---|
| `direct_lan` | Same local network. | Show as "direct" |
| `direct_ipv6` | Global IPv6, no NAT. | Show as "direct" |
| `direct_reflexive` | The ordinary hole punch. | Show as "direct" |
| `predicted_ports` | Predicted the peer's next port. | Show as "direct" |
| `birthday` | Many sockets toward a random NAT. | Show as "direct" |
| `mapped_port` | A router-held mapping (PCP, NAT-PMP, UPnP). | Show as "direct" |
| `peer_relay` | Another member relays it; `through` names them. | **Show** ("through {person}") |

## `PathOutcome` (`tried[].outcome`), Diag

`established`, `no_answer`, `one_way`, `refused_by_peer`, `no_facilitator`, `not_tried_no_evidence`, `not_tried_untrusted`, `budget_refused`.

## NAT classes (`NatReport`), all Diag

- `NatMapping`: `none`, `endpoint_independent`, `address_dependent`, `address_and_port_dependent`, `unknown`.
- `NatAllocation`: `preserving`, `sequential`, `random`, `unknown`.
- `NatFiltering`: `endpoint_independent`, `address_dependent`, `address_and_port_dependent`, `unknown`.
- `RouterMapping`: `held_pcp`, `held_nat_pmp`, `held_upnp`, `none`, `not_tried`.
- `AddressFamily`: `v4`, `v6`.
- `NatEvidence`: `two_observer`, `own_evidence`, `none`.
- `LegacyClass` (RFC 3489 display word): `open`, `full_cone`, `restricted`, `port_restricted`, `symmetric`, `unknown`.
- `NatReportSource` (`peer_nat.source`): `self_reported`.

On leviculum v0.34.0+ciris.3 every NAT field reads `unknown` / `none`, because nothing is measured yet.

## Counters (`av_plane`, `direct_link`, `blob_scoped_carriers`), Diag

| Label | Meaning |
|---|---|
| `relay_shed:relay_off` | A child shed because this node turned relaying off. The wire says `relay_shed:upstream_lost`, a code every C3 peer decodes. |
| `relay_serve_seat` | This serve seat refused a relay SUBSCRIBE. The wire says `relay_class_refused`. |
| `alm_offer_refused:serve_seat` | A serve seat's OFFER for a stream it does not publish, dropped. |
| `alm_uplink_stall` | This node's uplink stalled: two or more legs held a control message unproved past 400 ms. It sheds to one child. |
| `direct_link_released_link_closed` | A direct path forgotten because its link closed; the next dial re-punches at once, once per peer per 60 s. |
| `holder_rank:direct` / `:peer_relay` / `:other` / `:seat_only` | How the best holder of a blob fetch was reached. A fetch asks only the best-ranked holders. |

Wire ledger: media this node forwards for another member is counted in the `relay` plane of `transport_wire_bytes` (it was `av`).

## Other host-visible additions

- `ReticulumTransport::set_serve_seats` and `serve_seats` (the Edge wires its canonical set in at build).
- `ReticulumTransport::holder_path_rank`.
- `blob_swarm::PeerState::path_rank` and `PATH_RANK_*`.
- `AvLinkSender::send_media_relayed` (a default method) and `AvDispatcher::forward_inner_report`.
- `AlmCounts::relayed_bytes`.
- `media_path::{RelayFacts, relay_standing, call_path_verdict}`. `MediaPathFailure::from_facts(facts, relay, now)` gained the `relay` argument.
- `Edge::local_nat_report`; UniFFI `local_nat_report()` with `EdgeNatReport`.
