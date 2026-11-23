# Calls cut: peer relay — events, tokens and levers (for hosts)

Edge 45.1.x, branch `feat/calls-relay-wiring`. Eric 2026-11-21: a member that cannot
punch a direct path to another is heard through a third member (the ALM mesh: direct,
then a member relay); the canonical never relays call media, audio included.

## Host defaults (the host decides; edge does not)

`CallOptions::relay: bool` is unchanged. The server passes `true` for member nodes and
`false` for canonicals and for a client on a metered or mobile network. Edge adds one rule
of its own: **a serve seat never relays**, whatever `relay` says.

## Live relay role

- `Call::set_relay(on: bool)` (Python `Call.set_relay(on)`): start or stop relaying
  mid-call. Off sheds every child make-before-break; a serve seat stays off.
- `Call::relay_status() -> (relaying: bool, relaying_for: u16)` (Python
  `Call.relay_status()`).
- `Call::relayed_to() -> Vec<RelayedTo { child, bytes, chunks, streams }>`: what this
  node forwarded, per child node, since the call began.

## Call events (new and changed)

| Event (`kind` on the Python dict) | Fields | When |
|---|---|---|
| `relay_status` (`CallEvent::RelayStatus`) **new** | `relaying: bool`, `relaying_for: u16` | On change, once a value has held one 250 ms tick, and at once on `set_relay`. `relaying_for` counts distinct child **nodes**; the host maps nodes to people. |
| `media_path_restored` (`CallEvent::MediaPathRestored`) **changed** | `member`, `via: PathKind`, `through: Option<key id>` **new** | A direct leg came up after a `media_path_failed`; or the member's primary stream is first heard through another member (`via = peer_relay`, `through` = that member's node key id); re-fired whenever `via` or `through` changes, a move back to the publisher included. |
| `media_path_failed` (`CallEvent::MediaPathFailed`) **changed** | as before; `relay` is computed | Only when there is neither a direct leg nor a member relay: at once in a two-person call, else after `RELAY_WAIT` (6 s) with no member relaying. |

## Closed token lists

`PathKind` (`via`): `direct_lan`, `direct_ipv6`, `direct_reflexive`, `predicted_ports`,
`birthday`, `mapped_port`, **`peer_relay`** (new).

`RelayStanding` (`relay` on `media_path_failed`):

| Token | Meaning |
|---|---|
| `peer_relay_in_use` | Another member relays the member's stream here (not raised on a failure). |
| `none_available` | No member offered to relay it. |
| `refused_by_policy` | Only a serve seat offered, and a serve seat never relays call media. |

`MediaPathCause` (`cause`): `both_nats_random`, `punch_no_answer`, `punch_one_way`,
`nat_undetermined`, `no_facilitator`, `refused_by_peer_policy`, `peer_unsupported`,
`budget_refused`, `not_trusted`, **`no_member_could_relay`** (new: the call has others in
it, none relays the member; retryable; `detail` still names why the direct path failed),
`other`.

`PathDetail` (`detail`): unchanged (`proposing_off`, `facilitator_unresolved`,
`peer_untrusted`, `escalation_gated`, `probe_failed`, `peer_reject_unsupported`,
`peer_reject_policy`, `both_random`, `escalation_budget`, `peer_punch_failed`,
`heard_not_acked`, `punch_silent`, `peer_timeout`, `proposal_unanswered`, `peer_busy`,
`glare`, `peer_holding`, `peer_reject_unknown`, `interface_lost`, `held_too_long`,
`peer_fell_back`, `no_link`, `backing_off`, `yielded`, `propose_refused`, `path_stands`).

Decided once by `media_path::call_path_verdict(direct_facts, relay_facts)` and
`media_path::relay_standing(relay_facts)` (pure; table tests in `media_path.rs`).

## Counters (`av_plane`)

| Label | Meaning |
|---|---|
| `relay_shed:relay_off` | A child shed because this node turned relaying off. The wire says `relay_shed:upstream_lost` (a code every C3 peer decodes; an unknown shed code is refused as malformed by older peers). |
| `relay_serve_seat` | This serve seat refused a relay SUBSCRIBE. The wire says `relay_class_refused`. |
| `alm_offer_refused:serve_seat` | A serve seat's OFFER for a stream it does not publish, dropped. |

`blob_scoped_carriers` gains `holder_rank:direct`, `holder_rank:peer_relay`,
`holder_rank:other`, `holder_rank:seat_only`: how the best holder of each blob fetch is
reached. A fetch asks only holders at the best rank, so a body never crosses the canonical
while another member reaches it.

Wire ledger: media this node forwards for another member is counted in the `relay` plane of
`transport_wire_bytes` (it was `av`).

## The lever

`av_call::CANONICAL_AV_FALLBACK: bool = false` (45.x). Off: a serve seat never relays, and
receivers drop a seat's relay offers. On (not on 45.x): the FSD §6.4 V2 audio-only canonical
tier.
