# FSD — The CIRIS Mesh: relay selection for peers that cannot be reached directly

**Status:** normative target, with the present behaviour cited at edge v43.4.1 (main 0f73576, leviculum
c6d0a22, persist v59.1.2). **Direction:** Eric, 2026-11-01: "peers behind hard NATs use contacts
offering relay (which should be most/all) before the canonical for transport, exact same primitives as
the ALM mesh … evaluate if we need to prevent any video streams from reflecting off canonicals."
**Sources, in order of authority:** the CIRIS Constitution (CC 5.4.6 direct-path MUST and the
scoped-body-on-identity-link ruling, rc6 4fd2e9e; CC 5.3.3.5 E1, rc9 7401a24; the rc9 c8f0d12 invariants,
I5 "a canonical is never a required party"; CC 5.4.3 link shaping; CC 3.3.7 `consent:replication`),
`docs/AV_ALM_DESIGN.md`, `docs/FEDERATION_SCALING_MODEL.md`, `docs/SHAPING_RHO_W_2026-10-22.md`,
`FSD/FIRST_CONTACT.md`, `FSD/CIRIS_EDGE_TRANSPORT.md`, and the ALM controller on branch
`feat/alm-controller` (stage 1, uncommitted at the time of writing; cited by module, not line).

Citations are `path:line` at 0f73576 unless marked otherwise. **[inf]** marks an inference that was not
checked by running code. Nothing here was built or run for this document.

The one sentence this document exists to make structural: **a relayed transport path is a parent, and
it is chosen, admitted, measured, switched and logged by the same controller that chooses an A/V
parent.** There is one selection mechanism in the mesh, not two.

---

## 0. Vocabulary (frozen)

| Term | Meaning |
|---|---|
| **Hard-NAT peer** | A node with no inbound reachability that a direct punch can rely on: symmetric NAT, CGNAT, a firewall dropping unsolicited UDP, or any pair whose punch has failed (`PunchFailed`) within the last backoff window. Mobile on cellular is the default case. |
| **Direct path** | A one-hop path between the two endpoints: a shared interface (LAN, AutoInterface), one end's public listener, or a punched UDP interface (#805 item 8). `hops_to == 1` (`src/transport/reticulum.rs:6080-6084`). |
| **Relay** | A Reticulum transport node (`enable_transport = true`) that forwards the link packets of a link it is not an endpoint of. It never holds the link's keys. |
| **Contact relay** | A relay that is a consented peer of the requester (§3.3) and offers relay (§3.2). |
| **Canonical** | A serve-tier node named in the genesis bundle (`serve_transport_destinations`), announced (CC 5.3, rc9 1a46e03), transport-enabled, publicly reachable. Production has one. |
| **Attachment** | A hard-NAT node's live link to a relay over an interface that does not itself cross the canonical. The node's attachments are what make it reachable through that relay. |
| **Relayed link** | An RNS link `A ↔ B` whose path crosses one relay `C`. Its keys are `A`'s and `B`'s alone. |
| **Flow class** | `control` (path requests, route fetch, KEX, C3 frames, first contact), `replication` (identity and community rounds, chat rows, scoped bodies on the identity link), `bulk` (blob/file chunks), `audio`, `video`. |

---

## 1. The rule

For every flow from a node `A` to a node `B`:

1. **Direct first.** If a direct path exists or can be brought up, the flow MUST use it.
2. **Then a contact relay.** Otherwise the flow MUST ride a relayed link through a contact relay
   chosen by the ALM parent selector (§4), when one is eligible and admits it.
3. **The canonical last.** Only when no direct path and no contact relay is available MAY the flow ride
   the canonical, and then only within the canonical's per-class policy (§6.4): never video.

**Why this order.** Direct is required by CC 5.4.6 wherever the endpoints can bring it up, and it is
the most private path (no third party sees timing or volume, `src/transport/direct_path.rs:100-104`).
A contact is a party the requester has already chosen to trust with its traffic metadata, and
contacts are many, so load spreads. The canonical is one machine that every hard-NAT node can reach.
Left to default it becomes the herd attractor, and its failure takes down bootstrap, discovery and
push-to-wake for the whole federation. CC rc9 I5 already says a canonical is never a required party;
this rule extends that from "not required" to "not preferred".

---

## 2. How it works today (v43.4.1)

### 2.1 Identity, routes and the seal

- **Two keypairs per node.** The federation key signs records. The RNS transport identity
  (X25519 ‖ Ed25519) is bound to it only by the node's signed `TransportDestination` row (the "route
  row") or its announce attestation (`src/transport/identity_model.rs`; `FSD/CIRIS_EDGE_TRANSPORT.md` §5).
- **The route row carries no network address.** It names a destination hash and transport keys. How
  the bytes get there is Reticulum's business: "Reticulum routes to it across however many hops
  separate the two nodes — edge does not implement relaying, path discovery, or a DHT"
  (`src/contact.rs:37-47`, `:1181-1184`).
- **E1 per-link seal.** Every edge frame on every RNS link rides under a hybrid transit seal
  (X25519 + ML-KEM-768, run once per link as its first frame, bound to `link_id`), with no classical
  fallback (`src/transport/link_seal.rs:1-80`). The dialler must hold a transit pair *authenticated*
  to the dialled node: a Rooted binding, the node's own hybrid-signed route row, or a pairing pin
  (`link_seal.rs:651` `resolve_pair`). Two strangers bootstrap with the pre-seal route fetch
  (`src/transport/route_fetch.rs:1-30`). Seal overhead is 25 B per frame (`link_seal.rs:106-114`).
- **The seal is end to end on a relayed link.** A relay forwards RNS link packets. It is not a link
  endpoint, so it never runs the KEX and never holds `k_dir` [inf: from RNS transport semantics and
  the seal being keyed on link endpoints; there is no edge code on the forwarding path at all].

### 2.2 Who forwards, and who chooses

- **Only transport-enabled nodes forward.** `ReticulumTransportConfig::enable_transport` defaults to
  `false`: "a leaf edge does NOT relay for strangers unless opted in"
  (`src/transport/reticulum.rs:1947-1961`, default `:2020`). In production the canonical is the
  transport-enabled node every NAT'd node dials out to.
- **Edge does not choose the relay. leviculum's path table does.** Edge selects among a peer's
  *destination* candidates by whether a path exists (`select_dial_candidate`, `reticulum.rs:1675-1712`;
  used at `:8248-8259`). The path to the chosen destination, and therefore its next hop, is a single
  path-table entry per destination. That entry is replaced by fewer hops or a newer announce emission
  (leviculum c6d0a22 `leviculum-core/src/transport.rs:270-276`, `:6074-6095`). Nothing in it weighs
  capacity, load, consent or trust.
- **No steering API exists at the pin.** leviculum exposes `has_path`, `hops_to`, `request_path`,
  `remove_path`, `drop_all_paths_via`, `path_table_entries` and `link_stats`
  (`leviculum-std/src/driver/mod.rs:3503-3816`). There is no way to install or prefer a path via a
  named transport node. Edge's `routing_path_request` takes an `on_interface` argument and ignores it
  (`reticulum.rs:7606-7631`).

**Consequence.** Today a hard-NAT node's relayed traffic goes through whichever transport node won
the announce race. In production that is the canonical, because it is the only transport node most
leaves share.

### 2.3 Consent-gated routes, and which relayed routes are asked about

- **Rule 1, consent-gated routes** (Eric 2026-10-30). A relayed route row of an owned node goes to a
  peer only if the node's owner granted that peer, or the peer's owner, `consent:replication`
  (`src/replication/bridge.rs:10092-10140`). Unowned nodes (the canonical) and a node's own route are
  never withheld. It ships behind `ReplicationRuntimeConfig::consent_gated_routes`, default `false`
  (`src/replication/runtime.rs:842`, `bridge.rs:2448`). It stays off until CIRISPersist#1165 lets a
  relay hold a contact grant.
- **Relayed routes are asked about only for send-set peers** (v43.4.1, 47c596e). A
  `TransportDestination` offered by someone other than its own node is a relayed route
  (`src/replication/missing_signer.rs:104`). It is parked on its absent Key and asked about only when
  its node is in this node's resolved attestation send set (`bridge.rs:3822-3836`, `sends_to` at
  `:8620`). The send set covers consent, owner-routed nodes, own devices, and a contact's node once
  the grant names it. Before this fix, 778 parked routes on the cross-NAT harness would each have
  spent a replication round.

Both rules already encode this document's eligibility principle: **a node learns how to reach exactly
the peers it has consented to.** §3.3 reuses that set for relay eligibility.

### 2.4 Direct links (#805 item 8)

- **Config.** `DirectLinksConfig { facilitator, serve_facilitator, accept }`. The default proposes
  nothing (`src/transport/direct_path.rs:124-160`). Accepting is asked of the host per request
  (`AskHost`, leviculum#82) and answered by `direct_standing`: shares a room, or a consented contact
  named via `allow_direct_contact` (`reticulum.rs:6280-6306`).
- **Proposal sites.** The A/V dial (`ensure_direct_path`, `reticulum.rs:6044`, called at `:5753`).
  A room peer reached through a transport node, after a send (#915, `:9114`) or on the reverse path
  (#920, `:9074`), via `propose_direct_to_room_peer` (`:6142`).
- **State: proposing is OFF in production.** After the 2026-10-31 Eric↔Francesco incident (a punch
  that succeeded on one side only left links dead one way), server 0.5.243 sets the facilitator to
  `None`. It stays off until leviculum#89 (two-sided commit) and CIRISEdge#926 (Channel stall guard)
  ship. Serving a facilitator and `allow_direct_contact` stay on.
- **Unwired helpers.** `direct_leg_stalled` (`direct_path.rs:243`), `fall_back_from_direct`
  (`reticulum.rs:6417`) and `admit_dialled_subscriber` (`:6351`) have no production caller.

### 2.5 A/V today

- **A/V legs are one hop by construction.** A leg dials the member's *derived* address. Derived
  addresses are announce-suppressed (CC 5.4) and answer only a one-hop neighbour, so a leg can never
  establish across a transport node (`tests/av_call_nat_805.rs:7-11`; `reticulum.rs:5748-5753`).
  Between two NAT'd members a call has legs only over a punched interface. With proposing off, two
  hard-NAT phones whose only common node is the canonical get **no leg at all** (the E4 fail-before,
  `av_call_nat_805.rs:20-22`).
- **Production is a full mesh plus an optional flood.** `Edge::join_call` (`src/edge.rs:4372`) leads
  to `Call::join` (`src/transport/av_call.rs:1102`). Every publisher dials every member
  (`reconcile_legs` `:1694`, `dial_leg` `:1732`). With `CallOptions::relay` (a host bool, default
  `false`, `:111-131`) a node re-sends every first-hand chunk to every other member it has a leg to
  (`:1885-1897`, `relay` `:1931-1949`). There is no subscribe, no admission and no capacity check.
  The relay is a room member: it holds the stream DEK and opens what it relays (`:1898-1903`).
- **The ALM kit is dormant.** `AlmJoinPlanner::plan`, `CapacityEstimator`, `SignedRelayCapacity`,
  `TransitGate` and `LegChoice` have no production caller. The planner herds: RTT-sorted with
  `has_room_for(B, 0)` (`src/transport/realtime_av_alm/join.rs:297`, `:318-320`), and sim M9 shows
  500 of 500 joiners on one parent (`sim.rs:1635-1680`). The signed capacity ad signs only
  `{peer_id, uplink_mbps as whole u32, epoch}` (`realtime_av_alm/capacity.rs:390-398`, `:409`), so
  its freshness is unsigned.
- **Source authentication** (branch `fix/av-chunk-sender-auth`, 88b68c3 + 8c77bc5, unreleased).
  The publisher mints a per-stream ephemeral Ed25519 key at stream start and every epoch roll, and
  binds it in a `StreamKeyBinding` (room, publisher, join nonce, stream id, epoch, key) that is
  hybrid-signed by its federation identity. Every chunk carries a 64-byte signature over header and
  inner ciphertext. Receivers and *member* relays verify it before anything else. Forged or unbound
  chunks are dropped and counted, and a member relay forwards only chunks whose verified publisher
  is the link's peer. A non-member forwarder never sees bindings or trailers (§4.4 M4).

### 2.6 The gap

| Target (this FSD) | Today |
|---|---|
| Direct, then contact relay, then canonical | Direct only if a facilitator is configured (off), else whatever transport node won the announce race (the canonical) |
| "Offering relay" is a signed, discoverable, consent-served fact | Not representable: route rows carry no address; `infra:transport` exists only as the dormant TransitGate's input (`transit_gate.rs:1-30`) |
| Relay chosen by measured score with hysteresis, dwell, jitter, make-before-break, warm standby | Chosen by leviculum's hop count and announce recency; one path per destination, no standby |
| Admission at the relay against committed capacity | None: a transport node forwards everything it routes |
| Per-class canonical policy (no video) | Video *cannot* cross the canonical today, but only because A/V legs are one-hop (§2.5). Nothing states it as policy, and every other class crosses unmetered |
| One decision log for A/V and transport | No log for either in production |

---

## 3. The target: relay preference

### 3.1 Normative rules

- **R1.** A node MUST attempt a direct path to `B` before any relayed path when the CC 5.4.6
  conditions hold. *Why:* the CC makes it a MUST, and it is the private path.
  While proposing is held off (§2.4), R1 is satisfied by an existing one-hop path only.
- **R2.** When no direct path exists, the node MUST choose among eligible relays (§3.3) using the
  parent selector (§4), with contact relays ranked before the canonical. The canonical's score MUST
  NOT be compared with contacts' scores. It is a separate, last tier, entered only when the eligible
  contact set is empty, or every member is `Down`, `Suspected` or refusing. *Why:* scoring the canonical
  alongside contacts would make it win often, since it is usually the best-provisioned and
  lowest-RTT candidate. That is the herding the design exists to prevent.
- **R3.** A node on the canonical tier MUST keep probing its contact tier with the selector's
  jittered backoff, and MUST move back make-before-break when a contact relay admits it.
  *Why:* the canonical is a fallback, not a resting place.
- **R4.** First contact, discovery, path requests and the pre-seal route fetch MAY use the canonical
  freely (`control` class). *Why:* a stranger has no contacts yet. Eric's 2026-10-30 ruling has the
  canonical relay the contact-consent request itself.
- **R5.** A relayed link MUST be a Reticulum-layer relay, so the E1 seal stays end to end between
  `A` and `B`. A relay MUST NOT terminate and re-seal a non-A/V flow. *Why:* an application-layer
  relay would see every replication row in the clear under its own seal, and identity-plane rows have
  no other confidentiality layer (§5.1).

### 3.2 What "offering relay" means

A node **offers relay** iff all four hold:

1. **It forwards.** `enable_transport = true` (`reticulum.rs:1961`).
2. **It is reachable without the canonical.** It has a public listener (TCP or UDP server interface,
   port-forwarded, UPnP or IPv6), or it can bring a direct link up with the requester.
3. **It says so, signed.** It publishes a hybrid-signed **relay offer** row (proposed
   `transport:relay_offer:v1`), containing:
   - the node key, its reachable endpoints and the interface kind;
   - the flow classes it carries;
   - a servable-capacity bucket (AV_ALM_DESIGN §5.1: denominated in whole class units, re-signed only
     on a bucket crossing);
   - `epoch` and `valid_until` **inside the signed preimage**. *Why:* the existing
     `SignedRelayCapacity` leaves freshness unsigned (§2.5). A replayed "lots of capacity" ad must
     fail verification, not just a staleness check.

   The row carries the `infra:transport` self-offer that `resolve_transit_eligibility` (persist#561)
   already reads.
4. **It admits.** It runs C2 admission (§4) and answers reservation requests.

**Default.** Offering relay SHOULD be on by default for every node whose budget class is `server`,
`home` or desktop on an unmetered link. *Why:* Eric's "most/all contacts". Always-on home nodes are
already each person's member-owned mailbox (the 2026-11-01 mobile ruling), so they are the natural
relays, and they already hold the person's room traffic.

**Phones (RULED, Eric 2026-11-01).**

- **P-R1.** A phone MUST offer relay while, and only while, BOTH of these hold:
  - it is on an unmetered network (Wi-Fi or Ethernet that the OS reports as not metered);
  - it is on external power.

  It MUST NOT offer relay otherwise: on cellular, on a metered Wi-Fi, on battery, or while the host
  has suspended it. *Why:* relaying spends uplink and battery, and both are free only under those
  two conditions. A phone that cannot pay them is a poor relay anyway, because it suspends without
  warning.
- **P-R2.** When either condition ends, the phone MUST withdraw its offer at once. It MUST stop
  admitting new reservations and attachments, and MUST re-sign its relay offer with a zero bucket,
  or let it lapse at `valid_until` if it cannot sign in time.
- **P-R3.** The phone MUST hand off what it is already relaying make-before-break. It sheds each
  reservation and attachment with `ShedReason::UpstreamLost` (reason label `relay_conditions_ended`).
  It keeps forwarding until the requester's selector confirms the new path (`mbb_confirm_chunks`
  frames over `mbb_confirm_ms`), or until a handoff budget of `down_silence_ms` (5 s) passes,
  whichever comes first. Then it releases the path. *Why:* power and network changes are routine,
  and they must never cut a relayed call or round. The requesters' standbys absorb the handoff, as
  in §10 S3.
- **P-R4.** If the host suspends the phone before the handoff completes, it closes the relayed links
  immediately. That is the C6 `Down` path (§4.2): requesters fail over to their standbys within the
  S3 bound. *Why:* a suspended phone has no sockets (the 2026-11-01 mobile ruling), so a clean
  handoff is not possible.
- **P-R5.** Conditions are re-checked on every OS network or power change event. The offer comes
  back only after both conditions have held for `recover_clean_ms` (5 s). *Why:* this damps
  plug/unplug and Wi-Fi flap, so the offer does not oscillate.

**Endpoint disclosure.** The relay offer reveals a public address. It MUST be served only to the
offering node's send set, exactly as consent-gated routes are (§2.3). *Why:* the same reasoning as
direct-link accept (`direct_path.rs:100-104`): only a party already consented to learns the address.

### 3.3 Who may relay for whom

A relay `C` is **eligible** to carry `A`'s traffic to `B` iff:

- **E1, `A` consents to `C`.** `C`'s node is in `A`'s resolved send set: a `consent:replication`
  grant (a contact), an owner-routed node, own devices, or family. Room co-membership is enough
  only for flows of that room. *Why:* `C` will see `A`'s traffic metadata (§5.1), and the send set is
  the existing statement of whom `A` shares with.
- **E2, `C` consents to `A`.** `A` is in `C`'s send set. *Why:* relaying spends `C`'s owner's
  uplink; the owner decides.

**RULED (Eric 2026-11-01).** The existing `consent:replication` grant, meaning the send set in both
directions (E1 and E2), is sufficient to make a contact eligible as a relay. There is no separate
relay grant. A node that does not want to relay simply does not offer (§3.2). *Why:* the grant
already states whom each side shares traffic with. A second grant would be a second rule owning the
same decision.
- **E3, `C` can reach `B`.** `B` is attached to `C` (§3.4) or is otherwise one hop from `C`.
- **E4, `C` passes the transit gate.** It is a directory-present `node`, self-offers
  `infra:transport`, and shares a valid trust root with `A` (`transit_gate.rs:13-20`).

The canonical satisfies E3 and E4 for everyone and needs no E1 or E2 (it is unowned infrastructure).
That universality is exactly why it is the last tier and not a peer in the ranking.

### 3.4 Attachment: how a hard-NAT node becomes reachable through a contact

A hard-NAT node `B` keeps **attachments** to relays it chose: a primary and one warm standby.
It publishes the set as a consent-served **reach row**: "reach me via `{C1, C2}`, valid until …",
hybrid-signed and served on the same rule as its route row. A dialler `A`:

1. reads `B`'s reach set and intersects it with `A`'s own eligible relays;
2. attaches to the best `C` in that intersection (an interface to `C`'s listener), if it is not
   already attached;
3. dials `B` with the path steered through `C` (§3.5).

If the intersection is empty, `A` falls to the canonical tier for `B` (R2). In the attachment
decision, `B` is the subscriber, the relay is the parent, and `B` is reachable through it. In the
per-link decision, `A` is the subscriber of a reservation on the same relay (§4).

### 3.5 Path steering: the leviculum asks

Edge cannot satisfy R2 without choosing the next hop. These asks are not yet filed:

- **L1, steer a path.** A host-installed path entry for a destination via a named transport id on a
  named interface. It must survive announce-driven replacement for a TTL, and `remove_path` must
  revert it. *Why:* the path table holds one entry chosen by hops and recency (§2.2). A 2-hop path
  via a contact and a 2-hop path via the canonical tie, and the newer announce wins.
- **L2, a directed path request.** `request_path` sent on one interface only. This would complete
  edge's ignored `on_interface` (`reticulum.rs:7610`).
- **L3, a per-forwarded-link meter and cap at a transport node.** Bytes and packets per `link_id`
  forwarded, plus a host-set token bucket per link with a host callback on breach. *Why:* a relay
  cannot see inside a relayed link (R5), so admission (C2) and the canonical's class policy (§6.4)
  are enforced on rates per `link_id`.
- **Also needed:** leviculum#89 (two-sided punch commit) and CIRISEdge#926 (stall guard), for R1.

---

## 4. Same primitives as the ALM mesh

### 4.1 The mapping

| ALM A/V role | Transport-relay role | Notes |
|---|---|---|
| **Stream** | A **relay reservation**: one relayed link `A ↔ B` through `C`, with a flow class | Links are bidirectional, so the commitment counts both directions |
| **Publisher** (depth 0) | The far endpoint `B` | `B` is the parent's upstream: `C` must hold `B`'s attachment (E3), as an A/V relay must be receiving the stream (`Offer::forwarding`) |
| **Parent / forwarder** | The relay `C` | Runs `Admission::relay`. `Offer.depth = 1`, `ancestry = [B]` |
| **Subscriber** | The dialler `A` (per link). The hard-NAT node `B` (per attachment) | Runs `ParentSelector` |
| **Primary** | The relay the live link rides | |
| **Warm standby** | A second relay with a live, sealed, keepalive-only link (or attachment) | The A/V standby is audio-only. The transport standby is keepalive-only, about 0 bps, and measured by real keepalive RTT and delivery |
| **`Role::Primary` / `Role::Standby` cost** | Measured bidirectional rate of the reservation's class / keepalive rate | `ControllerConfig::role_bps` |
| **Offer (C3)** | The relay's per-requester offer on the requester's own sealed link to `C` | The headroom is the relay's C2 answer, not its signed bucket |
| **Signed capacity ad** | The `transport:relay_offer:v1` bucket (§3.2) | A slow-loop discovery hint only; admission uses `min(advertised, measured)` |
| **Shed** | The relay sheds the reservation (`OverCommitted`, `UpstreamLost` when `B` detaches) | The requester fails over to its standby |

Multi-hop does not arise. A relayed transport path is depth 1 by rule (one relay). A path through
two relays is not offered, and `max_depth = 1` for the transport class. *Why:* every extra relay adds
an observer (§5.1) and a failure point. The parent's ancestry is then `[B]` alone, and the
controller's loop checks are trivially satisfied.

**Two kinds of parent, never confused.**

- A **transport-layer parent** is a forwarder `C` on the path of ONE link between two endpoints. In
  a call, those endpoints are two members. `C` carries that one link's ciphertext 1:1 and nothing
  else.
- An **ALM media parent** is a node in a stream's ALM tree. It receives a stream and fans it out on
  several downstream legs.

A non-member, whether a contact or the canonical, may only ever be a transport-layer parent. ALM tree
nodes are members (the MCON floor; CC 6.1.6). The rules are in §4.4.

### 4.2 Component by component

The controller is generic over `P: PeerRef` and does no I/O (`controller/mod.rs` docs, branch
`feat/alm-controller`). The transport class reuses the same types. Its only change is a class
config, `ControllerConfig::transport_relay()`, with the same structure as `::interactive()`.

- **C1 PathMeter (per path, both directions).** Inputs are leviculum `link_stats(link_id)` diffs
  (`driver/mod.rs:3816`; edge's per-link `LinkCounters`, `realtime_av_alm/capacity_estimator.rs:141`,
  `reticulum.rs:7141`), Channel delivery and `Busy`/pacing rejections, keepalive RTT and
  `last_inbound_ms`. Outputs are delivered bps, loss with a burst flag, `min_rtt`, stability and
  `measured_sustainable`.
- **C2 Admission (at the relay).**
  `usable = min(advertised, measured) − committed − reserve`, with commitments never above
  `commit_fraction = 0.65` of measured. There is one trial slot while unmeasured, and the most recent
  admittee is shed first (LIFO) on sustained over-commit.

  `measured` recovers. A ceiling with no congested window for 30 s is stale and forgotten, and growth
  returns to the probe allowance; each ceiling learned again stands twice as long, up to 240 s. A
  publisher's `measured` is never read below one stream. *Why:* a ceiling rises only on a window that
  sent more than it, and a forwarder shed down to it sends less and offers no room, so nothing else
  could lift it. A publisher is the one path nothing replaces: with no child, its stream reaches
  nobody and no relay has anything to offer. An advertised cap and the uplink's other streams still
  bind, and a forwarder flagged for over-claiming keeps its ceiling.

  For a transport node, `measured` is a **vector**: egress bps *and* forwarded packets/s. `usable`
  is the minimum across both. *Why:* a relay's forwarding runs under leviculum's single node lock
  (leviculum#29), so packet rate can bind before bytes (§6.2). This is the one extension to C2, and
  it is a resource vector, not a new rule.
- **C3 Reservation frame.** `Subscribe { role, class }`, `Unsubscribe`, `Admit`, `Refuse { reason,
  retry_after }`, `Shed { reason }`. They are carried on the requester's own sealed link to the relay
  (A/V carries them on the subscriber's leg). The reservation names the relayed `link_id` once that
  link is up, so the relay meters it (L3). An unreserved relayed link gets the **default allowance**:
  the `control` and `replication` classes at the relay's shaping class rate (`server` 7000 B/s per
  link, SHAPING doc table). *Why:* bootstrap and replication must never wait on a reservation round
  trip.
- **C4 ParentSelector.** The same score `S = w·(delivery, headroom, −latency, stability)` (weights
  0.45/0.15/0.25/0.15 in `::interactive()`), with:
  - 20% hysteresis held for 3 windows;
  - 10 s minimum dwell, and failure switches at most 1 per 2 s;
  - jittered backoff `U(0.5,1.5)·base·2^k`, capped;
  - a 10% pick band with a seeded random tie-break (`selector.rs` `PICK_BAND`);
  - make-before-break: the new path must be sealed and must deliver `mbb_confirm_chunks = 8` frames
    over `mbb_confirm_ms` before the old one is released;
  - a warm standby.

  Eligibility (§3.3) is `set_eligible`. Trust never enters the score.
- **C6 Peer states.** `Available → Degraded → Suspected → Down → Recovering`
  (`controller/peer_state.rs`). They are driven by link silence (`suspect_silence_ms`
  = `PARENT_SILENCE_HEAL_MS` 1500, `realtime_av_alm/heal.rs:74`; `down_silence_ms` 5 s), loss over
  `degraded_loss`, and the #926 stall guard (N zero-landed Channel sends make a link `Down`).
  Suspicion never emits a trust or scores-plane signal.
- **C7 Decision log.** The same SHA-256-chained `DecisionLog`, with the kinds attach, detach,
  reserve, refuse, shed, promote, and tier change (contact ↔ canonical). Every field decision replays
  in the sim from its seed.

### 4.3 Which flows ride a relayed link

| Flow | Contact relay | Canonical (§6.4) |
|---|---|---|
| `control`: path requests, route fetch, CTKX, C3, first contact, push-to-wake registration | yes | yes, always |
| `replication`: identity rounds, community rounds to member mailbox nodes, chat rows, scoped bodies on the identity link (CC 5.4.6) | yes | yes, at the default allowance |
| `bulk`: blob and file chunks | yes, admitted | yes, admitted within a small committed fraction, lowest priority, preemptible |
| `audio` | yes, admitted | fallback only, admitted within a small fraction |
| `video` | yes, admitted | **no** |

A/V on a contact relay has two shapes:

- **Member relay (app layer).** The relay is a room member, so it holds the DEK and, with source
  authentication, cannot forge. This is today's `CallOptions::relay`, replaced by C3 admission.
- **Non-member forwarder of one member-to-member leg.** The relay is a contact. This is new work:
  A/V legs today dial derived addresses and are one hop (§2.5). It is permitted by the existing CC
  text, under the conditions in §4.4.

### 4.4 A non-member contact forwarding a room's call (CC answer, 2026-11-01)

**Source.** The CC answered Q4 from the existing text, with no new ruling needed:

- CC 5.4.6, the forwarder paragraph: a forwarder is a ciphertext relay, never handed anything naming
  the room;
- read with CC 5.3.3.5 E1 item 1: every byte on an RNS link is under the per-link hybrid seal;
- and the CC 6.1.6 ALM tree: tree nodes are members.

rc16 adds one sentence naming live media explicitly.

**YES, under all of M1–M6:**

- **M1. No direct path.** A non-member MAY forward a member-to-member call link only when no direct
  path between the two members exists. The direct path MUST be preferred (R1). When one appears, the
  leg MUST move to it make-before-break and the forwarder MUST drop out. *Why:* CC 5.4.6 makes
  direct a MUST, and direct is the zero-observer path.
- **M2. One link, 1:1, never a fan-out.** The forwarder carries one member's link ciphertext to one
  other member. It MUST NOT be a fan-out point of the call's ALM tree. The selector MUST enforce this
  structurally, as follows.
  - The forwarder MUST be modelled as a transport-layer parent (§4.1). It is never an `Offer`-issuing
    media forwarder: it publishes no `Offer` for the stream and runs no stream `Admission::relay`.
  - `ParentSelector::set_eligible(p, true)` for a stream's *media* parent MUST be refused for any
    `p` that is not a live room member.
  - A non-member's admission ledger MUST hold at most one reservation per (stream, upstream member).
    That reservation names exactly one relayed `link_id`. A second downstream leg of the same stream
    through the same non-member is refused (`RefuseReason::NotMember`, a new variant, token
    `relay_nonmember_fanout`).

  *Why:* MCON (members-only tree nodes) is the CC 6.1.6 floor. A non-member fan-out point would
  learn the call's membership shape and become a single point of failure for several members.
- **M3. No custody.** The forwarder retains nothing beyond its transport (link) table. For live
  media it buffers nothing beyond forwarding a frame, and a chunk past its window is dropped, not
  queued. The sealed mailbox (store-and-forward, LXMF) is for envelopes and MUST NOT accept live
  chunks. *Why:* custody of live media would make the forwarder a recorder and a presence oracle,
  which is the LXMF distinction in `src/transport/lxmf_serve.rs:215-250`.
- **M4. Nothing that names the room.** A non-member forwarder MUST NOT receive or verify
  `StreamKeyBinding`s. It forwards hop-sealed frames opaque, because they are inside the A↔B link
  under E1 and it is not a link endpoint. Binding and trailer verification are for member relays
  and receivers only. *Why:* the binding names the room, publisher and stream, and CC 5.4.6 says a
  forwarder is handed nothing naming the room.
- **M5. What it learns is the CC 1.13.3.1 concession and no more.** That is: a link exists between
  two announced endpoints, and its timing and sizes. It holds no grant for the pair, and serves no
  owned route for either endpoint.
- **M6. Consent.** The forwarder MUST be a consented contact, in both directions, of at least one
  endpoint. §3.3 E1/E2 meet this: the requester or the attaching node consents to the forwarder and
  the forwarder to it. Lending a device as a relay is the owner's own setting, with its cost stated
  to the owner (uplink, battery, metadata exposure). That is the same shape as the onion-relay device
  policy, and matches the phone default in §3.2 P-R1.

**The canonical as a non-member forwarder.** It is bound by M1–M5, and additionally by §6.4: audio
only, never video.

---

## 5. Security and privacy

### 5.1 What a relay sees

- **A transport relay (R5) sees:**
  - the link request's destination hash;
  - the `link_id`;
  - packet sizes, timing and volume in each direction;
  - the interface each end arrives on, and so their IP addresses where the interface is IP;
  - anything in path requests and announces.
- **It does not see:**
  - any frame content. Every frame is under the E1 hybrid seal keyed between the endpoints
    (`link_seal.rs:61-72`), inside RNS link encryption;
  - scoped bodies, chat content, blob chunks and A/V. These carry their own content DEKs on top:
    community DEK and key_grant v2 (X25519 + ML-KEM-768), MLS 0x004D, and the A/V stream-epoch DEK
    (`av_call_key.rs` `stream_epoch_dek`).
- **Traffic analysis is the residual.** With a contact relay, the relay learns that `A` and `B` talk,
  when, and how much. That is why E1 requires `A`'s consent (§3.3). Link shaping (CC 5.4.3), where
  on, makes a shaped link a constant-rate stream to a relay ("a relay / third edge: nothing beyond
  the wire", SHAPING doc). A/V and other unshaped links stay observable.
- **The canonical, as today's default relay, sees this metadata for every relayed pair.** Moving
  traffic to contact relays spreads that knowledge across parties each pair chose, instead of
  concentrating it in one place. That privacy gain from R2 is independent of the bandwidth argument.
- **An app-layer A/V member relay** (`CallOptions::relay`) additionally opens chunks: it holds the
  DEK as a member (`av_call.rs:1898-1903`). It is a co-member, so this discloses nothing it is not
  already entitled to. Source authentication stops it from injecting into another member's stream.

### 5.2 Trust gates eligibility, never the weight

Eligibility (§3.3 E1–E4) is a boolean filter applied before scoring. The score uses only measured
delivery, headroom, latency and stability. *Why:*

- a trust-weighted score lets a highly trusted but overloaded relay attract everyone (herding by
  reputation);
- it turns congestion into a trust event, against "give grace" (AV_ALM_DESIGN §6);
- it makes selection depend on slow-loop reputation reads in the fast path.

The slow loop still exists. Edge emits measured-vs-claimed observations to the scores plane, and
LensCore scores them (AV_ALM_DESIGN §7). A relay whose corroborated score falls below a root's
threshold drops out of E4. That is an eligibility change, not a weight change.

### 5.3 What a malicious relay can and cannot do

| Attack | Possible? | Bound |
|---|---|---|
| Drop or withhold | yes | C1 sees loss or silence. C6 moves it to `Suspected` in 1.5 s and `Down` in 5 s at depth 0, scaled by (2+depth)/2 for a relay deeper in the tree (2.25 s and 7.5 s at depth 1). The warm standby takes over (make-before-break where degradation is gradual), within the failover bound (§10 S3). **Not covered:** with no other path delivering, the idle check reads silence as an idle stream, so a sole black hole, or a primary and standby that both drop, does not fail over (CIRISEdge#945). Standing is per call and has no memory, so a repeat dropper pays only the bound each time |
| Delay or jitter | yes | The latency term and `Degraded` state. The switch waits for the hysteresis and dwell |
| Replay frames | no effect | E1 per-lane replay window (`link_seal.rs:70-72`). A/V has the per-hop dense counter and the `(stream, epoch, chunk_seq)` dedupe |
| Lie about capacity | yes, briefly | Admission uses measured capacity: live admissions pass no advertised figure, so `min(advertised, measured)` reduces to measured and the over-claim flag cannot fire. A cold relay gets one trial slot, so there is no herd at t=0 |
| Replay an old relay offer | no, on one link | CALM OFFER is unsigned; the E1 per-lane replay window refuses a repeat. Its fields, depth among them, are self-reported by the attributed sender, and a member can claim depth 0 (CIRISEdge#945) |
| Observe metadata | yes | §5.1. This is accepted, and is why E1 requires consent |
| Forge or alter content | no | The E1 AEAD tag fails and the link closes (`link_seal.rs:74-80`). Content is under content DEKs. A/V chunks carry per-stream Ed25519 signatures bound by a hybrid-signed `StreamKeyBinding`. Receivers and member relays drop forgeries (§2.5). A non-member forwarder cannot see the chunks at all (§4.4 M4) |
| Decrypt | no | It never holds link keys or content DEKs, and E1 is hybrid PQ |
| Impersonate `B` | no | The dialler resolves a transit pair authenticated to `B` before dialling (`link_seal.rs:20-30`). A relay answering for `B` cannot complete the KEX |
| Attract traffic (eclipse) | bounded | See §5.4 |

### 5.4 Sybil, eclipse and diversity

- **Sybil.** Candidates come only from the requester's own send set (E1). An attacker must first be
  someone `A` consented to, and minting identities buys nothing, because consent is per identity and
  granted by a person.
- **Eclipse.** A contact relay that is also `B`'s only attachment sees all of `A ↔ B`. It cannot
  read the traffic, but it could drop it all.
  - *Bound:* `B` keeps a standby attachment (§3.4). R2/R3 keep the canonical tier as an independent
    path that no contact controls.
  - *Diversity rule (SHOULD):* `B`'s primary and standby attachments SHOULD belong to different
    owners and, where known, different networks (the selector's `STANDBY_SHARED_DOMAIN_FACTOR` 0.6
    penalty applies with the owner as the domain).
  - *Deferred:* operator- or AS-level diversity (`swarm::diversity`). At depth 1 with a per-person
    consent set, the owner is the meaningful domain.
- **Herding is a security property here too.** A relay that every hard-NAT node picks becomes a
  metadata concentrator. Admission, jitter, hysteresis and the pick band keep picks spread (§10 S1).

### 5.5 The canonical's role, reduced

After this FSD the canonical is:

1. **bootstrap:** genesis-bundle serve TDs and the first link for a fresh node;
2. **discovery and facilitation:** announces, path requests, the pre-seal route fetch, the direct-link
   facilitator, and the relay of the contact-consent request (Eric 2026-10-30);
3. **push-to-wake:** it holds push tokens and wakes a phone with no content. The phone then pulls
   from its member-owned mailbox node (the 2026-11-01 ruling: the canonical holds no room rows or
   blobs);
4. **federation-scope rows:** identity, key-plane and route rows at federation scope;
5. **last-resort relay**, within §6.4.

It is never a required party (CC rc9 I5). It is never the preferred relay (R2), and never a video
relay (§6.4).

---

## 6. Should video be prevented from reflecting off canonicals?

### 6.1 Today it cannot, by accident

A/V legs dial derived addresses that answer one hop only (§2.5). The canonical is not a room member,
so it is not an app-layer relay either. Today no video crosses a canonical, and no audio does
either. The question is about the target: once A/V legs can ride relayed identity links (§4.3), they
can cross *any* transport node, the canonical included, unless a rule says otherwise.

### 6.2 The numbers

**Per-stream wire rates.** Edge is codec-opaque on the call path. `Frame` carries host-encoded bytes
(`av_call.rs:133-142`), and the bitrate is the host's choice: the AV1 wrapper takes `bitrate_kbps`
(`realtime_av_codec/av1.rs:85-89`, `:195-214`), and Opus takes `Option<u32>` kbps
(`opus_voice.rs:86-89`). The working profiles are the scaling model's (FEDERATION_SCALING_MODEL
§2.1: Opus 24 kbps, 720p30 AV1 SVC 2.5 Mbps, BLINKING_DOT ~50 kbps) and the controller's interactive
class (1 Mbit/s video, 64 kbit/s audio standby; `ControllerConfig::interactive()`).

Per-chunk overhead:

- 84 B chunk header and tags (`realtime_av.rs:320-333`, `:824`);
- 64 B sender signature;
- about 60 B for the seal and RNS header (estimate).

Payload per packet is a 1321 B Channel on an MTU-1400 path. All-TCP paths can carry about 16 KB
[inf: from the loopback identity-link limit of 16297 before migration, #805 item 8 notes].

| Stream | Wire rate | Packets/s (1321 B MDU) | Packets/s (16 KB MDU) |
|---|---|---|---|
| Opus 32 kbps, 20 ms frames | 0.115 Mbps | 50 | 50 |
| Opus 32 kbps, 60 ms frames | 0.060 Mbps | 17 | 17 |
| BLINKING_DOT 50 kbps @15 fps | 0.075 Mbps | 15 | 15 |
| Video 1 Mbps @30 fps (controller class) | 1.20 Mbps | 120 | 30 |
| Video 2.5 Mbps @30 fps (720p anchor) | 2.95 Mbps | 270 | 30 |

**Per relayed call through one relay.** Each stream enters and leaves the relay once. These are the
relay's egress figures; its ingress is the same.

| Call | Egress | Forwarded packets/s | Egress per call-hour |
|---|---|---|---|
| 1:1, 1 Mbps video + audio | 2.63 Mbps | 340 | 1.18 GB |
| 1:1, 2.5 Mbps video + audio | 6.13 Mbps | 640 | 2.76 GB |
| 4 people all hard-NAT, full mesh, 1 Mbps + audio (12 stream copies) | 15.8 Mbps | 2040 | 7.1 GB |
| 1:1 audio only, 20 ms | 0.23 Mbps | 100 | 0.10 GB |
| 1:1 audio only, 60 ms | 0.12 Mbps | 34 | 0.05 GB |

**The canonical's capacity.** There is no measured figure in the tree. Assumptions, flagged for
Phase 0:

- **(a)** one VM with a 1 Gbit/s NIC;
- **(b)** leviculum forwards packets under its single node lock (leviculum#29), at an assumed
  20 µs per packet, so about 50k packets/s if it did nothing else;
- **(c)** the same lock and process already carry every replication link of the federation hub. In
  #930 that hub was CPU-bound on replication alone: one thread at 99% for hours before server
  0.5.243, and about 800 indexed reads/s after it, across 7,226 federation keys.

At the 65% commit ceiling (650 Mbps; 32.5k packets/s):

| Call mix through the canonical | Saturates on bandwidth at | Saturates on the lock at (assumption b) |
|---|---|---|
| 1:1, 1 Mbps video | 247 calls | **95 calls** |
| 1:1, 2.5 Mbps video | 106 calls | **50 calls** |
| 4-person hard-NAT mesh, 1 Mbps | 41 calls | **16 calls** |
| 1:1 audio, 20 ms | 2,800 calls | 325 calls |
| 1:1 audio, 60 ms | 5,400 calls | 955 calls |

**The comparison that decides it.** One relayed 1 Mbps 1:1 video call costs the canonical 2.63 Mbps
of egress. That is the full shaped λ of about 47 `server`-class replication links at 7000 B/s each
(SHAPING doc). Those 340 packets/s also take the same node lock, and every replication frame of
every peer of the federation hub waits behind them. With the lock assumption, 16 four-person
hard-NAT calls saturate the canonical outright: all of its forwarding, before any replication.
At a CPU-bound hub (#930) the real number is lower.

### 6.3 Options considered

1. **No rule; the canonical admits video through C2 like any relay.** Rejected. The canonical is the
   one candidate every hard-NAT node can reach, so its admission is always full and becomes a
   first-come lottery. Its failure domain is the federation itself (bootstrap, KEX, push-to-wake,
   replication), and a call could degrade first contact for strangers. It also concentrates call
   metadata.
2. **A per-class cap on video at the canonical** (for example, 5% of measured). Rejected. 5% of
   650 Mbps is about 12 one-to-one 1 Mbps calls, or fewer on the lock. That is too few to matter as
   a service, so it would mostly create unpredictable quality ("video works until the 13th call")
   while keeping all the failure-domain coupling.
3. **Hard refusal of video, small admitted audio fallback.** Chosen. Audio costs 4% (60 ms framing)
   to 9% (20 ms) of the egress, and 10–30% of the packet rate, of a 1 Mbps video call. It keeps a
   call alive for the rare pair with no contact relay, and stays inside a budget that cannot threaten
   replication.

### 6.4 The ruling (normative)

- **V1.** A canonical MUST NOT relay `video`, at any layer, including the base layer and BLINKING_DOT.
  *Why:* §6.2–6.3. One rule with no layer arithmetic is predictable and testable.
- **V2 (RULED, Eric 2026-11-01).** A canonical MAY relay `audio` as a fallback. Audio reservations go through the same C2
  admission with a class ceiling of **5% of measured egress and 5% of measured forwarding
  packets/s**, and no trial slot. *Why:* a bounded, admitted fallback keeps calls alive. 5% of the
  assumed capacity is about 25–73 one-to-one audio calls on the lock (20 ms vs 60 ms framing), and
  ample on bandwidth. The fraction is a config value, revisited with Phase 0's measurements.
- **V3.** A canonical relays `bulk` only within a committed fraction (default 5%), preemptible by
  `replication` and `control`. It relays `replication` at the default allowance, and `control`
  always.
- **V4.** Refusals use stable tokens:
  - `relay_class_refused:video` (V1);
  - `relay_capacity:audio` (V2 ceiling);
  - `relay_capacity:bulk` (V3).

  They are carried in C3 `Refuse` with a jittered `retry_after`, counted by label, and surfaced to
  the host as a call event.
- **V5.** Enforcement is two-sided, because the canonical cannot see the class inside a relayed
  link (R5):
  - **Endpoint (primary).** A leg whose path's next hop is a canonical (its transport identity is in
    the bundle's `serve_transport_destinations`) MUST send audio only and MUST hold an `audio`
    reservation before sending.
  - **Canonical (backstop).** It meters each relayed `link_id` (L3). A link exceeding its
    reservation, or the default allowance when it has none, for more than one 10 s window is
    throttled. After a second window it is torn down with the V4 token.

  *Why:* honest endpoints never trip the backstop, and a dishonest or buggy one cannot turn the
  canonical into a video relay.

### 6.5 Graceful degradation: when only the canonical can relay

The call MUST continue as **audio-only**:

- the host gets `CallEvent::VideoUnavailable { reason: "relay_canonical_audio_only" }`;
- outgoing video is paused, not dropped silently;
- the receivers' video tiles show the paused state.

Meanwhile the selector keeps probing the contact tier (R3) and the direct path (R1), with jittered
backoff. When a contact relay admits the call, or a punch succeeds, video resumes make-before-break:

1. the new path delivers `mbb_confirm_chunks` frames and passes the dwell;
2. the audio leg moves;
3. video resumes on the new path.

If the canonical refuses audio as well (V2 ceiling), the call reports `relay_capacity:audio` and
retries on backoff. A call MUST NOT fall back to an unadmitted path.

---

## 7. Load shedding: the service ladder (Eric, 2026-11-01)

**Direction.** Eric, verbatim:

- "make sure we can shed load using the same approach agent does with capacity monitoring — edge can
  help us identify and shed load", for "audio calls and relayed peers";
- "The idea is we degrade from full ops, to audio and files, to supporting basic chat/contacts etc...";
- hot paths are to be treated "like a router".

This section is normative for every node: the canonical, home nodes and phones alike. §6.4 is the
canonical's *standing* class policy. This ladder is how *any* node degrades under pressure.

### 7.1 Authority: what a node may shed on its own, and what it may not

- **L-A1. Transport load is the node's own decision.** A node MAY shed its A/V relay load at any
  time, under any tier:
  - relayed links it admitted;
  - A/V relay legs;
  - its relay offer.

  It does not close forwarding on a tier. A canonical is the last relay tier, so a link it refuses
  has nowhere else to go, and the dialler's next try is one more request (Eric, 2026-11-06; v44
  turned one refused dial into 48 retries and stalled first contact for the ladder's cooldown).
  What bounds forwarding is a configured link bound and the link table's cap, fixed process bounds
  set before the node starts.

  *Why:* this is a node's own transport decision, the same as refusing a link (CC 5.3.3.5 E1 item 1,
  under which a responder serves nothing and tears down on a named refusal). The CC reads lending a
  device as a relay as the owner's own setting (§4.4 M6, §3.2 P-R1).
- **L-A2. Federation duty is not edge's to drop.** The following stay under **report-then-relief**:
  - serving replication as a seated canonical;
  - rounds owed to the send set;
  - acked custody.

  The node reports its pressure via `config:load`. The relief comes from the root's `mesh_config`
  `load.ceiling` (CC 4.2.1, #503). Edge MAY stretch or reorder that work under any tier: lengthen a
  round interval, page smaller, serve obligation peers first. It MUST NOT drop it locally. *Why:* a
  duty another node relies on can only be relieved by the authority that imposed it. A locally dropped
  round is a silent refusal (the "closed gate files no bug" class).
- **L-A3. The never-shed set**, served at full rate under every tier:
  - the node's own devices and its owner;
  - federation duty (L-A2);
  - `control` traffic: KEX, route fetch, path requests, first contact, push-to-wake;
  - the minimum viable role of a transport node, which is what first contact needs (CC 5.4.6):
    forwarding link requests and keyed links, answering subject Pulls for keys, occurrences, routes
    and owner bindings, and announces;
  - revocations of every kind.

  *Why:* shedding any of these turns pressure into a security or availability failure instead of a
  quality loss. A revocation that waits behind load is a key that stays trusted.

### 7.2 The tiers

A tier is a set of shed levers. Each tier includes every lever of the tiers above it.

| Lever | Tier 0, full ops | Tier 1, audio + files | Tier 2, basic chat + contacts |
|---|---|---|---|
| **V-shed:** video and heavy A/V on legs this node relays. Relayed legs are degraded to base/audio layer (`set_layer_policy` toward `BLINKING_DOT`, then audio only); standbys go keepalive-only | – | **on** | on |
| **Admit-close:** no new relay reservations or A/V relay legs; C2 answers `Refuse { retry_after }`; the relay offer is re-signed with a 0 bucket. Forwarded links are not relay work here and are admitted at every tier | – | **on** | on |
| **Stretch:** expensive non-obligation replication rounds, i.e. rounds to relayed peers that are not the owner, own devices or the send set. Moved to the host's `walk` lever (§7.7); the tier does not pull it | host | host | host |
| **A-shed:** audio relay legs this node carries are shed newest-first (LIFO, `ShedReason::OverCommitted`, token `load_shed:audio`), each with a `Shed` notice so the requester moves make-before-break | – | – | **on** |
| **B-pause:** a shaped link's slow path for non-owner peers waits. Blob swarm pulls and the durability pass are the host's `bulk` lever (§7.7), and the tier does not pull it | – | – | **on** |
| **Own A/V:** this node's OWN call (as a publisher and receiver) | full | full; video is host-degraded on `CallEvent::LoadTier` | audio only |

**What keeps working.**

- **Tier 1:** audio calls (direct, or through other relays), file transfer, chat, contacts, and all
  never-shed traffic. The node stops *carrying others'* heavy A/V, and stops taking new relay work.
- **Tier 2:** chat rows, contact requests and acceptances, the owner's own devices at full rate, and
  the never-shed set.

**Mapping each lever to planes and flows.** The planes are `EnvelopeKind`,
`src/replication/protocol.rs:113`.

| Plane / flow | Class | Tier 1 | Tier 2 |
|---|---|---|---|
| `Key`, `IdentityOccurrence`, `TransportDestination` (bootstrap kinds) | never-shed (L-A3; first contact depends on them) | full | full |
| `Revocation`, `IdentityOccurrenceRevocation`, `FamilyMembershipRevocation`, `CommunityMembershipRevocation` | never-shed | full | full |
| `AccordQuorumEvidence` | federation duty | full | full |
| `KeyGrant` | chat needs it to open content | full | full |
| `Family`, `Community`, `CommunityMembershipWidening`, `FamilyMembershipWidening`, `CommunityMembershipListing` | contacts and rooms | full | full |
| `Attestation`, `chat:*` and `consent:*` rows | chat and contacts | full | full |
| `Attestation`, everything else (file descriptors, call rows, scores, other) | ordinary | Stretch for non-obligation peers | Stretch ×8; file descriptors still flow so a paused file resumes |
| `LocationProof`, `Organization`, `OrgMembership`, `PartnerRecord` | ordinary | Stretch for non-obligation peers | Stretch ×8 |
| Blob/file chunk transfer (blob swarm), the durability pass | bulk | full | B-pause (own devices' self-tier durability excepted, L-A3) |
| A/V: legs this node *relays* (member relay or non-member forwarder) | relay | V-shed, Admit-close | A-shed |
| A/V: this node's own call | own | host-degraded video | audio only |
| Transit: relayed links this node forwards (RNS transport) | never-shed (L-A3) | full; configured per-link caps (L3) hold at every tier | full |

An `Attestation` row is classed by its attestation type prefix. That is a field the row is already
routed on (§7.5), so classification reads no row body.

### 7.3 The signal path

This mirrors the agent's resource monitor
(`ciris_engine/logic/services/infrastructure/resource_monitor/service.py:179-213`):

- sample every 1 s against a budget;
- `warning` and `critical` thresholds per resource, each with a cooldown;
- actions throttle, defer, reject or shutdown on a bus;
- each consumer decides what to do.

- **L-S1. Host pressure from the server.**
  - The server samples the host: CPU, RSS, DB read time from persist's observe surface, and per-call-site
    read time.
  - It calls `Edge::set_load_pressure(LoadPressure::{Normal, Warning, Critical})` (new API; also in
    PyO3).
  - Normal maps to tier 0, Warning to tier 1, Critical to tier 2.

  *Why:* the server already owns the host budget, as the agent's monitor does. It reads edge's gauges
  beside its own and pulls edge's levers (§7.7).
- **L-S2. Edge's own signals** MAY raise the tier and never lower it below the host tier:

  | Signal | Tier 1 | Tier 2 |
  |---|---|---|
  | Relay commitments ≥ 0.65 × measured on either resource (§4.2 C2), sustained 3 windows | raise | — |
  | A/V inbound queue age > 800 ms (2 × `REORDER_WINDOW_MAX`, `av_call.rs:94`), sustained 3 windows | raise | — |
  | Forwarded pps ≥ 65% of measured forward capacity (L3) | raise | — |
  | Forwarded pps ≥ 90% of measured forward capacity | — | raise |

  The effective tier is `max(host tier, edge tier)`.
- **L-S3. Asymmetric hysteresis.**
  - **Raising** takes effect at once.
  - **Lowering** is one step at a time, and only after every input has stayed below its lower
    threshold for a cooldown: 60 s from tier 2 to tier 1, and 120 s from tier 1 to tier 0. The lower
    threshold is the raise threshold × 0.8.

  *Why:* react fast to degradation, recover slowly (GCC's `K_u ≫ K_d`, AV_ALM_DESIGN §4). Shedding
  costs requesters a make-before-break move, so a flapping tier would herd them back and forth.
- **L-S4. Every change is logged and counted.**
  - Each tier change and each shed decision is logged with a stable token. The tokens are:
    - `load_tier:{0,1,2}` with the cause (`host:warning`, `edge:relay_commit`, `edge:av_queue_age`,
      `edge:transit_pps`);
    - `load_shed:{video,audio,bulk,transit}`;
    - `load_refuse:admit_closed`;
    - `load_stretch:{plane}`.
  - Each token is counted under its label.
  - Each shed decision is a C7 decision-log record, so a field event replays in the sim.
  - The host gets `CallEvent::LoadTier` and a transport event.

- **L-S5. The host's verdict is a lease.** A verdict not renewed in 30 s lapses to Normal, and the
  tier falls through its cooldowns. *Why:* a dead or wedged server must leave a node that serves, not
  one held at the last pressure it reported.

### 7.4 Identify: the `load_ledger`

Edge exposes a `load_ledger` metrics family with the top N (default 10) cost entries, per peer and per
plane, over a sliding 60 s window:

- **Transit:** bytes and packets/s per forwarded `link_id`, attributed to the requesting peer. This
  needs leviculum#93 (per-link forward accounting; the L3 meter).
- **A/V:** legs and bitrate per relayed stream and per requester.
- **Replication:** rounds per (peer, `EnvelopeKind`), and round read-ms per (peer, plane). This needs
  persist observe attribution, i.e. read time tagged by the caller's (peer, plane) context.

*Why:* shedding without attribution sheds blind. The #930 storm was found by a server-side read probe,
and named only after a manual read of `bridge.rs`. The ledger makes the next one name itself, and lets
the ladder shed the costliest non-obligation consumer first.

### 7.5 The router principle for hot paths

- **The case.** The #930 storm is the Attestation-plane advertise gates running persist's per-row
  folds on every (peer × kind) tick. Those are the owner-of, rooting and audience folds. Per the
  coordinator's count there are about 10 call sites into `list_composers_referencing_any`. Edge's one
  direct call is `src/replication/key_plane_rows.rs:247`; the rest are reached through persist folds
  and were not counted edge-side.
- **The rule.** A router does not recompute its forwarding table per packet. It indexes the fields it
  routes on and looks up.
- **L-R1.** A peer's audience and route set MUST be computed once per consent or membership change and
  indexed on the routing fields. The audience and route set means: the resolved send set and reach,
  owner-routed nodes, room memberships, and route consent. The routing fields are: subject key id,
  attestation type prefix, scope, and owner. A round then joins candidate rows against a ready set.
  Invalidation is event-driven: a new grant, revocation, membership row or owner-binding. It is not
  driven by a TTL. *Why:* today's `fresh_consent_memo` is a 10 s TTL memo
  (`src/replication/bridge.rs:2355`, `:8627`). That bounds staleness but recomputes every 10 s per
  node, whether or not anything changed, and the key-plane listings sweep every Global subject per
  round (`list_revocation_rows` `:9512`, `list_occurrence_withdrawal_rows` `:9531`; #930).
- **L-R2.** Hot logic MUST touch only hot data. The advertise and serve decision for a row MUST be
  answerable from the row's routing fields and the ready set. It MUST NOT read the row body, call a
  per-row persist fold, or read the directory per row. Anything that needs those is computed at
  invalidation time.
- **L-R3.** The ladder's own decisions obey L-R2. Plane class, peer obligation class and tier lookup
  are O(1) reads of the ready set. *Why:* a load-shedding check that costs a fold per row would itself
  be load.

### 7.6 Tests for the ladder

Stretch and bulk moved to the levers of §7.7 and are witnessed there. LS1 and LS2's bulk and
ordinary-round rows read through those levers.

These are sim scenarios in `closed_loop_sim` with a host-pressure input. They use the same seeds, log
hash and soak as §10.

| ID | Setup | Pass criteria |
|---|---|---|
| **LS1 Ordering** | A relay carries 4 video legs, 4 audio legs, 2 bulk transfers, chat and own-device rounds. Pressure ramps Normal → Warning → Critical | Video is shed before audio, and audio before chat: every `load_shed:video` record precedes the first `load_shed:audio`, which precedes any chat-plane effect (there must be none). At Critical, chat rows, contact rows, own-device rounds and revocations are delivered at ≥ 99% of their tier-0 rate |
| **LS2 Never-shed** | Critical for 600 s, with replication from the send set and own devices, a revocation burst, and first contact from a stranger | Every never-shed flow (L-A3) is delivered within its tier-0 latency p95 × 1.2. Zero federation-duty rounds are dropped (stretch or reorder only). Zero `load_shed` records name a never-shed plane |
| **LS3 No flapping** | Pressure oscillates around the Warning threshold at 0.2 Hz with ±10% noise for 900 s | ≤ 1 tier change per cooldown period. Zero tier-1 → tier-0 → tier-1 cycles shorter than 120 s. Requesters' parent changes caused by shedding ≤ 1 per 120 s |
| **LS4 Make-before-break shed** | Tier 2 sheds 4 audio legs from a relay while 3 other contact relays have headroom | Each shed leg moves to another relay with zero frames lost to the move. LIFO order holds by admission time. No requester falls to the canonical while a contact has headroom |
| **LS5 Edge self-raise** | No host pressure. Transit pps climbs to 95% of measured | The tier rises to 1 at 65% and to 2 at 90%. The cause is logged as `edge:transit_pps`. It returns to 0 only after the cooldowns |
| **LS5-mut** | LS3 with the hysteresis and cooldowns set to 0 | MUST fail LS3 |
| **LS6 Router** | 5,000 subjects, 50 peers × all kinds, a steady state of rounds, then one consent grant | Per-round persist reads in steady state are O(rows advertised), not O(subjects × peers): the count is asserted flat as subjects grow 10×. One grant triggers exactly one ready-set recompute for the affected peers |

### 7.7 The host's levers (Eric, 2026-11-06)

Edge implements the gauges and the levers. The server reads and pulls them in concert with its own,
and edge decides nothing here. With no host pulling, every lever is at 0 and the node serves its
whole role.

**The rules, for every lever.**

- **No lever is a scram.** It moves one step at a time: at most one up per 10 s and one down per 30 s.
  Each step halves a cost and none ends one, so no step takes the node off a role. Pulling or releasing
  a lever does not itself cause work: nothing a lever touches is refused, so nothing it does is
  retried, and nothing piles up behind it to burst on release.
- **A lever is a lease.** A pull holds for its lease, at most 300 s, and the host renews by pulling
  again. A lease that runs out walks the lever down at the release pace. A dead or wedged server
  leaves a node that serves.
- **The minimum viable role is not on a lever.** No lever names forwarding, subject Pulls, announces
  or the planes L-A3 keeps. Fixed process bounds stay what they are, and are not levers.

**The levers.** `Edge::pull_shed_lever(lever, level, lease)`, `pull_shed_lever` in PyO3; read back in
`Edge::shed_levers()` and `load_ledger`.

| Lever | Sheds, per step | At the top (3) | Costs | Stays |
|---|---|---|---|---|
| `walk` | Cadence ticks of `Attestation`, `LocationProof`, `Organization`, `OrgMembership`, `PartnerRecord` toward a peer owed nothing, ×2 | ×8 | Convergence with that peer takes longer. A row a peer was not sent by a kick waits up to ×8 cadence | Kicks; every round to own devices, seats and the send set; every other plane. A failed obligation read stretches nothing |
| `page` | The Attestation advertise page, ½, to a floor of 32 rows | ⅛ | The re-sweep and catch-up take more rounds. Bears on every peer, which L-A2 allows | First-contact sweeps; subject Pulls; the rows themselves, which the next round reads |
| `bulk` | The blob puller's concurrent pulls, ½, to a floor of 1; the durability pass runs on every 2nd tick | ⅛, one pull; pass ×8 | Files arrive later; repairs wait | Running pulls finish. Serving chunks to peers: a refused serve is retried, so it is not levered |

**The gauges.** `load_ledger` and the telemetry catalogue.

| Question | Gauge |
|---|---|
| What is forwarded | `forward_links_live`, `forward_admitted_total`, `forward_packets_per_second`, `forward_bits_per_second`, the ledger's top links |
| What is refused | `forward_refusals_total{load_refuse:capacity}`, with an INFO line per move |
| What each plane costs | `replication_round_duration_seconds`, `replication_envelopes_served_total`, `replication_inbound_wait_seconds`, `replication_reply_wait_seconds`, `sweep_permit_wait_seconds`, `responder_rounds_total` |
| Queue and link pressure | `replication_reply_queued`, `seal_keyer_queued`, `seal_held_bytes`, `seal_awaiting_links`, `leviculum_events_queued`, `leviculum_events_dropped`, `leviculum_shed_packets`, `inbound_links`, `outbound_links`, `link_pool_links` |
| What is shed now | `load_lever_level`, `load_lever_lease_seconds`, `load_lever_changes_total`, `load_tier`, `load_tier_changes_total` |

**Tests.** A relay at tier 2 with every lever at the top forwards a stranger's link and serves it the
rows of first contact. A lever pulled to the top and left walks home with no second of the walk above
its unlevered peak, while `Key` and owed rounds keep their cadence and a kick still runs.

---

## 8. Transport tiers and canonical homing: the numbers

Modelled in `FSD/TRANSPORT_TIERS_MODEL.md`, produced by `tools/models/transport_tiers.py`
(`python3 -I`, standard library, seeded). Eric's rulings of 2026-11-04 (CIRISEdge#935,
CIRISConstitution#200), in one paragraph each:

**Three tiers.** *Slow shaped:* every ordinary peer that offers a class. Eric ruled the bound
(2026-11-04, verbatim: "we shape with shaped peers if possible, otherwise refuse and offer unshaped
(bulk transfers) if available"): a node keeps L = 8 shaped links (minus the layer reserve while the
Anonymous Tier runs), each at the full class rate (7,000 B/s on `server`, a 2.3 s gap, 10.7 s p99),
refuses the ninth shaping peer's row link (`link_shaping_home_elsewhere`) so it homes elsewhere, and
still offers it an unshaped bulk link. The accepted trade-off is that the refused peer's bulk link is
a visible spill; the alternative, dividing the cap with no floor, publishes the node's link count on
every link and reaches 29 s gaps at 100 peers and 4.8 min at 1,000 (kept in the model as the
sensitivity arm). The bound caps receive as well as send, 56,000 B/s and 145 GB/month each way. With
every link at the class rate the 15 s / 30 s replication constants hold coalesced and still fail with
one message per frame across the five bootstrap planes, so the model recommends coalescing and
timeouts derived from the agreed λ. *Fast shaped:* the proposed `seat` class between serve seats, own
budget, 2 frames/s recommended: 84 GB/month per link each way, a quarter of the canonical's 4,096 GB
quota at nine seats with today's usage and the slow cap. *Unshaped:* bulk over 64 KiB and live media,
as CC 5.4.3 "two planes" already says. Onion adds no tier and no pairwise negotiation (CC 5.4.6 items
1, 5): a relay's layer links are shaped links inside the reserve.

**Homing (peer of last resort).** Each node ranks the M canonicals by `H(node ‖ canonical ‖ period)`
and homes on the top k = 2; the rest are an ordered fallback. Homed nodes per seat are N·k/M (222 at
1,000 nodes and 9 seats; 2,222 at 10,000), balanced within 1–8 %; under the bound a seat serves L = 8
of them shaped and refuses the rest to bulk, so homing sets who is refused, not a shaped load. One
seat down orphans nobody at k = 2; two down orphan 2.8 % at M = 9, who take their next-ranked seat.
The roll is harmless once each node rolls at its own phase inside the period with make-before-break,
and under the bound it cannot move a slot holder at all (the new home is full and refuses); the
stampede to size for is failover, N·k/(M(M − 1)) dials per survivor over the jitter window. The
seat's shaped slots are a loss system: with no standing links they carry hourly home rounds from a
tenth of 10,000 nodes with under 1 % blocked; standing links consume them for good, so the slots are
the last-resort standing set and every other homed node rounds on the bulk plane. The gauge for the
`load_ledger` (§7.4) is shaped slots held and refusals issued, not homed nodes.

**Prior art, and where it cuts against the rulings.** The model's prior-art section (Tarzan, the
anonymity trilemma, Tor's guard record with Guard Sets, Herd, Loopix) records three contradictions
and models each as an alternative beside the ruled design: a floorless cap/N split is unprecedented
and publishes N on every link (Tarzan and Herd keep the shaped-link count a small bounded constant;
modelled as a bound L with a per-class floor and redirect through the fallback order); per-period
re-homing is a measured net loss for exposure (COGS, Dingledine 2013, Prop 236; modelled against a
stable top-k and a beacon-seeded long period: daily rotation shows a node to all nine seats within
weeks, a stable top-k to 2.4 in a year, and rotation buys no balance the hash does not already give);
and Poisson per link beats slots on observability by Loopix's merging property, slots winning only
the worst-case bound. The first is now ruled (the bound); the second is open for Eric, with the
exposure numbers as the decision table (a stable top-k shows a node to 2.4 of nine seats in a year,
a daily rehash to all nine). The active-dropper warning (Levine 2004, Feigenbaum 2010) is an open item:
edge has no defensive dropping today.

The open CC questions (seat class, rotation vs Poisson, the floor, inbound asymmetry, the dropper)
are listed in that document's §10.

---

## 9. Phases

| Phase | Builds | Depends on |
|---|---|---|
| **P0 Measure** | The canonical's forwarding packets/s and CPU per packet under leviculum's lock, egress baseline, and replication load. Replace the §6.2 assumptions with measured numbers. A bench against a leviculum transport node on canonical-class hardware | none |
| **P1 Controller core** | `feat/alm-controller` stage 1: C1, C2, C4, C6, C7 and the closed-loop sim. Add `ControllerConfig::transport_relay()` and the C2 resource vector (bps and packets/s) | none (in progress) |
| **P2 leviculum** | L1 steered path, L2 directed path request, L3 per-link forward meter and cap. leviculum#89 two-sided punch commit | none (file the asks) |
| **P3 Edge stall guard** | CIRISEdge#926: N zero-landed Channel sends make a link `Down` and it is re-dialled (C6 input). Re-enable direct-link proposing (R1) after #89 | P2 (#89) |
| **P4 Relay offer and reach rows** | `transport:relay_offer:v1` and the reach row, hybrid-signed with `epoch` and `valid_until` in the preimage (CIRISVerify builder: fix the `SignedRelayCapacity` freshness gap in the same change). Consent-served like route rows, which needs consent-gated routes on (persist#1165) | persist#1165, verify |
| **P5 Attachment and steering** | Hard-NAT nodes keep a primary and a standby attachment chosen by C4. Diallers steer through a reach-set relay (L1). C3 reservation on the identity link. The canonical tier as R2's last tier | P1, P2, P4 |
| **P6 A/V on relays** | C3 replaces the `CallOptions::relay` flood (stage 2). A/V legs through a non-member forwarder under §4.4 M1–M6 (selector member-only media parents; the `relay_nonmember_fanout` refusal). V1–V5 at endpoints | P1, P5, source-auth merged |
| **P7 Canonical policy** | V2–V4 admission at the canonical. The V5 backstop via L3 | P2 (L3), P5 |
| **P9 Service ladder** (§7) | `Edge::set_load_pressure`; the tier state machine with asymmetric cooldowns; levers wired to C2 (Admit-close), C3 `Shed` (A-shed), `set_layer_policy` (V-shed), the replication scheduler (Stretch) and the blob swarm (B-pause); the `load_ledger`; the event-driven ready set (L-R1/L-R2). Server: the host sampler. LS1–LS6 green | P1, P5; leviculum#93; persist observe attribution; server sampler. The ready set (L-R1) has no dependency and starts at once |
| **P8 Field witness** | Two hosts behind distinct NATs (network namespaces with NAT rules): direct → contact → canonical ladder, end to end | P5, P6 |

Parallel lanes: {P0}, {P1}, {P2 → P3} and {P4} start together. P5 joins P1, P2 and P4. P6 and P7
follow P5.

---

## 10. Tests and pass criteria

All sim scenarios run in the closed-loop seeded sim (`closed_loop_sim`, branch `feat/alm-controller`)
driving the production controller types. They use 64 seeds in CI and soak under `CIRIS_ALM_SOAK`.
Each prints its seed, decision-log tail and offending node on failure. Every scenario asserts that
the same seed gives the same decision-log hash.

| ID | Setup | Pass criteria |
|---|---|---|
| **S1 No herding onto contacts** | 200 hard-NAT nodes. 40 contact relays with capacities drawn from {5, 10, 20} reservation units. Each node's contact set is a random 8 of the 40. The canonical is present. All join at t=0. 600 s | (1) Every node has a primary attachment by t ≤ 30 s, and ≥ 99% on a *contact*. (2) No relay is ever committed above 0.65 × measured. (3) Per-relay load ÷ capacity: max/min ≤ 1.5 at convergence. (4) After convergence, ≤ 1 voluntary parent change per node per 120 s, and zero A→B→A flips within 3 × dwell. (5) The canonical carries 0 reservations at convergence |
| **S1-mut** | S1 with `herding_mutant()` | MUST fail S1: ≥ 5 A→B→A flips across the population, or a relay above capacity. If it passes, S1 does not test herding |
| **S2 Relay lies about capacity** | S1, but relay R advertises 10× and delivers 1× | Commitments to R ≤ 0.65 × R's *measured* capacity within 2 meter windows. R gets one trial slot at t=0, not a herd. Affected nodes move within dwell + 2 windows. The over-claim flag is raised for R. No affected node falls to the canonical while an eligible contact has headroom |
| **S3 Contact relay goes offline** | A node's primary contact relay vanishes at t=100 s. Variant: it silently blackholes | The standby (another contact) is promoted. `control` and `replication` gap ≤ `suspect_silence_ms` + RTT + one reservation round. A new standby is chosen with jittered backoff, **from contacts first**. The canonical is used only if no contact is eligible; that variant is asserted separately. The decision log shows `Suspected → Down → promote` |
| **S4 Make-before-break** | The primary relay degrades (latency ramp). A better contact appears | The switch happens only after the hysteresis and dwell. The new link is sealed and delivers 8 frames before the old one is released. Zero frames are lost because of the switch. Duplicate bytes ≤ overlap × rate |
| **S5 Canonical saturation** | 200 hard-NAT nodes with *no* contacts, all placing 1:1 calls with video | Zero video reservations at the canonical (V1): every video request is refused `relay_class_refused:video`. Audio commitments ≤ 5% of measured on both resources (V2). `replication` and `control` delivery at the canonical stays within 5% of the no-call baseline. Every call reports `VideoUnavailable` and runs audio-only, or is refused `relay_capacity:audio`, and never sits on an unadmitted path |
| **S6 Recovery to the contact tier** | S5, then 40 contact relays appear at t=200 s | Nodes leave the canonical tier make-before-break within dwell + backoff. Video resumes. The canonical's audio commitments fall to ≤ 10% of their peak by t=400 s. The S1 herding criteria hold during the move |
| **S8 Phone relay loses power or Wi-Fi** | A phone relay (P-R1 satisfied) carries 3 reservations, one of them a call. At t=100 s it is unplugged. Variant: it moves to cellular. Variant: the host suspends it mid-handoff | The offer is withdrawn at once: no admission after t=100 s, and the re-signed bucket is 0. Each reservation moves make-before-break to another contact: zero frames lost because of the handoff, and the phone releases each path only after confirmation or 5 s. In the suspend variant, requesters fail over within the S3 bound. The offer returns only after both conditions have held 5 s, so a plug-flap at 1 Hz yields zero offers |
| **S7 Endpoint dishonesty** | One endpoint sends video on a canonical-relayed link with an audio reservation | The V5 backstop throttles it after one 10 s window and tears it down after the second with `relay_class_refused:video`. Other reservations are unaffected |

**Unit and real-RNS witnesses** (test suffix `_mesh`):

- **W1.** R2 ordering is a pure function: with any eligible contact `Available`, the canonical is
  never chosen. Mutation: comparing the canonical's score with contacts' scores must make W1 fail.
- **W2.** The relay offer refuses a replayed row whose `valid_until` was altered (the signature
  fails) and a row served to a peer outside the send set (withheld,
  `WithholdReason::RouteNotConsented` shape).
- **W3.** Loopback, 4 nodes: `A` and `B` leaves, `C` a contact transport node, `T` a canonical-shaped
  transport node. `A`'s link to `B` rides `C`, checked by the path entry's next hop on `A` *and*
  `C`'s forwarded-link counter. Then `C` stops, and the link re-establishes via `T` within the S3
  bound. The pass criterion names the row: `A`'s decision log shows `tier: contact → canonical`.
- **W4.** Loopback: an A/V leg whose next hop is `T` sends no video frames (counter = 0 on both
  sides) and raises `VideoUnavailable`.
- **W5 (§4.4).** Three checks on non-member forwarders:
  - **(a)** The selector refuses a non-member as a stream's media parent (`set_eligible`), and its
    admission refuses a second downstream leg of one stream through the same non-member with
    `relay_nonmember_fanout`. Mutation: allowing two legs must fail the test.
  - **(b)** Loopback with members `A` and `B` and a non-member contact `C` as forwarder: `C`'s
    binding-verification and binding-received counters stay 0, `C` holds no `StreamKeyBinding`,
    and the call's frames arrive byte-identical at `B`.
  - **(c)** When a direct path between `A` and `B` comes up, the leg moves make-before-break, and
    `C`'s forwarded-link counter for that `link_id` stops.

---

## 11. Open questions for Eric

**Ruled, Eric 2026-11-01** (folded in as normative rules):

1. **Phones as relays: YES.** A phone offers relay on an unmetered network AND external power, and
   only then. It hands off make-before-break when either condition ends (§3.2 P-R1–P-R5).
2. **Relay consent: YES, the grant suffices.** The `consent:replication` send set, both ways, makes a
   contact eligible. There is no separate relay grant (§3.3).
3. **Canonical audio fallback: YES.** Audio-only, through the same admission, capped at 5% of
   measured egress and of measured packets/s. Video is never relayed there (§6.4 V1, V2).

4. **A/V through a non-member relay: YES, answered by the CC from existing text.** CC 5.4.6
   forwarder paragraph with CC 5.3.3.5 E1 item 1 and CC 6.1.6; rc16 names live media. Folded in
   as §4.4 M1–M6.

**Still open:**

5. **Canonical hardware. Pending Bridge.** NIC, vCPUs and egress pricing for the production
   canonical, to replace the §6.2 assumptions until P0 measures them.

---

## 12. Change log

- 2026-11-01: first draft (branch `docs/fsd-ciris-mesh`, from 0f73576 / v43.4.1).
- 2026-11-01: Eric's rulings on Q1–Q3 folded in:
  - phones relay on unmetered network plus external power, with a make-before-break handoff
    (§3.2 P-R1–P-R5);
  - the grant suffices for relay eligibility (§3.3);
  - canonical audio fallback is ruled (§6.4 V2).

  Q4 is pending CC and Q5 is pending Bridge.
- 2026-11-01: the CC's answer to Q4 folded in as §4.4 M1–M6:
  - a non-member contact may forward one member-to-member call link 1:1, only when no direct path
    exists;
  - it is never an ALM fan-out point, and the selector enforces member-only media parents;
  - it takes no custody and is handed nothing naming the room;
  - it learns only the CC 1.13.3.1 metadata;
  - it is a consented contact of at least one endpoint.

  Q5 is still pending Bridge.
- 2026-11-01: §7 Load shedding: the service ladder (Eric's direction).
  - Authority: transport load is the node's own decision; federation duty is report-then-relief via
    `config:load` / `load.ceiling` (CC 4.2.1, #503).
  - Tiers 0/1/2, with levers mapped to `EnvelopeKind` planes, A/V and transit.
  - The signal path mirrors the agent's resource monitor (`set_load_pressure`, edge self-raise,
    asymmetric cooldowns, stable tokens).
  - The `load_ledger`.
  - The router principle for hot paths (#930).
  - LS1–LS6, and phase P9.

  Sections 7–10 renumbered to 8–11.
- 2026-11-04: §8 Transport tiers and canonical homing, pointing to `FSD/TRANSPORT_TIERS_MODEL.md`
  and `tools/models/transport_tiers.py` (Eric's rulings on the three tiers and rendezvous homing;
  CIRISEdge#935, CIRISConstitution#200). Sections 8–11 renumbered to 9–12.
- 2026-11-04: §8 rewritten on Eric's BoundedWithFloor ruling (L = 8 shaped links at the class rate,
  refuse and offer bulk past the bound); the model's A, D, E recomputed on it; homing rotation left
  open with the exposure decision table.
- 2026-11-06: Eric's ruling: the tier no longer closes forwarding (L-A1, §7.2), and transit joins the
  never-shed set with the rest of a transport node's minimum viable role (L-A3). The host's verdict is
  a lease (L-S5). §7.7 adds the host's levers and gauges: edge implements, the server pulls, and every
  lever is graduated, leased and refuses nothing. Stretch and the blob half of B-pause, which no code
  ever consumed, move there.
