# `ciris-edge`

`ciris-edge` is the networking layer of CIRIS. CIRIS is a network that people,
organisations and AI agents share, running on the phones and computers people
already own, with no company in the middle. Edge is the part that moves signed
messages between those devices, over the internet or over radio, and decides
who may receive each one.

The network is formalised: its rules are written down once, precisely, and
checked, rather than left to an operator's goodwill. One specification, the
[CIRIS Constitution](https://github.com/CIRISAI/CIRISConstitution), says what
the network owes the people it touches and exactly which bytes a device must
send to show it. Its rules are kept as data that generates test cases, a shared
kernel turns signed messages into answers (who is in a room, what a vote
decided) with its key properties proved by machine, and a conformance suite
checks the separate programs against each other. Edge implements the
Constitution's transport part,
[Part 5](https://github.com/CIRISAI/CIRISConstitution/blob/main/constitution/part_5_transport_substrate.md).

The network needs no central coordinator because of how its data is shaped.
Every act is a signed record (a *row*), and rows are only ever added: taking
something back is a new row, not a deletion. An answer that only grows as rows
arrive comes out the same on every device, whatever order the rows came in,
with no coordination. An answer that a later row could change, such as a vote
or a removal, becomes final once enough of the people who could change it have
acknowledged it. This split is the CALM result from distributed-systems research
("consistency as logical monotonicity"), which the Constitution and the kernel
build on, so no device has to put events in one global order and no server has
to confirm them.

## Where the rules, the evidence and the kernel live

- **The rules: [CIRISConstitution](https://github.com/CIRISAI/CIRISConstitution).**
  The specification, including the wire format edge sends. Read it to learn what
  the network promises and why; its
  [`VISION.md`](https://github.com/CIRISAI/CIRISConstitution/blob/main/VISION.md)
  is the plain-words starting point.
- **The evidence and models: [CEWP](https://github.com/CIRISAI/CEWP)** (the CIRIS
  Epistemic Web Platform). The platform the Constitution governs, with
  simulations of the network at the scale of billions of devices, comparisons
  with other decentralised networks, and the evidence behind each claim. Go
  there to see what the design does at scale and what it costs. This repo's own
  models are in [`docs/models/`](docs/models/).
- **The kernel: [CIRISKernel](https://github.com/CIRISAI/CIRISKernel).** The one
  function every device runs to turn the rows it holds into answers, with its
  proofs. Go there to see why devices agree without a coordinator.
- **The cross-check: [CIRISConformance](https://github.com/CIRISAI/CIRISConformance).**
  The suite that checks the separate components against each other.

## What edge does

```
the app (host code)
    │ registers handlers                     ┌─ Reticulum mesh (TCP / UDP / LoRa radio / serial / I²P)
    ▼                                         │
ciris-edge ── keeps peers' copies in sync ────┼─ HTTPS
    │ checks who sent each message;           │
    │ sends each row only where it may go     └─ packet radio
    ▼
ciris-persist ── keys · signed rows · storage · admission
```

Edge is a library linked into the app, not a separate service. It checks who
sent every incoming message before any app code sees it. It never holds the raw
bytes of a secret key; it asks the key store to sign. Every way of moving bytes
plugs into one interface. Reticulum is the main one, and HTTPS is the fallback
so servers in ordinary data centres can take part.

## Why each piece exists

Edge exists to make communication and coordination reliable, secure, private,
performant and efficient, and free and easy for everyone to use. Each piece
below is here because one of those fails without it. The longer reasoning is in
[`MISSION.md`](MISSION.md); what is promised, and what is not, is in the
[threat model](docs/THREAT_MODEL.md). What is not finished is listed at the end
of this section.

### Reliable

- **Reticulum transport, on Leviculum.** People's devices sit on home Wi-Fi,
  mobile data, a local network, or a radio with no internet at all.
  [Reticulum](https://reticulum.network) is a networking protocol that addresses
  a device by its cryptographic key rather than by an IP address or a domain
  name, so no naming or addressing authority sits in the middle, and the same
  connection runs over TCP, UDP, a local network or long-range low-power radio
  (LoRa). Edge uses [Leviculum](https://github.com/CIRISAI/leviculum), a Rust
  implementation of Reticulum. Detail:
  [`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md).
- **Catch-up sync between peers.** Connections drop and phones sleep, so "send
  once and hope" loses messages. Two peers regularly compare what they hold and
  fetch what is missing (called anti-entropy), so a message sent while a device
  was away arrives when it comes back. A phone app can pause edge in the
  background and resume it later. A public server can also hold messages for a
  sleeping device; that queue is off unless the server turns it on
  (`src/transport/store_and_forward.rs`).
- **Connections that notice they are dead.** Mobile networks and home routers
  fail silently. A connection whose sends get nowhere three times, or for 30
  seconds, is closed and redialled, and a direct connection falls back to its
  relayed route (`src/transport/link_stall.rs`). A server that forwards traffic
  for others sheds work under load but never stops forwarding, because a device
  that can only be reached through it would become unreachable (threat model,
  item AV-57).
- **Files that outlive a lost phone.** A personal or family file is copied to
  more of its owners' own devices until enough of them hold it, so losing one
  device does not lose the file. For large groups the file is split into
  erasure-coded pieces (RaptorQ), any large-enough subset of which rebuilds it
  (`src/blob_swarm/durability.rs`).

### Secure

- **Know the sender before acting.** If code could act on bytes before knowing
  who sent them, anyone could inject messages. Every incoming message is tied to
  a known signing key at the moment it arrives, and one that cannot be is
  dropped before anything acts on it
  ([`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)).
- **Encryption that holds against future quantum computers.** Traffic recorded
  today could be decrypted later by a quantum computer. So every signature pairs
  a classical algorithm with a post-quantum one (Ed25519 with ML-DSA-65), and
  every byte on a Reticulum connection is sealed with keys agreed the same
  paired way (X25519 with ML-KEM-768). The Reticulum layer under that seal is
  still classical, so the fact that two devices connect is not protected against
  a quantum attacker (threat model, item AV-53).
- **Keys in hardware, two keys per device.** A stolen key is a stolen identity.
  Edge signs through the key store of [CIRISVerify](https://github.com/CIRISAI/CIRISVerify),
  so a secret key can stay in the device's secure hardware
  ([`MISSION.md`](MISSION.md)). A device's identity key is separate from the key
  Reticulum uses to address it, and the link between the two must be signed, so
  a forged announcement cannot redirect a device's messages (threat model, item
  AV-42).
- **One rate limiter.** A flood should cost the sender of the flood, not the
  quiet peer next to it. Every limiter in edge is one module that charges the
  largest source and counts every refusal
  ([`docs/FSD_RATE_LIMIT.md`](docs/FSD_RATE_LIMIT.md)).

### Private

- **End-to-end encrypted rooms.** A device that carries a chat or a call should
  not be able to read it. A chat message is encrypted under the room's key, that
  key is sent to each member encrypted the same quantum-resistant way, and it is
  replaced when a member is removed (`src/chat.rs`). Call media is keyed from the
  room's group-key protocol (MLS, RFC 9420, with a quantum-resistant suite), and
  each piece of media is signed by its sender so a relaying device cannot fake a
  member's stream ([`docs/av_chunk_auth_wire.md`](docs/av_chunk_auth_wire.md)).
- **Groups outsiders cannot see.** Knowing that a group exists can itself do
  harm. A group's network addresses are worked out from information its members
  already hold and are never announced, so an outsider cannot learn the group is
  there ([`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)).
- **Data moves only when it should.** A row goes to a peer when the peer asked
  for it, or needs it, and it is appropriate, never just because it is public.
  A claim that needs consent goes only where its author's consent allows
  (threat model, item AV-56).
- **Shaped traffic.** Encryption hides what is said, not who talks to whom, when,
  or how much. A shaped connection sends same-size packets at a steady random
  rate whether busy or idle, so someone watching it learns nothing about how
  much it carries. That costs bandwidth and adds delay, so it is on by default
  for servers and opt-in for home and phone devices; a device shapes at most
  eight direct connections, and calls and large files travel unshaped. Costs
  per device class: [`docs/LINK_SHAPING_COST.md`](docs/LINK_SHAPING_COST.md);
  the model behind the defaults:
  [`docs/SHAPING_RHO_W_2026-10-22.md`](docs/SHAPING_RHO_W_2026-10-22.md).
- **Onion routing.** Shaping hides how much a connection carries, not who your
  peers are. An onion-routed packet is wrapped in one layer of encryption per
  relay, so each relay learns only the hop before and the hop after, and no
  single relay learns both ends. In edge it is built but dormant: off by
  default, and not yet usable anywhere (see the list below). Detail:
  [`FSD/ONION_ROUTING.md`](FSD/ONION_ROUTING.md),
  [`docs/onion_packet_wire.md`](docs/onion_packet_wire.md).
- **Metrics without addresses.** Operators need numbers to keep a network
  working, but numbers can leak who talked to whom. Edge's metrics carry no
  network address or peer identity, and nothing leaves the device on its own:
  the app reads them and decides
  ([`docs/TELEMETRY_CATALOGUE.md`](docs/TELEMETRY_CATALOGUE.md)).

### Performant and efficient

- **Direct connections through home routers.** Most devices sit behind a home
  router or a mobile carrier's router that blocks incoming connections (network
  address translation, NAT), so without a way through, every call and file
  between two people would pass through someone's server. Edge asks a helper
  server (a facilitator) to tell each side its public address, then both sides
  open a hole toward each other at once, and the connection moves to the direct
  path only once both sides have proved it works. Edge tries this by default,
  accepts it only from people it shares a room with, and falls back to the
  relayed path if the direct one dies (`src/transport/direct_path.rs`,
  [`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md)).
- **Members relay calls for each other.** A phone's upload cannot carry a copy
  of its video to every member of a group call, and a central media server costs
  money and sees everyone's traffic. Instead, members forward streams for one
  another in a tree that grows from each member's own measurements (an
  application-layer multicast tree). A sender starts with two direct receivers
  and adds more as its upload shows room, sheds to one when its upload stalls,
  and a receiver whose media arrives late moves to a member who relays it;
  servers never relay call media, and each app decides whether its user relays
  ([`docs/AV_ALM_DESIGN.md`](docs/AV_ALM_DESIGN.md); the wire format of
  [the call tree's control messages](docs/alm_calm_wire.md)).
- **Late media is dropped, not queued.** Live media travels as unordered
  packets, and a receiver drops any older than 800 ms, because a late frame only
  delays the ones behind it ([`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md)).
- **Idle costs near nothing.** Phones run on batteries and data plans, and a
  server pays for every storage read. When there is nothing new, a sync round
  reads nothing from storage, and a paused edge closes every connection and
  stops its background work ([`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md)).

### Free and easy

- **A library anyone can build on.** Edge is open source (AGPL-3.0), a library
  rather than a hosted service. An app links it in as a Rust crate, or through
  Kotlin and Swift bindings on Android and iOS (see [Distribution](#distribution)),
  and its users reach one another by key, with no naming authority to register
  with.

### What is not done yet

- **Harder ways through routers.** The call screen's vocabulary already names
  port prediction, many-socket punches and router port mappings (PCP, NAT-PMP,
  UPnP), but at this commit the transport reports only whether a hole punch
  worked, so the router type of each side reads `unknown`
  ([`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md)).
- **Calls across real home and carrier routers are not yet measured.** The
  acceptance tests run on one machine (see [Status](#status)).
- **Onion routing is dormant.** It is off by default and unavailable on every
  device today, because no layer of the route has the three relays it needs; its
  packet format is edge's proposal, not yet fixed by the Constitution; and an
  anonymous device takes no calls (threat model, item AV-59).
- **Shaping leaves some things visible.** Which connections exist, and when they
  are set up, is still visible, and calls and large files travel unshaped
  (threat model, item AV-54).
- **Holding messages for sleeping devices** is off unless a server turns it on.

## Read in this order

1. **[`MISSION.md`](MISSION.md)**: why edge exists, how each module serves the
   goal of the CIRIS Accord (CIRIS's ethical framework), the mistakes to avoid, and how edge fails safely.
2. **[`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)**: the
   protocol, with diagrams and pointers into the code.
3. **[`FSD/CIRIS_EDGE.md`](FSD/CIRIS_EDGE.md)**: the architecture, the crate's
   shape and its public interface.

## How the protocol works, in one paragraph

Everything edge carries is a signed row of one of
[15 message kinds](FSD/CIRIS_EDGE_TRANSPORT.md#2-the-15-envelopekinds), and each
kind is kept in sync separately. Each row says how far it may travel, in
widening circles from "just me" through family and community out to everyone
(its `cohort_scope`). Your own private rows are never advertised; a group's rows
are held and passed along among its members; public rows go to everyone, with
markers that stop an old version from coming back. Two peers stay in sync with a
three-step exchange: one sends a summary of what it holds, the other answers
with what it is missing, and the first sends those rows (Summary, Diff,
Deliver). Every incoming message is tied, on arrival, to a signing key the
network vouches for and the sender proves it holds; a newcomer may send only the
few rows that introduce it. Some signed claims (attestations) need consent:
such a claim goes to a peer only if its author's consent covers that peer, the
peer is allowed to serve it, and the peer meets any condition the claim names.
The rule for who may receive a row is built into the format, so it cannot be
widened by mistake.

## Public and private planes

Edge runs two layers at once (the Constitution's "lightnet" and "darknet"
split). The public layer carries announced identities that anyone can check and
promises no anonymity. The private layer carries groups: each group's addresses
are worked out from information its members already hold and are never
announced, so outsiders cannot learn the group exists. Members find each other
by computing the same answer, not by asking a directory. What that buys
(private groups that can still be moderated, video relayed by members, and a
proposed ballot whose existence outsiders cannot see) and how far each claim has
been tested are in [`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md). The
tests run as a multi-container bench, [`bench-mesh/`](bench-mesh/README.md),
with real video and files through real relays; its current state is under
Status.

## Status

**Current release: v45.1.10, on the long-term support line.** It builds on
CIRISPersist v61.4.4, CIRISVerify v22.2.4 and Leviculum v0.34.0+ciris.3, needs
Rust 1.92 or newer, follows Constitution 1.0-rc17, and speaks message
vocabulary v1.0.3. Release notes: [`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md);
threat model and its stated limits: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**45.2.0, in preparation (not released).** Calls run on member relays: members
forward for one another, and servers never relay call media, audio included. A
sender starts with two direct receivers and adds more as its upload allows; a
stalled upload sheds to one; a receiver with late media moves to a member relay.
The words an app shows for call paths and relays are fixed for the 45.x line in
[`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md). Direct connections
have been tried by default since v44, with the network's bootstrap server as
the helper that reports each side's public address; the router type still reads
`unknown`. This tree pins Leviculum by commit ahead of its release tag.

**What has been measured, and how far.** The multi-container acceptance bench
([`bench-mesh/`](bench-mesh/README.md); evidence in
[`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)) delivered real encrypted
video and files through a relay that could neither read them nor learn the
group existed, with people joining mid-stream, keys changing without lost
frames, retired addresses and outsiders refused. It ran on one machine with one
relay and up to four receivers (seven containers); its recorded baselines are
from v18.6 to v18.8, and its weekly run has not passed since 2026-10-12, so no
run is recorded passing on the 44.x line. Real home and carrier routers, long
distances, radio and larger meshes are not measured by it, and calls across real
routers are unproven ([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §9.1).

## Distribution

Edge ships as a Rust crate and as generated bindings for Kotlin and Swift
(made with UniFFI); it no longer ships Python. Rust apps pin the git tag
(`ciris-edge = { git = "https://github.com/CIRISAI/CIRISEdge", tag = "v…" }`).
Android and iOS apps take the GitHub Release files: the Android `.so` libraries
per processor type (Android API 24 and up), `CIRISEdge.xcframework` for Apple
platforms, and the Kotlin and Swift bindings, with signed manifests and
`SHA256SUMS`. Python users (the CIRIS agent) get edge inside CIRISServer's
Python package, which builds edge's Python binding in. Nothing is published to
PyPI, and `pip install ciris-edge` is not supported. **v45.1.9 is the last
release with Python files** (desktop wheels, and the Android and iOS Python
builds). The Python binding (`pyo3` feature, `src/ffi/pyo3.rs`,
`pyproject.toml`, `python/`) stays in the tree, built and tested in CI, until
the v62 line removes it. See [`docs/PYPI_PUBLISH.md`](docs/PYPI_PUBLISH.md).

## Related repositories

- [CIRISConstitution](https://github.com/CIRISAI/CIRISConstitution): the rules.
  Part 5 is the transport edge implements; Part 2 is the grammar of rows.
- [CEWP](https://github.com/CIRISAI/CEWP): the platform, its simulations and its
  evidence.
- [CIRISKernel](https://github.com/CIRISAI/CIRISKernel): the function that turns
  rows into answers, with proofs.
- [CIRISConformance](https://github.com/CIRISAI/CIRISConformance): checks the
  components against each other.
- [CIRISPersist](https://github.com/CIRISAI/CIRISPersist): decides which signed
  rows are allowed to become state and stores them; edge syncs what it holds.
- [CIRISVerify](https://github.com/CIRISAI/CIRISVerify): the signing and
  encryption building blocks and the key store, used through persist.
- [CIRISServer](https://github.com/CIRISAI/CIRISServer): the node, which combines
  persist, edge and verify into one program.
- [CIRISClient](https://github.com/CIRISAI/CIRISClient): the app where a person
  meets the network.
- [CIRISAgent](https://github.com/CIRISAI/CIRISAgent): the AI agent; it emits
  signed records of its reasoning that edge carries.
- [CIRISRegistry](https://github.com/CIRISAI/CIRISRegistry): verifies agent and
  build identity and distributes revocations.
- [CIRISLens](https://github.com/CIRISAI/CIRISLens): metrics, traces and logs
  for CIRIS infrastructure.
- [Leviculum](https://github.com/CIRISAI/leviculum): the Rust Reticulum
  implementation edge's transport runs on.

## License

AGPL-3.0-or-later, matching the rest of CIRIS. Why the license protects the
mission is in [`MISSION.md`](MISSION.md) §10.
