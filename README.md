# `ciris-edge`

`ciris-edge` is the part of CIRIS that moves signed messages between devices,
over the internet or over radio, and decides who may receive each one.

- **CIRIS** is a network that people, organisations and AI agents share. It runs
  on the phones and computers people already own, with no company in the middle.
- **Its rules are written down and checked.** The
  [CIRIS Constitution](https://github.com/CIRISAI/CIRISConstitution) states them
  precisely. Tests, machine proofs and a conformance suite check the programs
  against it. Edge implements its transport part,
  [Part 5](https://github.com/CIRISAI/CIRISConstitution/blob/main/constitution/part_5_transport_substrate.md).
- **No coordinator is needed.** Every act is a signed record, and records are
  only ever added: taking something back is a new record. So devices that hold
  the same records reach the same answer, in any order. An answer a later record
  could change, such as a vote, is final once enough of the people who could
  change it have acknowledged it. (This is the CALM result, which the
  Constitution and the [CIRISKernel](https://github.com/CIRISAI/CIRISKernel)
  build on.)
- **Why all the technology below:** each piece is needed to make communication
  and coordination reliable, secure, private, performant and efficient, and
  free and easy for all.

## The most advanced open peer-to-peer stack we know of

That is a strong claim. Here is what backs it:

- **Every connection's states are written down and machine-checked.** A
  connection between two devices is always in one of four states: *none*,
  *relayed* (through a server), *upgrading* (trying to go direct) or *direct*.
  Only six moves between them are allowed. A model checker
  ([TLA+](https://lamport.azurewebsites.net/tla/tla.html)) tries every possible
  order of events, across 45 pairings of router behaviour and 107 scenarios in
  all (forged answers, a stranger in the way, lost packets, both sides starting
  at once), and proves that:
  - both sides go direct together, or neither does;
  - a failed attempt leaves the relayed connection exactly as it was;
  - a device never ends up talking to a stranger's address;
  - the helper server never carries your data, and learns only the public
    address of a device that asked it;
  - an address learned along the way is never written into any record;
  - every attempt ends.

  The model and its results are in
  [Leviculum's `docs/direct_link/`](https://github.com/CIRISAI/leviculum/tree/v0.34.0%2Bciris.4/docs/direct_link).
- **It gets through hard routers.** Most home routers block incoming
  connections. When either side's router is the well-behaved kind, both sides
  sending toward each other at once is enough. For routers that
  hand out ports in order, it predicts the next one. For routers that pick ports
  at random, it opens many ports at once until two meet (the "birthday"
  method), with fixed limits on how many. It does this only toward people you
  share a room with. If nothing works, the relayed connection simply stays.
- **Every connection is quantum-resistant.** Every signature, and every byte on
  every connection, direct or relayed, is protected by a classical algorithm
  and a post-quantum one together, so traffic recorded today stays unreadable
  even to a future quantum computer. (The fact that two devices are connected is
  not hidden this way; see AV-53 in the [threat model](docs/THREAT_MODEL.md).)
- **Devices are addressed by their key, not by an IP address or a domain
  name.** No naming authority sits in the middle, and the same messages travel
  over the internet, a local network or radio.
- **Calls are relayed by their own members**, not by a media server, and each
  piece of media is signed, so a relay cannot fake anyone's stream.

What is not proven yet is said plainly in [Not done yet](#not-done-yet) and
[Status](#status). In particular, connections through real home and carrier
routers have not yet been measured against the model.

## Where to go

- [CIRISConstitution](https://github.com/CIRISAI/CIRISConstitution): the rules,
  down to the bytes edge sends. Start with its
  [`VISION.md`](https://github.com/CIRISAI/CIRISConstitution/blob/main/VISION.md).
- [CEWP](https://github.com/CIRISAI/CEWP): the evidence and models, including
  simulations at billions of devices. This repo's models: [`docs/models/`](docs/models/).
- [CIRISKernel](https://github.com/CIRISAI/CIRISKernel): the one function that
  turns records into answers, with its proofs.
- [CIRISConformance](https://github.com/CIRISAI/CIRISConformance): checks the
  separate programs against each other.

## What edge does

```
the app
   │                                ┌─ Reticulum mesh (TCP / UDP / LoRa radio / serial)
   ▼                                │
ciris-edge ── keeps peers in sync ──┼─ HTTPS
   │ checks every sender            └─ packet radio
   ▼
ciris-persist ── keys · signed records · storage
```

- Edge is a library linked into the app, not a separate service.
- It checks who sent every incoming message before any app code sees it, and it
  asks the key store to sign rather than holding the raw bytes of a secret key.
- Every transport plugs into one interface. Reticulum is the main one; HTTPS is
  the fallback, so servers in ordinary data centres can take part.

## Why each piece exists

Each piece is here because one of the five goals fails without it. The longer
reasoning is in [`MISSION.md`](MISSION.md); what is promised, and what is not,
is in the [threat model](docs/THREAT_MODEL.md) (cited below by item, e.g. AV-53).

### Reliable

| Piece | The problem | What edge does |
|---|---|---|
| **Reticulum transport, on Leviculum** | Devices sit on home Wi-Fi, mobile data, a local network, or a radio with no internet. | [Reticulum](https://reticulum.network) addresses a device by its key, not an IP address or domain name, so no naming authority sits in the middle. Edge runs it on [Leviculum](https://github.com/CIRISAI/leviculum), a Rust implementation ([detail](FSD/CIRIS_EDGE_TRANSPORT.md)). |
| **Catch-up sync** | Connections drop and phones sleep, so "send once and hope" loses messages. | Two peers regularly compare what they hold and fetch what is missing, so a message sent while a device was away arrives when it returns. An app can pause edge in the background and resume it. |
| **Connections that notice they are dead** | Mobile networks and home routers fail silently. | A connection whose sends get nowhere three times, or for 30 seconds, is closed and redialled; a direct one falls back to its relayed route. If the other side is plainly alive and sending to us, its count starts over, though the 30 seconds still apply ([`link_stall.rs`](src/transport/link_stall.rs)). A server that forwards for others sheds work under load but never stops forwarding (AV-57). |
| **Files that outlive a lost phone** | Losing one device should not lose a family's files. | A personal or family file is copied to more of its owners' devices until enough hold it. For large groups it is split into pieces, any large-enough set of which rebuilds it ([`durability.rs`](src/blob_swarm/durability.rs)). |

### Secure

| Piece | The problem | What edge does |
|---|---|---|
| **Know the sender before acting** | If code acted on bytes before knowing who sent them, anyone could inject messages. | Every incoming message is tied to a known signing key on arrival, or dropped before anything acts on it ([protocol](FSD/CIRIS_EDGE_TRANSPORT.md)). |
| **Quantum-resistant encryption** | Traffic recorded today could be decrypted later by a quantum computer. | Every signature, and every byte on a Reticulum connection, pairs a classical algorithm with a post-quantum one. The layer under that seal is still classical, so the fact that two devices connect is not hidden from a quantum attacker (AV-53). |
| **Keys in hardware** | A stolen key is a stolen identity. | Edge signs through the [CIRISVerify](https://github.com/CIRISAI/CIRISVerify) key store, so a secret key can stay in secure hardware. A device's identity key is separate from its network address, and the link between them is signed, so a forged announcement cannot redirect its messages (AV-42). |
| **One rate limiter** | A flood should cost its sender, not the quiet peer next to it. | Every limit in edge is one module that charges the largest source and counts every refusal ([design](docs/FSD_RATE_LIMIT.md)). |

### Private

| Piece | The problem | What edge does |
|---|---|---|
| **End-to-end encrypted rooms** | A device that carries a chat or a call should not be able to read it. | Chat is encrypted under the room's key, which is sent to each member quantum-resistantly and replaced when a member is removed. Call media is keyed by the room's group-key protocol, and each piece is signed, so a relay cannot fake a member's stream ([wire](docs/av_chunk_auth_wire.md)). |
| **Groups outsiders cannot see** | Knowing that a group exists can itself do harm. | A group's addresses are worked out from what its members already hold and are never announced ([design](docs/LIGHTNET_DARKNET.md)). |
| **Data moves only when it should** | Being public is not a reason to send something everywhere. | A record goes to a peer only when the peer asked for it or needs it, and it is appropriate. A claim that needs consent goes only where its author's consent allows (AV-56). |
| **Shaped traffic** | Encryption hides what is said, not who talks to whom, when, or how much. | A shaped connection sends same-size packets at a steady random rate, busy or idle. That costs bandwidth and delay, so it is on for servers and opt-in for home and phone devices, at most eight connections per device. Calls and large files travel unshaped ([costs](docs/LINK_SHAPING_COST.md), [model](docs/SHAPING_RHO_W_2026-10-22.md)). |
| **Onion routing (dormant)** | Shaping hides how much a connection carries, not who your peers are. | Each packet is wrapped once per relay, so no single relay learns both ends. It is built but off, and not usable anywhere yet ([design](FSD/ONION_ROUTING.md), [wire](docs/onion_packet_wire.md)). |
| **Metrics without addresses** | Numbers that keep a network working can leak who talked to whom. | Edge's metrics carry no network address or peer identity, and nothing leaves the device on its own: the app decides ([catalogue](docs/TELEMETRY_CATALOGUE.md)). |

### Performant and efficient

| Piece | The problem | What edge does |
|---|---|---|
| **Direct connections through home routers** | Most routers block incoming connections, so every call and file would pass through a server. | A helper server (a facilitator) tells each side its public address, both open a path toward each other at once, and traffic moves only once both prove it works. Tried by default, accepted only from people you share a room with, with the relay as fallback. A device answers a request only if it has a facilitator of its own configured ([`direct_path.rs`](src/transport/direct_path.rs)). |
| **Members relay calls for each other** | A phone cannot upload its video to every member, and a central media server costs money and sees everyone. | Members forward streams in a tree built from their own measurements. A sender starts with two receivers, adds more as its upload allows, and sheds to one when it stalls; a receiver whose media is late moves to a member who relays it. Servers never relay call media; each app decides whether its user relays ([design](docs/AV_ALM_DESIGN.md), [wire](docs/alm_calm_wire.md)). |
| **Late media dropped** | A late frame only delays the ones behind it. | Live media travels as unordered packets, and a receiver drops any older than 800 ms ([notes](docs/RELEASE_NOTES.md)). |
| **Idle costs near nothing** | Phones run on batteries and data plans; servers pay for every storage read. | With nothing new, a sync round reads nothing from storage. A paused edge closes every connection and stops its background work ([notes](docs/RELEASE_NOTES.md)). |

### Free and easy

| Piece | The problem | What edge does |
|---|---|---|
| **A library anyone can build on** | An app should not need a hosted service or a name registration. | Edge is open source (AGPL-3.0). Apps link it as a Rust crate, or through Kotlin and Swift bindings on Android and iOS ([Distribution](#distribution)). Users reach one another by key. |

### Not done yet

- **Harder ways through routers.** The call screen names them, but the transport
  reports only whether a punch worked, so each side's router type reads
  `unknown` ([`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md)).
- **Calls across real home and carrier routers** are not yet measured.
- **Onion routing is dormant.** No layer of the route has the three relays it
  needs; its packet format is not yet fixed by the Constitution; an anonymous
  device takes no calls (AV-59).
- **Shaping leaves visible** which connections exist and when they open (AV-54).
- **Holding messages for sleeping devices** is off unless a server turns it on
  ([`store_and_forward.rs`](src/transport/store_and_forward.rs)).

## How it works

1. **Every message is a signed record** (a *row*), one of
   [15 kinds](FSD/CIRIS_EDGE_TRANSPORT.md#2-the-15-envelopekinds), each kept in
   sync separately.
2. **Each record says how far it may travel**, in widening circles from "just
   me" through family and community to everyone. Private records are never
   advertised; group records stay among members; public ones go to everyone.
   The limit is part of the format, so it cannot be widened by mistake.
3. **Two devices compare and fetch what is missing.** One sends a summary, the
   other names what it lacks, and the first sends it.
4. **Every incoming message is tied to a known key first**: one the network
   vouches for and the sender proves it holds. A newcomer may send only the few
   records that introduce it.
5. **Some records need their author's consent to move.** They go to a peer only
   if that consent covers the peer and the peer may serve them.

Read next: [`MISSION.md`](MISSION.md) (why edge exists, how it fails safely),
[`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md) (the full protocol)
and [`FSD/CIRIS_EDGE.md`](FSD/CIRIS_EDGE.md) (the architecture and interface).

**Public and private layers.** Edge runs both at once. The public layer carries
announced identities anyone can check, and promises no anonymity. The private
layer carries groups whose members find each other by computing the same
address, not by asking a directory; what that buys and how far it is tested is
in [`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md).

## Status

**Current release: v45.2.1, on the long-term support line. Calls are supported
for up to four people in this release.** It builds on
CIRISPersist v61.4.4, CIRISVerify v22.2.4 and Leviculum v0.34.0+ciris.4, needs
Rust 1.92 or newer, and follows Constitution 1.0-rc17 (message vocabulary
v1.0.3). [Release notes](docs/RELEASE_NOTES.md).

- **Calls** run on member relays; servers never relay call media, audio
  included. A stalled sender sheds to one receiver, and the others return
  within about half a minute of it recovering. A member whose app stops reading
  keeps relaying. The call-screen words are fixed for 45.x
  ([`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md)).
- **Direct connections** have been tried by default since v44, with the
  network's bootstrap server as the helper; router type still reads `unknown`.
- **Measured:** the [`bench-mesh/`](bench-mesh/README.md) bench delivered real
  encrypted video and files through a relay that could neither read them nor
  learn the group existed, with mid-stream joins, key changes without lost
  frames, and retired addresses and outsiders refused. It ran on one machine, one relay, up to four
  receivers. Its baselines are from v18.6 to v18.8; its weekly run has not
  passed since 2026-10-12, so no run is recorded passing on the 44.x line.
- **Not measured:** real home and carrier routers, long distances, radio and
  larger meshes. Calls across real routers are unproven
  ([threat model](docs/THREAT_MODEL.md) §9.1).

## Distribution

- **Rust:** pin the git tag
  (`ciris-edge = { git = "https://github.com/CIRISAI/CIRISEdge", tag = "v…" }`).
- **Android and iOS:** the GitHub Release files: Android `.so` libraries per
  processor type (API 24 and up), `CIRISEdge.xcframework`, and Kotlin and Swift
  bindings (UniFFI), with signed manifests and `SHA256SUMS`.
- **Python:** no longer shipped. The CIRIS agent gets edge inside CIRISServer's
  Python package. Nothing is on PyPI, and `pip install ciris-edge` is not
  supported. **v45.1.9 is the last release with Python files.** The Python
  binding (`pyo3` feature) stays in the tree, built and tested in CI, until the
  v62 line removes it ([`docs/PYPI_PUBLISH.md`](docs/PYPI_PUBLISH.md)).

## Related repositories

- [CIRISConstitution](https://github.com/CIRISAI/CIRISConstitution): the rules (Part 5 transport, Part 2 records).
- [CEWP](https://github.com/CIRISAI/CEWP): the platform, its simulations and evidence.
- [CIRISKernel](https://github.com/CIRISAI/CIRISKernel): records into answers, with proofs.
- [CIRISConformance](https://github.com/CIRISAI/CIRISConformance): cross-checks the components.
- [CIRISPersist](https://github.com/CIRISAI/CIRISPersist): admits and stores signed records.
- [CIRISVerify](https://github.com/CIRISAI/CIRISVerify): signing, encryption and the key store.
- [CIRISServer](https://github.com/CIRISAI/CIRISServer): the node; persist, edge and verify in one program.
- [CIRISClient](https://github.com/CIRISAI/CIRISClient): the app where a person meets the network.
- [CIRISAgent](https://github.com/CIRISAI/CIRISAgent): the AI agent, whose signed reasoning edge carries.
- [CIRISRegistry](https://github.com/CIRISAI/CIRISRegistry): agent and build identity, and revocations.
- [CIRISLens](https://github.com/CIRISAI/CIRISLens): metrics, traces and logs for CIRIS infrastructure.
- [Leviculum](https://github.com/CIRISAI/leviculum): the Rust Reticulum implementation under edge's transport.

## License

AGPL-3.0-or-later, matching the rest of CIRIS. Why the license protects the
mission: [`MISSION.md`](MISSION.md) §10.
