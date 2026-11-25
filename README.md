# `ciris-edge`

**The transport and replication layer of the CIRIS Epistemic Web
([CEWP](https://ciris.ai/cewp)).** A single Rust crate that moves the 15 signed
envelope kinds of the CEG grammar between federation peers over any medium —
Reticulum mesh, HTTPS, packet radio — decides *who is allowed to learn a claim
exists*, and attributes every inbound byte to a cryptographic identity **before
any handler sees it**.

Edge is the operational realization of
**[Constitution Part 5 — Transport & Substrate](../CIRISConstitution/constitution/part_5_transport_substrate.md)**,
built on two disciplines: **fail-secure** (a missing key or unresolved consent
resolves to *less* access, never a silent downgrade) and **integrity through
structure** (privacy and authenticity are properties the wire format *cannot
violate*, not promises an operator makes). Its design thesis, from
[contextual integrity](https://ciris.ai/contextual-integrity/):
**"the strongest flow rule is one the network cannot express breaking."**

> **📖 The protocol spec: [`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)** —
> the 15 EnvelopeKinds, the cohort/namespace projections, the anti-entropy state
> machine, the transport attribution pipeline, the serve/consent gates, and the
> CEG-vs-OSI layering, with diagrams and code anchors. Start there.

## What edge does

```
host application code
    │ registers handlers                    ┌─ Reticulum mesh (TCP / LoRa / serial / I²P)
    ▼                                        │
ciris-edge  ──── anti-entropy replication ───┼─ HTTPS (bearer / mTLS)
    │ attribute at the wire · serve by consent │
    ▼                                        └─ packet radio
ciris-persist  ──── keys · attestations · trace · admission
```

One shape, many peers. **Library, not sidecar.** Verify happens at the wire,
before any handler sees a byte. Key seeds never cross the FFI boundary. Every
transport is a projection of one `Transport` trait; Reticulum is canonical, HTTPS
is the production fallback so cloud deployments participate today.

## Why each piece exists

Edge exists to make communication and coordination reliable, secure, private,
performant and efficient, and free and easy for everyone to use. Each piece
below is here because one of those fails without it. The longer reasoning is in
[`MISSION.md`](MISSION.md); what is promised, and what is not, is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

### Reliable

- **Reticulum transport, on Leviculum.** People's devices sit on home Wi-Fi,
  mobile data, a local network, or a radio with no internet at all. Reticulum
  addresses a node by its key, not by an IP address or a domain name, so no
  naming or addressing authority sits in the middle, and the same link runs over
  TCP, UDP, a local interface or LoRa-class packet radio (the
  `transport-reticulum-*` features in `Cargo.toml`). Leviculum is the Rust
  Reticulum implementation edge builds on. See
  [`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md).
- **Anti-entropy replication.** Links drop and phones sleep, so "send once and
  hope" loses messages. Peers compare what they hold (Summary, Diff, Deliver)
  and fetch what is missing, so a message sent while a device was away arrives
  when it comes back. A phone host can suspend edge in the background and resume
  it later (`Edge::suspend` / `Edge::resume`). A store-and-forward queue lets a
  public node hold messages for a sleeping device; it is off unless the node
  wires it in (`src/transport/store_and_forward.rs`).
- **Links that notice they are dead.** Mobile links and home routers fail
  silently. A link whose sends land nothing three times, or for 30 s, is closed
  and redialled, and a punched direct link falls back to its relayed path
  (`src/transport/link_stall.rs`). A relay under load sheds work through leased
  levers but never stops forwarding, because a device behind NAT that can only
  be reached through it would lose first contact (threat model AV-57).
- **Files that outlive a lost phone.** A personal or family file is
  re-replicated to the devices of its own audience until enough of them hold it,
  using fountain (RaptorQ) pieces for large audiences, so losing one device does
  not lose the file (`src/blob_swarm/durability.rs`).

### Secure

- **Attribution before any handler.** If code could act on bytes before knowing
  who sent them, anyone could inject. Every inbound frame is tied to a rooted
  federation identity at the wire, and a frame that cannot be is dropped before
  any handler or serve gate sees it
  ([`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)).
- **Hybrid post-quantum crypto.** Traffic recorded today could be decrypted by a
  future quantum computer. Every producer signs with Ed25519 plus ML-DSA-65.
  Every byte on a Reticulum link travels under a hybrid X25519 + ML-KEM-768 seal
  set up once per link, and content keys are wrapped the same hybrid way. The
  Reticulum layer under the seal (link request, announce, path request) is still
  classical, so the fact that two nodes connect is not post-quantum protected
  (threat model AV-53).
- **Hardware-backed identity, two keypairs per node.** A stolen key is a stolen
  identity. Edge signs through `ciris-keyring`'s `HardwareSigner`, so the seed
  can stay in secure hardware and never enters edge ([`MISSION.md`](MISSION.md)).
  A node's federation key is separate from its Reticulum transport identity, and
  the link between them must be signed, so a forged announce cannot redirect a
  node's messages (threat model AV-42).
- **One rate limiter.** A flood should cost the flooder, not the quiet peer next
  to it. Edge's keyed limiters share one module that charges the largest source
  and counts every denial ([`docs/FSD_RATE_LIMIT.md`](docs/FSD_RATE_LIMIT.md)).

### Private

- **End-to-end encrypted rooms.** A node that carries a chat or a call should
  not be able to read it. A chat body is encrypted under the room's key, wrapped
  for each member with hybrid X25519 + ML-KEM-768 and rotated when a member is
  removed (`src/chat.rs`). Call media is keyed from the room's MLS group (RFC
  9420, the X-Wing post-quantum hybrid suite), and each chunk is signed by its
  publisher so a relay cannot forge a member's stream
  ([`docs/av_chunk_auth_wire.md`](docs/av_chunk_auth_wire.md)).
- **Groups outsiders cannot see.** Knowing that a group exists can itself be
  harmful. Group addresses are derived from state members already hold and are
  never announced, so an outsider cannot learn the group is there
  ([`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)).
- **Data moves only when it should.** A row moves to a peer when it is requested,
  or required, and appropriate, never just because it is public to the
  federation, and consentable claims move only under the producer's consent
  grant (threat model AV-56).
- **Shaped traffic.** Encryption hides what is said, not who talks to whom, when
  or how much. A shaped link sends fixed-size frames at a steady random rate,
  busy or idle, so a watcher of that link learns nothing about its load. It
  costs bandwidth and adds delay: the fleet default is on for servers and
  opt-in for home and phone classes, a node shapes at most eight one-hop links,
  and calls and large files ride unshaped. Which links exist stays visible.
  Costs per class are in
  [`docs/LINK_SHAPING_COST.md`](docs/LINK_SHAPING_COST.md); the model behind
  the defaults is in
  [`docs/SHAPING_RHO_W_2026-10-22.md`](docs/SHAPING_RHO_W_2026-10-22.md).
- **Onion routing (the Anonymous Tier).** Shaping hides a link's load but not
  who your peers are. An onion packet is wrapped in layers so each relay learns
  only the hop before and the hop after, and no single relay learns both ends.
  It is wired and dormant: off by default, unavailable on every node today
  because no layer has three relays, and its packet format is edge's proposal,
  not yet pinned by the Constitution. An anonymous node carries no calls. See
  [`FSD/ONION_ROUTING.md`](FSD/ONION_ROUTING.md) and
  [`docs/onion_packet_wire.md`](docs/onion_packet_wire.md).
- **Telemetry without addresses.** Operators need numbers to keep a network
  working, but numbers can leak who talked to whom. Edge's metrics carry no
  address or peer identifier, and nothing leaves the node on its own: the host
  reads the snapshot and decides
  ([`docs/TELEMETRY_CATALOGUE.md`](docs/TELEMETRY_CATALOGUE.md)).

### Performant and efficient

- **NAT traversal and direct links.** Most devices sit behind a home router or a
  carrier NAT (network address translation), which blocks connections from
  outside. Without traversal, every call and file between two people would pass
  through someone's server. Edge asks a facilitator (a node that tells each side
  its public address), both sides punch through at once, and the link moves to
  the direct path only when both sides prove it works; if the direct path dies,
  the link returns to its relayed one. Proposing is on by default, and a node
  accepts direct paths only from peers it shares a room with
  (`src/transport/direct_path.rs`). The call events already name harder
  techniques (port prediction, many-socket "birthday" punches, router mappings
  through PCP, NAT-PMP or UPnP), but at this commit the transport reports only
  whether a punch worked, so NAT details read `unknown`
  ([`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md)). Calls across
  real NATs are not yet measured (threat model §9.1).
- **Member relay for calls (ALM).** A group call usually needs a central media
  server, which costs money and sees everyone's traffic, and a phone's uplink
  cannot send a copy of its video to every member. In edge's application-layer
  multicast (ALM), members forward streams for one another, and the tree forms
  from each member's own measurements. A publisher starts with two direct
  children and widens as its uplink shows room (slow start); a stalled uplink
  sheds to one child; a receiver whose media arrives late moves to a member
  relay. Servers never relay call media, audio included, and each host decides
  whether its member relays (`CallOptions::relay`). See
  [`docs/AV_ALM_DESIGN.md`](docs/AV_ALM_DESIGN.md),
  [`docs/alm_calm_wire.md`](docs/alm_calm_wire.md) and
  [`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md).
- **Media that is late is dropped, not queued.** Live media rides unordered
  datagrams, and a receiver drops media older than 800 ms, because a late frame
  only delays the ones behind it ([`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md)).
- **Idle costs near nothing.** Phones run on batteries and data caps, and a
  server pays for every read. An idle replication round reads nothing from the
  store (an in-memory holdings index answers it), and a suspended edge closes
  every socket and stops its loops ([`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md)).

### Free and easy

- **A library anyone can embed.** Edge is an AGPL-3.0 library, not a hosted
  service. A host links it in as a Rust crate, or through the Kotlin and Swift
  bindings on Android and iOS (see [Distribution](#distribution)), and its users
  address one another by key, with no naming authority to register with.

## Read in this order

1. **[`MISSION.md`](MISSION.md)** — the WHY. Mission-Driven Development alignment to
   CIRIS Accord Meta-Goal M-1; per-module missions; anti-patterns; failure modes.
2. **[`FSD/CIRIS_EDGE_TRANSPORT.md`](FSD/CIRIS_EDGE_TRANSPORT.md)** — the protocol.
   State machines, the 15 kinds, namespaces, attribution, consent-routing, CEG↔OSI.
3. **[`FSD/CIRIS_EDGE.md`](FSD/CIRIS_EDGE.md)** — the architecture spec, crate shape,
   public API surface, verify-via-persist contract, test categories.

## The shape of the protocol (one-paragraph tour)

Every claim is one of **15 signed [`EnvelopeKind`s](FSD/CIRIS_EDGE_TRANSPORT.md#2-the-15-envelopekinds)**,
each its own anti-entropy stream. A claim's **`cohort_scope`** (`self` → `family`
→ `community` → `affiliations` → `species` → `biosphere` → `federation`) resolves
to a **projection** — `SelfOwn` (publish-your-own, *structurally invisible* — no
directory advertisement), `Cohort` (roster hold-and-forward), or `Global`
(commons + anti-rollback tombstones). Peers reconcile per `(peer, kind)` via a
bidirectional **Summary → Diff → Deliver** round. Every inbound frame is
**attributed** at ingest to a `Rooted ∧ owns_key` federation identity (a fresh
peer bootstraps via a narrow, self-authenticating `{Key, IdentityOccurrence,
TransportDestination}` carve-out); an unattributable frame is dropped before any
serve gate is consulted. Only the `Attestation` plane is **consent-gated** — a
consentable claim flows to a peer only if the producer's consent grant includes
it, the recipient holds `infra:serve`, and it satisfies any `recipient_capability`
restriction. The recipient axis *cannot exceed* the transmission principle,
by construction.

## The two-plane hybrid

Edge realizes the **lightnet/darknet split** of
[CC 5.4.6](../CIRISConstitution/constitution/part_5_transport_substrate.md): a
**public identity plane** (announced, rooted, attributable — no anonymity
claim) and a **derived group plane** (per-group destinations derived from
directory state members already hold — never announced, so group *existence*
is structurally invisible to outsiders). Derivation replaces discovery;
determinism replaces coordination. What that buys — private *manageable*
groups, decentralized video over member-relays, and the posited
occurrence-invisible ballot — and the measurement status of each claim, is in
**[`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)**. The proofs run as
the multi-container acceptance bench (**[`bench-mesh/`](bench-mesh/README.md)**,
real video + real blobs through real relays, in CI).

## Status

**v45.1.10 (LTS).** Pins `ciris-persist` v61.4.4 (exact, by tag), CIRISVerify v22.2.4 and
leviculum v0.34.0+ciris.3 (`Cargo.toml`); MSRV 1.92; CC 1.0-rc17;
wire vocabulary v1.0.3 (since v44.1.2). Release notes: [`docs/RELEASE_NOTES.md`](docs/RELEASE_NOTES.md);
threat model and its stated residuals: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

**45.2.0, in preparation (not released).** Calls run on member relays: every
call runs the ALM controller, members forward for one another, and serve seats
never relay call media, audio included. A publisher starts with two direct
children and widens as its uplink allows; a stalled uplink sheds to one child;
a receiver with late media moves to a member relay. The host-facing call and
relay tokens are frozen for 45.x in
[`docs/calls_relay_tokens.md`](docs/calls_relay_tokens.md). Direct-link
proposing has been on by default since v44, with the bundle's canonical as
facilitator; NAT details still read `unknown` because the transport reports a
punch outcome only. This tree pins leviculum by commit ahead of its tag.

**Measured, and its scope.** The multi-container acceptance sweep
([`bench-mesh/`](bench-mesh/README.md); labels and evidence in
[`docs/LIGHTNET_DARKNET.md`](docs/LIGHTNET_DARKNET.md)) delivered real
encrypted video and files through a relay that can neither read them nor learn
the group exists, with mid-stream joins, key rotation without frame loss,
address retirement and outsider refusal. Its scope is one host, one relay, up
to four subscribers (seven containers), and its committed baselines are from
v18.6–v18.8; the weekly lane has not passed since 2026-10-12, so no sweep is
recorded green on 44.x. Real NATs, WAN latency, radio and larger meshes are
not measured by it, and A/V across real NATs is unproven
([`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) §9.1).

Under the hood: production CEG-native transport with a hybrid transit seal on
every Reticulum link (CC 5.3.3.5 E1); per-link traffic shaping under CC 5.4.3
(one hop, eight links, bulk and A/V unshaped); the CC 5.2 rule for what moves
to a peer; scope-native addressing end to end (`#499`); the A/V mesh spine;
Reticulum + HTTPS + packet-radio transports; the anti-entropy replication
engine; the `#393` two-item attribution gate; MLS cohorts (TreeKEM, X-Wing)
with scope-derived addressing and seal/retirement; mandatory hybrid Ed25519 +
ML-DSA-65 on every producer; UniFFI Kotlin + Swift surfaces (Android floor:
API 24). The Anonymous Tier is wired and dormant. Pinned in lockstep to
`ciris-persist` via drift-witnessed policy hashes.

## Distribution

Edge ships as a **Rust crate** and as **UniFFI bindings**; it no longer ships
Python. Rust consumers pin the git tag
(`ciris-edge = { git = "https://github.com/CIRISAI/CIRISEdge", tag = "v…" }`).
Native and mobile consumers take the GitHub Release assets: the Android
per-ABI `.so` tarball, `CIRISEdge.xcframework`, and the generated Kotlin and
Swift bindings, beside their signed manifests and `SHA256SUMS`. Python
consumers (the agent) get edge inside CIRISServer's wheel, which compiles
edge's `pyo3` binding in. Nothing is published to PyPI, and `pip install
ciris-edge` is not a supported path. **v45.1.9 is the last release with Python
assets** (desktop abi3 wheels, Chaquopy `android-wheels.tar.gz`, BeeWare
`ios.tar.gz`). The `pyo3` feature, `src/ffi/pyo3.rs`, `pyproject.toml` and
`python/` stay in the tree, compiled and tested in CI, until the v62 line
removes them. See [`docs/PYPI_PUBLISH.md`](docs/PYPI_PUBLISH.md).

## Sister repos

- [`CIRISConstitution`](../CIRISConstitution) — the canonical CEG spec (Part 5 is
  edge's transport substrate; Part 2 the grammar; Part 3 the namespace).
- [`CIRISPersist`](../CIRISPersist) — substrate: federation keys, attestations,
  trace storage, admission (the `put_*` surface edge replicates onto).
- [`CIRISVerify`](../CIRISVerify) — hybrid crypto primitives (Ed25519 + ML-DSA-65,
  X-Wing), consumed transitively via persist.
- [`CIRISAgent`](../CIRISAgent) — reasoning loop; emits signed traces edge replicates.
- [`CIRISRegistry`](../CIRISRegistry) · [`CIRISLens`](../CIRISLens) — identity/build
  directory · analytical observatory; federation peers.

## License

AGPL-3.0, matching the CIRIS stack. License-locked mission preservation per
[`MISSION.md`](MISSION.md) §6.
