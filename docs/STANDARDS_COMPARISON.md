# CIRISEdge: Standards Comparison and Mesh-Transport Peer Analysis

**Version**: 1.0
**Date**: 2026-05-28
**Author**: CIRIS L3C
**Baseline release**: v0.10.0 (post-CIRISEdge#19 / #20 / #21)
**Scope**: federated mesh transport + peer discovery + delivery semantics
**Out of scope**: cryptographic primitive standards — that is
[CIRISVerify/docs/STANDARDS_COMPARISON.md](https://github.com/CIRISAI/CIRISVerify/blob/main/docs/STANDARDS_COMPARISON.md)'s
domain. Edge consumes verify's hybrid Ed25519 + ML-DSA-65 primitive;
it does not re-implement it (MISSION.md §1.4).

## Executive Summary

CIRISEdge is the federation transport substrate: one Rust crate that
carries cryptographic envelopes between sovereign peers across
whatever network media exist (TCP, LoRa, packet radio, serial, I²P,
HTTP fallback). It sits in a crowded field — libp2p, iroh,
Reticulum, MeshChat, Sideband, Briar, Matrix federation, Hyperswarm,
NATS, gRPC — each of which has solved some subset of the mesh-or-
federation problem. This document compares edge's design choices
against that field, frankly, and identifies where edge is genuinely
differentiated from where it is "a CIRIS-flavored fork of an
existing pattern."

The CIRIS Accord §VII Meta-Goal M-1 — *sustainable adaptive
coherence* — names the constraint: a federation primitive that can
only route via cloud infrastructure is `k` deployments correlated
through one chokepoint (`ρ → 1`, `k_eff → 1`), not `k` independent
peers. Edge's design choices — Reticulum as canonical wire,
cryptographic addressing (the destination IS the public key), hybrid
PQC on every envelope, multi-tier delivery semantics, recursive
multi-sig verification at the wire layer (CIRISEdge#19) — are not
optimization decisions, they are what makes "two independent peers"
a physically true statement rather than a diagram. The benchmarks
in [docs/BENCHMARKS.md](BENCHMARKS.md) measure the cost of holding
that line; this document measures the design against the field that
sometimes holds it and often doesn't.

The summary, frankly stated: **edge is closest in architectural
shape to Reticulum (Python reference) — that is by design, since
edge vendors Leviculum which is a fork of Reticulum's Rust port.
Edge's differentiators relative to Reticulum are the policy layer
above the wire** (typed handler dispatch, hybrid PQC, multi-tier
delivery semantics, recursive multi-sig). **Edge is closest in
crypto stance to libp2p** (mandatory wire-layer signature
verification) **but distinguished by hybrid PQC on day 1 vs.
libp2p's Ed25519/secp256k1 classical-only posture**. **Edge is
explicitly NOT** competing with NATS / gRPC on raw throughput;
verify-at-the-wire is non-negotiable, and the throughput floor is
the cost of holding that invariant.

---

## Part I: Comparison Against Mesh/Federation Peers

### 1. libp2p (rust-libp2p)

The foundational Rust mesh framework. Decade of production
deployment; powers IPFS, Polkadot, Filecoin, and a long tail.

**Reference**: [github.com/libp2p/rust-libp2p](https://github.com/libp2p/rust-libp2p)

| Aspect | rust-libp2p | CIRISEdge |
|---|---|---|
| Transport diversity | TCP, QUIC, WebSocket, WebRTC, WebTransport, memory; tor (3rd-party) | Reticulum (canonical), HTTP (fallback); LoRa / serial / I²P via Leviculum future |
| Peer discovery | Kademlia DHT, mDNS, rendezvous server, identify | Reticulum announce + `AnnounceAttestation` (CIRISEdge#15) |
| Delivery semantics | request/response, gossipsub, floodsub, ping; durable: 3rd-party | Ephemeral / Durable / Federation / Mandatory — typed at the `Message` impl, not the call site |
| Attestation | Noise XX handshake (Ed25519 / secp256k1 / RSA / Ecdsa) | Hybrid Ed25519 + ML-DSA-65 on every envelope + announce-binding attestation |
| Cohabitation model | One Swarm per process; multi-tenant via `NetworkBehaviour` composition | Same-wheel cohabitation with persist via PyCapsule (CIRISEdge#22 / persist#109) |
| Config-as-code | `SwarmBuilder` (in-code only); no canonical config file format | `EdgeBuilder` + edge#25 config-as-code (proposed) |
| Event observability | `Swarm: Stream<Item = SwarmEvent>` (per-event tokio Stream) | Inline-text subscriber registry + per-MessageType handler; `SubscriptionHandle` (v0.9.0 Tier 2) |

**CIRISEdge Alignment vs libp2p**:

- ✅ Mandatory wire-layer verification before any application code
  sees a byte — both projects share this discipline
- ✅ Address-from-public-key (`PeerId = multihash(pubkey)` in libp2p;
  `dest = sha256(pubkey)[..16]` in edge via Reticulum)
- ✅ Trait-based transport abstraction — `Transport` in both projects
  (one of the few cases where the names are literally the same)
- ⚠️ Edge is **not** trying to be libp2p's breadth — edge ships ONE
  canonical wire (Reticulum) + one fallback (HTTP); libp2p ships
  five+ transports. Edge's apophatic bound: *"Not HTTP-first; not
  TCP-only; Reticulum is canonical"* (MISSION.md §1.4) means we
  deliberately reject the "many-transport-equal-citizenship" stance
  libp2p takes. Edge declares one canonical wire because pluralism
  on transport is achieved through Reticulum's medium-agnostic
  shape (TCP + LoRa + serial + I²P under one interface), not
  through stacking N transport crates.
- ❌ Edge has no DHT — peer discovery is via signed-announce-rooted-
  against-persist's-`federation_keys`-directory, not a Kademlia
  routing table. This is by design (`PeerResolver` cold-start path,
  CIRISEdge#15 / AV-42) — a DHT is a routing-table-of-record, and
  the federation rejects routers-of-record (MISSION.md §1.4
  anti-pattern: *"Not a broker; not a router-of-record"*).
- ❌ No gossipsub — edge's `Delivery::Mandatory` is broadcast-to-
  every-peer-in-directory, not topic-based gossip. PoB §5.6 is the
  federation-level acceptance policy; topic-based subscription is
  application-layer (the host crate's concern).

**Gaps identified**:

- libp2p's NAT-traversal story (`AutoNAT`, `DCUtR`, hole-punching)
  has no edge equivalent yet — Reticulum's transport-tier handles
  this for LoRa / serial but the TCP / HTTP path assumes routable
  endpoints. **Track for v1.1.x** (`OQ-DCUtR` would be the entry).
- libp2p's identify protocol gives a peer's claimed capabilities;
  edge has no analog — peers must know each other's `MessageType`
  support out-of-band. This is intentional (typed `Message` impls
  are compile-time, not runtime), but a `CapabilityDescriptor`
  message that ships per-peer at announce time would close the gap
  without violating the typed-handler discipline.

**Frank assessment**: edge is **not** "libp2p but smaller." libp2p
is a generic mesh substrate aiming for protocol-pluralism; edge is
a federation-substrate aiming for verify-at-the-wire on every
envelope with a fixed crypto policy. The architectural Venn diagram
has overlap (trait-based transports, public-key addressing,
mandatory verify) but the centers are different.

### 2. iroh / iroh-net

Modern Rust mesh — QUIC-based, magicsock-routed, magic-DNS
discovery. The "what would libp2p look like if you started over in
2023" project.

**Reference**: [github.com/n0-computer/iroh](https://github.com/n0-computer/iroh)

| Aspect | iroh | CIRISEdge |
|---|---|---|
| Transport diversity | QUIC over UDP (with relay fallback) | Reticulum + HTTP |
| Peer discovery | `NodeId` (Ed25519 pubkey) → magicsock relay; DNS-based discovery | Signed announce-attestation + persist directory rooting |
| Delivery semantics | bidirectional QUIC streams; iroh-gossip for pub/sub; iroh-blobs for content | Ephemeral / Durable / Federation / Mandatory + `ContentFetch`/`ContentBody` (CIRISEdge#21) |
| Attestation | QUIC handshake (TLS 1.3 with self-signed cert keyed by NodeId Ed25519) | Hybrid Ed25519 + ML-DSA-65 + announce-attestation |
| Cohabitation model | One `Endpoint` per process; embed via `iroh-net` crate | Edge as embeddable Rust crate (`crate-type = ["cdylib", "rlib"]`) |
| Config-as-code | `Endpoint::builder()` in-code | `EdgeBuilder` + edge#25 |
| Event observability | `Endpoint::events_stream()` (async Stream) | `SubscriptionHandle` (v0.9.0) + per-handler dispatch |

**CIRISEdge Alignment vs iroh**:

- ✅ `NodeId` ↔ federation `key_id` analogy is exact — both are
  *public-key-derived* identifiers, not assigned by an authority
- ✅ Both wrap a single embeddable Rust crate (similar
  `cdylib`+`rlib` story for Python bindings)
- ✅ Both ship a relay/fallback for non-routable environments —
  iroh's `derp` relay, edge's HTTP fallback
- ⚠️ iroh's QUIC handshake gives 0-RTT after first contact; edge's
  per-envelope hybrid verify is ~280 µs every time. iroh trades
  ongoing per-envelope verify cost for per-session crypto state;
  edge trades per-session state for stateless wire-layer verify
  (which lets a relay never know it's a relay)
- ❌ iroh is Ed25519-only (TLS 1.3 with Ed25519 self-signed cert).
  No PQC posture. **This is the single sharpest differentiator** —
  edge's hybrid Ed25519 + ML-DSA-65 day-1 stance is what edge ships
  that iroh does not, and the gap will grow as PQC standards
  mature (FIPS 204 finalized August 2024; NSA CNSA 2.0 dates
  classical signing "Prefer By 2025, Exclusive By 2030")

**Gaps identified**:

- iroh-blobs is **better** than edge's `ContentFetch` Phase 1
  (single-frame allocation, capped at `MAX_BODY_BYTES`) — iroh-blobs
  ships content-addressed transfer with BLAKE3 verification and
  range requests. Edge's Phase 2 (`MessageType::ContentChunk`, see
  messages/mod.rs:1270) is the proposed closure but is not yet
  implemented; iroh-blobs is the reference to study.
- iroh's magic-DNS auto-discovery (encrypted DNS records keyed by
  NodeId) is more ergonomic than edge's manual rooting via persist
  directory — but the trade-off is that magic-DNS leans on DNS as
  a discovery infrastructure (which is a centralization vector
  edge structurally rejects, §1.4 MISSION.md)

**Frank assessment**: edge is **closest in spirit to iroh** of any
project in this comparison — same scale, same Rust-first stance,
same "embeddable crate" shape. The architectural differences are
narrow (QUIC vs Reticulum; classical Ed25519 vs hybrid PQC; magic
DNS vs persist directory) but each difference is load-bearing for
edge's M-1 alignment. **If iroh had hybrid PQC and didn't depend
on DNS for discovery, edge's existence would be harder to
justify**. As it stands, the divergence holds.

### 3. Reticulum (Python reference implementation)

The protocol edge vendors via Leviculum. Markqvist's foundational
Python implementation; the reference for the wire spec.

**Reference**: [github.com/markqvist/Reticulum](https://github.com/markqvist/Reticulum)

| Aspect | Reticulum (Python) | CIRISEdge |
|---|---|---|
| Transport diversity | TCP, UDP, LoRa, packet radio (KISS), serial, I²P, RNode | Reticulum (Leviculum-backed) — same medium set, Rust impl |
| Peer discovery | Announce-driven; destination hash = `sha256(pubkey)[..16]` | Same primitive; rooted via `root_binding` against persist directory (AV-42) |
| Delivery semantics | Packet, Link, Resource (size-tiered) | Same wire shapes; *typed* `Delivery` layer above (`Ephemeral`/`Durable`/`Federation`/`Mandatory`) |
| Attestation | Announce signed by destination pubkey | Announce signed by *transport identity*; **plus** `AnnounceAttestation` binding transport-identity to federation `key_id` (the edge addition, CIRISEdge#15) |
| Cohabitation model | Standalone daemon (`rnsd`) or library import | Embedded Rust crate; shares persist's process and PyCapsule resources |
| Config-as-code | `reticulum.conf` — de-facto standard config format | `EdgeBuilder` (in-code); edge#25 declarative config (proposed) |
| Event observability | `RNS.Packet` callbacks; `Announce` callbacks | Typed `Handler` impls per `MessageType` |

**CIRISEdge Alignment vs Reticulum**:

- ✅ Cryptographic addressing — *direct lift*. `destination =
  sha256(pubkey)[..16]` is Reticulum's design; edge inherits it
- ✅ Multi-medium reach — Reticulum's `Interface` abstraction (TCP,
  LoRa, serial, I²P) is the model edge's `Transport` trait
  encodes. The same Reticulum wire envelope round-trips
  byte-equivalent across mediums
- ✅ No DNS, no CA, no broker — Reticulum's foundational stance.
  Edge is structurally aligned
- ⚠️ Edge adds typed `Message` discriminators where Reticulum keeps
  the bytes opaque. This is the policy-layer-above-the-wire
  distinction
- ➕ **Hybrid PQC on the envelope** — Reticulum is Ed25519 +
  X25519. Edge adds ML-DSA-65 to the verify path (consumed via
  CIRISVerify v3.0.1 `ciris-keyring`). This is edge's contribution
  to the Reticulum lineage
- ➕ **Authenticated transport-identity binding (AV-42)** — edge's
  `AnnounceAttestation` binds the Reticulum transport identity to
  a federation `key_id` via a federation-key signature.
  Reticulum's native announce is signed only by the transport
  identity itself (trust-on-first-use for the transport pubkey,
  with no binding to an external identity authority)

**Gaps identified**:

- Reticulum's `Transport.find_path()` is a path-discovery primitive
  edge does not yet surface — peers in a multi-hop mesh need
  explicit path setup before Resource transfer. Leviculum exposes
  this; edge's API does not. Track for the LoRa-mesh Phase 3
  productionization
- Reticulum's `reticulum.conf` is operator-readable; edge's
  `EdgeBuilder` is code-readable. Both have merit; edge#25 is the
  proposed config-as-code surface that closes the operator gap
  without sacrificing type safety

**Frank assessment**: **edge is the Rust policy layer above
Reticulum's wire**. The honest framing: if you removed CIRISEdge's
hybrid-PQC posture, typed `Message` dispatch, federation
`Delivery` semantics, and AV-42 attestation, you would have
Leviculum (the Rust port of Reticulum). Edge is *what makes
Reticulum federation-grade for CIRIS specifically*, not a generic
mesh competitor. **This is intentional and named in MISSION.md
§2: "the Leviculum stack" is one of edge's listed protocol
contracts.** Edge is a deliberate vertical extension of
Reticulum, not a competitor.

### 4. MeshChat (Reticulum-based UI)

Liam Cottle's Reticulum-based chat UI. Closest reference for what
edge's Network screen should look like when a host application
needs operator visibility into the peer graph.

**Reference**: [github.com/liamcottle/reticulum-meshchat](https://github.com/liamcottle/reticulum-meshchat)

| Aspect | MeshChat | CIRISEdge |
|---|---|---|
| Transport diversity | Reticulum (all interfaces) | Reticulum (Leviculum) + HTTP |
| Peer discovery | Reticulum announce + manual contact-add | Authenticated announce-rooting via persist directory |
| Delivery semantics | Single-tier (lxmf messages) | Four-tier (`Ephemeral`/`Durable`/`Federation`/`Mandatory`) |
| Attestation | Reticulum native (transport-identity signed) | + hybrid PQC + `AnnounceAttestation` |
| Cohabitation model | Standalone Electron-or-Web app | Embeddable Rust crate |
| Config-as-code | JSON config files | edge#25 proposed |
| Event observability | Real-time WebSocket UI updates | Per-handler dispatch + subscriber bus |

**CIRISEdge Alignment vs MeshChat**:

- ✅ Both ride Reticulum's announce + Resource for discovery and
  transfer
- ✅ Both treat the destination hash as the identity — no usernames
- ⚠️ MeshChat is an application; edge is a transport substrate.
  The comparison axis is "what edge enables a host crate to
  build" vs "what MeshChat ships as a product"

**Frank assessment**: MeshChat is the reference for what an edge
host crate's Network screen should look like — peer-list-by-
destination-hash, signal-strength-or-RTT indicator, contact-add
via announce-receipt. **Edge's contribution is the transport
substrate underneath; MeshChat is what gets built on top of it
when the host crate is a chat app.** Not a competitor; an
inspiration for the host-crate UI layer.

### 5. Sideband (Reticulum messaging)

Markqvist's Reticulum-based messaging app. Same audience as
MeshChat; reference for mobile-first Reticulum.

**Reference**: [github.com/markqvist/Sideband](https://github.com/markqvist/Sideband)

| Aspect | Sideband | CIRISEdge |
|---|---|---|
| Transport diversity | Reticulum (TCP, LoRa, Bluetooth — Android) | Reticulum + HTTP; LoRa / Bluetooth via Leviculum (Phase 3) |
| Peer discovery | Reticulum announce + LXMF | `AnnounceAttestation` + rooting |
| Delivery semantics | LXMF (Lightweight eXtensible Message Format) | Four-tier `Delivery` |
| Attestation | LXMF signature (Ed25519) | Hybrid Ed25519 + ML-DSA-65 |
| Cohabitation model | Standalone mobile app (Kivy) | Embeddable Rust crate; mobile via CIRISEdge#17 Android NDK |
| Config-as-code | App-internal config | edge#25 |
| Event observability | LXMF inbox callbacks | Typed handler dispatch |

**CIRISEdge Alignment vs Sideband**:

- ✅ Both target mobile deployments as first-class (Sideband ships
  Android Play Store; edge ships Android NDK builds via
  CIRISEdge#17, mirroring CIRISPersist#96–99 pattern)
- ✅ Both treat LoRa as a peer, not a degraded tier
- ⚠️ Sideband uses LXMF (a Reticulum-native message format); edge
  defines its own `EdgeEnvelope` typed format. The two are not
  interoperable at the message layer — that is by design (LXMF is
  human-messaging; `EdgeEnvelope` is federation-machine-messaging)

**Frank assessment**: Sideband is the operator-deployment proof
that Reticulum-as-canonical-wire works on mobile + LoRa in the
field. **Edge's CIRISEdge#17 Android NDK story is calibrated
against Sideband's deployment model.** Different message format,
same medium stance.

### 6. Briar (Java/Android meet-in-person trust)

Java/Android federated messenger with meet-in-person QR-based
trust and Tor + Bluetooth + WiFi transport.

**Reference**: [briarproject.org](https://briarproject.org/)

| Aspect | Briar | CIRISEdge |
|---|---|---|
| Transport diversity | Tor, Bluetooth, WiFi mesh | Reticulum + HTTP; Bluetooth via Leviculum (Phase 3) |
| Peer discovery | QR-code exchange (meet-in-person) | Signed announce + persist rooting |
| Delivery semantics | Store-and-forward via mailbox; per-conversation transport | `Durable` (persist queue + ACK matching) |
| Attestation | Per-contact key exchange (BHTP protocol) | Hybrid Ed25519 + ML-DSA-65 on every envelope |
| Cohabitation model | Standalone Android app | Embeddable crate |
| Config-as-code | App config | edge#25 |
| Event observability | Conversation event stream | Per-handler dispatch |

**CIRISEdge Alignment vs Briar**:

- ✅ Both reject DNS / CA / broker dependencies
- ⚠️ Briar's meet-in-person QR trust is **stronger** than edge's
  directory-rooting for first-contact (the QR exchange is
  physically attested); edge depends on persist's
  `federation_keys` directory being sound (THREAT_MODEL.md
  Assumption 1 — "load-bearing"). For peer-to-peer first contact
  *without an external directory*, Briar is the reference
- ❌ Briar has no PQC posture
- ❌ Briar's store-and-forward via mailbox is conceptually similar
  to edge's `Durable` delivery, but Briar's mailbox is a peer-
  owned service; edge's `edge_outbound_queue` is a persist-owned
  SQLite table. Architecturally different

**Frank assessment**: Briar's strongest contribution that edge
should learn from is **the QR-based bootstrap for peer-to-peer
first contact**. The federation directory is great when it exists
and is sound (Assumption 1); for two CIRIS peers meeting offline
in a LoRa-only environment with no directory access, a Briar-
style QR exchange of `(transport_pubkey, federation_key_id,
ed25519_pubkey, ml_dsa_pubkey)` would close the bootstrap gap.
**Track as `OQ-QR-bootstrap` for Phase 3.**

### 7. Matrix federation (Conduit / Synapse server-server)

The Matrix federation wire protocol — the server-server API that
homeservers use to talk to each other.

**Reference**: [github.com/conduit-rs/conduit](https://github.com/conduit-rs/conduit) (Rust impl); [spec.matrix.org](https://spec.matrix.org/v1.10/server-server-api/)

| Aspect | Matrix federation | CIRISEdge |
|---|---|---|
| Transport diversity | HTTPS only (server-server API) | Reticulum canonical; HTTP fallback |
| Peer discovery | DNS SRV records (`_matrix._tcp.<domain>`) + `.well-known/matrix/server` | Signed announce + persist rooting (no DNS) |
| Delivery semantics | Persistent Data Units (PDUs) with hash-chain causality | Typed `Delivery` classes + `body_sha256` join key |
| Attestation | Ed25519 signing of PDUs by homeserver | Hybrid Ed25519 + ML-DSA-65 on `EdgeEnvelope` |
| Cohabitation model | Homeserver-per-domain (DNS-bound) | Per-deployment (key-bound; no DNS) |
| Config-as-code | YAML/TOML per server | edge#25 |
| Event observability | EDU stream + federation transactions | Per-handler dispatch |

**CIRISEdge Alignment vs Matrix federation**:

- ✅ Both sign at the envelope/PDU layer (Matrix Ed25519 PDU
  signatures vs edge hybrid envelope signatures)
- ⚠️ Matrix's PDU hash-chain is *causality* — every PDU references
  prior PDUs to establish a partial order. Edge has no
  hash-chain causality at the wire layer; `in_reply_to`
  (`body_sha256` of the parent envelope) gives ACK-matching but
  not full DAG causality. **This is intentional** — wire-layer
  causality is a persist-layer concern (the audit chain in
  CIRISVerify's domain), not a transport concern
- ❌ Matrix's reliance on DNS for federation routing is the
  architectural choice edge most explicitly rejects. A Matrix
  homeserver behind a CA-issued cert behind a DNS A-record is
  three centralization vectors stacked; edge's
  `destination_key_id` is none of them
- ❌ Matrix is HTTPS-only — no mesh, no LoRa, no Reticulum

**Frank assessment**: Matrix is what edge is **not trying to be**.
Matrix is a federated-but-DNS-bound architecture; edge is a
mesh-first cryptographically-addressed architecture. The
comparison axis is informative for "what does federated wire
look like at scale" (Matrix has the deployment scale) but not
for "what should edge's wire look like."

### 8. Hyperswarm (DAT/Hyper DHT)

The DAT project's DHT-based peer discovery. The reference for
hash-table-based mesh routing without central authority.

**Reference**: [github.com/hyperswarm/hyperswarm](https://github.com/hyperswarm/hyperswarm)

| Aspect | Hyperswarm | CIRISEdge |
|---|---|---|
| Transport diversity | UDP DHT for discovery; TCP/UTP for transfer | Reticulum + HTTP |
| Peer discovery | Kademlia-style DHT over UDP; topic-based lookup | Announce + persist directory rooting |
| Delivery semantics | Stream-per-peer (`Duplex`) | Typed `Message` + `Delivery` |
| Attestation | Noise (XX) handshake | Hybrid envelope sig + attestation |
| Cohabitation model | Embeddable Node.js library | Embeddable Rust crate |
| Config-as-code | JS-only | edge#25 |
| Event observability | EventEmitter (Node.js native) | Per-handler dispatch + subscriber bus |

**CIRISEdge Alignment vs Hyperswarm**:

- ✅ Both ship as embeddable libraries, not standalone daemons
- ❌ Hyperswarm is DHT-routed; edge is directory-rooted (the same
  trade-off as the libp2p comparison — DHT routing is
  decentralized but trusts the routing table; edge directory
  rooting trusts persist's directory, which is bootstrapped from
  the federation steward set)

**Frank assessment**: Hyperswarm proves DHT-based mesh discovery
works at scale; edge deliberately doesn't use a DHT because the
federation already has an authority structure (the steward set
+ rooted `federation_keys` directory). DHT routing would be
*redundant* — edge would be carrying two routing-of-record
mechanisms.

### 9. NATS JetStream (durable messaging reference)

The high-throughput durable-messaging reference. The throughput
ceiling for "messaging without verify-at-the-wire."

**Reference**: [github.com/nats-io/nats.rs](https://github.com/nats-io/nats.rs)

| Aspect | NATS JetStream | CIRISEdge |
|---|---|---|
| Transport diversity | TCP, WebSocket; clustered + leaf-node topologies | Reticulum + HTTP |
| Peer discovery | Static config + cluster gossip | Signed announce + persist directory |
| Delivery semantics | At-most-once, at-least-once, exactly-once; durable streams | Ephemeral / Durable / Federation / Mandatory |
| Attestation | TLS + NKey/JWT for auth | Hybrid PQC on every envelope |
| Cohabitation model | Standalone daemon (nats-server) | Embeddable crate |
| Config-as-code | `nats-server.conf` (de-facto reference) | edge#25 |
| Event observability | Subscription consumer | `SubscriptionHandle` (v0.9.0 Tier 2) |

**CIRISEdge Alignment vs NATS**:

- ✅ Both name durable delivery as a first-class tier (NATS
  JetStream durable streams; edge `Delivery::Durable` + persist's
  `edge_outbound_queue`)
- ✅ Both name event-bus throughput as a benchable axis
- ❌ NATS does **not** verify per-envelope; auth is at the
  connection layer (TLS + NKey). NATS hits ~3 M msg/sec because
  it doesn't pay per-message verify cost. Edge pays ~280 µs per
  envelope. **This is the structural throughput gap — and it is
  load-bearing**. NATS is the *what we'd be if verify-at-the-
  wire weren't mission-critical*; we are not it

**Frank assessment**: NATS is the throughput ceiling edge will
**never reach by design**. The cost asymmetry is the AV-1
defense — NATS would accept any in-cluster envelope (it trusts
the connection); edge rejects any envelope whose hybrid sig
doesn't verify against the directory. The gap is the cost of
mission alignment.

### 10. gRPC bidirectional streams (RPC + duplex streaming)

The de-facto reference for typed bidirectional streaming with
Protobuf wire format. The pattern most enterprise RPC follows.

**Reference**: [github.com/hyperium/tonic](https://github.com/hyperium/tonic)

| Aspect | gRPC (tonic) | CIRISEdge |
|---|---|---|
| Transport diversity | HTTP/2 | Reticulum + HTTP |
| Peer discovery | DNS + service mesh (Envoy / Linkerd / etc.) | Signed announce + directory |
| Delivery semantics | Unary / server-stream / client-stream / bidi | Typed `Message` + `Delivery` |
| Attestation | TLS (mTLS optional) | Per-envelope hybrid sig |
| Cohabitation model | Embeddable Rust crate | Embeddable Rust crate |
| Config-as-code | `.proto` files (schema-first) | `Message` Rust traits + edge#25 |
| Event observability | Streaming RPC handlers | Per-handler dispatch |

**CIRISEdge Alignment vs gRPC**:

- ✅ Both are typed-at-the-schema-boundary (Protobuf vs Rust
  `serde::Deserialize` impls); both reject untyped bytes past the
  parse boundary
- ❌ gRPC's auth is at the channel layer (mTLS); edge's is at the
  envelope layer. The trade-off is the same as NATS — channel
  auth is fast and lets the RPC handler trust everything past
  parse; envelope auth pays per-message cost but lets the
  envelope be relayed without losing the auth context
- ❌ gRPC is HTTP/2-only — same DNS/CA dependency as Matrix

**Frank assessment**: gRPC is the typed-RPC stance edge inherits
(`MessageType` discriminator + per-type `Handler` impls) but with
envelope-layer auth instead of channel-layer. Useful inspiration
for the schema discipline; not a competitor.

---

## Part II: Standards Alignment

### W3C Decentralized Identifiers (DID)

W3C DID v1.0 (recommended 2022) defines a URI scheme for
self-sovereign identity: `did:method:identifier`.

**Reference**: [w3.org/TR/did-core/](https://www.w3.org/TR/did-core/)

| Aspect | W3C DID | CIRISEdge |
|---|---|---|
| Identifier shape | `did:method:identifier` (URI) | `signing_key_id` (hex-encoded sha256-prefix-of-pubkey) |
| Method registry | Open ecosystem of methods (did:key, did:web, did:ion, etc.) | One method: persist's `federation_keys` directory rooting |
| Key resolution | DID Document resolved via method-specific resolver | `lookup_public_key(signing_key_id)` via persist directory |
| Verifiable credentials | W3C VC ecosystem | `EdgeEnvelope` body bytes (typed `Message` impls) |

**CIRISEdge Alignment**:
- ⚠️ Edge's `signing_key_id` is conceptually a DID — public-key-
  derived, self-sovereign — but does not use the `did:` URI scheme
- ✅ Could expose a `did:ciris:<key_id>` method that resolves to the
  persist `federation_keys` row; documenting this would close the
  integration gap with W3C VC tooling

**Gap**: edge does not advertise a DID method. **Track as v1.1.x
docs work** — define `did:ciris` method spec.

### libp2p PeerId / iroh NodeId — the address-from-public-key pattern

Not a formal standard, but a strong convergent pattern across
modern mesh projects:

- **libp2p PeerId**: `multihash(pubkey)` — typically `Qm...` base58
  for sha256, or `12D...` for Ed25519
- **iroh NodeId**: raw 32-byte Ed25519 public key (no hash)
- **Reticulum destination**: `sha256(pubkey)[..16]` — 16-byte hash
- **CIRISEdge `signing_key_id`**: persist-managed identifier
  derived from public key

**CIRISEdge Alignment**: ✅ structurally aligned with the
address-from-key convergence; the specific encoding is
persist's responsibility (CIRISVerify#27 / CIRISPersist rooting).

### ActivityPub (W3C federated social-web)

W3C ActivityPub (2018) defines a federated social-web protocol:
HTTPS POST of JSON-LD Activities to inboxes, with HTTP Signatures
for sender auth.

**Reference**: [w3.org/TR/activitypub/](https://www.w3.org/TR/activitypub/)

| Aspect | ActivityPub | CIRISEdge |
|---|---|---|
| Wire format | JSON-LD over HTTPS | Typed Rust structs over Reticulum / HTTP |
| Auth | HTTP Signatures (RFC 9421) | Hybrid PQC on `EdgeEnvelope` |
| Discovery | WebFinger + `.well-known/webfinger` | Signed announce + persist directory |
| Delivery | Per-actor inbox URL | `signing_key_id` + transport directory |

**CIRISEdge Alignment**:
- ❌ Edge is not JSON-LD; not HTTPS-only; not WebFinger-discovered.
  ActivityPub assumes DNS as discovery infrastructure
- ✅ The signed-envelope-to-inbox shape is conceptually similar;
  the typed wire format differs

**Frank assessment**: ActivityPub solved "federated wire" at the
web tier with DNS as the trust anchor; edge solves it at the mesh
tier with cryptographic addressing as the trust anchor. Different
deployment models; not a competitive comparison.

### Reticulum.conf — operator config-as-code

`reticulum.conf` (Reticulum's INI-style config) is the de-facto
standard config format in the Reticulum ecosystem. MeshChat,
Sideband, NomadNet all extend it.

**CIRISEdge Alignment**:
- ⚠️ Edge does not currently consume `reticulum.conf` — Leviculum
  is initialized via Rust API (`reticulum-std::node::Node`)
- ✅ **edge#25 (proposed)**: a declarative config-as-code surface
  that reads operator-supplied Reticulum interface declarations
  and bridges them into the `Transport` trait construction. This
  closes the operator-readability gap

**Gap**: edge#25 is the tracker; this is forward-looking work.

### Briar BHTP (meet-in-person trust)

Briar's BHTP (Briar Handshake and Transport Protocol) defines a
QR-based meet-in-person trust bootstrap.

**CIRISEdge Alignment**:
- ❌ Edge has no meet-in-person bootstrap; first contact requires
  persist's federation directory to know the peer
- **Gap**: see Briar frank-assessment above. `OQ-QR-bootstrap`
  proposed for Phase 3

### Signal Safety Numbers / pubkey-fingerprint comparison

Signal's "safety numbers" — operator-visible numeric encoding of
the pairwise pubkey fingerprint, for out-of-band verification.

**CIRISEdge Alignment**:
- ⚠️ Edge has `signing_key_id` (the public-key-derived identifier)
  but does not surface a human-readable pairwise fingerprint
- ✅ Could be added at the host-crate UI layer (host renders
  `signing_key_id` as base32 + word-list); not edge's concern at
  the substrate layer

### AsyncIterator event-stream pattern (libp2p + iroh)

Both libp2p and iroh expose events as `Stream<Item = Event>` (Rust
async stream). Not formally standardized but convergent across
the modern mesh field.

**CIRISEdge Alignment**:
- ⚠️ Edge does **not** expose a single unified event stream
  currently — events are per-handler dispatch + inline-text
  subscriber registry (`SubscriptionHandle`, v0.9.0 Tier 2). The
  per-handler model is more typed; the unified stream is more
  ergonomic
- **Gap (architectural choice, not deficiency)**: edge could
  expose an `Endpoint::events_stream()` analog as an opt-in
  surface above the handler dispatch, mirroring iroh's pattern.
  Track as v1.1.x ergonomics work

---

## Part III: Differentiators

What CIRISEdge does that **none of the projects in Part I
do**, ordered by load-bearing-ness for M-1 alignment:

### 1. Hybrid Ed25519 + ML-DSA-65 on every envelope (day-1 posture)

No mesh-transport peer in Part I ships PQC on the wire. libp2p,
iroh, Reticulum, MeshChat, Sideband, Briar, Matrix, Hyperswarm,
NATS, gRPC — all are Ed25519 / secp256k1 / Ecdsa / TLS-1.3-RSA at
best. Edge ships hybrid PQC on every envelope from v0.1.0 (OQ-11
closure, [docs/THREAT_MODEL.md](THREAT_MODEL.md) Residual §9.2).
The cost is measured in [docs/BENCHMARKS.md](BENCHMARKS.md)
(`envelope_verify` ~280 µs hybrid vs ~20 µs Ed25519-only — the
14× factor is what edge pays for harvest-now-decrypt-later
resistance).

### 2. Multi-tier delivery semantics typed at the `Message` impl

Most peers offer one delivery tier (libp2p request/response,
iroh QUIC streams, Reticulum Packet/Link/Resource, Matrix PDU,
NATS subjects). Edge ships **four typed `Delivery` classes** —
`Ephemeral` / `Durable` / `Federation` / `Mandatory` — chosen at
the `Message` impl, not at the call site (`handler.rs`). A
caller cannot pick the wrong delivery class; the type system
enforces it (OQ-09 closure). This is the federation policy
layer above the wire that the mesh-transport peers don't have.

### 3. Recursive Golden Rule wire-layer multi-sig verification (CIRISEdge#19)

The `AccordCarrier` 2-of-3 multi-sig check is **wire-layer**, not
application-layer. Most projects defer multi-sig to the
application (libp2p apps roll their own; Matrix has no analog;
iroh has no analog). Edge verifies threshold signatures at the
`verify/` pipeline before any handler is invoked — a
threshold-sig fail is a typed wire-level reject. This is the
*Golden Rule* (the Accord requires the threshold of stewards
attest) rendered as wire-layer enforcement.

### 4. Cohabitation contract via PyCapsule (CIRISEdge#22 + persist#109)

Two Python wheels (edge + persist) loaded into the same
interpreter share the **same persist `Engine`** without
cross-module PyClass identity (the v0.9.1 cohabitation
regression). PyCapsule accessors on `PyEngine`
(`federation_directory_capsule`, `outbound_queue_capsule`,
`keyring_signer_capsule`) let edge consume persist's substrate
through opaque-handle accessors. No mesh-transport peer in Part I
solves this — they assume single-extension-module deployment.

### 5. Verify-at-the-wire via authority delegation, never re-implementation

Every signing/verifying primitive is behind CIRISVerify
(`ciris-keyring` / `ciris-crypto`); every canonicalization rule is
behind CIRISPersist (`canonicalize_envelope_for_signing`). Edge
takes **zero** direct deps on `ed25519` / `ml-dsa` / `sha2`-as-a-
signer primitives (MISSION.md §1.4). The discipline is enforced
by `cargo deny` + PR review. No other project in Part I makes
this delegation contract explicit; libp2p re-implements its own
Noise; iroh re-implements its TLS handshake; Reticulum re-
implements its own crypto. Edge's stance — *consume an external
crypto authority, never re-implement* — is structurally
auditable in a way the peer projects' merged crypto + transport
modules are not.

### 6. CIRIS Accord-grounded design

Every architectural decision cites the Accord. M-1 (sustainable
adaptive coherence) is the constraint. The corridor (`k_eff =
k / (1 + ρ(k−1))`) is the cosmology. No mesh-transport peer in
Part I is grounded in an ethics-framework-as-spec the way edge
is. **This is not a marketing differentiator** — it is what
makes the apophatic bound (`§1.4 MISSION.md`) testable: edge
*will not* become a broker, *will not* hold seed bytes, *will
not* default to HTTP, *will not* trust-on-first-use, because
each refusal cites a Principle from the Accord and breaking the
refusal is a mission violation that fails PR review on grounds
beyond style.

---

## Part IV: v1.0 SOTA Targets

The benchmark numbers (in [docs/BENCHMARKS.md](BENCHMARKS.md))
edge measures itself against on the path to v1.0. Calibrated
against the peers above.

| Axis | Target | Calibration anchor |
|---|---|---|
| `envelope_verify` rate, single-thread | > 3.5 K verifies/sec (hybrid Ed25519 + ML-DSA-65) | CIRISVerify v2.7.0 `hybrid_verify` 276 µs ⇒ 3 623 verifies/sec; edge inherits |
| `envelope_verify` rate, 8-thread | > 25 K verifies/sec | Linear scaling assumption; verify is CPU-bound and independent |
| `dispatch_inbound` (256 B typical envelope) | < 400 µs end-to-end | Verify 280 µs + canonicalize 10 µs + replay-window 5 µs + handler 80 µs |
| LocalInterface RTT | < 500 µs | iroh magicsock loopback ~200 µs + verify cost; edge floor is verify-dominated |
| HTTP loopback RTT | < 1 ms (256 B) | `axum` + `reqwest` loopback + verify |
| `subscription_throughput` (1 Python subscriber) | > 50 K events/sec | NATS at ~3 M (no verify); edge at verify-bound floor of ~3.5 K verifies × batched fan-out to 1 subscriber ≈ 50 K |
| `subscription_throughput` (16 concurrent subscribers) | > 15 K events/sec | GIL contention floor — batched drainer holds the line |
| `outbound_enqueue` (`Durable`) | < 1.5 ms | persist SQLite write ~1 ms + sign ~466 µs |
| `steward_fanout` (N = 16) | < 24 ms | Linear in N (1.5 ms × 16) |
| `content_fetch_roundtrip` (4 KiB) | < 2 ms | SHA-256 verify @ ~3 GiB/s + loopback |
| `accord_threshold_verify` (3 of 3 valid) | < 900 µs | 3 × ~280 µs verify (every holder's sig checked — fail-loud, no short-circuit) |
| Wheel size (Python distribution) | < 20 MiB | Leviculum + persist + crypto + edge (iroh-py ~12 MiB; libp2p-py ~25 MiB) |

**Throughput floor**: hybrid PQC on every envelope sets a hard
ceiling at ~3.6 K verifies/sec single-thread. Closing the gap to
NATS (~3 M msg/sec) is not on the roadmap; the gap **is the cost
of M-1 alignment**, measured and named.

**Bandwidth floor**: Reticulum's per-medium throughput (LoRa
~5 kbps; serial ~115 kbps; TCP ~Gbit/s) bounds the per-transport
RTT. Edge does not optimize per-medium; Leviculum does.

---

## Sources

- [libp2p documentation](https://docs.libp2p.io/)
- [iroh documentation](https://iroh.computer/docs)
- [Reticulum Network Stack manual](https://markqvist.github.io/Reticulum/manual/)
- [MeshChat GitHub](https://github.com/liamcottle/reticulum-meshchat)
- [Sideband GitHub](https://github.com/markqvist/Sideband)
- [Briar project](https://briarproject.org/)
- [Matrix Server-Server API](https://spec.matrix.org/v1.10/server-server-api/)
- [Hyperswarm GitHub](https://github.com/hyperswarm/hyperswarm)
- [NATS JetStream documentation](https://docs.nats.io/nats-concepts/jetstream)
- [tonic (gRPC for Rust)](https://github.com/hyperium/tonic)
- [W3C DID v1.0](https://www.w3.org/TR/did-core/)
- [W3C ActivityPub](https://www.w3.org/TR/activitypub/)
- [Reticulum: Cryptographic Primitives and Properties](https://markqvist.github.io/Reticulum/manual/understanding.html#cryptographic-primitives)

---

**Document Status**: v1.0 — establishes the v1.0 SOTA targets
**Baseline release**: CIRISEdge v0.10.0
**Cross-references**:
[MISSION.md](../MISSION.md) (M-1 alignment) |
[docs/THREAT_MODEL.md](THREAT_MODEL.md) (AV-* invariants) |
[docs/BENCHMARKS.md](BENCHMARKS.md) (measured against these targets)
**Next Review**: post-v1.0 cut — re-measure against the peer field's
v1.x releases (libp2p 0.55+, iroh 0.30+, NATS 2.11+)
