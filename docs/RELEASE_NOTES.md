# CIRISEdge Release Notes

# v20.1.0 — chat attribution is the attester, never a claim (CIRISEdge#564)

**2026-09-03** — SECURITY. Reported by CIRISServer against v20.0.0.

## The defect

`ChatMessage::from_row` preferred the envelope's `on_behalf_of_key_id` over
`attesting_key_id`:

```rust
let author_key_id = env.get(FIELD_ON_BEHALF_OF)...
    .map_or_else(|| a.attesting_key_id.clone(), str::to_owned);
```

That member sits inside the attester's **own signed envelope**, so the
signature proves only that *the attester wrote that string* — never that the
named key authored anything. Any member of a room could set it to another
key's id and have the message render as that person's words; CIRISServer's
repro shows a row emitted under `bob-v1` coming back with the reader's owner
as `author` and `mine: true`.

Two things made it worse. The precedence was backwards for the v19+ model —
the human attests, `on_behalf_of_key_id` is documented "read, never written",
so the branch never taken for edge's own rows was the only attacker-controlled
one. And it contradicted edge's own crypto: `open_body` binds the seal to
`attesting_key_id`, so a row could decrypt as the attester and display as the
claim.

## The fix

- **`ChatMessage::author_key_id` is the ATTESTER** — the key whose hybrid
  signature persist verified against its registered pubkeys. `from_row` never
  reads authorship out of an envelope member.
- **`ChatMessage::on_behalf_of_claim: Option<String>` (NEW)** carries the raw
  member, named as what it is: an unverified claim by the attester.
- **`messages_in_room` promotes a claim only when a live owner binding backs
  it** (`owner_of(attester) == claim`) — the legitimate pre-v39 shape, where a
  node speaks for its owner. A node can satisfy that for its own owner and for
  nobody else, so the promotion is unforgeable. Fail-closed: an unresolvable or
  ambiguous owner promotes nothing. One owner walk per distinct attester.

**A minor, not a major.** `author_key_id`'s meaning changes (it no longer
returns the claim) and `ChatMessage` gains a public field — but v20.0.0 was
never adopted downstream, so no consumer holds the old meaning. Consumers that
defended themselves by projecting `attesting_key_id` — as CIRISServer does —
are already correct and can now use `author_key_id` directly.

## Witness

`a_forged_on_behalf_of_claim_projects_the_attester` builds a **properly
signed** forgery (the claim goes inside the envelope and the row is re-signed,
because mutating after signing is refused by `PromotionMovedThePreimage` — the
substrate working, not the attack), then asserts `from_row` attributes to the
attester, surfaces the claim separately, and that `messages_in_room` promotes
nothing without an owner binding.

Local: chat 22/22, lib 1447 passed, clippy `-D warnings` clean. Pins unchanged
(persist v40.0.0, verify v14.1.0, leviculum v0.24.0+ciris.1).

# v20.0.0 — a widening carries the claim's instant (adopt CIRISPersist v40.0.0)

**2026-09-03** — BREAKING, and the break is upstream's: persist v40.0.0
(CIRISPersist#801, reported by CIRISServer while adopting v39.0.0) fixes a
defect v39.0.0 shipped — `widen_audience` treated `asserted_at` as placement
bookkeeping and re-minted it, so a widening's signed instant was *when it was
placed*, not *when the claim was asserted*. Because a widening is the only row
a peer ever sees (a `self` row is structurally undiscoverable, CC 5.2), the
claim's own instant was unrecoverable off-node. v40 carries it verbatim and
gives the placement its own signed member, `widened_at`.

Persist calls it a MAJOR because `paths::WIDENED_AT` re-pins
`ENVELOPE_VOCABULARY_SHA256`. Edge does not assert that hash, and the four
persist hashes edge *does* pin are unchanged, as are all four ABI constants
and the wire vocabulary hash. Verify stays at v14.1.0 and leviculum at
v0.24.0+ciris.1 — one copy of each.

## What edge changes

- **`build_widening` takes the placement instant.** `attestation_bind`'s
  widening path passes ONE `now` to both `build_widening` (which signs it as
  `widened_at`) and `stamp_and_canonicalize`, so the act is recorded once
  while the claim's `asserted_at` is carried off the prior rather than
  re-minted.
- **The chat seal binds the claim's instant again.** v19.0.0 keyed the body
  under room + author + epoch and deliberately *excluded* the instant, because
  v39's re-stamping meant a key derived from it would open the author's own
  `self` copy and nothing else. v40 removes that constraint, so the HKDF info
  is room + author + **claim instant** + epoch: a ciphertext lifted onto any
  other row — another author's, another room's, or the same author's at a
  different instant — no longer opens. `seal_body` / `open_body` take the
  instant; `ChatMessage::from_row` reads it off the envelope, where a widening
  now carries the prior's.

**This is a wire break for chat.** A message sealed by v19.0.0 does not open
under v20.0.0 — its key was derived without the instant. Chat shipped one day
earlier with no deployed corpus, and the failure is honest
(`Body::Unopened { reason }`), not a crash, so there is no compatibility path.

## Witness

`a_widening_carries_the_claims_instant_and_records_its_own` asserts the
guarantee the seal now rests on, against real sqlite: the widening's
`asserted_at` equals the prior's verbatim, the column agrees, `widened_at` is
present, canonical (`.sssZ`) and not before the claim — and the far end opens
the widened row, which is the row it actually receives.

Pins: ciris-persist v40.0.0 (wheel floor `>=40,<41`), CIRISVerify v14.1.0,
leviculum v0.24.0+ciris.1.

# v19.0.0 — Promotion is two verbs and the ACTOR signs (adopt CIRISPersist v39.0.0)

**2026-09-03** — BREAKING. Adopts CIRISPersist v39.0.0 (CIRISEdge#562,
CIRISPersist#799): the one promotion primitive is gone and two operations
stand where it stood. `share` / `publish` now compose `enter_mesh` (tier
crossing over the SAME bytes — the actor's signature stays the base scrub,
the node may only APPEND a co-scrub with `cosigned_at`) and `widen_audience`
(a `supersedes` the ACTOR signs at a strictly wider `cohort_scope`; the prior
row is untouched). Design record: `docs/FSD_REPLICATION_DX.md` §0/§3 and
persist's `FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE.md` (read its §11).

## What broke, and why it had to

Under persist ≤ v38 `promote_attestation` re-signed every promoted row with
the NODE's key, cleared every co-scrub, and rewrote `cohort_scope` inside the
signed envelope — so the fabric became the author of an actor's claim, and a
row attested by anyone but the node was refused at every peer while promotion
returned `Ok`. Edge's `share` rode it, and the chat producer named the node as
attester with the human as `on_behalf_of_key_id` to survive it.

## Edge's surface (`replication::attestation_bind`)

- `share(dir, row, With, CrossingBasis, Signers)` / `publish(dir, row,
  CrossingBasis, Signers)`. `Signers { node, actor }` — the node is CUSTODY,
  the actor (the attester's signer, when in hand) SIGNS. `custody_for` decides
  who signs from the row (edge's copy of persist's `Engine::custody_for`
  table): signed at write by another key → the node co-scrubs; unsigned and
  attested by this node → the node signs as the actor; unsigned by another
  key with no signer → `AwaitingActor`; the WRONG key in hand → refused.
- **A widening share yields TWO rows.** `share(self-row, With::Community
  { .. })` leaves the original at `(federation, self)` (replicated to the
  owner's own devices, never advertised) plus a `supersedes` at `community`
  — the row the peer receives. `Shared::Placed { attestation_id }` carries
  the NEW row's id. `Shared::AlreadyThere` / `AwaitingActor` are typed; a
  narrowing is refused by name (`share_plan`, pure, before any directory).
- `With::MyFamily { family_key_id }` / `With::Community { community_key_id }`
  NAME their cohort (AV-45: a placement is a membership claim about one
  cohort). `EncryptedCohort` likewise.
- `CrossingBasis` — the `transmission_principle` axis rides the CALL
  (`ProducerAuthority` or a named `ConsentGrant`), validated against the
  stored grant; never a reseal member.
- **`Flow` is deleted.** `Crossing.ci` is persist's nine-axis
  `ContextualIntegrity` (CC 4.5.1.1: sender, data_subject, recipient_see,
  recipient_revoke, recipient_receive, information_type,
  transmission_principle, temporal_lifecycle, content), verified at the
  crossing and refused by axis name. `describe_crossing` is persist's own.
  `Crossing.routes_to` / `discoverable` say what edge does with it; `entered`
  / `widened` carry both verb outcomes verbatim.
- Removed: `promote_to_scope`, `describe_flow`, `already_promoted_verdict`,
  `truncate_to_micros`.

## Chat is ENCRYPTED — community tier is always encrypted

- **The body is sealed under the room's MLS record secret** (`RoomKey`, the
  group's record exporter; ciphersuite `0x004D` X-Wing) with
  XChaCha20-Poly1305, keyed through HKDF over the room, the author and the
  epoch. What crosses the wire — and what the relay and every non-member
  node holds — is ciphertext inside a signed envelope. There is no plaintext
  producer: `chat_message_attestation(author, recipient, body, at, key)`.
  `messages_in_room(.., key)` opens; a row that will not open is
  `Body::Unopened { reason }`, never dropped and never returned as text.
  A wrong key, a rotated epoch, another author's row or another room does
  not open (`a_wrong_key_epoch_or_context_does_not_open_the_body`).
- **The MLS handshake rides the room — directory-only MLS.** The joiner
  (`PairRole::Joiner`, the greater fed-ID) shares its KeyPackage as a
  community-scoped row (`chat:key_package:v1`); the creator admits it and
  shares the Welcome (`chat:welcome:v1`); the joiner joins. Both rows are
  ordinary rows the person signs (full hybrid), admitted against their
  directory record — that is what binds the MLS credential to the person —
  and served by the audience gate to exactly the other member's nodes.
  `mls::cohort_group::{key_package_to_bytes, key_package_from_bytes}` is the
  KeyPackage byte codec the harness used to hand-roll.
- The mesh harness now runs the handshake over the mesh (`ladder.open_chat`
  reports role, KeyPackage/Welcome sizes and waits, epoch), seals the
  message, and the receiver OPENS it with its own copy of the room key —
  failing the leg on a leaked self copy OR any chat row carrying the
  plaintext (`plaintext_on_wire`).

## Trust is derived, never read — the durable-store heal re-walks the chain

Found by the no-fallback rule: with every peer now hybrid, a peer whose
steward is NOT in this node's anchor was being attributed anyway. Its own
`SignedTransportDestination` (which `self_route` writes with
`binding_provenance: Rooted`) replicated into this node's directory, and the
#432 divergence heal treated the store's `Rooted` as this node's trust —
authenticated as "the peer said so", never walked against the anchor. That is
the confused-deputy shape #337 closed for bare rows, wearing a signature, and
it was masked only while classical-only peers could not publish the row at
all. `heal_or_report_attribution_miss` now re-runs `root_binding` (with the
key's registered pubkey — `RootingDirectory::registered_pubkey_ed25519_base64`,
new) under the transport's hybrid policy before upgrading, and a store claim
whose chain does not root here is `DivergenceHeal::StoreClaimUnrooted`:
logged, not laundered. `tests/route_table_e2e.rs`'s #393/#353 witnesses now
inject the peer as ADVISORY (`inject_advisory_peer_with_transport_identity_for_test`,
new) and are green for the reason they state — they had been green because
the peer was hybrid-pending.

## Every signature is the FULL hybrid — no classical-only fallback

`identity::sign_bound_hybrid` and `identity::sign_envelope` REFUSE a signer
without its ML-DSA-65 half, naming what was being signed. The old
warn-and-continue produced rows and envelopes every Strict verifier refused
one hop later with the cause lost. Every test and bench fixture moved to a
hybrid signer with the matching pubkey on its record.

## Discovery and chat waits kick the round — `sync_and_await`

`ReplicationRuntime::round_now(peer)` fires an anti-entropy round toward a
peer NOW (`SchedulerCommand::RoundNow`; a kick during a round is held and
runs right after; the scheduled tick resets so a kick never doubles a round).
`sync_and_await(peer, budget, is_present)` is the anti-entropy twin of
`pull_and_await` for rows a subject Pull cannot ask for by identifier —
another person's owner binding, the rows they placed in a room you share —
and re-kicks on every admission until the walk resolves, so the Key →
attribution → Attestation chain runs back to back instead of one plane per
cadence tick. The discovery leg and every chat wait use it.

## Pair rooms are authored at standup

Each node authors its pair room with every roster owner before replication
starts, so a peer's message or handshake row is admissible the moment it
arrives (AV-45 proves membership against the room the row names; an unknown
room was a transient refusal costing a round).

## Chat (`chat`)

- `chat_message_attestation(author: &LocalSigner, recipient, body, at, key)` —
  the AUTHOR attests and signs, **at write** (persist FSD §5.4 OQ-2, answered
  by edge: an unsigned row has nothing to co-scrub and a key rotation strands
  it). The node is custody. `on_behalf_of_key_id` is read for pre-v39 rows,
  never written.
- The room member is `community_key_id` (persist's canonical cohort-target
  alias — its widening carries the placement under that name).
- `pair_community(a, b, founded_at)` / `signed_pair_community(.., authority)`
  — the two-person room as a record, **both people `founder`s under
  `unanimous`**: each is an authority root and so a zero-hop named moderator
  by construction (§11.11 — persist refuses to federate an unmoderated
  community), not by the accident of a protocol setting. The harness, the
  tests and the bridge witnesses all open rooms through it; pinned by
  `both_members_of_the_pair_room_are_moderators` against persist's own
  `moderators_of`.
- `messages_in_room(dir, participants, room)` lists by the humans who speak
  and FOLDS `supersedes`: one message per thing said. `ChatMessage.widens`
  names the `self` row a widening supersedes.

## CC 2.6.2 — signed instants are canonical, millisecond

Every instant edge signs (`bind_attestation_envelope`, the chat producer, the
A/V delivery producer) renders through persist's `render_signed_instant`
(`YYYY-MM-DDTHH:MM:SS.sssZ`) and truncates the typed column through
`truncate_to_substrate_resolution` (now 1 ms). Consumers windowing on a raw
`Utc::now()` can drop a row stamped "at" that instant by up to 1 ms —
truncate the bound the way the producer truncates the row.

## CC 5.2 — the AUDIENCE gate on attestation rows (found by the first v19 mesh run)

Persist v39 admits `(federation, self)` at the crossing, so a self-scoped row
now EXISTS on the wire — and edge's `SelfOwn` projection filter was
producer-keyed and peer-blind (publish-own). Measured: the owner's `self` copy
of a chat message landed on ANOTHER person's node; the receiver leg passed
because it accepted any row with the right body. The roster planes had a
per-peer owner-axis test since #523; the attestation rows did not.

`bridge.rs#audience_withholds` now asks CC 5.2's question per recipient, on
the advertise AND the direct-fetch twin: a `self` row is served only to nodes
whose PRINCIPAL is the row's principal (persist's
`admission_identity_for_writer` — a person is their own, a node's is its
owner); a `family` / `community` row only to members' nodes (persist's
`list_*_for_member`); a row naming no cohort, or a principal that will not
resolve, is withheld and booked (`RecipientNotInSendSet`). Memoized per sweep.
Witnessed on a real memory backend (self → the owner's other node only;
community → members' nodes only; malformed → nobody). The harness receiver now
requires the WIDENING and fails the leg on a leaked `self` copy
(`leaked_self_rows` in the census).

## Mesh harness

`ladder.send_message` now authors with the OWNER's signer, shares with
`Signers { node, actor: Some(owner) }`, reports the whole `Crossing` (nine
axes, both outcomes, `routes_to`) in the census, and the receiver expects the
row ATTESTED BY THE PEER'S HUMAN — the widening — keyed on the sender's id,
and reports any leaked `self` copy.

Pins: ciris-persist v39.0.0 (`>=39,<40` wheel floor), CIRISVerify v14.1.0
(unchanged, one copy), leviculum v0.24.0+ciris.1 (unchanged).

# v1.1.0 — Routing-table FFI flip-on (CIRISEdge#44)

**2026-05-30** — Closes 5 of the 8 routing-table read surfaces that
shipped as documented `Vec::new()` stubs in v0.15.0. The CIRISAI/
leviculum fork is bumped to a feature branch that exposes the
underlying NodeCore accessors publicly on the `ReticulumNode` async-
runtime wrapper.

## What v1.1.0 flips on

The Portal Network screen + federation-maintainer diagnostics now
get real values from:

- `routing_path_table(max_hops)` — every known path-table entry,
  filtered by hop cap. `peer_key_id` is resolved against edge's
  rooted-peer map (the CIRISEdge#15 cold-start authenticated path);
  `expires_at` is a wall-clock projection of leviculum's monotonic
  `expires_ms`.
- `routing_path_to(destination_hash)` — single-row lookup by 16-byte
  destination hash.
- `routing_path_drop(destination_hash)` — drop one entry. Idempotent
  (POSIX `rm -f` ergonomics).
- `routing_path_drop_via(transport_identity_hash)` — drop every path
  whose `next_hop` matches; useful when a transport peer is known
  to be down.
- `routing_rate_table()` — per-identity announce rate / violations /
  ban-until snapshot. `announce_freq_per_min` is `0.0` (leviculum's
  rate-table export doesn't store the sliding-window rate; consumers
  that need a curve sample `last_ms` across snapshots).

## What stays Vec::new() (forever, in this Leviculum fork)

The remaining 3 routing reads continue to return empty for
structural reasons:

- `routing_tunnels()` — the CIRISAI/leviculum fork does not maintain
  a tunnels collection (only `tunnel_synthesize_hash` for control-
  destination routing).
- `routing_announce_table()` — the in-flight announce retry queue is
  scoped to the driver event loop and not surfaced on `ReticulumNode`
  at any visibility level.
- `routing_reverse_table()` — leviculum's `ReverseEntry` stores
  `(timestamp_ms, receiving_interface_index, outbound_interface_index)`
  keyed by packet hash, which doesn't project to Edge's pinned
  `EdgeReverseEntry { source_hash, destination_hash, last_seen_at }`
  wire schema. Closing this needs a Leviculum design pass, not just
  a visibility widening.

The wire shapes stay pinned so a future Leviculum cut can flip on
real values without binding-side churn.

## Leviculum bump

`Cargo.toml` `reticulum-core` / `reticulum-std` pin advances from
`a7e11028` to `d8e44bc7` (CIRISAI/leviculum feature/edge-44-public-
accessors branch). The branch adds 6 public methods on
`reticulum_std::driver::ReticulumNode`:

- `path_table_entries() -> Vec<PathTableExport>`
- `rate_table_entries() -> Vec<RateTableExport>`
- `get_path_clone(&DestinationHash) -> Option<PathEntry>`
- `remove_path(&DestinationHash) -> bool`
- `drop_all_paths_via(&DestinationHash) -> usize`
- `now_ms() -> u64` (for wall-clock anchoring of the ms-stamped exports)

No new types — all returned shapes are existing `pub` structs from
`reticulum_core::{transport, storage_types}`.

## Test surface

- `tests/routing_ffi.rs` — 23 tests pass. The 8 ex-stub tests are
  updated to exercise the real Leviculum reads (empty-table behaviour
  on a freshly-built transport, idempotent drop ergonomics, bad-length
  typed errors).
- The 3 forever-stubbed reads (tunnels / announces / reverse) keep
  their empty-Vec assertions with updated rationale comments.

# v1.0.0 GA — Agent 3.0 / CEWP

**2026-05-30** — Federation transport tier of the seven-repo CIRIS
Epistemic Web Platform (CEWP) Agent 3.0 stack.

CIRISEdge is the federation transport substrate that makes
**"no datacenters required"** and **"switching cost approaches zero"**
true on the wire. v1.0 is the GA cut — every architectural surface
the v0.5.0 → v0.20.1 waterfall built lands here, anchored against
the CEWP-aligned substrate (ciris-persist v3.6.3 + ciris-verify
v4.4.2), with the seven-invariant security contract (AV-43 → AV-49)
structurally mitigated. No new features in this cut — v1.0.0 is the
ship label + the consolidated release record.

## What v1.0 ships

### Transport — production-grade, byte-equivalent

- **Reticulum** (canonical mesh; primary) — multi-medium reach via
  Leviculum (CIRISAI/leviculum fork): TCP-server / TCP-client / UDP /
  RNode (LoRa) / Local (AF_UNIX cohabitation IPC) / AutoInterface
  (LAN multicast discovery) / I²P (gate present, runtime impl deferred
  post-v1.0). Per-interface sub-features (`transport-reticulum-*`)
  with an umbrella feature for the full set.
- **HTTPS** (fully-equivalent transport, not a degraded fallback) —
  server-side TLS via `axum-server` + rustls; client-side TLS via
  `reqwest`/rustls. Three auth lanes: **mTLS** (Subject CN +
  Ed25519 SPKI must match a `federation_keys` row via
  `FederationCnVerifier`); **bearer token** (federation-key-signed
  JWT, EdDSA); **dev self-signed** (rcgen-minted ephemeral cert
  for the conformance harness, loud-warns on bind). Every
  `MessageType::*` round-trips byte-equivalent to Reticulum.

### MessageType registry — the wire surface

- **InlineText** — outbound Classify + Scrub + AES-GCM-encrypt
  pipeline so cleartext never crosses the wire (`send_inline` /
  `send_durable_inline`).
- **FederationAnnouncement**, **DeliveryAttestation**,
  **DeliveryRefusalAttestation** — the federation gossip + delivery-
  receipt surfaces.
- **ContentFetch** / **ContentBody** (Inline + External wire shapes)
  / **ContentMiss** — content-addressable byte transport over the
  federation wire (CIRISEdge#21 v0.8.0; External shape added at
  v0.20.1 #52 — `kind == "external"` discriminator routes edge to
  skip AV-13 + SHA gates because the consumer's client fetches
  external bytes directly per MEDIA_SHARING.md §2.6).
- **ContributionSubmit** — including the `takedown_notice` subject_kind
  (TVEC / GIFCT-CIP / NCMEC `legal_basis` fast-path) and `key_grant`
  subject_kind (addressed point-to-point) sub-routes
  (v0.20.1 #52). Unknown subject_kinds fall through unchanged.
- **StewardDirective**, **GoalDeclaration**, **GoalRetirement** —
  federation-tier governance + goal-lifecycle wire (CIRISEdge#41).
- **Withdraws** (CEG §10.1.2) — the federation-issued withdraw
  primitive.

### FFI surface

- **UniFFI** single-UDL source (`udl/ciris_edge.udl`) generates
  Python + Kotlin Multiplatform + Swift bindings via
  `uniffi::generate_scaffolding` (CIRISEdge#36 GO):
  - **Peer-mgmt** CRUD: `peer_add` / `peer_remove` / `peer_set_alias` /
    `peer_set_trust` / `peer_set_notes` / `peer_set_policy` (#26).
  - **Transport-mgmt**: `transport_list` / `transport_add` /
    `transport_remove` / `transport_health` (#25).
  - **Links**: `link_list` / `link_open` / `link_teardown` /
    `link_request` (#32).
  - **Routing-table**: paths / blackhole (durable per
    CIRISPersist#120) / rate / tunnels / announce / reverse (#33).
  - **Identity reads** (#31) + **observability snapshot** (#28).
- **PyO3** for cohabitation primitives (the GO-spike carve-out):
  - `init_edge_runtime` with **7 PyCapsule** extractions
    (federation_directory + outbound_queue + keyring_signer +
    runtime_handle + blob_storage + local_signer + trust_scoring).
  - **Tier 3 reads**: `peer_reachability` / `fetch_content` /
    `subscribe_feed`.
  - **6 AsyncIterator subscribe_*** event streams (announces /
    link_events / interface_events / path_events / resource_events /
    verified_feed) over `tokio::sync::broadcast::Receiver` via
    `pyo3-async-runtimes` (#34).
  - **`peer_sas` / `peer_sas_digits`** — Short Authentication String
    (SHA-256 + BIP39 English wordlist; protocol constant
    `ciris-edge::peer-sas::v1\0` locked) for MITM-resistant
    out-of-band peer verification (#47).
  - **`metrics_snapshot`** — typed observability surface (#28).

### Cohabitation — "each capsule one job"

- **7-PyCapsule discipline**: `federation_directory_capsule` +
  `outbound_queue_capsule` + `keyring_signer_capsule` +
  `runtime_handle_capsule` + `blob_storage_capsule` +
  `local_signer_capsule` + `trust_scoring_capsule`. The split
  between the **hardware-rooted hybrid signer** (P-256 + ML-DSA
  under `hardware_hsm_only`) on `keyring_signer_capsule` and the
  **32-byte Ed25519 Reticulum transport identity** on
  `local_signer_capsule` is what makes AV-43 closure structural
  rather than a runtime check (#43).
- **Cross-cdylib libsqlite3 unification** (CIRISPersist#136 wheel
  fix + edge v0.19.7 closure of CIRISEdge#50): persist's manylinux
  wheel dynamically links the system libsqlite3 (matching `cargo
  install`); the auditwheel sidecar at `ciris_persist.libs/`
  bundles a copy. Five sibling traits (FederationDirectory /
  OutboundQueue / TrustScoring / BlackholeRules / LocalSigner) are
  structurally protected against cross-cdylib vtable null-slot
  crashes — the wheel-tier SIGSEGV root cause.

### Posture — CEWP L0/L1 tier model

- **AgentMode** `{Client, Proxy=L0, Server=L1}` per FSD
  `FEDERATION_SCALING_MODEL.md` + CIRISNodeCore `FSD/CEWP.md`:

  | Mode    | Listener | Out-queue | Disk budget | Trust recursion |
  |---------|----------|-----------|-------------|-----------------|
  | Client  | no       | 256       | 0           | 0               |
  | Proxy   | yes      | 4096      | 256 GB (L0) | 0 (strict)      |
  | Server  | yes      | 65536     | 1 TB  (L1)  | 1 (FoF)         |

- Disk budgets **advisory at edge** — persist (or the host) enforces;
  edge does not store anything (apophatic bound §1.4 "Not a storage
  layer").
- Trust recursion depth threaded into `TrustScoring::trust_score`
  (replacing v0.19.6's hardcoded `0`); L2+ depths deferred
  post-v1.0.
- **`bootstrap_peers` + canonical reseed semantics** (#46) —
  bootstrap peers re-seeded on every Edge start; operator can flip
  trust state and the flip survives restarts; `peer_remove(hard=true)`
  on a canonical peer returns typed `CANNOT_REMOVE_CANONICAL_PEER`.

### Compliance — CIRIS 3.0 wire types

- **testimonial_witness preservation** (#37 v0.16.0): edge propagates
  the field verbatim across federation forwarding and signs it as
  part of canonical envelope bytes; edge does **not** interpret the
  opaque payload. M-1 rendered as architecture: the wire crate must
  never silently re-interpret what a higher tier has signed (AV-44).
- **key_boundary `{scope}` slot** (#38 v0.16.0): wire-form scope
  slot `process | tenant | channel | cohort | data_class` extending
  the AV-17 invariant string. Signature-to-scope binding enforcement
  deferred post-v1.0 (declared-not-enforced at GA — wire surface
  stable for downstream consumers; AV-45).
- **cohort_scope refusal at outbound_enqueue** (#48-A v0.19.1, full
  closure v0.19.6 against CIRISPersist#127): edge structurally
  enforces the wire-format locality dividend. Self/family-scoped
  Contributions never leave the producer's enclosing federation.
  Source-of-truth lives in persist's
  `federation_peer_metadata.policy_blob.cohort_scope`.
- **trust short-circuit at dispatch_inbound** (#48-B v0.19.6 against
  CIRISPersist#123): edge consumes the `TrustScoring` trait;
  envelopes whose verified `signing_key_id` scores below
  `trust_threshold` drop, fire a `EventKind::TrustShortCircuited`
  moderation signal, and increment `inbound_dropped_low_trust`. The
  v0.20.0 RC1 cohabitation residual closed via the 7th capsule (AV-48).
- Five sibling traits structurally protected against cross-cdylib
  vtable null-slot crashes via persist's dynamic libsqlite3
  unification (v0.19.7).

### Substrate pins (locked)

- **ciris-persist v3.6.3** (8-release line 2026-05-29 → -30:
  #117 / #118 / #119 / #120 / #121 / #122 / #123 / #127 / #129 /
  #130 / #132 / #133 / #134 / #136).
- **ciris-verify v4.4.2** (lockstep — both `ciris-keyring` and
  `ciris-crypto`).

### Tests

- **~417 passing** across the full feature surface:
  wire-correctness / verify-enforcement / replay-rejection /
  authenticated-resolution / identity-boundary / multi-medium-reach /
  spec-drift / links / routing / peer-mgmt / SAS / cohort-scope /
  trust-short-circuit / multimedia / cohabitation / UniFFI /
  HTTPS-init / per-MessageType-HTTPS-roundtrip.
- **CIRISConformance harness** pinned at the CEWP-aligned matrix
  (the four cells: Reticulum-only, Reticulum+HTTPS coexistence,
  HTTPS-only, HTTPS-with-mTLS).

### Threat model — v1.0 security contract

The seven AV invariants AV-43 through AV-49 are **the v1.0 security
contract**. Each is structurally mitigated; see
`docs/THREAT_MODEL.md` §10 for the full Posture Summary GA block.

- **AV-43** Federation transport identity 32-byte vs 65-byte hybrid
  split (dual-capsule extraction + LocalSignerHardwareAdapter).
- **AV-44** testimonial_witness preservation invariant (Option-wrapped
  wire field; canonical bytes via persist).
- **AV-45** key_boundary `{scope}` wire form shipped; cohort_scope
  persist-backed; key_boundary-scope-to-signature binding deferred
  post-v1.0.
- **AV-46** Schema-level separation of operator opinion
  (`federation_peer_metadata`) from federation attestation
  (`federation_keys`).
- **AV-47** UniFFI pre-init invariant — typed `NotInitialized` rather
  than panics.
- **AV-48** Trust short-circuit at dispatch_inbound; cohabitation
  cohab residual CLOSED via the 7th capsule.
- **AV-49** Multimedia tier transport semantics — takedown fast-path
  observability; BlobBody::External non-fetch contract; L1-as-CDN-edge
  opt-in OFF by default.

## Closed in the v1.0 line

The full waterfall from v0.13.0 through v1.0.0:

- **#19** AccordCarrier authority verification at the transport layer
- **#20** Per-install steward addressing in gossip topology
- **#21** MessageType::ContentFetch + ContentBody + ContentMiss
- **#22** Surface PeerResolver + ContentFetch + reachability for the
  CIRIS Epistemic Commons Framework UI
- **#23** HTTPS transport hardening — every wire type over TLS,
  mutual auth, cert mgmt
- **#24** Leviculum interface diversity — TCP / UDP / Local / RNode /
  I²P / AutoInterface as separately-configurable transport features
- **#25** Transport management pymethods
- **#26** Peer management pymethods + manual seed + peer probe
- **#27** Cross-transport federation conformance
- **#28** Observability — tracing spans, metrics counters,
  diagnostic pymethods
- **#29** Per-medium reachability substrate
- **#30** PyEdge FFI surface for CIRISAgent 2.9.4 Network screen
- **#31** Identity FFI surface — display_name / identity_hash /
  pubkeys / QR / ratchet
- **#32** Links FFI surface
- **#33** Routing-table FFI surface
- **#34** AsyncIterator event-stream FFI
- **#35** pyo3-stub-gen — generate `.pyi` type stubs
- **#36** UniFFI spike — single-source FFI for Python + Kotlin + Swift
- **#37** testimonial_witness preservation primitive
- **#38** key_boundary `{scope}` slot (D26)
- **#39** ProbePatternObserver — edge-side Counter-RII detection
- **#40** Persist v2.7.0 → v2.8.0 currency
- **#41** MessageType::GoalDeclaration + GoalRetirement
- **#42** CEG 0.1 landed — Edge's §5.4 + §10.1 transport substrate
- **#43** Cohabitation pubkey-shape mismatch (32B vs 65B) — AV-43
- **#45** agent_mode init param (client / proxy / server)
- **#46** bootstrap_peers + canonical-peer reseed semantics
- **#47** SAS helper for peer verification UI
- **#48** Trust short-circuit at dispatch_inbound + cohort_scope
  refusal at outbound_enqueue
- **#49** PyEdge HTTPS transport-init surface (mTLS + bearer + dev
  self-signed)
- **#50** send_durable_inline_text reactor crash — wheel-tier
  libsqlite3 unification closure
- **#51** v0.20.0 RC1 — CEWP infrastructure cut (trust_scoring_capsule +
  L0/L1 tiers)
- **#52** v0.20.1 — multimedia tier transport (last feature cut
  before GA)

## Cross-repo coordination

The persist line shipped 13+ cuts in 36 hours alongside this v1.0
push, locking the CEWP-aligned substrate:

- **v3.0.0** anchor (4/3/1 triple with verify v4.0.0)
- **v3.1.0** #117 peer-mutation (`add_peer_record` / `remove_peer_record` /
  `update_peer_*` + `TrustClass` + `PeerPolicyBlob`)
- **v3.1.1** #118 `put_edge_detection_event` + #119
  `local_signer_capsule`
- **v3.2.0** #120 `BlackholeRules` durable trait + V052
  `cirislens.blackhole_rules` table
- **v3.3.0 / 3.3.1** #121 / #122
- **v3.4.0 / 3.4.1 / 3.4.2** #123 `TrustScoring` trait + #127
  `peer_metadata_for` + verify pin recovery
- **v3.5.0 → 3.5.4** #125 + #128 + #129 `trust_scoring_capsule` (7th
  cohab capsule) + #130 + #132 / #133 libsqlite3 dynamic-linkage chain
- **v3.6.0** #134 multimedia substrate (MEDIA_SHARING / CEG 0.3)
- **v3.6.1** #133 darwin-wheel CI refinement
- **v3.6.3** #136 auditwheel `--exclude` for the cross-wheel libsqlite3
  fix

The verify v4.4.2 cut recovered the v4.3.0 PyPI publish failure,
restoring cross-wheel installability for the persist v3.5.4+ chain.

## What's next

- **v1.0.x patch line** for:
  - D14 multi-provider WisdomAdvice aggregation (CIRISEdge#37
    follow-on).
  - D18 verify → edge linkage (CIRISEdge#37 follow-on).
  - Leviculum-fork accessor exposure (#44; gap-stubs functional).
- **v1.1.x**:
  - ~~L2+ trust recursion depths.~~ *(Retro-note, 2026-08: the depth knob
    shipped as `EdgeConfig::trust_recursion_depth` — default 0/0/1 for
    Client/Proxy/Server, `src/edge.rs` — threaded per CIRISEdge#51; L2+
    CEWP *tier* semantics remain deferred, and no persist `TrustScoring`
    impl yet honors any depth — CIRISPersist#748.)*
  - L1-as-CDN-edge full HTTP fetch (the prefetch stub at v0.20.1 is
    wire-shape + dispatch-path locked; full implementation deferred).
- **Production deployments** per
  [`docs/HTTPS_DEPLOYMENT.md`](HTTPS_DEPLOYMENT.md) and
  [`docs/PYPI_PUBLISH.md`](PYPI_PUBLISH.md).

---

*Earlier releases (v0.1.0 through v0.20.1) are documented in their
respective commit messages and the architectural surfaces enumerated
in `MISSION.md` §11.*
