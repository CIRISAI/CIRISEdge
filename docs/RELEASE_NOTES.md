# CIRISEdge Release Notes

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
  - L2+ trust recursion depths.
  - L1-as-CDN-edge full HTTP fetch (the prefetch stub at v0.20.1 is
    wire-shape + dispatch-path locked; full implementation deferred).
- **Production deployments** per
  [`docs/HTTPS_DEPLOYMENT.md`](HTTPS_DEPLOYMENT.md) and
  [`docs/PYPI_PUBLISH.md`](PYPI_PUBLISH.md).

---

*Earlier releases (v0.1.0 through v0.20.1) are documented in their
respective commit messages and the architectural surfaces enumerated
in `MISSION.md` §11.*
