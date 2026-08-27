# CIRISEdge — Transport & Replication Protocol

> **What this is.** `ciris-edge` is the transport and replication layer of the
> CIRIS Epistemic Web ([CEWP](https://ciris.ai/cewp)). It moves the 15 signed
> envelope kinds of the CEG grammar between federation peers over any medium
> (Reticulum mesh, HTTPS, packet radio), decides *who is allowed to learn a
> claim exists*, and attributes every inbound byte to a cryptographic identity
> **before any handler sees it**. It is the operational realization of
> **[Constitution Part 5 — Transport & Substrate](../../CIRISConstitution/constitution/part_5_transport_substrate.md)**.
>
> Two disciplines run through every rule below, taken verbatim from Part 5:
> - **Non-maleficence / fail-secure** — a missing key, an unreachable peer, an
>   unresolved consent view all resolve to *less* access and an honest miss,
>   never a silent downgrade or a fabricated success.
> - **Integrity through structure** — privacy and authenticity are properties
>   the wire format *cannot violate*, not promises an operator makes.
>
> The thesis, from [ciris.ai/contextual-integrity](https://ciris.ai/contextual-integrity/):
> **"the strongest flow rule is one the network cannot express breaking."** Every
> gate in this document is built so that the inappropriate flow is unrepresentable,
> not merely disallowed.

---

## 1. Where edge sits — CEG vs OSI

CEG is not an OSI clone. It has the familiar layers, but three properties are
**woven through** them that OSI never models: **identity *is* addressing**,
**consent *is* routing**, and **integrity through structure**. Edge occupies OSI
layers 4–6 and is where those three properties are *enforced on the wire*.

| OSI | CEG / CIRIS realization | Owned by |
|---|---|---|
| 7 Application | The CEG grammar — semantic claims: the 15 `EnvelopeKind`s, attestations, dimensions | persist / verify (grammar); edge transports it |
| 6 Presentation | Wire codec (CRPL framing, JCS canonicalization, `Signed*` wrappers) + **hybrid crypto** (Ed25519 + ML-DSA-65) | edge (framing) / verify (crypto) |
| 5 Session | **Anti-entropy replication session** — Summary → Diff → Deliver, per `(peer, kind)` | **edge** (§4) |
| 4 Transport | Authenticated, encrypted links + the `Transport` trait; **source attribution at ingest** | **edge** (§5) |
| 1–3 Physical/Link/Network | TCP/IP, LoRa, serial, I²P — addressing + routing | Reticulum / Leviculum |

**The three orthogonal properties (no OSI analogue):**

| Property | What it means | Where enforced |
|---|---|---|
| **Identity = addressing** | A peer's transport address *is* a projection of its federation key; there is no separate naming layer to spoof. | `#393` attribution (§5) — a frame is attributed iff its link proved `Rooted ∧ owns_key`. |
| **Consent = routing** | *Who* may receive a flow is bounded by the transmission principle (the consent grant), not merely by reachability. | The Attestation serve gates (§6). |
| **Integrity through structure** | `self`/`family` content emits **no directory advertisement** — the network cannot learn it exists. | Structural invisibility (Part 5 §5.2); the `SelfOwn` projection (§3). |

---

## 2. The 15 EnvelopeKinds

Every load-bearing claim is a signed wire artifact. Edge replicates exactly 15
kinds — the `EnvelopeKind` enum ([`protocol.rs:90`](../src/replication/protocol.rs)),
1:1 with persist's admission surface (`EnvelopeKind::ALL`, `protocol.rs:188`,
order-pinned by `REPLICATION_POLICY_HASH`). Each kind is its own anti-entropy
stream, so a partition on one kind never gates convergence on another.

| # | Kind | Purpose | persist admit | Wire | Flags |
|---|---|---|---|---|---|
| 1 | `Key` | Public key registrations | `put_public_key` | v1 | **bootstrap** |
| 2 | `Attestation` | Trust grants / scores / withdraws / `delegates_to` | `put_attestation` | v1 | **consentable** |
| 3 | `Revocation` | Key-level revocations (R1/Q1 quorum-merge) | `put_revocation` | v1 | tombstone |
| 4 | `IdentityOccurrence` | Agent/human/partner occurrence records | `put_identity_occurrence` | v1 | **bootstrap** |
| 5 | `Family` | Family roster declarations | `put_family` | v1 | |
| 6 | `Community` | Community roster declarations | `put_community` | v1 | |
| 7 | `IdentityOccurrenceRevocation` | Forward-secrecy tombstone | `put_identity_occurrence_revocation` | v1 | tombstone |
| 8 | `FamilyMembershipRevocation` | Forward-secrecy tombstone | `put_family_membership_revocation` | v1 | tombstone |
| 9 | `CommunityMembershipRevocation` | Forward-secrecy tombstone | `put_community_membership_revocation` | v1 | tombstone |
| 10 | `LocationProof` | H3 rough-only geo claim (resolution ≤ 7) | `put_location_proof` | v1 | |
| 11 | `Organization` | Public org identity row | `put_organization` | v2 | |
| 12 | `OrgMembership` | Authz binding (user/org/role) | `put_org_membership` | v2 | |
| 13 | `PartnerRecord` | License+Partner, M-of-N steward quorum | `put_partner_record` | v2 | |
| 14 | `TransportDestination` | Reachability address (hybrid-signed) | `put_signed_transport_destination` | v2 | **bootstrap** |
| 15 | `AccordQuorumEvidence` | Steward-quorum evidence bundle (proposal + participations) projecting `RoleWithdrawals` | `apply_replicated_accord_evidence` (re-tally) | v2 | **cursor-served** |

- **`consentable`** = **only `Attestation`.** It is the sole kind whose flow to a
  recipient is gated by a consent grant (§6). Every other kind is a *structural
  plane* that replicates by policy, never by end-user consent
  ([`resolved_state.rs:36`](../src/replication/resolved_state.rs)).
- **`bootstrap`** = exactly `{Key, IdentityOccurrence, TransportDestination}`
  (`is_bootstrap`, [`protocol.rs:228`](../src/replication/protocol.rs)) — the
  self-authenticating kinds a fresh peer must deliver to introduce itself, exempt
  from the attribution gate (§5.4). A proptest asserts this set is *exactly*
  those three over all 15 kinds (§5.4).
- **`cursor-served`** = **only `AccordQuorumEvidence`** (`is_cursor_served`,
  `protocol.rs:263`, pinned over `ALL` by
  `cursor_served_is_exactly_accord_quorum_evidence`, `protocol.rs:672`). A bundle
  is an aggregate whose hash moves as each participation lands, so persist keeps
  it out of the `signed_wire_index` (`persist_index_kind` → `None`,
  `protocol.rs:319`). It is therefore **never advertised by content-hash** —
  `list_envelope_refs` returns empty for it
  ([`bridge.rs:1202`](../src/replication/bridge.rs); advertising a ref would be
  the listed-then-unfetchable LIST-vs-FETCH class) — and converges over the
  dedicated cursor path `CursorPull → Deliver`, resuming on `evidence_at`
  (§4.1). The receiver **re-tallies** each bundle against its own roster
  (`apply_accord_quorum_evidence` → persist `apply_replicated_accord_evidence`,
  `bridge.rs:3189`), so the cursor is an optimization, never a trust input.
- Kinds 1–10 ride wire version `0x01`; the 5 post-v1 kinds (`Organization`,
  `OrgMembership`, `PartnerRecord`, `TransportDestination`,
  `AccordQuorumEvidence`) require `0x02` (`min_wire_version`,
  `protocol.rs:346`) — v1-only peers serde-reject their unknown tags.

---

## 3. The namespace — cohort tiers & projections

### 3.1 The seven cohort scopes

Every claim carries a `cohort_scope` — Nissenbaum's *recipient* parameter,
narrowest to widest ([persist `types.rs` `cohort_scope`](../../CIRISPersist/src/federation/types.rs)):

`self` 🪞 → `family` 🏡 → `community` 🏘️ → `affiliations` 🤝 → `species` 🧬 → `biosphere` 🌍 → `federation` 🌐

**What the seven scopes map to on the wire.** The lattice above is persist's
policy vocabulary. Edge's wire `CohortScope` — the field an `EdgeEnvelope`
actually carries — has exactly **4 variants**
([`cohort_scope.rs:73`](../src/cohort_scope.rs)): `Public`, `SelfOnly`,
`Family`, `Cohort { cohort_id }`. `affiliations` / `species` / `biosphere` are
**inexpressible in an `EdgeEnvelope`**. The mapping onto persist's tokens is
`Public → federation`, `SelfOnly → self`, `Family → family`,
`Cohort{..} → community` — one mapping, lifted from `CohortScope::crypto_tier`
so the projection axis and the crypto-tier axis cannot drift
(`persist_scope_token`, [`swarm/scope.rs:129`](../src/swarm/scope.rs)). Note
the promotion: an edge-side `Public` is persist's *widest* scope
(`federation`), not a mid-lattice tier.

### 3.2 The projection taxonomy

Projection is a function of **four inputs** — `projection_for(plane,
cohort_scope, authority, is_tombstone)` (persist `namespace::projection_for`;
edge feeds it at [`bridge.rs:2058`](../src/replication/bridge.rs), totality
pinned over all four axes by `check_cohort_scope_projection`
([`field_conformance.rs:265`](../src/field_conformance.rs))). It resolves to one
of **five projections** — the rule for *who advertises and receives* a claim:

| Projection | Meaning | Who advertises |
|---|---|---|
| **`SelfOwn`** | Publish-your-own (KERI shape) — the structurally-invisible identity plane | Only the subject node (`attesting_key_id ∈ self_set`) |
| **`Cohort`** | Hold-and-forward over a roster | The anti-entropy cohort |
| **`Global`** | Commons + widest-audience gossip | Own ∪ cohort (widest enumerable) |
| **`Capability(token)`** | Role-keyed audience (e.g. `trace:*` → `infra:serve` holders) | Cohort candidate set; narrowed per recipient at send/fetch by the token-holder check |
| **`Subject`** | Subject-keyed audience (e.g. `scores:*` about you) | Cohort candidate set; narrowed per recipient at send/fetch by the data-subject grant |

`Capability`/`Subject` audiences are not enumerable from a roster, so they
enumerate the `Cohort` candidate set and the fail-closed per-recipient gates cut
it down ([`bridge.rs:1565`](../src/replication/bridge.rs); all five variants
branched at `bridge.rs:1948`).

**Resolution rule** (`projection_for`, live-scope inputs):

```
self | family                                        → SelfOwn  # structural invisibility
community | affiliations                             → Cohort
species | biosphere | federation                     → Global iff authority.is_trust_root(), else Cohort
unrecognized scope                                   → Cohort   # conservative negative default
```

**Tombstones project at a per-plane CEILING, not unconditionally `Global`.**
`is_tombstone → tombstone_ceiling(plane, authority)` (CIRISPersist#713; pinned
at [`field_conformance.rs:344-378`](../src/field_conformance.rs)). Key-plane
tombstones stay `Global` — verify-relevance is unbounded, anti-rollback wins.
But a non-trust-root `self`-scope `TransportDestination` tombstone projects
**`Cohort`, NOT `Global`**: *widening a tombstone would disclose more than the
original fact* — "this route was withdrawn" reveals the route existed
(`field_conformance.rs:354`). On the Attestation plane every family's ceiling
is still an advertised projection (`Global`/`Cohort`/`Capability`/`Subject` —
never `SelfOwn`), so a withdraw always advertises, at its plane's audience
([`bridge.rs:7333-7343`](../src/replication/bridge.rs)).

**Where resolution runs.** Per-record `projection_for` resolution runs on the
**Attestation plane only** (`attestation_projection`,
[`bridge.rs:2039`](../src/replication/bridge.rs) — value-keyed on the record's
`dimension` + `cohort_scope` + tombstone status). Every other plane advertises
under a constant, resolved once per plane
([`bridge.rs:1174`](../src/replication/bridge.rs)):

- `SelfOwn` — `Key`, `IdentityOccurrence`, `TransportDestination`
  (`bridge.rs:1671/1699/1722`);
- `Global` — `Revocation` (`bridge.rs:2772`), `IdentityOccurrenceRevocation`
  (`bridge.rs:1750`), `FamilyMembershipRevocation` +
  `CommunityMembershipRevocation` (`bridge.rs:2811`);
- `Cohort` — `Family`, `Community`, `LocationProof` (rows filtered to the
  cohort roster, `bridge.rs:2806`);
- unfiltered public-operational — `Organization`, `OrgMembership`,
  `PartnerRecord` (`in_scope = |_| true`, `bridge.rs:2936`);
- not advertised at all — `AccordQuorumEvidence` (the cursor plane, §2).

The projection gate applies on both advertise and fetch paths
(`attestation_is_advertised`, `bridge.rs:1912`, and the per-record re-gate in
`fetch_envelope_bytes_for_peer`, `bridge.rs:977`) — a ref a peer could not be
served is neither listed to it nor resolvable by it.

> **Structural invisibility (Part 5 §5.2, normative).** A `self`/`family` claim
> projects `SelfOwn` and emits **no `holds_bytes:sha256:*` directory attestation** —
> "outsiders cannot route to it, read it, or even learn that it exists." This is
> the *unconditional* privacy promise; at-rest encryption is defense-in-depth on
> top, never a substitute.

### 3.3 Scope-native gates are STAGED (armed, not unconditional)

The `#499` scope-native gates — the fountain holdings gate and the blob scope
router — are **default-open until a `ScopeAddressTable` is installed**. Both
read the identical arming condition `is_scope_native`
([`swarm/scope.rs:435`](../src/swarm/scope.rs),
[`blob_swarm/scope.rs:316`](../src/blob_swarm/scope.rs)): a deployment with no
table has no scope roster to resolve anyone against, so a gate over it could
only refuse everything — it therefore behaves byte-identically to pre-#499
(every held content announced to every cohort peer;
[`swarm/scope.rs:90-99`](../src/swarm/scope.rs) — "refusing every holding on a
node that cannot resolve a roster would not be fail-closed, it would be
fail-broken"). Default-open is the **deliberate production state**: installing
the table is operator **opt-in** (`EdgeBuilder::scope_native_addressing`,
[`edge.rs:6388`](../src/edge.rs)) because scoped destinations are one-hop by
CC 5.4.6 (CIRISConstitution#91) — a real reach trade, chosen, never inherited
from a default. The derivation itself is shipped, not pending: CIRISVerify#259
is closed and `ScopePrivacyDeriver` reproduces verify v13.4.0's
`k_destination` + `derive_destination` byte-for-byte
([`scope_addressing.rs:907`](../src/scope_addressing.rs)). Installing the one
table arms every scope-native path at once — transport inbound admission, blob
router + serve gate, swarm holdings gate — so "which addresses I answer on" and
"which I send to" cannot drift ([`edge.rs:6214`](../src/edge.rs)).

---

## 4. The anti-entropy replication session (OSI 5)

Replication is **per `(peer, kind)`**, bidirectional, and eventually consistent.
Each round both sides advertise what they hold, request what they lack, and
deliver it. The state machine is **message-typed, not phase-gated** — a session
reacts to the *type* of the inbound message
([`session.rs`](../src/replication/session.rs)).

### 4.1 Roles & messages

- **`SessionRole`** ([`session.rs:47`](../src/replication/session.rs)):
  `Initiator` (the only role for which `start_round` is valid) · `Responder`
  (reacts to inbound messages).
- **`start_round` has THREE opening moves**: a content-hash kind opens with
  `Summary` (`session.rs:268`); a self-publishing initiator adds a proactive
  `Deliver` alongside it (#927/#380, `session.rs:275`); a **cursor-served kind
  opens with `CursorPull`, never a Summary** (`session.rs:259-267`).
- **Messages** (`ReplicationMessage`, `#[serde(tag="type")]`, **six** variants,
  [`protocol.rs:492`](../src/replication/protocol.rs)):

| Message | Fields | Meaning |
|---|---|---|
| `Summary` | `kind`, `refs: [(envelope_hash, seq)]` | "Here are the hashes I hold for `kind`." |
| `Diff` | `kind`, `want: [envelope_hash]` | "I want these — you have them, I don't." |
| `Fetch` | `kind`, `want: [envelope_hash]` | **Responder-only status**: edge parses and serves `Fetch` (`on_fetch` → the `Diff` path, `session.rs:581`) but no production path produces one — `Pull` superseded its initiating role, and every `Fetch` constructor in-tree is `#[cfg(test)]`. Kept for wire compat. |
| `Deliver` | `kind`, `envelopes: [signed_bytes]` | The requested signed envelopes. |
| `Pull` (#462) | `kind`, `subject_key_id` | Subject-scoped RECEIVE-axis discovery ([`protocol.rs:440`](../src/replication/protocol.rs)): "which `kind` records do you hold where `subject_key_id` is data-subject or sender?" Answered with a subject-scoped `Summary` (projection-gated, `capacity:*` G2-carved); the ordinary Diff/Deliver flow carries the bytes. **Fail-closed to `peer == subject`**: a requester not authenticated as the subject is served nothing ([`bridge.rs:943`](../src/replication/bridge.rs)). |
| `CursorPull` (#474) | `kind`, `since: Option<evidence_at>` | Cursor request for the index-less accord plane ([`protocol.rs:464`](../src/replication/protocol.rs)). Answered DIRECTLY with a `Deliver` of bundles past the watermark. **Stateless `since: None` is always correct** — the receiver re-tallies on apply, so a from-the-beginning replay is a `Duplicate`, never a double-count; the cursor is an optimization, not a trust input. |

Both `Pull` and `CursorPull` are post-v1 verbs: v1 peers serde-refuse the
unknown `type` tag (coordinated by the `SERVE_ADVERTISE_POLICY_HASH` re-pin).

### 4.2 The round

```mermaid
sequenceDiagram
    participant A as Initiator
    participant B as Responder
    A->>B: Summary(kind, refs_A)
    Note over B: want_B = refs_A ∖ local_B
    B->>A: Summary(kind, refs_B)  %% bidirectional
    B->>A: Diff(kind, want_B)
    Note over A: want_A = refs_B ∖ local_A
    A->>B: Deliver(kind, envelopes for want_B)
    A->>B: Diff(kind, want_A)
    B->>A: Deliver(kind, envelopes for want_A)
    Note over A,B: each side apply()s inbound Deliver → Applied{admitted, refused, staleness}
```

Two additional openings share the same session machinery:

- **Subject pull** (#462): `A→B: Pull(kind, subject)` → `B→A: Summary(subject's
  refs)` → the ordinary Diff/Deliver flow above. The Pull only seeds `on_summary`
  with a subject-scoped ref set; every byte is still served through the
  per-record serve gate (`session.rs:425-454`).
- **Cursor round** (#474): `A→B: CursorPull(kind, since)` → `B→A:
  Deliver(bundles past since)` — no Summary/Diff phase exists for the
  index-less accord plane; the answering Deliver is solicited
  (`awaiting_cursor_deliver`, `session.rs:173-178`), and an empty result still
  completes the round cleanly.

### 4.3 State transitions

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> AwaitingReply: start_round (Initiator) / emit Summary — or CursorPull for a cursor kind
    Idle --> Replying: on Summary (Responder) / emit Summary+Diff
    AwaitingReply --> Delivering: on Diff / emit Deliver
    Replying --> Delivering: on Diff / emit Deliver
    Delivering --> Complete: on Deliver / apply → Applied
    AwaitingReply --> Complete: on Deliver / apply → Applied
    Complete --> Idle: coordinator reset() (keeps peer summary + proactive ledger)
```

> **This diagram is ILLUSTRATIVE.** The session is **message-typed, not
> phase-gated**: `on_message` dispatches on the inbound message's *type*
> ([`session.rs:373-396`](../src/replication/session.rs)) with no phase check,
> so two legal transitions run off-diagram. (1) A **bare `Deliver` with no
> round in flight** — the #927 proactive push — is applied, not refused:
> `on_deliver` distinguishes solicited from unsolicited and admits both,
> DEBUG-logging the bootstrap planes and WARN-logging the rest
> (`session.rs:599-647`). (2) A **refused message leaves session state
> UNTOUCHED** — every kind-mismatch check early-returns `UnexpectedMessage`
> before any mutation (`session.rs:415/441/461/547/605`), and the coordinator
> maps it to `DriveStep::Refused` without resetting
> ([`coordinator.rs:347`](../src/replication/coordinator.rs)). **"Refused" is
> an outcome, not a state**: the only reset is the coordinator's, on
> `Complete`/`SendThenComplete` (`coordinator.rs:266-271`).

| Inbound | Handler | Emits | Notes |
|---|---|---|---|
| *(none, Initiator)* | `start_round` | `Summary` (+ proactive `Deliver` per #380/#927) — or `CursorPull` for a cursor kind (`session.rs:259`) | Only valid for `Initiator` |
| `Summary` | `on_summary` | `Summary` (Responder) + `Diff` | Records remote summary; **`want = remote ∖ local`** (`diff_refs`, [`summary.rs:253`](../src/replication/summary.rs)) — local side is the peer-blind `local_holdings`, not the send-gated offer (#414, `session.rs:465-471`) |
| `Diff` / `Fetch` | `on_diff` / `on_fetch` | `Deliver` (byte-bounded, §4.4) | Fetch each wanted hash from the provider; unfetchable wants are logged LOUD, never inferred from a short count (#429) |
| `Pull` | `on_pull` | `Summary` (subject-scoped refs) | #462; entitlement fail-closed to `peer == subject` at the provider (`bridge.rs:943`) |
| `CursorPull` | `on_cursor_pull` | `Deliver` (bundles past `since`) | #474; empty result is a well-formed empty `Deliver` (`session.rs:410-423`) |
| `Deliver` | `on_deliver` | *(applies)* → `Applied{admitted, refused, staleness}` | Sets `completed`; tallies admits/refusals |
| *wrong kind* | any | — | `UnexpectedMessage` → `DriveStep::Refused`; session state untouched |

The coordinator maps each `ReplicationOutcome` to a **`DriveStep`**
([`coordinator.rs`](../src/replication/coordinator.rs)): `SendThenWait` · `SendThenComplete`
(initiator-final, #380) · `Complete(RoundReport)` · `Refused`. The responder drain
is bounded (`RESPONDER_REPLY_SEND_TIMEOUT`, #373); assembly latency is O(1) in
consent reads via a per-round memo (#400).

### 4.4 Byte budgets

Two constants bound what a single round can put on the wire
([`session.rs`](../src/replication/session.rs)):

| Constant | Value | Bounds |
|---|---|---|
| `MAX_DELIVER_ENVELOPE_BYTES` (`session.rs:73`) | 512 KiB | The raw-envelope total packed into ONE `Deliver` answering a `Diff`/`Fetch` (`pack_bounded_deliver`, `session.rs:517-539`). The remainder is honest deferral: never-admitted hashes stay in the peer's `want`, so the next round's re-diff carries them — and the reported `BoundedBy` staleness stays truthful. Caps the frame's fragment count so reassembly survives packet loss (#414/#932). |
| `PROACTIVE_PUSH_BUDGET_BYTES` (`session.rs:189`) | 256 KiB | The per-round batch of the #927/#380 proactive initiator push (delta-aware, oldest-seq first; spillover converges over subsequent rounds, `session.rs:313-327`). Replaced the v13.7.0 unbounded full-set push that re-blasted megabytes every 30 s on the Attestation plane. |

Both budgets bound the *batch*, never strand an envelope: a single envelope
larger than the whole budget still ships, alone (the transport fragments it).

---

## 5. Transport attribution (OSI 4) — identity *is* addressing

Every inbound CRPL frame is attributed to a federation `key_id` **at ingest**,
before any serve gate is consulted. Attribution is a private, unforgeable newtype
[`SourceKeyId`](../src/transport/mod.rs) constructible only by vetted paths.

### 5.1 The `SourceKeyId` constructors

| Constructor | Yields `Some` iff | Used by |
|---|---|---|
| `from_rooted_binding(key_id, provenance, owns_key)` | `provenance == Rooted ∧ owns_key` | Reticulum (the E3 trust gate) |
| `transport_authenticated(key_id)` | always — the *channel* vouches | HTTPS mTLS/bearer, packet radio, FFI, the §5.4 carve-out |

### 5.2 The two-item gate (`#393`, Reticulum)

Both items must pass or `source_key_id = None`:

- **Item 1 — `Rooted ∧ owns_key`.** The link's proven transport identity matches a
  `RootedPeer` that (a) roots to a trusted steward (`provenance == Rooted`) and
  (b) *proved control* of the federation key (`owns_key`).
- **Item 2 — `hybrid_transport_binding_exists`.** A stored, **ML-DSA-signed**
  `SignedTransportDestination` must bind that transport identity (the PQ half of
  attribution). Fail-closed with no rooting directory.

An unattributed frame (`None`) is **`#317 SkippedNoSourceKeyId`** — delivered, then
dropped *before* `peer_has_serve_capability` is ever reached. Defense in depth: the
serve gate is never even asked about a peer the transport couldn't attribute.

### 5.3 Binding provenance & route supersession

A peer binding lives in one of two provenance states, updated by received
announces under `route_supersession_decision` (a pure, exhaustively-tested fn):

```mermaid
stateDiagram-v2
    [*] --> Advisory: self-consistent announce (owns_key, not steward-rooted)
    Advisory --> Rooted: roots to a trusted steward (advisory→rooted upgrade)
    Rooted --> Rooted: owner re-announce (Admit / AdmitRouteKeepTrust)
    Advisory --> Advisory: owner re-announce (Admit)
    note right of Rooted
        HijackRefused: a non-owning announce can
        NEVER supersede a Rooted route (#337 CRITICAL-1)
    end note
```

| Verdict | When | Effect |
|---|---|---|
| `Admit` | fresh peer / newer epoch / advisory→rooted upgrade / same-owner rooted reroute | Write incoming route **and** trust |
| `AdmitRouteKeepTrust` (**#404**) | owner re-announces **Advisory** over a **Rooted** binding (new dest/epoch) | Heal the route, **preserve** `Rooted ∧ owns_key` — a churn blip must not de-attribute a rooted peer |
| `IgnoreStale` | same/lower epoch, no upgrade or reroute | Cached binding stands |
| `HijackRefused` (**#337**) | announce that **cannot prove ownership** over a Rooted route | Refused *first*, epoch-independent — the anti-spoof invariant |

### 5.4 The bootstrap carve-out (`#402`)

A fresh peer is `UnknownKeyId` until its `Key` is admitted — but that `Key` frame is
exactly what admits it. To break the deadlock, an *un-attributed* CRPL frame whose
kind `is_bootstrap` (`{Key, IdentityOccurrence, TransportDestination}`) is routed on
the link's transport identity (`transport_authenticated`) instead of dropping.
**Safe by construction:** these kinds self-authenticate at persist admission
(`signer_acts_for`), grant no trust, and are served no `trace:*` — the trace-serve
gate stays strictly `Rooted ∧ owns_key`. Every non-bootstrap unattributed frame
still drops (`#317`). A proptest over all 15 kinds × link presence proves the
carve-out admits *exactly* the three
(`bootstrap_carve_out_source_holds_over_all_kinds`,
[`edge.rs:8488`](../src/edge.rs)).

### 5.5 The node transport identity (`#541`)

The carve-out above attributes a bootstrap frame on **the link's transport
identity**. That identity is therefore the one that walks through the lightnet
door, publicly visible to anyone on the interface — and it also resolves
§5.2's item 2 `SignedTransportDestination` and the de-admission self.

CC **3.4.7.3** makes `node` non-cohabitable with `agent`/`user`: persist's agency
gate constrains a recipient resolving to a **node-only** identity, so fusing the
roles onto one key does not blur "infrastructure must not have agency" — it
switches the rule off. Historically `init_edge_runtime` derived the transport
identity from the engine with no override, so the key at this door was
agency-bearing and **no caller could change it**: the caller is Python, the
node signer has no `#[pyfunction]`, and CIRISServer folds onto an
already-running edge.

`init_edge_runtime(use_node_identity=True, node_identity_dir=…)` resolves the
node's own key instead — the `<alias>-node` sealed keystore entry beside the one
the engine opened, plus its **own** `node_ml_dsa_65.seed` (a different file from
the actor's `ml_dsa_65.seed`, so the split is complete on both halves).

Three properties are load-bearing:

- **A flag, not a key export.** Python states the intent; Rust resolves the key.
  Nothing exportable crosses the FFI boundary. `node_identity_dir` is
  configuration the caller already passes to `Engine(identity_dir=…)`, not key
  material.
- **Fail-closed.** Every failure is an error, never a fallback to the engine's
  identity — a node handed the actor's key under a flag claiming to have cured
  the defect would reproduce it. Edge **opens** and never **mints**: a minted
  key is registered by no directory and owner-bound by nobody.
- **One identity, advertised and addressable.** `set_self_key_id`, the announce
  attestation's `federation_key_id` (`ReticulumTransportConfig::local_key_id`),
  and the key that signs that attestation are all the node's under this flag.
  They have to agree: an attestation advertising one id while signing with
  another key is a public-key mismatch at every receiver — it could never root
  and could never supersede an existing rooted route — and a
  `revocation:peer_admission:v1` aimed at the advertised id would not match the
  engine's self, leaving the node un-de-admittable.
- **Envelope authorship stays with the actor**, and so does its fast path. The
  transport identity and the envelope author are *different jobs*: edge keeps
  the ACTOR's in-memory signer in `Edge::local_signer` regardless of this flag,
  so the v1.1.1 keyring-IPC bypass (`#50`, headless darwin / locked Keychain)
  survives it. `local_signer_authors_envelopes` is the guard that makes the
  separation safe rather than merely intended: a non-actor signer reaching that
  slot falls back to the forensic signer instead of quietly authoring CEG rows
  under an identity that holds no agency.

### Provisioning comes first, and edge does not do it

Edge **opens** the node identity; it never creates one. The mint belongs to the
party that owns the node identity's lifecycle, so the boot order is:

1. the agent builds the engine;
2. the agent calls `ciris_server.provision_node_identity(engine, keystore_alias,
   identity_dir)` — mints `<alias>-node` plus both seed halves, registers the key
   `identity_type = node`, and returns the key_id;
3. the agent calls `init_edge_runtime(…, use_node_identity=True,
   node_identity_dir=…)` — the key now exists, so `open_existing` succeeds;
4. CIRISServer folds on and finds the identity already there.

Step 2 is idempotent across boots (it open-or-mints), and step 3 re-opens rather
than re-mints. A deployment that sets the flag without step 2 ahead of it gets a
refusal at init rather than a degraded start — that is the intended behaviour,
and the error names the provisioning call rather than an internal symbol.

Absent or `false`, behaviour is byte-for-byte what it was.

---

## 6. Serve & consent — consent *is* routing (Attestation plane only)

Only the `Attestation` plane is recipient-gated; every other kind serves per its
projection (§3). Three gates compose, narrowest question last
([`bridge.rs`](../src/replication/bridge.rs)):

| Gate | Question | Mechanism |
|---|---|---|
| **`#396` item 1 — consent membership** | May *any* consentable claim flow to this peer? | `list_consent_peers(local)` → `ResolvedPeerSet`; a `ResolvedRecipient` exists **iff** consent includes the peer. Fail-closed → no advertise, no fetch. |
| **`#379` `infra:serve`** | May a `trace:*` attestation be served at all? | `peer_has_serve_capability` = accord-conferred `infra:serve` (`has_effective_role`) **AND** roots to a root *this node* trusts (`capability_roots_to_trusted_root`). |
| **`#396` item 6 — `recipient_capability`** | Which serve-eligible peer still gets *this* row? | The row owner's live consent grant may attach `recipient_capability` restrictions covering the row's `dimension`; the recipient must hold each. |

By construction, the fan-out recipient axis can never exceed the consent grant: a
`ResolvedRecipient` is the only key the serve path accepts, and it is unforgeable
without a `list_consent_peers` hit. This is the wire-level expression of Nissenbaum's
"the recipient must not exceed the transmission principle."

**Serve-time field stripping is deliberately NOT an edge operation.** A
`StripField` consent restriction resolves to a **no-op at the serve layer**
([`bridge.rs:2309-2314`](../src/replication/bridge.rs)): edge's wire is
content-addressed and signed — the recipient fetches by content-hash and
re-verifies the hybrid signature at `put_attestation`, so stripping a field at
serve time would break both (#397). The strip is applied at **persist
PROMOTION**, before the row is signed
(`promote_attestation_with_transforms`); edge's field-conformance harness
accounts for the deferral explicitly rather than skipping it
(`DEFERRED_PENDING_PLANE`,
[`field_conformance.rs:110-129`](../src/field_conformance.rs)). Edge still pins
persist's transform-algebra hash so a vocabulary change is a build failure
first (`lib.rs` `PERSIST_TRANSFORM_ALGEBRA_HASH`) — it just never *applies*
strip on the serve path.

---

## 7. Transports (one interface, many media)

Edge is transport-agnostic: every medium implements `Transport` (`send` +
`listen(sink)`) and produces an `InboundFrame` that carries `source_key_id`
(+ the raw `link_key_id` routing hint).

| Transport | Feature | Attribution source | Status |
|---|---|---|---|
| **Reticulum** (canonical) | `transport-reticulum` (+ per-interface: tcp/udp/rnode/i2p/…) | Full `#393` two-item gate + `link_key_id` | Production |
| **HTTPS** | `transport-http` | `transport_authenticated` (bearer / mTLS) | Production fallback |
| **Packet radio** | `transport-packet-radio` | `None` (attribution not yet wired) | Experimental |

`TransportId`: `HTTP` · `RETICULUM_RS` · `LEVICULUM` · `LORA` · `SERIAL` · `I2P`.
A frame is routed as replication only if it carries the CRPL magic **and** an
attribution (or a §5.4 bootstrap carve-out); otherwise it falls through to envelope
dispatch or drops.

---

## 8. Contextual integrity, on the wire

The [five Nissenbaum parameters](https://ciris.ai/contextual-integrity/) are wire
fields, and edge enforces each as a routing property:

| CI parameter | Wire field | Enforced by |
|---|---|---|
| Data subject | `subject_key_ids` | Wire-level revocation authority |
| Sender | `attesting_key_id` | Every claim signed; attributed at ingest (§5) |
| Recipient | `cohort_scope` / `subject_key_ids` | Projection (§3) + serve gates (§6) |
| Information type | `dimension` | Per-record projection + `recipient_capability` |
| Transmission principle | `consent:*` grant | Consent-membership fan-out (§6, item 1) |

Every gate above is designed so the inappropriate flow is **unrepresentable** — the
type system (`SourceKeyId`, `ResolvedRecipient`) and the projection rules make
"serve a claim past its consent" a compile-or-admission error, not a runtime check
an operator can skip. That is the whole of the design: *the strongest flow rule is
one the network cannot express breaking.*

---

## 9. Invariants (the short list that must never regress)

1. **Fail-secure** — unresolved consent / missing key / unattributable link ⇒ *less*
   access, never a downgrade or a fabricated success.
2. **Structural invisibility** — `self`/`family` emits no directory advertisement.
3. **Attribution before serve** — an unattributed frame never reaches a serve gate.
4. **`Rooted ∧ owns_key` is the sole trace-serve attributor** — the bootstrap
   carve-out (§5.4) never carves out `Attestation`; `#337` hijack refusal is checked
   first.
5. **Consent narrows, never widens** — the fan-out recipient set ⊆ `list_consent_peers`.
6. **Tombstones win at their plane's ceiling** — a tombstone projects
   `tombstone_ceiling(plane, authority)`, never narrower than the live fact it
   retracts (anti-rollback) and never wider (widening a tombstone would
   disclose more than the original fact — §3.2, CIRISPersist#713).
7. **PQC-mandatory** — hybrid Ed25519 + ML-DSA-65 for authenticity; item-2 requires
   the ML-DSA transport binding.

---

*Grounded in [Constitution Part 5](../../CIRISConstitution/constitution/part_5_transport_substrate.md),
[Part 2 (grammar)](../../CIRISConstitution/constitution/part_2_the_grammar.md),
[Part 3 (namespace)](../../CIRISConstitution/constitution/part_3_the_namespace.md), and the
code as of edge v18.0.2 (2026-08 doc audit: every claim re-verified against the
code; the v14.3.0 revision taught 14 kinds / 4 messages / three projections /
unconditional tombstone-Global, all superseded above). Section anchors cite
`src/…:line` for navigation.*
