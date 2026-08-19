# The lightnet/darknet hybrid — claims, mechanisms, and their proofs

**Status**: living document. Every claim below carries one of four labels —
**Normative** (the Constitution requires it), **Shipped** (code on `main`
enforces it), **Measured** (a bench-mesh leg or CI lane demonstrates it on a
real network), **Posited** (the substrate exists; the end-to-end demonstration
does not yet). A claim may carry more than one. The discipline of this
document is that *no claim is promoted without naming the measurement that
promoted it* — the same fail-loud stance [`MISSION.md`](../MISSION.md) §1.6
applies to code.

**Canonical source**: [CC 5.4.6 *Position*](../../CIRISConstitution/constitution/part_5_transport_substrate.md)
(the CIRISConstitution#91 prior-art record). This document maps that
constitutional positioning onto edge's shipped machinery and its acceptance
bench. Where vocabulary differs, the Constitution's wins: what we informally
call the **lightnet** is CC's *public identity plane*; the **darknet** is CC's
*derived group plane*.

---

## 1. The two-plane split

The design occupies what CC 5.4.6 names the **zero-emission corner** of the
anonymity trilemma — the *membership-concealment* corner, where reachability
information flows only to authorized parties, and the impossibility floor
("whoever relays for you must know how to reach you"; Vasserman et al., CCS
2009) is satisfied **entirely by members**: members relay for members.

| | **Lightnet — public identity plane** | **Darknet — derived group plane** |
|---|---|---|
| What it is | The federation directory: rooted node identities, announced transport destinations, hybrid Ed25519 + ML-DSA-65 keys, quorum trust root, hardware-attested accord holders | Per-group destinations *derived* (per-group HKDF over the cached directory) — never announced, never discoverable |
| Anonymity claim | **None, by design.** Nodes announce normally; every inbound byte is attributed `Rooted ∧ owns_key` before any handler sees it | Group **existence** is invisible to non-members: no emission exists to observe. The destination hash is "the last non-scope-private identifier" |
| Announce policy | RNS announces propagate normally | **Normative prohibition** (CC 5.4.6 `announce-suppress`): a group-scoped destination never announces — *including directed announces* (multi-hop path learning is outsider observation; path state is what a subpoena reaches) |
| Edge machinery | `src/transport/reticulum.rs` attribution gate, rooting, announce install; the federation directory via `ciris-persist` | `ScopeAddressTable` + arrival-scope admission (`src/transport/reticulum.rs`), A/V half in `src/av_addressing.rs` + `src/scope_lifecycle.rs`; the derivation itself is owned by `ciris-verify` (one derivation, no second expectation) |

### 1.1 Has anyone proposed this? (the composite prior-art record)

The composite — "just enough light to work, the rest private," with the light
plane an *accountable identity directory* and the dark plane *derived* from
it — appears unproposed. Every fragment has a nameable nearest ancestor, and
naming them is the claim's strength (the same discipline as the
CIRISConstitution#91 anonymity-corner survey):

- **The minimal-light pattern**: Alpenhorn (OSDI '16) — public keyservers +
  metadata-free private dialing — is the closest spirit-ancestor, but dyadic
  (no groups, no management) and centralized-server-based. Freenet/Hyphanet
  literally ships "opennet"/"darknet" *modes*, but as alternative connection
  strategies for one plane, its darknet paying the out-of-band bootstrap this
  design's derivation dissolves. Tor's public consensus + v3 onion services
  is the pattern in infrastructure form, but onion services still *emit*
  (blinded descriptors retained in public HSDirs) — CC 5.4.6's
  "nearest admissible relaxation," not an instance.
- **Machine-enforceable constitutions**: the 2025–26 agent-economy cluster
  (AgentCity's protocol-level separation of powers; AgentBound's signed
  constitutional policy artifacts + governance receipts) — governance stacks
  over smart-contract substrates; no privacy theory, no groups, no wire.
- **Contextual integrity operationalized**: Barth et al. (2006) formalized CI
  in logic for *analysis*; MCIP (EMNLP 2025) borrows the name for MCP
  tool-safety guardrails; the Dignity-Centric Stack (2026) names CI as one
  pillar of a commons-governed federated *architecture* — the closest
  ideological neighbor, but not a protocol carrying CI's five parameters as
  signed wire fields.
- **"Cannot express breaking" as mechanism**: the DIFC lineage
  (Myers/Liskov → HiStar/Fabric) and object-capability systems
  (Willow/Meadowcap, Spritely OCapN) — unforgeable *access*, but not
  flow-appropriateness, and their namespaces are visible to sync peers.

What no surveyed system combines: an attested, constitutionally governed
identity plane (prior light planes are infrastructure metadata — relay
lists, keyservers — never accountable identity); a group plane derived by
pure function from it (zero-emission, vs. blinded-retained-state); CI as the
wire grammar; the relay floor satisfied by members; and an acceptance
harness that *measures* the privacy claims and fails when a leg doesn't run.

The hybrid is the point: past systems chose one plane. The identity plane
gives manageability its root of trust; the group plane gives groups their
invisibility. Each buys back one of the corner's two historical prices:

1. **Derivation replaces discovery.** Surveyed systems that hide group
   existence accept *out-of-band address exchange* (the darknet bootstrap
   problem). Here the group address is a pure function of directory state
   members already hold — so there is no bootstrap emission at all.
   *(Shipped: CIRISEdge#499, edge v17.9.0→v18.0.0.)*
2. **Determinism replaces coordination.** The member-relay ALM tree is a pure
   function every member computes identically (CC 6.1.6), recovering
   ⌈log_k N⌉ fan-out without a coordinator that would otherwise have to learn
   the group exists. Surveyed zero-emission systems accept **linear** fan-out
   as the corner's price; coordinator-efficient systems uniformly declare
   group metadata out of scope (RFC 9750 delegates it to exactly this layer).
   *(Shipped: `AlmJoinPlanner`, TOPOLOGY_VERSION 2; Measured: log-depth
   curves in [BENCHMARKS.md](BENCHMARKS.md), depth 2/4/5 at N=10/100/1000
   against bounds 4/6/7.)*

---

## 2. The demonstration instrument

Claims about a network are proven on a network. The acceptance instrument is
**[`bench-mesh/`](../bench-mesh/README.md)**: separate containers, each a
distinct edge occurrence with its own identity and keystore, pushing real
encoded video and a real blob across a real docker network through relays
while the roster changes. Its census is honest by construction — a leg that
did not run fails the run — and it runs in CI (`bench-mesh.yml`, weekly +
dispatch).

First CI datapoint (2026-08-19, K=1 relay, M=2 subscribers, run 32268885154):
**28 of 28 executed legs passed** — delivery, rooting, cohort join, scope
install/rotation, non-member refusal, relay address-blindness — with the three
skipped legs being exactly the two known in-flight seams (§5).

---

## 3. Claim: private, manageable groups

**The claim.** A group whose *existence* outsiders cannot observe, whose
relays carry only ciphertext and hold no group address, and which is
nevertheless *manageable*: members are admitted and removed, keys rotate,
superseded addresses retire, and moderation duties are held by accountable,
hardware-attested identities — with no coordinator and no out-of-band ritual.

**Why past attempts could not hold all of it at once** (the #91 survey, as
CC 5.4.6 records): systems that concealed group existence paid with
out-of-band bootstrap and linear fan-out; systems with efficient fan-out
pushed group metadata out of scope entirely. Manageability — revocation,
rotation, retirement, moderation — was the casualty either way.

**The mechanisms and their labels:**

| Property | Mechanism | Label |
|---|---|---|
| Group existence invisible | Derived destinations, `announce-suppress` | Normative + Shipped |
| Non-member cannot fetch | Scope-gated serve; arrival-scope admission | **Measured** (`conformance.nonmember_cannot_fetch`) |
| Relay holds no group address | Relay serves transit on the identity plane only | **Measured** (`conformance.relay_holds_no_cohort_address`) |
| Membership + rotation | MLS cohorts (TreeKEM, X-Wing 0x004D), `welcome-wrap` (CC 5.4.4) | Shipped; rotation **Measured** (`conformance.rotation_frame_loss`: zero loss across an epoch advance) |
| Address retirement | Seal: a superseded epoch's address stops being admitted | Owner half **Measured** (`scope.seal`); network-observed half in flight (§5) |
| Moderation with accountability | Accord-conferred duty-holders, quorum trust root, revocation planes | Shipped (persist substrate; edge replicates + refuses) |

---

## 4. Claim: decentralized video

**The claim.** Real encoded video from a publisher to N members over
member-relays at log depth, keys rotating mid-stream, no SFU, no coordinator.

**Labels.** Shipped (the A/V spine: join → subscribe → publish → heal → seal;
MLS-keyed streams; MDC/SVC codec planes) and **Measured** at K=1/M∈{1,2}:
real video frames + a 120 KB blob delivered through a relay container with
byte-intact verification, blob completion ~20–23 ms/peer, zero frame loss
across a mid-stream epoch advance. **In flight**: M=4 fan-out currently
wedges on MLS commit ordering under concurrent admissions (§5), and blob
distribution still uses direct push — the scope-native swarm fetch is the
designed mechanism (`scope_native_fetch: false` in the leg detail marks it).

---

## 5. Claim: online voting

**The claim — as CC 5.4.6 states it:** N→1 deterministic aggregation under
the CC 6.1.2.1 dominance gate composes with the MLS-epoch roster,
steward-binding (CC 6.1.8), quorum-above-time ordering (CC 5.3
`MergeBallot`), and the CC 5.4.5 member-only witness chain into **a ballot
process whose *occurrence* is invisible to outsiders** at scopes below
federation. *"A classical secret ballot hides the vote; structural
invisibility hides the election."*

**Label: Posited, on shipped substrate.** What exists today: persist's
`MergeBallot` comparator (V058) and reverse-quorum objection-ballot plane
(`ballot_envelope`, `record_objection_ballot`, governing-ballot resolution);
edge's `AccordQuorumEvidence` cursor replication (v16.3.0) and wire-layer
M-of-N accord threshold verification (measured by `accord_carrier_verify`).
What does not exist yet: the end-to-end demonstration.

**The planned proof (bench-mesh Track V):** members cast signed ballots
inside the cohort; every member independently computes the governing tally
and the census asserts the tallies **byte-equal** across members;
quorum-above-time resolves concurrent casts; and — the flagship leg — the
**non-member and the relay observe no election**: no new announces, no
group-plane emission, no fetchable ballot material, traffic
indistinguishable from the stream it rides beside.

**What is deliberately NOT claimed:** ballot secrecy *among members* (members
of a cohort see the cohort's ballots — the reverse-quorum design is
accountable, not anonymous); anonymity for the identity plane (it is public
by design); multi-hop anonymity of any kind. If a future amendment wants
multi-hop, CC 5.4.6 names the nearest admissible relaxation (the Tor
v3 / I2P b33 blinded-retained-state family) and its non-negotiable rotation
rule: rotation clocks global, never group-event-driven.

---

## 6. In-flight seams (the gap between Measured and 100%)

Tracked as the bench-mesh 100% program; each seam has an owner-track:

1. **MLS commit ordering at M≥4** — commits fan out unordered; a laggard hits
   `WrongEpoch` fatally. Fix: bounded hold-buffer in the production cohort
   layer + non-fatal harness handling + admission pacing. *(Track A.)*
2. **`seal_retires` measured the impossible thing** — it tried to RNS-dial a
   derived address through a relay, which CC 5.4.6 now normatively forbids
   the preconditions of (no announce, so no multi-hop path — by design, not
   defect). Redesign: probe over the identity-plane rooted link, answered by
   the production arrival-admission lookup; the live-address probe is the
   aliveness control that makes "refused" distinguishable from "down."
   *(Track C.)*
3. **Census role-contracts** — the deliberate late joiner can never satisfy
   across-the-advance legs; the census gains per-role expected-leg sets with
   the honesty rule intact. *(Track D.)*
4. **Swarm fetch as the blob mechanism** — replace/augment direct push with
   the scope-native holdings fetch. *(Second wave, after Track A.)*
5. **Voting legs** — §5's planned proof. *(Track V, after integration.)*

---

## 7. Spec debt

The [`FSD/CIRIS_EDGE_TRANSPORT.md`](../FSD/CIRIS_EDGE_TRANSPORT.md) refresh
landed (2026-08, re-pinned to v18.0.2): it now covers the 15 EnvelopeKinds
(including the #474 cursor plane), all six wire messages (`Pull`,
`CursorPull`), the five-projection taxonomy with per-plane tombstone ceilings,
the wire `CohortScope` mapping, and — for the scope-native plane — the §3.3
arming condition (default-open until a `ScopeAddressTable` is installed, the
deliberate opt-in production state). Residual gap: the FSD still does not
specify the derived group plane's full lifecycle (epoch rotation /
convergence sealing), `announce-suppress` inheritance, or the A/V addressing
verbs — for those, CC Part 5 §5.4.4–5.4.6 and this document remain the
authorities. The FSD is the authority on the EnvelopeKinds, projections, and
the anti-entropy session.
