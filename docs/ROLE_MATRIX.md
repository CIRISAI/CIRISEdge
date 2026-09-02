# The Role Matrix — five actor axes, five flow parameters

**Status:** normative for edge; every cell cites its source. Written after two
mis-keyings in one week (retention gated on `AgentMode`; a directory-serving
predicate nearly built on the same field) proved that orthogonal axes were
living in people's heads as one.

**The rule this document enforces:** the five actor axes below are ORTHOGONAL.
No decision may key on an axis other than its own row's. An agent node can be a
full server; a `server`-posture node can be an unconferred bystander; a blessed
canonical under one root is a stranger under another. Reading one axis off
another is the one-variable-two-jobs bug, and it shipped once already.

Two decompositions live here and must not be confused:

* **Actor axes** (this file's first half) — what a *participant* is and may do.
* **Flow parameters** (the cross-walk, second half) — whether one *claim
  moving once* is an appropriate flow: Nissenbaum's five, embedded in the wire
  (ciris.ai/contextual-integrity): data subject (`subject_key_ids`), sender
  (`attesting_key_id`), recipient (three deliberately distinct axes:
  `cohort_scope` / `subject_key_ids` / `delivery_mode`), information type
  (`dimension`), transmission principle (`consent:scope`).

Every actor-axis decision is ultimately in service of a flow decision, and the
cross-walk is where each row proves it resolves all five parameters.

---

## Axis 1 — `AgentMode`: local resource posture

"Has a brain attached" — the agent runtime's connectivity posture. Listener
binding and outbound queue sizing. **Nothing else.** Not storage, not serving,
not trust, not directory role.

| mode | listener | outbound queue | source |
|---|---|---|---|
| `Client` | none (egress-only) | 256 rows | `src/edge.rs` `AgentMode` |
| `Proxy` (default) | binds configured | v0.17.x default | ibid. |
| `Server` | always-on + propagate | 65 536 rows | ibid. |

Transport posture (Roaming/Full/Gateway/AP) is **derived**, never configured
(CIRISEdge#514): *"A node's behavior = `AgentMode` (local resources) ×
conferred capabilities (directory) × per-interface transit declarations ×
normative announce policy."* That sentence is this document in one line.

## Axis 2 — `identity_type`: what the entity IS

`user` / `agent` / `node` / `family` / `community` / steward / … — the CC 3.4.7.1
taxonomy, resolved from the directory row (never from the shape of the string:
`key_id` is `label-fingerprint` with an operator-chosen label). Decides *who
consents* — an agent resolves to its owner, a steward is not contactable. Never
decides posture, storage, or trust. **An agent node can be a full server.**

## Axis 3 — `infra:serve` conferral: the serving tier

Three states, two granters. CC 4 ("two granters — standing vs infrastructure
role"): the **owner** grants standing; the **trust root** blesses
infrastructure role. `infra:*` is server-class, allowed for a `node`-role
delegate (CC 4 scope table).

| tier | established by | may do | trusted for | resolving check |
|---|---|---|---|---|
| **none** | — | hold own records; answer a subject Pull for **itself** and for **its own record** | nothing beyond its own signatures | (absence) |
| **mesh server** | owner's `delegates_to(owner → node, [infra:serve])` — resolver-INDEPENDENT, since an owner's conferral over its own node does not depend on who is asking | **store & serve to help the mesh**: carries the directory as HASHES and serves bodies BY HASH. Does NOT answer identifier lookups — answering one requires the body, and it has chosen not to hold them | *nothing* — and needs no trust: everything served is a self-authenticating signed envelope, re-verified at the receiver's admission gate | own row `claims_role(infra:serve)` **∧** the owner's grant bears the scope (a claim alone is *"visibility, never conferral"* — persist v19.0.0 `lift_envelope_attested_roles`) |
| **canonical** | 2-of-3 accord co-scrub over a `canonical,node` registration envelope bearing `roles: ["infra:serve"]` (CC 4.4.3.8 — the same ceremony that mints a portable trust root) | holds the directory as **BODIES**, so it is the tier that answers **identifier lookups** (rate limited per requester) — and be relied on before verification is possible | **bootstrap**: the `CanonicalBootstrapPeer` set, rooting a fresh fleet, the E3 trace-plane serve gate | leg A: `has_accord_conferred_role` — the co-scrub **re-derived from the row's own cryptography** every call, so a withdrawn blessing bites immediately; leg B: `capability_roots_to_trusted_root` — chains to the resolver's root (see Axis 5) |

The load-bearing distinction: a mesh server helps **after** trust exists
(records prove themselves); a canonical is who you lean on **before** it does
(bootstrap is precisely the moment you cannot yet verify). *"A root serves and
vouches, or it is inert"* — root validity minimum is `[infra:serve,
infra:attest]` (CC 4).

**Identifier lookups are entitled by a MUTUAL TRUST ROOT, not by a tier.**

node/fed/agent IDs are **federation cohort**: servable by any peer holding
them, to any requester under a shared root — and any node that received an ID
may hold it, unless revoked or superseded, precisely because any ID may be
load-bearing. That is what "federation cohort" buys, and it is why hash-first
is a CAPACITY choice rather than a permission one.

CC 4 supplies the rule: two nodes under one shared root cross-attest and
vouch; two nodes with no shared root compose nothing. So the gate asks whether
the requester is in the same trust domain, never what rung either node stands
on. An earlier revision keyed this to the canonical rung and was too narrow —
it stopped the fleet's storage helpers answering for records they legitimately
hold.

**Abuse is bounded by extraction rate, across LAYERED windows.** A single
window cannot see a slow drain: a peer that stays under a per-minute cap
forever still copies the directory out by hash, one compliant request at a
time. The attack is defined by its aggregate, so only an aggregate ceiling
sees it — hence per-minute AND per-hour AND per-day, all of which must permit.

**Historical note — why the earlier "canonical-only" framing was wrong.**
Answering "which records do you hold for subject S" requires the BODY:
`subject_holdings_inner` resolves through `lookup_public_key`, and persist's
subject-scoped reads are built from the held records (`wire_refs_for_subject`
reads `list_signed_key_records_since`, and the Key plane has no subject-indexed
signed read at all). There is no body-free identifier path anywhere in the
stack, so a hash-first node cannot answer whatever it is entitled to. An
earlier revision keyed this to "any conferred server" and was therefore
unsatisfiable.

That fact lands the **anti-harvest** property in the right place. The harvest
unit is the (identity, destination) PAIR — a destination with no owner is an
address you cannot attribute, an ID with no destination is a name you cannot
reach — so all three identity planes move together. Bulk enumeration is only
possible where bodies are, and bodies concentrate at canonicals: few,
accountable, rate limited. Mesh servers can be scraped for "these records
exist" and nothing more. And the identifier Pull cannot enumerate on its own —
the requester must NAME the subject, so it confirms people it already knows
rather than discovering new ones.

This is **friction on a public plane, not confidentiality**. The identity plane
is announced, attributable, and makes no anonymity claim; the invisibility
property lives on the GROUP plane, by derivation (CC 5.4.6). Nothing here may
be described as privacy (CC 1.13.3.1's bounding non-goals).

## Axis 4 — announce: are your IDs with the canonicals?

The first-run wizard's choice, presented as an **opt-out**. Not opting out ⇒
your nodeIDs, fedID, and agentIDs are shared with the canonicals and available
on request.

**What this axis is NOT — three near-misses, each wrong:**

1. **Not tier promotion.** Everything a wire admit may claim is already
   federation tier — `WireTier::FederationOnly`, persist's E5, enforced per
   kind in `replication_policy.rs::policy_for`. The wizard could not be
   controlling tier even in principle.
2. **Not cohort scope.** `cohort_scope` (self → family → community →
   affiliations → species → biosphere → federation) is a per-CLAIM recipient
   parameter resolved to a projection (`SelfOwn`/`Cohort`/`Global`). The
   wizard does not move claims between cohorts — but claims DO move: see
   "the three promotions" below.
3. **Not a confidentiality feature of the identity plane.** The identity plane
   is public — announced, rooted, attributable, *no anonymity claim* (README).
   What this system makes invisible is **group existence**, by deriving
   group destinations from state members already hold (CC 5.4.6: group-scoped
   destinations never announce). Announce is the #499 federation-visibility
   opt-in for *identity* records only.

**What it actually is, in CI terms:** the data subject's **transmission
principle** for the identity plane, set once — consent to `share` your
identity records at federation scope. The identity plane is the degenerate
case where subject = sender = the identity itself, which is why one wizard
choice can cover it and no per-request consent check exists on a promoted Key.

**Consequences of opting out:** unreachable by fedID lookup; group discovery,
federation reputation, and every mesh service that starts from "look them up"
are unavailable — and the kill switch depends on the agentID being announced,
which is why agent use effectively requires it. **Direct P2P still works**: a
v2 fedcode is self-contained — it carries the key_id, the Ed25519 pubkey, and
a `transport_hint` (`ciris_verify_core::fedcode::FedCode`), so two people who
exchange codes out of band can connect with the canonicals never involved.

### The three promotions — one word, three different acts

"Promote" names three distinct lifecycle events, and conflating any two of
them reproduces the near-misses above:

| act | what moves | who decides | when | mechanism |
|---|---|---|---|---|
| **tier promotion** (local → federation) | one record, from unsigned local tier to signed wire tier | the producer — and for consent revocations it is an OBLIGATION, not a choice (CC 5.3.2.2, the 24-hour rule) | when a record must become carriable at all | re-signed as the identical canonical bytes; *"byte-indistinguishable on the wire from one born federation-tier"* (CC 5) |
| **cohort widening** (narrow → wide) | one record, from the cohort it was BORN at to a wider one | the data subject / producer — each widening is a NEW consent, a fresh transmission-principle resolution | most data is born at `self`, `family`, or `community` and only some of it ever widens; widening later is the normal life of a record, not an exception | re-emission at the wider `cohort_scope`; the reverse is not un-publishing but REVOCATION (`withdraws` — "life changed" — or `recants` — "originally false", distinct at protocol level because they move trust differently) |
| **announce** (Axis 4) | your identity records, to the canonicals | the person, once, at first run (opt-out) | setup | the #499 federation-visibility opt-in |

Born-narrow-widen-later is the expected shape of the corpus: the default
cohort is intimate, the wide cohorts are earned per record, and nothing about
holding a record at `self` today forecloses sharing it at `community` next
year. What widening never does is travel backwards silently — a widened
record is recalled by revocation, which is itself a mandatory-flow tombstone.

## Axis 5 — trust base: canonical is a (node, resolver) pair

*"The CIRIS root is the shipped default, never the only option… every client
chooses which roots to trust"* (ciris.ai/constitutional-mesh). A consumer
trusts a root by hanging `delegates_to(user → root, [infra:attest,
infra:serve])` off its base; two nodes with no shared root compose nothing
(CC 4). A default-plus-re-root is a federation (CC 3.2).

So **canonical-ness is not a property of a node** — it is a property of the
pair (node, resolver). Leg B (`capability_roots_to_trusted_root`) already
takes the resolver as its first argument; the code knew before the table did.
Every row below that says "canonical" means *canonical under the resolver's
root*.

---

## The decision matrix

Every runtime decision, the ONE axis it keys on, and the check that proves it.
A decision keying on any other axis is a bug by definition. **Enforced by
`src/role_matrix_gauntlet.rs`** — one test per row, the orthogonality rows as
full tier×mode cross-products; the mode column of R3 is vacuous by
construction because `BridgeConfig` no longer has a mode field at all.

**R0 is the WIRING row, and it exists because the table alone was not enough.**
Every decision row pins the tier and asks whether the decision is right; all of
them stayed green while the refresh sat on the peer-blind diagnostic path and
production never resolved a tier at all. A decision table cannot catch an
unwired decision. R0 drives the bridge through the trait method production
calls and asserts the resolver was consulted.

Axis-3 resolution status: **both rungs live** as of persist v38.8.0
(CIRISPersist#788). Edge delegates to `resolve_serve_tier` rather than
re-deriving either — the walk reuses persist's one scope-parse and one
CEG-tombstone fold, and forking either into a consumer doubles the policy the
FSD insists lives in a single authority. `claims_role` alone still buys
nothing: lifting an envelope-attested role creates VISIBILITY, never
conferral.

| decision | keys on | correct check | status in code |
|---|---|---|---|
| bind a listener / queue size | Axis 1 | `AgentMode` | ✅ correct |
| who consents / who is contactable | Axis 2 | `identity_type` via directory | ✅ correct (`contact::resolve`) |
| retention: `Bodies` vs `HashFirst` | **Axis 3 = mesh server** | `serve_tier().holds_hash_directory()` | ✅ gauntlet R3 — a canonical holds BODIES, not a ladder |
| record known-hashes from advertisements | Axis 3 = mesh server | `holds_hash_directory()` | ✅ gauntlet R4 |
| queue a missing-signer recovery | Axis 3 = mesh server (via Key retention) | `should_note_missing_signer(retention)` | ✅ gauntlet R5 |
| answer a third-party identifier Pull on a public plane | **mutual trust root** (Axis 5), NOT a tier | `shares_a_trust_root_with(requester)` + layered per-requester ceilings | ✅ `identifier_lookups_are_entitled_by_a_mutual_trust_root`; R6 pins the negative |
| answer a subject Pull for the subject itself | always | `requester == subject` (#462) | ✅ correct |
| answer a Pull for this node's OWN record | always | `subject == local_key_id` | ✅ correct (#556) |
| serve trace-plane attestations | **Axis 3 = canonical** under Axis 5 | leg A ∧ leg B (`peer_has_serve_capability`) | ✅ correct (#386/#379, value-provenance-locked to persist's `INFRA_SERVE`) |
| bootstrap / rooting peer set | Axis 3 = canonical under Axis 5 | `CanonicalBootstrapPeer` machinery | ✅ correct |
| discoverable by fedID | Axis 4 | announced records present at the canonicals | ✅ (it *is* the directory) |
| contactable by fedcode | none — self-contained | `parse_contact_input` + the key-binding check | ✅ gauntlet R12 |
| group destination reachable | never announced | derived from member-held state (CC 5.4.6) | ✅ correct (the #499 line) |

## The claims ladder (how much a positive answer proves)

1. `claims_role(role)` — **a claim, not a capability.** Wire-supplied and
   envelope-lifted roles are visibility only (persist v19.0.0).
2. owner-conferred — claim ∧ the owner's `delegates_to` bears the scope.
   Attenuation-bound: a grant resolves only where every edge on the chain
   bears the scope; no amplification (CC 4).
3. blessed — the accord co-scrub, re-derived from the record's own
   cryptography on every consultation, never from write-gate history.
4. rooted-for-*me* — leg B, Axis 5 applied: the same blessing resolves
   differently under different roots.

---

## The CI cross-walk — each decision row as a flow

The validation the contextual-integrity framing makes possible: a serving
decision is appropriate iff the five flow parameters resolve. Where a
parameter collapses to a constant, the plane-level rule is safe; where it
cannot collapse, the gate must be per-row. **This is the derivation that
predicts every gate in the codebase.**

| flow | data subject | sender | recipient | info type | transmission principle | ⇒ gate |
|---|---|---|---|---|---|---|
| serve a promoted `Key` / `IdentityOccurrence` / `TransportDestination` to an attributed requester | the identity itself | the identity itself (`SelfOwn` / `OwnerOf` binding, persist `policy_for`) | any attributed peer | identity plane (public, no anonymity claim) | **set once at announce** (Axis 4 = the consent) | plane-level: any mesh server answers; no per-request consent check exists *because the principle already resolved* |
| serve an `Attestation` | the subject(s) named in the row — **≠ sender** | the attesting key (`SignerActsFor`) | consent-gated peer | per-`dimension` | **per-record** `consent:scope` grants (`retain`/`share`/`analyze`/`train`/`publish`) | per-row: producer's grant ∧ recipient `infra:serve` (blessed) ∧ `recipient_capability` — the one plane where the five cannot collapse |
| serve a `Revocation` / tombstone | the revoked identity | quorum from the receiver's own directory | everyone (`Global`, tombstone ceiling) | anti-rollback | mandatory flow — CC 5.3.2.2: consent revocations MUST promote, never local | never hash-first, never withheld: the flow is obligatory, so no gate may be able to stop it |
| answer a data-subject Pull ("what do you hold about me") | the requester | various | **the subject themselves** | any subject-pullable kind | subject access is not a disclosure | `requester == subject`, on every node (#462) |
| group traffic | members | members | derived destination — **never announced** | group planes | membership itself is the consent | no directory flow exists to gate: invisibility is structural, not policy (CC 5.4.6) |
| fedcode exchange | the code's issuer | the code's issuer | whoever they hand it to, out of band | identity + transport hint | **the handing-over is the consent** — scoped to the holder, not the federation | no announce needed; verify the key binding (a code is self-issued; its CRC proves transit integrity, not authorship) |
| widen a record's cohort | unchanged | unchanged | **wider** — the parameter that moves | unchanged | **a NEW resolution** — the subject consents again at the wider scope | the widening is itself the gate: absent a fresh emission at the wider scope, the old record simply does not flow there |

Reading the cross-walk backwards is the audit: if a proposed change makes a
plane-level gate answer a flow whose subject ≠ sender, or whose transmission
principle is per-record, the change is wrong — that is exactly the shape of
both mistakes this document was written after.
