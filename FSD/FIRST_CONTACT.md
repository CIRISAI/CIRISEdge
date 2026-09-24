# FSD — First Contact: the complete state space between two CIRIS nodes

**Status:** normative for edge (CIRISEdge#671 lands the last missing transition). **Sources this
document is derived from, in order of authority:** the CIRIS Constitution (CC 4.4.3.8 Policy A —
direct trust and its pluggable-root graph; CC 3.3.7 `consent:replication`; CC 3.3.6.2 the
authenticated identity↔address binding; CC 3.2 owner-binding; CC 4.2.2 hardware class; CC 5.2
structural invisibility), persist's `FSD/TRUST_ROOT_HOLDER_HARDWARE.md` (v47.3.0, #901), and
[ciris.ai/first-contact](https://ciris.ai/first-contact) (the six First-Contact Protocols, quoted in
§8). `FSD/CIRIS_EDGE_TRANSPORT.md` §5 remains the transport-layer detail (the `SourceKeyId`
constructors, the link-state × frame-kind table, round correlation); this document is the
**pair-level** view above it: every state two nodes can be in from the first frame to full
service, which gate answers at each rung, and what crosses.

The one sentence this document exists to make structural: **a node can never be asked to trust or
consent to a peer it cannot yet see.** Policy A is a *reader-side* walk over the *peer's*
allegiance facts (its owner-binding, its owner's acceptance of a root, its own acceptance); consent
is the other admission path. If either path gates the very rows the other path needs, the pair can
never leave first contact. CIRISEdge#668 found that for the trust path (the Rooted floor) and
CIRISEdge#671 for the consent path (the send set). Both are one carve-out with one name here: the
**allegiance facts** are the Attestation-plane members of the bootstrap set.

---

## 0. Vocabulary (frozen)

| Term | Meaning | Source |
|---|---|---|
| **Bootstrap kinds** | `Key`, `IdentityOccurrence` (carrying `transport_destination`), `TransportDestination` (the signed route). Self-authenticating: each verifies against the key it names, so they cross an *Identified* link. | CC 3.3.6.2; transport FSD §5.4 (#402/#636) |
| **Allegiance facts** | The four self-authored `delegates_to` rows that make a node *judgeable*: **owner-binding** `delegates_to(owner → node)` (CC 3.2, persist `owner_binding::DIMENSION` / CC 2.4.1.2 `delegation_purpose = owner_binding`); **acceptance** `delegates_to(owner → R, [infra:attest, infra:serve])` and `delegates_to(node → R, …)` (`trust:accepts:v1`, CC 4.4.3.8 item 3); and, when the node *is* a root, its **self-charter** `delegates_to(R → R, scopes)` (item 2). All at `cohort_scope: federation`, federation tier. | CC 4.4.3.8 items 1–3 |
| **Attributed** (per direction) | The frame's sender is a federation key: `owns_key` (the announced key fingerprints the record's pubkey) ∧ a hybrid-signed transport binding exists. Says nothing about trust. | transport FSD §5.2 (#659) |
| **Rooted** (pair) | `rooted_with(peer)`: the two owner-bindings resolve, and the two owners' acceptances name **one root in common that is valid at this node** (persist `trust_root_valid`, incl. the v47.3.0 holder-hardware leg). Computed every sweep, never stored. | CC 4.4.3.8 item 3 ("two nodes with no shared root compose nothing"); persist #901 |
| **Send set** (per direction) | The peers this node has granted `consent:replication` (persist `list_consent_peers(local)`), widened by the owner-binding axis (#524) and the self-collective axis (persist #884). A `ResolvedRecipient` exists only from this set. | CC 3.3.7 |
| **Reach** | Which rows a resolved recipient may be handed: `Consent` (everything the other gates allow), `SelfCollective` / `Family` (only rows of that scope), **`FirstContact`** (only this node's allegiance facts — #671). | `src/replication/resolved_state.rs` |
| **Conferral** | Accord co-scrub / `infra:serve` conferred by a root the node trusts. Authority, not standing. Never implied by Rooted. | CC 4.2.1; transport FSD §5.4.1 invariant 1 |

---

## 1. The two axes, and why they are two

Every direction `A → B` ("what A hands B") is a point in a product of two independent axes:

1. **The link axis** — what A can prove about B's identity: `Identified → Attributed`, then the pair
   property `Rooted`. Persist owns the truth (records, bindings, `trust_root_valid`); edge composes.
2. **The consent axis** — what A has *chosen* to hand B: none → `FirstContact` → (`SelfCollective` |
   `Family`) → `Consent`. Persist owns the grant rows; edge resolves them per round.

They are independent by construction (CC 4.4.3.8 vs CC 3.3.7 are different admission paths), and
that independence is the whole design problem of first contact: **the rows that move a pair along
the link axis are themselves Attestation rows, which the consent axis gates.** So the table below
names, for each cell, the *smallest* set that must cross so the other axis can advance — and
proves that set is closed (it can never widen into "everything").

---

## 2. What crosses at each rung (the closed sets)

| Rung of the sender `A` toward peer `B` | Bootstrap kinds | Allegiance facts of **A** | Rows A holds about **others** (charters of roots, third-party attestations, consent rows, content) |
|---|---|---|---|
| **R0** B unknown (no frame yet) | — | — | — |
| **R1** B *Identified* (a link exists, B not yet attributable) | ✅ delivered on the link (#402: only self-authenticating kinds) | ❌ | ❌ |
| **R2** B *Attributed*, **A has not consented to B** (production: the canonical toward every agent) | ✅ | ✅ **#671** — served under `Reach::FirstContact`; nothing else | ❌ `recipient_not_in_send_set` |
| **R3** B *Attributed*, A **has** consented to B, pair **not Rooted** | ✅ | ✅ **#668** — the floor's self-authored exemption | ❌ `recipient_not_rooted` |
| **R4** B *Attributed*, A consented, pair **Rooted** | ✅ | ✅ | ✅ subject to audience (CC 5.2), `#379` conferral for `trace:*`, item 6 `recipient_capability` |
| **R2′** B Attributed, A not consented, pair Rooted (A's owner and B's owner accept a common valid root but A never wrote a grant) | ✅ | ✅ (FirstContact) | ❌ `recipient_not_in_send_set` — **Rooted is not consent** (CC 3.3.7: out-of-group flow needs the explicit object) |

Two closure facts make the table safe:

- **The allegiance set is closed under the predicate**, not under "self-authored": a row is an
  allegiance fact iff `attesting_key_id ∈ self-publish set` ∧ `attestation_type = delegates_to` ∧
  (`is_owner_binding_envelope` ∨ `dimension = trust:accepts:v1`). A self-authored `consent:*`,
  `scores`, chat or content row is **not** in the set and stays behind the send set (#671 narrows
  #668: at R3 the floor exemption serves any self-authored row *to a consented peer*, which is
  fine — consent already covers it; at R2 the first-contact reach serves only the four).
- **`Reach::FirstContact` admits only `Audience::Federation`** — allegiance facts are federation
  rows by definition (CC 3.3.7 makes governance records public; the acceptance and owner-binding
  are exactly that). A `self`/`family`/`community` row can never ride first contact.

---

## 3. The pair state machine (both directions)

Let `L(A→B) ∈ {Unknown, Identified, Attributed}` and `C(A→B) ∈ {None, FirstContact, Consent}` (the
collective/family reaches are consent-shaped for this purpose), and `Rooted(A,B)` the symmetric pair
property. The **pair state** is the tuple `(L(A→B), C(A→B), L(B→A), C(B→A), Rooted)`.

```
                   announce(B) admitted at A            announce(A) admitted at B
  Unknown ──────────────────────────► Identified ───────────────────────► Attributed
                                       (link only)      owns_key ∧ hybrid binding (#636/#659)
```

**Transitions that need rows to cross** (the ones this FSD exists for):

| From | Needs | Which rung serves it | To |
|---|---|---|---|
| A Attributed at B, B holds none of A's allegiance | A's owner-binding + acceptances land on B | **R2** (FirstContact) or R3/R4 | B can evaluate `rooted_with(A)` |
| Both hold the other's allegiance, owners accept a common valid root | nothing further — computed | — | `Rooted(A,B) = true` at both (independently, from each one's records) |
| Rooted, A has consented to B | — | **R4** | A serves B everything the row gates allow |
| Rooted, A has **not** consented to B | A's grant (`consent:replication`, CC 3.3.7) — a governance act, never inferred | R2′ → R4 on the grant | full service |

**Regressions (all re-evaluated per sweep; nothing is cached past its cause):**

| Event | Effect | Ledger |
|---|---|---|
| `withdraws` of an acceptance, or an owner-binding revoked | `Rooted` false at the next sweep (both sides) | `recipient_not_rooted` resumes |
| Root halt latched, charter lapsed, pre-rotation commitment missing | root invalid → not Rooted | same |
| A holder of the common root has **no / malformed hardware evidence** (persist v47.3.0 #901) | root invalid → not Rooted — *the ruling, not a regression* | same |
| `withdraws` of the consent grant | R4 → R2′ at the next send | `recipient_not_in_send_set` resumes |
| A node's policy drops a hardware class | every root held by that class invalid at that node (persist I154) | same |
| Peer announces a key whose pubkey does not match its record (`PubkeyMismatch`) | never Attributed — the E3 spoof stays refused | `rooting_rejection` warn |

**Degenerate points, each with its own answer:**

- **The node is its own trust subject** (unowned): `owner_of(node) = node`; its acceptance is
  `delegates_to(node → R)`; allegiance set = {acceptance, (charter)}.
- **The node is a root** (`delegates_to(R → R)` charter): the charter is in its allegiance set; a
  peer that accepts R needs it to judge R valid (persist leg 2 / holder-hardware leg 5).
- **Never ourselves**: `recipient(local)` is `None` and first contact is not minted for `local`.
- **Both directions are separate first contacts.** Production: the agent has consented to the
  canonical (C(agent→canonical) = Consent) while C(canonical→agent) = FirstContact. The agent
  reads the canonical Rooted only because R2 exists; the canonical reads the agent Rooted through
  the agent's consented flow. Neither direction alone is enough; §4 walks it.
- **Different valid roots, forever**: the pair sits at (Attributed, FirstContact, Attributed,
  Consent, ¬Rooted) — each holds the other's allegiance, each serves nothing about others. Not a
  stall: the ladder's negative witness.

---

## 4. Production's topology, rung by rung (the CIRISServer#632 / #671 measurement)

A split, owned, announced **agent** that consents to the **canonical**; a canonical that consents to
**nobody** (production's canonical authors zero `consent:replication` rows). Both owners accept
the same valid root R whose holders carry attested hardware.

| # | Event | Gate that answers | State after |
|---|---|---|---|
| 1 | Agent announces; canonical admits the announce (`owns_key`, binding persisted) | transport §5.2 | canonical: agent *Attributed* |
| 2 | Canonical announces; agent admits | same | agent: canonical *Attributed* |
| 3 | Agent's rows offered to the canonical: its allegiance facts + its consent row + (nothing else yet) | agent → canonical is **R3** (consented, not yet Rooted): allegiance crosses by the #668 floor exemption; the consent row is self-authored and crosses too | canonical holds agent's owner-binding + acceptances |
| 4 | Canonical evaluates `rooted_with(agent)`: needs **its own** owner-binding and acceptance (it has them) and the agent's (it has them now) → common valid root R | persist `owner_of`, `trusted_roots_of`, `trust_root_valid` | canonical: agent **Rooted** |
| 5 | Canonical's rows offered to the agent | canonical → agent is **R2**: **before #671 the send-set gate withheld the whole plane** (`recipient_not_in_send_set: 4`, the measurement) — the #668 exemption sits *behind* it and was never reached. **After #671**: `Reach::FirstContact` serves exactly the canonical's owner-binding + acceptances (+ charter if it is a root) | agent holds the canonical's allegiance facts |
| 6 | Agent evaluates `rooted_with(canonical)` → R in common, valid | same walk | agent: canonical **Rooted** |
| 7 | Agent serves `trace:*` to the canonical | agent → canonical is R4 **and** the canonical holds conferred `infra:serve` (#379) | traces flow |
| 8 | Canonical serves the agent anything about others | still **R2′** — Rooted is not consent | withheld until the canonical's operator writes a grant (or the agent joins the infrastructure community and rides cohort membership, CC 3.3.7's in-group path) |

Step 5 is the whole of #671. Step 8 is deliberately unchanged: a canonical that consents to nobody
serves nobody's *others*; it only becomes judgeable.

---

## 5. The gates, in the order they run, and what each may say

For every Attestation row A considers handing B (advertise and the direct-fetch twin agree):

1. **Recipient resolution** (`resolve_attestation_recipient`): `local_key_id` missing →
   `local_identity_missing`; send set unresolvable → `send_set_unresolved` (fail-closed: whole
   plane); B in the send set / owner-routed / collective-routed → `Reach::{Consent, SelfCollective,
   Family}`; **otherwise → `Reach::FirstContact` (#671), never `None`** except for `local`.
2. **Projection** (`attestation_is_advertised`): is A a publisher of this row at all (CC 5.2
   structural invisibility)? Not a withhold — never eligible.
3. **`#379` conferral** for `trace:*`: recipient holds conferred `infra:serve` rooting to a root A
   trusts. Unchanged by first contact (allegiance facts are never `trace:*`).
4. **Item 6 `recipient_capability`**: producer-declared restrictions. Fail-open when none.
5. **Audience** (`audience_withholds`), in this order:
   1. reach admits the row's audience — `FirstContact` admits only `federation`;
   2. **first-contact narrowing (#671)**: under `FirstContact` the row must be an allegiance fact
      of A, else `recipient_not_in_send_set` (detail names the narrowing);
   3. the row's own audience membership (self = same principal; family/community = member's node);
   4. **the Rooted floor (#659/#668)**: not Rooted → `recipient_not_rooted`, except A's own
      self-authored rows.

The ledger tokens are unchanged by #671: a non-allegiance row toward a non-consented peer still
books `recipient_not_in_send_set`, so a run that reads that counter reads the same thing it read
before — minus the four rows that now cross.

---

## 6. Invariants (each has a witness)

| # | Invariant | Witness |
|---|---|---|
| I1 | **The first-contact reach carries only A's allegiance facts, at `federation` audience, and nothing under any other scope or of any other shape.** A self-authored non-allegiance row toward a non-consented peer is withheld and booked. | `bridge::a_peer_outside_the_send_set_is_served_exactly_this_nodes_allegiance_facts_671` (advertise + fetch twin) |
| I2 | **Rooted is never consent.** A Rooted pair with no grant is served nothing about others. | same test, second half; ladder rung 4 negative |
| I3 | **Rooted is never sufficient** (transport §5.4.1 invariant 1): `trace:*` keeps its conferral gate; trust weighting and audience untouched. | `trace_serve_requires_accord_blessing_and_trusted_root` (test-anchor lane) |
| I4 | **Nothing about others crosses below Rooted**, whatever the consent state. | `bridge::an_attributed_but_unrooted_peer_in_the_send_set_is_served_nothing`; ladder different-roots witness (ledger `recipient_not_rooted` moved) |
| I5 | **A valid root is as attested as its holders** (persist #901); edge re-derives nothing. | `bridge::a_common_root_whose_holder_is_unattested_is_not_rooted_901` |
| I6 | **Attribution is not trust**: an Advisory/self-signed peer is Attributed; `PubkeyMismatch` never is. | `route_table_e2e::identified_link_from_an_advisory_key_owning_peer_is_attributed_659` |
| I7 | **The bootstrap kinds cross an Identified link and nothing else does.** | transport §5.4.1 proptest |
| I8 | **Both directions are first contacts.** Production's topology (one-directional consent) converges to Rooted at both ends and to `trace:*` flowing one way. | `first_contact_ladder_659::…_shared_root…` with one-directional consent (#671) |
| I9 | **Never ourselves.** | `resolved_state` test "never ourselves" |

---

## 7. What is still owed (certification rungs, tracked on CIRISEdge#659)

- **Genesis-shaped**: the canonical's owner and the anchor's real holder records (YubiKey Layer B
  against the production pin) instead of the ladder's software mock — the rung persist's note asks
  the server to run before pinning.
- **Split-installed**: two hosts, two persist engines, real `identity_dir`s — the shape #661's
  baked-dial gate protects.
- **Community path** (CC 3.3.7's in-group alternative to a grant): a peer inside the infrastructure
  community rides cohort membership to R4 without a `consent:replication` row — today's
  `Audience::Community` arm; a ladder rung should measure it.

---

## 8. The six First-Contact Protocols, and where each one is mechanism here

Quoted from [ciris.ai/first-contact](https://ciris.ai/first-contact); the right-hand column is
the load-bearing rule in this document that realises it.

| Protocol | Text | Mechanism |
|---|---|---|
| **First, Do No Harm** | "When you do not know what you are looking at, the first job is to not make it worse." | Fail-closed everywhere a decision is unresolved (`send_set_unresolved`, `local_identity_missing`, malformed audience); an Identified link delivers only self-authenticating kinds; nothing about others below Rooted (I4). |
| **Admit What You Do Not Know** | "Watch for surprises. Accept that predictions have limits. The system that is sure it understands everything is the one most likely to fail." | *Attributed ≠ trusted* (I6): attribution is a fact about the sender, never a verdict; `RetryAfterRoster` is transient, not terminal; every withhold is booked by name so an absence can be read. |
| **Boundaries That Learn** | "Boundaries are not fixed walls. They are limits, guided by conscience, that adjust as understanding grows." | Rooted is computed every sweep from live rows and never stored; consent is a row that can be withdrawn between rounds; un-trust is deleting one acceptance (CC 4.4.3.8 item 4). |
| **Look Before You Leap** | "Begin with observation. Proceed with give-and-take. When the stakes are unclear, ask someone wiser before acting." | The rung order itself: observe (announce, bootstrap kinds) → exchange the allegiance facts (give-and-take at R2/R3 — *this is what #671 restores*) → judge (`rooted_with`) → serve. A root's validity defers to its holders' attested hardware (persist #901). |
| **Treat Others as You Would Want to Be Treated** | "Recognize every other thinking being as worthy of respect. Act only in ways that protect their ability to think, choose, and thrive." | The symmetry rule: what we require a peer to deliver so we can judge it, we let the peer pull from us so it can judge us — the allegiance facts cross **before** consent or trust exists, in both directions (I8). |
| **Know When to Ask for Help** | "Some decisions should not be made alone. When the uncertainty is too high, stop, gather context, and hand it to a designated human." | Consent is never inferred (I2): R2′ → R4 needs an operator's `consent:replication` grant; conferral (`infra:serve`) needs the accord ceremony (CC 4.2.1); the withhold ledger and the throttled `warn`s are the context handed up. |

---

## 9. Change log

- **v30.3.1 (CIRISEdge#671)** — `Reach::FirstContact`: a non-consented Attributed peer is minted a
  recipient that carries only this node's allegiance facts; production's canonical becomes
  judgeable by every agent. Ledger tokens unchanged. Ladder's shared-root rung made one-directional
  (I8).
- **v30.3.0 (persist v47.3.0, #901)** — the holder-hardware leg folded into `valid` (I5).
- **v30.2.0 (#659/#668)** — Attributed state; `rooted_with`; the Rooted floor with the self-authored
  exemption; the two-node ladder.
