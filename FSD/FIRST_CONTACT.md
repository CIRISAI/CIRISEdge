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
| **Announced** (per node) | The node's owner-binding `owner → node` is live at `cohort_scope: federation` — written there, or widened there by persist's `widen_audience` `supersedes` (`POST /v1/federation/announce`, CIRISServer#655). The person chooses it per device; a minor's binding can never be announced (persist, CC 3.4.13 Q5). An unowned node has no announce axis. | CC 5.4.6; persist `check_minor_owner_binding_not_announced` |
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

### 2.1 The announce axis on the bootstrap kinds (CIRISEdge#682)

The bootstrap kinds are self-authenticating, so they could cross any link. Whether they
*should* cross is the owner's choice, made per node (CC 5.4.6: identity rows are lightnet
only for the devices the person announced). The gate is on the SENDER's side and keyed on
the row's occurrence key `n`; it narrows the ✅ in the bootstrap column of the table above
for two of the three kinds:

| `n` is… | `IdentityOccurrence` / `TransportDestination` about `n` go to | Ledger |
|---|---|---|
| unowned (its own trust subject: the canonical, a bare server) | every peer, as before | — |
| owned and **announced** | every peer, as before | — |
| owned and **not announced** | `n` itself and `nodes_owned_by(owner_of(n))` — never a stranger, never an unbound requester | `identity_row_node_not_announced` |
| owner or announce state unreadable (`AmbiguousNodeOwner`, a read error) | `n` itself only (fail-closed) | `identity_row_announce_unresolved` |

`Key` is not gated: a key record carries no route and is what every verifier needs to check
a signature. The same predicate holds on the advertise, the direct-fetch twin and the subject
Pull (`bridge::an_unannounced_nodes_route_reaches_only_its_owners_nodes_682`).

**How it composes with the rungs.**

- **An announced node is unchanged at every rung** (R1–R4), so first contact between announced
  or unowned nodes — production's agent ↔ canonical topology, and the ladder — is untouched.
- **An unannounced node never becomes Attributed at a stranger**, because Attributed needs a
  hybrid-signed transport binding and its route is exactly what is withheld. That is the
  point, not a regression: a darknet device is reached by its person's own nodes and by
  whoever holds its code, and is never listed. It can still *dial* announced peers, whose
  routes are public.
- **An unannounced second device and its owner's first device (CIRISEdge#683).** The second
  device B *reaches* the first device A as before: A is announced, so A's route is public and
  B dials it; A answers on the link B opened (#353). What the gate adds is on B's serve: B
  hands A its occurrence and route only once B can see that A is its owner's node, i.e. B
  holds `owner → A`. That row is A's owner-binding at `federation` — public, but at B it
  arrives only by a path that does not need B to be Attributed at A first. Precondition
  **I14**: the device-join answer (#683's opaque response, the server's second-device flow)
  carries the owner's binding to A alongside the new binding to B. Without it B withholds
  its route from A (booked), and A cannot attribute B — the same state as before #683, never
  a worse one.
- **Consent does not widen it.** A peer in B's send set that is not one of the owner's nodes is
  still a stranger for these two rows: announce is the owner's disclosure decision about the
  device, not a replication grant.

### 2.2 First contact on the opaque plane (CIRISEdge#683)

§2.1 leaves one pair with no way in: a device the first device has **never seen**. The new phone
B asks its owner's first device A to let it join (the server's device-join kind, `0x0000_0002`).
The request is an `OpaqueRequest` signed by B's key, and A has no record of that key, so A's
verify answers `UnknownKey` and the frame is dropped. B cannot fix that through replication: B
becomes Attributed at A only through its route, and §2.1 withholds B's route from A until B
holds `owner → A`, which is exactly what B is asking for. So the request has to carry what A
needs to check it.

**What a first-contact request may carry.** Two fields and nothing else: `key_record`, the
sender's own `SignedKeyRecord`, **self-signed** (`scrub_key_id = key_id = envelope.signing_key_id`),
and `challenge`, 32 fresh random bytes (`OsRng`, hex), present exactly when `key_record` is. No
attestation, no route, no third party's record. The challenge exists for the answer: see the
requester's order below. It is the same object a #402 bootstrap
`Deliver` carries, arriving on the opaque plane instead of the replication plane.

**The receiver's order (A).** All of it runs *before* the envelope verify, because the verify
records the nonce in the replay window first: a verify that failed `UnknownKey` and was re-run
after admission would read as a replay.

| Step | Check | Refusal (dropped, counted under `first_contact_outcomes`, throttled `warn`) |
|---|---|---|
| 0 | Applies only to an `OpaqueRequest` carrying `key_record` whose signing key A's directory does **not** hold. A known key ignores the record and takes the ordinary path. An unknown key **without** a record is dropped `UnknownKey` exactly as before. | — (`first_contact_known_key` counts the ignored case) |
| 1 | The record names the envelope's signer and is self-signed. | `first_contact_record_names_other_key`, `first_contact_record_not_self_signed` |
| 2 | **Rate limit** before any cryptography: per sender key, per link (the path the frame arrived on; a transport with no link identity shares one bucket), and one node-wide ceiling. The node-wide ceiling is the one that holds under identity rotation, where every request brings a fresh key. | `first_contact_sender_budget_spent`, `first_contact_link_budget_spent`, `first_contact_node_budget_spent`, `first_contact_at_capacity` |
| 3 | **Proof of possession**: persist's `verify_key_registration` (Strict hybrid, subject-bound, the gate `register_federation_key` runs). | `first_contact_proof_of_possession_failed`, and nothing is written |
| 4 | **Admission** through the replicated Key door: the bridge's `apply_key`, which calls persist `apply_replicated_key_record` (`KeyDoor::ReplicatedInsert`, a key minted elsewhere). That is the #402 door. With no replication runtime installed, the same persist call is made on the directory directly. | `first_contact_key_refused` (persist names the reason) |
| 5 | The envelope verify, unchanged. | the existing `verify_failures_total` classes |
| 6 | The host handler runs with `first_contact = true`. | — |

A refused request gets **no answer**. An answer to a refused request would tell the sender which
check failed, and a sender who can see that can tune its retries against it (#554 D3).
`first_contact_admitted` counts the ones that got through.

**What admission is, and what it is not.** A holds one more key row. That row grants nothing.
Attributed still needs a hybrid-signed transport binding and Rooted still needs an acceptance.
The Key plane's advertise is `SelfOwn` (`list_keys`), so A never offers B's key to anyone; a
subject Pull naming B can return it, which is true of every key (keys are public by design, §2.1).
The request writes no attestation, no consent row and no CEG record. This is not a new plane. It
is the #402 carve-out's door, reached from the opaque plane. A record can be admitted and its
envelope then fail verify; the result is a PoP-proven key and nothing else, which is also what a
#402 bootstrap `Deliver` leaves.

**The reply rides the requester's link** (#353). B is unannounced and usually NAT'd, so A has no
route to dial. The inbound frame carries a transport-level *reply path* (Reticulum: the link it
arrived on), and every opaque response is sent on it first. The by-key send is used only if that
link is gone. Before #683 the reply looked for the freshest *attributed* link to the requester.
Over Reticulum a dialing device usually has one, because #627's on-link announce binds the link
(Advisory) before the request arrives. But that depends on the announce arriving first, and a
transport with no on-link announce has no such binding at all. The reply path is a fact about the
frame and depends on neither.

**The answer carries the binding (I14).** A first-contact handler answers with
`OpaqueAnswer { response, introductions }`. `introductions` is a list of key records and
attestations. On a first-contact answer edge adds A's own key record, so B can verify the reply.
The host adds `owner → A` (A's owner-binding), the owner's key record, and `owner → B` once it
mints that binding. Only the host can mint it, because it depends on the person approving the join.

**The requester's order (B).** B admits introductions only from a **solicited** answer: its
`in_reply_to` matches a request B sent, B sent that request to the key that signed the answer, and
the answer arrived on the transport the request went out on. Anything else is ignored and counted
`first_contact_unsolicited_introductions`.

Why the request carries a challenge. The correlation is the request body's hash, and the solicited
check reads it off a frame nobody has verified yet. Without the challenge every field of a join
request is public or guessable: the join kind is fixed, the payload is often deterministic, and
the key record is the sender's published row. Anyone could compute the correlation and forge an
answer that introduces a record *claiming* A's `key_id` with the attacker's keys. That record
passes proof of possession (see I19), and the attacker signs the answer with those keys. With 32
random bytes in the body, only a party that saw the request can name it. The path check is the
second belt: an answer must come back on the medium the request left on. Only the transport is
checked, not the link: edge sends by key and never learns which link the transport picked, and
recording it would be new machinery.

1. Keys, **before** verifying the answer, since the responder's key may be among them: known
   keys are skipped; each unknown one goes through the same PoP and Key door as step 3–4 above.
   Capped at 8.
2. Verify the answer (unchanged pipeline).
3. Attestations, through the replication apply door (`apply_envelope_bytes`, unattributed). That
   is the door replication uses, so the bridge's owner memo is invalidated on admit. A side door
   into persist would leave the §2.1 gate reading a stale owner. Capped at 16.
4. The caller's `send_opaque_request_introducing` returns the response **and** a report of what was
   admitted, known or refused. By then B holds `owner → A`, so §2.1 lets B serve its occurrence and
   route to A, and A can attribute B on B's next link.

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
| I10 | **Deployment precondition — the self-publish set names the owner.** First contact carries only rows *authored by* a self-publish identity, and an owned node is judged through its **owner's** acceptance; a set of `[node]` alone hands a peer the node's own acceptance and no root for the trust subject, and the pair never Roots. The server's `self_publish_set` for a production node is `[node_key, owner_key]`. | ladder: `Node` publishes `[key, owner]`; `bridge::a_peer_outside_the_send_set_…_671` publishes `[local, owner]` and asserts the OWNER's acceptance crosses |
| I11 | **Deployment precondition — a root is judged from the judge's own records.** `trust_root_valid` reads the charter and every holder's evidence-carrying key record from the judging node's directory; nothing at first contact carries a *third party's* charter (rung R2′). For the accord these rows are genesis-seeded on every node; for any other root they must have replicated (or been chartered locally) before acceptance can Root anyone. | ladder: `Node::new(.., roots, chartered)` — the different-roots rung withholds R's charter until the roots meet, and a peer that lacks a root's KEY refuses its charter at admission |
| I12 | **A stalled root still Roots the pairs already attached to it** (persist v51.0.0, CC 3.2 T7 + T4). A trust-root community below M+1 active founders is *valid but non-admitting*: `resolve_community` serves it with `live: false` (v50 returned no resolution), `trust_root_valid` deliberately ignores `live` (persist `FSD/TRUST_ROOT_RC6.md` §3; the mutant "a stalled root is invalid" is KILLED by I195), and "non-admitting" is enforced where something new is conferred — `admit_community_change` refuses a new member with `liveness_stalled_non_admitting`. `rooted_with` composes `trust_root_valid(..).valid` and reads no liveness, so two subjects attached before the stall stay Rooted; refusing them would detach the attached, which T4 forbids. Edge adds no stall gate. | persist I195 (stalled ⇒ `trust_root_valid` unchanged, new member refused); edge's `rooted_with` reads only `.valid` — no edge fixture stands up a trust-root *community* (its roots are key roots), so the community arm is persist's witness |

| I13 | **An unannounced node's identity rows reach only its owner's nodes** (CIRISEdge#682, CC 5.4.6). An owned node's `IdentityOccurrence` / `TransportDestination` go to every peer iff its owner-binding is live at `federation`; otherwise only to `nodes_owned_by(owner)`, on the advertise, the fetch twin and the subject Pull, booked `identity_row_node_not_announced`. Unowned nodes and announced nodes are unchanged; the decision is read from persist, memoized per sweep. | `bridge::an_unannounced_nodes_route_reaches_only_its_owners_nodes_682` (advertise + fetch + unbound); `bridge::an_announced_nodes_route_reaches_a_stranger_682`; `bridge::the_announce_walk_is_memoized_across_peers_and_planes_682`; ladder unchanged (its owner-bindings are at `federation`) |
| I14 | **Deployment precondition: a device learns its siblings from its owner's bindings.** An unannounced device serves its route to a sibling only once it holds `owner → sibling`. The second-device join (#683) must deliver the owner's binding to the approving device with the new device's own binding. | §2.1, §2.2; `bridge::the_first_devices_binding_in_the_answer_opens_the_new_devices_route_683` (withheld before the answer's rows are admitted through the requester's door, served after); `first_contact_opaque_683::the_answer_introductions_land_at_the_requester_683` |
| I15 | **A first-contact opaque request admits at most its sender's own key, and nothing else.** Admission happens only after the shape check, the rate limit (per sender, per link, node-wide) and persist's proof of possession, in that order, and goes through the replicated Key door. A refused request leaves no row and gets no answer. | `first_contact_opaque_683::a_forged_record_is_refused_and_nothing_is_admitted_683`, `…::a_record_naming_another_key_is_refused_683`, `…::the_first_contact_budget_trips_by_name_683`; `first_contact::tests::*` (the three budgets) |
| I16 | **An unknown key without a record is dropped exactly as before.** | `first_contact_opaque_683::an_unknown_key_without_a_record_is_dropped_as_before_683` |
| I17 | **An opaque answer rides the path its request arrived on**, and falls back to the by-key send only when that path is gone. | `first_contact_opaque_683::a_never_peered_device_with_its_key_record_is_verified_handled_and_answered_on_its_path_683` (the path is asserted); `reticulum_loopback::a_never_peered_device_is_answered_on_the_link_it_opened_683` (end to end over Reticulum; the #627 on-link announce also binds the link there, so this one does not distinguish the path) |
| I18 | **A requester admits introductions only from a solicited answer** (its `in_reply_to` matches a request it sent to the answer's signer), keys by proof of possession before the verify and attestations through the replication apply door after it. | `first_contact_opaque_683::an_unsolicited_answer_introduces_nothing_683`, `…::the_answer_introductions_land_at_the_requester_683` |
| I19 | **The remaining limit is on-path trust on first use.** A device cannot tell the true holder of a `key_id` it has never seen. persist binds the `key_id` inside the registration envelope and checks the self-signature against the record's own public keys, but never derives `key_id` from the public key, so a self-signed record may claim any `key_id`. The challenge (off-path parties cannot name the request) and the path check (the answer must arrive on the request's medium) narrow who can attempt the substitution to a party that saw the request on that medium; neither prevents it. Closing it needs the key id to be derivable from the key (a persist change) or an out-of-band commitment to the first device's key (the pairing code). | `first_contact_opaque_683::a_forged_answer_built_from_public_material_introduces_nothing_683` (the off-path half; fails on the pre-challenge code, where the forged record was admitted as the first device's key) |

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

*Non-normative.* This section is the rationale a reviewer checks the contract against, not a
source of gates: the normative rules are §2–§6 and the Constitution clauses they cite. Two of the
six are structural here (**Look Before You Leap** is the rung order itself; **Treat Others** is the
symmetry rule that #668/#671 implement); the rest name a disposition the mechanism honours.

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

- **CIRISEdge#683** — §2.2 first contact on the opaque plane. An `OpaqueRequest` may carry its
  sender's self-signed `key_record`. The receiver checks shape, then rate (per sender, per link,
  node-wide), then proof of possession, then admits through the #402 Key door, all before the
  envelope verify. Every opaque answer rides the path its request arrived on (a reply path the
  transport stamps on the inbound frame; Reticulum uses the link id). A first-contact answer
  carries `introductions`, which the requester admits only from a solicited answer. Ledger:
  `first_contact_outcomes`. I15–I19; I14 witnessed. Review: a key-carrying request also carries a
  random `challenge`, so an off-path attacker cannot compute the correlation, and introductions are
  admitted only from an answer on the request's transport. I19 records the on-path TOFU limit.
- **CIRISEdge#682 / #678** — §2.1 the announce axis: an owned, unannounced node's occurrence and
  route reach only its owner's nodes (advertise, fetch twin, subject Pull; ledger tokens
  `identity_row_node_not_announced` / `identity_row_announce_unresolved`); I13, I14.
  `SERVE_ADVERTISE_POLICY_HASH` re-pinned. The `SelfOwn` publish set may be chosen per plane
  (`KindPublishSelector`, #678); unset, unchanged.
- **v30.3.1 (CIRISEdge#671)** — `Reach::FirstContact`: a non-consented Attributed peer is minted a
  recipient that carries only this node's allegiance facts; production's canonical becomes
  judgeable by every agent. Ledger tokens unchanged. Ladder's shared-root rung made one-directional
  (I8).
- **v30.3.0 (persist v47.3.0, #901)** — the holder-hardware leg folded into `valid` (I5).
- **v30.2.0 (#659/#668)** — Attributed state; `rooted_with`; the Rooted floor with the self-authored
  exemption; the two-node ladder.
