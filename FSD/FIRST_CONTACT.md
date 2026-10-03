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
| **R2** B *Attributed*, **A has not consented to B** (production: the canonical toward every agent) | ✅ | ✅ **#671** — served under `Reach::FirstContact`; nothing else | ❌ `recipient_not_in_send_set`, with two exceptions: **(#752, §2.3)** the live `federation` owner-binding of a node in A's `Key`/`IdentityOccurrence` publish set, when A installed a `KindPublishSelector` (the public roster, CC 5.4.6), still behind the Rooted floor; and **(#756, §2.4)** the membership ceremony addressed to B's person: a proposal naming B's owner, and the invitee's reply to B's owner's proposal held at A (no Rooted floor on those two) |
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
  are exactly that). A `self`/`family`/`community` row can never ride first contact, with one
  exception (§2.4, CIRISEdge#756): the membership ceremony addressed to the peer's own person — a
  `membership:proposal:v1` naming it, and the invitee's reply to its proposal — at the group's
  `family`/`community` target.
- **The one row about others that R2 carries is itself public** (§2.3, #752): an announced
  owner-binding is the device roster CC 5.4.6 makes public, and it crosses only for nodes the
  relay already publishes on the bootstrap kinds. The set stays closed under a predicate persist
  answers; it does not become "rows about others".

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

### 2.1.1 The owner-binding rung — a binding signed by the receiver's own owner (CIRISEdge#727)

I14 is the designed path: the device-join answer carries the owner's bindings, so a device knows
its siblings before it needs to. This rung is the **belt** under it, for a device that skipped or
lost that exchange: two devices of one owner, both claimed before announcing (owner-binding at
`self`), each knowing only its own binding. Without it they deadlock on §2.1, witnessed in
`owned_devices_route_682::unannounced_devices_of_one_owner_exchange_routes_and_admit_682` (on
the pre-#727 code: ≈320 `identity_row_node_not_announced` per side in 120 s, no route crosses).
The shape is the one #402 closed for `Key` / `IdentityOccurrence` — the row that would earn
attribution is the row attribution is demanded for — so the answer has the same shape: a rung
beside the #402 rung, for one more row, on the same door.

**Why the row is self-authenticating to its receiver, and to nobody else.** An owner-binding
`O → X` is `delegates_to(O → X, delegation_purpose: owner_binding)`, signed by O ([CC 3.2]: the
owner signs its own owner-binding, MUST). A receiver R whose own owner is O already holds O's key
record — it is R's trust subject — so R can verify the signature with what it holds, and nothing
in the row needs the link's attribution to be true. That is exactly why a self-signed `Key` crosses
an Identified link (#402). To a node that is *not* O's, the same row is a claim about a stranger's
household: it has no standing to hold it and no use for it ([CC 5.4.6] #111: a node whose binding
is held only at `self` is reachable by the person's own nodes and by whoever holds a code they
issued, and MUST NOT be enumerated to any node outside the owner's `self` cohort).

**Why the push is the owner's act.** Dialling is what an unannounced node does to a peer its owner
chose — the peer set the owner configured, or the code the owner issued ([CC 2.6.8], [CC 5.4.6]).
So a node revealing "I am O's" on a link *it* dialed reveals it to a peer O chose. A link a
stranger opened reveals nothing: the stranger learned X's transport destination from the RNS
announce every routing node emits, which places nothing on the roster, and X answers on it with
what §2.1 already allows and nothing more.

**The rule, three parts.**

1. **Admission carve-out.** A receiver R with `owner_of(R) = O` admits an owner-binding
   attestation `O → X` arriving on ANY link, attributed or not, when the attester is R's OWN owner
   and the signature verifies against the owner key R holds. A binding whose attester is not R's
   owner takes the ordinary path, unchanged: dropped un-attributed, admitted through the sync door
   attributed. On admit the #682 owner memo invalidates (the same hook `owner_binding_touched`
   fires for every admitted binding), so R serves `O → R` and its route to X on the next round —
   bounded in rounds, never a TTL wait (#568).
2. **Send carve-out.** A node X pushes its OWN owner-binding `O → X` — about itself, nothing else —
   as an unsolicited bootstrap-plane `Deliver` (the #927 bare-Deliver shape, kind `Attestation`,
   one envelope) in exactly two situations: **(i) on a link X itself dialed**, right after the link
   is identified and its announce and bundle are served (#627 / #436 order); **(ii) as the answer**
   to a sibling's binding X has just admitted as NEW under rule 1, on the reply path of the link it
   arrived on (the #683 answer shape, `send_on_reply_path`). Case (ii) exists because the initiator
   direction does not always dial: a node whose sends ride the link its sibling opened (#531 link
   reuse) never reaches the dial-path push, and without the answer the exchange is one-way — the
   sibling withholds its route forever (witnessed on the first cut of this rung). The answer's
   recipient is proven to be O's node, a stronger warrant than a dial; it is sent only on a NEW
   admission, never on a row already held, so two siblings exchange exactly one binding each and
   stop. Never advertised, never on a link a stranger opened, never any binding about another node.
   The serve policy (advertise, fetch twin, subject Pull, the #884 send-set gate) is untouched: the
   row still crosses no round toward a peer outside its audience.
3. **Privacy bound.** A stranger S (not O's) receiving `O → X` refuses it under rule 1 by name
   (`owner_binding_not_own_owner`, or `owner_binding_receiver_unowned` when S has no owner), before
   any cryptography, and stores nothing; O's device set stays non-enumerable to S. No announce, no
   directory listing, no derived plane is touched.

**State table (the receiver R, for one inbound un-attributed `Deliver` of kind `Attestation`).**

| Frame | `owner_of(R)` | Attester | Signature vs R's held owner key | Verdict | Ledger (`first_contact_outcomes`) |
|---|---|---|---|---|---|
| any envelope is not an owner-binding `delegates_to` | — | — | — | not this rung: dropped `SkippedNoSourceKeyId` as before | — |
| more than `MAX_OWNER_BINDING_PUSH` envelopes | — | — | — | refused, nothing read | `owner_binding_deliver_oversized` |
| all owner-bindings | unresolved (read error, `AmbiguousNodeOwner`) | — | — | refused, fail-closed | `owner_binding_owner_unresolved` |
| all owner-bindings | `None` (R unowned) | — | — | refused | `owner_binding_receiver_unowned` |
| all owner-bindings | `O` | `≠ O` | not checked | refused, per row | `owner_binding_not_own_owner` |
| all owner-bindings | `O` | `O` | fails | refused, per row | `owner_binding_signature_invalid` |
| all owner-bindings | `O` | `O` | verifies | persist's replicated-attestation door (Wire origin, every admission gate intact — the single-owner gate included) | `owner_binding_admitted` / `owner_binding_held` / `owner_binding_door_refused` |
| same frame, `source_key_id` present (an attributed link) | — | — | — | the ordinary attributed path, unchanged | the Attestation plane's own counters |

**The sender X, for one link.**

| Link | X holds a live owner-binding about itself | Pushed | Ledger |
|---|---|---|---|
| X dialed it | yes (`attester = owner_of(X)`, `attested = X`, not retired, not expired) | that one row, once, after announce + bundle | `owner_binding_pushed` (or `owner_binding_push_incomplete` when the Channel stalls) |
| X dialed it | no (unowned, or the owner is ambiguous — fail-closed) | nothing | — |
| a sibling's binding was just admitted as NEW on it (either direction) | yes | that one row, once, on the reply path | `owner_binding_answered` (or `owner_binding_answer_failed`) |
| a sibling's binding arrived on it but was already held, or was refused | — | nothing (the exchange is complete, or the sender is no sibling) | — |
| a peer opened it, nothing admitted on it | — | nothing | — |

**Convergence (the un-ignored witness).** X dials R; X pushes `O → X`; R admits (rule 1), the memo
invalidates, R's next round serves `O → R` and its route to X (§2.1: X is now in
`nodes_owned_by(O)` as R resolves it); R's own dial of X pushes `O → R` the same way; both hold
each other's binding, both serve their routes, both Attributed, both Rooted (#393 item 2 holds both
ways), a Resource-carried row crosses. The bound is in **rounds** (the witness asserts it), and no
TTL is waited on: every state change that moves the answer fires the memo invalidation.

**Recovery (the wiped device).** A device X wiped to its seed and its owner's key record holds no
binding, so it pushes nothing and — being unowned in its own directory — admits nothing on this
rung. It re-converges by dialling a sibling R that still holds `O → X`: X's bootstrap rows cross
(#402), R attributes X and, X being one of O's nodes as R resolves it, serves it `O → X`, `O → R`
and its route on the ordinary attributed path; X then holds its binding again and the rung applies
to it as before. The genesis rule (CC 3.2: the first binding is set at provisioning, never by a
landgrab) is untouched: nothing here mints a binding, and a receiver never admits one signed by
anyone but the owner it already has.

**Invariants (each witnessed in §6, I20).**

- **(I-a)** An owner-binding whose attester is the receiver's OWN owner is admitted on any link,
  after signature verification against the owner key the receiver holds.
- **(I-b)** A node pushes only its OWN owner-binding, only on a link it dialed or in answer to a
  sibling's binding newly admitted on that link, and never advertises it. A stranger's link gets
  nothing: no push (it was not dialed by this node), no answer (nothing of a stranger's admits).
- **(I-c)** A stranger receiving it refuses by name, before any cryptography, and O's device set is
  not enumerable to it.
- **(I-d)** Admission invalidates the #682 memo, so convergence is bounded in rounds, with no TTL.

[CC 3.2]: https://github.com/CIRISAI/CIRISConstitution/blob/4fd2e9e/constitution/part_3_the_namespace.md
[CC 5.4.6]: https://github.com/CIRISAI/CIRISConstitution/blob/4fd2e9e/constitution/part_5_transport_substrate.md
[CC 2.6.8]: https://github.com/CIRISAI/CIRISConstitution/blob/4fd2e9e/constitution/part_2_the_grammar.md

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

### 2.3 A relay's published devices: the public roster at first contact (CIRISEdge#752)

§2.1 lets an announced device's occurrence and route reach a stranger; a host with a
`KindPublishSelector` (#678, the canonical in CIRISServer#701) publishes them for devices that are
not its own. A stranger that peers only that relay then holds `D`'s key and occurrence but cannot
list `D` under its owner `O`, because `O → D` is a row about a third party and R2 carried none. It
cannot even admit `D`'s occurrence: persist's `signer_acts_for` lifts a node signing its own
occurrence only through the owner-binding.

**Normative basis.** CC 5.4.6 ([CC 5.4.6], CIRISConstitution#111, ruled): a person's device
roster is public exactly for the devices announced, and announcing IS carrying the owner-binding
at `cohort_scope: federation`. That binding is public by definition, so a relay that hands it to a
stranger concedes nothing the CC withholds.

**The rule.** Under `Reach::FirstContact`, an Attestation row that is not one of A's allegiance
facts is still served when **all four** hold, each read from persist:

| | Condition | Read |
|---|---|---|
| (a) | the row is an **owner-binding** | persist `is_owner_binding_envelope`, on a `delegates_to` or the `supersedes` widening that announces it |
| (b) | at **`cohort_scope: federation`** (the announce) | the row's column |
| (c) | **live**: its attester is the subject's single live owner, and the row is one of the live announcing rows | persist `owner_of`, then the #682 announce walk (`retired_ids`, `expires_at`, the widening judged on its prior) — the same liveness §2.1 reads |
| (d) | its **subject is in A's `Key` or `IdentityOccurrence` publish set** | the host's `KindPublishSelector` answer for those kinds |

No selector installed ⇒ the rule never fires and R2 is #671's, byte for byte.

**What stays withheld**, under the unchanged `recipient_not_in_send_set`: consent grants (even
about a published node), every non-owner-binding row about others, bindings at `self` (an
unannounced device — the projection already hides these from a non-producer), bindings of nodes A
does not publish, and a binding whose attester is not the node's live owner. **The Rooted floor
(#659) still runs** on the rows the rule admits: they are rows about others, so a peer A is not
Rooted with is served none of them (`recipient_not_rooted`). Production's canonical is Rooted with
every agent through the accord, so the floor does not bite there.

**The three axes.** The rule sits in the audience gate's first-contact narrowing, which the
advertise and the direct-fetch twin both run, so they agree. The subject Pull needs no twin: it
answers only with rows about or by the requester, and a relay's binding of a third party's device
is neither.

---

### 2.4 The membership ceremony at first contact (CIRISEdge#756)

(§2.3 is CIRISEdge#752's relayed owner-binding, on the v37.1 track; the numbering leaves it room.)

**What it is for.** An invitation is how a stranger joins a group. CC rc6 3.1.3.2 (CIRISConstitution
#133, as amended in edb0253) makes admission two consents, the group's and the joiner's own, and
names `subject_key_ids` as "the key the substrate delivers on — a proposal is readable by, and
applied on, any node whose self-collective contains that entry, without that node holding the
group's roster". persist ships the wire (CIRISPersist#955, `FSD/MEMBERSHIP_ACCEPTANCE.md` §3.1, §7)
and leaves the routing to the transport: the proposal reaches K's node keyed on `subject_key_ids`,
and K's `membership:acceptance:v1` / `membership:decline:v1` reaches the proposer's nodes. The
invitee is, in the normal case, a stranger to the group's nodes: no `consent:replication` grant
names K's node, so it is reached as `Reach::FirstContact`. Before #756 that reach admitted only
`federation` rows and only this node's allegiance facts, so the invitation was withheld and the
joiner could never consent. #754 added the audience arms (`peer_is_proposal_invitee`,
`peer_is_reply_proposer`); this section adds the reach half.

**persist 8fcbeb9e (CIRISEdge#761).** Who a ceremony row is addressed to is now persist's
`replication_audience::may_receive`: a proposal reaches every node whose principals
(`self_collective::principals_of`) include its invitee, an acceptance or decline the nodes of the
proposer of the held proposal it answers, and every stage the group's membership-plane audience.
Edge's own invitee and proposer checks (`peer_is_proposal_invitee`, `peer_is_reply_proposer`,
`proposal_invites_peer`) are retired. What stays edge's is the transport half: under first contact
a `membership:proposal|acceptance|decline:v1` row at a `family`/`community` audience that
`may_receive` admits as **refers-to** crosses the reach and skips the Rooted floor below. A row that
reaches X only as a member of the group is not first-party and keeps the floor. The text below is
the pre-v53 statement of the same addressing.

**The rule.** Under `Reach::FirstContact` a node N serving peer X additionally serves exactly two
row classes, both at a `family` or `community` audience (the group's target), and nothing else:

- **(a) the invitation.** A `membership:proposal:v1` row whose `subject_key_ids` contains
  `owner_of(X)` (persist's resolver; X itself when X is unowned), i.e. the proposal addressed to
  X's person.
- **(b) the answer.** A `membership:acceptance:v1` / `membership:decline:v1` row whose
  `references_attestation_id` resolves to a proposal row **held in N's store**, whose
  `attested_key_id` (persist §10: the reply is attested to the invitee) is in that proposal's
  `subject_key_ids`, and whose proposal's proposer resolves to X's person (`owner_of` of the
  proposal's `attesting_key_id` equals `owner_of(X)`, or the proposal's attester is X). This is the
  reply travelling from the invitee's node back to the node(s) of the person who invited.

Everything else a first-contact peer is withheld stays withheld, under the same token
(`recipient_not_in_send_set`): any other row at the group's target, a proposal addressed to anyone
else, a reply to a proposal N does not hold, a reply to someone else's proposal, and every other
shape the §2 table lists. The owner reads are persist's `owner_of`, memoized per sweep with the
other reach reads; a proposal is read once per sweep per reference.

**The #659 Rooted floor does not apply to these two classes** (decision, #756). The floor keeps
"rows A holds about **others**" (§2 table) from an un-Rooted peer. Neither class is about others to
the recipient: the invitation names the recipient's own person as its data subject, and the answer
replies to the recipient's own person's proposal. Both are first-party to the recipient in exactly
the sense the subject Pull's first-party carve (CIRISEdge#462, v16 review) uses, and that carve
does not run the floor either. The normative text decides it: CC 3.1.3.2 makes delivery keyed on
`subject_key_ids` "without that node holding the group's roster", and "nobody joins without their
own consent" (CIRISConstitution#133) is unsatisfiable if the invitation cannot reach an invitee who
shares no root with the inviter, since a stranger is exactly who an invitation is for. Rooted
remains required for everything else, and a proposal or reply authored by N's own self-publish set
was already exempt (#668).

**Which path carries each row.** The advertise (`list_attestations`) and the direct-fetch twin
(`fetch_envelope_bytes_for_peer`) share the gate (`audience_withholds`), so they agree. The subject
Pull answers only a requester about itself (`requester == subject`) with rows about or by it: a
proposal names K's *person*, not K's node, and a reply names K and is authored by K's node, so
neither is ever listed to the other side's node by a subject Pull; there is no third twin to add
and no ref is disclosed that the fetch would refuse.

**Invariant I22** (§6).

### 2.5 A group's record reaches its members and live invitees, nobody else (CIRISEdge#758)

**persist v53 S1 (CIRISEdge#761).** The rule below is now persist's
`replication_audience::may_receive_group_plane(X, scope, group, named)`, called per row by the
advertise (`list_group_plane_for_peer`) and the fetch twin (`group_plane_fetch_serves`) over the same
`(scope, group, named)` read (`replication::group_plane`). It covers the record AND the five
membership planes (revocations, widenings, the listing): a private group's rows reach its members'
nodes, its live invitees' nodes (full plane history) and the nodes of the member a row names; a public
group's (`is_public_group`) reach every peer, an unbound requester included. A node is resolved to its
person through its identity occurrence (`active_identities_for_occurrence`), never the owner-binding
alone. The text below is the pre-v53 statement of the same rule.

**The rule.** A `Family` or `Community` **record** (the roster declaration itself, not a row at
its target) is served to a peer X only when X's person, `owner_of(X)` (X itself when unowned), is

- **(a) a live member** of that group: persist's `list_*_for_member_active` over X, X's principal
  and `owner_of(X)`, the audience gate's own membership read (#597); or
- **(b) a live invitee:** named in the `subject_key_ids` of a **live** `membership:proposal:v1` into
  that group **held in this node's store** (federation tier, unexpired, not declined by the invitee,
  not withdrawn or recanted by its proposer). The predicate is the one §2.4 serves the proposal row
  on (`proposal_invites_peer`, now persist's `live_invitees_of`): the record travels with the
  invitation, and never ahead of it.

Anyone else is withheld and booked `group_record_not_member_or_invitee`. It holds on every reach:
at first contact the invitee gets the record its proposal needs (CC rc6 3.1.3.2 lets it admit the
proposal without the roster, but following the group once it joins needs the record) and nothing
widens for a stranger. The advertise (`list_envelope_refs_for_peer` → `list_group_records_for_peer`)
and the direct-fetch twin (`fetch_envelope_bytes_for_peer` → `group_record_fetch_serves`) read the
same servable set, so they agree; an unbound peer gets nothing. The record planes answer no subject
Pull (`receive: none`), so there is no third twin.

**Why.** CC 5.4.6: the construction "hides the group's existence, membership, and
`querier → invitee` edges from outsiders". Under persist v52 (CIRISPersist#955) a group is founded
by its opener alone, so to get the record to an invitee #754 (communities) and #756 / #736
(families) made a founder's node list the groups its own person founded. The record planes were
peer-blind (`serve: public`), so that listing went to **every** peer before any proposal existed:
an outsider learned that the group exists and who founded it. The sweep may still consider those
groups; who *receives* one is now this gate. Before v52 a record crossed only because a member sat
in the operator's cohort, and then to any peer; members keep receiving it, outsiders no longer do.

**The public-group carve-out (CIRISEdge#762).** The gate applies to **private** groups only. A
**public** group's record keeps the pre-v38 `public` serve, to every peer, on the advertise and the
fetch twin, at every reach including first contact and an unbound requester. A group is public when
`replication::public_group::is_public_group` says so, with persist's markers read where persist's
own readers read them:

- a **Community** whose `policy_blob.cohort_subkind` is `infrastructure` (persist's
  `community_subkind(&c) == Some(admission::COHORT_SUBKIND_INFRASTRUCTURE)`). The subkind, not the
  id: `ciris-canonical` carries it, and so does every other infrastructure community;
- a **Family** named by configured id: the accord / charter family
  (`canonical_community::accord_family_key_id()` and `genesis::canonical_genesis_bundle()
  .family_key_id`; under `test-anchor` also the anchored accord family,
  `genesis::accord_family_genesis_record().family_key_id`), and the deployment's Wise-Authority
  reclaim body, `ReclaimPolicy::from_deployment_pin().wa_family_key_id` (published by
  `CIRIS_PERSIST_WA_ADJUDICATION_FAMILY_KEY_ID`, the source persist's reclaim admission reads).

*Why.* CC 5.4.6 hides a group's existence and membership "from outsiders **only**", and CC
4.4.3.2.1 makes `infrastructure` communities Commons-tier and publicly auditable. Every node
resolves its trust root through groups it is not a member of: persist's `trust_root_valid` takes the
family arm by `lookup_family(root_ref)` and the community arm by the stored standing of
`ciris-canonical` (`trust_root.rs`), and ownership reclaim reads the WA body's record and active
roster (`ownership_reclaim.rs` `wa_quorum_over_body`). Gating those records to members broke
trust-root resolution on every node outside them. persist's ruling on CIRISEdge#761: public groups'
records stay visible to every peer; only private groups are gated.

*The accord family is carried for completeness, not because the gate could break it.* persist
reserves `humanity-accord` at every admission door (`ConstitutionalFamilyReserved`,
CIRISPersist#648): it enters a directory only through the genesis seeder / assemble ceremony
(`put_family_local`), carries no signed record, and so is never listed on the Family plane nor
admitted from a peer, on v37.1.0 as now. Every node resolves the family arm from its own genesis
seed. Its marker stays in the predicate because it is persist's list and v53's predicate carries it.

The predicate is a stand-in for
persist v53's `federation::replication_audience::is_public_group`, which will replace it. The
**membership planes** (widenings, revocations, listings) are untouched here: persist v53's
`may_receive` decides them (#761).

**Invariant I23** (§6).

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
   0. **the membership ceremony (#756, §2.4)**: under `FirstContact`, a proposal naming B's owner
      or the invitee's reply to B's owner's proposal held at A skips 1–2 and the floor in 4, and is
      served by 3's membership arms;
   1. reach admits the row's audience — `FirstContact` admits only `federation`;
   2. **first-contact narrowing (#671)**: under `FirstContact` the row must be an allegiance fact
      of A, **or (#752, §2.3) a live `federation` owner-binding of a node in A's selector-chosen
      `Key`/`IdentityOccurrence` publish set**, else `recipient_not_in_send_set` (detail names the
      narrowing);
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
| I20 | **The owner-binding rung (§2.1.1, CIRISEdge#727).** (I-a) A binding whose attester is the receiver's own owner is admitted on any link after signature verification against the held owner key, through persist's replicated-attestation door. (I-b) A node pushes only its own binding, only on a link it dialed or in answer to a sibling's binding newly admitted on that link, never advertises it. (I-c) A stranger refuses it by name before any cryptography and stores nothing. (I-d) Admission invalidates the #682 memo; the unannounced pair converges in a bounded number of rounds. | `owned_devices_route_682::unannounced_devices_of_one_owner_exchange_routes_and_admit_682` (I-a, I-d: the round bound is asserted; fails on the pre-#727 code); `…::a_binding_signed_by_a_key_that_is_not_the_receivers_owner_is_refused_by_name_727` (I-a negative, both the attester field and the signature); `…::a_stranger_refuses_another_owners_binding_and_holds_nothing_727` (I-c); `…::a_node_pushes_its_binding_only_on_a_link_it_dialed_727` (I-b); `…::a_wiped_device_reconverges_by_dialling_its_sibling_727` (recovery); `protocol::tests::an_owner_binding_push_is_exactly_a_deliver_of_owner_binding_rows_727` (the shape) |
| I21 | **A relay serves a first-contact peer the announced owner-binding of a node it publishes, and no other row about others** (§2.3, CIRISEdge#752, CC 5.4.6). The binding must be an owner-binding, at `federation`, live (attester = `owner_of(subject)`, the row in the #682 live announcing set), and its subject in the relay's `KindPublishSelector` `Key`/`IdentityOccurrence` set. Without a selector R2 is #671's. Consent grants, `self` bindings and bindings of unpublished nodes stay withheld; the Rooted floor still runs. | `relay_roster_752::a_stranger_lists_a_relays_published_device_under_its_owner_752` (three identities over real links: the stranger admits the device's key, occurrence and binding from the relay and `nodes_owned_by(owner)` names the device; fails on the pre-#752 code); `…::without_a_selector_nothing_about_others_reaches_the_stranger_752`; `bridge::a_relay_serves_a_published_nodes_announced_binding_at_first_contact_752` (advertise + fetch twin, the three negatives, selector unset) |
| I22 | **The membership ceremony reaches its stranger (§2.4, CIRISEdge#756; CIRISPersist#955, CC rc6 3.1.3.2, CIRISConstitution#133).** Under `Reach::FirstContact` a node additionally serves (a) a `membership:proposal:v1` whose `subject_key_ids` contains `owner_of(peer)` and (b) an acceptance/decline, attested to the invitee of a proposal held here, whose proposal's proposer is `owner_of(peer)`; on the advertise and the fetch twin alike, without the Rooted floor (first-party to the recipient). Nothing else widens: no other row at the group's target, no proposal to anyone else, no reply to a proposal not held here or to someone else's proposal. | `membership_first_contact_756::a_stranger_is_invited_accepts_and_joins_over_first_contact_756` (community) and `…_a_family_over_first_contact_756` (three nodes over Reticulum, no consent, no common root; fails on the pre-#756 gate: the invitee's node never holds the proposal); `bridge::first_contact_serves_the_membership_ceremony_to_its_parties_and_nothing_else_756` (advertise + fetch twin, relayed un-Rooted proposal, the four negatives) |
| I23 | **A group's record reaches its members and live invitees, nobody else (§2.5, CIRISEdge#758; CC 5.4.6).** A `Family` / `Community` record is served to a peer only when `owner_of(peer)` is a live member of the group or the `subject_key_ids` invitee of a live proposal into it held here; otherwise withheld as `group_record_not_member_or_invitee`, on the advertise and the fetch twin alike, at every reach. **Public groups are exempt (CIRISEdge#762; CC 5.4.6 "from outsiders only", CC 4.4.3.2.1, persist's #761 ruling):** an `infrastructure` community and the accord / genesis / WA reclaim families keep the `public` serve to every peer, so every node still resolves its trust root and reclaim authority through them. | `group_record_reach_758::a_group_record_reaches_only_members_and_live_invitees_758` (four nodes over Reticulum: a stranger never holds G's or F's record, an invitee only once proposed, a member as a member, and the pair room's invitee gets its record; fails on the pre-#758 code: every peer holds both records before any proposal); `bridge::a_group_record_is_served_only_to_members_and_live_invitees_758` (advertise + fetch twin: stranger, invitee, declined invitee, member, unbound peer); `public_group_reach_762::a_public_group_resolves_on_a_non_member_762` (a non-member node receives an infrastructure community and the configured WA family, and persist's `stored_standing` and reclaim reads answer on it as on the holder, while a private community and family stay withheld; fails on the pre-#762 gate); `bridge::a_public_group_record_is_served_to_every_peer_762` (advertise + fetch twin, attributed stranger and unbound requester; the genesis-seated accord family is never listed) |

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

- **CIRISEdge#762** (edge v38.0.0) — §2.5 / I23: the group-record gate exempts PUBLIC groups
  (`public_group::is_public_group`: an `infrastructure` community by subkind; the accord family,
  the genesis bundle's family, the anchored accord family under `test-anchor`, and the deployment's
  WA reclaim family by configured id). Their records keep the pre-v38 `public` serve, so a node
  outside them still resolves its trust root and reclaim authority (CC 5.4.6 "from outsiders only",
  CC 4.4.3.2.1, persist's #761 ruling). Stand-in for persist v53's
  `replication_audience::is_public_group`. The Family and Community `serve` cells state the
  carve-out; `SERVE_ADVERTISE_POLICY_HASH` re-pinned a09e34a6… → e3070d53…. Membership planes unchanged (v53
  `may_receive`).
- **CIRISEdge#758** (edge v38.0.0) — §2.5: a group's record (Family, Community) reaches only the
  group's live members and the invitees of a live proposal held here (the §2.4 predicate, reused);
  everyone else is withheld as `group_record_not_member_or_invitee` (CC 5.4.6). Closes the
  founder-advertise leak #754 / #756 / #736 opened: the founder's node offered the record of every
  group its person founded to every peer, before any proposal. The record planes' `serve` cell
  moves from `public` to the gate; `SERVE_ADVERTISE_POLICY_HASH` re-pinned. I23.
- **CIRISEdge#756** (persist v52 adopt, edge v38.0.0) — §2.4 the membership ceremony at first
  contact: a stranger's node is served the proposal naming its person, and the invitee's node
  serves the reply back to the proposer's person's nodes; the Rooted floor does not apply to these
  two first-party classes (CC rc6 3.1.3.2 delivers on `subject_key_ids`; CIRISConstitution#133).
  The R2 row, the closure note and §5 name the exception; I22. `SERVE_ADVERTISE_POLICY_HASH`
  re-pinned (the Attestation `serve` cell states what first contact carries).
  The Family plane now also advertises this node's own-founded families (the family twin of
  #754's Community arm): a family is founded by its opener alone, so without it the joined
  invitee's node never held the record and could not follow the family (witnessed: the family
  case fails without it). (That listing went to every peer; #758, §2.5, gates it per peer.)
- **CIRISEdge#752** — §2.3 the public roster at first contact: with a `KindPublishSelector`
  installed, `Reach::FirstContact` also carries the live `federation` owner-binding of each node in
  the relay's `Key`/`IdentityOccurrence` publish set (CC 5.4.6; CIRISServer#701). Advertise and
  fetch twin agree; the subject Pull is unaffected; the Rooted floor still applies. Ledger tokens
  unchanged. The Attestation `serve` cell of the serve/advertise manifest now names the
  first-contact carriage, so `SERVE_ADVERTISE_POLICY_HASH` is re-pinned (a server re-pin). I21.
- **CIRISEdge#727** — §2.1.1 the owner-binding rung, the belt under I14: an owner-binding whose
  attester is the receiver's own owner is self-authenticating to that receiver and is admitted on
  any link (signature verified against the held owner key, then persist's replicated-attestation
  door; the #682 memo invalidates on admit); a node pushes its own binding, once, on a link it
  dialed, after the announce and bundle; a stranger refuses it by name before any cryptography.
  Ledger: `owner_binding_*` under `first_contact_outcomes`. The serve policy is untouched
  (`SERVE_ADVERTISE_POLICY_HASH` / `REPLICATION_POLICY_HASH` unchanged). I20; the unannounced pair
  of `owned_devices_route_682` un-ignored and bounded in rounds.
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
