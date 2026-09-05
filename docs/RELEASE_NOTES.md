# CIRISEdge Release Notes

# v20.3.0 — adopt persist v41.2.0 + leviculum v0.25.0; the dial outlives its round (#568); the pyo3 envelope helper signs hybrid (#573); the rotation seal names its hazard (leviculum#52)

**2026-09-05** — Additive at every public surface. Two substrate adopts, one
transport fix, one FFI fix.

## Adopts

**CIRISPersist v41.0.0 → v41.2.0.** Two minors, both currency for edge. All
four ABI constants unchanged across both, verify stays v14.2.0, so the
`ciris-persist>=41,<42` wheel floor holds. v41.1.0 (#807) fixes
`list_widening_candidates` offering an announced node's owner-binding as a
widening candidate forever. v41.2.0 (#810) adds `rejected` to the mirrored
CIRISLens `TaskStatus` vocabulary with a SQLite V136 rebuild. **Edge drives
none of the affected APIs** — no `TaskStatus`, no lens tables, none of the
lens features enabled.

**leviculum v0.24.0+ciris.1 → v0.25.0+ciris.1.** Three things matter here:

- **leviculum#64 unbreaks our own wheels.** The upstream catch-up (+92) brought
  a BLE interface declaring `bluer`/`dbus` unconditionally; both pull
  `libdbus-sys`, which builds on neither macOS nor Windows. leviculum's own
  changelog names the consumer: *"CIRISEdge's darwin and win_amd64 wheels
  resolve this crate as a git dependency and would have failed at build
  time."* The deps are now target-gated.
- **leviculum#63 gives us the instrument for #568** (below).
- **leviculum#52** is addressed below.

## CIRISEdge#568 — a round no longer destroys the link it paid for

The first fix for #568 (v20.2.0) addressed the missing-signer race. Re-measured
on the two-node ladder, the number did not move: **181 s and 210 s**. The
owner's key was on the peer at 31 s, so the key was never the bottleneck. This
is a second, independent mechanism.

**What it is.** The scheduler abandons a round at `DEFAULT_ROUND_TIMEOUT`
(10 s). A peer with a known path is allowed `LINK_ESTABLISH_TIMEOUT` (30 s) to
establish. The dial ran **inline inside the round's future**, so a cold dial
could never finish inside the round that started it — that is arithmetic, not
load — and abandoning the round **dropped the half-established link**. Every
retry began cold; the peer converged only when it dialled us. The observed
shape matches exactly: first Attestation round to a fresh peer times out at
+10 s, next completed round lands ~150 s later — five 30 s cadence ticks.

This is the #532 establish:identify gap one layer up. #532 stopped N
coordinators discarding *each other's* links; nothing stopped a round
discarding *its own*.

**The fix.** The dial runs in a spawned task holding a cloneable `DialCtx`, so
abandoning a round abandons the **wait**, not the **link**. The task runs to
completion and publishes into `reusable_dialed_link` — `dial_and_identify`'s
existing "PUBLISH LAST" step — so the next round takes the fast reuse path
instead of dialling cold again.

`DialCtx` is a context struct rather than a `Weak<Self>` because
`ReticulumTransport::new` returns `Self`: a self-handle would need installing
at every construction site, and a site that forgot would silently lose the
detach. The dial-gate permit is acquired **inside** the task, since a permit
held by the caller would be released on cancellation while the dial it gates
still ran — leaving #532's single-flight property true only for callers that
survive.

**Measurement, not inference.** `ladder.owner_binding_converged` now records
leviculum#63's `retry_queued` / `retry_queue_cap` / `retry_dropped_total`
beside `elapsed_ms`. A slow convergence with a flat retry queue and one with
`dropped_total` climbing are different bugs that read identically as a
stopwatch value — leviculum reported that exact pattern from the live canonical
(*"the retry queue climbed past its warning threshold and began discarding
traffic while the log read as quiet"*). The next run distinguishes them.

**What is not claimed:** that the 181/210 s numbers are now fixed. The unit
tests pin the mechanism; only a mesh run measures the outcome. One run each was
not a regression call in either direction, and it is not a fix call either.

## leviculum#52 — the rotation seal docstring named the wrong hazard

Audited against leviculum's finding that `seal` retires the old IFAC key for
inbound, so sealing with no dwell after `activate` strands in-flight traffic
(~50% packet loss on a zero-dwell rotation upstream, `drops_ifac` incrementing
exactly once each time).

**Edge is exposed as the API surface, not as a driver.** It wraps and
re-exports the three phases (`ifac_install_next` / `ifac_activate_next` /
`ifac_seal_rotation`), and **nothing in edge sequences them** — no
`activate → seal` pair in `src/`, `tests/` or `src/bin/`. Edge cannot commit
the defect itself; it hands it to the operator. Two things it told that
operator were wrong.

**The docstring named the wrong hazard.** Both seal wrappers said "call after
the convergence window". That window is about *membership* — every member
holding the new key. Sealing also retires the old key for *inbound*, so it
rejects packets already on the wire under the old mask, sent by the members
that **did** re-key. An operator who followed the instruction correctly still
stranded traffic. Worse than no guidance, because it read as complete. Both
docstrings now name the drain hazard as distinct from membership, state that
install/activate are make-before-break and only seal breaks, and quote the
upstream evidence.

**The one observable never reached Python.** Four things carry the retired
mask — this node's retry queue, its socket buffer, bytes in flight, and the
peer's receive buffer — and edge observes exactly one, `retry_queued`. That
gauge had a single caller, the mesh harness; the operator holding the one call
that can strand traffic could not see the one thing edge can. `retry_queue_gauges`
is now on `PyEdge`, documented as **necessary, not sufficient**.

**A default, derived rather than chosen.** `DEFAULT_IFAC_ROTATION_DWELL` =
`RESOURCE_TRANSFER_TIMEOUT` (120 s), exported as
`default_ifac_rotation_dwell_ms()`. Edge already asserts a resource transfer
can legitimately be in flight for two minutes, and since leviculum#62 a single
delivery spans many segments over that window under the key being retired. 10 s
was proposed; 10 s is shorter than all four of edge's own in-flight windows. It
is the *safe* default: ejecting a compromised member is a reason to go lower on
purpose and accept the drops.

**No `seal_after_drain` helper, deliberately.** It would have to invent a
policy for the queue never draining, and both answers belong to the operator:
block forever and the member being excluded stays admitted indefinitely; time
out and seal anyway and the hazard returns, buried in a function whose name
promises it cannot happen.

**No test, stated plainly.** Nothing in edge sequences the IFAC trio, so there
is zero coverage and nothing to regress from. `scope.rotation` and
`conformance.rotation_frame_loss` drive the MLS epoch advance and the
scope-address table, not IFAC. Per upstream the natural test is a ~50% flake; a
test worth having is a soak.

Upstream Reticulum's IFAC is static config with no rotation ceremony, so there
is no prior art and no ecosystem number to borrow — leviculum's 500 ms is a
loopback floor it disclaims as a deployment value.

## CIRISEdge#573 — the pyo3 envelope helper signs hybrid

`Edge.build_signed_inbound_envelope` hard-coded `None` for the PQC half, so
since **v19.0.0** — when every signature became the full hybrid — it could not
build a single envelope on the wheel that ships it. Its doc justified the
omission with two claims that were both false on this wheel.

Nothing here caught it because the Rust twin the doc names as its counterpart
(`tests/trust_short_circuit.rs::FedKey::local_signer`) *had* been moved to
hybrid. The two codepaths the doc calls identical had silently diverged, and
the only caller of the broken one is Python.

`pqc_seed_bytes` (optional, 32 bytes) now builds the PQC half. The seed is
**taken, not derived** from `seed_bytes`: a derivation convention has to be
known identically by whoever REGISTERS the ML-DSA pubkey and whoever SIGNS with
it, and when they disagree the only symptom is a verify refusal at the far end
with nothing pointing at the cause. `Edge.derive_ml_dsa_65_pubkey_base64` gives
the matching `federation_keys` pubkey from the same code that signs.

The argument stays optional so the classical-only refusal remains reachable and
loud. Surfaced by CIRISConformance#91; unblocks `test_230_intake_gate` and
`test_520_wire_vocabulary::test_tier1_and_opaque_variants_accepted`, whose
xfails are keyed on the exact refusal token rather than blanket markers.

---

# v20.2.1 — republish v20.2.0's artifacts past a stale registry guard

**2026-09-04** — No code change. v20.2.0 is byte-identical in behaviour; this
tag exists because **v20.2.0 shipped with no artifacts and no GitHub Release**.

## What happened

The v20.2.0 tag run's `Generate + sign build manifest` job failed its pre-flight:

```
##[error]No deployed stewards in registry response (AV-28 ephemeral-mode guard)
```

That skipped the tag-gated artifact upload, so no release was created at all.
Every other edge-side job on that tag was green — all five feature combos, the
network gauntlet, test-anchor, clippy + fmt, every mobile lane, all four wheels,
the XCFramework, bench, cargo-deny, pin-skew and the uniffi drift gate.

**The registry was healthy.** `/v1/steward-key` has moved to the CEG 0.2 accord
bundle and no longer returns `stewards` in any form:

```json
{"bundle": {"holders": [3], "authorizations": [2], "serve_nodes": [1],
            "consensus_protocol": "quorum:2/3", "family_key_id": "humanity-accord"},
 "bundle_fingerprint": "sha256:12d7fc…", "charter_root_key_id": "humanity-accord",
 "served_by": {"node_key_id": "75c29fcc…", "accepts_this_root": false}}
```

There is no `deployed` flag anywhere, so the guard's `data.get("stewards", [])`
produced `[]` and hard-refused a registry carrying a full 2-of-3 quorum. This is
the second time this response has moved out from under that guard; the first
move (v0.8.1 singleton → per-install list) is recorded in the step's own comment.
Both times the failure mode was a silent mis-parse presenting as a security
refusal.

The tag could not be rebuilt in place: a tag run uses the workflow file at the
tag's ref, so re-running v20.2.0 re-runs the same stale guard — and a published
tag is not moved. This tag carries the same code with a guard that reads the
current shape.

## The guard, rewritten (PR #571)

AV-28's intent is unchanged: refuse to sign a release manifest against a registry
with no real root. Under the bundle shape that means holders present **and the
bundle's own declared quorum actually met** — parsed from `consensus_protocol`
and checked, never assumed, because a bundle carrying one signature under
`quorum:2/3` is exactly the ephemeral state the guard exists to catch. An
unparseable protocol refuses rather than guessing a threshold. The v0.8.x shape
still works so a registry rollback cannot red the lane, and an unrecognised
*third* shape fails closed naming the keys it saw.

Verified against the live registry response plus seven fault injections: quorum
not met, no holders, no charter root, unparseable protocol, both old-shape arms,
and an unknown shape. Live passes and emits `A1,B1,C1`; every degraded case
refuses.

`served_by.accepts_this_root` is surfaced as a warning and deliberately does not
gate — `false` is normal for an unauthenticated read.

## Unrelated, still red

The six `cohabitation / conformance` cells fail on PyPI retention:
`ciris-server==0.5.176` has aged off the index. That is a CIRISConformance
matrix pin and reds every sibling repo's tag run, not just edge's.

Downstream is unaffected; Rust consumers pinning v20.2.0 lose nothing by staying
there.

---

# v20.2.0 — persist v41 write-origin doors, the #568 announce race, the fedcode v3 edge half

**2026-09-04** — Adopts CIRISPersist v41.0.0 and CIRISVerify v14.2.0. A MINOR:
v20.1.1 was never adopted downstream (CIRISServer was on v18.14.0), so no
consumer held the meaning anything here changes.

## persist v41 — origin-aware write budgets (CIRISEdge#569, CIRISPersist#804)

`put_attestation_with_origin` is the one required trait method, and edge
implements `FederationDirectory` nowhere, so no call site broke. All four ABI
constants are unchanged (`DIRECTORY_ABI_VERSION` stays 5) and
`ENVELOPE_VOCABULARY_SHA256` did not move — **the pyproject wheel floor still
moves to `>=41,<42`**, because a major always moves it: that line means "the
wheel co-resident in this process is the crate edge linked", independent of ABI.

Origin is a property of the **call**, not of the row: the AV-76 quota runs at
tier 0, ahead of any signature check, so `attesting_key_id` is only a claim
there. Metering the node's own emissions as a stranger's is what #804 measured
at 652 of 900 chat sends refused.

| site | door |
|---|---|
| `bridge::apply_attestation` | `put_attestation_synced` when attributed, unchanged otherwise |
| `realtime_av_alm/delivered.rs` | `put_attestation_authored` |
| `edge_node.rs` ×4 (owner binding, consent grant, both chat puts) | `put_attestation_authored` |

`source_peer` was reaching the #425 choke as a **trace field** and being dropped
before the door; it is now threaded through `dispatch_apply`. Edge vouches for
exactly what persist asks for and no more — *which identity its transport
authenticated* — and persist bounds the privilege itself via `shares_cohort_with`
against its own rosters, so routing a stranger through the privileged door cannot
widen their budget.

The chat/share path needed no change: persist's `assemble_and_put` and
`widen_audience` already take the authored door.

Doors are tested by the budget they **select**
(`peer_quota_observation().tracked_peers`), never by a refusal count — a refusal
count measures the burst window's refill.

## CIRISEdge#568 — the announce race

A node's announce bundle rides two planes with no ordering between them, so an
owner→node binding was routinely delivered a round before the owner key that
verifies it: **33 s one direction, 90 s (three rounds) the other**, the largest
single item in a 3 min 33 s claim-to-message timeline.

The recovery machinery already existed and was off by one line —
`should_note_missing_signer` gated on the Key plane's retention, and
`ServeTier::None`, what every ordinary claimed node runs at, is `Bodies`. It was
dead in precisely the common case and live only for conferred mesh servers.

Retention was never the predicate. `HashFirst` means "never arrives"; `Bodies`
means "arrives, at a latency nobody bounded". Both are the same fact about the
row — *it named a key this node does not hold* — so the predicate is now that
fact and the function is deleted rather than left returning a constant.

`ladder.owner_binding_converged` puts the number on the mesh artifact per
direction; the race was produced on every run and observed by nothing, because
every ladder leg read the peer's owner from the roster.

## fedcode v3 — the edge half (CIRISVerify#272)

`CodeAdmission` now carries `ml_dsa_65_pubkey_sha256` and is `#[non_exhaustive]`.
Without it the code's commitment died at edge's boundary and
`ContactResolution::ReadyFromCode` could not produce a conformant hybrid
registration. Review notes filed as CIRISVerify#274.

---

# v20.1.1 — republish v20.1.0's artifacts on a locked dependency graph

**2026-09-03** — No code change. v20.1.0 is byte-identical in behaviour; this
tag exists because **v20.1.0 shipped with no artifacts**.

## What happened

`tinyvec 1.13.0` published broken —

```
error: could not compile `tinyvec` (lib) due to 1 previous error
note: `vec` is imported here, but it is a module, not a macro
```

— and `Cargo.lock` was gitignored, so CI re-resolved ~700 crates on every run
and picked it up unreviewed. Every compiling job on `main` and on the v20.1.0
tag went red on a tree that had been green minutes earlier, including the
tag-gated artifact upload. So the v20.1.0 release carries no wheels, no
XCFramework, no Android/iOS bundles and no signed build manifests.

The tag could not simply be rebuilt: `v20.1.0` points at a tree that predates
the lockfile, so it would re-resolve and break again — and a published tag is
not moved.

## The fix

`Cargo.lock` is now committed, which **is** the pin (`tinyvec 1.12.0`) without
adding a phantom direct dependency on a crate no edge code imports. An
explicit upper bound would have been whack-a-mole across the whole transitive
graph, and unsatisfiable the day another dependency needs the newer version.

Edge ships binaries and a hybrid-signed build manifest, so a build whose
dependency graph nobody pinned was attesting to something that could not be
reproduced. Dependency updates are now a reviewable commit
(`cargo update -p <crate>` in its own PR), handled case by case.

**Downstream is unaffected**: cargo ignores a dependency's lockfile, so
CIRISServer and CIRISAgent resolve their own graphs exactly as before. Rust
consumers pinning the v20.1.0 tag lose nothing by staying there; adopt v20.1.1
only if you want the published artifacts.

Everything in v20.1.0 stands — chat attribution is the attester
(CIRISEdge#564), on persist v40.0.0.

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
