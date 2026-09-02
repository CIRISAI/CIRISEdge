# Chat Harness Integration — edge's contact-ladder DX

**Audience:** CIRISServer, building the chat harness on edge (CIRISServer#524).
**Compile-pinned by:** `tests/chat_harness_dx.rs` — every symbol named here is
referenced by that test, so an edge API change that would invalidate this
document reds the build instead of silently rotting the guide.

Edge `main` (`d321256`, CIRISEdge#556) ships the contact-ladder DX the chat harness needs. This is the precise integration: what to call, in what order, what each failure means, and the three places the API will let you do something that silently does not work.

Everything below is `ciris_edge::contact` and `ciris_edge::invite_gate`, both `pub mod` in `lib.rs`. Server composes edge in Rust, so these are direct calls — no FFI.

**Feature required:** `transport-reticulum`, for the production `RouteLens`
(`ReticulumRoutes`). Everything else in this guide is available on a default
build.

---

## 0. Wiring you MUST do, or the whole path is inert

One field. A default-constructed config leaves it `None`, and the failure is
silent — nothing breaks, three subsystems just never run:

```rust
let mut config = ciris_edge::replication::ReplicationRuntimeConfig::default();

// The serve-tier resolver, the own-record Pull responder, and missing-signer
// recovery are ALL keyed on this. Left None, each is silently inert.
config.local_key_id = Some(my_signer_key_id.to_string());
```

**Do NOT set a bridge "mode" — the field no longer exists, deliberately.**
`AgentMode` (client/proxy/server) is the local-resources posture: listener
binding and outbound queue size, on the Edge itself. Whether a node holds the
directory and answers identifier lookups keys on a different axis entirely:
its own **`infra:serve` conferral** (`docs/ROLE_MATRIX.md`, Axis 3) —
conferred by the owner (a mesh server: stores and serves to help the mesh),
blessed by the trust root (a canonical: additionally trusted for bootstrap).
The runtime resolves the tier from the directory automatically once
`local_key_id` is set; there is nothing to configure and no knob to get wrong.

Until CIRISPersist#788 ships the owner-conferred resolver, only the canonical
rung resolves; a node whose row claims `infra:serve` without a verifiable
blessing logs a WARN naming that issue and serves conservatively.

---

## 1. The ladder, and who owns each rung

`Rung` is a shared diagnostic vocabulary, not a claim about who executes what:

| rung | `as_str()` | owner |
|---|---|---|
| `Announce` | `announce` | **edge** — publishes identity + transport key |
| `Discover` | `discover` | **edge** — `contact::discover` |
| `RequestContact` | `request_contact` | **server** — `POST /v1/contacts` |
| `Consent` | `consent` | **server** — grants replication consent |
| `OpenChat` | `open_chat` | **server** — the 2-member community |
| `SendMessage` | `send_message` | **server** — `/v1/chat/{id}/messages` |

`Rung::previous()` gives the rung before, because a failure is nearly always the previous rung not having completed. Use it to point an operator at the right place instead of the symptom.

---

## 2. Contact by fedID, nodeID, or agentID — one call

**Do not branch on identifier shape.** `key_id` is `"<label>-<fingerprint>"` with an operator-chosen label, so the string cannot tell you what it is; `identity_type` in the directory is the only authority.

```rust
use ciris_edge::contact::{self, PersistLens, ReticulumRoutes};

let lens = PersistLens::new(federation_directory)
    .with_replication(replication_directory); // see §5

// ReticulumRoutes is behind the `transport-reticulum` feature. Without it you
// get "no `ReticulumRoutes` in `contact`", which reads like a missing symbol
// rather than a missing feature — enable it in your Cargo.toml.
let routes = ReticulumRoutes::new(&reticulum_transport);

match contact::discover(&lens, &routes, whatever_the_user_typed).await {
    Ok(found) => {
        // found.subject.fed_id     — the PERSON. Who consents.
        // found.subject.nodes      — every node they own.
        // found.reachable          — the subset you can actually dial. Never empty.
        // found.subject.resolved_from — Person | Node | Agent | Other(String)
    }
    Err(stall) => { /* §3 */ }
}
```

Three rules the resolution encodes, so the harness does not have to:

* **An agent resolves to its OWNER.** An agent cannot consent, so "add frank-laptop" means "add Frank". `resolved_from` tells you it arrived via a node/agent, which matters for the log line.
* **A steward or accord holder is `NotContactable` and TERMINAL** — not "wait for convergence". Retrying is retrying forever.
* **`discover` proves REACHABILITY, `resolve` proves ownership.** A person can own nodes you have no route to. Use `discover` before any send; `resolve` alone hands you a `Subject` whose every send fails.

Once a destination is known, distance stops mattering: the peer's published RNS transport key gives Reticulum multi-hop routing for free. Edge does no relaying to make that work, and you do not need to ask for it.

---

## 3. Stalls: what to retry, what to surface, what to stop

`LadderStall` is deliberately not a wrapper over underlying errors. Branch on the variant; never parse prose.

```rust
if stall.self_resolving() {
    // Converges on its own. Log at INFO, retry later, do NOT alarm a user.
} else {
    // A person or an operator must act. Surface it, with:
    show(stall.remedy());
}
```

| variant | `self_resolving()` | what the harness should do |
|---|---|---|
| `NotYetDiscovered { fed_id }` | ✅ | wait for replication; retry |
| `Unreachable { fed_id }` | ✅ | peer offline; RNS routes when it returns |
| `BodyFetchQueued { key_id }` | ✅ | a fetch is queued; retry after the next Key round |
| `AwaitingConsent { fed_id }` | ❌ | waiting on a **human**. Retrying does not help and re-sending is spam |
| `ConsentNotGranted { fed_id }` | ❌ | *this* node has not granted; accept the request |
| `NotContactable { key_id, identity_type }` | ❌ | a steward/accord holder is not a person. Contact its owner |
| `DirectoryUnreadable { key_id }` | ❌ | **LOCAL** backend fault. Send them to the node, not the mesh |
| `PriorRungIncomplete { rung, prior }` | ❌ | look at `prior` on this node first |

`remedy()` returns operator-facing prose for every variant — a stall with no remedy is a bug report, not a diagnostic. Use it verbatim rather than writing your own; they are worded to stop specific wrong actions (e.g. `AwaitingConsent` explicitly says re-sending is spam).

---

## 4. The invite gate — receiver-side, before a human sees anything

```rust
use ciris_edge::invite_gate::{InviteGate, InviteVerdict, RefuseReason, Ts};

// ONE instance per receiving node, long-lived. Not per request.
let mut gate = InviteGate::new();

match gate.admit(sender_fed_id, now_unix_seconds as Ts) {
    InviteVerdict::Allow => present_to_user(invite),
    InviteVerdict::Refuse { reason } => {
        // Drop it. Log `reason` for the RECEIVER's operator.
        // Never tell the sender why, and never tell them when they may retry —
        // that is telling a spammer the optimal send rate.
    }
}

// When the person accepts, permanently lift the stranger budget:
gate.mark_accepted(sender_fed_id);
```

Placement is the whole design:

* **Receiver-side.** A sender-side limit is advice.
* **Before presentation, not at admission.** Do NOT gate replication admission on this. An invite arriving as a signed `Community` record is legitimate federation state; refusing to admit it would withhold carriage of correctly-signed data on a rate heuristic. What is being limited is *presentation to a person*, which is why the gate lives in your tier and not in edge's replication path.
* `STRANGER_BUDGET = 1`, `CONTACT_BUDGET = 8`, `REFILL_SECS = 86_400`. An accepted contact is never throttled like a stranger — throttling replies is how an anti-spam control breaks the conversations it protects.
* `mark_accepted` is what makes that promotion permanent. **If you forget to call it, every established contact stays on the 1-invite stranger budget.**
* `RefuseReason::ReceiverAtCapacity` means the node is tracking its cap of strangers (65,536) and none could be released. Treat as backpressure, not as a verdict about that sender.

The clock is yours — the gate never reads one, so it is testable and drives off whatever time source you already trust.

---

## 5. Logging: one shape for every rung

```rust
contact::log_rung(Rung::Discover, &fed_id, Some(&stall)); // or None on success
```

Emits one structured line per rung with a stable `step=` field, so an operator greps and a dashboard groups without parsing prose. Success is INFO (walking the ladder is rare and meaningful, not a hot path). **Use this for your rungs too** — the value of a shared vocabulary is that `step=consent` and `step=discover` appear in the same stream with the same shape.

`contact::discover` already logs its own resolution stalls before returning, so do not double-log what it hands you.

---

## 6. Stranger contact — a code OR a fedID

Both work now. They fail in different places, so know which you have.

### A pasted code (works even if they never announced)

```rust
use ciris_edge::contact::{self, ContactResolution};

match contact::resolve_contact(&lens, whatever_the_user_pasted).await? {
    ContactResolution::Known(subject) => { /* already admitted — go to consent */ }
    ContactResolution::ReadyFromCode { subject, admission } => {
        // `admission` is verified, typed key material. Feed it to YOUR
        // register_federation_key gate — edge never registers a key off a
        // pasted string.
        register_federation_key(&admission.key_id, &admission.pubkey_ed25519_base64, admission.identity_type)?;

        // `subject.fed_id` is the PERSON — who consents, and who the
        // conversation is with. Use it for the consent rung.
        //
        // `subject.nodes` is EMPTY, and that is correct: a user code names a
        // person, not their nodes, and a stranger has no owner bindings on your
        // node yet. Reach them through the hint that travelled with the key:
        match admission.transport_hint.as_deref() {
            Some(hint) => start_contact_request(&subject, hint)?,
            // Identity you can verify, no way to contact them yet. Ask for a
            // code that carries a hint, or wait for them to announce.
            None => surface_no_transport(&subject),
        }
    }
}
```

**`subject.nodes` depends on the code's version.** A **v3** code (`CIRIS-V3-…`) names the subject's own nodes — `subject.nodes` holds real node ids, and `admission.owned_nodes` carries each one's **transport** pubkey, which is what a destination derives from (the node's federation key is a different key for a different job). A **v1/v2** code names only a person, so `subject.nodes` is empty and the fallback is `admission.transport_hint`. An earlier revision put the person's own `key_id` in `nodes`, which made callers dial a person key as though it were a node.

**The subject is built from the code, not the directory, and that is load-bearing.** An earlier shape returned "admit, then retry" — but the retry runs `nodes_owned_by` against the directory, and a stranger has no owner-binding attestations there. Admitting a key never creates an ownership graph, so that retry returned `NotYetDiscovered` forever. If you find yourself re-resolving after admission and waiting for convergence, you are on the old model.

`parse_contact_input` classifies by the unambiguous `CIRIS-V…` prefix, so a code is a code **or an error** — never silently posted as a `key_id`. A `CIRIS-V…` string that will not decode is `MalformedCode`, and one whose carried key does not derive its claimed address is `CodeIdentityMismatch` — refuse it and do not admit: a code's CRC proves it survived transit, never who wrote it.

**Which code kinds reach `ReadyFromCode`:** `user` only. A family/community code is `NotContactable` before you are told to admit anything — a roster is not a party you converse with. So is a **stranger's node or agent code**, and that one is subtler: `Subject.fed_id` is *the party who consents*, and a node cannot consent — its owner does. For a node you already know, `resolve` routes through `owner_of` and hands you the owner, so `Known` is correct. For a stranger there is no owner binding on your node yet, so there is nothing to route to and the honest answer is terminal: **ask for the owner's code.** The remedy says exactly that. If you key the consent rung on `subject.fed_id` — which §6's code block does — this is what stops you aiming it at a machine.

### A bare fedID (needs them to have announced)

Resolves through the directory as always. On a hash-first node that holds only the hash, `request_key_body` now queues a fetch and the lookup reports `BodyFetchQueued` — retry after the next Key round. That works because a **conferred** server answers an identifier Pull for any subject on a public plane (ROLE_MATRIX axis 3): ask a server, fetch bodies by content hash, canonicals hold the contents.

If they opted out of announcing, no directory anywhere has them — only a code will do.

## 6b-bis. Standing up replication — five footguns, all now disarmed

Edge's own bench-mesh harness got every one of these wrong and burned a long
arc of mesh runs on them, with no error anywhere. Each is now a
one-liner in the API. Do not hand-roll them.

**1. Route inbound frames — through `InboundRouter`, not by hand.**

`Transport::listen` runs in YOUR dispatch loop, so wiring replication into it
is your job. The obvious version is wrong:

```rust
// DON'T — this deadlocks the bootstrap.
if let Some(peer) = frame.source_key_id.as_ref() {
    registry.route_inbound_bytes(peer.as_str(), &frame.envelope_bytes).await?;
}
```

A peer first heard by announce is admitted **advisory** (`owns_key = false`),
and is promoted only by anti-entropying its bootstrap planes *over that same
link*. Demanding attribution before routing means the exchange that earns
attribution is the exchange attribution is required for. Nothing ever converges,
and a dropped frame looks exactly like a frame that never arrived.

```rust
let router = InboundRouter::new(runtime.registry());
while let Some(frame) = rx.recv().await {
    if router.try_route(&frame).await.consumed() { continue; }
    // ... your own framing
}
```

`try_route` returns a typed `RouteDisposition` (`Routed` / `NotReplication` /
`Unattributed` / `Failed`) — count them. A steady stream of `Unattributed` is
the field diagnosis for footgun 2.

**2. Replicate every `BOOTSTRAP_PLANE`.**

```rust
for kind in EnvelopeKind::BOOTSTRAP_PLANES.into_iter().chain([EnvelopeKind::Attestation]) { … }
```

`Key`, `IdentityOccurrence` **and** `TransportDestination` — the third is what
satisfies #393 item 2 (`hybrid_transport_binding_exists`). Omit any one and the
link never promotes, so no other plane ever flows. Silently.

**3. Do NOT register `EnvelopeKind::ALL`.**

A coordinator exists per `(peer, kind)`. Fifteen kinds across four peers is
**sixty** of them dialing one transport; it saturates the link pool and starves
your own traffic (leviculum#29, CIRISEdge#508/#531). We measured it as
`resource transfer failed: Timeout` on ordinary application sends. Register the
bootstrap planes plus what you actually read.

**4. Pass a self-publish set — `self_provider: None` is almost always wrong.**

```rust
Some(self_publish_set([&node_key_id, &agent_key_id, &owner_key_id]))
```

It gates the `SelfOwn` planes: your `Key`, your `IdentityOccurrence`, and your
`TransportDestination`. That last one is your node's **transport hint** — the
`(peer, dest)` binding a peer needs to satisfy #393 item 2 — so a node that does
not publish it has its frames DROPPED at every peer's attribution gate, reported
as `item 1 PASSED (Rooted ∧ owns_key) but item 2 FAILED`. The row exists on its
author the whole time; nothing offers it. Edge's own harness lost runs to this,
so `start` now WARNs when the set is absent.

Include **every** identity the node holds. Three keys are the minimum for a
viable agent — **human, node, agent** — and they are separate on purpose: an
agentID resolves to its owner, the owner resolves to the nodes they own, and the
NODE is what you dial. Conflate the agent with the node and that walk is a
tautology; omit the owner's row and it stops one hop out.

**5. Author a directed `consent:replication:v1` grant per peer.**

The Attestation plane is consent-gated at the **recipient**, not per row: a peer
that does not resolve to a consent-membership proof withholds the WHOLE plane,
fail-closed, before any per-row question is asked.

```rust
let grant = attestation_bind::replication_consent_attestation(
    &node_key_id, &peer_key_id, &attestation_bind::DEFAULT_CONSENT_PREFIXES, now, &signer,
).await?;
directory.put_attestation(SignedAttestation { attestation: grant }).await?;
```

Consent is **directed and self-attested** (CEG 1.0-RC29 §5.6.8.15): A granting B
says nothing about B granting A, so each node authors its own half.
`DEFAULT_CONSENT_PREFIXES` matches CIRISServer's list — if you restate it, you
will drop a plane and stay green while doing it (that is how the server shipped
eight releases moving zero traces).

**And install a log subscriber.** Edge emits `tracing` events; a binary with no
subscriber emits nothing, and its silence is indistinguishable from a code path
that never ran. That cost us five of the six runs.

---

## 6c. Waiting for the mesh — use the helper, do not write a poll loop

Every plane is eventually consistent: `pull_subject_testimony` is
**fire-and-forget** by design (it returns once the sends are queued; the rows
arrive later through Diff/Deliver). If you need the answer, do NOT write this:

```rust
// DON'T. This is the shape that appeared four times in our own harness.
loop {
    if resolve(&lens, &fed_id).await.is_ok() { break }
    if started.elapsed() >= timeout { return Err(..) }
    sleep(Duration::from_millis(500)).await;
}
```

Use the one helper. It subscribes BEFORE dispatching (so a row admitted between
the send and the wait is not missed), wakes on an **admitted envelope** rather
than a timer, and reports how long convergence actually took:

```rust
let outcome = replication
    .pull_and_await(&peer_key_id, &fed_id, Duration::from_secs(10), || async {
        contact::resolve(&lens, &fed_id).await.is_ok()
    })
    .await?;                      // Err ONLY if the Pull could not be SENT

if outcome.is_converged() {
    // contact found; outcome.waited() / outcome.checks() are yours to log
}
```

A sent Pull that never converges is `Converged::TimedOut`, **not** an error —
the peer may simply not hold what you asked for, and that is an answer.

Waiting on something replication does not signal (a transport route, a file)?
Same helper, no pull:

```rust
let mut waiter = replication.convergence();          // or ConvergenceWaiter::unsignalled()
let out = waiter.await_until(budget, || async { routes.has_destination(&node).await }).await;
```

The predicate must be a question about **observable state**, not about a message
having arrived, and it must not capture anything mutably — keep it `Fn`-shaped
and read what you need afterwards.

---

## 6d. The two-person chat, rung by rung

`tests/chat_two_person_community.rs` walks the whole flow on real substrate —
real hybrid signatures, a real persist directory, real MLS. It is the reference
to copy; every call below is exercised there.

| your UI | the call | who owns it |
|---|---|---|
| "search for a fedID or NodeCode" | `contact::parse_contact_input` then `contact::resolve` / `contact::discover` | edge |
| "Contact Found, adding to contact book" | the `Subject` it returns — `fed_id` + `nodes` | edge |
| "Send request to join chat community" | your `POST /v1/contacts` | **server** |
| "Request received from X" + optional note | your transport of choice; edge carries the bytes | **server** |
| accept → consent | your consent grant | **server** |
| "Joined community with X" | `CohortGroup::create` (inviter) → `add_member` → `CohortGroup::join` (invitee, from the Welcome) | edge |
| "Chat with Y" | `contact::the_other_member(&group.member_key_ids().await, own_key_id)` | edge |
| send a message | `group.destination_secret()` — both sides derive the same key | edge |

Four things worth knowing before you build on it:

1. **A nodeID and a fedID must land on the same person.** A node cannot consent
   and cannot be a contact, so pasting either into one search box is correct and
   supported — `resolve` walks a node to its owner. Do not create two contact
   entries for one human.
2. **The invitee is a moderator, not a guest.** MLS has no owner role: whoever
   was invited can change membership, and the founder applies their commit like
   anyone else's. If your UI implies the creator is privileged, it is describing
   a rule the substrate does not enforce.
3. **"Chat with Y" is derived, never stored.** `the_other_member` returns `None`
   unless the room is exactly two people *and* you are one of them — so a group
   chat cannot silently render under one participant's name. Decide what an
   unnamed room shows; do not unwrap.
4. **The conversation key moves when membership does.** `destination_secret()`
   changes on every membership commit, which is what stops a removed member from
   reading on. Re-derive after applying a commit rather than caching it.

Two rungs above are ours and are now proven over the real mesh, not just in
unit tests: `bench-mesh`'s `ladder.discover_by_fedid` resolves a PEER's owner
from a binding it learned over the Attestation plane, having seeded nothing.

---

## 6b. Still genuinely unbuilt

1. **`KnownHashes` records holders but nothing dispatches a point `Fetch` yet.** The learned directory is a sink until that path is wired.
2. **Owner-conferred mesh servers are recognized but inert** pending CIRISPersist#788, so hash-first and third-party serving are canonical-only in practice today.

---

## 7. Pin

Adopt `SERVE_ADVERTISE_POLICY_HASH = c0a13e031815163ac6972538a0597aff3d3396373f2e1f7d4fdbe3aa28e7d4b3` (CIRISServer#522) — this supersedes `e8216fec…`, `e54c5677…` and `75ceef58…`, none of which shipped. `REPLICATION_POLICY_HASH` (persist) is unchanged.

Also note: **`agent_mode="server"` no longer implies directory-holding.** Retention and identifier serving key on the node's own `infra:serve` conferral (`docs/ROLE_MATRIX.md` axis 3), not on mode. If your deployment relied on mode to turn hash-first on, it was relying on a bug.

---

Anything in here that does not compile against edge `main` is a bug in this guide — tell me and I will fix edge or the guide, whichever is actually wrong.
