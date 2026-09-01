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

Edge's Python entry point sets two config fields that a **Rust composer has to set itself**. Both default to something that looks correct and behaves wrong:

```rust
let mut config = ciris_edge::replication::ReplicationRuntimeConfig::default();

// Selects retention. Default is Proxy => Retention::Bodies for every plane.
// A server that wants hash-first MUST say so; there is no autodetect.
config.bridge.mode = ciris_edge::AgentMode::Server;

// The Pull responder answers an identifier request for THIS NODE'S OWN record.
// It cannot recognise "its own" without knowing which key_id that is. Left
// None, signer-key recovery is silently inert.
config.local_key_id = Some(my_signer_key_id.to_string());
```

Neither failure is loud. A server-mode node with `mode` unset behaves *exactly* like a correctly configured proxy; recovery with `local_key_id` unset just never recovers. We shipped both bugs during #556 and only found them in review — hence this section first.

`AgentMode` is `Client | Proxy | Server`, **Proxy by default**. Only `Server` takes hash-first retention, and that is deliberate: if every node converged the whole hash set, the directory would be enumerable from any node.

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

## 6. Three things that will not work, by design

Know these before you build against them:

1. **A third-party identifier cannot be resolved on a hash-first node whose directory lacks the body.** `request_key_body` returns `false` always, and says why. The Pull responder answers for the subject itself or for the responding node's own record; a third-party probe is refused, because answering it would make a body-holding server an address-book oracle for records it never advertised. Closing this needs a separately authorized, rate-limited resolver — not built. See `docs/FSD_SIGNER_RECOVERY.md` §7.
2. **`KnownHashes` records holders but nothing dispatches a point `Fetch` yet.** The learned directory is a sink until that path is wired.
3. **Stranger contact is meant to start from a nodecode, not a directory lookup.** You hand out an identifier out-of-band, the peer dials that specific node (which serves its own record), and consent follows. Building "search the federation for a person" on top of `discover` will work only for people you already have a consented relationship with — that is the boundary, not a gap to route around.

---

## 7. Pin

Adopt `SERVE_ADVERTISE_POLICY_HASH = e54c56775e8d56442f9fdbaa0346397cdc169e7cc6237f5a6fe71681710dbf25` (CIRISServer#522). `REPLICATION_POLICY_HASH` is unchanged.

---

Anything in here that does not compile against edge `main` is a bug in this guide — tell me and I will fix edge or the guide, whichever is actually wrong.
