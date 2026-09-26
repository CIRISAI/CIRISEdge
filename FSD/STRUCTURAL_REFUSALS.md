# FSD — Structural refusals: refuse by name, park until the dependency lands, and what the offer set can and cannot precondition

**Status:** normative for edge's replication receive axis. **Issue:** CIRISEdge#679 (from
CIRISServer#488). **Sources, in order of authority:** the CIRIS Constitution — CC 5.3.2.4.3.1
(every federation-tier admission gate MUST verify both signature halves and MUST reject; the
refusal this document is about is that gate doing its job), CC 5.3.2.4.3 (the tier invariant),
CC 5.3.2.1 (the `ContentMiss` feedback rule on the bytes plane — the one place the Constitution
already makes a miss a typed, consumer-acted-on signal), CC 5.2 (structural invisibility; why
the Key plane offers only the node's own record); `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4/§3.5
(the anti-entropy shape and the version rule), `FSD/REPLICATION_ROUND_CORRELATION.md` (CRPL v3:
round id + direction, never sequence numbers), `docs/ROLE_MATRIX.md` axis 3 (who answers an
identifier `Pull` for whom); leviculum at the pin (every `send_on_link` is already a reliable
Channel — nothing here proposes reliability mechanics). The receive-axis lessons this composes:
#414 (the send gate must never darken receive), #544 (the re-offer loop is **receiver-pulled**;
back off the ASK, never the ADMIT), #552 B (a transient refusal names the key it waits on; the
drain decides absence where the store can be afforded).

---

## 0. The problem, from the receiver's ledger

On the canonical (`ciris-server` 0.5.216, 2026-09-25, read-only logs): **107 refusals in 6 h**,
one reason — `Attestation: admission refused (refusal=federation_invalid_argument): attesting_key_id
<k> does not exist in federation_keys` — from **three attesters** whose `Key` rows the canonical
has never held, the same keys a month after the first measurement (1,907 per 30 min on 0.5.188;
504 distinct content hashes, individual hashes re-offered up to 31× in a window).

What the ledger reads today, and why each reading is *correct* and still not converging:

| Ledger fact | Why it is right | Why it does not converge |
|---|---|---|
| `apply_refusals_by_kind{Attestation}` climbs | CC 5.3.2.4.3.1: an attestation whose signer is unknown MUST be refused | the counter fuses "a gate said no" with "this row can never land here" |
| `retry=transient` on every refusal | the token `federation_invalid_argument`/`unverifiable_signature` covers *malformed* (terminal) AND *signer not yet replicated* (recoverable); the #544 rule for an ambiguous token is transient | transient means "re-ask on the 20 s → 300 s schedule forever": ≤12 asks / hour / row, each a Deliver + deserialize + hybrid verify + admission check |
| `missing_signer` noted; a `Pull { Key, subject }` goes back to the delivering peer (#552 B) | the peer that delivered the row is the best holder guess | the Key plane is **`SelfOwn`** (CC 5.2 / `serve_policy`): a node advertises and answers a `Pull` **only for its own key**. A third party's key never comes from the peer that relayed the row. The pull returns an empty Summary, the name is consumed, the next refusal re-notes it |

So the loop is bounded by #544 and infinite by construction: the verdict is a function of a
row (`Key <attester>`) that **cannot arrive through the channel being retried**. That is what
"structural" means here: *re-asking the same peer for the same bytes cannot change the answer,
and the dependency that would change it does not travel on this path.*

**The fix, stated once:** the receiver already chooses what is asked (`want = remote ∖ holdings`,
#544). Give that choice one more input — *the row is waiting on a key this directory does not
hold* — and one event that reverses it — *that key landed*. Everything else in the three asks is
either observability or a wire change, and is classified below as such.

---

## 1. The three asks, each on the side where the choice actually lives

### Ask 2 — back off on a structural refusal until the attester's key lands

**Mechanism (RECEIVER side; no wire change; shipped in this PR).** At the apply choke
(`apply_envelope_bytes`), after the outcome is decided and classified:

- if the outcome is a **transient refusal** and the row **names a signer** (`missing_signer_of`,
  the #552 B extractor — pure) and that signer is **absent from this directory**
  (`lookup_public_key == None`, the one store read, made where the store can be afforded, exactly
  as #552 B decides absence at the drain) → **park** the row on that signer:
  `RefusalBackoff::record_waiting_on_at(kind, hash, signer)`. The park installs the **terminal**
  schedule (`1800 s → 6 h` cap; never silence) and indexes the row under the signer.
- if the outcome is a **`Key` admit or duplicate** → **release** every row parked on that key:
  `RefusalBackoff::release_signer(key_id)`. The next round's `want` asks for them at once.

Why the sender is told nothing: it never chose. The Summary it sends is its full offer; the
receiver's `want` is the only thing that puts bytes on the wire (`Deliver` packs `want`). Quieting
the want quiets the wire. This is the #544 argument verbatim, one level up.

Why terminal-shaped rather than the 20 s transient base: the transient window exists for
*ordering* — a signer's key that is in flight this very round. Under the park that case is
strictly better served: the key's admit **releases** the row on the next round instead of the
row re-asking on a 20/40/80 s ladder hoping to land after it. A park costs ≤ ~4 asks/day per row
if the key never lands; the un-parked loop cost 12/hour.

**Bounds.** The park lives in the same front-drop-capped memory (`DEFAULT_MAX_KEYS = 4096`, the
`LogThrottle` cure); the signer index is kept in lockstep with entries (`clear`, eviction,
re-park). Eviction costs one re-ask. Restart empties it (a restart is the one event that can
change a verdict without a row moving — a new build, a re-wired provider).

**Ledger tokens.** `rows_parked_on_signer` (parks since construction) and `signer_releases`
(rows released by a `Key` admit) on the bridge, beside `retry_suppressions`; the park logs at
DEBUG (the refusal itself already WARNs at the choke with reason + disposition) with
`signer`, `backoff_secs`, `parked`; the release logs at INFO with `signer`, `released`.
`apply_refusals_by_kind` is **not** changed: it still counts the first refusal of each row. What
stops is the *repeat* — the pollution the issue names is the 2nd…Nth refusal of the same bytes,
and those no longer happen, because the bytes are no longer asked for.

**What this does not do.** It never classifies. `ApplyRefusalClass`, `key_refusal_retry`, the
`refuse`/`refuse_as` mapping and #459's typed `AttestationRefusalReason` adopt are untouched;
the park reads the disposition and the named signer, both already decided. When #459 lands a
typed `attester unknown` reason, the park's "is the signer absent?" read becomes redundant with
the reason — keep the read (it is the honest predicate, and a typed reason that says "unknown"
about a key that is in fact held would be a bug the read catches).

### Ask 3 — the Key plane as a precondition in the offer set

**What the Key plane's projection makes true.** `list_keys` advertises under `Projection::SelfOwn`
(FSD wire-format §3.4; `serve_policy` row `Key → ("self_own", "public")`; CC 5.2): a node offers
**its own** key record and nothing else. A relay never carries a third party's key on the Key
plane, and a non-canonical answers an identifier `Pull` only for itself (ROLE_MATRIX axis 3; the
canonical answers for any subject from an attributed requester — and the canonical **is** the
receiver in #488, so it has nobody to ask).

**Consequence for ask 3 as stated (sender-side):** the sender cannot make a third-party attester's
key *precede* the attestation on the Key plane — it does not offer that key at all, by design.
The only precondition it can evaluate is "do I hold the attester's key", which is true by
construction for every row it admitted. So a sender-side offer gate has exactly one useful
form: **offer only attestations whose attester is a self-publish identity of the sender** (own
rows) — which is the `SelfOwn` projection the Attestation plane already applies to `self`/
`family` rows and deliberately does **not** apply to federation-scope rows (a relayed federation
row is the corpus; the canonical exists to carry it). Applying it would shrink the corpus a
canonical serves to first-party rows and is rejected.

**The precondition, where it is decidable:** the receiver. "Do not admit — and therefore do not
keep asking for — an Attestation row whose attester's `SignedKeyRecord` has not been admitted on
the Key plane first" is precisely the park (ask 2). The order is enforced by the memory, not by
the offer: the row is asked for again only after the key admits.

**The one thing that does make a third party's key precede its rows:** the attester itself
announcing to the receiver (bootstrap kinds cross on an Identified link, `FSD/FIRST_CONTACT.md`
R1) or a canonical the receiver can `Pull` from. For the three legacy senders in #488 neither has
happened in a month; those rows are permanently unadmittable at the canonical until the attesters
register, and the park is the correct standing state for them.

### Ask 1 — refuse with a reason back to the sender

**Mechanism (wire change; proposed here, NOT shipped).** A new `ReplicationMessage` variant,
sent by the **applying** side within the round that carried the `Deliver`:

```text
Refused {
  kind,
  refusals: [ { envelope_hash, reason: <stable token>, retry: transient|terminal|parked } ],
}
```

- **Rides in the round, not beside it.** CRPL v3 frame, same `ROUND` id, `FROM_RESPONDER` set by
  the applying side's role (either side applies a `Deliver`; both directions deliver). No
  sequence numbers — the round id is the correlation (`FSD/REPLICATION_ROUND_CORRELATION.md`);
  a `Refused` for a round the peer no longer has in flight is a `ReplyDropped { RoundMismatch }`
  like any other late reply.
- **Why a new variant rather than riding an existing reply.** `Summary`/`Diff` say what a node
  holds and wants; `Deliver` carries bodies; `Pull` asks. None carries a verdict about bytes the
  peer sent, and overloading `Diff.want` (e.g. "I want it again" vs silence) is exactly the
  fused-signal shape #414 removed. A verdict is a new noun.
- **Version gating (wire FSD §3.7 / §3.5).** Every variant is `#[serde(tag = "type")]`; a peer
  that does not know `refused` **serde-refuses the frame** (it does not ignore it), so a `Refused`
  sent to an older peer breaks that peer's round. Gate: send `Refused` only on a round whose
  opening frame was **v3** *and* after the peer has demonstrated the vocabulary — the honest
  way is a new wire version byte `0x04` on the round-open, the way v2 added kinds and v3 added
  round metadata; a `0x03` opener gets no `Refused`. This is a coordinated cut with a
  `SERVE_ADVERTISE_POLICY_HASH` re-pin, and the server fleet crosses together (§7 of the CRPL
  FSD).
- **What the sender does with it.** For a `parked`/`terminal` verdict: stop *proactively pushing*
  those bytes to that peer (the #927 unsolicited-Deliver path — the **only** path where the
  sender chooses what crosses) for the terminal window; nothing else, because the ordinary
  round already delivers only what the peer's `want` names. For `transient`: nothing.
- **Payload discipline (threat check, §4).** Hash + tokens only. **Never the key id** the receiver
  lacks: the sender can derive the attester from its own row, and a reply that names keys the
  receiver does *not* hold is a negative-membership oracle over the directory.
- **Value, honestly.** With ask 2 shipped, `Refused` changes no traffic on the ordinary
  anti-entropy path; it gives the sender a ledger of *why it is not being asked* and bounds the
  unsolicited-push path. That is observability and a narrow correctness gain, not the fix.
  **Decision: defer** until ask 2 has been measured on the canonical (§5) and the next
  `SERVE_ADVERTISE_POLICY_HASH` re-pin is due; ship it then as `0x04`.

---

## 2. State table — sender × receiver, per `(peer, kind, envelope_hash)`

Sender states are about **offering**; receiver states are about **asking** (the receiver's
memory) and **holding**.

| # | Receiver: holds? | Receiver memory | Receiver `want` | Sender `Deliver` | Wire cost / round | Leaves by |
|---|---|---|---|---|---|---|
| S0 | no | none | asks | delivers | 1 body | admit → S4; refuse → S1/S2/S3 |
| S1 | no | transient window (20 s → 5 min) | asks after window | delivers | ≤ 12/h | admit → S4; signer absent → S3; terminal → S2 |
| S2 | no | terminal window (30 min → 6 h) | asks after window | delivers | ≤ 2/h → ~4/day | admit → S4; window → S0 |
| **S3** | no | **parked on `Key <signer>`** (terminal schedule + index) | quiet | — | 0 until window (≤ 2/h → ~4/day), **0 wire-side deliveries otherwise** | **`Key <signer>` admits → S0 on the next round**; window elapses → S0 (re-ask, re-park if still absent); eviction → S0 |
| S4 | yes | cleared | — | — | 0 | never re-offered (diff drops it) |
| P | — | any | — | **unsolicited push** (#927) | 1 body | applied on its merits regardless of memory (the ADMIT is never gated) |

Invariant across every row: **the memory gates the ASK, never the ADMIT** (#544). S3 is a longer,
named S2 with an early exit. Row P is why nothing here can withhold state.

---

## 3. Invariants and witnesses

| # | Invariant | Witness |
|---|---|---|
| I1 | A transient refusal naming a signer **absent** from the directory parks the row on that signer; the row is quiet past every transient window. | `bridge::an_attestation_from_an_unknown_attester_is_parked_on_that_signer` (through the real choke) |
| I2 | A `Key` admit through the choke releases every row parked on that key; the next `want` asks at once. | `bridge::a_key_admitted_through_the_choke_releases_the_rows_parked_on_it` |
| I3 | Parks are bounded and the signer index never outlives its entry (clear, eviction, re-park). | `refusal_backoff::tests_679::clear_and_eviction_keep_the_signer_index_in_lockstep`, `…a_re_park_moves_the_index_and_keeps_doubling` |
| I4 | A row parked on signer A is untouched by signer B's admit; release is idempotent. | `refusal_backoff::tests_679::rows_parked_on_a_signer_stay_quiet_until_that_signer_is_released` |
| I5 | The park never classifies: dispositions, `ApplyRefusalClass` and the Key-plane mapping are unchanged. | I1 asserts the outcome is still `Transient`; `conflicting_version_is_terminal_and_the_ambiguous_key_reasons_stay_transient` unchanged |
| I6 | A transient refusal whose named signer **is** held (a roster/race refusal) keeps the ordinary #544 window — no park. | by construction (`lookup_public_key == Some` returns before the park); `a_community_scoped_row_ahead_of_its_roster_refuses_as_named_transient` still reads transient with no park counter movement |
| I7 | An unsolicited push of parked bytes is applied on its merits. | `a_suppressed_row_is_still_applied_when_a_peer_pushes_it_anyway` (#544; unchanged) |

---

## 4. Threat check

- **Can a peer starve a receiver with refusals?** No: the park is *receiver-local*, keyed on
  bytes the receiver itself refused, and gates only what the receiver asks. A peer cannot park a
  row on another node; a peer cycling junk hashes hits the front-drop cap and costs one re-ask
  per eviction (the #544 bound, unchanged).
- **Can a peer make a receiver stop asking for a row it *would* admit?** Only by delivering
  bytes the receiver refuses — and a refused row is by definition one the receiver would not
  admit. A corrected, superseding record is different bytes → a different hash → never parked.
- **Can the park mask a key that later lands through a path other than the choke?** A `Key`
  written locally (`put_public_key` by the host, a genesis seed) does not pass the choke and does
  not release. The row is then re-asked when its terminal window elapses (≤ 6 h) and admits. This
  is the same bound #544 accepts for terminal rows; if the host wants the early exit it calls the
  same `release_signer` after a local registration (a one-line host follow-up, not a wire
  concern).
- **Enumeration via ask 1.** A `Refused` that named the missing key would tell a sender which
  keys the receiver lacks. Hash + tokens only (§1, ask 1). Deferred anyway.
- **Amplification via ask 1.** One `Refused` per `Deliver`, bounded by the `Deliver` it answers;
  never sent for an unsolicited push beyond a per-peer throttle. Deferred anyway.

---

## 5. Acceptance on the canonical (what to measure after the tag)

On the canonical's logs over 6 h after adopting this cut:

1. `unknown-key refusals` for the three legacy attesters: **≤ 1 per attester per 6 h** (the
   terminal cap), down from 107 in 6 h.
2. `rows_parked_on_signer` ≥ the number of distinct refused hashes; `signer_releases` = 0 (the
   keys have not landed) — the loop is parked, not hidden.
3. `apply_refusals_by_kind{Attestation}` growth ≈ *new* rows only.
4. Negative control: a split-install agent whose node key admits on the Key plane in the same
   window shows `signer_releases > 0` and its rows admit on the next round (CIRISServer#629/#632
   shape) — the park must not have slowed an honest late registration.

---

## 6. Owed

- **Ask 1** as wire version `0x04` at the next `SERVE_ADVERTISE_POLICY_HASH` re-pin (§1).
- **#459** — adopt persist's typed `AttestationRefusalReason`; when it lands, the park keys on
  the typed `attester unknown` reason *and* the absence read (I5 stays true).
- Host follow-up: call `release_signer` after a local `put_public_key` so a locally registered
  signer releases its parked rows without waiting for the terminal window (§4).
