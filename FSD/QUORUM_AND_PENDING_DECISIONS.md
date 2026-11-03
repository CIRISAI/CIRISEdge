# Quorum and pending decisions: edge's part

**Status:** normative for CIRISEdge v44 (persist v61.0.0, CC 1.0-rc16).
**Ownership:** [CIRISConstitution#198](https://github.com/CIRISAI/CIRISConstitution/issues/198) §5. This document covers only edge's share.

| owner | owns |
|---|---|
| persist | the policy table (`governance_policy::PolicyTable::admit`, the corridor), the two-path and mirror evaluators, the room record, the roster folds, the room doors (`consensus::evaluate` today; the CC rows from CIRISPersist#1173 in v62) |
| server | the act doors that open a window and tally it, the moderator's ruling route, the pending-decision queue and its answer door, presenting the act's shape before it is signed |
| **edge** | **carrying the rows and their cosignatures**, and telling the host when a decision-relevant row lands |
| client | showing the shape and the open window's state |

**Edge evaluates no quorum.** It holds no threshold, no window and no `at_window` outcome. It does not tally, defer, or decide when a change lands. Every "is this enough?" is persist's door's answer.

## 1. Roster changes edge can sign (`community_roster`, `membership`)

Under persist v61, a room's roster changes only by a row its door admits under the room's `consensus_protocol`: `membership:widening:v1` or `membership:removal:v1`, with the cosignatures in `additional_scrubs` (CC 2.4 cosigned rows; CC 3.1.3.2; CHANGELOG [61.0.0]). Edge provides three primitives and nothing more:

1. **The event**, `RosterEvent::{widening, revocation}`. These are the exact bytes persist verifies: `CommunityMembershipWidening::signing_envelope()` / `CommunityMembershipRevocation::signing_envelope()`, with every instant truncated to the millisecond (CC 2.6.2).
2. **A cosignature**, `cosign(event, pen) -> RosterCosignature`. The pen's hybrid signature over those bytes. Each signer makes it on their own node, with their own pen.
3. **Assembly**, `assemble(dir, event, signatures)`. It hands the first signature as the authority and the rest as `cosignatures`, in the order given and unaltered, to persist's door. **The door decides.** A short set is refused `roster_consensus_insufficient`, and edge surfaces that refusal verbatim without counting anything.

`widen_community` / `revoke_community_member` take a slice of pens and are exactly `cosign` × N followed by `assemble`. The single-pen form that v43 shipped is gone.

`membership::MembershipWidener` (the bridge's widen-on-acceptance) offers **one** voice: the proposer's own pen, which the host handed it. That voice admits only where the room's protocol says one voice is enough. The cases are:

- a room of one, where the newcomer's acceptance is the second voice (CC 3.1.3.2 and #198 §3 inv. 1);
- a `founder_only` family.

Anywhere else, persist refuses by rule. The widener logs the refusal and leaves the rest to the server's cosign flow. It never retries the refusal and never adds a signature it was not given.

## 2. Carriage guarantees (edge's, and witnessed)

| # | guarantee | witness |
|---|---|---|
| C1 | `membership:{proposal,acceptance,decline,widening,removal,resignation}`, `group:roster`, `objection:*`, `moderation:*` and `accord:invoke:*` rows reach the act's standing set promptly. An admitted row propagates on the round that admitted it (CIRISEdge#636). A row written locally kicks every peer on the Attestation plane at once (`note_local_write`), rather than waiting for the next cadence tick. | `tests/quorum_carriage_v44.rs` |
| C2 | Cosignatures travel with their row byte-for-byte: edge re-signs, re-orders and strips nothing. | the strip-a-cosign mutation in C-e2e |
| C3 | Edge never withdraws a cosigned act, and never drops or re-orders one. Rule 0, CC 2.4.1.1: only a cosigned `withdraws` retracts it, and that is the server's act. | edge has no producer of `withdraws` over a roster row |
| C4 | Edge stamps no window instant and reads none from receipt. Windows are judged by persist on the signed instants. A late-delivered vote counts by what it signed, not by when it arrived. | the late-objection case in C-e2e |

**Known gap (persist):** `RosterCosignature` carries no signed instant of its own, so v61 judges the `open:self_admit` removal window (259 200 s) on the **local door's receipt**. CC#198 requires it on each counted cosignature's signed scrub instant. Filed as CIRISPersist#1189. Edge carries what persist defines. It cannot add a signed instant to a cosignature.

## 3. Decision-relevant rows: event and cursor (`decision_rows`)

The server builds its pending-decision queue over persist's folds. Edge tells it **which rows to re-read**, so the server never has to poll.

```rust
pub enum DecisionRowKind {
    MembershipProposal, // "membership:proposal:"
    MembershipReply,    // "membership:acceptance:", "membership:decline:"  (cosign progress)
    Objection,          // "objection:"  (proposal / assent / raised / ...)
    RosterLanded,       // "group:roster:", "membership:widening:", "membership:removal:", "membership:resignation:"
    ModerationAction,   // "moderation:"
    AccordHalt,         // attestation_type "accord:invoke:"
    ContactRequest,     // "consent:replication:"
}
pub struct DecisionRowRef {
    pub attestation_id: String,
    pub kind: DecisionRowKind,
    pub cohort_scope: String,          // self | family | community | affiliations | federation
    pub scope_id: Option<String>,      // family_key_id / community_key_id; None at self/federation
    pub proposal_id: Option<String>,   // the proposal a reply or a widening completes, when known
    pub cursor: DecisionCursor,        // resume point that INCLUDES this row
}
```

- **Event.** `ReplicationRuntime::subscribe_decision_rows()` returns a `broadcast::Receiver<DecisionRowRef>`. It fires:
  - when a row is admitted through the apply choke;
  - when the bridge's own widener writes a widening, with `proposal_id` set. That marks the proposal/acceptance pair complete.
  - when the host calls `note_local_write(&row)` after a local write. This is required: local writes bypass the choke (memory: *local writes bypass the choke*).
- **Cursor.** `DecisionCursor` is persist's serve position, the `(admitted_at, attestation_id)` resume pair of `list_attestations_since`. Its text form is `"{rfc3339-ms}|{attestation_id}"`. The cursor on an event is a lower bound: `decision_rows_since(cursor)` includes that row. It may also return some rows the host has already seen, so dedup by id.
- **Rebuild.** `decision_rows_since(dir, Option<DecisionCursor>, limit) -> (Vec<DecisionRowRef>, Option<DecisionCursor>)`. Use it after a suspend, a restart, or a lagged receiver. Nothing fires while the node is suspended: there is no transport, so there is nothing to carry.
- **No standing filter at edge.** A row is on this node only because persist's audience gate admitted it here (CC 5.2, `may_receive`). Whether this person has *standing* on it is a persist fold the server asks for.
- **Not rows edge can name:** the owner-request (#837) and the setup/consent-disclosure items. Those are server-local, and the server enqueues them itself.

## 4. Witnesses

| witness | file |
|---|---|
| the six v61 room producer tests, re-shaped to cosign (un-ignored) | `src/community_roster.rs` |
| a one-voice add in a room of two is refused by the door (mutation: `assemble` drops cosignatures → the cosigned tests fail) | `src/community_roster.rs` |
| a 4-node room over the bridges: yes lands everywhere at once; a stripped cosign is refused everywhere; a below-protocol row lands nowhere; a room of one grows by proposal + acceptance, and the event marks the pair complete; a late objection under `reverse_quorum` counts by its signed instant | `tests/quorum_carriage_v44.rs` |
| decision-row classification, cursor round-trip, rebuild covers local and replicated rows | `src/decision_rows.rs` |

**Not witnessable at v61 (persist owns them; tracked):**

- `moderation_action`'s 48 h fallback and the room doors reading `community_invite` / `community_remove`: CIRISPersist#1173.
- `accord_halt` firing and lapsing at the 24 h fuse: the `mirror` rows are `policy_not_two_path` in `governance_policy::PolicyTable::policy_of`, and no evaluator is exposed (CIRISPersist#1191).
- The removal window on signed instants: CIRISPersist#1189.

When persist ships these, the e2e file gains one case each. The carriage is already exercised by the cases above.

## 5. Persist tickets

- CIRISPersist#1189: the removal window on each cosignature's signed instant (`RosterCosignature` needs one);
- CIRISPersist#1190: a decision-row cursor read (`list_attestations_since` narrowed by family prefixes, plus a row's own serve position), so `decision_rows_since` stops scanning the whole plane and events carry exact cursors;
- CIRISPersist#1191: callable `mirror` / `cosigned` evaluators (`moderation_action` tallied, `accord_halt` fuse and lapse, 2/2 cosign), beside CIRISPersist#1173.
