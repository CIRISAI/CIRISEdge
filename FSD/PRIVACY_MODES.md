# FSD — Privacy modes: the first-run choices, what each one gives, what each one costs

**Status: LOCKED** by the CC under Eric's delegation, 2026-11-04, pending only stable homing (Eric's; out of scope here beyond
this reference), Q16 and Q6. Nothing here was built or run for this document.
**Direction:** Eric, 2026-11-04: "make sure the first run wizard choices are clear - with benefit and
downside. … There should be 3 lists of items that change as the choices change: features, performance,
and privacy level - base is all features, good privacy. If they enable shaped traffic by default, slower
performance, same features, if they disable anything BUT shaped traffic then live features drop off,
performance drops further, but privacy increases, and then finally if they enable onion routing,
performance drops further but features are I think the same as shaped traffic only. Validate/check - the
choices and impacts need to be clear, and what can be transported over shaped links."

**Sources, in order of authority:** CC rc17 (`constitution/part_5_transport_substrate.md` 5.3.3.5, 5.4.3,
5.4.6; `part_1_foundation.md` 1.13.3.x); this repo's `FSD/TRANSPORT_TIERS_MODEL.md` and `FSD/CIRIS_MESH.md`;
CIRISClient#272 and its CSDs; CIRISServer `compose.rs`, `config_reconcile.rs`, `auth/bootstrap.rs`,
`media_gate.rs`; the inputs Server, Client and the CC reader sent while this was written.

**Citations.** `edge:` means `/home/emoore/CIRISEdge-onion`, branch `feat/onion-v44` at 1eeeb14 with its
uncommitted edits, 2026-11-04. Line numbers will move; symbols are given with them. **[inf]** marks an
inference from the code or arithmetic that no one has measured. **[model]** marks a model output, not a
live mesh. Transfer durations here are what a person waits; this document makes no estimate of build work.

**Rung numbers.** Eric's order: 1 Standard, 2 Shaped, 3 Shaped only, 4 Anonymous mode. The CC reader's note numbers the same four
0–3. This document uses 1–4. Rung 4 is a rung by name only: it is a first-run choice of identity, not a setting (§4).

**The one sentence:** the ladder's order is right, but its steps are not the same size: rung 2 changes
how rows travel and only toward peers who also shape, rung 3 is the expensive step because it cuts off
every peer who does not shape, and rung 4 is not a step at all: it is a separate identity set up at first
run or never, and it is held until rooms can ride the tier.

---

## 1. Verdict on the ladder

| # | The assumption | Verdict | What is true, and the cite |
|---|---|---|---|
| 1 | "Base is all features, good privacy" | **True for home and phone with announce on; not for a server** | Without announce a node gets no service access (§6.5). CC 5.4.3 fleet defaults: shaping is on by default for `server`, off otherwise, so the default rung is **per class** (§6.1, gated §6.11). `edge:src/transport/link_shaping.rs:287` `FLEET_DEFAULTS`. |
| 2 | Server shapes by default | **Not yet true in the running product** | CIRISServer `compose.rs:5442` sets `shaping: Default::default()`, which is `off` (`link_shaping.rs:505`). Edge has the default; server does not pass the class. S1 must not flip it silently (§6.11). |
| 3 | Rung 2: "slower performance, same features" | **True for the feature list, with two new limits** | Calls and files still work and are not hidden. But (a) a row link past a peer's eight shaped links is refused, never run unshaped: rows to that peer fail by name for 120 s (`link_shaping_home_elsewhere`; `reticulum.rs:9705`) and the fallback order is not built (CIRISEdge#935). (b) Slower only toward peers who also shape: a peer offering `off` leaves the link unshaped and just as fast (`agree`, `link_shaping.rs:833`), and also just as exposed. |
| 4 | Rung 2 shapes "the rows" | **Not all of them** | A scoped link is never shaped (`shaping_applies_to`, `reticulum.rs:526`), so a body on a scoped lane (a direct member address, a file chunk pull) is not. CC 5.4.3 item 4 is normative: at rungs 2 and 3 the derived-address link itself is shaped. That is an edge gap (E4). |
| 5 | Rung 3: "live features drop off" | **Understated** | Rung 3 also loses every contact who does not shape, directly, for every feature (§3.1). At fleet defaults that is nearly every home and phone. |
| 6 | Rung 3: "performance drops further" | **Half true** | Row delay is the same as rung 2: same timer, same links. What drops is everything that was on the bulk link: files, attachments of any size, large catch-up (§2.3). |
| 7 | Rung 3 exists | **Not yet** | `require_shaped_links` is a partial start: it does not stop bulk, calls, scoped lanes or inbound unshaped links (§3.4). |
| 8 | Rung 4: "features … the same as shaped traffic only" | **False: fewer** | Eric's later ruling: anonymous mode is this rung. No announced identity, no ordinary contacts, no rooms, no service access as the rule stands. Pending, §4.2. Shaped-only is implied by the mode. |
| 9 | Rung 4: "performance drops further" | **True, for everything** | About 13–58 s per packet by class [inf], and everything it publishes goes that way (§4.3). |
| 10 | Each rung adds privacy | **True, and rung 4 buys it with identity** | Rungs 2 and 3 are about links. Rung 4 gives up announced identity. Nothing on the ladder removes (a) which links exist or (b) that your groups exist (§5.1). |
| 11 | A straight ladder | **Two more settings cross it** | Announce and relay offering are separate and interact with it (§5.4, §6.5). Turning shaping on at home is what starts handing the node's route to strangers, because free slots are reported only on shaped links. |
| 12 | The CC's latency figures | **Corrected in rc17** (2ad9675) | The draft found 1.6 / 4 / 8 / 26–32 s were the row delay at a 1,400 B frame; on TCP the MDU is 16,272 B and the measured gap at `server` is 2,325 ms (commit 1eeeb14). rc17 now states the link's agreed mean, about 2.3 / 5.8 / 11.6 / 47 s. `docs/LINK_SHAPING_COST.md` and CIRISClient#272 still carry the old figures (E11, C7). Superseded by rc17 a3dd97a (edge 44.1.1): the shaped frame is one 1,400 B constant, and the gaps are 0.2 / 0.5 / 1.0 / 4 s. |
| 14 | "Finally if they enable onion routing" | **It cannot be enabled** | CC 5.4.6 item 1 (rc17 ae86ea0): anonymous from first run or never. It is a separate identity chosen before keys exist, irreversible, and held until rooms ride the tier. Rungs 1–3 are the reversible ladder; rung 4 is not on it (§4, §6.10). |
| 13 | Onion needs "9 conferred relays" | **Stricter than the CC** | CC 5.4.6 item 4: floor is three per layer, and other relays are capped at ⌈2 × conferred⌉ per layer. So the minimum is nine relays of which three are conferred. |

Corrections to the CC reader's note, accepted by the CC on review:

- "Who you talk to is encrypted end to end" cannot be said at any rung. CC 1.13.3: privacy "does **not**
  mean metadata privacy, communication-graph privacy, or unobservability"; 1.13.3.1: "Cohort scope hides
  *content*, not *contact*." The sentence here is "what you say is encrypted end to end".
- The shrinking list drops (d), the publisher of a federation-scope item, at rung 2. Shaping does not
  hide it: a shaped node's public post is signed by its own key and handed to a storage node. (d) goes
  only at rung 4. Corrected list in §5.1.
- "No blobs above the shaped budget's reach; small images only" needed care: edge treats every attachment as
  bulk by kind whatever its size, and has a slow path. The CC admits the slow path and rules by size (§2.2, §2.3).

---

## 2. What can be transported over shaped links

### 2.1 Three limits, not one

1. **The row limit, 64 KiB** (`SHAPED_ROW_MAX_BYTES`, `link_shaping.rs:361`): edge's own, larger messages
   leave for the bulk link. The CC's limit is the next one.
2. **The window's reach**, `ceil(ρ·λ·W)` real frames (CC 5.4.3 item 3; `Agreement::reach_frames`):
   129 frames, about 2.1 MB per 10 minutes at `server`; §2.4 for the others.
3. **The kind**, in edge only: `ContentFetch`, `ContentBody`, `BlobChunkFetch`, `BlobChunkBody` are bulk at any
   size (`BULK_MESSAGE_TYPES`, `link_shaping.rs:347`). In the CC the rule is size; this is a code gap (E5).

There is also a fourth, unplanned one on phones: a sender waits at most 60 s for a queued row to leave
(`ROW_LEAVE_MAX`, `link_shaping.rs:1529`), then retracts and retries. At the 47 s `phone-cellular` gap,
about one single-frame row in four needs a retry, a two-frame row usually does, and a 64 KiB row
(5 frames) almost never leaves in 60 s, so its retries do not converge. On `phone-wifi` a 5-frame row
leaves in time a bit over half the time. [inf, from `leave_budget`, `link_shaping.rs:1235`.]
**Fixed (E7, then CIRISEdge#963 at the 1,400 B frame):** the cap is the largest row's own Poisson p99
(`LinkShaper::row_leave_cap`, 64 KiB = 48 frames at 1,400 B, about 330 s on `phone-cellular`), stated in row
bytes rather than gaps; witness `a_64_kib_row_converges_on_phone_cellular_at_the_shaped_frame`. Was: must be fixed
for rungs 2 and 3 on phones (§7, E7).

### 2.2 The table

"Shaped?" means: when both ends shape and a slot is free. At rung 1, and toward any peer who does not
shape at rung 2, everything is unshaped and works as it does today.

| What | Typical size | Shaped link? | Rung 2 above the limit, or if it is not a row | Rung 3 (as specified, §3.3) | Rung 4 |
|---|---|---|---|---|---|
| Text message, room post | mean row 8.5 KB (T2 sample) | **Yes**, 1 frame | Unshaped on a scoped lane until E4 | Shaped | **No rooms; pending #202.** |
| Reaction, read marker, control | 55–220 B bodies | **Yes**, coalesced (`KIND_MULTI`) | n/a | Shaped | Public reactions under a pseudonym only |
| Contact request and acceptance, invitation, group key wrap | bounded, sealed | **Yes**; a stranger may carry them (CC 5.4.6) | n/a | Shaped, only to a peer who shapes (§3.1) | Only through its circuit and rendezvous (item 10) |
| Consent, revocation, halt, tombstone | small | **Yes** | n/a | Shaped | Through the tier where it has anyone to answer |
| Add a device (pinned first contact) | a few frames | **No**: dials with no offer (`send_first_contact_pinned`, `reticulum.rs:5749`) | Unshaped, one exchange | **Carve-out**: stays unshaped, stated (§3.3) | Pending (§4.2) |
| Public post | row | **Yes** | n/a | Shaped, signed by you | Through the tier, signed by a pseudonym; about three packets [inf] (§4.2) |
| Small image, as a row | ≤ 64 KiB | **In the CC by size; in edge by kind until E5** | Until E5 an attachment takes the bulk link at any size | Slow path (§2.3) | Not through the tier today [inf] |
| Larger image, file | 256 KiB chunks (`group_content/store.rs:726`); media up to 16–100 MB (`media_gate.rs`) | **No** | Bulk link, unshaped, visible as bulk. A NAT'd peer with no dialable link: slow path, counted `link_shaping_bulk_on_shaped_fallback` | Slow path (§2.3), one chunk at a time | Not through the tier today [inf] |
| Voice note | about 240 KB a minute at 32 kbit/s [inf]; audio ≤ 16 MB | **No** (a file) | Bulk link | Slow path: a one-minute note takes 70 s at `server`, 6 min `phone-wifi`, 23 min `phone-cellular` | Not through the tier today [inf] |
| Call, audio or video | live | **Never** (CC 5.4.3 item 4; `LinkPlane::Av`) | Unshaped, works, not hidden | **Refused by name** (to build). Not fragmented: live media cannot wait for a timer. | **Refused**: `onion_anonymous_no_media` |
| Live stream, watch or publish | live | **Never** | Unshaped, works, not hidden | **Refused by name** (to build) | **Refused** |
| Replication catch-up | rows ≤ 1,024 per plane; Deliver ≤ 512 KiB (`session.rs`) | **Yes up to 64 KiB**; a larger Deliver is not | Bulk link | Slow path. A 512 KiB Deliver is 32 frames: 2.5 min `server`, 12 min `phone-wifi`, and most of an hour's budget on `phone-cellular`. | Public rows only; path pending |
| Blob catch-up, drive sync | as files | **No** | Bulk link | Slow path | Not through the tier today [inf] |
| Cover, key exchange, shaping offer | n/a | Cover yes; the handshake and offer happen before shaping begins | n/a | Same; link setup is always visible (item 5) | Same |

**Headline.** Rows ride shaped links. Everything that is a file, of any size, leaves them at rung 2 and
crawls at rung 3. Live media is never on them and stops at rung 3. Rung 4 publishes and reads public rows.

### 2.3 At rung 3, are files impossible or just slow?

> **Superseded by CC 5.4.3 rc17, `CLM-shaped-link-one-hop`.** Bulk is unshaped only, and a failed bulk
> dial refuses by name, retries on its schedule or goes by a carrier that said yes. The slow path this
> section and §6.12 describe is removed; every slow-path figure below records the old design. How a
> rung 3 node carries files is 44.2's routing work. A shaped link is one direct hop: a peer with no
> direct path gets none, and what reaches it crosses a forwarder sealed and unshaped, or refuses under
> `require_shaped_links`.

**Slow, not impossible.** The CC rules: a chunk MAY ride a shaped link chunk by chunk when the node has no bulk link,
within the row budget, rows first. The mechanism exists: `bulk_on_shaped` (`reticulum.rs:8859`) carries a message in
shaped-budget fragments, paced by the same timer, so the link stays one size and one rate. A witness carries 1 MiB
(`tests/link_shaping_e1.rs:727`, at a raised test rate). Today it is the last resort for a peer no unshaped link can
reach. Rung 3 makes it the only path, and a 256 KiB chunk fits one window at every class.

Two defects stand:

- **It starves the rows.** The fallback shares the link's FIFO queue (`enqueue_within_queue`, `link_shaping.rs:1367`) and
  feeds up to the queue's 4,096 frames at once, about 66 MB. A message sent behind a large file waits behind all of it and
  times out at 60 s. "A row behind a file is a starved row": E3 is required.
- **A long message restarts from zero.** A link drop means the whole envelope is retried (`run_bulk_fallback`,
  `reticulum.rs:14981`). Files are safe because each 256 KiB chunk is its own envelope, so a drop costs at most one chunk.
  A chunk pull's own timeout is unverified at these rates [inf].

### 2.4 The numbers per class

Frame 1,400 B since CC 5.4.3 rc17 (CIRISConstitution a3dd97a; edge 44.1.1, CIRISEdge#963); it was the
16,272 B TCP MDU (`FSD/TRANSPORT_TIERS_MODEL.md` §1), where the gaps were 2.3 / 5.8 / 11.6 / 47 s. The rate
is a byte rate, so only the first byte moved: volumes take the same time at either frame. A link runs at the
lower class of its two ends: a server talking to a phone on Wi-Fi moves at `phone-wifi`.

| | `server` | `home` | `phone-wifi` | `phone-cellular` | Basis |
|---|---|---|---|---|---|
| Timer gap: the wait for a row, mean | **0.2 s** | 0.5 s | 1.0 s | 4 s | frame ÷ rate, CC 5.4.3 rc17; less at the Reticulum base frame |
| 95th percentile wait | 0.6 s | 1.5 s | 3 s | 12 s | Exp, 3 gaps [inf] |
| Real bytes moved | 3.5 KB/s | 1.4 KB/s | 700 B/s | 175 B/s | ρ × rate |
| Window's reach | 1,500 frames, 2.1 MB in 10 min | 840 KB in 10 min | 420 KB in 10 min | 630 KB in 60 min | `LINK_SHAPING_COST.md` |
| 64 KiB row (48 frames) | 10 s | 24 s | 48 s | 3.2 min | every fire real while queued |
| 1 MB by slow path | **5 min** | 12 min | 24 min | 95 min | sustained; a quiet link's first window is up to twice as fast |
| 10 MB by slow path | **48 min** | 2 h | 4 h | 16 h | sustained, link up throughout |
| Cover, one link, month, each way, on the wire | 20.9 GB | 8.4 GB | 4.2 GB | 1.0 GB | `FLEET_DEFAULTS`: budget × 1.154 (seal, packet header, proof) |
| Cover, eight links, month, each way, on the wire | 167 GB | 67 GB | 33.5 GB | 8.4 GB | same; both ways is double |
| Battery | n/a | n/a | not measured | not measured | see below |

Cover is spent "whether or not anything real is sent" (CC 5.4.3). The eight-link figure is the ceiling. A
phone holding two links costs a quarter of it [inf]. A pooled shaped lane idle for 120 s closes
(`DEFAULT_LINK_POOL_IDLE_BOUND`, `reap_idle_pooled_links`), so cost follows open links.

**Battery and data on a phone: unmeasured, [inf].** With eight links on `phone-wifi` a frame leaves every 1.5 s, and on
`phone-cellular` every 5.8 s; a radio given that traffic does not sleep (CC 5.4.6 item 1: "a radio that never sleeps"). The
wizard says "uses more battery" with no figure until there is a measurement.

**A phone's cover stops while it sleeps.** `enter_background` suspends the transport, and suspend closes every link
(`edge:fix/v44-first-contact src/transport/reticulum.rs:18681`). So a phone pays for its awake hours, not the month, and the
figures above are a ceiling. **What that reveals:** the links close and reopen when the app does, so a watcher learns when the phone
is awake and when it sleeps. Shaping hides what happens inside a link, not this (CC 5.4.3 item 5).

**Catch-up, measured at `server`:** a four-node bootstrap takes 53 s unshaped; shaped, rounds are p90 35 s,
p99 165 s, max 221 s (`LINK_SHAPING_COST.md`). Those are per round, so they are not directly comparable
with the 53 s total, and no shaped whole-bootstrap time is on record. Scaled by rate, a round's p99 is
about 7 min at `home`, 14 min at `phone-wifi`, 55 min at `phone-cellular` [inf, linear]. Nothing below
`server` has been measured.

---

## 3. Rung 3 consequences

### 3.1 Peers who do not shape: unreachable directly, for everything

The link runs at the lower of two offers, so a node requiring shaping closes the link when the peer is
`off` (CC 5.4.3 item 1; `peer_offer`, `link_shaping.rs:2185`; witness `tests/link_shaping_e1.rs:508`,
`link_shaping_refused_unshaped_peer`). That is every feature, text included, because no link exists.

- **Who that is.** At fleet defaults only servers shape, so a shaped-only home or phone reaches servers
  and people who also opted in. Every other contact is out of direct reach. **This is the largest
  consequence on the ladder and it was not in the direction as given.**
- **Contact requests too.** A contact request to a peer who does not shape fails the same way: the link
  through a forwarder is still a link to them. A mailbox would avoid it (CC 5.4.6 "a mailbox it keeps for
  a sleeping peer"), but that path is deprioritised (#169) [inf for this use].
- **Rooms survive partly.** A room's rows reach you through any member who shapes, so a room with one
  shaping member still flows. A 1:1 chat with a non-shaping contact has no such carrier. [inf]
- **The wizard must count them.** Before rung 3 is chosen on a node that has contacts: "4 of your 11
  contacts can't be reached in this mode". Knowing that needs a per-peer shaping fact (E8). At first run
  there are no contacts, so the wizard says it in words.

### 3.2 Eight peers, and a full node

- **Eight links at a time** (CC 5.4.3 the bound, CIRISEdge#952). A node set to shaped-only or to the
  anonymous tier refuses a ninth shaping peer with referrals, and that peer waits for a slot to free; a
  lane idle for 120 s frees one. Any other node runs the ninth link unshaped, and a shaped link is never
  run below its class. Relay offering spends the same slots
  (§5.4).
- **A full peer.** Past its eight, a peer refuses your row link and offers a bulk link "where one exists"
  (CC 5.4.3). A shaped-only node has none, so that peer is unreachable until a slot frees or a referral
  homes you elsewhere. "Homing does not re-address a row" (`LINK_SHAPING_COST.md`): the refused send still
  fails by name for 120 s. Displacement is #939, the fallback order #935.
- **Rooms and the eight.** Once scoped links are shaped (E4), a room's direct members may take slots too [inf]. Q16.
- **The class leaves less room on a phone.** Rung 3 at `phone-cellular` is possible, and it is the extreme
  case: 175 B/s real toward each peer, up to 8.4 GB a month each way at the cap on the wire, 4 s before a
  row's first byte and about 3 min for a 64 KiB row (§2.1). Lawful, stated, and not recommended; the wizard says so.

### 3.3 What rung 3 means, normatively

A node at rung 3 (setting `net.shaped_only`):

1. MUST NOT carry any row, file or media on an unshaped link in either direction, except rule 5.
2. MUST close, by name, an identity link whose peer does not shape, dialled or inbound.
3. MUST refuse calls and live streams by a stable token, and say so at the choice (CC 5.4.3 Two planes, as
   the CC applies it to anonymous mode).
4. MUST carry files only by the slow path, chunk by chunk, within the row budget, rows first.
5. MAY open one unshaped exchange to add a device (the pinned first contact). The client states it. The
   frames before shaping starts on any link (the key exchange, the route fetch, the offer) are inherent.
6. MUST NOT silently fall back. Every refusal surfaces, in the person's words, against the contact.

**Scoped lanes.** CC 5.4.3 item 4 is normative: the derived-address link itself is shaped, at rungs 2 and 3. A scoped body MUST NOT
move onto the identity link when a direct path exists (CC 5.4.6). So rule 1 is met by E4, not by closing scoped lanes.

### 3.4 Does shaped-only exist today?

**Partly.** `ShapingPolicy::require_shaped_links` (`link_shaping.rs:192`), exposed as a PyO3 argument
(`src/ffi/pyo3.rs:6005`). No host sets it. Its behaviour:

| Case | What happens today | Rung 3 needs |
|---|---|---|
| I dial a peer who answers `off`, or does not answer in 10 s | Closed by name (`offer_shaping`, `reticulum.rs:12006`) | The same |
| A peer's explicit `off` offer reaches me | Closed by name | The same |
| A peer dials me and sends no offer (every `off` peer: `offer_shaping` returns early, `reticulum.rs:11931`) | **Nothing happens; the link runs unshaped.** The responder only reacts to an offer. The comment at `reticulum.rs:11727` ("a peer that requires shaping closes it on its side") is not what the code does. | A deadline, then close |
| I send bulk | **A bulk link is dialled, no offer** (`settle_plane`, `reticulum.rs:11737`) | Refuse the dial, so the existing fallback runs |
| A peer dials me a bulk link | **Accepted, unshaped** | Close |
| A call or stream | **Opens**; only the tier refuses media (`media_allowed`) | Refuse by name |
| Scoped lane | **Opens**, never shaped | E4: shaped, or it does not open |
| Turning it on with unshaped links running | **They stay**: `set_policy` only examines shaped links (`link_shaping.rs:1644`) | Close them |

---

## 4. Rung 4: a node in anonymous mode

**Eric's ruling, now CC 5.4.6 item 1 (rc17 ae86ea0).** Using the tier and being anonymous are one thing, **anonymous mode**, "a property of a node and not of a
publication". Three rules bind this rung:

1. **Held.** "The mode is offered only when rooms can be carried through the tier … until rooms ride the tier a client lists the mode and does not enable it." The wizard lists it
   and does not enable it.
2. **A separate, dedicated identity.** "a fresh user key and node key with no self roster shared with, and no row linking it to, any announced identity of the person, who MAY later
   prove the two are theirs by a signed statement under both keys and is never found out otherwise."
3. **First run or never.** "an announced node never enters anonymous mode and an anonymous node never announces; a person who wants both runs two nodes."

So rung 4 is **"set up this device as an anonymous identity"**: a first-run choice, made before identity creation because it decides the keys, irreversible, and no toggle on any
existing node. It holds only layer and rendezvous links, all shaped, so shaped-only is implied. Everything below describes the mode as the text stands; **no one can be in it while it is held.**

### 4.1 What it protects

**The path from what you publish to you.** "The tier carries federation-scope publication. Other scopes are not routed through it." (CC 5.4.6
item 2.) It "hides who published a federation-scope item from the nodes that store it, from the directory, and, with shaping, from an observer of
the network"; "the tier hides the path from the pseudonym to the person, which is the whole of what it hides" (item 9).

**The goal, which is not a present claim.** Eric, 2026-11-04: "yes we need rooms over onion, that is the goal for the onion tier, the way the mesh
works now the shaped traffic provides us a self-growing mesh to carry the onion traffic". Rooms over the onion are what would let a node in anonymous
mode into any room, and since item 1 they are also **the condition for offering the mode at all**. They are not what the code does. **Normative: the wizard states only what is true at activation, never the
goal as a present claim.** Nothing user-facing mentions rooms over the onion until CIRISConstitution#202 is ruled and they work.

For the record (numbers belong to `FSD/ONION_ROOMS_MODEL.md`):

- **CC scope.** Item 2 limits the tier. The carrier rule is closer: "a relay in the Anonymous Tier that has not opted out" counts as a carrier that has
  said yes, though the next sentence still limits a scoped body to "a consented contact or, as last resort, a serve seat".
- **The carrier mesh.** Relays must shape, so the self-growing mesh grows only as people move to rung 2. At fleet defaults only servers shape. Uptake of rung 2
  and helping is the supply for this goal. That is a reason to state those choices honestly, not to pre-select them.

### 4.2 Features: fewer than rung 3

**"Same features as shaped only" is false: it is fewer,** as the text stands today, before #202. When the hold lifts, rooms ride the tier by definition, so this table and the option's
wording are rewritten then. A node in anonymous mode keeps public reading and pseudonymous publishing.

| | Rung 3 | Rung 4 |
|---|---|---|
| Identity | Announced, your own | **A separate one**, with fresh user and node keys. It never announces. Everything published is signed by a fresh pseudonym with no occurrence and no standing, read as a stranger's (item 9). The person MAY later prove the two identities are theirs by a signed statement under both keys; nothing else links them |
| Rooms | Over shaped links | **None until #202.** It cannot join a room over a direct or forwarded link, "since a member would then hold its address" (item 1) |
| Ordinary contacts | Those who shape | **None under an announced identity, until #202.** It has no route to hand. A contact exists only through its rendezvous, and it is reached there, answers through its own circuit, and never goes direct; the announced peer's client says so (item 10). The mailbox is not built (CIRISPersist#1149) |
| Calls, streams | Refused | Refused: `onion_anonymous_no_media` (`edge:src/onion/runtime.rs:202`; `av_call.rs:373`; CC 5.4.3 Two planes) |
| Files, images | Slow path | Not through the tier today [inf]; the CC says it "publishes and reads rows" |
| Blocking | Normal | Readers may block a pseudonym like anyone; "a pseudonym has no reputation and can be blocked like anyone" may be said (`formal/anonymous`) |
| Public posts | Signed by you, with your standing | Through the tier, pseudonymous, no reputation. An item may span packets on one route within the hour (item 3 pins packet length, not one packet per item). A body is 8,174 B (`packet.rs:87`) and a pseudonym row carries its roughly 17 KB key record inline (`ONION_TIER_MODEL`, line 82), so a row is about three packets [inf]. That is a fit cost, not a bar. Edge builds one packet today (E9) |
| Your other devices | Normal | **None.** No self roster shared with any announced identity. Add-device does not apply: a person who wants both runs two nodes |
| Agent, services | Normal | **None as the rule stands.** See below |
| Helping | Your choice | **Never a relay** (the CC's answer, Q17; rc17 at 330094e does not yet carry the correction) |

**Service access.** An anonymous node never announces, and Join's rule is plain: "A node that does not announce gets no service access on the mesh and no agent services" (`peer.rs:523`).
As the rule stands, **a node in anonymous mode gets neither**, and the choice says so before keys exist. The Join announce control and the AI step do not apply to it: they are not shown.
Whether that stands is Eric's, at the hold's lift (§8).

### 4.3 Performance

Publishing, three hops with a 2 s mean hold per hop (`mix_mean_delay_ms`), per packet:

| Class, relays at `server` | Frames (12 per crossing at 1,400 B) | Holds | One packet [inf] |
|---|---|---|---|
| `server` | 3 × 12 × 0.2 s | 6 s | **13 s** (model: 13.8 s, `ONION_TIER_MODEL` §e) |
| `home` | 12 × 0.5 + 2 × 2.4 s | 6 s | **17 s** |
| `phone-wifi` | 12 × 1.0 + 2 × 2.4 s | 6 s | **23 s** |
| `phone-cellular` | 12 × 4 + 2 × 2.4 s | 6 s | **59 s** |

A three-packet row adds two gaps at the publisher's class [inf]. Seat relays would shorten the inter-relay gaps. Targeted delivery to a rendezvous is six hops plus a mailbox fetch:
41 s at `server`, 135 s at `phone-wifi` **[model]**. The packet is 15,296 B, twelve 1,400 B frames (it was one at the 16 KB frame; the time a packet takes is its bytes over the rate either way). **So "performance drops further" is true of everything this node does**, since everything goes through
the tier.

### 4.4 What it does not hide

Item 8, stated in the choice: a relay can count packets sent to one rendezvous in a period; the set you hide among is only the traffic your relays carry in a window, "with few users per relay the
anonymity set is small"; below ten answering relays per layer the client says the set is small (`small_set`). It does not hide which links the node holds, or that it runs the tier. A pseudonym is not no
one: "a sender is never unattributed" (item 9). Two pseudonyms are not linked by the tier, but what you write may link them.

**Never later.** "a node that has announced holds a route and an address others have held, and no later act unlearns them" (item 1). That is why there is no path from rungs 1–3.

### 4.5 Activation gates

The mode is **held** until rooms can be carried through the tier (item 1; CIRISConstitution#202, E13). That hold comes first. The tier is also **dormant in v44** (Eric, 2026-11-02), and these seven must hold as
well before the wizard may enable it:

| Gate | State |
|---|---|
| CC pins the packet (item 3) | Not pinned. `docs/onion_packet_wire.md` is edge's submission |
| Relay floor | Nine relays with at least three conferred (§1 row 13). `edge:FSD/ONION_ROUTING.md`: one today |
| Hop key | `HOP_KEY_SOURCE = TransitStandIn` until persist 61.0.x (`onion/hop_key.rs:43`) |
| Fold reader for candidates | Not built; needs `INFRA_RELAY` and the markers |
| Exit door, pseudonym gate, rendezvous row and mailbox | Pending persist; CIRISPersist#1149 open |
| A caller | `onion_publish` has no caller in the tree and no PyO3 or server route (`grep`, 2026-11-04) |
| Over-the-wire loopback | Not done |

**What the wizard shows until then:** the listing of §6.2, disabled, with its reason line. It records nothing and never shows a working control.

**The code's "active" falls short of the mode.** `OnionPolicy::enabled` is a runtime flag on any node, and `onion_set_enabled` is a live toggle. Neither fresh keys nor never-announcing is enforced, and an announced node could
set it. E16 removes that path: the mode is fixed at identity creation.

---

## 5. Privacy level: what each rung hides, from whom

### 5.1 The list that shrinks

**What stays visible:**

- (a) which links exist, and who is reachable where
- (b) that your groups exist, their rough size, and when they change
- (c) timing and volume on unshaped links
- (d) who published a public post

| Rung | Still visible |
|---|---|
| 1 Standard | a, b, c everywhere, d |
| 2 Shaped | a, b, d; c on every link that is not shaped: calls, files, peers who don't shape, scoped lanes until E4 |
| 3 Shaped only | a, b, d |
| 4 Anonymous mode | a, b, for the layer and rendezvous links it holds. Its groups are none today |

**Nothing on the ladder removes (a) or (b).** CC 1.13.3.1; 5.4.3 item 5: "Shaping hides timing and volume
inside a shaped link, not which links exist".

### 5.2 By who is looking

| Who | Every rung | Rung 2 adds | Rung 3 adds | Rung 4 adds |
|---|---|---|---|---|
| **Someone watching your connection** | Cannot read what you say (AEAD + DEK). Sees your links, when they open, your groups' traffic (1.13.3.3) | On shaped links, not timing or size. Sees a constant stream at a rate that shows only device class | No call or file to see, because none happens. Unshaped links no longer mark you: you are "a node that shapes every link" (item 5) | Sees only layer and rendezvous links; onion packets are shaped-frame bodies (item 5) |
| **A global observer of every link** | Opt-in only (1.13.3.4). Graph, timing, group size and churn available | Timing and size hidden on shaped links only. Not unobservability | Not unobservability either: the graph of links remains | May be told: a passive observer of every link does not learn who published a federation-scope item through the tier, among the traffic those relays carry (item 8) |
| **A contact** | Sees everything you send them, and your route once they accept | Learns the real share, bounded by ρ, and the timing of your real frames smeared over W (`SHAPING_RHO_W`) | The same | No ordinary contacts. One reached at a rendezvous learns the pseudonym only |
| **A relay or forwarder** | Link ciphertext; that a link crossed it (5.4.6) | What a wire observer learns, no more | The same | Each onion hop learns only the next hop (item 3); can count packets to one rendezvous (item 8) |
| **The canonical or any node holding your rows** | "reads every attestation row and every structural fact it holds"; cannot read sealed bodies (1.13.3.3) | Unchanged | Unchanged | Sees the last relay, never the publisher (item 5). Holds no announced identity for this node |

### 5.3 The words

Per CC 1.13.3.3, every representation states the default protection and its residual limit. **No comparisons of any kind:** no
product names, no "more private", and between rungs no "fastest", "a bit slower", "slowest". State the number. No absolutes the CC does
not give: nothing "doesn't lead back to you", nothing "hidden everywhere". Placeholders are §6.6's list.

- **Everything on.** "What you say in your groups is encrypted and outsiders can't read it. Someone watching the network can see who your
  device connects to, that your groups exist and roughly how big they are, and when you are active."
- **Hide when I talk.** "This protects you with others who also chose this. On connections where both sides chose this, a watcher can't see when you send or how much. A watcher can still see who
  you connect to, your calls and large files, and anything on a connection beside it. Messages wait about {gap_s}. It uses up to {gb_month_cap} GB a month each
  way, whether you send anything or not."
- **Always hide when I talk.** "A watcher can't see when you send or how much, with anyone you can reach. It can still see who you connect to and that your
  groups exist. No calls or streams. A 1 MB file takes {file_1mb_s}. {contacts_unreachable} of your {contacts_total} contacts can't be reached: only people who also
  chose this can be. You can connect through others, but others can't connect through you."
- **A separate anonymous identity (listed, held).** Only what §6.2 shows. The full wording is written when the hold lifts, because rooms change it. It may then say "a pseudonym has no
  reputation and can be blocked like anyone".

A phone's option adds: "While your phone sleeps its connections close, so a watcher can see when it is awake. It uses data only while the app is awake."

### 5.4 Relay offering: a separate choice that interacts

Relay offering is "offers to carry for others", on by default for servers and homes and for a phone only on
Wi-Fi while charging (`relay_offering`, `edge:src/onion/policy.rs`; CC 5.4.6 item 1).

- **The concession.** CC 5.4.6: "an owner who turns relay offering on hands the node's route to strangers for
  first contact and consent, three at a time to peers a full node refuses … a referred stranger learns such a
  node's route, and roughly where it is, without being a contact." On a home connection that is the home's
  address and rough location. It must be said at the choice.
- **It is tied to shaping.** Free slots are reported only on shaped links (`capability_body`), so a home at rung
  1 is never referred, whatever the default says. **Moving to rung 2 is what starts the referrals**, and it does
  so silently under today's default. The wizard shows relay offering on the same screen as the rung, right after
  it, whenever rung ≥ 2.
- **It spends the same eight slots.** A referred stranger holds a slot your contacts could use. **Settled: on at rung 2, off at rung 3.** The rung 3 option says "You can connect through others, but others can't connect through you.":
  a rung 3 node is a net consumer, fine while rare (`formal/transport_tiers`).
- **It must not contradict announce.** The CC refers "announced nodes", and "announces" in 5.4.6 means an owner
  binding at federation scope. The code's test is presence in the peer table (`pick_referrals`,
  `reticulum.rs:14755`), which is the Reticulum announce [inf]. A home with `net.announce_ownership` off and relay
  offering on would be referred while "never listed". Rule: the choice is not shown on an unannounced node (it reads the Join answer) until E10 checks the binding.
- **`FSD/CIRIS_MESH.md` §3.2 is stale here:** it says the endpoint "MUST be served only to the offering node's
  send set". CC rc17 and Eric's 2026-11-04 ruling supersede it for referrals.
- **Phones: a gap, not a conflict.** CC 5.4.6's device policy says a phone relays on Wi-Fi while charging; the text does not change. v44's phones are client-only (`compose::client_only_wanted`): no listener, nothing to
  offer. The text is ahead of the code. The helping choice is not shown on a client-only node, and **referrals must not count a phone until it can relay** (E14). Today `relay_offering` still reports a phone's slots.
- **Anonymous relaying is different.** Tier relaying is default-on so that "running a relay identifies no one" (1.13.3.3 guidance). It is stated as part of
  rung 4, not this choice.

---

## 6. The wizard contract

### 6.1 The questions Client asked

1. **The default is per class.** Home and phone: rung 1 preselected. Server: rung 2 preselected, subject to the
   rollout gate (§6.11). A server operator sees the same ladder with its cost stated.
2. **"Disable anything but shaped traffic" is a new control**, `net.shaped_only`, shown as rung 3. It is not
   announce, which stays one control on the Join step.
3. **Calls at rung 2 still run, unhidden,** and the privacy list says so.
4. **Onion and anonymous mode are one thing** (CC 5.4.6 item 1). It is not an option on the ladder: it is a first-run choice of identity, listed and held (§6.2).

### 6.2 The choices

The wizard is a sequence of `choice` items in the `self` circle. Position: a new step **Privacy**, immediately after
**Join the federation** (`YOU → JOIN_FEDERATION → PRIVACY → AI → COMPLETE`; without AI,
`YOU → JOIN_FEDERATION → PRIVACY → COMPLETE`). It is a step of its own because Join already carries four questions
and this one needs a live preview.

| Step | Choice | Options | Preselected | Control |
|---|---|---|---|---|
| Join | Announce (the substrate's words; **unchanged, one control**) | on / off | **On** (`announceOwnership = true`, `SetupState.kt:844`). Not offered to minor or undeclared accounts | `toggle_announce_ownership`, `net.announce_ownership` |
| Privacy | The rung | rungs 1–3, §6.3 | Per class, §6.1 | `net.shaping_opt_in`, `net.shaping_opt_in_cellular`, `net.shaped_only` |
| Privacy | Helping others connect | on / off | §6.8 | `net.relay_offering` |

The radio is one control over those keys, so a contradictory combination cannot be chosen, and the rung is read from them, never stored: rung 1 has both opt-ins off, rung 2 has at least one on with
`net.shaped_only` off, rung 3 has `net.shaped_only` on and both opt-ins on. On a phone the two network controls replace rung 2's single on-state (§6.8). The `net.*` names
are server's. The helping choice is shown only when rung ≥ 2, the Join answer was announce on, and the node is not
client-only (§5.4).

**Item shape.** The node serves absolute lists per option, never deltas; the client computes nothing but the
highlight of what differs from the selected option.

```yaml
kind: choice
circle: self
id: privacy.rung
options:
  - value: shaped                 # internal, one stable tag per option
    title:    {id: ..., text: ...}   # the disclosure's shape, §6.6
    benefit:  {id: ..., text: ...}
    downside: {id: ..., text: ...}   # never empty, the default option included
    params:   {gap_s: 5.8, gb_month_link: 7.3, gb_month_cap: 58.1, file_1mb_s: 714}
    lists:
      features:    [{id: ..., text: ...}]
      performance: [{id: ..., text: ...}]
      privacy:
        hides:         [{id: ..., text: ...}]
        does_not_hide: [{id: ..., text: ...}]
    available: true
    unavailable: null             # {id, text}: the reason line, when available is false
```

**Rung 3 disabled** uses `available: false` and a reason line: "This needs more of the network to take part first." The reason says where the thing stands and why, never who is big enough
(`docs/five-year-old-test.md` 1.7, 1.8).

**Rung 4 is listed before identity creation, not here.** It decides the keys, so it comes before `mintUserIdentity` (`POST /v1/self/identity`) on the YOU step, after the age band so that a minor
never sees it: a held line, tag `txt_setup_anonymous_identity`. It is served as a `choice` item with one option, `available: false`, title and reason only: no lists, because rooms will change them.

- **Title:** "Set up this device as a separate anonymous identity"
- **Reason:** "Not ready yet. Helpers on the network today: {relays_answering}."
- **Note:** "You can only choose this when you first set up a device, and it can't be undone."

The count is a fact, not the condition: the mode stays held until rooms ride the tier and all seven gates of §4.5 hold, so the reason never implies the count is what is missing. A client that cannot read the count
shows the line without it. When the hold lifts, this becomes a real decision, stated before keys are made, with the wording of that day; choosing it skips the Join announce control, the helping choice and the AI step, and
implies shaped only.

**Next.** Selecting previews from the served table and writes nothing. **One write, on Next.** Back re-reads. Next works on
the preselected rung without a touch, because its cost is on screen.

**The quoted obligation, CC 5.4.3 (rc17 at 2ad9675):** "**The choice is explained before it is made (normative).** A client that offers the setting states the give and the take in plain words at the moment of choosing: what shaping hides (the timing and size of what rides the shaped link, from an observer of that link) and what it does not (the fact of the link, and anything on an unshaped link beside it); the latency it adds, stated as the link's own agreed mean, which is the frame size over the class budget: at the 16 KB frame of a TCP link about 2.3 s on a server, 5.8 s at home, 11.6 s on a phone on Wi-Fi and 47 s on cellular, and a fifth of that at the Reticulum base frame, so a stated cost never understates the served one; and the cover traffic it costs (the byte budget below, spent whether or not anything real is sent). A default is never silent about its cost."

### 6.3 The three lists, per option

The names are proposed for `docs/five-year-old-test.md` and are settled before translation. "Shaped", "shaped only",
"link", "relay" are internal words and never reach the screen. Options state numbers, not comparisons: no "fastest",
"a bit slower", "slowest". Numbers shown are `home`; each is a parameter.

| | 1 Standard | 2 Shaped | 3 Shaped only |
|---|---|---|---|
| **Name on screen** | **Everything on** | **Hide when I talk** | **Always hide when I talk** |
| **One line** | Everything works. What you say is private. When you talk is not. | Everything works. On connections where both sides chose this, a watcher can't see when you talk. | A watcher can't see when you talk, with anyone you can reach. No calls. Files take a long time. You can only reach people who also chose this. |
| **Benefit** | A message arrives in under a second | A watcher can't see when or how much you send to people who also chose this | No call or file shows a watcher what you are doing, because there are none |
| **Downside** | A watcher can see when you are active | Each message waits about {gap_s}. Uses data whether you send or not. Calls and files can still be seen | No calls or streams. A 1 MB file takes {file_1mb_s}. People who didn't choose this can't be reached |
| **Messages, rooms, reactions** | Yes | Yes | With people who also chose this |
| **Calls, streams** | Yes | Yes, a watcher can see them | **No** |
| **Files, images, voice notes** | Yes | Yes, a watcher can see them | **Yes: 1 MB in {file_1mb_s}** (12 min) |
| **People who didn't choose this** | Yes | Yes, not hidden | **No** |
| **Connected at once** | No limit here | 8 hidden; others not hidden, or refused for a while | **8** |
| **Public posts** | Yes | Yes | Yes |
| **A message arrives in** | Under a second | {gap_s} (0.5 s) with people who also chose this | {gap_s} |
| **A 1 MB file** | Depends on your connection | Depends on your connection | {file_1mb_s} |
| **Finding someone new** | §6.4 | §6.4 | §6.4 |
| **Catching up after a long time away** | 53 s (4 nodes, measured at `server`) | One round up to about 7 min [inf] | Large batches take longer |
| **Data** | What you use | Up to {gb_month_link} GB a month for each connection, {gb_month_cap} GB at most, each way, whether you send or not. Phones: only while the app is awake (§6.8) | Same |
| **Service access, agent** | With announce on | Same | Same |
| **Battery on a phone** | Normal | Uses more, not yet measured | Same |
| **Hidden from outsiders** | What you say | + when and how much, on connections where both sides chose this | + when and how much, with everyone you can reach |
| **Still visible** | a, b, c, d | a, b, d; c for calls, files and people who didn't choose this | a, b, d |

The base rung's `downside` MUST NOT be empty. The (a)–(d) entries are served as sentences (§5.1, §5.3).

### 6.4 Finding someone new, in the performance list

| Stage | Rung 1 | Rungs 2, 3 |
|---|---|---|
| Found at all | Needs them to announce. An unannounced person is found only by a code they gave you. | Same |
| Lookup | A subject Pull costs 5 of 60 lookups a minute, so 12 a minute at most; a throttled answer looks like "not found" (#936, #937) | Same, plus two gaps per round trip: 12 s `home`, 23 s `phone-wifi`, 93 s `phone-cellular` [inf] |
| Request reaches them | Seconds, over the canonical's forwarding [inf] | One gap if they shape; rung 2 no added wait if not; **rung 3 refused if not** |
| They accept | A person, then one link time | A person, then one gap |
| Direct link | Only after acceptance | Same; shaped if both shape |

No end-to-end first-contact time has been measured at any rung. The list gives the gap, not a total, until one has been.

### 6.5 Announce crosses the ladder

Announce answers *who can find me*; the rung answers *what a watcher learns*. Rungs 1–3 are available either way, and the helping
choice reads the Join answer (§5.4). An anonymous identity never announces and never reaches this control (§4.2).

**"Base is all features" holds only with announce on.** The wizard preselects on because "A node that does not announce
gets no service access on the mesh and no agent services" (`mesh.announce_requirement`, `peer.rs:523`). The layer below,
`net.announce_ownership`, defaults false (`config_reconcile.rs:207`) for a node no wizard has touched. Off, a bare
federation ID does not find the node. **Two costs (CC rc17, 5.4.6, 4.4.3.2):** it is reached only by its node code, handed directly by its owner, and it cannot take part in a public group, because open admission needs a live federation-scope binding: the room's rows are served to strangers. An anonymous node is unannounced, so it is never in a public room either (`public_room_needs_announce`, `formal/anonymous`). Its owner's own nodes still reach it. CC 5.4.6
makes announcing a MUST only for serve seats; the wider rule is the service's. So announce off is a real choice with a
real cost, on the Join screen in the substrate's words, and rung 1's feature list assumes on.

**Two consents, not one (Eric, 2026-11-04): "1) announce (be found) 2) share traces".** Announcing authors a `consent:replication` grant to each canonical with the prefixes `ownership:` and `self:delegates_to:`. That makes the canonical a replication peer; Key, IdentityOccurrence and TransportDestination reach it by publish set and announced reach, without reading the grant. The canonical therefore holds who owns the node, its keys and how to reach it. It does not get traces unless the person shares them. **That last sentence is not yet true:** prefixes place a row by the union of all grants (`resolve_row_placement`) and the serve path tests send-set membership, so one default contact grant carrying `trace:` promotes traces to a canonical that is a consent peer with `infra:serve` [read, not witnessed]. Server owes: no grant carries `trace:` unless that consent is on, and turning it off narrows existing grants. No user-facing text claims it until then.

### 6.6 Who supplies what

- **One owner: the node.** It serves the table, in the disclosure's envelope (`{"data": …}`). Reading:
  `GET /v1/setup/privacy-choices`.
- **With AI there are two setup surfaces.** `consent-disclosure` is on the node and on the agent
  (`routes/setup/providers.py:85`, which calls `ciris_server.consent_disclosure()`), and the wizard talks to :8080. The agent
  adds a thin read route the same way, over `ciris_server.privacy_choices()`. **The agent has no write route.** A proxied
  write would reach the node from loopback and defeat the check below, so the client writes to the node URL.
- **Writes:** `POST /v1/setup/privacy-choices`. Before the claim it carries `require_loopback`: the node binds
  0.0.0.0:4243, and a LAN peer must not change someone's posture. After the claim it needs an owner session.
- **Strings** use the disclosure's `{id, text}` shape: locale wins, substrate English is the fallback, never a raw key.
  `DisclosureString` has no params; S2 defines them, with the English text carrying the same placeholders.
- **One placeholder list, and the server sends raw values; the client formats for locale:** `gap_s`, `gap_p95_s`,
  `gb_month_link`, `gb_month_cap`, `file_1mb_s`, `file_10mb_s`, `contacts_total`, `contacts_unreachable`,
  `relays_answering`. A phone's option carries a second set with `_cellular`. `check_localization_sync` enforces parity across
  all 29 languages.
- **The node reports the link class.** The client does not know it. A phone host reports its facts through
  `shaping_set_device_state`, and **those facts reach the node before the table is read**, or a phone sees the wrong class.
  The table is evaluated for the class before serving.
- **Edge to server:** a typed status with class, rate, gap, shaped links, free slots, and `OnionStatus` including
  `confines_media`. Edge has `ReticulumTransport::onion()`, `shaping_policy()`, `set_shaping_policy()`, `set_device_state()`
  in Rust and `onion_status()` in UniFFI, none through PyO3 or `Edge` (E8). Server sees anonymous-mode refusal as the token.
- **Queue:** the wizard runs before a session exists, so these are not rows on a live circle. Same item shape, served at
  `/v1/setup/*` before claim, carried into the `self` queue after (CIRISServer#851, not built).

### 6.7 When a choice applies

- **The choice applies on Next, before the claim.** It is a local transport setting, nothing needs signing, and waiting would
  leak the first links. The wizard says what has already happened: the node may have connected before this screen, and links
  opened earlier are not undone.
- **The hold is a file under the home, read at compose,** so the rung survives the no-AI process replacement, a crash, or a phone
  kill before the claim.
- **The record follows the claim.** After it, the choice becomes an owner-signed `config:*` row read at compose, and the row
  supersedes the file. Consent is authored after the claim because `author_consent_embedded` refuses on an unclaimed node; this
  differs in timing and that is deliberate.
- **Per node, never per person.** A phone and a desktop can differ. Add-device inherits nothing silently.
- **The rung 4 line needs no hold.** It records nothing. When enabled, the choice is the key setup itself.
- **Add-device waits until after the join.** CSD-093 asks no age band, so the device cannot know the age. The step comes after
  the join; until then the device is at its class default, with no announce and no helping.

### 6.8 Per device

| | Home | Phone on Wi-Fi | Phone on cellular | Server |
|---|---|---|---|---|
| Preselected rung | 1 | 1 | 1 | 2, gated (§6.11) |
| Class | `home` | `phone-wifi` | `phone-cellular` | `server` |
| Shows | §6.3 | Wi-Fi and cellular figures | Same, cellular first | §6.3, server figures |
| Rung 3, once offered | Yes | Yes, on Wi-Fi | Yes, "a message waits about 4 s, up to 8.4 GB a month each way" | Yes |
| Helping others connect | On at rung 2, off at rung 3, if announced | **Not shown**: client-only (§5.4) | **Not shown** | On at rung 2, off at rung 3 |

**A phone pays only while awake.** `enter_background` suspends the transport, and suspend closes every link
(`edge:fix/v44-first-contact src/transport/reticulum.rs:18681`). So "whether you send or not" is true only while the app runs;
the month figures are a ceiling for a device awake all month.

**A phone chooses each network separately (settled, Q8).** `phone-wifi` and `phone-cellular` are separate classes the person turns on separately, so "on Wi-Fi only" exists. Today `DeviceState::with_network` keeps one
`shaping_opt_in` across a move (E17). A phone's option states each class's figures on its own control. The two controls appear under "Hide when I talk": selecting it turns Wi-Fi on and mobile data off, and turning both off returns to "Everything on", so that option with both off cannot be reached.

**Rung 3 is one setting for the node, never per network.** §3.3 binds the node: a Wi-Fi-only rung 3 would carry rows on unshaped links after a move to cellular, which is the fallback rule 6 forbids and which makes "Always" false. So choosing rung 3 turns both opt-ins on and shows no network controls, and the option states the cellular figures (§3.2). Leaving it for rung 2 keeps both on until the person changes them. Wi-Fi-only reveals only that the phone moved to cellular, which is already conceded (CC 5.4.3 item 5).

### 6.9 States

| State | Behaviour |
|---|---|
| Node-client path (`hasAgent = false`) | Same step, same route; the copy is the node's |
| Remote client | **Read-only before the claim.** The node's class and figures, labelled as the node's. The choice arrives as a pending queue item after the claim |
| Client-only node | The helping choice is not shown |
| Minor account | Announce not offered (CC 5.4.6, 3.4.13 Q5). Rungs 1–3 as for anyone. The anonymous-identity line and the helping choice are **absent, not greyed** (`five-year-old-test` 1.7, 3.8): a minor's node holds no federation-scope binding and does not publish at federation scope (CC 5.4.6, the text's reading), and helping would hand its route to strangers |
| Undeclared age | As minor |
| Node cannot serve the table | No fallback copy. "Your privacy settings couldn't be loaded; your device stays at its default." The default holds and the wizard may finish. The unanswered item waits in the `self` queue once #851 exists; **until then a notice on CSD-032's surface** carries it, so a default's cost is still stated |
| Rung 3 disabled (v44) | `available: false`, reason line, §6.2 |
| Anonymous identity listing | Shown only on a first run with no user key: absent on add-device, existing installs, a remote client, a serve seat (which must announce), and for minors. Held, §6.2 |
| Rung 3 with contacts, later change | Counts who becomes unreachable first (§3.1) |

### 6.10 Changing it later

Same items, same words, in CSD-032's surface. Rungs 1–3, helping and announce are reversible.

**Rung 4 is irreversible and has no later-change path, in either direction.** No setting, route or CSD-032 control enters or leaves it: an announced node never enters anonymous mode and an anonymous node never
announces (item 1). A person who wants both runs two nodes.

| Change | Effect on running links | Live? |
|---|---|---|
| Rung 1 → 2 | New links shape. **Running unshaped links stay unshaped until they close** (`set_policy`); E2 closes them, so the promise holds at once | Live, `set_shaping_policy` |
| Rung 2 → 1 | Shaped links stop and close, redial unshaped: a brief interruption | Live |
| Rung 2 → 3 | Unshaped links close; calls end, with a warning; transfers move to the slow path | Live (E1) |
| Rung 3 → 2 | New links may be unshaped | Live |
| Class change (Wi-Fi ↔ cellular) | A link above the new rate closes and redials; a lower one keeps its agreement until it closes | Live, `set_device_state` |
| Helping | Reports zero at once, peers stop ranking it. Forwarding itself (`transport.node`) is boot-structural | Offering live; forwarding on restart |
| Announce | **Two things.** `POST /v1/federation/announce` widens the owner binding rows live (`claim_remote.rs:1809`). The Reticulum announce's identity attestation is boot-structural (`config_reconcile.rs:324`) | Rows live; announce gate next boot |

Routes already handed out cannot be recalled: turning helping off stops referrals, and strangers who hold the route keep it. The
wizard says so.

### 6.11 Existing installs, and the server default (settled, Q15)

Eric's fleet default is on for `server` (CC 5.4.3), but the canonical has no wizard, and existing installs never see one.

- **The class default ships on.** A fresh install of class `server` gets rung 2 preselected, cost stated.
- **No flip on upgrade.** "A default is never silent about its cost", so S1 flips nothing. A node that already exists keeps shaping `off` until its owner chooses; an operator notice (startup log, CSD-032 surface, the queue once
  #851 exists) states the cost and the choice.
- **The canonical stays OFF until measured.** It is a per-node setting ("every value stays a per-node setting"). The bridge measures bandwidth and CPU there; turning it on is Eric's go. **Nothing claims the canonical shapes.**
- **Consequence.** While the canonical is off, rung 2 on a phone shapes toward nobody who has not also opted in, and pays only for those links; rung 3 could not reach the canonical at all. So rung 3 stays disabled at least until the
  canonical shapes.

### 6.12 Shaping under load shedding (settled)

`Edge::set_load_pressure` sheds down to chat and contacts (`FSD/CIRIS_MESH.md` §7.2; `edge:fix/v44-first-contact src/edge.rs:2265`).
**Does cover spend budget during shed? Yes, today and by rule.** No ladder lever touches the shaper (`src/load_ladder.rs`,
`apply_service_tier`), and that stands:

- **Cover is not shed.** A shaped link runs "each at the full rate of its class" and never "below its class" (CC 5.4.3), both directions or
  neither (item 2). Thinning cover would show a watcher the node's load, which is the thing shaping hides. And there is little to save: outbound
  is fixed at the cap, 56 KB/s at `server`, under 2 % of a vCPU per 1,000 peers **[model]** (`TRANSPORT_TIERS_MODEL.md` §8), and cover never reaches
  the DB.
- **A shaped link sheds whole.** Tier 1 (Admit-close): no new shaped links for non-obligation peers, and zero slots reported. A shaped-only or anonymous-tier node refuses them with referrals; any other node answers `off` with its referrals as a hint, and the link runs unshaped (CIRISEdge#952).
  Tier 2: may close shaped links, newest first, for non-obligation peers, never the owner's devices or a `seat` link. A closure is visible, and that is
  the accepted cost; it says a link closed, not how loaded the rest are. As built (`feat/v44-status-shed`): one link a second, links this node dialled are not closed, and a refusal at tier 1 carries `load_shed:shaped`.
- **Rows keep their place.** Tier 2 keeps chat and contacts on the shaped link at the unchanged real budget.
- **The slow path is gone** (CC 5.4.3 rc17). What followed read: B-pause stops it at tier 2 for non-owner peers (`CIRIS_MESH.md` §7.2), so a rung 3 file waits, by kind, and the row does not.
- The ladder and the shaper are not yet on one branch: `feat/onion-v44` has no `load_ladder`; v44 integration brings them together.

---

## 7. What must be built

**Edge**

| # | Item | Rung | v44? |
|---|---|---|---|
| E1 | `shaped_only`: deadline on inbound no-offer links, refuse bulk dials and inbound bulk, refuse media and streams by token, close unshaped links on turning on (§3.4) | 3 | Later |
| E2 | Close running unshaped row links on an upgrade | 2 | v44 |
| E3 | **Required by CC:** the slow path yields to rows; a row behind a file is a starved row | 3; also rung 2 NAT case | With E1; the NAT case v44 |
| E4 | **Required by CC 5.4.3 item 4:** shape the derived-address link at rungs 2 and 3. Today `shaping_applies_to` excludes it. Slots and chunk lanes per Q16 | 2, 3 | **Next release.** The wizard's line stays true ("on connections where both sides chose this"); the CC's register row states which links the server default covers until then |
| E5 | Bulk by size, not kind: small attachments ride shaped, up to the window's reach or the row limit | 2, 3 | v44 |
| E6 | `#935` fallback order and `#939` displacement | 2, 3 | Tracked |
| E7 | `ROW_LEAVE_MAX` scaled to the class, or a class row limit | 2, 3 on phones | v44 |
| E8 | A typed status surface for hosts: class, gap, slots, per-peer shapes or not, `OnionStatus`, through `Edge` | all | v44 |
| E9 | One publication spanning packets on one route within the hour (item 3 admits it; today `onion_publish` builds one). A fit cost, not a gate | 4 | Later |
| E10 | Referrals test the federation-scope owner binding | 2 | v44 |
| E11 | Correct `docs/LINK_SHAPING_COST.md`, the `FLEET_DEFAULTS` comment (timers), and the `reticulum.rs:11727` comment | n/a | v44 |
| E12 | Onion gates, §4.5 | 4 | Later |
| E13 | Rooms over the onion, after CIRISConstitution#202 and `FSD/ONION_ROOMS_MODEL.md`: scoped bodies through the tier, row fit, delivery path, then the wording of §4 and the full option. **This lifts the hold** | 4 | Later; the tier's goal |
| E14 | A client-only node reports no slots and is never referred: referrals do not count a phone until it can relay (`relay_offering` does not see it today) | 2 | v44 |
| E17 | Per-class opt-in: `phone-wifi` and `phone-cellular` separate; `with_network` keeps both (Q8) | 2 | v44 |
| E15 | Shed levers on shaped slots, §6.12 | 2 | v44 |
| E16 | The mode is fixed at identity creation: no live toggle (`onion_set_enabled`, `OnionPolicy::enabled`), refusal on any node that has announced, never announces, never relays, only layer and rendezvous links, pseudonym for everything published | 4 | Later |

**Server**

| # | Item | Rung | v44? |
|---|---|---|---|
| S1 | Compose reads the `net.*` settings and passes the class. Canonical value OFF; no flip on upgrade (§6.11) | 2 | 0.5.245 |
| S2 | `/v1/setup/privacy-choices`: read and loopback-gated write pre-claim, owner session post-claim; table evaluated for class, locale and the Join answer (with announce off, the served lines must not claim what Join turned off; first-run read takes it as a GET parameter, no client-added line); params added to `DisclosureString` | all | With C1 (0.5.239) |
| S3 | Live re-apply through edge, §6.10; the hold file, §6.7 | all | With C1 (0.5.239) |
| S4 | Pending items carried into the queue (#851); interim notice on CSD-032's surface | all | With #851 |
| S5 | Media and stream routes answer the refusal tokens in plain words | 3, 4 | Later |
| S6 | The listing's item and count now; later, minting the separate identity from the first-run choice, with no shared roster and no linking row, and the signed statement under both keys | 4 | Listing with C1; the rest later |
| S7 | Operator notice for existing installs, §6.11 | 2 | With S1 |

**Client**

| # | Item | Rung | v44? |
|---|---|---|---|
| C1 | PRIVACY step, radio, lists, states of §6.9, tags, strings in all 29 languages, not before 0.5.239 | all | 0.5.239 |
| C2 | Device facts to the node before the table is read | phones | With C1 |
| C3 | Later-change surface in CSD-032 with the warnings of §6.10 | all | With C1 |
| C4 | Per-contact "didn't choose this" marker; refusals in contact view | 3 | Later |
| C5 | The add-device item, after the join, in CSD-093 | all | With C1 |
| C6 | Names through `docs/five-year-old-test.md`, before translation | all | With C1 |
| C8 | The held line before `mintUserIdentity`, after the age band | 4 | With C1 |
| C9 | Separate Wi-Fi and cellular controls on a phone | 2 | With C1 |
| C7 | Correct CIRISClient#272: it carries the old timer figures | all | Now |

**Agent**

| # | Item | Rung | v44? |
|---|---|---|---|
| A1 | `GET /v1/setup/privacy-choices` beside `/consent-disclosure`, over `ciris_server.privacy_choices()`. No write route (§6.6) | all | With C1 |

**CSDs.** CSD-088 is the first-run card: it owns the whole order and every choice. CSD-082
and CSD-083 reduce to their passes, with CSD-084's screens referenced. CSD-045, CSD-032 (later change) and CSD-093 (add-device) point at
it. CIRISClient#272 closes against the card.

**What ships in v44:** rungs 1 and 2 selectable, rungs 3 and 4 listed and disabled with reasons. Rung 3 is later because it has new edge
behaviour on every plane and depends on the canonical shaping (§6.11).

---

## 8. Questions

**Settled by the CC, under Eric's delegation, 2026-11-04.**

| # | Question | Settled |
|---|---|---|
| 1 | Timer figures | rc17 (2ad9675): the link's agreed mean, then about 2.3 / 5.8 / 11.6 / 47 s at the 16 KB frame; rc17 a3dd97a moved the frame to 1,400 B, about 0.2 / 0.5 / 1.0 / 4 s. The wizard shows the served value |
| 2 | Slow path; small images | A chunk MAY ride a shaped link chunk by chunk when the node has no bulk link, within the row budget, rows first. Small images are by size in the CC, by kind in edge until E5 |
| 3 | Scoped lanes | Item 4 is normative: at rungs 2 and 3 the derived-address link itself is shaped, and a scoped body MUST NOT move onto the identity link when a direct path exists. Edge gap, E4, next release |
| 4 | Item 10 | An anonymous peer has no announced identity and is reached only at its rendezvous |
| 5 | Minors and rung 4 | No: a minor's node has no federation-scope binding and does not publish at federation scope |
| 7 | Rung 3 in v44 | Listed, disabled, with the one-line reason |
| 8 | Wi-Fi-only shaping | Yes: `phone-wifi` and `phone-cellular` are separate classes the person turns on separately. It reveals only that the phone moved to cellular (item 5). The controls sit under rung 2; rung 3 is node-wide, §6.8 |
| 9 | Rung 3 before rung 4 | Yes, by definition; shaped-only is implied by the mode. Closed |
| 10 | Helping | On at rung 2, off at rung 3; the wizard says "You can connect through others, but others can't connect through you.". A rung 3 node is a net consumer, fine while rare (`formal/transport_tiers`) |
| 11 | Onion and anonymous mode | One thing, CC 5.4.6 item 1. Held; a separate identity; first run or never. Closed |
| 12 | Homes | "protects you with others who also chose this" is enough with the four stated things |
| 13 | Scope | S1 in 0.5.245; route, table and hold with client 0.5.239 |
| 14 | Phones and relaying | The text stands; v44's client-only phones are text ahead of code, a gap. Referrals must not count a phone until it can relay (E14) |
| 15 | Server default | Canonical OFF until measured, per-node setting, shipped class default on, nothing claims the canonical shapes; turning it on is Eric's go. No flip on upgrade |
| 17 | Anonymous node and relaying | It is NOT a relay. The CC's answer; item 1 at rc17 330094e still reads "it relays onion traffic for others by default", so the correction has yet to land there |

`formal/anonymous` proves the mode's promises.

**Still open; the lock waits on these only.**

6. **Rooms over the onion:** CIRISConstitution#202. Nothing user-facing mentions them until ruled and working.
16. **Scoped links and the eight.** Does a shaped derived-address link count within the eight? Does one person take two slots, one identity and one scoped? Is one shaped lane per address enough for chunk pulls? *Proposed: yes, and one
    link per peer where the two can share.* If they all count, a room of more than eight direct members cannot be fully direct at rungs 2 and 3.
- **Stable homing:** settled by Eric, 2026-11-04: stable, no rotation (CIRISEdge#935).

**Eric's, at the hold's lift, and not part of the lock:** service and agent access for an anonymous identity (§4.2).

---

## 9. Validation record

Checked by reading the code and CC text at the citations, 2026-11-04. Figures recomputed from the class rates, frame
16,272 B, ρ 0.5, W 600/3,600 s. No test, build, mesh run or measurement was made. Measured figures are the 53 s
bootstrap, the round percentiles and the 2,325 ms gap; everything else marked [inf] or [model] is not. Not verified:
the blob pull timeout at slow-path rates; whether `ctx.peers` is restricted further than a Reticulum announce; the
exact size of a pseudonym row; end-to-end first contact at any rung; battery at any class.

## 10. Change log

- 2026-11-04: first draft, with Server's, Client's and the CC reader's inputs; Eric's rooms-over-onion goal recorded as a goal, not a claim.
- 2026-11-04: amended with Server's, Client's and the CC's reviews; rc17 2ad9675's timers; Eric's ruling that the onion and anonymous mode are one rung; load shedding settled (§6.12).
- 2026-11-04: rc17 ae86ea0: rung 4 is held, a separate identity, first run or never; moved off the reversible ladder to before identity creation.
- 2026-11-04: the CC's answers under Eric's delegation applied; LOCKED pending stable homing, Q16 and Q6.
- 2026-11-04: Client's and Server's reviews: plain wording, S2 takes the Join answer, phone controls under rung 2, rung 3 node-wide; stable homing settled. LOCKED pending Q16 and Q6.
