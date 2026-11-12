# Link shaping: defaults and bandwidth cost per class (edge v44)

CC 5.4.3 (rc17), `CLM-link-shaping`, `CLM-shaped-link-bound-refuse`, `CLM-seat-class`. Eric, as steward, ruled the fleet default
on 2026-11-02; the ruling is final. The shaped frame is 1,400 bytes (CC 5.4.3 rc17, CIRISConstitution a3dd97a;
edge 44.1.1, CIRISEdge#963): see [The shaped frame](#the-shaped-frame).

| Class | On by default | Rate per link | ρ | W | Per link, per month, each way, on the wire | At the 8-link cap, per month, each way, on the wire |
|---|---|---|---|---|---|---|
| `server` | **yes** | 7,000 B/s | 0.5 | 600 s | 20.9 GB | 167.4 GB |
| `home` | opt-in | 2,800 B/s | 0.5 | 600 s | 8.4 GB | 67.0 GB |
| `phone-wifi` | opt-in | 1,400 B/s | 0.5 | 600 s | 4.2 GB | 33.5 GB |
| `phone-cellular` | opt-in | 350 B/s | 0.5 | 3,600 s | 1.0 GB | **8.4 GB** |
| `seat` | seat to seat only | 33,000 B/s | 0.5 | 600 s | 98.7 GB | outside the eight |

The rate is a budget of frame bytes. On the wire each 1,400 B frame also carries the E1 seal (25 B), the
transport's packet header (107 B) and the proof the receiver returns (83 B): about 15 % on top of the budget,
against about 1 % at the old 16 KB frame. The columns above include it, as CC 5.4.3 requires of a stated cost
("which a stated cost includes"). The budget alone is 18.1 / 7.3 / 3.6 / 0.9 / 85.5 GB per link.

The `seat` class runs only between two serve seats proved from the signed roster.
Its budget sits outside the eight; beside a non-seat a seat runs at the non-seat's
class.

## What it costs in latency (CC 5.4.3: "the choice is explained before it is made")

A shaped link carries real bytes at ρ of its rate: at the `server` class that is
0.5 × 7,000 B/s = **3.5 KB/s of real bytes per peer**, however many lanes the
peer has, and one 1,400 B frame every 0.2 s on average. What that means for the
person at the moment of choosing:

| What | Unshaped | Shaped at the class rate |
|---|---|---|
| A small row (a post, a message) to a peer | tens of milliseconds | about one frame gap: 0.2 s mean at `server`, 0.5 s `home`, 1.0 s `phone-wifi`, 4 s `phone-cellular` |
| A larger row | tens of milliseconds | its bytes over the rate, whatever the frame: a 64 KiB row is 48 frames, about 10 s at `server`, 24 s `home`, 48 s `phone-wifi`, 3 min `phone-cellular` |
| First contact (a handful of request/answer steps) | about 15 s through a relay (measured on the server rig) | each step waits about a gap more; contact rows go ahead of the link's serve and sync backlog (the contact lane, below) |
| Catch-up (many rows at once) | a four-node bootstrap in 53 s (measured) | the backlog drains at 3.5 KB/s per peer at `server`; a volume of bytes takes the same time at any frame |
| Bulk (files, chunks, media) | unchanged | unchanged: bulk never rides a shaped link |

In production only servers shape by default; a person who opts in pays the
row latency above toward every peer that shapes too. A peer that does not shape
leaves the link unshaped (lower of the two offers), so opting in costs nothing
toward it.

## How to read the table

- **Where the table lives in code.** The single source is
  `src/transport/link_shaping.rs` `FLEET_DEFAULTS`. To change a default, change
  the `on_by_default` cell in that one row. The witness
  `the_fleet_default_is_on_for_server_only_and_opt_in_elsewhere` reads the
  table and checks the cost columns against the rate.
- **How the cost is computed.** A shaped link always runs at its class rate:
  cover frames fill whatever real traffic leaves unused. A month is 30 days,
  2,592,000 s.
  - One link costs `rate × 2,592,000 s` in each direction.
  - At the cap, eight links cost eight times that.
  - Both directions together cost twice the "each way" figure.
- **What the person can change.** Opting in at any class, cellular included,
  shapes every identity link at that class. The opt-in is a choice the person
  makes, not a fact about the network, so it survives a move between Wi-Fi and
  cellular (`DeviceState::with_network`). Without an opt-in, a node shapes only
  its Anonymous Tier layer links, and those exist only while the tier runs.
- **What a phone also pays.** A shaped link keeps the radio awake, which costs
  battery on top of the data above.
- **Where clients read the table.** The mobile surface exposes it as
  `shaping_class_table()`, the UniFFI function for the client to show at the
  moment of choosing. PyO3 hosts name the device with `shaping_class` and the
  person's choice with `shaping_opt_in` / `shaping_opt_in_cellular`:
  - `"server"` gives the server default (every identity link).
  - `"home"`, `"phone-wifi"` or `"phone-cellular"` shapes the layer links only,
    unless the matching opt-in is set. Naming the class is not the opt-in.
  - No class is the platform's device at its fleet default.
  - `shaping_set_device_state` keeps an opt-in the call leaves out.

## The bound: shape with shaped peers if possible, otherwise refuse

CC 5.4.3 rc17: a node runs at most eight shaped links, each at the full rate of
its class. **The bound is a refusal, never a diluted link.** The share policy is
one enum, `ShapedSharePolicy`, and the default is one line in
`ShapingPolicy::for_class`.

- **One rate, both ways.** Every shaped link runs at the one negotiated rate.
  Rows to a peer share its one shaped link; they never open a second.
- **Layer links count within the eight**, at the class rate. A layer neighbour
  has priority by holding, not by taking: while layer neighbours wait, other
  peers stop short of the eight by up to `layer_reserve_links` (4). Nothing is
  taken from a running link, and a ninth link of any kind is refused.
- **`seat` links sit outside the eight**, so a seat-to-seat layer link takes no
  slot.
- **Past the bound** a shaping peer's row link is refused with
  `link_shaping_home_elsewhere`: the responder answers the refusal on the wire
  (class byte `home-elsewhere`; a 43.x peer reads it as malformed and closes
  too), a dialler at its own bound refuses at the answer, and the row link is
  never run unshaped. The refused peer's row sends fail by name for 120 s without
  a dial; its bulk (over 64 KiB, chunks, media) still dials an unshaped link of
  its own. A peer whose offer is `off` is not a shaping peer and gets its ordinary
  unshaped link. The refusal carries referrals (below).

**Fair order.** rc17 also admits a higher-class newcomer by displacing the
lowest-class peer to a shaped peer below it. That, and the per-link carriage
setting, are CIRISEdge#939; until then a higher-class newcomer at a full node is
refused like any other.

**The accepted leak.** The refused peer's bulk link is observable: an observer
learns the node is at its bound and sees that peer's bulk in a Resource's shape.
Prior art (Tarzan, Herd) homes the peer elsewhere; the referrals below do, and
this spill stays as the trade-off for a peer's bulk, bounded to one unshaped link
per refused peer.

## Referrals: where a refused peer goes

A peer bounced at the bound still has to reach a first contact, a consent, a
contact request and its acceptance. So the refusal names up to three nodes that
will take it. Module: `src/transport/shaping_referral.rs`.

**The frame.** `SHRF` frames on the Channel, sealed like everything else on the
link, in the `fragment_tagged` framing of the route answer, at most 96 KiB (past
that the last entries are dropped). The body is JSON:

```json
{"action": "refused", "referrals": [{"route": <signed row>, "key_record_row": <row>}]}
```

- `action` is `refused`, or `move`, reserved for displacement (CIRISEdge#939): the
  same frame, sent to a running shaped peer. v44 sends only `refused`.
- Each entry is a route answer: the referred node's own hybrid-signed
  `transport_destination` row and its `key:record:v1` row, all the peer needs to
  dial without a lookup. The peer verifies it as it verifies a route it fetched
  from that node, then installs it as an `Advisory` binding. A referrer can
  withhold, and can vouch for nothing it could not have fetched.
- The frames go **before** the `SHAP` refusal, because the dialler closes when the
  answer lands. They are taken only while the dialler waits on its offer's answer.
  The list is never skipped: an empty one means "no targets known". A 43.x dialler
  closes on the refusal's class byte either way.

**Who is named.** Offering relay is the consent to be referred (CC 5.4.3, 5.4.6
rc17, `CLM-refusal-carries-referrals`): an owner who turns relay offering on hands
the node's route to strangers for first contact and consent.
A referral names any announced node, owned or not, that reports free shaped slots,
with a live route carrying a transit pair. Announced means the CC's sense: an owned
node has a live owner binding at federation scope, so a node that chose not to be
listed is never referred, whatever its relay offering. A node reports slots only while its
relay offering is on (`onion::policy::relay_offering`: on for servers and home
nodes, a phone only on Wi-Fi while charging, the user's override either way, less
the operator's relay opt-out). When the offering ends the node reports zero at
once on its running links and peers stop ranking it. A client-only node (every v44
phone) reports zero whatever its state. Edge nodes come first; one
serve seat may take the last entry when fewer than three edge nodes qualify.

**Capacity.** The free slots ride the in-band capability body
(`SHCP ‖ version ‖ free_slots`, inside the constant frames, not in the fixed-length
`SHAP` offer, so a 43.x peer is unaffected), sent on a fresh link and on every
shaped link when the value changes. Zero means no claim.

**Against herding.** Most free slots first, ties in random order, and a node handed
out first loses a slot in the referrer's local hint until its next report. So
refused peers spread even when one node reports more room than the rest.

**On the receiving side.** The peer dials the referrals in order on its row lane
and stops at the first that takes a shaped link. A referred node treats it as any
shaping peer. It skips the node that refused it and any node that refused it within
the last 120 s; those are the peer's exclusions, and no message carries them. The
refusal's token and the outcome are logged and counted:
`link_shaping_referral_{sent,empty,withheld,received,rejected,homed,failed,exhausted}`.

**Asked of a node that does not offer.** The setting says whether a node offers
shaping by default; the capability is every node's (CC 5.4.3,
`CLM-shaping-offered-never-refused`). On a direct link a node with shaping off
answers a peer that asks at its own device class, and the agreement takes the lower of
the two, so a phone on cellular pays no more than its class. The wire does not
change: an old peer's `off` ends as it always did. The node drops the link ten
minutes after its last real frame, either way, with up to a tenth more by link so
a fleet's links do not close together; cover does not count. The ten minutes are
the operator's, `Edge::set_shaping_asked_idle_ttl`. The close is a plain one
(`link_shaping_asked_idle_closed`), and the asker dials again when it has something
to send.

**Past the bound.** Only a node set to shaped-only or to the anonymous tier refuses
(CIRISEdge#952). Any other node answers `off`, sends its referrals as a hint, and
the link runs unshaped, counted `link_shaping_unshaped:past_bound` at the end that
had no slot. A dialler past its own bound offers nothing, so no shaper starts at
the other end alone. A refusal is the peer's choice and does not count against
its reachability.

**A referral is a hint, never a guarantee.** A stale report costs one refused dial
and the peer tries the next. **With no targets known the refusal carries an empty
list and the peer uses its fallback order** (other canonicals, CIRISEdge#935). At
v44 that order is not built: an empty or exhausted list leaves the peer's row sends
to that node failing by name for 120 s, with its bulk link unaffected.

**A homed node is used.** Edge registers it as a replication peer on the bootstrap
planes (`Key`, `IdentityOccurrence`, `TransportDestination` and their revocations)
by itself, so a refused peer's first contact and consent flow there with no host
step, and a host's later peer set keeps it. The refused send itself still fails by
name: homing does not re-address a row.

**`DivideNoFloor`** (`cap ÷ links`, however small) stays as the non-default arm
for comparison. It does not conform to rc17.

## Latency

Well below ρ, the Poisson timer sets latency, not the budget. The mean
latency per class is:

| Class | Mean latency | 95th percentile |
|---|---|---|
| `server` | about 0.2 s | 0.6 s |
| `home` | about 0.5 s | 1.5 s |
| `phone-wifi` | about 1.0 s | 3.0 s |
| `phone-cellular` | about 4 s | 12 s |

These are the link's own agreed mean, the frame size over the class budget, at the
1,400 B shaped frame (CC 5.4.3 rc17). At the Reticulum base frame (about 400 B)
they are shorter still. The 16 KB figures (2.3 / 5.8 / 11.6 / 47 s) are superseded.

## The shaped frame

CC 5.4.3 rc17 (CIRISConstitution a3dd97a), shipped in edge 44.1.1 (CIRISEdge#963):

- **One constant.** The shaped frame is 1,400 bytes before the E1 seal, the `SHPF`
  header included, or the link's channel payload MDU where that is smaller. It is
  not per class and not negotiated (`link_shaping::SHAPED_FRAME_BYTES`,
  `shaped_frame`). Seat links get the same frame.
- **Old peers.** A 44.0 or 44.1 peer still offers its 16,272 B MDU; the agreement
  takes the smaller frame and re-quotes the byte budget at it, so the link runs at
  1,400 B at the peer's own byte rate. Nothing on the wire changes shape.
- **What moves and what does not.** The rate is a byte rate, so the byte budget, the
  cover volume, what an observer of the link sees and the time a volume of bytes
  takes to cross are the same at any frame. Only the first byte moves: a row waits
  for the next frame, now a fraction of a second.
- **What it costs.** About 15 % more on the wire than the budget (seal, packet header
  and proof per frame; the cost table above includes it), and a seal per frame: a
  few tens a second at the eight-link bound.
- **Fragments.** A payload larger than the frame is fragmented (`CFRG`) and
  reassembled. An onion packet (15,296 B) spans twelve frames
  (`an_onion_packet_crosses_a_1400_byte_shaped_link_in_fragments_and_arrives_intact`).
- **Waits are stated in row bytes, not gaps.** A sender waits for its row to leave at
  most the Poisson p99 of the largest row (64 KiB, 48 frames at 1,400 B), or 60 s
  where that is more (`LinkShaper::row_leave_cap`): about 60 s at `server`, 330 s at
  `phone-cellular`. Sixteen gaps covered a 64 KiB row at the 16 KB frame (five
  frames) and would time out every such row on cellular at 1,400 B.
- **The queue is in bytes.** Each lane of a link's queue holds one window's real
  budget in body bytes, at least one 64 KiB row (`queue_bytes_for`): about 2.1 MB at
  `server`, 840 KB `home`, 420 KB `phone-wifi`, 630 KB `phone-cellular`. A burst past
  it is deferred and retried by the sender (`shaping_queue_full`).

## The contact lane

CIRISEdge#962. A shaped link's queue has two lanes. The next real frame takes the
**contact lane** first, so first contact never waits behind a serve or sync backlog on
the same link. The wire is unchanged: one Poisson stream of constant frames, real or
cover.

- **Contact lane** (`Lane::of`, read from the frame's bytes):
  - a replication frame of any verb on the bootstrap planes and their revocations:
    `key`, `identity_occurrence`, `transport_destination`, `revocation`,
    `identity_occurrence_revocation`;
  - an `attestation` `Deliver` whose every row is a `consent:replication:v1` grant, an
    owner binding, or a retraction (`withdraws` / `recants`): a contact request, its
    acceptance, the binding that roots a stranger, and their undoing. Revocation is the
    privacy-critical direction, so it is never slower than the grant it undoes. A
    retraction names only the id and type of the row it revokes, not the grant's
    dimension, so every retraction rides this lane;
  - a `PublicKeyRegistration` envelope;
  - the node's own link-up pushes (announce, owner binding, build bundle), the link's
    capability report and referrals.
- **Sync lane:** everything else, including an attestation page that mixes those rows
  with others, chat, and the onion.
- The route fetch, its answer and the CTKX handshake run before the seal, bare on the
  link, and never reach a shaper.
- Each lane is FIFO and numbers its own bodies, so a sender's wait for its row
  (`ticket_left`) and its retraction on a timeout stay exact across lanes.
- **No starvation.** While both lanes hold bodies, at least one real frame in every four
  carries a sync body (`CONTACT_RUN_MAX`; a frame carrying both counts). A peer that
  induces contact traffic, for example by pulling key rows, takes at most three
  quarters of the link's real frames. A contact row arriving at a quiet contact lane
  still takes the next frame.

## Two planes

**The row plane is shaped.** A shaped link carries rows: posts, messages,
reactions, and small images. A message counts as a row only if it is at most
64 KiB and fits within one window's real-frame budget, `ceil(ρ·λ·W)` frames.
That budget is:

| Class | Real-frame budget per window |
|---|---|
| `server` | about 2.1 MB |
| `home` | about 840 KB |
| `phone-wifi` | about 420 KB |
| `phone-cellular` | about 630 KB |

**Bulk moves to an unshaped link.** A message needs the bulk plane when its
link is shaped and either of these holds:

- it is bulk by kind: `ContentFetch`, `ContentBody`, `BlobChunkFetch` or
  `BlobChunkBody` (`BULK_MESSAGE_TYPES`, the wire spelling of `MessageType`);
- it is larger than `SHAPED_ROW_MAX_BYTES`, 64 KiB, whatever its type. At the
  `server` rate of 3.5 KB/s that is about 20 s, the most a row should wait;
- it is larger than one window's real-frame budget (only a very small budget
  puts this below 64 KiB).

Such a message takes the freshest unshaped link to the peer. If there is none,
the node dials one with no shaping offer and marks it bulk, so rows do not use
it. Fetches count as bulk so that the answer has an unshaped way back, even to
a peer this node cannot dial.

**Live media.** An A/V leg is on the `Av` plane and is never shaped. A scoped
link is never shaped either. Neither makes a shaping claim.

**No fallback.** If no unshaped link can be had because the dial fails (for
example, a NAT'd phone reachable only over the link it dialled in), the message
is refused by name, `link_shaping_bulk_refused`, and the durable dispatcher
retries it on its schedule (CC 5.4.3, `CLM-shaped-link-one-hop`). It never rides
the shaped link. A failed dial stands for 120 s per peer, so a NAT'd peer costs
one failed dial, not one per send.

The shaper itself also refuses a message beyond its reach, under the same token,
and queues none of it. The send paths move bulk before it gets there.
