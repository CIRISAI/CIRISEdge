# Link shaping: defaults and bandwidth cost per class (edge v44)

CC 5.4.3 (rc17), `CLM-link-shaping`, `CLM-shaped-link-bound-refuse`, `CLM-seat-class`. Eric, as steward, ruled the fleet default
on 2026-11-02; the ruling is final.

| Class | On by default | Rate per link | ρ | W | Per link, per month, each way | At the 8-link cap, per month, each way |
|---|---|---|---|---|---|---|
| `server` | **yes** | 7,000 B/s | 0.5 | 600 s | 18.1 GB | 145.2 GB |
| `home` | opt-in | 2,800 B/s | 0.5 | 600 s | 7.3 GB | 58.1 GB |
| `phone-wifi` | opt-in | 1,400 B/s | 0.5 | 600 s | 3.6 GB | 29.0 GB |
| `phone-cellular` | opt-in | 350 B/s | 0.5 | 3,600 s | 0.9 GB | **7.3 GB** |
| `seat` | seat to seat only | 33,000 B/s | 0.5 | 600 s | 85.5 GB | outside the eight |

The `seat` class runs only between two serve seats proved from the signed roster.
Its budget sits outside the eight; beside a non-seat a seat runs at the non-seat's
class.

## What it costs in latency (CC 5.4.3: "the choice is explained before it is made")

A shaped link carries real bytes at ρ of its rate: at the `server` class that is
0.5 × 7,000 B/s = **3.5 KB/s of real bytes per peer**, however many lanes the
peer has, and one 16 KB frame every 2.3 s on average. What that means for the
person at the moment of choosing:

| What | Unshaped | Shaped at the class rate |
|---|---|---|
| A row (a post, a message) to a peer | tens of milliseconds | about one frame gap: 2.3 s mean at `server`, 4 s `home`, 8 s `phone-wifi`, 26–32 s `phone-cellular` |
| A reply, or a round of replication | a second | two to three gaps, so 5–7 s at `server` |
| First contact and catch-up (many rows at once) | a four-node bootstrap in 53 s (measured) | several times slower: rounds p90 35 s, p99 165 s, max 221 s in the same bootstrap (measured, `server`, coalescing on), because the rows queue behind each other at 3.5 KB/s per peer |
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
  moment of choosing. PyO3 hosts read it through `shaping_class`:
  - `"server"` gives the server default.
  - Any other class is the person's opt-in for that class.
  - No class shapes the layer links only.

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

**Who is named.** Offering relay is the consent to be referred (Eric, 2026-11-04).
A referral names any announced node, owned or not, that reports free shaped slots,
with a live route carrying a transit pair. A node reports slots only while its
relay offering is on (`onion::policy::relay_offering`: on for servers and home
nodes, a phone only on Wi-Fi while charging, the user's override either way, less
the operator's relay opt-out). When the offering ends the node reports zero at
once on its running links and peers stop ranking it. Edge nodes come first; one
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

**A referral is a hint, never a guarantee.** A stale report costs one refused dial
and the peer tries the next. **With no targets known the refusal carries an empty
list and the peer uses its fallback order** (other canonicals, CIRISEdge#935). At
v44 that order is not built: an empty or exhausted list leaves the peer's row sends
to that node failing by name for 120 s, with its bulk link unaffected.

**Homing does not re-address a row.** The refused send still fails by name. The
peer now holds a shaped link to the referred node, and what it sends there is the
host's choice (`homed_on_referrals`).

**`DivideNoFloor`** (`cap ÷ links`, however small) stays as the non-default arm
for comparison. It does not conform to rc17.

## Latency

Well below ρ, the Poisson timer sets latency, not the budget. The mean
latency per class is:

| Class | Mean latency |
|---|---|
| `server` | about 1.6 s |
| `home` | about 4 s |
| `phone-wifi` | about 8 s |
| `phone-cellular` | 26–32 s |

These figures come from the CC 5.4.3 model.

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

**The last resort.** If no unshaped link can be had because the dial fails (for
example, a NAT'd phone reachable only over the link it dialled in), the message
rides the shaped link in shaped-budget fragments and is counted
`link_shaping_bulk_on_shaped_fallback`. The shaper paces it like every other
frame, so the link stays constant-size and constant-rate. It is slow, but it
does not fail: `Delivered` means every fragment left this node, and a transfer
that stops part-way is an error the durable dispatcher retries. A second send of
the same envelope joins the transfer rather than queueing it twice, and a failed
dial stands for 120 s per peer, so a NAT'd peer costs one failed dial, not one
per send. The rate is the link's real budget: at the `server` class on a 16 KB
frame, about 0.2 real frames per second, or 3.5 KB/s, so 1 MiB takes about five
minutes.

**The refusal.** The shaper itself still refuses a message beyond its reach
outside that fallback (`link_shaping_bulk_refused`), and queues none of it. The
send paths move bulk before it gets there, so a count here means a path that
skipped them.
