# Link shaping: defaults and bandwidth cost per class (edge v44)

CC 5.4.3 (rc16), `CLM-link-shaping`. Eric, as steward, ruled the fleet default
on 2026-11-02; the ruling is final.

| Class | On by default | Rate per link | ρ | W | Per link, per month, each way | At the 8-link cap, per month, each way |
|---|---|---|---|---|---|---|
| `server` | **yes** | 7,000 B/s | 0.5 | 600 s | 18.1 GB | 145.2 GB |
| `home` | opt-in | 2,800 B/s | 0.5 | 600 s | 7.3 GB | 58.1 GB |
| `phone-wifi` | opt-in | 1,400 B/s | 0.5 | 600 s | 3.6 GB | 29.0 GB |
| `phone-cellular` | opt-in | 350 B/s | 0.5 | 3,600 s | 0.9 GB | **7.3 GB** |

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
reactions, and small images. A message counts as a row only if it fits within
one window's real-frame budget, `ceil(ρ·λ·W)` frames. That budget is:

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
- it is larger than one window's real-frame budget.

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
does not fail. The bound is the window budget: at the `server` class on a 16 KB
frame, about 0.2 real frames per second, or about 3 KB/s.

**The refusal.** The shaper itself still refuses a message beyond its reach
outside that fallback (`link_shaping_bulk_refused`), and queues none of it. The
send paths move bulk before it gets there, so a count here means a path that
skipped them.
