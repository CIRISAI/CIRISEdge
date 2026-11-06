# The Anonymous Tier, modelled — layers, Sybil bound, churn, latency, sizes

Edge `feat/onion-fsd`, 2026-10-22, for the steward's model ask on CC 5.4.6 (rc10 `89e6915`). Companion to
`FSD/ONION_ROUTING.md`. **MEASURED** = run on this host: the Rust determinism witness over the CSD/4
catalogue (`src/transport/onion_layers.rs`) and the shaping grid's Poisson base latencies
(`docs/SHAPING_RHO_W_2026-10-22.md`). **MODELLED** = `docs/models/onion_tier_model.py`, arithmetic and
simulation over stated assumptions. Nothing is from a live mesh: no relay exists yet.

## (a) Determinism, cap and floor over T0–T19 — MEASURED (Rust witness)

`two_nodes_holding_the_same_rows_deal_identical_layers_over_the_catalogue` runs `deal_layers` on every
catalogue topology (seats = canonicals; announced and unannounced nodes as the YAML says), twice per
topology with the rows in different orders, at four periods and at c ∈ {1, 2, 3}: the two deals are
byte-identical; in every layer non-seats ≤ c × seats; `available` equals the floor; unannounced nodes are
never dealt; every relay is dealt or capped. `the_floor_makes_the_tier_unavailable_on_every_catalogue_topology`:
all twenty topologies are below the floor at c = 2 (one or two seats), as the design intends.
`the_cap_admits_two_per_seat_per_layer_and_rotates_the_rest`: 3 seats + 20 others deal [3, 3, 3] with 14
capped, the next period deals a different set, c = 1 gives [2, 2, 2] and c = 3 gives [4, 4, 4].

## (b)–(f) — the script's output

```
## (b) layer sizes, floor, anonymity set per layer vs adoption  [MODELLED]
Assumptions: seats = canonicals; phones = 60% of non-seat nodes; device policy relays a phone only on
Wi-Fi while charging (30% of phones at any time); 10% of eligible non-phones opt out; opt-in to USE = adoption.
      N seats  relays  dealt/layer  capped avail | crowd per relay per 10-min window at adoption 1%/5%/20% (users×1 msg/h)
      1     0       0    [0, 0, 0]       0 False | 0.00 / 0.01 / 0.03
      2     1       1    [1, 0, 0]       0 False | 0.00 / 0.02 / 0.07
      3     1       1    [1, 0, 0]       0 False | 0.00 / 0.03 / 0.10
      4     1       2    [2, 0, 0]       0 False | 0.00 / 0.02 / 0.07
      7     1       3    [3, 0, 0]       0 False | 0.00 / 0.02 / 0.08
     10     1       5    [3, 0, 0]       2 False | 0.01 / 0.03 / 0.11
     50     2      28    [3, 3, 0]      22 False | 0.03 / 0.14 / 0.56
   1000     3     541    [3, 3, 3]     532  True | 0.56 / 2.78 / 11.11
   1000    10     544   [12, 9, 9]     514  True | 0.14 / 0.69 / 2.78
  10000    10    5404   [12, 9, 9]    5374  True | 1.39 / 6.94 / 27.78
  10000    30    5413 [30, 30, 30]    5323  True | 0.56 / 2.78 / 11.11
 100000    30   54013 [30, 30, 30]   53923  True | 5.56 / 27.78 / 111.11
 100000   100   54046 [102, 99, 99]   53746  True | 1.63 / 8.17 / 32.68
Reading: the cap ties the dealt set to 3 × (1+c) × seats-per-layer; with one seat per layer each layer holds ≤ 3 members, the floor just passes, and
everything else waits. The anonymity set per layer is the layer size; the crowd per relay per window is what mixing actually needs (≫1).

## (c) the Sybil bound the cap buys  [MODELLED]
Adversary controls fraction f of the non-seat relays and no seat. Within a layer its share ≤ c·f/(1+c) (cap saturated, worst case).
 c    f adv share/layer  P(all 3 hops adv)  P(hop1 & hop3 adv)
 1  0.1           0.050             0.0001              0.0025
 1  0.5           0.250             0.0156              0.0625
 1  0.9           0.450             0.0911              0.2025
 1  1.0           0.500             0.1250              0.2500
 2  0.1           0.067             0.0003              0.0044
 2  0.5           0.333             0.0370              0.1111
 2  0.9           0.600             0.2160              0.3600
 2  1.0           0.667             0.2963              0.4444
 3  0.1           0.075             0.0004              0.0056
 3  0.5           0.375             0.0527              0.1406
 3  0.9           0.675             0.3075              0.4556
 3  1.0           0.750             0.4219              0.5625
Reading: at c=2 with EVERY non-seat relay hostile, a layer is at most 2/3 hostile: 44% of routes have both ends hostile (the
timing-correlation case) and 30% are hostile end to end; c=1 gives 25% / 12.5%, c=3 gives 56% / 42%.
Seats being honest is the assumption that does the work; the cap converts 'how many seats' into 'how hostile a layer can get'.

## (d) delivery with phone churn: device policy vs phones always relaying  [MODELLED]
A 3-hop route built at t0; each hop must still be online when the packet reaches it (t0+Δ, Δ≈10 s/hop under shaping); a phone
relaying only on Wi-Fi+charging churns ~5%/h; a phone always relaying churns ~40%/h (sleep, carrier NAT, battery). Non-phones 1%/h.
  device policy          P(delivery, single try) = 0.9997; with one retry over a fresh route ≈ 1.0000
  phones always relay    P(delivery, single try) = 0.9959; with one retry over a fresh route ≈ 1.0000
  A route REUSED for an hour (the rendezvous blob) must survive the whole period: device policy 0.942; always 0.509;
Reading: per-packet delivery barely moves; the REUSED receiver route is what phone churn breaks (0.51 vs 0.94 survival over the hour), which is why
the policy matters and why a rendezvous node should be a seat.

## (e) latency per hop and end to end  [MEASURED base from the shaping grid; MODELLED sum]
Packet = 15,200 B = 12 shaped frames at 1360 B body (TCP) or 43 at 360 B (RNS base). Per-hop wait ≈ (frames+1)/λ under budget
(the grid's Poisson base), plus the sender-chosen mixing delay Exp(μ), μ = 2 s (edge knob).
  server      per hop:   4.6 s (TCP) /   4.5 s (RNS base); 3-hop publication  13.8 s /  13.5 s; targeted (6 hops + mailbox fetch 3 hops)  41.4 s /  40.6 s
  home        per hop:   8.5 s (TCP) /   8.3 s (RNS base); 3-hop publication  25.5 s /  24.9 s; targeted (6 hops + mailbox fetch 3 hops)  76.5 s /  74.6 s
  phone-wifi  per hop:  15.0 s (TCP) /  14.6 s (RNS base); 3-hop publication  45.0 s /  43.7 s; targeted (6 hops + mailbox fetch 3 hops) 135.0 s / 131.1 s
Reading: a server-class path publishes in ~15 s over TCP; a home-class path in ~25 s; phone relays push a targeted delivery toward 2–3 minutes.

## (f) sizes against the carrier bounds  [MODELLED, exact arithmetic]
  X-Wing ct 1120 B + routing block 48 B = slot 1168 B; 6 slots (safety 3 + private 3, always) = 7008 B; body 8192 B; packet 15200 B
  frames: TCP 1400 B MDU (1360 body) → 12; RNS base 400 B (360 body) → 43; CFRG body bound 8 MiB → fine; Channel u16 envelope → fragments anyway
  rendezvous route blob = 3 slots = 3504 B raw, 4672 B base64; row payload ≈ 5072 B + inline hybrid key record ≈ 17,000 B → ≈ 22072 B per row
  mailbox per rendezvous key per period at 64 packets cap: 950 KiB; a seat holding 1,000 active rendezvous keys: 928 MiB
```

## The finding the steward should see first

**The cap as ruled ties the whole tier to the seat count.** Non-seats ≤ c × seats-in-layer means a layer
holds at most (1 + c) × its seats, so with three seats (one per layer) every layer is three nodes and 532
of 541 relays at N = 1,000 wait every period; at N = 100,000 with 30 seats the layers are 30 each and
53,923 relays wait. The Sybil bound (c) is exactly what this buys: a layer is never more than c/(1+c)
hostile however many strangers arrive. The anonymity set per layer is the layer size, so at today's fleet
it is three, and the crowd per relay per ten-minute window (what mixing needs to be well above one) only
passes one at N ≈ 10³ with several percent adoption. There is no setting of c that gives both a large layer
and a bounded hostile share with few seats: **the lever is seats**, which are vetted and in the bundle. Edge
recommends keeping c = 2 as ruled and saying in the client that the tier's capacity grows with the serve
seats; if the steward prefers larger layers at a known Sybil cost, an additive knob `k₀` (non-seats ≤
c × seats + k₀, default 0) is the one-line change, and (c) gives the share it concedes.

Two smaller points: a rendezvous node should be a seat (the reused hour-long route is what phone churn
breaks, 0.51 vs 0.94 survival under the device policy); and the hop count's latency is set by the shaping
class, not by the crypto (≈ 14 s server, 25 s home, 45 s phone for a three-hop publication; a targeted
delivery with the mailbox fetch is three times that).
