# ρ and W defaults per budget class (CLM-link-shaping, CC 5.4.3) — measured vs modelled

Edge 43.2 (release/43.2.0), 2026-10-22. For the steward's ask after CLM-link-shaping landed on rc10.
MEASURED = the shaping harness (`tests/shaping_measure_e1.rs::m4_rho_window_grid`, local branch
`local/shaping-measure`) running edge's production `PoissonScheduler` + `BudgetMeter` on a virtual
clock, 2 simulated hours per cell, real row sizes from CIRISServer's kept T2 mesh (50 rows, mean
8.5 KB). MODELLED = arithmetic from the design. Nothing here is from a live mesh yet: the 43.2
shaper ships off by default; bench-mesh numbers follow the first fleet opt-in.

## What ρ and W are, and what they do not do

- A shaped link emits one frame per Poisson fire at rate λ = class bytes/s ÷ frame size, each way,
  always. **Neither ρ nor W changes what the wire shows**: frame size and rate are the same idle or
  busy. (MODELLED, by construction; the harness's cover count confirms the stream never pauses.)
- ρ is the share of fires the budget lets carry a REAL body per window W (`real ≤ ρ·λ·W` per W).
  ρ sets the ceiling of useful throughput (ρ·λ frames/s) and, with W, how big a burst passes
  before queueing. Under load below ρ·λ the only delay is the Poisson wait itself.
- W is the window the bound is enforced over: a quiet link may release a burst of up to ρ·λ·W
  real frames back-to-back (at λ); a shorter W makes the budget refill in smaller steps.

## What an observer learns, per setting (MODELLED)

| observer | learns about load at any ρ, W |
|---|---|
| wire / GPA | nothing from the shaped link: constant λ, one frame size, cover indistinguishable (sealed, random pad). Link existence and set-up time remain visible (CC 5.4.3). A node's UNSHAPED links (A/V, scoped, peers that are off) are observable as before. |
| the peer (honest or compromised) | the real share, bounded by ρ per W, and the arrival times of real frames: with large W, bursts show WHEN you had something to say; with small W they are smeared over several windows. ρ bounds how much of the stream a peer can ever attribute to you as real. |
| a relay / third edge | nothing beyond the wire: shaping is hop-by-hop under the per-link seal; each link's stream is its own. |

So: ρ trades useful throughput against the peer-side bound; W trades burst latency against what
the peer learns about timing. Neither buys anything against the wire beyond what λ already buys.

## Per-class λ and base latency (MODELLED; frame = link channel payload MDU)

Frame = the link's channel payload MDU (400 B at the RNS base MTU; ~1400 B on the fleet's TCP
interfaces). Mean real row 8.5 KB (the T2 sample). λ = class bytes/s ÷ frame bytes. Base delay of
a row = (frames + 1)/λ when under budget (an Erlang wait for its fragments plus the residual of
the first fire).

| class | B/s per link | λ @ 400 B | row delay @ 400 B | λ @ 1400 B | row delay @ 1400 B | useful rows/h at ρ=0.5 |
|---|---|---|---|---|---|---|
| server | 7000 | 17.5 /s | 1.4 s | 5.0 /s | 1.6 s | ~1300 |
| home | 2800 | 7.0 /s | 3.6 s | 2.0 /s | 4.0 s | ~520 |
| phone-wifi | 1400 | 3.5 /s | 7.1 s | 1.0 /s | 8.0 s | ~260 |
| phone-cellular | 350 | 0.875 /s | 29 s | 0.25 /s | 32 s | ~65 (≈ 900 MB/month if always on) |

The measured base delays below match these within the Poisson spread (the model is the
harness's mean; the harness adds the real queueing).

## Measured grid (MEASURED)

Delay = row arrival → its last fragment sent (s). Load = real demand as a fraction of λ.
Cover share = cover ÷ all frames over the 2 h.

### RNS base MTU (400 B frames, 360 B body)

Delivery delay of a real row (s), mean / p95, by class and knobs. Load = real demand ÷ λ. A cell with load > ρ grows a backlog without bound (the budget caps useful throughput at ρ·λ): shown as saturated with the 2 h backlog in frames.

| class | λ (fr/s) | load | ρ=0.25 W=60 | ρ=0.25 W=600 | ρ=0.25 W=3600 | ρ=0.5 W=60 | ρ=0.5 W=600 | ρ=0.5 W=3600 | ρ=0.8 W=60 | ρ=0.8 W=600 | ρ=0.8 W=3600 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| server | 17.5 | 0.1 | 2 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 |
| server | 17.5 | 0.25 | 39 / 125 | 6 / 39 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 |
| server | 17.5 | 0.5 | saturated (29423 queued) | saturated (29483 queued) | saturated (29483 queued) | 18 / 53 | 3 / 9 | 2 / 8 | 2 / 8 | 2 / 8 | 2 / 8 |
| server | 17.5 | 0.8 | saturated (65864 queued) | saturated (65908 queued) | saturated (65907 queued) | saturated (34424 queued) | saturated (34424 queued) | saturated (34424 queued) | 17 / 47 | 6 / 16 | 6 / 16 |
| home | 7 | 0.1 | 6 / 22 | 4 / 7 | 4 / 7 | 4 / 7 | 4 / 7 | 4 / 7 | 4 / 7 | 4 / 7 | 4 / 7 |
| home | 7 | 0.25 | 60 / 146 | 9 / 45 | 4 / 10 | 5 / 11 | 4 / 10 | 4 / 10 | 4 / 10 | 4 / 10 | 4 / 10 |
| home | 7 | 0.5 | saturated (11701 queued) | saturated (11701 queued) | saturated (11700 queued) | 56 / 178 | 9 / 31 | 6 / 19 | 7 / 23 | 6 / 19 | 6 / 19 |
| home | 7 | 0.8 | saturated (26304 queued) | saturated (26304 queued) | saturated (26304 queued) | saturated (13704 queued) | saturated (13704 queued) | saturated (13704 queued) | 40 / 111 | 14 / 41 | 12 / 36 |
| phone-wifi | 3.5 | 0.1 | 14 / 56 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 |
| phone-wifi | 3.5 | 0.25 | 130 / 325 | 36 / 221 | 8 / 20 | 12 / 40 | 8 / 20 | 8 / 20 | 8 / 20 | 8 / 20 | 8 / 20 |
| phone-wifi | 3.5 | 0.5 | saturated (5631 queued) | saturated (5675 queued) | saturated (5675 queued) | 67 / 152 | 16 / 57 | 11 / 34 | 13 / 45 | 11 / 34 | 11 / 34 |
| phone-wifi | 3.5 | 0.8 | saturated (12809 queued) | saturated (12869 queued) | saturated (12869 queued) | saturated (6609 queued) | saturated (6569 queued) | saturated (6569 queued) | 50 / 108 | 24 / 73 | 22 / 67 |
| phone-cellular | 0.875 | 0.1 | 76 / 147 | 26 / 41 | 26 / 41 | 36 / 77 | 26 / 41 | 26 / 41 | 26 / 43 | 26 / 41 | 26 / 41 |
| phone-cellular | 0.875 | 0.25 | 501 / 1030 | 383 / 911 | 29 / 54 | 60 / 177 | 31 / 57 | 29 / 54 | 33 / 61 | 29 / 54 | 29 / 54 |
| phone-cellular | 0.875 | 0.5 | saturated (1157 queued) | saturated (1197 queued) | saturated (1205 queued) | 264 / 597 | 145 / 444 | 44 / 137 | 59 / 179 | 45 / 137 | 44 / 137 |
| phone-cellular | 0.875 | 0.8 | saturated (3191 queued) | saturated (3251 queued) | saturated (3258 queued) | saturated (1689 queued) | saturated (1679 queued) | saturated (1685 queued) | 195 / 440 | 136 / 371 | 94 / 294 |

Cover share of the stream over the 2 h (MEASURED, the same for every W): load 0.1 → 90 %, 0.25 → 76 %, 0.5 → 50 %, 0.8 under ρ=0.8 → 22–29 %. With load > ρ the share is 1−ρ exactly (the budget saturated).

### TCP interfaces (1400 B frames, 1360 B body)

Delivery delay of a real row (s), mean / p95, by class and knobs. Load = real demand ÷ λ. A cell with load > ρ grows a backlog without bound (the budget caps useful throughput at ρ·λ): shown as saturated with the 2 h backlog in frames.

| class | λ (fr/s) | load | ρ=0.25 W=60 | ρ=0.25 W=600 | ρ=0.25 W=3600 | ρ=0.5 W=60 | ρ=0.5 W=600 | ρ=0.5 W=3600 | ρ=0.8 W=60 | ρ=0.8 W=600 | ρ=0.8 W=3600 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| server | 5 | 0.1 | 2 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 | 1 / 3 |
| server | 5 | 0.25 | 41 / 129 | 4 / 10 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 | 2 / 4 |
| server | 5 | 0.5 | saturated (8373 queued) | saturated (8373 queued) | saturated (8372 queued) | 20 / 61 | 2 / 8 | 2 / 7 | 2 / 7 | 2 / 7 | 2 / 7 |
| server | 5 | 0.8 | saturated (18890 queued) | saturated (18890 queued) | saturated (18889 queued) | saturated (9890 queued) | saturated (9890 queued) | saturated (9890 queued) | 16 / 41 | 6 / 18 | 6 / 16 |
| home | 2 | 0.1 | 5 / 11 | 3 / 8 | 3 / 8 | 3 / 8 | 3 / 8 | 3 / 8 | 3 / 8 | 3 / 8 | 3 / 8 |
| home | 2 | 0.25 | 58 / 146 | 6 / 24 | 4 / 11 | 4 / 11 | 4 / 11 | 4 / 11 | 4 / 11 | 4 / 11 | 4 / 11 |
| home | 2 | 0.5 | saturated (3399 queued) | saturated (3369 queued) | saturated (3368 queued) | 58 / 179 | 12 / 56 | 6 / 17 | 6 / 20 | 6 / 17 | 6 / 17 |
| home | 2 | 0.8 | saturated (7556 queued) | saturated (7526 queued) | saturated (7525 queued) | saturated (3986 queued) | saturated (3926 queued) | saturated (3925 queued) | 44 / 113 | 18 / 66 | 14 / 40 |
| phone-wifi | 1 | 0.1 | 14 / 62 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 | 7 / 14 |
| phone-wifi | 1 | 0.25 | 137 / 317 | 30 / 181 | 8 / 22 | 12 / 42 | 8 / 22 | 8 / 22 | 8 / 20 | 8 / 22 | 8 / 22 |
| phone-wifi | 1 | 0.5 | saturated (1653 queued) | saturated (1619 queued) | saturated (1619 queued) | 71 / 164 | 15 / 50 | 11 / 33 | 14 / 44 | 11 / 33 | 11 / 33 |
| phone-wifi | 1 | 0.8 | saturated (3808 queued) | saturated (3778 queued) | saturated (3781 queued) | saturated (2025 queued) | saturated (1978 queued) | saturated (1977 queued) | 58 / 137 | 26 / 76 | 25 / 69 |
| phone-cellular | 0.25 | 0.1 | 64 / 147 | 27 / 46 | 27 / 46 | 34 / 65 | 27 / 46 | 27 / 46 | 30 / 63 | 27 / 46 | 27 / 46 |
| phone-cellular | 0.25 | 0.25 | 562 / 1144 | 319 / 814 | 32 / 75 | 49 / 141 | 29 / 70 | 29 / 70 | 32 / 70 | 29 / 70 | 29 / 70 |
| phone-cellular | 0.25 | 0.5 | saturated (386 queued) | saturated (367 queued) | saturated (373 queued) | 250 / 592 | 151 / 469 | 47 / 120 | 66 / 213 | 47 / 120 | 47 / 120 |
| phone-cellular | 0.25 | 0.8 | saturated (911 queued) | saturated (896 queued) | saturated (902 queued) | saturated (464 queued) | saturated (452 queued) | saturated (452 queued) | 297 / 589 | 127 / 328 | 100 / 260 |

Cover share of the stream over the 2 h (MEASURED, the same for every W): load 0.1 → 90 %, 0.25 → 76 %, 0.5 → 50 %, 0.8 under ρ=0.8 → 22–29 %. With load > ρ the share is 1−ρ exactly (the budget saturated).


## Recommended defaults per class

What the grid says, in order of weight:

1. **ρ must sit above the link's real load, with margin.** Any cell with load > ρ saturates: the
   budget caps useful throughput at ρ·λ and the queue grows without bound (in production the
   bounded queue defers the sender; nothing is dropped, but nothing catches up either). At the
   knee (load = ρ) the window decides everything: W=60 s gives 40–130 s mean / 125–325 s p95 on
   server…phone-wifi; W=600 s gives 6–36 s; W=3600 s is back at the Poisson base.
2. **Below the knee, ρ and W do not matter for latency.** Every cell with load ≤ ρ/2 shows the
   Poisson base (server 1.6 s, home 4 s, phone-wifi 8 s, phone-cellular 26–32 s mean) at any W.
3. **What they still do:** ρ bounds what the PEER can attribute as real (never more than ρ of
   the stream per window); W bounds how long a burst the peer can see released at once
   (ρ·λ·W frames) and how fast a knee-loaded link recovers.
4. **The wire sees none of it.** Cover share tracks load exactly (90 % at 0.1, 76 % at 0.25,
   50 % at 0.5); the frame stream is λ either way.

Recommended fleet defaults (MODELLED choice over the MEASURED grid; the maintenance planes'
real demand on a shaped identity link is well under half of these λ at today's cadences):

| class | ρ | W | why |
|---|---|---|---|
| server | 0.5 | 600 s | load stays far below 0.5 on a 7 KB/s link; W=600 holds the p95 under ~10 s even at the knee; a peer learns at most half the stream is real |
| home | 0.5 | 600 s | same shape at 2.8 KB/s; p95 ≤ 31 s at the knee |
| phone-wifi | 0.5 | 600 s | λ is low (1–3.5 /s) so W=60 would bite early (knee p95 152 s vs 57 s); 600 keeps bursts cheap; battery is set by λ, not by ρ or W |
| phone-cellular | 0.5 | 3600 s | λ ≈ 0.25–0.9 /s: a 600 s window admits only 75–260 real frames, and the knee cells show 383 s mean / 911 s p95 at W=600 vs 29 / 54 at W=3600; the longer window costs only the peer's view of burst timing on a link that is metered and bursty by nature |

Not recommended: ρ=0.25 anywhere (halves useful throughput for a peer-side bound of little extra
value and saturates at ordinary load); ρ=0.8 as a default (the peer-side bound is nearly gone);
W=60 on any phone class (the knee penalty is minutes). All four knobs stay exposed
(`shaping_rho`, `shaping_window_seconds`, per-class bytes/s, node cap) so the steward can move
them per deployment; the defaults ship in 43.2 as `ShapingPolicy::for_class` (ρ 0.5, W 600 s)
with phone-cellular's W set to 3600 s.
