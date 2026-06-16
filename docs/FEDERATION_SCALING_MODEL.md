# Federation Scaling Model — CIRISEdge v3.8.0 Realtime A/V

> **Status**: load-bearing FSD for the v3.8.0 substrate cut. Substantiates the
> "stream at scale" claim in the release notes by deriving — from first
> principles — the participant-streams-per-SFU-core, the mesh→SFU crossover,
> and the per-receiver bandwidth at every degradation level. Cross-referenced
> from [`src/transport/realtime_av.rs`](../src/transport/realtime_av.rs) and
> [`src/transport/realtime_av_relay.rs`](../src/transport/realtime_av_relay.rs).
>
> **Out of scope** for this FSD: end-to-end UX testing, codec selection,
> the `federation_directory` KeyPackage publish/fetch surface.

---

## §1 Goal and scope

### Goal

The v3.8.0 release notes describe the realtime A/V substrate as "stream at
scale." That claim is meaningless without a model. This FSD substantiates it
by deriving:

1. The maximum mesh participant count `N_mesh_max` as a function of
   `(available_uplink, codec_bitrate, layer_policy)`.
2. The mesh→SFU crossover — the value of `N` at which a publisher *must* emit
   one copy to a relay rather than `N-1` copies into a mesh.
3. The forwarding capacity of a single SFU core in
   participant-streams-per-second, both bandwidth-bound and CPU-bound.
4. The cumulative rekey latency at meeting-start cold-join for a 20–50-person
   room, both with and without L5-C `RosterDelta::Batch`.

### Scope

CEG §10.5.8 *realtime A/V* — group video, voice, and screen sharing. This is
the low-latency interactive profile, the complement of CEG §10.5.5 E2's
broadcast pull path (which lives at 1–10 s latency and is fundamentally
unsuitable for interactive calls).

### Non-goals

- Codec selection (the substrate is codec-agnostic; encoder choice is
  upstream).
- End-to-end UX testing of any specific application built on the substrate.
- The `federation_directory` KeyPackage publish/fetch surface (a separate
  L3 cut, tracked in CIRISEdge#129's follow-ups).
- Packet-radio mediums (Reticulum supports them; the bitrate floor makes
  them irrelevant to the *scale* question).
- Active congestion control (SCReAM, GCC) — see §8.

---

## §2 Bandwidth axes — the load-bearing math

### §2.1 Codec bitrate table

The numbers below are typical operating-point bitrates for the codec
configurations CIRISEdge expects to see in the wild. They are working
assumptions, not codec specifications. Real bitstreams vary with scene
complexity and rate-control mode.

| Profile             | Bitrate (typical)      | Notes                                    |
|---------------------|------------------------|------------------------------------------|
| Opus voice          | 24 kbps                | Per-stream, mono, 20 ms frames           |
| 360p15 H.264 / AV1  | 400–600 kbps           | Low-fi video, mobile-friendly            |
| 720p30 AV1 SVC      | 2.5 Mbps               | **The anchor configuration**             |
| 1080p30 AV1 SVC     | 4–5 Mbps               | "HD" desk-call default                   |
| 4K30 SVC            | 15–25 Mbps             | Practical max for any home upload tier   |
| BLINKING_DOT        | ~50 kbps               | Per-receiver layer policy degraded layer |

The substrate exposes `ReceiverLayerPolicy` (CIRISEdge#128) so each receiver
can self-cap independently of the publisher's encode bitrate. The publisher
emits the full SVC stream once; the relay (or, in mesh mode, the publisher
itself) drops the layers a given receiver isn't entitled to *before*
[`seal_av_outer`](../src/transport/realtime_av.rs) runs.

### §2.2 Mesh uplink as a function of N

In full-mesh mode the publisher emits **one copy per other participant**.
Uplink demand per publisher is therefore:

```
uplink_mesh(N, bitrate) = (N - 1) × bitrate
```

At the user's anchor configuration — 720p30 at 2.5 Mbps, 50 participants —
this is:

```
uplink_mesh(50, 2.5 Mbps) = 49 × 2.5 Mbps = 122.5 Mbps
```

That is **infeasible on any consumer connection**. The DOCSIS 3.x upload
ceiling is ~100 Mbps in the rare top-tier configuration; the median US home
upload as of 2024 is ~30 Mbps. The 50-participant 720p30 mesh requires more
upload than the fastest consumer line can deliver.

At 6 participants × 720p30: `5 × 2.5 = 12.5 Mbps` up. Feasible on most
modern home tiers.

### §2.3 Mesh-cap derivation

The general form, given an available uplink `U` and a per-stream bitrate
`B`, is:

```
N_mesh_max(U, B) = 1 + floor(U / B)
```

Worked points:

| Available uplink | Codec        | Bitrate | N_mesh_max |
|------------------|--------------|---------|------------|
| 30 Mbps (median home) | 720p30 AV1     | 2.5 Mbps | 13     |
| 30 Mbps           | 1080p30 AV1   | 4.5 Mbps | 7      |
| 30 Mbps           | 4K30 SVC      | 20 Mbps  | 2 (degenerate) |
| 30 Mbps           | Opus voice    | 24 kbps  | 1251   |
| 30 Mbps           | BLINKING_DOT  | 50 kbps  | 601    |
| 100 Mbps (top home) | 720p30 AV1   | 2.5 Mbps | 41     |
| 1 Gbps (datacenter) | 720p30 AV1   | 2.5 Mbps | 401    |

The "~50 participants" hand-wave at `realtime_av.rs:9` corresponds to either
**voice-only** or **BLINKING_DOT-degraded** mesh on a high-end home line, not
to 720p30 mesh. The substrate's `RealtimeFanout::plan_layered` plus
`ReceiverLayerPolicy` is precisely the lever that lets a 50-person room
operate mesh-mostly with receiver-self-degradation, instead of forcing
everyone to a relay.

### §2.4 SFU egress

A relay forwards one inner-sealed chunk per stream and emits one outer-sealed
copy per subscriber. Per-stream egress demand is:

```
egress_sfu(N_subs, bitrate) = N_subs × bitrate
```

For one publisher's 720p30 stream forwarded to 50 subscribers:

```
egress_sfu(50, 2.5 Mbps) = 125 Mbps
```

A single SFU stream burns ~125 Mbps of relay egress. Modern production SFUs
(LiveKit, Janus, mediasoup, Jitsi Videobridge) publish per-core forwarding
numbers in the 100–200 Mbps range under realistic codec mixes. Public
benchmarks vary wildly with configuration; the lower bound is a defensible
working assumption.

**Best-effort estimate from public production write-ups**: ~150 Mbps
sustained egress per core, with the bound dominated by the kernel-side TX
path and the per-subscriber AEAD work the substrate already amortizes via
the inner-once / outer-N split (CIRISEdge#122).

---

## §3 CPU axes

### §3.1 Per-chunk crypto cost (from `realtime_av_fanout.rs`)

The L4-A bench measures the inner-once / outer-N split at N=64 with 16 KiB
chunks. Empirical numbers, quoted verbatim from
[`benches/realtime_av_fanout.rs`](../benches/realtime_av_fanout.rs) and the
L4 commit message:

- Naive `seal_av_chunk × N`: **201.21 µs** per fanned-out chunk at N=64,
  16 KiB.
- Inner-once + outer-N split (CIRISEdge#122): **104.25 µs** per fanned-out
  chunk at the same point. **1.93× sender-CPU win**, within noise of the
  substrate's claimed ~1.98× win at N=50.
- 7-cell SVC layered variant (CIRISEdge#128 composed with #122):
  **~548 µs** per fanned-out chunk at N=64, 16 KiB.

### §3.2 What that means at frame cadence

At 30 fps the sender pays the per-chunk cost 30 times per second per outbound
fan-out. For 16 KiB chunks at N=64:

- Inner-once / outer-N at 30 fps: `104.25 µs × 30 ≈ 3.13 ms / sec` ≈
  **0.3% of one CPU core**.
- 7-cell SVC at 30 fps: `548 µs × 30 ≈ 16.4 ms / sec` ≈ **1.6% of one CPU
  core**.

**Crypto is not the bottleneck**. Bandwidth is. The substrate could fan out
to several hundred mesh participants on a single core if the uplink existed
to carry the bytes.

### §3.3 MLS rekey cost (from `realtime_av_rekey.rs`)

The L4-B bench measures MLS `advance_epoch` against the v3.7.x flat-unicast
baseline. Empirical numbers from
[`benches/realtime_av_rekey.rs`](../benches/realtime_av_rekey.rs) and the
L4 commit message:

- N=8 Join: flat ~657 µs, MLS ~2.4 ms. **Flat wins 3.7× at small N** — the
  per-commit MLS overhead dominates.
- N=128 Join: flat ~11.0 ms, MLS ~9.7 ms. **MLS overtakes flat by ~12% at
  large N**.
- Crossover sits between N=32 and N=128.

The release-notes-quotable caveat from the bench's top-of-file docs: these
numbers are **sender CPU under unicast** — the worst case for MLS. MLS's
receiver-side O(log N) win and multicast amortization show up in the relay
path (§5), not in this bench.

---

## §4 The mesh → SFU crossover

### §4.1 The formal derivation

Combining §2.3 with the receiver-layer-policy lever, the crossover is:

```
N_mesh_max(U, B_active, policy) =
  1 + floor(U / max_over_receivers(B_receiver(policy)))
```

Where `B_receiver(policy)` is the receiver-specific bitrate the publisher
must emit for that receiver under its declared `ReceiverLayerPolicy`. A
receiver capped at BLINKING_DOT consumes 50 kbps of publisher uplink, not
2.5 Mbps; a receiver uncapped consumes the full 2.5 Mbps. The publisher's
uplink budget is the sum over receivers.

### §4.2 Concrete crossover points (home upload, 30 Mbps)

| Active layer mix                                | N_mesh_max | Bottleneck         |
|-------------------------------------------------|------------|--------------------|
| All UNCAPPED at 720p30                          | 13         | Uplink             |
| Half UNCAPPED + half BLINKING_DOT at 720p30     | 24         | Uplink (mixed)     |
| All BLINKING_DOT                                | 601        | Effectively none — receiver count |
| Voice-only (Opus 24 kbps)                       | 1251       | None at any realistic N |
| All UNCAPPED at 4K SVC                          | 2          | Uplink             |

### §4.3 When the relay enters

The relay (`realtime_av_relay::RelayNode`) enters whenever **any** receiver
requires full-quality streams from multiple publishers AND that publisher's
fanned-out demand exceeds `N_mesh_max` for the active bitrate. The publisher
sends one inner-sealed copy to the relay; the relay applies N outer seals,
one per subscriber.

The substrate is structurally able to operate in **hybrid mode**: a 50-person
room with three "main speakers" might run the speakers' streams through the
relay (fanned to 47 subscribers) while running everyone else's BLINKING_DOT
streams direct-mesh (49 × 50 kbps = 2.5 Mbps per publisher, easily fits the
remaining uplink). The substrate exposes the primitives; the policy lives
above this layer.

### §4.4 Replacing the "~50" hand-wave

The current docstring at [`realtime_av.rs:9`](../src/transport/realtime_av.rs#L9)
reads "(≤ ~50 participants)". That number was always a stand-in for "the
configuration where mesh stops working". This FSD's §2.3 and §4.2 give the
precise model. The docstring is updated to reference §4 here:

> *"The mesh is infeasible above `N_mesh_max(uplink, codec, layer)`
> participants per CEG §10.5.8 / `FEDERATION_SCALING_MODEL.md` §4. For
> 720p30 on a typical consumer connection this is ~13; for BLINKING_DOT it
> is >200."*

The relay's "bandwidth accounting / abuse policy" follow-up at
[`realtime_av_relay.rs:82`](../src/transport/realtime_av_relay.rs#L82) is
similarly updated to point at §5 + §8 here for the model and §8 for the
specific follow-ups carved out.

---

## §5 Per-SFU-core forwarding capacity

### §5.1 Egress-bound capacity

```
streams_per_core_egress =
  available_egress_per_core_Mbps / (mean_bitrate_per_stream × subs_per_stream)
```

For 720p30 (2.5 Mbps per stream) fanned to 50 subscribers on a relay core
with 150 Mbps egress budget:

```
streams_per_core_egress = 150 / (2.5 × 50) = 1.2 streams per core
```

A 50-person all-720p30 conference would need ~50 cores' worth of relay
egress if every publisher emits a full-quality stream to every other
participant via the SFU. With the receiver layer policy active and most
receivers self-capped to a thumbnail tier, the practical capacity goes up by
the average receiver-tier reduction (often 5–20×).

### §5.2 CPU-bound capacity

From §3.1, the per-subscriber outer-seal cost is ~1.6 µs at 16 KiB chunks
(derived from the inner-once / outer-N N=64 numbers, ~104 µs / 64
subscribers). At 30 fps:

```
streams_per_core_cpu =
  1 / (mean_outer_seal_us × subs_per_stream × fps) × 1_000_000
```

For 720p30, 50 subs:

```
streams_per_core_cpu = 1 / (1.6 × 50 × 30) × 1_000_000 ≈ 416 streams per core
```

### §5.3 Which dominates

Egress dominates CPU by ~**350×** at the anchor configuration. The bottleneck
on a v3.8.0 relay is the outbound link, not the AEAD work. This is exactly
what the substrate's inner-once / outer-N split (CIRISEdge#122) is designed
for: hold the CPU cost at ~zero so the relay can saturate its link.

### §5.4 Empirical sanity check

L5-B (the relay capacity bench) will cross-reference these once it lands.
The L4-C `realtime_av_relay` bench's `mesh_vs_relay_comparison` group is
the foundation: it gives the publisher-side savings and the per-subscriber
relay cost separately, so the consumer can plug their own
`(egress_budget, target_N, target_bitrate)` into the formula above without
re-deriving anything.

---

## §6 Burst rekey at meeting-start

### §6.1 The scenario

A 20–50-person meeting starts. Participants click "join" within a 1–2 second
window. The publisher must rekey the stream once per join to maintain
forward secrecy (CEG §10.5.5 forward-secrecy boundary), and the rekey must
land before the first frame of the new epoch.

### §6.2 v3.7.x flat baseline

20 separate flat rewraps at the L4-B N=8 number (~657 µs per rewrap, which
is conservative — the per-rewrap cost grows with the *current* roster, so
the 20th rewrap pays a higher cost than the first):

```
total_flat ≈ 20 × 657 µs = 13.1 ms
```

Cumulative wait is well under one 30fps frame interval (33 ms). At v3.7.x the
substrate would have survived this scenario fine.

### §6.3 v3.8.0 single-delta MLS (no batching)

The v3.8.0 substrate runs MLS per join. The L4-B N=128 number is ~9.7 ms per
`advance_epoch(Join)`. 20 sequential joins:

```
total_mls_unbatched ≈ 20 × 9.7 ms = 194 ms
```

At 30 fps that is **~6 dropped frames** while the room stabilizes — a
visible stutter at meeting-start. A 50-person cold-start would be ~485 ms,
~15 dropped frames.

This is the regression L5-C is designed to close.

### §6.4 v3.8.0 batched MLS (`RosterDelta::Batch`, L5-C)

L5-C's `RosterDelta::Batch` collapses M joins into one MLS commit. The
commit work is dominated by the per-commit fixed overhead plus the
sum-of-copath-resolutions term, not by M separately. Working estimate:

```
total_mls_batched ≈ 10–20 ms (one commit covering all 20–50 joins)
```

That is ~one 30fps frame. The meeting starts at one-frame latency, not
fifteen.

### §6.5 Cross-reference

This is the *rekey* side of the "at scale" claim. Once L5-C lands, the
realtime_av_rekey bench will grow a `mls_rekey_batched` group, and this
section gets the empirical numbers folded back in.

---

## §7 Verdict matrix — what scales where

```
+-----------------------------------+------------------+----------------------+---------------------------------+
| Profile                           | N max            | Bottleneck           | Mitigation                      |
+-----------------------------------+------------------+----------------------+---------------------------------+
| 720p30 home-uplink full mesh      | 13               | Uplink bandwidth     | Drop to SFU or BLINKING_DOT     |
| 1080p30 home-uplink full mesh     | 7                | Uplink bandwidth     | Drop to SFU or 720p layer       |
| 4K home-uplink full mesh          | 2                | Uplink bandwidth     | Drop to SFU; degrade            |
| Voice-only mesh (Opus 24 kbps)    | 1000+            | None at any real N   | None needed                     |
| BLINKING_DOT mesh                 | 600+             | None at any real N   | None needed                     |
| Layered mesh (mixed receivers)    | ~24 at 50/50 mix | Uplink (avg-weighted)| Push uncapped subs to SFU       |
| 720p30 SFU per core (egress)      | ~1.2 streams     | Relay egress         | Cascade SFUs (Phase 1.x)        |
| 720p30 SFU per core (CPU)         | ~416 streams     | Crypto AEAD          | n/a — egress dominates by ~350x |
| Cold-join burst (20p, unbatched)  | 6 dropped frames | MLS commit serial    | L5-C RosterDelta::Batch         |
| Cold-join burst (20p, batched)    | ~1 frame         | MLS commit overhead  | n/a — already mitigated         |
+-----------------------------------+------------------+----------------------+---------------------------------+
```

---

## §8 Out of scope — filed as follow-ups

The substrate at v3.8.0 deliberately defers the following, each of which has
its own well-scoped landing surface. Per the task brief, no time estimates;
the work is identified, not scheduled.

- **Cascade SFUs for >100p rooms.** A single relay's egress dominates per
  §5.3. Trees of relays (CIRISEdge#66 next phase) carve the egress demand
  across multiple boxes. The substrate's chunk-seal shape is already wire-
  compatible with the cascade case; the work is the routing layer.

- **Active congestion control.** SCReAM and Google CC analogs adjust the
  publisher's bitrate dynamically based on observed RTT and loss. The
  substrate exposes the bitrate axis through layer policy (`#128`); a
  congestion controller is a consumer of that surface, not a primitive in
  it.

- **Multi-tenant resource limits at the relay.** Per-subscriber rate caps,
  per-stream egress quotas, abuse-policy hooks. Tracked as a follow-up
  from `realtime_av_relay.rs:82`. The substrate's `RelayNode` API is
  resource-policy-blind by design; the policy layer sits above it.

- **Codec / encoder selection.** The substrate is codec-agnostic. Encoder
  choice (bitrate target, rate control mode, SVC layer count) is the
  caller's. The CEG §10.5.8 surface is bytes-in / bytes-out.

- **The `federation_directory` KeyPackage publish/fetch surface.** Cold-join
  needs a way for a joiner to fetch the current group state's KeyPackage
  set. The L3 federation-directory cut owns that; the substrate consumes
  it but does not define it.

- **L5-B relay capacity bench** + **L5-C `RosterDelta::Batch`.** Both are
  in-flight v3.8.0 cuts. §5.4 and §6.4 will fold their empirical numbers
  back into this FSD once they land.

---

## §9 Summary

The "stream at scale" claim decomposes into four substantiated assertions:

1. **Mesh is feasible up to `N_mesh_max(U, B)` per §2.3.** For 720p30 on a
   median home line, ~13. For BLINKING_DOT, >600. The substrate's
   `RealtimeFanout::plan_layered` plus `ReceiverLayerPolicy` is the lever
   that pushes the effective cap higher by self-capping receivers.

2. **The relay enters above the mesh cap and handles N up to its per-core
   egress budget (§5).** ~1.2 streams per core at 720p30/50-sub fan-out,
   bandwidth-bound by ~350× over CPU. The substrate amortizes the CPU work
   to near-zero via the inner-once / outer-N split (CIRISEdge#122,
   empirically 1.93× at N=64 / 16 KiB per L4-A).

3. **MLS rekey on cold-join is the v3.8.0 release-critical edge** (§6).
   Unbatched, 20-person cold-join drops ~6 frames at 30 fps. L5-C
   `RosterDelta::Batch` collapses that to one frame.

4. **Crypto is not the bottleneck anywhere on the substrate at v3.8.0.**
   Bandwidth is, in both mesh and SFU mode. This is the deliberate design
   outcome of CIRISEdge#122 and #128.

The substrate ships a model where the policy layer above it (the lens / agent
UX) can read `(N, codec, available_uplink, per-receiver-policy)` and select
mesh / SFU / hybrid without re-deriving the math each time. This FSD is the
ground truth for that policy.
