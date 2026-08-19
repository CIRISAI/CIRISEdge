# CIRISEdge Benchmarks

The criterion benchmark suite — what it measures, how to read the
curves, the leak guarantee behind them, and where we stand against the
state of the art.

> **Status (v15.7.0):** the `benches/` suite is **in-tree and running**,
> and — new in v15.7.0 (CIRISEdge#430 bench-superset) — it publishes a
> **release-over-release trend page**:
>
> ### 📈 https://cirisai.github.io/CIRISEdge/dev/bench/
>
> `.github/workflows/bench.yml` runs the suite on a weekly cron +
> `workflow_dispatch` + every push to `main` + PRs touching `benches/**`,
> `src/transport/**`, `src/replication/**`, or `Cargo.toml`, and publishes
> to gh-pages **on push-to-main only** (mirrors persist). It is **not** a
> pass/fail gate — shared runners are too noisy — but it normalizes against
> a calibration anchor so a real regression is legible above the noise, and
> it comments the regression analysis on PRs (`alert-threshold: 110%`,
> `fail-on-alert: false`).
>
> **⚠️ One-time human step:** enabling GitHub Pages is a repo *setting* the
> workflow cannot flip. A maintainer must set **Settings → Pages → Source =
> "Deploy from a branch", Branch = `gh-pages` / `/ (root)`** once. Until
> then benchmark-action still pushes the per-bench JSON history to the
> gh-pages branch (no data lost); only the rendered site 404s. (The
> gh-pages root has no index.html by design — the bare Pages URL 404s; the
> charts live under `/dev/bench/`.)

## The mesh acceptance sweep (the third lane: does it actually work?)

Micro-benches measure what an operation costs. The **acceptance sweep**
measures whether the whole system does what we say it does, on a real
network: separate containers, each its own identity and keystore, real
encoded video and a real file pushed through a relay while members join and
keys rotate.

**Current result — 100%** (2026-08-19, edge v18.1.0; baselines in
[`bench-mesh/results/`](../bench-mesh/results/)):

| Group size | Nodes | Checks run | Failures |
|---|---|---|---|
| 1 subscriber | 4 | 23 | 0 |
| 2 subscribers | 5 | 31 | 0 |
| 4 subscribers (one joining mid-stream) | 7 | 47 | 0 |

What "0 failures" covers, in plain terms: the video and the file arrived
intact at every member; the relay carried them without being able to read
them or learn the group exists; a member who joined mid-stream received
correctly from that point; the key rotation lost nobody a single frame; a
retired address verifiably stopped answering while its replacement kept
working; and an outsider who asked was refused. The scoring is honest by
construction — a check that doesn't run counts as a failure, so silence can
never look like success.

Known honest numbers from the sweep: the test publisher sends to each member
one at a time (~4.5 chunks/s through the relay) — a pipelined sender is the
obvious next improvement, for the test and for production alike. File
distribution currently measures direct push; the swarm-fetch mechanism is
the next measurement to add.

Run it yourself: `cd bench-mesh && ./run.sh --sweep` (docker required; see
[`bench-mesh/README.md`](../bench-mesh/README.md)).

## The two publishing lanes

The trend page carries two kinds of series, both consumed by the same
`benchmark-action/github-action-benchmark@v1` publish:

**Lane A — single-value trends** (one scalar per release):

- **Criterion micro-benches** (wall-clock, **normalized** against the
  calibration anchor — `benches/calibration.rs`, a SplitMix64 CPU anchor +
  a DRAM-random-walk MEM anchor, adopted verbatim from persist so the two
  repos share a runner-noise model): `envelope_verify`,
  `envelope_canonicalize`, `dispatch_inbound`,
  `transport_reticulum_loopback`, `transport_http_loopback`,
  `transport_reticulum_inbound_contention` (CIRISEdge#369 — the node-lock
  concurrency trend: V's inbound drain rate quiescent vs while-sending, over
  a real N-flooder fixture; runs **tolerantly** — a flaked transport-timing
  run is a warning, not a red job — and is **version-blind for the µs-scale
  leviculum#29 class** by construction, so it trends COARSE end-to-end
  concurrency changes, not per-packet lock-holds; see the bench's own docs
  for the A/B that established this),
  `realtime_av_fanout` (seal cost), `realtime_av_relay`,
  `realtime_av_rekey`, `realtime_av_mdc_substrate`. Each bench's
  `required-features` (see `Cargo.toml`) is honored.
- **Fixed-operating-point SIM metrics** (semantic values — ratios / ms /
  rounds — published **un-normalized**, emitted by the three
  `#[cfg(test)]` value dumps
  `realtime_av_alm::sim::tests::bench_dump_mesh_metrics` +
  `replication::sim::tests::bench_dump_replication_metrics` +
  `holonomic::fountain_defaults::tests::bench_dump_fountain_metrics`):
  `mesh/m1_rtt_stretch_p95_x1000` (M1),
  `mesh/m2_reparent_p99_ms` (M2),
  `mesh/m8_continuity_first_delivery_loss5pct_x100000` (M8),
  `replication/antientropy_rounds_loss2pct_mean_x1000`,
  `replication/reassembly_delivery_ratio_loss3pct_x100000`.

**Lane B — scaling/sweep curves** (the superset gap — no sibling repo has
these). `github-action-benchmark` can't draw a curve, so each curve is
**exploded into one benchmark name per point**; each point trends on its
own and the set forms the curve:

| Curve (`plane/…` prefix) | Points | Source |
|---|---|---|
| `mesh/depth/N{n}` + `mesh/depth_bound/N{n}` | N ∈ {10, 100, 1000} | ALM sim **M4** — measured tree depth vs the ⌈log_k N⌉+2 reference (both published so the gap trends) |
| `mesh/continuity/loss{p}pct_x100000` | loss ∈ {0, 5, 10, 15, 20}% | ALM sim **M8** — 3-parent first-delivery ratio across the loss axis |
| `mesh/m3_heal_gap_p95/churn{p}pct_ms` | churn ∈ {0, 5, 10, 15, 20}%/s | ALM sim **M3** — delivery-gap p95 under sustained churn (the task's "reparent_p95/churn" curve; M3 is the only churn-parameterized scenario) |
| `relay_streams_per_core/N_{n}/S_{s}` | N ∈ {32, 100} × S ∈ {1, 4, 16, 64} | criterion `realtime_av_relay` — the bench's own `BenchmarkId` sweep (no extra code) |
| `replication/convergence_rounds/N{n}_x1000` | N ∈ {1, 8, 32, 128} | replication sim — mean `rounds_used` vs initiator-corpus size at 2% loss |
| `fountain/reconstruction/avail{p}pct_x100000` | p ∈ {80, 85, 90, 95} | fountain_defaults dump (#438) — Monte-Carlo survival-floor reconstruction ratio vs per-peer availability at the shipped (N=20, K=6, R=30) tuple; the doc table's measured oracle |

**Scale suffixes** (the `ns/iter` unit on the SIM series is a libtest-format
artifact, *not* nanoseconds — the integer scale is baked into the name so
the chart is self-documenting): `_x1000` = value × 1000 (1000 ⇒ 1.000×),
`_x100000` = ratio × 100000 (100000 ⇒ ratio 1.0), `_ms` = raw milliseconds,
bare depth/bound = integer node count.

## Named honesty (grades publish loud — above or below bar)

The SIM dumps **never assert** — every grade publishes its NUMBER rather
than hiding behind a red gate, so a below-SOTA-bar release shows its value
loud and a regression that crosses the bar shows as a trend break, not a
silent pass. The load-bearing cases:

- **M4 tree depth vs the ⌈log_k N⌉+2 reference** — the page publishes BOTH
  the measured `mesh/depth/N{n}` AND the `mesh/depth_bound/N{n}` reference as
  paired series, so the depth-vs-bound gap trends per-release regardless of
  which side of the bar a given cut lands. At v15.7.0 the new **log-depth
  topology** (the "log-depth topology + mesh spine" cut) holds a homogeneous
  fleet *within* bound — measured depth `N10/N100/N1000 = 2/4/5` against
  bound `4/6/7`. Earlier cuts were BELOW bar here (the deterministic
  planner's MDC sub-path duplication penalty steered a homogeneous fleet into
  a near-linear tree, depth ~25 at N=100); publishing the paired series is
  precisely what makes such a regression legible if it ever returns.
  Structural invariants (acyclic + per-stream cap) are hard-asserted
  separately in the M4 gate `#[test]`.
- **M5 balance / M6 MDC distribution** — documented BELOW-BAR graded findings
  in the `realtime_av_alm::sim` module header (same root cause: mean fan-out
  ≈ 1; a single consumer's K quadrants are not diversified across parents).
  These are recorded by their asserting gate tests but are **not yet Lane-B
  published series** in this cut — adding `mesh/balance/*` + `mesh/mdc_hhi/*`
  dumps is a noted follow-on.
- **Structural PQC verify ceiling** — `envelope_verify` is ~280 µs
  (ML-DSA-65-dominated), a ~14× constant-factor gap vs Ed25519-only peers.
  This is the price of hybrid PQC on every envelope by design
  (`HYBRID_REQUIRED`, THREAT_MODEL Assumption 10); it is *measured*, not
  closed — a first-class normalized Lane-A series, never hidden. See
  [State of the art](#state-of-the-art).

Every metric prints its N + the fixed operating point in its name/comment,
and the sim scenarios are deterministic on `(seed, commit)` — a below-bar
point reproduces exactly. Local repro:

```bash
# the value dumps (opt-level-independent — pure deterministic sim):
cargo test --release --lib bench_dump -- --nocapture
# a single normalized criterion micro-bench (proves the bencher output):
cargo bench --bench envelope_canonicalize -- --output-format bencher
```

> **Follow-ons (acceptable, noted):** a custom overlaid-curve renderer (the
> gh-pages page trends each Lane-B point separately — it does not draw the
> curve as one overlaid line yet); cachegrind "twins" (instruction-count
> companions to the wall-clock benches, immune to runner noise);
> change-point / step-detection alerting (richer than the flat 110%
> threshold). None block the v15.7.0 cut.

> **Historical note (pre-v15.7.0):** the tables below were authored at
> v0.10.0 as the bench-surface *contract* before `benches/` existed. They
> remain the shape spec + expected-curve reference; the live numbers are on
> the trend page above.

## Running

```bash
# Default-feature benches — surface that does not need a transport:
# envelope_canonicalize, envelope_verify, dispatch_inbound,
# outbound_enqueue, accord_threshold_verify, steward_fanout,
# content_fetch_roundtrip, inline_text_pipeline.
cargo bench --workspace

# Transport-loopback benches — explicit feature gates so a host that
# can't build Leviculum (LoRa Pi minus libtss2, e.g.) still gets the
# core suite.
cargo bench --features "transport-reticulum" --bench transport_reticulum_loopback
cargo bench --features "transport-http"      --bench transport_http_loopback

# Subscription bus throughput — requires the pyo3 surface.
cargo bench --features "pyo3" --bench subscription_throughput

# Fountain reconstruction (#438) — real-RaptorQ decode-success curve
# d(m) + availability×decode composite + decode/encode wall-clock.
# Requires the codec wrap layer; not yet in the CI bench lanes.
cargo bench --features "codec-fountain" --bench fountain_reconstruction
```

## CI integration

- **`.github/workflows/bench.yml`** (v15.7.0) runs the full suite on a
  weekly cron + `workflow_dispatch` + push-to-`main` + path-scoped PRs, and
  publishes the **trend page** ([above](#-httpscirisaigithubiocirisedgedevbench))
  on push-to-main. It also saves the raw `target/criterion/**` tree + the
  calibration/normalized/sim files as a 90-day artifact. **Not** a
  pass/fail gate — GitHub's shared runners are too noisy — it answers "what
  are our numbers over time" and surfaces unexplained curve shapes. See
  [The two publishing lanes](#the-two-publishing-lanes) for what it emits.
- **`ci.yml`'s `benches` job** (proposed) is the fast per-PR gate: it
  compiles every bench (`--no-run`, including the feature-gated
  transports + pyo3 subscription) so they cannot bit-rot, without
  running them.
- **The `alloc_stability` test** (the leak gate, [§ leak guarantee
  below](#leak-guarantee)) runs in the normal `ci.yml` test job. It
  gates; it must pass.

## What is benched

| Bench | Crate | Surface |
|---|---|---|
| `envelope_canonicalize` | ciris-edge | Canonical bytes for `FederationAnnouncement` / `DeliveryAttestation` / `ContentBody` / `InlineText`. Sweep body size 256 B → 64 KiB (geometric, ×4). Calls `ciris_persist::canonicalize_envelope_for_signing` — edge owns no canonicalization (§3, MISSION.md). |
| `envelope_verify` | ciris-edge | Hybrid Ed25519 + ML-DSA-65 verify path via persist's `verify_hybrid_via_directory`. Per-envelope; bulk over 1 K envelopes for amortization profile. |
| `dispatch_inbound` | ciris-edge | Full receive pipeline: body-cap → typed deserialize → schema-version allowlist → destination check → replay window → hybrid verify → ACK-match → attestation-emission → handler-dispatch. Per `MessageType`. |
| `outbound_enqueue` | ciris-edge | Build envelope + sign + persist into `edge_outbound_queue`. Per `Delivery` class (Ephemeral / Durable / Federation / Mandatory). |
| `accord_threshold_verify` | ciris-edge | CIRISEdge#19 `AccordCarrier` wire-layer 2-of-3 multi-sig check (3 valid sigs, 2 valid + 1 invalid, 2 valid + 1 missing, 1 valid + 2 invalid, 0 holders → typed reject). |
| `steward_fanout` | ciris-edge | CIRISEdge#20 `Edge::send_federation` enumeration + per-recipient enqueue. Sweep steward set size N ∈ {1, 4, 16, 64}. |
| `content_fetch_roundtrip` | ciris-edge | CIRISEdge#21 `ContentFetch` → `ContentBody` → SHA-256 integrity check. Sweep body size 256 B → 16 MiB (default `MAX_BODY_BYTES` ceiling). |
| `inline_text_pipeline` | ciris-edge | Classify + Scrub + EncryptAndStore on outbound `InlineTextMessage`. Sweep text length 64 B → 4 KiB; cleartext never crosses the wire (§1.6, MISSION.md). |
| `subscription_throughput` | ciris-edge | v0.9.0 Tier 2 — broadcast → drainer → GIL-acquire → Python-callback rate. Sweep concurrent-subscriber count 1 / 4 / 16. |
| `transport_reticulum_loopback` | ciris-edge | Round-trip over Leviculum `LocalInterface`. End-to-end wall clock; sweep envelope size 256 B → 64 KiB (resource layer kicks in past MDU). |
| `transport_http_loopback` | ciris-edge | Round-trip over the HTTP transport. End-to-end wall clock; same size sweep — comparison anchor for the Reticulum curve. |
| `fountain_reconstruction` | ciris-edge | CIRISEdge#438 — real-RaptorQ half of the fountain survival-floor oracle. Prints the measured decode-success curve `d(m)` (m ∈ 18..=26 distinct symbols, 1000 subsets each) + the `Σ_m P(X=m)·d(m)` composite next to `fountain_defaults`' availability table; times decode at m ∈ {20, 23, 26} + encode at the recommended tuple. `required-features = ["codec-fountain"]`; not yet wired into bench.yml/ci.yml lanes. |

## Reading the curves

Every swept curve has an expected shape. A point that deviates from
its shape is a bug to investigate, not noise to wave away. The size
sweep is geometric (×4 per step) so the shape is legible from the
data, not merely asserted.

| Curve | Expected shape | A deviation means |
|---|---|---|
| `envelope_canonicalize` (body size) | linear in body size — `canonicalize_envelope_for_signing` writes bytes verbatim from `RawValue` | non-linear ⇒ canonicalization started re-serializing the body (AV-5 regression, CIRISPersist#7 trap) |
| `envelope_verify` (per-call) | flat — Ed25519 + ML-DSA-65 keys are fixed size | rise with body size ⇒ verify started re-canonicalizing instead of verifying over the canonical bytes the sender signed |
| `envelope_verify` (bulk, N envelopes) | linear in N, slope = single-verify cost | sub-linear ⇒ a verify cache snuck in (AV-21 — discipline violation, MISSION.md §6) |
| `dispatch_inbound` (per MessageType) | constant per-type + linear-in-body (verify dominates) | step-function on `MessageType` ⇒ per-type special-casing crept in (AV-22) |
| `outbound_enqueue` (per Delivery class) | constant per-class — `Ephemeral` shortest; `Durable`/`Federation`/`Mandatory` add persist roundtrip | `Federation`/`Mandatory` not linear in fan-out set ⇒ enumeration is happening per-envelope instead of once-per-call |
| `accord_threshold_verify` | flat across signature-count permutations — every holder's signature is verified once | early-reject (≥M valid sigs short-circuits) ⇒ the wire-layer 2-of-3 gate is exiting before checking all holders — a fail-loud violation; every holder's sig must be checked so a tampered-holder is named in the reject |
| `steward_fanout` (N stewards) | linear in N — one enqueue per steward | super-linear ⇒ enqueue is iterating directory per-recipient instead of once |
| `content_fetch_roundtrip` (body size) | linear in body size (SHA-256 ~3 GiB/s + transport) | super-linear ⇒ Phase 2 chunked-transfer placeholder regressed to a single-frame allocation |
| `inline_text_pipeline` (text length) | linear in text length (Classify scans, Scrub regex-walks, AES-GCM encrypts) | flat ⇒ a transit-touch step skipped silently — mission violation (cleartext crosses the wire) |
| `subscription_throughput` (subscribers) | sub-linear rise then plateau — GIL contention is the wall | linear scaling past 4 subscribers ⇒ the GIL release is being held across the callback (the drainer-then-batch model is the design; a per-event GIL acquire is the regression) |
| `transport_reticulum_loopback` (size) | step at MDU (~470 B) where Resources kick in, then linear | flat after MDU step ⇒ resource reassembly is short-circuiting; below-MDU rise ⇒ packet-layer regressed |
| `transport_http_loopback` (size) | linear in size — TCP throughput-bound | flat ⇒ HTTP transport is buffering before send (latency hidden behind buffer) |

## v1.0 baseline — pending

This is the forward-tracked baseline. The bench suite proposed in this
doc is **not yet implemented in-tree** — first measurements land with
the bench suite cut. When they do, the per-bench tables below get
filled in with measured numbers; the *expected* targets are recorded
now as the contract.

Targets are calibrated against CIRISVerify v2.7.0 (which we share the
crypto primitive with — `hybrid_verify` 276 µs is verify's recorded
number, edge inherits it) and the peers reviewed in
[STANDARDS_COMPARISON.md](STANDARDS_COMPARISON.md) Part IV.

### envelope_canonicalize (target)

| Body size | 256 B | 1 KiB | 4 KiB | 16 KiB | 64 KiB |
|---|---|---|---|---|---|
| `envelope_canonicalize` | < 1 µs | < 2 µs | < 8 µs | < 32 µs | < 128 µs |

**Curve expectation:** linear in body size — the canonicalizer writes
`RawValue` bytes verbatim plus a fixed-size domain-separated frame.
The slope is governed by `serde_json` for the header fields plus a
single `Vec::extend_from_slice` for the body. A ~250 ns/KiB slope is
what to expect from `ciris-persist`'s canonicalizer at parity with the
CIRISVerify build_manifest curve (~94 ns/KiB).

### envelope_verify (target)

| Operation | Time |
|---|---|
| `envelope_verify` (single, hybrid Ed25519 + ML-DSA-65) | ~280 µs |
| `envelope_verify` bulk (1 K envelopes) | ~280 ms |

**Curve expectation:** flat across body size — verify is dominated by
the ML-DSA-65 signature check (per CIRISVerify v2.7.0 `hybrid_verify`
276 µs on `ubuntu-latest`); the SHA-256 over the canonical bytes is
sub-microsecond at 4 KiB and rises ~3 ns/byte beyond. The flat shape
*is* the receipt that we are verifying-via-persist (the canonical
bytes are the same bytes the sender signed; we do not re-canonicalize).

### dispatch_inbound (target)

| MessageType | Per-message |
|---|---|
| `InlineText` (typical text, 256 B) | < 400 µs |
| `FederationAnnouncement` | < 350 µs |
| `DeliveryAttestation` | < 320 µs |
| `ContentBody` (4 KiB) | < 450 µs |
| `AccordCarrier` (2-of-3) | < 900 µs (three verifies) |

Per-message target: 280 µs ML-DSA verify + ~10 µs canonicalize + ~5 µs
replay-window lookup + ~5 µs typed deserialize + ~5 µs body-cap +
schema-allowlist + destination check + ~80 µs handler. ≈ **~400 µs
end-to-end** for a typical 256 B envelope — equivalent to ~2.5 K
messages/sec on a single thread before parallelism.

### outbound_enqueue (target)

| Delivery class | Time |
|---|---|
| `Ephemeral` (no persist write) | < 600 µs (sign-dominated) |
| `Durable` (one persist row) | < 1.5 ms |
| `Federation` (N stewards × persist row) | < 1.5 ms × N |
| `Mandatory` (every-peer × persist row) | < 1.5 ms × N\_peers |

Hybrid sign at ~466 µs (CIRISVerify v2.7.0 `hybrid_sign`) dominates
`Ephemeral`. `Durable` adds a single `edge_outbound_queue` row write.

### accord_threshold_verify (target)

| Scenario | Outcome | Time |
|---|---|---|
| 3 of 3 valid sigs | accept | ~840 µs (3× ~280 µs) |
| 2 of 3 valid + 1 invalid | accept (threshold = 2) | ~840 µs |
| 2 of 3 valid + 1 missing | accept | ~560 µs |
| 1 of 3 valid + 2 invalid | reject (typed) | ~840 µs |
| 0 holders enumerable | reject (typed config error) | < 100 µs |

**The flat shape across "all 3 valid" vs "2 valid + 1 invalid" is
load-bearing** — every holder's signature is verified so that the
typed reject can name *which* holder produced an invalid sig. An
implementation that short-circuits on hitting `M = 2` valid sigs
*looks faster* but **fails the mission stance §1.6** (silent drop of
the third-holder error).

### steward_fanout (target)

| Steward set N | Time |
|---|---|
| 1 | < 1.5 ms |
| 4 | < 6 ms |
| 16 | < 24 ms |
| 64 | < 96 ms |

**Expected shape:** linear in N — directory enumeration is once per
call (`StewardDirectory::enumerate()`), then per-steward enqueue.

### content_fetch_roundtrip (target)

| Body size | Time |
|---|---|
| 256 B | < 1 ms |
| 4 KiB | < 2 ms |
| 64 KiB | < 30 ms |
| 1 MiB | < 500 ms |
| 16 MiB (`MAX_BODY_BYTES`) | < 8 s |

SHA-256 verify at ~3 GiB/s + transport-loopback. Phase 2 chunked
transfer (`MessageType::ContentChunk`) shifts the constant for large
bodies but does not change the linear shape.

### inline_text_pipeline (target)

| Text length | Time |
|---|---|
| 64 B | < 100 µs |
| 256 B | < 200 µs |
| 1 KiB | < 500 µs |
| 4 KiB | < 2 ms |

Classify (regex walk) + Scrub (replace) + AES-GCM encrypt all linear
in text length. AES-GCM at ~5 GiB/s (CIRISVerify v2.8.0 `ring`
backend) is the throughput floor; Classify/Scrub regex passes are
~5–10 ns/byte.

### subscription_throughput (target)

| Concurrent subscribers | Events/sec |
|---|---|
| 1 | > 50 K |
| 4 | > 30 K (GIL contention) |
| 16 | > 15 K (GIL-amortized) |

The drainer batches; the GIL is acquired once per drain, not once per
event. A linear scaling past 4 subscribers indicates a per-event GIL
acquire — that is the regression shape.

### transport_reticulum_loopback (target)

| Envelope size | RTT (LocalInterface) |
|---|---|
| 256 B (single packet) | < 500 µs |
| 1 KiB (Resource, single frame) | < 1.5 ms |
| 16 KiB (Resource, multi-frame) | < 20 ms |
| 64 KiB | < 80 ms |

LocalInterface is in-process loopback — the floor is the verify cost
(~280 µs) plus Leviculum's `Resource` reassembly. The step at MDU
(~470 B for Reticulum's default network MTU) is where Resources kick
in; below that, raw `Packet` is the path.

### transport_http_loopback (target)

| Envelope size | RTT |
|---|---|
| 256 B | < 800 µs |
| 1 KiB | < 1 ms |
| 16 KiB | < 4 ms |
| 64 KiB | < 16 ms |

HTTP-loopback is `axum` extractor + `reqwest` client over loopback
TCP. The slope is roughly bandwidth-bound; the HTTP transport is the
fallback (§1.4, MISSION.md), not the optimization target.

## Leak guarantee

The benches give timing curves; an **`alloc_stability` test** —
proposed at `tests/alloc_stability.rs`, mirroring CIRISVerify's
`src/ciris-verify-core/tests/alloc_stability.rs` — gives the memory
guarantee behind them. It installs a counting global allocator and
asserts every read-path operation is allocation-neutral across
20 000 iterations:

- `envelope_canonicalize` (canonical bytes for every `MessageType`)
- `envelope_verify` (hybrid Ed25519 + ML-DSA-65 via
  `verify_hybrid_via_directory`)
- `replay_window::check_and_record` (the LRU on the verify path)
- `dispatch_inbound` (the full pipeline minus persistence)
- `accord_threshold_verify` (the 2-of-3 check)

Each call allocates and frees the same working set, so net live heap
returns to baseline. A leak would climb linearly with the iteration
count. The test gates; it runs in `ci.yml`'s normal test job (not
under `bench.yml`).

**Cross-reference: AV-17 in [docs/THREAT_MODEL.md](THREAT_MODEL.md)**
— the seed-bytes-stay-out-of-edge's-heap invariant is a separate
property test (`identity_boundary`), distinct from
`alloc_stability`. `alloc_stability` is "we don't leak the working
set"; `identity_boundary` is "we never *held* the seed in the first
place." Both must hold.

## State of the art

The mesh-transport SOTA is the topic of
[STANDARDS_COMPARISON.md](STANDARDS_COMPARISON.md) Part IV. The
axes that matter for benches, and where edge lands:

| Axis | Best-in-class peer | CIRISEdge v0.10.0 target |
|---|---|---|
| Envelope verify rate (commodity hardware) | libp2p Noise-XX ~50 K verifies/sec (Ed25519-only) | ~3.6 K verifies/sec (hybrid Ed25519 + ML-DSA-65) — the 14× gap *is the PQC cost edge pays day-1* |
| LocalInterface RTT (sub-millisecond regime) | iroh magicsock ~200 µs loopback | < 500 µs target (verify dominates) |
| Wheel size (Python distribution) | iroh-py ~12 MiB | < 20 MiB target (Leviculum + persist + crypto) |
| Event-bus throughput | NATS JetStream ~3 M msg/sec (no verify) | > 50 K events/sec to one Python subscriber (verify-on-wire dominates) |
| Append-only durable queue (per-row write) | NATS JetStream ~100 µs/row | < 1.5 ms/row (SQLite via persist; PG path is the v1.1.x extension) |

The constant-factor gap on verify rate is **structural** — every
envelope carries hybrid PQC by design (`HYBRID_REQUIRED` policy is
the v0.1.0 posture per [docs/THREAT_MODEL.md](THREAT_MODEL.md)
Assumption 10 + OQ-11 closure). Closing the gap is not on the
roadmap; *being measured against it* is.

---

**Document Status:** v15.7.0 — bench suite in-tree + trend page live
(CIRISEdge#430). The v0.10.0 target tables below the fold are the
expected-curve contract; live numbers are on the
[trend page](#-httpscirisaigithubiocirisedgedevbench). Update on every
bench-suite cut.
**Next Review:** when the overlaid-curve renderer / cachegrind twins
follow-on lands, or on the next plane added to the suite.
