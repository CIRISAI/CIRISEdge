# CIRISEdge Benchmarks

The criterion benchmark suite — what it measures, how to read the
curves, the leak guarantee behind them, and where we stand against the
state of the art.

> **Status (v0.10.0):** the bench suite proposed below is the *contract*
> for v1.0. A `benches/` directory is **not yet present in-tree** — the
> first measurements land in a follow-up cut (see
> [v1.0 baseline — pending](#v100-baseline--pending)). This document
> is the bench surface specification: when `benches/` lands, it lands
> against this shape, not a different one.

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
```

## CI integration

- **Proposed `.github/workflows/bench.yml`** (lands with the bench
  suite) runs the full set on every push to `main` and on manual
  dispatch, publishing the criterion HTML report (`criterion-report`)
  and a text summary (`bench-results-txt`) as artifacts. **Not** a
  pass/fail gate — GitHub's shared runners are too noisy — it answers
  "what are our numbers" and surfaces unexplained curve shapes. This
  mirrors CIRISVerify's `bench.yml` cadence verbatim (daily +
  workflow_dispatch).
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

**Document Status:** v0.10.0 baseline — bench suite proposed; first
measurements pending. Update on every bench-suite cut.
**Next Review:** when `benches/` directory lands (follow-up to
v0.10.0).
