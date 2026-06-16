# v3.8.0 recommended stack — raptorq + AV1 as the holographic data layer

This document locks in the CIRIS recommended stack for shipping the v3.8.0 substrate's holographic / graceful-degradation property without inventing a new codec. It also surfaces a genuinely novel architectural insight: applying the same fountain-code data-layer approach to **reasoning traces and context storage** under disk pressure — a use case where no prior art was found.

## The codec gap (recap)

`docs/V3_8_0_SOTA_VALIDATION.md` documents the SOTA finding: no production-grade symmetric MDC video codec has shipped. The substrate is ready (codec-agnostic `codec_id` namespace, variable-depth `SubStreamPath`, `ChunkLayer { spatial, temporal, quality }`), but the codec it was designed for (CODEC_MDC = 0x03, "holographic" sub-stream splitting) is a 2024 research prototype (NeuralMDC), not productionized.

This document closes that gap by composing existing production-grade Rust crates.

## The recommended stack (production-deployable today)

| Layer | Crate | Role |
|---|---|---|
| Video codec | **`rav1e`** (encoder) + **`dav1d`** (decoder) | AV1 — mature, royalty-free, what WebRTC / Meet / Teams / Zoom ship |
| Forward error correction / holographic data layer | **`raptorq`** (RFC 6330 RaptorQ) | Fountain code: encode N source blocks → K > N output symbols; any subset of ≥N symbols reconstructs source |
| Substrate transport | CIRIS Edge v3.8.0 | Per-peer ALM relay, MLS X-Wing rekey, multi-parent dedup, layer-aware fan-out |

### Wiring

1. **Encoder**: rav1e produces video chunks. App-tier picks `codec_id`.
2. **Fountain wrap**: each chunk's payload is wrapped via RaptorQ → N source symbols + K extra symbols. Each symbol becomes one substrate `SealedAvChunk` with `ChunkLayer.quality` = symbol-index-in-fountain-set.
3. **Substrate routing**: edge's ALM machinery routes the N+K symbols through the mesh tree.
4. **Receiver**: collects symbols. As soon as ≥N have arrived, RaptorQ decoder reconstructs the original payload.

### What this gives us

- **Holographic property at the data layer**: any subset of ≥N symbols reconstructs.
- **Graceful degradation under loss**: missing symbols recoverable up to the K headroom; beyond K, partial reconstruction with documented probability.
- **Codec freedom**: AV1 today, anything tomorrow.
- **Zero new substrate code**: edge's existing `ChunkLayer` + `SubStreamPath` express the fountain symbol identity.
- **Production-grade Rust everywhere**: rav1e, dav1d, raptorq (3GPP MBMS + DVB-H deployment).

## Disk-pressure eviction policy

```
ChunkLayer.quality axis = fountain symbol position
  - quality = 0      : minimum-required source symbol
  - quality = 1..N-1 : remaining source symbols
  - quality = N..N+K : repair symbols (FEC headroom)

Persist eviction policy under DiskPressure:
  - Tier 1 (no pressure)        : keep all N+K symbols (full FEC)
  - Tier 2 (warn, ≥1 GiB)       : evict repair symbols (quality ≥ N)
  - Tier 3 (crit, ≥500 MiB)     : evict highest-quality source symbols
  - Tier 4 (stop, ≥200 MiB)     : keep BLINKING_DOT-equivalent set
  - Tier 5 (host_at_risk)       : metadata-only retention
```

Composes with v6.8.0 `Engine::serve_blob_to_peer` + `BlobError::DiskPressureProxyRefused` — adds a fourth axis (per-chunk quality) to the existing (proxy/local/family) priority.

## Novel insight: reasoning traces under fountain-code degradation

**The user's question — "could we apply it to reasoning traces and context instead of TimescaleDB-style capabilities? Has anyone done that?" — surfaces genuinely novel architectural territory.**

### What we searched (no prior art)

- Fountain codes used for **forward error correction in network transmission** (canonical)
- Fountain codes used for **DNA data storage** (PMC11570749) — unrelated
- **CassandrEAS** — Cassandra + erasure coding for storage-efficiency vs replication, NOT degradation
- Log-structured systems use erasure coding for compaction efficiency

**No published work treats fountain coding as the time-series / structured-log graceful-degradation primitive.**

### Why this works for CIRIS reasoning traces — persist's actual contract

Reasoning traces in CIRIS already have CEG-shaped structure: signed envelopes, content hashes, deterministic byte layout. CIRISPersist v8.0.0 ([#227](https://github.com/CIRISAI/CIRISPersist/issues/227)) ships exactly this with the `FountainContentV1` types.

**Persist's key design choice**: the signed manifest (which includes the trace's own #225 hybrid-signed envelope plus the SHA-256-per-symbol hash chain) is **always-retained**. It does not evict under disk pressure. The evictable surface is the per-symbol `FountainSymbolV1` table; the manifest is structural.

The three degradation classes persist returns (`FountainContent` enum, [persist/src/fountain/types.rs:128](https://github.com/CIRISAI/CIRISPersist/blob/main/src/fountain/types.rs#L128)):

| Class | Survivors | Persist returns | Consumer's codec sees |
|---|---|---|---|
| `Full` | `present ≥ n_source` | manifest + all present symbols | Lossless reconstruct guaranteed |
| `Partial` | `min_viable_symbols ≤ present < n_source` | manifest + surviving symbols + present count | RaptorQ overhead-profile probability of decode — the genuine middle zone |
| `EnvelopeOnly` | `present < min_viable_symbols` | manifest only | "Existed with signature X, content unavailable" — envelope still shape-valid |

The producer pins `min_viable_symbols` at manifest creation as a BLINKING_DOT floor. Persist's eviction policy honors `retention_priority` (`FountainSymbolV1.retention_priority`, a u8) — the producer folds SVC `ChunkLayer.quality` AND source-vs-repair position into one byte; persist orders by it, evicts highest-value first.

### What "envelope shape valid at every tier" buys CIRIS

The manifest is the signed contract; it carries the trace's #225 hybrid envelope inline. At every tier:

- **The envelope verifies**: `verify_hybrid` over `canonical_bytes(canonicalizer)` returns true at Full, Partial, AND EnvelopeOnly — same bytes, same signature, same key id
- **The symbol-hash chain authenticates surviving bytes**: every `FountainSymbolV1` retrieved is SHA-256-re-verified against its `symbol_hashes[symbol_id]` entry in the manifest; bit-flips fail verification at read time, never silently
- **The shape of the answer is the same**: persist's typed `FountainContent` return is the substrate's honest report — Full / Partial / EnvelopeOnly, not silently-degraded bytes ("substrate honesty" per persist's own module doc)

This is the property the user asked about: persist preserves envelope shape validity *as a primitive*, by retaining the manifest unconditionally and authenticating every surviving symbol against the signed chain. Edge's substrate emits the chain; persist holds the chain; both sides agree on the byte-exact canonical form.

### Why this is better than TimescaleDB-style rollup

TimescaleDB continuous aggregates compute pre-rolled summaries at known time buckets. Loses **specific detail**, retains **aggregate**.

Fountain-code degradation per persist's contract:
- Preserves **shape-valid signed envelope at every tier** — verifiable trace-existed claim survives unconditionally
- The `Partial` class is a genuine middle zone — RaptorQ's overhead profile maps `present/n_source` to reconstruction probability (not a hard fail like a missing index page)
- Eviction granularity is per-symbol via `retention_priority`, not per-time-bucket — granular under pressure
- No schema choice required — fountain codes treat content as opaque bytes
- **Complement, not replacement**: TimescaleDB-style rollup gives you "aggregate answers at degraded fidelity"; fountain-coded eviction gives you "individual-trace existence + probabilistic content recovery at degraded fidelity." Pick rollup when you need aggregate queries; pick fountain when you need provable retention boundaries for audit.

### Use cases

- **Reasoning trace storage**: full fidelity when disk is plentiful; degrade to "trace-existed-with-metadata" under sustained pressure
- **Context windows for agent decisions**: keep full context in primary state; under pressure, accept context-window reconstruction probability < 1
- **Audit / hard-case event corpus**: signed claims survive at max pressure (metadata is small); content reconstructs probabilistically

### Status

**Novel composition, shipped in persist v8.0.0.** No published prior art applies fountain coding to structured-log graceful degradation. The composition is real, the production primitives (raptorq, ChunkLayer) are mature, and CIRISPersist v8.0.0 ([#227](https://github.com/CIRISAI/CIRISPersist/issues/227)) ships the `FountainContentV1` types as the at-rest contract. The property delivered:

1. **Envelope shape valid at every degradation tier** — the signed manifest (carrying the trace's #225 hybrid envelope) is always-retained; verification works at Full, Partial, and EnvelopeOnly identically.
2. **Genuine middle zone via RaptorQ overhead profile** — the `Partial` class returns surviving symbols and a present-count; the consumer's codec maps to a documented reconstruction probability. Not a hard fail.
3. **Authenticated symbol-level integrity** — every surviving symbol is SHA-256-re-verified against the signed `symbol_hashes` chain at read time.
4. **Schema-blind eviction primitive** — `retention_priority: u8` folds SVC `ChunkLayer.quality` AND fountain source-vs-repair position into one ORDER BY column.

Edge's substrate already speaks `ChunkLayer.quality`; persist v8.0.0 honors it. The v3.9.0 codec wiring binds the loop end-to-end.

## Filed follow-ups

- **CIRISEdge#NEW** — substrate-side raptorq + rav1e/dav1d integration. v3.9.0 candidate.
- **CIRISPersist#NEW** — layer-aware DiskPressure eviction policy. Apply to both blob storage AND trace storage.

## Status of v3.8.0 cut

This document **locks in the direction** but does NOT add raptorq / rav1e to the v3.8.0 codebase. v3.8.0 substrate is codec-agnostic and shipping; raptorq integration is additive at v3.9.0+.

## Citations

- [raptorq crate — fastest Rust RaptorQ](https://www.cberner.com/2020/10/12/building-fastest-raptorq-rfc6330-codec-rust/)
- [Raptor codes — Wikipedia (3GPP MBMS, DVB-H deployment)](https://en.wikipedia.org/wiki/Raptor_code)
- [rav1e — Mozilla/Xiph AV1 encoder](https://github.com/xiph/rav1e)
- [Fountain codes — Wikipedia](https://en.wikipedia.org/wiki/Fountain_code)
- [CassandrEAS — Cassandra + erasure coding (IEEE 9306729)](https://ieeexplore.ieee.org/document/9306729/)
- [Fountain codes for DNA data storage (PMC11570749)](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC11570749/)
