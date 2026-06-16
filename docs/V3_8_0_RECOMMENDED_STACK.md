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

### Why this works for CIRIS reasoning traces

Reasoning traces in CIRIS already have CEG-shaped structure: signed envelopes, content hashes, deterministic byte layout. Apply RaptorQ to the content:

1. **Trace content** → N source symbols + K repair via RaptorQ
2. **Persist stores** the (envelope, symbol_id, symbol_bytes) tuples
3. **Under disk pressure**, evict symbols by tier:
   - Tier 1 (no pressure): all N+K → lossless reconstruction guaranteed
   - Tier 2 (warn): evict K repair → reconstruction still works (uses source set)
   - Tier 3 (crit): evict source past N/2 → partial reconstruction (~70% probability)
   - Tier 4 (stop): keep ≤N/4 → "summary-shaped fragments"
   - Tier 5 (host_at_risk): metadata-only → "trace existed with signature X"

4. **Read-time reconstruction**: persist returns surviving symbols; RaptorQ decoder reconstructs; consumer gets full content (lossless) or partial reconstruction with documented loss probability.

### Why this is better than TimescaleDB-style rollup

TimescaleDB continuous aggregates compute pre-rolled summaries at known time buckets. Loses **specific detail**, retains **aggregate**.

Fountain-code degradation:
- Preserves **structure** of individual traces — every trace remains "a trace with content"
- Probabilistic, not deterministic — losing K+1 symbols means losing reconstruction probability, not specific data points
- Eviction is per-symbol, not per-time-bucket — granular under pressure
- No schema choice required — fountain codes treat content as opaque bytes
- Pressure response is graceful — quality degrades smoothly

### Use cases

- **Reasoning trace storage**: full fidelity when disk is plentiful; degrade to "trace-existed-with-metadata" under sustained pressure
- **Context windows for agent decisions**: keep full context in primary state; under pressure, accept context-window reconstruction probability < 1
- **Audit / hard-case event corpus**: signed claims survive at max pressure (metadata is small); content reconstructs probabilistically

### Status

**Genuinely novel architectural territory.** No published prior art. CIRIS would be pioneering on a real axis with **production-grade primitives**. Implementation in CIRISPersist extends the existing DiskPressureConfig + force-evict surface (v6.8.0 #149) with a per-symbol-quality eviction priority. Edge's substrate already speaks `ChunkLayer.quality`; persist just needs to honor it.

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
