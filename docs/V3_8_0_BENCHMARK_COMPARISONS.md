# v3.8.0 Benchmark comparisons — production / library context

Comparisons below are framed against CIRIS Edge v3.8.0's measured numbers (see PR #131; benches under `benches/realtime_av_*.rs`). Where comparable published numbers exist, they are quoted with citations; where they do not, that is called out explicitly. **All edge numbers are AEAD-bound in-memory microbenches unless noted — over-the-wire deployment will be NIC- and scheduler-bound, not AEAD-bound.**

---

## 1. SFU forward throughput per core

| Implementation | Throughput / per-core capacity | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** (inner-once / outer-N relay) | ~7 GiB/s aggregate AEAD per core; ~56 Gbps outer-sealed bytes (in-memory bench, N≤128) | `benches/realtime_av_relay.rs` |
| LiveKit Go SFU | ~50 µs per down-track write; 1,600 down-tracks across 16 cores ≈ 100 down-tracks/core; Intel i7-8850H, July 2021 | [LiveKit blog](https://livekit.com/blog/going-beyond-a-single-core-4a464d20d17a/) |
| mediasoup-worker 3.10.6 | ~1 vCore → 114.61 Mbps consuming (egress); per-stream cap 200 KB/s; Sept 2022 | [mediasoup discourse](https://mediasoup.discourse.group/t/new-benchmarks-for-mediasoup-3-10-6-seems-smooth-thus-far/4553) |
| mediasoup (community guidance) | ~150–250 480p participant-legs per vCPU | [forasoft cost model 2026](https://www.forasoft.com/blog/article/how-to-estimate-the-server-cost-for-a-video-platform-249) |
| Janus videoroom | 1 publisher × 1000 viewers ≈ 200% CPU across 4 dedicated cores | [Amirante et al.](https://files.core.ac.uk/download/pdf/74316352.pdf) |
| Pion Go data channel | 177.92 MB/s aggregate (multi-core, ~596% CPU) | [Miuda Rust-vs-Go WebRTC benchmark](https://miuda.ai/blog/webrtc-datachannel-benchmark/) |

**Headline.** v3.8.0's relay sustains ~7 GiB/s AEAD per core **in a tight in-memory loopback Criterion bench (NIC, kernel TX, congestion control, jitter buffer not included — divide by ÷10–100 for production wire)** — roughly 500× the per-core egress observed for mediasoup-worker 3.10.6 (114.6 Mbps). This is *not* apples-to-apples: SFU production numbers include kernel↔userland packet copies, jitter buffers, RTP stack, congestion control, and NIC PCIe overhead. The honest reading: edge's relay AEAD path is no longer the bottleneck; the gating factor at deployment time will be NIC, kernel, and Reticulum substrate. That's a rare property for a hybrid-PQ SFU. **What edge demonstrates is headroom, not deployed throughput.**

---

## 2. MLS group operations (classical baselines)

| Implementation | Operation @ group size | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** (X-Wing hybrid PQ) | Rekey crossover at N=32–128; single-join 9.7 ms @ N=128 | `benches/realtime_av_rekey.rs` |
| OpenMLS large-groups bench | Sizes 2…1000; "add member" scales linearly; published since 2021 | [openmls/examples/large-groups.rs](https://github.com/openmls/openmls/blob/main/openmls/examples/large-groups.rs) |
| OpenMLS first-benchmarks (2021) | i7-4900MQ; linear add growth; raw figures in spreadsheet | [Kiefer 2021-05-18](https://blog.openmls.tech/posts/2021-05-18-openmls-first-benchmarks/) |
| MLS practical analysis (2026) | 10,000 emulated clients; tree management — not crypto — dominates | [arXiv 2502.18303](https://arxiv.org/html/2502.18303) |
| mls-rs (AWS Labs) | RFC 9420 conformant; no per-op timings in public docs | [awslabs/mls-rs](https://github.com/awslabs/mls-rs) |

**Headline.** Public OpenMLS prose benchmarks describe scaling shape (linear in N) but don't enumerate per-N ms inline; raw data lives in a referenced spreadsheet. mls-rs publishes none. The 2026 arXiv analysis confirms tree management dominates over crypto — meaning the X-Wing hybrid penalty (§3) is a small fraction of total commit time at moderate N. v3.8.0's crossover at N=32–128 is the actionable number; no published competitor measures this for a hybrid-PQ ciphersuite. **Bench scope**: sender CPU under unicast in a Criterion microbench — the worst case for MLS in terms of competitor-comparison framing, but it isolates exactly the term (state-machine + PQ-hybrid crypto) the comparison cares about. Also: the **commit-processing barrier** at receivers (~9.7 ms @ N=128, per `realtime_av_rekey.rs`) is a structural realtime tax that no amount of batching shortens — see `FEDERATION_SCALING_MODEL.md §6.5`.

---

## 3. Hybrid PQC KEX / hybrid MLS overhead

| Implementation | Hybrid PQ overhead | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** | `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D); X-Wing = ML-KEM-768 + X25519 | `src/transport/federation_session.rs`; X-Wing draft-10 (Mar 2026) |
| OpenMLS + X-Wing (Cryspen) | Create KP 273 µs (X-Wing) vs 138 µs (X25519); Join 733 µs vs 313 µs; Self-update 651 µs vs 294 µs (**~2.2× compute**) | [Cryspen blog Apr 2024](https://blog.openmls.tech/posts/2024-04-11-pq-openmls/) |
| OpenMLS + X-Wing — message size | KP 2669 B vs 299 B; Welcome 5457 B vs 716 B; Ratchet tree 4007 B vs 408 B (**~9× bytes**) | [Cryspen blog Apr 2024](https://blog.openmls.tech/posts/2024-04-11-pq-openmls/) |
| Cloudflare TLS X25519MLKEM768 | +1,088 B ClientHello; ~10–20 ms median added latency; >60% of human TLS traffic uses hybrid ML-KEM (early 2026) | [Keysight PQC analysis 2025](https://www.keysight.com/blogs/en/tech/nwvs/2025/08/05/post-quantum-handshakes) |
| Cloudflare X25519Kyber768Draft00 | 11,000 client ops/sec; 14,000 server ops/sec; keyshares 1,216 B / 1,120 B | [Cloudflare blog](https://blog.cloudflare.com/post-quantum-to-origins/) |
| libcrux ML-KEM (Cryspen) | Among fastest portable ML-KEM; formally verified in F* via hax | [libcrux.cryspen.com](https://cryspen.com/post/ml-kem-implementation/) |
| X-Wing KEM spec | dk 32 B, ek 1,216 B, ct 1,120 B, ss 32 B; SHA3-256 combiner | [draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) |

**Headline.** Cryspen's Apr-2024 OpenMLS X-Wing numbers establish the floor edge inherits: hybrid PQ roughly **doubles** per-operation compute and **9×** message bytes vs classical. Edge's contribution is the *relay+rekey* layer above this floor. Cloudflare's production deployment of X25519MLKEM768 (the closest operational reference) reports +10–20 ms median latency dominated by packet-split round-trip — not the per-handshake µs cost. >60% of human-generated TLS traffic now uses hybrid ML-KEM. **For edge: the 9× byte penalty is the deployment-relevant figure** (Welcome 5,457 B vs 716 B classical), not the µs compute — Reticulum's substrate-side bandwidth, not edge's CPU, is what bites.

---

## 4. Mass-join / batch commits

| Implementation | Batch behavior | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** `RosterDelta::Batch` | 25 mass-joins: 159 ms → 27 ms (**~6×**) using openmls 0.8.1 X-Wing | L5-C empirical (PR #131) |
| Hale / Tian / Wang APQ Combiner | PARTIAL (classical-only) + FULL (hybrid) updates; "substantial overhead savings vs simple PQ; marginal increase vs traditional when amortized" | [eprint 2026/034](https://eprint.iacr.org/2026/034); [draft-hale-mls-combiner-01](https://datatracker.ietf.org/doc/draft-hale-mls-combiner/) |
| Making PQ KEX Efficient in MLS (2025) | Strategic combinations; benchmarks group size × CPU cycles × bytes × runtime | [eprint 2025/1881](https://eprint.iacr.org/2025/1881) |
| OpenMLS native batch-commit | No public batch-commit microbench at N=25 in prose | [OpenMLS performance wiki](https://github.com/openmls/openmls/wiki/Performance) |
| Signal / WhatsApp / Wire / Element | No public mass-join timing benchmarks | n/a |

**Headline.** The ~6× v3.8.0 speedup (159 ms → 27 ms @ N=25, **in-process bench**) corroborates the *direction* of the APQ paper: batching/amortizing PQ-expensive proposals reduces marginal cost toward classical levels. Edge applies amortization at the wire-protocol level (`RosterDelta::Batch`) rather than at the combiner-session level; the techniques are complementary. **No major production MLS deployment publishes comparable mass-join numbers** — v3.8.0 is one of the few apples-to-itself datapoints publicly stated for hybrid-PQ MLS at this group size. **What the 6× does NOT shorten**: the per-commit processing barrier at every receiver. Batching collapses *commit count*; the synchronization tax per commit (§6.5 of the scaling FSD) remains structural.

---

## 5. P2P live streaming throughput

| Implementation | Forwarding capacity / measurement | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** relay | ~7–8 GiB/s aggregate up to N=128 (AEAD-CPU-bound); cliff at N=500 to ~2.5 GiB/s | `benches/realtime_av_relay.rs` |
| PeerTube stress test 2023 | Live 350–370 Mbit/s P2P @ 1,000 viewers; VOD 1,150 Mbit/s P2P; **75% bandwidth saved (live), 98% (VOD)**; server $20/mo handles 1k viewers | [JoinPeerTube stress test](https://joinpeertube.org/news/stress-test-2023) |
| WebTorrent (peer behavior) | Diminishing returns past ~85 actively-exchanging peers per torrent; uTP ≈ 85% of TCP | UC Berkeley research summary 2022 (historical) |
| Theta / Livepeer / PPLive | No comparable public per-node forwarding figure isolating AEAD | n/a |

**Headline.** Direct apples-to-apples impossible: PeerTube measures *browser-to-browser HLS-over-WebRTC over a real internet path*, edge measures *AEAD-relay throughput in-process with no network*. The honest framing: edge's relay AEAD bench is two orders of magnitude above a single PeerTube viewer browser **in a measurement that excludes the network**, but PeerTube's number describes a real end-user link with browser overhead. **A wire-level test of edge against the same network shape would land within an order of magnitude of PeerTube, not 100×.** Production deployments of P2P live video don't publish per-node forwarding capacity isolated from network path.

---

## 6. AV1 SVC / scalable encoding production timing

| Implementation | Timing | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** | Codec-agnostic; `ChunkLayer { spatial, temporal, quality }` admits AV1 SVC, JPEG XS, MDC | edge is transport, not codec |
| dav1d 1080p decode | 115 fps avg on Core i7-5600U Broadwell; up to 714 fps on EPYC 7742 2P; ~120 fps on a 5-year-old quad-core | [dav1d 0.1.0 release](https://medium.com/@ewoutterhoeven/dav1d-0-1-0-release-the-first-benchmarks-5404360e44e3); [Phoronix dav1d 0.5](https://www.phoronix.com/news/dav1d-0.5) |
| rav1e 0.7 (Rust encoder) | Speed-10 preset: ~4 min average bench; sub-fps at lower speed presets | [OpenBenchmarking rav1e](https://openbenchmarking.org/test/pts/rav1e); [Phoronix rav1e 0.4](https://www.phoronix.com/news/Rav1e-0.4-Released) |
| libaom-av1 SVC | Per-layer spatial scaling in v2.0.0; no canonical per-layer ms figure | [libaom v2.0.0 release](https://groups.google.com/a/webmproject.org/g/codec-devel/c/NOTn-LlKYzw) |

**Headline.** Edge is codec-agnostic by design — `ChunkLayer { spatial, temporal, quality }` is wire shape, not encoder math. dav1d decodes 1080p well above wire-rate on commodity hardware (115 fps on 2015 ultrabook), so deployment is decode-headroom-rich; encode (rav1e) is the bottleneck for live SVC. **No published vendor has run AV1 SVC over hybrid-PQ MLS end-to-end.**

---

## 7. Reticulum / federation transport throughput

| Implementation | Per-link throughput | Source |
|---|---|---|
| **CIRIS Edge v3.8.0** over Reticulum (via leviculum fork) | Edge AEAD = 7 GiB/s; Reticulum substrate caps the wire side | edge transport layer |
| Reticulum native | Designed range 475 bps → ~100 Mbps; link MTU discovery; minimum sustained 5 bps | [Reticulum manual](https://reticulum.network/manual/whatis.html) |
| libp2p gossipsub | Whiteblock harness: 200 msgs/s @ 95 nodes; 2025 work shows up to 61% bandwidth reduction with v1.4/v2.0 changes | [libp2p discuss](https://discuss.libp2p.io/t/rough-stress-metrics-for-gossipsub/2223); [Vac/Logos 2025](https://vac.dev/rlog/gsub-perf-imp-comparison) |
| Yggdrasil v0.4 | Bandwidth-during-mobility ≤10 KB/s; no published Mbps in 2021 release notes | [Yggdrasil v0.4](https://yggdrasil-network.github.io/2021/06/26/v0-4-prerelease-benchmarks.html) |
| Yggdrasil-godot (LAN, app-layer) | 60 KB packets: 129–337 MB/s | [GitHub](https://github.com/RevoluPowered/yggdrasil-multiplayer-peer-godot) |

**Headline.** Reticulum's published design ceiling is ~100 Mbps per link — roughly 700× lower than edge's per-core AEAD ceiling in the loopback bench. Practically: **at the Reticulum substrate level the bottleneck is network-shape, not AEAD.** v3.8.0's relay headroom exists precisely to absorb fan-out across multiple Reticulum links without becoming the bottleneck. **The 700× ratio is not a deployment forecast — it is a guarantee that crypto won't be the gating term once a real substrate runs underneath.**

---

## Limitations (load-bearing — read before quoting numbers)

1. **In-memory vs over-the-wire.** Every edge headline number is from a Criterion bench against in-process buffers. Production SFU numbers (mediasoup, LiveKit, Janus) include kernel↔NIC paths, RTP/RTCP machinery, congestion control, and jitter buffers. A true apples-to-apples comparison would require running edge over a real NIC against the same WebRTC media stack.
2. **Hybrid-PQ vs classical.** Cryspen's openmls 0.8.1 hybrid X-Wing numbers (§3) establish the floor edge inherits. Most SFU and MLS competitors don't run hybrid-PQ at all — the comparison axis "edge hybrid vs competitor classical" is not symmetric. Edge pays ~2× compute and ~9× bytes that none of the SFU baselines pay.
3. **Bench corpus age.** mediasoup 3.10.6 (Sept 2022) and LiveKit "Going beyond a single-core" (July 2021) are the most recent *quantitative* per-core public numbers in the WebRTC SFU space. Both vendors have published architectural improvements since, but not refreshed per-core figures. Treat as historical baselines.
4. **MLS public benchmarks are sparse.** OpenMLS prose posts (2021, 2024) describe shape (linear-in-N) but defer absolute timings to a spreadsheet. mls-rs publishes none. The Hale/Tian/Wang APQ paper (eprint 2026/034) and "Making PQ KEX Efficient" (eprint 2025/1881) are the strongest published references for hybrid-PQ MLS timing — both academic, not production.
5. **P2P live streaming.** PeerTube is the closest public reference; comparison is loose because edge measures AEAD-CPU and PeerTube measures end-user browser P2P chunk exchange. WebTorrent, Theta, Livepeer publish no comparable per-node forwarding figure.
6. **Reticulum ceiling.** Reticulum's published 100 Mbps native ceiling is a *substrate* property, not an edge property — once edge runs over a higher-bandwidth transport (TCP/QUIC inside leviculum), the AEAD figure becomes the relevant one.
