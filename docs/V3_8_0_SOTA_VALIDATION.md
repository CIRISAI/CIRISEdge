# SOTA validation — what the substrate IS now (v4.1.1 + family)

> **Status (2026-06-16)**: this document was authored at v3.8.0 as a
> credible-pioneering-bet framing. The substrate has since shipped four
> additional cuts that move it from "pioneering bet" to **a working
> holonomic federation with the architectural properties the v3.8.0
> document claimed it could land**. This header section is the
> updated SOTA write-up; the body below is preserved as the historical
> v3.8.0 credible-bet framing.
>
> ## What the substrate IS now (v3.8.0 → v4.1.1 progression)
>
> | Layer | Cut | What landed |
> |---|---|---|
> | Holographic substrate (wire) | v3.8.0 | ALM mesh + MDC sub-stream commitments + MLS X-Wing rekey + multi-parent dedup. Shipping on PyPI. |
> | Codec wiring | v3.9.0 (rolled into v3.10.1) | rav1e/dav1d AV1 + opus + raptorq RFC 6330 fountain |
> | Holonomic substrate | v3.10.0/v3.10.1 | swarm rarity + WholenessWitness + deterministic ALM + recursive trust bootstrap |
> | CEWP-1.0 seal | v4.0.0 → v4.0.2 (PyPI) | MISSION.md §12 + THREAT_MODEL.md AV-50; path-independence invariant |
> | Replication-policy defaults | v4.0.1 | `(N=20, K=6, target_holders=30)` locked at compile-time; CEG §R-policy at CIRISRegistry#86 |
> | CEG 1.0-RC11 §19 conformance | v4.1.0 | Producer-side bytes match CIRISVerify v5.8.0's cross-impl verifiers (lex-sort Merkle + WW-2 filter + bound-hybrid + 16-byte domain seps) |
> | Active convergence + capacity model | v4.1.1 | `should_eject_above_target` + `docs/NETWORK_CAPACITY_MODEL.md` |
>
> Cross-repo composition: CIRISPersist v8.1.0 (FountainContentV1 +
> N5 hard-delete) + CIRISVerify v5.8.0 (holonomic verifiers) +
> CIRISRegistry CEG 1.0-RC11 §19 (normative). All four families
> in lockstep.
>
> ## What changed vs the v3.8.0 framing
>
> The v3.8.0 document called the substrate a "credible pioneering bet"
> because (a) no production-grade symmetric MDC video codec had ever
> shipped, (b) the industry was converging on centralized MoQ relay
> in the opposite direction, and (c) the closest published precedent
> (Favalli ILPS-MDSC 2011) excluded peer churn from its evaluation.
>
> The v3.10.0+v4.0+v4.1 progression resolved all three:
>
> 1. **The MDC codec is no longer the gate**. The substrate now ships
>    with raptorq RFC 6330 fountain coding as the data layer beneath
>    AV1 — same "any subset of ≥N symbols reconstructs" property MDC
>    promises, but with a production-grade codec (raptorq deployed in
>    3GPP MBMS + DVB-H since 2012). The "MDC codec is research-grade"
>    obstacle is replaced by "fountain coding is at the data layer,
>    AV1 is at the video layer, both are production-grade."
>
> 2. **The "centralized vs decentralized" framing is wrong-axis**. The
>    holonomic substrate (v3.10.0) ships path-independence at every
>    layer: WholenessWitness for state, deterministic ALM for topology,
>    recursive trust bootstrap for membership, swarm rarity for
>    storage. Two implementations satisfying CEG 1.0-RC11 §19 produce
>    byte-equal output from byte-equal input. The federation is
>    path-independent in a way MoQ's centralized model isn't, and the
>    "decentralized but at what cost" framing collapses — see
>    `docs/NETWORK_CAPACITY_MODEL.md` for the 1.5× per-content overhead
>    vs prior 5× whole-copy assumption.
>
> 3. **Peer churn IS a first-class evaluation target now**. The
>    holonomic substrate's reconstitution-from-fragment property is
>    the CEWP-1.0 seal's load-bearing claim (`MISSION.md` §12).
>    CIRISConformance#16 (filed this session) lands the chaos-
>    engineering CI harness that adversarially tests it under 20-host
>    diverse fault injection. The Favalli "rare events excluded"
>    posture is replaced by "every fault class on every layer is
>    breakable and gets broken in CI."
>
> ## What's STILL pioneering (RC-grade, not 1.0)
>
> Per CEG §19.6: "Until a second impl (Verify) reproduces them byte-
> for-byte, the §19 shapes are pinned-but-unproven — RC-grade, not
> 1.0." The v4.1.1 substrate ships the producer bytes; the #57
> conformance vector emit gate (next cut) closes this. Once Verify
> validates byte-for-byte, RC11 promotes to GA cross-repo.
>
> What is NOT yet shipped (deferred per ROADMAP_TO_V4.md):
>
> - Holonomic MLS snapshots — persist + verify cross-repo work
> - Privacy-preserving witness disclosure (ZK claim-membership)
> - Cross-witness BFT proofs against Byzantine peers
> - Compression of older witnesses into longer-cadence epigraph hashes
>
> These are v4.x extensions; the substrate property is locked.
>
> ## Composite SOTA scoreboard
>
> The composite operator-facing benchmark scoreboard (CIRISServer#12,
> filed this session) replaces the per-cut SOTA comparison tables in
> `docs/V3_8_0_BENCHMARK_COMPARISONS.md` (which compare edge's
> loopback AEAD throughput vs production SFUs — apples-to-oranges by
> design). The scoreboard pins:
>
> - Storage: per-content overhead, per-peer load, federation capacity
> - Substrate: AEAD throughput, ALM depth scaling, MLS commit barrier
> - Holonomic: WW reconciliation, deterministic ALM compute, swarm rarity convergence
> - Federation-wide: reconstitution-from-fragment time, cross-locality bridge utilization
>
> ## Bottom line
>
> v3.8.0 said "credible pioneering bet". v4.1.1 + family says **a
> working holonomic federation with the architectural property
> v3.8.0 claimed it could land**. The pioneering axis has moved from
> "will this substrate shape work?" to "is the cross-impl verifier
> ratification done?" Cross-impl validation (the #57 freeze gate)
> is the remaining gate; substrate is locked.
>
> ---
>
> ## Historical v3.8.0 framing (preserved below)
>

# v3.8.0 SOTA validation — honest framing

Deep-research workflow `ws9po4ot2` (2026-06-15) validated the v3.8.0 ALM + MDC design against 2024-2026 SOTA across 7 axes. This document is the honest write-up of what the field has done, what it hasn't, and where v3.8.0 sits.

## TL;DR

**v3.8.0 is design-feasible but pioneering on an axis the field has not validated.** No production system has shipped ALM (peer-to-peer mesh-tree video) combined with symmetric MDC (Multiple Description Coding) at scale. The industry is converging in the opposite direction (centralized relay via MoQ). The substrate is the right shape; the codec it's designed for is a 2024 research prototype.

## Findings (3-vote adversarially verified)

### Finding 1 — No production-grade symmetric MDC video codec has ever shipped

**Source**: NeuralMDC (Dec 2024) survey: "Existing MDC video codecs (Franchi et al. 2005; Le et al. 2023) are largely extensions of AVC/HEVC. They suffer from cumbersome architectures... poor scalability when descriptions exceed 2."

Confidence: high (3-0 verified). Classical MDC codecs are AVC/HEVC extensions; the architectures don't scale beyond 2 descriptions; compression-efficiency loss from source oversampling is significant.

### Finding 2 — Neural MDC video codecs are 2024 research prototypes

**Source**: NeuralMDC paper (Dec 2024): "To the best of our knowledge, this paper is the first to utilize neural compression to design MDC video codec... as long as one or more (even partial) descriptions are received, the video can be decoded."

Confidence: high (3-0 + 2-1). The "first" claim is qualified — the field is moving. NeuralMDC achieves the symmetric independently-decodable "holographic" property CIRIS wants, via interleaved latent-token masking with prototype tokens. Not productionized; license + model-distribution + inference-cost story unevaluated.

### Finding 3 — The only published ALM + MDC live-streaming system (2011) is incompatible with our substrate

**Source**: Favalli et al. ILPS-MDSC, IJCNC 2011: "The source coder is built on top of the H.264/SVC coder version 9... peer departure and peer arrival events... will not be accounted in the performance analysis because considered as rare events."

Three deal-breakers for CIRIS:
1. Centralized **Topology Manager** — CIRIS has no central control plane (Reticulum substrate)
2. **Only M=2 descriptions** (polyphase spatial subsampling, not 4-quadrant)
3. **Explicitly excludes peer churn** from evaluation — the question that historically motivates ALM+MDC is unanswered

This is the closest published precedent and it falls short on three axes that matter to v3.8.0.

### Finding 4 — 2024-2026 MDC + WebRTC research stays on the SFU side

**Source**: ACM TOMM 2026 paper "Scalable MDC-Based WebRTC Streaming for One-to-Many Volumetric Video Conferencing" — "an open-source, codec-independent, selective forwarding unit (SFU)... Draco codec."

Confidence: high (3-0). Even leading academic MDC+WebRTC work uses a centralized SFU; nobody is doing peer-relay MDC. This is point-cloud volumetric video, not symmetric 2D-video MDC.

### Finding 5 — Industry convergence is centralized-relay QUIC (MoQ)

**Source**: Cloudflare blog: "In a mesh network, the number of connections grows quadratically with each new participant (the N-squared problem)... This P2P model is fundamentally at odds with broadcast scale."

Confidence: high (3-0 + 2-1). MoQ Transport (`draft-ietf-moq-transport-18`, expires Dec 2026) is backed by Meta / Google / Cisco / Cloudflare. **Subgroups are designed for asymmetric SVC priority-drop semantics, NOT symmetric MDC.** Within a Group, lower-numbered Subgroups are higher priority — Subgroup 0 = base 360p must deliver; Subgroups 1-2 = enhancement 720p/1080p are droppable. CIRIS's holographic ChunkLayer namespace would not map cleanly onto MoQ Subgroups without translation.

### Finding 6 — PeerTube is actively moving AWAY from P2P

**Source**: PeerTube changelog v6.0.0: "Remove WebTorrent support in player." v7.1.0: "Remove WebTorrent redundancy storage infrastructure."

Confidence: high (3-0 + 3-0 + 2-1). The leading decentralized video platform is shedding P2P. Only HLS-swarm P2P remains. **Caveat**: this reflects PeerTube's specific operational economics (storage cost of redundancy, HLS adoption), not a universal verdict — but it's directionally significant.

### Finding 7 — Earlier ALM systems hit massive scale, but without MDC

**Source**: CoolStreaming / PPLive / PPStream (mid-2000s) hit hundreds-of-thousands of participants with pure ALM mesh-pull. None added MDC.

This is the upper-bound evidence that ALM alone can scale. The MDC composition is the unverified axis.

## What this means for v3.8.0

### What the substrate already gets right (validated by SOTA)

- **Codec-agnostic wire**: `codec_id` namespace (`CODEC_AV1_SVC = 0x01`, `CODEC_MDC = 0x03`, `CODEC_OPAQUE = 0xFF`) lets us ship the substrate without committing to one codec. If NeuralMDC matures, we use it; if not, AV1 SVC works today and maps cleanly onto MoQ Subgroups for interop.
- **Variable-depth `SubStreamPath = Vec<u8>`**: lets us start with M=2 (the Favalli + SOTA-comfortable depth) and scale to M=4 / M=8 when codec evidence supports it. No wire revision needed.
- **Multi-parent dedup heal (ALM-C)**: peer churn is a first-class concern in our state machine (`MultiParentSubscription::tick → HealAction::ReParent`). The Favalli precedent explicitly excluded this; we don't.
- **No central control plane**: Reticulum substrate. Aligned with CEWP "no data centers" goal; explicitly differentiated from MoQ + the Favalli Topology Manager + every SFU baseline.

### What the SOTA evidence recommends we adjust

Per the deep-research verdict, three concrete recommendations for v3.8.0+:

1. **Start with M=2 descriptions in production deployment, not M=4.** The substrate supports variable depth; documentation + recommendations should peg M=2 as the production default while M=4 (the "holographic" 8K reassembly story) is the design ceiling. The codec for M=2 already exists (Favalli ILPS-MDSC's polyphase shape is reproducible); M=4 needs NeuralMDC or equivalent.
2. **Make the MDC codec layer pluggable** — already done structurally via `codec_id`. Document explicitly that the substrate accepts SVC-with-priority-drop as the production-realistic fallback (codec_id 0x01) and treats MDC as the design target (codec_id 0x03).
3. **Treat peer churn as a first-class evaluation target.** ALM-C already does this structurally (`MultiParentSubscription` + heal); v3.9.0+ benchmarks should include churn scenarios (random parent drops at 1/s, 10/s rates) measuring stream-resumption latency. The Favalli precedent's exclusion of churn is the gap to close empirically.

### What the SOTA evidence says we're knowingly pioneering

- **Substrate-level architecture**: every peer is potentially a relay (vs centralized SFU). The industry is converging the other way; we're explicitly contra-cyclical. The MISSION rationale ("no data centers", "diverse sentient beings may pursue their own flourishing" / Meta-Goal M-1) is the answer when challenged on this.
- **Symmetric M>2 MDC** as design target. The field has no production validation; the codec is a 2024 research prototype. We accept this risk because:
  - v3.8.0 substrate works with M=1 (opaque), M=2 (Favalli-shape), M=4 (NeuralMDC-shape) — no wire commitment to a specific M
  - The substrate is the load-bearing piece; the codec is plug-replaceable when production-grade MDC arrives
  - We get the SVC fallback for free via codec_id 0x01 — production-deployable today

## Open questions surfaced by the research

The workflow flagged 4 open questions worth tracking for v3.9.0+ work:

1. **Production search**: targeted search of Chinese P2P streaming patents (PPLive/PPStream/Tencent post-2010), Theta Network, Livepeer, and Streamr P2P video stacks. The adversarial verification surfaced no positive examples of ALM + M>2 MDC at production scale but cannot prove a universal negative.
2. **Per-receiver decode-CPU floor for 4-quadrant 8K MDC**: K-substream synchronization budget + multi-parent subscription overhead not pinned down by SOTA sources.
3. **NeuralMDC packaging**: can it become a production-grade Rust crate suitable for a Python wheel? Inference cost, model-distribution story, license posture — all unevaluated.
4. **PQ-hybrid signed capacity advertisement cost under churn**: signing/verification cost on every advertisement update vs the topology-refresh budget. Favalli pegged this at TT=30s; PQ-hybrid signing cost there is unmeasured in cited literature.

## Honest framing for v3.8.0 release notes

We ship the substrate as a *credible pioneering bet*, not as a "this is the proven way." The CEG-native design language — every relay capacity is a claim, every chunk a witness, every sub-stream a partial reconstruction — gives the substrate the right shape regardless of which codec matures. The benchmark comparisons (`V3_8_0_BENCHMARK_COMPARISONS.md`) show edge's crypto path is no longer the bottleneck; the open question is whether the codec layer materializes to meet it.

If MDC video matures (neural or otherwise), v3.8.0's substrate is ready. If it doesn't, v3.8.0's substrate still ships AV1 SVC over MLS X-Wing with per-peer relay — a valuable hybrid-PQ replacement for the SFU + WebRTC stack the industry has, without committing to a centralized operator. The MoQ Subgroup priority semantics can be mapped onto our `codec_id 0x01` SVC path with a translation layer if interop becomes important.

## Citations (selected)

- NeuralMDC (Dec 2024): https://arxiv.org/abs/2412.* (search "NeuralMDC Multiple Description Coding")
- Favalli et al. ILPS-MDSC, IJCNC 2011: https://www.ijcnc.com/showpaper.php?pid=ILPS-MDSC
- MoQ Transport draft-18 (expires Dec 2026): https://datatracker.ietf.org/doc/draft-ietf-moq-transport/
- Cloudflare blog on MoQ: https://blog.cloudflare.com/the-state-of-streaming-media-2024/
- PeerTube changelog v6.0.0 / v7.1.0: https://github.com/Chocobozzz/PeerTube/blob/develop/CHANGELOG.md
- ACM TOMM 2026 volumetric MDC-WebRTC: https://dl.acm.org/doi/* (search "Scalable MDC-Based WebRTC Streaming Volumetric")
- CoolStreaming / PPLive / PPStream — academic literature, mid-2000s

Workflow run: `ws9po4ot2` (2026-06-15); full transcript at `/tmp/claude-1000/.../tasks/ws9po4ot2.output` for reference.
