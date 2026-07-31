# A/V ALM — Design Synthesis

**Status:** living design doc. The capacity-measurement *mechanism* (§5) is pending a
dedicated research pass; everything else is settled. Companion to
`NETWORK_CAPACITY_MODEL.md` and `THREAT_MODEL.md`.

The A/V mesh is edge's flagship. The primitives are all built and unit-tested
(ALM join/heal/capacity, `RelayNode`, `AvDispatcher`, MLS/`AvSession`, codecs);
the work is wiring them into a live runtime and getting the *selection* right.
This doc records the design we build to, the external evidence for it, the threat
model, and the acceptance criteria.

---

## 1. The architecture: consumer-driven trust-but-verify latching

The mesh is **not** a globally-computed authoritative tree (that would be a
`TOPOLOGY_VERSION` fleet-coordination event on every peer). It is a set of
**local, empirical, continuous latching decisions**, and the tree is *emergent*.

A consumer joining a stream:
1. **Attaches to two** offering relays concurrently (redundancy + a live A/B).
2. **Validates empirically** — measures actual source-latency and delivered
   quality against each relay's *signed* capacity claim. The claim is a hint;
   the measurement is ground truth.
3. **Keeps the best** latency×quality fit; **tries a third** if neither clears
   the bar (promoted from a warm candidate cache, not fresh discovery).
4. **Writes a stream-scoped latch attestation** to CEG state recording the bind
   and the measured-vs-claimed delta.
5. **Switches fast** — but *damped* (see §4) — when a parent degrades or lies.

Relays sign a **dynamic capacity attestation** (remaining uplink, servable
layers) updated cheaply as their available uplink changes, freshness-bound so a
replayed "lots of capacity" ad is rejected.

**Why the emergent tree is log-depth without a global optimizer:** each consumer
reads a parent's *current remaining* capacity and won't pile onto a full one, so
the tree fills breadth-first and depth ≈ `⌈log_k N⌉` emerges from local decisions
(k = attested fan-out). The evidence that local-greedy ≈ global-optimal is strong
(§3). The dynamic capacity attestation *is* the depth mechanism.

---

## 2. Why CEWP uniquely solves this

Every open-internet ALM fought capacity-honesty and Sybil with fragile tools —
reputation heuristics, tit-for-tat, or a central tracker — because a capacity
claim could not be bound to an accountable identity, so lying was cheap and a
caught liar respawned free. The honesty feedback loop never closed: there was
nothing durable to attach reputation to.

CEWP closes it:
- **Trust is cryptographic + accountable.** An offering node is a
  shared-root-anchored identity (CIRISEdge#430), its capacity claim a signed,
  freshness-bound attestation on CEG state; it can't cheaply mint a fresh Sybil
  to escape a bad reputation — a new identity costs a shared root.
- **Verify is empirical + attributable.** The consumer measures
  delivered-vs-claimed, and the honesty score **attaches to a durable rooted
  identity** — the thing every prior system lacked.
- **Pollution is structurally impossible.** Relays carry only ciphertext under
  the epoch DEK; a relay can withhold/delay but never *forge* content. This
  sidesteps the entire pollution class classic ALM never solved.

The dynamic capacity attestation + honesty score aren't bolt-ons; they're the ALM
expressed natively in CEWP's attestation grammar.

---

## 3. Lessons from the ALM literature (adopt / avoid)

Sourced from Overcast (OSDI'00), SplitStream (SOSP'03), NICE (SIGCOMM'02),
ZIGZAG (INFOCOM'03), mTreebone (ICDCS'07), CoolStreaming/DONet (INFOCOM'05),
PRIME, GridMedia, Chainsaw, Bullet (SOSP'03), PPLive/UUSee/Spotify
retrospectives, Contracts (NSDI'10), Eclipse attacks (INFOCOM'06), pollution
(P2P-TV'07), power-of-two-choices (TPDS'01), WebRTC GCC, MoQ, SFrame (RFC 9605).

**Adopt**
- **Local-greedy + fast *damped* switching ≈ globally-optimal.** Overcast reached
  70–100% of an optimal router tree; NICE ≈ centralized stretch; SplitStream >95%
  independent paths with no heuristics. **Do not build a global tree optimizer.**
- **Measure *delivered* performance, never a proxy or the claim.** Overcast timed
  a real 10 KB transfer (ping correlated poorly); CoolStreaming scored by observed
  retrieval rate; Bullet culled by observed duplicate ratio.
- **Two active parents is the sweet spot; keep a large *known* / small *active*
  set.** Power-of-two-choices: d=2 is an exponential gain over d=1, d≥3 only
  constant-factor. CoolStreaming M=4, Spotify 4-upload cap agree.
- **Advertise capacity event-driven-but-coalesced.** SplitStream's spare-capacity
  group (implicit membership), UUSee's 30 s dwell gate, Spotify's update-on-play.
  Re-sign only on a bucket/layer crossing — never per-event, never per-tick.
- **Small fixed-size digests.** CoolStreaming 120-bit buffer map; Bullet ~120-byte
  sketch. Cheap to compute and (for us) cheap to sign.
- **Treat an anchor/server fallback as first-class**, not an emergency (Spotify's
  10 s-hard-fallback; UUSee over-provisioning). "Try a third" includes an
  anchor-of-last-resort.
- **Prefer a *complementary* third candidate** (Bullet's lowest-similarity pick).

**Avoid**
- **Undamped re-selection** — the #1 unsolved gap across the mesh-pull generation
  (CoolStreaming/PRIME/Chainsaw/Bullet describe *no* hysteresis). We must supply
  our own (§4).
- **Per-packet / per-subscriber chatter as the control plane** (Chainsaw's
  overhead). Attest at segment/layer granularity; rate-limit re-signs and latch
  writes.
- **Trusting self-reported capacity/buffer-maps** — every classic system did, and
  it got exploited. Our empirical verification is the fix the literature lacked.
- **Reciprocity heuristics instead of verification + fallback.** Tit-for-tat is
  *known to fail in live streaming* (sequential block availability kills trading;
  Piatek et al., Contracts, NSDI'10). Do honesty Contracts-style: verifiable,
  third-party-attestable contribution, not bilateral exchange.
- **Conflating "unreachable/congested" with "lying"** — Spotify's 35% direct-
  connect success means most switch events are NAT/reachability, not malice.

**Verdict:** the local, measurement-driven, 2-then-3 architecture is right. The
gaps are *damping*, *accountable-honesty*, *eclipse-resistant discovery*, and the
*traffic-analysis residual* — not the topology strategy.

---

## 4. Damping (the design's most important missing mechanism)

"Fast switching" with no hysteresis is exactly the failure mode the mesh-pull
generation left open. Four coupled rules (each with a calibrated precedent):
- **Margin** — a challenger must beat the incumbent's latency×quality fit by a
  threshold (Overcast 10% / GetStream 20% reroute floor), not by any amount.
- **Dwell** — sustained over a window (Janus BWE cooldown; GCC over-use ≥10 ms;
  UUSee 30 s), not a single sample.
- **Rate-limit** — cap switches per unit time.
- **Make-before-break** — keep the incumbent delivering (≥ base layer) until the
  challenger is verified (Spotify multi-homing; mTreebone push/pull buffer).

Adaptation is **asymmetric**: react fast to degradation, promote slowly (GCC
`K_u ≫ K_d`). And respect **switch-cost asymmetry** — shed an enhancement layer on
the current parent first (cheap); only escalate to a parent switch if the *base*
layer is threatened or degradation persists past dwell.

---

## 5. The dynamic capacity attestation

The relay signs its **own live remaining uplink + servable layers**. Load-bearing
decisions:
- **Self-count, not latch-sum.** Remaining capacity is the relay's own signed
  self-count (it knows its real subscribers). It is NOT derived from the sum of
  consumer latches (that would be Sybil-gameable). Latch attestations are the
  consumer's routing record, not the capacity ledger.
- **Coalesced + quantized.** Re-sign only when remaining uplink crosses a *bucket*
  or a layer flips servable/unservable. Quantize so most subscriber events don't
  move the signed value — kills noise and signing cost.
- **Freshness-bound.** Carries an epoch/nonce + `valid_until` (the CIRISPersist#561
  pattern); stale/replayed ads are rejected.
- **Advisory, not a guarantee.** Consumers verify empirically anyway, so the
  attestation's job is *discovery/pre-filtering*. Stale-but-cheap beats
  fresh-but-expensive because measurement is ground truth.

### 5.1 Measurement mechanism (resolved)

**The physical fact that resolves it:** a relay actively forwarding a stream is
*application-limited* (sending exactly the stream bitrate, not saturating the
pipe). Passive delivery-rate observation therefore yields a rock-solid **floor**
("I am demonstrably sustaining X Mb/s with no congestion") but *not* the headroom
above it. That is exactly right for a self-scored, adversarially-verified claim:
**you can only sign capacity you have actually demonstrated** — over-claiming is
near-impossible by construction. (BBR delivery-rate estimation; the
`app_limited` flag distinguishes a floor from a real ceiling —
[draft-cheng-iccrg-delivery-rate-estimation].)

**Primary (ongoing, ~free): passive.** Per active link, read a delivery-rate
sample + congestion state (`app_limited`, RTT-over-min, loss) — on Linux literally
`getsockopt(TCP_INFO)` `tcpi_delivery_rate`/`tcpi_delivery_rate_app_limited`; over
Reticulum, the transport's own send/ack accounting. Aggregate to a node-level
*demonstrated-sustainable uplink*. One stat read per link per second, zero added
bytes, no battery hit.

**Secondary (rare, hard-gated): a short calibrated active probe** against a peer
we already have a link to — *only* to bootstrap an idle/first-latch node with no
samples, or to refresh a ceiling gone stale, and *never* on metered cellular /
battery (bufferbloat corrupts delay probing on LTE anyway). Fold into the filter,
never adopt raw.

**Disqualified: centralized web speed-test** — saturates the uplink (disrupts the
very stream), burns metered mobile data, and is a centralized dependency in a
100%-decentralized design. At most an opt-in offline calibration seed, marked
untrusted-to-peers.

**Never trusted: self-reported OS link capacity** (Android `getLinkUpstreamBandwidthKbps`
= first-hop *capability*; iOS `NWPath` gives no throughput number) and
self-reported peer rates (BitTyrant games these for +70%). Use OS capacity only as
an upper *clamp* and an interface-change detector. Peers score on **delivered
bytes**, never the claim.

**Coalesced attestation:** denominate spare in **whole servable stream-layers**
(0,1,2,…); re-sign only when the layer bucket changes. Downgrade a bucket
immediately (safety); upgrade only after it holds K=3 windows (anti-flap).

Portability invariant: as observability drops (Linux → mac/Win → Android → iOS →
cellular) the node claims **less, never more** — fewer signals ⇒ smaller
demonstrated set ⇒ more conservative bucket. The self-scoring safety guarantee
holds on every platform. Per-platform detail + the conservative-filter defaults
(p10 of the worst 30 s window, 0.75 safety margin, staleness 60–120 s) are in the
research transcript.

---

## 6. Give grace, stay safe (the decentralized self-scoring constraint)

**Every capacity commitment is a liability**: in a 100%-decentralized mesh, peers
score us on delivered-vs-claimed, so over-claiming is self-harm. Therefore:
- **Conservative by construction.** Sign a remaining-capacity a node can *virtually
  always* meet — a safety margin, EWMA of the *worst* recent window, reserved
  headroom. Under-promise so the honesty-score risk becomes a non-issue. (Details
  from the research.)
- **Give grace when scoring others.** Honest variance, congestion, and NAT/
  unreachability must **not** read as lying. Require **multi-observer corroboration**
  before a delivered-vs-claimed gap counts as a "lie" (also the eclipse defense),
  apply **hysteresis** before a bad score sticks, and **distinguish
  "unreachable/degraded" from "over-claiming under good connectivity"** in the
  recorded evidence.
- **Stay safe.** A persistent, corroborated, connectivity-good over-claimer accrues
  root-anchored negative evidence (Contracts-style) — private avoidance never
  disciplines liars (PPLive/UUSee proved it).

---

## 7. Boundary: edge emits, LensCore scores

- **Edge = sensor + emitter.** Edge runs the empirical validation and emits
  measured delivered-vs-claimed as **signed, attributable trust signals** onto
  persist's **scores plane** (`list_scores`/`resolve_scores`). Edge never scores.
- **CIRISServer's LensCore = scorer.** It reads the fleet-wide trust signals and
  computes the per-identity honesty score.
- **Two loops, different tempos.** Edge's own local measurements drive the
  immediate fast-switch (no lens round-trip for a reparent); LensCore's score is
  the slow global reputation, read back from state for selection.
- **CIRISEdge#352** (adopt persist v17.4.0 `list_scores` pushdown) is the enabling
  adopt for the emit/read path. This is a clean producer(edge)/consumer(lens)
  split over shared state — NOT a downstream dependency.

---

## 8. Threat model (CEWP-native)

Primitives: **(TV)** trust-but-verify measurement; **(DA)** dynamic signed
capacity; **(SR)** shared-root anchoring; **(CT)** ciphertext-only relay;
**(LATCH)** stream-scoped latch attestation. Recurring pattern: trust-but-verify
converts most *integrity* attacks into *availability* annoyances that attach-2 +
damped fast-switch blunt.

| Attack | Covered? | Residual / addition |
|---|---|---|
| Content pollution / forgery | **Yes, structurally (CT)** — relay can't forge plaintext | AEAD at admission rejects corrupted ciphertext → degenerates to availability |
| Capacity-lying | **Yes (TV+DA)** — measure delivered vs signed claim | Make accountable via **(LATCH)** measured-vs-claimed delta → LensCore score; guard false-positives (§6) |
| Free-riding / non-contribution | **Partial (DA+LATCH)** — under-delivery is demotable | Reward contribution with QoS/layers (Contracts), not download rate; keep anchor fallback |
| Sybil | **Mostly (SR)** — certified identities bound minting | Only as strong as root admission (M-of-N humanity-accord root helps) |
| **Eclipse / biased discovery** | **Weak — genuine gap** | **Source the 2(+1) candidates from independent discovery paths**; degree-bound; prefer diversity (reuse `swarm::diversity`). SR blocks trivial Sybil, not eclipse |
| Selective availability (drop/withhold, looks like loss) | **Detected, not attributed (TV)** | **Dual-source the base layer** during measure/switch (GridMedia multi-sender) so one relay's drop can't stall playback; weight keyframe-loss heavily |
| **Traffic analysis on encrypted layer sizes/timing** | **NOT covered — CT does not buy this** | The layer-size/cadence + dependency-descriptor metadata a relay MUST read to pick layers is the ~99% fingerprinting surface (Schuster USENIX'17; SFrame KID/CTR leaks by spec). Accept as residual or pay for padding; **bound hop count / require per-hop attestation continuity** |
| DoS via fake subscribers / attestation churn | **Partial (SR+DA)** | **Coalesce** re-signs (bucket/dwell) + soft-state TTL latches; else "re-sign per subscriber" IS the DoS surface |
| Interior-node SPOF | **Partial (multi-parent)** | Keep the standby parent **warm** (make-before-break); don't single-point-depend on any coordinator or the state store |
| Parent flapping / oscillation | **Addressed by §4 damping** | The design's original "fast switching" had none — §4 is mandatory |

---

## 9. Acceptance criteria (what green means)

The perf suite (`src/transport/realtime_av_alm/sim.rs`, deterministic N-node
virtual-clock sim forked from the DST harness) is the graded bar:
- **Bandwidth-constrained mesh formation** (the acceptance gate): 8K@X stream,
  N=100, per-node uplink 2X and 10X — **both must form + deliver to all N; the only
  difference is max latency ∝ depth ≈ ⌈log_k N⌉.** Currently RED against the
  chaining planner (depth 50 at 2X = 2500 ms), which is the point — green here IS
  the proof the planner respects the capacity attestation.
- M1 RTT-stretch ≤ 1.3 p95; M2 time-to-reparent p95 ≤ `PARENT_SILENCE_HEAL_MS`+RTT+
  backoff, p99 < 2500 ms; M8 loss resilience ≥ 0.999 first-delivery @5% with the
  full parent set.
- **To add** (from the research gaps): a **damping/flapping** criterion (no
  oscillation without a margin+dwell improvement) and an **emergent-tree** variant
  (N consumers latching locally against dynamic capacity — grades the live path,
  not just the global planner).

---

## 10. Cross-repo issues (verified + filed)

The measurement mechanism (§5.1) is now set, so the accurate set is filed. The
"crystal-clear-before-filing" discipline **dissolved the two speculative asks**:

**Filed:**
- **leviculum#35** (FILED) — expose per-link delivery telemetry (delivery-rate,
  min/smoothed RTT, and the app-limited/backpressure bit) so a relay can measure
  and honestly attest its demonstrated-sustainable uplink passively. The `Busy`/
  `TransferInProgress` backpressure signal *is* the congestion bit. Verified-needed:
  edge sees what it *offered*, but delivered/acked + congestion state live at
  leviculum's layer.
- **leviculum#29** (OPEN, strengthened) — transport concurrency ceiling (single
  `Mutex<StdNodeCore>` serializes sends). Commented with the A/V fan-out
  amplification; the criteria suite will pin the N-peer threshold. #29 raises the
  ceiling; #35 lets us read where it currently is. Not duplicated.
- **CIRISServer#334** (FILED) — honesty scoring over edge-emitted delivered-vs-claimed
  trust signals on the scores plane: multi-observer corroboration, attribution
  guard, hysteresis, blast-radius ordering (give grace, stay safe). Edge emits,
  the server's lens scores. Depends on CIRISEdge#352.

**Dissolved on verification (not filed):**
- **verify** — no new signing path needed. Re-attestation is *coalesced* (re-sign
  only on a servable-layer bucket crossing), so signing is infrequent → the
  existing hybrid signer is fine. The speculative "cheap re-sign" ask evaporated.
- **persist** — nothing new. The relay-capacity plane is edge-owned
  (CIRISPersist#144); the scores plane (`list_scores`/`resolve_scores`) already
  exists, and CIRISEdge#352 is the edge-side emit/read adopt.

---

## Sources
Overcast (OSDI'00), SplitStream (SOSP'03), NICE (SIGCOMM'02), ZIGZAG (INFOCOM'03),
mTreebone (ICDCS'07), CoolStreaming/DONet (INFOCOM'05), PRIME (INFOCOM'07),
GridMedia (ACM MM'05), Chainsaw (IPTPS'05), Bullet (SOSP'03), PPLive measurement
(Hei/Ross), UUSee (TOMCCAP'10), Spotify P2P (Kreitz & Niemelä, P2P'10), Contracts
(NSDI'10), BitTyrant (NSDI'07), Eclipse attacks (INFOCOM'06), pollution (P2P-TV'07),
power-of-two-choices (TPDS'01), encrypted-video traffic analysis (USENIX Sec'17),
SFrame (RFC 9605), AV1 Dependency Descriptor, frame-marking (RFC 9626), Trickle ICE
(RFC 8838), GCC (draft-ietf-rmcat-gcc-02), MoQ transport. Full URLs in the research
transcript.
