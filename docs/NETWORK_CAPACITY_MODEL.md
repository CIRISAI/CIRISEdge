# Network capacity model — v4.1.1+ fountain holonomic substrate

> **Status**: canonical model derivation. Replaces the pre-v3.10.0 whole-
> copy replication assumption. Cross-references CIRISRegistry#88 (the
> updated network model surface), CIRISRegistry#86 (CEG §R-policy
> defaults), and CIRISPersist v8.1.0's `FountainContentV1` contract.

## Why this exists

Before v3.10.0, federation capacity toy-models assumed **whole-content
replication** — every "copy" of a piece of content stored the full
content bytes on a peer. Typical assumptions ranged from 3× to 5×
overhead per content.

The v3.8.0 → v4.1.x substrate progression shipped a different model:
**per-symbol fountain-encoded retention** plus **holonomic substrate
guarantees**. The math is fundamentally different, and the headline
efficiency gain is ~3.3×. This document is the load-bearing derivation
for any capacity-planning conversation across the family.

## Inputs (the model's parameters)

| Parameter | Symbol | Default | Source |
|---|---|---|---|
| Federation peer count | `M` | varies | operator |
| Bytes per peer | `D` | varies | operator |
| Source-symbol count | `N` | 20 | `holonomic::fountain_defaults::DEFAULT_N_SOURCE` |
| Repair-symbol count | `K` | 6 | `holonomic::fountain_defaults::DEFAULT_K_REPAIR` |
| Target holders per content | `H` | 30 | `holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS` |
| Min viable (BLINKING_DOT floor) | `V` | 5 | `holonomic::fountain_defaults::DEFAULT_MIN_VIABLE_SYMBOLS` |
| Over-target safety margin | `S` | 15% | `holonomic::swarm_rarity::EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT` |
| Eject-above-target threshold | `H × (1 + S/100)` | 34 (at defaults) | derived |
| Locality count | `L` | varies | operator |

## Core derivation

```
content_size              ≈ N × symbol_size
symbols_per_holder        = 1                       (max-distribution model)
network_holders           = H                       (target_holders default)
network_storage_per_content = H × symbol_size
                            = (H / N) × content_size
                            = (30 / 20) × content_size
                            = 1.5 × content_size
```

**Replication factor: 1.5× per content** (vs 5× whole-copy → 3.3× more
efficient).

## Per-peer load

```
per_peer_storage_per_content = symbol_size
                             = content_size / N
                             = content_size / 20
                             = 5% of content_size
```

A peer participating in a content's retention holds **5%** of the
content size, not 100%.

## Federation-wide capacity

```
total_disk         = M × D
content_capacity   = total_disk / 1.5      (full-fidelity retention)
                   = M × D / 1.5

(vs prior whole-copy 5× assumption: M × D / 5)
```

Same hardware, **3.3× more content** carryable.

### Concrete numbers

| Federation shape | Total disk | Old toy (5×) capacity | New model (1.5×) capacity |
|---|---|---|---|
| 100 peers × 100 GB | 10 TB | 2 TB | 6.67 TB |
| 1,000 peers × 100 GB | 100 TB | 20 TB | 66.7 TB |
| 10,000 peers × 10 GB | 100 TB | 20 TB | 66.7 TB |
| 100 peers × 1 TB | 100 TB | 20 TB | 66.7 TB |

## Per-locality coverage

For a federation of `L` populated localities with peers distributed
roughly evenly, the per-locality holder count for any one content:

```
holders_per_locality ≈ H / L          (at convergence, assuming uniform spread)
locality_storage_per_content = holders_per_locality × symbol_size
                            = (H / L) × (content_size / N)
                            = (30 / L) × (content_size / 20)
```

For `L = 10` localities: each locality holds `3 × 5% = 15%` of any one
content. Inter-locality fetch is rare; intra-locality fetch (the LAN-
bandwidth path per FEDERATION_SCALING_MODEL.md §9) dominates.

## Degradation tiers (the holographic property)

Under disk pressure, the substrate degrades gracefully via per-symbol
tier eviction. The per-content overhead curve:

| Pressure level | Holder count | Per-content overhead | Reconstruction |
|---|---|---|---|
| None | 30 | **1.50×** | Full (lossless + FEC headroom) |
| Warn (1 GiB free) | 20 | **1.00×** | Full (lossless via source set) |
| Crit (500 MiB) | sub-20 | **< 1.00×** | Partial (RaptorQ overhead-profile probability) |
| Stop (200 MiB) | min_viable = 5 | **0.25×** | EnvelopeOnly threshold |
| Host-at-risk | 0 symbols | envelope_only | Auditable claim only |

The substrate-honest property: under pressure, federation *effective*
content capacity GROWS (more contents fit at lower fidelity). Whole-
copy replication has the opposite behavior — pressure forces wholesale
content loss.

## Survival floor (what fraction can leave before reconstruction fails)

For content with `H = 30` holders and `N = 20` reconstruction
threshold, the federation reconstitutes content losslessly as long as
≥ 20 of its 30 holders remain reachable. The model:

```
P(reconstruction | q peers reachable, R holders)
  = P(Binomial(R, q) ≥ N)
```

At default (R=30, N=20):

| Per-peer availability q | P(reconstruction) | Margin |
|---|---|---|
| 0.95 (datacenter) | 0.99996 | mean = 28.5 |
| 0.90 (typical wifi) | 0.9994 | mean = 27.0 |
| 0.85 (medium churn) | 0.9961 | mean = 25.5 |
| 0.80 (high churn) | 0.974 | mean = 24.0 |
| 0.70 (battlefield mesh) | 0.762 | mean = 21.0 (marginal) |

Design target: 99.95% reconstruction at q = 0.85. The federation
survives up to ~33% of holders going offline before reconstruction
probability drops below 99%.

## Active convergence — the eject primitive

Without proactive trim, the federation only converges to `H` via
rarity bias — eventually correct, but slow and reactive. v4.1.1 adds
`should_eject_above_target(holders_observed, policy, consent,
local_symbol_rarity)`:

```
over_target_threshold = H × (1 + S/100)  = 34 at defaults

if consent == Revoked:        EjectHardDelete   (calls persist#145)
elif holders_observed <= 34:  Keep
elif local_symbol_rarity is common:  EjectToTier
else:                         Keep              (rare local symbol; load-bearing)
```

This is the active-convergence half. Reactive rarity bias acts when a
peer evaluates a fountain content; `should_eject_above_target` acts
even when the local symbol passes rarity gating, because over-
replicated content wastes network-wide storage that could carry
additional content.

## What the model unifies

Anyone in the family doing capacity-planning should plug these
parameters into one formula:

```python
def content_capacity(M, D, N=20, K=6, H=30):
    overhead = H / N                       # = 1.5 at defaults
    return (M * D) / overhead

def per_peer_load(content_size, N=20):
    return content_size / N                # = 5% at defaults

def survival_probability(R, N, q):
    # Binomial CDF: P(X >= N | Binomial(R, q))
    from math import comb
    return sum(comb(R, k) * q**k * (1-q)**(R-k) for k in range(N, R+1))
```

## Cross-repo composition

- **CIRISEdge v4.1.1** — sources the `FountainPolicy` defaults +
  `should_eject_above_target` primitive. Modules:
  `holonomic::fountain_defaults`, `holonomic::swarm_rarity`.
- **CIRISPersist v8.1.0** — `FountainContentV1` at-rest contract;
  `evict_fountain_content_to_tier` + `evict_fountain_content_hard_delete`
  eviction surface.
- **CIRISVerify v5.8.0** — `ciris_verify_core::holonomic` verifier
  semantics that pin the wire shapes the model assumes.
- **CIRISRegistry#88** — composite operator-facing model + calculator
  built from this derivation.

## Citations

- CIRISEdge v3.10.0 holonomic substrate (PR #141)
- CIRISEdge v4.0.1 fountain defaults (PR #142 → v4.0.x)
- CIRISEdge v4.1.0 RC11 §19 conformance (PR #146)
- CIRISPersist#227 `FountainContentV1` primitive (v8.0.0)
- CIRISPersist v8.1.0 N5 hard-delete + verify v5.8.0 pin
- CEG 1.0-RC11 §19 holonomic substrate
- CIRISRegistry#85 (CEG normative absorption), #86 (§R-policy defaults),
  #87 (§H HSP), #88 (composite network capacity model)
- RFC 6330 RaptorQ overhead profile
