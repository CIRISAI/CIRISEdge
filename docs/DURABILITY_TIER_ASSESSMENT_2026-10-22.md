# The durability tier without RaptorQ — what survives, what leaves

Steward ruling 2026-10-22 (via the CC session): RaptorQ is dropped as the durability mechanism. The
durability tier becomes a per-item target-holder count with chunked replication over the blob swarm,
rarest-first, repaired when the holonomic view shows holders falling toward a floor. The codec stays for
realtime A/V only. Holding claims are over chunks: holders per item, not symbols per holder.

## The shape already in code

Edge already ships this exact mechanism for `self` and `family` files (CIRISEdge#763, CC 6.1.5.3):
`src/blob_swarm/durability.rs` — persist's `content_audience` (who should hold), `deficit_over` (who has a
live `custody:ack:v1` `here` within 72 h and who is missing), `rarest_first` ordering of repairs,
`BlobPuller::durability_sweep` pulling each from live holders, and the completed pull filing this node's
`here`, which for a chunk DAG is the whole DAG. The holding claim IS the custody row (persist v55,
CIRISPersist#989), placed at the content's cohort. The ruling generalises this to every tier and makes
the target a per-item holder count. **So the durability tier is mostly a scope widening of #763, not a new
mechanism.**

## FountainSwarmRuntime, piece by piece

| Piece | Today | Under the ruling |
|---|---|---|
| `FountainHoldingClaim { peer_id, content_id, symbol_ids, … }` (`holonomic/swarm_rarity.rs`) | built, never published | **superseded** by `custody:ack:v1` as the holding claim (holders per item). The struct and its signed preimage are deleted from the durability path; CC 6.1.5's PIN line for it is withdrawn. (If a signed "I hold this item" claim is wanted outside the custody plane, `symbol_ids` becomes empty and the preimage changes: a wire break, better taken as a delete.) |
| `compute_rarity_score` over `(content_id, symbol_id)` tuples | built | **repointed**: rarity is per item = live holders vs `target_holders`; `blob_swarm::durability::rarest_first` already orders by live-holder count. The symbol-grain scorer is deleted. |
| `should_eject_above_target`, `EjectionVerdict::{Keep, EjectToTier, …}`, `swarm/diversity.rs` (RTT-diverse ejection) | built | **kept**, repointed at items: a node holding an item whose live holders exceed target × (1 + grace) may step it down a tier (persist's blob tiering), preferring to eject from RTT-clustered holders. Verdict names unchanged (CC 6.1.2 mapping holds). |
| `SwarmEvent::RepairNeeded` (holders < `min_viable`) | emitted, consumed by nothing | **kept**, consumer = the blob swarm's `durability_sweep` (CIRISEdge#886 step 3). |
| Revocation descent (`evict_fountain_content_hard_delete` on `ConsentState::Revoked`) | built | **kept** as a chunk-level hard delete through persist's blob descent; N5 unchanged. |
| `FountainHoldingsSource` adapter (per-symbol list from the operator's store) | built | **deleted** (its reason was the symbol list). |
| `ObservedClaims` (per content, per peer, with `HoldingClaimVerification`) and `ConvergedClaimView` (`converged_view.rs`) | built / tap live | **kept**, fed from custody rows instead of claims; `symbols_claimed` becomes `items_held`; N6's weight rule is the stated interim (the challenger is staged for the tier's first release). |
| `SwarmRuntimeConfig::with_mesh_relief` and the four `redundancy.*` plane keys | consumer never installed | **kept**, but the keys change meaning: `k_repair_symbols` and `min_viable_symbols` lose their object and should be retired from persist's registry; `target_holders` (H) and `min_viable_holders` are the tier's two knobs. |
| `fountain_defaults.rs` (N=20, K=6, min_viable=5, H=30; the survival table; the compile-time asserts) | shipped constants | `DEFAULT_TARGET_HOLDERS = 30` **survives** as the tier's default target (its derivation C₁ = N + K loses its first term; C₃ locality reach = 10 and churn safety remain the honest basis, so the default should be re-derived and may fall). `DEFAULT_N_SOURCE`, `DEFAULT_K_REPAIR`, `DEFAULT_MIN_VIABLE_SYMBOLS`, the symbol-availability survival table and **the `K/N ≥ 20 %` compile-time assertion leave the durability path**; they are the A/V codec's only if that codec adopts them (today `realtime_av_codec/fountain.rs` takes `n_source`/`k_repair` per stream and does not read these constants). **Answer to the steward's question: the assertion does not survive the drop; 6.1.5.1 should not state it.** |
| `blob_swarm/durability.rs` `DurabilityMode::Tuple` and `FEASIBILITY_FLOOR = N + K` (full holding below 26 audience nodes, the fountain tuple at or above) | shipped | the `Tuple` arm **leaves**: the target becomes `min(audience, target_holders)` full holders at every size; `durability_mode` in persist simplifies to that. |
| `holonomic/aggregation.rs`, `multiplicity.rs` (noise floor) | shipped | untouched. |
| `realtime_av_codec/fountain.rs` (RaptorQ) | feature-gated | untouched: the realtime A/V codec's layered fountain wrap stays, behind `codec-fountain`. |

## The replacement, in one paragraph

Per item: a target-holder count H (default from the re-derived constant; relievable per corpus by
`redundancy.target_holders`), an audience (persist's `content_audience`), a live-holder count from
`custody:ack:v1` rows within the liveness window, a deficit (`deficit_over`), rarest-first repair by the
blob swarm's multi-peer chunk fetch, `RepairNeeded` when holders fall under `min_viable_holders`, eject-to-tier
when holders exceed H × (1 + grace) with RTT-diverse preference, hard delete on revocation. Every quantity
is a holonomic view the node computes from rows it holds; every target is a plane key, relieve-never-expand.
Nothing here needs a codec.

## What this does to the CC text

6.1.5: "RaptorQ-coded into N source + K repair symbols" → "replicated as content-addressed chunks to a
per-item target-holder count"; the holder directory speaks of holders per item (done, per the CC session);
`FountainHoldingClaim` / `FountainCompressRequest` PIN lines → withdrawn or re-pointed to `custody:ack:v1`;
6.1.5.1 §R-policy → the two knobs `target_holders` and `min_viable_holders` with the producer-silent default,
no symbol tuple and no `K/N` assertion; 6.1's "layered degradation" stays true of the A/V codec only and
should say so; 5.4.3/5.4.6 unaffected.
