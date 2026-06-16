//! Holonomic substrate primitives.
//!
//! "Holonomic" = each part contains a projection of the whole. The
//! substrate replaces leader-driven / path-dependent coordination with
//! pure, deterministic, byte-equal functions over shared snapshots —
//! every peer that observes the same input arrives at the same output
//! without consensus or messaging.
//!
//! ## Cut history
//!
//! - **v3.9.0** introduced [`consent_decay`] — the per-`content_id`
//!   Consensual Evolution Protocol decay scheduler. Walks fountain
//!   `content_id`s periodically; recomputes target
//!   [`DecayTier`](consent_decay::DecayTier) from
//!   `(now, admitted_at, consent_class, revoked_at)`; pushes tier
//!   changes through the [`PersistHandle`](consent_decay::PersistHandle)
//!   FFI trait.
//!
//! - **v3.10.0** lands the four-piece holonomic bundle. All four are
//!   pure-Rust types + scoring/algorithm primitives; signing /
//!   verification call shapes live at the transport layer.
//!
//!   - [`swarm_rarity`] — Part 1, CIRISEdge#134. Swarm-coordinated
//!     rarest-shard retention. BitTorrent rarest-first applied to
//!     RETENTION (not download). Each peer's local eviction policy
//!     reads [`swarm_rarity::compute_rarity_score`] over the set of
//!     observed [`swarm_rarity::FountainHoldingClaim`]s and biases
//!     toward keeping the rarest `(content_id, symbol_id)` tuples.
//!
//!   - [`wholeness_witness`] — Part 2, CIRISEdge#135.
//!     **WholenessWitness** = signed Merkle roots over CEG claim
//!     state. The keystone: every other piece verifies against
//!     witness chains. Bohm's implicit-order principle applied to
//!     federation state — each peer carries the whole state
//!     implicitly (as the leaf set behind its root), and the witness
//!     projects that whole into a single 32-byte handle.
//!
//!   - [`deterministic_topology`] — Part 3, CIRISEdge#136. Pure
//!     function `compute_alm_topology(snapshot) → AlmTopology` over
//!     the bundle `(capacity_ads, trust_grants,
//!     reachability_observations, locality, snapshot_epoch_id)`.
//!     Composes with #135 `WholenessWitness`: the inputs ARE the
//!     witness leaves so peers reconcile against shared state, not
//!     against each other. Authoritative home of [`TrustGrant`]
//!     (re-exported by Part 4).
//!
//!   - [`recursive_trust_bootstrap`] — Part 4, CIRISEdge#137. Generic
//!     signed-claim envelope + trust graph + witness chain + the
//!     bootstrap admission algorithm. A new peer can join the
//!     federation from ANY signed CEG claim that chains to a trust
//!     root in its own trust graph. No special "first peer"
//!     assumption; no central operator. The federation can
//!     re-establish itself from any sufficient fragment — including
//!     a single peer with a single signed witness chain.
//!
//! - **v4.0.1** adds [`fountain_defaults`] — the recommended
//!   replication-policy defaults `(N=20, K=6, min_viable=5,
//!   target_holders=30)` derived from the three-constraint binding
//!   (survival floor, demand spike, locality reach). Normatively
//!   absorbed into CEG 1.0 §R-policy via CIRISRegistry#86.
//!
//! See `docs/ROADMAP_TO_V4.md` for the cut sequence and the
//! CIRISRegistry#85 absorption gate for normative CEG status.
//!
//! [`TrustGrant`]: deterministic_topology::TrustGrant

#[cfg(feature = "holonomic-consent-decay")]
pub mod consent_decay;

pub mod deterministic_topology;
pub mod fountain_defaults;
pub mod recursive_trust_bootstrap;
pub mod swarm_rarity;
pub mod wholeness_witness;
