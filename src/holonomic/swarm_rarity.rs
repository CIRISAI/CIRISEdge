//! Swarm-coordinated rarest-shard retention — v3.10.0 holonomic Part 1.
//!
//! BitTorrent rarest-first applied to retention (not download). Each peer's
//! local eviction policy reads [`compute_rarity_score`] over the set of
//! observed [`FountainHoldingClaim`]s and biases toward keeping the
//! rarest `(content_id, symbol_id)` tuples. Closes
//! [CIRISEdge#134](https://github.com/CIRISAI/CIRISEdge/issues/134).
//!
//! # Wire-level shapes
//!
//! - [`FountainHoldingClaim`] — a peer publishes "I am retaining these
//!   `(content_id, symbol_id)` tuples". Hybrid-PQC signed via the existing
//!   `federation_session` signer. The signed canonical bytes are
//!   produced by [`FountainHoldingClaim::canonical_bytes`].
//! - [`FountainCompressRequest`] — a peer broadcasts "I'm about to evict
//!   from `(content_id, symbol_range)`; please increase your retention
//!   before I drop." Optional; the substrate composes whether or not
//!   peers respond.
//!
//! Both shapes carry their hybrid-PQC signature fields (`signature`,
//! `signature_ml_dsa_65`, `pqc_key_id`) **outside** the signed bytes —
//! [`FountainHoldingClaim::canonical_value`] and
//! [`FountainCompressRequest::canonical_value`] return ONLY the signed
//! fields, in the locked v1 field order. Signing/verification call shape
//! lives in `src/transport/federation_session.rs`; this module just hands
//! the caller the bytes to sign.
//!
//! # Rarity scoring
//!
//! [`compute_rarity_score`] is a pure function over a set of observed
//! claims: it counts how many distinct peers hold a given
//! `(content_id, symbol_id)` tuple, and returns a [`RarityScore`] where
//! **lower = rarer = keep**. The scoring is **deterministic** given the
//! same claim set, so two peers that share the same WholenessWitness
//! state (CIRISEdge#135) reach the same retention verdict locally.
//!
//! # Canonical-bytes contract (locked at v1)
//!
//! For [`FountainHoldingClaim`], the signed canonical value field order
//! is exactly:
//! `(peer_id, content_id, symbol_ids, observed_at_unix_ms, claim_version)`
//! with `symbol_ids` SORTED ascending, encoded as an explicit `u32`
//! array.
//!
//! For [`FountainCompressRequest`]:
//! `(peer_id, content_id, evicting_range_low, evicting_range_high,
//! deadline_unix_ms, request_version)`.
//!
//! Both encodings are length-prefixed (big-endian `u64` lengths) with a
//! per-shape domain-separation tag — matching the existing
//! `transport::attestation::AttestationPayload::canonical_bytes` and
//! `messages::FederationAnnouncement::canonical_bytes_for_accord_signatures`
//! patterns. Distinct field tuples NEVER share a byte string, so a
//! signature is bound to exactly one `(peer_id, content_id, …)` payload.
//!
//! The `canonical_value()` JSON projection returns a
//! [`serde_json::Value::Array`] of `[field_name, value]` two-element
//! arrays. This locks field order in the JSON shape independent of
//! whether `serde_json`'s `preserve_order` feature is enabled (default
//! `serde_json::Map` is alphabetical-key ordered, which is the WRONG
//! discipline for a signed wire shape).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Locked v1 domain-separation tag for [`FountainHoldingClaim`] signed
/// bytes. Changing this is a coordinated wire break — bump the tag and
/// the `claim_version` field in lockstep.
pub const HOLDING_CLAIM_DOMAIN: &[u8] = b"ciris-edge/holding-claim/v1";

/// Locked v1 domain-separation tag for [`FountainCompressRequest`]
/// signed bytes.
pub const COMPRESS_REQUEST_DOMAIN: &[u8] = b"ciris-edge/compress-request/v1";

/// v1 wire schema version pinned into the signed canonical bytes.
pub const HOLDING_CLAIM_VERSION: u32 = 1;

/// v1 wire schema version pinned into the signed canonical bytes.
pub const COMPRESS_REQUEST_VERSION: u32 = 1;

/// "Maximum rarity" sentinel — the score returned when zero peers are
/// observed to hold a `(content_id, symbol_id)` tuple. The local
/// eviction policy treats this as the strongest "keep" signal: no peer
/// is currently retaining this symbol; if we evict, the swarm loses it.
///
/// Encoded as `u32::MAX` so it sorts strictly larger than any peer-count
/// the rarity score returns (lower = rarer = keep), but the scoring
/// scheme inverts: the maximum-rarity sentinel is the SMALLEST score —
/// see [`compute_rarity_score`].
pub const MAX_RARITY_SCORE: u32 = 0;

/// A signed claim that a peer is retaining a set of fountain symbols
/// for a given content_id.
///
/// # Wire form
///
/// JSON, snake_case. `symbol_ids` is an explicit `Vec<u32>` (NOT a
/// bitmap) so the canonical bytes are unambiguous after a `symbol_ids
/// sort` step — the encoder sorts ascending before hashing so two peers
/// holding the same set in different orders produce the same signature
/// target.
///
/// The hybrid-PQC signature fields ride OUTSIDE the signed bytes:
/// `signature` (ed25519, base64), `signature_ml_dsa_65` (ML-DSA-65,
/// base64), `pqc_key_id` (the persist `federation_keys.key_id` for the
/// PQC half). Verification re-derives the canonical bytes via
/// [`Self::canonical_bytes`] and checks the signature pair through the
/// existing `federation_session` verifier — this module does NOT
/// re-implement signing or verification.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FountainHoldingClaim {
    /// The publishing peer's federation `key_id`.
    pub peer_id: String,
    /// The content this claim is about (opaque substrate-level
    /// identifier — typically the manifest sha256 hex).
    pub content_id: String,
    /// The fountain symbol ids the peer is retaining. SORTED ASCENDING
    /// in the canonical encoding — the encoder applies this sort even
    /// if the wire value arrives out of order, so the signature target
    /// is order-independent at the producer.
    pub symbol_ids: Vec<u32>,
    /// Observation timestamp in unix milliseconds. Used by consumers
    /// for staleness windows (a too-old claim is ignored), not for
    /// replay protection — replay protection rides at the envelope
    /// layer.
    pub observed_at_unix_ms: i64,
    /// Pinned to [`HOLDING_CLAIM_VERSION`] for v1. Bumping this is a
    /// coordinated wire break alongside [`HOLDING_CLAIM_DOMAIN`].
    pub claim_version: u32,
    /// Ed25519 signature over [`Self::canonical_bytes`], base64-standard.
    /// EXCLUDED from the signed bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// ML-DSA-65 signature over [`Self::canonical_bytes`], base64-
    /// standard. EXCLUDED from the signed bytes. Empty string when the
    /// signer is hybrid-pending (matches the `signature_pqc: Option<_>`
    /// discipline on `EdgeEnvelope` — empty string and absent JSON key
    /// both round-trip to "no PQC half").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_ml_dsa_65: String,
    /// The persist `federation_keys.key_id` for the PQC half of the
    /// hybrid signer. EXCLUDED from the signed bytes; verification
    /// looks up the matching ML-DSA-65 pubkey via the federation
    /// directory.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pqc_key_id: String,
}

/// A signed request a peer broadcasts when it intends to evict a range
/// of symbols, asking the swarm to increase retention BEFORE the drop.
///
/// The substrate composes whether or not peers respond — a peer that
/// can't take on more retention simply ignores the request, and the
/// dropping peer proceeds. The request is purely advisory.
///
/// Same hybrid-PQC signature discipline as [`FountainHoldingClaim`]:
/// the three signature fields ride outside the signed bytes.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct FountainCompressRequest {
    /// The publishing peer's federation `key_id`.
    pub peer_id: String,
    /// The content the eviction is about.
    pub content_id: String,
    /// Inclusive lower bound of the symbol-id range being evicted.
    pub evicting_range_low: u32,
    /// Inclusive upper bound of the symbol-id range being evicted.
    pub evicting_range_high: u32,
    /// Unix milliseconds after which the dropping peer proceeds
    /// regardless of swarm response.
    pub deadline_unix_ms: i64,
    /// Pinned to [`COMPRESS_REQUEST_VERSION`] for v1.
    pub request_version: u32,
    /// Ed25519 signature over [`Self::canonical_bytes`], base64-
    /// standard. EXCLUDED from the signed bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// ML-DSA-65 signature over [`Self::canonical_bytes`], base64-
    /// standard. EXCLUDED from the signed bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_ml_dsa_65: String,
    /// The persist `federation_keys.key_id` for the PQC half.
    /// EXCLUDED from the signed bytes.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pqc_key_id: String,
}

/// A rarity score consumed by the local eviction policy. **Lower =
/// rarer = keep**.
///
/// The numeric scheme: the score equals the number of DISTINCT peers
/// observed to hold the `(content_id, symbol_id)` tuple. Zero peers
/// holding ⇒ score `0` (= [`MAX_RARITY_SCORE`]) ⇒ strongest "keep"
/// signal; one peer ⇒ `1`; N peers ⇒ `N`. The local eviction policy
/// sorts ascending and evicts the highest-scored (= most-redundant)
/// symbols first.
///
/// Deterministic over the same claim set: this is the contract that
/// lets the [WholenessWitness pipeline][witness] reproduce a peer's
/// retention verdict from a shared witness leaf.
///
/// [witness]: https://github.com/CIRISAI/CIRISEdge/issues/135
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RarityScore(pub u32);

impl FountainHoldingClaim {
    /// Construct a fresh claim with empty signature fields. The caller
    /// is expected to populate `signature` / `signature_ml_dsa_65` /
    /// `pqc_key_id` by calling the `federation_session` signer over
    /// [`Self::canonical_bytes`].
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        content_id: impl Into<String>,
        symbol_ids: Vec<u32>,
        observed_at_unix_ms: i64,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            content_id: content_id.into(),
            symbol_ids,
            observed_at_unix_ms,
            claim_version: HOLDING_CLAIM_VERSION,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        }
    }

    /// JSON projection of the signed fields, in the locked v1 field
    /// order: `(peer_id, content_id, symbol_ids, observed_at_unix_ms,
    /// claim_version)`. EXCLUDES the three signature fields.
    ///
    /// Returned as a [`Value::Array`] of `[name, value]` two-element
    /// arrays so field order is locked in the JSON shape independent of
    /// `serde_json::Map` ordering rules — the upstream verifier
    /// re-derives this exact projection to confirm what was signed.
    ///
    /// `symbol_ids` is sorted ascending in the projection (idempotent
    /// when the caller already produced a sorted vec).
    #[must_use]
    pub fn canonical_value(&self) -> Value {
        let mut sorted = self.symbol_ids.clone();
        sorted.sort_unstable();
        let sym_array: Vec<Value> = sorted.into_iter().map(|s| json!(s)).collect();
        Value::Array(vec![
            json!(["peer_id", self.peer_id]),
            json!(["content_id", self.content_id]),
            json!(["symbol_ids", Value::Array(sym_array)]),
            json!(["observed_at_unix_ms", self.observed_at_unix_ms]),
            json!(["claim_version", self.claim_version]),
        ])
    }

    /// The exact bytes the federation signer signs / a verifier checks.
    ///
    /// Layout (length prefixes are big-endian `u64`):
    /// `DOMAIN ‖ u64(peer_id.len()) ‖ peer_id
    ///        ‖ u64(content_id.len()) ‖ content_id
    ///        ‖ u64(symbol_ids.len()) ‖ for each sym: u32_be(sym)
    ///        ‖ i64_be(observed_at_unix_ms)
    ///        ‖ u32_be(claim_version)`
    ///
    /// `symbol_ids` is SORTED ASCENDING before encoding so two peers
    /// holding the same set in different orders produce identical
    /// signature targets. `DOMAIN` is [`HOLDING_CLAIM_DOMAIN`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut sorted = self.symbol_ids.clone();
        sorted.sort_unstable();
        let mut out = Vec::with_capacity(
            HOLDING_CLAIM_DOMAIN.len()
                + 8
                + self.peer_id.len()
                + 8
                + self.content_id.len()
                + 8
                + sorted.len() * 4
                + 8
                + 4,
        );
        out.extend_from_slice(HOLDING_CLAIM_DOMAIN);
        write_len_prefixed(&mut out, self.peer_id.as_bytes());
        write_len_prefixed(&mut out, self.content_id.as_bytes());
        out.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
        for sym in &sorted {
            out.extend_from_slice(&sym.to_be_bytes());
        }
        out.extend_from_slice(&self.observed_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.claim_version.to_be_bytes());
        out
    }
}

impl FountainCompressRequest {
    /// Construct a fresh request with empty signature fields. The
    /// caller signs [`Self::canonical_bytes`] and populates the three
    /// signature fields.
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        content_id: impl Into<String>,
        evicting_range_low: u32,
        evicting_range_high: u32,
        deadline_unix_ms: i64,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            content_id: content_id.into(),
            evicting_range_low,
            evicting_range_high,
            deadline_unix_ms,
            request_version: COMPRESS_REQUEST_VERSION,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        }
    }

    /// JSON projection of the signed fields, in the locked v1 field
    /// order: `(peer_id, content_id, evicting_range_low,
    /// evicting_range_high, deadline_unix_ms, request_version)`.
    /// EXCLUDES the three signature fields.
    #[must_use]
    pub fn canonical_value(&self) -> Value {
        Value::Array(vec![
            json!(["peer_id", self.peer_id]),
            json!(["content_id", self.content_id]),
            json!(["evicting_range_low", self.evicting_range_low]),
            json!(["evicting_range_high", self.evicting_range_high]),
            json!(["deadline_unix_ms", self.deadline_unix_ms]),
            json!(["request_version", self.request_version]),
        ])
    }

    /// The exact bytes the federation signer signs / a verifier checks.
    ///
    /// Layout (length prefixes big-endian `u64`):
    /// `DOMAIN ‖ u64(peer_id.len()) ‖ peer_id
    ///        ‖ u64(content_id.len()) ‖ content_id
    ///        ‖ u32_be(evicting_range_low) ‖ u32_be(evicting_range_high)
    ///        ‖ i64_be(deadline_unix_ms)
    ///        ‖ u32_be(request_version)`.
    ///
    /// `DOMAIN` is [`COMPRESS_REQUEST_DOMAIN`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            COMPRESS_REQUEST_DOMAIN.len()
                + 8
                + self.peer_id.len()
                + 8
                + self.content_id.len()
                + 4
                + 4
                + 8
                + 4,
        );
        out.extend_from_slice(COMPRESS_REQUEST_DOMAIN);
        write_len_prefixed(&mut out, self.peer_id.as_bytes());
        write_len_prefixed(&mut out, self.content_id.as_bytes());
        out.extend_from_slice(&self.evicting_range_low.to_be_bytes());
        out.extend_from_slice(&self.evicting_range_high.to_be_bytes());
        out.extend_from_slice(&self.deadline_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.request_version.to_be_bytes());
        out
    }
}

/// CIRISEdge#184 (v6.3.0) — `Message` impl tying the substrate body
/// type to its wire discriminator [`crate::messages::MessageType::FountainHoldingClaim`].
/// Ephemeral, fire-and-forget — the substrate composes whether or not
/// peers respond, and stale observations age out via the runtime's
/// TTL prune.
impl crate::handler::Message for FountainHoldingClaim {
    const TYPE: crate::messages::MessageType = crate::messages::MessageType::FountainHoldingClaim;
    const DELIVERY: crate::handler::Delivery = crate::handler::Delivery::Ephemeral;
    type Response = ();
}

/// Compute the local rarity score for a `(content_id, symbol_id)` tuple
/// over a set of observed [`FountainHoldingClaim`]s. **Lower = rarer =
/// keep**.
///
/// The score equals the number of DISTINCT peers (by `peer_id`)
/// observed to hold the tuple. Zero ⇒ [`MAX_RARITY_SCORE`] (the
/// strongest keep signal: no peer holds this symbol; eviction would
/// drop it from the swarm).
///
/// Deterministic over the same claim set — peers sharing a
/// WholenessWitness leaf reproduce identical scores. The implementation
/// avoids any allocation that depends on hash-map iteration order, so
/// the count is order-independent over `claims`.
#[must_use]
pub fn compute_rarity_score(
    content_id: &str,
    symbol_id: u32,
    claims: &[FountainHoldingClaim],
) -> RarityScore {
    use std::collections::BTreeSet;
    // BTreeSet (not HashSet) because the count is the only observable
    // here, but determinism of iteration is part of the contract the
    // module documents — using BTreeSet makes that load-bearing.
    let mut distinct_peers: BTreeSet<&str> = BTreeSet::new();
    for c in claims {
        if c.content_id != content_id {
            continue;
        }
        if c.symbol_ids.contains(&symbol_id) {
            distinct_peers.insert(c.peer_id.as_str());
        }
    }
    // Cap at u32::MAX in the (impossible) case of overflow — keeps the
    // RarityScore total-ordered.
    let count = u32::try_from(distinct_peers.len()).unwrap_or(u32::MAX);
    RarityScore(count)
}

/// Consent state for a given `content_id`. Mirrors the CEG §3.2.3
/// consent surface; this is the substrate-side projection that rarity
/// scoring consults. Sourced by the caller — the substrate resolves a
/// `content_id`'s CEG consent state (active grant, withdraw, or
/// unobserved) and hands it to [`compute_consent_aware_rarity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    /// Producer has explicitly granted retention (active consent).
    /// Rarity scoring applies normally.
    Active,
    /// Producer or subject has revoked. Content is EVICT-ELIGIBLE
    /// regardless of rarity. Per §3.2.3 right-to-be-forgotten.
    Revoked,
    /// Unknown / unobserved consent state. Per fail-secure: NOT
    /// retained-as-rare. Treat as evict-eligible to avoid the
    /// "absent-evidence is consent" antipattern.
    Unknown,
}

/// Holding-claim verification gate. A claim counts toward rarity only
/// when its possession is challengeable (or has been verified). The
/// weights are wire-determinism-critical — see [`claim_weight`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldingClaimVerification {
    /// Claim's hybrid PQC signature verified AND a possession
    /// challenge (e.g. a fresh symbol-hash challenge-response) has
    /// been answered correctly within the trust horizon.
    PossessionVerified,
    /// Claim's signature is valid but possession has not been
    /// challenged (or the challenge is pending). Counts toward rarity
    /// at DISCOUNTED weight (1/2) to bound the lying-holder
    /// force-evict surface.
    SignatureOnly,
    /// Claim's signature is invalid or missing. Does NOT count.
    Unverified,
}

/// Output of [`compute_consent_aware_rarity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentAwareRarity {
    /// Rare and consent-active. Retain at high priority.
    RetainRare(RarityScore),
    /// Not-rare OR rare but consent-revoked OR consent-unknown.
    /// Evict-eligible.
    EvictEligible(EvictionReason),
}

/// Why a `(content_id, symbol_id)` tuple is evict-eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionReason {
    /// Content is NOT rare (enough verified-weight holders elsewhere).
    NotRare,
    /// Consent state is Revoked — §3.2.3 right-to-be-forgotten.
    ConsentRevoked,
    /// Consent state is Unknown — fail-secure default.
    ConsentUnknown,
}

/// Locked-v1 safety-margin percentage above [`fountain_defaults::DEFAULT_TARGET_HOLDERS`]
/// before [`should_eject_above_target`] returns `Eject`. 15% matches
/// the v4.0.1 derivation (`26 × 1.15 ≈ 30`); a peer that observes
/// `holders_observed > target_holders × (1 + 15/100)` AND finds its
/// own symbol "not rare" is eligible to evict.
///
/// **Wire-determinism-critical**: locked at v1 alongside the §R-policy
/// defaults. Any change is a coordinated CEG amendment.
pub const EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT: u32 = 15;

/// Verdict returned by [`should_eject_above_target`] — the proactive
/// trim primitive that drives the federation toward
/// [`fountain_defaults::DEFAULT_TARGET_HOLDERS`] convergence.
///
/// Without proactive trim, the federation only converges to target
/// via rarity bias — *eventually* correct, but slow and reactive.
/// `should_eject_above_target` lets a peer recognize "the network is
/// over-replicated; my symbol is common; safe to free local storage."
///
/// Composes with the persist v8.1.0+ eviction surface:
/// - [`EjectionVerdict::EjectHardDelete`] → caller invokes
///   `Persist::evict_fountain_content_hard_delete` (the §8.1.11.3 N5
///   deletion-SLA path)
/// - [`EjectionVerdict::EjectToTier`] → caller invokes
///   `Persist::evict_fountain_content_to_tier(T2)` (DiskPressure
///   tier eviction; the freed symbol can be re-fetched later if
///   demand spikes)
/// - [`EjectionVerdict::EjectAggregatedTierOnly { tier }`] (v4.5.0,
///   CEG 1.0-RC17 §19.7.3) → caller invokes persist v8.6.0's tier-
///   granular evict for the named pyramid stratum; finer AND coarser
///   tiers stay intact
/// - [`EjectionVerdict::Keep`] → no action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EjectionVerdict {
    /// Free local storage by evicting this symbol to the tier policy.
    /// The federation has more than [`fountain_defaults::DEFAULT_TARGET_HOLDERS`]
    /// (× safety margin) holders, and this peer's symbol is
    /// "common" locally — it's safe to drop. Other peers carry the load.
    ///
    /// One downward step on the §19.7 descent axis: still recoverable,
    /// lower fidelity. Composes with intra-object layer-drop OR N→1
    /// aggregation.
    EjectToTier,
    /// **§19.7.3 (CEG 1.0-RC17, edge v4.5.0)** — shed EXACTLY one
    /// pyramid stratum (the tier-`tier` `AggregationMetaV1` composite),
    /// leaving both finer AND coarser tiers intact. The tier-granular
    /// form of [`Self::EjectToTier`], applied under *targeted*
    /// pressure.
    ///
    /// Composes with [`Self::EjectHardDelete`]: a `tier` already below
    /// the noise floor is unreachable, so this never resurrects erased
    /// content. The substrate guarantees revocation routes through
    /// hard-delete (§19.3 N5), not through tier-only ejection.
    ///
    /// Persist v8.6.0+ drives the tier-tagged evict for the named
    /// pyramid stratum. Mirrors CIRISVerify v5.11.0's
    /// `holonomic::aggregation::EjectionVerdict::EjectAggregatedTierOnly`
    /// variant byte-for-byte at the verdict-shape boundary.
    EjectAggregatedTierOnly {
        /// The pyramid stratum (tier index) to shed. `tier = 0` is
        /// source-granularity (a degenerate case; callers SHOULD
        /// prefer [`Self::EjectToTier`] for source-tier pressure).
        tier: u32,
    },
    /// §3.2.3 revocation — call the persist hard-delete path
    /// regardless of holder count. The fastest descent below the
    /// noise floor; never tier-shed.
    EjectHardDelete,
    /// Keep the symbol. Either the federation is at/below target
    /// (this peer is needed), or this peer's symbol is rare
    /// (network depends on it), or the safety margin hasn't been
    /// cleared.
    Keep,
}

/// Proactive trim primitive — the active-convergence half of swarm
/// rarity. Reactive rarity bias only acts when a peer evaluates a
/// fountain content; this function acts even when the local symbol
/// passes rarity gating, because over-replicated content wastes
/// network-wide storage that could carry additional content.
///
/// Inputs:
/// - `holders_observed` — the count of distinct verified-weight
///   holders the peer's observed claim set names (i.e. the same
///   numerator [`compute_rarity_score`] uses).
/// - `policy` — the [`fountain_defaults::FountainPolicy`] in force
///   (typically [`recommended_policy()`](super::fountain_defaults::recommended_policy)).
/// - `consent` — the [`ConsentState`] for the content. Revoked
///   short-circuits to `EjectHardDelete` regardless of rarity.
/// - `local_symbol_rarity` — the rarity score the peer computed for
///   ITS own symbol; if this symbol is itself rare, KEEP it even when
///   the network is otherwise over-replicated.
///
/// Threshold math (locked v1):
/// ```text
/// over_target_threshold = target_holders +
///                         target_holders × EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT / 100
///                       = 30 + 30 × 15 / 100
///                       = 34 (default policy)
/// ```
///
/// At/below 34 verified-weight holders, the peer KEEPS its symbol.
/// At 35+, the peer ejects iff its own symbol is not rare.
///
/// **Wire-determinism-critical**: the threshold + the "is_common"
/// definition (rarity score above `policy.target_holders / 2`) appear
/// in CEG 1.0 §R conformance vectors; two peers MUST reach the same
/// verdict from the same inputs.
#[must_use]
pub fn should_eject_above_target(
    holders_observed: u32,
    policy: &crate::holonomic::fountain_defaults::FountainPolicy,
    consent: ConsentState,
    local_symbol_rarity: RarityScore,
) -> EjectionVerdict {
    // §3.2.3 revocation dominates rarity AND target-holder counts.
    if consent == ConsentState::Revoked {
        return EjectionVerdict::EjectHardDelete;
    }

    let safety = policy.target_holders * EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT / 100;
    let over_target_threshold = policy.target_holders + safety;

    // Below the over-target threshold: federation still needs this
    // peer's contribution. KEEP.
    if holders_observed <= over_target_threshold {
        return EjectionVerdict::Keep;
    }

    // Above the over-target threshold: only eject if the local
    // symbol is "common" (rarity score >= target_holders / 2 — the
    // network has substantial coverage of this symbol_id already).
    // Otherwise the symbol is rare and this peer's copy is
    // load-bearing for resilience; KEEP it even when the network is
    // over-replicated on average.
    let common_threshold = RarityScore(policy.target_holders / 2);
    if local_symbol_rarity >= common_threshold {
        EjectionVerdict::EjectToTier
    } else {
        EjectionVerdict::Keep
    }
}

/// CIRISEdge#184 (v6.3.0) — **latency-aware diversity refinement** of
/// [`should_eject_above_target`].
///
/// Layered on top of the v1 substrate verdict: this function calls
/// [`should_eject_above_target`] first; only when the base verdict is
/// `EjectToTier` AND a `diversity_score` is supplied does the diversity
/// gate engage. This preserves the locked v1 byte-determinism contract
/// on the substrate verdict (CEG 1.0 §R conformance vectors) — the
/// diversity refinement is a *policy-tier* refinement on top of the
/// substrate-tier verdict, not a wire break.
///
/// ## Inputs
///
/// - `holders_observed` / `policy` / `consent` / `local_symbol_rarity`
///   — passed straight through to [`should_eject_above_target`].
/// - `diversity_score`: the local peer's diversity contribution to
///   the holder set, computed via
///   [`crate::swarm::diversity::diversity_contribution`]. `None` falls
///   back to the substrate-tier verdict (no refinement).
/// - `diversity_floor`: the threshold below which "local position is
///   sufficiently clustered → safe to eject." Typically the median
///   diversity score across holders we have RTT data for; the runtime
///   estimates this on its converger tick.
///
/// ## Semantics
///
/// - Base verdict `Keep` → return `Keep` (substrate dominates).
/// - Base verdict `EjectHardDelete` → return `EjectHardDelete`
///   (revocation dominates; diversity does NOT override §3.2.3).
/// - Base verdict `EjectToTier` + `diversity_score = None` → return
///   `EjectToTier` (rarity-only fallback).
/// - Base verdict `EjectToTier` + `Some(score) < diversity_floor` →
///   return `EjectToTier` (local position is clustered; ejecting
///   preserves geographic spread).
/// - Base verdict `EjectToTier` + `Some(score) >= diversity_floor` →
///   return `Keep` (local position uniquely contributes diversity;
///   retain even though the swarm is over-target).
///
/// **Wire-determinism note**: this function is **policy-tier**, not
/// substrate-tier. Two peers running with different RTT observers may
/// reach DIFFERENT verdicts from the same observed-claims input —
/// that's the intended degree of freedom (each peer optimizes its
/// local geographic spread). The substrate's
/// [`should_eject_above_target`] remains the byte-determined
/// conformance surface; CEG 1.0 §R vectors continue to apply against
/// the substrate function unchanged.
#[must_use]
pub fn should_eject_with_diversity(
    holders_observed: u32,
    policy: &crate::holonomic::fountain_defaults::FountainPolicy,
    consent: ConsentState,
    local_symbol_rarity: RarityScore,
    diversity_score: Option<f64>,
    diversity_floor: Option<f64>,
) -> EjectionVerdict {
    let base = should_eject_above_target(holders_observed, policy, consent, local_symbol_rarity);
    match base {
        EjectionVerdict::EjectToTier => {
            // Diversity refinement: only fire when BOTH a score AND a
            // floor are present. Either-missing → fall back to the
            // substrate verdict.
            match (diversity_score, diversity_floor) {
                (Some(score), Some(floor)) => {
                    if score < floor {
                        // Clustered local position → safe to eject.
                        EjectionVerdict::EjectToTier
                    } else {
                        // Diverse local position → retain for spread.
                        EjectionVerdict::Keep
                    }
                }
                _ => EjectionVerdict::EjectToTier,
            }
        }
        // Base verdict Keep / EjectHardDelete / EjectAggregatedTierOnly
        // pass through unchanged. Diversity does NOT override
        // revocation (§3.2.3) or the keep-because-rare invariant.
        other => other,
    }
}

/// **§19.7.3 (CEG 1.0-RC17)** — construct an
/// [`EjectionVerdict::EjectAggregatedTierOnly`] for the named pyramid
/// stratum. Mirrors `ciris_verify_core::holonomic::aggregation::eject_aggregated_tier`
/// at the verdict-shape boundary.
///
/// Use this when applying targeted pressure to a single intermediate
/// pyramid level — for example, a peer that wants to retain both the
/// high-fidelity tier-0 source set AND the deepest collective gist,
/// but shed one intermediate aggregated stratum to free local storage.
///
/// A pure fabric node MAY compute this mechanically: the descent
/// step is symbol arithmetic over the pyramid; no agency required
/// (§1.3 + §19.7 mechanical-degradation invariant).
///
/// ## Composition with [`EjectionVerdict::EjectHardDelete`]
///
/// A `tier` already below the noise floor is unreachable, so this
/// never resurrects revoked content. The substrate routes revocation
/// through hard-delete (§19.3 N5) regardless of any tier-only
/// ejection; see [`should_eject_above_target`] for the dominant-
/// revocation path.
#[must_use]
pub const fn eject_aggregated_tier(tier: u32) -> EjectionVerdict {
    EjectionVerdict::EjectAggregatedTierOnly { tier }
}

/// Locked-v1 possession-verified holding-claim weight.
///
/// **Wire-determinism-critical**: these three weights
/// (possession=2 / signature_only=1 / unverified=0) will appear in
/// CEG 1.0 §R conformance vectors. Two peers MUST reach the same
/// weighted holder count from the same `(claim, verification)` set, so
/// the weights are integer-only and locked. Changing any of them is a
/// coordinated wire break alongside [`HOLDING_CLAIM_VERSION`].
pub const HOLDING_WEIGHT_POSSESSION_VERIFIED: u32 = 2;

/// Locked-v1 signature-only holding-claim weight (half of
/// possession-verified, integer-floored). See
/// [`HOLDING_WEIGHT_POSSESSION_VERIFIED`].
pub const HOLDING_WEIGHT_SIGNATURE_ONLY: u32 = 1;

/// Locked-v1 unverified holding-claim weight — does NOT count. See
/// [`HOLDING_WEIGHT_POSSESSION_VERIFIED`].
pub const HOLDING_WEIGHT_UNVERIFIED: u32 = 0;

/// The locked-v1 integer weight a claim contributes to the weighted
/// holder count, by verification state.
///
/// possession=2 / signature_only=1 / unverified=0. Wire-determinism-
/// critical (CEG 1.0 §R conformance vectors).
#[must_use]
pub const fn claim_weight(v: HoldingClaimVerification) -> u32 {
    match v {
        HoldingClaimVerification::PossessionVerified => HOLDING_WEIGHT_POSSESSION_VERIFIED,
        HoldingClaimVerification::SignatureOnly => HOLDING_WEIGHT_SIGNATURE_ONLY,
        HoldingClaimVerification::Unverified => HOLDING_WEIGHT_UNVERIFIED,
    }
}

/// Consent-aware rarity computation. Composes the §3.2.3 consent gate,
/// the possession-challengeability discount, and the rarity threshold
/// drawn from [`crate::holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS`].
///
/// `claims_with_verification`: each holding claim paired with its
/// verification state. Unverified claims do NOT count; signature-only
/// claims count at HALF weight (the v1 weights are
/// possession=2 / signature_only=1 / unverified=0 — integer-floored,
/// no floats). Each DISTINCT peer (by `peer_id`) contributes the
/// weight of its strongest verification state for this tuple; multiple
/// claims from one peer do not multiply its contribution.
///
/// `consent`: the substrate's projection of the content's CEG consent
/// state. Revoked or Unknown short-circuits to
/// [`ConsentAwareRarity::EvictEligible`] regardless of rarity.
///
/// **Rarity verdict**: the weighted holder count is compared to the
/// recommended `target_holders` survival floor. Below the floor ⇒
/// rare ⇒ [`ConsentAwareRarity::RetainRare`] (the swarm has too few
/// verified holders; keep this symbol). At-or-above ⇒ enough verified
/// holders elsewhere ⇒ [`EvictionReason::NotRare`].
///
/// The returned [`RarityScore`] on the `RetainRare` arm carries the
/// WEIGHTED holder count (not the raw distinct-peer count from
/// [`compute_rarity_score`]) so the inverted-but-determinstic
/// "lower = rarer = keep" ordering still holds under the weighting.
#[must_use]
pub fn compute_consent_aware_rarity(
    content_id: &str,
    symbol_id: u32,
    claims_with_verification: &[(FountainHoldingClaim, HoldingClaimVerification)],
    consent: ConsentState,
) -> ConsentAwareRarity {
    // CEG N6: consent_revoked OR consent_unknown SHORT-CIRCUITS to
    // EvictEligible regardless of rarity score. The §3.2.3 right-to-be-
    // forgotten gate dominates rarity — preserving the maximum-rare
    // score for a withdrawn item is the exact inversion to avoid.
    match consent {
        ConsentState::Revoked => {
            return ConsentAwareRarity::EvictEligible(EvictionReason::ConsentRevoked);
        }
        // Fail-secure: absent consent is NOT rarity protection. An
        // unobserved content_id must be evict-eligible, never retained-
        // as-rare on the strength of missing evidence.
        ConsentState::Unknown => {
            return ConsentAwareRarity::EvictEligible(EvictionReason::ConsentUnknown);
        }
        ConsentState::Active => {}
    }

    // CEG N7: each distinct peer contributes the weight of its STRONGEST
    // verification state for this tuple. A peer that publishes both an
    // unverified and a possession-verified claim counts as
    // possession-verified — and only once. Self-asserted (Unverified)
    // claims contribute weight 0, so they can NEVER lower another peer's
    // retention priority (the lying-holder force-evict surface is
    // closed at the weight gate).
    let mut peer_weight: std::collections::BTreeMap<&str, u32> = std::collections::BTreeMap::new();
    for (claim, verification) in claims_with_verification {
        if claim.content_id != content_id {
            continue;
        }
        if !claim.symbol_ids.contains(&symbol_id) {
            continue;
        }
        let w = claim_weight(*verification);
        let slot = peer_weight.entry(claim.peer_id.as_str()).or_insert(0);
        if w > *slot {
            *slot = w;
        }
    }
    let weighted_count: u32 = peer_weight
        .values()
        .copied()
        .try_fold(0u32, u32::checked_add)
        .unwrap_or(u32::MAX);

    // Rare iff the weighted holder count is below the recommended
    // survival floor. At-or-above the floor, enough verified holders
    // exist elsewhere that local eviction does not threaten the swarm.
    if weighted_count < crate::holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS {
        ConsentAwareRarity::RetainRare(RarityScore(weighted_count))
    } else {
        ConsentAwareRarity::EvictEligible(EvictionReason::NotRare)
    }
}

/// Verify a single fountain symbol against the signed manifest's
/// `symbol_hashes[symbol_id]`. Returns `true` iff
/// `lowercase_hex(SHA-256(symbol_bytes)) == manifest_symbol_hashes[symbol_id]`.
///
/// Reconstruction MUST call this for every symbol before trusting it
/// (CEG N7 — substrate honesty: never silently accept unverified bytes
/// from the swarm). An out-of-bounds `symbol_id` returns `false` (a
/// symbol the manifest does not describe cannot be verified, so it is
/// not trusted).
#[must_use]
pub fn verify_symbol_against_manifest(
    symbol_bytes: &[u8],
    symbol_id: u32,
    manifest_symbol_hashes: &[String],
) -> bool {
    use sha2::{Digest, Sha256};
    let Ok(idx) = usize::try_from(symbol_id) else {
        return false;
    };
    let Some(expected) = manifest_symbol_hashes.get(idx) else {
        return false;
    };
    let digest = Sha256::digest(symbol_bytes);
    let mut actual = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(actual, "{byte:02x}");
    }
    // Constant-discipline string compare — these are public digests,
    // not secrets, so a plain `==` is correct here.
    actual == *expected
}

/// Failure of the §8.1.11.3 fountain hard-delete path.
#[derive(thiserror::Error, Debug)]
pub enum FountainEvictError {
    /// The persist-tier hard-delete call failed. Carries the
    /// implementation's error string so the policy layer can log /
    /// retry; the deletion SLA is NOT satisfied until this returns
    /// `Ok`.
    #[error("fountain hard-delete failed: {0}")]
    HardDeleteFailed(String),
}

/// §8.1.11.3 N5 deletion-SLA wiring (CIRISEdge#145 / persist v8.1.0).
///
/// The substrate-side trait the higher tiers implement against
/// persist's `evict_fountain_content_hard_delete(content_id,
/// corpus_kind)` API. Edge's policy layer calls into a
/// `dyn FountainEvictHardDelete` when it observes a withdraw or a
/// `consent:state:revoked` for a fountain `content_id`.
///
/// Call THIS — not a tier-T5 eviction (`evict_fountain_content_to_tier`)
/// — on revoke. The persist hard-delete path is structurally immune to
/// the rarity reweight in #134: no `retention_priority` value can
/// resurrect a hard-deleted content, which closes the inversion where a
/// maximally-rare score would otherwise pin a withdrawn item in cache.
///
/// # Producer-side N5 rule
///
/// Do NOT emit a [`FountainHoldingClaim`] for revoked content, and do
/// NOT count revoked content toward rarity (see [`ConsentState::Revoked`]
/// short-circuiting in [`compute_consent_aware_rarity`]). Hard-delete is
/// the terminal step AFTER the claim/rarity surfaces have already
/// stopped advertising the content.
///
/// `corpus_kind` selects the persist corpus the `content_id` lives in
/// (the same discriminator persist's eviction API takes); edge passes
/// it through opaquely.
pub trait FountainEvictHardDelete {
    /// Hard-delete `content_id` from the `corpus_kind` corpus per the
    /// §8.1.11.3 deletion SLA. Returns `Ok(())` once the content is
    /// irrecoverably removed.
    ///
    /// # Errors
    ///
    /// Returns [`FountainEvictError::HardDeleteFailed`] if the
    /// underlying persist call fails — the deletion SLA is unmet until
    /// a subsequent call returns `Ok`.
    fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<(), FountainEvictError>;
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_claim(peer: &str, content: &str, syms: Vec<u32>) -> FountainHoldingClaim {
        FountainHoldingClaim::new(peer, content, syms, 1_000_000)
    }

    #[test]
    fn canonical_bytes_locked_field_order() {
        let claim =
            FountainHoldingClaim::new("peer-a", "content-xyz", vec![3, 1, 2], 1_700_000_000);
        let v = claim.canonical_value();
        // The projection MUST be a Value::Array of [name, value] tuples
        // in the locked v1 order.
        let arr = v.as_array().expect("canonical_value must be an array");
        assert_eq!(arr.len(), 5, "exactly 5 signed fields in v1");
        assert_eq!(arr[0][0], "peer_id");
        assert_eq!(arr[1][0], "content_id");
        assert_eq!(arr[2][0], "symbol_ids");
        assert_eq!(arr[3][0], "observed_at_unix_ms");
        assert_eq!(arr[4][0], "claim_version");

        // symbol_ids MUST be sorted ascending in the projection.
        let syms = arr[2][1].as_array().expect("symbol_ids is an array");
        let nums: Vec<u64> = syms.iter().map(|s| s.as_u64().unwrap()).collect();
        assert_eq!(nums, vec![1, 2, 3]);

        // Signature fields MUST NOT appear in the canonical projection.
        let json_str = serde_json::to_string(&v).unwrap();
        assert!(!json_str.contains("signature"));
        assert!(!json_str.contains("signature_ml_dsa_65"));
        assert!(!json_str.contains("pqc_key_id"));

        // And canonical_bytes is non-empty + starts with the domain tag.
        let bytes = claim.canonical_bytes();
        assert!(bytes.starts_with(HOLDING_CLAIM_DOMAIN));
        // Even after the caller populates signature fields, the canonical
        // bytes MUST NOT change — the signature fields ride outside.
        let mut signed = claim.clone();
        signed.signature = "AAAA".into();
        signed.signature_ml_dsa_65 = "BBBB".into();
        signed.pqc_key_id = "kid".into();
        assert_eq!(
            signed.canonical_bytes(),
            bytes,
            "signature fields must NOT affect canonical_bytes"
        );
    }

    #[test]
    fn rarity_score_monotonic() {
        // 5 distinct peers all hold (content=X, symbol=1).
        let claims_5: Vec<FountainHoldingClaim> = (0..5)
            .map(|i| mk_claim(&format!("peer-{i}"), "X", vec![1]))
            .collect();
        // 1 peer holds (content=X, symbol=2).
        let mut claims_combined = claims_5.clone();
        claims_combined.push(mk_claim("solo", "X", vec![2]));

        let score_common = compute_rarity_score("X", 1, &claims_combined);
        let score_rare = compute_rarity_score("X", 2, &claims_combined);

        // The widely-held tuple scores HIGHER (= more redundant = evict
        // first) than the rare tuple. Lower = rarer = keep.
        assert!(
            score_common > score_rare,
            "5-peer tuple should score higher than 1-peer tuple ({score_common:?} vs {score_rare:?})"
        );
        assert_eq!(score_common, RarityScore(5));
        assert_eq!(score_rare, RarityScore(1));
    }

    #[test]
    fn rarity_score_empty_claims() {
        // 0 peers holding (content=X, symbol=0) ⇒ MAX_RARITY_SCORE.
        let score = compute_rarity_score("X", 0, &[]);
        assert_eq!(score, RarityScore(MAX_RARITY_SCORE));
        // And the canonical "maximum rarity" is the LOWEST score —
        // lower = rarer = keep. Any non-empty observation produces a
        // strictly larger score.
        let claims = vec![mk_claim("peer-a", "X", vec![0])];
        let score_seen = compute_rarity_score("X", 0, &claims);
        assert!(
            score_seen > score,
            "any peer-observed tuple must score higher than the zero-peer sentinel"
        );

        // A claim for a DIFFERENT content_id MUST NOT count, even if
        // the symbol_id matches.
        let claims_other = vec![mk_claim("peer-a", "Y", vec![0])];
        let score_other = compute_rarity_score("X", 0, &claims_other);
        assert_eq!(score_other, RarityScore(MAX_RARITY_SCORE));

        // And a claim for the right content_id but a DIFFERENT
        // symbol_id also MUST NOT count.
        let claims_wrong_sym = vec![mk_claim("peer-a", "X", vec![1, 2, 3])];
        let score_wrong = compute_rarity_score("X", 0, &claims_wrong_sym);
        assert_eq!(score_wrong, RarityScore(MAX_RARITY_SCORE));
    }

    #[test]
    fn compress_request_envelope_excludes_signatures() {
        let mut req =
            FountainCompressRequest::new("peer-a", "content-xyz", 100, 199, 1_700_000_000);
        // canonical_value field order locked
        let v = req.canonical_value();
        let arr = v.as_array().expect("canonical_value must be an array");
        assert_eq!(arr.len(), 6, "exactly 6 signed fields in v1");
        assert_eq!(arr[0][0], "peer_id");
        assert_eq!(arr[1][0], "content_id");
        assert_eq!(arr[2][0], "evicting_range_low");
        assert_eq!(arr[3][0], "evicting_range_high");
        assert_eq!(arr[4][0], "deadline_unix_ms");
        assert_eq!(arr[5][0], "request_version");

        // Signature-bearing fields MUST NOT appear in the canonical
        // projection.
        let json_str = serde_json::to_string(&v).unwrap();
        assert!(!json_str.contains("signature"));
        assert!(!json_str.contains("signature_ml_dsa_65"));
        assert!(!json_str.contains("pqc_key_id"));

        // canonical_bytes starts with the per-shape domain tag.
        let bytes_pre = req.canonical_bytes();
        assert!(bytes_pre.starts_with(COMPRESS_REQUEST_DOMAIN));

        // Mutating the signature fields MUST NOT change canonical_bytes
        // (they ride outside the signed shape).
        req.signature = "AAAA".into();
        req.signature_ml_dsa_65 = "BBBB".into();
        req.pqc_key_id = "kid".into();
        let bytes_post = req.canonical_bytes();
        assert_eq!(
            bytes_pre, bytes_post,
            "signature fields must NOT affect canonical_bytes"
        );

        // canonical_value also unchanged by signature field mutation.
        let v2 = req.canonical_value();
        assert_eq!(v, v2, "signature fields must NOT affect canonical_value");
    }

    #[test]
    fn rarity_score_dedupes_per_peer() {
        // A peer publishing two claims that BOTH hold the same tuple
        // counts as ONE distinct peer.
        let claims = vec![
            mk_claim("peer-a", "X", vec![1]),
            mk_claim("peer-a", "X", vec![1]),
            mk_claim("peer-b", "X", vec![1]),
        ];
        assert_eq!(compute_rarity_score("X", 1, &claims), RarityScore(2));
    }

    #[test]
    fn rarity_score_deterministic_over_claim_order() {
        // Determinism is the contract that lets the WholenessWitness
        // pipeline reproduce a peer's verdict from a shared leaf.
        let claims = vec![
            mk_claim("peer-a", "X", vec![1, 2]),
            mk_claim("peer-b", "X", vec![1]),
            mk_claim("peer-c", "X", vec![1, 3]),
        ];
        let mut reordered = claims.clone();
        reordered.reverse();
        assert_eq!(
            compute_rarity_score("X", 1, &claims),
            compute_rarity_score("X", 1, &reordered),
        );
        assert_eq!(
            compute_rarity_score("X", 2, &claims),
            compute_rarity_score("X", 2, &reordered),
        );
    }

    #[test]
    fn holding_claim_canonical_bytes_resist_field_confusion() {
        // peer_id="abc" content_id="d" vs peer_id="ab" content_id="cd"
        // must produce distinct canonical bytes (length prefixes make
        // the encoding injective — same property the existing
        // transport::attestation::AttestationPayload tests assert).
        let a = FountainHoldingClaim::new("abc", "d", vec![], 0).canonical_bytes();
        let b = FountainHoldingClaim::new("ab", "cd", vec![], 0).canonical_bytes();
        assert_ne!(a, b);
    }

    #[test]
    fn holding_claim_symbol_id_sort_is_idempotent() {
        // Pre-sorted and arbitrary-order MUST produce the same bytes —
        // the encoder applies the sort at producer-side so two peers
        // holding the same set produce identical signature targets.
        let pre = FountainHoldingClaim::new("p", "X", vec![1, 2, 3], 0).canonical_bytes();
        let arb = FountainHoldingClaim::new("p", "X", vec![3, 1, 2], 0).canonical_bytes();
        assert_eq!(pre, arb);
    }

    // ---- F-3: consent-aware rarity + possession-challengeable claims ----

    use crate::holonomic::fountain_defaults::DEFAULT_TARGET_HOLDERS;

    fn vclaim(
        peer: &str,
        content: &str,
        syms: Vec<u32>,
        v: HoldingClaimVerification,
    ) -> (FountainHoldingClaim, HoldingClaimVerification) {
        (FountainHoldingClaim::new(peer, content, syms, 1_000_000), v)
    }

    #[test]
    fn consent_active_rare_returns_retain_rare() {
        // One possession-verified holder (weight 2) — far below the
        // target_holders floor ⇒ rare ⇒ RetainRare.
        let claims = vec![vclaim(
            "peer-a",
            "X",
            vec![1],
            HoldingClaimVerification::PossessionVerified,
        )];
        let out = compute_consent_aware_rarity("X", 1, &claims, ConsentState::Active);
        assert_eq!(
            out,
            ConsentAwareRarity::RetainRare(RarityScore(HOLDING_WEIGHT_POSSESSION_VERIFIED))
        );
    }

    #[test]
    fn consent_revoked_rare_returns_evict_consent_revoked() {
        // Even with zero holders (maximally rare), a revoked content_id
        // is evict-eligible: §3.2.3 right-to-be-forgotten dominates.
        let claims: Vec<(FountainHoldingClaim, HoldingClaimVerification)> = vec![vclaim(
            "peer-a",
            "X",
            vec![1],
            HoldingClaimVerification::PossessionVerified,
        )];
        let out = compute_consent_aware_rarity("X", 1, &claims, ConsentState::Revoked);
        assert_eq!(
            out,
            ConsentAwareRarity::EvictEligible(EvictionReason::ConsentRevoked)
        );
        // And the zero-holder (MAX-rarity) case must ALSO evict.
        let out_empty = compute_consent_aware_rarity("X", 1, &[], ConsentState::Revoked);
        assert_eq!(
            out_empty,
            ConsentAwareRarity::EvictEligible(EvictionReason::ConsentRevoked)
        );
    }

    #[test]
    fn consent_unknown_rare_returns_evict_consent_unknown() {
        // Fail-secure: unknown consent on a maximally-rare item is NOT
        // retained-as-rare. Absent evidence is not consent.
        let out = compute_consent_aware_rarity("X", 1, &[], ConsentState::Unknown);
        assert_eq!(
            out,
            ConsentAwareRarity::EvictEligible(EvictionReason::ConsentUnknown)
        );
    }

    #[test]
    fn consent_active_not_rare_returns_evict_not_rare() {
        // target_holders distinct possession-verified peers ⇒ weighted
        // count = 2 * target_holders, well above the floor ⇒ NotRare.
        let claims: Vec<(FountainHoldingClaim, HoldingClaimVerification)> = (0
            ..DEFAULT_TARGET_HOLDERS)
            .map(|i| {
                vclaim(
                    &format!("peer-{i}"),
                    "X",
                    vec![1],
                    HoldingClaimVerification::PossessionVerified,
                )
            })
            .collect();
        let out = compute_consent_aware_rarity("X", 1, &claims, ConsentState::Active);
        assert_eq!(
            out,
            ConsentAwareRarity::EvictEligible(EvictionReason::NotRare)
        );
    }

    #[test]
    fn unverified_claims_dont_count() {
        // 10 self-asserted (unverified) claims contribute weight 0 each
        // ⇒ weighted count 0 ⇒ still rare. This is the lying-holder
        // force-evict defense: forged claims cannot push honest content
        // over the not-rare threshold.
        let claims: Vec<(FountainHoldingClaim, HoldingClaimVerification)> = (0..10)
            .map(|i| {
                vclaim(
                    &format!("liar-{i}"),
                    "X",
                    vec![1],
                    HoldingClaimVerification::Unverified,
                )
            })
            .collect();
        let out = compute_consent_aware_rarity("X", 1, &claims, ConsentState::Active);
        assert_eq!(out, ConsentAwareRarity::RetainRare(RarityScore(0)));
    }

    #[test]
    fn signature_only_claims_count_half_weight() {
        // 4 distinct signature-only peers (weight 1 each = 4) produce
        // the SAME weighted count as 2 distinct possession-verified
        // peers (weight 2 each = 4).
        let sig_only: Vec<(FountainHoldingClaim, HoldingClaimVerification)> = (0..4)
            .map(|i| {
                vclaim(
                    &format!("sig-{i}"),
                    "X",
                    vec![1],
                    HoldingClaimVerification::SignatureOnly,
                )
            })
            .collect();
        let possession: Vec<(FountainHoldingClaim, HoldingClaimVerification)> = (0..2)
            .map(|i| {
                vclaim(
                    &format!("pos-{i}"),
                    "X",
                    vec![1],
                    HoldingClaimVerification::PossessionVerified,
                )
            })
            .collect();
        let a = compute_consent_aware_rarity("X", 1, &sig_only, ConsentState::Active);
        let b = compute_consent_aware_rarity("X", 1, &possession, ConsentState::Active);
        assert_eq!(a, b);
        assert_eq!(a, ConsentAwareRarity::RetainRare(RarityScore(4)));
    }

    #[test]
    fn possession_verified_claims_count_full_weight() {
        // N distinct possession-verified peers ⇒ exact weighted count
        // of 2 * N, deterministically.
        let n = 5u32;
        let claims: Vec<(FountainHoldingClaim, HoldingClaimVerification)> = (0..n)
            .map(|i| {
                vclaim(
                    &format!("pos-{i}"),
                    "X",
                    vec![1],
                    HoldingClaimVerification::PossessionVerified,
                )
            })
            .collect();
        let out = compute_consent_aware_rarity("X", 1, &claims, ConsentState::Active);
        assert_eq!(
            out,
            ConsentAwareRarity::RetainRare(RarityScore(n * HOLDING_WEIGHT_POSSESSION_VERIFIED))
        );
    }

    fn hex_sha256(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(bytes);
        let mut s = String::with_capacity(64);
        for b in digest {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    #[test]
    fn verify_symbol_against_manifest_correct_hash_returns_true() {
        let bytes = b"the rarest shard";
        let manifest = vec![hex_sha256(b"other"), hex_sha256(bytes)];
        assert!(verify_symbol_against_manifest(bytes, 1, &manifest));
    }

    #[test]
    fn verify_symbol_against_manifest_wrong_hash_returns_false() {
        let bytes = b"the rarest shard";
        // manifest[0] is the hash of DIFFERENT bytes.
        let manifest = vec![hex_sha256(b"tampered"), hex_sha256(b"unrelated")];
        assert!(!verify_symbol_against_manifest(bytes, 0, &manifest));
    }

    #[test]
    fn verify_symbol_against_manifest_oob_symbol_id_returns_false() {
        let bytes = b"x";
        let manifest = vec![hex_sha256(bytes)];
        // symbol_id 1 is out of bounds for a 1-entry manifest.
        assert!(!verify_symbol_against_manifest(bytes, 1, &manifest));
        // u32::MAX is also OOB and must not panic.
        assert!(!verify_symbol_against_manifest(bytes, u32::MAX, &manifest));
    }

    // ---- §8.1.11.3 N5 hard-delete trait wiring ----

    /// A stand-in persist tier that records the hard-delete calls the
    /// policy layer would make on revoke.
    #[derive(Default)]
    struct FakeEvictor {
        calls: std::cell::RefCell<Vec<(String, String)>>,
        fail: bool,
    }

    impl FountainEvictHardDelete for FakeEvictor {
        fn evict_fountain_content_hard_delete(
            &self,
            content_id: &str,
            corpus_kind: &str,
        ) -> Result<(), FountainEvictError> {
            if self.fail {
                return Err(FountainEvictError::HardDeleteFailed("simulated".into()));
            }
            self.calls
                .borrow_mut()
                .push((content_id.to_string(), corpus_kind.to_string()));
            Ok(())
        }
    }

    #[test]
    fn hard_delete_trait_dispatches_content_and_corpus() {
        let evictor = FakeEvictor::default();
        let dynref: &dyn FountainEvictHardDelete = &evictor;
        dynref
            .evict_fountain_content_hard_delete("content-X", "fountain-corpus")
            .expect("hard-delete ok");
        assert_eq!(
            *evictor.calls.borrow(),
            vec![("content-X".to_string(), "fountain-corpus".to_string())]
        );
    }

    #[test]
    fn hard_delete_trait_surfaces_failure() {
        let evictor = FakeEvictor {
            fail: true,
            ..Default::default()
        };
        let err = evictor
            .evict_fountain_content_hard_delete("content-X", "fountain-corpus")
            .expect_err("must surface the persist failure");
        assert!(matches!(err, FountainEvictError::HardDeleteFailed(_)));
    }

    // ─── should_eject_above_target — proactive trim primitive ──────

    #[test]
    fn eject_at_or_below_target_returns_keep() {
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        // Default: target_holders=30, safety=15% => over-threshold=34
        for holders in [0u32, 10, 20, 30, 34] {
            let v = should_eject_above_target(
                holders,
                &policy,
                ConsentState::Active,
                RarityScore(holders + 100), // not-rare doesn't matter at-or-below
            );
            assert_eq!(
                v,
                EjectionVerdict::Keep,
                "at holders={holders} expected Keep"
            );
        }
    }

    #[test]
    fn eject_above_target_with_common_local_returns_eject_to_tier() {
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        // 35+ holders + local symbol >= target/2 = 15 is "common"
        let v = should_eject_above_target(
            35,
            &policy,
            ConsentState::Active,
            RarityScore(20), // >= 15, common
        );
        assert_eq!(v, EjectionVerdict::EjectToTier);
    }

    #[test]
    fn eject_above_target_with_rare_local_returns_keep() {
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        // Even at 100 holders, if THIS peer's local symbol is rare
        // (rarity < target/2 = 15), KEEP it — the network is over-
        // replicated on average but this symbol_id is load-bearing.
        let v = should_eject_above_target(
            100,
            &policy,
            ConsentState::Active,
            RarityScore(5), // < 15, rare
        );
        assert_eq!(v, EjectionVerdict::Keep);
    }

    #[test]
    fn eject_consent_revoked_returns_hard_delete_regardless_of_count() {
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        // Revoked dominates rarity AND holder-count.
        for (holders, rarity) in [(0u32, 0u32), (30, 30), (200, 1)] {
            let v = should_eject_above_target(
                holders,
                &policy,
                ConsentState::Revoked,
                RarityScore(rarity),
            );
            assert_eq!(
                v,
                EjectionVerdict::EjectHardDelete,
                "Revoked must EjectHardDelete regardless of holders={holders} rarity={rarity}"
            );
        }
    }

    #[test]
    fn eject_consent_unknown_behaves_like_active() {
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        // Unknown is fail-secure (don't keep-as-rare) but is NOT
        // hard-delete. At <= target it's Keep (no over-replication
        // to free); at > target with common local it's EjectToTier.
        assert_eq!(
            should_eject_above_target(20, &policy, ConsentState::Unknown, RarityScore(50)),
            EjectionVerdict::Keep
        );
        assert_eq!(
            should_eject_above_target(50, &policy, ConsentState::Unknown, RarityScore(50)),
            EjectionVerdict::EjectToTier
        );
    }

    #[test]
    fn eject_threshold_locked_at_15_percent_safety_margin() {
        // Wire-determinism-critical: any change to the threshold math
        // is a coordinated CEG amendment. This test pins the v1
        // threshold for the §R conformance vectors.
        assert_eq!(EJECT_ABOVE_TARGET_SAFETY_MARGIN_PCT, 15);
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let safety = policy.target_holders * 15 / 100;
        let over_target = policy.target_holders + safety;
        assert_eq!(
            over_target, 34,
            "v1 over-target threshold at default policy"
        );
    }

    // ─── §19.7.3 EjectAggregatedTierOnly (v4.5.0 / CEG 1.0-RC17) ──

    #[test]
    fn eject_aggregated_tier_constructs_at_tier() {
        for tier in [0u32, 1, 2, 3, 7, u32::MAX] {
            let v = eject_aggregated_tier(tier);
            assert_eq!(
                v,
                EjectionVerdict::EjectAggregatedTierOnly { tier },
                "tier={tier} must round-trip through the constructor"
            );
        }
    }

    #[test]
    fn eject_aggregated_tier_distinct_from_other_verdicts() {
        // The tier-only variant must NOT collide with EjectToTier /
        // EjectHardDelete / Keep at any tier; it is a distinct
        // verdict shape (§19.7.3).
        let v1 = eject_aggregated_tier(1);
        assert_ne!(v1, EjectionVerdict::EjectToTier);
        assert_ne!(v1, EjectionVerdict::EjectHardDelete);
        assert_ne!(v1, EjectionVerdict::Keep);
    }

    #[test]
    fn eject_aggregated_tier_different_tiers_are_inequal() {
        // Two tier-only verdicts with different `tier` values are
        // structurally distinct — composes with persist v8.6.0's
        // tier-granular evict so a tier-2 ejection does NOT touch
        // tier-1 or tier-3.
        let a = eject_aggregated_tier(1);
        let b = eject_aggregated_tier(2);
        assert_ne!(a, b);
    }

    #[test]
    fn revocation_still_dominates_over_tier_only_pressure() {
        // §19.3 N5 invariant: even under targeted tier pressure,
        // ConsentState::Revoked routes through hard-delete. The
        // tier-only verdict is for capacity pressure, NOT for the
        // §19.7 forced descent below the noise floor.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        // 100 holders + Revoked → EjectHardDelete (NOT
        // EjectAggregatedTierOnly), regardless of tier-pressure
        // potential.
        let v = should_eject_above_target(100, &policy, ConsentState::Revoked, RarityScore(50));
        assert_eq!(v, EjectionVerdict::EjectHardDelete);
    }

    // ─── CIRISEdge#184 (v6.3.0) — diversity refinement ─────────────

    #[test]
    fn diversity_none_falls_back_to_rarity_only() {
        // No diversity score → behavior IDENTICAL to should_eject_above_target.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let base = should_eject_above_target(35, &policy, ConsentState::Active, RarityScore(20));
        let with_div = should_eject_with_diversity(
            35,
            &policy,
            ConsentState::Active,
            RarityScore(20),
            None,
            None,
        );
        assert_eq!(base, with_div);
    }

    #[test]
    fn diversity_low_score_keeps_eject() {
        // 35 holders + common symbol + low diversity (clustered) →
        // still EjectToTier.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let v = should_eject_with_diversity(
            35,
            &policy,
            ConsentState::Active,
            RarityScore(20),
            Some(0.05), // clustered → low score
            Some(0.30), // median floor
        );
        assert_eq!(v, EjectionVerdict::EjectToTier);
    }

    #[test]
    fn diversity_high_score_flips_eject_to_keep() {
        // 35 holders + common symbol + high diversity (topologically
        // unique) → flip to Keep.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let v = should_eject_with_diversity(
            35,
            &policy,
            ConsentState::Active,
            RarityScore(20),
            Some(0.50), // diverse → high score
            Some(0.30), // median floor
        );
        assert_eq!(v, EjectionVerdict::Keep);
    }

    #[test]
    fn diversity_does_not_override_revocation() {
        // Revoked + sky-high diversity → still EjectHardDelete.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let v = should_eject_with_diversity(
            100,
            &policy,
            ConsentState::Revoked,
            RarityScore(50),
            Some(99.0),
            Some(0.10),
        );
        assert_eq!(v, EjectionVerdict::EjectHardDelete);
    }

    #[test]
    fn diversity_does_not_override_keep_when_rare() {
        // Rare symbol → substrate says Keep; diversity refinement
        // can't override "preserve rare copy" invariant.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let v = should_eject_with_diversity(
            35,
            &policy,
            ConsentState::Active,
            RarityScore(2), // rare (below target_holders/2 = 15)
            Some(0.01),     // clustered — would normally argue for eject
            Some(0.50),
        );
        assert_eq!(v, EjectionVerdict::Keep);
    }

    #[test]
    fn diversity_score_with_no_floor_falls_back() {
        // Score present but floor missing → diversity gate doesn't
        // engage; substrate verdict survives.
        let policy = crate::holonomic::fountain_defaults::recommended_policy();
        let v = should_eject_with_diversity(
            35,
            &policy,
            ConsentState::Active,
            RarityScore(20),
            Some(0.99),
            None,
        );
        assert_eq!(v, EjectionVerdict::EjectToTier);
    }
}
