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
}
