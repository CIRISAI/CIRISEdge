//! Recursive trust bootstrap — v3.10.0 holonomic Part 4
//! (CIRISEdge#137).
//!
//! A new peer is admitted if its signed claim chains (via witness
//! chain) to a trust root in our trust graph. No special first-peer
//! assumption. The federation can re-establish itself from any
//! sufficient fragment — including a single peer with a single
//! signed witness chain.
//!
//! Composes with:
//!
//! - #135 `WholenessWitness` — the witness chain is composed of
//!   `WholenessWitness` entries + signed claims.
//! - #134 swarm rarity — admitted peer immediately participates in
//!   rarity computation.
//! - #136 deterministic ALM — admitted peer arrives at the same
//!   topology as the existing federation.
//!
//! # Algorithm
//!
//! [`recursive_trust_bootstrap`] takes an already-verified candidate
//! [`SignedClaim`] plus the local node's [`TrustGraph`] and the
//! candidate's supplied [`WitnessChain`]. The function:
//!
//! 1. Refuses with [`AdmissionRefusal::SignatureInvalid`] if the
//!    candidate's `verified` flag is false. **Signature verification
//!    is the caller's job** — this function operates over the trust
//!    topology only.
//! 2. If the candidate's `signer_peer_id` is in `trust_graph.roots`,
//!    admits at [`trust_distance`](AdmissionVerdict::Admit) `0`.
//! 3. Refuses with [`AdmissionRefusal::ChainTooLong`] if the chain's
//!    length exceeds `trust_graph.max_chain_depth`.
//! 4. Walks the witness chain in reverse chronological order (newest
//!    claim first, oldest last — i.e. `claims.iter().enumerate().rev()`
//!    since index `0` is the OLDEST). For each chain entry that is
//!    itself unverified, refuses with [`AdmissionRefusal::SignatureInvalid`]
//!    (refusal propagates fast — the chain must be fully signed).
//!    For each verified chain entry, if its `signer_peer_id` is in
//!    `trust_graph.roots`, anchor distance is `0`; if it's a granter
//!    in `trust_graph.grants` with `chain_depth <=
//!    trust_graph.max_chain_depth`, anchor distance is
//!    `chain_depth`. Otherwise the entry is unanchored and
//!    the loop continues. When an anchor is found at chain index
//!    `i` with anchor distance `d`, the candidate is admitted at
//!    `d + (chain.len() - i)` — `(chain.len() - i)` is the number
//!    of trust hops between the anchor's claim and the candidate
//!    (the candidate sits "after" the newest claim, so one extra
//!    hop than the index gap).
//! 5. If the cumulative candidate distance would exceed
//!    `trust_graph.max_chain_depth`, refuses with
//!    [`AdmissionRefusal::BudgetExceeded`].
//! 6. If no chain entry anchors, refuses with
//!    [`AdmissionRefusal::ChainExhausted`].
//!
//! # Wire contract
//!
//! [`SignedClaim::canonical_value`] produces the canonical-bytes
//! input the hybrid signer must sign over. The signed canonical
//! value field order is (see [`SignedClaim::CANONICAL_FIELD_ORDER`]):
//!
//! 1. `signed_at_unix_ms` — 8 bytes BE u64
//! 2. `claim_version` — 2 bytes BE u16
//! 3. `claim_kind` — length-prefixed UTF-8 (4 bytes BE u32 length +
//!    bytes)
//! 4. `signer_peer_id` — length-prefixed UTF-8 (4 bytes BE u32
//!    length + bytes)
//! 5. `claim_bytes_hex` — length-prefixed lowercase-hex ASCII
//!    (4 bytes BE u32 length + bytes)
//!
//! `claim_bytes` is encoded as lowercase hex in the canonical value
//! so the canonical-bytes input remains pure-ASCII and is safe to
//! diff/log/structure-print. Hybrid sig fields (Ed25519 + ML-DSA-65)
//! live OUTSIDE the canonical bytes on [`SignedClaim`].
//!
//! # `TrustGrant` re-export
//!
//! v3.10.0 Part 3 (CIRISEdge#136, deterministic ALM topology)
//! authors the canonical [`TrustGrant`] type. Part 4 re-exports it
//! from `crate::holonomic::deterministic_topology` so there is exactly
//! one wire-shape across the substrate.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

// ─── Trust-graph types ─────────────────────────────────────────────

/// A signed grant of trust from one peer to another.
///
/// Re-exported from Part 3 ([`crate::holonomic::deterministic_topology`])
/// — that module owns the canonical shape. Part 4 reads the
/// `chain_depth` field as the distance-from-root anchor when computing
/// trust budgets in [`bootstrap_admit`].
pub use crate::holonomic::deterministic_topology::TrustGrant;

/// The local node's view of trust.
///
/// `roots` are pubkey-form peer ids the local node trusts directly
/// (out-of-band, hard-coded, or via prior accord acceptance).
/// `grants` extend trust transitively; `max_chain_depth` caps how
/// far a witness chain may extend before bootstrap refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraph {
    /// Pubkey-form peer ids the local node trusts directly.
    pub roots: Vec<String>,

    /// Transitive grants — same shape as Part 3.
    pub grants: Vec<TrustGrant>,

    /// Maximum number of trust hops from a root before bootstrap
    /// refuses with [`AdmissionRefusal::ChainTooLong`] or
    /// [`AdmissionRefusal::BudgetExceeded`].
    pub max_chain_depth: u8,
}

impl TrustGraph {
    /// Look up the anchor distance of a peer id in this graph.
    ///
    /// Returns:
    /// - `Some(0)` if the peer id is in [`Self::roots`].
    /// - `Some(chain_depth)` of the FIRST grant whose
    ///   `granter_peer_id == peer_id` and `chain_depth <=
    ///   max_chain_depth`.
    /// - `None` otherwise.
    ///
    /// Iteration is deterministic in the order grants were added.
    fn anchor_distance_for(&self, peer_id: &str) -> Option<u8> {
        if self.roots.iter().any(|r| r == peer_id) {
            return Some(0);
        }
        for grant in &self.grants {
            if grant.granter_peer_id == peer_id && grant.chain_depth <= self.max_chain_depth {
                return Some(grant.chain_depth);
            }
        }
        None
    }
}

// ─── Signed-claim envelope ─────────────────────────────────────────

/// Generic signed-claim envelope — the bootstrap surface.
///
/// We already have specific signed-claim types like
/// [`SignedRelayCapacity`](crate::transport::realtime_av_alm::SignedRelayCapacity);
/// this is the **generic** shape used by the recursive-trust
/// bootstrap algorithm. `claim_bytes` is the canonical bytes of the
/// inner claim — opaque to this module.
///
/// # Signature contract
///
/// `signature_ed25519_base64` and `signature_ml_dsa_65_base64` are
/// **hybrid sig fields outside the canonical bytes**. Same hybrid
/// shape as [`SignedRelayCapacity`]: classical Ed25519 over
/// [`Self::canonical_value`], then ML-DSA-65 over `(canonical ||
/// ed25519_sig)`.
///
/// The `verified` flag is a documented caller contract:
/// [`recursive_trust_bootstrap`] DOES NOT re-verify the signature
/// — the verification call lives at the caller. The function takes
/// already-verified claims as input and trusts `verified` to be
/// true; if it's false, the function refuses with
/// [`AdmissionRefusal::SignatureInvalid`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedClaim {
    /// What kind of claim this is — e.g. `"trust_grant"`,
    /// `"holding_claim"`, `"wholeness_witness"`. Opaque to the
    /// bootstrap algorithm; bound into the canonical bytes so a
    /// `trust_grant` signature can't be replayed as a
    /// `holding_claim`.
    pub claim_kind: String,

    /// Pubkey-form peer id of the signer. Bound into the canonical
    /// bytes so the signer can't be substituted post-sign.
    pub signer_peer_id: String,

    /// Canonical bytes of the inner claim. Opaque to this module.
    pub claim_bytes: Vec<u8>,

    /// Wall-clock the claim was signed. Bootstrap doesn't validate
    /// the timestamp — that's the policy layer's job.
    pub signed_at_unix_ms: u64,

    /// Schema version of the inner claim. Bound into the canonical
    /// bytes so a v1 signature can't be replayed as v2.
    pub claim_version: u16,

    /// Base64 Ed25519 signature over [`Self::canonical_value`].
    /// Outside the canonical bytes.
    pub signature_ed25519_base64: String,

    /// Base64 ML-DSA-65 signature over `(canonical ||
    /// ed25519_sig)`. Outside the canonical bytes.
    pub signature_ml_dsa_65_base64: String,

    /// Caller-asserted "the hybrid signature on this claim has
    /// already been verified against `signer_peer_id`'s pubkeys".
    /// [`recursive_trust_bootstrap`] does NOT re-verify — it
    /// refuses with [`AdmissionRefusal::SignatureInvalid`] when
    /// this is false.
    pub verified: bool,
}

impl SignedClaim {
    /// Documented canonical-value field order. The signed canonical
    /// value field order is locked here so cross-language signers
    /// (PyO3 / UniFFI / future Swift binding) all produce the same
    /// bytes.
    pub const CANONICAL_FIELD_ORDER: &'static [&'static str] = &[
        "signed_at_unix_ms",
        "claim_version",
        "claim_kind",
        "signer_peer_id",
        "claim_bytes_hex",
    ];

    /// Domain separator for the canonical bytes. Disambiguates from
    /// other CIRIS signed envelopes (relay-capacity, accord,
    /// envelope, ...).
    pub const DOMAIN_SEP: &'static [u8; 16] = b"CIRIS-CLAIM-v1\0\0";

    /// Build the canonical-bytes input the hybrid signer signs
    /// over. Field order matches [`Self::CANONICAL_FIELD_ORDER`].
    ///
    /// `claim_bytes` is encoded as lowercase hex so the canonical
    /// bytes remain pure-ASCII (safe to diff / log / structure-
    /// print). Each variable-length field is length-prefixed with
    /// a 4-byte BE u32 byte length.
    #[must_use]
    pub fn canonical_value(&self) -> Vec<u8> {
        let claim_bytes_hex = lowercase_hex(&self.claim_bytes);

        let mut out = Vec::with_capacity(
            Self::DOMAIN_SEP.len()
                + 8
                + 2
                + 4
                + self.claim_kind.len()
                + 4
                + self.signer_peer_id.len()
                + 4
                + claim_bytes_hex.len(),
        );

        out.extend_from_slice(Self::DOMAIN_SEP);
        out.extend_from_slice(&self.signed_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.claim_version.to_be_bytes());

        let kind = self.claim_kind.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        let kind_len = kind.len() as u32;
        out.extend_from_slice(&kind_len.to_be_bytes());
        out.extend_from_slice(kind);

        let signer = self.signer_peer_id.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        let signer_len = signer.len() as u32;
        out.extend_from_slice(&signer_len.to_be_bytes());
        out.extend_from_slice(signer);

        let hex_bytes = claim_bytes_hex.as_bytes();
        #[allow(clippy::cast_possible_truncation)]
        let hex_len = hex_bytes.len() as u32;
        out.extend_from_slice(&hex_len.to_be_bytes());
        out.extend_from_slice(hex_bytes);

        out
    }
}

/// Lowercase hex encoder. Local because this module has no
/// `hex`-crate dep at the Cargo level for the holonomic surface
/// (and the canonical-bytes path is hot enough we'd rather not
/// pull a transitive dep just for this one call site).
fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ─── Witness chain ─────────────────────────────────────────────────

/// An ordered list of [`SignedClaim`]s, each signed by a peer.
///
/// Index `0` is the OLDEST claim. The bootstrap algorithm walks
/// BACKWARDS through the chain (newest first, oldest last) looking
/// for the first claim whose signer anchors to a trust root.
///
/// `chain_version` lets the federation evolve the chain encoding
/// without breaking already-circulating chains; v1 is the only
/// version defined today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessChain {
    /// Ordered chronologically; index `0` is the oldest claim.
    pub claims: Vec<SignedClaim>,

    /// Schema version of the witness-chain encoding. v1 today.
    pub chain_version: u16,
}

// ─── Admission verdict ─────────────────────────────────────────────

/// The outcome of [`recursive_trust_bootstrap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionVerdict {
    /// Peer is admitted. `trust_distance` is the number of trust
    /// hops between the peer and the anchoring root (0 means the
    /// peer IS a root). `anchored_to_root` is the pubkey-form peer
    /// id of the root the chain anchored at.
    Admit {
        trust_distance: u8,
        anchored_to_root: String,
    },
    /// Peer cannot be transitively trusted within the chain budget.
    Refuse { reason: AdmissionRefusal },
}

/// Why a peer was refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionRefusal {
    /// No claim in the witness chain anchored to a root in the
    /// local trust graph.
    ChainExhausted,
    /// The candidate claim or a chain entry was not pre-verified
    /// by the caller. [`recursive_trust_bootstrap`] does NOT
    /// re-verify signatures.
    SignatureInvalid,
    /// The witness chain has more entries than
    /// [`TrustGraph::max_chain_depth`] allows.
    ChainTooLong,
    /// An anchor exists but the candidate's cumulative trust
    /// distance would exceed [`TrustGraph::max_chain_depth`].
    BudgetExceeded,
}

// ─── The function ──────────────────────────────────────────────────

/// Bootstrap a new peer's admission via recursive trust.
///
/// See module-level docs for the full algorithm. Pure compute over
/// the trust topology — signature verification lives at the caller
/// per the [`SignedClaim::verified`] contract.
#[must_use]
pub fn recursive_trust_bootstrap(
    p_signed_claim: &SignedClaim,
    trust_graph: &TrustGraph,
    witness_chain: &WitnessChain,
) -> AdmissionVerdict {
    // Step 1 — refuse fast if the candidate claim isn't verified.
    if !p_signed_claim.verified {
        return AdmissionVerdict::Refuse {
            reason: AdmissionRefusal::SignatureInvalid,
        };
    }

    // Step 2 — if the candidate's signer is already a root, admit
    // at distance 0.
    if trust_graph
        .roots
        .iter()
        .any(|r| r == &p_signed_claim.signer_peer_id)
    {
        return AdmissionVerdict::Admit {
            trust_distance: 0,
            anchored_to_root: p_signed_claim.signer_peer_id.clone(),
        };
    }

    // Step 3 — chain length check. If the chain itself is longer
    // than the max chain depth, refuse before any walk.
    let chain_len = witness_chain.claims.len();
    if chain_len > usize::from(trust_graph.max_chain_depth) {
        return AdmissionVerdict::Refuse {
            reason: AdmissionRefusal::ChainTooLong,
        };
    }

    // Step 4 — walk the chain in reverse chronological order
    // (newest first, oldest last; index 0 == oldest, so
    // `.iter().enumerate().rev()` produces (len-1, newest) down to
    // (0, oldest)).
    //
    // First anchor wins. If a chain entry is unverified we refuse
    // immediately — the whole chain must be signed.
    let roots_set: BTreeSet<&str> = trust_graph.roots.iter().map(String::as_str).collect();
    for (i, claim) in witness_chain.claims.iter().enumerate().rev() {
        if !claim.verified {
            return AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::SignatureInvalid,
            };
        }

        // Direct-root anchor at chain index i.
        if roots_set.contains(claim.signer_peer_id.as_str()) {
            return admit_at_chain_index(
                i,
                chain_len,
                0,
                &claim.signer_peer_id,
                trust_graph.max_chain_depth,
            );
        }

        // Granter anchor at chain index i.
        if let Some(d) = trust_graph.anchor_distance_for(&claim.signer_peer_id) {
            // Granter must transitively chain to SOMETHING — but
            // `anchor_distance_for` already filtered out grants
            // whose distance exceeds `max_chain_depth`, so the
            // pure topology check passes. We still need to name a
            // root for `Admit::anchored_to_root`; we name the
            // granter's pubkey (the closest known anchor on the
            // candidate's side of the graph). Downstream callers
            // who want the exact root can re-walk the grants
            // graph themselves.
            return admit_at_chain_index(
                i,
                chain_len,
                d,
                &claim.signer_peer_id,
                trust_graph.max_chain_depth,
            );
        }
    }

    // Step 5 — no anchor found in the entire chain.
    AdmissionVerdict::Refuse {
        reason: AdmissionRefusal::ChainExhausted,
    }
}

/// Compute the candidate's distance given an anchor at chain index
/// `i` with anchor distance `anchor_dist`. Returns
/// [`AdmissionVerdict::Refuse`] with [`AdmissionRefusal::BudgetExceeded`]
/// when the sum exceeds `max_chain_depth`.
///
/// `chain_len - i` is the number of trust hops between the anchor
/// claim and the candidate (the candidate sits "after" the newest
/// claim, so one extra hop than the index gap to the end).
fn admit_at_chain_index(
    i: usize,
    chain_len: usize,
    anchor_dist: u8,
    anchored_to_root: &str,
    max_chain_depth: u8,
) -> AdmissionVerdict {
    // hops_to_candidate = (chain_len - i) — guaranteed >= 1 because
    // `i < chain_len` everywhere this is called from. Bound to u8
    // via saturating cast — the chain-length check earlier ensures
    // chain_len <= max_chain_depth <= u8::MAX so no truncation in
    // practice.
    let hops_to_candidate = chain_len - i; // >= 1
    let hops_u8 = u8::try_from(hops_to_candidate).unwrap_or(u8::MAX);
    let total = anchor_dist.saturating_add(hops_u8);
    if total > max_chain_depth {
        return AdmissionVerdict::Refuse {
            reason: AdmissionRefusal::BudgetExceeded,
        };
    }
    AdmissionVerdict::Admit {
        trust_distance: total,
        anchored_to_root: anchored_to_root.to_string(),
    }
}

// ───────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(kind: &str, signer: &str, version: u16) -> SignedClaim {
        SignedClaim {
            claim_kind: kind.to_string(),
            signer_peer_id: signer.to_string(),
            claim_bytes: vec![0xde, 0xad, 0xbe, 0xef],
            signed_at_unix_ms: 1_700_000_000_000,
            claim_version: version,
            signature_ed25519_base64: "ed25519-stub".into(),
            signature_ml_dsa_65_base64: "ml-dsa-65-stub".into(),
            verified: true,
        }
    }

    #[allow(clippy::similar_names)]
    fn grant(granter: &str, grantee: &str, dist: u8) -> TrustGrant {
        TrustGrant {
            granter_peer_id: granter.to_string(),
            grantee_peer_id: grantee.to_string(),
            chain_depth: dist,
            granted_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn direct_root_admits_at_distance_zero() {
        let candidate = claim("trust_grant", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Admit {
                trust_distance: 0,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }

    #[test]
    fn one_hop_chain_admits_at_distance_one() {
        // Candidate isn't a root, but the chain has a single entry
        // whose signer IS a root. Candidate distance = 1.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let root_witness = claim("wholeness_witness", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            // Grant from root to candidate — bootstrap doesn't
            // require this grant to exist (the chain itself is
            // the evidence), but it's the realistic shape.
            grants: vec![grant("ROOT_PEER", "CANDIDATE_PEER", 0)],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![root_witness],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Admit {
                trust_distance: 1,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }

    #[test]
    fn chain_exhausted_returns_refuse_chain_exhausted() {
        // Candidate isn't a root; no chain entry's signer anchors
        // to a root or to a grant.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let stranger_a = claim("wholeness_witness", "STRANGER_A", 1);
        let stranger_b = claim("wholeness_witness", "STRANGER_B", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![stranger_a, stranger_b],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::ChainExhausted,
            }
        );
    }

    #[test]
    fn chain_longer_than_max_depth_returns_refuse_chain_too_long() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        // max_chain_depth = 2 but chain has 3 entries.
        let c1 = claim("wholeness_witness", "PEER_1", 1);
        let c2 = claim("wholeness_witness", "PEER_2", 1);
        let c3 = claim("wholeness_witness", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 2,
        };
        let chain = WitnessChain {
            claims: vec![c1, c2, c3],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::ChainTooLong,
            }
        );
    }

    #[test]
    fn canonical_bytes_locked_field_order() {
        // Lock the canonical-bytes field order against accidental
        // reorder. Field order is asserted via two checks:
        //
        //   1. CANONICAL_FIELD_ORDER constant matches the doc.
        //   2. The byte layout puts each field at its documented
        //      offset.
        assert_eq!(
            SignedClaim::CANONICAL_FIELD_ORDER,
            &[
                "signed_at_unix_ms",
                "claim_version",
                "claim_kind",
                "signer_peer_id",
                "claim_bytes_hex",
            ]
        );

        let c = SignedClaim {
            claim_kind: "tg".into(),
            signer_peer_id: "P".into(),
            claim_bytes: vec![0xab, 0xcd],
            signed_at_unix_ms: 0x0011_2233_4455_6677,
            claim_version: 0x0102,
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
            verified: true,
        };
        let bytes = c.canonical_value();

        // Domain sep — 16 bytes.
        assert_eq!(&bytes[..16], SignedClaim::DOMAIN_SEP);

        // signed_at_unix_ms — 8 bytes BE.
        assert_eq!(&bytes[16..24], &0x0011_2233_4455_6677_u64.to_be_bytes());

        // claim_version — 2 bytes BE.
        assert_eq!(&bytes[24..26], &0x0102_u16.to_be_bytes());

        // claim_kind — 4 byte BE u32 length + 2 bytes "tg".
        assert_eq!(&bytes[26..30], &2u32.to_be_bytes());
        assert_eq!(&bytes[30..32], b"tg");

        // signer_peer_id — 4 byte BE u32 length + 1 byte "P".
        assert_eq!(&bytes[32..36], &1u32.to_be_bytes());
        assert_eq!(&bytes[36..37], b"P");

        // claim_bytes_hex — 4 byte BE u32 length + 4 bytes
        // "abcd" (lowercase hex of [0xab, 0xcd]).
        assert_eq!(&bytes[37..41], &4u32.to_be_bytes());
        assert_eq!(&bytes[41..45], b"abcd");

        // No trailing bytes.
        assert_eq!(bytes.len(), 45);
    }

    #[test]
    fn walks_chain_backwards() {
        // Chain ordering: [oldest, newer, newest]. Only the OLDEST
        // signer (index 0) is a root. Bootstrap walks newest →
        // oldest and anchors at index 0. The candidate's distance
        // therefore equals chain_len - 0 == 3.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let oldest = claim("wholeness_witness", "OLDEST_ROOT", 1);
        let newer = claim("wholeness_witness", "MID_PEER", 1);
        let newest = claim("wholeness_witness", "NEWEST_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["OLDEST_ROOT".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![oldest, newer, newest],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Admit {
                trust_distance: 3,
                anchored_to_root: "OLDEST_ROOT".to_string(),
            }
        );
    }

    // ─── Bonus invariant tests ───────────────────────────────────

    #[test]
    fn unverified_candidate_refused_signature_invalid() {
        let mut candidate = claim("trust_grant", "ROOT_PEER", 1);
        candidate.verified = false;
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::SignatureInvalid,
            }
        );
    }

    #[test]
    fn unverified_chain_entry_refused_signature_invalid() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let mut anchor = claim("wholeness_witness", "ROOT_PEER", 1);
        anchor.verified = false;
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![anchor],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::SignatureInvalid,
            }
        );
    }

    #[test]
    fn budget_exceeded_when_anchor_distance_plus_hops_overflows_depth() {
        // max_chain_depth = 2, chain length = 2 (passes ChainTooLong),
        // anchor at index 0 has chain_depth = 1 → total
        // distance = 1 + 2 = 3 > 2 → BudgetExceeded.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let mid = claim("wholeness_witness", "MID_PEER", 1);
        let granter = claim("wholeness_witness", "GRANTER_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            // GRANTER_PEER is at distance 1 from ROOT_PEER —
            // within max_chain_depth (2), so anchor_distance_for
            // returns Some(1). Adding 2 hops to candidate → 3.
            grants: vec![grant("GRANTER_PEER", "OTHER", 1)],
            max_chain_depth: 2,
        };
        let chain = WitnessChain {
            claims: vec![granter, mid],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::BudgetExceeded,
            }
        );
    }

    #[test]
    fn lowercase_hex_matches_documented_alphabet() {
        assert_eq!(lowercase_hex(&[]), "");
        assert_eq!(lowercase_hex(&[0x00]), "00");
        assert_eq!(lowercase_hex(&[0xff]), "ff");
        assert_eq!(lowercase_hex(&[0x0a, 0xbc, 0xde, 0xf0]), "0abcdef0");
    }
}
