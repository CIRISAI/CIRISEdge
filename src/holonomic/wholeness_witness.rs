//! WholenessWitness — v3.10.0 holonomic Part 2 (the keystone).
//!
//! Each peer publishes signed Merkle roots over its CEG claim state.
//! Other peers cross-compare; mismatch surfaces reconciliation work.
//!
//! Composes with #134 swarm rarity, #136 deterministic ALM, and
//! #137 recursive trust bootstrap — all consume witness chains as
//! the path-independent membership-and-state primitive.
//!
//! This is Bohm's "implicit order made explicit" applied to federation
//! state: the witness chain projects each peer's hidden CEG claim
//! tree into a single 32-byte root, so divergence between peers
//! becomes a constant-time comparison rather than a tree-walk.
//!
//! # Wire-format lock — v1 (DO NOT change without a CEG amendment)
//!
//! Two pieces of wire surface are byte-exact LOCKED at v1; any change
//! requires a CEG normative-amendment cycle and a `witness_version`
//! bump. Sibling implementations (Python / Swift / Kotlin via UniFFI)
//! reproduce the byte sequences below or they will disagree with this
//! crate at the root level.
//!
//! ## Canonical-bytes contract (signed-bytes basis)
//!
//! [`WholenessWitness::canonical_value`] emits a JSON object whose
//! field order is exactly:
//!
//! ```text
//! peer_id, epoch_id, merkle_root, leaf_count, claim_namespaces,
//! observed_at_unix_ms, witness_version
//! ```
//!
//! - `merkle_root` is the lowercase-hex encoding of the 32-byte root
//!   (64 chars, no `0x` prefix).
//! - `claim_namespaces` is sorted lexicographically BEFORE
//!   canonicalization (so any peer recomputing the bytes lands on
//!   the same array regardless of insertion order).
//! - The hybrid-signature fields (`signature`, `signature_ml_dsa_65`,
//!   `pqc_key_id`) are NOT included in the canonical bytes — they
//!   live on the envelope wrapper, signing the canonical bytes from
//!   outside.
//!
//! ## Merkle construction (CT-style, last-node duplication)
//!
//! The algorithm is byte-exact:
//!
//! 1. If `leaves.is_empty()` → return `SHA-256(b"WW-v1-empty")`
//!    (well-known sentinel; documented because there is no natural
//!    Merkle root for the empty multiset).
//! 2. Hash each leaf: `layer = leaves.iter().map(SHA-256).collect()`
//!    (each leaf is already `canonical_bytes` of a signed claim at
//!    the claim layer — we apply ONE additional SHA-256 here so the
//!    leaf-hash domain is distinct from the inner-node domain).
//! 3. While `layer.len() > 1`:
//!    - If `layer.len()` is odd, push `layer.last().clone()`
//!      (Bitcoin / RFC 6962 Certificate Transparency convention).
//!    - `new = layer.chunks(2).map(|p| SHA-256(p[0] || p[1])).collect()`
//!    - `layer = new`
//! 4. Return `layer[0]`.
//!
//! Leaf ordering matters: two peers MUST agree on the leaf order
//! (typically: lexicographic sort of leaf bytes BEFORE calling
//! [`compute_merkle_root`]). The function itself does NOT sort — it
//! treats the slice as authoritative — because reconciliation
//! protocols sometimes want a specific structural ordering (e.g.
//! claim-emission order) instead of bytewise order. The contract is:
//! same leaves in same order → same root.
//!
//! # Composition
//!
//! - Issue #134 (swarm rarity): each peer's rarity vector is a
//!   namespace in `claim_namespaces`; rarity proofs verify against
//!   the witness root for the epoch they were emitted under.
//! - Issue #136 (deterministic ALM): the ALM-decision audit trail
//!   is a leaf set; consumers replaying a decision verify their
//!   replay against the publisher's witness.
//! - Issue #137 (recursive trust bootstrap): bootstrap nodes
//!   confirm their incoming view matches the publisher's witness
//!   before grafting onto the federation graph.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Sentinel hashed when the leaf set is empty. Documented sentinel —
/// changing this byte sequence breaks the v1 wire-format contract.
const EMPTY_LEAF_SENTINEL: &[u8] = b"WW-v1-empty";

/// Failure to canonicalize a witness. The error is rare in practice
/// (serde_json over a fixed-shape struct), but propagating it lets
/// callers distinguish a malformed witness from a signing failure.
#[derive(thiserror::Error, Debug)]
pub enum CanonError {
    /// `serde_json::to_vec` failed over the canonical struct.
    #[error("witness canonical serialize: {0}")]
    Serialize(String),
}

/// A signed Merkle witness over a peer's CEG claim state.
///
/// The signed-bytes basis is [`Self::canonical_bytes`]; the hybrid
/// signature fields live outside the signed bytes (the caller signs
/// `canonical_bytes()` with both `ed25519` and `ML-DSA-65`, then
/// fills in the three signature fields below before transmission).
///
/// # Wire-format lock — v1
///
/// Field order, hex-encoding of `merkle_root`, and lex-sort of
/// `claim_namespaces` are LOCKED — see the module-level docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WholenessWitness {
    /// Federation `key_id` of the publishing peer.
    pub peer_id: String,
    /// Monotonically increasing within `(peer_id, namespace_set)`.
    /// Cross-peer comparison is by `(epoch_id, merkle_root)` pairs,
    /// not by epoch alone — two peers may publish epoch 42 with
    /// different roots (the [`WitnessDelta::Divergent`] case).
    pub epoch_id: u64,
    /// 32-byte SHA-256 root over the leaves. Carried as raw bytes
    /// inside this struct; serialized as lowercase hex (64 chars)
    /// inside [`Self::canonical_value`] for cross-language stability.
    pub merkle_root: [u8; 32],
    /// Number of leaves that fed the Merkle construction. Carried
    /// explicitly so a consumer can sanity-check "leaf set claimed
    /// to be empty but root != empty-sentinel" before any expensive
    /// reconciliation work.
    pub leaf_count: u32,
    /// CEG namespaces covered by this witness, e.g.
    /// `["holding_claim", "relay_capacity", "trust_grant"]`.
    /// Sorted lexicographically inside [`Self::canonical_value`]
    /// before serialization — the in-memory order does not affect
    /// the signed bytes.
    pub claim_namespaces: Vec<String>,
    /// Wall-clock observation timestamp (unix milliseconds) of the
    /// claim state this root summarizes. Distinct from "publication
    /// time" — the witness may be republished later.
    pub observed_at_unix_ms: u64,
    /// Wire-format version. `1` at v3.10.0; bumped only via a CEG
    /// normative amendment.
    pub witness_version: u16,
    /// Base64-encoded Ed25519 signature over [`Self::canonical_bytes`].
    /// Outside the signed bytes.
    pub signature: String,
    /// Base64-encoded ML-DSA-65 signature over [`Self::canonical_bytes`].
    /// Outside the signed bytes. Hybrid PQC half of the signing
    /// pair.
    pub signature_ml_dsa_65: String,
    /// Federation `key_id` of the PQC half (typically `"{peer_id}-pqc"`).
    /// Outside the signed bytes.
    pub pqc_key_id: String,
}

/// Cross-peer comparison verdict.
///
/// Returned by [`compare_witnesses`]. The `Divergent` case is the
/// reconciliation trigger — two peers claim the same epoch but
/// disagree on the leaf set, so a reconciliation protocol (#136
/// deterministic ALM, #137 recursive trust bootstrap) needs to
/// surface the disagreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WitnessDelta {
    /// Same `(epoch_id, merkle_root)`. Peers are in agreement at
    /// this epoch.
    Identical,
    /// `ours.epoch_id > theirs.epoch_id`; the wrapped value is
    /// `ours.epoch_id - theirs.epoch_id`. The remote peer needs
    /// to catch up; no reconciliation work for our side yet.
    EpochAhead(u64),
    /// `ours.epoch_id < theirs.epoch_id`; the wrapped value is
    /// `theirs.epoch_id - ours.epoch_id`. We need to catch up.
    EpochBehind(u64),
    /// Same epoch, different root. This is the reconciliation case:
    /// the peers cannot both be correct at this epoch, so the
    /// claim sets need to be exchanged and reconciled.
    Divergent,
}

impl WholenessWitness {
    /// Canonical value for signing. Field order, `merkle_root` hex,
    /// and sorted `claim_namespaces` are LOCKED at v1 — see module
    /// docs. The signature fields are EXCLUDED.
    ///
    /// We build the canonical JSON via a private `#[derive(Serialize)]`
    /// struct (rather than `serde_json::json!`) because
    /// `serde_json::Map` without the `preserve_order` feature is
    /// backed by `BTreeMap` (alphabetical key order), which would
    /// break the locked field order at the byte level. Serde's
    /// default serializer emits struct fields in DECLARATION order,
    /// which is what the v1 contract requires.
    #[must_use]
    pub fn canonical_value(&self) -> serde_json::Value {
        // The intermediate struct is the audit-explicit witness of
        // the v1 field order: any reordering here is a wire-format
        // break and MUST be paired with a `witness_version` bump.
        let canonical = self.canonical_repr();
        // `to_value` over a struct preserves field declaration order
        // because the resulting Value is built by sequential
        // `serialize_field` calls.
        serde_json::to_value(canonical)
            .expect("WholenessWitness canonical struct serializes to Value")
    }

    /// Compact canonical byte serialization. This is the basis the
    /// hybrid signature is computed over.
    ///
    /// Serializes the private `#[derive(Serialize)]` canonical struct
    /// directly to bytes — bypasses [`Self::canonical_value`]'s
    /// Value intermediate so the byte stream is the minimal
    /// compact-JSON form (no extra whitespace, struct fields in
    /// declaration order).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonError> {
        let canonical = self.canonical_repr();
        serde_json::to_vec(&canonical).map_err(|e| CanonError::Serialize(e.to_string()))
    }

    /// Build the private serialize-only canonical view. Shared by
    /// [`Self::canonical_value`] and [`Self::canonical_bytes`].
    fn canonical_repr(&self) -> CanonicalRepr<'_> {
        // Hex-encode merkle_root as lowercase 64-char string.
        let mut root_hex = String::with_capacity(64);
        for b in &self.merkle_root {
            use std::fmt::Write as _;
            let _ = write!(root_hex, "{b:02x}");
        }

        // Lex-sort claim_namespaces. The in-memory order does not
        // affect the signed bytes.
        let mut namespaces = self.claim_namespaces.clone();
        namespaces.sort();

        CanonicalRepr {
            peer_id: &self.peer_id,
            epoch_id: self.epoch_id,
            merkle_root: root_hex,
            leaf_count: self.leaf_count,
            claim_namespaces: namespaces,
            observed_at_unix_ms: self.observed_at_unix_ms,
            witness_version: self.witness_version,
        }
    }
}

/// Private serialize-only view of [`WholenessWitness`] that pins the
/// v1 field order via struct declaration order. Serde emits struct
/// fields in declaration order, so the resulting JSON byte sequence
/// is byte-exact across implementations as long as this struct's
/// field list does not change.
///
/// **WIRE-FORMAT LOCKED — DO NOT REORDER FIELDS**.
#[derive(Serialize)]
struct CanonicalRepr<'a> {
    peer_id: &'a str,
    epoch_id: u64,
    merkle_root: String,
    leaf_count: u32,
    claim_namespaces: Vec<String>,
    observed_at_unix_ms: u64,
    witness_version: u16,
}

/// Compute the v1-locked Merkle root over the leaf set.
///
/// See module-level docs for the byte-exact algorithm. The function is
/// pure: given the same `leaves` slice, it returns the same 32-byte
/// root on every implementation (Rust / Python / Swift / Kotlin).
///
/// # Leaf ordering
///
/// Callers MUST order leaves deterministically before invoking — the
/// function treats the slice as authoritative. The recommended order
/// is lexicographic over the leaf bytes; the canonical alternative
/// (claim-emission order) is also legal as long as both peers agree.
///
/// # Empty input
///
/// Returns `SHA-256(b"WW-v1-empty")` — the documented sentinel.
#[must_use]
pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return sha256(EMPTY_LEAF_SENTINEL);
    }

    // Layer 0: hash each leaf. This step makes the leaf-hash domain
    // distinct from the inner-node domain (defense against length-
    // extension / second-preimage attacks where a forged inner node
    // looks like a leaf and vice-versa).
    let mut layer: Vec<[u8; 32]> = leaves.iter().map(|l| sha256(l)).collect();

    // Reduce upward.
    while layer.len() > 1 {
        // CT / Bitcoin convention: duplicate the last node on
        // odd-count layers so every internal node has two children.
        if layer.len() % 2 == 1 {
            let last = *layer.last().expect("layer non-empty");
            layer.push(last);
        }

        // Pair-hash. `chunks(2)` is safe here — we just made the
        // count even.
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            let mut hasher = Sha256::new();
            hasher.update(pair[0]);
            hasher.update(pair[1]);
            let out: [u8; 32] = hasher.finalize().into();
            next.push(out);
        }
        layer = next;
    }

    layer[0]
}

/// Compare two witnesses and return a [`WitnessDelta`].
///
/// The comparison is `epoch_id` first (the cheap path: "we're ahead"
/// / "we're behind" is a u64 compare), then root-equality at the
/// same epoch (the reconciliation trigger).
///
/// `peer_id` is NOT consulted — the caller is expected to scope the
/// comparison by peer separately (a witness is meaningful only
/// within a `(peer_id, claim_namespace_set)` lane).
#[must_use]
pub fn compare_witnesses(ours: &WholenessWitness, theirs: &WholenessWitness) -> WitnessDelta {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match ours.epoch_id.cmp(&theirs.epoch_id) {
        Greater => WitnessDelta::EpochAhead(ours.epoch_id - theirs.epoch_id),
        Less => WitnessDelta::EpochBehind(theirs.epoch_id - ours.epoch_id),
        Equal => {
            if ours.merkle_root == theirs.merkle_root {
                WitnessDelta::Identical
            } else {
                WitnessDelta::Divergent
            }
        }
    }
}

/// Compute a single-shot SHA-256 over a byte slice and return the
/// 32-byte digest as a fixed-size array.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: lowercase-hex 64-char string for asserting raw roots
    /// in tests without pulling `hex` at runtime.
    fn hex(bytes: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Construct a minimally-populated witness for comparison tests.
    fn witness(epoch_id: u64, root: [u8; 32]) -> WholenessWitness {
        WholenessWitness {
            peer_id: "peer-a".into(),
            epoch_id,
            merkle_root: root,
            leaf_count: 0,
            claim_namespaces: vec!["holding_claim".into()],
            observed_at_unix_ms: 1_700_000_000_000,
            witness_version: 1,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        }
    }

    #[test]
    fn merkle_empty_leaves_returns_sentinel() {
        let got = compute_merkle_root(&[]);
        let want = sha256(b"WW-v1-empty");
        assert_eq!(got, want, "empty-input root must hash the v1 sentinel");
        // Byte-exact assertion against the known SHA-256 of the
        // sentinel string — this anchors the wire format. The hex
        // below is `sha256("WW-v1-empty")`; recompute with
        // `printf 'WW-v1-empty' | sha256sum`.
        assert_eq!(
            hex(&got),
            "2280d27f232100367e86211b5349fe0d6fbaee98e4c2b489a86008049563464f",
            "empty sentinel root is wire-locked at v1"
        );
    }

    #[test]
    fn merkle_single_leaf() {
        let leaf = b"alpha".to_vec();
        let got = compute_merkle_root(std::slice::from_ref(&leaf));
        // Single leaf: ONE hash of the leaf (no inner-node hashing
        // because the layer is already length 1). This is the
        // documented `layer[0]` exit.
        let want = sha256(&leaf);
        assert_eq!(
            got, want,
            "single-leaf root must be SHA-256(leaf) per the documented contract"
        );
    }

    #[test]
    fn merkle_two_leaves() {
        let l0 = b"alpha".to_vec();
        let l1 = b"beta".to_vec();
        let got = compute_merkle_root(&[l0.clone(), l1.clone()]);

        let h0 = sha256(&l0);
        let h1 = sha256(&l1);
        let mut hasher = Sha256::new();
        hasher.update(h0);
        hasher.update(h1);
        let want: [u8; 32] = hasher.finalize().into();
        assert_eq!(got, want, "two-leaf root must be SHA-256(H(l0) || H(l1))");
    }

    #[test]
    fn merkle_odd_count_duplicates_last() {
        // 3 leaves — layer 0 becomes [H(l0), H(l1), H(l2)]; odd
        // count → duplicate last → [H(l0), H(l1), H(l2), H(l2)];
        // pair-hash → [H(H(l0)||H(l1)), H(H(l2)||H(l2))]; pair-hash
        // → root.
        let l0 = b"alpha".to_vec();
        let l1 = b"beta".to_vec();
        let l2 = b"gamma".to_vec();
        let got = compute_merkle_root(&[l0.clone(), l1.clone(), l2.clone()]);

        let h0 = sha256(&l0);
        let h1 = sha256(&l1);
        let h2 = sha256(&l2);

        let pair01 = {
            let mut h = Sha256::new();
            h.update(h0);
            h.update(h1);
            let o: [u8; 32] = h.finalize().into();
            o
        };
        // CT-style duplicate-last: pair[H(l2), H(l2)].
        let pair22 = {
            let mut h = Sha256::new();
            h.update(h2);
            h.update(h2);
            let o: [u8; 32] = h.finalize().into();
            o
        };
        let root = {
            let mut h = Sha256::new();
            h.update(pair01);
            h.update(pair22);
            let o: [u8; 32] = h.finalize().into();
            o
        };
        assert_eq!(
            got, root,
            "odd-count layer must duplicate the last node (CT/Bitcoin convention)"
        );
    }

    #[test]
    fn merkle_deterministic_across_orderings_in_layer() {
        // Order MATTERS for Merkle — document this contract by
        // proving that swapping leaves produces a DIFFERENT root.
        // Implementations that "helpfully" sort the leaves would
        // make this test pass by accident; this test asserts the
        // opposite (no implicit sort).
        let l0 = b"alpha".to_vec();
        let l1 = b"beta".to_vec();

        let ordered = compute_merkle_root(&[l0.clone(), l1.clone()]);
        let swapped = compute_merkle_root(&[l1, l0]);

        assert_ne!(
            ordered, swapped,
            "Merkle root MUST depend on leaf order — implementations \
             that pre-sort would mask reordering bugs at the claim layer"
        );
    }

    #[test]
    fn canonical_bytes_locked_field_order() {
        let w = WholenessWitness {
            peer_id: "peer-xyz".into(),
            epoch_id: 42,
            merkle_root: [0xAB; 32],
            leaf_count: 7,
            // Unsorted on purpose — the canonicalization MUST sort.
            claim_namespaces: vec![
                "trust_grant".into(),
                "holding_claim".into(),
                "relay_capacity".into(),
            ],
            observed_at_unix_ms: 1_700_000_000_000,
            witness_version: 1,
            // These three live OUTSIDE the canonical bytes — set to
            // non-empty values to prove they don't appear in the
            // output.
            signature: "should-not-appear".into(),
            signature_ml_dsa_65: "also-should-not-appear".into(),
            pqc_key_id: "neither-this".into(),
        };

        let bytes = w.canonical_bytes().expect("canonical_bytes ok");
        let s = std::str::from_utf8(&bytes).expect("canonical bytes are utf8");

        // 1. Field order is exact — assert by reading the substrings
        //    in the order they must appear, with no intervening
        //    fields. We check that each key appears AFTER the previous.
        let positions = [
            "\"peer_id\"",
            "\"epoch_id\"",
            "\"merkle_root\"",
            "\"leaf_count\"",
            "\"claim_namespaces\"",
            "\"observed_at_unix_ms\"",
            "\"witness_version\"",
        ];
        let mut last = 0;
        for key in positions {
            let pos = s
                .find(key)
                .unwrap_or_else(|| panic!("missing canonical key {key}"));
            assert!(
                pos >= last,
                "canonical field order violated at key {key}: pos={pos} last={last}"
            );
            last = pos;
        }

        // 2. Signature fields are absent.
        assert!(
            !s.contains("\"signature\""),
            "signature field must NOT appear in canonical bytes"
        );
        assert!(
            !s.contains("\"signature_ml_dsa_65\""),
            "signature_ml_dsa_65 must NOT appear in canonical bytes"
        );
        assert!(
            !s.contains("\"pqc_key_id\""),
            "pqc_key_id must NOT appear in canonical bytes"
        );

        // 3. merkle_root is lowercase 64-char hex (0xAB * 32 = "ab" * 32).
        let expected_root_hex = "ab".repeat(32);
        assert!(
            s.contains(&format!("\"merkle_root\":\"{expected_root_hex}\"")),
            "merkle_root must be lowercase 64-char hex; got: {s}"
        );

        // 4. claim_namespaces is lex-sorted regardless of in-memory
        //    order. Expected sort: holding_claim, relay_capacity,
        //    trust_grant.
        let expected_namespaces =
            "\"claim_namespaces\":[\"holding_claim\",\"relay_capacity\",\"trust_grant\"]";
        assert!(
            s.contains(expected_namespaces),
            "claim_namespaces must be lex-sorted; got: {s}"
        );
    }

    #[test]
    fn compare_identical_witnesses() {
        let root = [0x11; 32];
        let a = witness(5, root);
        let b = witness(5, root);
        assert_eq!(compare_witnesses(&a, &b), WitnessDelta::Identical);
    }

    #[test]
    fn compare_epoch_ahead() {
        let a = witness(10, [0x11; 32]);
        let b = witness(7, [0x22; 32]); // different root — irrelevant when epoch differs
        assert_eq!(compare_witnesses(&a, &b), WitnessDelta::EpochAhead(3));
    }

    #[test]
    fn compare_epoch_behind() {
        let a = witness(2, [0x11; 32]);
        let b = witness(9, [0x11; 32]);
        assert_eq!(compare_witnesses(&a, &b), WitnessDelta::EpochBehind(7));
    }

    #[test]
    fn compare_divergent() {
        // Same epoch, different root → the reconciliation case.
        let a = witness(42, [0x11; 32]);
        let b = witness(42, [0x22; 32]);
        assert_eq!(compare_witnesses(&a, &b), WitnessDelta::Divergent);
    }
}
