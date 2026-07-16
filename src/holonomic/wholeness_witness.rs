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
//! ## Merkle construction (last-node duplication — NOT RFC 6962)
//!
//! [`compute_merkle_root`] is re-exported from the shared §19.1 owner
//! (`ciris-verify-core`); the algorithm is byte-exact:
//!
//! 1. **Lex-sort the leaves** by their canonical bytes (§19.1 RC11).
//!    The leaf order is NOT caller-controlled — the function sorts
//!    internally so two peers with the same leaf multiset always land
//!    on the same root regardless of in-memory order.
//! 2. If `leaves.is_empty()` → return `SHA-256(b"WW-v1-empty")`
//!    (well-known sentinel; documented because there is no natural
//!    Merkle root for the empty multiset).
//! 3. Hash each leaf: `layer = sorted.iter().map(SHA-256).collect()`
//!    (each leaf is already `canonical_bytes` of a signed claim at
//!    the claim layer — we apply ONE additional SHA-256 here so the
//!    leaf-hash domain is distinct from the inner-node domain).
//! 4. While `layer.len() > 1`:
//!    - If `layer.len()` is odd, duplicate the last node
//!      (`node = SHA-256(last ‖ last)`).
//!    - `new = layer.chunks(2).map(|p| SHA-256(p[0] || p[1])).collect()`
//!    - `layer = new`
//! 5. Return `layer[0]`.
//!
//! This deliberately does **NOT** use the RFC 6962 Certificate
//! Transparency construction: RFC 6962 does not duplicate the odd node
//! (it splits at the largest power of two below the leaf count) and uses
//! `0x00`/`0x01` domain prefixes. The odd-node duplication here is the
//! Bitcoin-merkle rule, whose CVE-2012-2459 malleability is not
//! exploitable in this setting — every witness root is mandatorily
//! hybrid-signed (no consumer trusts an unsigned root) and is verified
//! by full recomputation, never partial inclusion proofs. See the
//! `ciris-verify-core` `wholeness_witness` doc for the frozen rationale.
//!
//! §19.1 RC11 — leaves MUST be lex-sorted before Merkle construction,
//! and the sort is done INSIDE [`compute_merkle_root`] (not by the
//! caller). CIRISVerify's `holonomic::compute_merkle_root` sorts
//! and recomputes; an unsorted producer root would mismatch on the
//! wire. The previous v1 contract ("caller controls order") is
//! superseded — there is no legal alternative ordering. The contract
//! is now: same leaf multiset → same root, independent of order.
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

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// §19.1 WW Merkle root — CIRISEdge#359 F-4 re-export debt.
///
/// The construction (lexicographic leaves, `leaf = SHA-256(bytes)`,
/// `node = SHA-256(left ‖ right)`, odd-node duplication, `WW-v1-empty`
/// empty-tree sentinel) is genuinely identical to the shared §19.1
/// owner and is KAT-locked there, so edge re-exports it rather than
/// maintaining a byte-for-byte twin. See
/// [`ciris_verify_core::holonomic::wholeness_witness::compute_merkle_root`].
pub use ciris_verify_core::holonomic::wholeness_witness::compute_merkle_root;

/// Locked v1 domain-separation tag for [`EquivocationProof`] signed
/// bytes. This is a NEW CEG-shape claim (the `hard_case:*` namespace)
/// distinct from the witnesses it wraps — changing it is a coordinated
/// wire break.
pub const EQUIVOCATION_PROOF_DOMAIN: &[u8] = b"ciris-edge/equivocation-proof/v1";

/// §19.0 RC11 — 16-byte null-padded domain separator for the binary
/// [`WholenessWitness::canonical_preimage_bytes`] signing basis:
/// the 14 ASCII bytes `WW-PREIMAGE-v1` padded to 16 with two trailing
/// NULs. Wire-locked: changing it is a coordinated break paired with
/// `witness_version`.
pub const WITNESS_PREIMAGE_DOMAIN: &[u8; 16] = b"WW-PREIMAGE-v1\0\0";

/// §19.1 WW-2 — namespace prefix whose leaves are filtered out before
/// Merkle construction (deniable / anonymous-tier content).
pub const WW2_ANONYMOUS_NAMESPACE_PREFIX: &str = "anonymous";

/// §19.1 WW-2 — cohort scope whose leaves are filtered out before
/// Merkle construction (self-private content).
pub const WW2_SELF_COHORT_SCOPE: &str = "self";

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

    /// §19.0 RC11 binary signing preimage — the bytes the hybrid
    /// signature pair is actually computed over.
    ///
    /// This SUPERSEDES [`Self::canonical_bytes`] (compact-JSON) as the
    /// signed basis. The JSON forms ([`Self::canonical_value`] /
    /// [`Self::canonical_bytes`]) are retained for debugging /
    /// human-inspection, but per §19 the wire signature binds the
    /// length-prefixed binary preimage — NOT JCS, NOT JSON.
    ///
    /// Layout (`||` = concatenation; every variable field is preceded
    /// by a big-endian `u32` byte-length prefix; scalars are
    /// big-endian; the leading 16 bytes are [`WITNESS_PREIMAGE_DOMAIN`]):
    ///
    /// ```text
    ///   WITNESS_PREIMAGE_DOMAIN                      (16 bytes)
    ///   u32_be(peer_id.len)            || peer_id    (utf-8)
    ///   u64_be(epoch_id)
    ///   merkle_root                                  (32 raw bytes)
    ///   u32_be(leaf_count)
    ///   u32_be(claim_namespaces.len as count)
    ///     for each ns (lex-sorted):
    ///       u32_be(ns.len) || ns                     (utf-8)
    ///   u64_be(observed_at_unix_ms)
    ///   u16_be(witness_version)
    /// ```
    ///
    /// `claim_namespaces` is lex-sorted before encoding so in-memory
    /// order does not perturb the preimage. Length prefixes make the
    /// encoding injective: no two distinct witnesses share a preimage.
    /// The signature fields are EXCLUDED (they sign this, from outside).
    ///
    /// §19 re-export debt (CIRISEdge#359 F-4): the §19.1 signed preimage
    /// framing is owned by
    /// [`ciris_verify_core::holonomic::wholeness_witness::WholenessWitness::canonical_preimage`]
    /// (byte-frozen there by the §19.6 vectors). Edge's shape carries
    /// edge-only fields (the hybrid-signature trio, serde derives) so it
    /// cannot re-export verify's type wholesale; it delegates the shared
    /// preimage byte-for-byte. [`WITNESS_PREIMAGE_DOMAIN`] is
    /// edge-authored and verify reproduces it, so the bytes are unchanged.
    #[must_use]
    pub fn canonical_preimage_bytes(&self) -> Vec<u8> {
        ciris_verify_core::holonomic::wholeness_witness::WholenessWitness {
            peer_id: self.peer_id.clone(),
            epoch_id: self.epoch_id,
            claim_namespaces: self.claim_namespaces.clone(),
            merkle_root: self.merkle_root,
            leaf_count: self.leaf_count,
            observed_at_unix_ms: self.observed_at_unix_ms,
            witness_version: self.witness_version,
        }
        .canonical_preimage()
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

/// §19.1 WW-2 — filter deniable / self-private leaves BEFORE Merkle
/// construction.
///
/// A leaf whose claim namespace begins with
/// [`WW2_ANONYMOUS_NAMESPACE_PREFIX`] (`anonymous`) or whose cohort
/// scope equals [`WW2_SELF_COHORT_SCOPE`] (`self`) MUST be dropped
/// before its bytes feed [`compute_merkle_root`]. Re-attributing
/// deniable or self-private content to a stable `peer_id` (by binding
/// it into a published, signed witness root) is the exact failure WW-2
/// prevents: a witness root is a durable, non-repudiable attestation,
/// and anonymous-tier / `cohort_scope: self` rows are precisely the
/// content that must NOT become durably attributable.
///
/// `claim_namespaces` on the witness MUST NOT name `anonymous` or
/// `self` — those rows are filtered here, so naming them in the
/// witness's namespace set would advertise coverage the root does not
/// actually contain.
///
/// The three slices are parallel: `namespaces_per_leaf[i]` and
/// `cohort_scopes_per_leaf[i]` describe `leaves[i]`. A leaf with no
/// parallel metadata (index beyond either slice) is conservatively
/// DROPPED — absent provenance is treated as not-attributable rather
/// than silently published.
///
/// Returns the surviving leaves as owned `Vec<u8>` in their input
/// order (the caller passes the result straight to
/// [`compute_merkle_root`], which lex-sorts internally).
#[must_use]
pub fn filter_witness_leaves<L: AsRef<[u8]>>(
    leaves: &[L],
    namespaces_per_leaf: &[&str],
    cohort_scopes_per_leaf: &[&str],
) -> Vec<Vec<u8>> {
    leaves
        .iter()
        .enumerate()
        .filter_map(|(i, leaf)| {
            let (Some(ns), Some(scope)) =
                (namespaces_per_leaf.get(i), cohort_scopes_per_leaf.get(i))
            else {
                // Missing provenance ⇒ not attributable ⇒ drop.
                return None;
            };
            if ns.starts_with(WW2_ANONYMOUS_NAMESPACE_PREFIX) || *scope == WW2_SELF_COHORT_SCOPE {
                return None;
            }
            Some(leaf.as_ref().to_vec())
        })
        .collect()
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
///
/// **PRECONDITION**: BOTH `ours` and `theirs` must have been
/// previously verified via [`verify_witness_hybrid`] returning
/// [`WitnessVerification::Valid`]. This function does NOT re-verify
/// signatures; it computes the structural delta only. An unverified
/// witness fed here lets a forged root drive reconciliation —
/// per the §10.1.5.1.1 store-path discipline, verify FIRST.
///
/// If you have UNVERIFIED witnesses, gate the call:
///
/// ```text
/// let v = verify_witness_hybrid(&theirs, verify_ed, verify_pq, &ed_pub, &mldsa_pub);
/// if v != WitnessVerification::Valid { reject }
/// let delta = compare_witnesses(&ours, &theirs);
/// ```
///
/// For rollback protection on top of comparison, combine with
/// [`AntiRollbackState::accept_if_monotonic`] BEFORE acting on an
/// [`WitnessDelta::EpochBehind`] result. For non-repudiable Byzantine
/// detection on a [`WitnessDelta::Divergent`] result, hand both
/// already-verified witnesses to [`detect_equivocation`].
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

/// Verification result for an incoming [`WholenessWitness`]. Reject at
/// ingest before persistence; never store-then-quarantine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessVerification {
    /// Both hybrid halves verified against the signer's pubkey set.
    Valid,
    /// ML-DSA-65 half missing or empty.
    PqcMissing,
    /// Ed25519 half failed verification.
    ClassicalSignatureInvalid,
    /// ML-DSA-65 half failed verification.
    PqcSignatureInvalid,
    /// Both classical and PQ halves failed.
    BothSignaturesInvalid,
    /// Canonical-bytes serialization failed (malformed witness).
    CanonicalSerializationFailed,
}

/// A non-repudiable equivocation proof: two validly-signed witnesses
/// from the same peer at the same epoch with different Merkle roots.
/// Both signatures verify; the peer signed contradictory state. This
/// proves the peer is Byzantine.
///
/// This is a NEW CEG-shape claim (the `hard_case:*` namespace) — it
/// carries its own [`Self::canonical_bytes`] / [`Self::canonical_value`]
/// over the locked field order
/// `(peer_id, epoch_id, witness_a_canonical, witness_b_canonical,
/// observed_at_unix_ms)`, where each witness canonicalizes via its
/// existing [`WholenessWitness::canonical_bytes`] path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationProof {
    /// Federation `key_id` of the equivocating peer.
    pub peer_id: String,
    /// The epoch at which the peer signed contradictory roots.
    pub epoch_id: u64,
    /// One of the two contradictory witnesses.
    pub witness_a: WholenessWitness,
    /// The other contradictory witness (different `merkle_root`).
    pub witness_b: WholenessWitness,
    /// Unix milliseconds when the equivocation was first observed.
    pub observed_at_unix_ms: u64,
}

impl EquivocationProof {
    /// JSON projection of the proof in the locked v1 field order:
    /// `(peer_id, epoch_id, witness_a_canonical, witness_b_canonical,
    /// observed_at_unix_ms)`. Each witness is projected via its own
    /// [`WholenessWitness::canonical_value`] path.
    ///
    /// Returned as a [`serde_json::Value::Array`] of `[name, value]`
    /// two-element arrays so field order is locked in the JSON shape
    /// independent of `serde_json::Map` ordering rules — matching the
    /// discipline `swarm_rarity` uses for its signed shapes.
    #[must_use]
    pub fn canonical_value(&self) -> serde_json::Value {
        serde_json::Value::Array(vec![
            serde_json::json!(["peer_id", self.peer_id]),
            serde_json::json!(["epoch_id", self.epoch_id]),
            serde_json::json!(["witness_a_canonical", self.witness_a.canonical_value()]),
            serde_json::json!(["witness_b_canonical", self.witness_b.canonical_value()]),
            serde_json::json!(["observed_at_unix_ms", self.observed_at_unix_ms]),
        ])
    }

    /// The exact bytes a verifier checks for the proof.
    ///
    /// Layout (length prefixes are big-endian `u64`):
    /// `DOMAIN ‖ u64(peer_id.len()) ‖ peer_id
    ///        ‖ u64_be(epoch_id)
    ///        ‖ u64(witness_a_canonical.len()) ‖ witness_a_canonical
    ///        ‖ u64(witness_b_canonical.len()) ‖ witness_b_canonical
    ///        ‖ u64_be(observed_at_unix_ms)`
    ///
    /// where `witness_*_canonical` is the bytes from each witness's
    /// [`WholenessWitness::canonical_bytes`]. `DOMAIN` is
    /// [`EQUIVOCATION_PROOF_DOMAIN`]. Length prefixes make the encoding
    /// injective so the proof binds to exactly one
    /// `(peer_id, epoch_id, witness_a, witness_b)` tuple.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonError> {
        let a = self.witness_a.canonical_bytes()?;
        let b = self.witness_b.canonical_bytes()?;
        let mut out = Vec::with_capacity(
            EQUIVOCATION_PROOF_DOMAIN.len()
                + 8
                + self.peer_id.len()
                + 8
                + 8
                + a.len()
                + 8
                + b.len()
                + 8,
        );
        out.extend_from_slice(EQUIVOCATION_PROOF_DOMAIN);
        out.extend_from_slice(&(self.peer_id.len() as u64).to_be_bytes());
        out.extend_from_slice(self.peer_id.as_bytes());
        out.extend_from_slice(&self.epoch_id.to_be_bytes());
        out.extend_from_slice(&(a.len() as u64).to_be_bytes());
        out.extend_from_slice(&a);
        out.extend_from_slice(&(b.len() as u64).to_be_bytes());
        out.extend_from_slice(&b);
        out.extend_from_slice(&self.observed_at_unix_ms.to_be_bytes());
        Ok(out)
    }
}

/// Per-peer rollback-protection state. Tracks the highest epoch ever
/// accepted from each peer; a witness with `epoch_id ≤ tracked_max`
/// is a rollback attempt (eclipse via stale roots) and is rejected.
///
/// Apply this BEFORE using a [`WitnessDelta::EpochBehind`] result as
/// input to anything — `EpochBehind` with no anti-rollback lets an
/// adversary replay an old, validly-signed witness to drag a peer's
/// view backward.
#[derive(Debug, Clone, Default)]
pub struct AntiRollbackState {
    /// peer_id → highest epoch_id ever accepted from that peer.
    highest_seen: std::collections::HashMap<String, u64>,
}

impl AntiRollbackState {
    /// A fresh state with no peers tracked.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept the witness if and only if its `epoch_id` is strictly
    /// greater than the highest previously accepted from the same
    /// peer. Returns `true` if accepted (and updates state); `false`
    /// to reject as a rollback attempt.
    ///
    /// The first witness ever seen from a peer is always accepted
    /// (no prior bound). Equal-epoch is rejected: a second witness at
    /// the same epoch is either a duplicate or the divergent half of
    /// an equivocation, neither of which advances the per-peer head.
    pub fn accept_if_monotonic(&mut self, peer_id: &str, epoch_id: u64) -> bool {
        match self.highest_seen.get(peer_id) {
            Some(&prev) if epoch_id <= prev => false,
            _ => {
                self.highest_seen.insert(peer_id.to_string(), epoch_id);
                true
            }
        }
    }

    /// The highest epoch ever accepted from `peer_id`, or `None` if no
    /// witness has been accepted from that peer yet.
    #[must_use]
    pub fn highest_seen(&self, peer_id: &str) -> Option<u64> {
        self.highest_seen.get(peer_id).copied()
    }
}

/// Verify a [`WholenessWitness`]'s hybrid PQC signature pair. Returns
/// [`WitnessVerification::Valid`] ONLY if BOTH halves verify and the
/// canonical bytes serialize cleanly. There is NO partial-verification
/// path — the §10.1.5.1.1 store-path discipline is binary: reject at
/// ingest, before persistence, never store-then-quarantine.
///
/// # Caller-controlled verification surface
///
/// `verify_ed25519` and `verify_ml_dsa_65` are caller-supplied
/// closures with the shape `(message, signature, pubkey) -> bool`,
/// each returning `true` on a good signature. This callback design is
/// deliberate (over a direct call into the in-tree signer): it keeps
/// the verification surface caller-controlled, lets the caller resolve
/// pubkeys from the federation directory itself, and avoids the
/// "verified: bool in-band" antipattern (a verified flag riding on the
/// struct) that the sibling F-5 work addresses. This module does NOT
/// do directory lookup — `ed25519_pubkey` and `ml_dsa_65_pubkey` are
/// the signer's already-resolved public keys.
///
/// # Signed basis — §19.0 BOUND-hybrid
///
/// The preimage is [`WholenessWitness::canonical_preimage_bytes`] (the
/// binary, length-prefixed, domain-separated §19 basis — NOT JSON, NOT
/// JCS). The two halves are NOT independent:
/// - `sig_ed25519` verifies against `preimage`
/// - `sig_ml_dsa_65` verifies against `preimage || sig_ed25519_bytes`
///   (the DECODED classical signature is appended to the message the
///   PQ half signs)
///
/// This binds the PQ half to the exact classical signature, so an
/// adversary who strips/forges one half cannot reuse the other. The
/// `signature` / `signature_ml_dsa_65` fields are base64-standard; a
/// half that does not base64-decode is an invalid half (never a silent
/// pass). PQC-empty is reported distinctly as
/// [`WitnessVerification::PqcMissing`]. Because the PQ message depends
/// on the decoded classical signature, a classical half that fails to
/// base64-decode forces the PQ check to fail too (there is no valid
/// bound message), which surfaces as
/// [`WitnessVerification::BothSignaturesInvalid`].
pub fn verify_witness_hybrid(
    witness: &WholenessWitness,
    verify_ed25519: impl Fn(&[u8], &[u8], &[u8]) -> bool,
    verify_ml_dsa_65: impl Fn(&[u8], &[u8], &[u8]) -> bool,
    ed25519_pubkey: &[u8],
    ml_dsa_65_pubkey: &[u8],
) -> WitnessVerification {
    // PQC-missing is checked FIRST: an empty ML-DSA-65 half is the
    // forge-later surface this hardening closes, and it must be
    // distinguishable from a present-but-wrong half.
    if witness.signature_ml_dsa_65.is_empty() {
        return WitnessVerification::PqcMissing;
    }

    // §19 binary preimage — supersedes the compact-JSON basis.
    let preimage = witness.canonical_preimage_bytes();

    let b64 = base64::engine::general_purpose::STANDARD;
    // Decode the classical half first — its bytes are part of the PQ
    // message under the bound scheme.
    let ed_sig = b64.decode(&witness.signature).ok();
    let ed_ok = match &ed_sig {
        Some(sig) => verify_ed25519(&preimage, sig, ed25519_pubkey),
        None => false,
    };

    // Bound message: preimage || classical-signature-bytes. If the
    // classical half didn't decode there is no defined bound message,
    // so the PQ half cannot verify.
    let pq_ok = match (&ed_sig, b64.decode(&witness.signature_ml_dsa_65)) {
        (Some(ed_sig), Ok(pq_sig)) => {
            let mut bound = Vec::with_capacity(preimage.len() + ed_sig.len());
            bound.extend_from_slice(&preimage);
            bound.extend_from_slice(ed_sig);
            verify_ml_dsa_65(&bound, &pq_sig, ml_dsa_65_pubkey)
        }
        _ => false,
    };

    match (ed_ok, pq_ok) {
        (true, true) => WitnessVerification::Valid,
        (false, true) => WitnessVerification::ClassicalSignatureInvalid,
        (true, false) => WitnessVerification::PqcSignatureInvalid,
        (false, false) => WitnessVerification::BothSignaturesInvalid,
    }
}

/// Compare two ALREADY-VERIFIED witnesses from the same peer for
/// non-repudiable equivocation.
///
/// **PRECONDITION**: BOTH `ours` and `theirs` must have already
/// returned [`WitnessVerification::Valid`] from [`verify_witness_hybrid`].
/// This function does NOT re-verify signatures — two unverified
/// witnesses are not a proof of anything.
///
/// Returns `Some(EquivocationProof)` if and only if the two witnesses
/// share the same `(peer_id, epoch_id)` but carry different
/// `merkle_root`s — the peer signed contradictory state at one epoch,
/// which is non-repudiable Byzantine behavior. Otherwise `None`
/// (same root = agreement; different epoch = not equivocation;
/// different peer = out of scope).
///
/// `observed_at_unix_ms` stamps when the equivocation was first
/// observed (caller-supplied so the proof is reproducible).
#[must_use]
pub fn detect_equivocation(
    ours: &WholenessWitness,
    theirs: &WholenessWitness,
    observed_at_unix_ms: u64,
) -> Option<EquivocationProof> {
    if ours.peer_id != theirs.peer_id {
        return None;
    }
    if ours.epoch_id != theirs.epoch_id {
        return None;
    }
    if ours.merkle_root == theirs.merkle_root {
        return None;
    }
    Some(EquivocationProof {
        peer_id: ours.peer_id.clone(),
        epoch_id: ours.epoch_id,
        witness_a: ours.clone(),
        witness_b: theirs.clone(),
        observed_at_unix_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn merkle_empty_leaves_wire_locked_via_shared_owner() {
        // CIRISEdge#359 F-4: the algorithmic KATs (single/two/odd/order-
        // independence) are OWNED by ciris-verify-core, whose
        // wholeness_witness tests pin them; edge no longer duplicates
        // them. This one cross-crate anchor guards the §19.1 re-export
        // against a verify-side regression: the shared owner MUST still
        // produce edge's wire-locked empty-sentinel root
        // (`sha256("WW-v1-empty")`; recompute with
        // `printf 'WW-v1-empty' | sha256sum`).
        let got = compute_merkle_root(&[]);
        let want: [u8; 32] = [
            0x22, 0x80, 0xd2, 0x7f, 0x23, 0x21, 0x00, 0x36, 0x7e, 0x86, 0x21, 0x1b, 0x53, 0x49,
            0xfe, 0x0d, 0x6f, 0xba, 0xee, 0x98, 0xe4, 0xc2, 0xb4, 0x89, 0xa8, 0x60, 0x08, 0x04,
            0x95, 0x63, 0x46, 0x4f,
        ];
        assert_eq!(got, want, "empty sentinel root is wire-locked at v1");
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

    /// A witness signed with simple stand-in halves so verification
    /// is testable without pulling the federation signer. The `signature`
    /// fields here are base64 placeholders matched by the test closures.
    fn signed_witness(epoch_id: u64, root: [u8; 32], ed: &str, pq: &str) -> WholenessWitness {
        WholenessWitness {
            peer_id: "peer-a".into(),
            epoch_id,
            merkle_root: root,
            leaf_count: 0,
            claim_namespaces: vec!["holding_claim".into()],
            observed_at_unix_ms: 1_700_000_000_000,
            witness_version: 1,
            signature: base64::engine::general_purpose::STANDARD.encode(ed),
            signature_ml_dsa_65: base64::engine::general_purpose::STANDARD.encode(pq),
            pqc_key_id: "peer-a-pqc".into(),
        }
    }

    const ED_PUB: &[u8] = b"ed-pubkey";
    const PQ_PUB: &[u8] = b"pq-pubkey";

    /// An Ed25519 verifier stub: good iff the decoded sig is `b"ed-ok"`
    /// and the pubkey is [`ED_PUB`]. Message is consulted for binding.
    fn verify_ed_stub(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
        !msg.is_empty() && sig == b"ed-ok" && pubkey == ED_PUB
    }

    /// A PQ verifier stub asserting the §19 BOUND scheme: the PQ
    /// message MUST be `preimage || classical_sig_bytes`, so it ends
    /// with whichever classical signature was present on the witness
    /// (`b"ed-ok"` for a good classical half, `b"ed-WRONG"` for a
    /// present-but-invalid one). A bare `preimage` (the INDEPENDENT
    /// scheme) ends with the encoded `witness_version` u16 (`0,1`), not
    /// a classical sig, so this stub rejects it — proving the verifier
    /// uses the bound message. The PQ half's own validity is `sig ==
    /// b"pq-ok"`, independent of whether the appended classical sig is
    /// itself valid (real ML-DSA verifies its own sig over the given
    /// bytes; it does not re-judge the classical half).
    fn verify_pq_stub(msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
        let bound = msg.ends_with(b"ed-ok") || msg.ends_with(b"ed-WRONG");
        bound && sig == b"pq-ok" && pubkey == PQ_PUB
    }

    #[test]
    fn verify_witness_hybrid_valid_returns_valid() {
        let w = signed_witness(5, [0x11; 32], "ed-ok", "pq-ok");
        assert_eq!(
            verify_witness_hybrid(&w, verify_ed_stub, verify_pq_stub, ED_PUB, PQ_PUB),
            WitnessVerification::Valid
        );
    }

    #[test]
    fn verify_witness_hybrid_missing_pqc_returns_pqc_missing() {
        let mut w = signed_witness(5, [0x11; 32], "ed-ok", "pq-ok");
        w.signature_ml_dsa_65 = String::new();
        assert_eq!(
            verify_witness_hybrid(&w, verify_ed_stub, verify_pq_stub, ED_PUB, PQ_PUB),
            WitnessVerification::PqcMissing
        );
    }

    #[test]
    fn verify_witness_hybrid_invalid_classical_returns_classical_invalid() {
        let w = signed_witness(5, [0x11; 32], "ed-WRONG", "pq-ok");
        assert_eq!(
            verify_witness_hybrid(&w, verify_ed_stub, verify_pq_stub, ED_PUB, PQ_PUB),
            WitnessVerification::ClassicalSignatureInvalid
        );
    }

    #[test]
    fn verify_witness_hybrid_invalid_pqc_returns_pqc_invalid() {
        let w = signed_witness(5, [0x11; 32], "ed-ok", "pq-WRONG");
        assert_eq!(
            verify_witness_hybrid(&w, verify_ed_stub, verify_pq_stub, ED_PUB, PQ_PUB),
            WitnessVerification::PqcSignatureInvalid
        );
    }

    #[test]
    fn verify_witness_hybrid_both_invalid_returns_both_invalid() {
        let w = signed_witness(5, [0x11; 32], "ed-WRONG", "pq-WRONG");
        assert_eq!(
            verify_witness_hybrid(&w, verify_ed_stub, verify_pq_stub, ED_PUB, PQ_PUB),
            WitnessVerification::BothSignaturesInvalid
        );
    }

    #[test]
    fn detect_equivocation_returns_some_for_same_epoch_diff_root() {
        let a = witness(42, [0x11; 32]);
        let b = witness(42, [0x22; 32]);
        let proof = detect_equivocation(&a, &b, 1_700_000_000_999);
        let proof = proof.expect("divergent roots at same (peer,epoch) are equivocation");
        assert_eq!(proof.peer_id, "peer-a");
        assert_eq!(proof.epoch_id, 42);
        assert_eq!(proof.witness_a.merkle_root, [0x11; 32]);
        assert_eq!(proof.witness_b.merkle_root, [0x22; 32]);
        assert_eq!(proof.observed_at_unix_ms, 1_700_000_000_999);
    }

    #[test]
    fn detect_equivocation_returns_none_for_identical_witnesses() {
        let root = [0x11; 32];
        let a = witness(42, root);
        let b = witness(42, root);
        assert!(
            detect_equivocation(&a, &b, 0).is_none(),
            "same root at same epoch is agreement, not equivocation"
        );
    }

    #[test]
    fn detect_equivocation_returns_none_for_different_epochs() {
        let a = witness(42, [0x11; 32]);
        let b = witness(43, [0x22; 32]);
        assert!(
            detect_equivocation(&a, &b, 0).is_none(),
            "different epochs cannot be equivocation"
        );
    }

    #[test]
    fn equivocation_proof_canonical_bytes_locked_field_order() {
        let a = witness(42, [0x11; 32]);
        let b = witness(42, [0x22; 32]);
        let proof = detect_equivocation(&a, &b, 1_700_000_000_999).expect("equivocation detected");

        // canonical_value field order is locked as a Value::Array of
        // [name, value] tuples, matching the swarm_rarity discipline.
        let v = proof.canonical_value();
        let arr = v.as_array().expect("canonical_value must be an array");
        assert_eq!(arr.len(), 5, "exactly 5 fields in v1");
        assert_eq!(arr[0][0], "peer_id");
        assert_eq!(arr[1][0], "epoch_id");
        assert_eq!(arr[2][0], "witness_a_canonical");
        assert_eq!(arr[3][0], "witness_b_canonical");
        assert_eq!(arr[4][0], "observed_at_unix_ms");

        // canonical_bytes starts with the per-shape domain tag and is
        // injective (length-prefixed), so a different observed_at or a
        // swapped witness pair produces different bytes.
        let bytes = proof.canonical_bytes().expect("canonical_bytes ok");
        assert!(bytes.starts_with(EQUIVOCATION_PROOF_DOMAIN));

        let mut later = proof.clone();
        later.observed_at_unix_ms += 1;
        assert_ne!(
            later.canonical_bytes().unwrap(),
            bytes,
            "observed_at must bind into the canonical bytes"
        );

        // Swapping the witness halves changes the bytes (a≠b roots).
        let swapped = detect_equivocation(&b, &a, 1_700_000_000_999).expect("equivocation");
        assert_ne!(
            swapped.canonical_bytes().unwrap(),
            bytes,
            "witness order binds into the canonical bytes"
        );
    }

    #[test]
    fn anti_rollback_accepts_monotonic_increase() {
        let mut state = AntiRollbackState::new();
        assert!(state.accept_if_monotonic("peer-a", 1));
        assert!(state.accept_if_monotonic("peer-a", 2));
        assert!(state.accept_if_monotonic("peer-a", 100));
        assert_eq!(state.highest_seen("peer-a"), Some(100));
        // A different peer is tracked independently.
        assert!(state.accept_if_monotonic("peer-b", 1));
        assert_eq!(state.highest_seen("peer-b"), Some(1));
        assert_eq!(state.highest_seen("peer-c"), None);
    }

    #[test]
    fn anti_rollback_rejects_equal_epoch() {
        let mut state = AntiRollbackState::new();
        assert!(state.accept_if_monotonic("peer-a", 5));
        assert!(
            !state.accept_if_monotonic("peer-a", 5),
            "re-presenting the same epoch must be rejected"
        );
        // State head is unchanged after a rejection.
        assert_eq!(state.highest_seen("peer-a"), Some(5));
    }

    #[test]
    fn anti_rollback_rejects_lower_epoch() {
        let mut state = AntiRollbackState::new();
        assert!(state.accept_if_monotonic("peer-a", 10));
        assert!(
            !state.accept_if_monotonic("peer-a", 3),
            "a stale (lower) epoch is a rollback attempt and must be rejected"
        );
        assert_eq!(state.highest_seen("peer-a"), Some(10));
    }

    // ---- §19.1 WW-2 leaf filter ----

    #[test]
    fn ww2_filter_drops_anonymous_and_self_leaves() {
        let leaves: Vec<&[u8]> = vec![b"keep-a", b"drop-anon", b"drop-self", b"keep-b"];
        let namespaces = [
            "holding_claim",
            "anonymous:rumor",
            "trust_grant",
            "relay_capacity",
        ];
        let scopes = ["community", "community", "self", "federation"];
        let kept = filter_witness_leaves(&leaves, &namespaces, &scopes);
        assert_eq!(kept, vec![b"keep-a".to_vec(), b"keep-b".to_vec()]);
    }

    #[test]
    fn ww2_filter_drops_anonymous_prefix_namespaces() {
        // Any namespace STARTING with "anonymous" is filtered.
        let leaves: Vec<&[u8]> = vec![b"x", b"y"];
        let namespaces = ["anonymous", "anonymous-tier:deniable"];
        let scopes = ["community", "community"];
        assert!(filter_witness_leaves(&leaves, &namespaces, &scopes).is_empty());
    }

    #[test]
    fn ww2_filter_drops_leaf_with_missing_provenance() {
        // A leaf whose parallel metadata is absent is conservatively
        // dropped — absent provenance is not-attributable.
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let namespaces = ["holding_claim"]; // only describes leaf 0
        let scopes = ["community"];
        let kept = filter_witness_leaves(&leaves, &namespaces, &scopes);
        assert_eq!(kept, vec![b"a".to_vec()]);
    }

    // ---- §19.0 binary preimage ----

    #[test]
    fn canonical_preimage_starts_with_domain_and_is_order_independent() {
        let w = WholenessWitness {
            peer_id: "peer-a".into(),
            epoch_id: 7,
            merkle_root: [0xab; 32],
            leaf_count: 3,
            // Deliberately unsorted — the preimage sorts internally.
            claim_namespaces: vec!["trust_grant".into(), "holding_claim".into()],
            observed_at_unix_ms: 1_700_000_000_000,
            witness_version: 1,
            signature: "ignored".into(),
            signature_ml_dsa_65: "ignored".into(),
            pqc_key_id: "ignored".into(),
        };
        let pre = w.canonical_preimage_bytes();
        assert!(pre.starts_with(WITNESS_PREIMAGE_DOMAIN));

        // Reordering claim_namespaces does not change the preimage.
        let mut w2 = w.clone();
        w2.claim_namespaces = vec!["holding_claim".into(), "trust_grant".into()];
        assert_eq!(pre, w2.canonical_preimage_bytes());

        // The signature fields are EXCLUDED from the preimage.
        let mut w3 = w.clone();
        w3.signature = "totally-different".into();
        w3.signature_ml_dsa_65 = "also-different".into();
        assert_eq!(pre, w3.canonical_preimage_bytes());
    }

    #[test]
    fn canonical_preimage_is_injective_over_fields() {
        let base = WholenessWitness {
            peer_id: "peer-a".into(),
            epoch_id: 7,
            merkle_root: [0xab; 32],
            leaf_count: 3,
            claim_namespaces: vec!["holding_claim".into()],
            observed_at_unix_ms: 1_700_000_000_000,
            witness_version: 1,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        };
        let pre = base.canonical_preimage_bytes();

        let mut diff_epoch = base.clone();
        diff_epoch.epoch_id = 8;
        assert_ne!(pre, diff_epoch.canonical_preimage_bytes());

        let mut diff_root = base.clone();
        diff_root.merkle_root = [0xac; 32];
        assert_ne!(pre, diff_root.canonical_preimage_bytes());

        let mut diff_version = base.clone();
        diff_version.witness_version = 2;
        assert_ne!(pre, diff_version.canonical_preimage_bytes());
    }

    #[test]
    fn witness_preimage_domain_is_16_bytes() {
        assert_eq!(WITNESS_PREIMAGE_DOMAIN.len(), 16);
        assert_eq!(&WITNESS_PREIMAGE_DOMAIN[..14], b"WW-PREIMAGE-v1");
        assert_eq!(&WITNESS_PREIMAGE_DOMAIN[14..], b"\0\0");
    }
}
