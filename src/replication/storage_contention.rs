//! CC 6.1.5.2 §Q `storage-contention` — the 4th replication axis
//! (CIRISConstitution CC 0.9). This module carries the two PIN-NORMATIVE
//! signed wire shapes the axis introduces:
//!
//!   * [`StorageBudgetV1`] — an owner's per-`cohort_scope` allotment
//!     (`budget_bytes` ceiling + `pin_reserve_bytes` floor) and the
//!     `pinned_class` set it elects to spend budget on (B3).
//!   * [`CorpusWantV1`] — a peer's want/have advertisement: exactly what
//!     corpus it will accept and its per-object `size_cap` (B4). A
//!     producer pulls only against it — wanted-then-pulled, never
//!     unsolicited-pushed.
//!
//! # These are CC 6.1 substrate shapes, NOT CC 2.1 attestations
//!
//! Per CC 6.1.5.2, both are substrate-framing objects — no 1+4 change.
//! Their signing preimage uses the **CC 6.1.3 binary discipline**
//! (length-prefixed, big-endian, 16-byte domain-separated — **NOT**
//! CC 2.6.1 JCS) and a **bound-hybrid** signature: `Ed25519(preimage)`
//! plus `ML-DSA-65(preimage ‖ ed25519_sig)`. A verifier MUST reject a
//! shape lacking a valid ML-DSA-65 half at ingest and before persistence
//! (the CC 5.3.2.4.3.1 store-path rule — both are federation-tier). This
//! mirrors edge's existing CC 6.1 hybrid shape `SignedRelayCapacity`
//! (`src/transport/realtime_av_alm/capacity.rs`); §Q lives in edge
//! because all replication logic lives in edge (CIRISEdge#257).
//!
//! # Edge-side verify-at-ingest
//!
//! Unlike the 13 replication `EnvelopeKind` directory rows (which delegate
//! signature verification to persist's `put_*` admit path), these shapes
//! have **no persist admit path** — edge verifies them itself via
//! [`StorageBudgetV1::verify`] / [`CorpusWantV1::verify`] before acting on
//! them (CIRISEdge#258 Cut 1).

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_persist::fountain::FountainHeldMeta;
use serde::{Deserialize, Serialize};

/// The `self` / `family` `cohort_scope` values that MUST NOT appear in a
/// signed / federated §Q shape (CC 5.2 suppression — B3/B4). A budget or
/// want naming these would leak the existence of structurally-invisible
/// content; those budgets are enforced locally only.
const SUPPRESSED_SCOPES: [&str; 2] = ["self", "family"];

/// 16-byte domain separator for [`StorageBudgetV1`] (exact).
const STORAGE_BUDGET_DOMAIN: &[u8; 16] = b"CIRIS-STG-BUDGET";
/// 16-byte domain separator for [`CorpusWantV1`] (exact; one trailing NUL).
const CORPUS_WANT_DOMAIN: &[u8; 16] = b"CIRIS-WANT-HAVE\0";

/// Wire version pinned into both preimages (`version = 1`).
const SHAPE_VERSION: u32 = 1;

/// Errors validating / verifying a §Q shape.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum StorageContentionError {
    /// `pin_reserve_bytes > budget_bytes` for some scope (B3 floor ≤ ceiling).
    #[error("pin_reserve_bytes ({reserve}) exceeds budget_bytes ({budget}) for scope {scope:?}")]
    ReserveExceedsBudget {
        scope: String,
        reserve: u64,
        budget: u64,
    },
    /// A `self` / `family` scope appeared in a signed shape (CC 5.2 / B3).
    #[error("suppressed cohort_scope {0:?} MUST NOT appear in a signed §Q shape (CC 5.2)")]
    SuppressedScope(String),
    /// A list that must be lexicographically sorted + deduplicated was not
    /// (the PIN-NORMATIVE canonical-order rule).
    #[error("{0} is not lexicographically sorted + deduplicated (PIN-NORMATIVE)")]
    NotSortedDedup(&'static str),
    /// The Ed25519 or ML-DSA-65 signature half did not verify.
    #[error("bound-hybrid signature did not verify ({0})")]
    SignatureMismatch(&'static str),
    /// A base64 signature field did not decode.
    #[error("signature decode: {0}")]
    SignatureDecode(String),
    /// The verifier was not supplied the ML-DSA-65 pubkey required for the
    /// hybrid check (a classical-only verify is REJECTED — CC 6.1.3).
    #[error("hybrid verify requires the ML-DSA-65 pubkey; classical-only is rejected")]
    MissingPqcKey,
}

/// One `cohort_scope`'s allotment inside a [`StorageBudgetV1`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeBudget {
    /// The `cohort_scope` this allotment binds (`community` | `affiliations`
    /// | `species` | …). NEVER `self` / `family` (B3 suppression).
    pub cohort_scope: String,
    /// Total byte ceiling for this scope.
    pub budget_bytes: u64,
    /// Byte floor reserved for pinned corpus (MUST be ≤ `budget_bytes`).
    pub pin_reserve_bytes: u64,
}

/// The owner's per-`cohort_scope` storage allotment (CC 6.1.5.2 §Q B3),
/// bound-hybrid signed. A higher `revision` from the same `node_id`
/// supersedes; a lower one MUST be rejected (anti-rollback).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageBudgetV1 {
    /// The owner node this budget binds.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// Monotonic revision; a higher value from the same `node_id`
    /// supersedes (anti-rollback, B3).
    pub revision: u64,
    /// Per-`cohort_scope` allotments. MUST be sorted by `cohort_scope`
    /// (lexicographic over UTF-8 bytes) and deduplicated.
    pub scopes: Vec<ScopeBudget>,
    /// Corpus `subject_kind`s the owner elects to pin (B2-ii). MUST be
    /// sorted (lexicographic over UTF-8 bytes) and deduplicated.
    pub pinned_class: Vec<String>,
    /// Ed25519 signature over [`Self::canonical_preimage`], base64 standard.
    pub signature_ed25519_base64: String,
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig`, base64 standard.
    pub signature_ml_dsa_65_base64: String,
}

impl StorageBudgetV1 {
    /// The exact bytes the bound-hybrid signature covers (CC 6.1.3 binary
    /// discipline — length-prefixed, big-endian, domain-separated).
    ///
    /// ```text
    /// b"CIRIS-STG-BUDGET" ‖ u32_be(version=1)
    ///   ‖ lp(node_id) ‖ lp(epoch_id) ‖ u64_be(revision)
    ///   ‖ u32_be(scope_count)
    ///   ‖ scope_count × ( lp(cohort_scope) ‖ u64_be(budget) ‖ u64_be(pin_reserve) )
    ///   ‖ u32_be(pinned_class_count) ‖ pinned_class_count × lp(subject_kind)
    /// ```
    #[must_use]
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(STORAGE_BUDGET_DOMAIN);
        out.extend_from_slice(&SHAPE_VERSION.to_be_bytes());
        push_lp(&mut out, &self.node_id);
        push_lp(&mut out, &self.epoch_id);
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&u32_len(self.scopes.len()).to_be_bytes());
        for s in &self.scopes {
            push_lp(&mut out, &s.cohort_scope);
            out.extend_from_slice(&s.budget_bytes.to_be_bytes());
            out.extend_from_slice(&s.pin_reserve_bytes.to_be_bytes());
        }
        out.extend_from_slice(&u32_len(self.pinned_class.len()).to_be_bytes());
        for c in &self.pinned_class {
            push_lp(&mut out, c);
        }
        out
    }

    /// Structural validation (CC 6.1.5.2 §Q — pre-signature). A verifier
    /// MUST reject on any failure: `pin_reserve > budget`; a `self`/`family`
    /// scope entry; or lists not sorted+deduplicated.
    pub fn validate(&self) -> Result<(), StorageContentionError> {
        for s in &self.scopes {
            if SUPPRESSED_SCOPES.contains(&s.cohort_scope.as_str()) {
                return Err(StorageContentionError::SuppressedScope(
                    s.cohort_scope.clone(),
                ));
            }
            if s.pin_reserve_bytes > s.budget_bytes {
                return Err(StorageContentionError::ReserveExceedsBudget {
                    scope: s.cohort_scope.clone(),
                    reserve: s.pin_reserve_bytes,
                    budget: s.budget_bytes,
                });
            }
        }
        if !is_sorted_dedup(self.scopes.iter().map(|s| s.cohort_scope.as_str())) {
            return Err(StorageContentionError::NotSortedDedup(
                "scopes[].cohort_scope",
            ));
        }
        if !is_sorted_dedup(self.pinned_class.iter().map(String::as_str)) {
            return Err(StorageContentionError::NotSortedDedup("pinned_class"));
        }
        Ok(())
    }

    /// `true` iff `self` supersedes `other` under the anti-rollback rule:
    /// same `node_id`, strictly-higher `revision` (B3). A lower revision
    /// from the same node MUST be rejected by the caller.
    #[must_use]
    pub fn supersedes(&self, other: &Self) -> bool {
        self.node_id == other.node_id && self.revision > other.revision
    }

    /// Bound-hybrid-sign the (already structurally-valid) budget with the
    /// owner's deterministic keys. Overwrites the two signature fields.
    ///
    /// # Errors
    /// [`StorageContentionError`] on a crypto failure or if [`Self::validate`]
    /// fails (never sign a malformed shape).
    pub fn sign(
        &mut self,
        ed: &impl ClassicalSign,
        pqc: &impl PqcSign,
    ) -> Result<(), StorageContentionError> {
        self.validate()?;
        let (ed_b64, pqc_b64) = bound_hybrid_sign(&self.canonical_preimage(), ed, pqc)?;
        self.signature_ed25519_base64 = ed_b64;
        self.signature_ml_dsa_65_base64 = pqc_b64;
        Ok(())
    }

    /// Verify structure + the bound-hybrid signature at ingest. Rejects a
    /// shape lacking a valid ML-DSA-65 half (CC 6.1.3).
    pub fn verify(
        &self,
        ed_pub: &[u8; 32],
        ml_dsa_65_pub: &[u8],
    ) -> Result<(), StorageContentionError> {
        self.validate()?;
        bound_hybrid_verify(
            &self.canonical_preimage(),
            &self.signature_ed25519_base64,
            &self.signature_ml_dsa_65_base64,
            ed_pub,
            ml_dsa_65_pub,
        )
    }
}

/// A peer's want/have advertisement (CC 6.1.5.2 §Q B4). A producer MUST
/// NOT push a corpus object exceeding `size_cap_bytes`, nor any object
/// whose `content_id` is absent from an active `CorpusWantV1` from the
/// receiver — wanted-then-pulled, never unsolicited-pushed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusWantV1 {
    /// The advertising peer.
    pub node_id: String,
    /// Epoch keying (CC 5.1).
    pub epoch_id: String,
    /// The scope this want draws budget from. NEVER `self` / `family`.
    pub cohort_scope: String,
    /// Max single-object size this peer will accept.
    pub size_cap_bytes: u64,
    /// Advertised headroom in the scope.
    pub remaining_budget_bytes: u64,
    /// Content-addressed ids wanted. MUST be sorted (lexicographic over
    /// UTF-8 bytes) and deduplicated.
    pub want: Vec<String>,
    /// Ed25519 signature over [`Self::canonical_preimage`], base64 standard.
    pub signature_ed25519_base64: String,
    /// ML-DSA-65 signature over `preimage ‖ ed25519_sig`, base64 standard.
    pub signature_ml_dsa_65_base64: String,
}

impl CorpusWantV1 {
    /// The exact bytes the bound-hybrid signature covers (CC 6.1.3).
    ///
    /// ```text
    /// b"CIRIS-WANT-HAVE\0" ‖ u32_be(version=1)
    ///   ‖ lp(node_id) ‖ lp(epoch_id) ‖ lp(cohort_scope)
    ///   ‖ u64_be(size_cap_bytes) ‖ u64_be(remaining_budget_bytes)
    ///   ‖ u32_be(want_count) ‖ want_count × lp(content_id)
    /// ```
    #[must_use]
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(CORPUS_WANT_DOMAIN);
        out.extend_from_slice(&SHAPE_VERSION.to_be_bytes());
        push_lp(&mut out, &self.node_id);
        push_lp(&mut out, &self.epoch_id);
        push_lp(&mut out, &self.cohort_scope);
        out.extend_from_slice(&self.size_cap_bytes.to_be_bytes());
        out.extend_from_slice(&self.remaining_budget_bytes.to_be_bytes());
        out.extend_from_slice(&u32_len(self.want.len()).to_be_bytes());
        for cid in &self.want {
            push_lp(&mut out, cid);
        }
        out
    }

    /// Structural validation: no `self`/`family` scope; `want` sorted+deduped.
    pub fn validate(&self) -> Result<(), StorageContentionError> {
        if SUPPRESSED_SCOPES.contains(&self.cohort_scope.as_str()) {
            return Err(StorageContentionError::SuppressedScope(
                self.cohort_scope.clone(),
            ));
        }
        if !is_sorted_dedup(self.want.iter().map(String::as_str)) {
            return Err(StorageContentionError::NotSortedDedup("want"));
        }
        Ok(())
    }

    /// `true` iff a producer may push `content_id` of `object_bytes` against
    /// this want (B4): the id is wanted AND within the advertised size cap.
    #[must_use]
    pub fn admits(&self, content_id: &str, object_bytes: u64) -> bool {
        object_bytes <= self.size_cap_bytes && self.want.iter().any(|w| w == content_id)
    }

    /// Bound-hybrid-sign the want with the peer's deterministic keys.
    ///
    /// # Errors
    /// [`StorageContentionError`] on crypto failure or structural invalidity.
    pub fn sign(
        &mut self,
        ed: &impl ClassicalSign,
        pqc: &impl PqcSign,
    ) -> Result<(), StorageContentionError> {
        self.validate()?;
        let (ed_b64, pqc_b64) = bound_hybrid_sign(&self.canonical_preimage(), ed, pqc)?;
        self.signature_ed25519_base64 = ed_b64;
        self.signature_ml_dsa_65_base64 = pqc_b64;
        Ok(())
    }

    /// Verify structure + the bound-hybrid signature at ingest.
    pub fn verify(
        &self,
        ed_pub: &[u8; 32],
        ml_dsa_65_pub: &[u8],
    ) -> Result<(), StorageContentionError> {
        self.validate()?;
        bound_hybrid_verify(
            &self.canonical_preimage(),
            &self.signature_ed25519_base64,
            &self.signature_ml_dsa_65_base64,
            ed_pub,
            ml_dsa_65_pub,
        )
    }
}

// ── bound-hybrid sign/verify (CC 6.1.3) ───────────────────────────────

/// Minimal classical-signer surface (Ed25519). Implemented by
/// `ciris_crypto::Ed25519Signer`; abstracted so the shapes are testable
/// without threading a concrete signer type.
pub trait ClassicalSign {
    /// Sign `msg`, returning the 64-byte Ed25519 signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, StorageContentionError>;
}
/// Minimal PQC-signer surface (ML-DSA-65). Implemented by
/// `ciris_crypto::MlDsa65Signer`.
pub trait PqcSign {
    /// Sign `msg`, returning the ML-DSA-65 signature.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, StorageContentionError>;
}

impl ClassicalSign for ciris_crypto::Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, StorageContentionError> {
        ciris_crypto::ClassicalSigner::sign(self, msg)
            .map_err(|e| StorageContentionError::SignatureDecode(format!("ed25519 sign: {e}")))
    }
}
impl PqcSign for ciris_crypto::MlDsa65Signer {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, StorageContentionError> {
        ciris_crypto::PqcSigner::sign(self, msg)
            .map_err(|e| StorageContentionError::SignatureDecode(format!("ml-dsa-65 sign: {e}")))
    }
}

/// The CC 6.1.3 bound-hybrid signature: `Ed25519(preimage)` +
/// `ML-DSA-65(preimage ‖ ed25519_sig)`. Returns `(ed_b64, pqc_b64)`.
fn bound_hybrid_sign(
    preimage: &[u8],
    ed: &impl ClassicalSign,
    pqc: &impl PqcSign,
) -> Result<(String, String), StorageContentionError> {
    let ed_sig = ed.sign(preimage)?;
    let mut bound = Vec::with_capacity(preimage.len() + ed_sig.len());
    bound.extend_from_slice(preimage);
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = pqc.sign(&bound)?;
    Ok((B64.encode(&ed_sig), B64.encode(&pqc_sig)))
}

/// Verify the bound-hybrid signature. REJECTS a shape whose ML-DSA-65 half
/// is missing or invalid (CC 6.1.3 — classical-only is not acceptable).
fn bound_hybrid_verify(
    preimage: &[u8],
    ed_sig_b64: &str,
    pqc_sig_b64: &str,
    ed_pub: &[u8; 32],
    ml_dsa_65_pub: &[u8],
) -> Result<(), StorageContentionError> {
    use ciris_crypto::{ClassicalVerifier, PqcVerifier};

    if ml_dsa_65_pub.is_empty() {
        return Err(StorageContentionError::MissingPqcKey);
    }
    let ed_sig = B64
        .decode(ed_sig_b64)
        .map_err(|e| StorageContentionError::SignatureDecode(format!("ed25519 b64: {e}")))?;
    let pqc_sig = B64
        .decode(pqc_sig_b64)
        .map_err(|e| StorageContentionError::SignatureDecode(format!("ml-dsa-65 b64: {e}")))?;

    let ed_ok = ciris_crypto::Ed25519Verifier::new()
        .verify(ed_pub, preimage, &ed_sig)
        .map_err(|e| StorageContentionError::SignatureDecode(format!("ed25519 verify: {e}")))?;
    if !ed_ok {
        return Err(StorageContentionError::SignatureMismatch("ed25519"));
    }

    let mut bound = Vec::with_capacity(preimage.len() + ed_sig.len());
    bound.extend_from_slice(preimage);
    bound.extend_from_slice(&ed_sig);
    let pqc_ok = ciris_crypto::MlDsa65Verifier::new()
        .verify(ml_dsa_65_pub, &bound, &pqc_sig)
        .map_err(|e| StorageContentionError::SignatureDecode(format!("ml-dsa-65 verify: {e}")))?;
    if !pqc_ok {
        return Err(StorageContentionError::SignatureMismatch("ml-dsa-65"));
    }
    Ok(())
}

// ── preimage helpers (CC 6.1.3 length-prefix discipline) ──────────────

/// `lp(x) = u32_be(byte_len(utf8(x))) ‖ utf8(x)`.
fn push_lp(out: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    out.extend_from_slice(&u32_len(bytes.len()).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// `usize → u32` for a length prefix, saturating (a > 4 GiB field is not a
/// legitimate `cohort_scope`/`subject_kind`/`content_id`; saturation keeps
/// the preimage total-and-deterministic rather than panicking).
fn u32_len(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// `true` iff the iterator yields strictly-ascending (sorted + no dup) items
/// over UTF-8 byte order.
fn is_sorted_dedup<'a>(it: impl Iterator<Item = &'a str>) -> bool {
    let mut prev: Option<&str> = None;
    for cur in it {
        if let Some(p) = prev {
            if p >= cur {
                return false;
            }
        }
        prev = Some(cur);
    }
    true
}

// ── B5 consumption accounting (edge-internal) ─────────────────────────

/// CC 6.1.5.2 §Q **B5 consumption accounting** — sum the durable bytes
/// actually held, grouped by `cohort_scope`, recomputed **edge-internally**
/// from what persist holds. Consumption is NEVER trusted from the wire; it
/// is reconciled against real bytes so a forged `StorageBudgetV1` cannot
/// become a force-evict channel (B5 consumption-challengeability).
///
/// Input is persist's [`FountainHeldMeta`] rows
/// (`FederationDirectory::list_held_fountain_content`, enriched with
/// `content_bytes` + `cohort_scope` as of CIRISPersist v12.1.0 / #349).
/// Content whose signed envelope declares no scope (`cohort_scope: None`)
/// rolls up under the `None` key — **unattributed budget** (CIRISEdge#260).
///
/// Producers of edge-published fountain content that should draw from a
/// scope's budget MUST set the `cohort_scope` key in the content's signed
/// envelope; persist round-trips it verbatim (it does not infer scope), and
/// unscoped content lands as `None` here.
#[must_use]
pub fn consumption_by_scope(held: &[FountainHeldMeta]) -> BTreeMap<Option<String>, u64> {
    let mut acc: BTreeMap<Option<String>, u64> = BTreeMap::new();
    for meta in held {
        let bucket = acc.entry(meta.cohort_scope.clone()).or_default();
        *bucket = bucket.saturating_add(meta.content_bytes);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::{Ed25519Signer, MlDsa65Signer};

    fn budget(revision: u64) -> StorageBudgetV1 {
        StorageBudgetV1 {
            node_id: "node-a".into(),
            epoch_id: "epoch-1".into(),
            revision,
            scopes: vec![
                ScopeBudget {
                    cohort_scope: "affiliations".into(),
                    budget_bytes: 1_000_000,
                    pin_reserve_bytes: 500_000,
                },
                ScopeBudget {
                    cohort_scope: "community".into(),
                    budget_bytes: 2_000_000,
                    pin_reserve_bytes: 0,
                },
            ],
            pinned_class: vec!["corpus.image".into(), "corpus.text".into()],
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        }
    }

    fn want() -> CorpusWantV1 {
        CorpusWantV1 {
            node_id: "node-b".into(),
            epoch_id: "epoch-1".into(),
            cohort_scope: "community".into(),
            size_cap_bytes: 4_096,
            remaining_budget_bytes: 1_000_000,
            want: vec!["cid-aaa".into(), "cid-bbb".into()],
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        }
    }

    #[test]
    fn domains_are_exactly_16_bytes() {
        assert_eq!(STORAGE_BUDGET_DOMAIN.len(), 16);
        assert_eq!(CORPUS_WANT_DOMAIN.len(), 16);
        assert_eq!(&CORPUS_WANT_DOMAIN[15], &0u8, "one trailing NUL");
    }

    #[test]
    fn preimage_is_deterministic() {
        assert_eq!(
            budget(1).canonical_preimage(),
            budget(1).canonical_preimage()
        );
        assert_eq!(want().canonical_preimage(), want().canonical_preimage());
    }

    #[test]
    fn preimage_is_injective_over_fields() {
        // revision, budget bytes, and pinned_class each change the bytes.
        assert_ne!(
            budget(1).canonical_preimage(),
            budget(2).canonical_preimage()
        );
        let mut b = budget(1);
        b.scopes[0].budget_bytes += 1;
        assert_ne!(b.canonical_preimage(), budget(1).canonical_preimage());
        let mut b2 = budget(1);
        b2.pinned_class.push("corpus.video".into());
        assert_ne!(b2.canonical_preimage(), budget(1).canonical_preimage());
        // domain separation: a want and a budget never collide.
        assert_ne!(budget(1).canonical_preimage(), want().canonical_preimage());
    }

    #[test]
    fn validate_rejects_reserve_over_budget() {
        let mut b = budget(1);
        b.scopes[0].pin_reserve_bytes = b.scopes[0].budget_bytes + 1;
        assert!(matches!(
            b.validate(),
            Err(StorageContentionError::ReserveExceedsBudget { .. })
        ));
    }

    #[test]
    fn validate_rejects_self_and_family_scope() {
        let mut b = budget(1);
        b.scopes[0].cohort_scope = "self".into();
        assert!(matches!(
            b.validate(),
            Err(StorageContentionError::SuppressedScope(_))
        ));
        let mut w = want();
        w.cohort_scope = "family".into();
        assert!(matches!(
            w.validate(),
            Err(StorageContentionError::SuppressedScope(_))
        ));
    }

    #[test]
    fn validate_rejects_unsorted_or_dup_lists() {
        let mut b = budget(1);
        b.pinned_class = vec!["corpus.text".into(), "corpus.image".into()]; // wrong order
        assert!(matches!(
            b.validate(),
            Err(StorageContentionError::NotSortedDedup(_))
        ));
        let mut b2 = budget(1);
        b2.scopes.push(b2.scopes[1].clone()); // dup "community"
        assert!(matches!(
            b2.validate(),
            Err(StorageContentionError::NotSortedDedup(_))
        ));
        let mut w = want();
        w.want = vec!["cid-bbb".into(), "cid-aaa".into()]; // wrong order
        assert!(matches!(
            w.validate(),
            Err(StorageContentionError::NotSortedDedup(_))
        ));
    }

    #[test]
    fn anti_rollback_supersede() {
        let older = budget(3);
        let newer = budget(4);
        assert!(newer.supersedes(&older));
        assert!(!older.supersedes(&newer));
        // different node never supersedes.
        let mut other_node = budget(9);
        other_node.node_id = "node-z".into();
        assert!(!other_node.supersedes(&older));
    }

    #[test]
    fn want_admits_only_wanted_and_within_cap() {
        let w = want();
        assert!(w.admits("cid-aaa", 4_096));
        assert!(!w.admits("cid-aaa", 4_097), "over size_cap");
        assert!(!w.admits("cid-zzz", 1), "not wanted");
    }

    #[test]
    fn budget_hybrid_sign_verify_round_trip() {
        let ed = Ed25519Signer::from_seed(&[7u8; 32]).unwrap();
        let pqc = MlDsa65Signer::from_seed(&[7u8; 32]).unwrap();
        let ed_pub: [u8; 32] = ciris_crypto::ClassicalSigner::public_key(&ed)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let pqc_pub = ciris_crypto::PqcSigner::public_key(&pqc).unwrap();

        let mut b = budget(1);
        b.sign(&ed, &pqc).unwrap();
        assert!(b.verify(&ed_pub, &pqc_pub).is_ok());

        // tamper the revision → signature no longer covers the preimage.
        let mut tampered = b.clone();
        tampered.revision = 99;
        assert!(matches!(
            tampered.verify(&ed_pub, &pqc_pub),
            Err(StorageContentionError::SignatureMismatch("ed25519"))
        ));

        // classical-only verify (empty PQC key) is REJECTED (CC 6.1.3).
        assert!(matches!(
            b.verify(&ed_pub, &[]),
            Err(StorageContentionError::MissingPqcKey)
        ));
    }

    #[test]
    fn want_hybrid_sign_verify_round_trip() {
        let ed = Ed25519Signer::from_seed(&[9u8; 32]).unwrap();
        let pqc = MlDsa65Signer::from_seed(&[9u8; 32]).unwrap();
        let ed_pub: [u8; 32] = ciris_crypto::ClassicalSigner::public_key(&ed)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        let pqc_pub = ciris_crypto::PqcSigner::public_key(&pqc).unwrap();

        let mut w = want();
        w.sign(&ed, &pqc).unwrap();
        assert!(w.verify(&ed_pub, &pqc_pub).is_ok());

        let mut tampered = w.clone();
        tampered.size_cap_bytes = 1;
        assert!(tampered.verify(&ed_pub, &pqc_pub).is_err());
    }

    fn held(scope: Option<&str>, content_bytes: u64) -> FountainHeldMeta {
        FountainHeldMeta {
            content_id: "cid".into(),
            corpus_kind: "corpus.text".into(),
            pqc_key_id: "pub".into(),
            original_content_length: content_bytes,
            n_source: 10,
            k_repair: 5,
            min_viable_symbols: 10,
            symbol_size: 100,
            held_symbols: 10,
            content_bytes,
            cohort_scope: scope.map(String::from),
            recoverable: true,
            admitted_at: "2026-07-03T00:00:00Z".into(),
        }
    }

    #[test]
    fn consumption_sums_content_bytes_by_scope() {
        let rows = vec![
            held(Some("community"), 100),
            held(Some("community"), 250),
            held(Some("affiliations"), 40),
            held(None, 7), // unscoped envelope → unattributed budget
        ];
        let by = consumption_by_scope(&rows);
        assert_eq!(by.get(&Some("community".to_string())), Some(&350));
        assert_eq!(by.get(&Some("affiliations".to_string())), Some(&40));
        assert_eq!(by.get(&None), Some(&7));
        assert_eq!(by.len(), 3);
        assert!(consumption_by_scope(&[]).is_empty());
    }
}
