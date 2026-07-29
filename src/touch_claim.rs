//! Edge touch-claim producer (CIRISEdge#411 §2) — the PRODUCER half of
//! persist's signed `fresh_as_of` **freshness floor**
//! ([`ciris_persist::federation::freshness`]).
//!
//! # What this is
//!
//! persist owns storage + monotonic-max merge + admission + the `NOfM`
//! tally; it does NOT decide *when* a thing is alive. `now()` is not pure,
//! so producing a `fresh_as_of` value is an **attestation**, never a
//! transform opcode — "reading emits a claim" is CEG-native here. This
//! module is that attestor: it builds + hybrid-signs a
//! [`ciris_persist::federation::types::SignedTouchClaim`] on the liveness
//! events edge already observes, and submits it via
//! [`ciris_persist::federation::FederationDirectory::put_touch_claim`].
//!
//! This is load-bearing for the ownerless-lock reclaim (CC 3.2): a node
//! becomes reclaimable only after it has emitted an `ownership_binding`
//! freshness floor and then gone dark ≥180 days. **Absent floor = NEVER
//! reclaimable** (fail-safe). So the single most important thing this
//! module makes easy is [`TouchClaimProducer::produce_ownership_self_touch`].
//!
//! # The three signer forms
//!
//! - **`self_touch`** — the node's own dead-man's-switch. The attester IS
//!   the target (or a registered occurrence of it). Edge produces this for
//!   its own key.
//! - **`witness_touch`** — edge witnessing a peer alive (off
//!   [`crate::reachability::ReachabilityTracker`]). The attester MUST be
//!   independent of the target (a witness cannot be the thing it
//!   witnesses).
//! - **`n_of_m_cosigned`** — a collusion-resistant "death finding": the
//!   primary attester + ≥[`ciris_persist::federation::freshness::NOFM_MIN_COSIGNERS`]
//!   independent co-signers, each hybrid-verifying over the SAME envelope
//!   bytes.
//!
//!   **⚠️ Trap (why this module implements the real co-sig carriage):** the
//!   [`ciris_persist::federation::types::SignerForm::NOfMCosigned`]
//!   docstrings say it verifies identically to `witness_touch` (1-of-1) —
//!   that is STALE v21.6.0 documentation. persist v21.10.0
//!   (`admission.rs` step 5) runs a REAL m-of-n tally: a `NOfMCosigned`
//!   claim WITHOUT a valid co-signature set under `touch_cosignatures` is
//!   silently REJECTED at admission. Edge holds only its OWN
//!   [`LocalSigner`], so it produces the PRIMARY leg + attaches
//!   externally-supplied co-signatures ([`attach_cosignatures`]); a
//!   co-signing node produces its leg with [`build_cosignature`]. Edge
//!   never fabricates other nodes' signatures.
//!
//! # Signing discipline
//!
//! The signature is over **plain JCS** of the claim's `signing_envelope()`
//! via [`ciris_persist::prelude::ceg_produce_canonicalize`] (RFC 8785 JCS,
//! the same canonicalizer admission re-derives) — NOT the `EdgeEnvelope`
//! path (`canonicalize_envelope_for_signing`). The detached hybrid
//! signature mirrors [`crate::identity::sign_envelope`]'s bound-sig
//! discipline: Ed25519 over the JCS bytes, ML-DSA-65 over
//! `JCS_bytes ‖ ed25519_sig`. persist's admission verifies at threshold
//! **1-of-1 RequireHybrid** — a classical-only touch does not count, so a
//! produced touch needs a PQC half and the attesting key must have a
//! registered ML-DSA-65 pubkey.
//!
//! # `fresh_as_of` — floor, never ceiling
//!
//! Repeated touches within one coalescing bucket dedupe on the wire
//! (identical `fresh_as_of` ⇒ identical signed envelope ⇒ identical content
//! hash). We floor a freshly-observed instant down to a bucket boundary
//! ([`coalesce_fresh_as_of`]); persist exports no precision const so
//! [`DEFAULT_TOUCH_COALESCE_SECS`] is edge's choice. Flooring can only make
//! the asserted lower bound MORE conservative; ceiling past `now` would
//! trip persist's future-skew guard
//! ([`ciris_persist::federation::admission::DEFAULT_MAX_TOUCH_SKEW`]).
//!
//! # `cohort_scope` — MANDATORY + tight (privacy)
//!
//! A touch-claim is cohort-scoped and consent-gated: an ungated
//! read-receipt trail is an access-pattern surveillance surface, and for
//! `trace:*` targets it leaks who reads whose reasoning. `cohort_scope` is
//! therefore a **required argument** on every builder here (never a
//! default-to-federation) and is validated against the closed set BEFORE
//! signing/submission — an invalid scope (`"global"`, …) is refused up
//! front. A self_touch defaults to [`cohort_scope::SELF`]; a witness of a
//! peer is scoped as tightly as the relationship allows (self/family).

use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};

use ciris_persist::federation::freshness::{
    coalesce_touch_ts, TouchApplyOutcome, TOUCH_COSIGNATURES_FIELD,
};
use ciris_persist::federation::ownership_reclaim::OWNERSHIP_FRESHNESS_TARGET_KIND;
use ciris_persist::federation::types::{cohort_scope, SignedTouchClaim, SignerForm};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::ceg_produce_canonicalize;
use ciris_verify_core::threshold::ThresholdSignature;
use ciris_verify_core::transport_binding::TransportBindingSignature;

use crate::identity::LocalSigner;
use crate::reachability::ReachabilityTracker;

/// Default `fresh_as_of` coalescing bucket, in seconds. persist exports NO
/// precision const (the general `round(precision)` opcode is a sibling
/// concern), so a producer picks its own bucket; 60s is a sane default —
/// repeated touches within the same wall-clock minute dedupe to one signed
/// envelope. Always applied as a FLOOR, never a ceiling (see
/// [`coalesce_fresh_as_of`]).
pub const DEFAULT_TOUCH_COALESCE_SECS: i64 = 60;

/// A general node-liveness `target_kind` for a self/witness touch that is
/// NOT the ownership-reclaim tie-in. Open vocab (`target_kind` is resolved
/// by the consumer); use [`OWNERSHIP_FRESHNESS_TARGET_KIND`]
/// (`"ownership_binding"`) for the CC 3.2 reclaim floor instead.
pub const NODE_LIVENESS_TARGET_KIND: &str = "node_liveness";

/// A fault building, signing, or submitting a [`SignedTouchClaim`].
#[derive(Debug)]
pub enum TouchClaimError {
    /// `cohort_scope` is not one of the closed-set values (`self`,
    /// `family`, `community`, `affiliations`, `species`, `biosphere`,
    /// `federation`). Refused BEFORE signing/submission — `"global"` and
    /// friends never reach `put_touch_claim`.
    InvalidCohortScope(String),
    /// A `witness_touch` / `n_of_m_cosigned` primary attester equals the
    /// touched target. A witness cannot be the thing it witnesses; refused
    /// before signing (admission would reject it anyway).
    AttesterNotIndependent {
        /// The key that is both attester and target.
        key_id: String,
    },
    /// [`attach_cosignatures`] was called on a claim whose `signer_form`
    /// is not [`SignerForm::NOfMCosigned`].
    NotNofmCosigned,
    /// A claim's `signed_envelope` is not a JSON object (cannot carry the
    /// `touch_cosignatures` extra). A well-formed produced claim never
    /// hits this.
    MalformedEnvelope,
    /// RFC 8785 JCS canonicalization fault.
    Canonicalize(String),
    /// A signer fault (Ed25519 or ML-DSA-65 half).
    Sign(String),
    /// serde serialization fault attaching the co-signature set.
    Serialize(String),
    /// `put_touch_claim` failed at persist's admission or storage layer.
    Put(String),
}

impl std::fmt::Display for TouchClaimError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCohortScope(s) => write!(
                f,
                "invalid cohort_scope `{s}`: touch-claims are cohort-scoped and consent-gated \
                 (one of self/family/community/affiliations/species/biosphere/federation; \
                 `global` is not valid)"
            ),
            Self::AttesterNotIndependent { key_id } => write!(
                f,
                "attester {key_id} equals the touched target — a witness/co-signer must be \
                 independent of the thing it witnesses"
            ),
            Self::NotNofmCosigned => write!(
                f,
                "attach_cosignatures requires an n_of_m_cosigned claim (self/witness touches \
                 carry no co-signature set)"
            ),
            Self::MalformedEnvelope => {
                write!(
                    f,
                    "signed_envelope is not a JSON object; cannot attach touch_cosignatures"
                )
            }
            Self::Canonicalize(e) => write!(f, "JCS canonicalize: {e}"),
            Self::Sign(e) => write!(f, "hybrid sign: {e}"),
            Self::Serialize(e) => write!(f, "serialize co-signatures: {e}"),
            Self::Put(e) => write!(f, "put_touch_claim: {e}"),
        }
    }
}

impl std::error::Error for TouchClaimError {}

/// Floor `observed_at` DOWN to the nearest `coalesce_secs` bucket, capping
/// to `now()` first so the result is never in the future (defense-in-depth
/// over persist's skew guard — flooring a freshly-observed `now` is already
/// well under the 5-minute tolerance). Mirrors persist's
/// [`coalesce_touch_ts`], with the extra never-ceiling / never-future
/// guarantee a producer wants.
///
/// `coalesce_secs` ≤ 0 is treated as a 1-second bucket (a no-op rounding
/// unit) rather than panicking.
#[must_use]
pub fn coalesce_fresh_as_of(observed_at: DateTime<Utc>, coalesce_secs: i64) -> DateTime<Utc> {
    // Never assert a `fresh_as_of` past the moment we are attesting from.
    let capped = observed_at.min(Utc::now());
    coalesce_touch_ts(capped, Duration::seconds(coalesce_secs.max(1)))
}

/// Produce the detached hybrid signature halves over `bytes` with `signer`:
/// Ed25519 over `bytes`, ML-DSA-65 over `bytes ‖ ed25519_sig` (the bound-sig
/// discipline). Returns `(ed25519_b64, Option<mldsa65_b64>)` — the PQC half
/// is `None` only while `signer.pqc` is `None` (hybrid-pending), in which
/// case the claim will not admit at persist's federation-tier RequireHybrid
/// gate. Mirrors [`crate::identity::sign_envelope`].
async fn sign_bound_hybrid(
    signer: &LocalSigner,
    bytes: &[u8],
) -> Result<(String, Option<String>), TouchClaimError> {
    let ed = signer
        .classical
        .sign(bytes)
        .await
        .map_err(|e| TouchClaimError::Sign(format!("ed25519: {e}")))?;
    let ed_b64 = B64.encode(&ed);
    let mldsa_b64 = if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed);
        let sig = pqc
            .sign(&bound)
            .await
            .map_err(|e| TouchClaimError::Sign(format!("ml-dsa-65: {e}")))?;
        Some(B64.encode(&sig))
    } else {
        // CIRISEdge#425 — the signer has NO PQC half (hybrid-pending), so this touch
        // is CLASSICAL-ONLY and will be REFUSED at persist's federation-tier
        // RequireHybrid gate — surfacing later as a generic `Put` error with the
        // cause lost. Name it HERE, at the source, so "the touch didn't admit" is a
        // one-line read, not an investigation.
        tracing::warn!(
            key_id = %signer.key_id,
            "touch claim signed CLASSICAL-ONLY — signer has no ML-DSA-65 (PQC) half \
             (hybrid-pending). This claim will NOT admit at RequireHybrid; provision the \
             PQC signer half to emit an admissible hybrid touch (CIRISEdge#425)"
        );
        None
    };
    Ok((ed_b64, mldsa_b64))
}

/// Build + hybrid-sign a [`SignedTouchClaim`] with `signer` as the
/// `attesting_key_id`. The `signed_envelope` is the claim's
/// `signing_envelope()` VERBATIM (authority is the envelope, never the
/// typed projection — persist's admission cross-checks field-by-field and
/// never rebuilds). `fresh_as_of` is [`coalesce_fresh_as_of`]-floored.
///
/// `cohort_scope` is validated up front — an invalid scope is refused
/// BEFORE signing.
async fn build_signed_touch_claim(
    signer: &LocalSigner,
    target_key_id: &str,
    target_kind: &str,
    signer_form: SignerForm,
    cohort: &str,
    observed_at: DateTime<Utc>,
    coalesce_secs: i64,
) -> Result<SignedTouchClaim, TouchClaimError> {
    // (0) MANDATORY privacy row — refuse an out-of-set scope before we
    // sign or touch the directory.
    if !cohort_scope::is_valid(cohort) {
        return Err(TouchClaimError::InvalidCohortScope(cohort.to_owned()));
    }

    // (1) FLOOR the observed instant (never ceiling, never future).
    let fresh_as_of = coalesce_fresh_as_of(observed_at, coalesce_secs);

    // (2) unsigned skeleton — `signed_envelope = Null` + empty signature.
    let unsigned = SignedTouchClaim {
        target_key_id: target_key_id.to_owned(),
        target_kind: target_kind.to_owned(),
        fresh_as_of,
        signer_form,
        attesting_key_id: signer.key_id.clone(),
        signed_envelope: serde_json::Value::Null,
        signature: TransportBindingSignature {
            ed25519_signature_base64: String::new(),
            mldsa65_signature_base64: None,
        },
        cohort_scope: cohort.to_owned(),
    };

    // (3) canonicalize the 6-key envelope, hybrid-sign it, fill in the
    // signed_envelope VERBATIM + the signature container.
    let env = unsigned.signing_envelope();
    let bytes =
        ceg_produce_canonicalize(&env).map_err(|e| TouchClaimError::Canonicalize(e.to_string()))?;
    let (ed25519_signature_base64, mldsa65_signature_base64) =
        sign_bound_hybrid(signer, &bytes).await?;

    Ok(SignedTouchClaim {
        signed_envelope: env,
        signature: TransportBindingSignature {
            ed25519_signature_base64,
            mldsa65_signature_base64,
        },
        ..unsigned
    })
}

/// Build + hybrid-sign a **`self_touch`** (dead-man's-switch): this node
/// (`signer`) asserts its own freshness floor for `(signer.key_id,
/// target_kind)`. The attester IS the target — persist's admission requires
/// `signer_acts_for(attester, target)`, satisfied trivially when they are
/// the same key.
///
/// For the CC 3.2 ownerless-lock reclaim tie-in pass
/// `target_kind = OWNERSHIP_FRESHNESS_TARGET_KIND` (or use
/// [`TouchClaimProducer::produce_ownership_self_touch`]).
///
/// # Errors
/// [`TouchClaimError::InvalidCohortScope`] if `cohort` is out of set;
/// [`TouchClaimError::Canonicalize`] / [`TouchClaimError::Sign`] on a
/// canonicalizer or signer fault.
pub async fn build_self_touch(
    signer: &LocalSigner,
    target_kind: &str,
    cohort: &str,
    observed_at: DateTime<Utc>,
    coalesce_secs: i64,
) -> Result<SignedTouchClaim, TouchClaimError> {
    build_signed_touch_claim(
        signer,
        &signer.key_id,
        target_kind,
        SignerForm::SelfTouch,
        cohort,
        observed_at,
        coalesce_secs,
    )
    .await
}

/// Build + hybrid-sign a **`witness_touch`**: `signer` attests that it
/// observed `target_key_id` alive. The attester MUST be independent of the
/// target (refused here, and at admission).
///
/// # Errors
/// [`TouchClaimError::AttesterNotIndependent`] if `target_key_id ==
/// signer.key_id`; plus the errors of [`build_self_touch`].
pub async fn build_witness_touch(
    signer: &LocalSigner,
    target_key_id: &str,
    target_kind: &str,
    cohort: &str,
    observed_at: DateTime<Utc>,
    coalesce_secs: i64,
) -> Result<SignedTouchClaim, TouchClaimError> {
    if target_key_id == signer.key_id {
        return Err(TouchClaimError::AttesterNotIndependent {
            key_id: signer.key_id.clone(),
        });
    }
    build_signed_touch_claim(
        signer,
        target_key_id,
        target_kind,
        SignerForm::WitnessTouch,
        cohort,
        observed_at,
        coalesce_secs,
    )
    .await
}

/// Build + hybrid-sign the **PRIMARY leg** of an **`n_of_m_cosigned`**
/// touch. The returned claim's `signed_envelope` carries NO
/// `touch_cosignatures` — co-signatures cannot be inside the bytes they
/// sign (the sign-then-strip fixed point). Feed [`cosignature_preimage`] to
/// each co-signing node's [`build_cosignature`], then attach the set with
/// [`attach_cosignatures`] before submitting.
///
/// The primary attester MUST be independent of the target.
///
/// # Errors
/// [`TouchClaimError::AttesterNotIndependent`] if `target_key_id ==
/// signer.key_id`; plus the errors of [`build_self_touch`].
pub async fn build_nofm_primary(
    signer: &LocalSigner,
    target_key_id: &str,
    target_kind: &str,
    cohort: &str,
    observed_at: DateTime<Utc>,
    coalesce_secs: i64,
) -> Result<SignedTouchClaim, TouchClaimError> {
    if target_key_id == signer.key_id {
        return Err(TouchClaimError::AttesterNotIndependent {
            key_id: signer.key_id.clone(),
        });
    }
    build_signed_touch_claim(
        signer,
        target_key_id,
        target_kind,
        SignerForm::NOfMCosigned,
        cohort,
        observed_at,
        coalesce_secs,
    )
    .await
}

/// The exact bytes a co-signer signs for an `n_of_m_cosigned` touch:
/// `JCS(signed_envelope)` with the `touch_cosignatures` field STRIPPED (the
/// same preimage persist's admission re-derives before verifying each
/// co-signature). For a fresh [`build_nofm_primary`] leg the field is
/// already absent, so this is `JCS(signed_envelope)`; the strip keeps the
/// helper correct if called on a partially-attached claim.
///
/// # Errors
/// [`TouchClaimError::Canonicalize`] on a canonicalizer fault.
pub fn cosignature_preimage(claim: &SignedTouchClaim) -> Result<Vec<u8>, TouchClaimError> {
    let mut env = claim.signed_envelope.clone();
    if let Some(obj) = env.as_object_mut() {
        obj.remove(TOUCH_COSIGNATURES_FIELD);
    }
    ceg_produce_canonicalize(&env).map_err(|e| TouchClaimError::Canonicalize(e.to_string()))
}

/// Produce a co-signing node's [`ThresholdSignature`] over `bytes` (the
/// [`cosignature_preimage`] of the primary leg). A co-signing NODE calls
/// this with its OWN [`LocalSigner`]; edge cannot fabricate other nodes'
/// co-signatures, so this is the leg each independent participant computes
/// and hands back for [`attach_cosignatures`]. Hybrid (RequireHybrid at
/// admission) — the co-signer's key must have a registered ML-DSA-65 pubkey.
///
/// # Errors
/// [`TouchClaimError::Sign`] on a signer fault.
pub async fn build_cosignature(
    signer: &LocalSigner,
    bytes: &[u8],
) -> Result<ThresholdSignature, TouchClaimError> {
    let (ed25519_signature_base64, mldsa65_signature_base64) =
        sign_bound_hybrid(signer, bytes).await?;
    Ok(ThresholdSignature {
        member_id: signer.key_id.clone(),
        ed25519_signature_base64,
        mldsa65_signature_base64,
    })
}

/// Attach a co-signature set to an `n_of_m_cosigned` primary leg under the
/// `touch_cosignatures` extra INSIDE `signed_envelope` (the primary
/// signature is unchanged — co-sigs ride outside the bytes they sign).
/// Returns the submittable claim.
///
/// The tally at admission requires
/// ≥[`ciris_persist::federation::freshness::NOFM_MIN_COSIGNERS`] DISTINCT,
/// INDEPENDENT (≠ target), REGISTERED co-signers each hybrid-verifying over
/// [`cosignature_preimage`] — so `cosignatures` must carry at least that
/// many valid legs beyond the primary.
///
/// # Errors
/// [`TouchClaimError::NotNofmCosigned`] if `claim.signer_form` is not
/// [`SignerForm::NOfMCosigned`]; [`TouchClaimError::MalformedEnvelope`] if
/// the envelope is not a JSON object; [`TouchClaimError::Serialize`] on a
/// serde fault.
pub fn attach_cosignatures(
    mut claim: SignedTouchClaim,
    cosignatures: &[ThresholdSignature],
) -> Result<SignedTouchClaim, TouchClaimError> {
    if claim.signer_form != SignerForm::NOfMCosigned {
        return Err(TouchClaimError::NotNofmCosigned);
    }
    let value = serde_json::to_value(cosignatures)
        .map_err(|e| TouchClaimError::Serialize(e.to_string()))?;
    let obj = claim
        .signed_envelope
        .as_object_mut()
        .ok_or(TouchClaimError::MalformedEnvelope)?;
    obj.insert(TOUCH_COSIGNATURES_FIELD.to_owned(), value);
    Ok(claim)
}

/// Submit a produced touch-claim to the freshness floor — a thin wrapper
/// over [`FederationDirectory::put_touch_claim`] that re-validates
/// `cohort_scope` up front (defense-in-depth; a builder never produces an
/// invalid one). [`TouchApplyOutcome::NotFresher`] is a SILENT no-op
/// (anti-rollback), NOT an error — the stored floor only ever advances.
///
/// # Errors
/// [`TouchClaimError::InvalidCohortScope`] if the claim's scope is out of
/// set; [`TouchClaimError::Put`] on any admission/storage failure.
pub async fn submit_touch_claim(
    directory: &dyn FederationDirectory,
    claim: &SignedTouchClaim,
) -> Result<TouchApplyOutcome, TouchClaimError> {
    if !cohort_scope::is_valid(&claim.cohort_scope) {
        return Err(TouchClaimError::InvalidCohortScope(
            claim.cohort_scope.clone(),
        ));
    }
    directory
        .put_touch_claim(claim)
        .await
        .map_err(|e| TouchClaimError::Put(e.to_string()))
}

/// A minimal, opt-in producer bundling the held [`LocalSigner`] with a
/// [`FederationDirectory`] so the runtime can emit touch-claims on its own
/// cadence. **No background scheduler is wired here** (CIRISEdge#411 §2
/// explicitly): these are entrypoints a caller invokes, mirroring how
/// `emit_withdraws` is fired on an observed event rather than a timer.
#[derive(Clone)]
pub struct TouchClaimProducer {
    signer: Arc<LocalSigner>,
    directory: Arc<dyn FederationDirectory>,
    coalesce_secs: i64,
}

impl TouchClaimProducer {
    /// Construct a producer over the held signer + directory, using
    /// [`DEFAULT_TOUCH_COALESCE_SECS`] as the coalescing bucket.
    #[must_use]
    pub fn new(signer: Arc<LocalSigner>, directory: Arc<dyn FederationDirectory>) -> Self {
        Self {
            signer,
            directory,
            coalesce_secs: DEFAULT_TOUCH_COALESCE_SECS,
        }
    }

    /// Override the `fresh_as_of` coalescing bucket (seconds).
    #[must_use]
    pub fn with_coalesce_secs(mut self, coalesce_secs: i64) -> Self {
        self.coalesce_secs = coalesce_secs;
        self
    }

    /// Emit a `self_touch` for this node's own key at `(target_kind,
    /// cohort)`, floored to `now`. The dead-man's-switch entrypoint the
    /// runtime calls on its own cadence.
    ///
    /// # Errors
    /// See [`build_self_touch`] / [`submit_touch_claim`].
    pub async fn produce_self_touch(
        &self,
        target_kind: &str,
        cohort: &str,
    ) -> Result<TouchApplyOutcome, TouchClaimError> {
        let claim = build_self_touch(
            &self.signer,
            target_kind,
            cohort,
            Utc::now(),
            self.coalesce_secs,
        )
        .await?;
        submit_touch_claim(self.directory.as_ref(), &claim).await
    }

    /// The CC 3.2 ownerless-lock reclaim tie-in: an `ownership_binding`
    /// self_touch at [`cohort_scope::SELF`]. A node becomes reclaimable
    /// only after it has emitted such a floor and then gone dark ≥180 days;
    /// **absent floor = never reclaimable** (fail-safe). Make emitting this
    /// easy — it is the load-bearing reason this module exists.
    ///
    /// # Errors
    /// See [`build_self_touch`] / [`submit_touch_claim`].
    pub async fn produce_ownership_self_touch(&self) -> Result<TouchApplyOutcome, TouchClaimError> {
        self.produce_self_touch(OWNERSHIP_FRESHNESS_TARGET_KIND, cohort_scope::SELF)
            .await
    }

    /// Emit a `witness_touch` of `peer_key_id` at `(target_kind, cohort)`
    /// for an observed liveness instant. Scope the witness as tightly as
    /// the relationship allows (self/family) — NEVER an ungated
    /// read-receipt trail.
    ///
    /// # Errors
    /// See [`build_witness_touch`] / [`submit_touch_claim`].
    pub async fn produce_witness_touch(
        &self,
        peer_key_id: &str,
        target_kind: &str,
        cohort: &str,
        observed_at: DateTime<Utc>,
    ) -> Result<TouchApplyOutcome, TouchClaimError> {
        let claim = build_witness_touch(
            &self.signer,
            peer_key_id,
            target_kind,
            cohort,
            observed_at,
            self.coalesce_secs,
        )
        .await?;
        submit_touch_claim(self.directory.as_ref(), &claim).await
    }

    /// Off [`ReachabilityTracker`]: witness `peer_key_id`'s most recent
    /// observed liveness instant (floors `fresh_as_of` from
    /// [`ReachabilityTracker::last_liveness`]). Returns `Ok(None)` — no
    /// touch produced — when the tracker holds no liveness evidence for the
    /// peer (a `witness_touch` requires an actual observed event). The
    /// minimal, opt-in liveness hook edge's runtime calls when it observes
    /// a peer succeed; NOT a background timer.
    ///
    /// # Errors
    /// See [`build_witness_touch`] / [`submit_touch_claim`].
    pub async fn produce_witness_touch_from_tracker(
        &self,
        tracker: &ReachabilityTracker,
        peer_key_id: &str,
        target_kind: &str,
        cohort: &str,
    ) -> Result<Option<TouchApplyOutcome>, TouchClaimError> {
        let Some(observed_at) = tracker.last_liveness(peer_key_id) else {
            return Ok(None);
        };
        let outcome = self
            .produce_witness_touch(peer_key_id, target_kind, cohort, observed_at)
            .await?;
        Ok(Some(outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
    use ciris_persist::store::MemoryBackend;

    /// Deterministic 32-byte seed for `label` — first ≤32 bytes over a
    /// `0x11` fill (matching edge's existing fixture shape).
    fn seed32(label: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in label.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// A hybrid [`LocalSigner`] with deterministic Ed25519 + ML-DSA-65 keys
    /// for `key_id` (real signatures — mirrors `capacity.rs::test_signer`).
    async fn hybrid_signer(key_id: &str) -> Arc<LocalSigner> {
        let ed_seed = seed32(key_id);
        let mut pqc_seed = seed32(key_id);
        pqc_seed[0] ^= 0x55; // distinct from the ed seed
        let classical: Arc<dyn HardwareSigner> = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&ed_seed, key_id).expect("ed25519 from_bytes"),
        );
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&pqc_seed, format!("{key_id}-pqc"))
                .expect("ml_dsa_65 from_seed_bytes"),
        );
        Arc::new(LocalSigner::new(key_id, classical, Some(pqc)))
    }

    /// Register `signer`'s hybrid pubkeys as a federation key so its touch
    /// signatures verify against the pinned directory entry.
    async fn register(backend: &Arc<MemoryBackend>, signer: &LocalSigner) {
        let ed_pub = HardwareSigner::public_key(signer.classical.as_ref())
            .await
            .expect("ed25519 pubkey");
        let pqc_pub = PqcSigner::public_key(signer.pqc.as_ref().expect("has pqc").as_ref())
            .await
            .expect("ml_dsa_65 pubkey");
        let now = Utc::now();
        let record = KeyRecord {
            key_id: signer.key_id.clone(),
            pubkey_ed25519_base64: B64.encode(&ed_pub),
            pubkey_ml_dsa_65_base64: Some(B64.encode(&pqc_pub)),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::NODE.into(),
            identity_ref: format!("node-ref-{}", signer.key_id),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": signer.key_id,
                "identity_type": identity_type::NODE,
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: signer.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("register federation key");
    }

    fn backend() -> Arc<MemoryBackend> {
        Arc::new(MemoryBackend::new())
    }

    // ── round-trip: produced signed_envelope == signing_envelope(), and
    // the signature verifies (proved by admission accepting the put) ──────
    #[tokio::test]
    async fn self_touch_round_trip_signs_and_verifies() {
        let backend = backend();
        let signer = hybrid_signer("rt-self").await;
        register(&backend, &signer).await;

        let observed = Utc::now();
        let claim = build_self_touch(
            &signer,
            OWNERSHIP_FRESHNESS_TARGET_KIND,
            cohort_scope::SELF,
            observed,
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await
        .expect("build self_touch");

        // The stored envelope IS the typed projection's signing_envelope,
        // byte-for-byte (authority-is-the-envelope discipline).
        assert_eq!(claim.signed_envelope, claim.signing_envelope());
        assert_eq!(claim.attesting_key_id, "rt-self");
        assert_eq!(claim.target_key_id, "rt-self");
        assert!(claim.signature.mldsa65_signature_base64.is_some(), "hybrid");

        // A successful put proves the hybrid signature verifies at persist's
        // RequireHybrid 1-of-1 admission gate.
        let dir: Arc<dyn FederationDirectory> = backend;
        let outcome = submit_touch_claim(dir.as_ref(), &claim)
            .await
            .expect("admit self_touch");
        assert_eq!(outcome, TouchApplyOutcome::Advanced);
    }

    // ── put → Advanced, then a same-floored re-put → NotFresher ───────────
    #[tokio::test]
    async fn advanced_then_not_fresher_same_bucket() {
        let backend = backend();
        let signer = hybrid_signer("nf-self").await;
        register(&backend, &signer).await;
        let dir: Arc<dyn FederationDirectory> = backend;

        // Same observed instant → identical floored fresh_as_of → identical
        // signed envelope. First advances the floor; second is a silent
        // no-op (anti-rollback), NOT an error.
        let observed = Utc::now() - Duration::seconds(2);
        let first = build_self_touch(
            &signer,
            NODE_LIVENESS_TARGET_KIND,
            cohort_scope::SELF,
            observed,
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await
        .expect("build first");
        let second = build_self_touch(
            &signer,
            NODE_LIVENESS_TARGET_KIND,
            cohort_scope::SELF,
            observed,
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await
        .expect("build second");
        assert_eq!(
            first.fresh_as_of, second.fresh_as_of,
            "same bucket coalesces"
        );

        assert_eq!(
            submit_touch_claim(dir.as_ref(), &first).await.unwrap(),
            TouchApplyOutcome::Advanced
        );
        assert_eq!(
            submit_touch_claim(dir.as_ref(), &second).await.unwrap(),
            TouchApplyOutcome::NotFresher,
            "an equal fresh_as_of is never fresher (strict > guard) — silent no-op"
        );
    }

    // ── the n_of_m tally: THE regression guard against the stale-docstring
    // trap. A NOfMCosigned touch with primary + a real independent
    // co-signer admits; the same touch WITHOUT the co-sig set is refused ──
    #[tokio::test]
    async fn nofm_cosigned_tally_requires_real_cosigner() {
        let backend = backend();
        // Three DISTINCT identities: the target, the primary attester, the
        // co-signer. Primary + co-signer are both independent of the target.
        let target = hybrid_signer("nofm-target").await;
        let primary = hybrid_signer("nofm-primary").await;
        let cosigner = hybrid_signer("nofm-cosigner").await;
        register(&backend, &target).await;
        register(&backend, &primary).await;
        register(&backend, &cosigner).await;
        let dir: Arc<dyn FederationDirectory> = backend;

        // Primary leg — envelope carries NO touch_cosignatures yet.
        let leg = build_nofm_primary(
            &primary,
            &target.key_id,
            NODE_LIVENESS_TARGET_KIND,
            cohort_scope::FAMILY,
            Utc::now(),
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await
        .expect("build primary leg");
        assert_eq!(leg.attesting_key_id, "nofm-primary");
        assert_ne!(leg.attesting_key_id, leg.target_key_id, "independent");

        // (a) the bare primary leg (no co-sig set) MUST be refused — this is
        // the trap: pre-v21.10.0 docstrings claim it verifies as 1-of-1.
        let bare = submit_touch_claim(dir.as_ref(), &leg).await;
        assert!(
            matches!(bare, Err(TouchClaimError::Put(_))),
            "NOfMCosigned without a co-signature set must be refused, got {bare:?}"
        );

        // (b) primary + a real independent co-signature over the SAME
        // stripped preimage → admitted (proves a genuine ≥2-of-N tally).
        let preimage = cosignature_preimage(&leg).expect("preimage");
        let cosig = build_cosignature(&cosigner, &preimage)
            .await
            .expect("co-sign");
        let submittable = attach_cosignatures(leg.clone(), &[cosig]).expect("attach cosignatures");
        assert_eq!(
            submit_touch_claim(dir.as_ref(), &submittable)
                .await
                .unwrap(),
            TouchApplyOutcome::Advanced,
            "primary + a real independent co-signer must be admitted"
        );

        // (c) a forged co-signature (valid shape, wrong bytes) → refused.
        let forged = attach_cosignatures(
            leg,
            &[ThresholdSignature {
                member_id: "nofm-cosigner".to_owned(),
                ed25519_signature_base64: "AA".to_owned(),
                mldsa65_signature_base64: None,
            }],
        )
        .expect("attach forged");
        let forged_res = submit_touch_claim(dir.as_ref(), &forged).await;
        assert!(
            matches!(forged_res, Err(TouchClaimError::Put(_))),
            "a forged co-signature must be refused, got {forged_res:?}"
        );
    }

    // ── cohort_scope is required + validated (refused BEFORE put) ─────────
    #[tokio::test]
    async fn cohort_scope_out_of_set_refused_before_put() {
        let signer = hybrid_signer("cohort-self").await;

        // "global" is NOT in the closed set — the builder refuses before it
        // ever signs or reaches put_touch_claim.
        let err = build_self_touch(
            &signer,
            NODE_LIVENESS_TARGET_KIND,
            "global",
            Utc::now(),
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await
        .expect_err("global must be refused");
        assert!(matches!(err, TouchClaimError::InvalidCohortScope(s) if s == "global"));

        // Every closed-set value is accepted.
        for scope in [
            cohort_scope::SELF,
            cohort_scope::FAMILY,
            cohort_scope::COMMUNITY,
            cohort_scope::AFFILIATIONS,
            cohort_scope::SPECIES,
            cohort_scope::BIOSPHERE,
            cohort_scope::FEDERATION,
        ] {
            build_self_touch(
                &signer,
                NODE_LIVENESS_TARGET_KIND,
                scope,
                Utc::now(),
                DEFAULT_TOUCH_COALESCE_SECS,
            )
            .await
            .unwrap_or_else(|e| panic!("scope {scope} should build: {e}"));
        }
    }

    // ── fresh_as_of is FLOORED (never > now); witness attester != target ──
    #[tokio::test]
    async fn fresh_as_of_floored_and_witness_independent() {
        // Flooring: a past, non-bucket-aligned instant floors DOWN.
        let observed = DateTime::parse_from_rfc3339("2026-07-01T00:01:37Z")
            .unwrap()
            .with_timezone(&Utc);
        let floored = coalesce_fresh_as_of(observed, 60);
        assert_eq!(
            floored,
            DateTime::parse_from_rfc3339("2026-07-01T00:01:00Z")
                .unwrap()
                .with_timezone(&Utc),
            "37s past the minute floors to the minute boundary"
        );

        // Never ceiling / never future: a far-future observation is capped
        // to now before flooring, so the result never exceeds now.
        let now = Utc::now();
        let future = coalesce_fresh_as_of(now + Duration::hours(1), 60);
        assert!(
            future <= now,
            "a future observation must not push fresh_as_of past now"
        );

        // A produced witness_touch: attester differs from the target, and
        // fresh_as_of is floored below now.
        let witness = hybrid_signer("fresh-witness").await;
        let claim = build_witness_touch(
            &witness,
            "some-peer",
            NODE_LIVENESS_TARGET_KIND,
            cohort_scope::FAMILY,
            Utc::now(),
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await
        .expect("build witness_touch");
        assert_ne!(
            claim.attesting_key_id, claim.target_key_id,
            "witness ≠ target"
        );
        assert_eq!(claim.signer_form, SignerForm::WitnessTouch);
        assert!(claim.fresh_as_of <= Utc::now(), "floored below now");

        // Witnessing one's own key is refused up front.
        let self_witness = build_witness_touch(
            &witness,
            &witness.key_id,
            NODE_LIVENESS_TARGET_KIND,
            cohort_scope::FAMILY,
            Utc::now(),
            DEFAULT_TOUCH_COALESCE_SECS,
        )
        .await;
        assert!(matches!(
            self_witness,
            Err(TouchClaimError::AttesterNotIndependent { .. })
        ));
    }

    // ── the ReachabilityTracker hook: witness from observed liveness ──────
    #[tokio::test]
    async fn producer_witnesses_from_tracker() {
        use crate::reachability::AttemptOutcome;
        use crate::transport::TransportId;

        let backend = backend();
        let witness = hybrid_signer("track-witness").await;
        register(&backend, &witness).await;
        let dir: Arc<dyn FederationDirectory> = backend;
        let producer = TouchClaimProducer::new(witness, dir);

        let tracker = ReachabilityTracker::new(300);

        // No evidence yet → no touch produced.
        let none = producer
            .produce_witness_touch_from_tracker(
                &tracker,
                "peer-xyz",
                NODE_LIVENESS_TARGET_KIND,
                cohort_scope::FAMILY,
            )
            .await
            .expect("no-evidence path");
        assert!(none.is_none(), "no observed liveness → no witness touch");

        // Record a successful attempt → a liveness event to witness.
        tracker.record_attempt("peer-xyz", TransportId::HTTP, AttemptOutcome::SendSuccess);
        let some = producer
            .produce_witness_touch_from_tracker(
                &tracker,
                "peer-xyz",
                NODE_LIVENESS_TARGET_KIND,
                cohort_scope::FAMILY,
            )
            .await
            .expect("witness path");
        assert_eq!(some, Some(TouchApplyOutcome::Advanced));
    }
}
