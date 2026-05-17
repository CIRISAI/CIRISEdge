//! Identity binding — Reticulum address ↔ persist steward seed.
//!
//! Mission: bind the peer's network address to its persist-managed
//! cryptographic identity, with the seed never crossing the FFI
//! boundary. PoB §3.2: addressing IS identity — the Reticulum
//! destination is `sha256(public_key)[..16]`, computed from the same
//! key that signs `federation_keys` rows in persist.
//! ([`MISSION.md`](../../MISSION.md) §2 `identity/`.)
//!
//! The seed lives in persist's keyring (CIRISPersist v0.1.3+ AV-25
//! closure; OS-keyring backed by TPM / Secure Enclave / StrongBox
//! depending on tier). Edge holds `Arc<dyn HardwareSigner>` +
//! optional `Arc<dyn PqcSigner>` and calls into them for sign
//! operations. The seed bytes never enter edge's process memory;
//! AV-17 heap-scan property test enforces this empirically.

use std::sync::Arc;

use base64::Engine as _;
use chrono::Utc;
use ciris_keyring::{HardwareSigner, PqcSigner};
use serde::Serialize;
use uuid::Uuid;

use crate::messages::{EdgeEnvelope, MessageType, SchemaVersion};

/// Edge's local signing identity — the process-bound wrapper around
/// ciris-keyring's classical and (optional) PQC signers. Used by
/// `Edge::send` and `Edge::send_durable` to assemble + sign outbound
/// envelopes.
///
/// Naming: "local" describes the wrapper's process scope; the
/// IDENTITY the keys represent (steward / agent / registry / edge per
/// `federation_keys.identity_type`) is a separate concept. Matches
/// persist v1.4.0's `steward_*→local_*` rename (CIRISPersist#51).
pub struct LocalSigner {
    /// Edge's `federation_keys.key_id` — embedded as `signing_key_id`
    /// on outbound envelopes.
    pub key_id: String,
    pub classical: Arc<dyn HardwareSigner>,
    /// `None` during hybrid-pending bootstrap; `Some` once the
    /// `pqc_completed_at` row is filled in.
    pub pqc: Option<Arc<dyn PqcSigner>>,
}

/// Build an unsigned envelope around a typed message body. The
/// returned envelope has placeholder empty signatures; pass to
/// [`sign_envelope`] before transport.
pub fn build_envelope<M: Serialize>(
    message_type: MessageType,
    signing_key_id: &str,
    destination_key_id: &str,
    body: &M,
    in_reply_to: Option<[u8; 32]>,
) -> Result<EdgeEnvelope, crate::EdgeError> {
    let body_value = serde_json::to_value(body)
        .map_err(|e| crate::EdgeError::Config(format!("body serialize: {e}")))?;
    let body_raw = serde_json::value::to_raw_value(&body_value)
        .map_err(|e| crate::EdgeError::Config(format!("body raw: {e}")))?;

    Ok(EdgeEnvelope {
        edge_schema_version: SchemaVersion::V1_0_0,
        signing_key_id: signing_key_id.to_string(),
        destination_key_id: destination_key_id.to_string(),
        message_type,
        sent_at: Utc::now(),
        nonce: random_nonce(),
        body: body_raw,
        signature: String::new(),
        signature_pqc: None,
        in_reply_to,
    })
}

/// Sign an envelope in-place. Computes canonical bytes via persist's
/// `canonicalize_envelope_for_signing` (CIRISPersist#7 closure),
/// signs with Ed25519 (mandatory) and ML-DSA-65 (when available).
pub async fn sign_envelope(
    signer: &LocalSigner,
    envelope: &mut EdgeEnvelope,
) -> Result<(), crate::EdgeError> {
    let envelope_value = serde_json::to_value(&*envelope)
        .map_err(|e| crate::EdgeError::Config(format!("envelope to_value: {e}")))?;
    let canonical = ciris_persist::prelude::canonicalize_envelope_for_signing(&envelope_value)
        .map_err(|e| crate::EdgeError::Config(format!("canonicalize: {e}")))?;

    // Ed25519 sign (mandatory; AV-9 P0 invariant on the inbound side
    // means every legit message must have one).
    let ed25519_sig_bytes = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| crate::EdgeError::Persist(format!("classical sign: {e}")))?;
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(&ed25519_sig_bytes);

    // ML-DSA-65 sign (optional during hybrid-pending; required after).
    // Per persist's AV-33 bound-signature pattern: PQC signs
    // canonical_bytes || classical_sig (not just canonical_bytes) so
    // signature stripping doesn't degrade hybrid → classical-only.
    if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed25519_sig_bytes);
        let pqc_sig_bytes = pqc
            .sign(&bound)
            .await
            .map_err(|e| crate::EdgeError::Persist(format!("pqc sign: {e}")))?;
        envelope.signature_pqc =
            Some(base64::engine::general_purpose::STANDARD.encode(&pqc_sig_bytes));
    }

    Ok(())
}

/// Generate a 16-byte cryptographically random nonce. Used for the
/// `(signing_key_id, nonce)` replay-window key (AV-3).
fn random_nonce() -> [u8; 16] {
    let uuid = Uuid::new_v4();
    *uuid.as_bytes()
}

/// Compute the body sha256 — single-source-of-truth via persist's
/// `body_sha256` helper. Used as the forensic join key + the
/// `in_reply_to` ACK match key (FSD/EDGE_OUTBOUND_QUEUE.md §5).
pub fn envelope_body_sha256(envelope: &EdgeEnvelope) -> [u8; 32] {
    ciris_persist::prelude::body_sha256(&envelope.body)
}
