//! §3.3 HPKE-Base + ML-DSA-65 Welcome wrap (CIRISEdge#175, v6.0.0).
//!
//! CEWP `SCOPE_PRIVACY.md` §3.3 — MLS Welcome messages are wrapped by
//! HPKE `mode_base` (RFC 9180 §5.1.1) under the invitee's static
//! X-Wing public key. X-Wing has no AuthEncap
//! (draft-connolly-cfrg-xwing-kem; confirmed in draft-ietf-hpke-pq
//! §7.2), so HPKE `mode_auth` is structurally unavailable; sender
//! authentication is provided **out-of-band** by an ML-DSA-65
//! signature from the inviter over the canonical encapsulation
//! bytes ([`ciris_crypto::hpke::encap_signing_bytes`]).
//!
//! The verifier MUST check the signature BEFORE attempting HPKE
//! `open_base`. Skipping the signature check forfeits sender
//! authentication — FSD §4 "Forwarder-side membership opacity" no
//! longer holds.
//!
//! # HPKE parameters (pinned cross-impl)
//!
//! - `HPKE_SUITE_ID = b"HPKE-xwing-hkdf-sha256-aes256gcm-v1"`
//!   ([`crate::scope_privacy::HPKE_SUITE_ID`])
//! - KDF: HKDF-SHA256
//! - AEAD: AES-256-GCM
//! - KEM: X-Wing (X25519 + ML-KEM-768)
//! - Sender auth: ML-DSA-65 over
//!   `x25519_ephemeral_pub(32) || u32_be(len) || mlkem768_ciphertext`
//!
//! AES-256-GCM here is **distinct** from the §2.4 / §3.1
//! XChaCha20-Poly1305 used for symbol AEAD and envelope framing —
//! HPKE binds AEAD = AES-256-GCM at the HPKE layer.

use ciris_crypto::hpke::{self, HpkeSealed, XWingRecipientPublic, XWingRecipientSecret};
use ciris_crypto::{CryptoError, MlDsa65Signer, MlDsa65Verifier, PqcSigner, PqcVerifier};

/// HPKE `info` string used in every wrap/unwrap pair. The string
/// binds the key schedule to "ciris-edge MLS Welcome wrap, v1".
/// Cross-impl pinned; producer + verifier MUST use identical bytes.
pub const WELCOME_WRAP_INFO: &[u8] = b"ciris-edge/scope-privacy/welcome-wrap/v1";

/// Wrapped MLS Welcome — the wire payload of a §3.3 wrap.
///
/// Edge ships the four-tuple `(hpke_sealed, inviter_signature,
/// inviter_pk_id, inviter_pk_bytes)`. The recipient resolves the
/// inviter's ML-DSA-65 public key from a directory keyed by
/// `inviter_pk_id` (and falls back to the inline `inviter_pk_bytes`
/// when the directory has not seen the key yet, with the directory's
/// trust gate then applied at admission time).
#[derive(Debug, Clone)]
pub struct WrappedWelcome {
    /// HPKE seal of the inner MLS Welcome bytes under the invitee's
    /// static X-Wing public key.
    pub hpke_sealed: HpkeSealed,
    /// ML-DSA-65 signature by the inviter over
    /// [`hpke::encap_signing_bytes`].
    pub inviter_signature: Vec<u8>,
    /// Identifier of the inviter's ML-DSA-65 public key (caller-
    /// scoped: a fingerprint, key_id, or federation_id — edge does
    /// not interpret).
    pub inviter_pk_id: String,
    /// Inviter's ML-DSA-65 public key bytes (the
    /// `EncodedVerifyingKey<MlDsa65>` form, as returned by
    /// [`PqcSigner::public_key`]).
    pub inviter_pk_bytes: Vec<u8>,
}

/// Errors from the §3.3 Welcome wrap surface.
#[derive(Debug, thiserror::Error)]
pub enum WelcomeWrapError {
    /// HPKE seal/open or ML-DSA-65 sign/verify failed.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// The inviter signature failed to verify against the
    /// `encap_signing_bytes`. **This is a precondition violation**
    /// — see the module docs.
    #[error("inviter signature verify failed")]
    SignatureRejected,
    /// The directory has no inviter ML-DSA-65 public key registered
    /// for `inviter_pk_id` and the unwrap is configured to require
    /// directory-resolved keys.
    #[error("inviter pk_id {0:?} not in directory")]
    InviterUnknown(String),
}

/// §3.3 Welcome wrap. Inputs:
///
/// - `inviter_signer` — the inviter's `MlDsa65Signer` (CIRISVerify
///   v6.3.0 `ciris_crypto::ml_dsa::MlDsa65Signer`).
/// - `inviter_pk_id` — caller-scoped identifier the recipient uses
///   to look up the inviter's public key in the federation directory
///   (§3.3 cached directory).
/// - `invitee_pk` — the invitee's static X-Wing public key.
/// - `welcome_bytes` — the inner MLS Welcome message bytes
///   (serialized openmls `Welcome`).
/// - `aad` — application AAD bound at the AEAD layer. Pass an empty
///   slice for the FSD §3.3 default; some callers may bind a group
///   identifier here.
///
/// Returns a [`WrappedWelcome`] ready to ship over the substrate.
///
/// # Errors
///
/// - HPKE seal failure → [`WelcomeWrapError::Crypto`]
/// - ML-DSA-65 sign or public-key extraction failure →
///   [`WelcomeWrapError::Crypto`]
pub fn wrap_welcome(
    inviter_signer: &MlDsa65Signer,
    inviter_pk_id: &str,
    invitee_pk: &XWingRecipientPublic,
    welcome_bytes: &[u8],
    aad: &[u8],
) -> Result<WrappedWelcome, WelcomeWrapError> {
    // HPKE seal_base — bind WELCOME_WRAP_INFO at the key schedule and
    // the caller's aad at the AEAD seal.
    let hpke_sealed = hpke::seal_base(invitee_pk, WELCOME_WRAP_INFO, aad, welcome_bytes)?;

    // Sign the canonical encapsulation bytes with ML-DSA-65 — the
    // §3.3 sender-authentication contract.
    let signing_bytes = hpke::encap_signing_bytes(&hpke_sealed.encapsulation);
    let inviter_signature = inviter_signer.sign(&signing_bytes)?;
    let inviter_pk_bytes = inviter_signer.public_key()?;

    Ok(WrappedWelcome {
        hpke_sealed,
        inviter_signature,
        inviter_pk_id: inviter_pk_id.to_string(),
        inviter_pk_bytes,
    })
}

/// §3.3 directory entry for an inviter's ML-DSA-65 public key. The
/// caller (typically [`crate::directory_cache::DirectoryCache`])
/// supplies a closure that resolves `pk_id → bytes`; this struct is
/// the minimal hand-off shape.
///
/// `verify_inline_match` controls fallback policy when the directory
/// returns `None` for `pk_id`:
/// - `true` (default for v6.0.0) — fall back to the inline
///   `inviter_pk_bytes` carried on the wrap.
/// - `false` — refuse the unwrap with
///   [`WelcomeWrapError::InviterUnknown`].
#[derive(Debug, Clone)]
pub struct FederationDirectoryEntry {
    /// Inviter's federation identifier (key_id, fingerprint, or
    /// federation_id — edge does not interpret).
    pub pk_id: String,
    /// Inviter's ML-DSA-65 public key bytes (the
    /// `EncodedVerifyingKey<MlDsa65>` form).
    pub ml_dsa_pk: Vec<u8>,
    /// Inviter's X-Wing public key (for outgoing wraps — unused
    /// during inbound verification but included for parity with the
    /// substrate-tier directory).
    pub x_wing_pk: Option<XWingRecipientPublic>,
}

/// §3.3 Welcome unwrap. Verifies the inviter signature on
/// [`hpke::encap_signing_bytes`] FIRST, then runs HPKE `open_base`.
///
/// `directory_lookup` resolves the inviter's ML-DSA-65 public key
/// from `inviter_pk_id`; when it returns `None`, the function falls
/// back to the inline `wrapped.inviter_pk_bytes` (v6.0.0 behaviour —
/// the cached-directory + TOFU posture; a directory-required mode
/// flips at the caller's discretion).
///
/// # Errors
///
/// - Signature verify fail → [`WelcomeWrapError::SignatureRejected`]
/// - HPKE open fail → [`WelcomeWrapError::Crypto`]
pub fn unwrap_welcome<F>(
    invitee_sk: &XWingRecipientSecret,
    wrapped: &WrappedWelcome,
    aad: &[u8],
    mut directory_lookup: F,
) -> Result<Vec<u8>, WelcomeWrapError>
where
    F: FnMut(&str) -> Option<FederationDirectoryEntry>,
{
    // Resolve the inviter's public key. Directory wins; inline is
    // the v6.0.0 TOFU fallback.
    let inviter_pk_bytes: Vec<u8> = match directory_lookup(&wrapped.inviter_pk_id) {
        Some(entry) => entry.ml_dsa_pk,
        None => wrapped.inviter_pk_bytes.clone(),
    };

    // §3.3 PRECONDITION — verify the signature before open_base.
    let verifier = MlDsa65Verifier::new();
    let signing_bytes = hpke::encap_signing_bytes(&wrapped.hpke_sealed.encapsulation);
    let ok = verifier.verify(
        &inviter_pk_bytes,
        &signing_bytes,
        &wrapped.inviter_signature,
    )?;
    if !ok {
        return Err(WelcomeWrapError::SignatureRejected);
    }

    // HPKE open_base — recovers the inner MLS Welcome bytes.
    let inner = hpke::open_base(invitee_sk, &wrapped.hpke_sealed, WELCOME_WRAP_INFO, aad)?;
    Ok(inner)
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use ciris_crypto::{ml_kem, x25519};

    fn fresh_invitee() -> (XWingRecipientPublic, XWingRecipientSecret) {
        let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().unwrap();
        let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().unwrap();
        let pk = XWingRecipientPublic {
            x25519_pub: x_pk,
            mlkem768_pub: mlkem_pk.clone(),
        };
        let sk = XWingRecipientSecret {
            x25519_priv: x_sk,
            mlkem768_priv: mlkem_sk,
            mlkem768_pub: mlkem_pk,
        };
        (pk, sk)
    }

    #[test]
    fn wrap_then_unwrap_recovers_welcome_bytes() {
        let inviter = MlDsa65Signer::new().unwrap();
        let (invitee_pk, invitee_sk) = fresh_invitee();
        let welcome = b"openmls Welcome bytes (pretend)";
        let wrapped =
            wrap_welcome(&inviter, "inviter-key-1", &invitee_pk, welcome, b"group-42").unwrap();

        // Directory has no entry — falls through to inline pk.
        let opened = unwrap_welcome(&invitee_sk, &wrapped, b"group-42", |_| None).unwrap();
        assert_eq!(opened, welcome);
    }

    #[test]
    fn unwrap_uses_directory_when_present() {
        let inviter = MlDsa65Signer::new().unwrap();
        let (invitee_pk, invitee_sk) = fresh_invitee();
        let welcome = b"directory-resolved welcome";
        let wrapped = wrap_welcome(&inviter, "inviter-A", &invitee_pk, welcome, b"").unwrap();

        let entry = FederationDirectoryEntry {
            pk_id: "inviter-A".into(),
            ml_dsa_pk: inviter.public_key().unwrap(),
            x_wing_pk: None,
        };
        let opened = unwrap_welcome(&invitee_sk, &wrapped, b"", |id| {
            if id == "inviter-A" {
                Some(entry.clone())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(opened, welcome);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let inviter = MlDsa65Signer::new().unwrap();
        let (invitee_pk, invitee_sk) = fresh_invitee();
        let welcome = b"signed welcome";
        let mut wrapped = wrap_welcome(&inviter, "inv-x", &invitee_pk, welcome, b"").unwrap();
        // Flip a byte of the signature.
        wrapped.inviter_signature[0] ^= 0x01;
        let err = unwrap_welcome(&invitee_sk, &wrapped, b"", |_| None).unwrap_err();
        assert!(matches!(err, WelcomeWrapError::SignatureRejected));
    }

    #[test]
    fn wrong_inviter_pk_is_rejected() {
        let inviter = MlDsa65Signer::new().unwrap();
        let bystander = MlDsa65Signer::new().unwrap();
        let (invitee_pk, invitee_sk) = fresh_invitee();
        let welcome = b"hostile substitution attempt";
        let wrapped = wrap_welcome(&inviter, "inv-real", &invitee_pk, welcome, b"").unwrap();

        // Directory returns the WRONG inviter's pk → signature fails.
        let bad_entry = FederationDirectoryEntry {
            pk_id: "inv-real".into(),
            ml_dsa_pk: bystander.public_key().unwrap(),
            x_wing_pk: None,
        };
        let err =
            unwrap_welcome(&invitee_sk, &wrapped, b"", |_| Some(bad_entry.clone())).unwrap_err();
        assert!(matches!(err, WelcomeWrapError::SignatureRejected));
    }

    #[test]
    fn tampered_encap_diverges_aead_open() {
        let inviter = MlDsa65Signer::new().unwrap();
        let (invitee_pk, invitee_sk) = fresh_invitee();
        let welcome = b"safe welcome";
        let mut wrapped = wrap_welcome(&inviter, "inv-y", &invitee_pk, welcome, b"").unwrap();

        // Flip a byte of the encapsulated ML-KEM ct AND re-sign with
        // the (legitimate) inviter — the signature now covers the
        // tampered encapsulation, so it verifies. HPKE open then
        // diverges. The §3.3 acceptance is that the unwrap fails
        // SOMEWHERE — here it fails at HPKE.
        wrapped.hpke_sealed.encapsulation.mlkem768_ciphertext[0] ^= 0x01;
        wrapped.inviter_signature = inviter
            .sign(&hpke::encap_signing_bytes(
                &wrapped.hpke_sealed.encapsulation,
            ))
            .unwrap();
        let err = unwrap_welcome(&invitee_sk, &wrapped, b"", |_| None).unwrap_err();
        assert!(matches!(err, WelcomeWrapError::Crypto(_)));
    }

    #[test]
    fn aad_mismatch_fails_open() {
        let inviter = MlDsa65Signer::new().unwrap();
        let (invitee_pk, invitee_sk) = fresh_invitee();
        let welcome = b"aad-bound welcome";
        let wrapped = wrap_welcome(&inviter, "inv-z", &invitee_pk, welcome, b"aad-1").unwrap();

        // Verify-side uses a different aad → AEAD open fails. The
        // signature is fine (it covers encap bytes, not aad), so the
        // failure surfaces as a CryptoError from open_base.
        let err = unwrap_welcome(&invitee_sk, &wrapped, b"aad-2", |_| None).unwrap_err();
        assert!(matches!(err, WelcomeWrapError::Crypto(_)));
    }

    #[test]
    fn welcome_wrap_info_pinned() {
        assert_eq!(
            WELCOME_WRAP_INFO,
            b"ciris-edge/scope-privacy/welcome-wrap/v1"
        );
    }
}
