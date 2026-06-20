//! v6.0.0 (CIRISEdge#175, FSD §3.3) — Welcome wrap end-to-end.
//!
//! Inviter wraps an MLS Welcome to the invitee via HPKE-Base over
//! the invitee's static X-Wing public key + ML-DSA-65 sender
//! authentication signature over `encap_signing_bytes`. The
//! invitee verifies the signature BEFORE HPKE open_base; tampered
//! signatures are structurally rejected.

#![allow(clippy::similar_names)]

use ciris_crypto::hpke::{XWingRecipientPublic, XWingRecipientSecret};
use ciris_crypto::{ml_kem, x25519, MlDsa65Signer, PqcSigner};
use ciris_edge::{unwrap_welcome, wrap_welcome, FederationDirectoryEntry, WelcomeWrapError};

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
fn wrap_and_unwrap_round_trip() {
    let inviter = MlDsa65Signer::new().unwrap();
    let (invitee_pk, invitee_sk) = fresh_invitee();
    let welcome = b"MLS Welcome bytes (test stub)";

    let wrapped = wrap_welcome(
        &inviter,
        "inviter-fingerprint-A",
        &invitee_pk,
        welcome,
        b"group-id-42",
    )
    .unwrap();

    // Directory lookup returns None — falls back to inline pk.
    let opened = unwrap_welcome(&invitee_sk, &wrapped, b"group-id-42", |_| None).unwrap();
    assert_eq!(opened, welcome);
}

#[test]
fn signature_verification_is_precondition_to_open() {
    // FSD §3.3 acceptance — implementations MUST verify the inviter
    // signature on `encap_signing_bytes` before opening HPKE.
    let inviter = MlDsa65Signer::new().unwrap();
    let (invitee_pk, invitee_sk) = fresh_invitee();
    let welcome = b"sender-authed Welcome";
    let mut wrapped = wrap_welcome(&inviter, "inv-1", &invitee_pk, welcome, b"").unwrap();

    // Flip a byte of the inviter signature.
    wrapped.inviter_signature[0] ^= 0x01;

    let err = unwrap_welcome(&invitee_sk, &wrapped, b"", |_| None).unwrap_err();
    assert!(
        matches!(err, WelcomeWrapError::SignatureRejected),
        "tampered inviter signature MUST be rejected"
    );
}

#[test]
fn directory_resolved_pk_takes_precedence_over_inline() {
    let inviter = MlDsa65Signer::new().unwrap();
    let (invitee_pk, invitee_sk) = fresh_invitee();
    let welcome = b"directory-bound Welcome";
    let wrapped = wrap_welcome(&inviter, "inviter-id-real", &invitee_pk, welcome, b"").unwrap();

    let entry = FederationDirectoryEntry {
        pk_id: "inviter-id-real".into(),
        ml_dsa_pk: inviter.public_key().unwrap(),
        x_wing_pk: None,
    };
    let opened = unwrap_welcome(&invitee_sk, &wrapped, b"", |id| {
        if id == "inviter-id-real" {
            Some(entry.clone())
        } else {
            None
        }
    })
    .unwrap();
    assert_eq!(opened, welcome);
}

#[test]
fn directory_substitution_attack_is_rejected() {
    // If a directory hands back the WRONG inviter pk, the signature
    // fails — the directory cannot trick the invitee into accepting
    // a substituted Welcome.
    let inviter = MlDsa65Signer::new().unwrap();
    let attacker = MlDsa65Signer::new().unwrap();
    let (invitee_pk, invitee_sk) = fresh_invitee();
    let welcome = b"substitution-attack target";
    let wrapped = wrap_welcome(&inviter, "inv-real", &invitee_pk, welcome, b"").unwrap();

    let bad_entry = FederationDirectoryEntry {
        pk_id: "inv-real".into(),
        ml_dsa_pk: attacker.public_key().unwrap(),
        x_wing_pk: None,
    };
    let err = unwrap_welcome(&invitee_sk, &wrapped, b"", |_| Some(bad_entry.clone())).unwrap_err();
    assert!(matches!(err, WelcomeWrapError::SignatureRejected));
}

#[test]
fn aad_mismatch_fails_open_after_signature_verifies() {
    // The signature only covers encap bytes (FSD §3.3), so an aad
    // mismatch passes signature but fails HPKE open — surfaces as
    // CryptoError.
    let inviter = MlDsa65Signer::new().unwrap();
    let (invitee_pk, invitee_sk) = fresh_invitee();
    let welcome = b"aad-bound Welcome";
    let wrapped = wrap_welcome(&inviter, "inv-aad", &invitee_pk, welcome, b"aad-A").unwrap();

    let err = unwrap_welcome(&invitee_sk, &wrapped, b"aad-B", |_| None).unwrap_err();
    assert!(matches!(err, WelcomeWrapError::Crypto(_)));
}
