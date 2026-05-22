//! AV-42 acceptance gate — a spoofed announce is rejected
//! (CIRISEdge#15 deliverable (b)).
//!
//! **AV-42** — *spoofed transport-identity ↔ federation-key binding*.
//! An adversary announces a federation `key_id` it does not own,
//! paired with an adversary-controlled Reticulum destination. Under
//! v0.3.1's trust-on-first-use a sender calling `send(key_id, ..)`
//! would route the envelope to the adversary. The v0.4.0 cold-start
//! path closes this: the adversary cannot produce a federation-key
//! signature the persist directory will root.
//!
//! This suite asserts the rejection two ways:
//!
//! 1. **`root_binding` rejects the spoofed binding** — an adversary
//!    that signs an attestation for a victim's `key_id` with its own
//!    federation key fails `root_binding` with `PubkeyMismatch`; an
//!    unregistered `key_id` fails with `UnknownKeyId`. (Cold-start
//!    step 2.)
//! 2. **The attestation signature does not verify** — a forged /
//!    tampered attestation signature fails verification against the
//!    directory-confirmed pubkey. (Cold-start step 3.)
//!
//! Together these are the two gates an announce must clear before
//! the resolver records a peer. A spoofed announce fails at gate 1
//! or gate 2 and is dropped — the resolver never records it, so
//! `send(victim_key_id, ..)` surfaces `Unreachable` rather than
//! routing to the adversary.
//!
//! Requires `transport-reticulum`:
//! `cargo test --features transport-reticulum --test reticulum_av42`

#![cfg(feature = "transport-reticulum")]

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::ClassicalSigner;
use ciris_edge::transport::attestation::{
    AnnounceAttestation, AttestationError, AttestationPayload,
};
use ciris_edge::verify::{RootingDirectory, RootingRejection, RootingVerdict};

use common::{directory_with, signed_record, TestFedKey};

/// AV-42 gate 1 — an adversary that signs an attestation for a
/// `key_id` it does not own is rejected by `root_binding`.
///
/// The directory holds `edge-key-victim` registered to the **real**
/// victim's Ed25519 pubkey. The adversary builds an announce claiming
/// `key_id = edge-key-victim` but presents its *own* federation
/// pubkey (it cannot present the victim's — it does not hold the
/// victim's seed). `root_binding(directory, "edge-key-victim",
/// adversary_pubkey)` therefore fails: the claimed pubkey does not
/// match the directory row.
#[tokio::test]
async fn av42_spoofed_key_id_fails_root_binding_pubkey_mismatch() {
    let steward = TestFedKey::new("steward-av42", 0x01);
    let victim = TestFedKey::new("edge-key-victim", 0x0c);
    let adversary = TestFedKey::new("edge-key-adversary", 0xee);

    // Directory: steward bootstrap + the genuine victim row. The
    // adversary is NOT registered (or registered separately — either
    // way it cannot impersonate the victim row).
    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&victim, &steward, "agent"),
    ])
    .await;
    let rooting: std::sync::Arc<dyn RootingDirectory> = directory;

    // The adversary roots the VICTIM's key_id with the ADVERSARY's
    // pubkey — exactly what a spoofed announce attestation carries.
    let verdict = rooting
        .root_binding("edge-key-victim", &adversary.pubkey_b64())
        .await;

    match verdict {
        RootingVerdict::Rejected {
            rejection: RootingRejection::PubkeyMismatch { key_id, .. },
        } => {
            assert_eq!(key_id, "edge-key-victim");
            println!(
                "[AV-42] PASS gate 1 — spoofed announce for `edge-key-victim` \
                 paired with the adversary's pubkey rejected: \
                 rooting_pubkey_mismatch"
            );
        }
        other => panic!("AV-42 regression: spoofed binding was not rejected: {other:?}"),
    }
}

/// AV-42 gate 1 — an announce for a `key_id` that does not exist in
/// the directory at all is rejected with `UnknownKeyId`.
#[tokio::test]
async fn av42_unregistered_key_id_fails_root_binding_unknown() {
    let steward = TestFedKey::new("steward-av42-u", 0x02);
    let directory = directory_with(vec![signed_record(&steward, &steward, "steward")]).await;
    let rooting: std::sync::Arc<dyn RootingDirectory> = directory;

    let verdict = rooting
        .root_binding(
            "edge-key-ghost",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .await;

    assert!(
        matches!(
            verdict,
            RootingVerdict::Rejected {
                rejection: RootingRejection::UnknownKeyId { .. }
            }
        ),
        "AV-42 regression: an unregistered key_id must reject UnknownKeyId, got {verdict:?}",
    );
    println!(
        "[AV-42] PASS gate 1 — unregistered `edge-key-ghost` rejected: rooting_unknown_key_id"
    );
}

/// AV-42 gate 2 — even when the federation key roots, a forged /
/// tampered attestation signature does not verify.
///
/// This is the second cold-start gate: an adversary who somehow
/// presented a *registered* `key_id` + matching pubkey (gate 1
/// passes) still must produce a valid federation-key signature over
/// `{transport_identity_pubkey, key_id, epoch}`. Without the seed it
/// cannot — a tampered signature, or a signature over different
/// content, fails here.
#[tokio::test]
async fn av42_tampered_attestation_signature_fails_verify() {
    let victim = TestFedKey::new("edge-key-victim2", 0x0d);
    let victim_signer = ciris_crypto::Ed25519Signer::from_seed(&[0x0d; 32]).unwrap();
    let victim_pubkey: [u8; 32] = victim_signer.public_key().unwrap().try_into().unwrap();
    let transport_pubkey = [0x5a; 32];

    // A genuine attestation the victim itself would publish.
    let payload = AttestationPayload::new(&transport_pubkey, &victim.key_id, 3);
    let genuine_sig = victim_signer.sign(&payload.canonical_bytes()).unwrap();

    let genuine = AnnounceAttestation {
        transport_identity_pubkey: B64.encode(transport_pubkey),
        federation_key_id: victim.key_id.clone(),
        federation_pubkey_ed25519_base64: B64.encode(victim_pubkey),
        epoch: 3,
        signature: B64.encode(&genuine_sig),
    };
    // Sanity: the genuine attestation verifies.
    genuine
        .verify_signature(&victim_pubkey)
        .expect("genuine attestation must verify");

    // Spoof A — the adversary keeps the victim's key_id + pubkey but
    // swaps in an adversary-controlled transport identity. The
    // signature still covers the OLD transport pubkey, so it no
    // longer matches the announced binding.
    let mut swapped_transport = genuine.clone();
    swapped_transport.transport_identity_pubkey = B64.encode([0xad; 32]);
    assert!(
        matches!(
            swapped_transport.verify_signature(&victim_pubkey),
            Err(AttestationError::SignatureMismatch)
        ),
        "AV-42 regression: a swapped transport identity must fail attestation verify",
    );

    // Spoof B — a single flipped signature byte.
    let mut flipped = genuine.clone();
    let mut sig = genuine_sig.clone();
    sig[10] ^= 0xff;
    flipped.signature = B64.encode(&sig);
    assert!(
        matches!(
            flipped.verify_signature(&victim_pubkey),
            Err(AttestationError::SignatureMismatch)
        ),
        "AV-42 regression: a tampered signature must fail attestation verify",
    );

    // Spoof C — the adversary re-signs the binding with its OWN key.
    // Verified against the victim's directory-confirmed pubkey it
    // fails: the adversary's signature is not the victim's.
    let foe_key = ciris_crypto::Ed25519Signer::from_seed(&[0xee; 32]).unwrap();
    let foe_signature = foe_key.sign(&payload.canonical_bytes()).unwrap();
    let mut foe_attestation = genuine.clone();
    foe_attestation.signature = B64.encode(&foe_signature);
    assert!(
        matches!(
            foe_attestation.verify_signature(&victim_pubkey),
            Err(AttestationError::SignatureMismatch)
        ),
        "AV-42 regression: an adversary-key signature must fail against the victim's pubkey",
    );

    println!(
        "[AV-42] PASS gate 2 — swapped-transport, tampered-signature, and \
         adversary-signed attestations all rejected: attestation signature \
         verification failed"
    );
}
