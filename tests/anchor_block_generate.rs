//! Generate the `CIRIS_TEST_TRUST_ROOT*` block against THIS crate's pinned
//! persist + verify, and print it for `bench-mesh/compose.yaml`.
//!
//! CIRISServer publishes a block generated against ITS pins. The values are
//! byte-identical to transcribe, but the scrub signatures are over persist's
//! SYNTHESIZED envelope, so they only verify under the persist/verify pair they
//! were minted against. Transcribing them into edge produced a terminus whose
//! own self-scrub did not verify — "classical scrub-signature did not verify" —
//! and therefore a chain that never rooted.
//!
//! Run: `cargo test --test anchor_block_generate --features test-anchor -- --nocapture`
#![cfg(feature = "test-anchor")]

use base64::Engine as _;

#[test]
fn print_the_anchor_block_for_compose() {
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

    let b64 = base64::engine::general_purpose::STANDARD;
    let seed_b64 = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
    let ed_seed: [u8; 32] = b64.decode(seed_b64).unwrap().try_into().unwrap();

    // SAME derivation as CIRISServer's `examples/test_anchor_env` — one seed
    // feeds both halves of the hybrid root.
    let ml_seed: [u8; 32] = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(ed_seed);
        h.finalize().into()
    };
    let ed = Ed25519Signer::from_seed(&ed_seed).unwrap();
    let mldsa = MlDsa65Signer::from_seed(&ml_seed).unwrap();
    let ed_pub = b64.encode(ed.public_key().unwrap());
    let ml_pub = b64.encode(mldsa.public_key().unwrap());

    // PERSIST's synthesized envelope — not a local restatement of it. This is
    // the preimage the genesis record carries and the walk verifies over, so it
    // must come from the same crate that will later rebuild it.
    let envelope = ciris_persist::federation::genesis::test_anchor_registration_envelope(
        "test-accord-holder-0",
        &ed_pub,
        Some(&ml_pub),
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).unwrap();

    // sign_bound: Ed25519 over the canonical bytes, ML-DSA over `canonical ‖ ed_sig`.
    let ed_sig = ed.sign(&canonical).unwrap();
    let mut bound = canonical.clone();
    bound.extend_from_slice(&ed_sig);
    let ml_sig = mldsa.sign(&bound).unwrap();

    println!("\n  CIRIS_TESTING_MODE: \"true\"");
    println!("  CIRIS_TEST_TRUST_ROOT: \"{ed_pub}\"");
    println!("  CIRIS_TEST_TRUST_ROOT_PQC: \"{ml_pub}\"");
    println!("  CIRIS_TEST_TRUST_ROOT_SCRUB: \"{}\"", b64.encode(&ed_sig));
    println!(
        "  CIRIS_TEST_TRUST_ROOT_SCRUB_PQC: \"{}\"",
        b64.encode(&ml_sig)
    );
    println!("  CIRIS_TEST_TRUST_ROOT_SEED: \"{seed_b64}\"\n");
}
