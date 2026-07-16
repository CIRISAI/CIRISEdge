//! CIRISEdge#345 (ask #3) — edge-tier end-to-end proof of the test-anchor
//! admit→root flow, the same one the mesh-repro harness (CIRISServer#258)
//! exercises, at edge's tier, in CI.
//!
//! Gated on the compile-fenced `test-anchor` feature. Under a SW test trust
//! root supplied via env (CIRISPersist#451: PQC-complete holder + verifiable
//! self-scrub), persist's genesis seeds a fully scrub-VERIFYING
//! `test-accord-holder-0`, and a peer **hybrid-scrubbed by that root** must ROOT
//! (`Confirmed`) through edge's `RootingDirectory::root_binding` — proving the
//! full test model: the SW anchor is a real rooting terminus at edge's tier, not
//! just "the feature compiles and the engine boots."
//!
//! This test mutates process env, so it lives in its own test binary; the
//! `test-anchor` CI lane runs it with `--features test-anchor`.
//!
//! `cargo test --features "transport-reticulum test-anchor" --test test_anchor_e2e`

#![cfg(all(feature = "transport-reticulum", feature = "test-anchor"))]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sha2::{Digest, Sha256};

use ciris_crypto::{ClassicalSigner, Ed25519Signer, HybridSigner, MlDsa65Signer, PqcSigner};
use ciris_edge::verify::{RootingDirectory, RootingVerdict};
use ciris_persist::federation::genesis::test_anchor_genesis_records;
use ciris_persist::federation::{FederationDirectory, KeyRecord, SignedKeyRecord};
use ciris_persist::prelude::FederationDirectorySqlite;
use ciris_persist::verify::canonical::ceg_produce_canonicalize;

/// The CEG-canonical bytes of a registration envelope — the EXACT message a
/// scrub-signature covers (`root_binding` verifies `verify_hybrid(canonical,
/// …)`, empirically the canonical envelope, NOT the hash bytes — CIRISPersist
/// #344). Computed via persist's OWN `ceg_produce_canonicalize`, so what this
/// test signs matches byte-for-byte what rooting verifies.
fn canonical_bytes(envelope: &serde_json::Value) -> Vec<u8> {
    ceg_produce_canonicalize(envelope).expect("ceg canonicalize")
}

#[tokio::test]
async fn test_anchor_peer_roots_through_edge_root_binding() {
    // ── 1. The SW test trust root (hybrid: Ed25519 + ML-DSA-65). ──────────
    let root_ed = Ed25519Signer::from_seed(&[0x11; 32]).expect("root ed25519");
    let root_pqc = MlDsa65Signer::from_seed(&[0x22; 32]).expect("root ml-dsa");
    let root_ed_pub = root_ed.public_key().expect("root ed pub");
    let root_pqc_pub = PqcSigner::public_key(&root_pqc).expect("root pqc pub");
    // The hybrid signer binds the pair exactly as `verify_hybrid` checks it:
    // classical = Sign_ed(data); pqc = Sign_mldsa(data ‖ classical_sig).
    let root_signer = HybridSigner::new(root_ed, root_pqc).expect("hybrid root signer");

    // ── 2. The root's VERIFIABLE self-scrub over test-accord-holder-0's own
    //       CANONICAL envelope (CIRISPersist#451 CIRIS_TEST_TRUST_ROOT_SCRUB*). ─
    let holder_env = serde_json::json!({ "key_id": "test-accord-holder-0", "test_anchor": true });
    let holder_canonical = canonical_bytes(&holder_env);
    let holder_scrub = root_signer
        .sign(&holder_canonical)
        .expect("holder self-scrub");

    // ── 3. Arm the test anchor: the exact runtime contract the harness sets. ─
    std::env::set_var("CIRIS_TESTING_MODE", "true");
    for prod in ["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"] {
        std::env::remove_var(prod); // no production signal, or the tripwire refuses
    }
    std::env::set_var("CIRIS_TEST_TRUST_ROOT", B64.encode(&root_ed_pub));
    std::env::set_var("CIRIS_TEST_TRUST_ROOT_PQC", B64.encode(&root_pqc_pub));
    std::env::set_var(
        "CIRIS_TEST_TRUST_ROOT_SCRUB",
        B64.encode(&holder_scrub.classical.signature),
    );
    std::env::set_var(
        "CIRIS_TEST_TRUST_ROOT_SCRUB_PQC",
        B64.encode(&holder_scrub.pqc.signature),
    );

    // ── 4. persist synthesizes the fully scrub-verifying genesis holder. ─────
    let genesis = test_anchor_genesis_records()
        .expect("test-anchor override must be LIVE (feature on + CIRIS_TESTING_MODE + root)");
    assert!(
        genesis
            .iter()
            .any(|r| r.record.key_id == "test-accord-holder-0"
                && r.record.pubkey_ml_dsa_65_base64.is_some()),
        "genesis must seed a PQC-complete test-accord-holder-0 (CIRISPersist#451)",
    );

    // ── 5. A peer hybrid-scrubbed BY the SW root (= test-accord-holder-0). ────
    let peer_ed = Ed25519Signer::from_seed(&[0x0a; 32]).expect("peer ed25519");
    let peer_pqc = MlDsa65Signer::from_seed(&[0x0b; 32]).expect("peer ml-dsa");
    let peer_ed_pub = peer_ed.public_key().expect("peer ed pub");
    let peer_pqc_pub = PqcSigner::public_key(&peer_pqc).expect("peer pqc pub");
    let peer_env = serde_json::json!({ "key_id": "edge-key-peer" });
    let peer_canonical = canonical_bytes(&peer_env);
    let peer_scrub = root_signer
        .sign(&peer_canonical)
        .expect("peer scrub by root");
    let ts: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
    let peer = KeyRecord {
        key_id: "edge-key-peer".to_string(),
        pubkey_ed25519_base64: B64.encode(&peer_ed_pub),
        pubkey_ml_dsa_65_base64: Some(B64.encode(&peer_pqc_pub)),
        algorithm: "hybrid".to_string(),
        identity_type: "agent".to_string(),
        identity_ref: "edge-key-peer".to_string(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: peer_env,
        original_content_hash: hex::encode(Sha256::digest(&peer_canonical)),
        scrub_signature_classical: B64.encode(&peer_scrub.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&peer_scrub.pqc.signature)),
        scrub_key_id: "test-accord-holder-0".to_string(),
        scrub_timestamp: ts,
        pqc_completed_at: Some(ts),
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    };

    // ── 6. Seed a directory: the genesis holder(s) THEN the peer. ────────────
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory federation directory");
    // Genesis holders go through the dedicated seed path (direct insert), NOT
    // `put_public_key` — an accord_holder row seeded here is the trust ROOT, so
    // it is exempt from the platform-attestation admission a normal put demands.
    backend
        .seed_genesis_accord_holders(&genesis)
        .await
        .expect("seed genesis accord holders");
    backend
        .put_public_key(SignedKeyRecord { record: peer })
        .await
        .expect("put peer");

    // ── 7. Edge's rooting path CONFIRMS the peer through the SW test anchor. ─
    let rooting: Arc<dyn RootingDirectory> = backend;
    let verdict = rooting
        .root_binding("edge-key-peer", &B64.encode(&peer_ed_pub))
        .await;

    match verdict {
        RootingVerdict::Confirmed { chain } => {
            assert!(
                !chain.chain.is_empty(),
                "a confirmed rooting must carry a non-empty provenance chain"
            );
            println!(
                "[test-anchor] PASS — peer `edge-key-peer` ROOTED through the SW test \
                 anchor via edge root_binding ({} link(s) to test-accord-holder-0)",
                chain.chain.len(),
            );
        }
        other @ RootingVerdict::Rejected { .. } => panic!(
            "test-anchor peer MUST root through edge's root_binding — the whole admit→root \
             test model rides on it (CIRISEdge#345 / CIRISPersist#451); got {other:?}",
        ),
    }
}
