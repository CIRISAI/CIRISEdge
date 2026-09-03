//! Why does a harness node root `Advisory` instead of `Rooted`?
//!
//! The mesh reported `resolved_provenance=Advisory, resolved_owns_key=true` on
//! every inbound frame, which makes the E3 gate refuse to attribute any of them
//! and stops the Attestation plane dead. Six mesh runs were spent proposing
//! causes for that at ~15 minutes each.
//!
//! This reproduces the ACTUAL walk — persist's `root_binding` against a
//! directory seeded exactly as the harness seeds one — in about a second, and
//! prints the rejection rather than leaving it to be inferred.

#![cfg(feature = "test-anchor")]

use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use ciris_persist::prelude::KeyRecord;
use ciris_persist::store::MemoryBackend;
use sha2::Digest as _;
use std::sync::Arc;

const ROOT: &str = "test-accord-holder-0";
const SEED_B64: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

fn b64() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// The harness's own root signer: Ed25519 from the seed, ML-DSA derived the way
/// `examples/test_anchor_env` derives it.
fn root_signer() -> ciris_edge::identity::LocalSigner {
    let seed: [u8; 32] = b64().decode(SEED_B64).unwrap().try_into().unwrap();
    let ml_seed: [u8; 32] = {
        let mut h = sha2::Sha256::new();
        h.update(b"ciris-test-trust-root/mldsa/v1");
        h.update(seed);
        h.finalize().into()
    };
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&seed, ROOT).unwrap());
    let pqc: Arc<dyn PqcSigner> =
        Arc::new(MlDsa65SoftwareSigner::from_seed_bytes(&ml_seed, format!("{ROOT}-pqc")).unwrap());
    ciris_edge::identity::LocalSigner::new(ROOT, classical, Some(pqc))
}

/// Byte-for-byte the harness's `signed_record`.
async fn signed_record(
    subject: &str,
    ed_pub: &str,
    pqc_pub: &str,
    signer: &ciris_edge::identity::LocalSigner,
    signer_key_id: &str,
    identity_type: &str,
) -> KeyRecord {
    // The envelope must BIND the row's identity — `key_id`, `identity_type`,
    // and BOTH pubkey legs. CIRISVerify's provenance walk requires exactly
    // these (`ProvenanceLink::subject_binding`), and refuses a link whose
    // signed bytes omit any of them.
    //
    // The attack it closes: with the identity fields outside the signed bytes,
    // an attacker wraps a victim's genuine, validly-signed envelope in a link
    // declaring their OWN key_id and pubkeys. The content hash matches (it
    // really is the victim's envelope), the signatures verify (really signed by
    // the real parent), linkage passes — and the chain roots the attacker's
    // key. Both pubkey legs are bound, not just the name, because binding the
    // name alone loses on a node that has not yet replicated the victim's row.
    //
    // A `{"key_id": …}`-only envelope is why every harness node rooted
    // `Advisory`: each link was refused with "signed bytes do not carry
    // `identity_type` — an absent binding is skippable by omission", so the
    // chain never assembled and the E3 gate attributed nothing.
    let mut envelope = serde_json::json!({
        "key_id": subject,
        "identity_type": identity_type,
        "pubkey_ed25519_base64": ed_pub,
    });
    if !pqc_pub.is_empty() {
        envelope["pubkey_ml_dsa_65_base64"] = serde_json::json!(pqc_pub);
    }
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).unwrap();
    let digest = sha2::Sha256::digest(&canonical);
    let (sig, sig_pqc) = ciris_edge::identity::sign_bound_hybrid(signer, &canonical, "key record")
        .await
        .unwrap();
    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into();
    KeyRecord {
        key_id: subject.to_owned(),
        pubkey_ed25519_base64: ed_pub.to_owned(),
        pubkey_ml_dsa_65_base64: (!pqc_pub.is_empty()).then(|| pqc_pub.to_owned()),
        algorithm: "hybrid".to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: subject.to_owned(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: signer_key_id.to_owned(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// **The walk the mesh actually performs.** Seeds the synthetic genesis holders
/// and one node record scrub-signed by the root, then asks `root_binding` the
/// same question the announce path asks — and PRINTS the rejection.
#[tokio::test]
async fn a_node_signed_by_the_test_root_roots_confirmed() {
    // Load the anchor env from `bench-mesh/compose.yaml` — the values the mesh
    // actually deploys. Restating them here would let the test pass while the
    // harness ships a different (or incomplete) root, which is precisely the
    // failure mode being chased: persist and verify read DIFFERENT slots of
    // this name family, and a partial block yields a root that cannot be
    // assembled.
    let compose = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/bench-mesh/compose.yaml"
    ))
    .expect("read compose");
    let mut set = 0_usize;
    for line in compose.lines() {
        let t = line.trim();
        let Some((k, v)) = t.split_once(": ") else {
            continue;
        };
        if k.starts_with("CIRIS_TEST") || k == "CIRIS_TESTING_MODE" {
            std::env::set_var(k, v.trim().trim_matches('"'));
            set += 1;
        }
    }
    assert!(
        set >= 6,
        "expected the whole six-value anchor block in bench-mesh/compose.yaml, found {set} —          verify reads the Ed25519 pubkeys, persist reads the ML-DSA pubkeys AND both          scrub signatures"
    );

    let holders = ciris_persist::federation::genesis::test_anchor_genesis_records()
        .expect("the synthetic anchor must be armed — set the whole env block");
    println!("genesis holders: {}", holders.len());
    for h in &holders {
        println!(
            "  {} type={} scrub_by={} self_signed={}",
            h.record.key_id,
            h.record.identity_type,
            h.record.scrub_key_id,
            h.record.scrub_key_id == h.record.key_id
        );
    }

    let backend = Arc::new(MemoryBackend::new());
    for h in &holders {
        backend
            .put_public_key(h.clone())
            .await
            .expect("seed genesis holder");
    }

    // One node, scrub-signed by the root — exactly what the publisher writes.
    let root = root_signer();
    let node = {
        let seed = [7u8; 32];
        let classical: Arc<dyn HardwareSigner> =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&seed, "node-x").unwrap());
        let pqc: Arc<dyn PqcSigner> =
            Arc::new(MlDsa65SoftwareSigner::from_seed_bytes(&seed, "node-x-pqc").unwrap());
        ciris_edge::identity::LocalSigner::new("node-x", classical, Some(pqc))
    };
    let node_ed = b64().encode(node.classical.public_key().await.unwrap());
    let node_pqc = b64().encode(node.pqc.as_ref().unwrap().public_key().await.unwrap());
    backend
        .put_public_key(SignedKeyRecord {
            record: signed_record("node-x", &node_ed, &node_pqc, &root, ROOT, "node").await,
        })
        .await
        .expect("put node record");

    let verdict =
        ciris_persist::federation::rooting::root_binding(backend.as_ref(), "node-x", &node_ed)
            .await;
    // Summarise rather than dump: a Confirmed chain prints ~30KB of ML-DSA keys.
    match &verdict {
        ciris_persist::federation::rooting::RootingVerdict::Confirmed { chain } => {
            println!(
                "Confirmed — {} links, terminates_at_steward_bootstrap={}",
                chain.chain.len(),
                chain.terminates_at_steward_bootstrap
            );
            for link in &chain.chain {
                println!(
                    "  {} type={} scrub_by={} self_signed={}",
                    link.key_id, link.identity_type, link.scrub_key_id, link.is_self_signed
                );
            }
        }
        ciris_persist::federation::rooting::RootingVerdict::Rejected { rejection } => {
            println!("REJECTED: {rejection:?}");
        }
    }
    assert!(
        matches!(
            verdict,
            ciris_persist::federation::rooting::RootingVerdict::Confirmed { .. }
        ),
        "a node scrub-signed by the pinned test root MUST root Confirmed — Advisory \
         here is exactly why every mesh frame was refused attribution"
    );
}
