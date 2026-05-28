//! Shared test fixtures for the Reticulum authenticated-resolution
//! suites (CIRISEdge#15 / AV-42).
//!
//! Builds a real persist `federation_keys` directory seeded with
//! scrub-signed rows, plus the matching federation seed files, so the
//! cold-start `root_binding` path is exercised end-to-end against
//! genuine cryptography — not a mock.
#![cfg(feature = "transport-reticulum")]
#![allow(dead_code)]

use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::ClassicalSigner;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};

/// A test federation identity — a deterministic Ed25519 seed plus the
/// `key_id` it registers under. The seed is what edge's keyring
/// loader reads; the derived pubkey is what the directory row holds.
pub struct TestFedKey {
    pub key_id: String,
    pub seed: [u8; 32],
}

impl TestFedKey {
    #[must_use]
    pub fn new(key_id: &str, seed_byte: u8) -> Self {
        Self {
            key_id: key_id.to_string(),
            seed: [seed_byte; 32],
        }
    }

    /// The Ed25519 signer over this identity's seed.
    fn signer(&self) -> ciris_crypto::Ed25519Signer {
        ciris_crypto::Ed25519Signer::from_seed(&self.seed).expect("ed25519 from seed")
    }

    /// Base64-standard 32-byte Ed25519 public key.
    #[must_use]
    pub fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().expect("pubkey"))
    }

    /// Write the 32-byte raw seed file edge's keyring loader reads.
    /// Returns the directory containing `ed25519.seed`.
    pub fn write_seed_dir(&self, base: &Path) -> std::path::PathBuf {
        let dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&dir).expect("create seed dir");
        std::fs::write(dir.join("ed25519.seed"), self.seed).expect("write seed");
        dir
    }
}

/// Build a scrub-signed [`KeyRecord`]: `subject`'s row, scrub-signed
/// by `signer` (pass `signer == subject` for a self-signed steward
/// bootstrap). The scrub-signature is Ed25519 over
/// `original_content_hash` — the contract `root_binding` verifies.
#[must_use]
pub fn signed_record(subject: &TestFedKey, signer: &TestFedKey, identity_type: &str) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize envelope");
    let digest = Sha256::digest(&canonical);
    let original_content_hash = hex::encode(digest);

    // scrub-signature: Ed25519 over the original_content_hash bytes.
    let sig = signer.signer().sign(digest.as_slice()).expect("scrub sign");

    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into();

    KeyRecord {
        key_id: subject.key_id.clone(),
        pubkey_ed25519_base64: subject.pubkey_b64(),
        pubkey_ml_dsa_65_base64: None,
        algorithm: "hybrid".to_string(),
        identity_type: identity_type.to_string(),
        identity_ref: subject.key_id.clone(),
        valid_from: ts,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: B64.encode(sig),
        scrub_signature_pqc: None,
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        // v2.5.0 (CIRISPersist#102 Ask 8) — non-accord-holder rows
        // carry None; the V048 CHECK admits None for any
        // identity_type that isn't 'accord_holder'.
        attestation_evidence: None,
    }
}

/// Open a fresh in-memory persist federation directory and insert
/// every row in `records`.
pub async fn directory_with(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory federation directory");
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    backend
}
