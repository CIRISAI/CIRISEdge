//! In-memory `FederationDirectory` + `OutboundQueue` seeded with
//! scrub-signed federation_keys rows. The persist `SqliteBackend`
//! opened at `:memory:` IS the canonical in-memory shape — the
//! `OutboundQueue` blanket impl in persist's `OutboundQueue` trait
//! means the same `Arc<SqliteBackend>` works as both `VerifyDirectory`
//! and `OutboundHandle` (same FK target table for outbound rows).
//!
//! Mirrors `tests/common/mod.rs` so the bench surface matches the
//! test surface verbatim — a regression in `signed_record` shape
//! lands here and in the test suite at the same time.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::field_reassign_with_default,
    clippy::needless_raw_string_hashes
)]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer, HybridSigner, MlDsa65Signer, PqcSigner};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};

/// A deterministic-seed federation identity. The 32-byte seed is what
/// the keyring loader reads; the derived ed25519 pubkey is what the
/// `federation_keys` row holds. Same shape as
/// `tests/accord_carrier_verify.rs::FedKey` and
/// `tests/common/mod.rs::TestFedKey`.
pub struct BenchFedKey {
    pub key_id: String,
    pub seed: [u8; 32],
}

impl BenchFedKey {
    #[must_use]
    pub fn new(key_id: &str, seed_byte: u8) -> Self {
        Self {
            key_id: key_id.to_string(),
            seed: [seed_byte; 32],
        }
    }

    /// The Ed25519 signer over this identity's seed.
    pub fn signer(&self) -> Ed25519Signer {
        Ed25519Signer::from_seed(&self.seed).expect("ed25519 from seed")
    }

    /// Base64-standard 32-byte Ed25519 public key.
    #[must_use]
    pub fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().expect("pubkey"))
    }

    /// Sign canonical bytes with this identity's seed.
    pub fn sign(&self, canonical: &[u8]) -> Vec<u8> {
        self.signer().sign(canonical).expect("sign")
    }

    /// The ML-DSA-65 signer over this identity's seed (CIRISEdge#359 — accord
    /// signatures are hybrid). Same seed as the ed25519 key.
    pub fn ml_dsa_signer(&self) -> MlDsa65Signer {
        MlDsa65Signer::from_seed(&self.seed).expect("ml-dsa from seed")
    }

    /// Base64-standard ML-DSA-65 public key.
    #[must_use]
    pub fn ml_dsa_pubkey_b64(&self) -> String {
        B64.encode(PqcSigner::public_key(&self.ml_dsa_signer()).expect("ml-dsa pubkey"))
    }

    /// Hybrid-sign canonical bytes → `(ed25519_b64, ml_dsa_65_b64)`, bound
    /// exactly as `verify_hybrid` re-checks it (ml-dsa over `canonical ‖
    /// ed_sig`). This is the accord-carrier signature shape post-#359.
    pub fn hybrid_sign(&self, canonical: &[u8]) -> (String, String) {
        let hy = HybridSigner::new(self.signer(), self.ml_dsa_signer()).expect("hybrid signer");
        let sig = hy.sign(canonical).expect("hybrid sign");
        (
            B64.encode(sig.classical.signature),
            B64.encode(sig.pqc.signature),
        )
    }

    /// Write the 32-byte raw seed file edge's keyring loader reads.
    pub fn write_seed_dir(&self, base: &std::path::Path) -> std::path::PathBuf {
        let dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&dir).expect("create seed dir");
        std::fs::write(dir.join("ed25519.seed"), self.seed).expect("write seed");
        dir
    }
}

/// Build a scrub-signed `KeyRecord`. `subject` is the row's key;
/// `signer` is who scrub-signed it (`signer == subject` is a
/// self-signed bootstrap). `identity_type` matches persist's
/// `federation::types::identity_type` constants:
/// `"steward"` / `"agent"` / `"accord_holder"` / etc.
///
/// `accord_holder` rows MUST carry `attestation_evidence` per persist
/// v2.5.0+'s V048 schema gate (mirrors `tests/accord_carrier_verify.rs`).
#[must_use]
pub fn signed_record(
    subject: &BenchFedKey,
    signer: &BenchFedKey,
    identity_type: &str,
) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize envelope");
    let digest = Sha256::digest(&canonical);
    let original_content_hash = hex::encode(digest);

    let sig = signer.signer().sign(digest.as_slice()).expect("scrub sign");

    let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into();

    let attestation_evidence = if identity_type == "accord_holder" {
        Some(serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": Utc::now().to_rfc3339(),
        }))
    } else {
        None
    };

    // CIRISEdge#359 — accord_holder rows carry the ML-DSA-65 pubkey so the
    // hybrid accord-carrier verify (`verify_hybrid_via_directory`,
    // RequireHybrid) can gate both signatures. Other identity_types stay
    // ed25519-only (unchanged).
    let pubkey_ml_dsa_65_base64 = if identity_type == "accord_holder" {
        Some(subject.ml_dsa_pubkey_b64())
    } else {
        None
    };

    KeyRecord {
        key_id: subject.key_id.clone(),
        pubkey_ed25519_base64: subject.pubkey_b64(),
        pubkey_ml_dsa_65_base64,
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
        attestation_evidence,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// Open a fresh in-memory persist SQLite backend, run migrations, and
/// seed the directory with `records`. The same `Arc<SqliteBackend>`
/// satisfies both `VerifyDirectory` (federation_keys reads) and
/// `OutboundHandle` (edge_outbound_queue writes) — single connection
/// pool, FK from outbound rows to federation_keys resolves.
pub async fn build_in_memory_backend(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist directory");
    backend.run_migrations().await.expect("migrate");
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    backend
}

/// Build N stewards (`identity_type = "steward"`) named
/// `steward-{i:02}` (deterministic), all scrub-signed by `bootstrap`.
/// Used by the `steward_fanout` bench's sweep.
#[must_use]
pub fn seed_stewards(bootstrap: &BenchFedKey, count: usize) -> Vec<KeyRecord> {
    let mut rows = Vec::with_capacity(count + 1);
    rows.push(signed_record(bootstrap, bootstrap, "steward"));
    for i in 0..count {
        let key = BenchFedKey::new(&format!("steward-{i:02}"), 0xB0u8.wrapping_add(i as u8));
        rows.push(signed_record(&key, bootstrap, "steward"));
    }
    rows
}

/// Build M accord-holders (`identity_type = "accord_holder"`),
/// returning both the `KeyRecord` rows and the matching `BenchFedKey`
/// fixtures so the bench can produce signatures over the accord-
/// announcement's canonical bytes.
#[must_use]
pub fn seed_accord_holders(
    bootstrap: &BenchFedKey,
    holder_seeds: &[(&str, u8)],
) -> (Vec<KeyRecord>, Vec<BenchFedKey>) {
    let mut rows = Vec::with_capacity(holder_seeds.len());
    let mut keys = Vec::with_capacity(holder_seeds.len());
    for (key_id, seed_byte) in holder_seeds {
        let k = BenchFedKey::new(key_id, *seed_byte);
        rows.push(signed_record(&k, bootstrap, "accord_holder"));
        keys.push(k);
    }
    (rows, keys)
}
