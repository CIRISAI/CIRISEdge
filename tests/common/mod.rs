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
        consent_role: None,
        additional_scrubs: Vec::new(),
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

/// v7.0.0 (CIRISEdge#191 / #195) — cross-install each transport's
/// `(dest_hash, transport-tier ed25519)` binding into the OTHER
/// transport's rooted-peer map, bypassing the announce path that
/// explicit-hash addressing forbids.
///
/// Production peers learn this binding via the v6.0.0 directory-cache
/// anti-entropy path (CIRISEdge#175); this helper is the test-only
/// analogue. After this call, each transport's `knows_peer(<peer>)`
/// returns true and `link_open(peer_dest_hash, ..)` finds the entry —
/// the same observable state the legacy announce-rooting produced
/// before v7.0.0 broke the announce.
#[cfg(feature = "transport-reticulum")]
pub async fn prime_v7_peer_pair(
    transport_a: &ciris_edge::transport::reticulum::ReticulumTransport,
    key_id_a: &str,
    transport_b: &ciris_edge::transport::reticulum::ReticulumTransport,
    key_id_b: &str,
) {
    let a_dest = transport_a.local_dest_hash();
    let b_dest = transport_b.local_dest_hash();
    let mut a_ed = [0u8; 32];
    a_ed.copy_from_slice(&transport_a.local_transport_pubkey()[32..64]);
    let mut b_ed = [0u8; 32];
    b_ed.copy_from_slice(&transport_b.local_transport_pubkey()[32..64]);
    transport_b
        .inject_rooted_peer_for_test(key_id_a, a_dest, a_ed)
        .await;
    transport_a
        .inject_rooted_peer_for_test(key_id_b, b_dest, b_ed)
        .await;
}

/// Build a [`ReticulumTransport`], retrying on the transient
/// "address already in use" race.
///
/// The test suites pick loopback ports via `free_port()`, which binds an
/// ephemeral port and immediately releases it. Between that release and
/// the transport reclaiming the port, a parallel test (in this binary or
/// another test binary cargo runs concurrently) can win the same port —
/// surfacing as `Io("reticulum node start: ... Address already in use")`.
/// On that error we rebuild from a freshly-picked config; any other error
/// is a real failure and panics immediately.
///
/// `make` is invoked once per attempt and must return a *fresh* config
/// (re-picking its ephemeral `listen_addr`) together with the matching
/// [`ReticulumAuth`] — both are consumed by the build, so the auth signer
/// is rebuilt per attempt. Returns the live transport plus the
/// `listen_addr` that actually bound, so callers wiring a bootstrap peer
/// can learn the settled port.
#[cfg(feature = "transport-reticulum")]
pub async fn build_reticulum_with_retry<F, Fut>(
    mut make: F,
) -> (
    Arc<ciris_edge::transport::reticulum::ReticulumTransport>,
    std::net::SocketAddr,
)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
        Output = (
            ciris_edge::transport::reticulum::ReticulumTransportConfig,
            ciris_edge::transport::reticulum::ReticulumAuth,
        ),
    >,
{
    use ciris_edge::transport::reticulum::ReticulumTransport;

    const MAX_ATTEMPTS: usize = 16;
    let mut last_err = None;
    for _ in 0..MAX_ATTEMPTS {
        let (cfg, auth) = make().await;
        let addr = cfg.listen_addr;
        match ReticulumTransport::new(cfg, auth).await {
            Ok(transport) => return (Arc::new(transport), addr),
            Err(err) if is_addr_in_use(&err) => {
                // Re-pick a port and rebuild on the next loop iteration.
                last_err = Some(err);
            }
            Err(err) => panic!("build reticulum transport: {err:?}"),
        }
    }
    panic!("build reticulum transport: exhausted {MAX_ATTEMPTS} bind retries: {last_err:?}");
}

/// True if a transport build error is the transient ephemeral-port bind
/// race from `free_port()` (see [`build_reticulum_with_retry`]) rather
/// than a genuine configuration or crypto failure.
#[cfg(feature = "transport-reticulum")]
fn is_addr_in_use(err: &ciris_edge::transport::TransportError) -> bool {
    let msg = err.to_string();
    msg.contains("Address already in use") || msg.contains("os error 98")
}
