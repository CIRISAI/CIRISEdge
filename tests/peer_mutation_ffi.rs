//! v0.15.1 (CIRISEdge#26 mutation surface) — peer-mutation FFI
//! acceptance gate.
//!
//! Exercises the 6 UniFFI peer-mutation entry points
//! (`peer_add` / `peer_remove` / `peer_set_alias` /
//! `peer_set_trust` / `peer_set_notes` / `peer_set_policy`) against a
//! real `FederationDirectorySqlite` wired into a real `Edge`, then
//! installed via `install_edge_handle` so the UniFFI free functions
//! resolve to it.
//!
//! v0.13.0 stubbed these 6 functions as `PEER_MUTATION_FOLLOWUP`
//! returning `EdgeBindingsError::NotImplemented`. CIRISPersist v3.1.0
//! (CIRISPersist#117) added the 6 new `FederationDirectory` methods —
//! `add_peer_record`, `remove_peer_record`,
//! `update_peer_{alias,trust,notes,policy}` — this file is the
//! corresponding edge-side acceptance bar.
//!
//! `peer_probe` stays `NotImplemented` per the v0.15.1 brief — it's a
//! network primitive (Reticulum-backed live reachability), distinct
//! from the persist-backed metadata mutations covered here.
//!
//! Requires the UniFFI feature:
//! `cargo test --features "ffi-uniffi" --test peer_mutation_ffi`

#![cfg(feature = "ffi-uniffi")]

use std::path::Path;
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::{Edge, EdgeConfig, EdgePeerHandle, EdgePeerPolicy, EdgePeerTrust, HybridPolicy};
use ciris_persist::federation::{FederationDirectory, TrustClass};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex as TokioMutex};

// ─── Test fixtures ──────────────────────────────────────────────────

struct FedKey {
    key_id: String,
    seed: [u8; 32],
}

impl FedKey {
    fn new(key_id: &str, seed_byte: u8) -> Self {
        Self {
            key_id: key_id.to_string(),
            seed: [seed_byte; 32],
        }
    }

    fn signer(&self) -> Ed25519Signer {
        Ed25519Signer::from_seed(&self.seed).expect("ed25519 from seed")
    }

    fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().expect("pubkey"))
    }

    async fn local_signer(&self, base: &Path) -> Arc<LocalSigner> {
        let seed_dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&seed_dir).expect("create seed dir");
        std::fs::write(seed_dir.join("ed25519.seed"), self.seed).expect("write seed");
        let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
            key_id: self.key_id.clone(),
            key_path: seed_dir.join("ed25519.seed"),
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load_local_seed");
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, None))
    }
}

fn signed_record(subject: &FedKey, signer: &FedKey, identity_type: &str) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = Sha256::digest(&canonical);
    let sig = signer.signer().sign(digest.as_slice()).expect("sign");
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
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: B64.encode(sig),
        scrub_signature_pqc: None,
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: ts,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    }
}

/// No-op transport — the peer-mutation FFI calls only touch
/// persist's `federation_peer_metadata`; they never enter the send
/// path. `Transport` impl exists only to satisfy `EdgeBuilder::build`.
struct NullTransport;

#[async_trait]
impl Transport for NullTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
}

/// Open a fresh in-memory backend, seed a steward + an `existing-peer`
/// key (so we can test both "add new" and "add existing" code paths).
async fn fresh_backend() -> (Arc<SqliteBackend>, FedKey) {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist");
    let steward = FedKey::new("steward-peer-mut-ffi", 0xA0);
    let existing = FedKey::new("existing-peer-mut-ffi", 0xB0);
    for rec in [
        signed_record(&steward, &steward, "steward"),
        signed_record(&existing, &steward, "agent"),
    ] {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    (backend, existing)
}

/// Build an Edge with the supplied federation directory wired into
/// both the verify pipeline AND the v0.15.1 peer-mutation surface.
async fn build_edge(tmp: &Path, backend: Arc<SqliteBackend>) -> Edge {
    let me = FedKey::new("edge-self-peer-mut-ffi", 0x01);
    let signer = me.local_signer(tmp).await;
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    };
    Edge::builder()
        .directory(backend.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(backend.clone() as Arc<dyn FederationDirectory>)
        .queue(backend)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .config(config)
        .build()
        .expect("build edge")
}

/// Process-wide serialization guard. The UniFFI registry
/// (`install_edge_handle`) is a `OnceLock<RwLock<Weak<Edge>>>` — a
/// single global slot. Tests that install distinct `Edge` instances
/// would race on the slot, so each test that touches the FFI surface
/// must hold this lock for its duration. (Read-only smoke tests like
/// `peer_set_alias_unknown_key_returns_not_found` still need it,
/// because a sibling test could install a different backend mid-call.)
///
/// `tokio::sync::Mutex` is the async-aware variant — a `std::sync::Mutex`
/// guard held across `await` would deadlock with clippy's
/// `await_holding_lock` rejection. The guard's `Drop` releases the
/// lock at end-of-scope per the standard RAII discipline.
fn ffi_test_lock() -> &'static TokioMutex<()> {
    static LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| TokioMutex::new(()))
}

/// Stand up + install an `Arc<Edge>` so the UniFFI free functions
/// resolve through the process-global registry. Returns the
/// `Arc<Edge>` so the caller holds it live for the duration of the
/// test (the registry stores a `Weak`).
async fn install_test_edge(tmp: &Path) -> (Arc<Edge>, Arc<SqliteBackend>, FedKey) {
    let (backend, existing) = fresh_backend().await;
    let edge = Arc::new(build_edge(tmp, backend.clone()).await);
    ciris_edge::ffi::uniffi_impl::install_edge_handle(&edge);
    (edge, backend, existing)
}

fn sample_pubkey_b64(seed_byte: u8) -> String {
    FedKey::new("not-stored-anywhere", seed_byte).pubkey_b64()
}

fn sample_policy() -> EdgePeerPolicy {
    EdgePeerPolicy {
        subscription_filter: vec!["SystemAnnounce".to_string(), "OpaqueEvent".to_string()],
        max_queue_depth: 1024,
        ack_timeout_seconds_override: Some(60),
        priority_class: Some("normal".to_string()),
    }
}

// ─── #1 round-trip add ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_add_round_trip() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "added-peer-aaaa".to_string();
    let pubkey = sample_pubkey_b64(0x21);
    let handle = ciris_edge::peer_add(key_id.clone(), pubkey.clone(), None, None)
        .expect("peer_add succeeds");
    assert_eq!(handle.key_id, key_id);

    // Verify the row landed in persist.
    let row = backend.lookup_public_key(&key_id).await.expect("lookup");
    assert!(row.is_some(), "row visible after peer_add");
    let row = row.unwrap();
    assert_eq!(row.identity_type, "agent");
    assert_eq!(row.pubkey_ed25519_base64, pubkey);
}

// ─── #2 idempotent / conflict ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_add_idempotent_on_matching_pubkey_conflict_on_differing() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "idempotent-peer-bbbb".to_string();
    let pubkey = sample_pubkey_b64(0x22);

    ciris_edge::peer_add(key_id.clone(), pubkey.clone(), None, None).expect("first peer_add");
    // Second call with the SAME pubkey is a no-op (idempotent on key_id).
    ciris_edge::peer_add(key_id.clone(), pubkey.clone(), None, None)
        .expect("second peer_add with matching pubkey is idempotent");

    // Third call with a DIFFERING pubkey is rejected (persist's
    // Conflict → InvalidArgument per `map_federation_err`).
    let different = sample_pubkey_b64(0x33);
    let err = ciris_edge::peer_add(key_id.clone(), different, None, None)
        .expect_err("differing pubkey rejected");
    assert!(
        matches!(err, ciris_edge::EdgeBindingsError::InvalidArgument),
        "differing-pubkey rejection maps to InvalidArgument, got {err:?}",
    );
}

// ─── #3 soft-remove ─────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_remove_soft_hides_from_metadata_reads() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "soft-remove-cccc".to_string();
    let pubkey = sample_pubkey_b64(0x24);
    ciris_edge::peer_add(key_id.clone(), pubkey.clone(), None, None).expect("peer_add");

    let handle = EdgePeerHandle {
        key_id: key_id.clone(),
    };
    ciris_edge::peer_remove(handle, false).expect("soft remove");

    // federation_keys row is preserved on soft-remove (audit trail).
    let key_row = backend.lookup_public_key(&key_id).await.expect("lookup");
    assert!(
        key_row.is_some(),
        "soft remove preserves federation_keys row"
    );

    // But subsequent metadata updates surface `NotFound` (the metadata
    // row is now marked removed_at; persist treats removed rows as
    // not-found for the mutation surface).
    let err = ciris_edge::peer_set_alias(key_id.clone(), Some("nope".to_string()))
        .expect_err("metadata updates on soft-removed row fail");
    assert!(
        matches!(err, ciris_edge::EdgeBindingsError::NotFound),
        "soft-removed key surfaces NotFound on subsequent updates, got {err:?}",
    );
}

// ─── #4 hard-remove no attestations ─────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_remove_hard_with_no_attestations_succeeds() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "hard-remove-dddd".to_string();
    let pubkey = sample_pubkey_b64(0x25);
    ciris_edge::peer_add(key_id.clone(), pubkey.clone(), None, None).expect("peer_add");

    let handle = EdgePeerHandle {
        key_id: key_id.clone(),
    };
    ciris_edge::peer_remove(handle, true).expect("hard remove succeeds with no attestations");

    // federation_keys row is GONE after hard-remove.
    let key_row = backend.lookup_public_key(&key_id).await.expect("lookup");
    assert!(key_row.is_none(), "hard remove DELETEs federation_keys row");
}

// ─── #5 set_alias round-trip ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_alias_round_trip() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "alias-peer-eeee".to_string();
    let pubkey = sample_pubkey_b64(0x26);
    ciris_edge::peer_add(key_id.clone(), pubkey, None, None).expect("peer_add");

    // Set + clear.
    ciris_edge::peer_set_alias(key_id.clone(), Some("Alice Edge".to_string())).expect("set alias");
    ciris_edge::peer_set_alias(key_id.clone(), None).expect("clear alias");
}

// ─── #6 set_trust each variant ──────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_trust_each_variant_round_trips() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "trust-peer-ffff".to_string();
    let pubkey = sample_pubkey_b64(0x27);
    ciris_edge::peer_add(key_id.clone(), pubkey, None, None).expect("peer_add");

    for variant in [
        EdgePeerTrust::Untrusted,
        EdgePeerTrust::Trusted,
        EdgePeerTrust::Restricted,
        EdgePeerTrust::Blocked,
    ] {
        ciris_edge::peer_set_trust(key_id.clone(), variant)
            .expect("set_trust round-trips every variant");
    }
}

// ─── #7 set_notes round-trip ────────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_notes_round_trip() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "notes-peer-gggg".to_string();
    let pubkey = sample_pubkey_b64(0x28);
    ciris_edge::peer_add(key_id.clone(), pubkey, None, None).expect("peer_add");

    ciris_edge::peer_set_notes(
        key_id.clone(),
        Some("Operator note: trusted at v0.15.1 review".to_string()),
    )
    .expect("set notes");
    ciris_edge::peer_set_notes(key_id.clone(), None).expect("clear notes");
}

// ─── #8 set_policy round-trip via peer_add(policy) ──────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_policy_round_trip_with_inline_add_and_explicit_update() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let key_id = "policy-peer-hhhh".to_string();
    let pubkey = sample_pubkey_b64(0x29);

    // Path 1: peer_add(policy: Some(...)) wires policy in the same
    // transaction (well, two sequential calls; persist allows that
    // ordering).
    let policy = sample_policy();
    let handle = ciris_edge::peer_add(key_id.clone(), pubkey, None, Some(policy.clone()))
        .expect("peer_add with policy");
    assert_eq!(handle.key_id, key_id);

    // Path 2: peer_set_policy on the same key replaces the blob.
    let mut updated = sample_policy();
    updated.priority_class = Some("steward-class".to_string());
    updated.max_queue_depth = 65535;
    ciris_edge::peer_set_policy(handle, updated).expect("peer_set_policy replaces blob");
}

// ─── #9 set_alias on unknown key → NotFound ─────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_alias_on_unknown_key_returns_not_found() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let err =
        ciris_edge::peer_set_alias("no-such-peer-iiii".to_string(), Some("ghost".to_string()))
            .expect_err("unknown key surfaces NotFound");
    assert!(
        matches!(err, ciris_edge::EdgeBindingsError::NotFound),
        "PeerNotFound → NotFound, got {err:?}",
    );
}

// ─── #10 set_trust on unknown key → NotFound ────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_trust_on_unknown_key_returns_not_found() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let err = ciris_edge::peer_set_trust("no-such-peer-jjjj".to_string(), EdgePeerTrust::Trusted)
        .expect_err("unknown key surfaces NotFound");
    assert!(
        matches!(err, ciris_edge::EdgeBindingsError::NotFound),
        "PeerNotFound → NotFound, got {err:?}",
    );
}

// ─── #11 set_notes on unknown key → NotFound ────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_notes_on_unknown_key_returns_not_found() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let err =
        ciris_edge::peer_set_notes("no-such-peer-kkkk".to_string(), Some("doomed".to_string()))
            .expect_err("unknown key surfaces NotFound");
    assert!(
        matches!(err, ciris_edge::EdgeBindingsError::NotFound),
        "PeerNotFound → NotFound, got {err:?}",
    );
}

// ─── #12 set_policy on unknown key → NotFound ───────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_set_policy_on_unknown_key_returns_not_found() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_edge, _backend, _existing) = install_test_edge(tmp.path()).await;

    let handle = EdgePeerHandle {
        key_id: "no-such-peer-llll".to_string(),
    };
    let err = ciris_edge::peer_set_policy(handle, sample_policy())
        .expect_err("unknown key surfaces NotFound");
    assert!(
        matches!(err, ciris_edge::EdgeBindingsError::NotFound),
        "PeerNotFound → NotFound, got {err:?}",
    );
}

// ─── #13 EdgePeerTrust ↔ TrustClass mapping audit ───────────────────

#[test]
fn edge_peer_trust_variants_align_with_persist_trust_class_wire_strings() {
    // Direct trait-level check that the 4 variants resolve to the
    // 4 persist wire-strings. This is a compile-time-ish guard
    // against drift: if either side adds / renames a variant,
    // this test breaks.
    for (edge_variant, persist_wire) in [
        (EdgePeerTrust::Untrusted, "untrusted"),
        (EdgePeerTrust::Trusted, "trusted"),
        (EdgePeerTrust::Restricted, "restricted"),
        (EdgePeerTrust::Blocked, "blocked"),
    ] {
        let persist_variant = match edge_variant {
            EdgePeerTrust::Untrusted => TrustClass::Untrusted,
            EdgePeerTrust::Trusted => TrustClass::Trusted,
            EdgePeerTrust::Restricted => TrustClass::Restricted,
            EdgePeerTrust::Blocked => TrustClass::Blocked,
        };
        assert_eq!(persist_variant.as_wire_str(), persist_wire);
    }
}
