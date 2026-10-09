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

    /// The PQC half. Same seed with a byte flipped, so the fixture stays
    /// deterministic while the two keys stay distinct. Every signature is the
    /// FULL hybrid (v19.0.0: no classical-only fallback).
    fn pqc_signer(&self) -> ciris_keyring::MlDsa65SoftwareSigner {
        let mut seed = self.seed;
        seed[0] ^= 0x55;
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&seed, format!("{}-pqc", self.key_id))
            .expect("ml_dsa_65 from seed")
    }

    fn pqc_pubkey_b64(&self) -> String {
        use ciris_keyring::PqcSigner as _;
        B64.encode(futures::executor::block_on(self.pqc_signer().public_key()).expect("pqc pubkey"))
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
        let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(self.pqc_signer());
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
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
        pubkey_ml_dsa_65_base64: Some(subject.pqc_pubkey_b64()),
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
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
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

// ---------------------------------------------------------------------------
// CIRISEdge#809 — the Edge's metrics bag is the transport's, and the binding
// snapshot carries the two leviculum pressure signals.
// ---------------------------------------------------------------------------

/// A transport that records the metrics bag the Edge attaches and, when asked
/// to refresh, mirrors a known eviction count into it — the shape
/// `ReticulumTransport` has, without a Reticulum node.
struct RecordingTransport {
    attached: std::sync::Mutex<Option<ciris_edge::observability::EdgeMetrics>>,
    evictions_to_report: u64,
}

#[async_trait]
impl Transport for RecordingTransport {
    fn id(&self) -> TransportId {
        TransportId::RETICULUM_RS
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
    fn attach_metrics(&self, metrics: ciris_edge::observability::EdgeMetrics) {
        // First handle wins, as `ReticulumTransport`'s `OnceLock` does.
        let mut slot = self.attached.lock().expect("attached");
        if slot.is_none() {
            *slot = Some(metrics);
        }
    }
    fn attached_metrics(&self) -> Option<ciris_edge::observability::EdgeMetrics> {
        self.attached.lock().expect("attached").clone()
    }
    fn refresh_metrics(&self) {
        if let Some(m) = self.attached.lock().expect("attached").as_ref() {
            m.set_known_destination_evictions(1, self.evictions_to_report);
        }
    }
}

async fn build_edge_with_transport(
    tmp: &Path,
    backend: Arc<SqliteBackend>,
    transport: Arc<dyn Transport>,
) -> Edge {
    let me = FedKey::new("edge-self-metrics-809", 0x01);
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
        .transport(transport)
        .config(config)
        .build()
        .expect("build edge")
}

/// The handle the Edge attaches IS the bag `Edge::metrics()` reads: one
/// increment through the transport's copy is one in the Edge's snapshot. It
/// is attached at BUILD, before any listener can exist, so every spawn site
/// (`spawn_background_listeners`, `Edge::run`, a host calling `listen`
/// itself) is covered. On the pre-#809 code nothing attached, so a
/// transport's counters only reached a bag the tests built and production
/// read zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_edge_attaches_its_metrics_to_every_transport_at_build_809() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (backend, _existing) = fresh_backend().await;
    let transport = Arc::new(RecordingTransport {
        attached: std::sync::Mutex::new(None),
        evictions_to_report: 0,
    });
    let edge =
        build_edge_with_transport(tmp.path(), backend, transport.clone() as Arc<dyn Transport>)
            .await;

    let through_transport = transport
        .attached
        .lock()
        .expect("attached")
        .clone()
        .expect("the Edge attached its metrics at build, before any listener");
    through_transport.inc_transport_packet_dropped();
    assert_eq!(
        edge.metrics().snapshot().transport_packets_dropped,
        1,
        "the transport's bag and the Edge's bag are one bag"
    );
}

/// A transport a caller built WITH its own bag (`with_metrics(Some(..))` on
/// `ReticulumTransport`) keeps counting into it; the Edge must read that
/// same bag, not mint a second one. On ba3d434 the builder minted a fresh
/// bag, the transport's first-wins slot kept the caller's, and
/// `Edge::metrics()` read zero (Codex, #810).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_edge_adopts_a_bag_the_transport_was_built_with_809() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (backend, _existing) = fresh_backend().await;
    let callers_bag = ciris_edge::observability::EdgeMetrics::new();
    let transport = Arc::new(RecordingTransport {
        attached: std::sync::Mutex::new(Some(callers_bag.clone())),
        evictions_to_report: 0,
    });
    let edge =
        build_edge_with_transport(tmp.path(), backend, transport.clone() as Arc<dyn Transport>)
            .await;
    assert!(
        edge.metrics().is_same_bag(&callers_bag),
        "the Edge reads the bag its transport was built with"
    );
    callers_bag.inc_transport_packet_dropped();
    assert_eq!(edge.metrics().snapshot().transport_packets_dropped, 1);
}

/// Two transports built with DIFFERENT bags cannot both be read through one
/// `Edge::metrics()`: `build` refuses by name instead of returning an Edge
/// that silently undercounts. On 95a3bdf it adopted the first bag and only
/// WARNed (Codex, #810). One shared bag across both builds fine.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_refuses_transports_with_different_metrics_bags_809() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let mk = |bag: Option<ciris_edge::observability::EdgeMetrics>| -> Arc<dyn Transport> {
        Arc::new(RecordingTransport {
            attached: std::sync::Mutex::new(bag),
            evictions_to_report: 0,
        })
    };
    let build = |a: Arc<dyn Transport>, b: Arc<dyn Transport>, tmp: std::path::PathBuf| async move {
        let (backend, _existing) = fresh_backend().await;
        let me = FedKey::new("edge-self-metrics-split-809", 0x01);
        let signer = me.local_signer(&tmp).await;
        Edge::builder()
            .directory(backend.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
            .federation_directory(backend.clone() as Arc<dyn FederationDirectory>)
            .queue(backend)
            .signer(signer)
            .transport(a)
            .transport(b)
            .config(EdgeConfig {
                hybrid_policy: HybridPolicy::Ed25519Fallback,
                ..EdgeConfig::default()
            })
            .build()
    };
    let split = build(
        mk(Some(ciris_edge::observability::EdgeMetrics::new())),
        mk(Some(ciris_edge::observability::EdgeMetrics::new())),
        tmp.path().join("split"),
    )
    .await;
    match split {
        Err(ciris_edge::EdgeError::Config(why)) => {
            assert!(
                why.contains("different metrics bags"),
                "named refusal: {why}"
            );
        }
        Err(other) => panic!("expected a Config refusal, got {other:?}"),
        Ok(_) => panic!("two different bags must not build into one Edge"),
    }
    let shared = ciris_edge::observability::EdgeMetrics::new();
    let edge = build(
        mk(Some(shared.clone())),
        mk(None),
        tmp.path().join("shared"),
    )
    .await
    .expect("one shared bag (and a bag-less transport) builds");
    assert!(edge.metrics().is_same_bag(&shared));
}

/// The UniFFI snapshot carries both signals under their bundle field names
/// (`EdgeMetricsBundle::flatten`, CIRISEdge#848; `transport.*` before), and a
/// read refreshes the mirrored gauge first — a transport that has evicted
/// since the last read is reported without anyone asking it directly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_uniffi_snapshot_carries_both_pressure_signals_and_refreshes_first_809() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (backend, _existing) = fresh_backend().await;
    let transport = Arc::new(RecordingTransport {
        attached: std::sync::Mutex::new(None),
        evictions_to_report: 42,
    });
    let edge = Arc::new(
        build_edge_with_transport(tmp.path(), backend, transport.clone() as Arc<dyn Transport>)
            .await,
    );
    ciris_edge::ffi::uniffi_impl::install_edge_handle(&edge);
    let tasks = edge.spawn_background_listeners(&tokio::runtime::Handle::current());
    edge.metrics().inc_transport_packet_dropped();
    edge.metrics().inc_transport_packet_dropped();

    let snap = ciris_edge::ffi::uniffi_impl::metrics_snapshot().expect("snapshot");
    assert_eq!(
        snap.counters.get("transport_packets_dropped").copied(),
        Some(2),
        "packet drops reach the UniFFI counters: {:?}",
        snap.counters
    );
    assert_eq!(
        snap.counters.get("known_destination_evictions").copied(),
        Some(42),
        "the eviction gauge is refreshed by the snapshot read itself, not by a prior \
         transport-specific getter: {:?}",
        snap.counters
    );
    for t in tasks {
        t.abort();
    }
}

/// CIRISEdge#805 — the A/V plane ledger reaches the UniFFI counters as
/// `av_plane.<label>`, beside the Rust snapshot and the pyo3 dict: a counter
/// in one binding and not the other is invisible to mobile operators (the
/// #810 class).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_uniffi_snapshot_carries_the_av_plane_ledger_805() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (backend, _existing) = fresh_backend().await;
    let transport = Arc::new(RecordingTransport {
        attached: std::sync::Mutex::new(None),
        evictions_to_report: 0,
    });
    let edge = Arc::new(
        build_edge_with_transport(tmp.path(), backend, transport.clone() as Arc<dyn Transport>)
            .await,
    );
    ciris_edge::ffi::uniffi_impl::install_edge_handle(&edge);
    let m = edge.metrics();
    m.inc_av_plane(ciris_edge::observability::AV_INBOUND_DELIVERED);
    m.inc_av_plane(ciris_edge::observability::AV_INBOUND_DELIVERED);
    m.inc_av_plane(ciris_edge::observability::AV_SEND_REFUSED_CHUNK_TOO_LARGE);

    let snap = ciris_edge::ffi::uniffi_impl::metrics_snapshot().expect("snapshot");
    assert_eq!(
        snap.counters.get("av_plane.av_inbound_delivered").copied(),
        Some(2),
        "the A/V ledger reaches the UniFFI counters: {:?}",
        snap.counters
    );
    assert_eq!(
        snap.counters
            .get("av_plane.av_send_refused_chunk_too_large")
            .copied(),
        Some(1),
        "{:?}",
        snap.counters
    );
}

/// CIRISEdge#848 — PARITY: the UniFFI snapshot carries every
/// `EdgeMetricsBundle` field (as a counter or gauge key), walked from
/// `EDGE_METRICS_BUNDLE_FIELDS`, on a fresh Edge where nothing has been
/// recorded, so "absent" never stands in for "zero". And `queue_depth()` is
/// the RESIDENT durable depth (#845), not the constant 0 it returned before:
/// one enqueue is one resident row, in `queue_depth` and in the snapshot's
/// `durable.queue_depth` gauge, while the cumulative count rides the bundle's
/// `durable_enqueued_total`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_uniffi_snapshot_projects_every_bundle_field_and_queue_depth_is_resident_848() {
    let _guard = ffi_test_lock().lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (backend, existing) = fresh_backend().await;
    // The outbound queue references the sender's key row, so the Edge's own
    // key (the one `build_edge_with_transport` signs with) is registered.
    let steward = FedKey::new("steward-peer-mut-ffi", 0xA0);
    let me = FedKey::new("edge-self-metrics-809", 0x01);
    backend
        .put_public_key(SignedKeyRecord {
            record: signed_record(&me, &steward, "agent"),
        })
        .await
        .expect("put_public_key(self)");
    let transport = Arc::new(RecordingTransport {
        attached: std::sync::Mutex::new(None),
        evictions_to_report: 0,
    });
    let edge = Arc::new(
        build_edge_with_transport(tmp.path(), backend, transport as Arc<dyn Transport>).await,
    );
    ciris_edge::ffi::uniffi_impl::install_edge_handle(&edge);

    let snap = ciris_edge::ffi::uniffi_impl::metrics_snapshot().expect("snapshot");
    let missing: Vec<&str> = ciris_edge::observability::EDGE_METRICS_BUNDLE_FIELDS
        .iter()
        .copied()
        .filter(|f| !snap.counters.contains_key(*f) && !snap.gauges.contains_key(*f))
        .collect();
    assert!(
        missing.is_empty(),
        "UniFFI metrics_snapshot omits bundle fields: {missing:?}"
    );
    for legacy in [
        "reachability.attempts_total",
        "reachability.successes_total",
        "inbound.dropped_low_trust_total",
    ] {
        assert!(snap.counters.contains_key(legacy), "{legacy} kept");
    }

    // CIRISEdge#856 — the rooted-peer listing is its own door, not the
    // snapshot (a label per peer); a fresh Edge roots no one.
    assert!(
        !snap
            .counters
            .keys()
            .any(|k| k.starts_with("rooted_peer_last")),
        "the per-peer listing stays out of the snapshot"
    );
    assert!(ciris_edge::ffi::uniffi_impl::rooted_peer_rounds()
        .expect("rooted_peer_rounds")
        .is_empty());

    let all = ciris_edge::ffi::uniffi_impl::queue_depth(None).expect("queue_depth(all)");
    assert_eq!(all.get("all").copied(), Some(0));
    edge.send_durable(
        &existing.key_id,
        ciris_edge::OpaqueEvent {
            kind: 0x0000_0001,
            payload: b"durable text".to_vec(),
        },
    )
    .await
    .expect("send_durable");
    let all = ciris_edge::ffi::uniffi_impl::queue_depth(None).expect("queue_depth(all)");
    assert_eq!(all.get("all").copied(), Some(1), "one resident row");
    assert!(
        matches!(
            ciris_edge::ffi::uniffi_impl::queue_depth(Some("durable".to_string())),
            Err(ciris_edge::EdgeBindingsError::Unsupported)
        ),
        "persist's count has no delivery class; a named class is refused, not a made-up 0"
    );
    let snap = ciris_edge::ffi::uniffi_impl::metrics_snapshot().expect("snapshot");
    assert_eq!(snap.gauges.get("durable.queue_depth").copied(), Some(1.0));
    assert_eq!(
        snap.counters.get("durable_enqueued_total.durable").copied(),
        Some(1)
    );
}
