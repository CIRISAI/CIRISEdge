//! CIRISEdge#959 (44.1.2) — the CC wire vocabulary v1.0.3 (CC rc17 a08db38)
//! retires the Tier-1 kind `FountainHoldingClaim`: "a decoder that meets the
//! discriminator MUST reject it as an unknown kind; a receiver that previously
//! folded it drops it by name."
//!
//! These witnesses drive a REAL hybrid-signed `FountainHoldingClaim` envelope
//! from a directoried peer through the network receive path
//! (`Edge::dispatch_inbound_for_test` → verify → dispatch) and assert that it
//! is rejected at the typed decode, named (`retired_wire_kind`), counted, and
//! never folded into the converged view or an installed swarm runtime.
//!
//! Before 44.1.2 the same envelope verified and was folded into both
//! (CIRISEdge#184/#545); the mutation that restores that fold fails these.

#![cfg(feature = "transport-reticulum")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::Message;
use ciris_edge::holonomic::swarm_rarity::FountainHoldingClaim;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::observability::VerifyErrorClass;
use ciris_edge::swarm::{FountainSwarmRuntime, NoopFountainHoldingsSource, SwarmRuntimeConfig};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, MessageType};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, Mutex};

// ─── Fixtures ───────────────────────────────────────────────────────

struct FedKey {
    key_id: String,
    seed: [u8; 32],
}

impl FedKey {
    /// persist #1103 (CC 2.6.8) — the `key_id` is DERIVED from the key's own
    /// Ed25519 pubkey (`derive_key_id(label, pubkey)`), never hand-written:
    /// `put_public_key` refuses a `-<fp>` suffix that is not its key's
    /// fingerprint. Tests reference `key_id`, never the label.
    fn new(label: &str, seed_byte: u8) -> Self {
        use ciris_crypto::ClassicalSigner as _;
        let seed = [seed_byte; 32];
        let pubkey = ciris_crypto::Ed25519Signer::from_seed(&seed)
            .expect("ed25519 from seed")
            .public_key()
            .expect("pubkey");
        Self {
            key_id: ciris_verify_core::fedcode::derive_key_id(label, &pubkey),
            seed,
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

    fn write_seed_dir(&self, base: &std::path::Path) -> PathBuf {
        let dir = base.join(format!("seed-{}", self.key_id));
        std::fs::create_dir_all(&dir).expect("create seed dir");
        std::fs::write(dir.join("ed25519.seed"), self.seed).expect("write seed");
        dir
    }

    async fn local_signer(&self, base: &std::path::Path) -> Arc<LocalSigner> {
        let seed_dir = self.write_seed_dir(base);
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

async fn directory_with(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
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

fn test_edge_config() -> EdgeConfig {
    EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        // Phase 2 — `OpaqueRequest` sends now genuinely await a
        // correlated response; these tests wire no responder, so a
        // short timeout keeps each (ignored-result) send from parking
        // for the 30 s production default.
        ephemeral_response_timeout_ms: 10,
        ..EdgeConfig::default()
    }
}

/// Transport that records the outcome of each `send` call. Used by the
/// metric-on-send tests so we can drive both success and failure
/// classes from the call site.
#[derive(Clone)]
struct ConfigurableTransport {
    id: TransportId,
    next: Arc<Mutex<Vec<Result<TransportSendOutcome, TransportError>>>>,
}

impl ConfigurableTransport {
    fn new(id: TransportId, mut script: Vec<Result<TransportSendOutcome, TransportError>>) -> Self {
        script.reverse();
        Self {
            id,
            next: Arc::new(Mutex::new(script)),
        }
    }
}

#[async_trait]
impl Transport for ConfigurableTransport {
    fn id(&self) -> TransportId {
        self.id
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        let mut guard = self.next.lock().await;
        guard.pop().unwrap_or(Ok(TransportSendOutcome::Delivered))
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        // never produces traffic in these tests
        std::future::pending::<()>().await;
        Ok(())
    }
}

async fn signed_envelope_bytes<M: Message>(
    sender: &LocalSigner,
    destination_key_id: &str,
    body: &M,
) -> Vec<u8> {
    let mut env = build_envelope(M::TYPE, &sender.key_id, destination_key_id, body, None)
        .expect("build envelope");
    sign_envelope(sender, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("serialize envelope")
}

async fn build_edge(
    tmp: &tempfile::TempDir,
    transport: Arc<dyn Transport>,
) -> (Arc<Edge>, Arc<LocalSigner>, String) {
    let steward = FedKey::new("steward-fed", 0x01);
    let local = FedKey::new("local-self", 0xBB);
    let peer = FedKey::new("remote-peer", 0xAA);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&local, &steward, "node"),
        signed_record(&peer, &steward, "node"),
    ])
    .await;
    let queue = directory.clone();
    let local_signer = local.local_signer(tmp.path()).await;

    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(local_signer)
        .transport(transport)
        .config(test_edge_config())
        .build()
        .expect("build edge");

    // peer's signer so a separate test can drive inbound envelopes
    let peer_signer = peer.local_signer(tmp.path()).await;
    (Arc::new(edge), peer_signer, peer.key_id.clone())
}

fn claim_frame(envelope_bytes: Vec<u8>) -> InboundFrame {
    InboundFrame {
        envelope_bytes,
        transport: TransportId::HTTP,
        received_at: chrono::Utc::now(),
        source_key_id: None,
        link_key_id: None,
        arrival_scope: None,
        reply_path: None,
    }
}

fn the_claim(peer_key_id: &str) -> FountainHoldingClaim {
    FountainHoldingClaim::new(
        peer_key_id.to_string(),
        "shard-959".to_string(),
        vec![1, 2, 3],
        1_700_000_000_000,
    )
}

/// The decode-level rejection itself: the retired discriminator does not
/// deserialize as a `MessageType`, while the Rust variant still serializes
/// (the 44.x line keeps the type for downstream benches).
#[test]
fn the_retired_discriminator_does_not_decode_959() {
    assert_eq!(
        serde_json::to_string(&MessageType::FountainHoldingClaim).expect("serialize"),
        "\"FountainHoldingClaim\""
    );
    let err = serde_json::from_str::<MessageType>("\"FountainHoldingClaim\"")
        .expect_err("a retired wire kind must not decode");
    assert!(
        err.to_string().contains("unknown variant"),
        "rejected as an unknown kind, got: {err}"
    );
    assert!(ciris_edge::messages::RETIRED_WIRE_KINDS.contains(&"FountainHoldingClaim"));
}

/// The witness. A hybrid-signed claim from a directoried peer, received on
/// the network path with NO swarm runtime installed (the posture of every
/// production host): rejected at decode, named, counted, and the armed
/// converged view reads converged-to-nothing — not one claim.
#[tokio::test]
async fn a_received_fountain_holding_claim_is_dropped_by_name_959() {
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, peer_signer, peer_key_id) = build_edge(&tmp, transport).await;
    // A short warm-up so an armed, empty view answers `Converged` (zero)
    // rather than `Warming` within the test.
    edge.converged_claim_view()
        .align_to_converger(Duration::from_secs(600), Duration::from_millis(5));

    let claim = the_claim(&peer_key_id);
    let envelope_bytes = signed_envelope_bytes(&peer_signer, edge.signer_key_id(), &claim).await;

    let drops_before = ciris_edge::verify::retired_wire_kind_drops();
    edge.dispatch_inbound_for_test(claim_frame(envelope_bytes))
        .await;
    assert!(
        ciris_edge::verify::retired_wire_kind_drops() > drops_before,
        "the receive path counted the named drop"
    );

    let snap = edge.metrics().snapshot();
    assert_eq!(
        snap.verify_failures_total
            .get(&VerifyErrorClass::SchemaInvalid)
            .copied()
            .unwrap_or(0),
        1,
        "rejected at decode, as an unknown kind"
    );
    assert_eq!(
        snap.envelopes_received_total
            .get(&MessageType::FountainHoldingClaim)
            .copied()
            .unwrap_or(0),
        0,
        "never counted as a received (verified) envelope"
    );

    tokio::time::sleep(Duration::from_millis(30)).await;
    let reading = edge.swarm_convergence();
    let view = reading
        .converged()
        .copied()
        .unwrap_or_else(|| panic!("an armed view past warm-up answers; got {reading:?}"));
    assert_eq!(
        view.claims_converged, 0,
        "the claim never reached the converged view: {view:?}"
    );
}

/// Same claim, with a swarm runtime installed: it never reaches the
/// runtime's observed-claims map either.
#[tokio::test]
async fn a_received_fountain_holding_claim_never_reaches_an_installed_runtime_959() {
    let tmp = tempfile::tempdir().unwrap();
    let transport =
        Arc::new(ConfigurableTransport::new(TransportId::HTTP, vec![])) as Arc<dyn Transport>;
    let (edge, peer_signer, peer_key_id) = build_edge(&tmp, transport.clone()).await;

    let directory: Arc<dyn FederationDirectory> =
        Arc::new(ciris_persist::store::test_backend::test_backend());
    // Tasks end with the test's tokio runtime; the runtime has no Drop.
    let runtime = Arc::new(FountainSwarmRuntime::start(
        SwarmRuntimeConfig {
            publish_cadence: Duration::from_millis(5),
            observe_cadence: Duration::from_millis(5),
            ..Default::default()
        },
        Arc::new(NoopFountainHoldingsSource),
        directory,
        transport,
        Arc::new(Vec::new),
        edge.signer_key_id().to_string(),
        None,
    ));
    let observed = runtime.observed_handle();
    edge.install_swarm_runtime(runtime);

    let claim = the_claim(&peer_key_id);
    let envelope_bytes = signed_envelope_bytes(&peer_signer, edge.signer_key_id(), &claim).await;
    edge.dispatch_inbound_for_test(claim_frame(envelope_bytes))
        .await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    let g = observed.read().await;
    let inner = format!("{g:?}");
    assert!(
        !inner.contains("shard-959"),
        "a retired-kind claim reached the installed runtime: {inner}"
    );
    drop(g);

    let reading = edge.swarm_convergence();
    if let Some(view) = reading.converged() {
        assert_eq!(view.claims_converged, 0, "{view:?}");
    }
}
