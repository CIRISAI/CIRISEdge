//! Acceptance gate for CIRISEdge#18 — `MessageType::FederationAnnouncement`
//! + `Delivery::Mandatory` (subscription-bypass) + `MessageType::DeliveryAttestation`.
//!
//! Cross-references:
//!
//! - CIRISNodeCore FSD §2.1 (announcement wire shape) + §3.2.1
//!   (delivery_attestation wire shape, ratified 2026-05-27).
//! - CIRISPersist v2.2.0 `src/cirisnode/federation_announcement.rs`
//!   (byte-exact cross-repo counterpart; persist's golden vector
//!   guards the canonical-bytes encoding).
//!
//! This suite exercises the substrate-tier wire contracts without
//! standing up a full Reticulum mesh — it drives `Edge::send_mandatory`
//! directly against a shared persist SQLite backend and asserts the
//! load-bearing properties (fan-out, subscription bypass, attestation
//! shape, AV-spoof + AV-replay defenses on persist's admission side).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::Delivery;
use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::{
    AnnouncementKind, AnnouncementPriority, AuthorityClass, DeliveryAttestation, Edge,
    FederationAnnouncement, Message, MessageType, OutboundHandle, PeerDirectory,
    PeerSubscriptionFilter, TransportMedium,
};
use ciris_persist::cirisnode::sqlite::SqliteNodeCoreBackend;
use ciris_persist::cirisnode::NodeCoreService;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::outbound::Error as PersistOutboundError;
use ciris_persist::prelude::{
    FederationDirectorySqlite, KeyRecord, OutboundFilter, SignedKeyRecord,
};
use ciris_persist::store::backend::Backend;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

// ─── Test fixtures ──────────────────────────────────────────────────

/// A test federation identity: deterministic seed + key_id + the keys
/// derived from it.
struct FedKey {
    key_id: String,
    label: String,
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
            label: label.to_owned(),
            seed,
        }
    }

    fn signer(&self) -> Ed25519Signer {
        Ed25519Signer::from_seed(&self.seed).expect("ed25519 from seed")
    }

    fn pubkey_b64(&self) -> String {
        B64.encode(self.signer().public_key().expect("pubkey"))
    }

    /// The PQC half. Derived from the same seed so the fixture stays
    /// deterministic; the byte flip keeps it distinct from the Ed25519 seed.
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
        // HYBRID. A classical-only signer here would make every fixture a
        // producer of hybrid-pending rows, which persist's Strict policy
        // rejects at admission — the shape that reddened this file.
        let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(self.pqc_signer());
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
    }
}

impl FedKey {
    /// persist v60.0.0 — the signer `Engine::emit_attestation` takes. Its
    /// `derived_key_id()` is `derive_key_id(label, pubkey)`, so it is built
    /// from the LABEL (deriving from the derived id would re-suffix it).
    async fn emit_signer(&self, base: &std::path::Path) -> ciris_persist::signing::LocalSigner {
        let seed_dir = self.write_seed_dir(base);
        let mut pqc_seed = self.seed;
        pqc_seed[0] ^= 0x55;
        std::fs::write(seed_dir.join("ml_dsa_65.seed"), pqc_seed).expect("write pqc seed");
        let signer = ciris_persist::signing::LocalSigner::from_config(
            &ciris_persist::signing::LocalSignerConfig {
                key_id: self.label.clone(),
                key_path: seed_dir.join("ed25519.seed"),
                pqc_key_id: Some(format!("{}-pqc", self.key_id)),
                pqc_key_path: Some(seed_dir.join("ml_dsa_65.seed")),
            },
        )
        .expect("persist LocalSigner");
        assert_eq!(
            signer.derived_key_id(),
            self.key_id,
            "emit signer derives the key_id"
        );
        assert_eq!(
            signer.pqc_public_key_b64().await.expect("pqc pubkey"),
            Some(self.pqc_pubkey_b64()),
            "emit signer carries the registered ML-DSA-65 half"
        );
        signer
    }
}

/// Build a scrub-signed `KeyRecord`. `subject` is the row's key;
/// `signer` is who scrub-signed it.
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
        // v2.5.0 (CIRISPersist#102 Ask 8) — None for non-accord-holder
        // rows; admission CHECK requires Some only when identity_type
        // is 'accord_holder'.
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// Open an in-memory persist SQLite backend and seed it with rows.
/// Shares the same connection as the outbound queue (one SqliteBackend
/// holds every substrate primitive).
async fn directory_with(records: Vec<KeyRecord>) -> Arc<SqliteBackend> {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist directory");
    // Re-run migrations explicitly so all schemas (federation_keys,
    // edge_outbound_queue, cirisnode tables incl. V046 federation
    // announcement + delivery attestations) are present on the
    // shared connection. `FederationDirectorySqlite::open` only runs
    // the federation-directory schema by default.
    backend.run_migrations().await.expect("migrate");
    for rec in records {
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("put_public_key");
    }
    backend
}

/// Wrap a shared `SqliteBackend` in a `SqliteNodeCoreBackend` to call
/// the `NodeCoreService` `put_delivery_attestation` /
/// `count_delivery_attestations` surface (CIRISPersist v2.2.0).
fn node_core(directory: &Arc<SqliteBackend>) -> SqliteNodeCoreBackend {
    SqliteNodeCoreBackend::new(directory.conn_handle())
}

/// Hold a real `contribution:federation_announcement:v1` row, signed by
/// `author`, so persist's delivery-attestation door finds the announcement it
/// names (persist v60.0.0: a Contribution is a `scores` row on the attestation
/// plane; the delivery door checks the row is held). Returns its
/// `attestation_id`, the Contribution's id.
async fn put_test_announcement(
    directory: &Arc<SqliteBackend>,
    author: &FedKey,
    base: &std::path::Path,
    priority: ciris_persist::cirisnode::AnnouncementPriority,
    authority_class: ciris_persist::cirisnode::AuthorityClass,
    kind: ciris_persist::cirisnode::AnnouncementKind,
) -> String {
    use ciris_persist::cirisnode::types::{Cell, ContributionType};

    let payload = ciris_persist::cirisnode::FederationAnnouncementPayload {
        priority,
        kind,
        title: "test announcement".into(),
        body: "exercise the substrate FK".into(),
        authority_class,
        accord_payload: None,
        supersedes: None,
        expires_at: Utc::now() + chrono::Duration::days(1),
        evidence_refs: vec![],
    };
    let input = ciris_persist::cirisnode::ContributionInput {
        contribution_type: ContributionType::Proposal,
        subject: Cell {
            domain: "federation".into(),
            language: "en".into(),
            subject: Some(ciris_persist::cirisnode::SUBJECT_KIND.into()),
        },
        payload: serde_json::to_value(&payload).expect("payload to_value"),
        witness_set: None,
    };
    let row = ciris_persist::cirisnode::rows::plan_any_contribution(&input, &author.key_id)
        .expect("plan the announcement row");
    // A view over the shared directory; its own composed signer is unused
    // (the row is signed by `author` through `emit_attestation`).
    let engine = ciris_persist::Engine::from_shared(
        ciris_persist::BackendDispatch::Sqlite(directory.clone()),
        Arc::new(ciris_keyring::Ed25519SoftwareSigner::new(
            "announcement-view",
        )),
    );
    let signer = author.emit_signer(base).await;
    engine
        .emit_attestation(&signer, row)
        .await
        .expect("announcement row admitted")
}

/// A `PeerDirectory` backed by a static `Vec` — the fan-out target
/// for `Edge::send_mandatory`.
struct StaticPeerDirectory(Vec<String>);

#[async_trait]
impl PeerDirectory for StaticPeerDirectory {
    async fn list_recipients(&self) -> Result<Vec<String>, PersistOutboundError> {
        Ok(self.0.clone())
    }
}

/// A `PeerSubscriptionFilter` that explicitly rejects every peer for
/// `MessageType::FederationAnnouncement`. The Mandatory wire path
/// MUST bypass this — that is the load-bearing wire change.
struct RejectFederationAnnouncementFilter;

#[async_trait]
impl PeerSubscriptionFilter for RejectFederationAnnouncementFilter {
    async fn is_subscribed(&self, _peer: &str, mt: &MessageType) -> bool {
        !matches!(mt, MessageType::FederationAnnouncement)
    }
}

/// A no-op transport — `Edge::send_mandatory` only enqueues into the
/// outbound queue; we read rows out via `list_outbound`. The
/// dispatcher loop is not run.
struct NullTransport;

#[async_trait]
impl Transport for NullTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP // arbitrary; we never actually send
    }
    async fn send(&self, _: &str, _: &[u8]) -> Result<TransportSendOutcome, TransportError> {
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
}

async fn build_edge(
    tmp: &tempfile::TempDir,
    me: &FedKey,
    directory: Arc<SqliteBackend>,
    queue: Arc<SqliteBackend>,
    peers: Vec<String>,
    subscription_filter: Option<Arc<dyn PeerSubscriptionFilter>>,
) -> Edge {
    let signer = me.local_signer(tmp.path()).await;
    let mut b = Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .peer_directory(Arc::new(StaticPeerDirectory(peers)));
    if let Some(f) = subscription_filter {
        b = b.subscription_filter(f);
    }
    b.build().expect("build edge")
}

/// Build a representative `FederationAnnouncement` payload — an
/// Advisory-priority policy update signed by `RootWa` (the simplest
/// non-AccordCarrier shape that passes persist's constitutional
/// asymmetry).
fn sample_announcement() -> FederationAnnouncement {
    FederationAnnouncement {
        priority: AnnouncementPriority::Advisory,
        kind: AnnouncementKind::PolicyUpdate,
        title: "test policy update".into(),
        body: "exercise the substrate-tier Mandatory wire class".into(),
        authority_class: AuthorityClass::RootWa,
        accord_payload: None,
        supersedes: None,
        expires_at: chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        evidence_refs: vec![],
        accord_signatures: vec![],
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Round-trip — `Edge::send_mandatory` enqueues one outbound row per
/// peer in the directory (excluding the local steward's own key_id).
/// The wire envelopes are addressed individually; persist's
/// `list_outbound` reflects the per-peer expansion.
#[tokio::test]
async fn send_mandatory_enqueues_one_row_per_peer_in_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer_b = FedKey::new("peer-b", 0xBB);
    let peer_c = FedKey::new("peer-c", 0xCC);
    let peer_d = FedKey::new("peer-d", 0xDD);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&peer_b, &steward, "agent"),
        signed_record(&peer_c, &steward, "agent"),
        signed_record(&peer_d, &steward, "agent"),
    ])
    .await;
    // Same SqliteBackend instance for directory and outbound queue —
    // one connection, one set of federation_keys + edge_outbound_queue
    // tables, so the outbound's FK to federation_keys resolves
    // (V007 SQLite schema).
    let queue = directory.clone();
    let edge = build_edge(
        &tmp,
        &me,
        directory,
        queue.clone(),
        vec![
            me.key_id.clone(), // included in the directory; MUST be filtered
            peer_b.key_id.clone(),
            peer_c.key_id.clone(),
            peer_d.key_id.clone(),
        ],
        None,
    )
    .await;

    let handles = edge
        .send_mandatory(sample_announcement())
        .await
        .expect("send_mandatory");

    // FSD §3.2 reach property — one outbound row per non-self peer.
    assert_eq!(
        handles.len(),
        3,
        "Mandatory broadcast must produce one DurableHandle per non-self peer"
    );

    let rows = OutboundHandle::list_outbound(
        &*queue,
        OutboundFilter {
            message_type: Some("FederationAnnouncement".into()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list_outbound");
    assert_eq!(rows.len(), 3, "one outbound row per non-self peer");
    let destinations: std::collections::BTreeSet<String> =
        rows.iter().map(|r| r.destination_key_id.clone()).collect();
    let expected: std::collections::BTreeSet<String> = [&peer_b, &peer_c, &peer_d]
        .iter()
        .map(|k| k.key_id.clone())
        .collect();
    assert_eq!(destinations, expected);
    assert!(
        !destinations.contains(&me.key_id),
        "self-loopback must be filtered out of the Mandatory fan-out"
    );
}

/// Subscription-bypass — the load-bearing wire change of CIRISEdge#18.
///
/// Configure a `PeerSubscriptionFilter` that **rejects** every peer
/// for `MessageType::FederationAnnouncement`. `would_subscription_accept`
/// returns `false` for each peer. `send_mandatory` MUST bypass this
/// and still enqueue one row per peer.
///
/// Without the bypass, "Mandatory" is just a name. With it, the
/// federation has a substrate-tier governance reach path.
#[tokio::test]
async fn send_mandatory_bypasses_subscription_filter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer_b = FedKey::new("peer-b", 0xBB);
    let peer_c = FedKey::new("peer-c", 0xCC);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&peer_b, &steward, "agent"),
        signed_record(&peer_c, &steward, "agent"),
    ])
    .await;
    // Same SqliteBackend instance for directory and outbound queue —
    // one connection, one set of federation_keys + edge_outbound_queue
    // tables, so the outbound's FK to federation_keys resolves
    // (V007 SQLite schema).
    let queue = directory.clone();
    let edge = build_edge(
        &tmp,
        &me,
        directory,
        queue.clone(),
        vec![peer_b.key_id.clone(), peer_c.key_id.clone()],
        Some(Arc::new(RejectFederationAnnouncementFilter)),
    )
    .await;

    // Sanity: the filter rejects FederationAnnouncement for every
    // peer — under a subscription-respecting path these would be
    // dropped.
    assert!(
        !edge
            .would_subscription_accept(&peer_b.key_id, &MessageType::FederationAnnouncement)
            .await
    );
    assert!(
        !edge
            .would_subscription_accept(&peer_c.key_id, &MessageType::FederationAnnouncement)
            .await
    );
    // The filter still accepts OTHER message types — proves the
    // filter is wired and selectively vetoes FederationAnnouncement.
    assert!(
        edge.would_subscription_accept(&peer_b.key_id, &MessageType::AttestationGossip)
            .await
    );

    // The wire-level bypass: send_mandatory fans the announcement to
    // every peer despite the filter rejection.
    let handles = edge
        .send_mandatory(sample_announcement())
        .await
        .expect("send_mandatory");
    assert_eq!(handles.len(), 2, "Mandatory must reach both peers");

    let rows = OutboundHandle::list_outbound(
        &*queue,
        OutboundFilter {
            message_type: Some("FederationAnnouncement".into()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list");
    assert_eq!(
        rows.len(),
        2,
        "FSD §3.2 wire contract: Mandatory bypasses the per-peer subscription gate"
    );
}

/// AV-spoofed-attestation: an attestation whose
/// `signature_classical_base64` was signed by a key that doesn't match
/// `peer_key_id`'s federation pubkey is rejected at persist's
/// `put_delivery_attestation` admission (hybrid verify via directory).
///
/// This pins the persist-side admission gate that closes the loop on
/// edge-emitted attestations — edge's signing path produces verifiable
/// attestations; a spoofed one is caught here.
#[tokio::test]
async fn av_spoofed_attestation_rejected_at_persist_admission() {
    let steward = FedKey::new("steward-fed", 0x01);
    let peer = FedKey::new("peer-honest", 0xBB);
    let attacker = FedKey::new("attacker", 0xEE);
    let author = FedKey::new("announcement-author", 0xC1);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&peer, &steward, "agent"),
        signed_record(&attacker, &steward, "agent"),
        signed_record(&author, &steward, "steward"),
    ])
    .await;

    // Build a persist-side attestation claiming to be from `peer`,
    // signed by `attacker`'s key. The denormalized
    // `peer_pubkey_ed25519_base64` matches the directory — so the
    // spoof is in the SIGNATURE, not the claimed pubkey field.
    // Persist routes verify through `federation_keys[peer_key_id]`
    // and checks the signature against the rooted pubkey; the
    // attacker's signature won't verify.
    // persist v60.0.0 — the door checks the announcement is a HELD
    // `contribution:federation_announcement:v1` row before the signature, so
    // the spoof is filed against a real announcement (otherwise it is refused
    // for the missing row and the signature is never reached).
    let tmp = tempfile::tempdir().expect("tempdir");
    let announcement_id = put_test_announcement(
        &directory,
        &author,
        tmp.path(),
        ciris_persist::cirisnode::AnnouncementPriority::Advisory,
        ciris_persist::cirisnode::AuthorityClass::RootWa,
        ciris_persist::cirisnode::AnnouncementKind::ThreatAdvisory,
    )
    .await;
    let hash = [0xCD; 32];
    let mut att = ciris_persist::cirisnode::DeliveryAttestation {
        announcement_id,
        announcement_canonical_hash_base64: B64.encode(hash),
        peer_key_id: peer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer.pubkey_b64(),
        received_at: Utc::now(),
        transport_id: ciris_persist::cirisnode::TransportMedium::Reticulum,
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };
    let canonical = att.canonical_bytes().expect("canonical");
    // ATTACKER signs (not the claimed peer).
    let bad_sig = attacker.signer().sign(&canonical).expect("attacker sign");
    att.signature_classical_base64 = B64.encode(bad_sig);

    let err = node_core(&directory)
        .put_delivery_attestation(att)
        .await
        .expect_err("spoofed attestation must reject");
    let kind = err.kind();
    assert_eq!(
        kind, "cirisnode_signature",
        "spoofed-signature attestation must reject as cirisnode_signature; got {kind}"
    );
}

/// AV-replayed-attestation: PK `(announcement_id, peer_key_id)` on
/// persist's `federation_delivery_attestations` table. A duplicate
/// write is idempotent (FSD §3.2.1 — replay-safe). Persist returns
/// `Ok(())` twice without conflict-erroring; `count` reads back 1.
#[tokio::test]
async fn av_replayed_attestation_is_idempotent() {
    let steward = FedKey::new("steward-fed", 0x01);
    let peer = FedKey::new("peer-honest", 0xBB);
    let author = FedKey::new("announcement-author", 0xC1);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&peer, &steward, "agent"),
        signed_record(&author, &steward, "steward"),
    ])
    .await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let nc = node_core(&directory);
    let announcement_id = put_test_announcement(
        &directory,
        &author,
        tmp.path(),
        ciris_persist::cirisnode::AnnouncementPriority::Advisory,
        ciris_persist::cirisnode::AuthorityClass::RootWa,
        ciris_persist::cirisnode::AnnouncementKind::ThreatAdvisory,
    )
    .await;
    let hash = [0x77; 32];
    let mut att = ciris_persist::cirisnode::DeliveryAttestation {
        announcement_id: announcement_id.clone(),
        announcement_canonical_hash_base64: B64.encode(hash),
        peer_key_id: peer.key_id.clone(),
        peer_pubkey_ed25519_base64: peer.pubkey_b64(),
        received_at: Utc::now(),
        transport_id: ciris_persist::cirisnode::TransportMedium::Reticulum,
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };
    let canonical = att.canonical_bytes().expect("canonical");
    let sig = peer.signer().sign(&canonical).expect("sign");
    att.signature_classical_base64 = B64.encode(&sig);
    // HYBRID, per AV-33: ML-DSA-65 over `canonical || classical_sig`. A
    // classical-only row is hybrid-pending and Strict rejects it at admission.
    att.signature_pqc_base64 = Some(
        B64.encode(
            futures::executor::block_on({
                use ciris_keyring::PqcSigner as _;
                let mut bound = canonical.clone();
                bound.extend_from_slice(&sig);
                let p = peer.pqc_signer();
                async move { p.sign(&bound).await }
            })
            .expect("pqc sign"),
        ),
    );

    nc.put_delivery_attestation(att.clone())
        .await
        .expect("first put");
    nc.put_delivery_attestation(att)
        .await
        .expect("replay must be idempotent");
    let count = nc
        .count_delivery_attestations(&announcement_id)
        .await
        .expect("count");
    assert_eq!(
        count, 1,
        "replayed attestation must collapse to one row (PK = announcement_id, peer_key_id)"
    );
}

/// Edge-emitted-attestation round-trip: edge's wire shape +
/// canonical-bytes encoder are byte-equal with persist v2.2.0's, so
/// an attestation signed by edge's signer deserializes into persist's
/// wire type AND passes persist's admission (hybrid verify against
/// the federation directory).
///
/// Drift here = cross-repo wire break = federation can't verify
/// edge-produced attestations = mission-blocking. This test is the
/// integration-side counterpart of the in-crate canonical-bytes
/// golden vector.
#[tokio::test]
async fn edge_emitted_attestation_passes_persist_admission() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let peer = FedKey::new("peer-honest", 0xBB);
    let author = FedKey::new("announcement-author", 0xC1);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&peer, &steward, "agent"),
        signed_record(&author, &steward, "steward"),
    ])
    .await;
    let peer_signer = peer.local_signer(tmp.path()).await;
    let nc = node_core(&directory);

    let announcement_id = put_test_announcement(
        &directory,
        &author,
        tmp.path(),
        ciris_persist::cirisnode::AnnouncementPriority::Advisory,
        ciris_persist::cirisnode::AuthorityClass::RootWa,
        ciris_persist::cirisnode::AnnouncementKind::ThreatAdvisory,
    )
    .await;
    let received_at = Utc::now();
    let body_hash = [0x99u8; 32];
    let mut edge_att = DeliveryAttestation {
        announcement_id: announcement_id.clone(),
        announcement_canonical_hash_base64: B64.encode(body_hash),
        peer_key_id: peer.key_id.clone(),
        peer_pubkey_ed25519_base64: B64
            .encode(peer_signer.classical.public_key().await.expect("pubkey")),
        received_at,
        transport_id: TransportMedium::Reticulum,
        signature_classical_base64: String::new(),
        signature_pqc_base64: None,
    };
    let canonical = edge_att.canonical_bytes().expect("canonical");
    let sig = peer_signer.classical.sign(&canonical).await.expect("sign");
    edge_att.signature_classical_base64 = B64.encode(&sig);
    // HYBRID, matching what edge's own producer now REQUIRES rather than
    // treats as optional — this test asserts edge-emitted rows pass persist
    // admission, so signing it any other way would test a shape edge can no
    // longer emit.
    {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&sig);
        let pqc = peer_signer.pqc.as_ref().expect("hybrid signer");
        edge_att.signature_pqc_base64 = Some(B64.encode(pqc.sign(&bound).await.expect("pqc sign")));
    }

    let json = serde_json::to_string(&edge_att).expect("ser");
    let persist_att: ciris_persist::cirisnode::DeliveryAttestation =
        serde_json::from_str(&json).expect("edge → persist JSON must round-trip");
    nc.put_delivery_attestation(persist_att)
        .await
        .expect("edge-emitted attestation must pass persist admission");

    assert_eq!(
        nc.count_delivery_attestations(&announcement_id)
            .await
            .expect("count"),
        1
    );
}

/// `Edge::send_mandatory` MUST refuse non-Mandatory message types and
/// MUST require a `PeerDirectory` — both are typed errors, never
/// silent drops (MISSION.md §3 anti-pattern 6).
#[tokio::test]
async fn send_mandatory_rejects_misuse_with_typed_errors() {
    use ciris_edge::messages::DSARRequest;
    use ciris_edge::EdgeError;

    let tmp = tempfile::tempdir().expect("tempdir");
    let steward = FedKey::new("steward-fed", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let peer = FedKey::new("peer-b", 0xBB);

    let directory = directory_with(vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&me, &steward, "agent"),
        signed_record(&peer, &steward, "agent"),
    ])
    .await;
    // Same SqliteBackend instance for directory and outbound queue —
    // one connection, one set of federation_keys + edge_outbound_queue
    // tables, so the outbound's FK to federation_keys resolves
    // (V007 SQLite schema).
    let queue = directory.clone();

    // (a) Wrong delivery class: a Durable DSARRequest cannot ride
    //     send_mandatory.
    let edge = build_edge(
        &tmp,
        &me,
        directory.clone(),
        queue.clone(),
        vec![peer.key_id.clone()],
        None,
    )
    .await;
    let bogus = DSARRequest {
        target_agent_id_hash: "a".into(),
        target_signature_key_id: "b".into(),
        requested_by: "c".into(),
        justification: "d".into(),
    };
    match edge.send_mandatory(bogus).await {
        Err(EdgeError::DeliveryClassMismatch(MessageType::DSARRequest, "Durable", "Mandatory")) => {
        }
        other => panic!("expected DeliveryClassMismatch; got {other:?}"),
    }

    // (b) Missing peer directory: typed Config error.
    let signer = me.local_signer(tmp.path()).await;
    let edge_no_dir = Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .build()
        .expect("build (no peer_directory)");
    match edge_no_dir.send_mandatory(sample_announcement()).await {
        Err(EdgeError::Config(msg)) => assert!(
            msg.contains("PeerDirectory"),
            "Config error must name the missing wiring; got: {msg}"
        ),
        other => panic!("expected Config error; got {other:?}"),
    }
}

/// `FederationAnnouncement` declares `Mandatory { bypass_subscription:
/// true }` and `DeliveryAttestation` declares `Durable { requires_ack:
/// false }`. Pin these at the integration boundary so a regression in
/// the trait impl is caught even if the lib unit tests are bypassed.
#[test]
fn federation_announcement_wire_contract_pinned() {
    match FederationAnnouncement::DELIVERY {
        Delivery::Mandatory {
            authority_signed,
            bypass_subscription,
        } => {
            assert!(authority_signed);
            assert!(bypass_subscription);
        }
        other => panic!("FederationAnnouncement must declare Mandatory; got {other:?}"),
    }
    match DeliveryAttestation::DELIVERY {
        Delivery::Durable { requires_ack, .. } => assert!(!requires_ack),
        other => panic!("DeliveryAttestation must declare Durable; got {other:?}"),
    }
    assert_eq!(
        FederationAnnouncement::TYPE,
        MessageType::FederationAnnouncement
    );
    assert_eq!(DeliveryAttestation::TYPE, MessageType::DeliveryAttestation);
}
