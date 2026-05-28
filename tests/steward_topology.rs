//! Acceptance gate for CIRISEdge#20 — `Delivery::Federation { priority:
//! StewardClass }` + `Edge::send_federation` per-install steward
//! addressing in gossip topology.
//!
//! Recipient set is dynamically derived from persist's
//! `federation_keys` directory (`identity_type = "steward"`,
//! persist v2.7.0 `list_keys_by_identity_type`); the issue's ask #4
//! "dynamic topology adjustment when steward set changes" is the
//! load-bearing invariant exercised by
//! `send_federation_resolves_set_dynamically_on_each_call`.
//!
//! The DeliveryAttestation emission for Federation-class envelopes is
//! the same wire shape v0.6.0 introduced for Mandatory-class
//! envelopes (CIRISEdge#20 ask #3, FSD §3.2.1 attestation reused).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::{ClassicalSigner, Ed25519Signer};
use ciris_edge::handler::{Delivery, FederationPriority};
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::{
    is_federation_attestation_emitting_type, Edge, EdgeConfig, EdgeError, HybridPolicy, Message,
    MessageType, OutboundHandle, PeerSubscriptionFilter, StewardDirective, StewardDirectory,
    StewardKey,
};
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

/// Open an in-memory persist SQLite backend and seed it with rows.
/// Same connection backs federation_keys + edge_outbound_queue so the
/// outbound FK to federation_keys resolves (V007 SQLite schema).
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

/// A `StewardDirectory` backed by a static `Vec` — used by the
/// "no-stewards" / "subscription-filter" tests where we want a
/// deterministic recipient set independent of persist's directory
/// state. The dynamic-rotation test uses the persist-backed blanket
/// impl directly.
struct StaticStewardDirectory(Vec<StewardKey>);

#[async_trait]
impl StewardDirectory for StaticStewardDirectory {
    async fn current_stewards(&self) -> Result<Vec<StewardKey>, PersistOutboundError> {
        Ok(self.0.clone())
    }
}

/// A `PeerSubscriptionFilter` that rejects every peer for
/// `MessageType::StewardDirective`. Used to assert that
/// `Delivery::Federation` RESPECTS the subscription filter (the
/// distinguishing property from `Delivery::Mandatory`).
struct RejectStewardDirectiveFilter;

#[async_trait]
impl PeerSubscriptionFilter for RejectStewardDirectiveFilter {
    async fn is_subscribed(&self, _peer: &str, mt: &MessageType) -> bool {
        !matches!(mt, MessageType::StewardDirective)
    }
}

/// A no-op transport — `Edge::send_federation` only enqueues into the
/// outbound queue; we read rows out via `list_outbound`. The
/// dispatcher loop is not run.
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

async fn build_edge(
    tmp: &tempfile::TempDir,
    me: &FedKey,
    directory: Arc<SqliteBackend>,
    queue: Arc<SqliteBackend>,
    steward_dir: Arc<dyn StewardDirectory>,
    subscription_filter: Option<Arc<dyn PeerSubscriptionFilter>>,
) -> Edge {
    let signer = me.local_signer(tmp.path()).await;
    // Tests seed Ed25519-only rows (no PQC); accept those via the
    // sovereign-mode policy so the verify pipeline can clear them.
    // Strict (the default) would reject every test row as
    // hybrid-pending.
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    };
    let mut b = Edge::builder()
        .directory(directory as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(queue)
        .signer(signer)
        .transport(Arc::new(NullTransport))
        .steward_directory(steward_dir)
        .config(config);
    if let Some(f) = subscription_filter {
        b = b.subscription_filter(f);
    }
    b.build().expect("build edge")
}

fn sample_directive() -> StewardDirective {
    StewardDirective {
        title: "test steward directive".into(),
        body: "exercise the substrate Federation-class fan-out".into(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Recipient set is the directory's steward subset — `Edge::send_federation`
/// enqueues one outbound row per `identity_type="steward"` row in
/// persist's `federation_keys`. Pins the issue's ask #1 + #2 (recognition +
/// high-priority class with per-row durability).
#[tokio::test]
async fn send_federation_fans_out_to_seeded_stewards() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let steward_us = FedKey::new("steward-us", 0xB1);
    let steward_eu = FedKey::new("steward-eu", 0xB2);
    let steward_apac = FedKey::new("steward-apac", 0xB3);
    let agent_peer = FedKey::new("agent-peer", 0xC1);

    // Three stewards + one agent (non-steward). Bootstrap scrub-signs
    // every row (incl. itself). The blanket impl over the directory
    // resolves the steward set via `list_keys_by_identity_type("steward")`.
    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&steward_us, &bootstrap, "steward"),
        signed_record(&steward_eu, &bootstrap, "steward"),
        signed_record(&steward_apac, &bootstrap, "steward"),
        signed_record(&agent_peer, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let steward_dir: Arc<dyn StewardDirectory> = directory.clone();
    let edge = build_edge(&tmp, &me, directory, queue.clone(), steward_dir, None).await;

    let handles = edge
        .send_federation(sample_directive(), None)
        .await
        .expect("send_federation");

    // Four stewards (incl. bootstrap which is itself steward + us /
    // eu / apac); `edge-self` is `agent` so it doesn't count toward
    // the steward set in the first place.
    assert_eq!(
        handles.len(),
        4,
        "Federation fan-out must produce one DurableHandle per steward in the directory"
    );

    let rows = OutboundHandle::list_outbound(
        &*queue,
        OutboundFilter {
            message_type: Some("StewardDirective".into()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list_outbound");
    assert_eq!(
        rows.len(),
        4,
        "one outbound row per steward in the directory"
    );

    let destinations: std::collections::BTreeSet<String> =
        rows.iter().map(|r| r.destination_key_id.clone()).collect();
    let expected: std::collections::BTreeSet<String> = [
        "bootstrap-steward",
        "steward-us",
        "steward-eu",
        "steward-apac",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    assert_eq!(destinations, expected);
    assert!(
        !destinations.contains("agent-peer"),
        "non-steward agent must NOT receive a Federation fan-out"
    );
    assert!(
        !destinations.contains("edge-self"),
        "self (an agent here) is structurally excluded from the steward set"
    );
}

/// Ask #4 — dynamic topology adjustment. Edge re-derives the steward
/// set from persist's directory on every `send_federation` call (no
/// caching). Seed 3 stewards, send, then add a 4th steward, send
/// again; the second send must reach the 4-steward set.
#[tokio::test]
async fn send_federation_resolves_set_dynamically_on_each_call() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let steward_us = FedKey::new("steward-us", 0xB1);
    let steward_eu = FedKey::new("steward-eu", 0xB2);
    let steward_apac = FedKey::new("steward-apac", 0xB3);

    // Round 1 — three stewards (bootstrap + us + eu).
    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&steward_us, &bootstrap, "steward"),
        signed_record(&steward_eu, &bootstrap, "steward"),
    ])
    .await;
    let queue = directory.clone();
    let steward_dir: Arc<dyn StewardDirectory> = directory.clone();
    let edge = build_edge(
        &tmp,
        &me,
        directory.clone(),
        queue.clone(),
        steward_dir,
        None,
    )
    .await;

    let r1 = edge
        .send_federation(sample_directive(), None)
        .await
        .expect("send_federation r1");
    assert_eq!(r1.len(), 3, "round 1 — three stewards in the directory");

    // Round 2 — register a 4th steward (APAC rotation per FSD-002 §2.1).
    // No edge-side cache to invalidate; the next send sees the new set.
    directory
        .put_public_key(SignedKeyRecord {
            record: signed_record(&steward_apac, &bootstrap, "steward"),
        })
        .await
        .expect("put apac steward");

    let r2 = edge
        .send_federation(sample_directive(), None)
        .await
        .expect("send_federation r2");
    assert_eq!(
        r2.len(),
        4,
        "round 2 — directory now has 4 stewards; recipient set re-resolved on this call \
         (NO stale 3-steward cache — CIRISEdge#20 ask #4)"
    );

    // 3 + 4 = 7 outbound rows total for the StewardDirective wire type.
    let rows = OutboundHandle::list_outbound(
        &*queue,
        OutboundFilter {
            message_type: Some("StewardDirective".into()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list_outbound");
    assert_eq!(rows.len(), 7);
    let apac_count = rows
        .iter()
        .filter(|r| r.destination_key_id == "steward-apac")
        .count();
    assert_eq!(
        apac_count, 1,
        "the newly-registered APAC steward must receive exactly one row from round 2"
    );
}

/// Zero stewards — typed `EdgeError::NoStewards` (NOT a panic, NOT a
/// silent no-op). Closes MISSION.md §3 anti-pattern 6 (fail-loud) on
/// the steward-set-empty operational condition.
#[tokio::test]
async fn send_federation_with_zero_stewards_returns_typed_error() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);

    // Directory has ONLY a steward (bootstrap) + the agent caller, but
    // we stub the StewardDirectory to return an empty set (simulating
    // "directory loaded but no stewards present yet" — pre-bootstrap
    // operational state).
    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let queue = directory.clone();
    let empty_steward_dir: Arc<dyn StewardDirectory> = Arc::new(StaticStewardDirectory(vec![]));
    let edge = build_edge(&tmp, &me, directory, queue, empty_steward_dir, None).await;

    match edge.send_federation(sample_directive(), None).await {
        Err(EdgeError::NoStewards(FederationPriority::StewardClass)) => {}
        other => panic!("expected EdgeError::NoStewards(StewardClass); got {other:?}"),
    }
}

/// Ask #3 — Federation-class envelopes auto-emit a `DeliveryAttestation`
/// on verified receipt at every steward, same wire shape v0.6.0
/// introduced for the Mandatory class. Pinned at the wire-type allow-
/// list helper so the dispatch-side emission keys on the correct types.
#[tokio::test]
async fn federation_delivery_emits_attestation_per_recipient() {
    let _ = tracing_subscriber::fmt::try_init();
    // The emission criterion is `is_federation_attestation_emitting_type(MessageType)`
    // — the helper dispatch_inbound consults. Pin both wire-types
    // (CIRISEdge#18 v0.6.0 + CIRISEdge#20 v0.10.0) so any future
    // regression that drops one is caught here.
    assert!(
        is_federation_attestation_emitting_type(&MessageType::FederationAnnouncement),
        "FederationAnnouncement must trigger attestation emission (FSD §3.2.1)"
    );
    assert!(
        is_federation_attestation_emitting_type(&MessageType::StewardDirective),
        "StewardDirective (Federation class) must trigger attestation emission \
         (CIRISEdge#20 ask #3 — same wire shape as the Mandatory class introduces)"
    );
    // Non-attestation-emitting wire types stay out of the set —
    // verify the helper isn't a tautology.
    assert!(!is_federation_attestation_emitting_type(
        &MessageType::DeliveryAttestation
    ));
    assert!(!is_federation_attestation_emitting_type(
        &MessageType::AccordEventsBatch
    ));
    assert!(!is_federation_attestation_emitting_type(
        &MessageType::InlineText
    ));

    // End-to-end emission round-trip: build a verified StewardDirective
    // envelope, run dispatch_inbound, and verify the steward enqueued a
    // DeliveryAttestation row addressed back at the sender. The full
    // verify pipeline runs over a real persist directory — the
    // attestation is what an operator-facing collector observes.
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let sender = FedKey::new("sender-steward", 0xC0);
    let receiver = FedKey::new("receiver-steward", 0xD0);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&sender, &bootstrap, "steward"),
        signed_record(&receiver, &bootstrap, "steward"),
    ])
    .await;
    let queue = directory.clone();
    let steward_dir: Arc<dyn StewardDirectory> = directory.clone();
    // Use `sender`'s LocalSigner to sign the directive envelope, and
    // build an edge from `receiver`'s perspective so dispatch_inbound
    // emits an attestation FROM `receiver` ADDRESSED TO `sender`.
    let sender_signer = sender.local_signer(tmp.path()).await;
    let receiver_edge = build_edge(
        &tmp,
        &receiver,
        directory.clone(),
        queue.clone(),
        steward_dir,
        None,
    )
    .await;

    // Build + sign a real StewardDirective envelope from `sender` to
    // `receiver`. This is what the receiver's transport would deliver.
    let directive = sample_directive();
    let mut env = build_envelope(
        StewardDirective::TYPE,
        &sender.key_id,
        &receiver.key_id,
        &directive,
        None,
    )
    .expect("build_envelope");
    sign_envelope(&sender_signer, &mut env)
        .await
        .expect("sign_envelope");
    let envelope_bytes = serde_json::to_vec(&env).expect("serialize env");

    // Drive the dispatch_inbound pipeline directly — synchronous,
    // no listener loop. The test helper exists precisely for this
    // shape (CIRISEdge#20 receive-side attestation emission).
    let frame = InboundFrame {
        envelope_bytes,
        received_at: chrono::Utc::now(),
        transport: TransportId::HTTP,
    };
    receiver_edge.dispatch_inbound_for_test(frame).await;

    let attestation_rows = OutboundHandle::list_outbound(
        &*queue,
        OutboundFilter {
            message_type: Some("DeliveryAttestation".into()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list_outbound (attestation)");
    assert_eq!(
        attestation_rows.len(),
        1,
        "exactly one DeliveryAttestation must be emitted on verified Federation-class receipt"
    );
    let att_row = &attestation_rows[0];
    assert_eq!(
        att_row.destination_key_id, sender.key_id,
        "attestation must be addressed BACK to the sender of the StewardDirective"
    );
    assert_eq!(
        att_row.sender_key_id, receiver.key_id,
        "attestation must be sent FROM the receiver (the peer attesting receipt)"
    );
}

/// Federation respects the per-peer subscription filter — the
/// distinguishing property from `Delivery::Mandatory`. A peer in the
/// steward set whose `PeerSubscriptionFilter` rejects
/// `StewardDirective` is filtered OUT of the fan-out (route-with-
/// preference, NOT bypass-everything).
///
/// Compare with `send_mandatory_bypasses_subscription_filter` in
/// `federation_announcement.rs` — same shape, opposite assertion. The
/// two tests pin the architectural boundary between the two delivery
/// classes.
#[tokio::test]
async fn federation_class_distinct_from_mandatory_class_no_subscription_bypass() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = FedKey::new("bootstrap-steward", 0x01);
    let me = FedKey::new("edge-self", 0xAA);
    let steward_us = FedKey::new("steward-us", 0xB1);
    let steward_eu = FedKey::new("steward-eu", 0xB2);

    let directory = directory_with(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&steward_us, &bootstrap, "steward"),
        signed_record(&steward_eu, &bootstrap, "steward"),
    ])
    .await;
    let queue = directory.clone();
    let steward_dir: Arc<dyn StewardDirectory> = directory.clone();
    let edge = build_edge(
        &tmp,
        &me,
        directory,
        queue.clone(),
        steward_dir,
        Some(Arc::new(RejectStewardDirectiveFilter)),
    )
    .await;

    // Sanity — the filter rejects StewardDirective for every peer.
    assert!(
        !edge
            .would_subscription_accept("steward-us", &MessageType::StewardDirective)
            .await
    );
    assert!(
        !edge
            .would_subscription_accept("steward-eu", &MessageType::StewardDirective)
            .await
    );
    // Other message types still go through — proves the filter is
    // wired and selectively gates StewardDirective.
    assert!(
        edge.would_subscription_accept("steward-us", &MessageType::AttestationGossip)
            .await
    );

    // The route-with-preference behavior: send_federation HONORS the
    // filter (unlike send_mandatory which bypasses).
    let handles = edge
        .send_federation(sample_directive(), None)
        .await
        .expect("send_federation");
    assert!(
        handles.is_empty(),
        "Federation MUST respect the subscription filter — peers filtering \
         StewardDirective receive no row (NOT bypass-by-default; that's \
         Mandatory's contract per CIRISEdge#18). Got {} handles.",
        handles.len()
    );

    let rows = OutboundHandle::list_outbound(
        &*queue,
        OutboundFilter {
            message_type: Some("StewardDirective".into()),
            ..Default::default()
        },
        100,
    )
    .await
    .expect("list");
    assert!(
        rows.is_empty(),
        "no outbound rows when every steward filtered the wire type \
         (Federation respects subscription, FSD §3.2 boundary)"
    );
}

/// `FederationPriority::StewardClass` wire-shape pin: serializes /
/// `Delivery::Federation` declaration on `StewardDirective` survives
/// const-context use, and the priority variant round-trips through
/// `Debug`-shape. This is a structural pin — a regression here would
/// mean the v0.10.0 wire contract drifted.
#[test]
fn federation_priority_steward_class_round_trip() {
    // The const Delivery declaration MUST hold StewardClass.
    match StewardDirective::DELIVERY {
        Delivery::Federation {
            priority,
            requires_ack,
            max_attempts,
            ttl_seconds,
            ack_timeout_seconds,
        } => {
            assert_eq!(
                priority,
                FederationPriority::StewardClass,
                "StewardDirective MUST declare priority=StewardClass — \
                 the v0.10.0 wire contract"
            );
            assert!(
                !requires_ack,
                "StewardDirective is fire-and-forget at the inline-ACK layer; \
                 the DeliveryAttestation emission IS the audit observable \
                 (FSD §3.2.1 convention)"
            );
            assert_eq!(max_attempts, 100);
            assert_eq!(ttl_seconds, 14 * 24 * 60 * 60);
            assert!(ack_timeout_seconds.is_none());
        }
        other => panic!("StewardDirective::DELIVERY must be Delivery::Federation; got {other:?}"),
    }
    assert_eq!(StewardDirective::TYPE, MessageType::StewardDirective);

    // Equality + Copy properties on the priority discriminator —
    // structural pins that downstream consumers (NodeCore admission,
    // operator UIs) rely on for routing-table membership checks.
    let a = FederationPriority::StewardClass;
    let b = a;
    assert_eq!(a, b);
    // Debug-shape pin — operational dashboards format the variant.
    assert_eq!(format!("{a:?}"), "StewardClass");
}
