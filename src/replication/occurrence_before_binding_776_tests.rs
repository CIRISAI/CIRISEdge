//! **CIRISEdge#776 — an identity occurrence that arrives before its owner
//! binding is re-asked the moment the binding lands, not after the backoff.**
//!
//! On the mesh (run 36803946329) sub-1's node occurrence reached the publisher
//! before the owner binding that makes its signer an occurrence of sub-1's
//! owner. persist's gated occurrence door refused it, correctly at that moment
//! (`federation_signature_invalid` — "signer … is neither identity … nor an
//! active occurrence of it, nor a node it owns"), the bridge booked the refusal
//! `Transient` and the #544 backoff withheld the re-ask for 20 s (doubling).
//! The binding landed ~5 s later and nothing released the occurrence: the
//! room's first epoch was minted without the node.
//!
//! The witness is the bridge's own apply door and refusal memory, in process:
//! the occurrence is refused, its re-ask is suppressed; the binding is
//! admitted; the re-ask must be released AT ONCE (well under the 20 s base),
//! and the re-delivered occurrence admits. The release is keyed on the
//! occurrence's SIGNER — never "clear all backoff".
//!
//! `cargo test --lib occurrence_before_binding_776`
//!
//! A lib test module, not a `tests/` binary (the `pyo3-full` CI lane is at its
//! runner's disk limit linking test binaries).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::group_content::PersistGroupContentStore;
use crate::replication::directory::ReplicationDirectory as _;
use crate::replication::{BridgeConfig, EnvelopeKind, FederationDirectoryReplicationBridge};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::Digest as _;

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
}

struct Ident {
    key_id: String,
    seed: u8,
    ed: Ed25519SoftwareSigner,
    pqc: MlDsa65SoftwareSigner,
}

impl Ident {
    fn new(key_id: &str, seed: u8) -> Self {
        let mut ed = Ed25519SoftwareSigner::new(key_id);
        ed.import_key(&[seed; 32]).expect("import ed key");
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
                .expect("ml-dsa from seed");
        Self {
            key_id: key_id.to_owned(),
            seed,
            ed,
            pqc,
        }
    }

    async fn record(&self) -> KeyRecord {
        let ed_pub = self.ed.public_key().await.expect("ed pubkey");
        let pqc_pub = self.pqc.public_key().await.expect("pqc pubkey");
        let envelope = serde_json::json!({ "key_id": self.key_id });
        let canonical = serde_json::to_vec(&envelope).expect("serialize");
        let digest = sha2::Sha256::digest(&canonical);
        let sig = self.ed.sign(digest.as_slice()).await.expect("self-sign");
        KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: B64.encode(&ed_pub),
            pubkey_ml_dsa_65_base64: Some(B64.encode(&pqc_pub)),
            algorithm: "hybrid".to_string(),
            identity_type: "user".to_string(),
            identity_ref: self.key_id.clone(),
            valid_from: ts(),
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: B64.encode(sig),
            scrub_signature_pqc: None,
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: ts(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn signer(&self) -> Arc<crate::identity::LocalSigner> {
        let hw: Arc<dyn HardwareSigner> = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&[self.seed; 32], self.ed.current_alias())
                .expect("rebuild the signer"),
        );
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(
                &[self.seed ^ 0x55; 32],
                format!("{}-pqc", self.key_id),
            )
            .expect("rebuild the pqc half"),
        );
        Arc::new(crate::identity::LocalSigner::new(
            self.key_id.clone(),
            hw,
            Some(pqc),
        ))
    }
}

/// One node: its substrate, content store, engine key (the node), its owner.
struct Node {
    dir: Arc<SqliteBackend>,
    /// Kept alive with the node: the engine its occurrence was provisioned by.
    _store: PersistGroupContentStore,
    owner: String,
    me: String,
}

/// A device of `owner`, the `family_files_wire_736::device` shape: the node
/// key is `device`'s derived id, the owner binding is signed by `owner`, the
/// engine occurrence is provisioned (node-signed) under the owner.
async fn device(seed_idents: &[&Ident], owner: &Ident, device: &Ident) -> Node {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open substrate");
    dir.run_migrations().await.expect("migrate");
    for id in seed_idents {
        dir.put_public_key(SignedKeyRecord {
            record: id.record().await,
        })
        .await
        .expect("seed identity");
    }
    let ed_pub = device.ed.public_key().await.expect("pubkey");
    let derived = ciris_verify_core::fedcode::derive_key_id(device.ed.current_alias(), &ed_pub);
    let mut rec = device.record().await;
    rec.key_id = derived.clone();
    rec.identity_ref = derived.clone();
    rec.scrub_key_id = derived.clone();
    rec.identity_type = "node".to_string();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the derived signing key");
    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[device.seed; 32], device.ed.current_alias())
            .expect("rebuild the registered signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[device.seed ^ 0x55; 32],
            format!("{}-pqc", device.key_id),
        )
        .expect("rebuild the registered pqc half"),
    );
    let identity = crate::identity::LocalSigner::new(derived.clone(), hw, Some(pqc));
    let binding = crate::replication::attestation_bind::owner_binding_attestation(
        &owner.key_id,
        &derived,
        ts(),
        &owner.signer(),
    )
    .await
    .expect("build this node's owner binding");
    dir.put_attestation_authored(SignedAttestation {
        attestation: binding,
    })
    .await
    .expect("admit this node's owner binding");
    let store = PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        dir.clone(),
        &identity,
    )
    .await
    .expect("hybrid content store");
    let (me, _) = crate::content_occurrence::provision_engine_occurrence(
        store.engine(),
        &*dir,
        &owner.key_id,
        "server",
    )
    .await
    .expect("provision this node's engine occurrence");
    Node {
        dir,
        _store: store,
        owner: owner.key_id.clone(),
        me,
    }
}

/// `from`'s node key, owner binding and signed engine occurrence, as wire
/// bytes for the Attestation / IdentityOccurrence apply doors.
async fn device_rows(from: &Node) -> (KeyRecord, Vec<u8>, Vec<u8>) {
    let rec = FederationDirectory::lookup_public_key(&*from.dir, &from.me)
        .await
        .expect("lookup")
        .expect("the engine's derived key is registered");
    let binding = FederationDirectory::list_attestations_since(&*from.dir, None, 256)
        .await
        .expect("list the attestation plane")
        .into_iter()
        .map(|r| r.attestation)
        .find(|a| {
            a.attested_key_id == from.me
                && ciris_persist::federation::admission::is_owner_binding_envelope(
                    &a.attestation_envelope,
                )
        })
        .expect("the node's owner binding");
    let occ = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .expect("list the signed occurrence plane")
        .into_iter()
        .map(|s| s.occurrence)
        .find(|o| {
            o.identity_occurrence.occurrence_key_id == from.me
                && o.identity_occurrence.identity_key_id == from.owner
        })
        .expect("the engine occurrence is on the signed plane");
    (
        rec,
        serde_json::to_vec(&binding).expect("encode binding"),
        serde_json::to_vec(&occ).expect("encode occurrence"),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_occurrence_refused_before_its_binding_is_re_asked_when_the_binding_lands_776() {
    let owner = Ident::new("person-o-776", 0x71);
    let dev = Ident::new("node-d-776", 0x72);
    let watcher_dev = Ident::new("node-x-776", 0x73);
    let watcher_owner = Ident::new("person-w-776", 0x74);
    // D: the device whose occurrence and binding travel. X: the node they
    // reach, which knows D's KEY (the Key plane is not what this is about)
    // but not yet its binding.
    let other_dev = Ident::new("node-e-776", 0x75);
    let d = device(&[&owner], &owner, &dev).await;
    // E: a second device of the same owner whose binding does NOT arrive —
    // the release must be keyed on D's signer, never a blanket clear.
    let e = device(&[&owner], &owner, &other_dev).await;
    let x = device(&[&owner, &watcher_owner], &watcher_owner, &watcher_dev).await;
    let (d_rec, d_binding, d_occ) = device_rows(&d).await;
    let (e_rec, _e_binding, e_occ) = device_rows(&e).await;
    for rec in [d_rec, e_rec] {
        x.dir
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("the devices' keys at X");
    }
    let bridge = FederationDirectoryReplicationBridge::with_config(
        Arc::clone(&x.dir) as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    )
    .with_local_key_id(Some(x.me.clone()));
    let occ_hash: [u8; 32] = sha2::Sha256::digest(&d_occ).into();

    // The occurrence first: refused (its signer is not yet bound to the
    // identity it names), and its re-ask suppressed by the backoff.
    let first = bridge
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &d_occ, Some(&d.me))
        .await;
    assert!(
        !first.is_admitted(),
        "precondition: refused before the binding: {first:?}"
    );
    assert!(
        bridge.retry_suppressed(EnvelopeKind::IdentityOccurrence, &occ_hash),
        "precondition: the backoff withholds the re-ask"
    );

    let e_hash: [u8; 32] = sha2::Sha256::digest(&e_occ).into();
    let e_first = bridge
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &e_occ, Some(&e.me))
        .await;
    assert!(
        !e_first.is_admitted(),
        "precondition: E's occurrence refused too"
    );

    // The binding lands.
    let bound = bridge
        .apply_envelope_bytes(EnvelopeKind::Attestation, &d_binding, Some(&d.me))
        .await;
    assert!(bound.is_admitted(), "the owner binding admits: {bound:?}");

    // The re-ask is released AT ONCE — keyed on the occurrence's signer.
    assert!(
        !bridge.retry_suppressed(EnvelopeKind::IdentityOccurrence, &occ_hash),
        "the occurrence's re-ask is still suppressed after its signer's binding landed: the next round will not ask for it until the 20 s+ backoff elapses (CIRISEdge#776)"
    );

    assert!(
        bridge.retry_suppressed(EnvelopeKind::IdentityOccurrence, &e_hash),
        "E's occurrence waits on E's binding, which has not landed: D's binding must \
         not release it"
    );

    // And re-delivered, it admits.
    let second = bridge
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &d_occ, Some(&d.me))
        .await;
    assert!(
        second.is_admitted(),
        "the re-delivered occurrence admits: {second:?}"
    );
    assert!(
        x.dir
            .list_identity_occurrences_active(&owner.key_id)
            .await
            .expect("read")
            .iter()
            .any(|o| o.occurrence_key_id == d.me),
        "D is an active occurrence of its owner at X"
    );
}

/// The release KICKS: two in-process runtimes over a loopback transport, the
/// scheduler cadence an hour, so only the kick can make X ask D again in
/// time. X pulls D's occurrence on the IdentityOccurrence plane before D's
/// binding exists at X (refused, indexed on D's signer with D as the peer);
/// the binding is then admitted at X; X must hold D's occurrence within a
/// bound far under both the cadence and the 20 s backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // two runtimes and a loopback, one sequence on purpose
async fn the_release_kicks_a_re_ask_of_the_peer_that_offered_the_row_776() {
    use crate::replication::registry::ReplicationRegistry;
    use crate::replication::{
        self_publish_set, ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig,
        SchedulerConfig,
    };
    use crate::transport::{
        InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
    };

    type Registries = Arc<std::sync::Mutex<HashMap<String, Arc<ReplicationRegistry>>>>;
    struct Loopback {
        me: String,
        registries: Registries,
    }
    #[async_trait::async_trait]
    impl Transport for Loopback {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            destination_key_id: &str,
            envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            let dest = self
                .registries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(destination_key_id)
                .cloned();
            let Some(dest) = dest else {
                return Err(TransportError::Io(format!("no node {destination_key_id}")));
            };
            let (me, bytes) = (self.me.clone(), envelope_bytes.to_vec());
            tokio::spawn(async move {
                let _ = dest.route_inbound_bytes(&me, &bytes).await;
            });
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
    }

    let owner = Ident::new("person-o-776k", 0x81);
    let dev = Ident::new("node-d-776k", 0x82);
    let watcher_owner = Ident::new("person-w-776k", 0x83);
    let watcher_dev = Ident::new("node-x-776k", 0x84);
    let d = device(&[&owner], &owner, &dev).await;
    let x = device(&[&owner, &watcher_owner], &watcher_owner, &watcher_dev).await;
    let (d_rec, d_binding, _d_occ) = device_rows(&d).await;
    x.dir
        .put_public_key(SignedKeyRecord { record: d_rec })
        .await
        .expect("D's key at X");

    let registries: Registries = Arc::new(std::sync::Mutex::new(HashMap::new()));
    let start = |node: &Node, peer: &str, publish: Option<Vec<String>>| {
        let registries = Arc::clone(&registries);
        let dir = Arc::clone(&node.dir);
        let me = node.me.clone();
        let peer = peer.to_owned();
        async move {
            let rt = ReplicationRuntime::start(
                dir as Arc<dyn FederationDirectory>,
                Arc::new(Loopback {
                    me: me.clone(),
                    registries: Arc::clone(&registries),
                }) as Arc<dyn Transport>,
                vec![ReplicationPeer {
                    peer_key_id: peer,
                    kind: EnvelopeKind::IdentityOccurrence,
                }],
                ReplicationRuntimeConfig {
                    scheduler: SchedulerConfig {
                        cadence: Duration::from_secs(3600),
                        round_timeout: Duration::from_secs(5),
                        ..SchedulerConfig::default()
                    },
                    local_key_id: Some(me.clone()),
                    ..ReplicationRuntimeConfig::default()
                },
                publish.map(self_publish_set),
            )
            .await;
            registries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(me, rt.registry());
            rt
        }
    };
    let mut rt_d = start(&d, &x.me, Some(vec![d.me.clone(), owner.key_id.clone()])).await;
    let mut rt_x = start(&x, &d.me, None).await;
    let holds_d = |x_dir: Arc<SqliteBackend>, owner: String, d_me: String| async move {
        x_dir
            .list_identity_occurrences_active(&owner)
            .await
            .unwrap_or_default()
            .iter()
            .any(|o| o.occurrence_key_id == d_me)
    };

    // X asks D: the occurrence arrives before its binding, and is refused.
    rt_x.round_now(&d.me).await.expect("kick X → D");
    let deadline = Instant::now() + Duration::from_secs(15);
    while rt_x.bridge().refusal_memory_len() == 0 {
        assert!(
            Instant::now() < deadline,
            "precondition: X refused D's occurrence (its binding is not at X yet)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!holds_d(Arc::clone(&x.dir), owner.key_id.clone(), d.me.clone()).await);

    // The binding lands at X (here by hand; on the mesh, the Attestation plane).
    let released_at = Instant::now();
    let bound = rt_x
        .bridge()
        .apply_envelope_bytes(EnvelopeKind::Attestation, &d_binding, Some(&d.me))
        .await;
    assert!(bound.is_admitted(), "the binding admits: {bound:?}");

    // Only the release KICK can bring the occurrence in time: the cadence is
    // an hour and the backoff 20 s.
    let bound_by = Duration::from_secs(5);
    while !holds_d(Arc::clone(&x.dir), owner.key_id.clone(), d.me.clone()).await {
        assert!(
            released_at.elapsed() < bound_by,
            "D's occurrence was not re-asked within {bound_by:?} of its binding landing: \
             the release did not kick a round toward the peer that offered it \
             (CIRISEdge#776)"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    rt_x.shutdown().await;
    rt_d.shutdown().await;
}

/// No kick loop: a refusal whose signer IS bound was about something else —
/// it waits on the ordinary window and is never indexed on the signer, so no
/// later binding admission can release-and-kick it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_whose_signer_is_bound_is_not_indexed_for_a_kick_776() {
    let owner = Ident::new("person-o-776n", 0x91);
    let dev = Ident::new("node-d-776n", 0x92);
    let watcher_owner = Ident::new("person-w-776n", 0x93);
    let watcher_dev = Ident::new("node-x-776n", 0x94);
    let d = device(&[&owner], &owner, &dev).await;
    let x = device(&[&owner, &watcher_owner], &watcher_owner, &watcher_dev).await;
    let (d_rec, d_binding, d_occ) = device_rows(&d).await;
    x.dir
        .put_public_key(SignedKeyRecord { record: d_rec })
        .await
        .expect("D's key at X");
    let bridge = FederationDirectoryReplicationBridge::with_config(
        Arc::clone(&x.dir) as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    )
    .with_local_key_id(Some(x.me.clone()));
    // The binding FIRST: D is bound.
    let bound = bridge
        .apply_envelope_bytes(EnvelopeKind::Attestation, &d_binding, Some(&d.me))
        .await;
    assert!(bound.is_admitted());
    // A tampered occurrence from D: refused for its signature, not its binding.
    let mut v: serde_json::Value = serde_json::from_slice(&d_occ).expect("occurrence json");
    let env = v
        .get_mut("signed_envelope")
        .and_then(serde_json::Value::as_object_mut)
        .expect("signed_envelope");
    env.insert("device_class".to_owned(), serde_json::json!("tampered"));
    let tampered = serde_json::to_vec(&v).expect("encode");
    let hash: [u8; 32] = sha2::Sha256::digest(&tampered).into();
    let refused = bridge
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &tampered, Some(&d.me))
        .await;
    assert!(
        !refused.is_admitted(),
        "the tampered occurrence is refused: {refused:?}"
    );
    assert_eq!(
        bridge.parked_on_signer_len(),
        0,
        "a bound signer's refusal is never indexed for a release kick"
    );
    if refused.retry_disposition().is_some() {
        assert!(
            bridge.retry_suppressed(EnvelopeKind::IdentityOccurrence, &hash),
            "it waits on the ordinary window"
        );
    }
}
