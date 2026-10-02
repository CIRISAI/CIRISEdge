//! CIRISEdge#752 — a relay's published devices reach a stranger with their
//! owner-binding (`FSD/FIRST_CONTACT.md` §2.3, I21; CC 5.4.6; CIRISServer#701).
//!
//! Three identities, two running nodes, real Reticulum links:
//!
//! - **owner `O`** with an announced device **`D`** (the owner-binding
//!   `O → D` at `cohort_scope: federation`) — `D`'s key, its content-only
//!   occurrence (identity `O`, signed by `D`) and the binding are rows the
//!   relay holds, as the canonical does after `D` announced to it;
//! - **relay `C`** (production's canonical shape) with a `KindPublishSelector`
//!   publishing `D` on `Key` and `IdentityOccurrence`;
//! - **stranger `X`**, peered only with `C`, and NO consent either way.
//!
//! `C` and `X` accept one valid root, so the #659 Rooted floor passes (as it
//! does in production through the accord) and what is measured is the
//! first-contact narrowing alone. Asserted on `X`'s ADMITTED rows, never on
//! logs: `X` holds `D`'s key, `D`'s occurrence and `O → D`, and persist's
//! `nodes_owned_by(O)` at `X` names `D`. On the pre-#752 code the binding is
//! withheld at `C` (`recipient_not_in_send_set`, first-contact narrowing), so
//! `X` never holds it — and cannot admit `D`'s occurrence either (persist's
//! `signer_acts_for` lifts a node signing its own occurrence only through the
//! owner-binding).
//!
//! Negatives, in the same run after the positive converged: `O → U` at `self`
//! (a published but unannounced device), `O → E` (announced, but `C` does not
//! publish `E`) and a consent grant `O → D` never reach `X`. And with no
//! selector nothing about others reaches `X` at all.
//!
//! `cargo test --features transport-http,transport-reticulum --test relay_roster_752`
#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::WithholdReason;
use ciris_edge::replication::attestation_bind::{
    bind_attestation_envelope, owner_binding_attestation, replication_consent_attestation,
    AttestationColumns, DEFAULT_CONSENT_PREFIXES,
};
use ciris_edge::replication::bridge::KindPublishSelector;
use ciris_edge::replication::{
    self_publish_set, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{
    Attestation, FederationDirectory, SignedAttestation, SignedIdentityOccurrence,
};
use ciris_persist::store::sqlite::SqliteBackend;
use common::{build_reticulum_with_retry, directory_with};
use sha2::Digest as _;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

/// A production-shaped identity: a friendly alias, a hybrid keypair, and a
/// key id that BINDS the pubkey fingerprint (`derive_key_id`), exactly as
/// persist derives it — so Stage 1's `key_id_binds_pubkey` holds for the
/// announce, which is what `owns_key` means for a first-contact peer.
struct Ident {
    key_id: String,
    ed: Arc<Ed25519SoftwareSigner>,
    pqc: Arc<MlDsa65SoftwareSigner>,
    ed_pub: Vec<u8>,
    pqc_pub_b64: String,
    /// Minted once per (identity, type): the same bytes on every directory,
    /// so the Key plane converges instead of refusing `conflicting_version`.
    records:
        tokio::sync::Mutex<std::collections::HashMap<String, ciris_persist::federation::KeyRecord>>,
}

impl Ident {
    async fn new(alias: &str, seed: u8) -> Self {
        let mut ed = Ed25519SoftwareSigner::new(alias);
        ed.import_key(&[seed; 32]).expect("import ed key");
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{alias}-pqc"))
                .expect("ml-dsa from seed");
        let ed_pub = ed.public_key().await.expect("ed pubkey");
        let pqc_pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pqc.public_key().await.expect("pqc pubkey"),
        );
        let key_id = ciris_verify_core::fedcode::derive_key_id(ed.current_alias(), &ed_pub);
        Self {
            key_id,
            ed: Arc::new(ed),
            pqc: Arc::new(pqc),
            ed_pub,
            pqc_pub_b64,
            records: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn ed_pub_b64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.ed_pub)
    }
    fn signer(&self) -> Arc<LocalSigner> {
        let classical: Arc<dyn HardwareSigner> = Arc::clone(&self.ed) as Arc<dyn HardwareSigner>;
        let pqc: Arc<dyn PqcSigner> = Arc::clone(&self.pqc) as Arc<dyn PqcSigner>;
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
    }
    /// A SELF-SIGNED registration the way persist's `register_self_federation_key`
    /// mints one: the envelope bound to its subject (CIRISPersist#659 — a
    /// subject-blind envelope is refused on the wire), CEG-canonical, hybrid-scrubbed.
    /// No steward, no test root: `root_binding` answers `NotRootedAtSteward`.
    async fn record(&self, identity_type: &str) -> ciris_persist::federation::KeyRecord {
        if let Some(r) = self.records.lock().await.get(identity_type) {
            return r.clone();
        }
        let r = self.mint_record(identity_type).await;
        self.records
            .lock()
            .await
            .insert(identity_type.to_owned(), r.clone());
        r
    }
    async fn mint_record(&self, identity_type: &str) -> ciris_persist::federation::KeyRecord {
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            identity_type,
            &self.ed_pub_b64(),
            Some(&self.pqc_pub_b64),
            None,
        )
        .expect("bind subject");
        let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
        let digest = sha2::Sha256::digest(&canonical);
        let (sig_classical, sig_pqc) =
            sign_bound_hybrid(&self.signer(), &canonical, "self registration")
                .await
                .expect("hybrid self-scrub");
        let now = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
            chrono::Utc::now(),
        );
        ciris_persist::federation::KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: self.ed_pub_b64(),
            pubkey_ml_dsa_65_base64: Some(self.pqc_pub_b64.clone()),
            algorithm: "hybrid".to_string(),
            identity_type: identity_type.to_string(),
            identity_ref: self.key_id.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig_classical,
            scrub_signature_pqc: sig_pqc,
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            // persist v47.3.0 (CIRISPersist#901): a Key-kind root is valid only if
            // its holder's record carries attested hardware evidence — persist's own
            // Layer-A-valid mock (the wire door checks structure where it lands).
            attestation_evidence: Some(
                ciris_persist::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }
}

/// A signed, bound `delegates_to` row at `federation` — the shape of both the
/// owner's ACCEPTANCE (`owner → R`, `[infra:attest, infra:serve]`) and a root's
/// self-CHARTER (`R → R`, plus its recovery pre-commitment).
async fn delegates_to_row(
    signer: &LocalSigner,
    attester: &str,
    subject: &str,
    scope: &[&str],
    extra: serde_json::Map<String, serde_json::Value>,
    label: &str,
) -> Attestation {
    let asserted_at = chrono::Utc::now();
    let attestation_id = {
        let mut h = sha2::Sha256::new();
        h.update(label.as_bytes());
        h.update(attester.as_bytes());
        h.update(subject.as_bytes());
        format!("{label}-{}", &hex::encode(h.finalize())[..24])
    };
    let subjects = vec![subject.to_owned()];
    let mut envelope = serde_json::json!({
        "id": attestation_id,
        "attesting_key_id": attester,
        "attested_key_id": subject,
        "attestation_type": "delegates_to",
        "scope": scope,
    });
    for (k, v) in extra {
        envelope[k] = v;
    }
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: attester,
            attestation_type: "delegates_to",
            attested_key_id: subject,
            subject_key_ids: &subjects,
            cohort_scope: "federation",
            weight: None,
        },
    );
    let asserted_at =
        ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(asserted_at);
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) = sign_bound_hybrid(signer, &canonical, label)
        .await
        .expect("hybrid sign");
    Attestation {
        attestation_id,
        attesting_key_id: attester.to_owned(),
        attested_key_id: subject.to_owned(),
        attestation_type: "delegates_to".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: attester.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

async fn put(dir: &SqliteBackend, att: Attestation) -> String {
    let id = att.attestation_id.clone();
    dir.put_attestation(SignedAttestation { attestation: att })
        .await
        .unwrap_or_else(|e| panic!("put {id}: {e:?}"));
    id
}

struct Root {
    key: Ident,
    successor: Ident,
}

impl Root {
    async fn new(name: &str, seed: u8) -> Self {
        Self {
            key: Ident::new(name, seed).await,
            successor: Ident::new(&format!("{name}-successor"), seed.wrapping_add(1)).await,
        }
    }
    async fn records(&self) -> Vec<ciris_persist::federation::KeyRecord> {
        vec![
            self.key.record("user").await,
            self.successor.record("user").await,
        ]
    }
    /// `delegates_to(R → R, [infra:serve, infra:attest])` with the recovery
    /// pre-commitment — persist's `trust_root_valid` leg 2.
    async fn charter(&self) -> Attestation {
        // persist v53 (CC 3.2 T3, rc7) — the commitment binds the successor's
        // key id AND both public keys, read off its registered record.
        let successor = ciris_persist::federation::trust_root::CommittedKey::from_record(
            &self.successor.record("user").await,
        )
        .expect("the successor is hybrid");
        let commitment = ciris_persist::federation::trust_root::pre_rotation_commitment(
            std::slice::from_ref(&successor),
        )
        .expect("commitment");
        let mut extra = serde_json::Map::new();
        extra.insert(
            "pre_rotation_commitment".into(),
            serde_json::Value::String(commitment),
        );
        // persist v51 (CIRISPersist#937/#938, CC 3.2 T4a/T6 rc6) — the rc6
        // charter carries its three members in the signed bytes. A KEY root
        // holds no lineage, so T4a's attach gate is not armed for it; the
        // members ride the charter every root now signs, and the ladder
        // proves they change nothing about rooting a key root.
        rc6_charter_members(&mut extra);
        extra.extend(trust_job(
            ciris_persist::federation::trust_root::TRUST_CHARTER_DIMENSION,
        ));
        delegates_to_row(
            &self.key.signer(),
            &self.key.key_id,
            &self.key.key_id,
            &["infra:serve", "infra:attest"],
            extra,
            "charter",
        )
        .await
    }
}

/// persist v53 (CIRISPersist#973, CC 3.2 T4a "bundle only") — a new
/// `delegates_to` with no `trust:{job}` label gives no acceptance and is no
/// charter, so each row names its job. The roots here are KEY roots (no
/// lineage), so an acceptance names no `attached_head_digest`.
fn trust_job(dimension: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("dimension".into(), dimension.into());
    m
}

/// The rc6 charter members (persist v51 `envelope::paths`): a 7-day attach
/// window, a 24-hour witness cadence, and witnessed mode off. persist v53
/// (#973) removed `DEFAULT_WITNESS_QUORUM` (was 1): silence and `0` are one
/// state, and a declared `1` is refused at the charter door.
fn rc6_charter_members(extra: &mut serde_json::Map<String, serde_json::Value>) {
    use ciris_persist::federation::envelope::paths;
    extra.insert(paths::ATTACH_WINDOW_SECS.into(), 604_800.into());
    extra.insert(paths::WITNESS_CADENCE_SECS.into(), 86_400.into());
    extra.insert(paths::WITNESS_QUORUM.into(), 0.into());
}

/// The owner-binding `delegates_to(owner → node)` exactly as
/// `attestation_bind::owner_binding_attestation` mints it, at a chosen
/// `cohort_scope`: `self` is what a claim writes; `federation` is the announce.
async fn owner_binding_at(owner: &Ident, node: &str, cohort_scope: &str) -> Attestation {
    owner_binding_signed_by(owner, owner, node, cohort_scope).await
}

/// CIRISEdge#727 — the same row with the attester FIELD naming `owner` but the
/// signature made by `signer`. With `signer == owner` it is the genuine
/// binding; with a stranger's key it is the forged-signature negative.
async fn owner_binding_signed_by(
    owner: &Ident,
    signer: &Ident,
    node: &str,
    cohort_scope: &str,
) -> Attestation {
    let asserted_at = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
        chrono::Utc::now(),
    );
    let attestation_id = format!("owner-binding-{node}");
    let subjects = vec![node.to_owned()];
    let mut envelope =
        ciris_persist::federation::self_at_login::owner_binding_delegates_to_envelope(
            node,
            &["infra:network_presence".to_string()],
        );
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: &owner.key_id,
            attestation_type: "delegates_to",
            attested_key_id: node,
            subject_key_ids: &subjects,
            cohort_scope,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) = sign_bound_hybrid(&signer.signer(), &canonical, "owner binding")
        .await
        .expect("hybrid sign");
    Attestation {
        attestation_id,
        attesting_key_id: owner.key_id.clone(),
        attested_key_id: node.to_owned(),
        attestation_type: "delegates_to".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope.to_owned(),
        // `tier` is where the row LIVES (persist's federation listings read
        // `tier = 'federation'` only — a `local` row is invisible to
        // `owner_of`); `cohort_scope` is the AUDIENCE. A claim's binding is a
        // federation-tier row at a `self` audience; the announce widens the
        // audience, never the tier.
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// `D`'s content-only occurrence under identity `O`, signed by `D` — the shape
/// persist admits once `O → D` is live (CIRISPersist#851 content-only form).
async fn occurrence(owner: &Ident, node: &Ident) -> SignedIdentityOccurrence {
    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let at = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        chrono::Utc::now().timestamp_millis(),
    )
    .expect("millis");
    let (x25519, ml_kem) = (b64(&[0x07; 32]), b64(&[0x09; 1184]));
    let device_class = ciris_persist::federation::types::device_class::SERVER;
    let env = serde_json::json!({
        "attesting_key_id": node.key_id,
        "identity_key_id": owner.key_id,
        "occurrence_key_id": node.key_id,
        "device_class": device_class,
        "encryption_pubkeys": { "x25519_base64": x25519, "ml_kem_768_base64": ml_kem },
        "asserted_at": at.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": serde_json::Value::Null,
        "hardware_attestation": serde_json::Value::Null,
    });
    let bytes = ciris_verify_core::jcs::canonicalize(&env).expect("jcs");
    let (ed, pqc) = sign_bound_hybrid(&node.signer(), &bytes, "occurrence")
        .await
        .expect("hybrid sign");
    SignedIdentityOccurrence {
        identity_occurrence: ciris_persist::federation::types::IdentityOccurrence {
            identity_key_id: owner.key_id.clone(),
            occurrence_key_id: node.key_id.clone(),
            device_class: device_class.into(),
            hardware_attestation: None,
            asserted_at: at,
            valid_until: None,
            encryption_pubkeys: Some(ciris_persist::federation::types::EncryptionPubkeys {
                x25519_base64: x25519,
                ml_kem_768_base64: ml_kem,
            }),
            transport_binding: None,
            persist_row_hash: String::new(),
        },
        attesting_key_id: node.key_id.clone(),
        signed_envelope: env,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: pqc,
        },
    }
}

/// A running node: a self-signed node key, a self-signed owner, the
/// owner-binding at `federation`, the owner's acceptance of the shared root.
struct Node {
    key: Arc<Ident>,
    owner: Ident,
    dir: Arc<SqliteBackend>,
    metrics: EdgeMetrics,
}

impl Node {
    async fn new(
        name: &str,
        key: Arc<Ident>,
        seed: u8,
        peer: &Ident,
        root: &Root,
        extra: Vec<ciris_persist::federation::KeyRecord>,
    ) -> Self {
        let owner = Ident::new(&format!("owner-{name}-752"), seed.wrapping_add(0x40)).await;
        let mut records = vec![
            key.record("node").await,
            owner.record("user").await,
            peer.record("node").await,
        ];
        records.extend(root.records().await);
        records.extend(extra);
        let dir = directory_with(records).await;
        put(&dir, root.charter().await).await;
        let binding = owner_binding_attestation(
            &owner.key_id,
            &key.key_id,
            chrono::Utc::now(),
            &owner.signer(),
        )
        .await
        .expect("owner binding");
        put(&dir, binding).await;
        let accepts = delegates_to_row(
            &owner.signer(),
            &owner.key_id,
            &root.key.key_id,
            &["infra:attest", "infra:serve"],
            trust_job(ciris_persist::federation::trust_root::TRUST_ACCEPTS_DIMENSION),
            "accepts",
        )
        .await;
        put(&dir, accepts).await;
        Self {
            key,
            owner,
            dir,
            metrics: EdgeMetrics::new(),
        }
    }

    async fn holds(&self, attestation_id: &str) -> bool {
        self.dir
            .list_attestations_since(None, 4096)
            .await
            .expect("list")
            .iter()
            .any(|r| r.attestation.attestation_id == attestation_id)
    }

    async fn holds_key(&self, key: &Ident) -> bool {
        self.dir
            .lookup_public_key(&key.key_id)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    async fn holds_occurrence(&self, owner: &Ident, node: &Ident) -> bool {
        self.dir
            .list_signed_identity_occurrences_for(&owner.key_id)
            .await
            .unwrap_or_default()
            .iter()
            .any(|o| o.identity_occurrence.occurrence_key_id == node.key_id)
    }

    /// Persist's own roster read: the nodes `owner` owns, as THIS node sees it.
    async fn lists_under(&self, owner: &Ident) -> Vec<String> {
        ciris_persist::federation::admission::nodes_owned_by(
            &*self.dir as &dyn FederationDirectory,
            &owner.key_id,
        )
        .await
        .unwrap_or_default()
    }

    fn auth(&self) -> ReticulumAuth {
        ReticulumAuth {
            signer: Some(self.key.signer()),
            rooting: Some(Arc::clone(&self.dir) as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            ..ReticulumAuth::default()
        }
    }
}

async fn start_runtime(
    node: &Node,
    transport: Arc<ReticulumTransport>,
    peer: &Ident,
    selector: Option<KindPublishSelector>,
) -> Arc<ReplicationRuntime> {
    let peers = [
        EnvelopeKind::Key,
        EnvelopeKind::IdentityOccurrence,
        EnvelopeKind::TransportDestination,
        EnvelopeKind::Attestation,
    ]
    .into_iter()
    .map(|kind| ReplicationPeer {
        peer_key_id: peer.key_id.clone(),
        kind,
    })
    .collect();
    let runtime = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&node.dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&transport) as Arc<dyn Transport>,
            peers,
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: Duration::from_secs(3),
                    round_timeout: Duration::from_secs(15),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(node.key.key_id.clone()),
                metrics: Some(node.metrics.clone()),
                kind_publish_selector: selector,
                ..Default::default()
            },
            Some(self_publish_set([
                node.key.key_id.as_str(),
                node.owner.key_id.as_str(),
            ])),
        )
        .await,
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(1024);
    let t = Arc::clone(&transport);
    tokio::spawn(async move {
        let _ = t.listen(tx).await;
    });
    let router = InboundRouter::new(runtime.registry());
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let _ = router.try_route(&frame).await;
        }
    });
    runtime
}

async fn wait_for_own_route(node: &Node, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if !node
            .dir
            .list_signed_transport_destinations_for(&node.key.key_id)
            .await
            .unwrap_or_default()
            .is_empty()
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "#406 producer never published {}'s signed route",
            node.key.key_id
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn drive_until<F, Fut>(
    runtimes: &[&Arc<ReplicationRuntime>],
    budget: Duration,
    mut done: F,
) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        for r in runtimes {
            let _ = r.round_now_all().await;
        }
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if done().await {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,ciris_edge=info".into()),
        )
        .with_test_writer()
        .try_init();
}

/// The third party's rows, all held at the relay only.
struct Roster {
    o: Ident,
    d: Ident,
    e: Ident,
    u: Ident,
    /// `O → D` at `federation` (announced, published) — the row that crosses.
    announced: String,
    /// `O → E` at `federation`, `E` NOT published by the relay.
    unpublished: String,
    /// `O → U` at `self`, `U` published — not announced.
    unannounced: String,
    /// A consent grant by `O` naming `D`.
    consent: String,
}

struct Fixture {
    c: Node,
    x: Node,
    roster: Roster,
    rt_c: Arc<ReplicationRuntime>,
    rt_x: Arc<ReplicationRuntime>,
    _tmp: tempfile::TempDir,
}

// The names are the issue's: owner O, devices D/E/U, relay C, stranger X.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)]
async fn fixture(tag: u8, with_selector: bool) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = Root::new(&format!("root-752-{tag}"), 0x70 ^ tag).await;
    let o = Ident::new(&format!("owner-o-752-{tag}"), 0x21 ^ tag).await;
    let d = Ident::new(&format!("device-d-752-{tag}"), 0x22 ^ tag).await;
    let e = Ident::new(&format!("device-e-752-{tag}"), 0x23 ^ tag).await;
    let u = Ident::new(&format!("device-u-752-{tag}"), 0x24 ^ tag).await;
    // Each side pre-seeds the other's NODE key (the ladder's convention: the
    // Key round is proven elsewhere); owners and the third party's keys cross
    // on the wire.
    let key_c = Arc::new(Ident::new(&format!("node-c-752-{tag}"), 0x0a ^ tag).await);
    let key_x = Arc::new(Ident::new(&format!("node-x-752-{tag}"), 0x0b ^ tag).await);
    let third_party = vec![
        o.record("user").await,
        d.record("node").await,
        e.record("node").await,
        u.record("node").await,
    ];
    let c = Node::new(
        &format!("c-{tag}"),
        Arc::clone(&key_c),
        0x0a ^ tag,
        &key_x,
        &root,
        third_party,
    )
    .await;
    let x = Node::new(
        &format!("x-{tag}"),
        Arc::clone(&key_x),
        0x0b ^ tag,
        &key_c,
        &root,
        Vec::new(),
    )
    .await;

    // What the relay holds about O's devices.
    let announced = put(
        &c.dir,
        owner_binding_attestation(&o.key_id, &d.key_id, chrono::Utc::now(), &o.signer())
            .await
            .expect("O -> D"),
    )
    .await;
    let unpublished = put(
        &c.dir,
        owner_binding_attestation(&o.key_id, &e.key_id, chrono::Utc::now(), &o.signer())
            .await
            .expect("O -> E"),
    )
    .await;
    let unannounced = put(&c.dir, owner_binding_at(&o, &u.key_id, "self").await).await;
    let consent = put(
        &c.dir,
        replication_consent_attestation(
            &o.key_id,
            &d.key_id,
            &DEFAULT_CONSENT_PREFIXES,
            chrono::Utc::now(),
            &o.signer(),
        )
        .await
        .expect("consent O -> D"),
    )
    .await;
    c.dir
        .put_identity_occurrence(occurrence(&o, &d).await)
        .await
        .expect("D's occurrence admits at the relay (O -> D is live there)");

    let selector = with_selector.then(|| {
        KindPublishSelector::from_sets(HashMap::from([
            (
                EnvelopeKind::Key,
                vec![
                    c.key.key_id.clone(),
                    c.owner.key_id.clone(),
                    d.key_id.clone(),
                    u.key_id.clone(),
                    o.key_id.clone(),
                ],
            ),
            (
                EnvelopeKind::IdentityOccurrence,
                vec![c.key.key_id.clone(), d.key_id.clone(), u.key_id.clone()],
            ),
        ]))
    });

    let base = tmp.path().to_path_buf();
    let (tc, addr_c) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("c/transport.id"), &c.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, c.auth())
    })
    .await;
    let port_c = addr_c.port();
    let (tx_, _) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("x/transport.id"), &x.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.bootstrap_peers = vec![format!("127.0.0.1:{port_c}").parse().unwrap()];
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, x.auth())
    })
    .await;
    let rt_c = start_runtime(&c, tc, &x.key, selector).await;
    let rt_x = start_runtime(&x, tx_, &c.key, None).await;
    wait_for_own_route(&c, Duration::from_secs(150)).await;
    wait_for_own_route(&x, Duration::from_secs(150)).await;
    Fixture {
        c,
        x,
        roster: Roster {
            o,
            d,
            e,
            u,
            announced,
            unpublished,
            unannounced,
            consent,
        },
        rt_c,
        rt_x,
        _tmp: tmp,
    }
}

/// The negatives every run asserts once the positive side has had its time:
/// nothing about O's devices beyond the one public roster entry reaches X.
async fn assert_nothing_else_reaches_the_stranger(f: &Fixture, label: &str) {
    let r = &f.roster;
    for (id, why) in [
        (
            &r.unannounced,
            "O -> U at `self` (a published but unannounced device)",
        ),
        (
            &r.unpublished,
            "O -> E (announced, but the relay does not publish E)",
        ),
        (&r.consent, "a consent grant O -> D"),
    ] {
        assert!(
            !f.x.holds(id).await,
            "[{label}] {why} must never reach the stranger"
        );
    }
    assert!(
        !f.x.holds_key(&r.e).await,
        "[{label}] the relay does not publish E's key"
    );
    assert!(
        !f.x.lists_under(&r.o).await.contains(&r.e.key_id)
            && !f.x.lists_under(&r.o).await.contains(&r.u.key_id),
        "[{label}] the stranger lists neither the unpublished nor the unannounced device"
    );
}

/// I21 — the stranger admits D's key, D's occurrence AND O -> D from the relay,
/// and persist's `nodes_owned_by(O)` at the stranger names D. FAILS on the
/// pre-#752 code: the relay withholds O -> D at the first-contact narrowing,
/// so the stranger never holds the binding (nor, therefore, the occurrence).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_lists_a_relays_published_device_under_its_owner_752() {
    init_tracing();
    let f = fixture(0x00, true).await;
    let r = &f.roster;
    let listed = drive_until(&[&f.rt_x, &f.rt_c], Duration::from_secs(240), || async {
        f.x.holds_key(&r.d).await
            && f.x.holds_key(&r.o).await
            && f.x.holds(&r.announced).await
            && f.x.holds_occurrence(&r.o, &r.d).await
            && f.x.lists_under(&r.o).await.contains(&r.d.key_id)
    })
    .await;
    if !listed {
        eprintln!(
            "stranger holds: D key={} O key={} O->D={} D occurrence={} lists_under(O)={:?}; \
             relay withholds={:?}",
            f.x.holds_key(&r.d).await,
            f.x.holds_key(&r.o).await,
            f.x.holds(&r.announced).await,
            f.x.holds_occurrence(&r.o, &r.d).await,
            f.x.lists_under(&r.o).await,
            f.c.metrics.snapshot().withholds_by_reason
        );
    }
    assert!(
        listed,
        "the stranger must admit D's key, D's occurrence and the announced O -> D from the \
         relay, and list D under O (FSD/FIRST_CONTACT.md I21)"
    );
    // Give every negative the rounds the positive took, and more.
    let leaked = drive_until(&[&f.rt_x, &f.rt_c], Duration::from_secs(20), || async {
        f.x.holds(&r.unannounced).await
            || f.x.holds(&r.unpublished).await
            || f.x.holds(&r.consent).await
    })
    .await;
    assert!(
        !leaked,
        "no other row about O's devices reached the stranger"
    );
    assert_nothing_else_reaches_the_stranger(&f, "selector").await;
    assert!(
        f.c.metrics.withholds(WithholdReason::RecipientNotInSendSet) > 0,
        "the relay's first-contact narrowing FIRED on the rows it kept back — an absence \
         alone is not a witness"
    );
}

/// Selector unset ⇒ #671 exactly: the stranger receives the relay's own
/// allegiance facts (the positive control that the pair is talking) and
/// nothing about O's devices — no key, no binding, no roster entry.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_selector_nothing_about_others_reaches_the_stranger_752() {
    init_tracing();
    let f = fixture(0x10, false).await;
    let r = &f.roster;
    let own = format!("owner-binding-{}", f.c.key.key_id);
    let talking = drive_until(&[&f.rt_x, &f.rt_c], Duration::from_secs(240), || async {
        f.x.holds(&own).await
    })
    .await;
    assert!(
        talking,
        "control: the relay's own owner-binding reaches the stranger at first contact (#671)"
    );
    let leaked = drive_until(&[&f.rt_x, &f.rt_c], Duration::from_secs(30), || async {
        f.x.holds(&r.announced).await || f.x.holds_key(&r.d).await
    })
    .await;
    assert!(
        !leaked,
        "with no selector neither D's key nor O -> D reaches the stranger"
    );
    assert!(
        f.x.lists_under(&r.o).await.is_empty(),
        "the stranger lists nothing under O"
    );
    assert_nothing_else_reaches_the_stranger(&f, "no selector").await;
}
