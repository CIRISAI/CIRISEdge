//! CIRISEdge#659 — the first-contact ladder, on real Reticulum links, with a
//! peer shaped like every production agent: **self-signed** (no steward, no
//! test root scrubs it — `root_binding` answers `NotRootedAtSteward`), **owned**
//! (a user key, a live owner-binding at `federation`), with the owner's
//! **acceptance** of a root the receiver also accepts. Nothing injects a peer
//! as Rooted and no link literal is pre-attributed: attribution comes from the
//! announce (`owns_key`) and the binding it persists (item 2), Rooted comes from
//! the rows that cross, and "served" is measured by what lands on the other
//! side.
//!
//! Two witnesses:
//! - **`a_self_signed_owned_peer_under_a_shared_root_is_attributed_and_served`** —
//!   B's rows land on A (delivery: Attributed), and A's rows land on B (served:
//!   Rooted), in both directions.
//! - **`under_different_roots_a_peer_delivers_but_is_served_nothing_until_the_roots_meet`** —
//!   B's owner accepts a different valid root: A still admits B's rows; A's OWN
//!   allegiance facts (the rows its self-publish identities authored) cross to
//!   B — the one exemption below the floor, without which two fresh peers each
//!   withhold what would have made them Rooted — while what A holds ABOUT
//!   OTHERS (root R's charter) never lands across N rounds, and A's withhold
//!   ledger shows `RecipientNotRooted` moved (the floor FIRED; an absence alone
//!   is not a witness). The moment B's owner also accepts R, the charter
//!   arrives. The positive control lives in the same run, so the negative is a
//!   floor and not a stall.
//!
//! Peers' Key records are pre-seeded on both sides (the Key round that would
//! carry them is proven elsewhere); everything the ladder is ABOUT — the
//! owner-binding, the acceptance, the attributed Attestation round — crosses on
//! the wire.
#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::WithholdReason;
use ciris_edge::replication::attestation_bind::{
    bind_attestation_envelope, owner_binding_attestation, replication_consent_attestation,
    AttestationColumns, DEFAULT_CONSENT_PREFIXES,
};
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
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::store::sqlite::SqliteBackend;
use common::{build_reticulum_with_retry, directory_with};
use sha2::Digest as _;
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
            attestation_evidence: None,
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
        let commitment = ciris_persist::federation::trust_root::pre_rotation_commitment(
            std::slice::from_ref(&self.successor.key_id),
        )
        .expect("commitment");
        let mut extra = serde_json::Map::new();
        extra.insert(
            "pre_rotation_commitment".into(),
            serde_json::Value::String(commitment),
        );
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

/// One genesis-shaped node: a self-signed node key, a self-signed owner, the
/// owner-binding at `federation`, and (later) the owner's acceptance.
struct Node {
    key: Arc<Ident>,
    owner: Ident,
    dir: Arc<SqliteBackend>,
    signer: Arc<LocalSigner>,
    /// The runtime's live metric bag — the withhold ledger is how a witness
    /// proves the serve floor FIRED rather than reading an absence.
    metrics: EdgeMetrics,
}

impl Node {
    async fn new(
        name: &str,
        key: Arc<Ident>,
        seed: u8,
        peers: &[&Ident],
        roots: &[&Root],
        chartered: &[&Root],
    ) -> Self {
        let owner = Ident::new(&format!("owner-{name}"), seed.wrapping_add(0x40)).await;
        let mut records = vec![key.record("node").await, owner.record("user").await];
        for p in peers {
            records.push(p.record("node").await);
        }
        for r in roots {
            records.extend(r.records().await);
        }
        let dir = directory_with(records).await;
        for r in chartered {
            put(&dir, r.charter().await).await;
        }
        let binding = owner_binding_attestation(
            &owner.key_id,
            &key.key_id,
            chrono::Utc::now(),
            &owner.signer(),
        )
        .await
        .expect("owner binding");
        put(&dir, binding).await;
        Self {
            signer: key.signer(),
            key,
            owner,
            dir,
            metrics: EdgeMetrics::new(),
        }
    }

    /// The owner accepts `root` — CC 4.4.3.8's `delegates_to(user → root)`.
    async fn accept(&self, root: &Root) -> String {
        let row = delegates_to_row(
            &self.owner.signer(),
            &self.owner.key_id,
            &root.key.key_id,
            &["infra:attest", "infra:serve"],
            serde_json::Map::new(),
            "accepts",
        )
        .await;
        put(&self.dir, row).await
    }

    /// This node consents `peer` into its send set.
    async fn consent(&self, peer: &Ident) {
        let row = replication_consent_attestation(
            &self.key.key_id,
            &peer.key_id,
            &DEFAULT_CONSENT_PREFIXES,
            chrono::Utc::now(),
            &self.signer,
        )
        .await
        .expect("consent");
        put(&self.dir, row).await;
    }

    async fn holds(&self, attestation_id: &str) -> bool {
        self.dir
            .list_attestations_since(None, 1024)
            .await
            .expect("list")
            .iter()
            .any(|r| r.attestation.attestation_id == attestation_id)
    }

    fn auth(&self) -> ReticulumAuth {
        ReticulumAuth {
            signer: Some(Arc::clone(&self.signer)),
            rooting: Some(Arc::clone(&self.dir) as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            ..ReticulumAuth::default()
        }
    }
}

/// The production wiring in miniature (`edge_node.rs`): a runtime per node over
/// its transport, peers registered on the discovery planes plus Attestation,
/// the self-publish set, and an inbound loop feeding the router.
async fn start_runtime(
    node: &Node,
    transport: Arc<ReticulumTransport>,
    peer: &Ident,
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
                },
                local_key_id: Some(node.key.key_id.clone()),
                metrics: Some(node.metrics.clone()),
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

async fn transports(
    a: &Node,
    b: &Node,
    base: &std::path::Path,
) -> (Arc<ReticulumTransport>, Arc<ReticulumTransport>) {
    let (ta, addr_a) = build_reticulum_with_retry(|| async {
        let mut c = ReticulumTransportConfig::new(base.join("a/transport.id"), &a.key.key_id);
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.announce_interval = Duration::from_secs(5);
        (c, a.auth())
    })
    .await;
    let port_a = addr_a.port();
    let (tb, _) = build_reticulum_with_retry(|| async {
        let mut c = ReticulumTransportConfig::new(base.join("b/transport.id"), &b.key.key_id);
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        c.announce_interval = Duration::from_secs(5);
        (c, b.auth())
    })
    .await;
    (ta, tb)
}

/// #406 — a node's own hybrid-signed reticulum route is what a PEER reads for
/// item 2 once it crosses on the TransportDestination plane. The producer emits
/// it after the transport settles; the ladder starts its clock only once both
/// nodes have published theirs, because until then item 2 cannot pass anywhere.
async fn wait_for_own_route(node: &Node, budget: Duration) {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let rows = node
            .dir
            .list_signed_transport_destinations_for(&node.key.key_id)
            .await
            .unwrap_or_default();
        if !rows.is_empty() {
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

/// What each side holds on the TransportDestination plane, beside what the
/// other side's item 2 will ask for — printed when delivery does not happen,
/// so a red rung names the missing row instead of a timeout.
async fn dump_routes(
    label: &str,
    holder: &Node,
    about: &Node,
    about_transport: &ReticulumTransport,
) {
    let want = hex::encode(about_transport.local_dest_hash());
    let rows = holder
        .dir
        .list_signed_transport_destinations_for(&about.key.key_id)
        .await
        .unwrap_or_default();
    eprintln!(
        "[{label}] {} holds {} signed route(s) for {} (item 2 wants dest={want}):",
        holder.key.key_id,
        rows.len(),
        about.key.key_id
    );
    for r in &rows {
        let td = &r.transport_destination;
        eprintln!(
            "    kind={} dest={} mldsa={} epoch={} asserted_at={} provenance={:?} retired={:?}",
            td.transport_kind,
            td.destination,
            r.signature.mldsa65_signature_base64.is_some(),
            td.epoch,
            td.asserted_at.to_rfc3339(),
            td.binding_provenance,
            td.retired_at.is_some()
        );
    }
}

/// The precondition every witness here must prove first: nothing roots the
/// peer. A test root that scrubbed it would pass the old walk and prove nothing.
async fn assert_not_rooted_at_steward(dir: &SqliteBackend, key: &Ident) {
    let verdict = RootingDirectory::root_binding(dir, &key.key_id, &key.ed_pub_b64()).await;
    assert!(
        matches!(
            verdict,
            ciris_edge::verify::RootingVerdict::Rejected {
                rejection: ciris_edge::verify::RootingRejection::NotRootedAtSteward { .. }
            }
        ),
        "precondition: a self-signed key must NOT root at the steward anchor, got {verdict:?}"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_self_signed_owned_peer_under_a_shared_root_is_attributed_and_served() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = Root::new("root-r", 0x70).await;
    let key_a = Arc::new(Ident::new("node-a", 0x0a).await);
    let key_b = Arc::new(Ident::new("node-b", 0x0b).await);
    let a = Node::new("a", Arc::clone(&key_a), 0x0a, &[&key_b], &[&root], &[&root]).await;
    let b = Node::new("b", Arc::clone(&key_b), 0x0b, &[&key_a], &[&root], &[&root]).await;
    assert_not_rooted_at_steward(&a.dir, &b.key).await;
    assert_not_rooted_at_steward(&b.dir, &a.key).await;
    // Both owners accept the same valid root; each node consents the other.
    let a_accepts = a.accept(&root).await;
    let b_accepts = b.accept(&root).await;
    a.consent(&b.key).await;
    b.consent(&a.key).await;

    let (ta, tb) = transports(&a, &b, tmp.path()).await;
    let (probe_a, probe_b) = (Arc::clone(&ta), Arc::clone(&tb));
    let rt_a = start_runtime(&a, ta, &b.key).await;
    let rt_b = start_runtime(&b, tb, &a.key).await;
    wait_for_own_route(&a, Duration::from_secs(150)).await;
    wait_for_own_route(&b, Duration::from_secs(150)).await;

    // DELIVERY (Attributed): B's allegiance rows land on A — the frames the old
    // gate dropped for five days.
    let delivered = drive_until(&[&rt_b, &rt_a], Duration::from_secs(180), || async {
        a.holds(&b_accepts).await && a.holds(&format!("owner-binding-{}", b.key.key_id)).await
    })
    .await;
    if !delivered {
        dump_routes("A about B", &a, &b, &probe_b).await;
        dump_routes("B about A", &b, &a, &probe_a).await;
        dump_routes("A about A (own)", &a, &a, &probe_a).await;
        dump_routes("B about B (own)", &b, &b, &probe_b).await;
    }
    assert!(
        delivered,
        "B's owner-binding and acceptance must land on A: an Attributed peer delivers"
    );

    // SERVING (Rooted): A's acceptance lands on B — A serves B only with a valid
    // root in common, and it has one.
    let served = drive_until(&[&rt_b, &rt_a], Duration::from_secs(180), || async {
        b.holds(&a_accepts).await
    })
    .await;
    assert!(
        served,
        "A's acceptance must land on B: a Rooted peer is served (both directions)"
    );
    std::mem::forget(tmp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn under_different_roots_a_peer_delivers_but_is_served_nothing_until_the_roots_meet() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let root_r = Root::new("root-r", 0x70).await;
    let root_q = Root::new("root-q", 0x74).await;
    let key_a = Arc::new(Ident::new("node-a", 0x0a).await);
    let key_b = Arc::new(Ident::new("node-b", 0x0b).await);
    // Both directories know both roots' KEYS; only A holds R's charter, only B
    // holds Q's. R's charter at A is a row A holds ABOUT ANOTHER — the floor's
    // marker: withheld from B while their owners accept different roots, served
    // once B's owner accepts R (and B needs it, to judge R valid itself).
    let a = Node::new(
        "a",
        Arc::clone(&key_a),
        0x0a,
        &[&key_b],
        &[&root_r, &root_q],
        &[&root_r],
    )
    .await;
    let b = Node::new(
        "b",
        Arc::clone(&key_b),
        0x0b,
        &[&key_a],
        &[&root_r, &root_q],
        &[&root_q],
    )
    .await;
    assert_not_rooted_at_steward(&a.dir, &b.key).await;
    let charter_r = root_r.charter().await.attestation_id;
    let a_accepts_r = a.accept(&root_r).await;
    let b_accepts_q = b.accept(&root_q).await;
    a.consent(&b.key).await;
    b.consent(&a.key).await;

    let (ta, tb) = transports(&a, &b, tmp.path()).await;
    let rt_a = start_runtime(&a, ta, &b.key).await;
    let rt_b = start_runtime(&b, tb, &a.key).await;
    wait_for_own_route(&a, Duration::from_secs(150)).await;
    wait_for_own_route(&b, Duration::from_secs(150)).await;

    // Attributed: B's rows land on A regardless of roots.
    let delivered = drive_until(&[&rt_b, &rt_a], Duration::from_secs(180), || async {
        a.holds(&b_accepts_q).await
    })
    .await;
    assert!(
        delivered,
        "an Attributed peer delivers, whatever its owner accepts"
    );

    // Attributed also means A's OWN allegiance facts cross to B (B needs them to
    // judge A) — the self-authored exemption — while a row A holds ABOUT ANOTHER
    // (R's charter) does not: across a bounded window of rounds it never lands.
    let self_facts = drive_until(&[&rt_b, &rt_a], Duration::from_secs(120), || async {
        b.holds(&a_accepts_r).await
    })
    .await;
    assert!(
        self_facts,
        "A's acceptance (self-authored) crosses to an Attributed peer"
    );
    let leaked = drive_until(&[&rt_b, &rt_a], Duration::from_secs(20), || async {
        b.holds(&charter_r).await
    })
    .await;
    assert!(
        !leaked,
        "no valid root in common ⇒ what A holds about OTHERS is withheld (the floor)"
    );
    let floor_hits = a.metrics.withholds(WithholdReason::RecipientNotRooted);
    assert!(
        floor_hits > 0,
        "the floor itself must have withheld at A (RecipientNotRooted={floor_hits}) — an \
         absence alone is not a witness"
    );

    // The roots meet: B's owner also accepts R. Same rows, same peer — now served.
    let b_accepts_r = b.accept(&root_r).await;
    let arrived = drive_until(&[&rt_b, &rt_a], Duration::from_secs(180), || async {
        a.holds(&b_accepts_r).await && b.holds(&charter_r).await
    })
    .await;
    assert!(
        arrived,
        "once both owners accept one valid root, what A holds about others arrives on B"
    );
    std::mem::forget(tmp);
}
