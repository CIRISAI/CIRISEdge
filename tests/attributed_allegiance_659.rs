//! CIRISEdge#659 — two PEOPLE, each on their own node, peered and Attributed
//! to each other, root each other through their own allegiance facts alone.
//!
//! The field shape (CIRISServer native T2, alice ↔ bob): each node is claimed
//! — the owner's CC 3.2 owner-binding and the owner's acceptance of one shared
//! root, both at `federation`, both signed at claim — and each node consents
//! the other into its send set with an OWNER-signed `consent:replication:v1`
//! grant, as the server's peering door writes it. No canonical serves either
//! of them: the only way A can read B as Rooted is to pull the rows B's own
//! self-publish identities authored about themselves, and B the same of A.
//! Neither holds the other's binding or acceptance at the start.
//!
//! A floor that withheld those rows from an Attributed-but-not-Rooted peer
//! would deadlock the pair forever: each waits for the other's allegiance and
//! withholds its own. Two witnesses — two people (field T2), and one person
//! on two devices claimed with the same pen (field T1), where the owner's
//! acceptance is the same row on both sides and only each device's
//! owner-binding has to cross. Each asserts:
//! - each side ends holding the other's owner-binding and acceptance;
//! - Rooted both ways, measured by what it unlocks: the row each node holds
//!   ABOUT ANOTHER (a third root's charter) then reaches the other side;
//! - that row was withheld until then: the floor booked `RecipientNotRooted`
//!   at BOTH nodes. An absence alone would not be a witness.
//!
//! Peers' NODE key records are pre-seeded, as in the first-contact ladder. The
//! owners' key records, the owner-bindings, the acceptances and the attestation
//! rounds all cross on real Reticulum links.
#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::WithholdReason;
use ciris_edge::replication::attestation_bind::{
    bind_attestation_envelope, owner_binding_attestation, AttestationColumns,
    DEFAULT_CONSENT_PREFIXES,
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
use ciris_persist::federation::{
    Attestation, FederationDirectory, SignedAttestation, SignedKeyRecord,
};
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

/// One genesis-shaped node: a self-signed node key, a self-signed owner, the
/// owner-binding at `federation`, and (later) the owner's acceptance.
struct Node {
    key: Arc<Ident>,
    owner: Arc<Ident>,
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
        let owner = Arc::new(Ident::new(&format!("owner-{name}"), seed.wrapping_add(0x40)).await);
        Self::with_owner(key, owner, peers, roots, chartered).await
    }

    /// A device of `owner` — the same person's pen on every node it claims,
    /// so each directory holds the SAME owner record bytes.
    async fn with_owner(
        key: Arc<Ident>,
        owner: Arc<Ident>,
        peers: &[&Ident],
        roots: &[&Root],
        chartered: &[&Root],
    ) -> Self {
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
            trust_job(ciris_persist::federation::trust_root::TRUST_ACCEPTS_DIMENSION),
            "accepts",
        )
        .await;
        put(&self.dir, row).await
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
                    ..SchedulerConfig::default()
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

/// One more transport on the same loopback RNS network: `bootstrap` is A's
/// listen port (every other node bootstraps to A, so all hear all announces).
async fn transport_for(
    node: &Node,
    base: &std::path::Path,
    name: &str,
    bootstrap: Option<u16>,
) -> (Arc<ReticulumTransport>, u16) {
    let (t, addr) = build_reticulum_with_retry(|| async {
        let mut c = ReticulumTransportConfig::new(
            base.join(format!("{name}/transport.id")),
            &node.key.key_id,
        );
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        if let Some(port) = bootstrap {
            c.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
        }
        // The node the others bootstrap to is the hub, and a hub forwards:
        // without it its TCP clients cannot reach each other (leaf mode is
        // the default), so a client-to-client path, the mutual peer's relay
        // included, never exists.
        c.enable_transport = bootstrap.is_none();
        c.announce_interval = Duration::from_secs(5);
        (c, node.auth())
    })
    .await;
    (t, addr.port())
}

/// [`start_runtime`] with several peers, each on the four planes.
async fn start_runtime_with(
    node: &Node,
    transport: Arc<ReticulumTransport>,
    peers: &[&Ident],
) -> Arc<ReplicationRuntime> {
    let peers: Vec<ReplicationPeer> = peers
        .iter()
        .flat_map(|p| {
            [
                EnvelopeKind::Key,
                EnvelopeKind::IdentityOccurrence,
                EnvelopeKind::TransportDestination,
                EnvelopeKind::Attestation,
            ]
            .into_iter()
            .map(|kind| ReplicationPeer {
                peer_key_id: p.key_id.clone(),
                kind,
            })
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

/// `from`'s signed routes, put at `to` through the ordinary door (one way).
async fn seed_route(from: &Node, to: &Node) {
    for r in from
        .dir
        .list_signed_transport_destinations_for(&from.key.key_id)
        .await
        .expect("own routes")
    {
        FederationDirectory::put_signed_transport_destination(&*to.dir, &r)
            .await
            .expect("seed the route");
    }
}

/// Does `holder` hold `node`'s OWN signed route row (the row that carries its
/// transit pair), as against the unsigned row an RNS announce writes?
async fn holds_signed_route_of(holder: &Node, node: &Node) -> bool {
    holder
        .dir
        .list_signed_transport_destinations_for(&node.key.key_id)
        .await
        .unwrap_or_default()
        .iter()
        .any(|r| {
            r.attesting_key_id == node.key.key_id && matches!(r.transit_kex_pair(), Ok(Some(_)))
        })
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

/// CC 5.3.3.5 E1 — each node holds the other's signed route, which carries
/// its transit pair, before either dials: a link is keyed by the dialled
/// node's Rooted pair or never made. In the field the row crosses on the
/// TransportDestination plane from a node both already reach (or a seated
/// serve node's comes in the genesis bundle); here it is put through the same
/// ordinary door, so the rung under test still starts from first contact.
async fn exchange_routes(a: &Node, b: &Node) {
    for (from, to) in [(a, b), (b, a)] {
        for r in from
            .dir
            .list_signed_transport_destinations_for(&from.key.key_id)
            .await
            .expect("own routes")
        {
            FederationDirectory::put_signed_transport_destination(&*to.dir, &r)
                .await
                .expect("seed the route");
        }
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

impl Node {
    /// The server's peering door (CIRISServer `peer.rs`): the OWNER consents
    /// `peer` into this node's send set, naming the machine the grant is FOR
    /// (persist v44.6.0 `for_key_id`). Consent is the human's act, so persist's
    /// `consent_peers_by_principals(node)` counts it as the node's send set.
    async fn consent_as_owner(&self, peer: &Ident) -> Attestation {
        let asserted_at = chrono::Utc::now();
        let attestation_id = format!("consent-replication-{}-{}", self.owner.key_id, peer.key_id);
        let subjects = vec![peer.key_id.clone()];
        let mut envelope = serde_json::json!({
            "dimension": ciris_persist::federation::consent_peer_set::DIMENSION,
            "for_key_id": self.key.key_id,
            "payload": {
                "grants": "replication",
                "direction": "egress",
                "kinds": ["Attestation"],
                "attestation_prefixes": DEFAULT_CONSENT_PREFIXES,
                "principle": "share",
                "audience": "federation",
                "restrictions": [],
            },
        });
        bind_attestation_envelope(
            &mut envelope,
            asserted_at,
            &AttestationColumns {
                attestation_id: &attestation_id,
                attesting_key_id: &self.owner.key_id,
                attestation_type: "scores",
                attested_key_id: &peer.key_id,
                subject_key_ids: &subjects,
                cohort_scope: "federation",
                weight: None,
            },
        );
        let asserted_at =
            ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
                asserted_at,
            );
        let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
        let digest = sha2::Sha256::digest(&canonical);
        let (sig_classical, sig_pqc) = sign_bound_hybrid(
            &self.owner.signer(),
            &canonical,
            "owner replication consent",
        )
        .await
        .expect("hybrid sign");
        let row = Attestation {
            attestation_id,
            attesting_key_id: self.owner.key_id.clone(),
            attested_key_id: peer.key_id.clone(),
            attestation_type: "scores".to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig_classical,
            scrub_signature_pqc: sig_pqc,
            scrub_key_id: self.owner.key_id.clone(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: subjects,
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: "federation".to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        put(&self.dir, row.clone()).await;
        // The grant must count: persist's one definition of this node's send
        // set names the peer, so the peer is Attributed AND consent-included —
        // not a first-contact stranger.
        let set = ciris_persist::federation::consent_by_humans::consent_peers_by_principals(
            &*self.dir,
            &self.key.key_id,
        )
        .await
        .expect("send set");
        assert!(
            set.contains(&peer.key_id),
            "precondition: the owner's grant must put {} in {}'s send set, got {set:?}",
            peer.key_id,
            self.key.key_id
        );
        row
    }
}

/// What each node's withhold ledger booked — printed when the allegiance
/// facts did not cross, so a red run names the gate instead of a timeout.
fn print_ledgers(nodes: &[(&Node, &str)]) {
    for (n, l) in nodes {
        eprintln!(
            "[{l}] withholds: not_rooted={} not_in_send_set={}",
            n.metrics.withholds(WithholdReason::RecipientNotRooted),
            n.metrics.withholds(WithholdReason::RecipientNotInSendSet),
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_attributed_people_root_each_other_through_their_own_allegiance_facts_659() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    // The one root both people accept at claim (the field's humanity-accord).
    let root = Root::new("root-r", 0x70).await;
    // Two more valid roots nobody here accepts: their charters are rows a node
    // holds ABOUT ANOTHER — never an allegiance fact. Q's charter only at B,
    // S's only at A. Both directories know every root's KEY.
    let root_q = Root::new("root-q", 0x74).await;
    let root_s = Root::new("root-s", 0x78).await;
    let key_a = Arc::new(Ident::new("node-alice", 0x0a).await);
    let key_b = Arc::new(Ident::new("node-bob", 0x0b).await);
    let a = Node::new(
        "alice",
        Arc::clone(&key_a),
        0x0a,
        &[&key_b],
        &[&root, &root_q, &root_s],
        &[&root, &root_s],
    )
    .await;
    let b = Node::new(
        "bob",
        Arc::clone(&key_b),
        0x0b,
        &[&key_a],
        &[&root, &root_q, &root_s],
        &[&root, &root_q],
    )
    .await;
    assert_not_rooted_at_steward(&a.dir, &b.key).await;
    assert_not_rooted_at_steward(&b.dir, &a.key).await;
    let charter_q = root_q.charter().await.attestation_id;
    let charter_s = root_s.charter().await.attestation_id;
    let a_binding = format!("owner-binding-{}", a.key.key_id);
    let b_binding = format!("owner-binding-{}", b.key.key_id);

    // THE CLAIM, on both nodes: owner-binding (Node::new) + acceptance.
    let a_accepts = a.accept(&root).await;
    let b_accepts = b.accept(&root).await;
    // PEERED: each owner consents the other node into its send set — both
    // peers are Attributed and consent-included, neither is a stranger.
    a.consent_as_owner(&b.key).await;
    b.consent_as_owner(&a.key).await;

    // Precondition: neither holds the other's allegiance facts, nor the row
    // about another that the other holds.
    for (holder, rows) in [
        (&a, [&b_accepts, &b_binding, &charter_q]),
        (&b, [&a_accepts, &a_binding, &charter_s]),
    ] {
        for id in rows {
            assert!(
                !holder.holds(id).await,
                "precondition: {} must not hold {id} at the start",
                holder.key.key_id
            );
        }
    }

    let (ta, tb) = transports(&a, &b, tmp.path()).await;
    let rt_a = start_runtime(&a, ta, &b.key).await;
    let rt_b = start_runtime(&b, tb, &a.key).await;
    wait_for_own_route(&a, Duration::from_secs(150)).await;
    wait_for_own_route(&b, Duration::from_secs(150)).await;
    exchange_routes(&a, &b).await;

    // THE ALLEGIANCE FACTS CROSS BOTH WAYS to a peer that is Attributed and not
    // yet Rooted: each pulls the other's owner-binding and acceptance.
    let rooted_facts = drive_until(&[&rt_a, &rt_b], Duration::from_secs(240), || async {
        a.holds(&b_binding).await
            && a.holds(&b_accepts).await
            && b.holds(&a_binding).await
            && b.holds(&a_accepts).await
    })
    .await;
    if !rooted_facts {
        print_ledgers(&[(&a, "alice"), (&b, "bob")]);
    }
    assert!(
        rooted_facts,
        "each node's own allegiance facts (owner-binding + acceptance) must cross to the \
         Attributed-but-not-Rooted peer — withholding them deadlocks the pair (CIRISEdge#659)"
    );

    // ROOTED BOTH WAYS, measured by what Rooted unlocks: each side now serves
    // the other the row it holds ABOUT ANOTHER.
    let served = drive_until(&[&rt_a, &rt_b], Duration::from_secs(180), || async {
        a.holds(&charter_q).await && b.holds(&charter_s).await
    })
    .await;
    assert!(
        served,
        "once each holds the other's allegiance facts the pair is Rooted both ways and a row \
         about another flows in each direction (alice holds Q's charter={}, bob holds S's \
         charter={})",
        a.holds(&charter_q).await,
        b.holds(&charter_s).await
    );

    // AND THAT ROW WAITED FOR ROOTED: the floor fired at both nodes while the
    // peer was Attributed only. An absence alone is not a witness.
    for (n, l) in [(&a, "alice"), (&b, "bob")] {
        let floor = n.metrics.withholds(WithholdReason::RecipientNotRooted);
        assert!(
            floor > 0,
            "the floor must have withheld at {l}'s node before the pair was Rooted \
             (RecipientNotRooted={floor}) — a non-allegiance row waits for Rooted"
        );
    }
    std::mem::forget(tmp);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_devices_of_one_owner_root_each_other_through_the_owners_acceptance_659() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = Root::new("root-r", 0x70).await;
    let root_q = Root::new("root-q", 0x74).await;
    let root_s = Root::new("root-s", 0x78).await;
    // ONE person, two devices, both claimed with the same pen (field T1).
    let owner = Arc::new(Ident::new("owner-one", 0x4a).await);
    let key_1 = Arc::new(Ident::new("node-d1", 0x0a).await);
    let key_2 = Arc::new(Ident::new("node-d2", 0x0b).await);
    let d1 = Node::with_owner(
        Arc::clone(&key_1),
        Arc::clone(&owner),
        &[&key_2],
        &[&root, &root_q, &root_s],
        &[&root, &root_s],
    )
    .await;
    let d2 = Node::with_owner(
        Arc::clone(&key_2),
        Arc::clone(&owner),
        &[&key_1],
        &[&root, &root_q, &root_s],
        &[&root, &root_q],
    )
    .await;
    assert_not_rooted_at_steward(&d1.dir, &d2.key).await;
    assert_not_rooted_at_steward(&d2.dir, &d1.key).await;
    let charter_q = root_q.charter().await.attestation_id;
    let charter_s = root_s.charter().await.attestation_id;
    let d1_binding = format!("owner-binding-{}", d1.key.key_id);
    let d2_binding = format!("owner-binding-{}", d2.key.key_id);
    // Each claim writes the owner's acceptance: the SAME fact on both devices.
    let accepts_1 = d1.accept(&root).await;
    let accepts_2 = d2.accept(&root).await;
    assert_eq!(
        accepts_1, accepts_2,
        "one owner, one root: the acceptance is the same row on both devices"
    );
    d1.consent_as_owner(&d2.key).await;
    d2.consent_as_owner(&d1.key).await;
    // Precondition: neither device holds the other's owner-binding, so each
    // reads the other as an unowned node with no root (field T1's
    // `peer_roots=0`).
    assert!(!d1.holds(&d2_binding).await && !d2.holds(&d1_binding).await);

    let (t1, t2) = transports(&d1, &d2, tmp.path()).await;
    let rt_1 = start_runtime(&d1, t1, &d2.key).await;
    let rt_2 = start_runtime(&d2, t2, &d1.key).await;
    wait_for_own_route(&d1, Duration::from_secs(150)).await;
    wait_for_own_route(&d2, Duration::from_secs(150)).await;
    exchange_routes(&d1, &d2).await;

    // Each device's owner-binding crosses to the other: with the owner's
    // acceptance already held locally, that is all Rooted needs.
    let bound = drive_until(&[&rt_1, &rt_2], Duration::from_secs(240), || async {
        d1.holds(&d2_binding).await && d2.holds(&d1_binding).await
    })
    .await;
    if !bound {
        print_ledgers(&[(&d1, "d1"), (&d2, "d2")]);
    }
    assert!(
        bound,
        "each device's owner-binding must cross to its sibling while the sibling still reads \
         it as unowned and unrooted — withholding it deadlocks the self room (CIRISEdge#659)"
    );

    // Rooted both ways, measured by what it unlocks.
    let served = drive_until(&[&rt_1, &rt_2], Duration::from_secs(180), || async {
        d1.holds(&charter_q).await && d2.holds(&charter_s).await
    })
    .await;
    assert!(
        served,
        "both devices read Rooted once the bindings cross: a row about another flows each way \
         (d1 holds Q's charter={}, d2 holds S's charter={})",
        d1.holds(&charter_q).await,
        d2.holds(&charter_s).await
    );
    for (n, l) in [(&d1, "d1"), (&d2, "d2")] {
        let floor = n.metrics.withholds(WithholdReason::RecipientNotRooted);
        assert!(
            floor > 0,
            "the floor must have withheld at {l} before the pair was Rooted \
             (RecipientNotRooted={floor})"
        );
    }
    std::mem::forget(tmp);
}

/// **CC 3.3.6.2 + 5.3.4 (rc9 `c8f0d12`, I2 + I5) — the field's T2, with no
/// canonical.** Two persons' nodes A and B hear each other's RNS announce
/// (the transport identity, never the transit pair) and share one ordinary
/// peer K that both reach and that consents to nobody. Under E1 a dial is
/// keyed only from the dialled node's own hybrid-signed route row, which
/// neither holds of the other, so without a relay they would never seal and
/// never root. K holds both rows: it relays them (a held signed route is a
/// bootstrap row of an announced node), each learns the other's pair, seals,
/// exchanges allegiance facts and roots. A canonical is one source of route
/// rows, never a required party.
///
/// Since Eric's 2026-10-30 ruling (CONSENT-GATED ROUTES) a relay that has the
/// rule on relays an owned node's route only to a peer its owner consented to;
/// the persons here have consented each other and K holds both grants, so this
/// witness holds with the rule on or off. The rule is off by default until
/// CIRISPersist#1165 (`with_the_switch_off_a_relayed_route_reaches_a_stranger_as_before`).
///
/// Fail-before: with the relay narrowed back to a node's own routes, A never
/// holds B's signed row and the first wait expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one ladder, three nodes, read top to bottom
async fn two_persons_nodes_root_through_a_mutual_peer_that_relays_their_signed_routes_e1() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = Root::new("root-r", 0x70).await;
    let root_q = Root::new("root-q", 0x74).await;
    let root_s = Root::new("root-s", 0x78).await;
    let key_a = Arc::new(Ident::new("node-alice-r", 0x1a).await);
    let key_b = Arc::new(Ident::new("node-bob-r", 0x1b).await);
    let key_k = Arc::new(Ident::new("node-kay-r", 0x1c).await);
    let a = Node::new(
        "alice-r",
        Arc::clone(&key_a),
        0x1a,
        &[&key_b, &key_k],
        &[&root, &root_q, &root_s],
        &[&root, &root_s],
    )
    .await;
    let b = Node::new(
        "bob-r",
        Arc::clone(&key_b),
        0x1b,
        &[&key_a, &key_k],
        &[&root, &root_q, &root_s],
        &[&root, &root_q],
    )
    .await;
    let k = Node::new(
        "kay-r",
        Arc::clone(&key_k),
        0x1c,
        &[&key_a, &key_b],
        &[&root, &root_q, &root_s],
        &[&root],
    )
    .await;
    assert_not_rooted_at_steward(&a.dir, &b.key).await;
    assert_not_rooted_at_steward(&b.dir, &a.key).await;
    let charter_q = root_q.charter().await.attestation_id;
    let charter_s = root_s.charter().await.attestation_id;
    let a_binding = format!("owner-binding-{}", a.key.key_id);
    let b_binding = format!("owner-binding-{}", b.key.key_id);
    let a_accepts = a.accept(&root).await;
    let b_accepts = b.accept(&root).await;
    k.accept(&root).await;
    // Peered: each person consents the other's node, exactly as the field.
    // Nobody consents K, and K consents nobody.
    let a_consents_b = a.consent_as_owner(&b.key).await;
    let b_consents_a = b.consent_as_owner(&a.key).await;
    // Eric 2026-10-30 (CONSENT-GATED ROUTES): K relays an owned node's route
    // only to a peer its owner consented to, so K holds both grants, as a relay
    // does once the contact's consent has crossed it.
    // A relay holds the persons' records and their announced owner-bindings
    // (how it knows whose consent a route needs).
    for n in [&a, &b] {
        k.dir
            .put_public_key(SignedKeyRecord {
                record: n.owner.record("user").await,
            })
            .await
            .expect("K holds the owner's record");
        let binding = owner_binding_attestation(
            &n.owner.key_id,
            &n.key.key_id,
            chrono::Utc::now(),
            &n.owner.signer(),
        )
        .await
        .expect("owner binding");
        put(&k.dir, binding).await;
    }
    put(&k.dir, a_consents_b).await;
    put(&k.dir, b_consents_a).await;

    let (ta, port_a) = transport_for(&a, tmp.path(), "a", None).await;
    let (tb, _) = transport_for(&b, tmp.path(), "b", Some(port_a)).await;
    let (tk, _) = transport_for(&k, tmp.path(), "k", Some(port_a)).await;
    for n in [&a, &b, &k] {
        wait_for_own_route(n, Duration::from_secs(150)).await;
    }
    // Everyone reaches K and K reaches everyone; A and B hold NOTHING signed
    // of each other, only what the announce carried.
    for n in [&a, &b] {
        seed_route(n, &k).await;
        seed_route(&k, n).await;
    }
    assert!(
        !holds_signed_route_of(&a, &b).await,
        "precondition: A holds no signed row of B"
    );
    assert!(
        !holds_signed_route_of(&b, &a).await,
        "precondition: B holds no signed row of A"
    );
    assert!(holds_signed_route_of(&k, &a).await && holds_signed_route_of(&k, &b).await);

    // No replication runtime has started yet (each node's own route is the
    // transport's producer), so the precondition above holds by construction.
    // A and B then start peered with K ONLY: since 43.2 a dial that holds no
    // authenticated pair fetches the dialled node's own signed route before
    // the handshake (CC 5.3.3.5 E1 pre-seal route fetch), so an A<->B round
    // before the relay would hand each the other's row directly and this would
    // no longer witness the relay (on macOS CI the precondition lost that race
    // on every attempt, and K, a live responder, could already have relayed).
    // They peer each other only once K has relayed both rows.
    let rt_a = start_runtime_with(&a, ta, &[&k.key]).await;
    let rt_b = start_runtime_with(&b, tb, &[&k.key]).await;
    let rt_k = start_runtime_with(&k, tk, &[&a.key, &b.key]).await;

    // THE RELAY: K hands each the other's signed row, so each resolves the
    // other's transit pair from a source authenticated to it.
    let relayed = drive_until(&[&rt_a, &rt_b, &rt_k], Duration::from_secs(240), || async {
        holds_signed_route_of(&a, &b).await && holds_signed_route_of(&b, &a).await
    })
    .await;
    if !relayed {
        print_ledgers(&[(&a, "alice"), (&b, "bob"), (&k, "kay")]);
    }
    assert!(
        relayed,
        "a mutual peer must relay each node's own signed route (its transit pair) to the other \
         (CC 5.3.4 I5): alice holds bob's={}, bob holds alice's={}",
        holds_signed_route_of(&a, &b).await,
        holds_signed_route_of(&b, &a).await
    );

    // Each now holds the other's own signed row from the relay, so the first
    // A<->B dial seals on it and fetches nothing.
    for (rt, peer) in [(&rt_a, &b.key), (&rt_b, &a.key)] {
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::TransportDestination,
            EnvelopeKind::Attestation,
        ] {
            rt.register_peer(peer.key_id.clone(), kind)
                .await
                .expect("peer A and B after the relay");
        }
    }

    // Now the pair seals and the allegiance facts cross both ways.
    let rooted_facts = drive_until(&[&rt_a, &rt_b, &rt_k], Duration::from_secs(240), || async {
        a.holds(&b_binding).await
            && a.holds(&b_accepts).await
            && b.holds(&a_binding).await
            && b.holds(&a_accepts).await
    })
    .await;
    if !rooted_facts {
        print_ledgers(&[(&a, "alice"), (&b, "bob")]);
    }
    assert!(
        rooted_facts,
        "the allegiance facts cross over the sealed A<->B links"
    );

    // ROOTED BOTH WAYS: a row about another flows in each direction.
    let served = drive_until(&[&rt_a, &rt_b, &rt_k], Duration::from_secs(180), || async {
        a.holds(&charter_q).await && b.holds(&charter_s).await
    })
    .await;
    assert!(
        served,
        "Rooted both ways with no canonical present (alice holds Q's charter={}, bob holds \
         S's charter={})",
        a.holds(&charter_q).await,
        b.holds(&charter_s).await
    );
    // The pair each sealed with came from the relay, not a pre-seeded Rooted
    // binding: the row A holds of B is B's own signed statement, and vice versa.
    assert!(holds_signed_route_of(&a, &b).await && holds_signed_route_of(&b, &a).await);
    std::mem::forget(tmp);
}
