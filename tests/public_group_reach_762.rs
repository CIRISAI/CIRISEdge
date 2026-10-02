//! CIRISEdge#762 — a PUBLIC group's record reaches every peer, because every
//! node resolves its trust root (and its reclaim authority) through groups it
//! is not a member of (CC 5.4.6 hides a group "from outsiders only"; CC
//! 4.4.3.2.1 makes `infrastructure` communities Commons-tier; persist's ruling
//! on CIRISEdge#761; `FSD/FIRST_CONTACT.md` §2.5, I23).
//!
//! Two running nodes over real Reticulum links, real SQLite directories, no
//! consent and no membership (first contact):
//!
//! - **node A**, owned by **P**, holds four groups P founded: an
//!   `infrastructure` community (public by its subkind on a substrate-authority
//!   key — persist v53's `is_public_group`, CIRISEdge#761), the deployment's WA
//!   reclaim family (public by `CIRIS_PERSIST_WA_ADJUDICATION_FAMILY_KEY_ID`,
//!   persist's `ReclaimPolicy::from_deployment_pin`), and a PRIVATE community
//!   and family;
//! - **node X**, owned by **Q**: a stranger, never a member, never invited.
//!
//! X receives both public records, and the persist reads that resolve
//! through them answer on X as on the holder: `stored_standing` (the
//! community arm of `trust_root_valid`, `rooted_community_family`) and the
//! reclaim reads (`lookup_family` + `active_family_members` of the WA
//! body, `ownership_reclaim.rs` `wa_quorum_over_body`). The private records
//! never reach X, and A books `group_record_not_member_or_invitee` (the #758
//! gate still fires for private groups).
//!
//! On the pre-#762 gate every group record is withheld from X, so neither
//! resolves.
//!
//! **The accord family is not in this two-node witness, by persist's rule.**
//! persist reserves `humanity-accord` at EVERY admission door
//! (`tier_ingest::verify_family_admission` →
//! `ConstitutionalFamilyReserved`, CIRISPersist#648): it enters a directory
//! only through the genesis seeder / assemble ceremony
//! (`put_family_local`), never from a peer, on v37.1.0 as on v38. So no
//! node ever resolves the accord family from a replicated record, and the
//! #758 gate could not break that arm. Edge still serves it as public (the
//! marker list is persist's, and v53's predicate carries it); the serve side
//! is witnessed by `bridge::a_public_group_record_is_served_to_every_peer_762`.
//!
//! `cargo test --features transport-http,transport-reticulum --test public_group_reach_762`
#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::membership::{GroupScope, MembershipWidener};
use ciris_edge::replication::attestation_bind::owner_binding_attestation;
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

/// A production-shaped identity: a hybrid keypair and a key id that binds
/// the pubkey fingerprint (`derive_key_id`), as persist derives it.
struct Ident {
    key_id: String,
    ed: Arc<Ed25519SoftwareSigner>,
    pqc: Arc<MlDsa65SoftwareSigner>,
    ed_pub: Vec<u8>,
    pqc_pub_b64: String,
    /// Minted once per identity type: the same bytes on every directory, so
    /// the Key plane converges instead of refusing `conflicting_version`.
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

    /// A SELF-SIGNED registration as persist's `register_self_federation_key`
    /// mints one. No steward, no test root.
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
            attestation_evidence: Some(
                ciris_persist::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }
}

async fn put(dir: &SqliteBackend, att: Attestation) -> String {
    let id = att.attestation_id.clone();
    dir.put_attestation(SignedAttestation { attestation: att })
        .await
        .unwrap_or_else(|e| panic!("put {id}: {e:?}"));
    id
}

/// A running node: its node key, its owner person, and the owner-binding
/// (announced, `federation`). No root, no acceptance: a stranger to everyone.
struct Node {
    key: Ident,
    owner: Ident,
    dir: Arc<SqliteBackend>,
    metrics: EdgeMetrics,
}

impl Node {
    /// `known`: the other identities this directory is seeded with — the
    /// peers' NODE keys (the ladder's convention; owners cross on the wire)
    /// and any third party this node must already know.
    async fn new(
        key: Ident,
        owner: Ident,
        known: Vec<ciris_persist::federation::KeyRecord>,
    ) -> Self {
        let mut records = vec![key.record("node").await, owner.record("user").await];
        records.extend(known);
        let dir = directory_with(records).await;
        put(
            &dir,
            owner_binding_attestation(
                &owner.key_id,
                &key.key_id,
                chrono::Utc::now(),
                &owner.signer(),
            )
            .await
            .expect("owner binding"),
        )
        .await;
        Self {
            key,
            owner,
            dir,
            metrics: EdgeMetrics::new(),
        }
    }

    fn binding_id(&self) -> String {
        format!("owner-binding-{}", self.key.key_id)
    }

    async fn holds(&self, attestation_id: &str) -> bool {
        self.dir
            .get_attestation(attestation_id)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    async fn roster(&self, scope: GroupScope, group: &str) -> Vec<String> {
        let mut out: Vec<String> = match scope {
            GroupScope::Community => self
                .dir
                .active_community_members(group)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.key_id)
                .collect(),
            GroupScope::Family => self
                .dir
                .active_family_members(group)
                .await
                .unwrap_or_default()
                .into_iter()
                .map(|m| m.key_id)
                .collect(),
        };
        out.sort();
        out
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

/// The planes the ceremony and the member path ride.
const KINDS: [EnvelopeKind; 8] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
    EnvelopeKind::Attestation,
    EnvelopeKind::Community,
    EnvelopeKind::CommunityMembershipWidening,
    EnvelopeKind::Family,
    EnvelopeKind::FamilyMembershipWidening,
];

async fn start_runtime(
    node: &Node,
    transport: Arc<ReticulumTransport>,
    peers: &[&Ident],
    widener: Option<MembershipWidener>,
) -> Arc<ReplicationRuntime> {
    let peers = peers
        .iter()
        .flat_map(|p| {
            KINDS.into_iter().map(move |kind| ReplicationPeer {
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
                membership_widener: widener,
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

/// Found `group` on `node` with its owner ALONE (the persist v52 founding,
/// CIRISPersist#955 Q1), signed by the owner. `infrastructure` marks the
/// community public by its subkind (a conformant `quorum:1/1` over its one
/// founder, CC 3.2).
async fn found(node: &Node, scope: GroupScope, group: &str, infrastructure: bool) {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::{
        Community, CommunityMember, Family, FamilyMember, SignedCommunity, SignedFamily,
    };
    let at = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
        chrono::Utc::now(),
    );
    let founder = &node.owner;
    match scope {
        GroupScope::Community => {
            let (protocol, policy_blob) = if infrastructure {
                (
                    "quorum:1/1",
                    Some(serde_json::json!({
                        "cohort_subkind": ciris_persist::federation::admission::COHORT_SUBKIND_INFRASTRUCTURE,
                    })),
                )
            } else {
                ("founder_only", None)
            };
            let community = Community {
                community_key_id: group.to_owned(),
                community_name: group.to_owned(),
                members: vec![CommunityMember {
                    key_id: founder.key_id.clone(),
                    joined_at: at,
                    role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
                }],
                founded_at: at,
                consensus_protocol: protocol.to_owned(),
                policy_blob,
                persist_row_hash: String::new(),
                prev_head_digest: String::new(),
                charter_digest: String::new(),
            };
            let canonical =
                ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
                    .expect("canonicalize");
            let (ed, pqc) = sign_bound_hybrid(&founder.signer(), &canonical, "found")
                .await
                .expect("sign");
            node.dir
                .put_community(SignedCommunity {
                    community,
                    authority_key_id: founder.key_id.clone(),
                    scrub_signature_classical: ed,
                    scrub_signature_pqc: pqc,
                    supersede_proof: None,
                    cosignatures: Vec::new(),
                    lineage: Vec::new(),
                })
                .await
                .unwrap_or_else(|e| panic!("found community {group}: {e:?}"));
        }
        GroupScope::Family => {
            let family = Family {
                dissolved_at: None,
                family_key_id: group.to_owned(),
                family_name: group.to_owned(),
                members: vec![FamilyMember {
                    key_id: founder.key_id.clone(),
                    joined_at: at,
                    role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
                }],
                founded_at: at,
                consensus_protocol: "founder_only".to_owned(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
                prev_head_digest: String::new(),
                charter_digest: String::new(),
            };
            let canonical =
                ciris_persist::prelude::ceg_produce_canonicalize(&family.signing_envelope())
                    .expect("canonicalize");
            let (ed, pqc) = sign_bound_hybrid(&founder.signer(), &canonical, "found")
                .await
                .expect("sign");
            node.dir
                .put_family(SignedFamily {
                    cosignatures: Vec::new(),
                    family,
                    authority_key_id: founder.key_id.clone(),
                    scrub_signature_classical: ed,
                    scrub_signature_pqc: pqc,
                    supersede_proof: None,
                })
                .await
                .unwrap_or_else(|e| panic!("found family {group}: {e:?}"));
        }
    }
}

/// Does `node` hold the record of `group`?
async fn holds_record(node: &Node, scope: GroupScope, group: &str) -> bool {
    match scope {
        GroupScope::Community => node
            .dir
            .lookup_community(group)
            .await
            .ok()
            .flatten()
            .is_some(),
        GroupScope::Family => node.dir.lookup_family(group).await.ok().flatten().is_some(),
    }
}

/// The group-record withholds `node` booked (the #758 reason, by its label).
fn record_withholds(node: &Node) -> u64 {
    node.metrics
        .snapshot()
        .withholds_by_reason
        .iter()
        .filter(|(r, _)| r.as_str() == "group_record_not_member_or_invitee")
        .map(|(_, n)| *n)
        .sum()
}

/// persist's `stored_standing`, by variant name — the read the community arm
/// of `trust_root_valid` (`rooted_community_family`) takes.
async fn standing(node: &Node, community: &str) -> &'static str {
    use ciris_persist::federation::canonical_community::{stored_standing, StoredStanding};
    match stored_standing(&*node.dir, community)
        .await
        .expect("stored_standing reads")
    {
        StoredStanding::Absent => "absent",
        StoredStanding::Rooted(_) => "rooted",
        StoredStanding::Stalled { .. } => "stalled",
        StoredStanding::NotRooted { .. } => "not_rooted",
    }
}

const WA_FAMILY: &str = "wa-reclaim-762";
const PRIVATE_COMMUNITY: &str = "private-community-762";
const PRIVATE_FAMILY: &str = "private-family-762";

/// I23's public-group carve-out: FAILS on the pre-#762 gate (X, a non-member,
/// holds neither public record, so neither read resolves).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole scenario, one fixture
async fn a_public_group_resolves_on_a_non_member_762() {
    init_tracing();
    // The deployment publishes its WA reclaim body — the pin persist's reclaim
    // admission reads (`ReclaimPolicy::from_deployment_pin`). Set before any
    // node starts; this binary holds this one test.
    std::env::set_var(
        ciris_persist::federation::ReclaimPolicy::WA_FAMILY_ENV,
        WA_FAMILY,
    );
    assert_eq!(
        ciris_persist::federation::ReclaimPolicy::from_deployment_pin()
            .map(|p| p.wa_family_key_id)
            .as_deref(),
        Some(WA_FAMILY),
        "control: the WA pin is published"
    );

    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new("node-a-762", 0x62).await;
    let key_x = Ident::new("node-x-762", 0x63).await;
    let p = Ident::new("person-p-762", 0x72).await;
    let q = Ident::new("person-q-762", 0x73).await;
    let a_node = key_a.record("node").await;
    let x_node = key_x.record("node").await;
    // persist v53 S1 — `is_public_group` honours an `infrastructure` label
    // only on a community whose own key is the substrate authority
    // (`is_authorized_infrastructure_community`, SecReview F2), as
    // `ciris-canonical`'s is. Both directories hold that key.
    let infra_key = Ident::new("infra-community-762", 0x64).await;
    let infra_rec = infra_key
        .record(ciris_persist::federation::types::identity_type::SUBSTRATE_PERSIST)
        .await;
    let infra = infra_key.key_id.clone();
    let infra = infra.as_str();
    let a = Node::new(key_a, p, vec![x_node, infra_rec.clone()]).await;
    let x = Node::new(key_x, q, vec![a_node, infra_rec]).await;

    let base = tmp.path().to_path_buf();
    let (ta, addr_a) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("a/transport.id"), &a.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, a.auth())
    })
    .await;
    let port_a = addr_a.port();
    let (tx, _) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("x/transport.id"), &x.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, x.auth())
    })
    .await;
    let rt_a = start_runtime(&a, ta, &[&x.key], None).await;
    let rt_x = start_runtime(&x, tx, &[&a.key], None).await;
    for n in [&a, &x] {
        wait_for_own_route(n, Duration::from_secs(150)).await;
    }
    let all = [&rt_a, &rt_x];

    // P founds the four groups on A, alone.
    found(&a, GroupScope::Community, infra, true).await;
    found(&a, GroupScope::Family, WA_FAMILY, false).await;
    found(&a, GroupScope::Community, PRIVATE_COMMUNITY, false).await;
    found(&a, GroupScope::Family, PRIVATE_FAMILY, false).await;
    let public = [
        (GroupScope::Community, infra.to_owned()),
        (GroupScope::Family, WA_FAMILY.to_owned()),
    ];

    // Control: the two are talking (the #671 allegiance facts cross).
    let talking = drive_until(&all, Duration::from_secs(240), || async {
        x.holds(&a.binding_id()).await && a.holds(&x.binding_id()).await
    })
    .await;
    assert!(talking, "control: the allegiance facts cross first contact");

    // X, a non-member, receives each public record.
    let received = drive_until(&all, Duration::from_secs(240), || async {
        for (scope, group) in &public {
            if !holds_record(&x, *scope, group).await {
                return false;
            }
        }
        true
    })
    .await;
    for (scope, group) in &public {
        assert!(
            holds_record(&x, *scope, group).await,
            "X (no membership, no invitation) holds the PUBLIC {scope:?} record {group} \
             (CIRISEdge#762); received={received}; A withholds={:?}",
            a.metrics.snapshot().withholds_by_reason
        );
    }

    // (i) The community arm of `trust_root_valid`: persist's stored standing of
    // the infrastructure community answers on X as on its holder.
    let (on_a, on_x) = (standing(&a, infra).await, standing(&x, infra).await);
    assert_ne!(
        on_x, "absent",
        "(i) X resolves the infrastructure community"
    );
    assert_eq!(on_x, on_a, "(i) the same standing on X as on the holder");

    // (ii) The reclaim reads (`wa_quorum_over_body`): the WA body resolves on
    // X, with the same non-empty active roster as on the holder.
    assert!(
        x.dir
            .lookup_family(WA_FAMILY)
            .await
            .expect("lookup_family")
            .is_some(),
        "(ii) X resolves the configured WA reclaim body"
    );
    let roster_x = x.roster(GroupScope::Family, WA_FAMILY).await;
    assert!(!roster_x.is_empty(), "(ii) the WA roster is not empty on X");
    assert_eq!(
        roster_x,
        a.roster(GroupScope::Family, WA_FAMILY).await,
        "(ii) the same WA roster on X as on the holder"
    );

    // Negatives: the PRIVATE groups beside them never reach X, and A's
    // #758 gate FIRED on them (an absence alone is not a witness).
    let leaked = drive_until(&all, Duration::from_secs(20), || async {
        holds_record(&x, GroupScope::Community, PRIVATE_COMMUNITY).await
            || holds_record(&x, GroupScope::Family, PRIVATE_FAMILY).await
    })
    .await;
    assert!(!leaked, "no private group record reaches the non-member");
    assert!(
        record_withholds(&a) > 0,
        "A's group-record gate FIRED on the private records; withholds={:?}",
        a.metrics.snapshot().withholds_by_reason
    );
}
