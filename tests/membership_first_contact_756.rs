//! CIRISEdge#756 — a membership proposal reaches its stranger invitee and the
//! reply comes back (`FSD/FIRST_CONTACT.md` §2.4, I22; CIRISPersist#955;
//! CC rc6 3.1.3.2; CIRISConstitution#133).
//!
//! Three running nodes over real Reticulum links, real SQLite directories,
//! and NO consent and NO trust root anywhere: every pair is at first contact
//! (`Reach::FirstContact`) and un-Rooted, which is what an invitation to a
//! stranger looks like.
//!
//! - **node A**, owned by person **P**, where P founds group **G** alone (a
//!   community in one test, a family in the other) and carries the
//!   `MembershipWidener` for P;
//! - **node B**, owned by person **K** (the invitee), peered with A;
//! - **node C**, owned by person **Q** (a different stranger), peered with A.
//!
//! The flow, asserted on ADMITTED rows, never on logs: A proposes K
//! (`membership::propose`); B receives the proposal and nothing else of G's
//! rows; K accepts on B (`membership::reply`); A receives the acceptance and
//! widens (the bridge's widener hook); K is a member at A and at B; A consents
//! to B and a subsequent G row reaches B through the ordinary member path.
//!
//! Negatives in the same run: before the proposal B holds no G row; a proposal
//! to a third person Z never reaches B (while it is still a stranger) nor C; C
//! gets neither K's proposal nor K's acceptance; K's decline of a proposal A
//! does not hold (M's, seeded at B) never reaches A.
//!
//! On the pre-#756 gate the invitation never arrives: A withholds the
//! proposal from B at the first-contact reach (`recipient_not_in_send_set`),
//! so B never holds it.
//!
//! `cargo test --features transport-http,transport-reticulum --test membership_first_contact_756`
#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::membership::{self, GroupScope, MembershipWidener};
use ciris_edge::observability::WithholdReason;
use ciris_edge::replication::attestation_bind::{
    owner_binding_attestation, replication_consent_attestation, DEFAULT_CONSENT_PREFIXES,
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

/// Found `group` on `node` with its owner ALONE (founder, `founder_only`),
/// signed by the owner: the only founding persist v52 admits for a member who
/// signed nothing else (CIRISPersist#955 Q1).
async fn found(node: &Node, scope: GroupScope, group: &str) {
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
            let community = Community {
                community_key_id: group.to_owned(),
                community_name: "G".to_owned(),
                members: vec![CommunityMember {
                    key_id: founder.key_id.clone(),
                    joined_at: at,
                    role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
                }],
                founded_at: at,
                consensus_protocol: "founder_only".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
                prev_head_digest: String::new(),
                charter_digest: String::new(),
            };
            let canonical =
                ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
                    .expect("canonicalize G");
            let (ed, pqc) = sign_bound_hybrid(&founder.signer(), &canonical, "found G")
                .await
                .expect("sign G");
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
                .expect("found the community");
        }
        GroupScope::Family => {
            let family = Family {
                dissolved_at: None,
                family_key_id: group.to_owned(),
                family_name: "G".to_owned(),
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
                    .expect("canonicalize G");
            let (ed, pqc) = sign_bound_hybrid(&founder.signer(), &canonical, "found G")
                .await
                .expect("sign G");
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
                .expect("found the family");
        }
    }
}

/// A federation-tier `chat:message:v1` row at `group`, authored and signed by
/// `author`: the placement AV-45 judges by the author's membership.
async fn group_row(
    scope: GroupScope,
    group: &str,
    author: &LocalSigner,
    dir: &SqliteBackend,
) -> String {
    use ciris_persist::federation::attestation_emit;
    let mut extra = serde_json::Map::new();
    extra.insert(scope.target_member().into(), group.into());
    extra.insert("score".into(), 1.0.into());
    let envelope = ciris_persist::federation::envelope::EnvelopeCore {
        dimension: Some(ciris_edge::chat::CHAT_MESSAGE_DIMENSION.to_owned()),
        extra,
        ..Default::default()
    };
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        "scores",
        envelope,
        scope.cohort_scope(),
    );
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, &author.key_id, chrono::Utc::now())
            .expect("stamp");
    let sig = ciris_edge::identity::sign_hybrid_raw(author, &canonical, "group row")
        .await
        .expect("sign");
    let row = attestation_emit::assemble(author.key_id.clone(), &canonical, sig, input)
        .expect("assemble")
        .0;
    let id = row.attestation_id.clone();
    dir.put_attestation_authored(SignedAttestation { attestation: row })
        .await
        .expect("a member's row at its group");
    id
}

struct Fixture {
    a: Node,
    b: Node,
    c: Node,
    rt_a: Arc<ReplicationRuntime>,
    rt_b: Arc<ReplicationRuntime>,
    rt_c: Arc<ReplicationRuntime>,
    /// A third person: A proposes them, and nothing of it may reach B or C.
    z: Ident,
    /// A person whose proposal naming K is held at B (A never held it).
    m: Ident,
    _tmp: tempfile::TempDir,
}

#[allow(clippy::many_single_char_names)] // the issue's names
async fn fixture(tag: u8) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new(&format!("node-a-756-{tag}"), 0x0a ^ tag).await;
    let key_b = Ident::new(&format!("node-b-756-{tag}"), 0x0b ^ tag).await;
    let key_c = Ident::new(&format!("node-c-756-{tag}"), 0x0c ^ tag).await;
    let p = Ident::new(&format!("person-p-756-{tag}"), 0x1a ^ tag).await;
    let k = Ident::new(&format!("person-k-756-{tag}"), 0x1b ^ tag).await;
    let q = Ident::new(&format!("person-q-756-{tag}"), 0x1c ^ tag).await;
    let z = Ident::new(&format!("person-z-756-{tag}"), 0x1d ^ tag).await;
    let m = Ident::new(&format!("person-m-756-{tag}"), 0x1e ^ tag).await;
    let (b_node, c_node, a_node) = (
        key_b.record("node").await,
        key_c.record("node").await,
        key_a.record("node").await,
    );
    let a = Node::new(key_a, p, vec![b_node, c_node, z.record("user").await]).await;
    let b = Node::new(key_b, k, vec![a_node.clone(), m.record("user").await]).await;
    let c = Node::new(key_c, q, vec![a_node]).await;

    let base = tmp.path().to_path_buf();
    let (ta, addr_a) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("a/transport.id"), &a.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, a.auth())
    })
    .await;
    let port_a = addr_a.port();
    let (tb, _) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("b/transport.id"), &b.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, b.auth())
    })
    .await;
    let (tc, _) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("c/transport.id"), &c.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, c.auth())
    })
    .await;
    let rt_a = start_runtime(
        &a,
        ta,
        &[&b.key, &c.key],
        Some(MembershipWidener::new(vec![a.owner.signer()])),
    )
    .await;
    let rt_b = start_runtime(&b, tb, &[&a.key], None).await;
    let rt_c = start_runtime(&c, tc, &[&a.key], None).await;
    for n in [&a, &b, &c] {
        wait_for_own_route(n, Duration::from_secs(150)).await;
    }
    Fixture {
        a,
        b,
        c,
        rt_a,
        rt_b,
        rt_c,
        z,
        m,
        _tmp: tmp,
    }
}

#[allow(clippy::too_many_lines)] // the whole ceremony, in order, on purpose
async fn a_stranger_is_invited_accepts_and_joins(scope: GroupScope, tag: u8) {
    init_tracing();
    let f = fixture(tag).await;
    let (a, b, c) = (&f.a, &f.b, &f.c);
    let all = [&f.rt_a, &f.rt_b, &f.rt_c];
    let group = format!("g-756-{tag}");
    let expires = chrono::Utc::now() + chrono::Duration::days(7);

    // G, founded on A by P alone; a row of G; a proposal to a third person Z.
    found(a, scope, &group).await;
    let early_row = group_row(scope, &group, &a.owner.signer(), &a.dir).await;
    let to_z = membership::propose(
        &*a.dir,
        scope,
        &group,
        &f.z.key_id,
        None,
        expires,
        &a.key.signer(),
    )
    .await
    .expect("P proposes Z")
    .attestation_id;
    // At B: M's proposal naming K (into a group A never held) and K's
    // decline of it — a reply to a proposal A does not hold.
    let m_proposal = membership::proposal_attestation(
        scope,
        &format!("m-group-756-{tag}"),
        &b.owner.key_id,
        None,
        expires,
        &f.m.signer(),
    )
    .await
    .expect("M's proposal");
    put(&b.dir, m_proposal.clone()).await;
    let decline_m = membership::reply(&*b.dir, &m_proposal.attestation_id, false, &b.key.signer())
        .await
        .expect("K declines M's proposal")
        .attestation_id;

    // Control: the three are talking — each stranger holds A's owner-binding
    // and A holds theirs (#671 allegiance facts).
    let talking = drive_until(&all, Duration::from_secs(240), || async {
        b.holds(&a.binding_id()).await
            && c.holds(&a.binding_id()).await
            && a.holds(&b.binding_id()).await
            && a.holds(&c.binding_id()).await
    })
    .await;
    assert!(
        talking,
        "control: the allegiance facts cross first contact (#671)"
    );
    for n in [b, c] {
        assert!(
            !n.holds(&early_row).await && !n.holds(&to_z).await,
            "before any proposal to its person a stranger holds no row of G"
        );
    }

    // 1. A proposes K. B receives the proposal.
    let proposal = membership::propose(
        &*a.dir,
        scope,
        &group,
        &b.owner.key_id,
        None,
        expires,
        &a.key.signer(),
    )
    .await
    .expect("P proposes K");
    let invited = drive_until(&all, Duration::from_secs(240), || async {
        b.holds(&proposal.attestation_id).await
    })
    .await;
    if !invited {
        eprintln!(
            "B never received the proposal; A withholds={:?}",
            a.metrics.snapshot().withholds_by_reason
        );
    }
    assert!(
        invited,
        "the invitation reaches the stranger invitee's node at first contact (I22)"
    );
    let inbox = membership::pending_proposals_for(&*b.dir, &b.owner.key_id)
        .await
        .expect("inbox");
    assert!(
        inbox
            .iter()
            .any(|p| p.proposal.attestation_id == proposal.attestation_id),
        "K's inbox on B lists P's proposal"
    );
    assert!(
        !b.holds(&early_row).await && !b.holds(&to_z).await,
        "B receives the proposal and nothing else of G: no row, no proposal to Z"
    );

    // 2. K accepts on B. A receives the acceptance and widens.
    let acceptance = membership::reply(&*b.dir, &proposal.attestation_id, true, &b.key.signer())
        .await
        .expect("K accepts on B")
        .attestation_id;
    let joined = drive_until(&all, Duration::from_secs(240), || async {
        a.holds(&acceptance).await && a.roster(scope, &group).await.contains(&b.owner.key_id)
    })
    .await;
    if !joined {
        eprintln!(
            "A holds acceptance={} roster={:?}; B withholds={:?}",
            a.holds(&acceptance).await,
            a.roster(scope, &group).await,
            b.metrics.snapshot().withholds_by_reason
        );
    }
    assert!(
        joined,
        "the reply comes back to the proposer's node and A widens K in (I22)"
    );
    assert!(
        !b.holds(&to_z).await,
        "a proposal to a third person never reached B while it was a stranger"
    );

    // 3. K is a member; A consents to B and a later G row reaches B on the
    //    ordinary member path (consent reach + the group's audience).
    put(
        &a.dir,
        replication_consent_attestation(
            &a.key.key_id,
            &b.key.key_id,
            &DEFAULT_CONSENT_PREFIXES,
            chrono::Utc::now(),
            &a.key.signer(),
        )
        .await
        .expect("consent A -> B"),
    )
    .await;
    let later_row = group_row(scope, &group, &a.owner.signer(), &a.dir).await;
    let member_path = drive_until(&all, Duration::from_secs(240), || async {
        b.roster(scope, &group).await.contains(&b.owner.key_id) && b.holds(&later_row).await
    })
    .await;
    if !member_path {
        eprintln!(
            "B roster={:?} holds later row={}; A withholds={:?}",
            b.roster(scope, &group).await,
            b.holds(&later_row).await,
            a.metrics.snapshot().withholds_by_reason
        );
    }
    assert!(
        member_path,
        "K is a member on B too, and a subsequent G row reaches B through the member path"
    );

    // Negatives, given the rounds the positives took and more.
    let leaked = drive_until(&all, Duration::from_secs(20), || async {
        c.holds(&proposal.attestation_id).await
            || c.holds(&acceptance).await
            || c.holds(&to_z).await
            || c.holds(&early_row).await
            || a.holds(&decline_m).await
    })
    .await;
    assert!(!leaked, "no leak (details below)");
    assert!(
        !c.holds(&proposal.attestation_id).await && !c.holds(&acceptance).await,
        "a different stranger gets neither the proposal nor the reply"
    );
    assert!(
        !c.holds(&to_z).await && !c.holds(&early_row).await,
        "nor anything else of G"
    );
    assert!(
        !a.holds(&decline_m).await,
        "a reply by K to a proposal A does not hold is not served back"
    );
    assert!(
        a.metrics.withholds(WithholdReason::RecipientNotInSendSet) > 0,
        "A's first-contact narrowing FIRED on the rows it kept back — an absence alone is \
         not a witness"
    );
}

/// I22, community: FAILS on the pre-#756 gate (B never holds the proposal).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_is_invited_accepts_and_joins_over_first_contact_756() {
    a_stranger_is_invited_accepts_and_joins(GroupScope::Community, 0x00).await;
}

/// I22, family: the same ceremony at a family target.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stranger_is_invited_accepts_and_joins_a_family_over_first_contact_756() {
    a_stranger_is_invited_accepts_and_joins(GroupScope::Family, 0x20).await;
}
