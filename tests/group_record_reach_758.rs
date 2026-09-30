//! CIRISEdge#758 — a group record reaches only its members and its live
//! invitees (CC 5.4.6: the construction "hides the group's existence,
//! membership, and `querier → invitee` edges from outsiders";
//! `FSD/FIRST_CONTACT.md` §2.5, I23; `FSD/CIRIS_EDGE_TRANSPORT.md` §6).
//!
//! Four running nodes over real Reticulum links, real SQLite directories, no
//! consent and no trust root anywhere (every pair is at first contact):
//!
//! - **node A**, owned by person **P**, where P founds community **G** and
//!   family **F** alone and carries the `MembershipWidener` for P;
//! - **node B**, owned by **J**: a stranger, never proposed;
//! - **node C**, owned by **K**: invited into G and F by a live proposal (and
//!   later into a pair room with P, the #754 case);
//! - **node D**, owned by **L**: invited, accepts, and becomes a member.
//!
//! Asserted on ADMITTED rows (`lookup_community` / `lookup_family`), never on
//! logs: B holds neither record at any point; C holds each only once
//! proposed, and holds the proposal; D holds each as a member; C receives the
//! pair room's record once P opens the room with K. A books the new
//! `group_record_not_member_or_invitee` withhold: the absence is the gate
//! firing, not a quiet link.
//!
//! On the pre-#758 code the record planes are peer-blind: A advertises the
//! groups its own person founded to EVERY peer, so B, C and D all hold G's and
//! F's records before any proposal exists.
//!
//! `cargo test --features transport-http,transport-reticulum --test group_record_reach_758`
#![cfg(feature = "transport-reticulum")]

mod common;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::membership::{self, GroupScope, MembershipWidener};
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

struct Fixture {
    a: Node,
    b: Node,
    c: Node,
    d: Node,
    rt_a: Arc<ReplicationRuntime>,
    rt_b: Arc<ReplicationRuntime>,
    rt_c: Arc<ReplicationRuntime>,
    rt_d: Arc<ReplicationRuntime>,
    _tmp: tempfile::TempDir,
}

async fn fixture(tag: u8) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_a = Ident::new(&format!("node-a-758-{tag}"), 0x2a ^ tag).await;
    let key_b = Ident::new(&format!("node-b-758-{tag}"), 0x2b ^ tag).await;
    let key_c = Ident::new(&format!("node-c-758-{tag}"), 0x2c ^ tag).await;
    let key_d = Ident::new(&format!("node-d-758-{tag}"), 0x2d ^ tag).await;
    let p = Ident::new(&format!("person-p-758-{tag}"), 0x3a ^ tag).await;
    let j = Ident::new(&format!("person-j-758-{tag}"), 0x3b ^ tag).await;
    let k = Ident::new(&format!("person-k-758-{tag}"), 0x3c ^ tag).await;
    let l = Ident::new(&format!("person-l-758-{tag}"), 0x3d ^ tag).await;
    let a_node = key_a.record("node").await;
    let others = vec![
        key_b.record("node").await,
        key_c.record("node").await,
        key_d.record("node").await,
    ];
    let a = Node::new(key_a, p, others).await;
    let b = Node::new(key_b, j, vec![a_node.clone()]).await;
    let c = Node::new(key_c, k, vec![a_node.clone()]).await;
    let d = Node::new(key_d, l, vec![a_node]).await;

    let base = tmp.path().to_path_buf();
    let (ta, addr_a) = build_reticulum_with_retry(|| async {
        let mut cfg = ReticulumTransportConfig::new(base.join("a/transport.id"), &a.key.key_id);
        cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        cfg.announce_interval = Duration::from_secs(5);
        (cfg, a.auth())
    })
    .await;
    let port_a = addr_a.port();
    let mut spokes = Vec::new();
    for (n, dir) in [(&b, "b"), (&c, "c"), (&d, "d")] {
        let (t, _) = build_reticulum_with_retry(|| async {
            let mut cfg = ReticulumTransportConfig::new(
                base.join(format!("{dir}/transport.id")),
                &n.key.key_id,
            );
            cfg.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            cfg.bootstrap_peers = vec![format!("127.0.0.1:{port_a}").parse().unwrap()];
            cfg.announce_interval = Duration::from_secs(5);
            (cfg, n.auth())
        })
        .await;
        spokes.push(t);
    }
    let rt_a = start_runtime(
        &a,
        ta,
        &[&b.key, &c.key, &d.key],
        Some(MembershipWidener::new(vec![a.owner.signer()])),
    )
    .await;
    let td = spokes.pop().expect("d");
    let tc = spokes.pop().expect("c");
    let tb = spokes.pop().expect("b");
    let rt_b = start_runtime(&b, tb, &[&a.key], None).await;
    let rt_c = start_runtime(&c, tc, &[&a.key], None).await;
    let rt_d = start_runtime(&d, td, &[&a.key], None).await;
    for n in [&a, &b, &c, &d] {
        wait_for_own_route(n, Duration::from_secs(150)).await;
    }
    Fixture {
        a,
        b,
        c,
        d,
        rt_a,
        rt_b,
        rt_c,
        rt_d,
        _tmp: tmp,
    }
}

/// The group-record withholds A booked (the new reason, read by its label).
fn record_withholds(node: &Node) -> u64 {
    node.metrics
        .snapshot()
        .withholds_by_reason
        .iter()
        .filter(|(r, _)| r.as_str() == "group_record_not_member_or_invitee")
        .map(|(_, n)| *n)
        .sum()
}

/// I23: FAILS on the pre-#758 code (B, C and D hold G's and F's records
/// before any proposal: the founder-advertise leak).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole lifecycle, in order, on purpose
async fn a_group_record_reaches_only_members_and_live_invitees_758() {
    init_tracing();
    let f = fixture(0x00).await;
    let (a, b, c, d) = (&f.a, &f.b, &f.c, &f.d);
    let all = [&f.rt_a, &f.rt_b, &f.rt_c, &f.rt_d];
    let g = "g-758".to_owned();
    let fam = "f-758".to_owned();
    let groups = [(GroupScope::Community, &g), (GroupScope::Family, &fam)];
    let expires = chrono::Utc::now() + chrono::Duration::days(7);

    // P founds G and F on A, alone.
    for (scope, group) in groups {
        found(a, scope, group).await;
    }

    // Control: the four are talking (each spoke holds A's owner-binding and
    // A holds theirs, the #671 allegiance facts), then more rounds on top.
    let talking = drive_until(&all, Duration::from_secs(240), || async {
        b.holds(&a.binding_id()).await
            && c.holds(&a.binding_id()).await
            && d.holds(&a.binding_id()).await
            && a.holds(&b.binding_id()).await
            && a.holds(&c.binding_id()).await
            && a.holds(&d.binding_id()).await
    })
    .await;
    assert!(
        talking,
        "control: the allegiance facts cross first contact (#671)"
    );
    let early_leak = drive_until(&all, Duration::from_secs(20), || async {
        for n in [b, c, d] {
            for (scope, group) in groups {
                if holds_record(n, scope, group).await {
                    return true;
                }
            }
        }
        false
    })
    .await;
    for (name, n) in [("B", b), ("C", c), ("D", d)] {
        for (scope, group) in groups {
            assert!(
                !holds_record(n, scope, group).await,
                "before any proposal, {name} (an outsider) holds the record of {scope:?} {group} \
                 — the founder-advertise leak (CC 5.4.6); early_leak={early_leak}"
            );
        }
    }

    // 1. P (through A) proposes K (C's person) and L (D's person) into both.
    let mut to_c = Vec::new();
    let mut to_d = Vec::new();
    for (scope, group) in groups {
        for (invitee, out) in [(&c.owner.key_id, &mut to_c), (&d.owner.key_id, &mut to_d)] {
            out.push(
                membership::propose(
                    &*a.dir,
                    scope,
                    group,
                    invitee,
                    None,
                    expires,
                    &a.key.signer(),
                )
                .await
                .expect("P proposes")
                .attestation_id,
            );
        }
    }
    let invited = drive_until(&all, Duration::from_secs(240), || async {
        for n in [c, d] {
            for (scope, group) in groups {
                if !holds_record(n, scope, group).await {
                    return false;
                }
            }
        }
        for id in to_c.iter() {
            if !c.holds(id).await {
                return false;
            }
        }
        for id in to_d.iter() {
            if !d.holds(id).await {
                return false;
            }
        }
        true
    })
    .await;
    if !invited {
        eprintln!(
            "C/D not invited; A withholds={:?}",
            a.metrics.snapshot().withholds_by_reason
        );
    }
    assert!(
        invited,
        "a live invitee's node holds the proposal AND the group record it needs"
    );
    let inbox = membership::pending_proposals_for(&*c.dir, &c.owner.key_id)
        .await
        .expect("inbox");
    assert_eq!(
        inbox.len(),
        2,
        "C admitted both proposals: K's inbox lists them"
    );

    // 2. L accepts both on D; A widens L in; D reads L as a member.
    for id in &to_d {
        membership::reply(&*d.dir, id, true, &d.key.signer())
            .await
            .expect("L accepts on D");
    }
    let joined = drive_until(&all, Duration::from_secs(240), || async {
        for (scope, group) in groups {
            if !a.roster(scope, group).await.contains(&d.owner.key_id)
                || !d.roster(scope, group).await.contains(&d.owner.key_id)
            {
                return false;
            }
        }
        true
    })
    .await;
    if !joined {
        eprintln!(
            "D not joined; A rosters={:?}/{:?}, D rosters={:?}/{:?}; A withholds={:?}",
            a.roster(GroupScope::Community, &g).await,
            a.roster(GroupScope::Family, &fam).await,
            d.roster(GroupScope::Community, &g).await,
            d.roster(GroupScope::Family, &fam).await,
            a.metrics.snapshot().withholds_by_reason
        );
    }
    assert!(
        joined,
        "the member holds the record and reads itself on the roster"
    );

    // 3. The #754 pair room: P opens a room with K; C gets the room record.
    let opened = ciris_edge::chat::open_pair_room(
        &*a.dir,
        &a.owner.key_id,
        &c.owner.key_id,
        ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
            chrono::Utc::now(),
        ),
        expires,
        &a.owner.signer(),
    )
    .await
    .expect("P opens the pair room with K");
    let room = opened.room.clone();
    let room_proposal = opened.proposal.expect("the room proposes K").attestation_id;
    let paired = drive_until(&all, Duration::from_secs(240), || async {
        holds_record(c, GroupScope::Community, &room).await && c.holds(&room_proposal).await
    })
    .await;
    assert!(
        paired,
        "the pair room's invitee gets the room record with the proposal (#754)"
    );

    // Negatives, over the rounds above and more: B, the stranger, holds no
    // record of G, F or the room; A's gate FIRED on it.
    let leaked = drive_until(&all, Duration::from_secs(20), || async {
        holds_record(b, GroupScope::Community, &g).await
            || holds_record(b, GroupScope::Family, &fam).await
            || holds_record(b, GroupScope::Community, &room).await
            || holds_record(d, GroupScope::Community, &room).await
    })
    .await;
    assert!(!leaked, "no outsider holds a group record (details below)");
    for (scope, group) in [
        (GroupScope::Community, &g),
        (GroupScope::Family, &fam),
        (GroupScope::Community, &room),
    ] {
        assert!(
            !holds_record(b, scope, group).await,
            "B, never proposed, never holds {scope:?} {group}"
        );
    }
    assert!(
        !holds_record(d, GroupScope::Community, &room).await,
        "D, a member of G but not of the pair room, never holds the room's record"
    );
    assert!(
        record_withholds(a) > 0,
        "A's group-record gate FIRED on the records it kept back — an absence alone is not a \
         witness; withholds={:?}",
        a.metrics.snapshot().withholds_by_reason
    );
}
