//! **CIRISEdge#736 — files cross a FAMILY room over the wire** (lane 3 of
//! CIRISEdge#734; `FSD/CONTENT_TRANSFER.md` §6.4.1 and §6.7's family row).
//!
//! Two persons, P and Q, each with one device (P1, Q1), and a family formed
//! under persist v52's consent rule (CIRISPersist#955, CIRISConstitution#133):
//! P founds it ALONE; P1 proposes Q; the founding record crosses to Q1 on
//! P1's publish-own arm (the family twin of #955's community arm) and the
//! proposal is admitted at Q1's bridge apply door; Q1 accepts for Q
//! (`membership::reply`, a device acting for its person); the acceptance is
//! admitted at P1's door and P1's bridge widens on arrival
//! (`MembershipWidener`); the widening crosses on P1's serve. A third person R consents
//! and is widened in too, but R has no device yet — the roster's `unresolved`
//! member.
//!
//! P1 publishes a 200 KiB (inline) and a 1.3 MiB (chunk DAG) file in the
//! family room, authored by the person P and co-signed by P1 (#675). Each
//! crossed row reaches Q1 through P1's bridge serve and Q1's bridge apply,
//! with Q1's pull sink wired; Q1's REAL puller (sink → `pull_one` → the
//! family `author_nodes` rung → the scope router → Reticulum) fetches the
//! bytes from P1's scope-native serve gate, whose chunk source answers only
//! from a row referencing the asked-for blob (the host rule, #717). Nothing in
//! this file calls `pull_one` or `pull_dag_with`, and nothing copies a byte.
//!
//! What each witness pins, from the side that must show it:
//! - **(a) delivered, never discovered** (CC 5.2): no node holds a
//!   `holds_bytes` row for either sha, at any audience — the discovery index
//!   (`list_holders`, `list_local_holders`) and the federation stream both.
//! - **(b) the send set is the roster**: for each file row, P1's bridge
//!   offers it to exactly `family_room::roster(..).nodes` (minus P1), and the
//!   roster's unresolved member R is NAMED on the publish
//!   (`PublishedFile::unresolved`), never a silent skip.
//! - **(c) a non-family node N** on the same mesh: P1's bridge offers N
//!   neither file row and serves neither by hash (booked
//!   `recipient_not_in_send_set`); N holds no row and no byte; N's direct
//!   blob request for either sha is refused on P1's serve gate by name
//!   (`blob_serve_arrival_scope_insufficient`, `PolicyDenied` on the wire);
//!   N's occurrence holds no content grant; N cannot even route the family.
//! - **(d) a non-member forwarder F**: with P1 and Q1 dialling only F, both
//!   bodies still cross — on the members' identity-plane link, the family
//!   discriminated inside it (#718) — and F holds nothing naming the family:
//!   not in its path table, not in a scope table, not in its directory, not
//!   a byte of either file.
//!
//! Requires the `transport-reticulum` feature.

#![cfg(feature = "transport-reticulum")]
#![allow(clippy::too_many_lines, clippy::similar_names)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::blob_swarm::{BlobMeaning, BlobPuller, ContentScope, PullConfig};
use ciris_edge::files::{FileRow, PublishedFile};
use ciris_edge::group_content::PersistGroupContentStore;
use ciris_edge::membership::{self, GroupScope, MembershipWidener};
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::observability::WithholdReason;
use ciris_edge::replication::attestation_bind::{Shared, Signers};
use ciris_edge::replication::{
    ApplyOutcome, BridgeConfig, BridgeEngine, EnvelopeKind, FederationDirectoryReplicationBridge,
    ReplicationDirectory as _,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport as _};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::{CohortScope, Edge, EdgeConfig, HybridPolicy};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::key_grant::{SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX};
use ciris_persist::federation::types::{Family, FamilyMember, SignedFamily};
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use common::build_reticulum_with_retry;
use sha2::Digest as _;

const FAMILY: &str = "family-moore-736";
/// Under the inline bound: one sealed blob inside the envelope.
const INLINE_LEN: usize = 200 * 1024;
/// Over it: a sealed chunk DAG (five 256 KiB chunks).
const DAG_LEN: usize = 1_300_000;

fn content(len: usize, seed: u32) -> Vec<u8> {
    (0..u32::try_from(len).expect("fits"))
        .map(|i| {
            let mixed = i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13;
            u8::try_from(mixed & 0xFF).expect("masked")
        })
        .collect()
}

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ciris_edge=warn")),
        )
        .with_test_writer()
        .try_init();
}

// ─── identities and nodes (the `self_dag_field_path_717` shape) ───────

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

    /// This identity as an edge signer under its own key id (a PERSON's key:
    /// the file's author, #675, and the roster's seat key).
    fn signer(&self) -> Arc<ciris_edge::identity::LocalSigner> {
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
        Arc::new(ciris_edge::identity::LocalSigner::new(
            self.key_id.clone(),
            hw,
            Some(pqc),
        ))
    }
}

/// One node: its own substrate, content store and engine key.
struct Node {
    dir: Arc<SqliteBackend>,
    store: PersistGroupContentStore,
    /// The owner (a person).
    identity: String,
    /// The engine's derived signing key — the node on the wire, its
    /// occurrence, the viewer for every read here.
    me: String,
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// A device of `owner` (`self_dag_field_path_717::device`): the node key is
/// `device`'s, the owner binding is signed by `owner`, the engine occurrence
/// is provisioned under the owner.
/// `class` is the occurrence's `device_class` (persist v53 S1, CC 3.3.7): a
/// person's own device is `phone`, so it is in its family's audience; the
/// forwarder is a `server`.
async fn device(seed_idents: &[&Ident], owner: &Ident, device: &Ident, class: &str) -> Node {
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
    let identity = ciris_edge::identity::LocalSigner::new(derived.clone(), hw, Some(pqc));
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
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
    let (me, _) = ciris_edge::content_occurrence::provision_engine_occurrence(
        store.engine(),
        &*dir,
        &owner.key_id,
        class,
    )
    .await
    .expect("provision this node's engine occurrence");
    Node {
        dir,
        store,
        identity: owner.key_id.clone(),
        me,
        signer: Arc::new(identity),
    }
}

/// The far node's key, owner binding and published occurrence — what the
/// Key / Attestation / IdentityOccurrence planes carry on a real mesh.
async fn federate(from: &Node, to: &Node) {
    let rec = FederationDirectory::lookup_public_key(&*from.dir, &from.me)
        .await
        .expect("lookup")
        .expect("the engine registered its derived key");
    to.dir
        .put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the far node's derived key");
    for row in FederationDirectory::list_attestations_since(&*from.dir, None, 256)
        .await
        .expect("list the attestation plane")
    {
        let att = row.attestation;
        if att.attested_key_id == from.me
            && ciris_persist::federation::admission::is_owner_binding_envelope(
                &att.attestation_envelope,
            )
        {
            to.dir
                .apply_replicated_attestation(SignedAttestation { attestation: att })
                .await
                .expect("carry the far node's owner binding");
        }
    }
    let occ = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .expect("list the signed occurrence plane")
        .into_iter()
        .map(|s| s.occurrence)
        .find(|o| {
            o.identity_occurrence.occurrence_key_id == from.me
                && o.identity_occurrence.identity_key_id == from.identity
        })
        .expect("the engine occurrence is on the signed plane");
    to.dir
        .put_identity_occurrence(occ)
        .await
        .expect("admit the far node's occurrence");
}

/// The far node's hybrid-signed reticulum route, through persist's gate.
async fn carry_route(from: &Node, to: &Node) {
    for row in FederationDirectory::list_signed_transport_destinations_for(&*from.dir, &from.me)
        .await
        .expect("list the far node's signed routes")
        .into_iter()
        .filter(|r| r.transport_destination.transport_kind == "reticulum")
    {
        let _ = FederationDirectory::put_signed_transport_destination(&*to.dir, &row).await;
    }
}

fn auth_for(node: &Node) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(Arc::clone(&node.signer)),
        rooting: Some(Arc::clone(&node.dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

async fn transport_for(
    node: &Node,
    id_path: PathBuf,
    bootstrap: &[u16],
    transport_node: bool,
) -> (Arc<ReticulumTransport>, u16) {
    let (rt, addr) = build_reticulum_with_retry(|| {
        let id_path = id_path.clone();
        let auth = auth_for(node);
        let key = node.me.clone();
        let boots: Vec<std::net::SocketAddr> = bootstrap
            .iter()
            .map(|p| format!("127.0.0.1:{p}").parse().unwrap())
            .collect();
        async move {
            let mut c =
                ReticulumTransportConfig::new(id_path, &key).with_transport_node(transport_node);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = boots;
            c.announce_interval = Duration::from_secs(10);
            (c, auth)
        }
    })
    .await;
    (rt, addr.port())
}

/// **The chunk source a scope-native HOST wires** (#717): a blob's scope is
/// the scope the rows placing it project, the family WIDENING before the
/// author's own `self` row ([`BlobMeaning::serve_scope`], #736) — for a
/// family file, the family room. `None` for an unreferenced sha.
struct RowScopedSource {
    inner: ciris_edge::blob_swarm::PersistBlobChunkSource,
    dir: Arc<SqliteBackend>,
}

#[async_trait::async_trait]
impl ciris_edge::blob_swarm::BlobChunkSource for RowScopedSource {
    async fn read_chunk(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        requesting_peer_key_id: &str,
    ) -> Result<Option<Vec<u8>>, ciris_edge::blob_swarm::ChunkSourceRefusal> {
        self.inner
            .read_chunk(blob_sha256, chunk_sha256, requesting_peer_key_id)
            .await
    }

    async fn chunk_scope(&self, blob_sha256: [u8; 32]) -> Option<ContentScope> {
        BlobMeaning::serve_scope(&*self.dir, &blob_sha256).await
    }

    fn answers_scope(&self) -> bool {
        true
    }
}

/// A running node: transport, a scope-native edge, and its replication
/// bridge (the apply door every replicated row takes, the serve every
/// advertised row leaves through).
struct Member {
    node: Node,
    rt: Arc<ReticulumTransport>,
    edge: Arc<Edge>,
    bridge: FederationDirectoryReplicationBridge,
    _stop: tokio::sync::watch::Sender<bool>,
    port: u16,
}

async fn member(
    node: Node,
    id_path: PathBuf,
    bootstrap: &[u16],
    widener: Option<MembershipWidener>,
) -> Member {
    let (rt, port) = transport_for(&node, id_path, bootstrap, false).await;
    let edge = Arc::new(
        Edge::builder()
            .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
            .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
            .queue(node.dir.clone())
            .signer(node.signer.clone())
            .reticulum_transport(Arc::clone(&rt))
            .blob_chunk_source(Arc::new(RowScopedSource {
                inner: ciris_edge::blob_swarm::PersistBlobChunkSource::new(
                    node.store.engine().clone(),
                ),
                dir: node.dir.clone(),
            }))
            .scope_native_addressing(Duration::from_secs(300))
            .config(EdgeConfig {
                hybrid_policy: HybridPolicy::Ed25519Fallback,
                ..EdgeConfig::default()
            })
            .build()
            .expect("build edge"),
    );
    let (stop, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = Arc::clone(&edge);
    tokio::spawn(async move {
        let _ = runner.run(shutdown_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let publish = vec![node.me.clone(), node.identity.clone()];
    let bridge = FederationDirectoryReplicationBridge::with_config(
        node.dir.clone() as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    )
    .with_engine(Some(BridgeEngine(node.store.engine().clone())))
    .with_local_key_id(Some(node.me.clone()))
    .with_self_provider(Some(Arc::new(move || publish.clone())))
    .with_membership_widener(widener)
    .with_metrics(Some(edge.metrics()));
    Member {
        node,
        rt,
        edge,
        bridge,
        _stop: stop,
        port,
    }
}

/// F — a real Reticulum transport node that is in no family: it forwards for
/// P1 and Q1 and runs a bare transport (its whole job is the Reticulum layer).
struct Relay {
    node: Node,
    rt: Arc<ReticulumTransport>,
    _listen: tokio::task::JoinHandle<()>,
}

// ─── the replication planes, carried byte-exact between bridges ───────

/// Every `kind` envelope `from` serves (structural planes: roster, keys) to
/// `to`'s apply door.
async fn carry_plane(from: &Member, to: &Member, kind: EnvelopeKind) -> Vec<ApplyOutcome> {
    let mut out = Vec::new();
    for r in from.bridge.list_envelope_refs(kind).await {
        let bytes = from
            .bridge
            .fetch_envelope_bytes(kind, &r.envelope_hash)
            .await
            .expect("an advertised envelope is fetchable");
        out.push(
            to.bridge
                .apply_envelope_bytes(kind, &bytes, Some(&from.node.me))
                .await,
        );
    }
    out
}

/// One Attestation round `from` → `to`: every row `from`'s bridge advertises
/// TO `to`, fetched through the recipient-aware serve and applied at `to`'s
/// door. Returns `(attestation_id, outcome)` per row carried.
async fn carry_rows(from: &Member, to: &Member) -> Vec<(String, ApplyOutcome)> {
    let mut out = Vec::new();
    for r in from
        .bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(&to.node.me))
        .await
    {
        let Some(bytes) = from
            .bridge
            .fetch_envelope_bytes_for_peer(
                EnvelopeKind::Attestation,
                &r.envelope_hash,
                Some(&to.node.me),
            )
            .await
        else {
            continue;
        };
        let id = serde_json::from_slice::<Attestation>(&bytes)
            .map(|a| a.attestation_id)
            .unwrap_or_default();
        let outcome = to
            .bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some(&from.node.me))
            .await;
        out.push((id, outcome));
    }
    out
}

/// Hand `row` to `to`'s bridge apply door as `from` sent it.
async fn deliver(to: &Member, row: &Attestation, from: &Member) -> ApplyOutcome {
    to.bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(row).expect("wire"),
            Some(&from.node.me),
        )
        .await
}

/// The stored row's content hash — what the advertise index keys on.
async fn envelope_hash_of(node: &Node, attestation_id: &str) -> [u8; 32] {
    let stored = node
        .dir
        .get_attestation(attestation_id)
        .await
        .expect("read")
        .expect("row");
    sha2::Sha256::digest(serde_json::to_vec(&stored).expect("json")).into()
}

/// Does `from`'s bridge advertise the row to `peer`?
async fn offered_to(from: &Member, attestation_id: &str, peer: &str) -> bool {
    let hash = envelope_hash_of(&from.node, attestation_id).await;
    from.bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
        .await
        .iter()
        .any(|r| r.envelope_hash == hash)
}

// ─── the family, formed by consent ─────────────────────────────────────

/// P founds the family ALONE (persist v52 refuses a founding that lists an
/// unsigned member), on P1.
async fn found_family(p1: &Node, p: &Ident) {
    let record = Family {
        dissolved_at: None,
        family_key_id: FAMILY.to_owned(),
        family_name: "The Moores".to_owned(),
        members: vec![FamilyMember {
            key_id: p.key_id.clone(),
            joined_at: ts(),
            role: Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
        }],
        founded_at: ts(),
        consensus_protocol: "founder_only".to_owned(),
        consensus_protocol_entrenched: false,
        persist_row_hash: String::new(),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
    };
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&record.signing_envelope())
        .expect("canonicalize the family");
    let (ed, pqc) = ciris_edge::identity::sign_bound_hybrid(&p.signer(), &canonical, "family")
        .await
        .expect("P signs the founding");
    p1.dir
        .put_family(SignedFamily {
            cosignatures: Vec::new(),
            family: record,
            authority_key_id: p.key_id.clone(),
            scrub_signature_classical: ed,
            scrub_signature_pqc: pqc,
            supersede_proof: None,
        })
        .await
        .expect("P founds the family alone");
}

async fn active_members(node: &Node) -> Vec<String> {
    ciris_edge::family_room::members(&*node.dir, FAMILY)
        .await
        .expect("the family is known here")
}

/// The v52 consent flow, across the bridges, exactly as hosts drive it:
/// P1 proposes Q → Q1's inbox → Q1 accepts for Q → P1 widens on arrival →
/// the widening reaches Q1. R (no device) consents too and is
/// widened in on P1 from R's own signed acceptance.
async fn form_family_by_consent(p1: &Member, q1: &Member, p: &Ident, q: &Ident, r: &Ident) {
    found_family(&p1.node, p).await;

    let expires = chrono::Utc::now() + chrono::Duration::days(7);
    // P1 (a device acting for P, a founder) proposes Q.
    let proposal = membership::propose(
        &*p1.node.dir,
        GroupScope::Family,
        FAMILY,
        &q.key_id,
        None,
        expires,
        &p1.node.signer,
    )
    .await
    .expect("P1 proposes Q");
    // The founding record reaches the INVITEE's node, after the proposal
    // names it (the record the proposal needs to be admitted). A non-family
    // node is handed nothing here: what the record plane may reach before a
    // proposal is its own fix (the v38 record-exposure blocker), and this
    // witness asserts nothing about a non-member's record.
    assert!(
        carry_plane(p1, q1, EnvelopeKind::Family)
            .await
            .iter()
            .all(ApplyOutcome::is_admitted),
        "the founding reaches the invitee's node"
    );
    assert_eq!(
        active_members(&q1.node).await,
        [p.key_id.as_str()],
        "founded by P alone"
    );
    // It reaches Q1 at Q1's apply door. Not through P1's serve: before the
    // widening Q1 is a first-contact stranger to P1 (no consent grant, not a
    // family member's node), and first-contact reach carries no family-scoped
    // row — the #955 invitee arm widens the AUDIENCE, not the send set
    // (persist's `may_receive`, CIRISEdge#761). A host whose persons consented to each
    // other carries it on the round; `pair_room_consent_955` hands it over
    // the same way.
    assert!(
        deliver(q1, &proposal, p1).await.is_admitted(),
        "Q1 admits the proposal naming Q"
    );
    let inbox = membership::pending_proposals_for(&*q1.node.dir, &q.key_id)
        .await
        .expect("Q1's inbox");
    assert_eq!(inbox.len(), 1, "Q1 holds exactly the proposal naming Q");
    assert_eq!(inbox[0].scope, GroupScope::Family);
    assert_eq!(inbox[0].group_key_id, FAMILY);
    let acceptance = membership::reply(
        &*q1.node.dir,
        &inbox[0].proposal.attestation_id,
        true,
        &q1.node.signer,
    )
    .await
    .expect("Q1 accepts for Q");
    // The acceptance reaches P1's apply door (the reply leg, as above);
    // P1's bridge widens on arrival.
    assert!(
        deliver(p1, &acceptance, q1).await.is_admitted(),
        "P1 admits Q's acceptance"
    );
    let mut want = vec![p.key_id.clone(), q.key_id.clone()];
    want.sort();
    assert_eq!(
        active_members(&p1.node).await,
        want,
        "P1 widened Q in on the acceptance"
    );

    // Q's widening reaches Q1 through P1's serve (it lands only where Q's
    // own acceptance is held, persist #955).
    let applied = carry_plane(p1, q1, EnvelopeKind::FamilyMembershipWidening).await;
    assert_eq!(applied.len(), 1, "one widening");
    assert!(applied[0].is_admitted(), "{applied:?}");
    assert_eq!(active_members(&q1.node).await, want, "Q1 reads the roster");

    // R consents too — signing their own acceptance (R has no device; the
    // row reaches P1 as any delivered row does).
    let proposal_r = membership::propose(
        &*p1.node.dir,
        GroupScope::Family,
        FAMILY,
        &r.key_id,
        None,
        expires,
        &p1.node.signer,
    )
    .await
    .expect("P1 proposes R");
    let accept_r = membership::reply_attestation(&proposal_r, true, &r.signer())
        .await
        .expect("R accepts");
    let outcome = p1
        .bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(&accept_r).expect("wire"),
            None,
        )
        .await;
    assert!(outcome.is_admitted(), "R's acceptance: {outcome:?}");
    want.push(r.key_id.clone());
    want.sort();
    assert_eq!(
        active_members(&p1.node).await,
        want,
        "P1 widened R in on the acceptance"
    );

    // R's consent rows reach Q1: the proposal on P1's REAL serve (Q1 is a
    // family member's node now, and P1 authored it); R's acceptance at Q1's
    // door — P1 holds it ABOUT another person, so it is served only to a
    // peer P1 is Rooted with (#659), and this harness roots no one.
    let carried = carry_rows(p1, q1).await;
    assert!(
        carried
            .iter()
            .any(|(c, o)| c == &proposal_r.attestation_id && o.is_admitted()),
        "P1 serves its proposal of R to Q1: {carried:?}"
    );
    assert!(
        deliver(q1, &accept_r, p1).await.is_admitted(),
        "Q1 admits R's acceptance"
    );
    let applied = carry_plane(p1, q1, EnvelopeKind::FamilyMembershipWidening).await;
    assert_eq!(applied.len(), 2, "both widenings offered");
    assert!(
        applied.iter().any(ApplyOutcome::is_admitted),
        "R's widening lands on Q1 once R's acceptance is held: {applied:?}"
    );
    assert_eq!(
        active_members(&q1.node).await,
        want,
        "Q1 reads the full roster"
    );
}

/// The family room's MLS group on P1 and Q1 — created by P1, Q1 added from
/// its KeyPackage and joined from the Welcome — and its addresses installed
/// on both. The group's members are asserted to BE the roster's nodes.
async fn install_family_room(p1: &Member, q1: &Member, roster_nodes: &[String]) {
    let store_for = |tag: &[u8]| {
        ScopeStateProvider::new(Arc::new(
            XChaChaKvStore::open_in_memory(tag).expect("in-memory scope state"),
        ))
    };
    let group_p1 = CohortGroup::create(store_for(b"736-p1"), FAMILY, &p1.node.me, 16)
        .await
        .expect("P1 creates the family room's group");
    let (material, kp) = mint_cohort_key_material(&q1.node.me).expect("Q1's key material");
    let add = group_p1
        .add_member(&q1.node.me, kp)
        .await
        .expect("P1 adds Q1");
    let group_q1 = CohortGroup::join(
        store_for(b"736-q1"),
        FAMILY,
        material,
        add.welcome().expect("welcome"),
        16,
    )
    .await
    .expect("Q1 joins from the Welcome");
    for (m, g) in [(p1, &group_p1), (q1, &group_q1)] {
        let snap = ciris_edge::family_room::snapshot(g, FAMILY)
            .await
            .expect("snapshot");
        let mut members = snap.members.clone();
        members.sort();
        assert_eq!(
            members, roster_nodes,
            "the family room IS the roster's nodes"
        );
        m.edge
            .scope_lifecycle()
            .expect("scope-native addressing is armed")
            .install(&CohortScope::Family, &snap)
            .expect("install the family room's addresses");
    }
}

fn family_scope() -> ContentScope {
    ContentScope::Group {
        scope: CohortScope::Family,
        group_id: ciris_edge::family_room::room(FAMILY).table_group_id(),
    }
}

/// Wait until `from` has rooted `to` AND reads the expected path shape.
async fn wait_for_path(from: &ReticulumTransport, to: &str, want_direct: bool, budget: Duration) {
    use ciris_edge::blob_swarm::ScopedPathShape;
    let deadline = Instant::now() + budget;
    loop {
        let rooted = from.peer_dest_hash_for_test(to).await.is_some();
        let shape = from.scoped_path_shape(to).await;
        let ok = rooted
            && match shape {
                ScopedPathShape::Direct { .. } => want_direct,
                ScopedPathShape::Forwarded { .. } => !want_direct,
                ScopedPathShape::Unknown => false,
            };
        if ok {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "never saw {to} at the expected path shape (want_direct={want_direct}); \
             rooted={rooted}, shape={shape:?}, paths={:?}",
            from.path_table_rows_for_test()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

// ─── the files ─────────────────────────────────────────────────────────

struct File {
    plain: Vec<u8>,
    published: PublishedFile,
    /// The crossed (federation-tier) row every family node receives.
    row: Attestation,
    sha: [u8; 32],
}

async fn publish(p1: &Member, p: &Ident, len: usize, seed: u32, name: &str) -> File {
    let plain = content(len, seed);
    let person = p.signer();
    let published = ciris_edge::files::publish(
        &*p1.node.dir,
        &p1.node.store,
        Signers {
            node: &p1.node.signer,
            actor: Some(&person),
        },
        &ciris_edge::files::FileWrite {
            room: &ciris_edge::family_room::room(FAMILY),
            bytes: &plain,
            media_type: "application/octet-stream",
            codec: None,
            filename: Some(name),
            asserted_at: ts(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("P1 publishes the family file {name}: {e}"));
    assert!(published.crossed, "the family file crosses");
    let crossed_id = match &published.shared {
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            attestation_id.clone()
        }
        other @ Shared::AwaitingActor { .. } => panic!("the family file must cross: {other:?}"),
    };
    let row = p1
        .node
        .dir
        .get_attestation(&crossed_id)
        .await
        .expect("read")
        .expect("the crossed row");
    assert_eq!(row.cohort_scope, "family", "precondition: a family row");
    assert_eq!(
        row.attestation_envelope
            .get("family_key_id")
            .and_then(serde_json::Value::as_str),
        Some(FAMILY),
        "the row names its family"
    );
    assert_eq!(row.attesting_key_id, p.key_id, "the PERSON authors (#675)");
    let sha: [u8; 32] = hex::decode(&published.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    File {
        plain,
        published,
        row,
        sha,
    }
}

/// P1's key_grant sets, applied at Q1's key-grant door — paced as a
/// replication round is.
async fn cross_keys(p1: &Node, q1: &Node) {
    p1.store
        .engine()
        .emit_pending_key_grants()
        .await
        .expect("P1 emits its key_grant sets");
    for set in p1
        .dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list P1's rows")
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
    {
        loop {
            match q1
                .store
                .engine()
                .apply_replicated_key_grant(SignedKeyGrantSet {
                    attestation: set.attestation.clone(),
                })
                .await
            {
                Ok(_) => break,
                Err(e) if e.to_string().contains("rate limited") => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => panic!(
                    "Q1 applies P1's key_grant set {}: {e}",
                    set.attestation.attestation_id
                ),
            }
        }
    }
}

/// Q1's real puller behind Q1's bridge apply door (the server's consent).
fn arm_puller(q1: &mut Member) {
    let (sink, _puller) = BlobPuller::spawn(
        Arc::clone(&q1.edge),
        q1.node.store.engine().clone(),
        q1.node.dir.clone(),
        q1.node.dir.clone() as Arc<dyn FederationDirectory>,
        q1.node.me.clone(),
        PullConfig {
            retry_backoff: Duration::from_millis(300),
            consent: ciris_edge::blob_swarm::OperatorStoreConsent {
                own: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                family: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                community: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                commons: ciris_edge::blob_swarm::ConsentDisposition::Decline,
            },
            ..PullConfig::default()
        },
    );
    let bridge = std::mem::replace(
        &mut q1.bridge,
        FederationDirectoryReplicationBridge::new(
            q1.node.dir.clone() as Arc<dyn FederationDirectory>,
            Arc::new(Vec::new),
        ),
    );
    q1.bridge = bridge.with_pull_sink(Some(sink));
}

/// Wait until Q1 opens `file` whole and byte-identical (the pull ran).
async fn wait_read_back(p1: &Member, q1: &Member, file: &File, what: &str, budget: Duration) {
    let deadline = Instant::now() + budget;
    let want_dag = file.published.pointer.stream_id.is_some();
    loop {
        let head = q1.node.dir.blob_head(&file.sha).await.expect("blob_head");
        let ready = head.as_ref().is_some_and(|h| {
            if want_dag {
                h.storage_kind == "chunk_dag"
            } else {
                true
            }
        });
        if ready {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Q1 never held the {what} (head={head:?}); Q1's pull refusals: {:?}, P1's serve \
             refusals: {:?}, Q1's carriers: {:?}",
            q1.edge.metrics().snapshot().blob_pull_refusals,
            p1.edge.metrics().snapshot().blob_serve_refusals,
            q1.edge.metrics().snapshot().blob_scoped_carriers,
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // The key follows the bytes, in either order (persist I61/I62; CC
    // 5.3.3.4's reconnect-then-pull shape). Through a forwarder the bytes
    // can land a few hundred ms before Q1's key_grant does, so the open is
    // waited for like the bytes were, bounded; a key that never comes still
    // fails here. (On persist v53.1.1's merge commit the immediate open hit
    // `not_granted` in 1 of 3 runs and opened within the wait in 4 of 4.)
    let row = FileRow::from_row(&file.row).expect("a file row");
    let key_wait = Instant::now();
    let got = loop {
        match row.open(&q1.node.store, &q1.node.me).await {
            Ok(bytes) => {
                eprintln!(
                    "family_files_wire_736: Q1 opened the {what} {} ms after holding it",
                    key_wait.elapsed().as_millis()
                );
                break bytes;
            }
            Err(e) => {
                assert!(
                    key_wait.elapsed() < Duration::from_secs(15),
                    "Q1 held the {what} but its key never arrived: {e}"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };
    assert_eq!(
        got.len(),
        file.plain.len(),
        "Q1 reads the {what}, not a manifest"
    );
    assert!(got == file.plain, "Q1's {what} is byte-identical");
}

/// (a) — CC 5.2: nothing on `node` points anyone at either file's bytes.
async fn assert_no_holds_bytes(node: &Node, files: &[&File], who: &str) {
    for f in files {
        assert!(
            node.dir
                .list_holders(&f.sha)
                .await
                .expect("list_holders")
                .is_empty(),
            "{who} lists a holder of a family file — a discovery surface at family (CC 5.2)"
        );
        assert!(
            node.dir
                .list_local_holders(&f.sha)
                .await
                .expect("list_local_holders")
                .is_empty(),
            "{who} holds a holds_bytes claim for a family file (CC 5.2)"
        );
    }
    for r in node
        .dir
        .list_attestations_since(None, 2000)
        .await
        .expect("list")
    {
        if !r.attestation.attestation_type.starts_with("holds_bytes:") {
            continue;
        }
        let text = serde_json::to_string(&r.attestation).expect("json");
        for f in files {
            assert!(
                !text.contains(&hex::encode(f.sha)) && !text.contains(&hex::encode(&f.sha[..8])),
                "{who} holds a holds_bytes row naming a family file: {text}"
            );
        }
    }
}

/// (c)/(d) — `node` holds no row naming the family's files and no byte of
/// them.
async fn assert_holds_nothing_of(node: &Node, files: &[&File], who: &str) {
    for f in files {
        assert!(
            !node.dir.has_blob(&f.sha).await.expect("has_blob"),
            "{who} holds the bytes of a family file"
        );
        assert!(
            node.dir
                .get_attestation(&f.row.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "{who} holds the family file's row"
        );
        assert!(
            node.dir
                .attestations_binding_content(&hex::encode(f.sha))
                .await
                .expect("read")
                .is_empty(),
            "{who} holds a row citing the family file's sha"
        );
        if let Some(stream) = &f.published.pointer.stream_id {
            assert!(
                node.dir
                    .stream_chunks(stream)
                    .await
                    .map_or(true, |l| l.chunks.is_empty()),
                "{who} holds a chunk of the family DAG"
            );
        }
    }
}

// ─── the witnesses ──────────────────────────────────────────────────────

/// **P1 → Q1 direct, with a non-family node N on the mesh**: both files read
/// byte-identical on Q1 through the real replication → sink → puller path;
/// (a) no `holds_bytes` anywhere; (b) the send set is the roster and R is
/// named unresolved; (c) N holds nothing, is offered nothing, is served
/// nothing, by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn family_files_cross_to_the_other_persons_device_and_never_to_a_non_member_736() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = Ident::new("person-p-736", 0x11);
    let p1_id = Ident::new("device-p1-736", 0x12);
    let q = Ident::new("person-q-736", 0x21);
    let q1_id = Ident::new("device-q1-736", 0x22);
    let r = Ident::new("person-r-736", 0x31);
    let n_owner = Ident::new("person-n-736", 0x41);
    let n_id = Ident::new("device-n-736", 0x42);
    let seeds = [&p, &p1_id, &q, &q1_id, &r, &n_owner, &n_id];
    let node_p1 = device(
        &seeds,
        &p,
        &p1_id,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    let node_q1 = device(
        &seeds,
        &q,
        &q1_id,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    let node_n = device(
        &seeds,
        &n_owner,
        &n_id,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    for (a, b) in [
        (&node_p1, &node_q1),
        (&node_q1, &node_p1),
        (&node_p1, &node_n),
        (&node_n, &node_p1),
        (&node_q1, &node_n),
        (&node_n, &node_q1),
    ] {
        federate(a, b).await;
    }

    let p1 = member(
        node_p1,
        tmp.path().join("p1.id"),
        &[],
        Some(MembershipWidener::new(vec![p.signer()])),
    )
    .await;
    let mut q1 = member(node_q1, tmp.path().join("q1.id"), &[p1.port], None).await;
    let n = member(node_n, tmp.path().join("n.id"), &[p1.port], None).await;
    for (a, b) in [(&p1, &q1), (&q1, &p1), (&p1, &n), (&n, &p1)] {
        carry_route(&a.node, &b.node).await;
    }

    form_family_by_consent(&p1, &q1, &p, &q, &r).await;
    let lens = ciris_edge::contact::PersistLens::new(&*p1.node.dir);
    let roster = ciris_edge::family_room::roster(&*p1.node.dir, FAMILY, &lens)
        .await
        .expect("the roster");
    let mut want_nodes = vec![p1.node.me.clone(), q1.node.me.clone()];
    want_nodes.sort();
    assert_eq!(roster.nodes, want_nodes, "the roster's nodes: P1 and Q1");
    assert_eq!(
        roster.unresolved,
        [r.key_id.as_str()],
        "R has no device yet"
    );
    install_family_room(&p1, &q1, &roster.nodes).await;
    arm_puller(&mut q1);

    wait_for_path(&q1.rt, &p1.node.me, true, Duration::from_secs(60)).await;
    wait_for_path(&p1.rt, &q1.node.me, true, Duration::from_secs(60)).await;
    wait_for_path(&n.rt, &p1.node.me, true, Duration::from_secs(60)).await;
    wait_for_path(&p1.rt, &n.node.me, true, Duration::from_secs(60)).await;

    // ── P1 publishes both files in the family room.
    let inline = publish(&p1, &p, INLINE_LEN, 0x0736, "note.bin").await;
    let dag = publish(&p1, &p, DAG_LEN, 0x1736, "video.bin").await;
    assert!(
        inline.published.pointer.stream_id.is_none(),
        "200 KiB is inline"
    );
    assert!(
        dag.published.pointer.stream_id.is_some(),
        "1.3 MiB is a chunk DAG"
    );
    for f in [&inline, &dag] {
        // (b) — the unresolved member is NAMED on the write, not skipped.
        assert_eq!(
            f.published.unresolved,
            [r.key_id.as_str()],
            "the publish names the family member no device of whom it reaches"
        );
        // (c) — the key half: wrapped to the family's devices, never to N.
        assert!(
            f.published.granted.contains(&q1.node.me),
            "Q1's occurrence is granted: {:?}",
            f.published.granted
        );
        assert!(
            !f.published.granted.contains(&n.node.me),
            "N's occurrence holds no grant: {:?}",
            f.published.granted
        );
    }
    cross_keys(&p1.node, &q1.node).await;

    // ── (b)/(c) the send set of each file row is exactly the roster's nodes.
    let not_in_set_before = p1
        .edge
        .metrics()
        .withholds(WithholdReason::RecipientNotInSendSet);
    for f in [&inline, &dag] {
        let mut offered: Vec<String> = Vec::new();
        for peer in [&p1.node.me, &q1.node.me, &n.node.me] {
            if peer != &p1.node.me && offered_to(&p1, &f.row.attestation_id, peer).await {
                offered.push(peer.clone());
            }
        }
        offered.push(p1.node.me.clone());
        offered.sort();
        assert_eq!(
            offered, roster.nodes,
            "the file row's send set is exactly the family roster's nodes"
        );
        // Served by hash? Not to N — the per-record serve gate re-checks.
        let hash = envelope_hash_of(&p1.node, &f.row.attestation_id).await;
        assert!(
            p1.bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hash, Some(&n.node.me))
                .await
                .is_none(),
            "P1 serves the family row to N by hash"
        );
    }
    assert!(
        p1.edge
            .metrics()
            .withholds(WithholdReason::RecipientNotInSendSet)
            > not_in_set_before,
        "P1 booked the withhold from N by name (recipient_not_in_send_set)"
    );

    // ── The rows cross: P1's serve → Q1's apply (the sink starts the pull),
    //    and one round P1 → N, which must carry neither.
    let to_q1 = carry_rows(&p1, &q1).await;
    for f in [&inline, &dag] {
        assert!(
            to_q1
                .iter()
                .any(|(id, o)| id == &f.row.attestation_id && o.is_admitted()),
            "Q1 admits the family file row through its bridge: {to_q1:?}"
        );
    }
    let to_n = carry_rows(&p1, &n).await;
    for f in [&inline, &dag] {
        assert!(
            !to_n.iter().any(|(id, _)| id == &f.row.attestation_id),
            "P1 carried a family file row to N"
        );
    }

    // ── Q1 reads both, byte-identical, through the real pull.
    wait_read_back(&p1, &q1, &inline, "inline file", Duration::from_secs(90)).await;
    wait_read_back(&p1, &q1, &dag, "DAG file", Duration::from_secs(120)).await;
    let sources = q1.edge.metrics().snapshot().blob_pull_sources;
    assert!(
        sources.get("family:author_nodes").copied().unwrap_or(0) >= 2,
        "both pulls asked the author's nodes, never list_holders: {sources:?}"
    );
    assert_eq!(
        sources.get("family:claim_index").copied().unwrap_or(0),
        0,
        "no family pull consulted the claim index: {sources:?}"
    );

    // ── (e) CIRISEdge#763 (CC 6.1.5.3) — durability at the family tier. Q1's
    //    completed pulls filed its `custody:ack:v1` `here` for each file; the
    //    reports cross Q1 → P1 through the real serve gate (persist's
    //    may_receive: the family's audience) and never Q1 → N. On P1,
    //    persist's deficit names the family's audience — the roster's nodes,
    //    N not among them — in Full mode, with Q1 a live full holder.
    for f in [&inline, &dag] {
        let deadline = Instant::now() + Duration::from_secs(30);
        let sha_hex = hex::encode(f.sha);
        loop {
            let here = ciris_persist::federation::custody_ack::device_custody_of(
                &*q1.node.dir,
                &q1.node.me,
                &sha_hex,
                None,
                chrono::Utc::now(),
            )
            .await
            .expect("custody fold")
            .state;
            if here == ciris_persist::federation::custody_ack::CustodyVerdict::Here {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Q1 never filed its `here` for the pulled family file ({here:?})"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    let custody_rows = |carried: &[(String, ApplyOutcome)], node: &Node| {
        let ids: Vec<String> = carried.iter().map(|(id, _)| id.clone()).collect();
        let dir = Arc::clone(&node.dir);
        async move {
            let mut count = 0;
            for id in ids {
                if let Ok(Some(row)) = dir.get_attestation(&id).await {
                    if ciris_persist::federation::admission::envelope_dimension(
                        &row.attestation_envelope,
                    ) == Some(ciris_persist::federation::custody_ack::CUSTODY_ACK_DIMENSION)
                    {
                        count += 1;
                    }
                }
            }
            count
        }
    };
    let to_p1 = carry_rows(&q1, &p1).await;
    assert_eq!(
        custody_rows(&to_p1, &q1.node).await,
        2,
        "both of Q1's custody reports reach P1, a family node: {to_p1:?}"
    );
    let to_n_reports = carry_rows(&q1, &n).await;
    assert_eq!(
        custody_rows(&to_n_reports, &q1.node).await,
        0,
        "no custody report reaches N, outside the family"
    );
    for f in [&inline, &dag] {
        let deficit = ciris_edge::blob_swarm::durability::row_deficit(
            &*p1.node.dir,
            &f.row,
            &f.sha,
            chrono::Utc::now(),
        )
        .await
        .expect("the deficit");
        assert_eq!(
            deficit.audience,
            ciris_persist::federation::durability::DeficitAudience::Nodes(roster.nodes.clone()),
            "the family file's audience is the roster's nodes"
        );
        assert_eq!(
            deficit.mode,
            Some(ciris_persist::federation::durability::DurabilityMode::Full),
            "two nodes < N + K: every audience node a full holder"
        );
        assert!(
            deficit.live_here.contains(&q1.node.me) && !deficit.missing.contains(&q1.node.me),
            "Q1 is a live full holder of the family file: {deficit:?}"
        );
    }

    // ── (c) N asks P1 for each file directly: refused on P1's serve gate
    //    by name; N cannot route the family at all.
    assert!(
        n.edge
            .blob_scope_router()
            .route(Some(&family_scope()), &p1.node.me)
            .is_err(),
        "N derives no family address"
    );
    let arrival_before = p1
        .edge
        .metrics()
        .withholds(WithholdReason::BlobArrivalScopeInsufficient);
    for f in [&inline, &dag] {
        match n
            .edge
            .fetch_blob_chunk(&p1.node.me, f.sha, f.sha, Duration::from_secs(20))
            .await
            .expect("P1 answers N")
        {
            ciris_edge::ChunkResult::ChunkMiss { reason } => assert!(
                reason.contains("PolicyDenied"),
                "a family blob asked for over the federation address is PolicyDenied: {reason}"
            ),
            ciris_edge::ChunkResult::Bytes(_) => {
                panic!("P1 served a family file's bytes to a non-family node")
            }
        }
    }
    assert_eq!(
        p1.edge
            .metrics()
            .withholds(WithholdReason::BlobArrivalScopeInsufficient),
        arrival_before + 2,
        "both refusals are booked blob_serve_arrival_scope_insufficient on P1"
    );
    assert_holds_nothing_of(&n.node, &[&inline, &dag], "N").await;

    // ── (a) delivered, never discovered — on every node.
    for (node, who) in [(&p1.node, "P1"), (&q1.node, "Q1"), (&n.node, "N")] {
        assert_no_holds_bytes(node, &[&inline, &dag], who).await;
    }
}

/// **(d) P1 and Q1 reachable only through a non-member forwarder F**: both
/// files still cross — on the identity-plane link with the family
/// discriminated inside it (#718) — and F holds nothing naming the family.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn family_files_cross_through_a_non_member_forwarder_that_learns_nothing_736() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let p = Ident::new("person-p-736f", 0x11);
    let p1_id = Ident::new("device-p1-736f", 0x12);
    let q = Ident::new("person-q-736f", 0x21);
    let q1_id = Ident::new("device-q1-736f", 0x22);
    let r = Ident::new("person-r-736f", 0x31);
    let f_id = Ident::new("forwarder-736f", 0x51);
    let seeds = [&p, &p1_id, &q, &q1_id, &r];
    let node_p1 = device(
        &seeds,
        &p,
        &p1_id,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    let node_q1 = device(
        &seeds,
        &q,
        &q1_id,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    // F knows only itself: it is in no family and never learns of one.
    let node_f = device(
        &[&f_id],
        &f_id,
        &f_id,
        ciris_persist::federation::types::device_class::SERVER,
    )
    .await;
    federate(&node_p1, &node_q1).await;
    federate(&node_q1, &node_p1).await;

    let (rt_f, port_f) = transport_for(&node_f, tmp.path().join("f.id"), &[], true).await;
    let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel::<InboundFrame>(64);
    let lf = Arc::clone(&rt_f);
    let listen_f = tokio::spawn(async move {
        let _ = lf.listen(relay_tx).await;
    });
    tokio::spawn(async move { while relay_rx.recv().await.is_some() {} });
    let f = Relay {
        node: node_f,
        rt: rt_f,
        _listen: listen_f,
    };

    let p1 = member(
        node_p1,
        tmp.path().join("p1.id"),
        &[port_f],
        Some(MembershipWidener::new(vec![p.signer()])),
    )
    .await;
    let mut q1 = member(node_q1, tmp.path().join("q1.id"), &[port_f], None).await;
    carry_route(&p1.node, &q1.node).await;
    carry_route(&q1.node, &p1.node).await;

    form_family_by_consent(&p1, &q1, &p, &q, &r).await;
    let lens = ciris_edge::contact::PersistLens::new(&*p1.node.dir);
    let roster = ciris_edge::family_room::roster(&*p1.node.dir, FAMILY, &lens)
        .await
        .expect("the roster");
    install_family_room(&p1, &q1, &roster.nodes).await;
    arm_puller(&mut q1);

    wait_for_path(&q1.rt, &p1.node.me, false, Duration::from_secs(60)).await;
    wait_for_path(&p1.rt, &q1.node.me, false, Duration::from_secs(60)).await;

    let inline = publish(&p1, &p, INLINE_LEN, 0x2736, "note.bin").await;
    let dag = publish(&p1, &p, DAG_LEN, 0x3736, "video.bin").await;
    cross_keys(&p1.node, &q1.node).await;
    let (f_fwd_before, f_bytes_before) = f.rt.relay_observation_for_test();
    let to_q1 = carry_rows(&p1, &q1).await;
    for file in [&inline, &dag] {
        assert!(
            to_q1
                .iter()
                .any(|(id, o)| id == &file.row.attestation_id && o.is_admitted()),
            "Q1 admits the family file row: {to_q1:?}"
        );
    }
    wait_read_back(&p1, &q1, &inline, "inline file", Duration::from_secs(150)).await;
    wait_read_back(&p1, &q1, &dag, "DAG file", Duration::from_secs(240)).await;
    let (f_fwd_after, f_bytes_after) = f.rt.relay_observation_for_test();

    // The carrier: the identity-plane link, discriminated inside (#718).
    let q1_carriers = q1.edge.metrics().snapshot().blob_scoped_carriers;
    assert!(
        q1_carriers.get("send:identity_link").copied().unwrap_or(0) >= 2,
        "the fetches rode the identity-plane link: {q1_carriers:?}"
    );
    assert_eq!(
        q1_carriers
            .get("send:derived_address")
            .copied()
            .unwrap_or(0),
        0,
        "no fetch dialled the family's derived address — P1 is only reachable through F: \
         {q1_carriers:?}"
    );
    let p1_carriers = p1.edge.metrics().snapshot().blob_scoped_carriers;
    assert!(
        p1_carriers
            .get("serve:identity_link_admitted")
            .copied()
            .unwrap_or(0)
            >= 2,
        "P1 admitted the in-link discriminator against its own table: {p1_carriers:?}"
    );
    assert!(
        f_bytes_after.saturating_sub(f_bytes_before) >= DAG_LEN as u64
            && f_fwd_after > f_fwd_before,
        "F carried the bodies (positive control on the instrument)"
    );

    // F holds nothing naming the family: path table, scope table, directory,
    // bytes.
    let mut derived: Vec<[u8; 16]> = Vec::new();
    for m in [&p1, &q1] {
        let table =
            m.rt.scope_address_table()
                .expect("the transport owns the table");
        for who in [&p1.node.me, &q1.node.me] {
            if let Some(a) = table.send_address(
                &CohortScope::Family,
                &ciris_edge::family_room::room(FAMILY).table_group_id(),
                who,
            ) {
                derived.push(*a.as_bytes());
            }
        }
    }
    assert!(derived.len() >= 2, "both members' family addresses derived");
    let paths = f.rt.path_table_rows_for_test();
    assert!(
        !paths.is_empty(),
        "F forwards: its path table holds P1's and Q1's destinations"
    );
    for (hash, hops, _) in &paths {
        assert!(
            !derived.contains(hash),
            "F's path table names a family-derived address {} (hops={hops})",
            hex::encode(hash)
        );
    }
    assert!(f.rt.scope_address_table().is_none(), "F has no scope table");
    for row in f
        .node
        .dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list F's rows")
    {
        let text = serde_json::to_string(&row.attestation).expect("json");
        assert!(
            !text.contains(FAMILY),
            "F holds a row naming the family: {text}"
        );
    }
    assert!(
        f.node
            .dir
            .list_families_for_member_active(&p.key_id)
            .await
            .map_or(true, |v| v.is_empty()),
        "F holds the family record"
    );
    assert!(
        FederationDirectory::lookup_public_key(&*f.node.dir, &p1.node.me)
            .await
            .expect("lookup")
            .is_none(),
        "F never holds P1's key — it forwards at the Reticulum layer and nothing else"
    );
    assert_holds_nothing_of(&f.node, &[&inline, &dag], "F").await;

    for (node, who) in [(&p1.node, "P1"), (&q1.node, "Q1"), (&f.node, "F")] {
        assert_no_holds_bytes(node, &[&inline, &dag], who).await;
    }
}
