//! CIRISEdge#718 — **a scoped body rides the identity-plane link when no
//! direct path exists** (CC 5.4.6 at `4fd2e9e`, CIRISConstitution#132, ruled (a)).
//!
//! Three nodes on real Reticulum loopback TCP. **A** and **B** each dial **C**
//! — a transport node (`with_transport_node(true)`) that is NOT a member of
//! the room — and never each other. A and B share a community room whose MLS
//! group both hold and whose scope-derived addresses both installed. A seals
//! a chat body and a small attachment and authors the rows; the key and the
//! holder claims cross by hand (the row/key planes are not what this file is
//! about). B pulls both bodies and opens them.
//!
//! **On main this fails**: B's router resolves A to the room's derived
//! address, `send_to_scoped_destination` broadcasts a link request that only
//! a directly attached neighbour could answer, C has no path to an
//! announce-suppressed address, the dial times out `NoRouteToPeer`, the
//! scheduler retires the one holder and the pull reports
//! `FetchFailed { reason: "... no holders left ..." }`.
//!
//! **After #718** the carrier is chosen once from the path table: A is at
//! two hops via C, so the fetch rides the members' end-to-end encrypted
//! identity-plane link with the room discriminated INSIDE the link
//! (`BlobChunkFetch::scope_discriminator`), A admits it against the same
//! `ScopeAddressTable` its arrival path consults, and the body crosses.
//!
//! Negative controls, each proven from the side that must show it:
//! - **direct-preferred** — with an A–B link present the body crosses the
//!   derived address; C's own interface counters move by less than the body
//!   (C carried no frame of it) and `send:identity_link` stays zero;
//! - **the forwarder holds nothing naming the room** — asserted on C's path
//!   table, C's (absent) scope table and C's directory, not on a log line;
//! - **a forged discriminator is refused by name** — B names its OWN address
//!   (which IS in A's reverse index) and random bytes; A books
//!   `blob_serve_discriminator_unheld` twice and serves nothing.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test scoped_body_identity_link_718`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::blob_swarm::{BlobPuller, ContentScope, PullConfig, PullOutcome};
use ciris_edge::cohort_addressing::{group_id_for, scope_for, snapshot};
use ciris_edge::group_content::{
    BlobPointer, ContentField, GroupContentStore, OpenRequest, PersistGroupContentStore,
    SealRequest,
};
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::{Edge, EdgeConfig, HybridPolicy};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::key_grant::{SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX};
use ciris_persist::federation::{FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use common::build_reticulum_with_retry;

const ROOM: &str = "room-718";
/// The attachment: several link-Channel fragments at the 431 B base MDU
/// (#716) and large enough that C's counters cannot miss it when C carries it.
const ATTACHMENT_LEN: usize = 12_000;

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
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ciris_edge=info")),
        )
        .with_test_writer()
        .try_init();
}

// ─── identities and nodes (the `blob_federation_e2e` shape) ──────────

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
        let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
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
}

/// One node: its own substrate, its own content store, its own engine key.
struct Node {
    dir: Arc<SqliteBackend>,
    store: PersistGroupContentStore,
    identity: String,
    /// The engine's derived signing key — this node's occurrence, the key on
    /// the wire, the viewer key for every read here, and the MEMBER named in
    /// the room's MLS group (holders are nodes).
    me: String,
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

async fn node(idents: &[&Ident], owner: &Ident) -> Node {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open substrate");
    dir.run_migrations().await.expect("migrate");
    for id in idents {
        dir.put_public_key(SignedKeyRecord {
            record: id.record().await,
        })
        .await
        .expect("seed identity");
    }
    let ed_pub = owner.ed.public_key().await.expect("pubkey");
    let derived = ciris_verify_core::fedcode::derive_key_id(owner.ed.current_alias(), &ed_pub);
    let mut rec = owner.record().await;
    rec.key_id = derived.clone();
    rec.identity_ref = derived.clone();
    rec.scrub_key_id = derived.clone();
    rec.identity_type = "node".to_string();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the derived signing key");

    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[owner.seed; 32], owner.ed.current_alias())
            .expect("rebuild the registered signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[owner.seed ^ 0x55; 32],
            format!("{}-pqc", owner.key_id),
        )
        .expect("rebuild the registered pqc half"),
    );
    let identity =
        ciris_edge::identity::LocalSigner::new(derived.clone(), hw.clone(), Some(pqc.clone()));
    let owner_signer = ciris_edge::identity::LocalSigner::new(
        owner.key_id.clone(),
        Arc::clone(&hw),
        Some(Arc::clone(&pqc)),
    );
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        &owner.key_id,
        &derived,
        ts(),
        &owner_signer,
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
        "server",
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

async fn seed_room(node: &Node, room: &str, members: &[&Ident]) {
    use ciris_persist::federation::types::{Community, CommunityMember, SignedCommunity};
    let founder = members[0];
    let community = Community {
        community_key_id: room.to_owned(),
        community_name: "The Room".to_owned(),
        members: members
            .iter()
            .map(|m| CommunityMember {
                key_id: m.key_id.clone(),
                joined_at: ts(),
                role: Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at: ts(),
        consensus_protocol: "founder_only".to_owned(),
        policy_blob: None,
        persist_row_hash: String::new(),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
    };
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
        .expect("canonicalize the room");
    let ed_sig = founder.ed.sign(&canonical).await.expect("ed sign");
    let pqc_sig = {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        ciris_keyring::PqcSigner::sign(&founder.pqc, &bound)
            .await
            .expect("pqc sign")
    };
    // persist v52.0.0 (CIRISPersist#955, Q1) — a founding record admits only
    // the members who signed it: every other listed member co-signs.
    let mut cosignatures = Vec::new();
    for m in &members[1..] {
        let ed = m.ed.sign(&canonical).await.expect("cosign ed");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed);
        let pqc = ciris_keyring::PqcSigner::sign(&m.pqc, &bound)
            .await
            .expect("cosign pqc");
        cosignatures.push(ciris_persist::federation::types::RosterCosignature {
            authority_key_id: m.key_id.clone(),
            scrub_signature_classical: B64.encode(&ed),
            scrub_signature_pqc: Some(B64.encode(&pqc)),
        });
    }
    node.dir
        .put_community(SignedCommunity {
            community,
            authority_key_id: founder.key_id.clone(),
            scrub_signature_classical: B64.encode(&ed_sig),
            scrub_signature_pqc: Some(B64.encode(&pqc_sig)),
            supersede_proof: None,
            cosignatures,
            lineage: Vec::new(),
        })
        .await
        .expect("seed the room");
}

/// The far node's key, owner binding and published occurrence — what the Key
/// / Attestation / IdentityOccurrence planes carry on a real mesh.
async fn federate(from: &Node, to: &Node) {
    let rec = FederationDirectory::lookup_public_key(&*from.dir, &from.me)
        .await
        .expect("lookup")
        .expect("the engine registered its derived key");
    to.dir
        .put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the far node's derived key");
    let rows = FederationDirectory::list_attestations_since(&*from.dir, None, 256)
        .await
        .expect("list the attestation plane");
    for row in rows {
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
    let served = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .expect("list the signed occurrence plane");
    let occ = served
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
        .expect("admit the far node's published occurrence");
}

/// The far node's hybrid-signed reticulum route (`SignedTransportDestination`,
/// the CIRISEdge#406 producer's row, emitted into its own directory when its
/// transport came up) — what the TransportDestination plane carries on a real
/// mesh, and what the #393 item-2 attribution gate reads. Admitted through
/// persist's REAL gate (`put_signed_transport_destination`: hybrid 1-of-1
/// against the key record `to` already holds for `from`), so this is the far
/// node's own re-verification, not trust in the fixture.
async fn carry_route(from: &Node, to: &Node) {
    let rows = FederationDirectory::list_signed_transport_destinations_for(&*from.dir, &from.me)
        .await
        .expect("list the far node's signed routes");
    let row = rows
        .into_iter()
        .find(|r| r.transport_destination.transport_kind == "reticulum")
        .expect("the #406 producer published this node's reticulum route at transport start");
    FederationDirectory::put_signed_transport_destination(&*to.dir, &row)
        .await
        .expect("admit the far node's signed route through persist's gate");
}

/// A community-scoped, federation-tier content row authored by THIS NODE'S
/// key — the chat row's wire shape (`chat::chat_row` on the fields that matter
/// to the pull).
async fn federation_content_row(
    author: &ciris_edge::identity::LocalSigner,
    room: &str,
    pointer: &BlobPointer,
    asserted_at: chrono::DateTime<chrono::Utc>,
) -> ciris_persist::federation::Attestation {
    use ciris_edge::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };
    use sha2::Digest as _;
    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let dimension = ciris_edge::chat::CHAT_MESSAGE_DIMENSION;
    let mut envelope = serde_json::json!({
        "dimension": dimension,
        ciris_edge::chat::FIELD_COMMUNITY_ID: room,
        "score": 1.0,
        ciris_edge::chat::FIELD_CONTENT: pointer,
    });
    let attestation_id = {
        let mut h = sha2::Sha256::new();
        h.update(dimension.as_bytes());
        h.update(room.as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(render_signed_instant(asserted_at).as_bytes());
        h.update(ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon"));
        format!("chat-{}", &hex::encode(h.finalize())[..32])
    };
    let subjects = vec![author_key_id.to_owned()];
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(author, &canonical, dimension)
            .await
            .expect("hybrid sign");
    ciris_persist::federation::Attestation {
        attestation_id,
        attesting_key_id: author_key_id.to_owned(),
        attested_key_id: author_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: ciris_persist::federation::types::cohort_scope::COMMUNITY.to_owned(),
        tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

/// What a scope-native host wires: persist's source for the bytes and a
/// `chunk_scope` answer for the one room this fixture holds.
struct RoomScopedSource {
    inner: ciris_edge::blob_swarm::PersistBlobChunkSource,
    scope: ContentScope,
}
#[async_trait::async_trait]
impl ciris_edge::blob_swarm::BlobChunkSource for RoomScopedSource {
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
    async fn chunk_scope(&self, _blob_sha256: [u8; 32]) -> Option<ContentScope> {
        Some(self.scope.clone())
    }
    fn answers_scope(&self) -> bool {
        true
    }

    // CIRISEdge#771 — a wrapper forwards the Edge's metrics bag to the
    // source it wraps, or the legacy-walk counter never reaches it.
    fn attach_metrics(&self, metrics: ciris_edge::observability::EdgeMetrics) {
        self.inner.attach_metrics(metrics);
    }
}

// ─── the mesh ─────────────────────────────────────────────────────────

fn auth_for(node: &Node) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(Arc::clone(&node.signer)),
        rooting: Some(Arc::clone(&node.dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

struct Member {
    node: Node,
    rt: Arc<ReticulumTransport>,
    edge: Arc<Edge>,
    _stop: tokio::sync::watch::Sender<bool>,
}

/// C — a real Reticulum transport node on the mesh that is NOT in the room:
/// rooted, reachable, forwarding for A and B, and holding nothing that names
/// the room. It runs a bare transport (its whole job is the Reticulum layer).
struct Relay {
    node: Node,
    rt: Arc<ReticulumTransport>,
    _listen: tokio::task::JoinHandle<()>,
}

impl Relay {
    /// What C can say about what it carried: leviculum's `packets_forwarded`
    /// and the bytes its interfaces moved (in + out), from C's own counters.
    fn observation(&self) -> (u64, u64) {
        self.rt.relay_observation_for_test()
    }
}

struct Mesh {
    a: Member,
    b: Member,
    c: Relay,
    _tmp: tempfile::TempDir,
}

async fn spawn_member(node: Node, rt: Arc<ReticulumTransport>) -> Member {
    let edge = Edge::builder()
        .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
        .queue(node.dir.clone())
        .signer(node.signer.clone())
        .reticulum_transport(Arc::clone(&rt))
        .blob_chunk_source(Arc::new(RoomScopedSource {
            inner: ciris_edge::blob_swarm::PersistBlobChunkSource::new(node.store.engine().clone()),
            scope: ContentScope::Group {
                scope: scope_for(ROOM),
                group_id: ROOM.to_owned(),
            },
        }))
        // The transport owns the table and registers the derived addresses
        // as real explicit-hash destinations (announce-suppressed).
        .scope_native_addressing(Duration::from_secs(300))
        .config(EdgeConfig {
            hybrid_policy: HybridPolicy::Ed25519Fallback,
            ..EdgeConfig::default()
        })
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    let (stop, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = Arc::clone(&edge);
    tokio::spawn(async move {
        let _ = runner.run(shutdown_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Member {
        node,
        rt,
        edge,
        _stop: stop,
    }
}

/// Stand the mesh up. A and B dial C; with `direct_ab`, B also dials A (the
/// direct-preferred negative control).
#[allow(clippy::too_many_lines)] // three transports, one room, one group: the topology in one place on purpose
async fn mesh(tag: &str, direct_ab: bool) -> Mesh {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path().to_path_buf();

    let alice = Ident::new(&format!("alice-{tag}"), 0x11);
    let bob = Ident::new(&format!("bob-{tag}"), 0x22);
    let carol = Ident::new(&format!("carol-{tag}"), 0x33);
    let node_a = node(&[&alice, &bob], &alice).await;
    let node_b = node(&[&alice, &bob], &bob).await;
    // C knows only itself. It is not in the room and never learns of it.
    let node_c = node(&[&carol], &carol).await;
    seed_room(&node_a, ROOM, &[&alice, &bob]).await;
    seed_room(&node_b, ROOM, &[&alice, &bob]).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;

    // C first, so A and B have something to dial.
    let (rt_c, addr_c) = build_reticulum_with_retry(|| {
        let base = base.clone();
        let auth = auth_for(&node_c);
        let key = node_c.me.clone();
        async move {
            let mut c =
                ReticulumTransportConfig::new(base.join("c/t.id"), &key).with_transport_node(true);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.announce_interval = Duration::from_secs(10);
            (c, auth)
        }
    })
    .await;
    let port_c = addr_c.port();
    let (rt_a, addr_a) = build_reticulum_with_retry(|| {
        let base = base.clone();
        let auth = auth_for(&node_a);
        let key = node_a.me.clone();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("a/t.id"), &key);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            c.bootstrap_peers = vec![format!("127.0.0.1:{port_c}").parse().unwrap()];
            c.announce_interval = Duration::from_secs(10);
            (c, auth)
        }
    })
    .await;
    let port_a = addr_a.port();
    let (rt_b, _addr_b) = build_reticulum_with_retry(|| {
        let base = base.clone();
        let auth = auth_for(&node_b);
        let key = node_b.me.clone();
        async move {
            let mut c = ReticulumTransportConfig::new(base.join("b/t.id"), &key);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            let mut boots = vec![format!("127.0.0.1:{port_c}").parse().unwrap()];
            if direct_ab {
                boots.push(format!("127.0.0.1:{port_a}").parse().unwrap());
            }
            c.bootstrap_peers = boots;
            c.announce_interval = Duration::from_secs(10);
            (c, auth)
        }
    })
    .await;

    // The TransportDestination plane, by hand: each member's signed route
    // reaches the other (the #393 item-2 gate on the identity-plane link
    // reads it). C gets nothing — it is not a member of anything here.
    carry_route(&node_a, &node_b).await;
    carry_route(&node_b, &node_a).await;

    // C's transport loop.
    let (relay_tx, mut relay_rx) = tokio::sync::mpsc::channel::<InboundFrame>(64);
    let lc = Arc::clone(&rt_c);
    let listen_c = tokio::spawn(async move {
        let _ = lc.listen(relay_tx).await;
    });
    tokio::spawn(async move { while relay_rx.recv().await.is_some() {} });

    // The room's MLS group on each node — the CC 5.4 addressing root. Members
    // are the NODE keys: those are the holders `list_holders` names.
    let store_for = |tag: &[u8]| {
        ScopeStateProvider::new(Arc::new(
            XChaChaKvStore::open_in_memory(tag).expect("in-memory scope state"),
        ))
    };
    let group_a = CohortGroup::create(store_for(b"718-a"), ROOM, &node_a.me, 16)
        .await
        .expect("A creates the room's group");
    let (material_b, kp_b) = mint_cohort_key_material(&node_b.me).expect("B's key material");
    let add = group_a
        .add_member(&node_b.me, kp_b)
        .await
        .expect("A adds B");
    let group_b = CohortGroup::join(
        store_for(b"718-b"),
        ROOM,
        material_b,
        add.welcome().expect("welcome"),
        16,
    )
    .await
    .expect("B joins from the Welcome");

    let a = spawn_member(node_a, rt_a).await;
    let b = spawn_member(node_b, rt_b).await;
    for (member, group) in [(&a, &group_a), (&b, &group_b)] {
        member
            .edge
            .scope_lifecycle()
            .expect("scope-native addressing is armed")
            .install(&scope_for(ROOM), &snapshot(group).await.expect("snapshot"))
            .expect("install the room's addresses");
    }
    // Both members derive the SAME address for A from their own group state.
    assert_eq!(
        a.edge
            .blob_scope_router()
            .route(Some(&room_content()), &a.node.me)
            .expect("A routes itself")
            .scoped_address()
            .map(|m| *m.as_bytes()),
        b.edge
            .blob_scope_router()
            .route(Some(&room_content()), &a.node.me)
            .expect("B routes A")
            .scoped_address()
            .map(|m| *m.as_bytes()),
        "every member derives the same destination (CC 5.4.6)",
    );

    Mesh {
        a,
        b,
        c: Relay {
            node: node_c,
            rt: rt_c,
            _listen: listen_c,
        },
        _tmp: tmp,
    }
}

fn room_content() -> ContentScope {
    ContentScope::Group {
        scope: scope_for(ROOM),
        group_id: ROOM.to_owned(),
    }
}

/// Every derived address A and B hold for the room — what must NEVER appear
/// in anything C retains.
fn derived_addresses(m: &Mesh) -> Vec<[u8; 16]> {
    let mut out = Vec::new();
    for member in [&m.a, &m.b] {
        let table = member
            .rt
            .scope_address_table()
            .expect("the transport owns the table");
        for who in [&m.a.node.me, &m.b.node.me] {
            if let Some(addr) = table.send_address(&scope_for(ROOM), &group_id_for(ROOM), who) {
                out.push(*addr.as_bytes());
            }
        }
    }
    assert!(out.len() >= 2, "both members' addresses derived");
    out
}

/// Wait until `from` has rooted `to` through the announce plane AND the path
/// table reads the expected shape — the two facts the send-side choice is
/// made from (CIRISEdge#718).
async fn wait_for_path(from: &Member, to: &Member, want_direct: bool, budget: Duration) {
    use ciris_edge::blob_swarm::ScopedPathShape;
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        let rooted = from.rt.peer_dest_hash_for_test(&to.node.me).await.is_some();
        let shape = from.rt.scoped_path_shape(&to.node.me).await;
        let ok = rooted
            && match shape {
                ScopedPathShape::Direct { .. } => want_direct,
                ScopedPathShape::Forwarded { .. } => !want_direct,
                ScopedPathShape::Unknown => false,
            };
        if ok {
            tracing::info!(from = %from.node.me, to = %to.node.me, ?shape, "path settled");
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{} never saw {} at the expected path shape (want_direct={want_direct}); rooted={rooted}, \
             shape={shape:?}, paths={:?}",
            from.node.me,
            to.node.me,
            from.rt.path_table_rows_for_test()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A seals `plaintext` for the room, authors the chat row, and hands B the
/// key set and the holder claim by hand (the row/key planes are elsewhere's).
/// Returns the row B pulls with, the sha and the pointer.
async fn author_body(
    m: &Mesh,
    plaintext: &[u8],
    what: &str,
) -> (
    ciris_persist::federation::Attestation,
    [u8; 32],
    BlobPointer,
) {
    let sealed =
        m.a.node
            .store
            .seal(SealRequest {
                cohort_scope: "community",
                community_key_id: Some(ROOM),
                author_key_id: &m.a.node.me,
                asserted_at: ts(),
                field: ContentField::Body,
                plaintext,
                description: Some(ciris_edge::group_content::Description {
                    name: Some(what),
                    format: "application/octet-stream",
                    codec: None,
                }),
            })
            .await
            .expect("seal at the community tier");
    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let row = federation_content_row(&m.a.node.signer, ROOM, &sealed.pointer, ts()).await;
    m.a.node
        .dir
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("A holds the row it authored");
    for set in
        m.a.node
            .dir
            .list_attestations_since(None, 200)
            .await
            .expect("list A's rows")
            .into_iter()
            .filter(|a| {
                a.attestation
                    .attestation_type
                    .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
            })
    {
        m.b.node
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: set.attestation.clone(),
            })
            .await
            .expect("B admits A's key_grant set");
    }
    for row in
        m.a.node
            .dir
            .list_attestations_since(None, 200)
            .await
            .expect("list A's rows")
            .into_iter()
            .filter(|a| a.attestation.attestation_type.starts_with("holds_bytes:"))
    {
        let _ =
            m.b.node
                .dir
                .put_attestation(SignedAttestation {
                    attestation: row.attestation,
                })
                .await;
    }
    (row, sha, sealed.pointer)
}

fn puller(m: &Mesh) -> Arc<BlobPuller<SqliteBackend>> {
    BlobPuller::new(
        Arc::clone(&m.b.edge),
        m.b.node.store.engine().clone(),
        m.b.node.dir.clone(),
        m.b.node.dir.clone() as Arc<dyn FederationDirectory>,
        m.b.node.me.clone(),
        PullConfig::default(),
    )
}

/// B pulls `sha` and opens it; the body must equal `plaintext`.
async fn pull_and_open(
    m: &Mesh,
    puller: &BlobPuller<SqliteBackend>,
    row: &ciris_persist::federation::Attestation,
    sha: [u8; 32],
    pointer: &BlobPointer,
    plaintext: &[u8],
    what: &str,
) {
    assert!(
        !m.b.node.dir.has_blob(&sha).await.expect("has_blob"),
        "precondition: B holds nothing of the {what}"
    );
    let verdict = tokio::time::timeout(Duration::from_secs(150), puller.pull_one(row, sha, 0))
        .await
        .unwrap_or_else(|_| panic!("the {what} pull reached no verdict in 150s"));
    assert!(
        matches!(verdict, PullOutcome::Stored { .. }),
        "the {what} must cross A → B over the ONLY path there is, C's forwarded link \
         (CC 5.4.6 / CIRISConstitution#132, CIRISEdge#718). Got {verdict:?}. \
         B's carriers: {:?}; A's serve refusals: {:?}",
        m.b.edge.metrics().snapshot().blob_scoped_carriers,
        m.a.edge.metrics().snapshot().blob_serve_refusals,
    );
    let got =
        m.b.node
            .store
            .open(OpenRequest {
                pointer,
                author_key_id: &m.a.node.me,
                asserted_at: ts(),
                viewer_key_id: &m.b.node.me,
            })
            .await
            .unwrap_or_else(|e| panic!("B opens the {what} sealed on A: {e:?}"));
    assert_eq!(got, plaintext, "B reads the {what} byte-for-byte");
}

fn attachment() -> Vec<u8> {
    (0..ATTACHMENT_LEN)
        .map(|i| u8::try_from((i * 31 + i / 251) % 251).unwrap())
        .collect()
}

/// C holds nothing that names the room — on C's own tables and directory.
fn assert_relay_holds_nothing_naming_the_room(m: &Mesh, derived: &[[u8; 16]]) {
    let paths = m.c.rt.path_table_rows_for_test();
    for (hash, hops, next_hop) in &paths {
        assert!(
            !derived.contains(hash),
            "C's path table names a derived address {} (hops={hops}, next_hop={next_hop:?}) — \
             a scoped address was announced, path-requested or dialled through the forwarder \
             (CC 5.4.6)",
            hex::encode(hash)
        );
    }
    assert!(
        !paths.is_empty(),
        "positive control on the instrument: C's path table holds A's and B's announced \
         destinations (it forwards for them), so an empty table means C saw nothing at all"
    );
    assert!(
        m.c.rt.scope_address_table().is_none(),
        "C is not in the room: it has no scope address table"
    );
    let all_derived_hex: Vec<String> = derived.iter().map(hex::encode).collect();
    for (hash, _, _) in
        m.a.rt
            .path_table_rows_for_test()
            .iter()
            .chain(m.b.rt.path_table_rows_for_test().iter())
    {
        assert!(
            !all_derived_hex.contains(&hex::encode(hash)),
            "a member's path table names a derived address — one was announced (CC 5.4.6)"
        );
    }
}

/// C's directory never learned of the room.
async fn assert_relay_directory_is_blind(m: &Mesh) {
    let rows =
        m.c.node
            .dir
            .list_attestations_since(None, 512)
            .await
            .expect("list C's rows");
    for r in rows {
        let text = serde_json::to_string(&r.attestation).expect("wire");
        assert!(
            !text.contains(ROOM),
            "C's directory holds a row naming the room: {text}"
        );
    }
    assert!(
        FederationDirectory::lookup_public_key(&*m.c.node.dir, &m.a.node.me)
            .await
            .expect("lookup")
            .is_none(),
        "C never even holds A's key record — it forwards at the Reticulum layer and nothing else"
    );
}

// ─── the witnesses ────────────────────────────────────────────────────

/// **The positive.** A and B each dial C, never each other. The chat body and
/// the attachment cross over C's forwarded identity-plane link, discriminated
/// inside it; C holds nothing naming the room and its counters show it
/// carried the ciphertext.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn forwarded_room_body_rides_the_identity_plane_link_718() {
    let m = mesh("fwd", false).await;
    wait_for_path(&m.b, &m.a, false, Duration::from_secs(60)).await;
    wait_for_path(&m.a, &m.b, false, Duration::from_secs(60)).await;
    let derived = derived_addresses(&m);

    let chat = b"a message for the room, through the canonical".to_vec();
    let file = attachment();
    let (chat_row, chat_sha, chat_ptr) = author_body(&m, &chat, "chat body").await;
    let (file_row, file_sha, file_ptr) = author_body(&m, &file, "attachment").await;

    let (c_fwd_before, c_bytes_before) = m.c.observation();
    let p = puller(&m);
    pull_and_open(&m, &p, &chat_row, chat_sha, &chat_ptr, &chat, "chat body").await;
    pull_and_open(&m, &p, &file_row, file_sha, &file_ptr, &file, "attachment").await;
    let (c_fwd_after, c_bytes_after) = m.c.observation();
    let c_forwarded = c_fwd_after.saturating_sub(c_fwd_before);
    let c_moved = c_bytes_after.saturating_sub(c_bytes_before);

    // ---- #718 post-fix assertions (begin) ----
    let b_carriers = m.b.edge.metrics().snapshot().blob_scoped_carriers;
    assert!(
        b_carriers.get("send:identity_link").copied().unwrap_or(0) >= 2,
        "both fetches rode the identity-plane link: {b_carriers:?}"
    );
    assert_eq!(
        b_carriers.get("send:derived_address").copied().unwrap_or(0),
        0,
        "no fetch dialled the derived address — A is only reachable through C: {b_carriers:?}"
    );
    let a_carriers = m.a.edge.metrics().snapshot().blob_scoped_carriers;
    assert!(
        a_carriers
            .get("serve:identity_link_admitted")
            .copied()
            .unwrap_or(0)
            >= 2,
        "A admitted the in-link discriminator against its own table: {a_carriers:?}"
    );
    assert!(
        m.a.edge.metrics().snapshot().blob_serve_refusals.is_empty(),
        "A refused nothing: {:?}",
        m.a.edge.metrics().snapshot().blob_serve_refusals
    );
    // C carried the ciphertext: the instrument's positive control, so the
    // direct-preferred witness's "C moved less than the body" is a finding.
    assert!(
        c_moved >= ATTACHMENT_LEN as u64 && c_forwarded > 0,
        "C's interfaces moved {c_moved} bytes and it forwarded {c_forwarded} packets during \
         the pulls — less than the attachment; the bodies did not cross through C"
    );
    assert_relay_holds_nothing_naming_the_room(&m, &derived);
    assert_relay_directory_is_blind(&m).await;
    // ---- #718 post-fix assertions (end) ----
}

/// **Direct-preferred.** With an A–B link present (B also dials A), the body
/// crosses the derived address exactly as before, and C — still on the mesh,
/// still a transport node — carries no frame of it: its interface counters
/// move by less than the body while the pulls run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_direct_link_keeps_the_body_on_the_derived_address_718() {
    let m = mesh("direct", true).await;
    wait_for_path(&m.b, &m.a, true, Duration::from_secs(60)).await;
    wait_for_path(&m.a, &m.b, true, Duration::from_secs(60)).await;
    let derived = derived_addresses(&m);

    let file = attachment();
    let (file_row, file_sha, file_ptr) = author_body(&m, &file, "attachment").await;

    let (_, c_bytes_before) = m.c.observation();
    let p = puller(&m);
    pull_and_open(&m, &p, &file_row, file_sha, &file_ptr, &file, "attachment").await;
    let (_, c_bytes_after) = m.c.observation();
    let c_moved = c_bytes_after.saturating_sub(c_bytes_before);

    let b_carriers = m.b.edge.metrics().snapshot().blob_scoped_carriers;
    assert!(
        b_carriers.get("send:derived_address").copied().unwrap_or(0) >= 1,
        "the fetch rode the derived address: {b_carriers:?}"
    );
    assert_eq!(
        b_carriers.get("send:identity_link").copied().unwrap_or(0),
        0,
        "MUST NOT route a scoped body through a forwarder when a direct path is available \
         (CC 5.4.6): {b_carriers:?}"
    );
    let a_carriers = m.a.edge.metrics().snapshot().blob_scoped_carriers;
    assert_eq!(
        a_carriers
            .get("serve:identity_link_admitted")
            .copied()
            .unwrap_or(0),
        0,
        "A admitted no discriminator — the request arrived ON the derived address: {a_carriers:?}"
    );
    // From C's side: announces and a dropped broadcast link request are a few
    // hundred bytes; the body is thousands. C did not carry it.
    assert!(
        c_moved < ATTACHMENT_LEN as u64,
        "C's interfaces moved {c_moved} bytes during a DIRECT pull of a {ATTACHMENT_LEN}-byte \
         body — the body went through the forwarder while a direct path existed"
    );
    assert_relay_holds_nothing_naming_the_room(&m, &derived);
}

/// **A forged discriminator is refused by name.** B names its OWN derived
/// address — which IS in A's reverse index, since the table holds every
/// member's — and then random bytes. A books `blob_serve_discriminator_unheld`
/// for each and serves nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forged_discriminator_is_refused_by_name_718() {
    let m = mesh("forge", false).await;
    wait_for_path(&m.b, &m.a, false, Duration::from_secs(60)).await;
    wait_for_path(&m.a, &m.b, false, Duration::from_secs(60)).await;

    let file = attachment();
    let (_row, sha, _ptr) = author_body(&m, &file, "attachment").await;
    let bobs_own =
        *m.b.rt
            .scope_address_table()
            .expect("table")
            .send_address(&scope_for(ROOM), &group_id_for(ROOM), &m.b.node.me)
            .expect("B's own address")
            .as_bytes();
    assert!(
        m.a.rt
            .scope_address_table()
            .expect("table")
            .accepts_inbound(&bobs_own)
            .is_some(),
        "precondition: A's reverse index DOES hold B's address — the forgery is the sharp one"
    );

    for forged in [bobs_own, [0x5A; 16]] {
        m.b.edge
            .send(
                &m.a.node.me,
                ciris_edge::messages::BlobChunkFetch {
                    blob_sha256: sha,
                    chunk_sha256: sha,
                    response_hint: None,
                    scope_discriminator: Some(forged),
                },
            )
            .await
            .expect("the identity-plane send itself succeeds; the refusal is A's");
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let refusals = m.a.edge.metrics().snapshot().blob_serve_refusals;
        let unheld = refusals
            .get("blob_serve_discriminator_unheld")
            .copied()
            .unwrap_or(0);
        if unheld >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "A never refused the forged discriminators by name — refusals: {refusals:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let a_carriers = m.a.edge.metrics().snapshot().blob_scoped_carriers;
    assert_eq!(
        a_carriers
            .get("serve:identity_link_admitted")
            .copied()
            .unwrap_or(0),
        0,
        "nothing was admitted: {a_carriers:?}"
    );
    assert!(
        !m.b.node.dir.has_blob(&sha).await.expect("has_blob"),
        "B was served nothing on a forged discriminator"
    );
}
