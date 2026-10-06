//! **CIRISEdge#717, field regression on v36.1.0 — a self-room chunk DAG
//! pulls its chunks on the REAL replication path.**
//!
//! CIRISServer's `selffiles` ladder (three peers + canonical, the phone
//! dialling the laptop directly) found every ≥ 1 MiB self file on the second
//! device stored as its 518 / 610 / 9,529-byte MANIFEST: the DAG walk adopted
//! the manifest and never adopted a chunk. The laptop's log names why —
//! `blob chunk source: no community-DEK binding and no referencing row
//! projects a scope for this blob … referencing_rows=0` for every chunk sha,
//! then `BlobChunkFetch WITHHELD on scope admission` (`PolicyDenied` on the
//! wire, 85 `BlobChunkMiss` on the phone). The #739 fetcher asked for each
//! chunk as `(blob = chunk, chunk = chunk)`; the holder's #499 serve gate asks
//! its chunk source for the scope of the request's BLOB, and a production
//! source answers that from a row referencing the blob. A row references the
//! MANIFEST; nothing references a chunk.
//!
//! Every edge DAG witness before this one wired a chunk source whose
//! `chunk_scope` answered ONE fixed scope for every sha (`bigfile_739`'s
//! `SelfRoomSource`: "the self room's scope for every blob this fixture
//! serves"), or drove `pull_dag_with` over a fetcher reading the author's
//! door directly — so the gate the field hit was never asked about a chunk.
//! This witness wires the source the way a host does: [`RowScopedSource`]
//! answers ONLY from a row that references the asked-for blob
//! (`attestations_binding_content` → `BlobMeaning::project` → its scope,
//! CIRISServer `backend.rs` `chunk_scope`'s rule), and `None` otherwise.
//!
//! The path is the field's: the owner (a PERSON) authors the file on device
//! A with A co-signing (`files::publish`, `Signers { actor: Some(person) }`,
//! #675), the crossed `file:v1` row reaches device B through B's replication
//! bridge (the apply door every replicated attestation takes) with the pull
//! sink wired, and B's real puller (sink → `pull_one` → `pull_one_inner` →
//! `pull_dag` → the `self` holder rung → the #739 swarm fetcher over the
//! scope router and B's direct Reticulum link to A) does the rest. Nothing in
//! the test calls `pull_one` or `pull_dag_with`, and nothing copies a byte.
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
use ciris_edge::files::FileRow;
use ciris_edge::group_content::PersistGroupContentStore;
use ciris_edge::replication::{
    ApplyOutcome, BridgeConfig, BridgeEngine, EnvelopeKind, FederationDirectoryReplicationBridge,
    ReplicationDirectory as _,
};
use ciris_edge::scope_lifecycle::ScopeGroupSnapshot;
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::{CohortScope, Edge, EdgeConfig, HybridPolicy};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::key_grant::{SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX};
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use common::build_reticulum_with_retry;
use sha2::Digest as _;

/// Over the inline bound on the SEALED size (#687), so `files::publish`
/// writes a chunk DAG: 1.3 MiB, several 256 KiB chunks — the ladder's
/// `just-over-1MiB` class, with room.
const FILE_LEN: usize = 1_300_000;

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
}

/// One node: its own substrate (on disk, so B can be closed and reopened),
/// its own content store, its own engine key.
struct Node {
    dir: Arc<SqliteBackend>,
    store: PersistGroupContentStore,
    identity: String,
    /// The engine's derived signing key — this node's occurrence, the key on
    /// the wire, the viewer key for every read here, and a MEMBER of the
    /// self room (holders are nodes).
    me: String,
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// A device of `owner`: the node's own signing key is `device`'s, the owner
/// binding is signed by `owner`, the engine occurrence is provisioned under
/// the owner's identity (`blob_federation_e2e::device_of`). `db` is the
/// sqlite path (`":memory:"` for a throwaway); `seed_idents` are the key
/// records every node must hold.
/// `class` is the occurrence's `device_class` (persist v53 S1, CC 3.3.7): the
/// phone adopts the laptop's self DAG only as a personal-class device.
async fn device(
    db: &str,
    seed_idents: &[&Ident],
    owner: &Ident,
    device: &Ident,
    class: &str,
) -> Node {
    let dir = FederationDirectorySqlite::open(db)
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
    let identity =
        ciris_edge::identity::LocalSigner::new(derived.clone(), hw.clone(), Some(pqc.clone()));
    let owner_hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[owner.seed; 32], owner.ed.current_alias())
            .expect("rebuild the owner's signer"),
    );
    let owner_pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[owner.seed ^ 0x55; 32],
            format!("{}-pqc", owner.key_id),
        )
        .expect("rebuild the owner's pqc half"),
    );
    let owner_signer =
        ciris_edge::identity::LocalSigner::new(owner.key_id.clone(), owner_hw, Some(owner_pqc));
    // Idempotent on a reopen: the binding row is already there.
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        &owner.key_id,
        &derived,
        ts(),
        &owner_signer,
    )
    .await
    .expect("build this node's owner binding");
    let _ = dir
        .put_attestation_authored(SignedAttestation {
            attestation: binding,
        })
        .await;

    let store = PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        dir.clone(),
        &identity,
    )
    .await
    .expect("hybrid content store");
    let me = match ciris_edge::content_occurrence::provision_engine_occurrence(
        store.engine(),
        &*dir,
        &owner.key_id,
        class,
    )
    .await
    {
        Ok((me, _)) => me,
        // A reopened store already holds its occurrence.
        Err(_) => store
            .engine()
            .local_derived_key_id()
            .await
            .expect("derive this engine's federation key id"),
    };
    Node {
        dir,
        store,
        identity: owner.key_id.clone(),
        me,
        signer: Arc::new(identity),
    }
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
            let _ = to
                .dir
                .apply_replicated_attestation(SignedAttestation { attestation: att })
                .await;
        }
    }
    let served = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .expect("list the signed occurrence plane");
    if let Some(occ) = served.into_iter().map(|s| s.occurrence).find(|o| {
        o.identity_occurrence.occurrence_key_id == from.me
            && o.identity_occurrence.identity_key_id == from.identity
    }) {
        let _ = to.dir.put_identity_occurrence(occ).await;
    }
}

/// The far node's hybrid-signed reticulum route (the #406 producer's row),
/// admitted through persist's real gate.
async fn carry_route(from: &Node, to: &Node) {
    let rows = FederationDirectory::list_signed_transport_destinations_for(&*from.dir, &from.me)
        .await
        .expect("list the far node's signed routes");
    for row in rows
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
    bootstrap: Option<u16>,
) -> (Arc<ReticulumTransport>, u16) {
    let (rt, addr) = build_reticulum_with_retry(|| {
        let id_path = id_path.clone();
        let auth = auth_for(node);
        let key = node.me.clone();
        async move {
            let mut c = ReticulumTransportConfig::new(id_path, &key);
            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
            if let Some(port) = bootstrap {
                c.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
            }
            c.announce_interval = Duration::from_secs(10);
            (c, auth)
        }
    })
    .await;
    (rt, addr.port())
}

/// **The chunk source a scope-native HOST wires** — the scope of a blob is
/// the scope a row REFERENCING it projects, and nothing else: CIRISServer's
/// `backend.rs` `chunk_scope` rule for a tier with no community-DEK binding
/// (self, family, plaintext), spelled here by shape. `None` when no row
/// references the asked-for sha — which is every chunk of a DAG, since rows
/// reference the manifest. This is the source the field ran and every
/// earlier DAG witness did not.
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
        let rows = self
            .dir
            .attestations_binding_content(&hex::encode(blob_sha256))
            .await
            .ok()?;
        rows.iter()
            .find_map(|row| BlobMeaning::project(row, &blob_sha256).ok())
            .map(|m| m.scope().clone())
    }

    fn answers_scope(&self) -> bool {
        true
    }
}

struct Member {
    node: Node,
    rt: Arc<ReticulumTransport>,
    edge: Arc<Edge>,
    _stop: tokio::sync::watch::Sender<bool>,
    port: u16,
}

/// A running member: transport, edge (scope-native, [`RowScopedSource`]),
/// and the self room's addresses installed with both devices as members.
async fn member(
    node: Node,
    id_path: PathBuf,
    bootstrap: Option<u16>,
    members: &[String],
) -> Member {
    let (rt, port) = transport_for(&node, id_path, bootstrap).await;
    let owner = node.identity.clone();
    let edge = Edge::builder()
        .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
        .queue(node.dir.clone())
        .signer(node.signer.clone())
        .reticulum_transport(Arc::clone(&rt))
        .blob_chunk_source(Arc::new(RowScopedSource {
            inner: ciris_edge::blob_swarm::PersistBlobChunkSource::new(node.store.engine().clone()),
            dir: node.dir.clone(),
        }))
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
    edge.scope_lifecycle()
        .expect("scope-native addressing is armed")
        .install(
            &CohortScope::SelfOnly,
            &ScopeGroupSnapshot {
                group_id: ciris_edge::self_room::room(&owner).table_group_id(),
                epoch: 1,
                members: members.to_vec(),
                destination_secret: [0x77; 32],
            },
        )
        .expect("install the self room's addresses");
    Member {
        node,
        rt,
        edge,
        _stop: stop,
        port,
    }
}

/// Wait until `from` has rooted `to` AND sees it one hop away.
async fn wait_direct(from: &Member, to: &Member, budget: Duration) {
    use ciris_edge::blob_swarm::ScopedPathShape;
    let deadline = Instant::now() + budget;
    loop {
        let rooted = from.rt.peer_dest_hash_for_test(&to.node.me).await.is_some();
        let direct = matches!(
            from.rt.scoped_path_shape(&to.node.me).await,
            ScopedPathShape::Direct { .. }
        );
        if rooted && direct {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} never saw {} direct (rooted={rooted}); paths={:?}",
            from.node.me,
            to.node.me,
            from.rt.path_table_rows_for_test()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// The person's own signer (the file's AUTHOR, #675) — the node co-signs.
fn person_signer(owner: &Ident) -> ciris_edge::identity::LocalSigner {
    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[owner.seed; 32], owner.ed.current_alias())
            .expect("rebuild the person's signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[owner.seed ^ 0x55; 32],
            format!("{}-pqc", owner.key_id),
        )
        .expect("rebuild the person's pqc half"),
    );
    ciris_edge::identity::LocalSigner::new(owner.key_id.clone(), hw, Some(pqc))
}

/// Every `key_grant` set A holds — what A's Attestation plane carries.
async fn key_grants_of(a: &Node) -> Vec<Attestation> {
    let mut grants: Vec<Attestation> = Vec::new();
    let mut after = None;
    loop {
        let page = a
            .dir
            .list_attestations_since(after, 1000)
            .await
            .expect("list A's rows");
        if page.is_empty() {
            break;
        }
        after = page
            .last()
            .map(|r| (r.admitted_at, r.attestation.attestation_id.clone()));
        let n = page.len();
        for r in page {
            if r.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
                && !grants
                    .iter()
                    .any(|g| g.attestation_id == r.attestation.attestation_id)
            {
                grants.push(r.attestation);
            }
        }
        if n < 1000 {
            break;
        }
    }
    grants
}

/// **The field path, end to end.** A person's file over the inline bound,
/// published on their laptop (A), replicated to their phone (B) through B's
/// replication bridge with the pull sink wired; B's real puller fetches the
/// manifest AND every chunk from A over Reticulum through A's scope-native
/// serve gate, whose chunk source answers only from a referencing row. B
/// then holds the file as `chunk_dag` and reads it byte-identical, whole
/// and chunk by chunk.
///
/// **On v36.1.0 this fails** at the `chunk_dag` wait: the manifest is
/// adopted `inline`, every chunk request is withheld on A
/// (`blob_serve_scope_undeterminable`), and B's `FileRow::open` reads the
/// manifest's JSON — the field's 518 / 610 / 9,529 bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_self_files_chunks_arrive_on_the_owners_other_device_through_the_real_pull_717() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let alice = Ident::new("alice-717", 0x11);
    let laptop = Ident::new("alice-laptop-717", 0x12);
    let phone = Ident::new("alice-phone-717", 0x13);
    let seeds = [&alice, &laptop, &phone];
    let node_a = device(
        ":memory:",
        &seeds,
        &alice,
        &laptop,
        ciris_persist::federation::types::device_class::LAPTOP,
    )
    .await;
    let node_b = device(
        ":memory:",
        &seeds,
        &alice,
        &phone,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    // The Key / owner-binding / occurrence planes, both ways — BEFORE A
    // publishes: the self room's key_grant sets wrap to the owner's
    // occurrences A holds at seal time.
    federate(&node_a, &node_b).await;
    federate(&node_b, &node_a).await;
    let members = vec![node_a.me.clone(), node_b.me.clone()];

    let a = member(node_a, tmp.path().join("a.id"), None, &members).await;
    let b = member(node_b, tmp.path().join("b.id"), Some(a.port), &members).await;
    carry_route(&a.node, &b.node).await;
    carry_route(&b.node, &a.node).await;
    wait_direct(&b, &a, Duration::from_secs(60)).await;
    wait_direct(&a, &b, Duration::from_secs(60)).await;

    // ── A: the person authors, the node co-signs (#675), as the server does.
    let plain = content(FILE_LEN, 0x0717);
    let room = ciris_edge::self_room::room(&alice.key_id);
    let person = person_signer(&alice);
    let published = ciris_edge::files::publish(
        &*a.node.dir,
        &a.node.store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &a.node.signer,
            actor: Some(&person),
        },
        &ciris_edge::files::FileWrite {
            room: &room,
            bytes: &plain,
            media_type: "video/mp4",
            codec: None,
            filename: Some("just-over-1MiB.mp4"),
            asserted_at: ts(),
        },
    )
    .await
    .expect("publish the self file");
    assert!(published.crossed, "the self file must cross");
    let stream_id = published
        .pointer
        .stream_id
        .clone()
        .expect("precondition: over the inline bound, the file is a chunk DAG");
    let sha: [u8; 32] = hex::decode(&published.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let crossed_id = match &published.shared {
        ciris_edge::replication::attestation_bind::Shared::Placed { attestation_id }
        | ciris_edge::replication::attestation_bind::Shared::AlreadyThere { attestation_id } => {
            attestation_id.clone()
        }
        other @ ciris_edge::replication::attestation_bind::Shared::AwaitingActor { .. } => {
            panic!("the self file must cross: {other:?}")
        }
    };
    let row = a
        .node
        .dir
        .get_attestation(&crossed_id)
        .await
        .expect("read")
        .expect("the crossed row");
    assert_eq!(
        row.attesting_key_id, alice.key_id,
        "precondition: the PERSON authors the file (#675), as on the field"
    );
    a.node
        .store
        .engine()
        .emit_pending_key_grants()
        .await
        .expect("A emits its key_grant sets");
    let grants = key_grants_of(&a.node).await;
    assert!(
        !grants.is_empty(),
        "precondition: A wrapped the file's keys"
    );

    // ── B: the real puller behind the real apply door.
    let (sink, _puller) = BlobPuller::spawn(
        Arc::clone(&b.edge),
        b.node.store.engine().clone(),
        b.node.dir.clone(),
        b.node.dir.clone() as Arc<dyn FederationDirectory>,
        b.node.me.clone(),
        PullConfig {
            retry_backoff: Duration::from_millis(300),
            // The server's consent (CIRISServer `backend.rs`).
            consent: ciris_edge::blob_swarm::OperatorStoreConsent {
                own: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                family: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                community: ciris_edge::blob_swarm::ConsentDisposition::Announce,
                commons: ciris_edge::blob_swarm::ConsentDisposition::Decline,
            },
            ..PullConfig::default()
        },
    );
    let bridge = FederationDirectoryReplicationBridge::with_config(
        b.node.dir.clone() as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    )
    .with_engine(Some(BridgeEngine(b.node.store.engine().clone())))
    .with_pull_sink(Some(sink))
    .with_local_key_id(Some(b.node.me.clone()));

    // The key plane: A's key_grant sets, paced as a replication round is.
    for g in &grants {
        loop {
            match b
                .node
                .store
                .engine()
                .apply_replicated_key_grant(SignedKeyGrantSet {
                    attestation: g.clone(),
                })
                .await
            {
                Ok(_) => break,
                Err(e) if e.to_string().contains("rate limited") => {
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
                Err(e) => panic!("B applies A's key_grant set {}: {e}", g.attestation_id),
            }
        }
    }
    assert!(
        !b.node.dir.has_blob(&sha).await.expect("has_blob"),
        "precondition: B holds nothing of the file"
    );

    // ── The ROW crosses through B's bridge — the last thing handed over.
    let outcome = bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(&row).expect("wire"),
            None,
        )
        .await;
    assert_eq!(outcome, ApplyOutcome::Admitted, "B admits the file row");

    // ── The pull: nothing else moves a byte.
    let deadline = Instant::now() + Duration::from_secs(90);
    let head = loop {
        let head = b.node.dir.blob_head(&sha).await.expect("blob_head");
        if head.as_ref().is_some_and(|h| h.storage_kind == "chunk_dag") {
            break head.expect("held");
        }
        if Instant::now() >= deadline {
            let chunks = b
                .node
                .dir
                .stream_chunks(&stream_id)
                .await
                .map_or(0, |l| l.chunks.len());
            panic!(
                "B never held the file as a chunk DAG (CIRISEdge#717, field regression): \
                 head={head:?}, chunks adopted={chunks}. A manifest held `inline` with no \
                 chunks is the field's shape — the chunk requests were withheld on A's \
                 scope gate because they named the CHUNK as their blob, and no row \
                 references a chunk"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        head.crypto_tier,
        ciris_persist::federation::types::cohort_scope::CryptoTier::InvisibleEncrypted,
        "the self file is held sealed"
    );

    // ── Read back on B, whole and chunk by chunk, byte-identical.
    let file = FileRow::from_row(&row).expect("a file row");
    let whole = file
        .open(&b.node.store, &b.node.me)
        .await
        .expect("B opens the file whole");
    assert_eq!(
        whole.len(),
        FILE_LEN,
        "B reads the FILE, not its manifest ({} bytes)",
        whole.len()
    );
    assert!(whole == plain, "B's whole read is byte-identical");
    let mut walked = Vec::with_capacity(FILE_LEN);
    let mut items = 0usize;
    let mut chunks = file.chunks(&b.node.store, &b.node.me);
    while let Some(item) = chunks.next().await {
        walked.extend_from_slice(&item.expect("each chunk opens"));
        items += 1;
    }
    assert!(items > 1, "a DAG reads as more than one chunk ({items})");
    assert_eq!(
        sha2::Sha256::digest(&walked).as_slice(),
        sha2::Sha256::digest(&plain).as_slice(),
        "B's chunk walk is byte-identical"
    );

    // ── B can serve what it pulled: its copy of the stream carries the same
    // cohort and community as the row naming it, so a second hop's
    // membership check (`chunk_in_named_dag`) reads B's chunks as the DAG's.
    let b_stream = b
        .node
        .dir
        .stream_chunks(&stream_id)
        .await
        .expect("B's stream listing");
    if let Some(head) = &b_stream.stream {
        assert_eq!(head.cohort_scope, row.cohort_scope, "B's stream cohort");
        if let Some(c) = &head.community_key_id {
            assert_eq!(
                c, &published.pointer.community_key_id,
                "B's stream community agrees with the pointer"
            );
        }
    }

    chunk_membership_is_the_named_dags(&a, &b, &alice, &row, sha, &stream_id).await;
    withdrawn_dag_is_refused_and_evicted_at_the_holder_771(&a, &b, &alice, &row, sha, &stream_id)
        .await;
}

/// **CIRISEdge#717 review — the widening this fix introduced, closed.**
///
/// Naming the DAG as the `blob` of a chunk request moved the scope gate onto
/// the NAMED file. Without a bound on the chunk, a requester entitled to file
/// X could name X and ask for a chunk of file Y by its sha. A's serve door
/// now serves `(dag, chunk)` only when `chunk` is one of that DAG's chunks
/// in A's store; otherwise it refuses `chunk_not_in_named_dag` (booked in
/// the withhold ledger and `blob_serve_refusals`, `PolicyDenied` on the
/// wire). Y here is a second file of the same owner, so the requester IS
/// entitled to both — the refusal is the membership bound alone, not the
/// scope gate, which is exactly the check a cross-room Y would have to pass.
///
/// The controls: `(X, x_chunk)` and `(Y, y_chunk)` are served, and `(X, X)`
/// — a DAG's root, the whole-blob shape — is served exactly as before.
async fn chunk_membership_is_the_named_dags(
    a: &Member,
    b: &Member,
    owner: &Ident,
    row_x: &Attestation,
    x: [u8; 32],
    x_stream: &str,
) {
    let plain_y = content(FILE_LEN, 0x0718);
    let room = ciris_edge::self_room::room(&owner.key_id);
    let person = person_signer(owner);
    let y = ciris_edge::files::publish(
        &*a.node.dir,
        &a.node.store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &a.node.signer,
            actor: Some(&person),
        },
        &ciris_edge::files::FileWrite {
            room: &room,
            bytes: &plain_y,
            media_type: "video/mp4",
            codec: None,
            filename: Some("another.mp4"),
            asserted_at: ts(),
        },
    )
    .await
    .expect("publish file Y");
    let y_sha: [u8; 32] = hex::decode(&y.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let y_stream = y.pointer.stream_id.clone().expect("Y is a chunk DAG");
    let first_chunk = |listing: ciris_persist::federation::StreamChunks| {
        listing
            .chunks
            .first()
            .map(|c| c.chunk_sha)
            .expect("a DAG has chunks")
    };
    let x_chunk = first_chunk(
        a.node
            .dir
            .stream_chunks(x_stream)
            .await
            .expect("X's stream"),
    );
    let y_chunk = first_chunk(
        a.node
            .dir
            .stream_chunks(&y_stream)
            .await
            .expect("Y's stream"),
    );
    assert_ne!(x_chunk, y_chunk, "precondition: two files, two chunk sets");
    assert_eq!(row_x.cohort_scope, "self", "precondition: X is a self file");

    let scope = ContentScope::Group {
        scope: CohortScope::SelfOnly,
        group_id: ciris_edge::self_room::room(&owner.key_id).table_group_id(),
    };
    let to_a = b
        .edge
        .blob_scope_router()
        .route(Some(&scope), &a.node.me)
        .expect("B routes to A on the self room's address");
    let ask = |blob: [u8; 32], chunk: [u8; 32]| {
        let edge = Arc::clone(&b.edge);
        let to_a = to_a.clone();
        async move {
            edge.fetch_blob_chunk_scoped(&to_a, blob, chunk, Duration::from_secs(15))
                .await
                .expect("A answers")
        }
    };
    let served = |r: &ciris_edge::ChunkResult, want: [u8; 32]| match r {
        ciris_edge::ChunkResult::Bytes(bytes) => {
            let got: [u8; 32] = sha2::Sha256::digest(bytes).into();
            got == want
        }
        ciris_edge::ChunkResult::ChunkMiss { .. } => false,
    };
    let withheld = || {
        a.edge
            .metrics()
            .withholds(ciris_edge::observability::WithholdReason::ChunkNotInNamedDag)
    };
    let before = withheld();

    // The attack: name X (entitled), ask for Y's chunk.
    let cross = ask(x, y_chunk).await;
    match &cross {
        ciris_edge::ChunkResult::ChunkMiss { reason } => assert!(
            reason.contains("PolicyDenied"),
            "a chunk outside the named DAG is PolicyDenied on the wire, got {reason}"
        ),
        ciris_edge::ChunkResult::Bytes(_) => panic!(
            "A served Y's chunk under a request naming X — the scope gate judged X, \
             so this is content the gate never judged (CIRISEdge#717 review)"
        ),
    }
    assert_eq!(
        withheld(),
        before + 1,
        "the refusal is booked chunk_not_in_named_dag on A"
    );

    // The controls.
    assert!(
        served(&ask(x, x_chunk).await, x_chunk),
        "(X, X's chunk) is served"
    );
    assert!(
        served(&ask(y_sha, y_chunk).await, y_chunk),
        "(Y, Y's chunk) is served"
    );
    assert!(
        served(&ask(x, x).await, x),
        "(X, X) — the DAG's root, the whole-blob shape — is served as before"
    );
    assert_eq!(withheld(), before + 1, "no control was refused");

    // ── The same refusal on a WARM door: the controls above served X's and
    // Y's chunks through it. Since CIRISEdge#771 the bound is persist's
    // chunk→manifest link (no per-file set is held), and a door that has
    // served answers exactly as a fresh one.
    let cross_warm = ask(x, y_chunk).await;
    assert!(
        matches!(&cross_warm, ciris_edge::ChunkResult::ChunkMiss { reason } if reason.contains("PolicyDenied")),
        "after serving X, Y's chunk named under X is still refused (CIRISEdge#771): \
         {cross_warm:?}"
    );
    assert_eq!(
        withheld(),
        before + 2,
        "booked chunk_not_in_named_dag again"
    );
    assert!(
        served(&ask(x, x_chunk).await, x_chunk),
        "(X, X's chunk) is served again"
    );

    a_forged_pointer_widens_no_dag_771(a, owner, row_x, x, &y_stream, y_chunk).await;
    withdrawn_files_chunks_stop_being_served_766(a, b, &person, (x, x_chunk), &y, y_chunk).await;
}

/// **CIRISEdge#766 / #771 — a door that has served a file stops serving it
/// at the file's withdrawal, armed or not, warm or cold.**
///
/// A serve door armed with the revocation register (as production wires it,
/// `replication::runtime`) serves Y's chunk, and then Y's author withdraws Y
/// (`files::withdraw`, the drive's delete). The register takes the
/// withdrawal through the same two calls the bridge makes ([`observe`] /
/// [`apply_observation`], with the evictor): the next request for Y's chunk
/// is refused `Withdrawn`. A door that is NOT armed reads no register; since
/// CIRISEdge#771 it refuses `Withdrawn` too (the named DAG's own fold, then
/// persist's link), and a door that served Y before (warm) answers exactly
/// what a fresh door (cold) answers. X, untouched, is still served.
///
/// [`observe`]: ciris_edge::blob_swarm::revocation::observe
/// [`apply_observation`]: ciris_edge::blob_swarm::revocation::apply_observation
async fn withdrawn_files_chunks_stop_being_served_766(
    a: &Member,
    b: &Member,
    person: &ciris_edge::identity::LocalSigner,
    (x, x_chunk): ([u8; 32], [u8; 32]),
    y: &ciris_edge::files::PublishedFile,
    y_chunk: [u8; 32],
) {
    use ciris_edge::blob_swarm::revocation::{apply_observation, observe};
    use ciris_edge::blob_swarm::{
        BlobChunkSource as _, BlobEvictor, BytesVerdict, ChunkSourceRefusal,
        PersistBlobChunkSource, RevocationRegister,
    };
    let y_sha: [u8; 32] = hex::decode(&y.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let register = Arc::new(RevocationRegister::default());
    let armed = PersistBlobChunkSource::new(a.node.store.engine().clone())
        .with_revocations(Some(Arc::clone(&register)));
    // The same door, unarmed: what a stale set could serve if the register
    // were not wired.
    let unarmed = PersistBlobChunkSource::new(a.node.store.engine().clone());
    let evictor: &dyn BlobEvictor = a.node.store.engine();
    // A holds Y's row; the register indexes it as the bridge would.
    assert!(
        apply_observation(
            &register,
            &*a.node.dir,
            Some(evictor),
            observe(&y.row).expect("a file row carries a pointer"),
        )
        .await
        .is_empty(),
        "indexing Y's row evicts nothing"
    );
    assert_eq!(register.verdict(&y_sha), BytesVerdict::Live);

    let peer = &b.node.me;
    for door in [&armed, &unarmed] {
        assert!(
            matches!(door.read_chunk(y_sha, y_chunk, peer).await, Ok(Some(ref bytes))
                if <[u8; 32]>::from(sha2::Sha256::digest(bytes)) == y_chunk),
            "precondition: (Y, Y's chunk) is served"
        );
        assert!(
            matches!(door.read_chunk(x, x_chunk, peer).await, Ok(Some(_))),
            "precondition: (X, X's chunk) is served"
        );
        assert!(
            matches!(
                door.read_chunk(x, y_chunk, peer).await,
                Err(ChunkSourceRefusal::ChunkNotInNamedDag)
            ),
            "persist's link bounds the chunk: Y's chunk under X is refused (CIRISEdge#771)"
        );
    }

    // ── Y's author withdraws Y; the holder's register takes it.
    let withdraws = ciris_edge::files::withdraw(
        &*a.node.dir,
        &y.row,
        "deleted from the drive",
        ts(),
        ciris_edge::replication::attestation_bind::Signers {
            node: &a.node.signer,
            actor: Some(person),
        },
    )
    .await
    .expect("Y's author withdraws Y");
    let evicted = apply_observation(
        &register,
        &*a.node.dir,
        Some(evictor),
        observe(&withdraws).expect("a withdraws is observed"),
    )
    .await;
    assert_eq!(
        evicted,
        vec![y_sha],
        "every reference to Y withdrawn: Y is evicted"
    );
    assert_eq!(register.verdict(&y_sha), BytesVerdict::Revoked);

    assert!(
        matches!(
            armed.read_chunk(y_sha, y_chunk, peer).await,
            Err(ChunkSourceRefusal::Withdrawn)
        ),
        "after the withdrawal Y's chunk is refused Withdrawn on the armed door \
         (CIRISEdge#766)"
    );
    // An UNARMED door reads no register: it answers from persist (the named
    // DAG's fold, the link), and a door that served Y before answers exactly
    // what a fresh door answers.
    let cold = PersistBlobChunkSource::new(a.node.store.engine().clone());
    let shape = |r: &Result<Option<Vec<u8>>, ChunkSourceRefusal>| match r {
        Ok(Some(_)) => "bytes".to_owned(),
        Ok(None) => "not held".to_owned(),
        Err(refusal) => format!("{refusal:?}"),
    };
    let warm_answer = shape(&unarmed.read_chunk(y_sha, y_chunk, peer).await);
    let cold_answer = shape(&cold.read_chunk(y_sha, y_chunk, peer).await);
    eprintln!("CIRISEdge#771 unarmed door after Y's withdrawal: warm -> {warm_answer}, cold -> {cold_answer}");
    assert_eq!(
        (warm_answer.as_str(), cold_answer.as_str()),
        ("Withdrawn", "Withdrawn"),
        "the unarmed door refuses a withdrawn file's chunk Withdrawn, warm and cold \
         (CIRISEdge#771)"
    );
    assert!(
        matches!(
            unarmed.read_chunk(x, y_chunk, peer).await,
            Err(ChunkSourceRefusal::ChunkNotInNamedDag)
        ),
        "and Y's chunk under X is still refused on the unarmed door"
    );
    assert!(
        matches!(armed.read_chunk(x, x_chunk, peer).await, Ok(Some(_))),
        "X, untouched, is still served"
    );
}

/// A self file of `owner` published on `m`, and the CROSSED row (the
/// federation-tier copy every holder receives) beside the authored one.
async fn publish_on(
    m: &Member,
    owner: &Ident,
    seed: u32,
    name: &str,
) -> (ciris_edge::files::PublishedFile, Attestation) {
    let person = person_signer(owner);
    let published = ciris_edge::files::publish(
        &*m.node.dir,
        &m.node.store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &m.node.signer,
            actor: Some(&person),
        },
        &ciris_edge::files::FileWrite {
            room: &ciris_edge::self_room::room(&owner.key_id),
            bytes: &content(FILE_LEN, seed),
            media_type: "video/mp4",
            codec: None,
            filename: Some(name),
            asserted_at: ts(),
        },
    )
    .await
    .unwrap_or_else(|e| panic!("publish {name}: {e}"));
    assert!(
        published.pointer.stream_id.is_some(),
        "precondition: {name} is a chunk DAG"
    );
    let crossed_id = match &published.shared {
        ciris_edge::replication::attestation_bind::Shared::Placed { attestation_id }
        | ciris_edge::replication::attestation_bind::Shared::AlreadyThere { attestation_id } => {
            attestation_id.clone()
        }
        other @ ciris_edge::replication::attestation_bind::Shared::AwaitingActor { .. } => {
            panic!("{name} must cross: {other:?}")
        }
    };
    let crossed = m
        .node
        .dir
        .get_attestation(&crossed_id)
        .await
        .expect("read")
        .expect("the crossed row");
    (published, crossed)
}

fn sha_of(pointer: &ciris_edge::group_content::BlobPointer) -> [u8; 32] {
    hex::decode(&pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes")
}

/// Persist's own fold of `sha` on `node` — the state the witnesses assert on.
async fn fold_of(
    node: &Node,
    sha: &[u8; 32],
) -> ciris_persist::federation::blob_tombstone::BindingState {
    ciris_persist::federation::blob_tombstone::binding_state(&*node.dir, sha)
        .await
        .expect("binding_state")
}

fn is_withdrawn(s: &ciris_persist::federation::blob_tombstone::BindingState) -> bool {
    matches!(
        s,
        ciris_persist::federation::blob_tombstone::BindingState::Withdrawn { .. }
    )
}

/// The persist V176 relation, edited through the node's own SQLite writer —
/// the shapes two real seals never produce on a v53.1 node: a manifest with
/// NO relation (sealed or pulled before persist v53.1.0, persist I486), and a
/// chunk two DAGs hold (persist I484).
fn drop_dag_link(node: &Node, manifest: &[u8; 32]) {
    let n = node
        .dir
        .conn_handle()
        .lock()
        .execute(
            &format!(
                "DELETE FROM federation_dag_chunks WHERE manifest_sha256 = X'{}'",
                hex::encode(manifest)
            ),
            [],
        )
        .expect("drop the V176 relation");
    assert!(n > 0, "precondition: the manifest was related ({n} rows)");
}

fn add_dag_link(node: &Node, manifest: &[u8; 32], seq: u64, chunk: &[u8; 32], stream: &str) {
    node.dir
        .conn_handle()
        .lock()
        .execute(
            &format!(
                "INSERT INTO federation_dag_chunks (manifest_sha256, seq, chunk_sha256, stream_id) \
                 VALUES (X'{}', {seq}, X'{}', '{}')",
                hex::encode(manifest),
                hex::encode(chunk),
                stream.replace('\'', "''")
            ),
            [],
        )
        .expect("relate a shared chunk");
}

/// The answer a door gave, as one word — so warm, cold, armed and bare doors
/// compare by value.
fn shape(r: &Result<Option<Vec<u8>>, ciris_edge::blob_swarm::ChunkSourceRefusal>) -> String {
    match r {
        Ok(Some(_)) => "bytes".to_owned(),
        Ok(None) => "not held".to_owned(),
        Err(refusal) => format!("{refusal:?}"),
    }
}

/// **CIRISEdge#771 — the two-node withdraw-and-evict witness** (persist
/// I482–I484, on edge's serve door).
///
/// A sealed X; B pulled it through the real puller above, so B's promote
/// wrote persist's chunk→manifest link (V176). B also holds a LIVE DAG Z of
/// its own, and the relation makes X's first chunk one of Z's too (the
/// I484 seam: two real seals never share a chunk).
///
/// 1. B's link names every chunk of X — the same `(seq, sha)` A sealed,
///    terminator included — and B's serve door serves each while X is live.
/// 2. X's author withdraws X on A; the `withdraws` reaches B. Every chunk of
///    X named under X is refused `Withdrawn` at B's door — the armed door
///    (production's wiring), a door that served X before (warm), and a fresh
///    one (cold), all alike; and over the wire to A. The shared chunk under
///    X is refused too, and still served under Z.
/// 3. B evicts the withdrawn manifest: the manifest and every chunk X holds
///    alone leave B's store; the shared chunk and all of Z stay; the
///    relation stays; and the door still answers `Withdrawn`, warm and cold.
#[allow(clippy::many_single_char_names)]
async fn withdrawn_dag_is_refused_and_evicted_at_the_holder_771(
    a: &Member,
    b: &Member,
    owner: &Ident,
    row_x: &Attestation,
    x: [u8; 32],
    x_stream: &str,
) {
    use ciris_edge::blob_swarm::revocation::{apply_observation, observe};
    use ciris_edge::blob_swarm::{
        BlobChunkSource as _, BytesVerdict, ChunkSourceRefusal, PersistBlobChunkSource,
        RevocationRegister,
    };
    let engine_b = b.node.store.engine();
    let peer = a.node.me.clone();

    // ── 1. B's link is A's seal.
    let sealed: Vec<(u64, [u8; 32])> = a
        .node
        .dir
        .stream_chunks(x_stream)
        .await
        .expect("A's listing of X")
        .chunks
        .iter()
        .map(|c| (c.seq, c.chunk_sha))
        .collect();
    let linked = engine_b
        .chunks_of_manifest(&x)
        .await
        .expect("chunks_of_manifest");
    assert_eq!(
        linked, sealed,
        "B's promote related X to every chunk A sealed, terminator included (persist I481)"
    );
    assert!(
        linked.last().is_some_and(|(seq, _)| *seq >= 1 << 62),
        "the terminator is related too: {linked:?}"
    );

    let (z, _z_row) = publish_on(b, owner, 0x0771, "live-z.mp4").await;
    let z_sha = sha_of(&z.pointer);
    let z_stream = z.pointer.stream_id.clone().expect("Z is a DAG");
    let (_, shared) = linked[0];
    add_dag_link(&b.node, &z_sha, 1_000_000, &shared, &z_stream);
    assert!(
        engine_b
            .dag_contains_chunk(&z_sha, &shared)
            .await
            .expect("dag_contains_chunk"),
        "precondition: X's first chunk is one of Z's too"
    );
    let z_chunks: Vec<[u8; 32]> = engine_b
        .chunks_of_manifest(&z_sha)
        .await
        .expect("Z's relation")
        .into_iter()
        .map(|(_, c)| c)
        .filter(|c| *c != shared)
        .collect();
    assert!(!z_chunks.is_empty(), "Z has chunks of its own");

    let register = Arc::new(RevocationRegister::default());
    let armed =
        PersistBlobChunkSource::new(engine_b.clone()).with_revocations(Some(Arc::clone(&register)));
    let warm = PersistBlobChunkSource::new(engine_b.clone());
    assert!(
        apply_observation(
            &register,
            &*b.node.dir,
            None,
            observe(row_x).expect("a file row carries a pointer"),
        )
        .await
        .is_empty(),
        "indexing X's row at B evicts nothing"
    );
    for (seq, c) in &linked {
        for door in [&armed, &warm] {
            let r = door.read_chunk(x, *c, &peer).await;
            assert!(
                matches!(&r, Ok(Some(bytes)) if <[u8; 32]>::from(sha2::Sha256::digest(bytes)) == *c),
                "control: B serves X's chunk {seq} while X is live: {}",
                shape(&r)
            );
        }
    }

    let scope = ContentScope::Group {
        scope: CohortScope::SelfOnly,
        group_id: ciris_edge::self_room::room(&owner.key_id).table_group_id(),
    };
    let to_b = a
        .edge
        .blob_scope_router()
        .route(Some(&scope), &b.node.me)
        .expect("A routes to B on the self room's address");
    let ask_b = |blob: [u8; 32], chunk: [u8; 32]| {
        let edge = Arc::clone(&a.edge);
        let to_b = to_b.clone();
        async move {
            edge.fetch_blob_chunk_scoped(&to_b, blob, chunk, Duration::from_secs(15))
                .await
                .expect("B answers")
        }
    };
    assert!(
        matches!(
            ask_b(x, linked[1].1).await,
            ciris_edge::ChunkResult::Bytes(_)
        ),
        "control: over the wire, B serves X's chunk to A while X is live"
    );

    // ── 2. X's author withdraws X; the `withdraws` reaches B.
    let person = person_signer(owner);
    let withdraws = ciris_edge::files::withdraw(
        &*a.node.dir,
        row_x,
        "deleted from the drive",
        ts(),
        ciris_edge::replication::attestation_bind::Signers {
            node: &a.node.signer,
            actor: Some(&person),
        },
    )
    .await
    .expect("X's author withdraws X");
    b.node
        .dir
        .put_attestation(SignedAttestation {
            attestation: withdraws.clone(),
        })
        .await
        .expect("B admits the withdraws");
    // The register takes it as the bridge does — without an evictor, so the
    // eviction below is persist's own door, asserted on its own.
    let _ = apply_observation(
        &register,
        &*b.node.dir,
        None,
        observe(&withdraws).expect("a withdraws is observed"),
    )
    .await;
    assert_eq!(register.verdict(&x), BytesVerdict::Revoked);
    assert!(
        is_withdrawn(&fold_of(&b.node, &x).await),
        "persist's fold of X at B is Withdrawn"
    );

    let refused_everywhere = |when: &'static str| {
        let (armed, warm, linked) = (&armed, &warm, &linked);
        let engine_b = engine_b.clone();
        let peer = peer.clone();
        async move {
            let cold = PersistBlobChunkSource::new(engine_b);
            for (seq, c) in linked {
                let answers = [
                    shape(&armed.read_chunk(x, *c, &peer).await),
                    shape(&warm.read_chunk(x, *c, &peer).await),
                    shape(&cold.read_chunk(x, *c, &peer).await),
                ];
                assert_eq!(
                    answers,
                    ["Withdrawn", "Withdrawn", "Withdrawn"],
                    "{when}: X's chunk {seq} named under X is refused Withdrawn at B on the \
                     armed, warm and cold door alike (CIRISEdge#771)"
                );
            }
        }
    };
    refused_everywhere("after the withdraw").await;
    for (seq, c) in &linked {
        if *c == shared {
            continue;
        }
        assert!(
            matches!(
                warm.read_chunk(*c, *c, &peer).await,
                Err(ChunkSourceRefusal::Withdrawn)
            ),
            "X's chunk {seq} asked for by its own sha is refused Withdrawn (persist's link)"
        );
    }
    for (when, door) in [("warm", &warm), ("armed", &armed)] {
        assert!(
            matches!(door.read_chunk(z_sha, shared, &peer).await, Ok(Some(_))),
            "{when}: the chunk X shares with the live Z is still served under Z"
        );
    }
    let wire = ask_b(x, linked[1].1).await;
    assert!(
        matches!(&wire, ciris_edge::ChunkResult::ChunkMiss { reason } if reason.contains("Withdrawn")),
        "over the wire, B refuses X's chunk to A Withdrawn: {wire:?}"
    );

    // ── 3. B evicts the withdrawn manifest.
    let rep = engine_b
        .evict_blob(&x, chrono::Utc::now())
        .await
        .expect("evict X at B");
    assert!(rep.blob_deleted, "X's manifest leaves B");
    assert_eq!(
        rep.dag_chunks_evicted,
        linked.len() - 1,
        "every chunk X holds alone leaves with it; the one Z shares stays (persist I483/I484)"
    );
    assert!(!b.node.dir.has_blob(&x).await.expect("has_blob"));
    for (seq, c) in &linked {
        let held = b.node.dir.has_blob(c).await.expect("has_blob");
        if *c == shared {
            assert!(held, "the chunk Z shares stays in B's store");
        } else {
            assert!(!held, "X's chunk {seq} is gone from B's store");
        }
    }
    assert!(
        b.node.dir.has_blob(&z_sha).await.expect("has_blob"),
        "Z's manifest is untouched"
    );
    for c in &z_chunks {
        assert!(
            b.node.dir.has_blob(c).await.expect("has_blob"),
            "Z's own chunks are untouched"
        );
    }
    assert_eq!(
        engine_b
            .chunks_of_manifest(&x)
            .await
            .expect("chunks_of_manifest"),
        linked,
        "the relation outlives the eviction (persist I483)"
    );
    refused_everywhere("after the eviction").await;
    assert!(
        matches!(warm.read_chunk(z_sha, shared, &peer).await, Ok(Some(_))),
        "the shared chunk is still served under Z after X's eviction"
    );

    unlinked_withdrawn_dag_is_refused_by_the_register_771(b, owner).await;
}

/// **CIRISEdge#771 item 2 — a withdrawn DAG persist has NO link for.**
///
/// Persist #979 does not cover it: a DAG sealed or pulled before persist
/// v53.1.0 has no relation, and promote refuses a withdrawn manifest, so it
/// is never backfilled (persist I486). Two shapes on B, each a DAG W whose
/// V176 relation is dropped through B's SQLite writer:
///
/// - **(a) the withdrawal persist sees** (the row cites W in `evidence_refs`):
///   persist's own chunk fold reads `Unbound`, its door serves each chunk by
///   sha, and its eviction of the manifest reaches no chunk — the gap,
///   measured. The armed door refuses every chunk under W `Withdrawn`, warm
///   and cold, before and after the manifest's eviction.
/// - **(b) a withdrawal only the register knows** (a reference persist's
///   predicate cannot see — a row citing W only by `BlobPointer` from a
///   producer that writes no `evidence_refs`; the register's own reference
///   set, CIRISEdge#606): persist's fold of W stays `Live`, so a bare door
///   SERVES every chunk, and the armed door refuses every one `Withdrawn`.
///   This is the case the register stays armed for.
async fn unlinked_withdrawn_dag_is_refused_by_the_register_771(b: &Member, owner: &Ident) {
    use ciris_edge::blob_swarm::revocation::{apply_observation, observe};
    use ciris_edge::blob_swarm::{
        BlobChunkSource as _, BlobEvictor, BytesVerdict, PersistBlobChunkSource, RevocationRegister,
    };
    use ciris_persist::federation::blob_tombstone::BindingState;
    let engine_b = b.node.store.engine();
    let peer = "a-peer-asking-771";
    let person = person_signer(owner);
    let signers = ciris_edge::replication::attestation_bind::Signers {
        node: &b.node.signer,
        actor: Some(&person),
    };

    // ── (a)
    let (w, w_crossed) = publish_on(b, owner, 0x0772, "pre-v53-1.mp4").await;
    let w_sha = sha_of(&w.pointer);
    let w_chunks = engine_b
        .chunks_of_manifest(&w_sha)
        .await
        .expect("W's relation");
    assert!(!w_chunks.is_empty(), "precondition: B's seal related W");
    drop_dag_link(&b.node, &w_sha);
    assert!(engine_b
        .chunks_of_manifest(&w_sha)
        .await
        .expect("chunks_of_manifest")
        .is_empty());

    let register = Arc::new(RevocationRegister::default());
    let armed =
        PersistBlobChunkSource::new(engine_b.clone()).with_revocations(Some(Arc::clone(&register)));
    for row in [&w.row, &w_crossed] {
        let _ = apply_observation(
            &register,
            &*b.node.dir,
            None,
            observe(row).expect("a file row"),
        )
        .await;
    }
    for (seq, c) in &w_chunks {
        assert_eq!(
            shape(&armed.read_chunk(w_sha, *c, peer).await),
            "bytes",
            "control: W's chunk {seq} is served while W is live, with no link (legacy reading)"
        );
    }
    for row in [&w_crossed, &w.row] {
        let withdraws = ciris_edge::files::withdraw(&*b.node.dir, row, "CC 2.3", ts(), signers)
            .await
            .expect("W's author withdraws W");
        let _ = apply_observation(
            &register,
            &*b.node.dir,
            None,
            observe(&withdraws).expect("a withdraws"),
        )
        .await;
    }
    assert!(
        is_withdrawn(&fold_of(&b.node, &w_sha).await),
        "precondition: persist's fold of W is Withdrawn"
    );
    assert_eq!(register.verdict(&w_sha), BytesVerdict::Revoked);
    for (seq, c) in &w_chunks {
        assert_eq!(
            fold_of(&b.node, c).await,
            BindingState::Unbound,
            "the gap: with no link, persist folds W's chunk {seq} Unbound (persist I486)"
        );
        assert!(
            engine_b.serve_blob_to_peer(c, peer).await.is_ok(),
            "the gap: persist's own door serves W's chunk {seq} by sha"
        );
    }
    let armed_doors_refuse = |when: &'static str| {
        let (armed, w_chunks) = (&armed, &w_chunks);
        let engine_b = engine_b.clone();
        let register = Arc::clone(&register);
        async move {
            let cold = PersistBlobChunkSource::new(engine_b).with_revocations(Some(register));
            for (seq, c) in w_chunks {
                let answers = [
                    shape(&armed.read_chunk(w_sha, *c, peer).await),
                    shape(&cold.read_chunk(w_sha, *c, peer).await),
                ];
                assert_eq!(
                    answers,
                    ["Withdrawn", "Withdrawn"],
                    "{when}: an unlinked withdrawn DAG's chunk {seq} is refused Withdrawn on \
                     the armed door, warm and cold (CIRISEdge#771)"
                );
            }
        }
    };
    armed_doors_refuse("(a) after the withdraw").await;
    let evictor: &dyn BlobEvictor = engine_b;
    let rep = evictor
        .evict_blob_bytes(&w_sha)
        .await
        .expect("evict W's manifest");
    assert!(rep.blob_deleted, "W's manifest leaves B");
    for (seq, c) in &w_chunks {
        assert!(
            b.node.dir.has_blob(c).await.expect("has_blob"),
            "the gap: with no link, the eviction cannot reach W's chunk {seq} — it stays"
        );
    }
    armed_doors_refuse("(a) after the manifest's eviction").await;

    // ── (b) V: a sealed DAG on B that NO row persist's predicate can see
    // references — the only reference is a pointer-only citation the
    // register indexed (`observe` reads pointers), and an authorized
    // withdrawal retired it. Persist folds V `Unbound` and has nothing to
    // refuse it by; the register's verdict is `Revoked`.
    let v_stream = format!("pointer-only-771-{}", &b.node.me[..8.min(b.node.me.len())]);
    for seq in 0..3u64 {
        engine_b
            .put_blob_chunk_scoped(
                "self",
                Some(&owner.key_id),
                &v_stream,
                seq,
                &content(4096, 0x0773 + u32::try_from(seq).expect("small")),
                0,
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("V chunk {seq}: {e}"));
    }
    let v_sha = engine_b
        .seal_stream_scoped("self", Some(&owner.key_id), &v_stream, None, None)
        .await
        .expect("seal V")
        .manifest_sha256;
    let v_chunks = engine_b
        .chunks_of_manifest(&v_sha)
        .await
        .expect("V's relation");
    assert!(!v_chunks.is_empty(), "precondition: B's seal related V");
    let register = Arc::new(RevocationRegister::default());
    let armed =
        PersistBlobChunkSource::new(engine_b.clone()).with_revocations(Some(Arc::clone(&register)));
    let bare = PersistBlobChunkSource::new(engine_b.clone());
    let pointer_only = "pointer-only-row-771";
    assert!(register.note_reference(v_sha, pointer_only));
    assert_eq!(register.note_withdrawn(pointer_only, &[v_sha]), vec![v_sha]);
    assert_eq!(
        register.verdict(&v_sha),
        BytesVerdict::Revoked,
        "precondition: the only known reference to V is withdrawn"
    );
    assert_eq!(
        fold_of(&b.node, &v_sha).await,
        BindingState::Unbound,
        "precondition: persist's fold cannot see that reference"
    );
    for (seq, c) in &v_chunks {
        assert_eq!(
            shape(&bare.read_chunk(v_sha, *c, peer).await),
            "bytes",
            "(b) the bare door serves V's chunk {seq}: persist has nothing to refuse it by"
        );
        assert_eq!(
            shape(&armed.read_chunk(v_sha, *c, peer).await),
            "Withdrawn",
            "(b) the armed door refuses V's chunk {seq} Withdrawn — the register is the only \
             refusal (CIRISEdge#771 item 2)"
        );
    }
}

/// **CIRISEdge#771 / persist I485 — an author-asserted pointer widens no
/// DAG.** A row referencing X whose pointer names Y's STREAM (same owner,
/// same `self` cohort and community, so the pre-#771 walk's agreement check
/// passes) is admitted on A. Before #771 the serve gate's own walk listed
/// Y's stream as X's and SERVED Y's chunk under a request naming X — content
/// the scope gate never judged. Since #771 membership is persist's link,
/// which no row writes: the request is refused `ChunkNotInNamedDag`.
async fn a_forged_pointer_widens_no_dag_771(
    a: &Member,
    owner: &Ident,
    row_x: &Attestation,
    x: [u8; 32],
    y_stream: &str,
    y_chunk: [u8; 32],
) {
    use ciris_edge::blob_swarm::{BlobChunkSource as _, PersistBlobChunkSource};
    use sha2::Digest as _;
    let person = person_signer(owner);
    let id = format!("forged-pointer-771-{}", row_x.attestation_id);
    let mut envelope = row_x.attestation_envelope.clone();
    let x_hex = hex::encode(x);
    let mut renamed = 0;
    for v in envelope.as_object_mut().expect("an object").values_mut() {
        if v.get("content_sha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| s.eq_ignore_ascii_case(&x_hex))
            && v.get("stream_id").is_some()
        {
            v["stream_id"] = serde_json::json!(y_stream);
            renamed += 1;
        }
    }
    assert!(
        renamed > 0,
        "precondition: X's row carries a pointer with a stream"
    );
    if let Some(mirror) = envelope.get_mut("row") {
        mirror["attestation_id"] = serde_json::json!(id);
    }
    let canonical =
        ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let (classical, pqc) =
        ciris_edge::identity::sign_bound_hybrid(&person, &canonical, "forged pointer")
            .await
            .expect("sign");
    let mut forged = row_x.clone();
    forged.attestation_id = id;
    forged.attestation_envelope = envelope;
    forged.original_content_hash = hex::encode(sha2::Sha256::digest(&canonical));
    forged.scrub_signature_classical = classical;
    forged.scrub_signature_pqc = pqc;
    forged.persist_row_hash = String::new();
    forged.additional_scrubs = Vec::new();
    a.node
        .dir
        .put_attestation(SignedAttestation {
            attestation: forged,
        })
        .await
        .expect("A admits a second row referencing X, its pointer naming Y's stream");
    let door = PersistBlobChunkSource::new(a.node.store.engine().clone());
    let answer = shape(&door.read_chunk(x, y_chunk, "a-peer-asking-771").await);
    assert_eq!(
        answer, "ChunkNotInNamedDag",
        "a row's stream_id does not make Y's chunk one of X's (CIRISEdge#771, persist I485)"
    );
}
