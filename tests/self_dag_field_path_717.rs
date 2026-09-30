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
async fn device(db: &str, seed_idents: &[&Ident], owner: &Ident, device: &Ident) -> Node {
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
        "server",
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
    let node_a = device(":memory:", &seeds, &alice, &laptop).await;
    let node_b = device(":memory:", &seeds, &alice, &phone).await;
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
}
