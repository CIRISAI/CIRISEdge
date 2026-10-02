//! **CIRISEdge#738 — CC 5.3.3.6 delivery receipts for files, on real
//! substrates.** Lane 4 of CIRISEdge#734; `FSD/CONTENT_TRANSFER.md` §6.10.
//!
//! Every node here is its own SQLite substrate, seeded with the same
//! identities and rosters, sharing nothing but what a test hands over — the
//! harness of `blob_federation_e2e.rs`. A file is published through
//! `files::publish`, its crossed row is admitted on the receiver, the
//! receiver's `BlobPuller` pulls it through persist's real doors over a
//! fetcher reading the author's peer-serve door (`pull_dag_with` walks a file
//! over the inline bound; `pull_inline_with` stores one under it, whose log is
//! persist's one-leaf `inline_blob_stream_id`, CIRISPersist#953),
//! and the receipt the receiver emits is handed back to the author's node and
//! admitted there — then read with `FileRow::received_by`.
//!
//! Each witness names the ROW on the receiving side: the receipt row the
//! receiver emitted, the receipt the author's store holds, the file row the
//! author's bridge no longer offers.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::blob_swarm::{BlobPuller, DagPullRefusal, PullConfig, PullOutcome};
use ciris_edge::files::{FileRow, FileWrite};
use ciris_edge::receipts::{self, ReceiptLedger, ReceiptRefusal, StreamLog as _};
use ciris_edge::replication::attestation_bind::{Shared, Signers};
use ciris_edge::scope_room::ScopeRoom;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::key_grant::{SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX};
use ciris_persist::federation::{Attestation, FederationDirectory as _, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
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

/// The file every witness moves: 1.3 MiB, five 256 KiB chunks.
const FILE_LEN: usize = 1_300_000;

fn body_of(len: usize, seed: u32) -> Vec<u8> {
    (0..u32::try_from(len).expect("fits"))
        .map(|i| {
            let mixed = i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13;
            u8::try_from(mixed & 0xFF).expect("masked")
        })
        .collect()
}

// ─── Identities and nodes (the `blob_federation_e2e` shape) ───────────

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

    /// The full hybrid signature over `canonical` (ML-DSA over canonical ‖ ed).
    async fn sign_hybrid(&self, canonical: &[u8]) -> (String, String) {
        let ed_sig = self.ed.sign(canonical).await.expect("ed sign");
        let mut bound = canonical.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = PqcSigner::sign(&self.pqc, &bound).await.expect("pqc sign");
        (B64.encode(&ed_sig), B64.encode(&pqc_sig))
    }
}

struct Node {
    dir: Arc<SqliteBackend>,
    store: ciris_edge::group_content::PersistGroupContentStore,
    identity: String,
    me: String,
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// A node of `owner`, its own key from `device` (the owner's first device when
/// the two are the same identity), with the owner binding and the node-class
/// engine occurrence provisioned — `blob_federation_e2e::build_node_with`.
/// `class` is the occurrence's `device_class`: under persist v53 S1 a
/// personal device (`phone` | `laptop`) is in its owner's self and family
/// audience, a server-class node is not (CC 3.3.7).
async fn device(idents: &[&Ident], owner: &Ident, device: &Ident, class: &str) -> Node {
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
    let store = ciris_edge::group_content::PersistGroupContentStore::from_shared_hybrid(
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

async fn node(idents: &[&Ident], owner: &Ident) -> Node {
    device(
        idents,
        owner,
        owner,
        ciris_persist::federation::types::device_class::LAPTOP,
    )
    .await
}

/// Hand `from`'s node key, owner binding and published occurrence to `to` —
/// what the Key and IdentityOccurrence planes carry on a mesh.
async fn federate(from: &Node, to: &Node) {
    let rec =
        ciris_persist::federation::FederationDirectory::lookup_public_key(&*from.dir, &from.me)
            .await
            .expect("lookup")
            .expect("the engine registered its derived key");
    to.dir
        .put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the far node's derived key");
    for row in from
        .dir
        .list_attestations_since(None, 256)
        .await
        .expect("list")
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
        .expect("list occurrences")
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

async fn federate_all(nodes: &[&Node]) {
    for a in nodes {
        for b in nodes {
            if a.me != b.me {
                federate(a, b).await;
            }
        }
    }
}

/// persist v52.0.0 (CIRISPersist#955, Q1) — a founding record admits only the
/// members who signed it: each of `members` co-signs `canonical`, as a real
/// founding does.
async fn cosign(
    members: &[&Ident],
    canonical: &[u8],
) -> Vec<ciris_persist::federation::types::RosterCosignature> {
    let mut out = Vec::new();
    for m in members {
        let (ed, pqc) = m.sign_hybrid(canonical).await;
        out.push(ciris_persist::federation::types::RosterCosignature {
            authority_key_id: m.key_id.clone(),
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
        });
    }
    out
}

/// A community `room` founded by `members[0]`, on `node`.
async fn seed_community(node: &Node, room: &str, members: &[&Ident]) {
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
    let (ed, pqc) = founder.sign_hybrid(&canonical).await;
    node.dir
        .put_community(SignedCommunity {
            community,
            authority_key_id: founder.key_id.clone(),
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
            supersede_proof: None,
            cosignatures: cosign(&members[1..], &canonical).await,
            lineage: Vec::new(),
        })
        .await
        .expect("seed the room");
}

/// A family `family` founded by `members[0]`, on `node`.
async fn seed_family(node: &Node, family: &str, members: &[&Ident]) {
    use ciris_persist::federation::types::{Family, FamilyMember, SignedFamily};
    let founder = members[0];
    let record = Family {
        dissolved_at: None,
        family_key_id: family.to_owned(),
        family_name: "The Household".to_owned(),
        members: members
            .iter()
            .enumerate()
            .map(|(i, m)| FamilyMember {
                key_id: m.key_id.clone(),
                joined_at: ts(),
                role: (i == 0)
                    .then(|| ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at: ts(),
        consensus_protocol: "founder_only".to_owned(),
        consensus_protocol_entrenched: false,
        persist_row_hash: String::new(),
        prev_head_digest: String::new(),
        charter_digest: String::new(),
    };
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&record.signing_envelope())
        .expect("canonicalize the family");
    let (ed, pqc) = founder.sign_hybrid(&canonical).await;
    node.dir
        .put_family(SignedFamily {
            cosignatures: cosign(&members[1..], &canonical).await,
            family: record,
            authority_key_id: founder.key_id.clone(),
            scrub_signature_classical: ed,
            scrub_signature_pqc: Some(pqc),
            supersede_proof: None,
        })
        .await
        .expect("seed the family");
}

// ─── An Edge for the puller's metrics; no transport runs ──────────────

struct NoWire;

#[async_trait::async_trait]
impl ciris_edge::transport::Transport for NoWire {
    fn id(&self) -> ciris_edge::transport::TransportId {
        ciris_edge::transport::TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        _bytes: &[u8],
    ) -> Result<ciris_edge::transport::TransportSendOutcome, ciris_edge::transport::TransportError>
    {
        Err(ciris_edge::transport::TransportError::Unreachable(format!(
            "no wire in this harness ({destination_key_id})"
        )))
    }

    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<ciris_edge::transport::InboundFrame>,
    ) -> Result<(), ciris_edge::transport::TransportError> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

fn edge_of(node: &Node) -> Arc<ciris_edge::Edge> {
    use ciris_persist::federation::FederationDirectory;
    Arc::new(
        ciris_edge::Edge::builder()
            .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
            .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
            .queue(node.dir.clone())
            .signer(node.signer.clone())
            .transport(Arc::new(NoWire) as Arc<dyn ciris_edge::transport::Transport>)
            .config(ciris_edge::EdgeConfig::default())
            .build()
            .expect("build edge"),
    )
}

fn puller_of(node: &Node, edge: &Arc<ciris_edge::Edge>) -> Arc<BlobPuller<SqliteBackend>> {
    use ciris_persist::federation::FederationDirectory;
    BlobPuller::new(
        Arc::clone(edge),
        node.store.engine().clone(),
        node.dir.clone(),
        node.dir.clone() as Arc<dyn FederationDirectory>,
        node.me.clone(),
        PullConfig::default(),
    )
}

/// Reads the author's store through persist's peer-serve door — the bytes a
/// holder puts on the wire — with one address optionally tampered.
struct StoreFetch {
    engine: ciris_persist::Engine,
    peer: String,
    holders: Vec<String>,
    tamper: Option<[u8; 32]>,
}

#[async_trait::async_trait]
impl ciris_edge::blob_swarm::DagByteFetch for StoreFetch {
    fn holders(&self) -> &[String] {
        &self.holders
    }

    async fn fetch(&self, sha: [u8; 32]) -> Result<Vec<u8>, String> {
        use ciris_persist::federation::blobs::BlobBody;
        let body = self
            .engine
            .serve_blob_to_peer(&sha, &self.peer)
            .await
            .map_err(|e| e.to_string())?;
        let BlobBody::Inline(mut bytes) = body else {
            return Err("not inline".into());
        };
        if self.tamper == Some(sha) {
            if let Some(last) = bytes.last_mut() {
                *last ^= 0x01;
            }
        }
        Ok(bytes)
    }
}

fn fetch_from(author: &Node, reader: &Node, tamper: Option<[u8; 32]>) -> StoreFetch {
    StoreFetch {
        engine: author.store.engine().clone(),
        peer: reader.me.clone(),
        holders: vec![author.me.clone()],
        tamper,
    }
}

// ─── The file, published and crossed ──────────────────────────────────

struct Published {
    /// The crossed (federation-tier) file row every receiver admits.
    row: Attestation,
    sha: [u8; 32],
    stream_id: String,
    /// The manifest's chunk addresses, for tampering one.
    chunks: Vec<[u8; 32]>,
}

async fn publish(author: &Node, room: &ScopeRoom, seed: u32) -> Published {
    let file = publish_len(author, room, seed, FILE_LEN).await;
    assert!(
        FileRow::from_row(&file.row)
            .expect("file")
            .pointer
            .stream_id
            .is_some(),
        "over the bound: a chunk DAG"
    );
    file
}

/// [`publish`] at any length: at or under the inline bound the file is one
/// blob, and its stream is the one-leaf log persist names after its address.
async fn publish_len(author: &Node, room: &ScopeRoom, seed: u32, len: usize) -> Published {
    let plain = body_of(len, seed);
    let published = ciris_edge::files::publish(
        &*author.dir,
        &author.store,
        Signers {
            node: &author.signer,
            actor: None,
        },
        &FileWrite {
            room,
            bytes: &plain,
            media_type: "video/mp4",
            codec: None,
            filename: Some("holiday.mp4"),
            asserted_at: ts(),
        },
    )
    .await
    .expect("publish a file");
    let stream_id = receipts::receipt_stream_id(&published.pointer).expect("a file's stream");
    let sha: [u8; 32] = hex::decode(&published.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let crossed_id = match &published.shared {
        Shared::Placed { attestation_id } | Shared::AlreadyThere { attestation_id } => {
            attestation_id.clone()
        }
        other @ Shared::AwaitingActor { .. } => panic!("the file must cross: {other:?}"),
    };
    let row = author
        .dir
        .get_attestation(&crossed_id)
        .await
        .expect("read")
        .expect("the crossed row");
    let chunks = if published.pointer.stream_id.is_some() {
        author
            .dir
            .stream_chunk_shas(&stream_id)
            .await
            .expect("stream chunks")
    } else {
        Vec::new()
    };
    Published {
        row,
        sha,
        stream_id,
        chunks,
    }
}

/// The author's key_grant sets, applied through `reader`'s key-grant door.
async fn cross_keys(author: &Node, reader: &Node) {
    author
        .store
        .engine()
        .emit_pending_key_grants()
        .await
        .expect("emit");
    for s in author
        .dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list")
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
    {
        let _ = reader
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: s.attestation.clone(),
            })
            .await;
    }
}

/// Every receipt row `node` holds for `stream_id`.
async fn receipt_rows(node: &Node, stream_id: &str) -> Vec<Attestation> {
    node.dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list")
        .into_iter()
        .map(|a| a.attestation)
        .filter(|a| receipts::receipt_row_stream(a) == Some(stream_id))
        .collect()
}

/// Admit a receipt row on the author's node the way the bridge does: persist
/// admits the replicated row, then edge validates and stores the receipt.
async fn deliver_receipt(
    author: &Node,
    row: &Attestation,
    ledger: &ReceiptLedger,
) -> Result<receipts::DeliveryReceiptView, ReceiptRefusal> {
    author
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("persist admits the receipt row");
    receipts::admit_receipt_row(&*author.dir, &*author.dir, row, ledger).await
}

fn counted(edge: &ciris_edge::Edge, tag: &str) -> u64 {
    edge.metrics()
        .snapshot()
        .delivery_receipts
        .get(tag)
        .copied()
        .unwrap_or(0)
}

/// A receipt `node` signs as itself over whatever it is told — the forger's
/// tool — emitted as a row at `file_row`'s cohort.
async fn forged_row(
    node: &Node,
    file_row: &Attestation,
    stream_id: &str,
    epoch: u64,
    root: [u8; 32],
    k: u64,
) -> Attestation {
    let receipt = receipts::sign_receipt(node.store.engine(), &node.me, stream_id, epoch, root, k)
        .await
        .expect("sign");
    let id = receipts::emit_receipt_row(node.store.engine(), file_row, &receipt)
        .await
        .expect("emit");
    node.dir
        .get_attestation(&id)
        .await
        .expect("read")
        .expect("the emitted row")
}

/// The author's replication bridge over its own substrate and engine — the
/// apply path admits receipts, the advertise path reads them. `publish_set`
/// is the node's SelfOwn publish set.
fn bridge_of(
    node: &Node,
    publish_set: Vec<String>,
) -> ciris_edge::replication::bridge::FederationDirectoryReplicationBridge {
    use ciris_edge::replication::bridge::{BridgeEngine, FederationDirectoryReplicationBridge};
    use ciris_persist::federation::FederationDirectory;
    FederationDirectoryReplicationBridge::new(
        node.dir.clone() as Arc<dyn FederationDirectory>,
        Arc::new(Vec::<String>::new),
    )
    .with_engine(Some(BridgeEngine(node.store.engine().clone())))
    .with_local_key_id(Some(node.me.clone()))
    .with_self_provider(Some(Arc::new(move || publish_set.clone())))
}

/// Does `bridge` advertise `row` (by its stored content hash) to `peer`?
async fn offered_to(
    bridge: &ciris_edge::replication::bridge::FederationDirectoryReplicationBridge,
    node: &Node,
    row: &Attestation,
    peer: &str,
) -> bool {
    use ciris_edge::replication::directory::ReplicationDirectory as _;
    use sha2::Digest as _;
    let stored = node
        .dir
        .get_attestation(&row.attestation_id)
        .await
        .expect("read")
        .expect("row");
    let hash: [u8; 32] = sha2::Sha256::digest(serde_json::to_vec(&stored).expect("json")).into();
    bridge
        .list_envelope_refs_for_peer(
            ciris_edge::replication::protocol::EnvelopeKind::Attestation,
            Some(peer),
        )
        .await
        .iter()
        .any(|r| r.envelope_hash == hash)
}

/// Hand `row` to `bridge`'s apply path as `peer` sent it.
async fn apply_through(
    bridge: &ciris_edge::replication::bridge::FederationDirectoryReplicationBridge,
    row: &Attestation,
    peer: &str,
) -> ciris_edge::replication::summary::ApplyOutcome {
    use ciris_edge::replication::directory::ReplicationDirectory as _;
    bridge
        .apply_envelope_bytes(
            ciris_edge::replication::protocol::EnvelopeKind::Attestation,
            &serde_json::to_vec(row).expect("wire"),
            Some(peer),
        )
        .await
}

// ─── SELF: two devices of one owner ───────────────────────────────────

/// **Self (two devices): exactly one receipt from the second device, none
/// before promote, none after a tampered chunk; a forged root and a duplicate
/// are refused by name.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole ladder, in order, on purpose
async fn a_self_file_is_receipted_once_by_the_owners_other_device() {
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let alice_phone = Ident::new("alice-phone", 0x33);
    let node_a = node(&[&alice], &alice).await;
    let node_b = device(
        &[&alice, &alice_phone],
        &alice,
        &alice_phone,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    federate_all(&[&node_a, &node_b]).await;
    let edge_b = edge_of(&node_b);

    let room = ciris_edge::self_room::room(&alice.key_id);
    let file = publish(&node_a, &room, 0x5e1f).await;

    // PUBLISH: the stream's root is published on A and rides the row.
    let sth_a = node_a
        .dir
        .latest_stream_sth(&file.stream_id)
        .await
        .expect("read")
        .expect("files::publish published the stream's STH");
    // CIRISEdge#797 (persist v53, CIRISPersist#969): the stream's leaves are
    // every chunk persist holds for it, epoch 0's empty terminator included,
    // so the root a receipt names commits to it too (CC 5.3.3.6).
    assert_eq!(
        sth_a.tree_size, 6,
        "4 × 256 KiB + the tail + epoch 0's terminator"
    );
    assert_eq!(sth_a.tree_size, file.chunks.len() as u64);
    let claim = receipts::StreamSthClaim::from_row(&file.row).expect("the row carries the STH");
    assert_eq!(claim.root().expect("root"), sth_a.root_hash);
    assert_eq!(claim.tree_size, 6);

    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    let puller = puller_of(&node_b, &edge_b);
    let file_row = FileRow::from_row(&file.row).expect("a file row");
    let ledger = ReceiptLedger::new();

    // 1. Before promote — the key has not crossed: parked, no receipt.
    assert!(matches!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b, None))
            .await,
        PullOutcome::DagAwaitingKey { .. }
    ));
    assert!(receipt_rows(&node_b, &file.stream_id).await.is_empty());
    assert!(node_b
        .dir
        .list_delivery_receipts_for(&file.stream_id, 10)
        .await
        .expect("list")
        .is_empty());

    // 2. A tampered chunk: refused at its position, no receipt.
    cross_keys(&node_a, &node_b).await;
    assert!(matches!(
        puller
            .pull_dag_with(
                &file.row,
                file.sha,
                &fetch_from(&node_a, &node_b, Some(file.chunks[1]))
            )
            .await,
        PullOutcome::DagRefused(DagPullRefusal::ChunkMismatch { seq: 1, .. })
    ));
    assert!(receipt_rows(&node_b, &file.stream_id).await.is_empty());
    assert_eq!(counted(&edge_b, receipts::RECEIPT_EMITTED), 0);

    // 3. The honest pull resumes and promotes: ONE receipt, as the node.
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b, None))
            .await,
        PullOutcome::Stored { announced: false }
    );
    let rows = receipt_rows(&node_b, &file.stream_id).await;
    assert_eq!(rows.len(), 1, "exactly one receipt row: {rows:#?}");
    let receipt_row = rows[0].clone();
    assert_eq!(
        receipt_row.attesting_key_id, node_b.me,
        "signed by the NODE"
    );
    assert_eq!(
        receipt_row.cohort_scope, "self",
        "the room's delivered path"
    );
    let held_b = node_b
        .dir
        .list_delivery_receipts_for(&file.stream_id, 10)
        .await
        .expect("list");
    assert_eq!(held_b.len(), 1);
    assert_eq!(held_b[0].k, 6, "K = tree_size, the terminator included");
    assert_eq!(
        held_b[0].chunk_root, sth_a.root_hash,
        "the root B's own chunks reproduce is A's published root"
    );
    assert_eq!(counted(&edge_b, receipts::RECEIPT_EMITTED), 1);

    // Held is held: a re-offer emits nothing more.
    assert_eq!(
        puller.pull_one(&file.row, file.sha, 0).await,
        PullOutcome::AlreadyHeld
    );
    assert_eq!(receipt_rows(&node_b, &file.stream_id).await.len(), 1);

    // 4. DELIVERED back to the author through A's bridge apply path: A
    //    admits it; received_by names B; A's advertise to B drops the row.
    let bridge = bridge_of(&node_a, vec![node_a.me.clone(), alice.key_id.clone()]);
    assert!(
        offered_to(&bridge, &node_a, &file.row, &node_b.me).await,
        "before the receipt, A offers the file row to alice's other device"
    );
    assert!(file_row
        .received_by(&node_a.store)
        .await
        .expect("read")
        .is_empty());
    assert_eq!(
        apply_through(&bridge, &receipt_row, &node_b.me).await,
        ciris_edge::replication::summary::ApplyOutcome::Admitted,
        "A's bridge admits B's receipt row"
    );
    let received = file_row.received_by(&node_a.store).await.expect("read");
    assert_eq!(received.len(), 1, "exactly one receipt: {received:?}");
    assert_eq!(received[0].node_key_id, node_b.me);
    assert_eq!((received[0].epoch, received[0].k), (0, 6));
    assert!(
        received[0].at > file.row.asserted_at && received[0].at <= chrono::Utc::now(),
        "`at` is when A's store took the receipt (CIRISPersist#953): {}",
        received[0].at
    );
    assert!(bridge
        .receipt_ledger()
        .is_receipted(&node_b.me, &file.stream_id));
    assert!(
        !offered_to(&bridge, &node_a, &file.row, &node_b.me).await,
        "a device that receipted the whole file is not re-offered its row"
    );

    // 5. A forged receipt naming a self-invented root: refused by name.
    let forged = forged_row(&node_b, &file.row, &file.stream_id, 0, [0x42; 32], 5).await;
    assert!(matches!(
        deliver_receipt(&node_a, &forged, &ledger).await,
        Err(ReceiptRefusal::RootUnpublished { .. })
    ));

    // 6. A second receipt for the same (stream, epoch, receiver): duplicate.
    let again = forged_row(&node_b, &file.row, &file.stream_id, 0, sth_a.root_hash, 5).await;
    assert_ne!(again.attestation_id, receipt_row.attestation_id);
    assert!(matches!(
        deliver_receipt(&node_a, &again, &ledger).await,
        Err(ReceiptRefusal::Duplicate { .. })
    ));
    assert_eq!(
        file_row
            .received_by(&node_a.store)
            .await
            .expect("read")
            .len(),
        1,
        "still exactly one"
    );
}

// ─── INLINE: a file under the bound is receipted too ──────────────────

/// The inline witness's file: well under the 1 MiB inline bound.
const INLINE_LEN: usize = 200_000;

/// **Inline (≤ 1 MiB, self, two devices): the one-leaf STH at publish,
/// exactly one receipt from the second device on inline admission, `at`
/// populated on the author's read, the re-offer stops, and a forged receipt
/// naming a self-invented root is refused by name.** (CIRISPersist#953.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole ladder, in order, on purpose
async fn an_inline_self_file_is_receipted_once_by_the_owners_other_device() {
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let alice_phone = Ident::new("alice-phone", 0x33);
    let node_a = node(&[&alice], &alice).await;
    let node_b = device(
        &[&alice, &alice_phone],
        &alice,
        &alice_phone,
        ciris_persist::federation::types::device_class::PHONE,
    )
    .await;
    federate_all(&[&node_a, &node_b]).await;
    let edge_b = edge_of(&node_b);

    let room = ciris_edge::self_room::room(&alice.key_id);
    let file = publish_len(&node_a, &room, 0x1a1e, INLINE_LEN).await;
    let file_row = FileRow::from_row(&file.row).expect("a file row");
    assert!(file_row.pointer.stream_id.is_none(), "an inline file");

    // PUBLISH: the one-leaf log is persist's name for the blob, and its STH
    // is published on A and rides the row.
    assert_eq!(
        file.stream_id,
        ciris_persist::federation::stream_sth::inline_blob_stream_id(&file.sha),
        "an inline file's log is named after its address"
    );
    let sth_a = node_a
        .dir
        .latest_stream_sth(&file.stream_id)
        .await
        .expect("read")
        .expect("files::publish published the inline file's one-leaf STH");
    assert_eq!(sth_a.tree_size, 1, "one leaf: the blob's own address");
    let claim = receipts::StreamSthClaim::from_row(&file.row).expect("the row carries the STH");
    assert_eq!(claim.stream_id, file.stream_id);
    assert_eq!(claim.root().expect("root"), sth_a.root_hash);
    assert_eq!(claim.tree_size, 1);

    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    cross_keys(&node_a, &node_b).await;
    let puller = puller_of(&node_b, &edge_b);
    assert!(receipt_rows(&node_b, &file.stream_id).await.is_empty());

    // A stream pointer is not the inline door's.
    // (The DAG door refuses this one by name, the mirror image.)
    assert!(matches!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b, None))
            .await,
        PullOutcome::Refused(_)
    ));
    assert!(receipt_rows(&node_b, &file.stream_id).await.is_empty());

    // INLINE ADMISSION: stored, and ONE receipt, as the node, K = 1.
    assert_eq!(
        puller
            .pull_inline_with(&file.row, file.sha, &fetch_from(&node_a, &node_b, None))
            .await,
        PullOutcome::Stored { announced: false }
    );
    let rows = receipt_rows(&node_b, &file.stream_id).await;
    assert_eq!(rows.len(), 1, "exactly one receipt row: {rows:#?}");
    let receipt_row = rows[0].clone();
    assert_eq!(
        receipt_row.attesting_key_id, node_b.me,
        "signed by the NODE"
    );
    assert_eq!(
        receipt_row.cohort_scope, "self",
        "the room's delivered path"
    );
    let held_b = node_b
        .dir
        .list_delivery_receipts_for(&file.stream_id, 10)
        .await
        .expect("list");
    assert_eq!(held_b.len(), 1);
    assert_eq!(held_b[0].k, 1, "K = tree_size = 1");
    assert_eq!(
        held_b[0].chunk_root, sth_a.root_hash,
        "the root B's own blob reproduces is A's published root"
    );
    assert_eq!(counted(&edge_b, receipts::RECEIPT_EMITTED), 1);

    // Held is held: a re-pull emits nothing more.
    assert_eq!(
        puller
            .pull_inline_with(&file.row, file.sha, &fetch_from(&node_a, &node_b, None))
            .await,
        PullOutcome::AlreadyHeld
    );
    assert_eq!(receipt_rows(&node_b, &file.stream_id).await.len(), 1);

    // DELIVERED back to A through its bridge apply path; received_by names B
    // with the instant A's store took it; the advertise to B drops the row.
    let bridge = bridge_of(&node_a, vec![node_a.me.clone(), alice.key_id.clone()]);
    assert!(
        offered_to(&bridge, &node_a, &file.row, &node_b.me).await,
        "before the receipt, A offers the file row to alice's other device"
    );
    assert!(file_row
        .received_by(&node_a.store)
        .await
        .expect("read")
        .is_empty());
    assert_eq!(
        apply_through(&bridge, &receipt_row, &node_b.me).await,
        ciris_edge::replication::summary::ApplyOutcome::Admitted,
        "A's bridge admits B's inline receipt row"
    );
    let received = file_row.received_by(&node_a.store).await.expect("read");
    assert_eq!(received.len(), 1, "exactly one receipt: {received:?}");
    assert_eq!(received[0].node_key_id, node_b.me);
    assert_eq!((received[0].epoch, received[0].k), (0, 1));
    assert!(
        received[0].at > file.row.asserted_at && received[0].at <= chrono::Utc::now(),
        "`at` is when A's store took the receipt: {}",
        received[0].at
    );
    assert!(bridge
        .receipt_ledger()
        .is_receipted(&node_b.me, &file.stream_id));
    assert!(
        !offered_to(&bridge, &node_a, &file.row, &node_b.me).await,
        "a device that receipted the inline file is not re-offered its row"
    );

    // A forged inline receipt naming a self-invented root: refused by name.
    let ledger = ReceiptLedger::new();
    let forged = forged_row(&node_b, &file.row, &file.stream_id, 0, [0x42; 32], 1).await;
    let refused = deliver_receipt(&node_a, &forged, &ledger).await;
    assert!(
        matches!(refused, Err(ReceiptRefusal::RootUnpublished { .. })),
        "{refused:?}"
    );
    assert_eq!(
        refused.expect_err("refused").tag(),
        receipts::RECEIPT_ROOT_UNPUBLISHED
    );
    assert_eq!(
        file_row
            .received_by(&node_a.store)
            .await
            .expect("read")
            .len(),
        1,
        "still exactly one"
    );
}

// ─── FAMILY: two persons ──────────────────────────────────────────────

/// **Family (two persons): a receipt from the other person's device; none
/// admitted from a non-family node.**
///
/// Was `#[ignore]`d twice: at persist 9d406712 no family file could be
/// published (CIRISPersist#953 item 1), and at e398da3c the other member's
/// node refused the bytes `NotPartyTo` (the hold gate's family arm read only
/// the operator predicate, CIRISPersist#960). Both fixed in persist v52;
/// un-ignored by the family lane (CIRISEdge#736).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_family_file_is_receipted_by_the_other_persons_device_and_no_one_else() {
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let carol = Ident::new("carol-fed", 0x44);
    let everyone = [&alice, &bob, &carol];
    let node_a = node(&everyone, &alice).await;
    let node_b = node(&everyone, &bob).await;
    let node_c = node(&everyone, &carol).await;
    for n in [&node_a, &node_b, &node_c] {
        seed_family(n, "family-moore", &[&alice, &bob]).await;
    }
    federate_all(&[&node_a, &node_b, &node_c]).await;
    let edge_b = edge_of(&node_b);

    let room = ciris_edge::family_room::room("family-moore");
    let file = publish(&node_a, &room, 0xfa31).await;
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the family row");
    cross_keys(&node_a, &node_b).await;
    let puller = puller_of(&node_b, &edge_b);
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b, None))
            .await,
        PullOutcome::Stored { announced: false }
    );
    let rows = receipt_rows(&node_b, &file.stream_id).await;
    assert_eq!(rows.len(), 1, "bob's device receipted once");
    assert_eq!(rows[0].cohort_scope, "family");
    assert_eq!(
        rows[0]
            .attestation_envelope
            .get("family_key_id")
            .and_then(serde_json::Value::as_str),
        Some("family-moore"),
        "the receipt is placed in the family, as the file is"
    );

    let ledger = ReceiptLedger::new();
    deliver_receipt(&node_a, &rows[0], &ledger)
        .await
        .expect("A admits bob's device's receipt");
    let file_row = FileRow::from_row(&file.row).expect("file");
    let received = file_row.received_by(&node_a.store).await.expect("read");
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].node_key_id, node_b.me);

    // Carol is not in the family. Her node signs a receipt for the file with
    // the REAL root and K — only membership can refuse it.
    let sth = node_a
        .dir
        .latest_stream_sth(&file.stream_id)
        .await
        .expect("read")
        .expect("published");
    let receipt = receipts::sign_receipt(
        node_c.store.engine(),
        &node_c.me,
        &file.stream_id,
        0,
        sth.root_hash,
        sth.tree_size,
    )
    .await
    .expect("sign");
    let mut from_carol = rows[0].clone();
    from_carol.attestation_id = format!("{}-carol", from_carol.attestation_id);
    from_carol.attesting_key_id = node_c.me.clone();
    from_carol.attestation_envelope[receipts::FIELD_RECEIPT] =
        serde_json::to_value(receipts::ReceiptClaim::of(&receipt)).expect("json");
    let refused = receipts::admit_receipt_row(&*node_a.dir, &*node_a.dir, &from_carol, &ledger)
        .await
        .expect_err("a non-family node's receipt is refused");
    assert!(
        matches!(refused, ReceiptRefusal::SignerNotMember { .. }),
        "{refused}"
    );
    assert_eq!(
        file_row
            .received_by(&node_a.store)
            .await
            .expect("read")
            .len(),
        1,
        "nothing from carol"
    );
}

// ─── COMMUNITY: three members ─────────────────────────────────────────

/// **Community (three members): a receipt per puller; a non-member's,
/// a wrong epoch's and a past-the-tree K's refused by name; the author's
/// bridge stops offering the file row to each peer that receipted it.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // three members and the bridge, in order, on purpose
async fn a_community_file_is_receipted_per_member_and_stops_being_offered() {
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let bob = Ident::new("bob-fed", 0x22);
    let carol = Ident::new("carol-fed", 0x44);
    let dave = Ident::new("dave-fed", 0x66);
    let everyone = [&alice, &bob, &carol, &dave];
    let node_a = node(&everyone, &alice).await;
    let node_b = node(&everyone, &bob).await;
    let node_c = node(&everyone, &carol).await;
    let node_d = node(&everyone, &dave).await;
    for n in [&node_a, &node_b, &node_c, &node_d] {
        seed_community(n, "room-738", &[&alice, &bob, &carol]).await;
    }
    federate_all(&[&node_a, &node_b, &node_c, &node_d]).await;

    let room = ScopeRoom::community("room-738");
    let file = publish(&node_a, &room, 0xc0de).await;
    let file_row = FileRow::from_row(&file.row).expect("file");
    let epoch = file_row
        .pointer
        .epoch
        .expect("a community pointer carries its sealed-under epoch");

    // A's bridge: the member's receipt row arrives on its apply path.
    let bridge = bridge_of(&node_a, vec![node_a.me.clone(), alice.key_id.clone()]);

    for reader in [&node_b, &node_c] {
        reader
            .dir
            .apply_replicated_attestation(SignedAttestation {
                attestation: file.row.clone(),
            })
            .await
            .expect("the member admits the community row");
        cross_keys(&node_a, reader).await;
        let edge = edge_of(reader);
        let pulled = puller_of(reader, &edge)
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, reader, None))
            .await;
        assert!(
            matches!(pulled, PullOutcome::Stored { .. }),
            "the member pulls the community DAG: {pulled:?}"
        );
        let rows = receipt_rows(reader, &file.stream_id).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cohort_scope, "community");
        assert_eq!(
            rows[0]
                .attestation_envelope
                .get("community_key_id")
                .and_then(serde_json::Value::as_str),
            Some("room-738")
        );
        // Delivered to A through A's bridge apply path.
        assert_eq!(
            apply_through(&bridge, &rows[0], &reader.me).await,
            ciris_edge::replication::summary::ApplyOutcome::Admitted,
            "A admits the member's receipt row"
        );
        assert!(bridge
            .receipt_ledger()
            .is_receipted(&reader.me, &file.stream_id));
    }
    let mut who: Vec<String> = file_row
        .received_by(&node_a.store)
        .await
        .expect("read")
        .into_iter()
        .inspect(|r| assert_eq!((r.epoch, r.k), (epoch, 5)))
        .map(|r| r.node_key_id)
        .collect();
    who.sort();
    let mut want = vec![node_b.me.clone(), node_c.me.clone()];
    want.sort();
    assert_eq!(who, want, "a receipt from each member that pulled");

    // The re-offer stops for each receipted peer: the ledger A's advertise
    // reads names both (the advertise itself is witnessed in the self test —
    // a community peer additionally needs a common trust root, CIRISEdge#659).
    assert!(!bridge
        .receipt_ledger()
        .is_receipted(&node_d.me, &file.stream_id));

    // Dave is not in the room: refused by membership, with a real root.
    let sth = node_a
        .dir
        .latest_stream_sth(&file.stream_id)
        .await
        .expect("read")
        .expect("published");
    let ledger = ReceiptLedger::new();
    let from_b = receipt_rows(&node_b, &file.stream_id).await.remove(0);
    let receipt = receipts::sign_receipt(
        node_d.store.engine(),
        &node_d.me,
        &file.stream_id,
        epoch,
        sth.root_hash,
        sth.tree_size,
    )
    .await
    .expect("sign");
    let mut from_dave = from_b.clone();
    from_dave.attestation_id = format!("{}-dave", from_dave.attestation_id);
    from_dave.attesting_key_id = node_d.me.clone();
    from_dave.attestation_envelope[receipts::FIELD_RECEIPT] =
        serde_json::to_value(receipts::ReceiptClaim::of(&receipt)).expect("json");
    assert!(matches!(
        receipts::admit_receipt_row(&*node_a.dir, &*node_a.dir, &from_dave, &ledger).await,
        Err(ReceiptRefusal::SignerNotMember { .. })
    ));

    // A member's receipt at the wrong epoch, and one past the published tree.
    let wrong_epoch = forged_row(
        &node_b,
        &file.row,
        &file.stream_id,
        epoch + 1,
        sth.root_hash,
        5,
    )
    .await;
    assert!(matches!(
        receipts::admit_receipt_row(&*node_a.dir, &*node_a.dir, &wrong_epoch, &ledger).await,
        Err(ReceiptRefusal::EpochMismatch { .. })
    ));
    let past_tree = forged_row(&node_b, &file.row, &file.stream_id, epoch, sth.root_hash, 6).await;
    assert!(matches!(
        receipts::admit_receipt_row(&*node_a.dir, &*node_a.dir, &past_tree, &ledger).await,
        Err(ReceiptRefusal::TreeSizeShort { .. })
    ));
    assert_eq!(
        file_row
            .received_by(&node_a.store)
            .await
            .expect("read")
            .len(),
        2,
        "nothing refused was stored"
    );
}
