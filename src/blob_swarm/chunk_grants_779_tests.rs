//! **CIRISEdge#779 — a pulled chunk DAG is not "pulled" until every chunk
//! opens here.**
//!
//! The field (CIRISServer bigfile-quick on v38.0.0): D1 writes a 256 MiB
//! `self` file, 1024 chunks of 256 KiB; D2 pulls it. Each chunk is sealed
//! under its own DEK, and its wrap to D2 is its own content-axis `key_grant`
//! set, which reached D2 in `seq` order at ~2.4 sets/s. The puller waited for
//! the MANIFEST's wrap (#717) but promoted the DAG, reported `Stored` and
//! receipted it (CC 5.3.3.6, #738) once every chunk's BYTES were held. D2's
//! streamed read stopped at chunk 782 with `NotGranted`, naming the FILE's
//! sha rather than chunk 782's.
//!
//! These witnesses run that order on two real SQLite substrates (the
//! `delivery_receipts_738` harness, in-process): the bytes first, the chunk
//! grants after, the last ones held back.
//!
//! **CIRISEdge#797 (persist v53, CIRISPersist#969).** A self/family stream
//! is sealed under one DEK per `(stream, epoch)`, granted by one
//! `key_grant:stream:v1` set per epoch, and each epoch ends in a zero-length
//! terminator chunk at `seq = 2^62 + epoch`. The author here rolls its epoch
//! label every [`EPOCH_CHUNKS`] chunks, so the file is two epochs (seq 0..=2
//! and 3..=4) and "chunks 3 and 4's keys arrive last" is epoch 1's stream
//! set held back: the same order as the field, one set where there were two.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::key_grant::{
    KeyGrantAxis, KeyGrantSet, SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
};
use ciris_persist::federation::{Attestation, FederationDirectory as _, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

use super::pull::{BlobPuller, DagByteFetch, PullConfig, PullOutcome, PullSink};
use crate::files::{FileError, FileRow, FileWrite};
use crate::group_content::{GroupContentError, GroupContentStore as _, PersistGroupContentStore};
use crate::receipts::{self, StreamLog};
use crate::replication::attestation_bind::{Shared, Signers};

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
}

/// 1.3 MiB: four 256 KiB chunks and a tail, seq 0..=4.
const FILE_LEN: usize = 1_300_000;

/// CIRISEdge#797 — the author rolls its epoch label every this many chunks:
/// epoch 0 is seq 0..=2, epoch 1 is seq 3..=4.
const EPOCH_CHUNKS: u64 = 3;

/// The chunks whose key arrives LAST — the field's seq 782..1023 — are
/// epoch 1's: its one stream set is held back.
const LATE: std::ops::RangeInclusive<u64> = 3..=4;
const LATE_EPOCH: u64 = 1;

/// persist's terminator position base (`TERMINATOR_SEQ_BASE`, #969): an
/// epoch's terminator sits at `2^62 + epoch`, after every data chunk.
const TERMINATOR_SEQ_BASE: u64 = 1 << 62;

fn body_of(len: usize, seed: u32) -> Vec<u8> {
    (0..u32::try_from(len).expect("fits"))
        .map(|i| {
            let mixed = i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13;
            u8::try_from(mixed & 0xFF).expect("masked")
        })
        .collect()
}

pub(crate) struct Ident {
    pub(crate) key_id: String,
    seed: u8,
    pub(crate) ed: Ed25519SoftwareSigner,
    pqc: MlDsa65SoftwareSigner,
}

impl Ident {
    pub(crate) fn new(key_id: &str, seed: u8) -> Self {
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

    pub(crate) fn signers(&self) -> (Arc<dyn HardwareSigner>, Arc<dyn PqcSigner>) {
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
        (hw, pqc)
    }
}

pub(crate) struct Node {
    pub(crate) dir: Arc<SqliteBackend>,
    pub(crate) store: PersistGroupContentStore,
    identity: String,
    pub(crate) me: String,
    signer: Arc<crate::identity::LocalSigner>,
}

/// Register `device`'s derived signing key as a node key on `dir`, with an
/// owner binding from `owner` naming it; returns the key id and its signer.
pub(crate) async fn register_node_key(
    dir: &SqliteBackend,
    owner: &Ident,
    device: &Ident,
) -> (String, crate::identity::LocalSigner) {
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
    let (hw, pqc) = device.signers();
    let identity = crate::identity::LocalSigner::new(derived.clone(), hw, Some(pqc));
    let (owner_hw, owner_pqc) = owner.signers();
    let owner_signer =
        crate::identity::LocalSigner::new(owner.key_id.clone(), owner_hw, Some(owner_pqc));
    let binding = crate::replication::attestation_bind::owner_binding_attestation(
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
    (derived, identity)
}

/// A device of `owner` keyed from `device`, with its owner binding and its
/// node-class engine occurrence (`delivery_receipts_738::device`).
pub(crate) async fn device(
    idents: &[&Ident],
    owner: &Ident,
    device: &Ident,
    chunks_per_epoch: Option<u64>,
) -> Node {
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
    let (_, identity) = register_node_key(&dir, owner, device).await;
    let store = PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        dir.clone(),
        &identity,
    )
    .await
    .expect("hybrid content store");
    let store = match chunks_per_epoch {
        Some(n) => store.with_chunks_per_epoch(n),
        None => store,
    };
    let (me, _) = crate::content_occurrence::provision_engine_occurrence(
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

/// Hand `from`'s node key, owner binding and occurrence to `to`.
pub(crate) async fn federate(from: &Node, to: &Node) {
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

struct NoWire;

#[async_trait::async_trait]
impl crate::transport::Transport for NoWire {
    fn id(&self) -> crate::transport::TransportId {
        crate::transport::TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        _bytes: &[u8],
    ) -> Result<crate::transport::TransportSendOutcome, crate::transport::TransportError> {
        Err(crate::transport::TransportError::Unreachable(format!(
            "no wire in this harness ({destination_key_id})"
        )))
    }

    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<crate::transport::InboundFrame>,
    ) -> Result<(), crate::transport::TransportError> {
        std::future::pending::<()>().await;
        Ok(())
    }
}

fn edge_of(node: &Node) -> Arc<crate::Edge> {
    use ciris_persist::federation::FederationDirectory;
    Arc::new(
        crate::Edge::builder()
            .directory(node.dir.clone() as Arc<dyn crate::verify::VerifyDirectory>)
            .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
            .queue(node.dir.clone())
            .signer(node.signer.clone())
            .transport(Arc::new(NoWire) as Arc<dyn crate::transport::Transport>)
            .config(crate::EdgeConfig::default())
            .build()
            .expect("build edge"),
    )
}

fn puller_of(node: &Node, edge: &Arc<crate::Edge>) -> Arc<BlobPuller<SqliteBackend>> {
    puller_with(node, edge, PullConfig::default())
}

fn puller_with(
    node: &Node,
    edge: &Arc<crate::Edge>,
    config: PullConfig,
) -> Arc<BlobPuller<SqliteBackend>> {
    use ciris_persist::federation::FederationDirectory;
    BlobPuller::new(
        Arc::clone(edge),
        node.store.engine().clone(),
        node.dir.clone(),
        node.dir.clone() as Arc<dyn FederationDirectory>,
        node.me.clone(),
        config,
    )
}

/// The author's peer-serve door: the bytes a holder puts on the wire.
struct StoreFetch {
    engine: ciris_persist::Engine,
    peer: String,
    holders: Vec<String>,
}

#[async_trait::async_trait]
impl DagByteFetch for StoreFetch {
    fn holders(&self) -> &[String] {
        &self.holders
    }

    async fn fetch(&self, sha: [u8; 32]) -> Result<Vec<u8>, String> {
        use ciris_persist::federation::blobs::BlobBody;
        match self
            .engine
            .serve_blob_to_peer(&sha, &self.peer)
            .await
            .map_err(|e| e.to_string())?
        {
            BlobBody::Inline(bytes) => Ok(bytes),
            _ => Err("not inline".into()),
        }
    }
}

fn fetch_from(author: &Node, reader: &Node) -> StoreFetch {
    StoreFetch {
        engine: author.store.engine().clone(),
        peer: reader.me.clone(),
        holders: vec![author.me.clone()],
    }
}

struct Published {
    row: Attestation,
    sha: [u8; 32],
    stream_id: String,
    plain: Vec<u8>,
    /// The data chunks' addresses in `seq` order.
    chunks: Vec<[u8; 32]>,
    /// CIRISEdge#797 — every chunk of the stream, terminators included, as
    /// `(seq, plaintext size, address)` in `seq` order.
    stream: Vec<(u64, u64, [u8; 32])>,
}

async fn publish_self_file(author: &Node, owner: &Ident) -> Published {
    let room = crate::self_room::room(&owner.key_id);
    let plain = body_of(FILE_LEN, 0x0779);
    let published = crate::files::publish(
        &*author.dir,
        &author.store,
        Signers {
            node: &author.signer,
            actor: None,
        },
        &FileWrite {
            room: &room,
            bytes: &plain,
            media_type: "video/mp4",
            codec: None,
            filename: Some("bigfile.mp4"),
            asserted_at: ts(),
        },
    )
    .await
    .expect("publish a file");
    assert!(published.pointer.stream_id.is_some(), "a chunk DAG");
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
    let stream: Vec<(u64, u64, [u8; 32])> = author
        .dir
        .stream_chunks(&stream_id)
        .await
        .expect("stream chunks")
        .chunks
        .into_iter()
        .map(|c| (c.seq, c.plaintext_size, c.chunk_sha))
        .collect();
    // CIRISEdge#797 — five data chunks, then one empty terminator per epoch
    // (two epochs: the label rolled at seq 3), sorting after every data chunk.
    let seqs: Vec<u64> = stream.iter().map(|c| c.0).collect();
    assert_eq!(
        seqs,
        vec![0, 1, 2, 3, 4, TERMINATOR_SEQ_BASE, TERMINATOR_SEQ_BASE + 1],
        "four 256 KiB chunks, the tail, and a terminator per epoch"
    );
    assert!(
        stream[5..].iter().all(|c| c.1 == 0),
        "terminators are empty"
    );
    let chunks = stream[..5].iter().map(|c| c.2).collect();
    Published {
        row,
        sha,
        stream_id,
        plain,
        chunks,
        stream,
    }
}

/// The key sets a crossing holds back.
#[derive(Debug, Clone, Default)]
struct Withhold {
    /// Content-axis sets for these rows (the manifest).
    rows: Vec<[u8; 32]>,
    /// CIRISEdge#797 — stream-axis sets for these epochs.
    epochs: Vec<u64>,
}

impl Withhold {
    fn none() -> Self {
        Self::default()
    }

    /// The late chunks' key: epoch 1's stream set.
    fn late() -> Self {
        Self {
            rows: Vec::new(),
            epochs: vec![LATE_EPOCH],
        }
    }
}

/// Apply the author's `key_grant` sets through `reader`'s key-grant door,
/// except those `withhold` names, and hand each admission to `sink` as the
/// bridge's key-grant door does. Returns how many were applied.
async fn cross_keys_except(
    author: &Node,
    reader: &Node,
    withhold: &Withhold,
    sink: Option<&PullSink>,
) -> usize {
    author
        .store
        .engine()
        .emit_pending_key_grants()
        .await
        .expect("emit");
    let held_back: Vec<String> = withhold.rows.iter().map(hex::encode).collect();
    let mut applied = 0;
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
        let set = KeyGrantSet::from_attestation(&s.attestation).expect("a well-formed set");
        match &set.axis {
            KeyGrantAxis::Content { at_rest_sha256, .. } if held_back.contains(at_rest_sha256) => {
                continue;
            }
            KeyGrantAxis::Stream { epoch, .. } if withhold.epochs.contains(epoch) => continue,
            _ => {}
        }
        let admission = reader
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: s.attestation.clone(),
            })
            .await
            .expect("the reader admits the set");
        if let Some(sink) = sink {
            sink.key_grant_admitted(&admission);
        }
        applied += 1;
    }
    applied
}

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

fn receipts_emitted(edge: &crate::Edge) -> u64 {
    edge.metrics()
        .snapshot()
        .delivery_receipts
        .get(receipts::RECEIPT_EMITTED)
        .copied()
        .unwrap_or(0)
}

async fn two_devices() -> (Ident, Node, Node) {
    let alice = Ident::new("alice-fed", 0x11);
    let alice_phone = Ident::new("alice-phone", 0x33);
    let node_a = device(&[&alice], &alice, &alice, Some(EPOCH_CHUNKS)).await;
    let node_b = device(&[&alice, &alice_phone], &alice, &alice_phone, None).await;
    federate(&node_a, &node_b).await;
    federate(&node_b, &node_a).await;
    (alice, node_a, node_b)
}

/// **The pull does not report a DAG Stored, promote it, or receipt it while
/// any chunk lacks this node's wrap; once the grants land it does, and the
/// whole file streams.** Fails on v38.0.0: the second pull reported
/// `Stored` and emitted a receipt with chunks 3 and 4 unopenable.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dag_is_not_stored_until_every_chunk_opens_here_779() {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let file = publish_self_file(&node_a, &alice).await;
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    let puller = puller_of(&node_b, &edge_b);

    // 1. No key at all: the manifest is held and parked (#717).
    assert!(matches!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::DagAwaitingKey { .. }
    ));

    // 2. The manifest's wrap and chunks 0..=2's land; 3 and 4's have not.
    //    Every chunk's BYTES arrive on this pull.
    assert!(cross_keys_except(&node_a, &node_b, &Withhold::late(), None).await > 0);
    let early = puller
        .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
        .await;
    assert!(
        matches!(early, PullOutcome::DagAwaitingKey { retrying: true, .. }),
        "every chunk's bytes are held but chunks {LATE:?} do not open here: the pull must park \
         on their keys, not report the file pulled; got {early:?}"
    );
    for (seq, _, chunk) in &file.stream {
        assert!(
            node_b.dir.has_blob(chunk).await.expect("has_blob"),
            "chunk {seq}'s bytes (terminators too) were adopted and are kept for the resume"
        );
    }
    assert!(
        receipt_rows(&node_b, &file.stream_id).await.is_empty(),
        "no delivery receipt for a file this node cannot read (CC 5.3.3.6)"
    );
    assert_eq!(receipts_emitted(&edge_b), 0);

    // 3. The last grants land: the resume promotes, receipts once, and the
    //    whole file streams through `FileRow::chunks`.
    assert!(cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await > 0);
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    assert_eq!(receipt_rows(&node_b, &file.stream_id).await.len(), 1);
    assert_eq!(receipts_emitted(&edge_b), 1);

    let file_row = FileRow::from_row(&file.row).expect("a file row");
    let mut walk = file_row.chunks(&node_b.store, &node_b.me);
    let mut read = Vec::with_capacity(FILE_LEN);
    let mut items = 0;
    while let Some(item) = walk.next().await {
        read.extend_from_slice(&item.expect("every chunk opens as this node"));
        items += 1;
    }
    assert_eq!(
        items, 5,
        "one item per data chunk; the empty terminators hold no byte"
    );
    assert!(
        read == file.plain,
        "the walk reads the file the author wrote"
    );
}

/// **A range refusal names the CHUNK that refused (seq and its own sha), not
/// the file.** The DAG is promoted here by persist's door directly, the
/// state v38.0.0's puller left in the field, with chunks 3 and 4 unwrapped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_refusal_names_the_chunk_not_the_file_779() {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let file = publish_self_file(&node_a, &alice).await;
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    let puller = puller_of(&node_b, &edge_b);
    cross_keys_except(&node_a, &node_b, &Withhold::late(), None).await;
    assert!(matches!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::DagAwaitingKey { .. }
    ));
    let file_row = FileRow::from_row(&file.row).expect("a file row");
    let aad = crate::group_content::content_aad(
        &file.row.attesting_key_id,
        file.row.asserted_at,
        file_row.pointer.content_field,
    );
    node_b
        .store
        .engine()
        .promote_adopted_manifest_to_dag(&file.sha, &node_b.me, Some(&aad))
        .await
        .expect("promote, as v38.0.0's puller did");

    let mut walk = file_row.chunks(&node_b.store, &node_b.me);
    for seq in 0..3 {
        assert!(
            walk.next().await.expect("an item").is_ok(),
            "chunk {seq} is wrapped to this node"
        );
    }
    let refused = walk.next().await.expect("an item");
    let late = hex::encode(file.chunks[3]);
    let Err(FileError::Unopened(reason)) = refused else {
        panic!("chunk 3 is not wrapped to this node: {refused:?}");
    };
    let said = format!("{reason:?}");
    assert!(
        said.contains(&late) && said.contains("seq 3"),
        "the refusal names chunk 3 by its own sha: {said}"
    );
    // CIRISEdge#797 — and it is the wait, not the verdict: this node is
    // authorized on the file and epoch 1's key has not landed yet.
    assert_eq!(reason.kind(), "awaiting_key", "{said}");
    assert!(
        reason.is_pending(),
        "a chunk's key still arriving is a state to wait through"
    );
    assert!(walk.next().await.is_none(), "a refusal ends the walk");

    // The store's typed error, directly: the file's sha, AND the chunk.
    let layout = file_row
        .layout(&node_b.store, &node_b.me)
        .await
        .expect("layout");
    let extent = layout.chunks[3];
    let err = node_b
        .store
        .open_range(
            crate::group_content::OpenRequest {
                pointer: &file_row.pointer,
                author_key_id: &file.row.attesting_key_id,
                asserted_at: file.row.asserted_at,
                viewer_key_id: &node_b.me,
            },
            extent.offset,
            extent.end_inclusive().expect("non-empty"),
        )
        .await
        .expect_err("chunk 3 is not wrapped to this node");
    // CIRISEdge#797 — persist's `blob_chunk_key_not_yet_granted`, typed:
    // never `NotGranted`, which is the stranger's refusal.
    let GroupContentError::ChunkKeyPending {
        sha256_hex,
        chunk,
        key,
    } = err
    else {
        panic!("ChunkKeyPending: {err:?}");
    };
    assert_eq!(
        sha256_hex,
        hex::encode(file.sha),
        "the read targeted the file"
    );
    assert_eq!((chunk.seq, chunk.sha256_hex), (3, late));
    assert!(
        key.contains("key_grant:stream:v1") && key.contains(&format!("epoch {LATE_EPOCH}")),
        "the key to wait for is epoch 1's stream set: {key}"
    );
}

async fn promoted(node: &Node, sha: &[u8; 32]) -> bool {
    node.dir
        .blob_head(sha)
        .await
        .expect("blob_head")
        .is_some_and(|h| h.storage_kind == "chunk_dag")
}

/// **A DAG parked past its whole retry ladder is still stored when its
/// grants land.** The ladder is bounded and the bridge offers a row once, so
/// before the wake a stall longer than the ladder left the file unpromoted
/// for good, even after every grant arrived. Here the ladder is two attempts
/// 50 ms apart; it runs out with chunks 3 and 4 unwrapped; the last grants
/// land through the key-grant door's hook; the puller's own loop promotes the
/// file and receipts it once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dag_parked_past_its_ladder_is_woken_by_its_grants_779() {
    parked_past_the_ladder_then_woken(false).await;
}

/// **The same for the manifest arm (#717):** no wrap on the manifest
/// either, so the pull parks before a chunk is fetched; the manifest's grant
/// lands after the ladder ran out and wakes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dag_parked_on_its_manifest_past_its_ladder_is_woken_779() {
    parked_past_the_ladder_then_woken(true).await;
}

async fn parked_past_the_ladder_then_woken(manifest_too: bool) {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let file = publish_self_file(&node_a, &alice).await;
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    let puller = puller_with(
        &node_b,
        &edge_b,
        PullConfig {
            // The manifest arm's witness is a booked retry after the wake;
            // a longer ladder keeps one booked for ~350 ms, not one tick.
            max_attempts: if manifest_too { 4 } else { 2 },
            retry_backoff: std::time::Duration::from_millis(50),
            ..PullConfig::default()
        },
    );
    let (sink, run) = Arc::clone(&puller).start();

    // Every key but chunks 3 and 4's — epoch 1's stream set — (and the
    // manifest's, on that arm).
    let mut withhold = Withhold::late();
    if manifest_too {
        withhold.rows.push(file.sha);
    }
    cross_keys_except(&node_a, &node_b, &withhold, Some(&sink)).await;
    assert!(matches!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::DagAwaitingKey { .. }
    ));

    // The stall: longer than the whole ladder. The loop's retries run out.
    // "No retry booked" is not "spent": a due retry leaves the ledger before
    // its pull books the next rung, so wait on the puller's own answer.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !puller.ladder_spent(file.sha) {
        assert!(std::time::Instant::now() < deadline, "the ladder runs out");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        puller.ladder_spent(file.sha),
        "nothing is left on the ladder"
    );
    assert!(!promoted(&node_b, &file.sha).await);
    assert!(receipt_rows(&node_b, &file.stream_id).await.is_empty());

    // The last grants land. Nothing re-offers the row; the grant wakes it.
    assert!(cross_keys_except(&node_a, &node_b, &Withhold::none(), Some(&sink)).await > 0);
    if manifest_too {
        // The woken pull opens the manifest and goes for the chunks, which
        // this harness's loop has no wire to fetch (`NoWire`): it fails the
        // fetch and books a retry from a fresh ladder. That retry is the
        // witness: without the wake nothing runs and nothing is booked.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !puller.retry_booked(file.sha) {
            assert!(
                std::time::Instant::now() < deadline,
                "the manifest is wrapped here now, and the parked DAG was never re-pulled"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        drop(sink);
        run.abort();
        return;
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !promoted(&node_b, &file.sha).await {
        assert!(
            std::time::Instant::now() < deadline,
            "chunks 3 and 4 are wrapped here now, and the parked DAG was never re-pulled"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // The loop's pull promotes, returns `Stored`, and only then signs and
    // stores the receipt (`on_file_pulled`), so `promoted` turning true does
    // not mean the receipt is there yet. Wait for the receipt itself (a fixed
    // 300 ms lost this race on a loaded CI runner, #798), then let any
    // duplicate wake run before counting.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while receipt_rows(&node_b, &file.stream_id).await.is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the woken pull promoted the file but never receipted it"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(receipt_rows(&node_b, &file.stream_id).await.len(), 1);
    assert_eq!(receipts_emitted(&edge_b), 1);

    let file_row = FileRow::from_row(&file.row).expect("a file row");
    let mut walk = file_row.chunks(&node_b.store, &node_b.me);
    let mut read = Vec::with_capacity(FILE_LEN);
    while let Some(item) = walk.next().await {
        read.extend_from_slice(&item.expect("every chunk opens as this node"));
    }
    assert!(
        read == file.plain,
        "the walk reads the file the author wrote"
    );
    drop(sink);
    run.abort();
}

/// **CIRISEdge#797 — a multi-epoch v4 DAG, its terminators held, reads and
/// range-reads as the file.** The file is two stream epochs (seq 0..=2 and
/// 3..=4) with an empty terminator per epoch at `2^62 + epoch`: the pull
/// adopts all seven chunks, each at its manifest epoch, and promotes; the
/// layout carries the terminators as empty extents at the file's end, never
/// as bytes; whole, streamed and ranged reads (one across the epoch
/// boundary) are the author's bytes; and the one receipt's `K` is the
/// stream's tree size, the terminators included, as persist's STH commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // every read shape over one pulled file, in order, on purpose
async fn a_multi_epoch_dag_reads_and_range_reads_across_its_terminators_797() {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let file = publish_self_file(&node_a, &alice).await;
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await;
    let puller = puller_of(&node_b, &edge_b);
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    let held: Vec<(u64, u64, [u8; 32])> = node_b
        .dir
        .stream_chunks(&file.stream_id)
        .await
        .expect("stream chunks")
        .chunks
        .into_iter()
        .map(|c| (c.seq, c.plaintext_size, c.chunk_sha))
        .collect();
    assert_eq!(
        held, file.stream,
        "every chunk, terminators too, at its position"
    );

    let file_row = FileRow::from_row(&file.row).expect("a file row");
    let layout = file_row
        .layout(&node_b.store, &node_b.me)
        .await
        .expect("layout");
    assert_eq!(layout.total_size, FILE_LEN as u64);
    let extents: Vec<(u64, u64, u64)> = layout
        .chunks
        .iter()
        .map(|c| (c.seq, c.offset, c.size))
        .collect();
    let chunk = 256 * 1024u64;
    assert_eq!(
        extents,
        vec![
            (0, 0, chunk),
            (1, chunk, chunk),
            (2, 2 * chunk, chunk),
            (3, 3 * chunk, chunk),
            (4, 4 * chunk, FILE_LEN as u64 - 4 * chunk),
            (TERMINATOR_SEQ_BASE, FILE_LEN as u64, 0),
            (TERMINATOR_SEQ_BASE + 1, FILE_LEN as u64, 0),
        ],
        "the terminators are empty extents at the end: no offset moves"
    );
    assert!(layout.chunks[5].end_inclusive().is_none());

    let whole = file_row
        .open(&node_b.store, &node_b.me)
        .await
        .expect("the whole file opens");
    assert!(whole == file.plain, "whole read: the author's bytes");
    let mut walk = file_row.chunks(&node_b.store, &node_b.me);
    let mut streamed = Vec::with_capacity(FILE_LEN);
    let mut items = 0;
    while let Some(item) = walk.next().await {
        let item = item.expect("every chunk opens");
        assert!(!item.is_empty(), "no empty item reaches the reader");
        streamed.extend_from_slice(&item);
        items += 1;
    }
    assert_eq!(items, 5);
    assert!(streamed == file.plain, "streamed read: the author's bytes");

    // Ranges: inside epoch 0, across the epoch boundary (chunk 2 → 3), inside
    // epoch 1, the last byte; past the end is refused, naming the size.
    let boundary = 3 * chunk;
    for (offset, len) in [
        (0u64, 10u64),
        (boundary - 100, 200),
        (boundary + 5, 1000),
        (FILE_LEN as u64 - 1, 1),
    ] {
        let got = file_row
            .open_range(&node_b.store, &node_b.me, offset, len)
            .await
            .unwrap_or_else(|e| panic!("range {offset}+{len}: {e}"));
        let at = usize::try_from(offset).expect("fits");
        let end = at + usize::try_from(len).expect("fits");
        assert!(got == file.plain[at..end], "range {offset}+{len}");
    }
    assert!(matches!(
        file_row
            .open_range(&node_b.store, &node_b.me, FILE_LEN as u64, 1)
            .await,
        Err(FileError::RangeNotSatisfiable { .. })
    ));

    let receipts = StreamLog::list_delivery_receipts_for(&*node_b.dir, &file.stream_id, 16)
        .await
        .expect("receipts");
    assert_eq!(receipts.len(), 1, "one receipt");
    assert_eq!(
        receipts[0].k,
        file.stream.len() as u64,
        "K is the stream's tree size: the data chunks and a terminator per epoch"
    );
}
