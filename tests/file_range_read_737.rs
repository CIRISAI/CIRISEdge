//! CIRISEdge#737 (lane 5 of #734) — **a file above persist's 64 MiB whole-read
//! cap is read by range and by chunk, on the device that pulled it.**
//!
//! A is alice's laptop, B her phone (one owner, two node keys). A publishes a
//! 100 MiB file into alice's self room through the file door — 400 × 256 KiB
//! chunks sealed at `invisible_encrypted`, a v2 manifest — and B pulls it
//! through the real DAG doors (`BlobPuller::pull_dag_with` over a fetcher that
//! reads A's store through persist's peer-serve door: `adopt_sealed_blob`,
//! `open_sealed_manifest_as`, `adopt_sealed_chunk` × 400,
//! `promote_adopted_manifest_to_dag`). On B:
//!
//! - a whole `FileRow::open` is `FileError::AboveWholeReadCap`, by name, not a
//!   persist error (RR3); `describe` opens the descriptor once;
//! - `FileRow::chunks()` yields exactly the manifest's 400 chunks in `seq`
//!   order, each ≤ 1 MiB, concatenating byte-identical (RR1), with the walk's
//!   peak live allocation over its baseline under 32 MiB — measured by a
//!   counting global allocator in this binary, against a 100 MiB file (RR4);
//! - `FileRow::open_range` is byte-identical at the first byte, a mid-chunk
//!   window, the last byte, a window across two chunks and across many; a
//!   window past the end, at the end or empty is `RangeNotSatisfiable`
//!   naming the size; one above the cap is `AboveWholeReadCap` (RR2).
//!
//! `FSD/CONTENT_TRANSFER.md` §6.7.3.

#![cfg(feature = "transport-reticulum")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::files::{FileError, FileRow, WHOLE_READ_CAP_BYTES};
use ciris_edge::group_content::PersistGroupContentStore;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory as _;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

// ─── RR4: a counting allocator — live bytes and their peak ──────────────

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Counts live bytes across the whole process. The witness resets the peak
/// to the live count before the chunk walk and reads it after: the delta is
/// what the walk buffered at its worst, whoever allocated it.
struct Counting;

fn grew(by: usize) {
    let now = LIVE.fetch_add(by, Ordering::SeqCst) + by;
    PEAK.fetch_max(now, Ordering::SeqCst);
}

fn shrank(by: usize) {
    LIVE.fetch_sub(by, Ordering::SeqCst);
}

// SAFETY: every path delegates to `System` and only adjusts two atomics.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        shrank(layout.size());
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grew(layout.size());
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                shrank(layout.size() - new_size);
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

fn live_bytes() -> usize {
    LIVE.load(Ordering::SeqCst)
}

fn reset_peak() -> usize {
    let now = live_bytes();
    PEAK.store(now, Ordering::SeqCst);
    now
}

fn peak_bytes() -> usize {
    PEAK.load(Ordering::SeqCst)
}

// ─── The two-device harness (as `tests/blob_federation_e2e.rs` builds it) ──

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
}

/// One federation identity, reproducible from a seed.
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

/// One node: its own substrate, its own content store.
struct Node {
    dir: Arc<SqliteBackend>,
    store: PersistGroupContentStore,
    identity: String,
    me: String,
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

async fn node(idents: &[&Ident], signer: &Ident) -> Node {
    build_node_with(idents, signer, signer).await
}

/// A SECOND device of `owner` (CIRISEdge#646).
async fn device_of(idents: &[&Ident], owner: &Ident, device: &Ident) -> Node {
    build_node_with(idents, owner, device).await
}

async fn build_node_with(idents: &[&Ident], owner: &Ident, signer: &Ident) -> Node {
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
    let ed_pub = signer.ed.public_key().await.expect("pubkey");
    let derived = ciris_verify_core::fedcode::derive_key_id(signer.ed.current_alias(), &ed_pub);
    let mut rec = signer.record().await;
    rec.key_id = derived.clone();
    rec.identity_ref = derived.clone();
    rec.scrub_key_id = derived.clone();
    rec.identity_type = "node".to_string();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the derived signing key");

    let hw: Arc<dyn HardwareSigner> = Arc::new(
        Ed25519SoftwareSigner::from_bytes(&[signer.seed; 32], signer.ed.current_alias())
            .expect("rebuild the registered signer"),
    );
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(
            &[signer.seed ^ 0x55; 32],
            format!("{}-pqc", signer.key_id),
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
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        &owner.key_id,
        &derived,
        ts(),
        &owner_signer,
    )
    .await
    .expect("build this node's owner binding");
    dir.put_attestation_authored(ciris_persist::federation::SignedAttestation {
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

/// `to` learns `from`'s derived key, owner binding and published occurrence.
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
    let rows = ciris_persist::federation::FederationDirectory::list_attestations_since(
        &*from.dir, None, 256,
    )
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
                .apply_replicated_attestation(ciris_persist::federation::SignedAttestation {
                    attestation: att,
                })
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
        .expect("the engine occurrence is ON the signed plane");
    to.dir
        .put_identity_occurrence(occ)
        .await
        .expect("admit the far node's published occurrence through the gated door");
}

/// One end of an in-process wire between two `Edge`s.
struct WireEnd {
    peer_key_id: String,
    to_peer: tokio::sync::mpsc::Sender<Vec<u8>>,
    inbound: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
}

fn wire(a_key: &str, b_key: &str) -> (Arc<WireEnd>, Arc<WireEnd>) {
    let (a_to_b, b_inbound) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    let (b_to_a, a_inbound) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    (
        Arc::new(WireEnd {
            peer_key_id: b_key.to_owned(),
            to_peer: a_to_b,
            inbound: tokio::sync::Mutex::new(Some(a_inbound)),
        }),
        Arc::new(WireEnd {
            peer_key_id: a_key.to_owned(),
            to_peer: b_to_a,
            inbound: tokio::sync::Mutex::new(Some(b_inbound)),
        }),
    )
}

#[async_trait::async_trait]
impl ciris_edge::transport::Transport for WireEnd {
    fn id(&self) -> ciris_edge::transport::TransportId {
        ciris_edge::transport::TransportId::HTTP
    }

    async fn send(
        &self,
        destination_key_id: &str,
        bytes: &[u8],
    ) -> Result<ciris_edge::transport::TransportSendOutcome, ciris_edge::transport::TransportError>
    {
        if destination_key_id != self.peer_key_id {
            return Err(ciris_edge::transport::TransportError::Unreachable(format!(
                "this wire reaches only {}, not {destination_key_id}",
                self.peer_key_id
            )));
        }
        self.to_peer
            .send(bytes.to_vec())
            .await
            .map_err(|e| ciris_edge::transport::TransportError::Io(e.to_string()))?;
        Ok(ciris_edge::transport::TransportSendOutcome::Delivered)
    }

    async fn listen(
        &self,
        sink: tokio::sync::mpsc::Sender<ciris_edge::transport::InboundFrame>,
    ) -> Result<(), ciris_edge::transport::TransportError> {
        let mut rx =
            self.inbound.lock().await.take().ok_or_else(|| {
                ciris_edge::transport::TransportError::Config("listen twice".into())
            })?;
        while let Some(envelope_bytes) = rx.recv().await {
            let frame = ciris_edge::transport::InboundFrame {
                envelope_bytes,
                transport: ciris_edge::transport::TransportId::HTTP,
                received_at: chrono::Utc::now(),
                source_key_id: None,
                link_key_id: None,
                arrival_scope: None,
                reply_path: None,
            };
            if sink.send(frame).await.is_err() {
                break;
            }
        }
        Ok(())
    }
}

/// An `Edge` on `node`, over `transport`, serving this node's blobs, running.
async fn spawn_edge(
    node: &Node,
    transport: Arc<WireEnd>,
) -> (Arc<ciris_edge::Edge>, tokio::sync::watch::Sender<bool>) {
    use ciris_persist::federation::FederationDirectory;
    let edge = ciris_edge::Edge::builder()
        .directory(node.dir.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(node.dir.clone() as Arc<dyn FederationDirectory>)
        .queue(node.dir.clone())
        .signer(node.signer.clone())
        .transport(transport as Arc<dyn ciris_edge::transport::Transport>)
        .blob_chunk_source(Arc::new(
            ciris_edge::blob_swarm::PersistBlobChunkSource::new(node.store.engine().clone()),
        ))
        .config(ciris_edge::EdgeConfig::default())
        .build()
        .expect("build edge");
    let edge = Arc::new(edge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runner = Arc::clone(&edge);
    tokio::spawn(async move {
        let _ = runner.run(shutdown_rx).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    (edge, shutdown_tx)
}

/// A `DagByteFetch` that reads the holder's store through persist's
/// peer-serve door — the bytes a `PersistBlobChunkSource` would put on the
/// wire — so the puller's own verification is what is exercised.
struct StoreFetch {
    engine: ciris_persist::Engine,
    peer: String,
    holders: Vec<String>,
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
        let BlobBody::Inline(bytes) = body else {
            return Err("not inline".into());
        };
        Ok(bytes)
    }
}

async fn rows_of(node: &Node, type_prefix: &str) -> usize {
    use ciris_persist::federation::FederationDirectory;
    node.dir
        .list_attestations_since(None, 5000)
        .await
        .expect("list rows")
        .into_iter()
        .filter(|a| a.attestation.attestation_type.starts_with(type_prefix))
        .count()
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

/// A deterministic, incompressible-looking body of `len` bytes.
fn body_of(len: usize, seed: u32) -> Vec<u8> {
    (0..u32::try_from(len).expect("fits"))
        .map(|i| {
            let mixed = i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 13;
            u8::try_from(mixed & 0xFF).expect("masked")
        })
        .collect()
}

const MIB: usize = 1024 * 1024;

/// **RR1–RR4** — the 100 MiB self file, on the owner's other device.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "CIRISEdge#797: persist v53 streams carry an epoch terminator chunk (#969); the reader adopts v4 stream-epoch DAGs in #797"]
#[allow(clippy::too_many_lines)] // one file, every read shape, in order, on purpose
async fn a_100_mib_self_file_streams_on_the_owners_other_device_by_chunk_and_by_range() {
    use ciris_edge::blob_swarm::{BlobPuller, PullConfig, PullOutcome};
    use ciris_edge::files::Descriptor;
    use ciris_edge::group_content::store::CHUNK_BYTES;
    use ciris_persist::federation::blobs::{BlobStorage as _, DEFAULT_INLINE_BYTES_CAP};
    use ciris_persist::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
    };
    use ciris_persist::federation::types::cohort_scope::CryptoTier;
    use ciris_persist::federation::FederationDirectory;
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let alice_phone = Ident::new("alice-phone", 0x33);
    let node_a = node(&[&alice], &alice).await;
    let node_b = device_of(&[&alice, &alice_phone], &alice, &alice_phone).await;
    federate(&node_b, &node_a).await;
    federate(&node_a, &node_b).await;
    let (wire_a, wire_b) = wire(&node_a.me, &node_b.me);
    let (_edge_a, _stop_a) = spawn_edge(&node_a, wire_a).await;
    let (edge_b, _stop_b) = spawn_edge(&node_b, wire_b).await;

    // ── A publishes 100 MiB into alice's self room through the file door ──
    let file_len = 100 * MIB;
    assert!(
        file_len as u64 > WHOLE_READ_CAP_BYTES,
        "the witness file is above persist's whole-read cap"
    );
    let plain = body_of(file_len, 0x0737);
    let room = ciris_edge::self_room::room(&alice.key_id);
    let published = ciris_edge::files::publish(
        &*node_a.dir,
        &node_a.store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &node_a.signer,
            actor: None,
        },
        &ciris_edge::files::FileWrite {
            room: &room,
            bytes: &plain,
            media_type: "application/octet-stream",
            codec: None,
            filename: Some("holiday-100.bin"),
            asserted_at: ts(),
        },
    )
    .await
    .expect("publish a 100 MiB file into alice's self room");
    assert_eq!(published.tier, CryptoTier::InvisibleEncrypted);
    let stream_id = published
        .pointer
        .stream_id
        .clone()
        .expect("over the bound: a chunk DAG");
    assert_eq!(published.pointer.size, Some(file_len as u64));
    let sha: [u8; 32] = hex::decode(&published.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let chunk_count = file_len.div_ceil(CHUNK_BYTES);
    assert_eq!(chunk_count, 400, "100 MiB as 256 KiB segments");
    assert_eq!(
        node_a
            .dir
            .stream_chunks(&stream_id)
            .await
            .expect("A's stream")
            .chunks
            .len(),
        chunk_count
    );
    let crossed_id = match &published.shared {
        ciris_edge::replication::attestation_bind::Shared::Placed { attestation_id }
        | ciris_edge::replication::attestation_bind::Shared::AlreadyThere { attestation_id } => {
            attestation_id.clone()
        }
        other @ ciris_edge::replication::attestation_bind::Shared::AwaitingActor { .. } => {
            panic!("the self file must cross: {other:?}")
        }
    };
    let row = node_a
        .dir
        .get_attestation(&crossed_id)
        .await
        .expect("read")
        .expect("the crossed row");
    node_b
        .dir
        .apply_replicated_attestation(ciris_persist::federation::SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .expect("B admits the crossed row");

    // ── The keys cross: a set per chunk and one for the manifest ──
    node_a
        .store
        .engine()
        .emit_pending_key_grants()
        .await
        .expect("A emits");
    let sets: Vec<_> = node_a
        .dir
        .list_attestations_since(None, 5000)
        .await
        .expect("list A's rows")
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
        .collect();
    assert!(
        sets.len() > chunk_count,
        "a set per chunk and the manifest: {}",
        sets.len()
    );
    for s in &sets {
        node_b
            .store
            .engine()
            .apply_replicated_key_grant(SignedKeyGrantSet {
                attestation: s.attestation.clone(),
            })
            .await
            .expect("B applies A's set");
    }

    // ── B pulls through the real DAG doors (the #733 pull path) ──
    let puller = BlobPuller::new(
        Arc::clone(&edge_b),
        node_b.store.engine().clone(),
        node_b.dir.clone(),
        node_b.dir.clone() as Arc<dyn FederationDirectory>,
        node_b.me.clone(),
        PullConfig::default(),
    );
    let fetch = StoreFetch {
        engine: node_a.store.engine().clone(),
        peer: node_b.me.clone(),
        holders: vec![node_a.me.clone()],
    };
    assert_eq!(
        puller.pull_dag_with(&row, sha, &fetch).await,
        PullOutcome::Stored { announced: false },
        "a 100 MiB sealed DAG pulls chunk-wise: the whole-read cap governs reads, not pulls \
         (refusals {:?})",
        edge_b.metrics().snapshot().blob_pull_refusals
    );
    let head = node_b
        .dir
        .blob_head(&sha)
        .await
        .expect("blob_head")
        .expect("held");
    assert_eq!(head.storage_kind, "chunk_dag", "promoted on B");
    assert_eq!(
        node_b
            .dir
            .stream_chunks(&stream_id)
            .await
            .expect("B's stream")
            .chunks
            .len(),
        chunk_count,
        "every chunk adopted at its position"
    );
    assert_eq!(
        rows_of(&node_b, "holds_bytes:").await,
        0,
        "CC 5.2: no holder claim for self bytes"
    );
    drop(fetch);

    let file = FileRow::from_row(&row).expect("a file row");

    // ── RR3: whole is refused BY NAME; the descriptor opens once ──
    let refused = file
        .open(&node_b.store, &node_b.me)
        .await
        .expect_err("100 MiB does not open whole");
    assert_eq!(
        refused,
        FileError::AboveWholeReadCap {
            attestation_id: file.attestation_id.clone(),
            bytes: file_len as u64,
            cap: WHOLE_READ_CAP_BYTES,
        },
        "the named refusal, not persist's cap error"
    );
    assert_eq!(refused.kind(), "above_whole_read_cap");
    assert!(
        file.open_described(&node_b.store, &node_b.me)
            .await
            .is_err_and(|e| matches!(e, FileError::AboveWholeReadCap { .. })),
        "open_described is the whole read, capped the same way"
    );
    assert_eq!(
        file.describe(&node_b.store, &node_b.me)
            .await
            .expect("the descriptor opens on its own"),
        Descriptor::Opened {
            format: "application/octet-stream".into(),
            codec: None,
            name: Some("holiday-100.bin".into()),
        }
    );

    // ── The layout B walks: the manifest's 400 chunks, in seq order ──
    let layout = file
        .layout(&node_b.store, &node_b.me)
        .await
        .expect("B opens the layout");
    assert_eq!(layout.stream_id, stream_id);
    assert_eq!(layout.total_size, file_len as u64);
    assert_eq!(layout.chunks.len(), chunk_count);
    let mut expect_off = 0u64;
    for (i, c) in layout.chunks.iter().enumerate() {
        assert_eq!(c.seq, i as u64, "seq order");
        assert_eq!(c.offset, expect_off, "contiguous from 0");
        assert_eq!(c.size, CHUNK_BYTES as u64, "every segment is 256 KiB");
        expect_off += c.size;
    }

    // ── RR1 + RR4: the chunk walk, byte-identical, bounded ──
    let baseline = reset_peak();
    let mut walk = file.chunks(&node_b.store, &node_b.me);
    let mut items = 0usize;
    let mut off = 0usize;
    let mut largest = 0usize;
    while let Some(item) = walk.next().await {
        let item = item.unwrap_or_else(|e| panic!("chunk {items}: {e}"));
        assert!(
            item.len() <= DEFAULT_INLINE_BYTES_CAP,
            "an item is at most persist's inline cap: {}",
            item.len()
        );
        assert_eq!(
            item.len() as u64,
            layout.chunks[items].size,
            "item {items} is exactly the manifest's chunk"
        );
        assert!(
            item.as_slice() == &plain[off..off + item.len()],
            "chunk {items} byte-identical at offset {off}"
        );
        off += item.len();
        largest = largest.max(item.len());
        items += 1;
    }
    let peak_over_baseline = peak_bytes().saturating_sub(baseline);
    drop(walk);
    eprintln!(
        "RR4: chunk walk of {file_len} bytes in {items} items; peak live allocation over the \
         baseline = {peak_over_baseline} bytes (~{} MiB, ~{} chunks of {} bytes)",
        peak_over_baseline / MIB,
        peak_over_baseline / CHUNK_BYTES,
        CHUNK_BYTES,
    );
    assert_eq!(items, chunk_count, "one item per manifest chunk");
    assert_eq!(off, file_len, "the walk covered the whole file");
    assert_eq!(largest, CHUNK_BYTES);
    assert!(
        peak_over_baseline < 32 * MIB,
        "RR4: the walk's peak live allocation over its baseline is {peak_over_baseline} bytes — \
         it must stay a constant number of chunks (< 32 MiB) while the file is {file_len} bytes; \
         a whole read would be ≥ {file_len}"
    );

    // ── RR2: windows, across chunk boundaries, byte-identical ──
    let c = CHUNK_BYTES;
    let windows: [(usize, usize, &str); 6] = [
        (0, 1, "the first byte"),
        (5 * c + 1000, 4096, "a mid-chunk window"),
        (file_len - 1, 1, "the last byte"),
        (7 * c - 100, 200, "a window across chunks 6|7"),
        (3 * c + 5, 3 * c, "a window across four chunks"),
        (c - 1, 2, "the two bytes either side of the first boundary"),
    ];
    for (offset, len, what) in windows {
        let got = file
            .open_range(&node_b.store, &node_b.me, offset as u64, len as u64)
            .await
            .unwrap_or_else(|e| panic!("{what}: {e}"));
        assert_eq!(got.len(), len, "{what}: exactly len");
        assert!(
            got.as_slice() == &plain[offset..offset + len],
            "{what}: byte-identical"
        );
    }
    // Past the end: refused by name, naming the size — never clamped.
    assert_eq!(
        file.open_range(&node_b.store, &node_b.me, file_len as u64 - 10, 11)
            .await
            .expect_err("len past EOF"),
        FileError::RangeNotSatisfiable {
            attestation_id: file.attestation_id.clone(),
            offset: file_len as u64 - 10,
            len: 11,
            size: Some(file_len as u64),
        }
    );
    assert!(matches!(
        file.open_range(&node_b.store, &node_b.me, file_len as u64, 1)
            .await
            .expect_err("offset at EOF"),
        FileError::RangeNotSatisfiable { size: Some(s), .. } if s == file_len as u64
    ));
    assert!(matches!(
        file.open_range(&node_b.store, &node_b.me, 0, 0)
            .await
            .expect_err("an empty range"),
        FileError::RangeNotSatisfiable { len: 0, .. }
    ));
    assert!(matches!(
        file.open_range(&node_b.store, &node_b.me, 0, WHOLE_READ_CAP_BYTES + 1)
            .await
            .expect_err("a window above the cap"),
        FileError::AboveWholeReadCap { bytes, .. } if bytes == WHOLE_READ_CAP_BYTES + 1
    ));

    // A stranger's occurrence opens nothing, by chunk or by range.
    assert_eq!(
        file.open_range(&node_b.store, "stranger-occ", 0, 1)
            .await
            .expect_err("a stranger")
            .kind(),
        "not_granted"
    );
    let mut stranger = file.chunks(&node_b.store, "stranger-occ");
    assert_eq!(
        stranger
            .next()
            .await
            .expect("one item")
            .expect_err("a stranger")
            .kind(),
        "not_granted"
    );
    assert!(stranger.next().await.is_none(), "a refusal ends the walk");
}
