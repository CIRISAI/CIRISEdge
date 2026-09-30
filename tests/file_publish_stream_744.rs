//! CIRISEdge#744 (lane 8 of #734) — **stream the WRITE**: `files::publish_stream`
//! seals a file chunk by chunk from a reader, so a 2 GiB publish holds a few
//! chunks, never the file.
//!
//! - **SW1** a 2 GiB self file (`invisible_encrypted`) published from a
//!   generating reader (deterministic bytes, never materialized, handed out in
//!   jagged reads), with the publish's peak live allocation over its baseline
//!   bounded by a counting global allocator; then read back ON THE AUTHOR via
//!   `FileRow::chunks()`, hashing to the generator's sha256. `L8_STREAM_BYTES`
//!   overrides the size (256 MiB when the disk cannot take 2 GiB).
//! - **SW2** a short reader (declared 10 MiB, yields 9 MiB) is
//!   `FileError::DeclaredLengthMismatch{declared, read}` by name, leaves no
//!   manifest and no `file:v1` row, and the chunks it wrote are evicted —
//!   `federation_blob_bytes` back to where it was; a long reader and a short
//!   inline reader are refused the same way.
//! - **SW3** a 200 KiB (inline) and a 1.3 MiB (DAG) file through `publish` and
//!   through `publish_stream` produce the same row shape and pointer modulo
//!   instants and per-write randomness, and read identically.
//!
//! `FSD/CONTENT_TRANSFER.md` §6.7.4.

// A 64-bit test host, byte arithmetic on a generator, MiB for a log line; and
// each witness is one scenario, in order, on purpose.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::too_many_lines
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::files::{FileError, FileRow, FileStreamWrite, FileWrite, PublishedFile};
use ciris_edge::group_content::PersistGroupContentStore;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory as _;
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::{Digest as _, Sha256};

// ─── A counting allocator — live bytes and their peak (as #737 counts) ───

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Counts live bytes across the whole process. The witness resets the peak
/// to the live count before the publish and reads it after: the delta is
/// what the write buffered at its worst, whoever allocated it (Rust heap —
/// SQLite's own `malloc` is not the global allocator, and is bounded by its
/// page cache, not by the file).
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

// ─── The author node (as `tests/file_range_read_737.rs` builds it) ──

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
    me: String,
    signer: Arc<ciris_edge::identity::LocalSigner>,
}

/// The owner's node over `path` (`":memory:"`, or a file for the 2 GiB
/// witness — an in-memory SQLite would hold the whole file in RAM, which is
/// exactly the residency this lane removes from edge).
async fn node_at(path: &str, idents: &[&Ident], signer: &Ident) -> Node {
    build_node_with(path, idents, signer, signer).await
}

async fn build_node_with(path: &str, idents: &[&Ident], owner: &Ident, signer: &Ident) -> Node {
    let dir = FederationDirectorySqlite::open(path)
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
        me,
        signer: Arc::new(identity),
    }
}

// ─── The generating reader ──────────────────────────────────────────────

/// The byte at `pos` of generator `seed` — deterministic, incompressible-
/// looking, computable anywhere (so the witness never holds the file).
fn byte_at(pos: u64, seed: u64) -> u8 {
    (pos.wrapping_add(seed).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 29) as u8
}

/// The first `len` bytes of generator `seed`, materialized — for the small
/// files only.
fn body_of(len: usize, seed: u64) -> Vec<u8> {
    (0..len as u64).map(|p| byte_at(p, seed)).collect()
}

/// An `AsyncRead` yielding `len` generated bytes, at most `stride` per read
/// (a jagged pace, as a socket or a multipart body hands them over), hashing
/// what it hands out.
struct Gen {
    pos: u64,
    len: u64,
    seed: u64,
    stride: usize,
    sha: Sha256,
}

impl Gen {
    fn new(len: u64, seed: u64) -> Self {
        Self {
            pos: 0,
            len,
            seed,
            // Prime, so reads straddle every chunk boundary differently.
            stride: 100_003,
            sha: Sha256::new(),
        }
    }
}

impl tokio::io::AsyncRead for Gen {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let left = me.len - me.pos;
        let n = (buf.remaining() as u64).min(left).min(me.stride as u64) as usize;
        let dst = buf.initialize_unfilled_to(n);
        for (i, b) in dst.iter_mut().enumerate() {
            *b = byte_at(me.pos + i as u64, me.seed);
        }
        me.sha.update(&dst[..n]);
        buf.advance(n);
        me.pos += n as u64;
        Poll::Ready(Ok(()))
    }
}

/// The sha256 of `len` generated bytes, computed without holding them.
fn gen_sha(len: u64, seed: u64) -> [u8; 32] {
    let mut sha = Sha256::new();
    let mut block = vec![0u8; 1 << 20];
    let mut pos = 0u64;
    while pos < len {
        let n = (len - pos).min(block.len() as u64) as usize;
        for (i, b) in block[..n].iter_mut().enumerate() {
            *b = byte_at(pos + i as u64, seed);
        }
        sha.update(&block[..n]);
        pos += n as u64;
    }
    sha.finalize().into()
}

// ─── Helpers ────────────────────────────────────────────────────────────

const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ciris_edge=info")),
        )
        .with_test_writer()
        .try_init();
}

fn signers(node: &Node) -> ciris_edge::replication::attestation_bind::Signers<'_> {
    ciris_edge::replication::attestation_bind::Signers {
        node: &node.signer,
        actor: None,
    }
}

fn stream_write<'a>(
    room: &'a ciris_edge::scope_room::ScopeRoom,
    len: u64,
    name: &'a str,
    at: chrono::DateTime<chrono::Utc>,
) -> FileStreamWrite<'a> {
    FileStreamWrite {
        room,
        declared_len: len,
        media_type: "application/octet-stream",
        codec: None,
        filename: Some(name),
        asserted_at: at,
    }
}

/// Every `file:v1` row this node holds, any tier.
async fn file_rows(node: &Node) -> usize {
    node.dir
        .list_attestations_since(None, 100_000)
        .await
        .expect("list rows")
        .into_iter()
        .filter(|a| {
            a.attestation.attestation_envelope.get("dimension")
                == Some(&serde_json::json!(ciris_edge::files::FILE_DIMENSION))
        })
        .count()
}

async fn rows_with_prefix(node: &Node, prefix: &str) -> usize {
    node.dir
        .list_attestations_since(None, 100_000)
        .await
        .expect("list rows")
        .into_iter()
        .filter(|a| a.attestation.attestation_type.starts_with(prefix))
        .count()
}

async fn drive_len(node: &Node, room: &ciris_edge::scope_room::ScopeRoom) -> usize {
    ciris_edge::files::in_room(node.store.engine(), room, &node.me, 100, None)
        .await
        .expect("the drive lists")
        .files
        .len()
}

fn vm_hwm_kib() -> Option<u64> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find(|l| l.starts_with("VmHWM:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

/// **SW1** — 2 GiB from a generating reader, a few chunks resident, read
/// back byte-identical on the author.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_2_gib_self_file_publishes_from_a_reader_holding_a_few_chunks() {
    use ciris_edge::group_content::store::CHUNK_BYTES;
    use ciris_persist::federation::types::cohort_scope::CryptoTier;
    init_tracing();
    let len: u64 = std::env::var("L8_STREAM_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2048 * MIB);
    // File-backed, under the crate's target dir (on /home), never tmpfs.
    let tmp = tempfile::Builder::new()
        .prefix("l8-sw1-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .expect("tempdir");
    let db = tmp.path().join("author.sqlite");
    let alice = Ident::new("alice-fed", 0x11);
    let node = node_at(db.to_str().expect("utf-8 path"), &[&alice], &alice).await;
    let room = ciris_edge::self_room::room(&alice.key_id);
    let seed = 0x0744;
    let want = gen_sha(len, seed);

    let baseline = reset_peak();
    let started = std::time::Instant::now();
    let published = ciris_edge::files::publish_stream(
        &*node.dir,
        &node.store,
        signers(&node),
        &stream_write(&room, len, "big.bin", ts()),
        Gen::new(len, seed),
    )
    .await
    .expect("a streamed publish of the whole file");
    let peak_over = peak_bytes().saturating_sub(baseline);
    let took = started.elapsed();
    eprintln!(
        "SW1: published {len} bytes ({} MiB) in {took:?}; peak live allocation over the \
         baseline = {peak_over} bytes (~{:.1} MiB, ~{:.1} chunks of {CHUNK_BYTES}); \
         process VmHWM = {:?} KiB",
        len / MIB,
        peak_over as f64 / MIB as f64,
        peak_over as f64 / CHUNK_BYTES as f64,
        vm_hwm_kib(),
    );
    assert_eq!(published.tier, CryptoTier::InvisibleEncrypted);
    assert!(published.crossed, "the self file crossed");
    assert_eq!(published.pointer.size, Some(len));
    assert_eq!(
        published.pointer.content_digest.as_deref(),
        Some(hex::encode(want).as_str()),
        "the digest folded in chunk by chunk is the generator's sha256"
    );
    let stream_id = published
        .pointer
        .stream_id
        .clone()
        .expect("above the bound: a chunk DAG");
    let chunk_count = usize::try_from(len).expect("fits").div_ceil(CHUNK_BYTES);
    assert_eq!(
        node.store
            .engine()
            .stream_chunks(&stream_id)
            .await
            .expect("the stream")
            .chunks
            .len(),
        chunk_count
    );
    assert!(
        peak_over < 32 * MIB as usize,
        "SW1: the publish's peak live allocation over its baseline is {peak_over} bytes — it \
         must stay a constant number of chunks (< 32 MiB) while the file is {len} bytes"
    );

    // ── Read back on the author, chunk by chunk, hashing ──
    let file = FileRow::from_row(&published.row).expect("a file row");
    let mut walk = file.chunks(&node.store, &node.me);
    let mut sha = Sha256::new();
    let mut items = 0usize;
    let mut total = 0u64;
    while let Some(item) = walk.next().await {
        let item = item.unwrap_or_else(|e| panic!("chunk {items}: {e}"));
        sha.update(&item);
        total += item.len() as u64;
        items += 1;
    }
    let got: [u8; 32] = sha.finalize().into();
    assert_eq!(items, chunk_count, "one item per chunk");
    assert_eq!(total, len);
    assert_eq!(got, want, "SW1: read back byte-identical by sha256");
    eprintln!("SW1: read back {items} chunks, sha256 {}", hex::encode(got));
}

/// **SW2** — a reader that disagrees with its declaration publishes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reader_that_does_not_yield_its_declared_length_publishes_nothing_by_name() {
    use ciris_persist::federation::key_grant::KEY_GRANT_ATTESTATION_TYPE_PREFIX;
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let node = node_at(":memory:", &[&alice], &alice).await;
    let room = ciris_edge::self_room::room(&alice.key_id);

    // A good file first, so "the drive lists nothing new" is not vacuous.
    ciris_edge::files::publish_stream(
        &*node.dir,
        &node.store,
        signers(&node),
        &stream_write(&room, 2 * MIB, "ok.bin", ts()),
        Gen::new(2 * MIB, 1),
    )
    .await
    .expect("a well-declared file publishes");
    assert_eq!(drive_len(&node, &room).await, 1, "the drive sees a file");
    let rows_before = file_rows(&node).await;
    let bytes_before = node
        .store
        .engine()
        .federation_blob_bytes()
        .await
        .expect("blob bytes");
    let grants_before = rows_with_prefix(&node, KEY_GRANT_ATTESTATION_TYPE_PREFIX).await;

    // ── Short: declared 10 MiB, yields 9 MiB ──
    let refused = ciris_edge::files::publish_stream(
        &*node.dir,
        &node.store,
        signers(&node),
        &stream_write(
            &room,
            10 * MIB,
            "short.bin",
            ts() + chrono::Duration::seconds(1),
        ),
        Gen::new(9 * MIB, 2),
    )
    .await
    .expect_err("a short reader is refused");
    assert_eq!(
        refused,
        FileError::DeclaredLengthMismatch {
            declared: 10 * MIB,
            read: 9 * MIB,
        },
        "refused by name, with both counts"
    );
    assert_eq!(refused.kind(), "declared_length_mismatch");
    assert_eq!(file_rows(&node).await, rows_before, "no file:v1 row");
    assert_eq!(
        drive_len(&node, &room).await,
        1,
        "the drive lists nothing new"
    );
    assert_eq!(
        node.store
            .engine()
            .federation_blob_bytes()
            .await
            .expect("blob bytes"),
        bytes_before,
        "no manifest and no chunk held: the 36 chunks it wrote were evicted"
    );
    let grants_after = rows_with_prefix(&node, KEY_GRANT_ATTESTATION_TYPE_PREFIX).await;
    eprintln!(
        "SW2: key_grant sets before {grants_before}, after {grants_after} (the per-chunk sets \
         put_blob_chunk_scoped emitted before the refusal stay; their ciphertext is gone)"
    );

    // ── Long: declared 2 MiB, yields 3 MiB — stopped, not drained ──
    let long = ciris_edge::files::publish_stream(
        &*node.dir,
        &node.store,
        signers(&node),
        &stream_write(
            &room,
            2 * MIB,
            "long.bin",
            ts() + chrono::Duration::seconds(2),
        ),
        Gen::new(3 * MIB, 3),
    )
    .await
    .expect_err("a long reader is refused");
    assert!(
        matches!(long, FileError::DeclaredLengthMismatch { declared, read }
            if declared == 2 * MIB && read > 2 * MIB),
        "{long:?}"
    );

    // ── Inline-sized short: declared 200 KiB, yields 100 KiB ──
    assert_eq!(
        ciris_edge::files::publish_stream(
            &*node.dir,
            &node.store,
            signers(&node),
            &stream_write(
                &room,
                200 * KIB,
                "tiny.bin",
                ts() + chrono::Duration::seconds(3)
            ),
            Gen::new(100 * KIB, 4),
        )
        .await
        .expect_err("a short inline reader is refused"),
        FileError::DeclaredLengthMismatch {
            declared: 200 * KIB,
            read: 100 * KIB,
        }
    );
    // ── Inline-sized long: declared 200 KiB, yields 201 KiB ──
    assert!(matches!(
        ciris_edge::files::publish_stream(
            &*node.dir,
            &node.store,
            signers(&node),
            &stream_write(&room, 200 * KIB, "tiny.bin", ts() + chrono::Duration::seconds(4)),
            Gen::new(201 * KIB, 5),
        )
        .await
        .expect_err("a long inline reader is refused"),
        FileError::DeclaredLengthMismatch { declared, read } if declared == 200 * KIB && read > declared
    ));

    assert_eq!(file_rows(&node).await, rows_before, "still no file:v1 row");
    assert_eq!(
        node.store
            .engine()
            .federation_blob_bytes()
            .await
            .expect("blob bytes"),
        bytes_before,
        "and still nothing held"
    );
}

/// The row's structure: object keys, array lengths, scalar kinds.
fn shape(v: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value as V;
    match v {
        V::Object(m) => V::Object(m.iter().map(|(k, v)| (k.clone(), shape(v))).collect()),
        V::Array(a) => V::Array(a.iter().map(shape).collect()),
        V::String(_) => V::String("s".into()),
        V::Number(_) => V::String("n".into()),
        V::Bool(_) => V::String("b".into()),
        V::Null => V::Null,
    }
}

/// The pointer with its per-write randomness blanked: the at-rest sha (a fresh
/// DEK every seal), the stream id (a fresh uuid), the sealed descriptor (a
/// fresh nonce). Everything else — tier, group, field, size, the plaintext
/// digest, epoch, clear format — must be equal.
fn stable(p: &ciris_edge::group_content::BlobPointer) -> ciris_edge::group_content::BlobPointer {
    let mut p = p.clone();
    p.content_sha256 = String::new();
    p.stream_id = p.stream_id.map(|_| "stream".to_owned());
    p.sealed_descriptor = p.sealed_descriptor.map(|_| "sealed".to_owned());
    p
}

/// **SW3** — `publish` and `publish_stream` are one path: same rows, same reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn publish_and_publish_stream_produce_the_same_row_and_read_the_same() {
    init_tracing();
    let alice = Ident::new("alice-fed", 0x11);
    let node = node_at(":memory:", &[&alice], &alice).await;
    let room = ciris_edge::self_room::room(&alice.key_id);
    let mut at = ts();
    for (len, what) in [(200 * KIB, "200 KiB inline"), (1331 * KIB, "1.3 MiB DAG")] {
        let seed = len;
        let plain = body_of(usize::try_from(len).expect("fits"), seed);
        at += chrono::Duration::seconds(10);
        let by_slice: PublishedFile = ciris_edge::files::publish(
            &*node.dir,
            &node.store,
            signers(&node),
            &FileWrite {
                room: &room,
                bytes: &plain,
                media_type: "application/octet-stream",
                codec: None,
                filename: Some("same.bin"),
                asserted_at: at,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("{what}: publish: {e}"));
        at += chrono::Duration::seconds(10);
        let by_stream = ciris_edge::files::publish_stream(
            &*node.dir,
            &node.store,
            signers(&node),
            &stream_write(&room, len, "same.bin", at),
            Gen::new(len, seed),
        )
        .await
        .unwrap_or_else(|e| panic!("{what}: publish_stream: {e}"));

        assert_eq!(
            by_slice.pointer.stream_id.is_some(),
            len > MIB,
            "{what}: the shape is the one publish always chose"
        );
        assert_eq!(
            stable(&by_slice.pointer),
            stable(&by_stream.pointer),
            "{what}: the same pointer modulo per-write randomness"
        );
        assert_eq!(by_slice.tier, by_stream.tier, "{what}: tier");
        assert_eq!(by_slice.granted, by_stream.granted, "{what}: granted");
        assert_eq!(by_slice.excluded, by_stream.excluded, "{what}: excluded");
        assert_eq!(by_slice.crossed, by_stream.crossed, "{what}: crossed");
        let (a, b) = (&by_slice.row, &by_stream.row);
        assert_eq!(
            shape(&a.attestation_envelope),
            shape(&b.attestation_envelope),
            "{what}: the same row shape"
        );
        assert_eq!(
            (
                &a.attestation_type,
                &a.cohort_scope,
                &a.tier,
                &a.attesting_key_id,
                &a.subject_key_ids
            ),
            (
                &b.attestation_type,
                &b.cohort_scope,
                &b.tier,
                &b.attesting_key_id,
                &b.subject_key_ids
            ),
            "{what}: the same row columns"
        );

        let (fa, fb) = (
            FileRow::from_row(a).expect("file row"),
            FileRow::from_row(b).expect("file row"),
        );
        let ra = fa
            .open(&node.store, &node.me)
            .await
            .expect("open slice-published");
        let rb = fb
            .open(&node.store, &node.me)
            .await
            .expect("open stream-published");
        assert!(
            ra == plain && rb == plain,
            "{what}: both read byte-identical"
        );
        assert_eq!(
            fa.describe(&node.store, &node.me).await.expect("describe"),
            fb.describe(&node.store, &node.me).await.expect("describe"),
            "{what}: the same description"
        );
        if by_slice.pointer.stream_id.is_some() {
            let la = fa.layout(&node.store, &node.me).await.expect("layout");
            let lb = fb.layout(&node.store, &node.me).await.expect("layout");
            let sizes = |l: &ciris_edge::group_content::ChunkLayout| {
                l.chunks
                    .iter()
                    .map(|c| (c.seq, c.offset, c.size))
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                sizes(&la),
                sizes(&lb),
                "{what}: the same chunk boundaries whatever the reader's pace"
            );
        }
    }
}
