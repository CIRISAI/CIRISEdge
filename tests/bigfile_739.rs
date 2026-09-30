//! CIRISEdge#739 (lane 7 of #734) — **a multi-GiB file transfers correct AND
//! fast, benched against the wire's own ceiling.**
//!
//! Two devices of one owner on real Reticulum loopback TCP (MDU 16297): **A**
//! (alice's laptop) publishes an N-byte self file at `invisible_encrypted`
//! through the file door, **B** (alice's phone) pulls it through the real DAG
//! doors (`BlobPuller::pull_one` → manifest → verified → chunks → promoted)
//! over the real transport, and reads it back byte-identical by range. The
//! content is generated on the fly from a seeded splitmix64 stream (never a
//! fixture in git); its sha256 is the witness.
//!
//! What it prints (one table per run, `--nocapture`):
//!
//! - **ceiling** — a raw transfer of the same byte count over the same
//!   two-node link shape through edge's transport (`Transport::send` of
//!   4 MiB frames, each a leviculum Resource — auto-compress on, as edge
//!   ships everything), at one lane and at four;
//! - **publish/seal** s; the key plane (the `key_grant` sets crossing) s;
//! - **pull** s and MB/s, the **ratio** pull/ceiling, the per-phase clocks on
//!   B (`dag_fetch_wait`, `inbound_verify_chunk_body`, `inbound_parse_chunk_body`,
//!   `dag_adopt`, `dag_promote`) and on A (`serve_chunk`), for each `K` in
//!   the curve (1, 4, 16 by default);
//! - **peak memory** during the pull — a counting global allocator's
//!   high-water mark over its baseline at pull start (heap only; the whole
//!   process, A's serve included) and the kernel's `VmHWM` (which also
//!   remembers A's publish buffer, and is reported for that reason);
//! - **read-back** s and MB/s (the at-rest open, by 4 MiB ranges);
//! - **resume** — B is torn down at ~50 % of the pull (the pull task
//!   aborted, its edge stopped, its transport dropped, its store closed),
//!   rebuilt from the same store path, and the pull completes with the held
//!   chunks skipped, every chunk adopted exactly once, byte-identical.
//!
//! Sizes: `CIRIS_BIGFILE_BYTES` (default 256 MiB) for the quick variant, and
//! the `#[ignore]`d 2 GiB variant, which checks free disk first (A's store +
//! B's store + the wire ≈ 3 × N; it aborts below 20 GB remaining).
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --release --features transport-reticulum --test bigfile_739 -- --nocapture`

#![cfg(feature = "transport-reticulum")]
#![allow(
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    // A bench that builds a printed table line by line.
    clippy::format_push_string,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::map_unwrap_or
)]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::blob_swarm::{BlobPuller, ContentScope, PullConfig, PullOutcome};
use ciris_edge::group_content::PersistGroupContentStore;
use ciris_edge::scope_lifecycle::ScopeGroupSnapshot;
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
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

// ─── the counting allocator ───────────────────────────────────────────

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// Allocations below this are not counted. The chunk pipeline's CPU work
/// (the envelope's JSON value tree and its canonical form) is millions of
/// small allocations per chunk across every worker thread; counting each on
/// two shared atomics turned the allocator into a cross-core lock and made
/// the bench measure its own instrument (K = 8 ran slower than K = 1). What
/// the peak is FOR — chunk buffers, envelopes, value-tree spines — is all
/// above this line; `VmHWM` (reported beside it) counts everything.
const COUNTED_FROM: usize = 4096;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() && layout.size() >= COUNTED_FROM {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            if live > PEAK.load(Ordering::Relaxed) {
                PEAK.fetch_max(live, Ordering::Relaxed);
            }
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() >= COUNTED_FROM {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        System.dealloc(ptr, layout);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            if layout.size() >= COUNTED_FROM {
                LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            }
            if new_size >= COUNTED_FROM {
                let live = LIVE.fetch_add(new_size, Ordering::Relaxed) + new_size;
                if live > PEAK.load(Ordering::Relaxed) {
                    PEAK.fetch_max(live, Ordering::Relaxed);
                }
            }
        }
        p
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// Reset the high-water mark to the current live bytes; returns the baseline.
fn mem_mark() -> usize {
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    live
}

fn mem_peak_over(baseline: usize) -> usize {
    PEAK.load(Ordering::Relaxed).saturating_sub(baseline)
}

/// The kernel's peak resident set for this process, in bytes.
fn vm_hwm_bytes() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|kb| kb.parse::<u64>().ok())
        })
        .map_or(0, |kb| kb * 1024)
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn mb_per_s(bytes: u64, elapsed: Duration) -> f64 {
    bytes as f64 / 1e6 / elapsed.as_secs_f64().max(1e-9)
}

// ─── deterministic content ───────────────────────────────────────────

/// `len` bytes of a seeded splitmix64 stream — incompressible, never a fixture.
fn content(len: usize, seed: u64) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut x = seed;
    for chunk in out.chunks_mut(8) {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let b = z.to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    out
}

// ─── identities and nodes (the `scoped_body_identity_link_718` shape) ───

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

// ─── the adopt clock by stream position (CIRISPersist#957) ────────────

/// The target the puller's per-batch adopt event is emitted under.
const ADOPT_TARGET: &str = "ciris_edge::blob_swarm::dag_adopt";

/// Every adopt batch the puller reported since the last [`take_adopts`]:
/// `(lowest seq in the batch, chunks, elapsed µs)`.
static ADOPTS: std::sync::Mutex<Vec<(u64, u64, u64)>> = std::sync::Mutex::new(Vec::new());

fn take_adopts() -> Vec<(u64, u64, u64)> {
    std::mem::take(&mut *ADOPTS.lock().expect("adopts"))
}

/// A tracing layer that records the puller's adopt events, whatever the
/// log filter says (it has its own per-layer filter).
struct AdoptCapture;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AdoptCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        #[derive(Default)]
        struct Fields {
            first: u64,
            chunks: u64,
            us: u64,
        }
        impl tracing::field::Visit for Fields {
            fn record_u64(&mut self, f: &tracing::field::Field, v: u64) {
                match f.name() {
                    "first_seq" => self.first = v,
                    "chunks" => self.chunks = v,
                    "elapsed_us" => self.us = v,
                    _ => {}
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        if event.metadata().target() != ADOPT_TARGET {
            return;
        }
        let mut f = Fields::default();
        event.record(&mut f);
        ADOPTS
            .lock()
            .expect("adopts")
            .push((f.first, f.chunks, f.us));
    }
}

/// Stream positions per bucket of the adopt curve.
const BUCKET: u64 = 512;

/// Mean adopt time per chunk (ms) by stream-position bucket: a batch's time
/// is split evenly over its chunks and booked at its lowest seq.
fn adopt_curve(adopts: &[(u64, u64, u64)]) -> Vec<(u64, f64, u64)> {
    let mut by: std::collections::BTreeMap<u64, (u64, u64)> = std::collections::BTreeMap::new();
    for &(first, chunks, us) in adopts {
        let slot = by.entry(first / BUCKET).or_insert((0, 0));
        slot.0 += us;
        slot.1 += chunks;
    }
    by.into_iter()
        .map(|(b, (us, n))| (b * BUCKET, us as f64 / n.max(1) as f64 / 1e3, n))
        .collect()
}

fn init_tracing() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::Layer as _;
    let fmt = tracing_subscriber::fmt::layer()
        .with_test_writer()
        .with_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("ciris_edge=warn")),
        );
    let capture = AdoptCapture.with_filter(
        tracing_subscriber::filter::Targets::new().with_target(ADOPT_TARGET, tracing::Level::DEBUG),
    );
    let _ = tracing_subscriber::registry()
        .with(fmt)
        .with(capture)
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

/// The self room's content scope (the key plane of an `invisible_encrypted`
/// self row: `SelfOnly`, group = the owner's identity).
fn self_scope(owner: &str) -> ContentScope {
    ContentScope::Group {
        scope: CohortScope::SelfOnly,
        group_id: ciris_edge::self_room::room(owner).table_group_id(),
    }
}

/// What a scope-native host wires: persist's source for the bytes and the
/// self room's scope for every blob this fixture serves.
struct SelfRoomSource {
    inner: ciris_edge::blob_swarm::PersistBlobChunkSource,
    scope: ContentScope,
}
#[async_trait::async_trait]
impl ciris_edge::blob_swarm::BlobChunkSource for SelfRoomSource {
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
}

struct Member {
    node: Node,
    rt: Arc<ReticulumTransport>,
    edge: Arc<Edge>,
    stop: tokio::sync::watch::Sender<bool>,
    port: u16,
}

/// A running member: transport, edge, the self room installed (both devices
/// as members, a fixed destination secret — the addresses are what this
/// bench is about, not the MLS tree that would normally derive them).
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
        .blob_chunk_source(Arc::new(SelfRoomSource {
            inner: ciris_edge::blob_swarm::PersistBlobChunkSource::new(node.store.engine().clone()),
            scope: self_scope(&owner),
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
        stop,
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

// ─── the ceiling ──────────────────────────────────────────────────────

/// A frame that fits every cap on both sides with room to spare.
const CEILING_FRAME: usize = 4 * 1024 * 1024;

/// A raw transfer of `total` bytes A → B over a bare two-transport pair of
/// the same shape (no edge, B's listener counting bytes), at `lanes`
/// concurrent senders. Returns MB/s.
async fn ceiling(total: u64, lanes: usize, tmp: &Path, tag: &str) -> f64 {
    let alice = Ident::new(&format!("ceil-a-{tag}"), 0x41);
    let bob = Ident::new(&format!("ceil-b-{tag}"), 0x42);
    let a = device(":memory:", &[&alice, &bob], &alice, &alice).await;
    let b = device(":memory:", &[&alice, &bob], &bob, &bob).await;
    federate(&a, &b).await;
    federate(&b, &a).await;
    let (rt_a, port_a) = transport_for(&a, tmp.join(format!("ceil-a-{tag}.id")), None).await;
    let (rt_b, _) = transport_for(&b, tmp.join(format!("ceil-b-{tag}.id")), Some(port_a)).await;
    carry_route(&a, &b).await;
    carry_route(&b, &a).await;
    let received = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(64);
    let lb = Arc::clone(&rt_b);
    let listen = tokio::spawn(async move {
        let _ = lb.listen(tx).await;
    });
    let counter = Arc::clone(&received);
    let drain = tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            counter.fetch_add(f.envelope_bytes.len() as u64, Ordering::Relaxed);
        }
    });
    // A's own listener must run for A to root B's announce.
    let (tx_a, mut rx_a) = tokio::sync::mpsc::channel::<InboundFrame>(64);
    let la = Arc::clone(&rt_a);
    let listen_a = tokio::spawn(async move {
        let _ = la.listen(tx_a).await;
    });
    let drain_a = tokio::spawn(async move { while rx_a.recv().await.is_some() {} });
    let deadline = Instant::now() + Duration::from_secs(60);
    while !(rt_a.knows_peer(&b.me).await && rt_b.knows_peer(&a.me).await) {
        assert!(
            Instant::now() < deadline,
            "the ceiling pair never rooted each other"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let frames = usize::try_from(total.div_ceil(CEILING_FRAME as u64)).expect("fits");
    let frame = content(CEILING_FRAME, 0xCE11);
    let started = Instant::now();
    let mut senders = Vec::with_capacity(lanes);
    for lane in 0..lanes {
        let rt = Arc::clone(&rt_a);
        let dest = b.me.clone();
        let frame = frame.clone();
        let mine = (lane..frames).step_by(lanes).count();
        senders.push(tokio::spawn(async move {
            for _ in 0..mine {
                rt.send(&dest, &frame).await.expect("ceiling send");
            }
        }));
    }
    for s in senders {
        s.await.expect("sender");
    }
    let want = frames as u64 * CEILING_FRAME as u64;
    let deadline = Instant::now() + Duration::from_secs(120);
    while received.load(Ordering::Relaxed) < want {
        assert!(
            Instant::now() < deadline,
            "the ceiling frames never all landed"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let elapsed = started.elapsed();
    listen.abort();
    drain.abort();
    listen_a.abort();
    drain_a.abort();
    drop((rt_a, rt_b));
    mb_per_s(want, elapsed)
}

// ─── the file ─────────────────────────────────────────────────────────

struct Published {
    row: Attestation,
    sha: [u8; 32],
    stream_id: String,
    aad: Vec<u8>,
    plain_sha: [u8; 32],
    total: u64,
    chunk_count: usize,
    grants: Vec<Attestation>,
    publish: Duration,
}

/// A publishes `total` bytes into alice's self room; the crossed row and
/// every `key_grant` set are collected for B.
async fn publish_on(a: &Node, owner: &Ident, total: u64) -> Published {
    let plain = content(usize::try_from(total).expect("fits"), 0x7390);
    let plain_sha: [u8; 32] = sha2::Sha256::digest(&plain).into();
    let room = ciris_edge::self_room::room(&owner.key_id);
    let started = Instant::now();
    let published = ciris_edge::files::publish(
        &*a.dir,
        &a.store,
        ciris_edge::replication::attestation_bind::Signers {
            node: &a.signer,
            actor: None,
        },
        &ciris_edge::files::FileWrite {
            room: &room,
            bytes: &plain,
            media_type: "application/octet-stream",
            codec: None,
            filename: Some("big.bin"),
            asserted_at: ts(),
        },
    )
    .await
    .expect("publish the big file into alice's self room");
    let publish = started.elapsed();
    drop(plain);
    assert!(published.crossed, "the self file must cross");
    let sha: [u8; 32] = hex::decode(&published.pointer.content_sha256)
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let stream_id = published.pointer.stream_id.clone().expect("a chunk DAG");
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
        .dir
        .get_attestation(&crossed_id)
        .await
        .expect("read")
        .expect("the crossed row");
    let aad = ciris_edge::group_content::content_aad(
        &row.attesting_key_id,
        row.asserted_at,
        published.pointer.content_field,
    );
    let view = a
        .store
        .engine()
        .open_sealed_manifest_as(&sha, &a.me, Some(&aad))
        .await
        .expect("A opens its own manifest");
    a.store
        .engine()
        .emit_pending_key_grants()
        .await
        .expect("A emits its key_grant sets");
    let mut grants = Vec::new();
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
                    .any(|g: &Attestation| g.attestation_id == r.attestation.attestation_id)
            {
                grants.push(r.attestation);
            }
        }
        if n < 1000 {
            break;
        }
    }
    Published {
        row,
        sha,
        stream_id,
        aad,
        plain_sha,
        total,
        chunk_count: view.chunks.len(),
        grants,
        publish,
    }
}

/// B admits the crossed row and every key_grant set (the row/key planes).
async fn cross_to(b: &Node, p: &Published) -> Duration {
    let started = Instant::now();
    let _ = b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: p.row.clone(),
        })
        .await;
    // Persist rate-limits a peer's replicated sets (`peer_burst`); a real
    // replication round backs off exactly this way. The key plane is not the
    // pull, so its pacing is reported but never counted in the pull's clock.
    for g in &p.grants {
        loop {
            match b
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
    started.elapsed()
}

/// Read the file back on B by 4 MiB ranges; returns (sha256, elapsed).
async fn read_back(b: &Node, p: &Published) -> ([u8; 32], Duration) {
    const WINDOW: u64 = 4 * 1024 * 1024;
    let started = Instant::now();
    let mut h = sha2::Sha256::new();
    let mut off = 0u64;
    while off < p.total {
        let end = (off + WINDOW).min(p.total) - 1;
        let bytes = b
            .store
            .engine()
            .read_blob_range_as(&p.sha, &b.me, off, end, Some(&p.aad))
            .await
            .unwrap_or_else(|e| panic!("B reads [{off}, {end}]: {e}"));
        assert_eq!(
            bytes.len() as u64,
            end - off + 1,
            "range [{off}, {end}] length"
        );
        h.update(&bytes);
        off = end + 1;
    }
    (h.finalize().into(), started.elapsed())
}

// ─── the shim over what this branch adds (swapped for the base run) ───

/// Printed in the table: the before-table is measured on a copy of this
/// file whose shim is the base's, and the marker keeps the two runs apart.
const BRANCH: &str = "pipelined (#739)";

const DEFAULT_K: usize = ciris_edge::blob_swarm::DEFAULT_DAG_CHUNKS_IN_FLIGHT;

const DEFAULT_BATCH: usize = ciris_edge::blob_swarm::DEFAULT_DAG_ADOPT_BATCH_CHUNKS;

fn with_lanes(mut cfg: PullConfig, k: usize, batch: usize) -> PullConfig {
    cfg.dag_chunks_in_flight = k;
    cfg.dag_adopt_batch_chunks = batch;
    cfg
}

fn phases(m: &ciris_edge::EdgeMetrics) -> Vec<(String, u64, u64)> {
    let mut v: Vec<(String, u64, u64)> = m
        .snapshot()
        .blob_dag_phases
        .into_iter()
        .map(|(k, (ns, n))| (k, ns, n))
        .collect();
    v.sort();
    v
}

fn ledger(m: &ciris_edge::EdgeMetrics, key: &str) -> u64 {
    m.snapshot().blob_dag_chunks.get(key).copied().unwrap_or(0)
}

/// Rows the durable outbound queue on `m` holds (any status) whose kind is
/// a chunk reply — the #739 witness that chunk bodies ride the arrival link
/// and never the queue.
async fn queued_chunk_replies(m: &Member) -> usize {
    m.edge
        .outbound_queue_handle()
        .list_outbound(ciris_persist::prelude::OutboundFilter::default(), 1_000_000)
        .await
        .expect("list_outbound")
        .iter()
        .filter(|r| r.message_type.to_ascii_lowercase().contains("chunk"))
        .count()
}

fn carrier(m: &Member, label: &str) -> u64 {
    m.edge
        .metrics()
        .snapshot()
        .blob_scoped_carriers
        .get(label)
        .copied()
        .unwrap_or(0)
}

async fn pool(rt: &ReticulumTransport) -> (usize, usize) {
    rt.scoped_link_pool_for_test().await
}

/// Whether this build answers chunk requests on the arrival link (the
/// witnesses below assert it); the base answers through the durable queue.
const REPLY_PATH: bool = true;

fn arm_reply_teardown(rt: &ReticulumTransport, n: u32) {
    rt.tear_down_next_reply_links_for_test(n);
}

/// The attribution seams (`CIRIS_BIGFILE_SEAM`), applied to B before a pull
/// in the curve: `nopool` — every request dials a fresh scoped link (the
/// pre-#739 link-per-chunk shape), the reply still on the arrival link;
/// `queue` — A tears down every answer's arrival link, so every answer
/// takes the durable-queue fallback AND the next request dials (the pre-#739
/// shape on both counts). Unset: the build as shipped.
fn arm_seam(a: &ReticulumTransport, rt: &ReticulumTransport) -> &'static str {
    match std::env::var("CIRIS_BIGFILE_SEAM").as_deref() {
        Ok("nopool") => {
            rt.bypass_scoped_pool_for_test(true);
            "nopool"
        }
        Ok("queue") => {
            a.tear_down_next_reply_links_for_test(u32::MAX);
            "queue"
        }
        _ => "",
    }
}

// ─── the run ──────────────────────────────────────────────────────────

struct PullReport {
    k: usize,
    batch: usize,
    /// `(bucket start seq, mean adopt ms per chunk, chunks)`.
    adopt_curve: Vec<(u64, f64, u64)>,
    adopt_batches: u64,
    adopt_batch_peak: u64,
    /// Sum of every batch's adopt wall time.
    adopt_total: Duration,
    elapsed: Duration,
    mem_peak: usize,
    phases_b: Vec<(String, u64, u64)>,
    phases_a: Vec<(String, u64, u64)>,
    adopted: u64,
    skipped: u64,
    in_flight_peak: u64,
    pool_b: (usize, usize),
    carriers_a: std::collections::HashMap<String, u64>,
    read_back: Duration,
}

fn puller_for(b: &Member, k: usize, batch: usize) -> Arc<BlobPuller<SqliteBackend>> {
    BlobPuller::new(
        Arc::clone(&b.edge),
        b.node.store.engine().clone(),
        b.node.dir.clone(),
        b.node.dir.clone() as Arc<dyn FederationDirectory>,
        b.node.me.clone(),
        with_lanes(PullConfig::default(), k, batch),
    )
}

fn fmt_phases(rows: &[(String, u64, u64)]) -> String {
    rows.iter()
        .map(|(k, ns, n)| {
            format!(
                "{k}={:.2}s/{n} (avg {:.2} ms)",
                *ns as f64 / 1e9,
                if *n == 0 {
                    0.0
                } else {
                    *ns as f64 / *n as f64 / 1e6
                }
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One fresh B pulls the file at `k` lanes; returns the report.
async fn pull_once(
    tmp: &Path,
    tag: &str,
    a: &Member,
    node_b: Node,
    members: &[String],
    p: &Published,
    (k, batch): (usize, usize),
) -> PullReport {
    federate(&a.node, &node_b).await;
    federate(&node_b, &a.node).await;
    let b = member(
        node_b,
        tmp.join(format!("b-{tag}.id")),
        Some(a.port),
        members,
    )
    .await;
    carry_route(&a.node, &b.node).await;
    carry_route(&b.node, &a.node).await;
    wait_direct(&b, a, Duration::from_secs(60)).await;
    wait_direct(a, &b, Duration::from_secs(60)).await;
    let key_plane = cross_to(&b.node, p).await;
    eprintln!(
        "[{tag}] key plane crossed in {:.2}s ({} sets)",
        key_plane.as_secs_f64(),
        p.grants.len()
    );

    let puller = puller_for(&b, k, batch);
    let seam = arm_seam(&a.rt, &b.rt);
    if !seam.is_empty() {
        eprintln!("[{tag}] attribution seam armed on B: {seam}");
    }
    let _ = take_adopts();
    let baseline = mem_mark();
    let started = Instant::now();
    let verdict = puller.pull_one(&p.row, p.sha, 0).await;
    let elapsed = started.elapsed();
    let mem_peak = mem_peak_over(baseline);
    let adopts = take_adopts();
    assert_eq!(
        verdict,
        PullOutcome::Stored { announced: false },
        "the pull at K={k} must store (an invisible-tier DAG is never announced)"
    );
    let head = b
        .node
        .dir
        .blob_head(&p.sha)
        .await
        .expect("blob_head")
        .expect("held");
    assert_eq!(head.storage_kind, "chunk_dag", "promoted");
    let (got, read_back) = read_back(&b.node, p).await;
    assert_eq!(got, p.plain_sha, "byte-identical on B at K={k}");
    a.rt.tear_down_next_reply_links_for_test(0);
    let adopted_chunks: u64 = adopts.iter().map(|a| a.1).sum();
    assert_eq!(
        adopted_chunks,
        ledger(&b.edge.metrics(), "adopted"),
        "every adopted chunk is in the adopt clock (the capture layer saw every batch)"
    );
    let report = PullReport {
        k,
        batch,
        adopt_curve: adopt_curve(&adopts),
        adopt_batches: adopts.len() as u64,
        adopt_batch_peak: ledger(&b.edge.metrics(), "adopt_batch_peak"),
        adopt_total: Duration::from_micros(adopts.iter().map(|a| a.2).sum()),
        elapsed,
        mem_peak,
        phases_b: phases(&b.edge.metrics()),
        phases_a: phases(&a.edge.metrics()),
        adopted: ledger(&b.edge.metrics(), "adopted"),
        skipped: ledger(&b.edge.metrics(), "skipped_held"),
        in_flight_peak: ledger(&b.edge.metrics(), "in_flight_peak"),
        pool_b: pool(&b.rt).await,
        carriers_a: a.edge.metrics().snapshot().blob_scoped_carriers,
        read_back,
    };
    let _ = b.stop.send(true);
    drop(b);
    report
}

// ─── the stall watch (CIRISEdge#749) ──────────────────────────────────

/// **How long a pull may hold no new chunk before the witness calls it
/// stopped.** Read off the protocol's own clocks, not off a host's speed: a
/// healthy lane's longest silence is one exchange at its worst — the scoped
/// dial's establish budget (`NO_PATH_ESTABLISH_TIMEOUT`, 5 s, a derived
/// address is never pathed) and identify, the request's Resource fallback
/// (`DIAL_NO_PROGRESS_WINDOW`, 30 s of no progress) and the wait for the
/// answer (`SwarmConfig::per_request_timeout`, 30 s; on its expiry the lane
/// STOPS the pull, which the watch sees as `Finished`) — plus the adopt that
/// follows. K lanes run that in parallel, so a chunk held within one worst
/// exchange is progress. The 30 s of slack above the 65 s sum covers a debug
/// build's adopt on a two-core runner (persist's `adopt_sealed_chunk` is one
/// writer). A pull that stops fetching trips this whatever the host's speed;
/// a slow one that keeps landing chunks never does.
const STALL: Duration = Duration::from_secs(5 + 30 + 30 + 30);

/// The overall backstop for one watched stretch (half a 256 MiB pull, or
/// its resume): only a pull that crawls without ever pausing for `STALL`
/// reaches it. It is not the witness's clock; the step's own timeout is
/// sized above two of these (`.github/workflows/ci.yml`).
const BACKSTOP: Duration = Duration::from_secs(20 * 60);

/// How a watched stretch of a pull ended.
#[derive(Debug, PartialEq, Eq)]
enum Watch {
    /// `target` chunks were held.
    Reached { held: u64, elapsed: Duration },
    /// The pull task returned before `target` (the caller decides whether
    /// that is the failure it names).
    Finished { held: u64 },
    /// No new chunk was held for `STALL`.
    Stalled {
        held: u64,
        total: u64,
        silent: Duration,
        elapsed: Duration,
    },
    /// Still moving, but past the backstop.
    Backstop {
        held: u64,
        total: u64,
        elapsed: Duration,
    },
}

impl std::fmt::Display for Watch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reached { held, elapsed } => {
                write!(f, "reached {held} chunks in {:.1}s", elapsed.as_secs_f64())
            }
            Self::Finished { held } => write!(f, "the pull returned with {held} chunks held"),
            Self::Stalled {
                held,
                total,
                silent,
                elapsed,
            } => write!(
                f,
                "STALLED — no new chunk held for {:.0}s (the stall bound) at {held}/{total}, \
                 {:.0}s into the pull",
                silent.as_secs_f64(),
                elapsed.as_secs_f64()
            ),
            Self::Backstop {
                held,
                total,
                elapsed,
            } => write!(
                f,
                "still moving at {held}/{total} after the {:.0}s backstop",
                elapsed.as_secs_f64()
            ),
        }
    }
}

/// Chunks of `stream` held in `node`'s store.
async fn held_chunks(node: &Node, stream: &str) -> u64 {
    node.dir
        .stream_chunks(stream)
        .await
        .map(|l| l.chunks.len() as u64)
        .unwrap_or(0)
}

/// Poll a pull's held-chunk count until it reaches `target`, the pull
/// returns, no new chunk lands for `stall`, or `backstop` passes. Prints a
/// line at each tenth of `total`, so a slow runner's log shows the rate.
#[allow(clippy::too_many_arguments)]
async fn watch_pull<H, F>(
    what: &str,
    target: u64,
    total: u64,
    mut held: impl FnMut() -> H,
    mut finished: F,
    stall: Duration,
    backstop: Duration,
    poll: Duration,
) -> Watch
where
    H: std::future::Future<Output = u64>,
    F: FnMut() -> bool,
{
    let started = Instant::now();
    let mut last = held().await;
    let mut last_moved = Instant::now();
    let step = (total / 10).max(1);
    let mut next_mark = (last / step + 1) * step;
    loop {
        let now = held().await;
        if now > last {
            last = now;
            last_moved = Instant::now();
            while now >= next_mark {
                eprintln!(
                    "[{what}] {now}/{total} chunks held at {:.1}s",
                    started.elapsed().as_secs_f64()
                );
                next_mark += step;
            }
        }
        if now >= target {
            return Watch::Reached {
                held: now,
                elapsed: started.elapsed(),
            };
        }
        if finished() {
            // One last read: the pull may have landed its final chunks
            // between the count above and its return.
            let now = held().await;
            if now >= target {
                return Watch::Reached {
                    held: now,
                    elapsed: started.elapsed(),
                };
            }
            return Watch::Finished { held: now };
        }
        if last_moved.elapsed() >= stall {
            return Watch::Stalled {
                held: now,
                total,
                silent: last_moved.elapsed(),
                elapsed: started.elapsed(),
            };
        }
        if started.elapsed() >= backstop {
            return Watch::Backstop {
                held: now,
                total,
                elapsed: started.elapsed(),
            };
        }
        tokio::time::sleep(poll).await;
    }
}

/// The watch's own witness, at a scaled clock: a pull that stops fetching
/// is `Stalled` (whatever it held), a slow one that keeps landing chunks is
/// not, a pull that returns early is `Finished`, and one that never pauses
/// but crawls meets the backstop. Runs in every lane that runs this file.
#[tokio::test]
async fn the_stall_watch_trips_on_a_stopped_pull_and_not_on_a_slow_one_749() {
    use std::sync::atomic::AtomicU64;
    let ms = Duration::from_millis;
    // Stops fetching at 5 of 100: stalled, not a deadline.
    let n = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&n);
    let w = watch_pull(
        "stops",
        50,
        100,
        || {
            let c = Arc::clone(&c);
            async move {
                let v = c.load(Ordering::SeqCst);
                if v < 5 {
                    c.store(v + 1, Ordering::SeqCst);
                }
                c.load(Ordering::SeqCst)
            }
        },
        || false,
        ms(200),
        ms(60_000),
        ms(5),
    )
    .await;
    assert!(
        matches!(w, Watch::Stalled { held: 5, .. }),
        "a pull that stops fetching trips the stall bound: {w:?}"
    );
    // Slow but moving (one chunk per 3 polls, well inside the bound): reaches.
    let polls = Arc::new(AtomicU64::new(0));
    let p2 = Arc::clone(&polls);
    let w = watch_pull(
        "slow",
        20,
        40,
        || {
            let p2 = Arc::clone(&p2);
            async move { p2.fetch_add(1, Ordering::SeqCst) / 3 }
        },
        || false,
        ms(200),
        ms(60_000),
        ms(5),
    )
    .await;
    assert!(
        matches!(w, Watch::Reached { held: 20, .. }),
        "a slow pull that keeps landing chunks is never called stalled: {w:?}"
    );
    // Returns early.
    let w = watch_pull(
        "done",
        50,
        100,
        || async { 7 },
        || true,
        ms(200),
        ms(60_000),
        ms(5),
    )
    .await;
    assert_eq!(w, Watch::Finished { held: 7 });
    // Crawls without ever pausing for the bound: the backstop.
    let polls = Arc::new(AtomicU64::new(0));
    let p3 = Arc::clone(&polls);
    let w = watch_pull(
        "crawl",
        1_000_000,
        1_000_000,
        || {
            let p3 = Arc::clone(&p3);
            async move { p3.fetch_add(1, Ordering::SeqCst) }
        },
        || false,
        ms(200),
        ms(100),
        ms(5),
    )
    .await;
    assert!(matches!(w, Watch::Backstop { .. }), "{w:?}");
}

/// Kill B at ~50 % and resume from the same store, the resumed pull's first
/// chunk answer forced onto the responder's queue fallback.
async fn resume_once(
    tmp: &Path,
    a: &Member,
    phone: &Phone,
    members: &[String],
    p: &Published,
    k: usize,
) -> Resumed {
    let (alice, phone, db_str) = (&phone.owner, &phone.ident, phone.db.clone());
    let node_b = device(&db_str, &[alice, phone], alice, phone).await;
    federate(&a.node, &node_b).await;
    federate(&node_b, &a.node).await;
    let b = member(node_b, tmp.join("b-resume.id"), Some(a.port), members).await;
    carry_route(&a.node, &b.node).await;
    carry_route(&b.node, &a.node).await;
    wait_direct(&b, a, Duration::from_secs(60)).await;
    wait_direct(a, &b, Duration::from_secs(60)).await;
    cross_to(&b.node, p).await;

    let puller = puller_for(&b, k, DEFAULT_BATCH);
    let row = p.row.clone();
    let sha = p.sha;
    let started = Instant::now();
    let pull = tokio::spawn(async move { puller.pull_one(&row, sha, 0).await });
    let half = (p.chunk_count / 2) as u64;
    // THE STALL WATCH (CIRISEdge#749), not a wall-clock deadline: the pull
    // fails the witness when no new chunk has been held for `STALL`, however
    // slow the host is while it keeps moving.
    let total_chunks = p.chunk_count as u64;
    let watched = watch_pull(
        "first half",
        half,
        total_chunks,
        || held_chunks(&b.node, &p.stream_id),
        || pull.is_finished(),
        STALL,
        BACKSTOP,
        Duration::from_millis(50),
    )
    .await;
    match watched {
        Watch::Reached { held, elapsed } => eprintln!(
            "[resume] 50 % reached: {held}/{total_chunks} chunks held in {:.1}s",
            elapsed.as_secs_f64()
        ),
        Watch::Finished { held } => {
            panic!("the pull finished before the kill point ({held}/{total_chunks} held)")
        }
        stopped => panic!("the pull never reached 50 %: {stopped}"),
    }
    // THE KILL: the pull task aborted mid-walk, B's edge stopped, its
    // transport dropped, its store closed.
    pull.abort();
    let _ = pull.await;
    let first_half = started.elapsed();
    let adopted_first = ledger(&b.edge.metrics(), "adopted");
    let _ = b.stop.send(true);
    drop(b);
    tokio::time::sleep(Duration::from_millis(500)).await;

    // THE RESTART: the same store path, a fresh transport on the same
    // identity, a fresh edge, the room re-installed, the row/key planes
    // re-crossed (idempotent), the same pull.
    let node_b = device(&db_str, &[alice, phone], alice, phone).await;
    federate(&a.node, &node_b).await;
    federate(&node_b, &a.node).await;
    let b = member(node_b, tmp.join("b-resume.id"), Some(a.port), members).await;
    carry_route(&a.node, &b.node).await;
    carry_route(&b.node, &a.node).await;
    wait_direct(&b, a, Duration::from_secs(60)).await;
    wait_direct(a, &b, Duration::from_secs(60)).await;
    cross_to(&b.node, p).await;
    let puller = puller_for(&b, k, DEFAULT_BATCH);
    // THE FALLBACK WITNESS: A tears down the arrival link of the resumed
    // pull's first answer just before riding it, so that answer takes the
    // durable queue by key — and still lands (the pull completes). Replies
    // A was still shipping to the killed B may take the same fallback, so
    // the count is at least one, and the armed teardown is consumed.
    let queued_before = carrier(a, "serve:reply_queued_fallback");
    let rows_before = queued_chunk_replies(a).await;
    arm_reply_teardown(&a.rt, 1);
    let started = Instant::now();
    let row = p.row.clone();
    let resumed = tokio::spawn(async move { puller.pull_one(&row, sha, 0).await });
    // The same stall watch over the resume, to the last chunk: a resume that
    // stops fetching fails by name instead of hanging the step. Once every
    // chunk is held only promotion is left, which adds no chunk, so the watch
    // ends there and the join below waits for the verdict.
    match watch_pull(
        "resume",
        total_chunks,
        total_chunks,
        || held_chunks(&b.node, &p.stream_id),
        || resumed.is_finished(),
        STALL,
        BACKSTOP,
        Duration::from_millis(50),
    )
    .await
    {
        Watch::Reached { .. } | Watch::Finished { .. } => {}
        stopped => panic!("the resumed pull did not complete: {stopped}"),
    }
    let verdict = tokio::time::timeout(STALL, resumed)
        .await
        .expect("every chunk is held, and the promote returns within the stall bound")
        .expect("the resumed pull task");
    let resume_time = started.elapsed();
    let fallbacks = carrier(a, "serve:reply_queued_fallback") - queued_before;
    let fallback_rows = queued_chunk_replies(a).await.saturating_sub(rows_before);
    if REPLY_PATH {
        assert_eq!(
            a.rt.pending_reply_teardowns_for_test(),
            0,
            "the armed teardown was consumed by an answer"
        );
        assert!(
            fallbacks >= 1 && fallback_rows >= 1 && fallback_rows as u64 <= fallbacks,
            "the torn-down link's answer takes the queue fallback: {fallbacks} counted, \
             {fallback_rows} queue rows"
        );
    }
    assert_eq!(
        verdict,
        PullOutcome::Stored { announced: false },
        "the resume stores"
    );
    let adopted_resume = ledger(&b.edge.metrics(), "adopted");
    let skipped_resume = ledger(&b.edge.metrics(), "skipped_held");
    let held = b
        .node
        .dir
        .stream_chunks(&p.stream_id)
        .await
        .expect("stream_chunks")
        .chunks
        .len();
    assert_eq!(
        held, p.chunk_count,
        "every chunk is at its position after the resume"
    );
    // Exactly once: the resume adopted precisely the positions the first
    // attempt did not leave held, so every position was adopted once in all.
    assert_eq!(
        skipped_resume + adopted_resume,
        p.chunk_count as u64,
        "each chunk adopted exactly once across the kill: {skipped_resume} held + \
         {adopted_resume} adopted on resume"
    );
    // What the first attempt left held is what it counted, plus at most the
    // lanes the kill cut between persist's commit and the lane's return.
    assert!(
        skipped_resume >= adopted_first && skipped_resume <= adopted_first + k as u64,
        "the resume skipped what the first attempt adopted ({adopted_first}, + at most K = {k} \
         cut mid-adopt): skipped {skipped_resume}"
    );
    let (got, _) = read_back(&b.node, p).await;
    assert_eq!(got, p.plain_sha, "byte-identical after the resume");
    let _ = b.stop.send(true);
    drop(b);
    Resumed {
        first_half,
        adopted_first,
        resume_time,
        adopted_resume,
        skipped_resume,
        fallbacks,
    }
}

/// One of the owner's other devices: who it is and where its store lives.
struct Phone {
    owner: Ident,
    ident: Ident,
    db: String,
}

struct Resumed {
    first_half: Duration,
    adopted_first: u64,
    resume_time: Duration,
    adopted_resume: u64,
    skipped_resume: u64,
    fallbacks: u64,
}

fn free_bytes(path: &Path) -> u64 {
    let out = std::process::Command::new("df")
        .arg("-Pk")
        .arg(path)
        .output()
        .expect("df");
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|kb| kb.parse::<u64>().ok())
        .map_or(0, |kb| kb * 1024)
}

/// The pulls to run: `CIRIS_BIGFILE_CURVE` as `KxB` entries (lanes x adopt
/// batch, e.g. `1x1,1x16,8x1,8x16`), else `CIRIS_BIGFILE_K_CURVE` (or
/// `ks`) at the default batch; the default `(K, batch)` is always included.
fn env_curve(ks: &[usize], default_k: usize) -> Vec<(usize, usize)> {
    let mut curve: Vec<(usize, usize)> = if let Ok(s) = std::env::var("CIRIS_BIGFILE_CURVE") {
        s.split(',')
            .filter_map(|e| {
                let (k, b) = e.trim().split_once('x')?;
                Some((k.parse().ok()?, b.parse().ok()?))
            })
            .collect()
    } else {
        std::env::var("CIRIS_BIGFILE_K_CURVE")
            .ok()
            .map(|s| s.split(',').filter_map(|k| k.trim().parse().ok()).collect())
            .unwrap_or_else(|| ks.to_vec())
            .into_iter()
            .map(|k| (k, DEFAULT_BATCH))
            .collect()
    };
    if !curve.contains(&(default_k, DEFAULT_BATCH)) {
        curve.push((default_k, DEFAULT_BATCH));
    }
    curve
}

/// A store's files (the database, its WAL and shared memory).
fn remove_store(db: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut p = db.as_os_str().to_owned();
        p.push(suffix);
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}

/// CIRISPersist#957's table: one column per `(K, batch)` pull, one row per
/// stream-position bucket (mean adopt ms per chunk), then the pull's MB/s
/// and its ratio to the 1-lane ceiling. Markdown, to paste.
fn lanes_by_batch_table(total: u64, ceiling_1: f64, reports: &[PullReport]) -> String {
    let mut t = format!(
        "\n#957 table, N = {:.0} MiB: mean adopt ms per chunk by stream position\n| chunks |",
        mib(total)
    );
    for r in reports {
        t.push_str(&format!(" K={} batch={} |", r.k, r.batch));
    }
    t.push_str("\n|---|");
    for _ in reports {
        t.push_str("---|");
    }
    t.push('\n');
    let buckets: std::collections::BTreeSet<u64> = reports
        .iter()
        .flat_map(|r| r.adopt_curve.iter().map(|c| c.0))
        .collect();
    for b in buckets {
        t.push_str(&format!("| {b}–{} |", b + BUCKET - 1));
        for r in reports {
            match r.adopt_curve.iter().find(|c| c.0 == b) {
                Some((_, ms, _)) => t.push_str(&format!(" {ms:.2} |")),
                None => t.push_str(" – |"),
            }
        }
        t.push('\n');
    }
    let row = |label: &str, f: &dyn Fn(&PullReport) -> String| {
        let mut line = format!("| {label} |");
        for r in reports {
            line.push_str(&format!(" {} |", f(r)));
        }
        line.push('\n');
        line
    };
    t.push_str(&row("adopt batches", &|r| r.adopt_batches.to_string()));
    t.push_str(&row("adopt wall s (sum)", &|r| {
        format!("{:.1}", r.adopt_total.as_secs_f64())
    }));
    t.push_str(&row("pull s", &|r| {
        format!("{:.1}", r.elapsed.as_secs_f64())
    }));
    t.push_str(&row("pull MB/s", &|r| {
        format!("{:.1}", mb_per_s(total, r.elapsed))
    }));
    t.push_str(&row("ratio to 1-lane ceiling", &|r| {
        format!("{:.2}x", ceiling_1 / mb_per_s(total, r.elapsed))
    }));
    t
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn run(
    total: u64,
    curve: &[(usize, usize)],
    default_k: usize,
    do_resume: bool,
    with_ceiling: bool,
) {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let free = free_bytes(tmp.path());
    // A's store + B's store + the resume device's ≈ 3 × N; a GiB-scale run
    // must also leave 20 GB for the host (the bench shares it).
    let floor: u64 = if total >= 1 << 30 { 20 << 30 } else { 1 << 30 };
    let need = 3 * total + floor;
    assert!(
        free >= need,
        "not enough free disk for a {:.0} MiB run: {:.1} GB free, need ≥ {:.1} GB (3×N + floor)",
        mib(total),
        free as f64 / 1e9,
        need as f64 / 1e9
    );
    let mut table = String::new();
    table.push_str(&format!(
        "\n=== CIRISEdge#739 bigfile [{BRANCH}]: N = {:.0} MiB ({} bytes) ===\n",
        mib(total),
        total
    ));

    // 1. The ceiling.
    let (ceiling_1, ceiling_4) = if with_ceiling {
        let one = ceiling(total, 1, tmp.path(), "one").await;
        let four = ceiling(total, 4, tmp.path(), "four").await;
        table.push_str(&format!(
            "ceiling (Transport::send, 4 MiB Resources, auto-compress on): {one:.1} MB/s at 1 lane, {four:.1} MB/s at 4 lanes\n"
        ));
        (one, four)
    } else {
        table.push_str("ceiling: not measured in this variant\n");
        (f64::NAN, f64::NAN)
    };
    eprintln!("{table}");

    // 2. A publishes.
    let alice = Ident::new("alice-739", 0x11);
    let db_a = tmp.path().join("a.sqlite");
    let node_a = device(db_a.to_str().expect("utf8"), &[&alice], &alice, &alice).await;
    let me_a = node_a.me.clone();
    // The owner's other devices — one fresh phone per pull in the curve and
    // one for the resume, each its own store (and content-KEM identity).
    // A must know every one (key, owner binding, occurrence) BEFORE it
    // publishes: the self room's key_grant sets are wrapped to the owner's
    // occurrences A holds at seal time, and every device is a member of the
    // self room.
    let mut phones: Vec<((usize, usize), Phone, Node)> = Vec::new();
    let mut members_b: Vec<String> = Vec::new();
    let mut resume_phone: Option<Phone> = None;
    for (i, k) in curve
        .iter()
        .copied()
        .map(Some)
        .chain(std::iter::once(None).filter(|_| do_resume))
        .enumerate()
    {
        let tag = k.map_or_else(|| "resume".to_owned(), |(k, b)| format!("k{k}b{b}"));
        let ident = Ident::new(
            &format!("alice-phone-739-{tag}"),
            0x40 + u8::try_from(i).expect("a short curve"),
        );
        let db = tmp
            .path()
            .join(format!("b-{tag}.sqlite"))
            .to_str()
            .expect("utf8")
            .to_owned();
        let node = device(&db, &[&alice, &ident], &alice, &ident).await;
        federate(&node, &node_a).await;
        let phone = Phone {
            owner: Ident::new("alice-739", 0x11),
            ident,
            db,
        };
        match k {
            Some(k) => phones.push((k, phone, node)),
            None => {
                // Reopened by `resume_once` from the same path.
                members_b.push(node.me.clone());
                drop(node);
                resume_phone = Some(phone);
            }
        }
    }
    let mut members = vec![me_a.clone()];
    members.extend(phones.iter().map(|(_, _, n)| n.me.clone()));
    members.extend(members_b);
    let a = member(node_a, tmp.path().join("a.id"), None, &members).await;
    let p = publish_on(&a.node, &alice, total).await;
    table.push_str(&format!(
        "publish/seal on A: {:.2}s ({:.1} MB/s), {} chunks, {} key_grant sets; VmHWM after publish {:.0} MiB\n",
        p.publish.as_secs_f64(),
        mb_per_s(total, p.publish),
        p.chunk_count,
        p.grants.len(),
        mib(vm_hwm_bytes())
    ));
    eprintln!("{table}");

    // 3. The K curve.
    let mut best: Option<&PullReport> = None;
    let mut reports = Vec::new();
    for ((k, batch), phone, node_b) in phones {
        let tag = format!("k{k}b{batch}");
        let r = pull_once(tmp.path(), &tag, &a, node_b, &members, &p, (k, batch)).await;
        // B's store is done with: free its disk before the next pull.
        remove_store(Path::new(&phone.db));
        drop(phone);
        table.push_str(&format!(
            "adopt clock K={k} batch={batch}: {} batches (largest {}), {:.2}s of adopt wall time; mean ms/chunk by stream position: {}\n",
            r.adopt_batches,
            r.adopt_batch_peak,
            r.adopt_total.as_secs_f64(),
            r.adopt_curve
                .iter()
                .map(|(s, ms, _)| format!("{s}:{ms:.2}"))
                .collect::<Vec<_>>()
                .join(" "),
        ));
        table.push_str(&format!(
            "pull K={:>2}: {:.2}s = {:.1} MB/s, ratio pull/ceiling(1 lane) = {:.2}x, (4 lanes) = {:.2}x; peak heap over baseline {:.1} MiB; adopted {} skipped {} in_flight_peak {}; B scoped pool (pooled, leased) = {:?}; read-back {:.2}s = {:.1} MB/s\n    B phases: {}\n    A phases: {}; A carriers: {:?}\n",
            r.k,
            r.elapsed.as_secs_f64(),
            mb_per_s(total, r.elapsed),
            ceiling_1 / mb_per_s(total, r.elapsed),
            ceiling_4 / mb_per_s(total, r.elapsed),
            mib(r.mem_peak as u64),
            r.adopted,
            r.skipped,
            r.in_flight_peak,
            r.pool_b,
            r.read_back.as_secs_f64(),
            mb_per_s(total, r.read_back),
            fmt_phases(&r.phases_b),
            fmt_phases(&r.phases_a),
            r.carriers_a,
        ));
        eprintln!("{table}");
        reports.push(r);
    }
    for r in &reports {
        if best.map_or(true, |b| r.elapsed < b.elapsed) {
            best = Some(r);
        }
    }
    if let Some(b) = best {
        table.push_str(&format!(
            "fastest in the curve: K={} batch={}\n",
            b.k, b.batch
        ));
    }
    table.push_str(&lanes_by_batch_table(total, ceiling_1, &reports));

    // 4. Resume.
    // The pulls above: every chunk answer rode its arrival link, none the
    // durable queue.
    let rows = queued_chunk_replies(&a).await;
    table.push_str(&format!(
        "A durable-queue rows for chunk replies after the curve: {rows}; A serve:reply_path {}, serve:reply_queued_fallback {}\n",
        carrier(&a, "serve:reply_path"),
        carrier(&a, "serve:reply_queued_fallback"),
    ));
    assert!(
        !REPLY_PATH || std::env::var("CIRIS_BIGFILE_SEAM").is_ok() || rows == 0,
        "no chunk body is written to the durable outbound queue: {rows}"
    );

    if do_resume {
        let phone = resume_phone.as_ref().expect("a resume device");
        let r = resume_once(tmp.path(), &a, phone, &members, &p, default_k).await;
        table.push_str(&format!(
            "resume at K={default_k}: killed at {:.2}s with {} chunks adopted; resumed in {:.2}s adopting {} and skipping {}; byte-identical; queue fallbacks on the resumed pull (one arrival link torn down by A before its answer, plus any answers to the killed B): {}\n",
            r.first_half.as_secs_f64(),
            r.adopted_first,
            r.resume_time.as_secs_f64(),
            r.adopted_resume,
            r.skipped_resume,
            r.fallbacks,
        ));
    }
    table.push_str(&format!("VmHWM at end: {:.0} MiB\n", mib(vm_hwm_bytes())));
    println!("{table}");
    eprintln!("{table}");

    if with_ceiling && std::env::var("CIRIS_BIGFILE_ASSERT_RATIO").is_ok_and(|v| v == "1") {
        let r = reports
            .iter()
            .find(|r| r.k == default_k && r.batch == DEFAULT_BATCH)
            .expect("the default K is in the curve");
        let ratio = ceiling_1 / mb_per_s(total, r.elapsed);
        assert!(
            ratio <= 2.0,
            "the pull at the default K={default_k} is {ratio:.2}x off the ceiling (criterion: ≤ 2x)"
        );
    }
    let _ = a.stop.send(true);
    drop(a);
}

/// The table: 256 MiB by default (`CIRIS_BIGFILE_BYTES`), the ceiling, the K
/// curve (`CIRIS_BIGFILE_K_CURVE`, default `1,4,16` plus the default K), the
/// resume at the default K. Release only; run alone:
/// `cargo test --release --features "transport-http transport-reticulum" --test bigfile_739 -- --ignored --nocapture a_256_mib`
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "the 256 MiB table: a release-build bench, run alone"]
async fn a_256_mib_self_file_pulls_within_the_ceiling_and_resumes_after_a_kill_739() {
    let total = env_usize("CIRIS_BIGFILE_BYTES", 256 * 1024 * 1024) as u64;
    let default_k = env_usize("CIRIS_BIGFILE_K", DEFAULT_K);
    let curve = env_curve(&[1, 4, 16], default_k);
    let do_resume = std::env::var("CIRIS_BIGFILE_RESUME").map_or(true, |v| v != "0");
    run(total, &curve, default_k, do_resume, true).await;
}

/// The 2 GiB variant, run alone: the ceiling, one pull at the default K,
/// the read-back. Refuses to start unless 3 × N + 20 GB of disk is free.
/// `cargo test --release --features "transport-http transport-reticulum" --test bigfile_739 -- --ignored --nocapture a_2_gib`
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "2 GiB on disk and on the wire; a release-build bench, run alone"]
async fn a_2_gib_self_file_pulls_within_the_ceiling_739() {
    let total = env_usize("CIRIS_BIGFILE_BYTES", 2 * 1024 * 1024 * 1024) as u64;
    let default_k = env_usize("CIRIS_BIGFILE_K", DEFAULT_K);
    let curve = env_curve(&[], default_k);
    run(total, &curve, default_k, false, true).await;
}

/// The CI witness (network gauntlet, run alone in its own step): a 256 MiB
/// self file at the default K, killed at ~50 %, resumed from the same store,
/// byte-identical, every position adopted exactly once, zero chunk replies
/// in the durable queue during the pull and the queue fallback taken when
/// the arrival link is torn down. No ceiling and no curve — correctness,
/// not speed, on a shared runner. The witness fails on a STALL (no new chunk
/// held for `STALL`), never on the host's speed: a debug build on a two-core
/// runner lands ≈ 0.7 chunks/s (CIRISEdge#749 — ≈ 12 min to 50 %, the CPU of
/// sign + verify + bz2 + adopt per chunk, reproduced under `taskset -c 0,1`),
/// so the step's budget (`.github/workflows/ci.yml`) is sized over two
/// `BACKSTOP`s, not over a guess at the rate.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
#[ignore = "256 MiB on the wire; CI runs it alone in the network gauntlet"]
async fn a_256_mib_self_file_resumes_after_a_kill_quick_739() {
    let total = env_usize("CIRIS_BIGFILE_BYTES", 256 * 1024 * 1024) as u64;
    run(total, &[], DEFAULT_K, true, false).await;
}
