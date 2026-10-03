//! CIRISEdge#601 — **pull on attestation**: the mechanism between "the
//! attestation arrived" and "the member can read it".
//!
//! # The model, stated once
//!
//! Attestations flow first. The attestation is both this node's
//! **authorization** to pull a blob and its **entire ability to know the
//! blob exists** — "no blobs without CEG envelopes/attestations signed by
//! someone; that is an invalid state" ([`super::meaning`]). Blobs never
//! replicate to all peers: holder claims anti-entropy within the roster and
//! bytes move on demand, by pulling. Before this module nothing turned an
//! arriving attestation into a pull, so on every non-author member the
//! transcript was pointers to bytes the node never asked for, reading
//! `Unopened` forever.
//!
//! # Where it sits
//!
//! The replication bridge, on ADMITTING an attestation that references a
//! blob, offers the row to a [`PullSink`] — a bounded channel, `try_send`,
//! never awaited, so admission never blocks on a fetch. The [`BlobPuller`]
//! drains it: for each sha the row references it projects the meaning, runs
//! the store gate (armed with [`super::PersistBlobStorePolicy`]), fetches
//! through the swarm from the holders persist knows, and stores the result
//! through the door the gate's verdict names. One "should we possess this"
//! predicate, run once, before a byte moves.
//!
//! # What it refuses to do
//!
//! - It never fetches on a `holds_bytes` row. Possession is not meaning
//!   ([`BlobMeaning::referenced_shas`] returns nothing for one), and a
//!   puller that fetched on possession claims would fetch every blob every
//!   peer announced.
//! - It never fetches what the store gate refuses. The gate runs inside the
//!   scheduler ahead of dispatch; a refusal ends the pull with no request
//!   sent.
//! - It never guesses an epoch. A `CommunityDek` pointer without a
//!   sealed-under epoch (a row from before the pointer carried one) is left
//!   unfetched and named, because a guessed binding is a blob that reads
//!   `NotGranted` forever with no way to tell it from a real refusal.
//! - It is bounded everywhere: the queue, the in-flight set, the retry
//!   ledger, and the retry count. Overflow drops WITH a log line and a
//!   counter, never a silent stall.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciris_persist::federation::blobs::BlobStorage;
use ciris_persist::federation::types::cohort_scope::CryptoTier;
use ciris_persist::federation::{
    AdoptDisposition, Attestation, BlobBody, BlobProvenance, FederationDirectory,
};
use futures::stream::{FuturesUnordered, StreamExt as _};
use tokio::sync::mpsc;

use super::key_wake::{self, KeyWaits};
use super::meaning::{BlobMeaning, MeaningRefusal};
use super::store_gate::{BlobStorePolicy, StoreDisposition};
use super::{
    BlobChunkVerifier, ChunkManifestLite, ChunkVerifyError, PersistBlobStorePolicy, SwarmConfig,
    SwarmError, SwarmScheduler,
};

/// An ADMITTED attestation that references at least one blob. The bridge
/// offers one per admitted row; the puller works out which shas.
#[derive(Debug, Clone)]
pub struct PullRequest {
    /// The referencing row, as persist admitted it.
    pub row: Attestation,
}

/// What happened when the bridge offered a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PullOffer {
    /// Queued for the puller.
    Queued,
    /// The row references no blob (or is a `holds_bytes` row); nothing to do.
    NotAReference,
    /// The queue is full; the offer was DROPPED, logged and counted. The
    /// row is still in persist, so a later re-read (a peer re-advertising
    /// it, a converger sweep) can offer it again.
    Dropped,
}

/// The bridge's handle: a bounded, non-blocking way to say "this row was
/// admitted and references a blob".
#[derive(Clone)]
pub struct PullSink {
    tx: mpsc::Sender<PullRequest>,
    dropped: Arc<AtomicU64>,
    /// CIRISEdge#779 — the puller's parked-DAG register, so the key-grant
    /// door can wake the DAG a grant names.
    key_waits: Arc<KeyWaits>,
}

impl std::fmt::Debug for PullSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PullSink")
            .field("capacity", &self.tx.capacity())
            .field("dropped", &self.dropped.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl PullSink {
    /// Offer an admitted row. Never blocks and never awaits: this runs on
    /// the replication apply path.
    ///
    /// The cheap pre-check ([`BlobMeaning::referenced_shas`]) keeps every
    /// row that references nothing — the overwhelming majority of the
    /// attestation plane — from being cloned across the channel.
    pub fn offer(&self, row: &Attestation) -> PullOffer {
        if BlobMeaning::referenced_shas(row).is_empty() {
            return PullOffer::NotAReference;
        }
        match self.tx.try_send(PullRequest { row: row.clone() }) {
            Ok(()) => PullOffer::Queued,
            Err(mpsc::error::TrySendError::Full(req)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                tracing::warn!(
                    attestation_id = %req.row.attestation_id,
                    dropped_total = n,
                    "pull queue FULL — an admitted row that references a blob was not \
                     queued for fetch. The row is held; the bytes will not be pulled \
                     until it is offered again (CIRISEdge#601)"
                );
                PullOffer::Dropped
            }
            Err(mpsc::error::TrySendError::Closed(req)) => {
                tracing::error!(
                    attestation_id = %req.row.attestation_id,
                    "pull queue CLOSED — the BlobPuller has exited; blob pulls are dark \
                     on this node (CIRISEdge#601)"
                );
                PullOffer::Dropped
            }
        }
    }

    /// CIRISEdge#779 — **a key_grant set was admitted.** If it wrote a wrap
    /// to this node, wake the parked DAG pull waiting on it: a content-axis
    /// set names the row (manifest or chunk) it opens, an epoch-axis set the
    /// epoch, a stream-axis set (CIRISEdge#797) the stream epoch. Never blocks and never awaits (the apply path's door, like
    /// [`Self::offer`]); the puller's next tick re-pulls each woken DAG once,
    /// from a fresh retry ladder, however many of its grants landed.
    pub fn key_grant_admitted(
        &self,
        admission: &ciris_persist::federation::key_grant::KeyGrantAdmission,
    ) {
        use ciris_persist::federation::key_grant::KeyGrantAxis;
        if admission.wraps_written == 0 {
            return;
        }
        match &admission.axis {
            KeyGrantAxis::Content { at_rest_sha256, .. } => {
                let mut sha = [0u8; 32];
                if hex::decode_to_slice(at_rest_sha256, &mut sha).is_ok() {
                    self.key_waits.wake_content(sha);
                }
            }
            KeyGrantAxis::Epoch { epoch, .. } => {
                self.key_waits.wake_epoch(*epoch);
            }
            // CIRISEdge#797 (persist v53, CIRISPersist#969) — a stream-epoch
            // set: one per `(stream, epoch)`, opening every chunk of a v4 DAG
            // sealed at that epoch.
            KeyGrantAxis::Stream {
                stream_id, epoch, ..
            } => {
                self.key_waits.wake_stream(stream_id, *epoch);
            }
        }
    }

    /// How many offers the full queue has dropped since start-up.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// A sink whose puller will never run — for tests and for consumers
    /// that want the bridge's hook wired but no puller behind it. Every
    /// offer reports `Dropped` (closed), loudly.
    #[doc(hidden)]
    #[must_use]
    pub fn disconnected() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            key_waits: Arc::new(KeyWaits::new(1)),
        }
    }
}

/// Bounds and cadence. Every number is a ceiling, never a target.
#[derive(Debug, Clone)]
pub struct PullConfig {
    /// Offers the bridge may queue ahead of the puller. Beyond this, offers
    /// are dropped and counted.
    pub queue_capacity: usize,
    /// Fetches the puller runs concurrently. Each is a swarm fetch with its
    /// own per-peer limits; this bounds the node's total pull fan-out.
    pub max_in_flight: usize,
    /// Rows the puller will retry after a fetch found no fresh holder or
    /// failed transiently. Beyond this the oldest retry is dropped.
    pub retry_capacity: usize,
    /// How many times one blob is retried before it is given up on.
    pub max_attempts: u32,
    /// Delay before the first retry; doubles per attempt.
    pub retry_backoff: Duration,
    /// The swarm scheduler's own knobs.
    pub swarm: SwarmConfig,
    /// The blessed-sender roster for COMMONS content (axis 1 of the store
    /// gate, `CIRISEdge#581`): a federation-tier blob is pulled only from a
    /// holder on this list. Empty refuses every commons blob — the
    /// standing rule ("only content from approved senders gets replicated
    /// at public/federation tiers"). Cohort/family/self content is judged
    /// on membership, not this list.
    pub commons_allowlist: Vec<String>,
    /// The operator's own answer (axis 3): what this node agrees to hold
    /// and whether it advertises holding it, per content class.
    pub consent: super::store_gate::OperatorStoreConsent,
    /// CIRISEdge#739 (`FSD/CONTENT_TRANSFER.md` §6.7.5) — **chunk requests a
    /// sealed-DAG pull keeps in flight at once** (`K`). Each is one leased
    /// lane on the holder's scoped link pool, so this is also the most
    /// scoped links the pull holds to one holder. The default is read off
    /// the measured curve in `tests/bigfile_739.rs`, not chosen by taste:
    /// it is the knee (§6.7.5: K = 4 → 8 is +49 %, 8 → 16 is inside the
    /// run-to-run noise while the per-lane transient heap doubles). `0`
    /// behaves as `1`.
    pub dag_chunks_in_flight: usize,
    /// CIRISEdge#739 — **the byte budget of those requests**: the sum of the
    /// STORED sizes (plaintext + `AT_REST_ENVELOPE_OVERHEAD`) of every chunk
    /// in flight stays at or under this, whatever `K` says — the bound on the
    /// chunk bytes the pull holds, independent of the file's size (each
    /// lane's transient — the answer envelope's JSON form, CIRISEdge#742 — is
    /// on top of it; §6.7.5 measures both). At least one request is always
    /// admitted, so a budget below one chunk degrades to `K = 1` rather than
    /// to a stall.
    pub dag_bytes_in_flight: u64,
    /// CIRISPersist#957 — **the most chunks one adopt hands persist** in a
    /// sealed-DAG pull. Verified chunks wait for a batch and go through
    /// `Engine::adopt_sealed_chunks` in one writer transaction. A batch is
    /// flushed when it holds this many chunks or persist's byte bound
    /// (`MAX_BATCH_BYTES`), when no fetch is in flight (the run drained, the
    /// byte budget is full, or the pull ended or stopped), and at the end.
    /// Chunks waiting for a batch still count against `dag_bytes_in_flight`
    /// until the adopt returns. The value is clamped to `1..=MAX_CHUNKS_PER_BATCH`.
    /// At `1`, each chunk is adopted as it arrives, concurrently, which is the
    /// v36.1.0 behaviour. Above `1`, one batch is adopted at a time while the
    /// lanes keep fetching. The default comes from the curve in
    /// `tests/bigfile_739.rs` (see [`DEFAULT_DAG_ADOPT_BATCH_CHUNKS`]).
    pub dag_adopt_batch_chunks: usize,
    /// CIRISEdge#763 (CC 6.1.5.3) — **how often the puller runs a
    /// durability pass** over this node's `self` and `family` files
    /// ([`BlobPuller::durability_sweep`]): it re-files a lapsing `here`,
    /// reports a lost copy `none`, and repairs what this node is missing,
    /// rarest first. `None` turns the pass off (a host driving it itself).
    pub durability_interval: Option<Duration>,
}

/// CIRISPersist#957 — the default adopt batch (see
/// [`PullConfig::dag_adopt_batch_chunks`]), read off the 256 MiB curve in
/// `tests/bigfile_739.rs` at the default `K` and byte budget. Per-chunk adopt
/// time falls from 90 ms (batch of 1, eight at once) to 8.7 ms at 16, and the
/// pull is fastest at 16. At 32 and 64 the waiting and adopting chunks take
/// the whole default budget (8 MiB, about 31 chunks of 256 KiB). The lanes
/// then stop fetching while a batch fills or commits, and the pull slows to
/// 1.3× and 3.1× the time at 16. So the default is about half the budget's
/// chunk count at `files::publish`'s segment size.
pub const DEFAULT_DAG_ADOPT_BATCH_CHUNKS: usize = 16;

/// CIRISEdge#763 — the default durability pass cadence (see
/// [`PullConfig::durability_interval`]): well inside the 24 h re-file horizon
/// ([`CUSTODY_REFRESH`](super::durability::CUSTODY_REFRESH)), and often
/// enough that a device that lost a copy is repaired within the hour.
pub const DEFAULT_DURABILITY_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// CIRISEdge#739 — the default `K` (see [`PullConfig::dag_chunks_in_flight`]).
pub const DEFAULT_DAG_CHUNKS_IN_FLIGHT: usize = 8;
/// CIRISEdge#739 — the default byte budget (see
/// [`PullConfig::dag_bytes_in_flight`]): eight of the largest chunk persist
/// admits (`DEFAULT_INLINE_BYTES_CAP`), i.e. `K` full lanes at the producer's
/// ceiling, and 32 lanes at `files::publish`'s 256 KiB segments.
pub const DEFAULT_DAG_BYTES_IN_FLIGHT: u64 =
    8 * ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP as u64;

impl Default for PullConfig {
    fn default() -> Self {
        Self {
            queue_capacity: 256,
            max_in_flight: 4,
            retry_capacity: 256,
            max_attempts: 5,
            retry_backoff: Duration::from_secs(5),
            swarm: SwarmConfig::default(),
            commons_allowlist: Vec::new(),
            consent: super::store_gate::OperatorStoreConsent::default(),
            dag_chunks_in_flight: DEFAULT_DAG_CHUNKS_IN_FLIGHT,
            dag_bytes_in_flight: DEFAULT_DAG_BYTES_IN_FLIGHT,
            dag_adopt_batch_chunks: DEFAULT_DAG_ADOPT_BATCH_CHUNKS,
            durability_interval: Some(DEFAULT_DURABILITY_INTERVAL),
        }
    }
}

/// The outcome of one `(row, sha)` pull. Every arm is a named state, so a
/// test can assert which one it reached and a log line can say why nothing
/// happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PullOutcome {
    /// The bytes were already here; nothing fetched.
    AlreadyHeld,
    /// Fetched, gated, stored. `announced` is whether a `holds_bytes` claim
    /// went out — the gate's verdict, carried into persist's door.
    Stored { announced: bool },
    /// Another pull for this sha is in flight; this one stood down.
    InFlight,
    /// The row does not give these bytes a meaning this node accepts.
    NoMeaning(MeaningRefusal),
    /// The store gate said no. The refusal is named on the error.
    Refused(String),
    /// persist knows no fresh holder; queued for retry (or given up, if
    /// `attempts` reached the ceiling).
    NoHolders { attempts: u32, retrying: bool },
    /// CIRISEdge#646 — a self/family pull found no node of the author to
    /// ask. These tiers never consult the claim index (CC 5.2: no
    /// `holds_bytes` exists for them by construction); the holders are the
    /// author's nodes, resolved through the directory
    /// (`FSD/CONTENT_TRANSFER.md` §6.2). `retrying` when the directory has
    /// not converged on the author yet (`NotYetDiscovered`) or every node
    /// resolved is this one — a device coming online is a retry, not a
    /// terminal miss.
    NoOtherNode { attempts: u32, retrying: bool },
    /// CIRISEdge#646 — a self/family row whose group id needs the author's
    /// identity (`FSD/CONTENT_TRANSFER.md` §6.2) arrived before the
    /// directory converged on that author. Distinct from
    /// [`Self::NoMeaning`]'s `GroupWithoutId`, which is a row that names no
    /// group at all: this one names it through a fact this node does not
    /// hold YET, so it is retried rather than refused. Distinct from
    /// [`Self::NoOtherNode`] too, which is the rung below — a group we could
    /// name but no node to ask.
    AuthorUnresolved { attempts: u32, retrying: bool },
    /// The fetch failed for a reason that may clear (timeout, transport,
    /// a dishonest holder); queued for retry or given up.
    FetchFailed { reason: String, retrying: bool },
    /// The bytes arrived and the store door refused them. Not retried: the
    /// same bytes and the same provenance will get the same answer.
    StoreFailed(String),
    /// A `CommunityDek` pointer with no sealed-under epoch. Not retried;
    /// the row will never carry one.
    NoEpoch,
    /// CIRISEdge#638 item 2 / CC 5.3.2.5 — the bytes hashed to the row's
    /// address but their length is not the size the row DECLARES (the OCI
    /// rule: a declared size is checked, never trusted). `declared` is the
    /// stored length the pointer's `size` implies at its tier. Not adopted,
    /// not retried: the row, not the holder, is wrong.
    SizeMismatch { declared: u64, received: u64 },
    /// CIRISEdge#717 — the pointer names a **chunk DAG** (`stream_id` is
    /// present) and the DAG pull (`FSD/CONTENT_TRANSFER.md` §6.7) refused it
    /// by name — before the manifest, at the manifest, or at a chunk — and
    /// left no file that reads wrong. Which rung, and why, is on the
    /// refusal; each is counted under its own `blob_pull_refusals` tag
    /// ([`DagPullRefusal::tag`]). Not retried: the row, the manifest or the
    /// holder is wrong, and none changes by asking again.
    DagRefused(DagPullRefusal),
    /// CIRISEdge#717 — a sealed DAG's manifest is held but this node cannot
    /// open it YET: the `key_grant` that wraps the DAG's DEK to this node
    /// has not arrived (the key follows the bytes, in either order — persist
    /// I61/I62). Queued for retry; the manifest stays held and the retry
    /// resumes from it.
    ///
    /// CIRISEdge#779 — also the state of a `self` / `family` DAG whose every
    /// chunk is HELD but some chunk's own wrap to this node has not arrived:
    /// it is not promoted, reported `Stored` or receipted until every chunk
    /// opens here. A retry that finds fewer chunks waiting than the last one
    /// restarts the attempt ladder; only consecutive stalls spend it.
    DagAwaitingKey { attempts: u32, retrying: bool },
}

/// A `CommunityDek` pointer with no sealed-under epoch cannot be adopted,
/// so it is not worth a fetch (CIRISEdge#601). Counted under
/// [`PULL_REFUSAL_NO_EPOCH`] like every other named refusal (CIRISEdge#735):
/// before, the only community-tier refusal the pull could reach was the one
/// it did not count.
fn epoch_refusal(
    row: &Attestation,
    blob_hex: &str,
    meaning: &BlobMeaning,
    metrics: Option<&crate::observability::EdgeMetrics>,
) -> Option<PullOutcome> {
    let pointer = meaning.pointer()?;
    if pointer.tier != CryptoTier::CommunityDek || pointer.epoch.is_some() {
        return None;
    }
    if let Some(m) = metrics {
        m.inc_blob_pull_refusal(PULL_REFUSAL_NO_EPOCH);
    }
    tracing::warn!(
        blob = %blob_hex,
        attestation_id = %row.attestation_id,
        "pull refused: a community_dek pointer with no sealed-under epoch — the \
         row predates the epoch-bearing pointer, and a guessed epoch is a blob \
         that reads NotGranted forever (CIRISEdge#601)"
    );
    Some(PullOutcome::NoEpoch)
}

/// The `blob_pull_refusals` tag for [`PullOutcome::SizeMismatch`].
pub const PULL_REFUSAL_SIZE_MISMATCH: &str = "size_mismatch";
/// The `blob_pull_refusals` tag for [`PullOutcome::NoEpoch`] (CIRISEdge#601 /
/// #735): a `community_dek` pointer naming no sealed-under epoch.
pub const PULL_REFUSAL_NO_EPOCH: &str = "no_epoch";
/// The `blob_pull_refusals` tag for [`DagPullRefusal::ManifestMismatch`].
pub const PULL_REFUSAL_DAG_MANIFEST_MISMATCH: &str = "dag_manifest_mismatch";
/// The `blob_pull_refusals` tag for [`DagPullRefusal::TotalSizeMismatch`].
pub const PULL_REFUSAL_DAG_TOTAL_SIZE_MISMATCH: &str = "dag_total_size_mismatch";
/// The `blob_pull_refusals` tag for [`DagPullRefusal::OverCap`].
pub const PULL_REFUSAL_DAG_OVER_CAP: &str = "dag_over_cap";
/// The `blob_pull_refusals` tag for [`DagPullRefusal::ChunkMismatch`].
pub const PULL_REFUSAL_DAG_CHUNK_MISMATCH: &str = "dag_chunk_mismatch";
/// The `blob_pull_refusals` tag for [`DagPullRefusal::ChunkMissing`].
pub const PULL_REFUSAL_DAG_CHUNK_MISSING: &str = "dag_chunk_missing";

/// CIRISEdge#717 — **why a chunk-DAG pull stopped**, by rung
/// (`FSD/CONTENT_TRANSFER.md` §6.7, the pull state table). Every arm is a
/// named state a test asserts and a `blob_pull_refusals` tag counts
/// ([`Self::tag`]). None is retried: the row, the manifest or the holder is
/// wrong, and asking again gets the same answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagPullRefusal {
    /// The bytes at the pointer's address are not the manifest the pointer
    /// describes: they do not hash to it, do not parse as a chunk manifest
    /// (persist names which — a sealed whole blob, a v1 manifest, a plaintext
    /// row), are not canonical, name a stream other than the pointer's, or
    /// are incoherent (chunk sizes that do not sum to `total_size`, a
    /// repeated `seq`, no chunks). `detail` is the finding.
    ManifestMismatch {
        /// What was found.
        detail: String,
    },
    /// The manifest's `total_size` is not the size the pointer declares
    /// (CC 5.3.2.5: a declared size is checked, never trusted). Compared to
    /// the PLAINTEXT total the manifest names — never to the row's
    /// `size_bytes`, which stays the manifest envelope's length after
    /// promotion (CIRISPersist#947).
    TotalSizeMismatch {
        /// The pointer's `size`.
        declared: u64,
        /// The manifest's `total_size`.
        manifest: u64,
    },
    /// The manifest asks for more than this node will do. `what` names the
    /// axis — `chunk_count`, `chunk_size` (the STORED body: the envelope at a
    /// sealed tier), `total_size` — `value` what it asked and `cap` the
    /// bound: persist's own caps, read off the opened view at a sealed tier
    /// and its constants at plaintext, decided BEFORE any chunk is fetched so
    /// a hostile manifest cannot make this node fetch or allocate unboundedly.
    OverCap {
        /// The axis.
        what: &'static str,
        /// What the manifest asked.
        value: u64,
        /// The bound.
        cap: u64,
    },
    /// A fetched chunk is not the one the manifest names at `seq`: it does
    /// not hash to the manifest's sha, or its length is not the one its
    /// declared size implies. Nothing of it is stored.
    ChunkMismatch {
        /// The chunk's position.
        seq: u64,
        /// What was found.
        detail: String,
    },
    /// Persist's promotion refused: a chunk the manifest names is not held
    /// as named, and `detail` (persist's own message) names the first
    /// missing `(seq, sha)`. Reached only if an adopt did not land what it
    /// said it did — the puller's own walk adopts every chunk first.
    ChunkMissing {
        /// Persist's finding.
        detail: String,
    },
}

impl DagPullRefusal {
    /// The `blob_pull_refusals` tag this refusal is counted under.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ManifestMismatch { .. } => PULL_REFUSAL_DAG_MANIFEST_MISMATCH,
            Self::TotalSizeMismatch { .. } => PULL_REFUSAL_DAG_TOTAL_SIZE_MISMATCH,
            Self::OverCap { .. } => PULL_REFUSAL_DAG_OVER_CAP,
            Self::ChunkMismatch { .. } => PULL_REFUSAL_DAG_CHUNK_MISMATCH,
            Self::ChunkMissing { .. } => PULL_REFUSAL_DAG_CHUNK_MISSING,
        }
    }
}

/// CIRISEdge#717 — **the manifest as the puller sees it, before a chunk
/// moves**: the shape [`check_dag_plan`] bounds, at either tier — built from
/// the view persist opened (sealed, [`Self::from_sealed_view`]) or the clear
/// manifest the puller parsed (plaintext, [`Self::from_clear_manifest`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DagPlan {
    /// The stream the manifest names. `None` for a v1 (plaintext) manifest,
    /// which names none.
    pub stream_id: Option<String>,
    /// The file's PLAINTEXT size, as the manifest states it.
    pub total_size: u64,
    /// `(seq, plaintext size)` per chunk, in manifest order.
    pub chunks: Vec<(u64, u64)>,
    /// Persist's per-chunk inline cap: the STORED body must fit it.
    pub inline_bytes_cap: u64,
    /// **The bytes this walk holds in memory at once, when it holds them
    /// all** (CIRISEdge#737). `Some` for a PLAINTEXT plan: persist's one-shot
    /// `put_blob_chunks_signing` takes every chunk together, so the walk
    /// buffers the whole DAG and bounds it by persist's whole-read constant.
    /// `None` for a sealed plan: each chunk is adopted at `(stream_id, seq)`
    /// as it arrives, so the pull is chunk-wise and its only size ceiling is
    /// the STORAGE bound (rule 4). The whole-read cap governs READS, not
    /// pulls (`FSD/CONTENT_TRANSFER.md` §6.7.3).
    pub in_memory_cap_bytes: Option<u64>,
    /// Persist's chunk-count cap.
    pub max_chunks: u64,
    /// Bytes persist adds to each chunk's stored body at this tier —
    /// `AT_REST_ENVELOPE_OVERHEAD` sealed, 0 at plaintext.
    pub per_chunk_overhead: u64,
}

impl DagPlan {
    /// The plan of a SEALED manifest persist opened for this node
    /// (`Engine::open_sealed_manifest_as`): the three caps are the view's.
    #[must_use]
    pub fn from_sealed_view(
        view: &ciris_persist::federation::chunk_dag_cascade::orchestrate::SealedManifestView,
    ) -> Self {
        Self {
            stream_id: Some(view.stream_id.clone()),
            total_size: view.total_size,
            chunks: view
                .chunks
                .iter()
                .map(|c| (c.seq, u64::from(c.size)))
                .collect(),
            inline_bytes_cap: view.inline_bytes_cap,
            in_memory_cap_bytes: None,
            max_chunks: view.max_chunks,
            per_chunk_overhead:
                ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD as u64,
        }
    }

    /// The plan of a CLEAR manifest (a plaintext DAG, [`parse_clear_manifest`]):
    /// the caps are persist's constants, and `inline_bytes_cap` is this
    /// node's. A v1 manifest positions no chunk, so `seq` is the index.
    #[must_use]
    pub fn from_clear_manifest(
        manifest: &ciris_persist::federation::ChunkManifest,
        inline_bytes_cap: u64,
    ) -> Self {
        Self {
            stream_id: manifest.stream_id.clone(),
            total_size: manifest.total_size,
            chunks: manifest
                .chunks
                .iter()
                .enumerate()
                .map(|(i, c)| (c.seq.unwrap_or(i as u64), u64::from(c.size)))
                .collect(),
            inline_bytes_cap,
            in_memory_cap_bytes: Some(
                ciris_persist::federation::chunk_dag_cascade::DAG_WHOLE_READ_CAP_BYTES,
            ),
            max_chunks: ciris_persist::federation::blobs::MAX_CHUNKS_PER_EPOCH,
            per_chunk_overhead: 0,
        }
    }
}

/// **The bounds, decided before a chunk moves** (CIRISEdge#717,
/// `FSD/CONTENT_TRANSFER.md` §6.7 — the `verified` rung). In order:
///
/// 1. the manifest names the POINTER's stream (a v1 manifest names none);
/// 2. `total_size` is the size the pointer declares (when it declares one:
///    a pre-#698 pointer declares nothing to check, as `declared_stored_len`);
/// 3. the chunk count is within `max_chunks` and is not zero;
/// 4. every chunk's STORED body (`size + per_chunk_overhead`) fits the inline
///    cap — the bound persist's adopt applies, applied here before the fetch;
/// 5. `total_size` is within what the chunk list can legally hold —
///    `chunk_count × (inline cap − per-chunk overhead)` — the STORAGE bound
///    (CIRISEdge#737; after rule 4 so an over-full chunk is named as such,
///    before rule 6 so an inflated total over well-sized chunks is named as
///    this; with rule 6 the bound is exact). A plaintext plan is also within
///    [`DagPlan::in_memory_cap_bytes`], the whole DAG being held until
///    persist's one-shot door takes it;
/// 6. the chunk sizes sum to `total_size` and no `seq` repeats.
///
/// Pure, so the rule is tested on the exact shapes `files::publish` produces.
///
/// # Errors
/// The first [`DagPullRefusal`] that applies.
pub fn check_dag_plan(
    pointer_stream_id: &str,
    declared: Option<u64>,
    plan: &DagPlan,
) -> Result<(), DagPullRefusal> {
    if let Some(named) = plan.stream_id.as_deref() {
        if named != pointer_stream_id {
            return Err(DagPullRefusal::ManifestMismatch {
                detail: format!(
                    "the manifest names stream {named:?} but the pointer names {pointer_stream_id:?}"
                ),
            });
        }
    }
    if let Some(declared) = declared {
        if declared != plan.total_size {
            return Err(DagPullRefusal::TotalSizeMismatch {
                declared,
                manifest: plan.total_size,
            });
        }
    }
    let count = plan.chunks.len() as u64;
    if count == 0 {
        return Err(DagPullRefusal::ManifestMismatch {
            detail: "a manifest over no chunks is content that opens to nothing".into(),
        });
    }
    if count > plan.max_chunks {
        return Err(DagPullRefusal::OverCap {
            what: "chunk_count",
            value: count,
            cap: plan.max_chunks,
        });
    }
    for (_, size) in &plan.chunks {
        let stored = size.saturating_add(plan.per_chunk_overhead);
        if stored > plan.inline_bytes_cap {
            return Err(DagPullRefusal::OverCap {
                what: "chunk_size",
                value: stored,
                cap: plan.inline_bytes_cap,
            });
        }
    }
    // CIRISEdge#737 — the pull is chunk-wise; its ceiling is what the
    // manifest can hold, not what a whole READ may materialize.
    let per_chunk_max = plan
        .inline_bytes_cap
        .saturating_sub(plan.per_chunk_overhead);
    let storage_bound = count.saturating_mul(per_chunk_max);
    if plan.total_size > storage_bound {
        return Err(DagPullRefusal::OverCap {
            what: "total_size_vs_chunks",
            value: plan.total_size,
            cap: storage_bound,
        });
    }
    if let Some(in_memory) = plan.in_memory_cap_bytes {
        if plan.total_size > in_memory {
            return Err(DagPullRefusal::OverCap {
                what: "total_size_in_memory",
                value: plan.total_size,
                cap: in_memory,
            });
        }
    }
    let mut sum: u64 = 0;
    let mut seen = HashSet::with_capacity(plan.chunks.len());
    for (seq, size) in &plan.chunks {
        sum = sum.saturating_add(*size);
        if !seen.insert(*seq) {
            return Err(DagPullRefusal::ManifestMismatch {
                detail: format!("chunk seq {seq} appears twice in the manifest"),
            });
        }
    }
    if sum != plan.total_size {
        return Err(DagPullRefusal::ManifestMismatch {
            detail: format!(
                "the chunk sizes sum to {sum} but the manifest says total_size {}",
                plan.total_size
            ),
        });
    }
    Ok(())
}

/// **A clear chunk manifest, read off the wire shape persist writes**
/// (`ChunkManifest::to_jcs_bytes`: `sha` as lowercase hex, keys sorted) —
/// the bytes a holder serves at a plaintext DAG's address. Persist's own
/// reader is crate-private, so the puller reads the same shape and PROVES
/// the reading by re-canonicalizing: the JCS of what it read must be the
/// bytes it was given, or the manifest is refused. A parse the puller cannot
/// round-trip is one it did not understand, whatever hashed.
///
/// # Errors
/// The finding, for [`DagPullRefusal::ManifestMismatch`].
pub fn parse_clear_manifest(
    bytes: &[u8],
) -> Result<ciris_persist::federation::ChunkManifest, String> {
    use ciris_persist::federation::{ChunkManifest, ChunkRef};
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ChunkRefWire {
        sha: String,
        size: u32,
        #[serde(default)]
        seq: Option<u64>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ManifestWire {
        v: u32,
        total_size: u64,
        chunks: Vec<ChunkRefWire>,
        #[serde(default)]
        chunk_tier: Option<String>,
        #[serde(default)]
        stream_id: Option<String>,
    }
    let wire: ManifestWire =
        serde_json::from_slice(bytes).map_err(|e| format!("not a chunk manifest: {e}"))?;
    let chunk_tier = match wire.chunk_tier.as_deref() {
        None => None,
        Some(s) => Some(
            [
                CryptoTier::Plaintext,
                CryptoTier::InvisibleEncrypted,
                CryptoTier::CommunityDek,
            ]
            .into_iter()
            .find(|t| t.as_str() == s)
            .ok_or_else(|| format!("unknown chunk_tier {s:?}"))?,
        ),
    };
    let mut chunks = Vec::with_capacity(wire.chunks.len());
    for (i, c) in wire.chunks.into_iter().enumerate() {
        let mut sha = [0u8; 32];
        hex::decode_to_slice(&c.sha, &mut sha)
            .map_err(|e| format!("chunk [{i}] sha is not 32 hex bytes: {e}"))?;
        chunks.push(ChunkRef {
            sha,
            size: c.size,
            seq: c.seq,
            // A clear manifest is never v4 (stream-keyed, sealed), so no
            // chunk names a stream epoch (CIRISPersist#969).
            epoch: None,
        });
    }
    let manifest = ChunkManifest {
        v: wire.v,
        total_size: wire.total_size,
        chunks,
        chunk_tier,
        stream_id: wire.stream_id,
    };
    if manifest.to_jcs_bytes() != bytes {
        return Err(
            "the manifest is not persist's canonical (JCS) encoding — the puller's reading of \
             it cannot be trusted"
                .into(),
        );
    }
    Ok(manifest)
}

/// CIRISEdge#717 — **where a DAG pull's bytes come from**, one address at a
/// time. Production is the swarm: [`BlobPuller::pull_one`] builds one over
/// the holders persist knows. A deployment with its own transport, or a
/// witness at the store level, hands [`BlobPuller::pull_dag_with`] its own.
///
/// A fetcher cannot inject bytes, only fail to produce them: the puller
/// verifies every body it receives against the address it asked for, and
/// the store gate (axis 1, trust) is asked of every holder the fetcher
/// names before the first fetch — whoever fetches, the gate runs.
#[async_trait::async_trait]
pub trait DagByteFetch: Send + Sync {
    /// The holders this fetcher draws from — the store gate's axis 1 is
    /// asked of every one of them before the first fetch.
    fn holders(&self) -> &[String];
    /// The bytes at `sha`, or why not. An `Err` ends the pull as
    /// [`PullOutcome::FetchFailed`] (retried; a sealed pull resumes from
    /// whatever it adopted before the failure).
    async fn fetch(&self, sha: [u8; 32]) -> Result<Vec<u8>, String>;
}

/// The production [`DagByteFetch`] (CIRISEdge#739): the pull's holders
/// ROUTED ONCE, then one `fetch_blob_chunk_scoped` per address — a chunk is
/// its own content-addressed row on the holder, served by
/// `PersistBlobChunkSource` exactly as a whole blob is, and asked for as
/// `(blob = the DAG's address, chunk = sha)`: the manifest as `(dag, dag)`,
/// each chunk as `(dag, chunk)`.
///
/// **Why the blob field is the DAG's, never the chunk's** (CIRISEdge#717,
/// field regression on v36.1.0): the holder's serve gate (CIRISEdge#499)
/// asks its chunk source for the SCOPE of the request's `blob_sha256`, and a
/// source answers that from a row that references the blob. A row references
/// the MANIFEST (the pointer's `content_sha256`); nothing references a
/// chunk. A self or family chunk has no community-DEK binding either, so a
/// request naming the chunk as its blob reads as `scope undeterminable` and
/// is withheld as `PolicyDenied` — every chunk, every retry, on every
/// scope-native holder, while the manifest (whose blob IS its row's) was
/// served. Naming the DAG puts the gate on the reference the row made, and a
/// withdrawal of that row (CIRISEdge#606) now refuses the chunks as it
/// refuses the manifest. Holder selection is the swarm's own rule
/// (`pick_peer`: lowest EWMA RTT with capacity, untimed holders first) kept
/// across the whole DAG in `peers`, so the second chunk already knows what
/// the first learned; a holder that misses or errors is struck and, at the
/// swarm's limits, retired for this pull.
///
/// Until this cut every chunk opened its own `SwarmScheduler` session: the
/// store gate asked again, every holder routed again, a task and a channel
/// per address, and the per-holder cap of `max_in_flight_per_peer` — which
/// bounded a single-holder pull (a self file: the author's one node) at four
/// lanes whatever the pipeline asked. The gate is asked once, in
/// `pull_dag_inner`, before the first byte moves; the fetcher never re-asks.
struct SwarmFetch {
    edge: Arc<crate::Edge>,
    holders: Vec<String>,
    meaning: BlobMeaning,
    swarm: SwarmConfig,
    /// The pipeline's `K`: the per-holder capacity here, since the pipeline
    /// itself never has more than `K` requests outstanding in total.
    lanes: u32,
    /// The DAG's address — the manifest's sha, the pointer's
    /// `content_sha256` — named as the `blob` of every request.
    dag: [u8; 32],
    blob_hex: String,
    routes: tokio::sync::OnceCell<Result<HashMap<String, super::BlobRecipient>, String>>,
    peers: Mutex<HashMap<String, super::PeerState>>,
}

impl SwarmFetch {
    fn new(
        edge: Arc<crate::Edge>,
        holders: Vec<String>,
        meaning: BlobMeaning,
        swarm: SwarmConfig,
        lanes: usize,
        dag: [u8; 32],
    ) -> Self {
        let peers = holders
            .iter()
            .map(|h| (h.clone(), super::PeerState::default()))
            .collect();
        Self {
            edge,
            holders,
            meaning,
            swarm,
            lanes: u32::try_from(lanes.max(1)).unwrap_or(u32::MAX),
            dag,
            blob_hex: hex::encode(dag),
            routes: tokio::sync::OnceCell::new(),
            peers: Mutex::new(peers),
        }
    }

    /// The holders' scoped addresses, resolved on the first fetch and held
    /// for the DAG (CIRISEdge#499: the route follows the key plane).
    async fn routes(&self) -> Result<&HashMap<String, super::BlobRecipient>, String> {
        self.routes
            .get_or_init(|| async {
                let router = self.edge.blob_scope_router();
                let metrics = self.edge.metrics();
                super::resolve_holder_routes(
                    &router,
                    Some(&self.meaning.key_plane()),
                    &self.holders,
                    &self.blob_hex,
                    Some(&metrics),
                )
            })
            .await
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Pick a holder with capacity and book one request against it.
    fn pick(&self) -> Option<String> {
        let mut peers = self.peers.lock().ok()?;
        let peer = super::pick_peer(&peers, self.lanes)?;
        if let Some(state) = peers.get_mut(&peer) {
            state.in_flight = state.in_flight.saturating_add(1);
        }
        Some(peer)
    }

    /// Release the booking and record what the holder did.
    fn settle(&self, peer: &str, record: impl FnOnce(&mut super::PeerState)) {
        if let Ok(mut peers) = self.peers.lock() {
            if let Some(state) = peers.get_mut(peer) {
                state.in_flight = state.in_flight.saturating_sub(1);
                record(state);
            }
        }
    }
}

#[async_trait::async_trait]
impl DagByteFetch for SwarmFetch {
    fn holders(&self) -> &[String] {
        &self.holders
    }

    async fn fetch(&self, sha: [u8; 32]) -> Result<Vec<u8>, String> {
        let routes = self.routes().await?;
        let alpha = self.swarm.ewma_alpha;
        let strike_limit = self.swarm.error_strike_limit;
        let timeout = self.swarm.per_request_timeout;
        // Bounded: every holder may be struck to its limit and no further.
        let max_attempts = routes.len().max(1) * (strike_limit.max(1) as usize + 1);
        let mut last = String::from("no holder accepted the request");
        for _ in 0..max_attempts {
            let Some(peer) = self.pick() else {
                return Err(format!("no holders left for {}: {last}", hex::encode(sha)));
            };
            let Some(recipient) = routes.get(&peer) else {
                // Unroutable holders were dropped by `resolve_holder_routes`
                // (loudly); one reaching here is not a candidate.
                self.settle(&peer, |s| s.demoted = true);
                continue;
            };
            let started = Instant::now();
            match self
                .edge
                .fetch_blob_chunk_scoped(recipient, self.dag, sha, timeout)
                .await
            {
                Ok(crate::ChunkResult::Bytes(bytes)) => {
                    self.settle(&peer, |s| s.record_rtt(started.elapsed(), alpha));
                    return Ok(bytes);
                }
                Ok(crate::ChunkResult::ChunkMiss { reason }) => {
                    // The wire reason is `MissReason`'s Debug repr (the
                    // scheduler's convention).
                    let gone = reason.contains("Withdrawn") || reason.contains("Revoked");
                    let hard = reason.contains("PolicyDenied") || reason.contains("DiskPressure");
                    self.settle(&peer, |s| {
                        if hard {
                            s.demoted = true;
                        } else {
                            s.record_error_strike(strike_limit);
                        }
                    });
                    if gone {
                        return Err(format!("withdrawn or revoked federation-wide: {reason}"));
                    }
                    last = format!("{peer}: chunk miss {reason}");
                }
                Err(e) => {
                    self.settle(&peer, |s| {
                        s.record_rtt(timeout, alpha);
                        s.record_error_strike(strike_limit);
                    });
                    last = format!("{peer}: {e}");
                }
            }
        }
        Err(last)
    }
}

/// CIRISEdge#739 (`FSD/CONTENT_TRANSFER.md` §6.7.5) — **may the pipeline
/// admit the next chunk request?** `in_flight` requests are outstanding
/// holding `bytes_in_flight` of stored bytes; the next would add `stored`.
/// Admitted while both bounds hold — fewer than `lanes` outstanding AND the
/// budget not exceeded — except that an EMPTY pipeline always admits one:
/// the budget bounds memory, it never stalls a pull whose chunks are larger
/// than it. Pure, so the rule is a test.
#[must_use]
pub fn pipeline_admits(
    in_flight: usize,
    lanes: usize,
    bytes_in_flight: u64,
    stored: u64,
    budget: u64,
) -> bool {
    if in_flight == 0 {
        return true;
    }
    in_flight < lanes.max(1) && bytes_in_flight.saturating_add(stored) <= budget
}

/// CIRISPersist#957 — **is the waiting run of verified chunks ready to go to
/// persist as one batch?** `pending` chunks of `pending_bytes` envelope bytes
/// are waiting and `fetching` requests are still out. Ready when the batch is
/// full (`batch_max` chunks, or persist's `MAX_BATCH_BYTES`), or when nothing
/// is being fetched: the run drained, the byte budget is full, or the pull
/// ended or stopped. Waiting for a fuller batch would then wait forever. Pure,
/// so the rule is a test.
#[must_use]
pub fn adopt_batch_ready(
    pending: usize,
    pending_bytes: usize,
    fetching: usize,
    batch_max: usize,
) -> bool {
    use ciris_persist::federation::blobs::MAX_BATCH_BYTES;
    pending > 0
        && (fetching == 0 || pending >= batch_max.max(1) || pending_bytes >= MAX_BATCH_BYTES)
}

/// CIRISPersist#957 — **how many of the waiting chunks (front first) one
/// batch takes**: at most `batch_max` (clamped to persist's
/// `MAX_CHUNKS_PER_BATCH`) and at most persist's `MAX_BATCH_BYTES` of
/// envelopes, and always at least one, so a chunk larger than the byte bound
/// still goes (persist refuses it by name rather than the pull stalling).
/// Pure, so the rule is a test.
#[must_use]
pub fn adopt_batch_take(sizes: &[usize], batch_max: usize) -> usize {
    use ciris_persist::federation::blobs::{MAX_BATCH_BYTES, MAX_CHUNKS_PER_BATCH};
    let cap = batch_max.clamp(1, MAX_CHUNKS_PER_BATCH);
    let mut bytes = 0usize;
    let mut n = 0usize;
    for &s in sizes.iter().take(cap) {
        if n > 0 && bytes.saturating_add(s) > MAX_BATCH_BYTES {
            break;
        }
        bytes = bytes.saturating_add(s);
        n += 1;
    }
    n
}

/// CIRISEdge#797 — **what a DAG parked on its chunk keys waits for**, from
/// persist's readiness door's `missing`: the stream epochs a v4 DAG lacks
/// (woken by their `key_grant:stream:v1` sets), else the rows a v2 DAG lacks
/// a content wrap for (each chunk, or a v3 child manifest). A DAG names one
/// shape: persist keys a stream per chunk or per epoch, never both.
pub(crate) fn awaiting_of(
    missing: &[ciris_persist::federation::chunk_dag_cascade::orchestrate::MissingChunkKey],
) -> key_wake::Awaiting {
    use ciris_persist::federation::chunk_dag_cascade::orchestrate::MissingChunkKey as M;
    let streams: Vec<(String, u64)> = missing
        .iter()
        .filter_map(|m| match m {
            M::Stream {
                stream_id, epoch, ..
            } => Some((stream_id.clone(), *epoch)),
            _ => None,
        })
        .collect();
    if !streams.is_empty() {
        return key_wake::Awaiting::Stream(streams);
    }
    key_wake::Awaiting::Content(
        missing
            .iter()
            .filter_map(|m| {
                let hex_sha = match m {
                    M::Content { chunk_sha256, .. } => chunk_sha256,
                    M::Child { child_sha256, .. } => child_sha256,
                    M::Stream { .. } => return None,
                };
                let mut sha = [0u8; 32];
                hex::decode_to_slice(hex_sha, &mut sha).ok().map(|()| sha)
            })
            .collect(),
    )
}

/// CIRISEdge#797 — **is this persist refusal the wait for a chunk's key?**
/// `blob_chunk_key_not_yet_granted` (CIRISPersist#969) is persist's typed
/// RETRYABLE: the viewer is authorized on the DAG and one chunk's key set
/// (its own content grant at v2, its stream epoch's at v4) has not arrived.
/// `Some` names what to park on; every other error is `None`, so a
/// stranger's `blob_not_granted` is never mistaken for a wait.
#[must_use]
pub(crate) fn awaiting_key_of(
    e: &ciris_persist::federation::BlobError,
) -> Option<key_wake::Awaiting> {
    use ciris_persist::federation::{BlobError, ChunkKeyRef};
    let BlobError::ChunkKeyNotYetGranted { key, .. } = e else {
        return None;
    };
    Some(match key {
        ChunkKeyRef::Stream { stream_id, epoch } => {
            key_wake::Awaiting::Stream(vec![(stream_id.clone(), *epoch)])
        }
        ChunkKeyRef::Content { at_rest_sha256 } => {
            let mut sha = [0u8; 32];
            key_wake::Awaiting::Content(
                hex::decode_to_slice(at_rest_sha256, &mut sha)
                    .ok()
                    .map(|()| sha)
                    .into_iter()
                    .collect(),
            )
        }
    })
}

/// One chunk the sealed-DAG walk still has to fetch: its position, its
/// ciphertext sha, its plaintext size (CIRISEdge#739), and the stream epoch
/// it is adopted at (CIRISEdge#797: the manifest's, for a v4 DAG).
struct DagWant {
    seq: u64,
    sha: [u8; 32],
    size: u64,
    epoch: u64,
}

/// CIRISEdge#797 — **the stream epoch a sealed chunk is adopted at**: the
/// manifest's own `epoch` for the chunk (a v4, stream-keyed DAG, whose reader
/// opens the chunk under that epoch's stream grant, CIRISPersist#969), else
/// the label a one-shot file is written under (a v2 DAG, per-chunk keys).
#[must_use]
pub fn chunk_adopt_epoch(manifest_epoch: Option<u64>) -> u64 {
    manifest_epoch.unwrap_or(crate::group_content::persist_store::STREAM_EPOCH)
}

/// CIRISEdge#797 — **how many of the waiting chunks (front first) share the
/// first one's epoch.** Persist's batch adopt takes ONE epoch per call, so a
/// batch never crosses an epoch: [`adopt_batch_take`]'s count is capped at
/// this run. Pure, so the rule is a test.
#[must_use]
pub fn same_epoch_run(epochs: &[u64]) -> usize {
    epochs
        .first()
        .map_or(0, |first| epochs.iter().take_while(|e| *e == first).count())
}

/// Why one lane of the sealed-DAG pipeline stopped (CIRISEdge#739).
enum LaneStop {
    /// The chunk did not arrive verified.
    Fetch(DagFetchStop),
    /// It arrived, but not at the length the manifest implies.
    Length { got: usize, expected: u64 },
}

/// Why one address did not arrive verified.
enum DagFetchStop {
    /// The fetcher could not produce it (transport, timeout, no holder).
    Transport(String),
    /// It arrived, but does not hash to the address asked for.
    HashMismatch { got: [u8; 32] },
}

/// The declared-size check (CIRISEdge#638 item 2): the hash already matched,
/// so a length that is not the declared one is the ROW misdescribing its
/// bytes — refused, never adopted.
fn size_refusal(
    row: &Attestation,
    blob_hex: &str,
    meaning: &BlobMeaning,
    received_len: usize,
    metrics: Option<&crate::observability::EdgeMetrics>,
) -> Option<PullOutcome> {
    let declared = meaning.pointer().and_then(declared_stored_len)?;
    let received = received_len as u64;
    if received == declared {
        return None;
    }
    if let Some(m) = metrics {
        m.inc_blob_pull_refusal(PULL_REFUSAL_SIZE_MISMATCH);
    }
    tracing::warn!(
        blob = %blob_hex,
        attestation_id = %row.attestation_id,
        declared,
        received,
        "pull refused: the bytes are not the size the row declares (CC 5.3.2.5)"
    );
    Some(PullOutcome::SizeMismatch { declared, received })
}

/// **The stored length a pointer's declared `size` implies** (CIRISEdge#638
/// item 2) — `None` when the row declares none (pre-#698) or the pointer is
/// a chunk DAG: its address is the manifest's, whose length no pointer
/// declares; the DAG pull compares `size` to the manifest's `total_size`
/// instead (CIRISEdge#717, [`check_dag_plan`]). A sealed tier stores the
/// plaintext inside an `AtRestEnvelope`, so the fetched body is `size` plus
/// persist's own exported overhead — the same arithmetic `files::must_chunk`
/// uses.
#[must_use]
pub fn declared_stored_len(pointer: &crate::group_content::BlobPointer) -> Option<u64> {
    if pointer.stream_id.is_some() {
        return None;
    }
    let size = pointer.size?;
    Some(match pointer.tier {
        CryptoTier::Plaintext => size,
        CryptoTier::CommunityDek | CryptoTier::InvisibleEncrypted => size.saturating_add(
            ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD as u64,
        ),
    })
}

/// Hash-only verifier for the pull's swarm fetch: the assembled blob is
/// stored by the puller through persist's own door, not chunk by chunk, so
/// the scheduler's per-chunk hook only has to answer "did the peer lie".
struct HashOnlyVerifier;

impl BlobChunkVerifier for HashOnlyVerifier {
    fn verify_and_store(
        &self,
        _blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        bytes: &[u8],
        // Honoured by the CALLER of the scheduler, not here: this verifier
        // stores nothing, so there is no door for it to choose. The puller
        // takes the same verdict back from
        // `fetch_blob_scoped_with_disposition` and picks the persist door.
        _disposition: StoreDisposition,
    ) -> Result<(), ChunkVerifyError> {
        use sha2::{Digest as _, Sha256};
        let got: [u8; 32] = Sha256::digest(bytes).into();
        if got != chunk_sha256 {
            return Err(ChunkVerifyError::Mismatch {
                chunk_sha: hex::encode(chunk_sha256),
            });
        }
        Ok(())
    }
}

/// A pull that did not complete and may be tried again.
#[derive(Debug, Clone)]
struct Retry {
    row: Attestation,
    sha: [u8; 32],
    attempts: u32,
    not_before: std::time::Instant,
}

/// The worker. One per node; built by [`BlobPuller::spawn`].
pub struct BlobPuller<B> {
    edge: Arc<crate::Edge>,
    engine: ciris_persist::Engine,
    backend: Arc<B>,
    local_key_id: String,
    policy: Arc<dyn BlobStorePolicy>,
    config: PullConfig,
    in_flight: Mutex<HashSet<[u8; 32]>>,
    retries: Mutex<HashMap<[u8; 32], Retry>>,
    /// CIRISEdge#779 — every sealed DAG parked on a key, and what it waits
    /// on; shared with the [`PullSink`] so an admitted grant wakes it.
    key_waits: Arc<KeyWaits>,
    /// CIRISEdge#779 — per sealed DAG parked on its chunk keys, how many
    /// chunks lacked this node's wrap at the last attempt. A retry that finds
    /// fewer restarts the attempt ladder: the grants arrive one set per chunk,
    /// in `seq` order, for minutes on a big file, so only CONSECUTIVE retries
    /// that see no new grant count toward the ceiling. The wake
    /// ([`Self::key_waits`]) is what un-parks a DAG whose ladder ran out; this
    /// keeps a pull that is being fed from running out in the first place.
    chunk_keys_missing: Mutex<HashMap<[u8; 32], u64>>,
    /// CIRISEdge#779 — pulls the loop has handed out and not seen finish. A
    /// retry is counted under the ledger's lock as it leaves the ledger, so a
    /// DAG between two rungs of its ladder always shows a booked retry or a
    /// pull outstanding, never neither (see [`Self::ladder_spent`]).
    dispatched: AtomicUsize,
}

/// CIRISEdge#646 — the `scope:source` label for `blob_pull_sources`. A
/// closed set (four scope kinds × two sources) so the counter's keys are
/// enumerable; `author_nodes` is the CC 5.2 path, `claim_index` is
/// `list_holders`.
fn pull_source_tag(scope: &crate::CohortScope, author_nodes: bool) -> &'static str {
    use crate::CohortScope;
    match (scope, author_nodes) {
        (CohortScope::SelfOnly, true) => "self:author_nodes",
        (CohortScope::SelfOnly, false) => "self:claim_index",
        (CohortScope::Family, true) => "family:author_nodes",
        (CohortScope::Family, false) => "family:claim_index",
        (CohortScope::Cohort { .. }, true) => "community:author_nodes",
        (CohortScope::Cohort { .. }, false) => "community:claim_index",
        (CohortScope::Public, true) => "federation:author_nodes",
        (CohortScope::Public, false) => "federation:claim_index",
    }
}

impl<B> BlobPuller<B>
where
    B: FederationDirectory + BlobStorage + Send + Sync + 'static,
{
    /// Build the puller and start its loop. Returns the sink the bridge
    /// offers rows to and the loop's handle.
    ///
    /// `backend` is the persist backend `engine` is built over — the same
    /// substrate, reached as a concrete `BlobStorage` because `list_holders`
    /// and `has_blob` are not object-safe. `local_key_id` is this node's
    /// derived federation key: it is excluded from every holder set (a node
    /// does not fetch from itself) and it is the gate's "me".
    ///
    /// The store gate is ARMED here unconditionally, with persist's rosters
    /// as its facts. There is no unarmed puller: a puller exists only to
    /// take bytes this node did not ask for by hand, which is exactly the
    /// path the gate was built for (CIRISEdge#581).
    pub fn spawn(
        edge: Arc<crate::Edge>,
        engine: ciris_persist::Engine,
        backend: Arc<B>,
        directory: Arc<dyn FederationDirectory>,
        local_key_id: impl Into<String>,
        config: PullConfig,
    ) -> (PullSink, tokio::task::JoinHandle<()>) {
        Self::new(edge, engine, backend, directory, local_key_id, config).start()
    }

    /// Build the puller without starting it. [`Self::pull_one`] can then be
    /// driven directly — how a test asserts the arm one `(row, sha)` reaches
    /// — and [`Self::start`] runs the loop behind a sink.
    pub fn new(
        edge: Arc<crate::Edge>,
        engine: ciris_persist::Engine,
        backend: Arc<B>,
        directory: Arc<dyn FederationDirectory>,
        local_key_id: impl Into<String>,
        config: PullConfig,
    ) -> Arc<Self> {
        let local_key_id = local_key_id.into();
        let retry_capacity = config.retry_capacity;
        let policy: Arc<dyn BlobStorePolicy> = Arc::new(
            PersistBlobStorePolicy::new(directory, local_key_id.clone())
                .with_commons_allowlist(config.commons_allowlist.iter().cloned())
                .with_consent(config.consent),
        );
        Arc::new(Self {
            edge,
            engine,
            backend,
            local_key_id,
            policy,
            config,
            in_flight: Mutex::new(HashSet::new()),
            retries: Mutex::new(HashMap::new()),
            key_waits: Arc::new(KeyWaits::new(retry_capacity)),
            chunk_keys_missing: Mutex::new(HashMap::new()),
            dispatched: AtomicUsize::new(0),
        })
    }

    /// Start the loop. Returns the sink the bridge offers rows to and the
    /// loop's handle.
    pub fn start(self: Arc<Self>) -> (PullSink, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(self.config.queue_capacity.max(1));
        let sink = PullSink {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
            key_waits: Arc::clone(&self.key_waits),
        };
        let handle = tokio::spawn(self.run(rx));
        (sink, handle)
    }

    async fn run(self: Arc<Self>, mut rx: mpsc::Receiver<PullRequest>) {
        let limiter = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_in_flight.max(1),
        ));
        let mut tick =
            tokio::time::interval(self.config.retry_backoff.max(Duration::from_millis(50)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // CIRISEdge#763 — the durability pass, on its own slower cadence.
        let mut durability = self.config.durability_interval.map(|every| {
            let mut t = tokio::time::interval_at(
                tokio::time::Instant::now() + every,
                every.max(Duration::from_secs(1)),
            );
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            t
        });
        loop {
            tokio::select! {
                () = async {
                    match durability.as_mut() {
                        Some(t) => { t.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let sweep = self.durability_sweep().await;
                    for r in sweep.repairs {
                        self.dispatched.fetch_add(1, Ordering::SeqCst);
                        self.dispatch(&limiter, r.row, r.sha, 0);
                    }
                }
                req = rx.recv() => {
                    let Some(req) = req else { break };
                    for sha in BlobMeaning::referenced_shas(&req.row) {
                        self.dispatched.fetch_add(1, Ordering::SeqCst);
                        self.dispatch(&limiter, req.row.clone(), sha, 0);
                    }
                }
                _ = tick.tick() => {
                    for r in self.due_retries() {
                        self.dispatch(&limiter, r.row, r.sha, r.attempts);
                    }
                    for (sha, row) in self.woken_dags() {
                        self.dispatch(&limiter, row, sha, 0);
                    }
                }
            }
        }
        tracing::info!("BlobPuller: sink closed, exiting");
    }

    /// Run one pull. The caller has already counted it in `dispatched`; the
    /// task uncounts it when the pull is over.
    fn dispatch(
        self: &Arc<Self>,
        limiter: &Arc<tokio::sync::Semaphore>,
        row: Attestation,
        sha: [u8; 32],
        attempts: u32,
    ) {
        let me = Arc::clone(self);
        let limiter = Arc::clone(limiter);
        tokio::spawn(async move {
            if let Ok(_permit) = limiter.acquire().await {
                let outcome = me.pull_one(&row, sha, attempts).await;
                tracing::debug!(
                    blob = %hex::encode(sha),
                    attestation_id = %row.attestation_id,
                    ?outcome,
                    "pull"
                );
            }
            me.dispatched.fetch_sub(1, Ordering::SeqCst);
        });
    }

    /// CIRISEdge#779 — the parked DAGs a grant woke since the last tick, not
    /// in flight, each once and from a fresh ladder (a booked retry for the
    /// same DAG is dropped: this dispatch replaces it).
    fn woken_dags(&self) -> Vec<([u8; 32], Attestation)> {
        let busy = match self.in_flight.lock() {
            Ok(set) => set.clone(),
            Err(_) => return Vec::new(),
        };
        let woken = self.key_waits.take_woken(&busy);
        if !woken.is_empty() {
            let mut retries = self.retries.lock().ok();
            if let Some(retries) = retries.as_mut() {
                for (sha, _) in &woken {
                    retries.remove(sha);
                }
            }
            // Counted before the lock drops: see `dispatched`.
            self.dispatched.fetch_add(woken.len(), Ordering::SeqCst);
            drop(retries);
        }
        woken
    }

    /// CIRISEdge#779 — a parked DAG stops waiting on its key once the pull
    /// ends any way but parked or deduped: stored, held, or refused for
    /// good. A transient failure keeps it, so a grant can still wake it.
    fn settle_key_wait(&self, sha: [u8; 32], outcome: &PullOutcome) {
        if matches!(
            outcome,
            PullOutcome::Stored { .. }
                | PullOutcome::AlreadyHeld
                | PullOutcome::Refused(_)
                | PullOutcome::DagRefused(_)
                | PullOutcome::NoMeaning(_)
        ) {
            self.key_waits.forget(sha);
        }
    }

    /// Whether a retry is booked for `sha`.
    #[cfg(test)]
    pub(crate) fn retry_booked(&self, sha: [u8; 32]) -> bool {
        self.retries.lock().is_ok_and(|r| r.contains_key(&sha))
    }

    /// Whether the loop has given up on `sha`: no retry booked and no pull
    /// outstanding. "No retry booked" alone is not it: a due retry leaves the
    /// ledger before its pull runs and books the next rung, so between rungs
    /// the ledger is empty while the ladder is not spent. Read under the
    /// ledger's lock, where a retry leaving it is already counted.
    #[cfg(test)]
    pub(crate) fn ladder_spent(&self, sha: [u8; 32]) -> bool {
        self.retries
            .lock()
            .is_ok_and(|r| !r.contains_key(&sha) && self.dispatched.load(Ordering::SeqCst) == 0)
    }

    fn due_retries(&self) -> Vec<Retry> {
        let now = std::time::Instant::now();
        let Ok(mut retries) = self.retries.lock() else {
            return Vec::new();
        };
        let due: Vec<[u8; 32]> = retries
            .iter()
            .filter(|(_, r)| r.not_before <= now)
            .map(|(k, _)| *k)
            .collect();
        let due: Vec<Retry> = due.into_iter().filter_map(|k| retries.remove(&k)).collect();
        // Counted before the lock drops: see `dispatched`.
        self.dispatched.fetch_add(due.len(), Ordering::SeqCst);
        due
    }

    /// CIRISEdge#779 — record that `sha` is parked with `missing` chunk
    /// keys outstanding (per chunk at v2, per stream epoch at v4); `true` when that is fewer than at the last attempt,
    /// i.e. the grants are arriving. A first sighting is not progress, so a
    /// memory dropped at the retry ledger's capacity can only spend attempts,
    /// never restart the ladder.
    fn chunk_keys_progressed(&self, sha: [u8; 32], missing: u64) -> bool {
        let Ok(mut seen) = self.chunk_keys_missing.lock() else {
            return false;
        };
        if seen.len() >= self.config.retry_capacity && !seen.contains_key(&sha) {
            seen.clear();
        }
        match seen.insert(sha, missing) {
            Some(before) => missing < before,
            None => false,
        }
    }

    fn forget_chunk_keys(&self, sha: [u8; 32]) {
        if let Ok(mut seen) = self.chunk_keys_missing.lock() {
            seen.remove(&sha);
        }
    }

    /// Book a retry, bounded. Returns whether it was booked (false when the
    /// attempt ceiling is reached).
    fn book_retry(&self, row: &Attestation, sha: [u8; 32], attempts: u32) -> bool {
        if attempts + 1 >= self.config.max_attempts {
            return false;
        }
        let backoff = self
            .config
            .retry_backoff
            .checked_mul(1u32 << attempts.min(6))
            .unwrap_or(self.config.retry_backoff);
        let Ok(mut retries) = self.retries.lock() else {
            return false;
        };
        if retries.len() >= self.config.retry_capacity && !retries.contains_key(&sha) {
            // Drop the retry that has waited longest. Bounded means bounded.
            if let Some(oldest) = retries
                .iter()
                .min_by_key(|(_, r)| r.not_before)
                .map(|(k, _)| *k)
            {
                retries.remove(&oldest);
                tracing::warn!(
                    dropped = %hex::encode(oldest),
                    "pull retry ledger FULL — dropped the oldest pending retry (CIRISEdge#601)"
                );
            }
        }
        retries.insert(
            sha,
            Retry {
                row: row.clone(),
                sha,
                attempts: attempts + 1,
                not_before: std::time::Instant::now() + backoff,
            },
        );
        true
    }

    /// CIRISEdge#763 (CC 6.1.5.3) — **one durability pass** over the `self`
    /// and `family` files this node's persons can read: the self room of each
    /// principal behind this node, and every family that principal is an
    /// active member of, through the drive's own gated listing
    /// ([`crate::files::in_room`]). For each file whose audience
    /// ([`durability::row_deficit`](super::durability::row_deficit), persist's
    /// rule) contains this node:
    ///
    /// - held whole, and this node's report is not a live `here` or is older
    ///   than [`CUSTODY_REFRESH`](super::durability::CUSTODY_REFRESH): `here`
    ///   is (re-)filed;
    /// - not held whole (never pulled, or a chunk lost): a live `here` of
    ///   this node's is corrected to `none`, so the cohort's deficit lists it,
    ///   and the file is a [`Repair`](super::durability::Repair).
    ///
    /// Repairs come back **rarest first**
    /// ([`rarest_first`](super::durability::rarest_first)); the run loop
    /// dispatches them in that order, each through [`Self::pull_one`], whose
    /// holder rung adds the deficit's live holders. A file outside this
    /// node's audience (a server-class node and the owner's self content, CC
    /// 3.3.7) is counted and left alone.
    pub async fn durability_sweep(&self) -> super::durability::DurabilitySweep {
        const PAGE: usize = 64;
        const MAX_FILES: usize = 4096;
        let mut out = super::durability::DurabilitySweep::default();
        let now = chrono::Utc::now();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut read = 0usize;
        for room in self.durability_rooms().await {
            let mut cursor = None;
            loop {
                let page = match crate::files::in_room(
                    &self.engine,
                    &room,
                    &self.local_key_id,
                    PAGE,
                    cursor.take(),
                )
                .await
                {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::warn!(room = %room, error = %e, "durability pass: listing failed");
                        break;
                    }
                };
                for file in page.files {
                    read += 1;
                    self.durability_of_file(&file, now, &mut seen, &mut out)
                        .await;
                }
                cursor = page.resume;
                if cursor.is_none() || read >= MAX_FILES {
                    break;
                }
            }
        }
        super::durability::rarest_first(&mut out.repairs);
        tracing::info!(
            files = read,
            repairs = out.repairs.len(),
            reported_here = out.reported_here.len(),
            not_in_audience = out.not_in_audience,
            "durability pass (CIRISEdge#763, CC 6.1.5.3)"
        );
        out
    }

    /// The rooms a durability pass lists: each principal's self room and
    /// every family that principal is an active member of.
    async fn durability_rooms(&self) -> Vec<crate::scope_room::ScopeRoom> {
        let dir: &dyn FederationDirectory = &*self.backend;
        let principals = match ciris_persist::federation::self_collective::principals_of(
            dir,
            &self.local_key_id,
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "durability pass: principals unreadable");
                return Vec::new();
            }
        };
        let mut rooms = Vec::new();
        for p in &principals {
            rooms.push(crate::self_room::room(p));
            match dir.list_families_for_member_active(p).await {
                Ok(families) => rooms.extend(families.into_iter().map(|f| {
                    crate::scope_room::ScopeRoom::Family {
                        family_key_id: f.family_key_id,
                    }
                })),
                Err(e) => tracing::warn!(
                    principal = %p,
                    error = %e,
                    "durability pass: families unreadable"
                ),
            }
        }
        rooms
    }

    /// One file of a durability pass — see [`Self::durability_sweep`].
    async fn durability_of_file(
        &self,
        file: &crate::files::FileRow,
        now: chrono::DateTime<chrono::Utc>,
        seen: &mut HashSet<[u8; 32]>,
        out: &mut super::durability::DurabilitySweep,
    ) {
        use super::durability::{self, Repair};
        use ciris_persist::federation::custody_ack::{
            device_custody_of, CustodyState, CustodyVerdict,
        };
        let me = self.local_key_id.as_str();
        let dir: &dyn FederationDirectory = &*self.backend;
        let Ok(sha) =
            <[u8; 32]>::try_from(hex::decode(&file.pointer.content_sha256).unwrap_or_default())
        else {
            return;
        };
        if !seen.insert(sha) {
            return;
        }
        let Ok(Some(row)) = dir.get_attestation(&file.attestation_id).await else {
            return;
        };
        if !durability::is_cohort_delivered(&row) {
            return;
        }
        let blob = hex::encode(sha);
        let deficit = match durability::row_deficit(dir, &row, &sha, now).await {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(blob = %blob, error = %e, "durability pass: deficit unreadable");
                return;
            }
        };
        if !durability::audience_of(&deficit).is_some_and(|a| a.iter().any(|n| n == me)) {
            out.not_in_audience += 1;
            return;
        }
        let whole = match durability::holds_whole(
            &self.engine,
            &*self.backend,
            me,
            &row,
            &sha,
            &file.pointer,
        )
        .await
        {
            Ok(w) => w,
            Err(e) => {
                tracing::debug!(blob = %blob, error = %e, "durability pass: holding unreadable");
                return;
            }
        };
        let mine = device_custody_of(dir, me, &deficit.sha256_hex, None, now)
            .await
            .ok();
        let live_here = mine
            .as_ref()
            .is_some_and(|c| c.state == CustodyVerdict::Here);
        let fresh = mine
            .as_ref()
            .and_then(|c| c.reported_at)
            .is_some_and(|at| now.signed_duration_since(at) < durability::CUSTODY_REFRESH);
        let report = match (whole, live_here) {
            // Held, reported, and the report is recent: nothing to do.
            (true, true) if fresh => return,
            (true, _) => Some(CustodyState::Here),
            // The copy this node reported is gone: say so, so the cohort's
            // deficit lists this node until it is repaired.
            (false, true) => Some(CustodyState::None),
            (false, false) => None,
        };
        if let Some(state) = report {
            match durability::file_custody(
                &self.engine,
                &*self.backend,
                me,
                &row,
                &sha,
                &file.pointer,
                state,
            )
            .await
            {
                Ok(_) if state == CustodyState::Here => out.reported_here.push(sha),
                Ok(_) => {}
                Err(e) => tracing::warn!(
                    blob = %blob,
                    state = state.as_str(),
                    error = %e,
                    "durability pass: custody report not filed"
                ),
            }
        }
        if !whole {
            out.repairs.push(Repair {
                row,
                sha,
                live_here: deficit.live_here.into_iter().filter(|n| n != me).collect(),
            });
        }
    }

    /// **The sequence**, for one blob one row references. Public so a test
    /// can drive it directly and assert the arm it reached.
    ///
    /// Trust → may we accept → should we accept, in that order: the meaning
    /// comes from the signed row (trust), the gate decides possession (may),
    /// and only then does a request go out (should — the holders answer).
    pub async fn pull_one(&self, row: &Attestation, sha: [u8; 32], attempts: u32) -> PullOutcome {
        // Dedupe: one fetch per sha at a time, across every row that names it.
        {
            let Ok(mut set) = self.in_flight.lock() else {
                return PullOutcome::InFlight;
            };
            if !set.insert(sha) {
                return PullOutcome::InFlight;
            }
        }
        let outcome = self.pull_one_inner(row, sha, attempts).await;
        self.settle_key_wait(sha, &outcome);
        if let Ok(mut set) = self.in_flight.lock() {
            set.remove(&sha);
        }
        outcome
    }

    /// CIRISEdge#646 / `FSD/CONTENT_TRANSFER.md` §6.2 — for a self or
    /// family row the author's identity is the self room's id and the
    /// author's NODES are the holders, so the one directory walk
    /// (`contact::resolve`: key → person → their nodes, CC 4.4.3.2.4.1(b))
    /// is done up front and feeds both the projector and the source rule.
    /// Community and commons rows never need it.
    async fn resolve_author(
        &self,
        row: &Attestation,
    ) -> Option<Result<crate::contact::Subject, crate::contact::LadderStall>> {
        if matches!(
            row.cohort_scope.as_str(),
            ciris_persist::federation::types::cohort_scope::SELF
                | ciris_persist::federation::types::cohort_scope::FAMILY
        ) {
            let lens = crate::contact::PersistLens::new(&*self.backend);
            Some(crate::contact::resolve(&lens, &row.attesting_key_id).await)
        } else {
            None
        }
    }

    /// **The source rule** (CIRISEdge#646, FSD §6.2). The holder SOURCE
    /// follows the key plane's tier, not the row's placement (persist#878):
    /// `InvisibleEncrypted` bytes are never claimed anywhere (CC 5.2,
    /// persist I52), so the claim index is not consulted and `NoHolders` is
    /// not a possible outcome — the holders are the author's nodes, the
    /// sealing node among them. Every other tier is discovered through
    /// `list_holders` as before. `Err` carries the outcome to return.
    async fn holders_for(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        meaning: &BlobMeaning,
        author: Option<&Result<crate::contact::Subject, crate::contact::LadderStall>>,
    ) -> Result<Vec<String>, PullOutcome> {
        let key_plane = meaning.key_plane();
        // The tier is the POINTER's (persist#878), which is also what
        // `key_plane` reads — one source, so the branch and the label cannot
        // disagree about which plane this blob is on.
        let tier = meaning.pointer().map_or(CryptoTier::Plaintext, |p| p.tier);
        if tier != CryptoTier::InvisibleEncrypted {
            self.edge
                .metrics()
                .inc_blob_pull_source(pull_source_tag(key_plane.cohort_scope(), false));
            return match self.backend.list_holders(&sha).await {
                Ok(h) => Ok(h.into_iter().filter(|k| *k != self.local_key_id).collect()),
                Err(e) => Err(PullOutcome::StoreFailed(format!("list_holders: {e}"))),
            };
        }
        let nodes = match author {
            Some(Ok(subject)) => subject.nodes.clone(),
            // A local backend failure is OUR fault, not the content's: naming
            // it a holder-rung refusal would hide a broken directory behind a
            // row's diagnosis (CIRISEdge#646 review).
            Some(Err(stall @ crate::contact::LadderStall::DirectoryUnreadable { .. })) => {
                return Err(PullOutcome::StoreFailed(format!(
                    "author resolution: {stall:?} — {}",
                    stall.remedy()
                )));
            }
            Some(Err(stall)) if stall.is_self_resolving() => {
                tracing::debug!(
                    blob = %hex::encode(sha),
                    author = %row.attesting_key_id,
                    stall = ?stall,
                    "self/family pull: the author's nodes are not resolvable yet — retrying \
                     on the directory, never asking the claim index (CIRISEdge#646)"
                );
                Vec::new()
            }
            // Terminal: convergence will not produce a node, so spending a
            // retry slot would both fail and evict a wait that could succeed.
            Some(Err(stall)) => {
                tracing::warn!(
                    blob = %hex::encode(sha),
                    author = %row.attesting_key_id,
                    stall = ?stall,
                    remedy = %stall.remedy(),
                    "self/family pull REFUSED at the holder rung: the row's author does not \
                     resolve to any node and no amount of waiting changes that (CIRISEdge#646)"
                );
                return Err(PullOutcome::NoOtherNode {
                    attempts,
                    retrying: false,
                });
            }
            // Unreachable by construction: a self/family row resolved its author.
            None => Vec::new(),
        };
        self.edge
            .metrics()
            .inc_blob_pull_source(pull_source_tag(key_plane.cohort_scope(), true));
        // CIRISEdge#763 (CC 6.1.5.3) — and every audience node with a live
        // `here`: a repair pulls from whichever of the cohort's own devices
        // still holds the file, not only from the author's (which may be the
        // one that lost it). Bounded to the audience by persist's deficit, so
        // no node outside the cohort is ever asked.
        let mut nodes = nodes;
        match super::durability::row_deficit(&*self.backend, row, &sha, chrono::Utc::now()).await {
            Ok(deficit) => {
                for holder in deficit.live_here {
                    if !nodes.contains(&holder) {
                        nodes.push(holder);
                    }
                }
            }
            Err(e) => tracing::debug!(
                blob = %hex::encode(sha),
                error = %e,
                "self/family pull: the durability deficit is unreadable — asking the \
                 author's nodes only (CIRISEdge#763)"
            ),
        }
        let others: Vec<String> = nodes
            .into_iter()
            .filter(|k| *k != self.local_key_id)
            .collect();
        if others.is_empty() {
            let retrying = self.book_retry(row, sha, attempts);
            return Err(PullOutcome::NoOtherNode { attempts, retrying });
        }
        Ok(others)
    }

    async fn pull_one_inner(&self, row: &Attestation, sha: [u8; 32], attempts: u32) -> PullOutcome {
        let blob_hex = hex::encode(sha);

        // Idempotent: held is held — with one exception (CIRISEdge#717). A
        // sealed DAG's manifest adopted by an earlier attempt and not yet
        // promoted is held `inline` at a sealed tier; under a stream pointer
        // that is a pull to RESUME, not a file to skip. Decided once the
        // pointer is read.
        let held = match self.backend.has_blob(&sha).await {
            Ok(h) => h,
            Err(e) => return PullOutcome::StoreFailed(format!("has_blob: {e}")),
        };
        if held {
            match self.backend.blob_head(&sha).await {
                Ok(Some(h))
                    if h.storage_kind == "inline" && h.crypto_tier != CryptoTier::Plaintext => {}
                // CIRISEdge#763 — a promoted sealed DAG is held only if every
                // chunk is; the DAG walk asks persist's readiness door and
                // REPAIRS the chunks this node lost (CC 6.1.5.3).
                Ok(Some(h))
                    if h.storage_kind == "chunk_dag" && h.crypto_tier != CryptoTier::Plaintext => {}
                Ok(_) => return PullOutcome::AlreadyHeld,
                Err(e) => return PullOutcome::StoreFailed(format!("blob_head: {e}")),
            }
        }

        // TRUST — what the signed row says these bytes are.
        let (meaning, author) = match self.project(row, sha, attempts).await {
            Ok(m) => m,
            Err(outcome) => return outcome,
        };
        let is_dag = meaning.pointer().is_some_and(|p| p.stream_id.is_some());
        if held && !is_dag {
            return PullOutcome::AlreadyHeld;
        }

        // The binding the adopt door will need, decided BEFORE any request:
        // a row that cannot be adopted is not worth a fetch.
        if let Some(refused) = epoch_refusal(row, &blob_hex, &meaning, Some(&self.edge.metrics())) {
            return refused;
        }

        // CIRISEdge#717 — a chunk DAG is not a whole blob: its address is its
        // MANIFEST's, and a whole-blob fetch of it would store the manifest
        // as the file. It has its own walk (`FSD/CONTENT_TRANSFER.md` §6.7),
        // through the same holder rung and the same gate.
        if is_dag {
            return self
                .pull_dag(row, sha, attempts, &meaning, author.as_ref())
                .await;
        }
        let metrics = self.edge.metrics();

        // Who has it — persist's holder plane, minus ourselves.
        let holders = match self
            .holders_for(row, sha, attempts, &meaning, author.as_ref())
            .await
        {
            Ok(h) => h,
            Err(outcome) => return outcome,
        };
        if holders.is_empty() {
            let retrying = self.book_retry(row, sha, attempts);
            return PullOutcome::NoHolders { attempts, retrying };
        }

        // MAY (the gate, inside the scheduler, ahead of dispatch) + the fetch.
        let scheduler = SwarmScheduler::new(
            Arc::clone(&self.edge),
            Arc::new(HashOnlyVerifier),
            self.config.swarm.clone(),
        )
        .with_store_policy(Arc::clone(&self.policy));
        let (bytes, disposition) = match scheduler
            .fetch_blob_scoped_with_disposition(
                sha,
                ChunkManifestLite::whole_blob(sha),
                holders,
                Some(meaning.clone()),
            )
            .await
        {
            Ok(ok) => ok,
            Err(SwarmError::StoreRefused { refusal, axis, .. }) => {
                return PullOutcome::Refused(format!("axis {axis}: {refusal:?}"));
            }
            Err(SwarmError::GoneFederationWide(_)) => {
                return PullOutcome::Refused("withdrawn or revoked federation-wide".into());
            }
            Err(e) => {
                let retrying = self.book_retry(row, sha, attempts);
                return PullOutcome::FetchFailed {
                    reason: e.to_string(),
                    retrying,
                };
            }
        };

        // CIRISEdge#638 item 2 (CC 5.3.2.5): the row's declared size, checked
        // before anything is stored.
        let received = bytes.len();
        if let Some(refused) = size_refusal(row, &blob_hex, &meaning, received, Some(&metrics)) {
            return refused;
        }

        self.store_whole(row, sha, &meaning, bytes, disposition)
            .await
    }

    /// **Store a whole (inline) blob**, through the door the gate's verdict
    /// names, then the inline file's receipt hook (CIRISEdge#738, CC 5.3.3.6):
    /// a file row's inline bytes, once stored, are receipted exactly as a
    /// promoted DAG is. The one inline call site of
    /// [`crate::receipts::on_file_pulled`].
    async fn store_whole(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        meaning: &BlobMeaning,
        bytes: Vec<u8>,
        disposition: StoreDisposition,
    ) -> PullOutcome {
        let tier = meaning.pointer().map_or(CryptoTier::Plaintext, |p| p.tier);
        let outcome = match tier {
            CryptoTier::Plaintext => {
                self.store_plaintext(row, sha, meaning, bytes, disposition)
                    .await
            }
            CryptoTier::CommunityDek | CryptoTier::InvisibleEncrypted => {
                self.adopt_sealed(row, sha, meaning, tier, &bytes, disposition)
                    .await
            }
        };
        crate::receipts::on_file_pulled(
            &self.engine,
            &*self.backend,
            &self.local_key_id,
            row,
            &outcome,
            &self.edge.metrics(),
        )
        .await;
        self.report_here(row, sha, meaning, &outcome).await;
        outcome
    }

    /// CIRISEdge#763 (CC 6.1.5.3, 3.1.3.3) — **a completed self/family pull
    /// files this node's `here`**, so the cohort can count the copy and the
    /// durability deficit stops listing this node. Acts on `Stored` only, and
    /// only at `self` / `family` (the tiers whose copies are otherwise
    /// unobservable: no `holds_bytes` at any audience, CC 5.2). For a chunk
    /// DAG `here` means the manifest and every chunk
    /// ([`durability::file_custody`](super::durability::file_custody)), so the
    /// `Stored` a chunk repair ends in re-files it for the whole DAG. A
    /// refused report is logged by name and changes nothing about the pull.
    async fn report_here(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        meaning: &BlobMeaning,
        outcome: &PullOutcome,
    ) {
        if !matches!(outcome, PullOutcome::Stored { .. })
            || !super::durability::is_cohort_delivered(row)
        {
            return;
        }
        let Some(pointer) = meaning.pointer() else {
            return;
        };
        match super::durability::file_custody(
            &self.engine,
            &*self.backend,
            &self.local_key_id,
            row,
            &sha,
            pointer,
            ciris_persist::federation::custody_ack::CustodyState::Here,
        )
        .await
        {
            Ok(report) => tracing::info!(
                blob = %hex::encode(sha),
                attestation_id = %row.attestation_id,
                report = %report,
                "custody `here` filed for a pulled file (CIRISEdge#763, CC 3.1.3.3)"
            ),
            Err(e) => tracing::warn!(
                blob = %hex::encode(sha),
                attestation_id = %row.attestation_id,
                error = %e,
                "custody `here` NOT filed for a pulled file (CIRISEdge#763)"
            ),
        }
    }

    /// **The whole-blob pull with a caller's fetcher** (CIRISEdge#738) — the
    /// inline counterpart of [`Self::pull_dag_with`]: trust (the row's
    /// meaning), may (the store gate, asked of `fetch`'s holders), the one
    /// fetch verified against the address, the declared size, then the store
    /// and the inline receipt hook [`Self::pull_one`] runs. For a deployment
    /// whose transport is not the swarm's, and for the store-level witness.
    /// A pointer carrying `stream_id` is [`Self::pull_dag_with`]'s and is
    /// refused here by name. Dedupes on `sha` against every other pull.
    pub async fn pull_inline_with(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        fetch: &dyn DagByteFetch,
    ) -> PullOutcome {
        {
            let Ok(mut set) = self.in_flight.lock() else {
                return PullOutcome::InFlight;
            };
            if !set.insert(sha) {
                return PullOutcome::InFlight;
            }
        }
        let outcome = self.pull_inline_inner(row, sha, fetch).await;
        if let Ok(mut set) = self.in_flight.lock() {
            set.remove(&sha);
        }
        outcome
    }

    async fn pull_inline_inner(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        fetch: &dyn DagByteFetch,
    ) -> PullOutcome {
        let blob_hex = hex::encode(sha);
        match self.backend.has_blob(&sha).await {
            Ok(true) => return PullOutcome::AlreadyHeld,
            Ok(false) => {}
            Err(e) => return PullOutcome::StoreFailed(format!("has_blob: {e}")),
        }
        let (meaning, _author) = match self.project(row, sha, 0).await {
            Ok(m) => m,
            Err(outcome) => return outcome,
        };
        if meaning.pointer().is_some_and(|p| p.stream_id.is_some()) {
            return PullOutcome::Refused(
                "pull_inline_with: the pointer names a stream_id — a chunk DAG is                  pull_dag_with's (CIRISEdge#717)"
                    .into(),
            );
        }
        let metrics = self.edge.metrics();
        if let Some(refused) = epoch_refusal(row, &blob_hex, &meaning, Some(&metrics)) {
            return refused;
        }
        let disposition = match super::store_admission_with(
            self.policy.as_ref(),
            sha,
            Some(&meaning),
            fetch.holders(),
        )
        .await
        {
            Ok(d) => d,
            Err(SwarmError::StoreRefused { refusal, axis, .. }) => {
                return PullOutcome::Refused(format!("axis {axis}: {refusal:?}"));
            }
            Err(e) => return PullOutcome::Refused(e.to_string()),
        };
        let bytes = match self.fetch_verified(fetch, sha).await {
            Ok(b) => b,
            Err(DagFetchStop::Transport(reason)) => {
                return PullOutcome::FetchFailed {
                    reason,
                    retrying: false,
                }
            }
            Err(DagFetchStop::HashMismatch { got }) => {
                return PullOutcome::Refused(format!(
                    "pull_inline_with: the fetched body hashes to {}, not {blob_hex}",
                    hex::encode(got)
                ))
            }
        };
        if let Some(refused) = size_refusal(row, &blob_hex, &meaning, bytes.len(), Some(&metrics)) {
            return refused;
        }
        self.store_whole(row, sha, &meaning, bytes, disposition)
            .await
    }

    /// TRUST — what the signed row says these bytes are, with the author
    /// walk a self/family row needs (CIRISEdge#646). `Err` carries the
    /// outcome to return: a refusal, or a wait on the directory.
    async fn project(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
    ) -> Result<
        (
            BlobMeaning,
            Option<Result<crate::contact::Subject, crate::contact::LadderStall>>,
        ),
        PullOutcome,
    > {
        let blob_hex = hex::encode(sha);
        // CIRISEdge#646 / `FSD/CONTENT_TRANSFER.md` §6.2 — for a self or
        // family row the author's identity is the self room's id and the
        // author's NODES are the holders, so the one directory walk
        // (`contact::resolve`: key → person → their nodes, CC 4.4.3.2.4.1(b))
        // is done up front and feeds both the projector and the source rule.
        // Community and commons rows never need it.
        let author = self.resolve_author(row).await;
        let author_identity = author
            .as_ref()
            .and_then(|r| r.as_ref().ok())
            .map(|subject| subject.fed_id.clone());
        match BlobMeaning::project_with(row, &sha, author_identity.as_deref()) {
            Ok(m) => Ok((m, author)),
            // A self/family row's group id can come from the author's
            // identity, so "no group" while the author is still converging is
            // a WAIT, not a refusal — refusing it terminally leaves the blob
            // unfetched forever after convergence, since nothing re-applies
            // the row (CIRISEdge#646 review).
            Err(MeaningRefusal::GroupWithoutId { .. })
                if author
                    .as_ref()
                    .and_then(|r| r.as_ref().err())
                    .is_some_and(crate::contact::LadderStall::is_self_resolving) =>
            {
                let retrying = self.book_retry(row, sha, attempts);
                tracing::debug!(
                    blob = %blob_hex,
                    author = %row.attesting_key_id,
                    retrying,
                    "self/family pull: the row's group id waits on the author's directory \
                     records, which are still converging (CIRISEdge#646)"
                );
                Err(PullOutcome::AuthorUnresolved { attempts, retrying })
            }
            Err(r) => Err(PullOutcome::NoMeaning(r)),
        }
    }

    /// CIRISEdge#717 — **the chunk-DAG pull, over the swarm**: the holder walk
    /// and the store gate exactly as a whole blob's, then
    /// [`Self::pull_dag_with`]'s walk with one swarm session as the fetcher.
    async fn pull_dag(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        meaning: &BlobMeaning,
        author: Option<&Result<crate::contact::Subject, crate::contact::LadderStall>>,
    ) -> PullOutcome {
        let holders = match self.holders_for(row, sha, attempts, meaning, author).await {
            Ok(h) => h,
            Err(outcome) => return outcome,
        };
        if holders.is_empty() {
            let retrying = self.book_retry(row, sha, attempts);
            return PullOutcome::NoHolders { attempts, retrying };
        }
        let fetch = SwarmFetch::new(
            Arc::clone(&self.edge),
            holders,
            meaning.clone(),
            self.config.swarm.clone(),
            self.config.dag_chunks_in_flight,
            sha,
        );
        self.pull_dag_inner(row, sha, attempts, meaning, &fetch)
            .await
    }

    /// **The chunk-DAG pull with a caller's fetcher** (CIRISEdge#717,
    /// `FSD/CONTENT_TRANSFER.md` §6.7): the same walk [`Self::pull_one`]
    /// runs for a pointer carrying `stream_id` — trust (the row's meaning),
    /// may (the store gate, asked of `fetch`'s holders), then manifest →
    /// verified → chunks → promoted — with `fetch` producing the bytes
    /// instead of the swarm. For a deployment whose transport is not the
    /// swarm's, and for the store-level witness. Every body `fetch` returns
    /// is verified against the address asked for; a fetcher can fail the
    /// pull, never feed it.
    ///
    /// A pointer without `stream_id` is [`Self::pull_one`]'s and is refused
    /// here by name. Dedupes on `sha` against every other pull, as
    /// `pull_one` does.
    pub async fn pull_dag_with(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        fetch: &dyn DagByteFetch,
    ) -> PullOutcome {
        {
            let Ok(mut set) = self.in_flight.lock() else {
                return PullOutcome::InFlight;
            };
            if !set.insert(sha) {
                return PullOutcome::InFlight;
            }
        }
        let outcome = async {
            let (meaning, _author) = match self.project(row, sha, 0).await {
                Ok(m) => m,
                Err(outcome) => return outcome,
            };
            if meaning
                .pointer()
                .and_then(|p| p.stream_id.as_deref())
                .is_none()
            {
                return PullOutcome::Refused(
                    "pull_dag_with: the pointer names no stream_id — a whole blob is \
                     pull_one's (CIRISEdge#717)"
                        .into(),
                );
            }
            self.pull_dag_inner(row, sha, 0, &meaning, fetch).await
        }
        .await;
        self.settle_key_wait(sha, &outcome);
        if let Ok(mut set) = self.in_flight.lock() {
            set.remove(&sha);
        }
        outcome
    }

    /// The DAG walk proper, tier-dispatched, after the gate.
    async fn pull_dag_inner(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        meaning: &BlobMeaning,
        fetch: &dyn DagByteFetch,
    ) -> PullOutcome {
        let blob_hex = hex::encode(sha);
        let Some(pointer) = meaning.pointer() else {
            return PullOutcome::Refused("a DAG is named only by a typed pointer".into());
        };
        let Some(stream_id) = pointer.stream_id.as_deref() else {
            return PullOutcome::Refused("the pointer names no stream_id".into());
        };
        if let Some(refused) = epoch_refusal(row, &blob_hex, meaning, Some(&self.edge.metrics())) {
            return refused;
        }
        // MAY — the gate, asked of the FETCHER's holders before a byte moves
        // (CIRISEdge#581), once per DAG: every chunk shares the row, the
        // meaning and the holder set the answer was given for (CIRISEdge#739
        // stopped re-asking it per chunk). A caller's fetcher gets no way
        // round it — nothing below runs without its disposition.
        let disposition = match super::store_admission_with(
            self.policy.as_ref(),
            sha,
            Some(meaning),
            fetch.holders(),
        )
        .await
        {
            Ok(d) => d,
            Err(SwarmError::StoreRefused { refusal, axis, .. }) => {
                return PullOutcome::Refused(format!("axis {axis}: {refusal:?}"));
            }
            Err(e) => return PullOutcome::Refused(e.to_string()),
        };
        let outcome = match pointer.tier {
            CryptoTier::Plaintext => {
                self.pull_plaintext_dag(row, sha, attempts, meaning, stream_id, disposition, fetch)
                    .await
            }
            CryptoTier::CommunityDek | CryptoTier::InvisibleEncrypted => {
                self.pull_sealed_dag(row, sha, attempts, meaning, stream_id, disposition, fetch)
                    .await
            }
        };
        // CIRISEdge#738 — the DAG's receipt hook: acts on `Stored` only.
        crate::receipts::on_file_pulled(
            &self.engine,
            &*self.backend,
            &self.local_key_id,
            row,
            &outcome,
            &self.edge.metrics(),
        )
        .await;
        // CIRISEdge#763 — and its custody report, for the whole DAG.
        self.report_here(row, sha, meaning, &outcome).await;
        outcome
    }

    /// One address through the fetcher, verified against it here — whoever
    /// fetched. Content addressing is the puller's belt, not the fetcher's.
    async fn fetch_verified(
        &self,
        fetch: &dyn DagByteFetch,
        sha: [u8; 32],
    ) -> Result<Vec<u8>, DagFetchStop> {
        use sha2::{Digest as _, Sha256};
        let bytes = fetch.fetch(sha).await.map_err(DagFetchStop::Transport)?;
        let got: [u8; 32] = Sha256::digest(&bytes).into();
        if got != sha {
            return Err(DagFetchStop::HashMismatch { got });
        }
        Ok(bytes)
    }

    /// A named DAG refusal: counted under its tag, logged with the row.
    fn dag_refused(
        &self,
        row: &Attestation,
        blob_hex: &str,
        refusal: DagPullRefusal,
    ) -> PullOutcome {
        self.edge.metrics().inc_blob_pull_refusal(refusal.tag());
        tracing::warn!(
            blob = %blob_hex,
            attestation_id = %row.attestation_id,
            refusal = ?refusal,
            "DAG pull refused (CIRISEdge#717, FSD/CONTENT_TRANSFER.md §6.7)"
        );
        PullOutcome::DagRefused(refusal)
    }

    /// A fetch that did not arrive: booked for retry, named.
    fn dag_fetch_failed(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        what: &str,
        reason: &str,
    ) -> PullOutcome {
        let retrying = self.book_retry(row, sha, attempts);
        PullOutcome::FetchFailed {
            reason: format!("{what}: {reason}"),
            retrying,
        }
    }

    /// **A sealed DAG** (`InvisibleEncrypted` / `CommunityDek`), persist's
    /// #947 order: adopt the manifest as received (an inline envelope, never
    /// opened here) → open it as this node → bound the work → adopt each
    /// chunk at `(stream_id, seq)` → promote. Resumable: a manifest held from
    /// an earlier attempt is not re-fetched, and chunks already held at their
    /// position with the manifest's sha are skipped, so a retry finishes
    /// what the last attempt started.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // the walk's rungs, in order, in one place on purpose
    async fn pull_sealed_dag(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        meaning: &BlobMeaning,
        stream_id: &str,
        disposition: StoreDisposition,
        fetch: &dyn DagByteFetch,
    ) -> PullOutcome {
        use ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD;
        use ciris_persist::federation::BlobError;
        let blob_hex = hex::encode(sha);
        let Some(pointer) = meaning.pointer() else {
            return PullOutcome::StoreFailed(
                "sealed tier without a typed pointer — cannot form a provenance".into(),
            );
        };
        // The provenance and AAD exactly as the whole-blob adopt forms them
        // (`adopt_sealed`): the row is the access grant, the pointer the key
        // plane, the minter derived by persist. The chunks share the
        // manifest's provenance — one access set per stream (persist D9).
        let provenance = match BlobProvenance::from_attestation(row, &sha, pointer.epoch, None) {
            Ok(p) => p,
            Err(e) => {
                return PullOutcome::StoreFailed(format!(
                    "provenance from the referencing row {}: {e}",
                    row.attestation_id
                ))
            }
        };
        let aad = crate::group_content::content_aad(
            &row.attesting_key_id,
            row.asserted_at,
            pointer.content_field,
        );
        let adopt = match disposition {
            StoreDisposition::Announce => AdoptDisposition::Announce,
            StoreDisposition::LocalOnly => AdoptDisposition::LocalOnly,
        };

        // ── manifest ── held from an earlier attempt, or fetched now.
        let announced;
        let held = match self.backend.has_blob(&sha).await {
            Ok(h) => h,
            Err(e) => return PullOutcome::StoreFailed(format!("has_blob: {e}")),
        };
        if held {
            // CIRISEdge#735 — a RESUME. The manifest was adopted, and its
            // `holds_bytes` emitted or not, by an earlier attempt; this one
            // skips the adopt, so `announced` is read off the claim that
            // exists rather than reported false for a door not called. At
            // `community_dek` the first attempt announced and the resume
            // used to deny it; at `invisible_encrypted` no claim exists
            // (CC 5.2) and this reads false, as before.
            announced = match self.backend.list_holders(&sha).await {
                Ok(holders) => holders.contains(&self.local_key_id),
                Err(e) => return PullOutcome::StoreFailed(format!("list_holders: {e}")),
            };
        } else {
            let bytes = match self.fetch_verified(fetch, sha).await {
                Ok(b) => b,
                Err(DagFetchStop::Transport(reason)) => {
                    return self.dag_fetch_failed(row, sha, attempts, "manifest", &reason)
                }
                Err(DagFetchStop::HashMismatch { got }) => {
                    return self.dag_refused(
                        row,
                        &blob_hex,
                        DagPullRefusal::ManifestMismatch {
                            detail: format!(
                                "the bytes served at the pointer's address hash to {}",
                                hex::encode(got)
                            ),
                        },
                    )
                }
            };
            announced = match self
                .engine
                .adopt_sealed_blob(&bytes, provenance.clone(), Some(&aad), adopt)
                .await
            {
                Ok(outcome) => outcome.announced,
                Err(e) => return PullOutcome::StoreFailed(format!("adopt manifest: {e}")),
            };
        }

        // ── verified ── opened as THIS NODE, under the row's AAD.
        let view = match self
            .engine
            .open_sealed_manifest_as(&sha, &self.local_key_id, Some(&aad))
            .await
        {
            Ok(v) => v,
            // The key follows the bytes, in either order (persist I61/I62):
            // the manifest is held; the wrap to this node has not landed.
            Err(BlobError::NotGranted { .. }) => {
                // CIRISEdge#779 — parked on the manifest's key: its wrap
                // (self / family) or its epoch's grant (`community_dek`)
                // wakes the pull, however long the ladder has given up.
                self.key_waits.park(
                    sha,
                    row,
                    match pointer.tier {
                        CryptoTier::InvisibleEncrypted => key_wake::Awaiting::Content(vec![sha]),
                        _ => key_wake::Awaiting::Epoch(pointer.epoch),
                    },
                );
                let retrying = self.book_retry(row, sha, attempts);
                tracing::debug!(
                    blob = %blob_hex,
                    attestation_id = %row.attestation_id,
                    retrying,
                    "DAG pull: the manifest is held but this node holds no wrap for it yet — \
                     waiting on the key_grant (CIRISEdge#717)"
                );
                return PullOutcome::DagAwaitingKey { attempts, retrying };
            }
            Err(BlobError::InvalidArgument(detail)) => {
                return self.dag_refused(
                    row,
                    &blob_hex,
                    DagPullRefusal::ManifestMismatch { detail },
                )
            }
            Err(e) => return PullOutcome::StoreFailed(format!("open_sealed_manifest_as: {e}")),
        };
        // Promoted already (a concurrent pull, a second offer of the same
        // row after completion, or a durability repair): the file is here iff
        // every chunk is. CIRISEdge#763 (CC 6.1.5.3) — a chunk this node lost
        // is fetched again below, the held ones skipped, and the DAG is
        // reported `Stored` once it is whole again, so a repair re-files the
        // node's `here` for the WHOLE DAG.
        let repairing = view.storage_kind == "chunk_dag";
        if repairing {
            match self
                .engine
                .sealed_dag_readiness(&sha, &self.local_key_id, Some(&aad))
                .await
            {
                Ok(r) if r.held => return PullOutcome::AlreadyHeld,
                Ok(r) => tracing::info!(
                    blob = %blob_hex,
                    attestation_id = %row.attestation_id,
                    not_held = ?r.not_held,
                    "DAG repair: the promoted DAG is missing chunks here — fetching them \
                     (CIRISEdge#763)"
                ),
                Err(e) => {
                    return PullOutcome::StoreFailed(format!("sealed_dag_readiness: {e}"));
                }
            }
        }
        let plan = DagPlan::from_sealed_view(&view);
        if let Err(refusal) = check_dag_plan(stream_id, pointer.size, &plan) {
            return self.dag_refused(row, &blob_hex, refusal);
        }

        // ── chunks ── each by its sha, adopted at its position; held ones skipped.
        let held_chunks: HashMap<u64, [u8; 32]> =
            match self.backend.stream_chunks(&view.stream_id).await {
                Ok(listing) => listing
                    .chunks
                    .into_iter()
                    .map(|c| (c.seq, c.chunk_sha))
                    .collect(),
                Err(e) => return PullOutcome::StoreFailed(format!("stream_chunks: {e}")),
            };
        // Every chunk's address is read off the view BEFORE the first request,
        // so a malformed manifest is refused with nothing fetched.
        let mut wanted: Vec<DagWant> = Vec::with_capacity(view.chunks.len());
        let mut skipped_held: u64 = 0;
        for c in &view.chunks {
            let mut want = [0u8; 32];
            if let Err(e) = hex::decode_to_slice(&c.sha256_hex, &mut want) {
                return self.dag_refused(
                    row,
                    &blob_hex,
                    DagPullRefusal::ManifestMismatch {
                        detail: format!("chunk seq {} sha is not 32 hex bytes: {e}", c.seq),
                    },
                );
            }
            if held_chunks.get(&c.seq) == Some(&want) {
                skipped_held += 1;
                continue;
            }
            wanted.push(DagWant {
                seq: c.seq,
                sha: want,
                size: u64::from(c.size),
                epoch: chunk_adopt_epoch(c.epoch),
            });
        }
        // Fetch order is `seq` (CIRISEdge#739, §6.7.5): the file's position
        // order, so a pull cut at any moment holds a prefix plus a window,
        // the resume's skip set is contiguous, and a reader that streams
        // (`FileRow::chunks`) behind a pull in progress meets held chunks
        // first. The view lists them in that order; sorting pins the rule
        // rather than inheriting it.
        wanted.sort_by_key(|w| w.seq);
        let metrics = self.edge.metrics();
        metrics.add_blob_dag_chunks("skipped_held", skipped_held);

        // ── the pipeline ── K lanes in flight, under a byte budget; each lane
        // fetches ONE chunk and checks it (CIRISEdge#739, §6.7.5). Verified
        // chunks wait for an adopt batch (CIRISPersist#957): one
        // `adopt_sealed_chunks` per batch, one writer transaction, while the
        // lanes keep fetching. At a batch of one, each chunk is adopted as it
        // arrives, concurrently (the v36.1.0 shape). Lanes and adopts are
        // futures on THIS task (never spawned). A waiting or adopting chunk
        // still counts against the byte budget, so the pull's memory bound is
        // unchanged. On a stop (a refusal, a fetch that did not arrive, a
        // refused adopt) no further lane is admitted, the lanes in flight
        // DRAIN, and every chunk that arrived verified is still adopted, so
        // everything the pull paid for is kept for the resume. The FIRST stop
        // names the outcome. Persist commits a batch's accepted items even
        // when others in it are refused, so a refused chunk is named and the
        // rest land. A killed pull (the task dropped) cancels every lane and
        // adopt instead. A chunk whose adopt had not returned is then either
        // absent (the resume fetches it) or held at its position (the resume
        // skips it), never held twice, since a position holds one row.
        let lanes = self.config.dag_chunks_in_flight.max(1);
        let budget = self.config.dag_bytes_in_flight;
        let batch_max = self
            .config
            .dag_adopt_batch_chunks
            .clamp(1, ciris_persist::federation::blobs::MAX_CHUNKS_PER_BATCH);
        // One batch at a time: a second concurrent batch would only queue on
        // persist's one writer. At a batch of one, up to K adopts run at once.
        let adopters = if batch_max == 1 { lanes } else { 1 };
        let overhead = AT_REST_ENVELOPE_OVERHEAD as u64;
        let stream = view.stream_id.as_str();
        let provenance = &provenance;
        let engine = &self.engine;
        let mut fetching = FuturesUnordered::new();
        let mut adopting = FuturesUnordered::new();
        let mut pending: Vec<(DagWant, Vec<u8>)> = Vec::new();
        let mut pending_bytes: usize = 0;
        let mut bytes_in_flight: u64 = 0;
        let mut peak: usize = 0;
        let mut batch_peak: usize = 0;
        let mut next = wanted.into_iter().peekable();
        let mut stop: Option<PullOutcome> = None;
        loop {
            while let Some(stored) = next
                .peek()
                .filter(|_| stop.is_none())
                .map(|w| w.size.saturating_add(overhead))
            {
                if !pipeline_admits(fetching.len(), lanes, bytes_in_flight, stored, budget) {
                    break;
                }
                let Some(w) = next.next() else { break };
                bytes_in_flight = bytes_in_flight.saturating_add(stored);
                fetching.push(async move {
                    let started = Instant::now();
                    let fetched = self.fetch_verified(fetch, w.sha).await;
                    let fetch_wait = started.elapsed();
                    let checked = match fetched {
                        Err(stop) => Err(LaneStop::Fetch(stop)),
                        // The stored body is the plaintext plus persist's
                        // envelope — the arithmetic `declared_stored_len`
                        // uses for a whole blob; persist's adopt checks the
                        // envelope's own length again behind this.
                        Ok(bytes) if bytes.len() as u64 != w.size.saturating_add(overhead) => {
                            Err(LaneStop::Length {
                                got: bytes.len(),
                                expected: w.size.saturating_add(overhead),
                            })
                        }
                        Ok(bytes) => Ok(bytes),
                    };
                    (w, fetch_wait, checked)
                });
            }
            peak = peak.max(fetching.len());
            while adopting.len() < adopters
                && adopt_batch_ready(pending.len(), pending_bytes, fetching.len(), batch_max)
            {
                // Fetched chunks wait in seq order, so a batch is a run of
                // positions and an epoch boundary (CIRISEdge#797) ends it.
                pending.sort_by_key(|(w, _)| w.seq);
                let sizes: Vec<usize> = pending.iter().map(|(_, b)| b.len()).collect();
                let epochs: Vec<u64> = pending.iter().map(|(w, _)| w.epoch).collect();
                let take = adopt_batch_take(&sizes, batch_max).min(same_epoch_run(&epochs));
                let epoch = epochs[0];
                let batch: Vec<(DagWant, Vec<u8>)> = pending.drain(..take).collect();
                pending_bytes -= sizes[..take].iter().sum::<usize>();
                batch_peak = batch_peak.max(batch.len());
                adopting.push(async move {
                    let items: Vec<ciris_persist::federation::AdoptChunkItem<'_>> = batch
                        .iter()
                        .map(|(w, bytes)| ciris_persist::federation::AdoptChunkItem {
                            seq: w.seq,
                            envelope: bytes,
                            plaintext_size: w.size,
                        })
                        .collect();
                    let started = Instant::now();
                    let adopted = engine
                        .adopt_sealed_chunks(stream, &items, epoch, provenance.clone())
                        .await
                        .map_err(|e| e.to_string());
                    let elapsed = started.elapsed();
                    drop(items);
                    let wants: Vec<DagWant> = batch.into_iter().map(|(w, _)| w).collect();
                    (wants, elapsed, adopted)
                });
            }
            tokio::select! {
                Some((w, fetch_wait, checked)) = fetching.next(), if !fetching.is_empty() => {
                    metrics.add_blob_dag_phase("dag_fetch_wait", fetch_wait);
                    let stopped = match checked {
                        Ok(bytes) => {
                            // Verified: it waits for a batch, even while the
                            // pull drains after a stop.
                            pending_bytes += bytes.len();
                            pending.push((w, bytes));
                            continue;
                        }
                        Err(_) if stop.is_some() => None,
                        Err(LaneStop::Fetch(DagFetchStop::Transport(reason))) => {
                            Some(self.dag_fetch_failed(
                                row,
                                sha,
                                attempts,
                                &format!("chunk seq {}", w.seq),
                                &reason,
                            ))
                        }
                        Err(LaneStop::Fetch(DagFetchStop::HashMismatch { got })) => {
                            Some(self.dag_refused(
                                row,
                                &blob_hex,
                                DagPullRefusal::ChunkMismatch {
                                    seq: w.seq,
                                    detail: format!(
                                        "the bytes served for {} hash to {}",
                                        hex::encode(w.sha),
                                        hex::encode(got)
                                    ),
                                },
                            ))
                        }
                        Err(LaneStop::Length { got, expected }) => Some(self.dag_refused(
                            row,
                            &blob_hex,
                            DagPullRefusal::ChunkMismatch {
                                seq: w.seq,
                                detail: format!(
                                    "{got} bytes arrived but the manifest's size {} implies {expected}",
                                    w.size
                                ),
                            },
                        )),
                    };
                    bytes_in_flight =
                        bytes_in_flight.saturating_sub(w.size.saturating_add(overhead));
                    if stop.is_none() {
                        stop = stopped;
                    }
                }
                Some((wants, elapsed, adopted)) = adopting.next(), if !adopting.is_empty() => {
                    for w in &wants {
                        bytes_in_flight =
                            bytes_in_flight.saturating_sub(w.size.saturating_add(overhead));
                    }
                    metrics.add_blob_dag_phase("dag_adopt", elapsed);
                    metrics.add_blob_dag_chunks("adopt_batches", 1);
                    tracing::debug!(
                        target: "ciris_edge::blob_swarm::dag_adopt",
                        first_seq = wants.iter().map(|w| w.seq).min().unwrap_or(0),
                        chunks = wants.len() as u64,
                        elapsed_us = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX),
                        "DAG pull: one adopt batch returned (CIRISPersist#957)"
                    );
                    // Either the batch was refused whole (nothing written),
                    // or each item answered in its slot, in order.
                    let answers: Vec<Result<(), String>> = match adopted {
                        Ok(per_item) => per_item
                            .into_iter()
                            .map(|r| r.map(|_| ()).map_err(|e| e.to_string()))
                            .collect(),
                        Err(e) => wants.iter().map(|_| Err(e.clone())).collect(),
                    };
                    for (w, answer) in wants.iter().zip(answers) {
                        match answer {
                            Ok(()) => metrics.add_blob_dag_chunks("adopted", 1),
                            Err(e) => {
                                tracing::warn!(
                                    blob = %blob_hex,
                                    stream_id = %stream,
                                    seq = w.seq,
                                    error = %e,
                                    "DAG pull: persist refused a chunk's adopt"
                                );
                                if stop.is_none() {
                                    stop = Some(PullOutcome::StoreFailed(format!(
                                        "adopt chunk seq {}: {e}",
                                        w.seq
                                    )));
                                }
                            }
                        }
                    }
                }
                else => break,
            }
        }
        metrics.max_blob_dag_chunks("in_flight_peak", peak as u64);
        metrics.max_blob_dag_chunks("adopt_batch_peak", batch_peak as u64);
        drop(fetching);
        drop(adopting);
        if let Some(outcome) = stop {
            return outcome;
        }

        // ── keyed ── CIRISEdge#779: every chunk opens as THIS NODE before the
        // file is promoted, reported Stored and receipted (CC 5.3.3.6). The
        // key follows the bytes on its own plane: promoting on the bytes
        // alone reported a 256 MiB file pulled with 242 of its 1024 chunks
        // unopenable here. CIRISEdge#797 — asked through persist's readiness
        // door, ONE call for both manifest versions, answered from the grant
        // rows with no chunk opened: per stream EPOCH for a v4 DAG (one DEK
        // per `(stream, epoch)`, CIRISPersist#969), per chunk for a v2 one
        // (persist I314c). At `community_dek` the chunks share the manifest's
        // epoch binding (one provenance per stream, adopted above), so the
        // manifest opening as this node already answered it.
        if pointer.tier == CryptoTier::InvisibleEncrypted {
            let readiness = match self
                .engine
                .sealed_dag_readiness(&sha, &self.local_key_id, Some(&aad))
                .await
            {
                Ok(r) => r,
                Err(e) => return PullOutcome::StoreFailed(format!("sealed_dag_readiness: {e}")),
            };
            if !readiness.missing.is_empty() {
                // Parked on exactly what the door names: each grant that
                // lands wakes the pull (coalesced per tick), so giving up on
                // the ladder below is not giving up on the file.
                let awaiting = awaiting_of(&readiness.missing);
                let missing = readiness.missing.len() as u64;
                self.key_waits.park(sha, row, awaiting);
                // Progress restarts the ladder (and its backoff); bounded,
                // since `missing` can only fall as many times as it has keys.
                let attempts_spent = if self.chunk_keys_progressed(sha, missing) {
                    0
                } else {
                    attempts
                };
                let retrying = self.book_retry(row, sha, attempts_spent);
                if !retrying {
                    self.forget_chunk_keys(sha);
                }
                tracing::info!(
                    blob = %blob_hex,
                    attestation_id = %row.attestation_id,
                    stream_id = %view.stream_id,
                    chunk_count = view.chunks.len() as u64,
                    chunk_keys = readiness.chunk_keys,
                    missing,
                    retrying,
                    "DAG pull: every chunk is held but this node holds no key for some yet — \
                     not promoted, waiting on their key_grant sets (CIRISEdge#779, #797)"
                );
                return PullOutcome::DagAwaitingKey { attempts, retrying };
            }
            self.forget_chunk_keys(sha);
        }

        // ── repaired ── the manifest row is a chunk_dag already; what made
        // it one was persist's check of every chunk row, and the readiness
        // door re-asks it of the chunks the repair adopted.
        if repairing {
            return match self
                .engine
                .sealed_dag_readiness(&sha, &self.local_key_id, Some(&aad))
                .await
            {
                Ok(r) if r.held && r.readable => {
                    tracing::info!(
                        blob = %blob_hex,
                        attestation_id = %row.attestation_id,
                        stream_id = %view.stream_id,
                        "DAG repaired: every chunk is held and opens here again (CIRISEdge#763)"
                    );
                    PullOutcome::Stored { announced }
                }
                Ok(r) => PullOutcome::StoreFailed(format!(
                    "DAG repair: still not whole after the fetch (not held {:?})",
                    r.not_held
                )),
                Err(e) => PullOutcome::StoreFailed(format!("sealed_dag_readiness: {e}")),
            };
        }

        // ── promoted ── persist checks every chunk row against the manifest.
        let promoting = Instant::now();
        let promoted = self
            .engine
            .promote_adopted_manifest_to_dag(&sha, &self.local_key_id, Some(&aad))
            .await;
        metrics.add_blob_dag_phase("dag_promote", promoting.elapsed());
        match promoted {
            Ok(promotion) => {
                tracing::info!(
                    blob = %blob_hex,
                    attestation_id = %row.attestation_id,
                    stream_id = %view.stream_id,
                    chunk_count = promotion.chunk_count,
                    total_size = promotion.total_size,
                    promoted = promotion.promoted,
                    announced,
                    "DAG pulled: the manifest row is a chunk_dag and reads as the file \
                     (CIRISEdge#717)"
                );
                PullOutcome::Stored { announced }
            }
            Err(BlobError::InvalidArgument(detail)) => {
                self.dag_refused(row, &blob_hex, DagPullRefusal::ChunkMissing { detail })
            }
            // CIRISEdge#797 — persist's typed retryable: this node is
            // authorized on the DAG and a chunk's key has not landed yet. The
            // state to wait through, parked on the key it names; never a
            // refusal and never `NotGranted`.
            Err(e) => match awaiting_key_of(&e) {
                Some(awaiting) => {
                    self.key_waits.park(sha, row, awaiting);
                    let retrying = self.book_retry(row, sha, attempts);
                    PullOutcome::DagAwaitingKey { attempts, retrying }
                }
                None => PullOutcome::StoreFailed(format!("promote_adopted_manifest_to_dag: {e}")),
            },
        }
    }

    /// **A plaintext DAG** (a commons file): the manifest is in clear, so the
    /// puller reads it itself, bounds the work, fetches every chunk, and
    /// stores the whole DAG in one shot through persist's
    /// `put_blob_chunks_signing` — every chunk verified against the manifest
    /// again inside the door, and the manifest's `holds_bytes` announced as
    /// `store_plaintext` announces a whole blob. Held in memory until the
    /// door takes it, bounded by the plan's `in_memory_cap_bytes` (persist's
    /// whole-read constant, reused as this walk's buffer bound — CIRISEdge#737).
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // the walk's rungs, in order, in one place on purpose
    async fn pull_plaintext_dag(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        attempts: u32,
        meaning: &BlobMeaning,
        stream_id: &str,
        disposition: StoreDisposition,
        fetch: &dyn DagByteFetch,
    ) -> PullOutcome {
        let blob_hex = hex::encode(sha);
        let Some(pointer) = meaning.pointer() else {
            return PullOutcome::Refused("a DAG is named only by a typed pointer".into());
        };
        if disposition == StoreDisposition::LocalOnly {
            return PullOutcome::StoreFailed(
                "the store gate said LocalOnly for PLAINTEXT bytes, and persist exposes no \
                 local-only plaintext door to a consumer (store_blob_local needs a \
                 StorageFloor only persist can mint, I22); refusing rather than announcing \
                 against the verdict"
                    .into(),
            );
        }
        // ── manifest ──
        let bytes = match self.fetch_verified(fetch, sha).await {
            Ok(b) => b,
            Err(DagFetchStop::Transport(reason)) => {
                return self.dag_fetch_failed(row, sha, attempts, "manifest", &reason)
            }
            Err(DagFetchStop::HashMismatch { got }) => {
                return self.dag_refused(
                    row,
                    &blob_hex,
                    DagPullRefusal::ManifestMismatch {
                        detail: format!(
                            "the bytes served at the pointer's address hash to {}",
                            hex::encode(got)
                        ),
                    },
                )
            }
        };
        // ── verified ──
        let manifest = match parse_clear_manifest(&bytes) {
            Ok(m) => m,
            Err(detail) => {
                return self.dag_refused(
                    row,
                    &blob_hex,
                    DagPullRefusal::ManifestMismatch { detail },
                )
            }
        };
        if manifest
            .chunk_tier
            .is_some_and(|t| t != CryptoTier::Plaintext)
        {
            return self.dag_refused(
                row,
                &blob_hex,
                DagPullRefusal::ManifestMismatch {
                    detail: format!(
                        "a plaintext pointer names a manifest sealed at {:?}",
                        manifest.chunk_tier
                    ),
                },
            );
        }
        let plan = DagPlan::from_clear_manifest(&manifest, self.backend.inline_bytes_cap() as u64);
        if let Err(refusal) = check_dag_plan(stream_id, pointer.size, &plan) {
            return self.dag_refused(row, &blob_hex, refusal);
        }
        // ── chunks ──
        let mut chunks = Vec::with_capacity(manifest.chunks.len());
        for (i, c) in manifest.chunks.iter().enumerate() {
            let seq = c.seq.unwrap_or(i as u64);
            let body = match self.fetch_verified(fetch, c.sha).await {
                Ok(b) => b,
                Err(DagFetchStop::Transport(reason)) => {
                    return self.dag_fetch_failed(
                        row,
                        sha,
                        attempts,
                        &format!("chunk seq {seq}"),
                        &reason,
                    )
                }
                Err(DagFetchStop::HashMismatch { got }) => {
                    return self.dag_refused(
                        row,
                        &blob_hex,
                        DagPullRefusal::ChunkMismatch {
                            seq,
                            detail: format!(
                                "the bytes served for {} hash to {}",
                                hex::encode(c.sha),
                                hex::encode(got)
                            ),
                        },
                    )
                }
            };
            if body.len() as u64 != u64::from(c.size) {
                return self.dag_refused(
                    row,
                    &blob_hex,
                    DagPullRefusal::ChunkMismatch {
                        seq,
                        detail: format!(
                            "{} bytes arrived but the manifest says {}",
                            body.len(),
                            c.size
                        ),
                    },
                );
            }
            chunks.push((c.sha, BlobBody::Inline(body)));
        }
        // ── stored + announced ──
        match self
            .engine
            .put_blob_chunks_signing(manifest, chunks, &row.attesting_key_id)
            .await
        {
            Ok(got) => {
                debug_assert_eq!(got, sha, "the DAG's address is its manifest's");
                tracing::info!(
                    blob = %blob_hex,
                    attestation_id = %row.attestation_id,
                    stream_id = %stream_id,
                    "plaintext DAG pulled and announced (CIRISEdge#717)"
                );
                PullOutcome::Stored { announced: true }
            }
            Err(e) => PullOutcome::StoreFailed(format!("put_blob_chunks_signing: {e}")),
        }
    }

    /// Commons bytes (a manifest, a public attachment): persist's plaintext
    /// door, `put_blob_signing` — stores AND emits this node's hybrid-signed
    /// `holds_bytes`.
    ///
    /// There is no `LocalOnly` plaintext door a consumer can reach:
    /// `store_blob_local` takes a `StorageFloor` that only persist can mint
    /// (I22 — "no code outside this crate can name a `StorageFloor`"). The
    /// commons is everyone's, so the gate answers `Announce` for it in every
    /// case edge has; if a policy ever says `LocalOnly` for plaintext, this
    /// refuses by name rather than announce against the verdict or store
    /// through a door that does not exist.
    async fn store_plaintext(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        meaning: &BlobMeaning,
        bytes: Vec<u8>,
        disposition: StoreDisposition,
    ) -> PullOutcome {
        if disposition == StoreDisposition::LocalOnly {
            return PullOutcome::StoreFailed(
                "the store gate said LocalOnly for PLAINTEXT bytes, and persist exposes no \
                 local-only plaintext door to a consumer (store_blob_local needs a \
                 StorageFloor only persist can mint, I22); refusing rather than announcing \
                 against the verdict"
                    .into(),
            );
        }
        let media_type = meaning.media_type().map(ToOwned::to_owned);
        match self
            .engine
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                media_type.as_deref(),
                &row.attesting_key_id,
                chrono::Utc::now(),
                uuid::Uuid::new_v4(),
            )
            .await
        {
            Ok(()) => PullOutcome::Stored { announced: true },
            Err(e) => PullOutcome::StoreFailed(e.to_string()),
        }
    }

    /// Sealed bytes: persist's `adopt_sealed_blob` — stored verbatim at the
    /// tier and `(community, epoch)` binding the AUTHOR declared on the row,
    /// never re-sealed (BLOB_REPLICATION.md §3). The AAD is rebuilt from the
    /// row exactly as a reader rebuilds it; persist carries it and does not
    /// record it.
    async fn adopt_sealed(
        &self,
        row: &Attestation,
        sha: [u8; 32],
        meaning: &BlobMeaning,
        tier: CryptoTier,
        bytes: &[u8],
        disposition: StoreDisposition,
    ) -> PullOutcome {
        let Some(pointer) = meaning.pointer() else {
            // A sealed tier is only ever declared by a typed pointer; an
            // `evidence_refs` reference has no tier and resolved Plaintext.
            return PullOutcome::StoreFailed(
                "sealed tier without a typed pointer — cannot form a provenance".into(),
            );
        };
        // v46.1.0 (CIRISPersist#878) — the provenance is READ OFF the row the
        // bytes flowed from, and the constructor now sees edge's reference
        // shape: a typed `BlobPointer` at these bytes is a reference, and it
        // is AUTHORITATIVE for the key plane (tier, community, epoch) while
        // the ROW's placement stands as the access grant. That is the rule
        // edge's own builder implemented; persist owns the one spelling now,
        // and adds what a caller could not: the row must reference the bytes,
        // a `community` row's pointer must name the cohort the row is signed
        // for, and the floor check binds tier to placement.
        //
        // `minter` is `None`: the minter is the key whose cascade MINTED the
        // epoch — the SEALING NODE that signed the `key_grant` set, not the
        // author (for a chat row the author is the person). This node neither
        // minted it nor is told who did, so persist derives it from the one
        // admitted set that granted this node a wrap, and rebinds a row
        // stored against a wrong minter when the next set arrives.
        let provenance = match BlobProvenance::from_attestation(row, &sha, pointer.epoch, None) {
            Ok(p) => p,
            Err(e) => {
                return PullOutcome::StoreFailed(format!(
                    "provenance from the referencing row {}: {e}",
                    row.attestation_id
                ))
            }
        };
        debug_assert_eq!(
            provenance.tier, tier,
            "the pointer persist read is the pointer the meaning projection read"
        );
        let aad = crate::group_content::content_aad(
            &row.attesting_key_id,
            row.asserted_at,
            pointer.content_field,
        );
        let adopt = match disposition {
            StoreDisposition::Announce => AdoptDisposition::Announce,
            StoreDisposition::LocalOnly => AdoptDisposition::LocalOnly,
        };
        match self
            .engine
            .adopt_sealed_blob(bytes, provenance, Some(&aad), adopt)
            .await
        {
            Ok(outcome) => {
                debug_assert_eq!(
                    outcome.sha256, sha,
                    "adopt stores at the ciphertext's address"
                );
                PullOutcome::Stored {
                    announced: outcome.announced,
                }
            }
            Err(e) => PullOutcome::StoreFailed(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::meaning::fixture::{bare_row, content_row};
    use super::*;

    /// CIRISEdge#739 — the pipeline's admission rule (§6.7.5): `K` bounds
    /// the requests, the byte budget bounds the memory, and an empty
    /// pipeline always admits one so a budget below one chunk degrades to
    /// `K = 1` rather than to a stall.
    #[test]
    fn the_pipeline_admits_by_lanes_and_by_bytes_and_never_stalls() {
        let chunk = 256 * 1024 + 44;
        // Lanes: K = 4 admits the fourth, refuses the fifth.
        assert!(pipeline_admits(3, 4, 3 * chunk, chunk, u64::MAX));
        assert!(!pipeline_admits(4, 4, 4 * chunk, chunk, u64::MAX));
        // Bytes: a budget of two chunks admits the second, refuses the third,
        // whatever K says.
        assert!(pipeline_admits(1, 16, chunk, chunk, 2 * chunk));
        assert!(!pipeline_admits(2, 16, 2 * chunk, chunk, 2 * chunk));
        // Never a stall: an empty pipeline admits a chunk larger than the
        // whole budget, and K = 0 behaves as K = 1.
        assert!(pipeline_admits(0, 16, 0, 10 * chunk, chunk));
        assert!(pipeline_admits(0, 0, 0, chunk, 0));
        assert!(!pipeline_admits(1, 0, chunk, chunk, u64::MAX));
        // The defaults hold `K` of the largest chunk persist admits.
        assert_eq!(
            DEFAULT_DAG_BYTES_IN_FLIGHT,
            DEFAULT_DAG_CHUNKS_IN_FLIGHT as u64
                * ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP as u64
        );
    }

    /// CIRISPersist#957 — a batch goes when it is full by count or by
    /// persist's byte bound, or when nothing more is being fetched (never a
    /// wait for chunks that are not coming), and never empty.
    #[test]
    fn an_adopt_batch_goes_when_full_or_when_the_run_drains_and_never_empty() {
        use ciris_persist::federation::blobs::MAX_BATCH_BYTES;
        let chunk = 256 * 1024 + 44;
        // Nothing waiting: never a batch, whatever else holds.
        assert!(!adopt_batch_ready(0, 0, 0, 16));
        // Lanes still fetching and the batch not full: wait.
        assert!(!adopt_batch_ready(15, 15 * chunk, 8, 16));
        // Full by count.
        assert!(adopt_batch_ready(16, 16 * chunk, 8, 16));
        // Full by persist's byte bound before the count.
        assert!(adopt_batch_ready(3, MAX_BATCH_BYTES, 8, 64));
        // The run drained (the end, a stop, or the byte budget full): go now.
        assert!(adopt_batch_ready(1, chunk, 0, 16));
        // A batch of one goes as each chunk arrives; 0 behaves as 1.
        assert!(adopt_batch_ready(1, chunk, 8, 1));
        assert!(adopt_batch_ready(1, chunk, 8, 0));
    }

    /// CIRISPersist#957 — a batch takes the front of the run, within persist's
    /// caps (`MAX_CHUNKS_PER_BATCH`, `MAX_BATCH_BYTES`), and always at least
    /// one chunk.
    #[test]
    fn an_adopt_batch_respects_persists_caps_and_always_takes_one() {
        use ciris_persist::federation::blobs::{MAX_BATCH_BYTES, MAX_CHUNKS_PER_BATCH};
        let chunk = 256 * 1024 + 44;
        assert_eq!(adopt_batch_take(&[chunk; 20], 16), 16);
        assert_eq!(adopt_batch_take(&[chunk; 5], 16), 5);
        // Clamped to persist's count cap, and 0 behaves as 1.
        assert_eq!(adopt_batch_take(&[16; 200], 1000), MAX_CHUNKS_PER_BATCH);
        assert_eq!(adopt_batch_take(&[chunk; 3], 0), 1);
        // The byte cap: 1 MiB envelopes stop before 32 MiB.
        let big = 1024 * 1024 + 44;
        let n = adopt_batch_take(&[big; 64], 64);
        assert_eq!(n, MAX_BATCH_BYTES / big);
        assert!(n * big <= MAX_BATCH_BYTES);
        // One chunk over the byte cap still goes alone (persist names it).
        assert_eq!(adopt_batch_take(&[MAX_BATCH_BYTES + 1, chunk], 16), 1);
        assert_eq!(adopt_batch_take(&[], 16), 0);
    }

    /// CIRISEdge#797 — a batch never crosses a stream epoch (persist's batch
    /// adopt takes one): the run of the front chunk's epoch caps it. A v4
    /// chunk is adopted at its manifest epoch; a v2 chunk (no epoch) at the
    /// label a file is written under.
    #[test]
    fn an_adopt_batch_stays_in_one_epoch_and_each_chunk_takes_its_own_797() {
        assert_eq!(same_epoch_run(&[0, 0, 0, 1, 1]), 3);
        assert_eq!(same_epoch_run(&[1, 1]), 2);
        assert_eq!(same_epoch_run(&[2, 0, 2]), 1, "a run, not a count");
        assert_eq!(same_epoch_run(&[]), 0);
        assert_eq!(chunk_adopt_epoch(Some(3)), 3, "v4: the manifest's epoch");
        assert_eq!(
            chunk_adopt_epoch(None),
            crate::group_content::persist_store::STREAM_EPOCH,
            "v2: the one-shot label, as before #969"
        );
    }

    /// CIRISEdge#797 — `blob_chunk_key_not_yet_granted` is the wait, parked
    /// on the key it names (a stream epoch at v4, a chunk's own row at v2);
    /// a stranger's `blob_not_granted` and every other error are not.
    #[test]
    fn a_chunk_key_not_yet_granted_is_a_wait_never_a_refusal_797() {
        use ciris_persist::federation::{BlobError, ChunkKeyRef};
        let pending = |key| BlobError::ChunkKeyNotYetGranted {
            sha256_hex: hex::encode([1u8; 32]),
            viewer_key_id: "me".into(),
            seq: 3,
            chunk_sha_hex: hex::encode([2u8; 32]),
            key,
        };
        let stream = pending(ChunkKeyRef::Stream {
            stream_id: "file-x".into(),
            epoch: 1,
        });
        assert_eq!(stream.kind(), "blob_chunk_key_not_yet_granted");
        assert!(matches!(
            awaiting_key_of(&stream),
            Some(key_wake::Awaiting::Stream(ref e)) if e == &[("file-x".to_owned(), 1)]
        ));
        assert!(matches!(
            awaiting_key_of(&pending(ChunkKeyRef::Content {
                at_rest_sha256: hex::encode([2u8; 32]),
            })),
            Some(key_wake::Awaiting::Content(ref c)) if c == &[[2u8; 32]]
        ));
        let stranger = BlobError::NotGranted {
            sha256_hex: hex::encode([1u8; 32]),
            viewer_key_id: "stranger".into(),
        };
        assert!(awaiting_key_of(&stranger).is_none());
        assert!(awaiting_key_of(&BlobError::Backend("x".into())).is_none());
    }

    /// CIRISEdge#797 — the readiness door's `missing`, as the park reads it:
    /// a v4 DAG waits on stream epochs (its stream sets wake it), a v2 DAG
    /// on each chunk row's content wrap (persist I314c's legacy branch).
    #[test]
    fn a_dag_parks_on_what_the_readiness_door_names_797() {
        use ciris_persist::federation::chunk_dag_cascade::orchestrate::MissingChunkKey as M;
        let v4 = [
            M::Stream {
                stream_id: "file-x".into(),
                epoch: 0,
                seq_from: 0,
                seq_to: 1 << 62,
            },
            M::Stream {
                stream_id: "file-x".into(),
                epoch: 1,
                seq_from: 3,
                seq_to: (1 << 62) + 1,
            },
        ];
        assert!(matches!(
            awaiting_of(&v4),
            key_wake::Awaiting::Stream(ref e)
                if e == &[("file-x".to_owned(), 0), ("file-x".to_owned(), 1)]
        ));
        let v2 = [
            M::Content {
                seq: 3,
                chunk_sha256: hex::encode([3u8; 32]),
            },
            M::Content {
                seq: 4,
                chunk_sha256: hex::encode([4u8; 32]),
            },
        ];
        assert!(matches!(
            awaiting_of(&v2),
            key_wake::Awaiting::Content(ref c) if c == &[[3u8; 32], [4u8; 32]]
        ));
    }

    const SHA: [u8; 32] = [0xAB; 32];

    /// CIRISEdge#638 item 2 — the declared size, as the field produces it:
    /// the pointer `files::publish` writes (plaintext `size`), read at the
    /// tier the row records. Sealed tiers add persist's envelope overhead;
    /// a DAG and a pre-#698 pointer declare nothing to check.
    #[test]
    fn a_pointers_declared_size_names_the_stored_length_at_its_tier() {
        use ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD;
        let mut p: crate::group_content::BlobPointer = serde_json::from_value(serde_json::json!({
            "community_key_id": "room",
            "tier": "plaintext",
            "content_sha256": "ab".repeat(32),
            "content_field": "body",
            "size": 1000,
        }))
        .expect("pointer");
        assert_eq!(declared_stored_len(&p), Some(1000));
        for tier in [CryptoTier::CommunityDek, CryptoTier::InvisibleEncrypted] {
            p.tier = tier;
            assert_eq!(
                declared_stored_len(&p),
                Some(1000 + AT_REST_ENVELOPE_OVERHEAD as u64),
                "{tier:?}: the envelope, not the plaintext, is what arrives"
            );
        }
        p.stream_id = Some("file-1".into());
        assert_eq!(
            declared_stored_len(&p),
            None,
            "a DAG's manifest pins its own sizes"
        );
        p.stream_id = None;
        p.size = None;
        assert_eq!(declared_stored_len(&p), None, "pre-#698: nothing declared");
    }

    /// CIRISEdge#717 — the plan of the file `files::publish` chunks: 1 MiB + 1
    /// as `CHUNK_BYTES` (256 KiB) segments at a sealed tier, the caps persist
    /// reports on the opened view.
    fn sealed_plan(total: u64) -> DagPlan {
        use ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD;
        let chunk = crate::group_content::store::CHUNK_BYTES as u64;
        let mut chunks = Vec::new();
        let mut off = 0;
        while off < total {
            let size = chunk.min(total - off);
            chunks.push((chunks.len() as u64, size));
            off += size;
        }
        DagPlan {
            stream_id: Some("file-717".into()),
            total_size: total,
            chunks,
            inline_bytes_cap: ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP as u64,
            in_memory_cap_bytes: None,
            max_chunks: ciris_persist::federation::blobs::MAX_CHUNKS_PER_EPOCH,
            per_chunk_overhead: AT_REST_ENVELOPE_OVERHEAD as u64,
        }
    }

    /// CIRISEdge#717 — the bounds, on the field's shapes: the honest plan
    /// passes; every refusal is named by its rung, in the order the walk
    /// checks them, and none needs a chunk fetched.
    #[test]
    fn the_dag_plan_is_bounded_before_a_chunk_moves() {
        let total = 1_048_577u64;
        let plan = sealed_plan(total);
        assert_eq!(plan.chunks.len(), 5, "4 × 256 KiB + 1 byte");
        assert_eq!(check_dag_plan("file-717", Some(total), &plan), Ok(()));
        assert_eq!(
            check_dag_plan("file-717", None, &plan),
            Ok(()),
            "a pre-#698 pointer declares nothing to check"
        );

        // The pointer names another stream.
        assert!(matches!(
            check_dag_plan("file-other", Some(total), &plan),
            Err(DagPullRefusal::ManifestMismatch { .. })
        ));
        // The pointer's size is not the manifest's total.
        assert_eq!(
            check_dag_plan("file-717", Some(total + 1), &plan),
            Err(DagPullRefusal::TotalSizeMismatch {
                declared: total + 1,
                manifest: total,
            })
        );
        // Count over the cap.
        let mut p = plan.clone();
        p.max_chunks = 4;
        assert_eq!(
            check_dag_plan("file-717", Some(total), &p),
            Err(DagPullRefusal::OverCap {
                what: "chunk_count",
                value: 5,
                cap: 4,
            })
        );
        // CIRISEdge#737 — a sealed DAG above persist's whole-READ cap pulls:
        // 100 MiB as 400 × 256 KiB is within what its chunk list can hold.
        let big = 100 * 1024 * 1024;
        let p = sealed_plan(big);
        assert_eq!(p.chunks.len(), 400);
        assert_eq!(
            check_dag_plan("file-717", Some(big), &p),
            Ok(()),
            "the pull is chunk-wise; the whole-read cap governs reads (§6.7.3)"
        );
        // Total above what the chunk list can legally hold (the STORAGE
        // bound): one well-sized chunk under a total no single chunk can
        // carry — named before the sum rule would call it a mismatch.
        let mut p = plan.clone();
        let per_chunk_max = p.inline_bytes_cap - p.per_chunk_overhead;
        p.chunks = vec![(0, 100)];
        p.total_size = per_chunk_max + 1;
        assert_eq!(
            check_dag_plan("file-717", Some(p.total_size), &p),
            Err(DagPullRefusal::OverCap {
                what: "total_size_vs_chunks",
                value: per_chunk_max + 1,
                cap: per_chunk_max,
            })
        );
        // A PLAINTEXT plan is held whole until persist's one-shot door takes
        // it, so it keeps an in-memory ceiling.
        let mut p = plan.clone();
        p.in_memory_cap_bytes = Some(total - 1);
        assert_eq!(
            check_dag_plan("file-717", Some(total), &p),
            Err(DagPullRefusal::OverCap {
                what: "total_size_in_memory",
                value: total,
                cap: total - 1,
            })
        );
        // A chunk whose STORED body (plaintext + envelope) is over the inline
        // cap — a 1 MiB chunk at a sealed tier does not fit persist's 1 MiB.
        // Named as the chunk's fault, though the storage bound would also
        // have caught it (rule 4 runs before rule 5).
        let cap = ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP as u64;
        let mut p = sealed_plan(cap);
        p.chunks = vec![(0, cap)];
        assert!(matches!(
            check_dag_plan("file-717", Some(cap), &p),
            Err(DagPullRefusal::OverCap { what: "chunk_size", cap: c, .. }) if c == cap
        ));
        // Sizes that do not sum to the total.
        let mut p = plan.clone();
        p.chunks[4].1 = 2;
        assert!(matches!(
            check_dag_plan("file-717", Some(total), &p),
            Err(DagPullRefusal::ManifestMismatch { .. })
        ));
        // A repeated position.
        let mut p = plan.clone();
        p.chunks[4].0 = 3;
        assert!(matches!(
            check_dag_plan("file-717", Some(total), &p),
            Err(DagPullRefusal::ManifestMismatch { .. })
        ));
        // No chunks at all.
        let mut p = plan;
        p.chunks.clear();
        p.total_size = 0;
        assert!(matches!(
            check_dag_plan("file-717", Some(0), &p),
            Err(DagPullRefusal::ManifestMismatch { .. })
        ));
    }

    /// CIRISEdge#717 — a clear (v1) manifest names no stream and positions
    /// no chunk: the plan takes the index as `seq` and skips the stream check.
    #[test]
    fn a_clear_manifest_plan_positions_by_index_and_names_no_stream() {
        use ciris_persist::federation::{ChunkManifest, ChunkRef};
        let manifest = ChunkManifest {
            v: 1,
            total_size: 300,
            chunks: vec![
                ChunkRef {
                    sha: [1; 32],
                    size: 200,
                    seq: None,
                    epoch: None,
                },
                ChunkRef {
                    sha: [2; 32],
                    size: 100,
                    seq: None,
                    epoch: None,
                },
            ],
            chunk_tier: None,
            stream_id: None,
        };
        let plan = DagPlan::from_clear_manifest(&manifest, 1024);
        assert_eq!(plan.stream_id, None);
        assert_eq!(plan.chunks, vec![(0, 200), (1, 100)]);
        assert_eq!(plan.per_chunk_overhead, 0);
        assert_eq!(check_dag_plan("any-stream", Some(300), &plan), Ok(()));
    }

    /// CIRISEdge#717 — the puller's reading of a clear manifest is persist's
    /// own encoding, proven by round trip; anything else is refused, however
    /// it hashed.
    #[test]
    fn a_clear_manifest_is_read_only_when_it_round_trips_canonically() {
        use ciris_persist::federation::{ChunkManifest, ChunkRef};
        let v1 = ChunkManifest {
            v: 1,
            total_size: 300,
            chunks: vec![
                ChunkRef {
                    sha: [0xAB; 32],
                    size: 200,
                    seq: None,
                    epoch: None,
                },
                ChunkRef {
                    sha: [0xCD; 32],
                    size: 100,
                    seq: None,
                    epoch: None,
                },
            ],
            chunk_tier: None,
            stream_id: None,
        };
        let bytes = v1.to_jcs_bytes();
        assert_eq!(
            parse_clear_manifest(&bytes).expect("persist's own shape"),
            v1
        );
        // The sealed (v2) shape reads too — the tier check is the caller's.
        let v2 = ChunkManifest {
            v: 2,
            chunk_tier: Some(CryptoTier::InvisibleEncrypted),
            stream_id: Some("file-1".into()),
            chunks: v1
                .chunks
                .iter()
                .enumerate()
                .map(|(i, c)| ChunkRef {
                    seq: Some(i as u64),
                    ..c.clone()
                })
                .collect(),
            ..v1.clone()
        };
        assert_eq!(parse_clear_manifest(&v2.to_jcs_bytes()).expect("v2"), v2);
        // Semantically identical, not canonical: refused.
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        )
        .unwrap();
        assert!(parse_clear_manifest(&pretty).is_err());
        // Not a manifest at all.
        assert!(parse_clear_manifest(b"{\"hello\":1}").is_err());
        assert!(parse_clear_manifest(b"not json").is_err());
    }

    /// The refusal tags are a closed set, distinct from each other and from
    /// the whole-blob tags.
    #[test]
    fn dag_refusal_tags_are_a_closed_set() {
        let tags = [
            DagPullRefusal::ManifestMismatch {
                detail: String::new(),
            }
            .tag(),
            DagPullRefusal::TotalSizeMismatch {
                declared: 0,
                manifest: 0,
            }
            .tag(),
            DagPullRefusal::OverCap {
                what: "chunk_count",
                value: 0,
                cap: 0,
            }
            .tag(),
            DagPullRefusal::ChunkMismatch {
                seq: 0,
                detail: String::new(),
            }
            .tag(),
            DagPullRefusal::ChunkMissing {
                detail: String::new(),
            }
            .tag(),
            PULL_REFUSAL_SIZE_MISMATCH,
        ];
        let set: HashSet<&str> = tags.iter().copied().collect();
        assert_eq!(set.len(), tags.len(), "{tags:?}");
        assert!(tags.iter().all(|t| !t.is_empty()));
    }

    fn sink_with(capacity: usize) -> (PullSink, mpsc::Receiver<PullRequest>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            PullSink {
                tx,
                dropped: Arc::new(AtomicU64::new(0)),
                key_waits: Arc::new(KeyWaits::new(4)),
            },
            rx,
        )
    }

    /// The sink is the apply path's one door, and it must never block or
    /// grow: a full queue drops, counts, and reports it.
    /// CIRISEdge#646 — the counter's keys are a closed set, and the
    /// self/family arms name `author_nodes`: the label a run greps for to
    /// prove a self pull never touched the claim index.
    #[test]
    fn pull_source_tags_are_a_closed_set() {
        use crate::CohortScope;
        let cohort = CohortScope::Cohort {
            cohort_id: "c".into(),
        };
        assert_eq!(
            pull_source_tag(&CohortScope::SelfOnly, true),
            "self:author_nodes"
        );
        assert_eq!(
            pull_source_tag(&CohortScope::Family, true),
            "family:author_nodes"
        );
        assert_eq!(pull_source_tag(&cohort, false), "community:claim_index");
        assert_eq!(
            pull_source_tag(&CohortScope::Public, false),
            "federation:claim_index"
        );
    }

    #[tokio::test]
    async fn a_full_sink_drops_and_counts_rather_than_blocking() {
        let (sink, _rx) = sink_with(1);
        let row = content_row("community", "room", &SHA);
        assert_eq!(sink.offer(&row), PullOffer::Queued);
        assert_eq!(sink.offer(&row), PullOffer::Dropped, "capacity 1 is full");
        assert_eq!(sink.dropped(), 1);
        assert_eq!(sink.offer(&row), PullOffer::Dropped);
        assert_eq!(sink.dropped(), 2);
    }

    /// A row that references nothing costs the apply path no clone and no
    /// channel slot — and a `holds_bytes` row counts as referencing nothing.
    #[tokio::test]
    async fn non_references_never_enter_the_queue() {
        let (sink, mut rx) = sink_with(4);
        let plain = bare_row("federation");
        assert_eq!(sink.offer(&plain), PullOffer::NotAReference);
        let mut holds = bare_row("federation");
        holds.attestation_type = format!("holds_bytes:sha256:{}", &hex::encode(SHA)[..8]);
        holds.attestation_envelope =
            serde_json::json!({ "kind": "holds_bytes", "evidence_refs": [hex::encode(SHA)] });
        assert_eq!(
            sink.offer(&holds),
            PullOffer::NotAReference,
            "possession is not meaning: a holds_bytes row never triggers a pull"
        );
        assert!(rx.try_recv().is_err(), "nothing was queued");
        assert_eq!(sink.dropped(), 0);
    }

    /// CIRISPersist#878 — the two axes of a sealed pull's provenance, on the
    /// shape production actually has: a chat row placed at `self` scope whose
    /// body is sealed under the room's DEK, referencing the bytes with a typed
    /// `BlobPointer` and NO `evidence_refs`. The row gives authorship and
    /// placement; the POINTER gives the community, the epoch and the tier.
    /// Resolving the tier from the row's scope would adopt community-DEK
    /// ciphertext as `InvisibleEncrypted`, and requiring `evidence_refs` would
    /// refuse the row outright — both regressions this pins.
    #[test]
    fn a_pointer_only_chat_row_keeps_the_pointers_tier_and_community() {
        let mut row = content_row(
            ciris_persist::federation::types::cohort_scope::SELF,
            "chat:pair:v1:room",
            &SHA,
        );
        row.attestation_envelope["content"]["tier"] = serde_json::json!("community_dek");
        row.attestation_envelope["content"]["epoch"] = serde_json::json!(7);
        assert!(
            row.attestation_envelope.get("evidence_refs").is_none(),
            "fixture drift: a chat row references its blob by POINTER only"
        );
        let meaning = BlobMeaning::project(&row, &SHA).expect("the pointer is the reference");
        let pointer = meaning.pointer().expect("typed pointer");
        assert_eq!(pointer.tier, CryptoTier::CommunityDek);

        let p = BlobProvenance::from_attestation(&row, &SHA, pointer.epoch, None)
            .expect("the row references the bytes by pointer");
        assert_eq!(p.author_key_id, "alice", "the ROW's attester authors");
        assert_eq!(
            p.cohort_scope,
            ciris_persist::federation::types::cohort_scope::SELF,
            "the ROW's placement is the row's own"
        );
        assert_eq!(
            p.community_key_id.as_deref(),
            Some("chat:pair:v1:room"),
            "the POINTER names the community whose DEK sealed the bytes"
        );
        assert_eq!(p.epoch, Some(7), "the POINTER carries the epoch");
        assert_eq!(
            p.tier,
            CryptoTier::CommunityDek,
            "the POINTER's resolved tier is authoritative — the row sits at self \
             scope and its bytes are sealed under the room's DEK"
        );
    }

    /// CIRISPersist#876 — the minter is NEVER the author. Edge does not mint
    /// epochs and is not told who did, so it always defers the derivation.
    #[test]
    fn the_minter_is_never_transcribed_from_the_author() {
        for author in ["alice", "ciris-node-a-3yr5psjdy4", "someone-else"] {
            let mut row = content_row("community", "room", &SHA);
            row.attesting_key_id = author.to_owned();
            row.attestation_envelope["content"]["tier"] = serde_json::json!("community_dek");
            let meaning = BlobMeaning::project(&row, &SHA).expect("pointer");
            let pointer = meaning.pointer().expect("typed pointer");
            let p = BlobProvenance::from_attestation(&row, &SHA, pointer.epoch, None)
                .expect("the row references the bytes by pointer");
            assert_eq!(p.author_key_id, author);
            assert_eq!(
                p.minter_key_id, None,
                "the sealing node minted the epoch; persist derives it from the \
                 admitted key_grant set (CIRISPersist#876)"
            );
        }
    }

    /// A closed sink (no puller) is loud, not a hang.
    #[test]
    fn a_disconnected_sink_reports_dropped() {
        let sink = PullSink::disconnected();
        let row = content_row("community", "room", &SHA);
        assert_eq!(sink.offer(&row), PullOffer::Dropped);
    }
}
