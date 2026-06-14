//! Adaptive multi-peer parallel byte-range scheduler for chunked blobs
//! (CIRISEdge#55 / CIRISPersist#145 seam).
//!
//! # Mission
//!
//! Given a content-addressed blob (`blob_sha256`) that exceeds the
//! AV-13 whole-file ceiling and is therefore stored chunked, fetch
//! every chunk from the set of holders persist's `list_holders`
//! returns — issuing many requests concurrently across multiple peers,
//! adaptively rebalancing as RTT and throughput shift, demoting peers
//! that lie about chunk SHAs, and ending in endgame mode (duplicate
//! requests for the last chunks; first response wins).
//!
//! Standard BitTorrent swarm-download pattern, applied to the CIRIS
//! content-addressed substrate.
//!
//! # Architectural seam (CIRISPersist#145 resolution)
//!
//! The maintainer call on persist#145 split responsibilities cleanly:
//!
//! - **Edge (this module + [`BlobChunkFetch`] wire types)** —
//!   transports bytes. Owns the Reticulum carrier op, the per-peer
//!   EWMA state, the scheduler's pick-fastest-with-capacity logic,
//!   and the endgame / dishonest-peer demotion machinery.
//!
//! - **Persist** — owns the trust seam. The atomic verify-on-write
//!   primitive (`sha256(bytes) == chunk_sha256` is checked at
//!   `put_blob` / `put_blob_chunks` time) returns `HashMismatch` on
//!   failure. The scheduler reaches persist through the
//!   [`BlobChunkVerifier`] trait — consumers wrap their persist
//!   `BlobStorage` handle, returning `Err(ChunkVerifyError::Mismatch)`
//!   on hash failure so the scheduler can demote the dishonest peer
//!   for the rest of the session.
//!
//! Trait-based wiring is required because persist's `BlobStorage` is
//! NOT object-safe (uses `async fn in trait` via `impl Future + Send`;
//! same pattern as edge's `VerifyDirectory` adapter erases
//! `FederationDirectory`).
//!
//! [`BlobChunkFetch`]: crate::messages::BlobChunkFetch
//!
//! # Scope: what this module owns vs. defers
//!
//! Owns:
//! - [`SwarmConfig`] — operator knobs (in-flight cap per peer,
//!   endgame trigger, EWMA alpha, dishonest-strike threshold).
//! - [`PeerState`] — per-peer EWMA + in-flight count + dishonest flag.
//! - [`SwarmError`] — typed error surface for the fetch driver.
//! - [`BlobChunkVerifier`] — trait consumers implement to hand bytes
//!   to `persist.put_blob_chunks` / equivalent atomic verify+store.
//! - [`BlobChunkSource`] — trait consumers implement so edge can
//!   answer inbound `BlobChunkFetch` envelopes from this peer's local
//!   store (the server-side hook in `dispatch_inbound`).
//! - [`SwarmScheduler::fetch_blob`] — the driver loop.
//!
//! Deferred:
//! - Manifest-SHA discovery from blob-SHA alone. The caller of
//!   `fetch_blob` provides the manifest (via [`ChunkManifestLite`]);
//!   higher-level orchestration owns the "given the overall blob SHA,
//!   where do I get the manifest" question (lens-core / agent).
//! - Stream-based chunk delivery (FSD §10.5.1 live-stream surface).
//!   v3.4.0-pre1 ships sealed-blob fetch only.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Operator knobs for the swarm scheduler. Defaults match the
/// CIRISEdge#55 TL;DR (in-flight cap 4 per peer, EWMA alpha 0.3,
/// endgame trigger when ≤2 chunks remain).
///
/// Constructed via [`SwarmConfig::default`] for production use; tests
/// override specific fields to exercise edge cases.
#[derive(Debug, Clone, PartialEq)]
pub struct SwarmConfig {
    /// Maximum concurrent in-flight chunk requests per holder. The
    /// scheduler never queues more than this many chunks against any
    /// single peer at once. 4 is the standard BitTorrent default —
    /// high enough to keep the peer's network pipeline full, low
    /// enough that a single slow peer doesn't starve the others.
    pub max_in_flight_per_peer: u32,
    /// EWMA smoothing factor for per-peer RTT updates. `α` in
    /// `new_ewma = α * sample + (1-α) * old_ewma`. 0.3 weights the
    /// most recent sample modestly — responsive to throughput shifts
    /// without overreacting to single outliers.
    pub ewma_alpha: f64,
    /// Switch to endgame mode (issue duplicate requests for the last
    /// chunks; first response wins) when remaining-chunks count
    /// drops to this threshold or below.
    pub endgame_threshold: usize,
    /// How many `ChunkMismatch` strikes from one peer before the
    /// scheduler permanently excludes them from the session's
    /// candidate set. 1 — a single hash-failure is the trust
    /// primitive's strongest signal of dishonesty; no benefit of the
    /// doubt.
    pub dishonest_strike_limit: u32,
    /// Per-request timeout. A holder that doesn't respond in this
    /// window is penalized via EWMA but not demoted (could be
    /// transient network) — chunk is re-queued elsewhere.
    pub per_request_timeout: Duration,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            max_in_flight_per_peer: 4,
            ewma_alpha: 0.3,
            endgame_threshold: 2,
            dishonest_strike_limit: 1,
            per_request_timeout: Duration::from_secs(30),
        }
    }
}

/// Per-peer scheduler state for one swarm-fetch session.
///
/// Held in a `HashMap<key_id, PeerState>` keyed by the holder's
/// federation `key_id` (the same identifier `list_holders` returns).
/// Mutated under the scheduler's lock as fetches dispatch and
/// complete.
///
/// Not `Serialize` / `Deserialize` — session-scoped only, never
/// crosses the wire.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct PeerState {
    /// EWMA-smoothed estimate of this peer's chunk-response RTT.
    /// Initialized to the first observed sample; updated per
    /// [`SwarmConfig::ewma_alpha`]. Lower = faster; the scheduler
    /// prefers low-EWMA peers among those with capacity.
    pub ewma_rtt: Option<Duration>,
    /// Number of chunks currently dispatched to this peer and not
    /// yet completed. Capped by
    /// [`SwarmConfig::max_in_flight_per_peer`].
    pub in_flight: u32,
    /// How many `ChunkMismatch`s this peer has produced. Compared to
    /// [`SwarmConfig::dishonest_strike_limit`] — at or above, the
    /// peer is demoted (excluded from further dispatch).
    pub dishonest_strikes: u32,
    /// Whether the peer has been demoted (either via dishonest
    /// strikes or a hard refusal like `Withdrawn` / `Revoked`).
    /// Demoted peers are skipped during pick-fastest-with-capacity;
    /// their existing in-flight requests are allowed to complete
    /// (canceling would just discard work).
    pub demoted: bool,
}

impl PeerState {
    /// Apply one observed RTT sample to the EWMA, per
    /// [`SwarmConfig::ewma_alpha`]. First sample initializes; later
    /// samples blend.
    pub fn record_rtt(&mut self, sample: Duration, alpha: f64) {
        let sample_secs = sample.as_secs_f64();
        let new_secs = match self.ewma_rtt {
            None => sample_secs,
            Some(prev) => alpha * sample_secs + (1.0 - alpha) * prev.as_secs_f64(),
        };
        self.ewma_rtt = Some(Duration::from_secs_f64(new_secs));
    }

    /// Record a `ChunkMismatch` strike; demotes if at threshold.
    pub fn record_dishonest_strike(&mut self, limit: u32) {
        self.dishonest_strikes = self.dishonest_strikes.saturating_add(1);
        if self.dishonest_strikes >= limit {
            self.demoted = true;
        }
    }

    /// True when the peer is both not-demoted AND has capacity for
    /// another in-flight chunk. The pick-fastest-with-capacity loop
    /// filters on this.
    #[must_use]
    pub fn can_accept(&self, max_in_flight: u32) -> bool {
        !self.demoted && self.in_flight < max_in_flight
    }
}

/// Typed errors from the swarm-fetch driver. Distinct from persist's
/// `BlobError` because the scheduler's failure modes are
/// composition-level (no peer left to ask, manifest unreachable)
/// rather than substrate-level.
#[derive(Debug, thiserror::Error)]
pub enum SwarmError {
    /// `BlobStorage::list_holders(sha)` returned an empty set. No
    /// peer claims to hold this blob — federation-wide miss.
    #[error("no holders registered for blob {0}")]
    NoHolders(String),
    /// The manifest blob itself couldn't be fetched from any holder
    /// (every responder returned ContentMiss or timed out). The
    /// scheduler can't proceed without it — manifest binds the chunk
    /// list.
    #[error("manifest fetch failed for blob {0}: {1}")]
    ManifestUnreachable(String, String),
    /// Every holder for one specific chunk has been demoted or
    /// declined. The scheduler stops short of partial assembly: a
    /// chunk that can't be fetched is a failed blob.
    #[error("no holders left for chunk {chunk_sha} (blob {blob_sha})")]
    ChunkUnreachable {
        /// Hex-encoded overall blob SHA-256.
        blob_sha: String,
        /// Hex-encoded chunk SHA-256.
        chunk_sha: String,
    },
    /// Persist's chunk verify-and-store returned an error that wasn't
    /// `ChunkMismatch` (which the scheduler handles internally as a
    /// dishonest-peer strike). Includes backend errors and the
    /// `Withdrawn` / `Revoked` federation-wide gone signals.
    #[error("substrate error during chunk verify-and-store: {0}")]
    Substrate(String),
    /// A federation-tier `Withdrawn` or `Revoked` response was
    /// observed — the blob is gone federation-wide. The scheduler
    /// aborts immediately on the first such response (retrying
    /// against other holders is pointless).
    #[error("blob {0} withdrawn or revoked federation-wide")]
    GoneFederationWide(String),
    /// The caller-supplied manifest is structurally invalid (zero
    /// chunks, `total_size` mismatch, etc.) so the scheduler refuses
    /// to start. Surfaced separately from `Substrate` so the
    /// PyEdge caller can distinguish "your input was malformed"
    /// from "the swarm broke."
    #[error("invalid manifest for blob {0}: {1}")]
    InvalidManifest(String, String),
}

/// Distinct outcomes from a [`BlobChunkVerifier::verify_and_store`]
/// call — the scheduler reacts to each differently.
#[derive(Debug, thiserror::Error)]
pub enum ChunkVerifyError {
    /// `sha256(bytes) != chunk_sha256` — the peer is dishonest.
    /// Scheduler records a strike and demotes per
    /// [`SwarmConfig::dishonest_strike_limit`].
    #[error("chunk sha mismatch for {chunk_sha}")]
    Mismatch {
        /// Hex-encoded chunk SHA-256 the responder claimed.
        chunk_sha: String,
    },
    /// Persist surfaced a backend error (DB down, disk full, etc.).
    /// Scheduler aborts the whole fetch — no peer can fix this.
    #[error("persist backend error: {0}")]
    Backend(String),
}

/// Trait the swarm scheduler uses to hand chunk bytes to persist for
/// the atomic verify-and-store step (CIRISPersist#145 §10.1.1 seam).
///
/// Consumer crates (lens-core / agent) implement this by wrapping
/// their `BlobStorage` handle. The impl typically calls
/// `put_blob_chunks` (or the lower-level signing variant) once it has
/// the full manifest's worth of chunks; the scheduler buffers chunks
/// in-memory and finalizes via [`Self::finalize`].
///
/// Per-chunk verification semantics: implementations MUST hash the
/// supplied bytes and compare to `chunk_sha256`, returning
/// `Err(ChunkVerifyError::Mismatch)` on mismatch. The scheduler
/// relies on this signal to demote dishonest peers.
pub trait BlobChunkVerifier: Send + Sync {
    /// Verify `sha256(bytes) == chunk_sha256` and stash for assembly.
    /// Returns `Ok(())` if the chunk passed; `Err(Mismatch)` if the
    /// peer lied; `Err(Backend)` on substrate fault.
    ///
    /// Implementations MAY persist incrementally or buffer in-memory
    /// until [`Self::finalize`] is called — the scheduler's
    /// observable contract is just the per-chunk pass/fail signal.
    fn verify_and_store(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        bytes: &[u8],
    ) -> Result<(), ChunkVerifyError>;

    /// Called once every chunk in the manifest has been verified.
    /// Implementations that buffered can flush here; implementations
    /// that wrote-through can no-op.
    fn finalize(&self, _blob_sha256: [u8; 32]) -> Result<(), ChunkVerifyError> {
        Ok(())
    }
}

/// Server-side hook: trait edge consults when an inbound
/// [`crate::MessageType::BlobChunkFetch`] envelope arrives, asking
/// "do you hold this blob's chunk; if so, what bytes?"
///
/// Implementations wrap persist's `BlobStorage`:
/// - `has_blob(blob_sha256)` -> existence check
/// - if present: parse the `ChunkManifest`, find the chunk by SHA,
///   compute its byte range, return `get_blob_range(blob_sha,
///   start, end)`
/// - if absent: `Ok(None)` -> edge emits `BlobChunkMiss(NotHeld)`
///
/// `Send + Sync + 'static`-bounded so it can live behind an
/// `Arc<dyn BlobChunkSource>` on Edge. Async-by-default shape: the
/// impl can be sync (just `block_on`s a runtime handle) or true
/// async, depending on how the consumer wires persist.
pub trait BlobChunkSource: Send + Sync + 'static {
    /// Look up `(blob_sha256, chunk_sha256)` in this peer's local
    /// store and return:
    /// - `Ok(Some(bytes))` if we hold the chunk
    /// - `Ok(None)` if we don't hold it (edge responds with
    ///   `BlobChunkMiss::NotHeld`)
    /// - `Err(reason)` for a hard refusal that maps to one of
    ///   `Withdrawn` / `Revoked` / `PolicyDenied`
    fn read_chunk(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
    ) -> Result<Option<Vec<u8>>, ChunkSourceRefusal>;
}

/// Refusal reasons surfaced by a [`BlobChunkSource::read_chunk`]
/// impl. Mirrors the [`crate::MissReason`] taxonomy minus `NotHeld`
/// (that's encoded by `Ok(None)`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkSourceRefusal {
    /// Bytes withdrawn at federation tier.
    Withdrawn,
    /// Originating signer's key was revoked.
    Revoked,
    /// Local policy denied the fetch.
    PolicyDenied,
    /// v3.5.0 (CIRISEdge#116 / CIRISPersist#149) — responder is under
    /// disk pressure and shedding proxy serves. Surfaces when a
    /// consumer's `BlobChunkSource` impl wraps persist's
    /// `Engine::serve_blob_to_peer` and observes
    /// `BlobError::DiskPressureProxyRefused`.
    DiskPressure,
}

impl ChunkSourceRefusal {
    /// Map to the wire-level [`crate::MissReason`].
    #[must_use]
    pub fn to_miss_reason(&self) -> crate::messages::MissReason {
        match self {
            Self::Withdrawn => crate::messages::MissReason::Withdrawn,
            Self::Revoked => crate::messages::MissReason::Revoked,
            Self::PolicyDenied => crate::messages::MissReason::PolicyDenied,
            Self::DiskPressure => crate::messages::MissReason::DiskPressure,
        }
    }
}

/// Minimal manifest shape the scheduler walks. Mirrors persist's
/// `ChunkManifest` (`v3.4.0-pre1` decouples scheduler from the
/// persist crate's typed shape so the swarm can be tested without a
/// running engine). Production callers construct from
/// `ChunkManifest::chunks.iter().map(|c| (c.sha, c.size as usize))`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkManifestLite {
    /// Ordered chunk list. Concatenating chunk bytes in this order
    /// reproduces the full blob.
    pub chunks: Vec<(/* sha */ [u8; 32], /* size */ usize)>,
    /// Σ chunk sizes — verified against `chunks` at scheduler entry.
    pub total_size: u64,
}

impl ChunkManifestLite {
    /// Construct from a persist `ChunkManifest` by projecting away
    /// the `v` field. Available only when the manifest is provided
    /// as a typed value.
    #[must_use]
    pub fn from_persist(manifest: &ciris_persist::federation::ChunkManifest) -> Self {
        Self {
            chunks: manifest
                .chunks
                .iter()
                .map(|c| (c.sha, c.size as usize))
                .collect(),
            total_size: manifest.total_size,
        }
    }

    /// Validate structural invariants: nonempty chunk list,
    /// `total_size == Σ sizes`. Returns the error string the
    /// scheduler wraps in `SwarmError::InvalidManifest`.
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.chunks.is_empty() {
            return Err("manifest has zero chunks".into());
        }
        let sum: u64 = self.chunks.iter().map(|(_, s)| *s as u64).sum();
        if sum != self.total_size {
            return Err(format!(
                "chunk sizes sum to {sum} but manifest total_size is {}",
                self.total_size
            ));
        }
        Ok(())
    }
}

/// Outcome of a single in-flight fetch — returned by the worker
/// closures via the join channel. Internal scheduler type.
struct FetchOutcome {
    peer_key_id: String,
    chunk_sha: [u8; 32],
    started_at: Instant,
    result: FetchResultBody,
}

enum FetchResultBody {
    Bytes(Vec<u8>),
    ChunkMiss {
        reason: String,
    },
    /// Transport / timeout. The string is for logging surface.
    Error(#[allow(dead_code)] String),
}

/// The driver. Holds an [`Arc<crate::Edge>`] handle (for issuing the
/// per-chunk fetches) + the verifier-and-store hook. Construct
/// per-fetch via [`SwarmScheduler::new`].
pub struct SwarmScheduler {
    edge: Arc<crate::Edge>,
    verifier: Arc<dyn BlobChunkVerifier>,
    config: SwarmConfig,
}

impl SwarmScheduler {
    /// Construct a new scheduler. Consumers typically call this once
    /// per blob fetch — peer state is fetch-scoped, not long-lived.
    pub fn new(
        edge: Arc<crate::Edge>,
        verifier: Arc<dyn BlobChunkVerifier>,
        config: SwarmConfig,
    ) -> Self {
        Self {
            edge,
            verifier,
            config,
        }
    }

    /// Test constructor: identical to `new` but takes ownership of
    /// the verifier directly instead of a trait object.
    #[doc(hidden)]
    #[cfg(test)]
    pub fn new_for_test(
        edge: Arc<crate::Edge>,
        verifier: Arc<dyn BlobChunkVerifier>,
        config: SwarmConfig,
    ) -> Self {
        Self::new(edge, verifier, config)
    }

    /// Drive a swarm fetch of `blob_sha256`, given the chunk
    /// manifest + the federation key_ids of every holder. Returns
    /// the assembled blob bytes.
    ///
    /// # Caller responsibilities (v3.4.0-pre1)
    ///
    /// - **Manifest discovery.** The caller fetches the
    ///   [`ChunkManifestLite`] separately (typically via
    ///   `Edge::fetch_content` against the manifest blob's own SHA).
    ///   The scheduler does not infer manifest-SHA from blob-SHA;
    ///   that's higher-level orchestration (lens-core / agent).
    /// - **Holder list.** The caller queries persist's
    ///   `BlobStorage::list_holders(blob_sha256)` and passes the
    ///   result. The scheduler does not call persist directly.
    #[allow(clippy::too_many_lines)] // the driver loop is the load-bearing composition site
    #[allow(clippy::cast_possible_truncation)] // assembled blob size is bounded by AV-13 family caps
    pub async fn fetch_blob(
        &self,
        blob_sha256: [u8; 32],
        manifest: ChunkManifestLite,
        holders: Vec<String>,
    ) -> Result<Vec<u8>, SwarmError> {
        let blob_hex = hex::encode(blob_sha256);

        manifest
            .validate()
            .map_err(|e| SwarmError::InvalidManifest(blob_hex.clone(), e))?;

        if holders.is_empty() {
            return Err(SwarmError::NoHolders(blob_hex));
        }

        // Per-peer state, fetch-scoped.
        let mut peers: HashMap<String, PeerState> = holders
            .iter()
            .map(|k| (k.clone(), PeerState::default()))
            .collect();

        // Pending chunks in arrival order. We pop from the front for
        // FIFO fairness; demoted-peer retries go back to the front so
        // they're picked up promptly.
        let mut pending: VecDeque<[u8; 32]> = manifest.chunks.iter().map(|(sha, _)| *sha).collect();
        let total_chunks = pending.len();

        // Assembly buffer keyed by chunk-SHA. Filled as each fetch
        // completes; final assembly walks the manifest in order.
        let mut chunk_bytes: HashMap<[u8; 32], Vec<u8>> = HashMap::with_capacity(total_chunks);

        // FuturesUnordered-equivalent via channel: each spawned fetch
        // sends a `FetchOutcome` here when it completes. We use a
        // bounded mpsc so the scheduler back-pressures naturally on
        // dispatcher slowness.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchOutcome>(64);

        // Track in-flight count by `(peer_key_id, chunk_sha)` so
        // endgame mode can issue duplicate requests safely.
        let mut total_in_flight: usize = 0;

        loop {
            // Schedule: while there's pending work AND a peer with
            // capacity, dispatch.
            while !pending.is_empty() {
                let Some(peer) = pick_peer(&peers, self.config.max_in_flight_per_peer) else {
                    break;
                };
                let Some(chunk_sha) = pending.pop_front() else {
                    break;
                };
                self.dispatch_chunk_fetch(&peer, blob_sha256, chunk_sha, &tx);
                if let Some(state) = peers.get_mut(&peer) {
                    state.in_flight = state.in_flight.saturating_add(1);
                }
                total_in_flight += 1;
            }

            // Endgame mode: if remaining chunks (in-flight + pending)
            // are at or below threshold, issue duplicate requests to
            // any peer with capacity. First response wins; later
            // arrivals find no pending oneshot and are dropped.
            //
            // v3.5.0 (CIRISEdge#118 fix) — `maybe_endgame_dispatch`
            // MUST update `total_in_flight` for the duplicates it
            // launches; otherwise the per-outcome decrement at line
            // ~548 saturates `total_in_flight` to 0 prematurely (one
            // decrement per response, including duplicates), the
            // loop-exit condition fires while real dispatches are
            // still outstanding, and the assemble pass fails with
            // `ChunkUnreachable` for whichever chunk's main-dispatch
            // response was still in flight.
            let remaining = pending.len() + total_in_flight;
            if remaining > 0 && remaining <= self.config.endgame_threshold {
                self.maybe_endgame_dispatch(
                    blob_sha256,
                    &chunk_bytes,
                    &manifest,
                    &mut peers,
                    &tx,
                    &mut total_in_flight,
                );
            }

            // If nothing is in flight AND nothing is pending, we're
            // done — assemble.
            if total_in_flight == 0 && pending.is_empty() {
                break;
            }

            // Await the next completion.
            let Some(outcome) = rx.recv().await else {
                return Err(SwarmError::Substrate(
                    "scheduler channel closed unexpectedly".into(),
                ));
            };

            // De-account in-flight on the peer that fired this
            // completion. (Endgame duplicates may decrement multiple
            // times for the same chunk-SHA; the per-peer counter is
            // per-peer-per-dispatch, not per-unique-chunk.)
            if let Some(state) = peers.get_mut(&outcome.peer_key_id) {
                state.in_flight = state.in_flight.saturating_sub(1);
            }
            total_in_flight = total_in_flight.saturating_sub(1);

            match outcome.result {
                FetchResultBody::Bytes(bytes) => {
                    let rtt = outcome.started_at.elapsed();
                    if let Some(state) = peers.get_mut(&outcome.peer_key_id) {
                        state.record_rtt(rtt, self.config.ewma_alpha);
                    }

                    // Endgame duplicate: another holder may have
                    // already filled this chunk-SHA. Skip the
                    // verifier call (it would just do redundant
                    // work) — first response wins.
                    if chunk_bytes.contains_key(&outcome.chunk_sha) {
                        continue;
                    }

                    match self
                        .verifier
                        .verify_and_store(blob_sha256, outcome.chunk_sha, &bytes)
                    {
                        Ok(()) => {
                            chunk_bytes.insert(outcome.chunk_sha, bytes);
                        }
                        Err(ChunkVerifyError::Mismatch { .. }) => {
                            // Dishonest peer — strike + demote.
                            if let Some(state) = peers.get_mut(&outcome.peer_key_id) {
                                state.record_dishonest_strike(self.config.dishonest_strike_limit);
                            }
                            // Re-queue the chunk; another holder may
                            // serve it honestly.
                            pending.push_front(outcome.chunk_sha);
                        }
                        Err(ChunkVerifyError::Backend(e)) => {
                            return Err(SwarmError::Substrate(e));
                        }
                    }
                }
                FetchResultBody::ChunkMiss { reason } => {
                    // Map the wire reason string to scheduler behavior.
                    // (Body of `ChunkResult::ChunkMiss` is formatted via
                    // `format!("{:?}", miss.reason)` so the variants
                    // match `MissReason`'s Debug repr.)
                    let r = reason.as_str();
                    if r.contains("Withdrawn") || r.contains("Revoked") {
                        return Err(SwarmError::GoneFederationWide(blob_hex));
                    }
                    if r.contains("PolicyDenied") {
                        if let Some(state) = peers.get_mut(&outcome.peer_key_id) {
                            state.demoted = true;
                        }
                    }
                    // v3.5.0 (CIRISEdge#116) — DiskPressure is a
                    // permanent-for-this-session refusal per persist's
                    // contract (pressure recovers on a monitor-loop
                    // cadence, not per-request). Demote the peer for
                    // the rest of the fetch; chunk re-queues for
                    // another holder.
                    if r.contains("DiskPressure") {
                        if let Some(state) = peers.get_mut(&outcome.peer_key_id) {
                            state.demoted = true;
                        }
                    }
                    // Re-queue for retry on another holder.
                    if !chunk_bytes.contains_key(&outcome.chunk_sha) {
                        pending.push_back(outcome.chunk_sha);
                    }
                }
                FetchResultBody::Error(_) => {
                    // Transport/timeout — penalize via a synthetic
                    // RTT sample of the configured per-request timeout
                    // (worst plausible), then re-queue.
                    if let Some(state) = peers.get_mut(&outcome.peer_key_id) {
                        state.record_rtt(self.config.per_request_timeout, self.config.ewma_alpha);
                    }
                    if !chunk_bytes.contains_key(&outcome.chunk_sha) {
                        pending.push_back(outcome.chunk_sha);
                    }
                }
            }

            // Sanity: if every peer is demoted AND we still have
            // pending chunks, surface ChunkUnreachable on the first
            // pending chunk. Avoids an infinite re-queue loop.
            if !pending.is_empty() && total_in_flight == 0 {
                let any_alive = peers
                    .values()
                    .any(|p| p.can_accept(self.config.max_in_flight_per_peer));
                if !any_alive {
                    let chunk_sha = pending.front().copied().unwrap_or([0u8; 32]);
                    return Err(SwarmError::ChunkUnreachable {
                        blob_sha: blob_hex,
                        chunk_sha: hex::encode(chunk_sha),
                    });
                }
            }
        }

        // Finalize verifier + assemble blob bytes in manifest order.
        self.verifier
            .finalize(blob_sha256)
            .map_err(|e| SwarmError::Substrate(format!("finalize: {e:?}")))?;

        let mut assembled = Vec::with_capacity(manifest.total_size as usize);
        for (sha, _size) in &manifest.chunks {
            match chunk_bytes.get(sha) {
                Some(b) => assembled.extend_from_slice(b),
                None => {
                    return Err(SwarmError::ChunkUnreachable {
                        blob_sha: hex::encode(blob_sha256),
                        chunk_sha: hex::encode(*sha),
                    });
                }
            }
        }

        Ok(assembled)
    }

    /// Spawn a single fetch_blob_chunk call against `peer_key_id` for
    /// `chunk_sha`, forwarding the result over `tx`.
    fn dispatch_chunk_fetch(
        &self,
        peer_key_id: &str,
        blob_sha256: [u8; 32],
        chunk_sha: [u8; 32],
        tx: &tokio::sync::mpsc::Sender<FetchOutcome>,
    ) {
        let edge = self.edge.clone();
        let peer = peer_key_id.to_string();
        let timeout = self.config.per_request_timeout;
        let tx = tx.clone();
        let started_at = Instant::now();
        tokio::spawn(async move {
            let result = match edge
                .fetch_blob_chunk(&peer, blob_sha256, chunk_sha, timeout)
                .await
            {
                Ok(crate::ChunkResult::Bytes(bytes)) => FetchResultBody::Bytes(bytes),
                Ok(crate::ChunkResult::ChunkMiss { reason }) => {
                    FetchResultBody::ChunkMiss { reason }
                }
                Err(e) => FetchResultBody::Error(e.to_string()),
            };
            let _ = tx
                .send(FetchOutcome {
                    peer_key_id: peer,
                    chunk_sha,
                    started_at,
                    result,
                })
                .await;
        });
    }

    /// Endgame: for any chunk still in-flight (not yet in
    /// `chunk_bytes`), if a holder with capacity exists, dispatch a
    /// duplicate request. First response wins via the
    /// `chunk_bytes.contains_key` check on the verifier path.
    fn maybe_endgame_dispatch(
        &self,
        blob_sha256: [u8; 32],
        chunk_bytes: &HashMap<[u8; 32], Vec<u8>>,
        manifest: &ChunkManifestLite,
        peers: &mut HashMap<String, PeerState>,
        tx: &tokio::sync::mpsc::Sender<FetchOutcome>,
        total_in_flight: &mut usize,
    ) {
        for (chunk_sha, _) in &manifest.chunks {
            if chunk_bytes.contains_key(chunk_sha) {
                continue;
            }
            // Pick any peer with capacity. (Could iterate by ewma_rtt
            // for the fastest; endgame is a coverage primitive, not a
            // latency primitive — any-capacity is fine.)
            let candidate = peers
                .iter()
                .filter(|(_, p)| p.can_accept(self.config.max_in_flight_per_peer))
                .map(|(k, _)| k.clone())
                .next();
            if let Some(peer) = candidate {
                self.dispatch_chunk_fetch(&peer, blob_sha256, *chunk_sha, tx);
                if let Some(state) = peers.get_mut(&peer) {
                    state.in_flight = state.in_flight.saturating_add(1);
                }
                // v3.5.0 (CIRISEdge#118 fix) — track endgame
                // duplicates in `total_in_flight` too. Each duplicate
                // dispatched here will produce a completion outcome,
                // which the main loop's per-outcome decrement at
                // line ~548 will subtract from `total_in_flight`. If
                // we don't add here, the decrement saturates and the
                // loop exits with real dispatches still outstanding.
                *total_in_flight += 1;
            }
        }
    }
}

/// Pick the peer with lowest EWMA-RTT that has capacity. Untimed
/// peers (no RTT samples yet) sort BEFORE timed peers — we want to
/// give every holder at least one chunk so the scheduler has RTT
/// data to make subsequent choices.
fn pick_peer(peers: &HashMap<String, PeerState>, max_in_flight: u32) -> Option<String> {
    let mut best: Option<(String, Option<Duration>)> = None;
    for (key, state) in peers {
        if !state.can_accept(max_in_flight) {
            continue;
        }
        match (&best, state.ewma_rtt) {
            (None, _) => best = Some((key.clone(), state.ewma_rtt)),
            (Some((_, Some(_))), None) => {
                // Candidate is untimed; prefer it.
                best = Some((key.clone(), None));
            }
            (Some((_, Some(prev))), Some(cand)) if cand < *prev => {
                best = Some((key.clone(), Some(cand)));
            }
            // Existing best is untimed (we already prefer untimed
            // peers) OR cand >= prev — keep current best.
            _ => {}
        }
    }
    best.map(|(k, _)| k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_design_doc() {
        let cfg = SwarmConfig::default();
        assert_eq!(cfg.max_in_flight_per_peer, 4);
        assert!((cfg.ewma_alpha - 0.3).abs() < f64::EPSILON);
        assert_eq!(cfg.endgame_threshold, 2);
        assert_eq!(cfg.dishonest_strike_limit, 1);
        assert_eq!(cfg.per_request_timeout, Duration::from_secs(30));
    }

    #[test]
    fn ewma_first_sample_initializes() {
        let mut peer = PeerState::default();
        peer.record_rtt(Duration::from_millis(100), 0.3);
        assert_eq!(peer.ewma_rtt, Some(Duration::from_millis(100)));
    }

    #[test]
    fn ewma_blends_subsequent_samples() {
        let mut peer = PeerState::default();
        peer.record_rtt(Duration::from_millis(100), 0.3);
        peer.record_rtt(Duration::from_millis(200), 0.3);
        // 0.3 * 200 + 0.7 * 100 = 130
        let got = peer.ewma_rtt.unwrap().as_millis();
        assert!((128..=132).contains(&got), "expected ~130ms, got {got}ms");
    }

    #[test]
    fn dishonest_strike_demotes_at_limit() {
        let mut peer = PeerState::default();
        peer.record_dishonest_strike(1);
        assert!(peer.demoted);
        assert_eq!(peer.dishonest_strikes, 1);
    }

    #[test]
    fn dishonest_strike_below_limit_does_not_demote() {
        let mut peer = PeerState::default();
        peer.record_dishonest_strike(3);
        assert!(!peer.demoted);
        assert_eq!(peer.dishonest_strikes, 1);
    }

    #[test]
    fn can_accept_respects_demoted_and_cap() {
        let mut peer = PeerState::default();
        assert!(peer.can_accept(4));
        peer.in_flight = 3;
        assert!(peer.can_accept(4));
        peer.in_flight = 4;
        assert!(!peer.can_accept(4));
        let peer = PeerState {
            in_flight: 1,
            demoted: true,
            ..PeerState::default()
        };
        assert!(!peer.can_accept(4));
    }

    #[test]
    fn manifest_validate_rejects_empty() {
        let m = ChunkManifestLite {
            chunks: vec![],
            total_size: 0,
        };
        assert!(m.validate().is_err());
    }

    #[test]
    fn manifest_validate_rejects_size_mismatch() {
        let m = ChunkManifestLite {
            chunks: vec![([0u8; 32], 100), ([1u8; 32], 50)],
            total_size: 200, // should be 150
        };
        assert!(m.validate().is_err());
    }

    #[test]
    fn manifest_validate_accepts_consistent() {
        let m = ChunkManifestLite {
            chunks: vec![([0u8; 32], 100), ([1u8; 32], 50)],
            total_size: 150,
        };
        assert!(m.validate().is_ok());
    }

    #[test]
    fn pick_peer_prefers_untimed() {
        let mut peers = HashMap::new();
        let timed = PeerState {
            ewma_rtt: Some(Duration::from_millis(10)),
            ..PeerState::default()
        };
        peers.insert("fast".to_string(), timed);
        peers.insert("fresh".to_string(), PeerState::default());

        // Untimed peer should be picked first.
        let pick = pick_peer(&peers, 4).unwrap();
        assert_eq!(pick, "fresh");
    }

    #[test]
    fn pick_peer_skips_demoted() {
        let mut peers = HashMap::new();
        let demoted = PeerState {
            demoted: true,
            ..PeerState::default()
        };
        peers.insert("dead".to_string(), demoted);
        peers.insert("alive".to_string(), PeerState::default());

        let pick = pick_peer(&peers, 4).unwrap();
        assert_eq!(pick, "alive");
    }

    #[test]
    fn pick_peer_skips_at_capacity() {
        let mut peers = HashMap::new();
        let busy = PeerState {
            in_flight: 4,
            ..PeerState::default()
        };
        peers.insert("busy".to_string(), busy);
        peers.insert("free".to_string(), PeerState::default());

        let pick = pick_peer(&peers, 4).unwrap();
        assert_eq!(pick, "free");
    }

    #[test]
    fn pick_peer_returns_none_when_all_demoted() {
        let mut peers = HashMap::new();
        let a = PeerState {
            demoted: true,
            ..PeerState::default()
        };
        let b = PeerState {
            demoted: true,
            ..PeerState::default()
        };
        peers.insert("a".into(), a);
        peers.insert("b".into(), b);
        assert!(pick_peer(&peers, 4).is_none());
    }

    #[test]
    fn chunk_source_refusal_maps_to_miss_reason() {
        assert_eq!(
            ChunkSourceRefusal::Withdrawn.to_miss_reason(),
            crate::messages::MissReason::Withdrawn
        );
        assert_eq!(
            ChunkSourceRefusal::Revoked.to_miss_reason(),
            crate::messages::MissReason::Revoked
        );
        assert_eq!(
            ChunkSourceRefusal::PolicyDenied.to_miss_reason(),
            crate::messages::MissReason::PolicyDenied
        );
    }
}
