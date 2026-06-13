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
//! - **Persist** — owns the trust seam. `BlobStorage::put_blob_chunk`
//!   atomically verifies `sha256(bytes) == chunk_sha256` and stores;
//!   returns `ChunkMismatch` on hash failure. The scheduler treats
//!   `ChunkMismatch` as evidence the responding peer is dishonest and
//!   excludes them from the candidate set for the rest of the
//!   session.
//!
//! No new persist surface is needed; the contracts (`list_holders`,
//! `ChunkManifest` + walker, `put_blob_chunk`) all already ship in
//! v5.x and are byte-stable through v5.8.0.
//!
//! [`BlobChunkFetch`]: crate::messages::BlobChunkFetch
//!
//! # Scope: what this module owns vs. defers
//!
//! Owns (v2.5.0 initial cut, current state of this scaffold):
//! - [`SwarmConfig`] — operator knobs (in-flight cap per peer,
//!   endgame trigger, EWMA alpha, dishonest-strike threshold).
//! - [`PeerState`] — per-peer EWMA + in-flight count + dishonest flag.
//! - [`SwarmError`] — typed error surface for the fetch driver.
//!
//! Deferred to a follow-up cut on this branch (not yet implemented):
//! - The `SwarmScheduler::fetch_blob(sha)` driver loop itself.
//! - The server-side dispatch handler for incoming `BlobChunkFetch`
//!   envelopes (lives in `dispatch_inbound` in `src/edge.rs`).
//! - The PyEdge wrapper exposing `edge.fetch_blob_swarm(sha)`.
//! - Endgame-mode duplicate-request logic.
//!
//! The scaffold lands first to lock down the type vocabulary; the
//! driver loop builds against it.

use std::time::Duration;

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
    /// Persist's `put_blob_chunk` returned an error that wasn't
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
        peer.in_flight = 1;
        peer.demoted = true;
        assert!(!peer.can_accept(4));
    }
}
