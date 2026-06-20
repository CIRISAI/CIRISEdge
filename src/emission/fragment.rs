//! §3.1 fragmentation / reassembly (CIRISEdge#175, v6.1.0).
//!
//! Larger payloads chunk into [`MAX_PAYLOAD_BYTES`] slices and ride
//! the emission scheduler as a fragment set. Receivers reassemble
//! by `(fragment_id, fragment_index)` with:
//!
//! - **Dedup-on-receive** — a duplicate `(record_id, fragment_id,
//!   fragment_index)` is dropped silently.
//! - **Drop-on-window-expiry** — fragments older than
//!   [`REASSEMBLY_WINDOW_MS`] are discarded; the reassembler walks
//!   its windows on every `accept` call and prunes.
//!
//! The fragment set is identified by `(record_id, fragment_id)`.
//! `fragment_id` is caller-chosen (typically a per-publication
//! monotonic counter; the publication's `record_id` plus
//! `fragment_id` makes the pair unique within the emitter's
//! reassembly window).
//!
//! # Fragment count limits
//!
//! `fragment_count` is `u32` on the wire. The emission scheduler
//! does not impose a maximum — bounded only by the §2.4 RaptorQ
//! symbol fan-out limit downstream.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::envelope::{EmissionHeader, EmissionScopeTag, MAX_PAYLOAD_BYTES};

/// Per-publication reassembly window (10 seconds at v6.1.0). Older
/// fragments are discarded. Operators tune this per the §3.1
/// inter-emission interval and the expected publication chunk
/// size.
pub const REASSEMBLY_WINDOW_MS: u64 = 10_000;

/// One fragment produced by [`fragment_payload`]. Each fragment is
/// destined for one [`super::envelope::seal_envelope`] call; the
/// scheduler pops one fragment per Poisson timer fire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Header to be sealed with the fragment.
    pub header: EmissionHeader,
    /// Bytes for this fragment (≤ [`MAX_PAYLOAD_BYTES`]).
    pub payload: Vec<u8>,
}

/// All fragments for one publication's payload — a contiguous
/// `Vec` so the scheduler can drain by indexing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentSet {
    /// Per-publication record_id (the FSD §2.4 HMAC-SHA3 output).
    pub record_id: [u8; 32],
    /// Caller-chosen identifier for THIS publication's fragment
    /// set (recent within the emitter's reassembly window).
    pub fragment_id: u32,
    /// Each fragment in order.
    pub fragments: Vec<Fragment>,
}

/// Errors from fragmentation / reassembly.
#[derive(Debug, thiserror::Error)]
pub enum FragmentError {
    /// Payload empty — fragment_count would be zero.
    #[error("empty payload")]
    EmptyPayload,
    /// Fragment count > `u32::MAX` (effectively unreachable).
    #[error("fragment count overflow: {0}")]
    CountOverflow(usize),
    /// Reassembled fragment count did not match the
    /// `fragment_count` field claimed in the header.
    #[error("fragment count mismatch: header claims {claimed}, got {got}")]
    CountMismatch {
        /// Header's claimed `fragment_count`.
        claimed: u32,
        /// Actual number of unique fragments observed.
        got: u32,
    },
}

/// Chunk `payload` into [`MAX_PAYLOAD_BYTES`]-sized fragments.
/// Each fragment carries a header with the matching
/// `(record_id, fragment_id, fragment_index, fragment_count)`.
///
/// # Errors
///
/// - [`FragmentError::EmptyPayload`] — payload is empty.
/// - [`FragmentError::CountOverflow`] — payload would chunk to
///   more than `u32::MAX` fragments (the wire-format limit).
pub fn fragment_payload(
    scope: EmissionScopeTag,
    record_id: [u8; 32],
    fragment_id: u32,
    emitted_at_unix_ms: u64,
    payload: &[u8],
) -> Result<FragmentSet, FragmentError> {
    if payload.is_empty() {
        return Err(FragmentError::EmptyPayload);
    }

    // Ceiling division: fragment_count = ceil(payload.len() / MAX_PAYLOAD_BYTES).
    let count_usize = payload.len().div_ceil(MAX_PAYLOAD_BYTES);
    let count =
        u32::try_from(count_usize).map_err(|_| FragmentError::CountOverflow(count_usize))?;

    let mut fragments = Vec::with_capacity(count_usize);
    for (i, chunk) in payload.chunks(MAX_PAYLOAD_BYTES).enumerate() {
        // Safe: `i < count_usize ≤ u32::MAX` by the try_from guard above.
        let fragment_index = u32::try_from(i).expect("i < count_usize ≤ u32::MAX");
        let header = EmissionHeader::real(
            scope,
            record_id,
            fragment_id,
            fragment_index,
            count,
            emitted_at_unix_ms,
        );
        fragments.push(Fragment {
            header,
            payload: chunk.to_vec(),
        });
    }

    Ok(FragmentSet {
        record_id,
        fragment_id,
        fragments,
    })
}

/// Reassembly state per `(record_id, fragment_id)` pair.
#[derive(Debug, Clone)]
struct InProgress {
    /// `fragment_count` claimed by the first fragment we observed.
    fragment_count: u32,
    /// Sparse buffer; `chunks[i]` is `Some` once we've seen
    /// fragment `i`. Sized at `fragment_count` on first observe.
    chunks: Vec<Option<Vec<u8>>>,
    /// Window first-seen instant. The reassembler drops the
    /// entry when `now - first_seen >= REASSEMBLY_WINDOW_MS`.
    first_seen: Instant,
}

/// Outcome of [`Reassembler::accept`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReassemblyOutcome {
    /// Cover fragment — no payload to reassemble.
    Cover,
    /// Duplicate (already observed). Silently dropped.
    Duplicate,
    /// More fragments expected.
    Partial {
        /// How many we've seen now.
        seen: u32,
        /// How many the header claims total.
        expected: u32,
    },
    /// Fully reassembled. Returns the joined payload.
    Complete {
        /// The publication's reassembled bytes.
        payload: Vec<u8>,
    },
}

/// In-memory reassembly buffer with dedup + window-expiry pruning.
#[derive(Debug, Default)]
pub struct Reassembler {
    in_progress: HashMap<(Vec<u8>, u32), InProgress>,
}

impl Reassembler {
    /// Construct an empty reassembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept one fragment (header + payload chunk). The
    /// `now` argument is the test seam — production callers
    /// pass [`Instant::now`].
    pub fn accept(
        &mut self,
        header: &EmissionHeader,
        payload: &[u8],
        now: Instant,
    ) -> Result<ReassemblyOutcome, FragmentError> {
        // Cover envelopes have no payload to reassemble.
        if header.is_cover() {
            return Ok(ReassemblyOutcome::Cover);
        }

        // Prune expired windows on every accept call. O(n_windows) — fine for
        // realistic in-flight set sizes.
        self.prune_expired(now);

        let key = (header.record_id.to_vec(), header.fragment_id);

        // Dedup or initialize.
        let entry = self
            .in_progress
            .entry(key.clone())
            .or_insert_with(|| InProgress {
                fragment_count: header.fragment_count,
                chunks: vec![None; header.fragment_count as usize],
                first_seen: now,
            });

        // Header consistency check: the fragment_count must match
        // the first-seen fragment.
        if entry.fragment_count != header.fragment_count {
            return Err(FragmentError::CountMismatch {
                claimed: entry.fragment_count,
                got: header.fragment_count,
            });
        }

        let idx = header.fragment_index as usize;
        if idx >= entry.chunks.len() {
            // Bogus fragment_index over the claimed fragment_count;
            // ignore as duplicate (no extra wire-state vulnerability
            // beyond what dedup already provides).
            return Ok(ReassemblyOutcome::Duplicate);
        }

        if entry.chunks[idx].is_some() {
            return Ok(ReassemblyOutcome::Duplicate);
        }
        entry.chunks[idx] = Some(payload.to_vec());

        // `entry.chunks.len() == fragment_count <= u32::MAX` (set
        // at first-insert from a `u32` header field), so the count
        // is bounded by u32::MAX.
        let seen = u32::try_from(entry.chunks.iter().filter(|c| c.is_some()).count())
            .expect("filtered count ≤ chunks.len() ≤ u32::MAX");
        let expected = entry.fragment_count;

        if seen < expected {
            return Ok(ReassemblyOutcome::Partial { seen, expected });
        }

        // Fully reassembled. Drain the buffer; join in index order.
        let in_progress = self.in_progress.remove(&key).expect("key just inserted");
        let mut joined = Vec::new();
        for chunk in in_progress.chunks {
            // Reassembled-complete path implies every slot is Some.
            joined.extend_from_slice(&chunk.expect("complete-path implies Some"));
        }
        Ok(ReassemblyOutcome::Complete { payload: joined })
    }

    /// Prune fragment-sets older than [`REASSEMBLY_WINDOW_MS`].
    pub fn prune_expired(&mut self, now: Instant) {
        let window = Duration::from_millis(REASSEMBLY_WINDOW_MS);
        self.in_progress
            .retain(|_, v| now.duration_since(v.first_seen) < window);
    }

    /// Number of in-progress reassemblies.
    #[must_use]
    pub fn in_progress_count(&self) -> usize {
        self.in_progress.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_payload_one_fragment() {
        let payload = b"hello world";
        let set = fragment_payload(EmissionScopeTag::Community, [1; 32], 7, 0, payload).unwrap();
        assert_eq!(set.fragments.len(), 1);
        assert_eq!(set.fragments[0].header.fragment_count, 1);
        assert_eq!(set.fragments[0].header.fragment_index, 0);
        assert_eq!(set.fragments[0].payload, payload);
    }

    #[test]
    fn large_payload_chunks() {
        let payload = vec![0xAA; MAX_PAYLOAD_BYTES * 3 + 17];
        let set = fragment_payload(EmissionScopeTag::Federation, [2; 32], 0, 0, &payload).unwrap();
        assert_eq!(set.fragments.len(), 4);
        assert_eq!(set.fragments[3].payload.len(), 17);
        for f in &set.fragments {
            assert_eq!(f.header.fragment_count, 4);
        }
    }

    #[test]
    fn empty_payload_rejected() {
        let err = fragment_payload(EmissionScopeTag::SelfScope, [0; 32], 0, 0, &[]).unwrap_err();
        assert!(matches!(err, FragmentError::EmptyPayload));
    }

    #[test]
    fn reassembly_round_trip() {
        let payload = vec![0xCD; MAX_PAYLOAD_BYTES * 2 + 100];
        let set = fragment_payload(EmissionScopeTag::Community, [3; 32], 9, 0, &payload).unwrap();

        let mut r = Reassembler::new();
        let now = Instant::now();
        // Process all but the last as Partial.
        for f in &set.fragments[..2] {
            let out = r.accept(&f.header, &f.payload, now).unwrap();
            assert!(matches!(out, ReassemblyOutcome::Partial { .. }));
        }
        let last = set.fragments.last().unwrap();
        let out = r.accept(&last.header, &last.payload, now).unwrap();
        match out {
            ReassemblyOutcome::Complete { payload: got } => assert_eq!(got, payload),
            other => panic!("expected Complete, got {other:?}"),
        }
        assert_eq!(r.in_progress_count(), 0);
    }

    #[test]
    fn dedup_drops_duplicates() {
        let payload = vec![0xEEu8; MAX_PAYLOAD_BYTES * 2];
        let set = fragment_payload(EmissionScopeTag::Federation, [4; 32], 0, 0, &payload).unwrap();
        let mut r = Reassembler::new();
        let now = Instant::now();
        let _ = r.accept(&set.fragments[0].header, &set.fragments[0].payload, now);
        let out = r
            .accept(&set.fragments[0].header, &set.fragments[0].payload, now)
            .unwrap();
        assert_eq!(out, ReassemblyOutcome::Duplicate);
    }

    #[test]
    fn cover_envelope_is_no_op_for_reassembly() {
        let header = EmissionHeader::cover(EmissionScopeTag::Family, 0);
        let mut r = Reassembler::new();
        let out = r.accept(&header, &[], Instant::now()).unwrap();
        assert_eq!(out, ReassemblyOutcome::Cover);
        assert_eq!(r.in_progress_count(), 0);
    }

    #[test]
    fn window_expiry_drops_partial() {
        let payload = vec![0u8; MAX_PAYLOAD_BYTES * 4];
        let set = fragment_payload(EmissionScopeTag::Community, [5; 32], 0, 0, &payload).unwrap();
        let mut r = Reassembler::new();
        let t0 = Instant::now();
        let _ = r.accept(&set.fragments[0].header, &set.fragments[0].payload, t0);
        assert_eq!(r.in_progress_count(), 1);
        // Advance the clock past the window.
        let later = t0 + Duration::from_millis(REASSEMBLY_WINDOW_MS + 1);
        r.prune_expired(later);
        assert_eq!(r.in_progress_count(), 0);
    }
}
