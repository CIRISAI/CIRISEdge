//! §24 NAT-traversal — store-and-forward primitive for asleep mobile edges
//! (CIRISEdge#169). Pairs with Reticulum Transport-node mode (#168).
//!
//! Public fabric nodes accept inbound messages tagged for currently-
//! unreachable destinations, queue them under a destination-keyed
//! store, and surface them on the client's wake-up fetch. Hybrid-PQC
//! verified at admission (persist v9.0.0 G1+G2 / federation-tier).
//!
//! ## Scope (CIRISEdge#169 — Scope B, CEG-native)
//!
//! Leviculum exposes no LXMF propagation surface (only LNS name
//! service), so #169 takes the CEG-native store-and-forward path
//! rather than the full LXMF wire spec. The queued bytes are the
//! existing byte-exact signed CEG envelope — this primitive never
//! re-signs or rewraps. Admission-time hybrid-PQC verification is the
//! caller's responsibility (the fabric node runs
//! [`crate::verify`] over the envelope before `queue`); this module
//! is the transport-tier queue, not the policy tier.
//!
//! ## Eviction policy
//!
//! Three independent caps, each enforced at `queue` time except TTL
//! which is also swept on `drain`:
//!
//! * `max_queued_per_destination` — a full per-destination queue
//!   evicts its oldest entry to admit the new one (newest-wins).
//! * `max_total_bytes` — a single envelope larger than the whole
//!   budget is rejected outright ([`SafError::EnvelopeTooLarge`]); an
//!   envelope that fits the budget but would overflow it evicts
//!   oldest entries across all destinations until it fits.
//! * `ttl_seconds` — entries older than the TTL are dropped lazily on
//!   the next `drain` for their destination, and proactively whenever
//!   `queue` needs to reclaim space.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Errors raised by the store-and-forward queue.
#[derive(thiserror::Error, Debug)]
pub enum SafError {
    /// The envelope is larger than the entire `max_total_bytes`
    /// budget — it can never fit, so it is rejected rather than
    /// evicting the whole queue for a message that still won't land.
    #[error("envelope too large for store-and-forward: {actual} bytes > total budget {budget}")]
    EnvelopeTooLarge { actual: u64, budget: u64 },

    /// Internal lock was poisoned by a panic in another thread.
    #[error("store-and-forward lock poisoned")]
    LockPoisoned,
}

/// A single queued, byte-exact signed CEG envelope awaiting an
/// offline destination's wake-up fetch.
#[derive(Clone, Debug)]
pub struct PendingDelivery {
    /// Destination this envelope is addressed to (federation key_id).
    pub destination_key_id: String,
    /// The byte-exact signed CEG envelope — carried verbatim, never
    /// re-signed by this layer.
    pub envelope_bytes: Vec<u8>,
    /// Admission timestamp (unix epoch milliseconds), used for TTL.
    pub queued_at_unix_ms: u64,
}

/// Per-node caps governing the queue. Defaults match the #169
/// deliverable: 256 entries / destination, 64 MiB total, 7-day TTL.
#[derive(Clone, Copy, Debug)]
pub struct StoreAndForwardConfig {
    /// Max entries retained per destination; oldest evicted on
    /// overflow.
    pub max_queued_per_destination: u32,
    /// Max total bytes (sum of `envelope_bytes.len()`) across all
    /// destinations.
    pub max_total_bytes: u64,
    /// Entries older than this are dropped on the next sweep.
    pub ttl_seconds: u64,
}

impl Default for StoreAndForwardConfig {
    fn default() -> Self {
        Self {
            max_queued_per_destination: 256,
            max_total_bytes: 64 * 1024 * 1024,
            ttl_seconds: 7 * 24 * 3600,
        }
    }
}

/// Store-and-forward queue surface (CIRISEdge#169).
pub trait StoreAndForward: Send + Sync {
    /// Queue an envelope for a currently-unreachable destination.
    fn queue(&self, dest: &str, envelope_bytes: &[u8]) -> Result<(), SafError>;

    /// Drain queued messages for the calling destination (called on
    /// the mobile's wake-up fetch). Returns at most `limit` entries
    /// oldest-first; consumed entries are evicted.
    fn drain(&self, dest: &str, limit: u32) -> Result<Vec<PendingDelivery>, SafError>;

    /// Operator surface — visibility into the queue.
    fn pending_count(&self, dest: &str) -> u32;
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => u64::try_from(d.as_millis()).unwrap_or(u64::MAX),
        Err(_) => 0,
    }
}

/// In-memory reference implementation. Production fabric nodes swap in
/// a persist-backed implementation; this is the conformance + dev
/// surface.
pub struct MemoryStoreAndForward {
    config: StoreAndForwardConfig,
    state: Mutex<State>,
}

struct State {
    queues: BTreeMap<String, VecDeque<PendingDelivery>>,
    total_bytes: u64,
}

impl MemoryStoreAndForward {
    #[must_use]
    pub fn new(config: StoreAndForwardConfig) -> Self {
        Self {
            config,
            state: Mutex::new(State {
                queues: BTreeMap::new(),
                total_bytes: 0,
            }),
        }
    }

    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(StoreAndForwardConfig::default())
    }

    /// Drop TTL-expired entries across every destination. Returns the
    /// number of bytes reclaimed. Caller holds the lock.
    fn sweep_expired(state: &mut State, ttl_seconds: u64, now_ms: u64) {
        if ttl_seconds == 0 {
            return;
        }
        let cutoff_ms = now_ms.saturating_sub(ttl_seconds.saturating_mul(1000));
        let mut reclaimed = 0u64;
        state.queues.retain(|_dest, q| {
            while let Some(front) = q.front() {
                if front.queued_at_unix_ms < cutoff_ms {
                    let evicted = q.pop_front().expect("front exists");
                    reclaimed += evicted.envelope_bytes.len() as u64;
                } else {
                    break;
                }
            }
            !q.is_empty()
        });
        state.total_bytes = state.total_bytes.saturating_sub(reclaimed);
    }
}

impl StoreAndForward for MemoryStoreAndForward {
    fn queue(&self, dest: &str, envelope_bytes: &[u8]) -> Result<(), SafError> {
        let incoming = envelope_bytes.len() as u64;
        if incoming > self.config.max_total_bytes {
            return Err(SafError::EnvelopeTooLarge {
                actual: incoming,
                budget: self.config.max_total_bytes,
            });
        }

        let mut state = self.state.lock().map_err(|_| SafError::LockPoisoned)?;
        let now_ms = now_unix_ms();

        // Reclaim TTL-expired space before deciding on byte-budget
        // evictions, so a stale backlog doesn't force out fresh mail.
        Self::sweep_expired(&mut state, self.config.ttl_seconds, now_ms);

        // Byte-budget eviction: drop oldest entries across all
        // destinations until the incoming envelope fits. The entry
        // can fit (checked above), so this terminates.
        while state.total_bytes + incoming > self.config.max_total_bytes {
            let oldest_dest = state
                .queues
                .iter()
                .filter_map(|(d, q)| q.front().map(|e| (e.queued_at_unix_ms, d.clone())))
                .min()
                .map(|(_, d)| d);
            let Some(d) = oldest_dest else {
                break;
            };
            let mut reclaimed = 0u64;
            let mut now_empty = false;
            if let Some(q) = state.queues.get_mut(&d) {
                if let Some(evicted) = q.pop_front() {
                    reclaimed = evicted.envelope_bytes.len() as u64;
                }
                now_empty = q.is_empty();
            }
            state.total_bytes = state.total_bytes.saturating_sub(reclaimed);
            if now_empty {
                state.queues.remove(&d);
            }
        }

        let entry = PendingDelivery {
            destination_key_id: dest.to_string(),
            envelope_bytes: envelope_bytes.to_vec(),
            queued_at_unix_ms: now_ms,
        };

        let mut reclaimed = 0u64;
        {
            let q = state.queues.entry(dest.to_string()).or_default();
            // Per-destination cap: newest-wins, evict oldest on overflow.
            if self.config.max_queued_per_destination > 0
                && q.len() >= self.config.max_queued_per_destination as usize
            {
                if let Some(evicted) = q.pop_front() {
                    reclaimed = evicted.envelope_bytes.len() as u64;
                }
            }
            q.push_back(entry);
        }
        state.total_bytes = state.total_bytes.saturating_sub(reclaimed) + incoming;
        Ok(())
    }

    fn drain(&self, dest: &str, limit: u32) -> Result<Vec<PendingDelivery>, SafError> {
        let mut state = self.state.lock().map_err(|_| SafError::LockPoisoned)?;
        let now_ms = now_unix_ms();
        Self::sweep_expired(&mut state, self.config.ttl_seconds, now_ms);

        let mut out = Vec::new();
        let mut reclaimed = 0u64;
        let mut now_empty = false;
        if let Some(q) = state.queues.get_mut(dest) {
            for _ in 0..limit {
                let Some(entry) = q.pop_front() else { break };
                reclaimed += entry.envelope_bytes.len() as u64;
                out.push(entry);
            }
            now_empty = q.is_empty();
        }
        state.total_bytes = state.total_bytes.saturating_sub(reclaimed);
        if now_empty {
            state.queues.remove(dest);
        }
        Ok(out)
    }

    fn pending_count(&self, dest: &str) -> u32 {
        let Ok(state) = self.state.lock() else {
            return 0;
        };
        state
            .queues
            .get(dest)
            .map_or(0, |q| u32::try_from(q.len()).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(n: usize, byte: u8) -> Vec<u8> {
        vec![byte; n]
    }

    #[test]
    fn queue_and_drain_round_trips() {
        let saf = MemoryStoreAndForward::with_defaults();
        saf.queue("dest-a", &env(4, 1)).unwrap();
        saf.queue("dest-a", &env(4, 2)).unwrap();
        saf.queue("dest-a", &env(4, 3)).unwrap();
        assert_eq!(saf.pending_count("dest-a"), 3);

        let drained = saf.drain("dest-a", 10).unwrap();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].envelope_bytes, env(4, 1));
        assert_eq!(drained[1].envelope_bytes, env(4, 2));
        assert_eq!(drained[2].envelope_bytes, env(4, 3));
        assert!(drained.iter().all(|d| d.destination_key_id == "dest-a"));
        assert_eq!(saf.pending_count("dest-a"), 0);
    }

    #[test]
    fn drain_respects_limit() {
        let saf = MemoryStoreAndForward::with_defaults();
        for i in 0..5u8 {
            saf.queue("d", &env(2, i)).unwrap();
        }
        let first = saf.drain("d", 2).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].envelope_bytes, env(2, 0));
        assert_eq!(first[1].envelope_bytes, env(2, 1));

        let second = saf.drain("d", 2).unwrap();
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].envelope_bytes, env(2, 2));
        assert_eq!(second[1].envelope_bytes, env(2, 3));

        assert_eq!(saf.pending_count("d"), 1);
    }

    #[test]
    fn max_per_destination_caps_queue() {
        let saf = MemoryStoreAndForward::new(StoreAndForwardConfig {
            max_queued_per_destination: 3,
            ..StoreAndForwardConfig::default()
        });
        for i in 0..5u8 {
            saf.queue("d", &env(1, i)).unwrap();
        }
        assert_eq!(saf.pending_count("d"), 3);
        let drained = saf.drain("d", 10).unwrap();
        // Oldest two (0,1) evicted; 2,3,4 retained oldest-first.
        assert_eq!(
            drained
                .iter()
                .map(|d| d.envelope_bytes[0])
                .collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn ttl_evicts_stale_entries() {
        let saf = MemoryStoreAndForward::new(StoreAndForwardConfig {
            ttl_seconds: 60,
            ..StoreAndForwardConfig::default()
        });
        // Inject a stale entry directly with an old timestamp, plus a
        // fresh one queued normally.
        {
            let mut state = saf.state.lock().unwrap();
            let old = PendingDelivery {
                destination_key_id: "d".into(),
                envelope_bytes: env(8, 9),
                queued_at_unix_ms: now_unix_ms().saturating_sub(120 * 1000),
            };
            state.total_bytes += old.envelope_bytes.len() as u64;
            state.queues.entry("d".into()).or_default().push_back(old);
        }
        saf.queue("d", &env(4, 1)).unwrap();

        let drained = saf.drain("d", 10).unwrap();
        // Stale (8-byte) entry swept; only the fresh 4-byte one returns.
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].envelope_bytes, env(4, 1));
    }

    #[test]
    fn total_bytes_cap_respected() {
        let saf = MemoryStoreAndForward::new(StoreAndForwardConfig {
            max_total_bytes: 16,
            ..StoreAndForwardConfig::default()
        });
        // An envelope larger than the entire budget is rejected.
        let err = saf.queue("d", &env(32, 0)).unwrap_err();
        assert!(matches!(
            err,
            SafError::EnvelopeTooLarge {
                actual: 32,
                budget: 16
            }
        ));

        // Fill to budget, then a fitting envelope evicts oldest to fit.
        saf.queue("d", &env(10, 1)).unwrap();
        saf.queue("d", &env(6, 2)).unwrap();
        assert_eq!(saf.pending_count("d"), 2);
        saf.queue("d", &env(10, 3)).unwrap(); // forces eviction of the 10-byte head
        let drained = saf.drain("d", 10).unwrap();
        let total: usize = drained.iter().map(|d| d.envelope_bytes.len()).sum();
        assert!(total <= 16, "retained bytes {total} exceed budget");
        // The first 10-byte entry was evicted; 6+10 = 16 retained.
        assert_eq!(
            drained
                .iter()
                .map(|d| d.envelope_bytes.len())
                .collect::<Vec<_>>(),
            vec![6, 10]
        );
    }
}
