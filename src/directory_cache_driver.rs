//! §3.3 federation directory anti-entropy driver (CIRISEdge#175,
//! v6.1.0).
//!
//! v6.0.0 shipped the [`crate::directory_cache::DirectoryCache`]
//! scaffold + manual `insert` / `remove` surface. v6.1.0 wires the
//! **active driver**: an event-stream consumer that pulls
//! [`DirectoryEvent`]s off a tokio `mpsc::Receiver` and applies
//! them to the cache.
//!
//! # Architectural shape
//!
//! The driver is a **passive consumer**. Its producer is the
//! substrate's existing `federation_keys` anti-entropy stream
//! (per FSD §3.3) — concretely, the
//! [`crate::messages::FederationKeyDirectoryQueryResponse`]
//! message dispatcher fans events into the driver's `mpsc::Sender`
//! at every directory mutation observed in-flight, and the
//! Reticulum L1 anti-entropy round emits a `DirectoryEvent::Add`
//! per persist-observed `federation_keys` row.
//!
//! The driver itself is transport-agnostic: it owns the channel
//! consumer + cache-apply loop. Test seam: callers can drive
//! events directly without standing up the full anti-entropy
//! stream.
//!
//! # Wire-format invariant preserved
//!
//! The cache becomes ground truth for the §3.3 Welcome-wrap
//! lookup ([`crate::DirectoryCache::welcome_wrap_lookup`]) and the
//! §3.3 announce-suppression path's "is this peer in our cached
//! directory?" gate. **No per-invitation directory query is
//! emitted** — the driver feeds cache state from the existing
//! `federation_keys` anti-entropy round, never from a
//! per-invitation query.

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::directory_cache::{DirectoryCache, DirectoryRecord, FederationKeyId};

/// One directory-mutation event consumed by the driver.
#[derive(Debug, Clone)]
pub enum DirectoryEvent {
    /// A new (or updated) federation-keys row was observed. The
    /// driver inserts / overwrites the corresponding cache record.
    Upsert(DirectoryRecord),
    /// A federation-keys revocation was observed. The driver
    /// removes the matching cache entry.
    Revoke(FederationKeyId),
}

/// Channel sender side. Producers (the anti-entropy stream
/// adapter) hold this and push events as they observe them.
pub type DirectoryEventSender = mpsc::Sender<DirectoryEvent>;

/// Channel receiver side. Owned by the driver.
pub type DirectoryEventReceiver = mpsc::Receiver<DirectoryEvent>;

/// Default channel capacity. Anti-entropy rounds are paced; a
/// 256-event buffer absorbs a full directory round without
/// back-pressuring on the producer.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 256;

/// Construct the matching producer/consumer pair.
#[must_use]
pub fn channel() -> (DirectoryEventSender, DirectoryEventReceiver) {
    mpsc::channel(DEFAULT_CHANNEL_CAPACITY)
}

/// §3.3 directory anti-entropy driver.
///
/// Spawn via [`DirectoryAntiEntropyDriver::start`] on a tokio
/// runtime; the returned [`JoinHandle`] ticks until the
/// `DirectoryEventReceiver` is dropped (closing the producer
/// side).
pub struct DirectoryAntiEntropyDriver {
    cache: DirectoryCache,
    rx: DirectoryEventReceiver,
}

/// Stats observable by callers — counters incremented on every
/// applied event. Useful for the FSD §9 acceptance test that
/// asserts the driver populated the cache.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DriverStats {
    /// Number of `Upsert` events the driver applied.
    pub upsert_count: u64,
    /// Number of `Revoke` events the driver applied (regardless
    /// of whether the cache had the entry to remove).
    pub revoke_count: u64,
}

impl DirectoryAntiEntropyDriver {
    /// Construct a driver that applies events from `rx` onto
    /// `cache`. The cache reference is `clone`-cheap (it's
    /// `Arc`-backed); callers typically share the same cache with
    /// the Welcome-wrap path + the emission scope-suppression
    /// path.
    #[must_use]
    pub fn new(cache: DirectoryCache, rx: DirectoryEventReceiver) -> Self {
        Self { cache, rx }
    }

    /// Apply one event to the cache; returns the resulting
    /// stats-delta (1 in the appropriate counter field).
    pub fn apply(&self, event: DirectoryEvent) -> DriverStats {
        match event {
            DirectoryEvent::Upsert(record) => {
                self.cache.insert(record);
                DriverStats {
                    upsert_count: 1,
                    revoke_count: 0,
                }
            }
            DirectoryEvent::Revoke(id) => {
                let _ = self.cache.remove(&id);
                DriverStats {
                    upsert_count: 0,
                    revoke_count: 1,
                }
            }
        }
    }

    /// Spawn the driver onto a tokio task. The task drains the
    /// `mpsc::Receiver` until it returns `None` (producer side
    /// dropped). Each event is applied immediately; there is no
    /// internal buffering above the channel capacity.
    pub fn start(self) -> JoinHandle<DriverStats> {
        tokio::spawn(async move { self.run().await })
    }

    async fn run(mut self) -> DriverStats {
        let mut totals = DriverStats::default();
        while let Some(event) = self.rx.recv().await {
            let delta = self.apply(event);
            totals.upsert_count = totals.upsert_count.saturating_add(delta.upsert_count);
            totals.revoke_count = totals.revoke_count.saturating_add(delta.revoke_count);
        }
        totals
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory_cache::{IdentityType, Reachability, XWingPublic};

    fn rec(id: &str, pk_byte: u8) -> DirectoryRecord {
        DirectoryRecord {
            federation_id: id.into(),
            ml_dsa_pk: vec![pk_byte; 1952],
            x_wing_pk: Some(XWingPublic {
                x25519_pub: [pk_byte; 32],
                mlkem768_pub: vec![pk_byte; 1184],
            }),
            identity_type: IdentityType::agent(),
            reachability: Reachability::Direct,
        }
    }

    #[tokio::test]
    async fn driver_applies_upsert_then_revoke() {
        let cache = DirectoryCache::new();
        let (tx, rx) = channel();
        let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
        let h = driver.start();

        tx.send(DirectoryEvent::Upsert(rec("alice", 0xAA)))
            .await
            .unwrap();
        tx.send(DirectoryEvent::Upsert(rec("bob", 0xBB)))
            .await
            .unwrap();
        tx.send(DirectoryEvent::Revoke("alice".into()))
            .await
            .unwrap();
        drop(tx); // close producer

        let stats = h.await.unwrap();
        assert_eq!(stats.upsert_count, 2);
        assert_eq!(stats.revoke_count, 1);
        assert!(cache.get("alice").is_none(), "revoked");
        assert!(cache.get("bob").is_some(), "still present");
    }

    #[tokio::test]
    async fn driver_applies_in_order() {
        let cache = DirectoryCache::new();
        let (tx, rx) = channel();
        let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
        let h = driver.start();

        // Two upserts to the same id; the second wins.
        tx.send(DirectoryEvent::Upsert(rec("alice", 0xAA)))
            .await
            .unwrap();
        tx.send(DirectoryEvent::Upsert(rec("alice", 0xBB)))
            .await
            .unwrap();
        drop(tx);

        let _ = h.await.unwrap();
        let got = cache.get("alice").unwrap();
        assert_eq!(got.ml_dsa_pk[0], 0xBB, "second upsert wins");
    }

    #[tokio::test]
    async fn welcome_wrap_lookup_picks_up_driver_events() {
        let cache = DirectoryCache::new();
        let (tx, rx) = channel();
        let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
        let h = driver.start();
        tx.send(DirectoryEvent::Upsert(rec("steward-1", 0xCC)))
            .await
            .unwrap();
        drop(tx);
        let _ = h.await.unwrap();
        // The §3.3 Welcome-wrap path resolves through the cache;
        // ensure the driven entry is visible there.
        let mut lookup = cache.welcome_wrap_lookup();
        let entry = lookup("steward-1").unwrap();
        assert_eq!(entry.pk_id, "steward-1");
        assert_eq!(entry.ml_dsa_pk[0], 0xCC);
    }

    #[test]
    fn apply_increments_correct_counter() {
        let cache = DirectoryCache::new();
        let (_tx, rx) = channel();
        let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
        let s = driver.apply(DirectoryEvent::Upsert(rec("a", 0x01)));
        assert_eq!(s.upsert_count, 1);
        assert_eq!(s.revoke_count, 0);
        let s2 = driver.apply(DirectoryEvent::Revoke("a".into()));
        assert_eq!(s2.upsert_count, 0);
        assert_eq!(s2.revoke_count, 1);
    }
}
