//! v6.1.0 (CIRISEdge#175, FSD §3.3) — federation_keys anti-entropy
//! driver end-to-end test.
//!
//! Asserts the v6.0.0-promised "active driver":
//!
//! - `Upsert` events populate the cache; `welcome_wrap_lookup`
//!   resolves the driven entries.
//! - `Revoke` events remove entries.
//! - The driver's `DriverStats` snapshot matches the observed event
//!   sequence (FSD §9 acceptance check).

use ciris_edge::directory_cache::{IdentityType, Reachability, XWingPublic};
use ciris_edge::{
    directory_event_channel, DirectoryAntiEntropyDriver, DirectoryCache, DirectoryEvent,
    DirectoryRecord,
};

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

#[tokio::test(flavor = "current_thread")]
async fn driver_populates_cache_from_upsert_stream() {
    let cache = DirectoryCache::new();
    let (tx, rx) = directory_event_channel();
    let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
    let h = driver.start();

    for (id, pk) in [("alice", 0xAAu8), ("bob", 0xBBu8), ("carol", 0xCCu8)] {
        tx.send(DirectoryEvent::Upsert(rec(id, pk))).await.unwrap();
    }
    drop(tx);

    let stats = h.await.unwrap();
    assert_eq!(stats.upsert_count, 3);
    assert_eq!(stats.revoke_count, 0);
    assert_eq!(cache.len(), 3);
    for (id, pk) in [("alice", 0xAAu8), ("bob", 0xBBu8), ("carol", 0xCCu8)] {
        let got = cache.get(id).unwrap();
        assert_eq!(got.ml_dsa_pk[0], pk);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn driver_revokes_remove_cache_entries() {
    let cache = DirectoryCache::new();
    let (tx, rx) = directory_event_channel();
    let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
    let h = driver.start();

    tx.send(DirectoryEvent::Upsert(rec("alice", 0xAAu8)))
        .await
        .unwrap();
    tx.send(DirectoryEvent::Upsert(rec("bob", 0xBBu8)))
        .await
        .unwrap();
    tx.send(DirectoryEvent::Revoke("alice".into()))
        .await
        .unwrap();
    drop(tx);

    let stats = h.await.unwrap();
    assert_eq!(stats.upsert_count, 2);
    assert_eq!(stats.revoke_count, 1);
    assert!(cache.get("alice").is_none());
    assert!(cache.get("bob").is_some());
}

#[tokio::test(flavor = "current_thread")]
async fn welcome_wrap_lookup_resolves_through_driven_cache() {
    // The §3.3 Welcome-wrap path resolves invitee X-Wing + ML-DSA-65
    // keys through the cache. After the driver populates it, the
    // lookup closure picks up the entries.
    let cache = DirectoryCache::new();
    let (tx, rx) = directory_event_channel();
    let driver = DirectoryAntiEntropyDriver::new(cache.clone(), rx);
    let h = driver.start();

    tx.send(DirectoryEvent::Upsert(rec("steward-1", 0xDDu8)))
        .await
        .unwrap();
    drop(tx);
    let _ = h.await.unwrap();

    let mut lookup = cache.welcome_wrap_lookup();
    let entry = lookup("steward-1").expect("driven entry");
    assert_eq!(entry.pk_id, "steward-1");
    assert_eq!(entry.ml_dsa_pk[0], 0xDD);
    assert!(entry.x_wing_pk.is_some());
}
