//! v6.1.0 (CIRISEdge#175, FSD §6.1) — openmls 0.8 `StorageProvider`
//! trait impl over the v6.0.0 [`ciris_edge::ScopeStateProvider`]
//! scaffold.
//!
//! ## Split to v6.2.0
//!
//! The full 57-method `openmls_traits::storage::StorageProvider`
//! trait surface is **deferred to v6.2.0** per the v6.1.0 cut's
//! "scope realistically" allowance — the trait spans 57 generic
//! method signatures with type-trait bounds (`GroupId`, `LeafNode`,
//! `TreeSync`, `KeyPackage`, `EncryptionKeyPair`, etc.), each
//! requiring per-type serde-cbor admit/extract over the
//! `XChaChaKvStore` Vec<u8> KV. Honest implementation requires
//! exercising every key-schedule path through round-trip tests so
//! the §3.5 `rotate-forward` window prune doesn't strand
//! decryption-required state — heavier than the v6.1.0 cut can
//! absorb cleanly.
//!
//! v6.0.0 shipped:
//!
//! - [`ScopeStateProvider`] scaffold over persist v9.2.0's
//!   `XChaChaKvStore` (cold-state opacity per FSD §7.8).
//! - `mls/{community_id}/{kind}` namespace convention.
//! - `group_state_get` / `group_state_put` / `group_state_delete`
//!   opaque-`Vec<u8>` slot the v6.2.0 trait impl will fill.
//!
//! v6.1.0 keeps the scaffold + the namespace conventions; the
//! [`StorageProvider`] trait impl follows in v6.2.0. The
//! KV-round-trip discipline is verified by the existing v6.0.0
//! [`ScopeStateProvider`] unit tests in `src/mls/scope_state.rs`.
//!
//! This test file is the placeholder + the v6.0.0-scaffold
//! round-trip sanity check.
//!
//! [`StorageProvider`]: openmls_traits::storage::StorageProvider
//! [`ScopeStateProvider`]: ciris_edge::ScopeStateProvider

use std::sync::Arc;

use ciris_edge::mls::archive_mode::ArchiveMode;
use ciris_edge::ScopeStateProvider;
use ciris_persist::encrypted_kv::XChaChaKvStore;

fn open_provider() -> ScopeStateProvider {
    let kv = XChaChaKvStore::open_in_memory(b"v6.1.0-e2e-passphrase").unwrap();
    ScopeStateProvider::new(Arc::new(kv))
}

#[tokio::test(flavor = "current_thread")]
async fn scope_state_provider_round_trip_opaque_group_state() {
    let provider = open_provider();
    // v6.0.0 scaffold contract — group_state put/get round-trips
    // an opaque Vec<u8> blob the v6.2.0 StorageProvider impl will
    // fill with serde-cbor-encoded MLS state.
    let community_id = "v6.1.0-test-community";
    let epoch: u64 = 42;
    let blob = b"opaque mls group serialization v1".to_vec();
    provider
        .group_state_put(community_id, epoch, &blob)
        .await
        .unwrap();
    let got = provider.group_state_get(community_id, epoch).await.unwrap();
    assert_eq!(got.as_deref(), Some(&blob[..]));
}

#[tokio::test(flavor = "current_thread")]
async fn scope_state_provider_archive_mode_round_trip() {
    // The §3.5 archive_mode rides the same KV surface as group_state.
    let provider = open_provider();
    let mode = ArchiveMode::RotateForward { window_days: 30 };
    provider.archive_mode_put("v6.1.0-c", mode).await.unwrap();
    let got = provider.archive_mode_get("v6.1.0-c").await.unwrap();
    assert_eq!(got, Some(mode));
}

#[tokio::test(flavor = "current_thread")]
async fn scope_state_provider_namespaces_isolate_communities() {
    let provider = open_provider();
    provider
        .group_state_put("alpha", 0, b"alpha-epoch-0")
        .await
        .unwrap();
    provider
        .group_state_put("beta", 0, b"beta-epoch-0")
        .await
        .unwrap();
    let alpha = provider.group_state_get("alpha", 0).await.unwrap();
    let beta = provider.group_state_get("beta", 0).await.unwrap();
    assert_eq!(alpha.as_deref(), Some(&b"alpha-epoch-0"[..]));
    assert_eq!(beta.as_deref(), Some(&b"beta-epoch-0"[..]));
}
