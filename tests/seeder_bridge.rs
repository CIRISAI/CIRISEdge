//! CIRISEdge#362 — the seeder-bridge edge adapter.
//!
//! `RootingDirectory::record_announced_peer` (edge's adapter over persist's
//! v17.8.0 `FederationDirectory::record_announced_peer`, CIRISPersist#469)
//! records a LAN-announced peer as a NON-canonical, untrusted directory
//! BOOKMARK — so it surfaces in the server's `GET /v1/federation/peers`
//! (`canonical=false`, `trust="unknown"`, `last_seen`) WITHOUT being an
//! admission (it never becomes a `federation_keys` row, never satisfies a
//! quorum/authority path). This guards the edge delegation: the announce-admit
//! path calls it beside `persist_transport_binding`.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::verify::RootingDirectory;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::FederationDirectorySqlite;

#[tokio::test]
async fn record_announced_peer_bookmarks_without_admitting() {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory federation directory");
    let pubkey_b64 = B64.encode([0x0au8; 32]);

    // Edge writes the bookmark through the RootingDirectory adapter (exactly as
    // `resolve_announce_cold_start` does on an advisory admit).
    let rooting: Arc<dyn RootingDirectory> = backend.clone();
    rooting
        .record_announced_peer(
            "edge-key-lan-peer",
            &pubkey_b64,
            None, // announce carries no PQC pubkey (enriches later)
            None, // no claimed identity_type
            chrono::Utc::now(),
        )
        .await;

    // It appears as an announced-peer bookmark …
    let bookmarks = FederationDirectory::list_announced_peers(&*backend)
        .await
        .expect("list_announced_peers");
    assert!(
        bookmarks
            .iter()
            .any(|p| p.key_id == "edge-key-lan-peer" && p.pubkey_ed25519_base64 == pubkey_b64),
        "the LAN-announced peer must be recorded as a bookmark (CIRISEdge#362)",
    );

    // … but is NOT admitted into the directory as a federation key of any
    // peer-relevant type (never an authority — the #469 invariant).
    for ty in [
        "node",
        "steward",
        "wise_authority",
        "accord_holder",
        "partner",
        "witness",
    ] {
        let keys = FederationDirectory::list_keys_by_identity_type(&*backend, ty)
            .await
            .unwrap_or_default();
        assert!(
            !keys.iter().any(|k| k.key_id == "edge-key-lan-peer"),
            "a bookmark must never become an admitted `{ty}` federation_keys row",
        );
    }

    // Idempotent + liveness: a second announce refreshes, never duplicates.
    rooting
        .record_announced_peer(
            "edge-key-lan-peer",
            &pubkey_b64,
            None,
            None,
            chrono::Utc::now(),
        )
        .await;
    let after = FederationDirectory::list_announced_peers(&*backend)
        .await
        .expect("list_announced_peers");
    assert_eq!(
        after
            .iter()
            .filter(|p| p.key_id == "edge-key-lan-peer")
            .count(),
        1,
        "a repeat announce must refresh the bookmark, not duplicate it",
    );
}
