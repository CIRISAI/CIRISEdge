//! CIRISEdge#587 — the persist-backed [`BlobChunkSource`] answers a peer
//! through persist's **gated** serve door.
//!
//! What this pins is the seam, end to end against a real persist
//! substrate: that a node which opened its own SQLite backend can build
//! an `Engine` view over it (`Engine::from_shared` — the claim that makes
//! blob-serving available to SOVEREIGN nodes and not just cohabitation
//! ones), that `serve_blob_to_peer` is reachable across that view, and
//! that its `NotHeld` arm arrives at the responder as a MISS rather than
//! a refusal — the one arm of the mapping that is not a refusal, and the
//! one a hand-rolled adapter is most likely to get wrong.
//!
//! The remaining arms are pinned as pure units in
//! `blob_swarm::tests::every_persist_serve_refusal_is_mapped`, which can
//! construct each `BlobError` directly; provoking a real quarantine or a
//! real disk-pressure tier from a test substrate would exercise persist's
//! gates rather than edge's translation of them.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use ciris_edge::blob_swarm::{BlobChunkSource, PersistBlobChunkSource};
use ciris_persist::prelude::FederationDirectorySqlite;
use ciris_persist::store::backend::Backend;

async fn sovereign_source() -> PersistBlobChunkSource {
    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist substrate");
    backend.run_migrations().await.expect("migrate");

    // The sovereign shape: the node has a backend and a signer, and
    // never a pre-built Engine. `from_shared` runs no migrations and
    // shares this pool — it is a VIEW over what we already opened, not a
    // second substrate.
    let signer: Arc<dyn ciris_keyring::HardwareSigner> =
        Arc::new(ciris_keyring::Ed25519SoftwareSigner::new("blob-serve-test"));

    PersistBlobChunkSource::from_shared(ciris_persist::BackendDispatch::Sqlite(backend), signer)
}

#[tokio::test]
async fn an_absent_blob_is_a_miss_not_a_refusal() {
    let source = sovereign_source().await;
    let absent = [0x11u8; 32];

    let answer = source
        .read_chunk(absent, absent, "peer-asking-key")
        .await
        .expect("NotHeld must not surface as a refusal");

    // `Ok(None)` is what the responder turns into
    // `BlobChunkMiss::NotHeld`, telling the peer to ask another holder.
    // A refusal here would tell it the opposite — that this node HAS the
    // bytes and is declining — and the swarm scheduler treats those two
    // answers very differently.
    assert_eq!(answer, None, "an absent blob must read as a miss");
}

#[tokio::test]
async fn the_scope_gate_stays_fail_closed_by_default() {
    let source = sovereign_source().await;

    // Persist knows a blob's cohort scope but not the MLS group id that
    // edge's `ContentScope::Group` routes on, so this implementation
    // declines to guess. `None` refuses the serve on a scope-native node
    // (CIRISEdge#499) — the correct posture for "undeterminable".
    assert!(
        source.chunk_scope([0x22u8; 32]).await.is_none(),
        "the persist-backed source must not invent a content scope",
    );
}
