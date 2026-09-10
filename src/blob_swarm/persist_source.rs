//! CIRISEdge#587 — the persist-backed [`BlobChunkSource`], serving
//! through the **gated** door.
//!
//! # Why this lives in edge
//!
//! [`BlobChunkSource`] is consumer-implemented and opt-in: edge core stays
//! domain-agnostic at the substrate tier, and nothing here changes that —
//! a deployment still chooses to wire a source, and can wire its own.
//! What changed is that there was no reference implementation at all, so
//! every consumer was writing the persist bridge from scratch against a
//! trait doc that recommended the *ungated* doors (`has_blob` +
//! `get_blob_range`). Persist named the exact failure that produces: an
//! adapter that consults only the disk-pressure verdict serves a
//! quarantined blob one chunk at a time, every chunk succeeding, nothing
//! red. That is a bridge worth writing once.
//!
//! # The two gates
//!
//! [`Engine::serve_blob_to_peer`](ciris_persist::Engine::serve_blob_to_peer)
//! is the only door carrying both:
//!
//! - **proxy shedding** — under disk pressure a blob with no
//!   local-or-family holder is refused, a PERMANENT signal telling the
//!   peer to fetch elsewhere rather than retry here;
//! - **quarantine** — any withheld local holder refuses the serve.
//!
//! The translation onto edge's wire vocabulary is
//! [`serve_result_to_chunk`](super::serve_result_to_chunk), which fails
//! closed on every arm it does not recognise.
//!
//! # Sovereign nodes get this too
//!
//! [`Engine::from_shared`](ciris_persist::Engine::from_shared) is
//! synchronous, infallible, runs no migrations and shares the caller's
//! connection pool — so a node that opened its own SQLite substrate via
//! [`Edge::from_keyring_seed_dir`](crate::EdgeBuilder) can build an
//! `Engine` view over the backend it already has. Serving blobs is not a
//! cohabitation-only capability, which matters precisely because the
//! Pi/iOS hosts that run sovereign are the ones that hit disk pressure.

use std::sync::Arc;

use super::{serve_result_to_chunk, BlobChunkSource, ChunkSourceRefusal, ContentScope};

/// A [`BlobChunkSource`] that answers from a persist substrate through
/// the gated peer-serve door.
///
/// Construct with [`new`](Self::new) from an `Engine` you already hold
/// (cohabitation), or [`from_shared`](Self::from_shared) from the backend
/// + signer a sovereign node opened for itself.
pub struct PersistBlobChunkSource {
    engine: ciris_persist::Engine,
}

impl std::fmt::Debug for PersistBlobChunkSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Engine` holds a signer and a connection pool; neither belongs
        // in a log line.
        f.debug_struct("PersistBlobChunkSource")
            .finish_non_exhaustive()
    }
}

impl PersistBlobChunkSource {
    /// Serve from an existing `Engine` — the cohabitation shape, where a
    /// persist engine is already resident in-process.
    #[must_use]
    pub fn new(engine: ciris_persist::Engine) -> Self {
        Self { engine }
    }

    /// Serve from a backend + signer the caller already opened — the
    /// sovereign shape. Shares the connection pool; runs no migrations
    /// (the caller's `open` already did).
    #[must_use]
    pub fn from_shared(
        backend: ciris_persist::BackendDispatch,
        signer: Arc<dyn ciris_keyring::HardwareSigner>,
    ) -> Self {
        Self::new(ciris_persist::Engine::from_shared(backend, signer))
    }
}

#[async_trait::async_trait]
impl BlobChunkSource for PersistBlobChunkSource {
    async fn read_chunk(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        requesting_peer_key_id: &str,
    ) -> Result<Option<Vec<u8>>, ChunkSourceRefusal> {
        // Serve the CHUNK's sha, not the blob's. Persist stores each
        // chunk as its own content-addressed `federation_blobs` row
        // (`ChunkManifest` is a one-level DAG of leaves), so the chunk sha
        // is the address of the bytes the peer asked for. For a
        // single-chunk inline blob — the signed build manifest, #587's
        // first real blob — the requester sends the same value in both
        // fields and this resolves to the blob itself.
        let served = self
            .engine
            .serve_blob_to_peer(&chunk_sha256, requesting_peer_key_id)
            .await;

        let Some(bytes) = serve_result_to_chunk(served)? else {
            return Ok(None);
        };

        // Content-addressing belt. Persist addresses rows BY hash, so this
        // should be unfalsifiable — which is exactly why it is cheap to
        // assert and worth asserting: the responder is about to hand these
        // bytes to a peer under the claim that they hash to
        // `chunk_sha256`, and #587's done-when is "the bytes verify
        // against the SHA". A mismatch means the store disagrees with its
        // own index; refuse rather than propagate it onto the wire.
        let got: [u8; 32] = {
            use sha2::{Digest as _, Sha256};
            Sha256::digest(&bytes).into()
        };
        if got != chunk_sha256 {
            tracing::error!(
                blob = %hex::encode(blob_sha256),
                want = %hex::encode(chunk_sha256),
                got = %hex::encode(got),
                peer = %requesting_peer_key_id,
                "PersistBlobChunkSource: stored bytes do not hash to the \
                 requested chunk sha; refusing to serve",
            );
            return Err(ChunkSourceRefusal::PolicyDenied);
        }

        Ok(Some(bytes))
    }

    /// Left at the fail-closed default (`None`) deliberately.
    ///
    /// Edge's [`ContentScope::Group`] carries the MLS `group_id` that
    /// content's flows derive addresses from, and persist's
    /// `blob_cohort_scope` returns the cohort scope alone — the group id
    /// is edge/MLS-side state, not a blob column. There is no honest
    /// mapping to make here, and inventing one would arm the #499 scope
    /// gate with a guess. `None` refuses the serve on a scope-native node,
    /// which is the correct posture: a deployment that installs an address
    /// table overrides this with the scope it actually knows.
    async fn chunk_scope(&self, _blob_sha256: [u8; 32]) -> Option<ContentScope> {
        None
    }
}
