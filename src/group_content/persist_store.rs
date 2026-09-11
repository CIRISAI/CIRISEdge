//! CIRISEdge#586 — the persist-backed [`GroupContentStore`].
//!
//! Wraps a `ciris_persist::Engine` and uses **the one write door and the one
//! read door**: `put_blob_scoped` and `read_blob_as`. Not `put_blob`, not
//! `store_blob_local`, not `get_blob` — those are either commons-only or
//! ungated, and picking among them at the application tier is how an
//! encrypted cohort ends up with a plaintext row.
//!
//! # Edge names the scope; persist resolves the tier
//!
//! This type passes `cohort_scope` through and never asks for a
//! `CryptoTier`. persist's §11.1 is that the row is the authority on its own
//! tier and the reader dispatches on the row's column — so an application
//! that decided the tier would be asserting something the substrate is about
//! to overrule anyway.
//!
//! # `Engine::from_shared` means sovereign nodes get this too
//!
//! Same construction as [`PersistBlobChunkSource`](crate::blob_swarm::PersistBlobChunkSource):
//! a node that opened its own SQLite substrate builds an Engine VIEW over
//! the backend it already has. Group content is not a cohabitation-only
//! feature.

use std::sync::Arc;

use super::store::{
    aad_for_open, aad_for_seal, GroupContentError, GroupContentStore, OpenRequest, SealRequest,
    SealedContent,
};
use super::BlobPointer;

/// Seals and opens group content against a persist substrate.
pub struct PersistGroupContentStore {
    engine: ciris_persist::Engine,
    /// Held so the seal can ASK persist which tier a write resolves to
    /// rather than predicting it — the resolution depends on directory
    /// state, not just the scope label.
    directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
}

impl std::fmt::Debug for PersistGroupContentStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The engine holds a signer and a pool; neither belongs in a log.
        f.debug_struct("PersistGroupContentStore")
            .finish_non_exhaustive()
    }
}

impl PersistGroupContentStore {
    /// Wrap an `Engine` the caller already holds (cohabitation).
    #[must_use]
    pub fn new(
        engine: ciris_persist::Engine,
        directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    ) -> Self {
        Self { engine, directory }
    }

    /// Build over a backend + signer the caller already opened (sovereign).
    /// Shares the connection pool; runs no migrations.
    #[must_use]
    /// `directory` is the same substrate `backend` wraps — passed rather
    /// than destructured out of `BackendDispatch`, whose arms are cargo-
    /// feature-gated on persist's side and so cannot be matched
    /// exhaustively from here without edge mirroring those features.
    pub fn from_shared(
        backend: ciris_persist::BackendDispatch,
        directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
        signer: Arc<dyn ciris_keyring::HardwareSigner>,
    ) -> Self {
        Self::new(
            ciris_persist::Engine::from_shared(backend, signer),
            directory,
        )
    }
}

/// Translate a persist blob error into the typed vocabulary, preserving the
/// distinctions that have different remedies.
fn map_err(sha256_hex: String, e: &ciris_persist::federation::BlobError) -> GroupContentError {
    use ciris_persist::federation::BlobError as B;
    match e {
        B::NotGranted { .. } => GroupContentError::NotGranted { sha256_hex },
        B::NotHeld { .. } => GroupContentError::NotHeld { sha256_hex },
        B::Evicted { .. } => GroupContentError::Evicted { sha256_hex },
        // persist#831: an AAD mismatch fails AFTER authorization, as a crypto
        // error and never as NotGranted. Preserving that is the difference
        // between "you may not read this" and "this did not open" — two
        // findings with nothing in common.
        B::Backend(msg) if msg.contains("decrypt") || msg.contains("seal") => {
            GroupContentError::SealMismatch { sha256_hex }
        }
        other => GroupContentError::Substrate(other.to_string()),
    }
}

#[async_trait::async_trait]
impl GroupContentStore for PersistGroupContentStore {
    async fn seal(&self, req: SealRequest<'_>) -> Result<SealedContent, GroupContentError> {
        // An AAD binds a ciphertext to its row. A PLAINTEXT tier has no
        // ciphertext to bind, and persist REFUSES `Some(aad)` there rather
        // than ignoring it — so this has to be right BEFORE the call.
        //
        // ASK persist; do not predict. An earlier version called the pure
        // `crypto_tier(cohort_scope, None)` under a comment claiming it was
        // "persist's own classifier, not a mapping rebuilt here". It WAS
        // rebuilt: the write door uses `resolve_write_tier`, which consults
        // the DIRECTORY, and an authorized infrastructure community at
        // `cohort_scope: community` resolves to Plaintext regardless of the
        // label. Edge predicted CommunityDek, sent an AAD, and every write
        // to such a community was refused.
        //
        // `resolve_write_tier` is the door's own resolver and is public, so
        // there is no reason to approximate it.
        let aad = aad_for_seal(&req);
        let tier = ciris_persist::federation::at_rest_cascade::resolve_write_tier(
            &*self.directory,
            req.cohort_scope,
            req.community_key_id,
        )
        .await
        .map_err(|e| map_err(String::new(), &e))?;
        let aad_arg = match tier {
            ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext => None,
            _ => Some(aad.as_slice()),
        };

        let out = self
            .engine
            .put_blob_scoped(
                req.cohort_scope,
                req.community_key_id,
                req.plaintext,
                req.media_type,
                aad_arg,
            )
            .await
            .map_err(|e| map_err(String::new(), &e))?;

        Ok(SealedContent {
            // persist RESOLVED this; we do not re-derive it. Re-deriving
            // from the scope drops the directory axis the door applied.
            tier: out.tier,
            pointer: BlobPointer {
                community_key_id: req.community_key_id.unwrap_or_default().to_owned(),
                tier: out.tier,
                content_sha256: hex::encode(out.at_rest_sha256),
                content_field: req.field,
                media_type: req.media_type.map(ToOwned::to_owned),
                // Whole-blob seal. A chunked write goes through the DAG
                // doors and sets this; the two are deliberately not one
                // call, because "does a reader want part of this" is a
                // decision the content type makes, not the store.
                stream_id: None,
            },
            epoch: out.epoch,
            granted: out.granted,
            excluded: out.excluded,
        })
    }

    async fn open(&self, req: OpenRequest<'_>) -> Result<Vec<u8>, GroupContentError> {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let sha_hex = req.pointer.content_sha256.clone();
        let raw = hex::decode(&sha_hex)
            .map_err(|e| GroupContentError::Substrate(format!("pointer sha is not hex: {e}")))?;
        let sha: [u8; 32] = raw
            .try_into()
            .map_err(|_| GroupContentError::Substrate("pointer sha is not 32 bytes".to_owned()))?;

        // Ask the ROW what tier it is, exactly as persist's own read door
        // does. Not the pointer, and not the scope label.
        //
        // The first cut inferred it from `pointer.community_key_id.is_empty()`
        // while SEAL inferred it from `crypto_tier(cohort_scope, None)` — two
        // different questions of two different inputs, neither of which is
        // what persist records. They diverge on a commons scope carrying a
        // community id: the write succeeds AAD-free, the read then presents
        // an AAD, and persist refuses it. Content written and permanently
        // unreadable, with the only signal arriving at read time.
        //
        // persist's read door says why this is the right source: the tier is
        // "the tier the WRITE DOOR RESOLVED and recorded — never re-derived
        // here from the scope, which would drop the directory axis the door
        // applied."
        let tier = req.pointer.tier;

        let aad = aad_for_open(&req);
        let aad_arg = match tier {
            CryptoTier::Plaintext => None,
            CryptoTier::InvisibleEncrypted | CryptoTier::CommunityDek => Some(aad.as_slice()),
        };
        self.engine
            .read_blob_as(&sha, req.viewer_key_id, aad_arg)
            .await
            .map_err(|e| map_err(sha_hex, &e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group_content::ContentField;

    async fn store() -> PersistGroupContentStore {
        use ciris_persist::store::backend::Backend as _;
        let backend = ciris_persist::prelude::FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open in-memory substrate");
        backend.run_migrations().await.expect("migrate");
        // `Ed25519SoftwareSigner::new` creates a signer with NO key; the seal
        // path signs a holder attestation, so it needs one imported.
        let mut ed = ciris_keyring::Ed25519SoftwareSigner::new("group-content-test");
        ed.import_key(&[7u8; 32]).expect("import test key");
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(ed);
        PersistGroupContentStore::from_shared(
            ciris_persist::BackendDispatch::Sqlite(backend.clone()),
            backend,
            signer,
        )
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
    }

    fn absent_pointer() -> BlobPointer {
        BlobPointer {
            community_key_id: "community-1".into(),
            tier: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
            content_sha256: "ab".repeat(32),
            content_field: ContentField::Body,
            media_type: None,
            stream_id: None,
        }
    }

    /// Reading content this substrate does not hold is a typed NOT-HELD, not
    /// a generic substrate string — the arm a caller routes to "ask another
    /// holder".
    #[tokio::test]
    async fn an_absent_blob_reads_as_not_held() {
        let s = store().await;
        let p = absent_pointer();
        let err = s
            .open(OpenRequest {
                pointer: &p,
                author_key_id: "alice",
                asserted_at: now(),
                viewer_key_id: "alice",
            })
            .await
            .expect_err("absent content must not open");
        assert!(
            matches!(err, GroupContentError::NotHeld { .. }),
            "expected NotHeld, got {err:?}",
        );
    }

    /// A malformed pointer is caught before the substrate is asked, and says
    /// what is wrong with it.
    #[tokio::test]
    async fn a_malformed_pointer_sha_is_refused_with_its_reason() {
        let s = store().await;
        for bad in ["not-hex", "abcd"] {
            let p = BlobPointer {
                content_sha256: bad.into(),
                ..absent_pointer()
            };
            let err = s
                .open(OpenRequest {
                    pointer: &p,
                    author_key_id: "alice",
                    asserted_at: now(),
                    viewer_key_id: "alice",
                })
                .await
                .expect_err("a malformed sha must not reach the substrate");
            assert!(
                matches!(err, GroupContentError::Substrate(_)),
                "{bad:?} → {err:?}",
            );
        }
    }
}
