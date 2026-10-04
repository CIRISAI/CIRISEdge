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
    aad_for_open, aad_for_seal, ContentReader, GroupContentError, GroupContentStore, OpenRequest,
    SealRequest, SealedContent, StreamSealRequest,
};
use super::BlobPointer;

/// Seals and opens group content against a persist substrate.
pub struct PersistGroupContentStore {
    engine: ciris_persist::Engine,
    /// Held so the seal can ASK persist which tier a write resolves to
    /// rather than predicting it — the resolution depends on directory
    /// state, not just the scope label.
    directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    /// CIRISEdge#797 (tests only) — roll the producer's epoch label every
    /// this many chunks, so a lib test can write a multi-epoch v4 DAG
    /// through the production write path (persist rolls the stream's DEK
    /// when the producer names a higher epoch, CIRISPersist#969). `None`:
    /// every chunk at [`STREAM_EPOCH`], as in production.
    #[cfg(test)]
    chunks_per_epoch: Option<u64>,
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
        Self {
            engine,
            directory,
            #[cfg(test)]
            chunks_per_epoch: None,
        }
    }

    /// CIRISEdge#797 (tests only) — see `chunks_per_epoch`.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_chunks_per_epoch(mut self, chunks: u64) -> Self {
        self.chunks_per_epoch = Some(chunks.max(1));
        self
    }

    /// The epoch label the chunk at `seq` is written under: [`STREAM_EPOCH`]
    /// (a file is one write, so one epoch), or a test's roll.
    #[cfg_attr(not(test), allow(clippy::unused_self))] // the roll is a test's
    fn chunk_epoch_label(&self, seq: u64) -> u64 {
        #[cfg(test)]
        if let Some(n) = self.chunks_per_epoch {
            return seq / n;
        }
        let _ = seq;
        STREAM_EPOCH
    }

    /// Build over a backend + a CLASSICAL-ONLY signer the caller already
    /// opened. Shares the connection pool; runs no migrations.
    ///
    /// # This store cannot write ENCRYPTED content on persist ≥ v44.3.0
    ///
    /// CIRISPersist#848: every write at an encrypted tier now emits the
    /// `key_grant` set as a federated attestation, and the federation tier is
    /// verified under `HybridPolicy::Strict` — so an engine with no PQC half
    /// gets `AttestationEmissionFailed` on the first community / self /
    /// family seal (the bytes are stored; the key cannot follow them). Commons
    /// writes are unaffected. Use [`Self::from_shared_hybrid`] for anything
    /// that seals; this constructor stays for commons-only stores and for
    /// hardware-rooted hosts that supply the PQC half another way.
    ///
    /// `directory` is the same substrate `backend` wraps — passed rather
    /// than destructured out of `BackendDispatch`, whose arms are cargo-
    /// feature-gated on persist's side and so cannot be matched
    /// exhaustively from here without edge mirroring those features.
    #[must_use]
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

    /// Build over a backend the caller already opened, with the FULL hybrid
    /// identity — the constructor a node that seals group content needs
    /// (CIRISPersist#848).
    ///
    /// The engine's federation signer is `signer.classical`; its
    /// `LocalSigner` carries the ML-DSA-65 half so the emitted `key_grant`
    /// set is hybrid-signed and admissible on every peer. persist's
    /// `LocalSigner::from_hardware_parts` keeps the classical key behind the
    /// `HardwareSigner` seal — nothing is unsealed to build this.
    ///
    /// The same engine is what the replication bridge must route
    /// `key_grant:*` rows to ([`Self::engine`] →
    /// `ReplicationRuntimeConfig::engine`), so one node has ONE view of the
    /// substrate that both seals and projects.
    ///
    /// # Errors
    /// The classical signer could not report its public key, or reports a
    /// non-Ed25519 length.
    pub async fn from_shared_hybrid(
        backend: ciris_persist::BackendDispatch,
        directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
        signer: &crate::identity::LocalSigner,
    ) -> Result<Self, String> {
        // The two `key_id` arguments are NOT the same identifier, and passing
        // edge's `signer.key_id` for both is a double derivation.
        //
        // persist's `LocalSigner::derived_key_id()` is
        // `derive_key_id(self.key_id, ed25519_pubkey)`, so the `key_id`
        // argument is the keystore ALIAS — `derive_key_id`'s INPUT. Edge's
        // `signer.key_id` is already the OUTPUT (`<alias>-<fingerprint>`), so
        // handing it over derived a second time and produced
        // `<alias>-<fp>-<fp>`. Meanwhile `Engine::local_derived_key_id()`
        // resolves the composed classical signer through
        // `federation_key_id_of` = `derive_key_id(current_alias(), pubkey)`,
        // which is the singly-derived id every federation row is keyed by. The
        // two disagreed on every node.
        //
        // Nothing compared them until persist v44.4.0: `publish_self_occurrence`
        // (§20.3, PR #852 review round five) requires the LocalSigner to BE this
        // node's identity, so the mismatch surfaced as a refusal to publish this
        // node's own occurrence. It was never harmless — a LocalSigner that
        // cannot name itself is not the claimed attester, which is the same
        // predicate persist's claim signer uses to decide whether to attach the
        // PQC half at all — it was only invisible, because no gate asked.
        //
        // Deriving through `current_alias()` makes the two agree BY
        // CONSTRUCTION: same alias, same pubkey, same `derive_key_id`.
        //
        // The PQC key id is a different thing again and stays as it was: it is
        // stored verbatim (never re-derived), and names the ONE hybrid
        // `KeyRecord` edge registers carrying both pubkeys — the row a verifier
        // resolves the ML-DSA pubkey from — which is keyed by the DERIVED id.
        let local = ciris_persist::signing::LocalSigner::from_hardware_parts(
            signer.classical.clone(),
            ciris_keyring::HardwareSigner::current_alias(&*signer.classical).to_owned(),
            signer.pqc.clone(),
            signer.pqc.as_ref().map(|_| signer.key_id.clone()),
        )
        .await
        .map_err(|e| format!("hybrid local signer for {}: {e}", signer.key_id))?;
        let engine = ciris_persist::Engine::from_shared_with_local(
            backend.clone(),
            signer.classical.clone(),
            Some(Arc::new(local)),
        );
        // CIRISEdge#768 — tell the SHARED backend which key is this node
        // (persist#607). `Engine::from_shared_with_local` does not, and persist
        // otherwise learns it only inside `register_self_federation_key`, which
        // a node whose key row already exists (a steward-registered node) never
        // calls. Untold, persist's receive doors skip every member-device
        // re-wrap of this node's own epochs (#916: "no node key set on this
        // backend"), so a member whose node occurrence arrives after an epoch
        // was minted is never wrapped that epoch and reads `NotGranted` for
        // good.
        //
        // DO NOT "fix" this to the advertised node. The id is the ENGINE's
        // federation signer — exactly what `register_self_federation_key` sets
        // (`local_derived_key_id`), and the minter of every epoch this engine
        // seals, which is what the #916 re-wrap compares against. Under
        // `use_node_identity` (CIRISEdge#541: peers see the node, storage and
        // agency are the actor) a host that builds this store over the ACTOR's
        // signer mints as the actor, so the backend must name the actor:
        // naming the advertised node there would make the re-wrap skip every
        // epoch this engine minted. Witnessed by
        // `under_an_actor_node_split_the_backend_names_the_engines_signer`.
        // This is edge's belt for CIRISPersist#966 (persist's shared-backend
        // constructors never tell the backend its key); drop it once persist
        // does.
        let node_key = engine
            .local_derived_key_id()
            .await
            .map_err(|e| format!("this engine's federation key id: {e}"))?;
        set_backend_node_key(&backend, &node_key);
        Ok(Self::new(engine, directory))
    }

    /// The engine this store seals through — hand a clone to
    /// `ReplicationRuntimeConfig::engine` so the bridge projects the
    /// `key_grant` sets this node receives into the same tables this store
    /// reads (CIRISPersist#848).
    #[must_use]
    pub fn engine(&self) -> &ciris_persist::Engine {
        &self.engine
    }
}

/// Tell the concrete backend behind `backend` which federation key is this
/// node — the fact persist's node-relative doors (the #916 re-wrap, the #607
/// "does THIS NODE trust that root" gates) read, and that a shared-backend
/// `Engine` is never told.
#[allow(unreachable_patterns)] // the wildcard is live only when persist builds without `postgres`
fn set_backend_node_key(backend: &ciris_persist::BackendDispatch, node_key_id: &str) {
    match backend {
        ciris_persist::BackendDispatch::Sqlite(b) => b.set_node_key_id(node_key_id),
        #[cfg(feature = "pyo3")]
        ciris_persist::BackendDispatch::Postgres(b) => b.set_node_key_id(node_key_id),
        _ => {}
    }
}

/// Translate a persist blob error into the typed vocabulary, preserving the
/// distinctions that have different remedies.
fn map_err(sha256_hex: String, e: &ciris_persist::federation::BlobError) -> GroupContentError {
    use ciris_persist::federation::BlobError as B;
    match e {
        B::NotGranted { .. } => GroupContentError::NotGranted {
            sha256_hex,
            chunk: None,
        },
        // CIRISEdge#797 (persist v53, CIRISPersist#969) — authorized on the
        // DAG, a chunk's key not landed yet: the retryable, never NotGranted.
        B::ChunkKeyNotYetGranted {
            seq,
            chunk_sha_hex,
            key,
            ..
        } => GroupContentError::ChunkKeyPending {
            sha256_hex,
            chunk: super::RefusedChunk {
                seq: *seq,
                sha256_hex: chunk_sha_hex.clone(),
            },
            key: key.to_string(),
        },
        B::NotHeld { .. } => GroupContentError::NotHeld { sha256_hex },
        B::Evicted { .. } => GroupContentError::Evicted { sha256_hex },
        // persist#831: an AAD mismatch fails AFTER authorization, as a crypto
        // error and never as NotGranted. Preserving that is the difference
        // between "you may not read this" and "this did not open" — two
        // findings with nothing in common.
        //
        // persist v47.1.0 (CIRISPersist#842, edge's ask): the variant is TYPED.
        // Until then this arm string-matched persist's prose (`contains("decrypt")`),
        // and a reword upstream would have dropped every AAD mismatch into
        // `Substrate` with nothing going red. `SealDidNotOpen` is raised only by
        // the body open; a DEK that will not unwrap stays a key/grant fault. The
        // witness `chat_message_federates::
        // a_pointer_copied_onto_another_authors_row_does_not_open` performs a
        // real substitution against a real community DEK and still binds here.
        B::SealDidNotOpen { .. } => GroupContentError::SealMismatch { sha256_hex },
        // persist v47.2.0 (CIRISPersist#853, CC 2.3 at the bytes plane;
        // CIRISEdge#669): the referencing row was retired. Typed, because a
        // withdrawn file must never read as "not here" or as a substrate
        // fault — it is the subject's retraction, honoured.
        B::Withdrawn {
            attestation_id,
            withdraws_id,
            ..
        } => GroupContentError::Withdrawn {
            sha256_hex,
            attestation_id: attestation_id.clone(),
            withdraws_id: withdraws_id.clone(),
        },
        // CIRISEdge#737 — RFC 9110 §14.4 at the range door: typed, because
        // "you asked past the end" carries the size and is the caller's to
        // act on, never a substrate fault.
        B::RangeNotSatisfiable { range_start, size } => GroupContentError::RangeNotSatisfiable {
            sha256_hex,
            range_start: *range_start,
            size: *size,
        },
        other => GroupContentError::Substrate(other.to_string()),
    }
}

/// The stream epoch label a one-shot file is written under.
///
/// persist §12.3: the epoch is "the producer's stream epoch label (recorded
/// as given)", **not** a DEK selector — which DEK sealed a community chunk
/// is the chunk row's own binding. A file is complete when it is written, so
/// it is one epoch; an appendable stream (A/V) rolls its own against CC
/// 5.3.3.1's `MAX_CHUNKS_PER_EPOCH`.
pub(crate) const STREAM_EPOCH: u64 = 0;

#[async_trait::async_trait]
impl GroupContentStore for PersistGroupContentStore {
    fn stream_log(&self) -> Option<Arc<dyn crate::receipts::StreamLog>> {
        crate::receipts::stream_log_of(&self.engine)
    }

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
                clear_format(tier, req.description.as_ref()),
                aad_arg,
            )
            .await
            .map_err(|e| map_err(String::new(), &e))?;
        let described = self
            .describe(
                out.tier,
                &out.at_rest_sha256,
                req.plaintext.len() as u64,
                &{
                    use sha2::{Digest as _, Sha256};
                    Sha256::digest(req.plaintext).into()
                },
                req.description.as_ref(),
                &out.granted,
            )
            .await?;

        Ok(SealedContent {
            // persist RESOLVED this; we do not re-derive it. Re-deriving
            // from the scope drops the directory axis the door applied.
            tier: out.tier,
            pointer: BlobPointer {
                community_key_id: req.community_key_id.unwrap_or_default().to_owned(),
                tier: out.tier,
                content_sha256: hex::encode(out.at_rest_sha256),
                content_field: req.field,
                media_type: described.media_type,
                // Whole-blob seal. A chunked write goes through the DAG
                // doors and sets this; the two are deliberately not one
                // call, because "does a reader want part of this" is a
                // decision the content type makes, not the store.
                stream_id: None,
                // CIRISEdge#601 — the sealed-under epoch, on the row, so a
                // far node can adopt these bytes at the binding the author
                // declares (BLOB_REPLICATION.md §3). The same value as
                // `SealedContent::epoch` below; carried twice because the
                // pointer is what goes on the wire and the struct is what
                // the caller sees.
                epoch: out.epoch,
                codec: described.codec,
                sealed_descriptor: described.sealed_descriptor,
                size: Some(described.size),
                content_digest: described.content_digest,
                placeholder: None,
            },
            epoch: out.epoch,
            granted: out.granted,
            excluded: out.excluded,
        })
    }

    async fn seal_chunked(&self, req: SealRequest<'_>) -> Result<SealedContent, GroupContentError> {
        // ONE chunk-seal path (CIRISEdge#744): a slice is a reader that ends
        // where the slice does, and declares its own length.
        let mut reader: &[u8] = req.plaintext;
        self.seal_chunked_stream(StreamSealRequest::of(&req), &mut reader)
            .await
    }

    async fn seal_chunked_stream(
        &self,
        req: StreamSealRequest<'_>,
        reader: &mut ContentReader<'_>,
    ) -> Result<SealedContent, GroupContentError> {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let aad = req.aad();
        // The tier is the DIRECTORY's answer, exactly as `seal` asks it — not
        // re-derived from the scope, which would drop the axis the write door
        // applies (an infrastructure community resolves plaintext whatever
        // its scope says).
        let tier = ciris_persist::federation::at_rest_cascade::resolve_write_tier(
            &*self.directory,
            req.cohort_scope,
            req.community_key_id,
        )
        .await
        .map_err(|e| map_err(String::new(), &e))?;
        let aad_arg = match tier {
            CryptoTier::Plaintext => None,
            _ => Some(aad.as_slice()),
        };

        // One stream per file. A random id rather than a content hash: the
        // stream is keyed before its content is known, and two files with
        // identical bytes are still two writes.
        let stream_id = format!("file-{}", uuid::Uuid::new_v4());
        let mut written: Vec<[u8; 32]> = Vec::new();
        let (read, digest) = match self
            .write_chunks(&req, &stream_id, aad_arg, reader, &mut written)
            .await
        {
            Ok(done) => done,
            Err(e) => {
                self.evict_unsealed(tier, &stream_id, &written).await;
                return Err(e);
            }
        };
        // An empty file would seal a stream with no chunks, which is a
        // manifest pinning nothing — refused here rather than stored as a
        // blob that opens to nothing.
        if written.is_empty() {
            return Err(GroupContentError::Substrate(
                "refusing to seal an empty chunk DAG: a manifest over no chunks is content \
                 that opens to nothing"
                    .to_owned(),
            ));
        }

        // The LAST chunk has landed and the count is the declared one: only
        // now does the stream seal (CIRISEdge#744) — and only a sealed stream
        // becomes a pointer, so no row can cite a partial file.
        let sealed = match self
            .engine
            .seal_stream_scoped(
                req.cohort_scope,
                req.community_key_id,
                &stream_id,
                clear_format(tier, req.description.as_ref()),
                aad_arg,
            )
            .await
        {
            Ok(sealed) => sealed,
            Err(e) => {
                self.evict_unsealed(tier, &stream_id, &written).await;
                return Err(map_err(String::new(), &e));
            }
        };
        // The descriptor binds to the MANIFEST — what a reader opens and what
        // the row cites — under the manifest's DEK. That this reaches every
        // chunk rests on persist's one-access-set-per-stream invariant (D9).
        let described = self
            .describe(
                sealed.tier,
                &sealed.manifest_sha256,
                read,
                &digest,
                req.description.as_ref(),
                &sealed.granted,
            )
            .await?;

        Ok(SealedContent {
            pointer: crate::group_content::BlobPointer {
                community_key_id: req.community_key_id.unwrap_or_default().to_owned(),
                tier: sealed.tier,
                content_sha256: hex::encode(sealed.manifest_sha256),
                content_field: req.field,
                media_type: described.media_type,
                // The presence of this IS the answer to "is this chunked".
                stream_id: Some(stream_id),
                epoch: sealed.epoch,
                codec: described.codec,
                sealed_descriptor: described.sealed_descriptor,
                size: Some(described.size),
                content_digest: described.content_digest,
                placeholder: None,
            },
            tier: sealed.tier,
            epoch: sealed.epoch,
            // The seal's grant split is the stream's, taken from the SEAL
            // rather than a chunk: the manifest is what a reader opens.
            granted: sealed.granted,
            excluded: sealed.excluded,
        })
    }

    async fn open(&self, req: OpenRequest<'_>) -> Result<Vec<u8>, GroupContentError> {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let (sha_hex, sha) = pointer_sha(req.pointer)?;

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

    async fn open_range(
        &self,
        req: OpenRequest<'_>,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, GroupContentError> {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let (sha_hex, sha) = pointer_sha(req.pointer)?;
        // The ROW's binding, exactly as `open` presents it (CIRISEdge#737):
        // persist frames it per chunk with `(stream_id, seq)` itself, so the
        // caller AAD is the same bytes for every chunk of the DAG.
        let aad = aad_for_open(&req);
        let aad_arg = match req.pointer.tier {
            CryptoTier::Plaintext => None,
            CryptoTier::InvisibleEncrypted | CryptoTier::CommunityDek => Some(aad.as_slice()),
        };
        match self
            .engine
            .read_blob_range_as(&sha, req.viewer_key_id, start, end_inclusive, aad_arg)
            .await
        {
            Ok(bytes) => Ok(bytes),
            // CIRISEdge#779 — a refusal names the CHUNK, not only the file.
            // CIRISEdge#797: persist v53 names it itself
            // (`ChunkKeyNotYetGranted`, mapped by `map_err`), from the key
            // the read door asked for — the stream epoch's at v4, where a
            // chunk row carries no wrap of its own to look up here.
            Err(e) => Err(map_err(sha_hex, &e)),
        }
    }

    async fn layout(&self, req: OpenRequest<'_>) -> Result<super::ChunkLayout, GroupContentError> {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let (sha_hex, sha) = pointer_sha(req.pointer)?;
        let Some(named_stream) = req.pointer.stream_id.as_deref() else {
            return Err(GroupContentError::Substrate(format!(
                "pointer {sha_hex} names no stream_id: not a chunk DAG, nothing to lay out \
                 (CIRISEdge#737)"
            )));
        };
        if req.pointer.tier == CryptoTier::Plaintext {
            // A v1 manifest is in clear and persist's range door assembles it
            // by `get_blob_range` with no layout needed; `open_sealed_manifest_as`
            // refuses it by name, and so does this, before the substrate.
            return Err(GroupContentError::Substrate(format!(
                "pointer {sha_hex} is a plaintext-tier DAG: no sealed manifest to open; read it \
                 by range (CIRISEdge#737)"
            )));
        }
        let aad = aad_for_open(&req);
        let view = self
            .engine
            .open_sealed_manifest_as(&sha, req.viewer_key_id, Some(aad.as_slice()))
            .await
            .map_err(|e| map_err(sha_hex.clone(), &e))?;
        // The manifest names the pointer's stream (the puller's rule 1,
        // re-asked at read so a layout is never handed out for another stream).
        if view.stream_id != named_stream {
            return Err(GroupContentError::Substrate(format!(
                "pointer {sha_hex} names stream {named_stream:?} but its manifest names {:?}",
                view.stream_id
            )));
        }
        let mut offset = 0u64;
        let mut chunks = Vec::with_capacity(view.chunks.len());
        for c in &view.chunks {
            let size = u64::from(c.size);
            chunks.push(super::ChunkExtent {
                seq: c.seq,
                offset,
                size,
            });
            offset = offset.saturating_add(size);
        }
        if offset != view.total_size {
            return Err(GroupContentError::Substrate(format!(
                "manifest {sha_hex}: chunk sizes sum to {offset} but total_size says {}",
                view.total_size
            )));
        }
        Ok(super::ChunkLayout {
            stream_id: view.stream_id,
            total_size: view.total_size,
            chunks,
        })
    }

    async fn open_descriptor(&self, req: OpenRequest<'_>) -> Result<Vec<u8>, GroupContentError> {
        use base64::Engine as _;
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let (sha_hex, sha) = pointer_sha(req.pointer)?;
        let sealed_b64 = req.pointer.sealed_descriptor.as_deref().ok_or_else(|| {
            GroupContentError::Substrate(format!(
                "pointer {sha_hex} carries no sealed descriptor to open"
            ))
        })?;
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(sealed_b64)
            .map_err(|e| {
                GroupContentError::Substrate(format!("sealed descriptor is not base64: {e}"))
            })?;
        // The ROW's binding, exactly as `open` presents it: persist
        // authenticates the blob under it before the descriptor opens, so a
        // transplanted pointer is refused at the door (#923 amendment, D8).
        let aad = aad_for_open(&req);
        let aad_arg = match req.pointer.tier {
            CryptoTier::Plaintext => None,
            CryptoTier::InvisibleEncrypted | CryptoTier::CommunityDek => Some(aad.as_slice()),
        };
        self.engine
            .open_descriptor_for_blob(&sha, req.viewer_key_id, &sealed, aad_arg)
            .await
            .map_err(|e| map_err(sha_hex, &e))
    }

    async fn custody(
        &self,
        pointer: &BlobPointer,
        viewer_key_id: &str,
    ) -> Result<ciris_persist::federation::blob_custody::BlobCustody, GroupContentError> {
        let (sha_hex, sha) = pointer_sha(pointer)?;
        self.engine
            .blob_custody(&sha, viewer_key_id)
            .await
            .map_err(|e| map_err(sha_hex, &e))
    }

    async fn redescribe(
        &self,
        req: super::RedescribeRequest<'_>,
    ) -> Result<crate::group_content::BlobPointer, GroupContentError> {
        use base64::Engine as _;
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let mut pointer = req.pointer.clone();
        // The tier the write recorded decides, as it did for the write
        // (§6.7.1): plaintext carries its description in clear, and the name
        // is the row's.
        if pointer.tier == CryptoTier::Plaintext {
            return Ok(pointer);
        }
        let (sha_hex, sha) = pointer_sha(req.pointer)?;
        // This node reads as its own derived key — the node-class occurrence
        // the write's describe tried first. A node that cannot open the
        // description cannot rename it.
        let own = self.engine.local_derived_key_id().await.map_err(|e| {
            GroupContentError::Substrate(format!("derive this engine's key id: {e}"))
        })?;
        let open = OpenRequest {
            pointer: req.pointer,
            author_key_id: req.author_key_id,
            asserted_at: req.asserted_at,
            viewer_key_id: &own,
        };
        let (format, codec) = if req.pointer.sealed_descriptor.is_some() {
            let jcs = self.open_descriptor(open).await?;
            let current: crate::files::SealedDescription =
                serde_json::from_slice(&jcs).map_err(|e| {
                    GroupContentError::Substrate(format!(
                        "{sha_hex}: the sealed descriptor is not {{name?, format, codec?}}: {e}"
                    ))
                })?;
            (current.format, current.codec)
        } else {
            // A pre-#698 pointer: the format rode in clear. Authenticate the
            // blob under the prior row first — a pointer that does not open
            // under its row is not renamed.
            self.open(open).await?;
            let format = pointer.media_type.clone().ok_or_else(|| {
                GroupContentError::Substrate(format!(
                    "{sha_hex}: neither a sealed nor a clear description to rename"
                ))
            })?;
            (format, pointer.codec.clone())
        };
        let jcs = super::Description {
            name: req.name,
            format: &format,
            codec: codec.as_deref(),
        }
        .to_jcs()
        .map_err(GroupContentError::Substrate)?;
        let envelope = self
            .engine
            .seal_descriptor_for_blob(&sha, &own, &jcs)
            .await
            .map_err(|e| map_err(sha_hex, &e))?;
        pointer.sealed_descriptor =
            Some(base64::engine::general_purpose::STANDARD.encode(envelope));
        // One description (D4): the seal replaces any clear one.
        pointer.media_type = None;
        pointer.codec = None;
        Ok(pointer)
    }
}

/// Read into `buf` until it is FULL or the reader ends; the count read.
///
/// A reader may hand back fewer bytes than asked on any call (a socket, a
/// multipart body); chunk boundaries must not follow that, or the same
/// content streamed two ways would seal two different DAGs. Filling each
/// chunk fully makes them `seq × CHUNK_BYTES` whatever the reader's pacing —
/// exactly the slice path's boundaries (CIRISEdge#744).
async fn fill_chunk(reader: &mut ContentReader<'_>, buf: &mut [u8]) -> std::io::Result<usize> {
    use tokio::io::AsyncReadExt as _;
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]).await {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

impl PersistGroupContentStore {
    /// Read `reader` a chunk at a time and write each chunk through
    /// `put_blob_chunk_scoped` as it arrives, pushing each chunk's at-rest
    /// sha onto `written` (the caller evicts them on refusal). Returns the
    /// plaintext size and SHA-256, folded in chunk by chunk — the descriptor's
    /// inputs, without the content (CIRISEdge#744).
    ///
    /// The ONE chunk buffer is reused: the content is never held, only the
    /// chunk in hand.
    async fn write_chunks(
        &self,
        req: &StreamSealRequest<'_>,
        stream_id: &str,
        aad: Option<&[u8]>,
        reader: &mut ContentReader<'_>,
        written: &mut Vec<[u8; 32]>,
    ) -> Result<(u64, [u8; 32]), GroupContentError> {
        use sha2::{Digest as _, Sha256};
        let mut buf = vec![0u8; crate::group_content::store::CHUNK_BYTES];
        let mut digest = Sha256::new();
        let mut read: u64 = 0;
        loop {
            let n = fill_chunk(reader, &mut buf)
                .await
                .map_err(|e| GroupContentError::Reader {
                    read,
                    detail: e.to_string(),
                })?;
            if n == 0 {
                break;
            }
            read += n as u64;
            // A LONG reader is refused at the first chunk that crosses the
            // declaration — before that chunk is written, and without
            // draining a reader that may never end.
            if read > req.declared_len {
                return Err(GroupContentError::DeclaredLengthMismatch {
                    declared: req.declared_len,
                    read,
                });
            }
            let chunk = &buf[..n];
            digest.update(chunk);
            let put = self
                .engine
                .put_blob_chunk_scoped(
                    req.cohort_scope,
                    req.community_key_id,
                    stream_id,
                    written.len() as u64,
                    chunk,
                    self.chunk_epoch_label(written.len() as u64),
                    aad,
                )
                .await
                .map_err(|e| map_err(String::new(), &e))?;
            written.push(put.chunk_sha256);
        }
        if read != req.declared_len {
            return Err(GroupContentError::DeclaredLengthMismatch {
                declared: req.declared_len,
                read,
            });
        }
        Ok((read, digest.finalize().into()))
    }

    /// **A refused streamed seal leaves nothing it wrote** (CIRISEdge#744,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.4) — the deterministic half of the
    /// refusal.
    ///
    /// Persist has no GC (`federation::blobs` "Why no GC": blobs persist
    /// forever unless a door deletes them), so without this a 2 GiB upload
    /// refused at its last chunk would hold 2 GiB of chunks no manifest and
    /// no row will ever name. Each chunk goes through persist's ONE eviction
    /// door, `Engine::evict_blob` (retract this node's `holds_bytes` for the
    /// sha — a chunk has none — then delete the row with its grants and
    /// epoch binding in one transaction).
    ///
    /// Only at an ENCRYPTED tier: each chunk there is sealed under its
    /// stream epoch's DEK with the STREAM nonce of its counter (self/family,
    /// persist v53, CIRISPersist#969) or a random nonce (community), so its
    /// ciphertext sha is this write's alone. A plaintext chunk's sha is its content's, and
    /// may be a chunk another file's manifest names; it is left in place —
    /// unreferenced by this call, unannounced, never pulled (no manifest
    /// names it).
    ///
    /// What does not go: persist's stream bookkeeping (`federation_streams`,
    /// `federation_stream_chunks` — ids and sizes, no bytes; there is no door
    /// for it, and `stream_chunks` lists nothing once the blobs are gone), and
    /// the `key_grant` sets `put_blob_chunk_scoped` already emitted (wraps of
    /// DEKs for ciphertext that no longer exists anywhere).
    /// Best-effort by construction: the refusal the caller gets is the
    /// reason the write failed, and an eviction that also fails is logged,
    /// never substituted for it.
    async fn evict_unsealed(
        &self,
        tier: ciris_persist::federation::types::cohort_scope::CryptoTier,
        stream_id: &str,
        written: &[[u8; 32]],
    ) {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        if written.is_empty() {
            return;
        }
        if tier == CryptoTier::Plaintext {
            tracing::info!(
                stream_id,
                chunks = written.len(),
                "streamed seal refused at the plaintext tier: its chunks are content-addressed \
                 and stay (unreferenced, unannounced) — CIRISEdge#744"
            );
            return;
        }
        let now = chrono::Utc::now();
        let mut failed = 0usize;
        for sha in written {
            if let Err(e) = self.engine.evict_blob(sha, now).await {
                failed += 1;
                tracing::warn!(
                    stream_id,
                    chunk = %hex::encode(sha),
                    error = %e,
                    "streamed seal refused, and evicting one of its chunks failed too"
                );
            }
        }
        tracing::info!(
            stream_id,
            written = written.len(),
            evicted = written.len() - failed,
            "streamed seal refused: the chunks it wrote are evicted (CIRISEdge#744)"
        );
    }
}

/// The pointer's at-rest address, parsed — hex for messages, bytes for doors.
fn pointer_sha(pointer: &BlobPointer) -> Result<(String, [u8; 32]), GroupContentError> {
    let sha_hex = pointer.content_sha256.clone();
    let raw = hex::decode(&sha_hex)
        .map_err(|e| GroupContentError::Substrate(format!("pointer sha is not hex: {e}")))?;
    let sha: [u8; 32] = raw
        .try_into()
        .map_err(|_| GroupContentError::Substrate("pointer sha is not 32 bytes".to_owned()))?;
    Ok((sha_hex, sha))
}

/// The format persist may record on the blob: the description's, at the
/// plaintext tier only. An encrypted write hands persist NO media type —
/// a format recorded on the blob or holder metadata beside sealed bytes is
/// exactly the leak CC 3.3.13 closes (CIRISEdge#698, D2).
fn clear_format<'a>(
    tier: ciris_persist::federation::types::cohort_scope::CryptoTier,
    description: Option<&super::Description<'a>>,
) -> Option<&'a str> {
    match tier {
        ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext => {
            description.map(|d| d.format)
        }
        _ => None,
    }
}

/// The pointer members a description becomes, once the tier is KNOWN.
struct Described {
    media_type: Option<String>,
    codec: Option<String>,
    sealed_descriptor: Option<String>,
    size: u64,
    content_digest: Option<String>,
}

impl PersistGroupContentStore {
    /// **Decide the description's shape after persist resolved the tier** —
    /// the one decision CIRISEdge#698 puts in the store, never the producer.
    ///
    /// Plaintext tier: clear `format`/`codec`, nothing sealed, no second
    /// digest (the address IS the plaintext's). Encrypted tier: the JCS
    /// `{name?, format, codec?}` sealed under the bytes' own DEK by persist's
    /// `seal_descriptor_for_blob`, the plaintext digest in clear, and no
    /// clear format anywhere.
    ///
    /// The sealing door recovers the DEK *as a viewer*, so it needs a key
    /// this node can unwrap for: this engine's own derived key first (the
    /// node-class occurrence), then each occurrence the write granted. None
    /// opening means this node cannot read what it just wrote — refused by
    /// name, never a pointer with a silently-missing description.
    ///
    /// Takes the plaintext's SIZE and SHA-256, never the plaintext
    /// (CIRISEdge#744): a streamed seal folds both in chunk by chunk and has
    /// no whole plaintext to hand over.
    async fn describe(
        &self,
        tier: ciris_persist::federation::types::cohort_scope::CryptoTier,
        at_rest_sha256: &[u8; 32],
        size: u64,
        plaintext_sha256: &[u8; 32],
        description: Option<&super::Description<'_>>,
        granted: &[String],
    ) -> Result<Described, GroupContentError> {
        use base64::Engine as _;
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        if tier == CryptoTier::Plaintext {
            return Ok(Described {
                media_type: description.map(|d| d.format.to_owned()),
                codec: description.and_then(|d| d.codec).map(ToOwned::to_owned),
                sealed_descriptor: None,
                size,
                content_digest: None,
            });
        }
        let content_digest = Some(hex::encode(plaintext_sha256));
        let Some(description) = description else {
            return Ok(Described {
                media_type: None,
                codec: None,
                sealed_descriptor: None,
                size,
                content_digest,
            });
        };
        let jcs = description.to_jcs().map_err(GroupContentError::Substrate)?;
        let mut candidates: Vec<String> = Vec::with_capacity(granted.len() + 1);
        if let Ok(own) = self.engine.local_derived_key_id().await {
            candidates.push(own);
        }
        for g in granted {
            if !candidates.contains(g) {
                candidates.push(g.clone());
            }
        }
        let mut last = None;
        for key_id in &candidates {
            match self
                .engine
                .seal_descriptor_for_blob(at_rest_sha256, key_id, &jcs)
                .await
            {
                Ok(envelope) => {
                    return Ok(Described {
                        media_type: None,
                        codec: None,
                        sealed_descriptor: Some(
                            base64::engine::general_purpose::STANDARD.encode(envelope),
                        ),
                        size,
                        content_digest,
                    });
                }
                Err(e) => last = Some(format!("{key_id}: {e}")),
            }
        }
        Err(GroupContentError::Substrate(format!(
            "sealed {} but could not seal its descriptor: no key this node unwraps for opens \
             the blob's DEK (tried {candidates:?}; last: {}) — CC 3.3.13 forbids the clear \
             fallback",
            hex::encode(at_rest_sha256),
            last.unwrap_or_else(|| "no candidate".to_owned())
        )))
    }
}

#[cfg(test)]
mod tests {
    /// CIRISEdge#669 — persist's typed `Withdrawn` is typed here too, never
    /// `Substrate(..)` (where it landed until this arm) and never `NotHeld`.
    #[test]
    fn a_withdrawn_blob_is_a_typed_withdrawn_answer() {
        use ciris_persist::federation::BlobError;
        let e = BlobError::Withdrawn {
            sha256_hex: "cd".repeat(32),
            attestation_id: "row-9".into(),
            withdraws_id: "withdraws-9".into(),
        };
        match super::map_err("cd".repeat(32), &e) {
            super::GroupContentError::Withdrawn {
                sha256_hex,
                attestation_id,
                withdraws_id,
            } => {
                assert_eq!(sha256_hex, "cd".repeat(32));
                assert_eq!(attestation_id, "row-9");
                assert_eq!(withdraws_id, "withdraws-9");
            }
            other => panic!("a withdrawn reference must be typed Withdrawn, got {other:?}"),
        }
    }

    use super::*;
    use crate::group_content::ContentField;

    /// CIRISEdge#698 D2, edge's half — an encrypted write hands persist NO
    /// media type (persist would record it beside the sealed bytes); only
    /// the plaintext tier passes the format through.
    #[test]
    fn an_encrypted_write_hands_persist_no_format() {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        let d = crate::group_content::Description {
            name: Some("boat.jpg"),
            format: "image/jpeg",
            codec: None,
        };
        assert_eq!(
            clear_format(CryptoTier::Plaintext, Some(&d)),
            Some("image/jpeg")
        );
        assert_eq!(clear_format(CryptoTier::InvisibleEncrypted, Some(&d)), None);
        assert_eq!(clear_format(CryptoTier::CommunityDek, Some(&d)), None);
        assert_eq!(clear_format(CryptoTier::Plaintext, None), None);
    }

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

    async fn migrated_backend() -> Arc<ciris_persist::store::sqlite::SqliteBackend> {
        use ciris_persist::store::backend::Backend as _;
        let backend = ciris_persist::prelude::FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open in-memory substrate");
        backend.run_migrations().await.expect("migrate");
        backend
    }

    /// A hybrid edge signer whose `key_id` is the id derived from `label`.
    async fn hybrid_signer(label: &str, seed: u8) -> crate::identity::LocalSigner {
        let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[seed; 32], label)
                .expect("ed25519 signer"),
        );
        let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
                &[seed ^ 0x55; 32],
                format!("{label}-pqc"),
            )
            .expect("ml-dsa signer"),
        );
        let derived = ciris_verify_core::fedcode::derive_key_id(
            label,
            &classical.public_key().await.expect("pubkey"),
        );
        crate::identity::LocalSigner::new(derived, classical, Some(pqc))
    }

    /// The node key `register_self_federation_key` sets for an engine built
    /// over `signer` — read off a twin backend, so the witness compares
    /// against persist's own door rather than a re-derivation of it.
    async fn node_key_register_self_sets(signer: &crate::identity::LocalSigner) -> Option<String> {
        use ciris_persist::federation::FederationDirectory as _;
        let twin = migrated_backend().await;
        let local = ciris_persist::signing::LocalSigner::from_hardware_parts(
            signer.classical.clone(),
            ciris_keyring::HardwareSigner::current_alias(&*signer.classical).to_owned(),
            signer.pqc.clone(),
            Some(signer.key_id.clone()),
        )
        .await
        .expect("persist signer");
        let engine = ciris_persist::Engine::from_shared_with_local(
            ciris_persist::BackendDispatch::Sqlite(twin.clone()),
            signer.classical.clone(),
            Some(Arc::new(local)),
        );
        let id = engine.local_derived_key_id().await.expect("derived id");
        engine
            .register_self_federation_key("node", &id, None, serde_json::json!({}), Vec::new())
            .await
            .expect("register self");
        twin.node_key_id()
    }

    /// CIRISEdge#768 — the hybrid sealing constructor tells the SHARED backend
    /// which key is this node (persist#607/#916). `Engine::from_shared_with_local`
    /// does not, and persist learns it otherwise only inside
    /// `register_self_federation_key`, which `provision_engine_occurrence`
    /// skips when the key row already exists (a steward-registered node).
    /// Untold, every receive-side member-device re-wrap is skipped ("no node
    /// key set on this backend … (#916)"), and a member whose node occurrence
    /// reaches this node after it minted a room epoch reads that room's bodies
    /// `NotGranted` for good — the mesh's pair-room chat body (run
    /// 36791574370: 90 s of `NotGranted`).
    #[tokio::test]
    async fn from_shared_hybrid_tells_the_backend_its_node_key() {
        use ciris_persist::federation::FederationDirectory as _;
        let backend = migrated_backend().await;
        let node = hybrid_signer("node-768", 3).await;
        assert_eq!(
            backend.node_key_id(),
            None,
            "precondition: an untold backend"
        );
        let store = PersistGroupContentStore::from_shared_hybrid(
            ciris_persist::BackendDispatch::Sqlite(backend.clone()),
            backend.clone(),
            &node,
        )
        .await
        .expect("hybrid store");
        let told = backend.node_key_id();
        assert_eq!(told.as_deref(), Some(node.key_id.as_str()));
        // (a) the FEDERATION signer's id — the engine's own signing key, the
        // id `register_self_federation_key` would have set, by persist's door.
        assert_eq!(
            told,
            store.engine().local_derived_key_id().await.ok(),
            "the key the engine signs and mints as"
        );
        assert_eq!(
            told,
            node_key_register_self_sets(&node).await,
            "the same id persist's own register-self door sets"
        );
    }

    /// CIRISEdge#768 (b) — `use_node_identity` (#541): peers see the NODE,
    /// storage and agency are the ACTOR. A host that builds this store over
    /// the actor's signer mints every epoch as the actor, so the backend's
    /// node key must be the ACTOR's (what persist's register-self sets for that
    /// engine, and the minter the #916 re-wrap compares) — never the
    /// advertised node, under which the re-wrap would skip every epoch this
    /// engine minted.
    #[tokio::test]
    async fn under_an_actor_node_split_the_backend_names_the_engines_signer() {
        use ciris_persist::federation::FederationDirectory as _;
        let backend = migrated_backend().await;
        let advertised_node = hybrid_signer("node-541", 5).await;
        let actor = hybrid_signer("actor-541", 6).await;
        assert_ne!(
            advertised_node.key_id, actor.key_id,
            "precondition: a real split"
        );
        let store = PersistGroupContentStore::from_shared_hybrid(
            ciris_persist::BackendDispatch::Sqlite(backend.clone()),
            backend.clone(),
            &actor,
        )
        .await
        .expect("hybrid store over the actor");
        let told = backend.node_key_id();
        assert_eq!(told.as_deref(), Some(actor.key_id.as_str()));
        assert_ne!(told.as_deref(), Some(advertised_node.key_id.as_str()));
        assert_eq!(told, store.engine().local_derived_key_id().await.ok());
        assert_eq!(told, node_key_register_self_sets(&actor).await);
    }

    fn absent_pointer() -> BlobPointer {
        BlobPointer {
            community_key_id: "community-1".into(),
            tier: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
            content_sha256: "ab".repeat(32),
            content_field: ContentField::Body,
            media_type: None,
            stream_id: None,
            epoch: None,
            codec: None,
            sealed_descriptor: None,
            size: None,
            content_digest: None,
            placeholder: None,
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
