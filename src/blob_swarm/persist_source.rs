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
    /// CIRISEdge#606 — the register a `withdraws` writes to. `Some` ARMS the
    /// serve-side refusal: a blob whose every known reference has been
    /// withdrawn answers [`ChunkSourceRefusal::Withdrawn`] instead of being
    /// served. `None` is pre-#606 behaviour.
    ///
    /// **CIRISEdge#771 — still load-bearing after persist #979.** Persist's
    /// chunk→manifest link (V176) is written only where a manifest becomes a
    /// DAG on this node (the seal, the promote). A withdrawn DAG with NO link
    /// — sealed or pulled before persist v53.1.0, or held by a node that never
    /// promoted it — is never backfilled, because promote refuses a withdrawn
    /// manifest; and a row that cites its blob only through a `BlobPointer`
    /// (no `evidence_refs`) is invisible to persist's own fold. For both, this
    /// register is the only refusal of the DAG's chunks once the manifest has
    /// been evicted. Production wires it on every source
    /// (`replication::runtime`, `edge_node`).
    revocations: Option<Arc<super::RevocationRegister>>,
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
        Self {
            engine,
            revocations: None,
        }
    }

    /// Arm the serve-side revocation check (CIRISEdge#606): hand this source
    /// the SAME register the replication apply path writes withdrawals to.
    #[must_use]
    pub fn with_revocations(mut self, register: Option<Arc<super::RevocationRegister>>) -> Self {
        self.revocations = register;
        self
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

impl PersistBlobChunkSource {
    /// CIRISEdge#717 / #771 — **is `chunk` one of the chunks of the DAG at
    /// `dag`, in this store, and is that DAG still live?**
    ///
    /// 1. **The named DAG's own fold.** Persist's `binding_state` of the
    ///    DAG's address: a DAG every referencing row of which is withdrawn
    ///    answers `Withdrawn` for every chunk named under it — including a
    ///    chunk another, live DAG also holds (which persist's chunk fold
    ///    rightly reads `Live`, and which would otherwise be served under the
    ///    withdrawn file's name).
    /// 2. **Persist's link** (CIRISPersist#979, V176):
    ///    [`Engine::dag_contains_chunk`](ciris_persist::Engine::dag_contains_chunk),
    ///    a point query over the relation persist itself wrote at the seal or
    ///    the promote — never an author's claim. A DAG that HAS a link is
    ///    answered by it alone: a chunk outside it is not a member, whatever
    ///    any row names (CIRISEdge#771 replaced the #766 per-file cache and
    ///    edge's own stream walk with this).
    /// 3. **A clear manifest.** A plaintext DAG's root is its manifest, which
    ///    lists the chunks by sha — a DAG pulled whole through
    ///    `put_blob_chunks`, which persist does not link.
    /// 4. **Legacy, a sealed DAG with no link** (sealed or pulled before
    ///    persist v53.1.0 and never promoted again): the pre-#771 reading —
    ///    the stream a referencing row names, counted only where the stream's
    ///    own row (V143) agrees with the row's cohort and community. Uncached,
    ///    so its O(chunks) listing is paid per chunk; it serves only such
    ///    DAGs, and goes when persist backfills their link.
    ///
    /// Anything unreadable reads as "not a member": this is a refusal gate,
    /// and it fails closed. A `Withdrawn` from ANY of these reads is the
    /// answer, never skipped (v40.0.2: a swallowed `Withdrawn` on a secondary
    /// door read as `ChunkNotInNamedDag`).
    async fn chunk_in_named_dag(
        &self,
        dag: [u8; 32],
        chunk: [u8; 32],
        requester: &str,
    ) -> DagMembership {
        use ciris_persist::federation::blob_tombstone::{binding_state, BindingState};
        use ciris_persist::federation::{BlobBody, BlobError};
        let dag_hex = hex::encode(dag);
        let directory = self.engine.federation_directory();
        match binding_state(&*directory, &dag).await {
            Ok(BindingState::Withdrawn { .. }) => return DagMembership::Withdrawn,
            Ok(_) => {}
            Err(e) => tracing::warn!(
                blob = %dag_hex,
                error = %e,
                "PersistBlobChunkSource: the named DAG's binding state could not be read — \
                 judged by its link and the chunk's own fold (CIRISEdge#771)"
            ),
        }
        match self.engine.dag_contains_chunk(&dag, &chunk).await {
            Ok(true) => return DagMembership::Member,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    blob = %dag_hex,
                    error = %e,
                    "PersistBlobChunkSource: persist's chunk→manifest link could not be read — \
                     not a member (fail-closed, CIRISEdge#771)"
                );
                return DagMembership::NotMember;
            }
        }
        match self.engine.chunks_of_manifest(&dag).await {
            // The DAG is linked and the chunk is not in it: the link is the
            // answer, and no row can widen it (persist I485).
            Ok(linked) if !linked.is_empty() => return DagMembership::NotMember,
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    blob = %dag_hex,
                    error = %e,
                    "PersistBlobChunkSource: persist's chunk→manifest link could not be read — \
                     not a member (fail-closed, CIRISEdge#771)"
                );
                return DagMembership::NotMember;
            }
        }
        match self.engine.serve_blob_to_peer(&dag, requester).await {
            Ok(BlobBody::ChunkDag(manifest)) => {
                return if manifest.chunks.iter().any(|c| c.sha == chunk) {
                    DagMembership::Member
                } else {
                    DagMembership::NotMember
                };
            }
            // persist v53.1 (#979): the manifest itself is refused Withdrawn.
            Err(BlobError::Withdrawn { .. }) => return DagMembership::Withdrawn,
            // A sealed root is an inline envelope: the legacy reading below.
            Ok(BlobBody::Inline(_)) => {}
            _ => return DagMembership::NotMember,
        }
        self.legacy_stream_membership(dag, chunk).await
    }

    /// CIRISEdge#717's reading, kept for a sealed DAG persist has not linked
    /// (see [`chunk_in_named_dag`](Self::chunk_in_named_dag), step 4).
    async fn legacy_stream_membership(&self, dag: [u8; 32], chunk: [u8; 32]) -> DagMembership {
        use ciris_persist::federation::BlobError;
        let dag_hex = hex::encode(dag);
        // CIRISEdge#736 — the widenings too: a family file's placement on its
        // author's node is the `supersedes` widening its own `self` row, and
        // the stream was written at the family.
        let rows = match crate::blob_swarm::BlobMeaning::referencing_rows(
            &*self.engine.federation_directory(),
            &dag,
        )
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(
                    blob = %dag_hex,
                    error = %e,
                    "PersistBlobChunkSource: the rows referencing the named DAG could not be \
                     read — its stream is unknown (CIRISEdge#717)"
                );
                return DagMembership::NotMember;
            }
        };
        for row in &rows {
            let Some(fields) = row.attestation_envelope.as_object() else {
                continue;
            };
            for pointer in fields
                .values()
                .filter(|v| v.is_object())
                .filter_map(|v| {
                    serde_json::from_value::<crate::group_content::BlobPointer>(v.clone()).ok()
                })
                .filter(|p| p.content_sha256.eq_ignore_ascii_case(&dag_hex))
            {
                let Some(stream_id) = pointer.stream_id.as_deref() else {
                    continue;
                };
                let listing = match self.engine.stream_chunks(stream_id).await {
                    Ok(l) => l,
                    // The stream refuses through a link persist holds for it:
                    // the chunk's DAG is withdrawn. That IS the answer.
                    Err(BlobError::Withdrawn { .. }) => return DagMembership::Withdrawn,
                    Err(_) => continue,
                };
                if let Some(head) = &listing.stream {
                    let community_agrees = match head.community_key_id.as_deref() {
                        Some(c) => {
                            pointer.community_key_id.is_empty() || c == pointer.community_key_id
                        }
                        None => true,
                    };
                    if head.cohort_scope != row.cohort_scope || !community_agrees {
                        tracing::warn!(
                            blob = %dag_hex,
                            stream_id,
                            row = %row.attestation_id,
                            "PersistBlobChunkSource: a row names a stream whose own cohort or \
                             community disagrees with it — not counted as the DAG's stream \
                             (CIRISEdge#717)"
                        );
                        continue;
                    }
                }
                if listing.chunks.iter().any(|c| c.chunk_sha == chunk) {
                    return DagMembership::Member;
                }
            }
        }
        DagMembership::NotMember
    }
}

/// CIRISEdge#717 / #771 — what the serve gate learns about `(dag, chunk)`.
///
/// Three answers, because two of them are refusals with different remedies:
/// a chunk that is not one of the named DAG's is `ChunkNotInNamedDag` (the
/// requester named the wrong file); a chunk of a withdrawn DAG is `Withdrawn`
/// (CC 2.3 at the bytes plane, the one refusal the fetcher aborts on). Every
/// read [`PersistBlobChunkSource::chunk_in_named_dag`] makes can return the
/// second, and each returns it rather than falling through to the first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DagMembership {
    Member,
    NotMember,
    Withdrawn,
}

#[async_trait::async_trait]
impl BlobChunkSource for PersistBlobChunkSource {
    async fn read_chunk(
        &self,
        blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        requesting_peer_key_id: &str,
    ) -> Result<Option<Vec<u8>>, ChunkSourceRefusal> {
        // CIRISEdge#606 — CC 2.3 at the bytes plane. Before anything is read
        // from disk: if every row known to reference this BLOB has been
        // withdrawn by an authorized withdrawal (the register recomputed the
        // rule against the local target when it recorded it), the answer is
        // `Withdrawn`, not the bytes and not `NotHeld`. `Withdrawn` is the
        // one refusal the fetcher ABORTS on rather than walking to the next
        // holder — which is the point: the next holder was told the same
        // thing. Asked about the blob, not the chunk, because the reference
        // names the blob. `Unknown` and `Live` fall through to today's path.
        if let Some(register) = self.revocations.as_deref() {
            if register.verdict(&blob_sha256) == super::BytesVerdict::Revoked {
                tracing::info!(
                    blob = %hex::encode(blob_sha256),
                    chunk = %hex::encode(chunk_sha256),
                    peer = %requesting_peer_key_id,
                    "PersistBlobChunkSource: every reference to this blob was withdrawn — \
                     refusing Withdrawn (CC 2.3 at the bytes plane, CIRISEdge#606)",
                );
                return Err(ChunkSourceRefusal::Withdrawn);
            }
        }
        // CIRISEdge#717 — the named DAG bounds the chunk. The responder's
        // scope gate judged `blob_sha256` (the file whose referencing row
        // projects the scope); a `chunk_sha256` that is not one of THAT
        // file's chunks would be served on the strength of a judgement about
        // another file. `(sha, sha)` — a whole blob, or a DAG's root — is
        // the file itself and never asks.
        if chunk_sha256 != blob_sha256 {
            match self
                .chunk_in_named_dag(blob_sha256, chunk_sha256, requesting_peer_key_id)
                .await
            {
                DagMembership::Member => {}
                DagMembership::Withdrawn => {
                    tracing::info!(
                        blob = %hex::encode(blob_sha256),
                        chunk = %hex::encode(chunk_sha256),
                        peer = %requesting_peer_key_id,
                        "PersistBlobChunkSource: the named DAG is withdrawn in this store — \
                         refusing Withdrawn (CC 2.3 at the bytes plane; persist #979)",
                    );
                    return Err(ChunkSourceRefusal::Withdrawn);
                }
                DagMembership::NotMember => {
                    tracing::debug!(
                        blob = %hex::encode(blob_sha256),
                        chunk = %hex::encode(chunk_sha256),
                        peer = %requesting_peer_key_id,
                        "PersistBlobChunkSource: the chunk is not one of the named DAG's chunks \
                         in this store — refusing ChunkNotInNamedDag (CIRISEdge#717)",
                    );
                    return Err(ChunkSourceRefusal::ChunkNotInNamedDag);
                }
            }
        }
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
    /// table overrides this with the scope it actually knows — and declares
    /// it with `answers_scope() -> true`, which this source deliberately does
    /// NOT: a scope-native node that wires this source bare is refused at
    /// build (`scope_native_chunk_source_gate`, CIRISEdge#640) instead of
    /// withholding every scoped fetch at runtime.
    async fn chunk_scope(&self, _blob_sha256: [u8; 32]) -> Option<ContentScope> {
        None
    }
}
