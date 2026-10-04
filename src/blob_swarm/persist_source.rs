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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::{serve_result_to_chunk, BlobChunkSource, ChunkSourceRefusal, ContentScope};

/// CIRISEdge#766 — **how many files' chunk sets the serve gate remembers.**
///
/// The #717 membership check is a question about a whole file (is this
/// chunk one of the DAG's?), and answering it from the stream listing costs
/// the whole listing: asked once per chunk served, that is O(n²) per file
/// (≈ 645 ms per chunk at 2 GiB). The answer is the same set for every chunk
/// of the file, so it is read once and kept, keyed by the DAG's address.
///
/// Bounded by FILE count, least-recently-used out: at most this many files'
/// sets are held. A set is 32 bytes per chunk (a sorted slice), so the bound
/// in bytes is `32 × Σ chunks` — at the ~2.5 GiB file ceiling in 256 KiB
/// chunks (≈ 10,240 chunks, 320 KiB a file), ≤ 10 MiB for 32 files. A node
/// serving more files than this at once re-reads a listing per file it
/// brings back, never per chunk.
pub const MEMBERSHIP_CACHE_FILES: usize = 32;

/// One file's chunk set, and the inputs it was read under.
struct Membership {
    /// The ids of the rows referencing the DAG when the set was read,
    /// sorted. The set is valid only while the same rows reference it: a
    /// row withdrawn out of the directory, or a new widening naming another
    /// stream, changes this and the set is read again.
    rows: Vec<String>,
    /// The chunk shas of every stream those rows name (and agree with),
    /// sorted and deduplicated — a lookup is a binary search.
    chunks: Box<[[u8; 32]]>,
    /// The cache's clock at the last hit, for least-recently-used eviction.
    used: u64,
}

/// CIRISEdge#766 — the per-file membership sets, LRU-bounded by file count.
/// Pure (no I/O), so its rules are unit-tested alone.
#[derive(Default)]
struct MembershipCache {
    entries: HashMap<[u8; 32], Membership>,
    clock: u64,
}

impl MembershipCache {
    /// Is `chunk` in the set held for `dag`, read under exactly `rows`?
    /// `false` covers "no set", "a set read under other rows" and "not in
    /// the set" alike: each sends the caller to the listing.
    fn hit(&mut self, dag: &[u8; 32], rows: &[String], chunk: &[u8; 32]) -> bool {
        self.clock += 1;
        let clock = self.clock;
        match self.entries.get_mut(dag) {
            Some(m) if m.rows == rows && m.chunks.binary_search(chunk).is_ok() => {
                m.used = clock;
                true
            }
            _ => false,
        }
    }

    /// Hold `chunks` as `dag`'s set, read under `rows`, evicting the
    /// least-recently-used file when `cap` files are already held.
    fn put(&mut self, dag: [u8; 32], rows: Vec<String>, mut chunks: Vec<[u8; 32]>, cap: usize) {
        if cap == 0 {
            return;
        }
        chunks.sort_unstable();
        chunks.dedup();
        self.clock += 1;
        if !self.entries.contains_key(&dag) && self.entries.len() >= cap {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, m)| m.used)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(
            dag,
            Membership {
                rows,
                chunks: chunks.into_boxed_slice(),
                used: self.clock,
            },
        );
    }

    /// Drop `dag`'s set (its references were withdrawn, or none remain).
    fn forget(&mut self, dag: &[u8; 32]) {
        self.entries.remove(dag);
    }

    fn holds(&self, dag: &[u8; 32]) -> bool {
        self.entries.contains_key(dag)
    }
}

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
    revocations: Option<Arc<super::RevocationRegister>>,
    /// CIRISEdge#766 — each served file's chunk set, read once per file
    /// instead of once per chunk ([`MEMBERSHIP_CACHE_FILES`]).
    membership: Mutex<MembershipCache>,
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
            membership: Mutex::new(MembershipCache::default()),
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

    /// CIRISEdge#766 — whether the serve gate currently holds `dag`'s chunk
    /// set. For witnesses that the membership cache was warm (or dropped)
    /// when they asked.
    #[doc(hidden)]
    #[must_use]
    pub fn holds_membership_of(&self, dag: &[u8; 32]) -> bool {
        self.membership.lock().is_ok_and(|c| c.holds(dag))
    }

    fn forget_membership(&self, dag: &[u8; 32]) {
        if let Ok(mut c) = self.membership.lock() {
            c.forget(dag);
        }
    }
}

impl PersistBlobChunkSource {
    /// CIRISEdge#717 — **is `chunk` one of the chunks of the DAG at `dag`,
    /// in this store?** Two readings, either sufficient, neither guessed:
    ///
    /// 1. **The stream a referencing row names.** A sealed DAG's manifest is
    ///    an envelope this door does not open, but every row referencing the
    ///    DAG carries its pointer in clear, and the pointer's `stream_id` is
    ///    the stream the chunks were written (or adopted) at. The chunk must
    ///    be listed there — AND the stream's own row (`federation_streams`,
    ///    V143: the cohort and community its first append named) must agree
    ///    with the row naming it, so a row cannot borrow another room's
    ///    stream by naming its id.
    /// 2. **A clear manifest.** A plaintext DAG's root is its manifest,
    ///    which lists the chunks by sha — including a DAG pulled whole
    ///    through `put_blob_chunks`, which writes no stream rows.
    ///
    /// Anything unreadable reads as "not a member": this is a refusal gate,
    /// and it fails closed.
    ///
    /// **CIRISEdge#766 — once per file, not once per chunk.** Reading (1)
    /// lists the whole stream; the set it yields is the same for every chunk
    /// of the file, so it is kept ([`MEMBERSHIP_CACHE_FILES`]) under the ids
    /// of the rows it was read through. The rows are read fresh on every
    /// call (an indexed lookup, as before), and a set read under other rows
    /// is not used: the membership answer rests on exactly the inputs the
    /// uncached check read, except the listing itself. A chunk NOT in the
    /// held set re-reads the listing (a relay still adopting the stream
    /// grows it), so a cached miss never refuses what the listing would
    /// admit. Withdrawal is honoured where it always was — the revocation
    /// register's `Revoked` verdict, checked before this gate on every
    /// chunk, which also drops the file's set — and the bytes are still
    /// read through the gated door per chunk: a held set says only "a
    /// member", never "servable".
    async fn chunk_in_named_dag(
        &self,
        dag: [u8; 32],
        chunk: [u8; 32],
        requester: &str,
    ) -> DagMembership {
        use ciris_persist::federation::{BlobBody, BlobError};
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
                Vec::new()
            }
        };
        let mut row_ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
        row_ids.sort_unstable();
        if row_ids.is_empty() {
            // Nothing references the DAG any more: no stream is its stream.
            self.forget_membership(&dag);
        } else if self
            .membership
            .lock()
            .is_ok_and(|mut c| c.hit(&dag, &row_ids, &chunk))
        {
            return DagMembership::Member;
        }
        let mut members: Vec<[u8; 32]> = Vec::new();
        let mut listed = false;
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
                    // persist v53.1 (#979): a withdrawn DAG's stream refuses
                    // through the chunk→manifest link. That IS the answer:
                    // the chunk is in the DAG, and the DAG is withdrawn.
                    Err(BlobError::Withdrawn { .. }) => {
                        self.forget_membership(&dag);
                        return DagMembership::Withdrawn;
                    }
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
                listed = true;
                members.extend(listing.chunks.iter().map(|c| c.chunk_sha));
            }
        }
        if listed {
            let found = members.contains(&chunk);
            if let Ok(mut c) = self.membership.lock() {
                c.put(dag, row_ids, members, MEMBERSHIP_CACHE_FILES);
            }
            if found {
                return DagMembership::Member;
            }
        }
        match self.engine.serve_blob_to_peer(&dag, requester).await {
            Ok(BlobBody::ChunkDag(manifest)) if manifest.chunks.iter().any(|c| c.sha == chunk) => {
                DagMembership::Member
            }
            // persist v53.1 (#979): the manifest itself is refused Withdrawn.
            Err(BlobError::Withdrawn { .. }) => {
                self.forget_membership(&dag);
                DagMembership::Withdrawn
            }
            _ => DagMembership::NotMember,
        }
    }
}

/// CIRISEdge#717 / #766 — what the serve gate learns about `(dag, chunk)`.
///
/// Three answers, because two of them are refusals with different remedies:
/// a chunk that is not one of the named DAG's is `ChunkNotInNamedDag` (the
/// requester named the wrong file); a chunk of a DAG whose every reference
/// is withdrawn is `Withdrawn` (CC 2.3 at the bytes plane, the one refusal
/// the fetcher aborts on). Since persist v53.1 (#979) the store answers the
/// second itself, through the chunk→manifest link, when the DAG's stream
/// or manifest is read; before this enum that answer was swallowed on the
/// cold path and reported as the first, while a warm cache reached the serve
/// door and reported the second: the same door answering two ways.
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
                // CIRISEdge#766 — and the file's held chunk set goes with it.
                self.forget_membership(&blob_sha256);
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

#[cfg(test)]
mod membership_cache_tests {
    use super::MembershipCache;

    fn rows(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_held_set_answers_only_its_own_chunks_under_its_own_rows_766() {
        let mut c = MembershipCache::default();
        let (x, y) = ([1u8; 32], [2u8; 32]);
        c.put(x, rows(&["r1"]), vec![[9; 32], [7; 32], [9; 32]], 4);
        assert!(c.hit(&x, &rows(&["r1"]), &[7; 32]), "a member of X's set");
        assert!(
            c.hit(&x, &rows(&["r1"]), &[9; 32]),
            "dedup keeps the member"
        );
        assert!(!c.hit(&x, &rows(&["r1"]), &[8; 32]), "not a member of X");
        assert!(
            !c.hit(&y, &rows(&["r1"]), &[7; 32]),
            "X's set says nothing about Y"
        );
        assert!(
            !c.hit(&x, &rows(&["r1", "r2"]), &[7; 32]),
            "a set read under other rows is not used (a row added)"
        );
        assert!(!c.hit(&x, &rows(&[]), &[7; 32]), "or a row gone");
        c.forget(&x);
        assert!(
            !c.holds(&x) && !c.hit(&x, &rows(&["r1"]), &[7; 32]),
            "forgotten"
        );
    }

    #[test]
    fn the_cache_holds_at_most_cap_files_least_recently_used_out_766() {
        let mut c = MembershipCache::default();
        let r = rows(&["r"]);
        for i in 0..3u8 {
            c.put([i; 32], r.clone(), vec![[i; 32]], 3);
        }
        // Touch file 0, so file 1 is the least recently used.
        assert!(c.hit(&[0; 32], &r, &[0; 32]));
        c.put([3; 32], r.clone(), vec![[3; 32]], 3);
        assert_eq!(c.entries.len(), 3, "bounded by file count");
        assert!(!c.holds(&[1; 32]), "the least recently used file went");
        assert!(c.holds(&[0; 32]) && c.holds(&[2; 32]) && c.holds(&[3; 32]));
        // Re-putting a held file replaces it without evicting another.
        c.put([3; 32], r.clone(), vec![[4; 32]], 3);
        assert_eq!(c.entries.len(), 3);
        assert!(c.hit(&[3; 32], &r, &[4; 32]) && !c.hit(&[3; 32], &r, &[3; 32]));
        // A zero cap holds nothing.
        let mut z = MembershipCache::default();
        z.put([5; 32], r.clone(), vec![[5; 32]], 0);
        assert!(!z.holds(&[5; 32]));
    }
}
