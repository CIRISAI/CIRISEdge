//! CIRISEdge#586 — the group-content store: seal, and open.
//!
//! The two doors every group-content consumer uses, and the seam that lets
//! edge own the *contract* while the persist-backed consumer owns the
//! *substrate* — the same split as [`BlobChunkSource`] for serving and
//! `BlobStorePolicy` for admission.
//!
//! # What this is NOT
//!
//! Not a chat API. Chat calls it; so will files, video, log bundles and A/V
//! recordings. Anything specific to one content type (what media type, what
//! retention, which room) belongs to that content type and is absent here.

use super::{content_aad, BlobPointer, ContentField};

/// What went wrong, typed so a caller can tell "you may not read this" from
/// "this is not here" from "the bytes are wrong".
#[derive(Debug, thiserror::Error)]
pub enum GroupContentError {
    /// The viewer holds no grant on this content.
    ///
    /// Distinct from every other arm because the remedy is membership, not
    /// a retry: this is what a non-member — or a member excluded at write
    /// time for carrying no `encryption_pubkeys` — sees.
    #[error(
        "not granted: this viewer holds no key for {sha256_hex}{}",
        chunk.as_ref().map(|c| format!(" (chunk seq {} = {})", c.seq, c.sha256_hex)).unwrap_or_default()
    )]
    NotGranted {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
        /// CIRISEdge#779 — when the read was a chunk DAG's and the refusal
        /// was one of its CHUNKS (not the manifest), the first chunk in the
        /// range this viewer holds no wrap for. `None` for a whole blob, a
        /// refused manifest, or a refusal the store could not attribute.
        chunk: Option<RefusedChunk>,
    },
    /// The bytes are not held here.
    #[error("not held: {sha256_hex}")]
    NotHeld {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
    },
    /// The row referencing the bytes was withdrawn (CC 2.3 at the bytes
    /// plane — persist v47.2.0, CIRISPersist#853; CIRISEdge#669). Not
    /// [`Self::NotHeld`]: the bytes may well be here, and the remedy is
    /// none — a subject pulled their row, so the bytes stop. Named so a
    /// caller never shows "not found" for a deliberate retraction.
    #[error(
        "withdrawn: {sha256_hex} — its binding row {attestation_id} was retired by \
         {withdraws_id}"
    )]
    Withdrawn {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
        /// The last live binding row, now retired.
        attestation_id: String,
        /// The `withdraws` (or `recants`) that retired it.
        withdraws_id: String,
    },
    /// The bytes were swept by a retention sweep. persist distinguishes
    /// this from [`Self::NotHeld`] so an operator can tell "swept" from
    /// "wrong handle"; the remedy differs (there is none for swept).
    #[error("evicted: {sha256_hex} was swept by a retention sweep")]
    Evicted {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
    },
    /// The AEAD tag did not verify.
    ///
    /// **Almost always an AAD mismatch, not corruption.** The binding
    /// inputs the reader rebuilt do not match what the writer sealed under
    /// — a different author, a different instant, or a different field. It
    /// arrives AFTER authorization, so it is never a permissions problem
    /// wearing a crypto error.
    #[error(
        "seal did not open for {sha256_hex} — the rebuilt AAD does not match what \
         was sealed (author / asserted_at / field), or the ciphertext was moved"
    )]
    SealMismatch {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
    },
    /// A range read whose start is at or past the content's end (RFC 9110
    /// §14.4; persist's `RangeNotSatisfiable`, CIRISEdge#737). Carries the
    /// PLAINTEXT total persist named, so the caller learns the size it
    /// overshot.
    #[error(
        "range not satisfiable for {sha256_hex}: start {range_start} is at or past the \
         {size}-byte end"
    )]
    RangeNotSatisfiable {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
        /// The first byte asked for.
        range_start: u64,
        /// The content's plaintext size.
        size: u64,
    },
    /// **A streamed write whose reader yielded a different number of bytes
    /// than the caller declared** (CIRISEdge#744, `FSD/CONTENT_TRANSFER.md`
    /// §6.7.4). Nothing is sealed: no manifest, no pointer, and the chunks
    /// the stream wrote before the count came out wrong are evicted (see
    /// [`GroupContentStore::seal_chunked_stream`]).
    ///
    /// `read` is exact when the reader ran SHORT (it hit EOF there). When it
    /// ran LONG the stream stops at the first chunk that crosses `declared`
    /// — an unbounded reader is never drained to count it — so `read` is the
    /// bytes consumed by then: a lower bound, always `> declared`.
    #[error(
        "declared {declared} bytes but the reader yielded {read}: nothing sealed, the chunks \
         written so far are evicted (FSD/CONTENT_TRANSFER.md §6.7.4)"
    )]
    DeclaredLengthMismatch {
        /// What the caller said the content weighs.
        declared: u64,
        /// What the reader produced (a lower bound when `> declared`).
        read: u64,
    },
    /// The reader itself failed mid-stream (CIRISEdge#744) — an I/O error,
    /// not a substrate refusal. Nothing is sealed; written chunks are evicted
    /// as for [`Self::DeclaredLengthMismatch`].
    #[error("reading the content failed after {read} bytes: {detail}")]
    Reader {
        /// Bytes consumed before the failure.
        read: u64,
        /// The reader's error.
        detail: String,
    },
    /// Anything else the substrate reported.
    #[error("substrate: {0}")]
    Substrate(String),
}

/// CIRISEdge#779 — the chunk of a DAG a read was refused at: its position
/// and its own at-rest address (over its ciphertext), which is what the
/// key_grant that would open it names. A refusal naming only the file's
/// address sent the field looking for the wrong row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedChunk {
    /// The chunk's position in its stream.
    pub seq: u64,
    /// Hex at-rest sha of the chunk row.
    pub sha256_hex: String,
}

/// **A chunk DAG's layout, for a viewer** (CIRISEdge#737,
/// `FSD/CONTENT_TRANSFER.md` §6.7.3): the manifest's per-chunk PLAINTEXT
/// sizes in `seq` order, with the file offset each chunk starts at — the
/// prefix sum persist's own range reader maps a range onto
/// (`ChunkManifest::slices_for_range`). What a streaming reader needs to
/// ask for exactly one chunk at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkLayout {
    /// The stream the manifest names — the one the pointer names.
    pub stream_id: String,
    /// The file's plaintext size: the sum of every chunk's `size`.
    pub total_size: u64,
    /// The chunks, in `seq` order, offsets contiguous from 0.
    pub chunks: Vec<ChunkExtent>,
}

/// One chunk's place in the file (CIRISEdge#737).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkExtent {
    /// The chunk's position in its stream — the `seq` its AAD is bound to.
    pub seq: u64,
    /// The first plaintext byte of the file this chunk holds.
    pub offset: u64,
    /// The chunk's plaintext length.
    pub size: u64,
}

impl ChunkExtent {
    /// The last byte this chunk holds, inclusive. `None` for an empty chunk.
    #[must_use]
    pub fn end_inclusive(&self) -> Option<u64> {
        self.size.checked_sub(1).map(|last| self.offset + last)
    }
}

/// A request to seal content into a group's blob store.
#[derive(Debug, Clone)]
pub struct SealRequest<'a> {
    /// The cohort scope the content is written at — `community`,
    /// `affiliations`, `family`, `self`. Edge names the scope; **persist
    /// resolves the tier** and writes it on the row.
    pub cohort_scope: &'a str,
    /// The group the write belongs to, in persist's own convention for the
    /// slot: the community whose DEK seals it at `community` /
    /// `affiliations`; the **owner's** key id at `self` (the
    /// self-collective's identity, CC 3.3.6); the **family's** key id at
    /// `family`. `None` for a commons write. Persist refuses a `self` /
    /// `family` write without it, and the pointer carries it — which is how
    /// `BlobMeaning::project` names the self room and the family group
    /// (`FSD/CONTENT_TRANSFER.md` §6.2).
    pub community_key_id: Option<&'a str>,
    /// Who authored it — an AAD input.
    pub author_key_id: &'a str,
    /// When they asserted it — an AAD input, rendered to the stored form
    /// inside [`content_aad`].
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// Which blob within the row this is — an AAD input.
    pub field: ContentField,
    /// The content.
    pub plaintext: &'a [u8],
    /// What the content is, and what to call it — **sealed or clear by the
    /// resolved tier, which the store decides and the producer never does**
    /// (CIRISEdge#698, CC 3.3.13, `FSD/CONTENT_TRANSFER.md` §6.7.1).
    ///
    /// Encrypted tier: persist is handed NO media type (it would record the
    /// format beside sealed bytes), and the description is sealed under the
    /// bytes' own DEK into [`BlobPointer::sealed_descriptor`]. Plaintext tier:
    /// the format and codec ride the pointer in clear, and nothing is sealed.
    /// `None` for content whose dimension already says what it is (a chat
    /// body).
    pub description: Option<Description<'a>>,
}

/// A request to seal content that arrives as a READER, chunk by chunk
/// (CIRISEdge#744) — [`SealRequest`] with `declared_len` in place of the
/// plaintext slice. Every AAD input is the same, so the two seal paths bind
/// the same row the same way.
#[derive(Debug, Clone)]
pub struct StreamSealRequest<'a> {
    /// As [`SealRequest::cohort_scope`].
    pub cohort_scope: &'a str,
    /// As [`SealRequest::community_key_id`].
    pub community_key_id: Option<&'a str>,
    /// As [`SealRequest::author_key_id`] — an AAD input.
    pub author_key_id: &'a str,
    /// As [`SealRequest::asserted_at`] — an AAD input.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// As [`SealRequest::field`] — an AAD input.
    pub field: ContentField,
    /// **What the reader will yield, exactly.** A reader that yields any
    /// other count is [`GroupContentError::DeclaredLengthMismatch`] and seals
    /// nothing.
    pub declared_len: u64,
    /// As [`SealRequest::description`].
    pub description: Option<Description<'a>>,
}

impl<'a> StreamSealRequest<'a> {
    /// The streaming form of a slice request: the same binding, the slice's
    /// length declared.
    #[must_use]
    pub fn of(req: &SealRequest<'a>) -> Self {
        Self {
            cohort_scope: req.cohort_scope,
            community_key_id: req.community_key_id,
            author_key_id: req.author_key_id,
            asserted_at: req.asserted_at,
            field: req.field,
            declared_len: req.plaintext.len() as u64,
            description: req.description,
        }
    }

    /// The AAD a seal under this request binds — [`aad_for_seal`]'s inputs,
    /// through the same function.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        content_aad(self.author_key_id, self.asserted_at, self.field)
    }
}

/// The reader a streamed seal consumes (CIRISEdge#744): any tokio
/// `AsyncRead` that can be held across the store's await points.
pub type ContentReader<'r> = dyn tokio::io::AsyncRead + Unpin + Send + 'r;

/// **What a sealed blob is** — the `{name?, format, codec?}` object CC 3.3.13
/// seals beside encrypted bytes (CIRISEdge#698).
///
/// `name: None` is absent-by-author — a nameless file is a valid file — and
/// is never written as an empty string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description<'a> {
    /// What to call it, if anything.
    pub name: Option<&'a str>,
    /// The media type (`format` in the CC Source struct).
    pub format: &'a str,
    /// The codec, when the format alone does not say.
    pub codec: Option<&'a str>,
}

impl Description<'_> {
    /// The JCS bytes a sealed descriptor carries: `{name?, format, codec?}`,
    /// absent members omitted (never `null`, never `""`).
    ///
    /// # Errors
    /// Canonicalization failure, as prose.
    pub fn to_jcs(&self) -> Result<Vec<u8>, String> {
        let mut obj = serde_json::Map::new();
        if let Some(name) = self.name {
            obj.insert("name".to_owned(), serde_json::json!(name));
        }
        obj.insert("format".to_owned(), serde_json::json!(self.format));
        if let Some(codec) = self.codec {
            obj.insert("codec".to_owned(), serde_json::json!(codec));
        }
        ciris_persist::prelude::ceg_produce_canonicalize(&serde_json::Value::Object(obj))
            .map_err(|e| format!("canonicalize the descriptor: {e}"))
    }
}

/// The result of a seal — the pointer to put on the row, plus **who can
/// actually read it**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContent {
    /// Goes on the row in place of the content.
    pub pointer: BlobPointer,
    /// **The tier persist RESOLVED for this write**, returned by the door
    /// rather than inferred by us.
    ///
    /// Carrying it closes a bug this type shipped with: `fully_readable`
    /// used `epoch.is_some()` as "was this encrypted", and persist returns
    /// `epoch: None` for `InvisibleEncrypted` (`self` / `family`) — only
    /// `CommunityDek` carries one. So the false-green guard covered one of
    /// the two encrypted tiers and the other stayed armed.
    ///
    /// The authoritative value was in the result all along. Re-deriving a
    /// tier from the scope label also drops the directory axis persist
    /// applies (an infrastructure community resolves plaintext whatever its
    /// scope says), which is why the door returns this and why nothing here
    /// should compute it.
    pub tier: ciris_persist::federation::types::cohort_scope::CryptoTier,
    /// The community epoch this sealed under. `CommunityDek` only —
    /// **not** a tier discriminator; use [`Self::tier`].
    pub epoch: Option<u64>,
    /// Occurrence key_ids that hold a grant — the people who can read it.
    pub granted: Vec<String>,
    /// Occurrence key_ids **excluded fail-secure** for carrying no valid
    /// `encryption_pubkeys`.
    ///
    /// persist's own words: *a caller that ignores this is ignoring who
    /// cannot read what it just wrote.* It is never a plaintext fallback —
    /// those members simply will not be able to open this content, and the
    /// only place that fact exists is here. Surface it; do not log it and
    /// move on.
    pub excluded: Vec<String>,
}

impl SealedContent {
    /// `true` when every intended recipient can read this — **and at least
    /// one can**.
    ///
    /// The second clause is not pedantry; it was a real false green. An
    /// earlier version returned `self.excluded.is_empty()` alone, and at an
    /// encrypted tier where the roster resolved to NO occurrences that is
    /// trivially true: nobody was dropped because nobody was found. The
    /// content is then unreadable by everyone, including its author, and the
    /// API reported it as fine.
    ///
    /// Commons content has no grants and is readable by anyone, so the
    /// grant clause correctly does not apply to it.
    #[must_use]
    pub fn fully_readable(&self) -> bool {
        if !self.excluded.is_empty() {
            return false;
        }
        // Any ENCRYPTED tier with an empty grant set = nobody can read it.
        // `tier`, not `epoch`: `InvisibleEncrypted` is encrypted and carries
        // no epoch, and using the epoch left that tier unguarded.
        !(self.is_encrypted() && self.granted.is_empty())
    }

    /// Whether persist sealed this under a DEK at all.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        use ciris_persist::federation::types::cohort_scope::CryptoTier;
        matches!(
            self.tier,
            CryptoTier::InvisibleEncrypted | CryptoTier::CommunityDek
        )
    }

    /// `true` when this went to an encrypted tier and NOBODY holds a grant —
    /// content that is sealed and unreadable by every party including its
    /// author.
    ///
    /// Worth its own name because the remedy is specific and is not
    /// "retry": the community's members have no `encryption_pubkeys`
    /// registered, so there was nothing to wrap the DEK to.
    #[must_use]
    pub fn readable_by_nobody(&self) -> bool {
        self.is_encrypted() && self.granted.is_empty()
    }
}

/// A request to open content a row points at.
#[derive(Debug, Clone)]
pub struct OpenRequest<'a> {
    /// The pointer from the row.
    pub pointer: &'a BlobPointer,
    /// The row's author — an AAD input, read off the row, never guessed.
    pub author_key_id: &'a str,
    /// The row's instant — an AAD input.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// Who is reading — **the reader's OCCURRENCE key id, not their identity
    /// key id.**
    ///
    /// This trips everyone once. The DEK cascade wraps the content key per
    /// ACTIVE OCCURRENCE (`resolve_community_members` →
    /// `list_identity_occurrences_active` → `encryption_pubkeys`), and
    /// authorization is `community_dek_has_member_grant(community, epoch,
    /// viewer)` against those same occurrence ids. Passing an identity key
    /// here returns [`GroupContentError::NotGranted`] even for a full member
    /// of the room — a refusal that looks like a permissions problem and is
    /// actually a wrong-handle problem.
    ///
    /// [`SealedContent::granted`] lists exactly the ids that work.
    pub viewer_key_id: &'a str,
}

/// A request to re-describe content a row already points at — a rename
/// (CIRISEdge#702, `FSD/CONTENT_TRANSFER.md` §6.7.2).
///
/// Carries the prior row's binding, never a new one: the bytes stay sealed
/// under the claim's `(author, asserted_at)`, so that is what the store
/// authenticates them under before it touches the description.
#[derive(Debug, Clone)]
pub struct RedescribeRequest<'a> {
    /// The prior row's pointer.
    pub pointer: &'a BlobPointer,
    /// The prior row's author — an AAD input.
    pub author_key_id: &'a str,
    /// The prior row's instant — an AAD input.
    pub asserted_at: chrono::DateTime<chrono::Utc>,
    /// The new name; `None` makes the file nameless (never `""`).
    pub name: Option<&'a str>,
}

/// Seal and open group content.
///
/// Implementations wrap a `ciris_persist::Engine`; see
/// [`PersistGroupContentStore`](super::persist_store::PersistGroupContentStore).
#[async_trait::async_trait]
pub trait GroupContentStore: Send + Sync + 'static {
    /// Seal `plaintext` into the group's store and return the pointer to
    /// put on the row.
    ///
    /// # Errors
    /// Substrate failure, or a refusal the tier imposes.
    async fn seal(&self, req: SealRequest<'_>) -> Result<SealedContent, GroupContentError>;

    /// **Seal as a chunk DAG** (CC 5.3.3.1) — the door for content above the
    /// inline bound (`FSD/CONTENT_TRANSFER.md` §6.7, CIRISEdge#633).
    ///
    /// CC 2.6.1.3 bounds a signed envelope at 1 MiB, and persist's
    /// `DEFAULT_INLINE_BYTES_CAP` is the same number for the same reason —
    /// the signed thing is the sized thing. Above it the bytes cannot ride
    /// inside the row, so they become a sealed chunk DAG: per-chunk AEAD
    /// with position-bound AAD, a manifest pinning the chunk shas and the
    /// total size, and a read that can ask for a range instead of the whole.
    ///
    /// The returned [`SealedContent::pointer`] carries `stream_id: Some(..)`,
    /// and **its presence is the answer to "is this chunked"** — one fact,
    /// one member, no way for two to disagree. `content_sha256` is the
    /// MANIFEST's, which is what a reader opens and what a row cites.
    ///
    /// # This is a one-shot file, not a live stream
    ///
    /// The whole plaintext is written in one pass as `seq = 0..n` under a
    /// single stream epoch label. An appendable stream (A/V) manages its own
    /// epochs and counters against CC 5.3.3.1's `MAX_CHUNKS_PER_EPOCH`; a
    /// file does not, because it is complete when it is written.
    ///
    /// # Errors
    /// [`GroupContentError`], as [`Self::seal`].
    async fn seal_chunked(&self, req: SealRequest<'_>) -> Result<SealedContent, GroupContentError>;

    /// **Seal a chunk DAG from a reader, one chunk at a time**
    /// (CIRISEdge#744, `FSD/CONTENT_TRANSFER.md` §6.7.4) — the door
    /// [`Self::seal_chunked`] is a slice over, so there is one chunk-seal
    /// path.
    ///
    /// Reads [`CHUNK_BYTES`] at a time (filling each chunk fully unless the
    /// reader ends, so the chunk boundaries are exactly the slice path's),
    /// seals and writes each chunk as it arrives, and only after the LAST
    /// chunk lands and the count equals `req.declared_len` seals the stream
    /// (manifest + descriptor). Peak buffering is one chunk plus the
    /// substrate's own copies of the chunk it is sealing — never the content.
    ///
    /// # On refusal
    /// A count that is not `declared_len` is
    /// [`GroupContentError::DeclaredLengthMismatch`]; a reader error is
    /// [`GroupContentError::Reader`]. Either way — and on a chunk or seal
    /// refusal from the substrate — no pointer is returned, and the chunks
    /// the call wrote at an ENCRYPTED tier are evicted before it returns
    /// (their ciphertext shas are unique to this write, so nothing else can
    /// cite them). A plaintext-tier chunk is content-addressed and may be the
    /// very bytes another file's chunk names, so it is left in place —
    /// unreferenced by this call, and unannounced (a chunk announces nothing;
    /// only the seal does).
    ///
    /// # Errors
    /// As above, and [`GroupContentError`] as [`Self::seal`]. A store with
    /// no streaming door says so as [`GroupContentError::Substrate`].
    async fn seal_chunked_stream(
        &self,
        req: StreamSealRequest<'_>,
        reader: &mut ContentReader<'_>,
    ) -> Result<SealedContent, GroupContentError> {
        let _ = (req, reader);
        Err(GroupContentError::Substrate(
            "this store has no streaming chunk-seal door (CIRISEdge#744)".to_owned(),
        ))
    }

    /// Open content a row points at.
    ///
    /// # Errors
    /// [`GroupContentError::NotGranted`] when the viewer holds no key,
    /// [`GroupContentError::SealMismatch`] when the rebuilt AAD does not
    /// match, and the rest as documented.
    async fn open(&self, req: OpenRequest<'_>) -> Result<Vec<u8>, GroupContentError>;

    /// **Open a plaintext range** `[start, end_inclusive]` of the content a
    /// row points at (CIRISEdge#737, `FSD/CONTENT_TRANSFER.md` §6.7.3) —
    /// persist's `Engine::read_blob_range_as` under the same AAD as
    /// [`Self::open`].
    ///
    /// A chunk DAG opens only the chunks covering the range, each under its
    /// own envelope and position-bound AAD; an inline body is opened once
    /// and sliced. Persist clamps `end_inclusive` to the content's last byte
    /// (RFC 9110 §14.4), so a short answer means the range ran past the end;
    /// `start` at or past the end is [`GroupContentError::RangeNotSatisfiable`].
    ///
    /// # Errors
    /// As [`Self::open`], plus `RangeNotSatisfiable`; a store without a range
    /// door says so as [`GroupContentError::Substrate`].
    async fn open_range(
        &self,
        req: OpenRequest<'_>,
        start: u64,
        end_inclusive: u64,
    ) -> Result<Vec<u8>, GroupContentError> {
        let _ = (req, start, end_inclusive);
        Err(GroupContentError::Substrate(
            "this store has no range door (CIRISEdge#737)".to_owned(),
        ))
    }

    /// **The chunk layout of a sealed DAG** the pointer names (CIRISEdge#737)
    /// — persist's `Engine::open_sealed_manifest_as` under the row's AAD:
    /// the manifest's chunks in `seq` order with their plaintext sizes, as
    /// [`ChunkLayout`]. Authorized as [`Self::open`] is; a pointer that names
    /// no stream, or a plaintext-tier DAG (a clear v1 manifest, which the
    /// range door assembles without a layout), is refused by name.
    ///
    /// # Errors
    /// As [`Self::open`]; a store without the door says so as
    /// [`GroupContentError::Substrate`].
    async fn layout(&self, req: OpenRequest<'_>) -> Result<ChunkLayout, GroupContentError> {
        let _ = req;
        Err(GroupContentError::Substrate(
            "this store has no sealed-manifest door (CIRISEdge#737)".to_owned(),
        ))
    }

    /// **Open the sealed descriptor a pointer carries** (CIRISEdge#698) —
    /// the JCS `{name?, format, codec?}` bytes, under the same grant as the
    /// bytes it describes.
    ///
    /// Takes the same [`OpenRequest`] as [`Self::open`]: the descriptor's own
    /// AAD binds it to its BLOB (the address digest), and the REFERENCING
    /// ROW's AAD — rebuilt from `req` exactly as [`aad_for_open`] does — must
    /// authenticate the blob before the descriptor opens (persist v51.0.0,
    /// the #923 amendment). A pointer transplanted onto another row, or
    /// moved to another blob, is refused at the door, after authorization.
    ///
    /// # Errors
    /// As [`Self::open`]; a store without a descriptor door says so as
    /// [`GroupContentError::Substrate`].
    async fn open_descriptor(&self, req: OpenRequest<'_>) -> Result<Vec<u8>, GroupContentError> {
        let _ = req;
        Err(GroupContentError::Substrate(
            "this store has no sealed-descriptor door (CIRISEdge#698)".to_owned(),
        ))
    }

    /// **Give the same bytes a new name** (CIRISEdge#702, §6.7.2) — the
    /// pointer a renaming row carries: the SAME blob, the description
    /// rewritten by the tier the pointer records.
    ///
    /// Encrypted tier: the current description is opened as this node (the
    /// blob authenticated under the prior row's AAD first), its `name`
    /// replaced, and `{name?, format, codec?}` sealed again under the bytes'
    /// own DEK; a pre-#698 pointer's clear format and codec move inside the
    /// seal. Plaintext tier: the pointer is returned with its clear format,
    /// and the name is the row's to carry in clear. The store decides, as it
    /// does for a write; the producer never handles the descriptor's bytes.
    ///
    /// # Errors
    /// As [`Self::open_descriptor`]; a store without a descriptor door says
    /// so as [`GroupContentError::Substrate`].
    async fn redescribe(
        &self,
        req: RedescribeRequest<'_>,
    ) -> Result<BlobPointer, GroupContentError> {
        let _ = req;
        Err(GroupContentError::Substrate(
            "this store has no re-describe door (CIRISEdge#702)".to_owned(),
        ))
    }

    /// **Who holds the bytes a pointer names, and who can open them**
    /// (persist v51.1.0 `Engine::blob_custody`, CIRISPersist#942) — tier,
    /// size, held-here, access per person, announced holders, and whether
    /// copies elsewhere are observable at all (never for `self`/`family`).
    ///
    /// About the BLOB, not a row: no row AAD is presented, and nothing about
    /// the description is released. Authorized as a read of the bytes is —
    /// a viewer who cannot open them is [`GroupContentError::NotGranted`].
    ///
    /// # Errors
    /// As [`Self::open`]; a store without a custody door says so as
    /// [`GroupContentError::Substrate`].
    async fn custody(
        &self,
        pointer: &BlobPointer,
        viewer_key_id: &str,
    ) -> Result<ciris_persist::federation::blob_custody::BlobCustody, GroupContentError> {
        let _ = (pointer, viewer_key_id);
        Err(GroupContentError::Substrate(
            "this store has no custody door (CIRISPersist#942)".to_owned(),
        ))
    }

    /// **The per-stream transparency log this store's chunk DAGs live in**
    /// (CIRISEdge#738, CC 5.3.3.3 / 5.3.3.6) — where `files::publish` puts a
    /// file stream's STH and where a file's delivery receipts are read.
    /// `None` (the default) for a store with no stream log: its files publish
    /// no STH and cannot be receipted, which `FileRow::received_by` reports as
    /// an empty list, never a failure.
    fn stream_log(&self) -> Option<std::sync::Arc<dyn crate::receipts::StreamLog>> {
        None
    }
}

/// Build the AAD for a seal request. Exposed so a test — or a second
/// implementation — cannot reach for a different spelling.
#[must_use]
pub fn aad_for_seal(req: &SealRequest<'_>) -> Vec<u8> {
    content_aad(req.author_key_id, req.asserted_at, req.field)
}

/// The plaintext bytes edge puts in one chunk of a DAG (CIRISEdge#633).
///
/// Not a CC constant — CC bounds the ENVELOPE (2.6.1.3) and the chunk COUNT
/// per epoch (5.3.3.1's `MAX_CHUNKS_PER_EPOCH = 2²⁴`), and leaves the chunk
/// size to the producer. 256 KiB is chosen for range granularity: a reader
/// asking for a few seconds of a video should not pull a megabyte, and at
/// this size the per-epoch ceiling is still 4 TiB of one stream.
pub const CHUNK_BYTES: usize = 256 * 1024;

/// Build the AAD for an open request.
///
/// **The same inputs as [`aad_for_seal`], read off the row.** That symmetry
/// is the whole contract: if a reader can rebuild these three values from
/// the row, the content opens; if it cannot, no permission can rescue it.
#[must_use]
pub fn aad_for_open(req: &OpenRequest<'_>) -> Vec<u8> {
    content_aad(
        req.author_key_id,
        req.asserted_at,
        req.pointer.content_field,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_767_225_296, 789_000_000).expect("ts")
    }

    fn pointer(field: ContentField) -> BlobPointer {
        BlobPointer {
            community_key_id: "community-1".into(),
            tier: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
            content_sha256: "ab".repeat(32),
            content_field: field,
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

    /// The load-bearing symmetry: what the writer sealed under and what the
    /// reader rebuilds are the same three values, by construction.
    #[test]
    fn seal_and_open_derive_the_same_aad_from_the_same_row() {
        let seal = SealRequest {
            cohort_scope: "community",
            community_key_id: Some("community-1"),
            author_key_id: "alice",
            asserted_at: now(),
            field: ContentField::Body,
            plaintext: b"hello",
            description: None,
        };
        let p = pointer(ContentField::Body);
        let open = OpenRequest {
            pointer: &p,
            author_key_id: "alice",
            asserted_at: now(),
            viewer_key_id: "bob",
        };
        assert_eq!(
            aad_for_seal(&seal),
            aad_for_open(&open),
            "a reader rebuilding from the row must reach the writer's binding",
        );
    }

    /// The viewer is NOT an AAD input — otherwise content would open only
    /// for the person who wrote it, which is the opposite of sharing.
    #[test]
    fn who_is_reading_does_not_change_the_binding() {
        let p = pointer(ContentField::Body);
        let a = OpenRequest {
            pointer: &p,
            author_key_id: "alice",
            asserted_at: now(),
            viewer_key_id: "bob",
        };
        let b = OpenRequest {
            viewer_key_id: "carol",
            ..a.clone()
        };
        assert_eq!(aad_for_open(&a), aad_for_open(&b));
    }

    /// Two blobs on one row are not exchangeable, through the store API as
    /// well as through the raw preimage.
    #[test]
    fn a_pointer_to_another_field_rebuilds_a_different_binding() {
        let body = pointer(ContentField::Body);
        let att = pointer(ContentField::Attachment);
        let mk = |p: &BlobPointer| {
            aad_for_open(&OpenRequest {
                pointer: p,
                author_key_id: "alice",
                asserted_at: now(),
                viewer_key_id: "bob",
            })
        };
        assert_ne!(mk(&body), mk(&att));
    }

    /// The false green this API shipped with for exactly one commit: an
    /// encrypted seal that granted to NOBODY reported itself fully readable,
    /// because no one was excluded — no one was found.
    #[test]
    fn an_encrypted_seal_that_granted_to_nobody_is_not_fully_readable() {
        let orphan = SealedContent {
            pointer: pointer(ContentField::Body),
            // CommunityDek AND InvisibleEncrypted must both be caught; the
            // epoch-based guard missed the latter entirely.
            tier: ciris_persist::federation::types::cohort_scope::CryptoTier::CommunityDek,
            epoch: Some(7),
            granted: vec![],
            excluded: vec![],
        };
        assert!(
            !orphan.fully_readable(),
            "nobody was excluded because nobody was FOUND — the content is \
             unreadable by everyone including its author",
        );
        assert!(orphan.readable_by_nobody());

        // Commons content has no grants and is readable by all, so the same
        // emptiness must NOT read as a failure there.
        let commons = SealedContent {
            tier: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
            epoch: None,
            ..orphan
        };
        assert!(commons.fully_readable());
        assert!(!commons.readable_by_nobody());
    }

    #[test]
    fn fully_readable_is_false_when_anyone_was_excluded() {
        let base = SealedContent {
            pointer: pointer(ContentField::Body),
            tier: ciris_persist::federation::types::cohort_scope::CryptoTier::CommunityDek,
            epoch: Some(3),
            granted: vec!["alice".into(), "bob".into()],
            excluded: vec![],
        };
        assert!(base.fully_readable());

        let partial = SealedContent {
            excluded: vec!["carol-no-pubkey".into()],
            ..base
        };
        assert!(
            !partial.fully_readable(),
            "a member excluded at write time cannot read this, and the only \
             place that fact exists is the seal result",
        );
    }
}
