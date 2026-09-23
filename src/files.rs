//! **Files, at every cohort — one door** (CIRISEdge#646,
//! `FSD/CONTENT_TRANSFER.md` §9).
//!
//! A file is a row that cites bytes. Everything that makes it reach the
//! right people already exists — persist seals and resolves the tier, the
//! pointer names the key plane, the crossing places the row in its cohort,
//! the puller fetches, the store gate admits — but until now a host had to
//! compose those five itself, and the composition differs per cohort in
//! ways that are easy to get wrong and silent when wrong: a `self` row
//! carries no cohort target while a `family` row must carry
//! `family_key_id`; a community file widens to the room while a self file
//! widens to the owner's devices; persist's group slot takes the community
//! at `community` and the OWNER at `self`.
//!
//! Getting one of those wrong does not fail — it produces a file that is
//! correct on the writer's node and unreachable from anywhere else, which
//! is the exact shape this arc has been removing since CIRISEdge#646.
//!
//! So: one call, any room.
//!
//! ```ignore
//! let published = files::publish(
//!     &*dir, &store, signers,
//!     &FileWrite {
//!         room: &self_room::room(&owner),   // or ScopeRoom::community(room)
//!         bytes: &jpeg,
//!         media_type: "image/jpeg",
//!         filename: Some("boat.jpg"),
//!         asserted_at: Utc::now(),
//!     },
//! ).await?;
//! ```
//!
//! The reader is the twin: [`in_room`] lists what a room holds and
//! [`FileRow::open`] resolves the bytes — with **row-held / bytes-absent**
//! as a first-class state ([`UnopenedReason::NotFetched`]), which is what a
//! drive shows as "on another device" (CIRISServer#615 §3).
//!
//! # Commons files are a different act
//!
//! `publish`-to-the-world is its own verb by design
//! ([`attestation_bind::publish`](crate::replication::attestation_bind::publish)):
//! "federation" reads like *the mesh* and means *anyone at all, in the
//! clear*. This door takes a room, so it cannot be the thing that
//! accidentally publishes a family photo.

use chrono::{DateTime, Utc};

use crate::chat::UnopenedReason;
use crate::group_content::{BlobPointer, ContentField, GroupContentStore, SealRequest};
use crate::replication::attestation_bind::{share, CrossingBasis, Shared, Signers};
use crate::scope_room::ScopeRoom;
use ciris_persist::federation::types::cohort_scope::CryptoTier;
use ciris_persist::federation::{Attestation, FederationDirectory};

/// The dimension a file row carries. Distinct from `chat:message:v1` so a
/// drive can enumerate files without walking every content row, and so a
/// chat client does not render a 4 GB video as a message body.
pub const FILE_DIMENSION: &str = "file:v1";

/// The envelope member carrying the file's name, when it has one.
pub const FIELD_FILENAME: &str = "filename";

/// A file to write into a room.
#[derive(Debug, Clone)]
pub struct FileWrite<'a> {
    /// Which room's members get it. The room decides the seal's tier, the
    /// row's cohort target and the crossing — all three from one value.
    pub room: &'a ScopeRoom,
    /// The plaintext. Sealed before it is stored; the bytes never ride the
    /// row.
    pub bytes: &'a [u8],
    /// What it is, so a reader knows before opening it.
    pub media_type: &'a str,
    /// What to call it. Optional: a file is identified by its sha, and a
    /// name is a convenience for people.
    pub filename: Option<&'a str>,
    /// When the author asserts it — an AAD input, so it is not free.
    pub asserted_at: DateTime<Utc>,
}

/// Why a file was not published. A door that returns one string for
/// "persist refused the seal" and "nobody can read this" makes the caller
/// parse prose to find out which; each arm here has a different remedy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FileError {
    /// The seal itself was refused.
    #[error("seal into {room}: {detail}")]
    Seal {
        /// The room the write was for.
        room: String,
        /// Persist's refusal.
        detail: String,
    },
    /// **Sealed and readable by nobody** — an encrypted tier resolved NO
    /// grantable occurrence, so the bytes are unopenable by every party
    /// including their author (`SealedContent::readable_by_nobody`).
    ///
    /// Refused rather than reported as success: the row would cross, the
    /// bytes would replicate, and every reader — the author's own second
    /// device first — would read `NotGranted` forever. The remedy is an
    /// occurrence with content-KEM keys (CC 3.3.6.1), not a retry.
    #[error(
        "{room}: sealed and readable by NOBODY — no grantable occurrence resolved          (excluded: {excluded:?}); publish refused rather than crossing bytes no one can open"
    )]
    ReadableByNobody {
        /// The room the write was for.
        room: String,
        /// Occurrences persist excluded fail-secure, if any.
        excluded: Vec<String>,
    },
    /// The authored row could not be stored locally.
    #[error("author {attestation_id}: {detail}")]
    Author {
        /// The row's id.
        attestation_id: String,
        /// The store's error.
        detail: String,
    },
    /// The crossing into the room's audience failed, so the row exists here
    /// and nowhere else.
    #[error("cross into {room}: {detail}")]
    Cross {
        /// The room the write was for.
        room: String,
        /// The crossing's error.
        detail: String,
    },
    /// The row was built but could not be signed or canonicalized.
    #[error("build the file row: {0}")]
    Row(String),
    /// The drive query failed in the substrate.
    #[error("list files in {room}: {detail}")]
    Drive {
        /// The room asked for.
        room: String,
        /// The substrate's error.
        detail: String,
    },
    /// **The §4.3 read gate cannot serve a targeted room** — its `community`
    /// and `family` arms are mutually unsatisfiable with AV-84 on the
    /// attestation plane (CIRISPersist#893): the write rule makes
    /// `attested_key_id` the row's PRODUCER, the read gate compares that
    /// column against the caller's room set, and the intersection is empty
    /// by construction, so no member can read their own room's rows.
    ///
    /// Refused rather than returned empty: a drive that silently shows
    /// nothing is indistinguishable from a room with no files. Lifts when
    /// CIRISPersist#893 lands.
    #[error(
        "{room}: the §4.3 read gate cannot serve a targeted room yet — its community/family \
         arms are unsatisfiable with AV-84 (CIRISPersist#893), so this would be silently empty"
    )]
    DriveGateUnavailable {
        /// The room asked for.
        room: String,
    },
    /// **Bigger than one envelope, with no chunk door to take it.**
    ///
    /// Unreachable from [`publish`] since CIRISEdge#633: content above CC
    /// 2.6.1.3's 1 MiB bound is now sealed as a chunk DAG rather than
    /// refused. Kept because a `GroupContentStore` that implements only
    /// `seal` can still say so by name, which is a better answer than an
    /// argument error from a layer the caller never called.
    #[error(
        "{size} bytes exceeds the {cap}-byte inline bound (CC 2.6.1.3) and this store has no \
         chunk-DAG door; `publish` seals content above the bound as a DAG (CIRISEdge#633)"
    )]
    TooLargeForInline {
        /// The file's size.
        size: usize,
        /// The inline bound (persist's `DEFAULT_INLINE_BYTES_CAP`).
        cap: usize,
    },
}

/// What [`publish`] did.
#[derive(Debug, Clone)]
pub struct PublishedFile {
    /// The AUTHORED row (`self`, local tier) — the producer's own copy.
    pub row: Attestation,
    /// The pointer at the sealed bytes: the key plane (tier, group, epoch).
    pub pointer: BlobPointer,
    /// The tier persist RESOLVED for this write — never inferred here.
    pub tier: CryptoTier,
    /// Where the crossing placed the row that others receive.
    pub shared: Shared,
    /// Occurrence key ids that hold a grant — who can open it. Empty for
    /// commons-tier content, which needs none.
    pub granted: Vec<String>,
    /// Whether the crossing actually placed the row (`Shared::Placed` /
    /// `AlreadyThere`). `false` means it PARKED awaiting the actor's
    /// signature: the file is authored locally and has reached nobody — it
    /// is not in the federation stream, so it is invisible to every other
    /// device AND to [`in_room`] until the actor signs. Recoverable, not a
    /// failure, which is why it is a field and not an error; but a caller
    /// that never reads it would believe the file shipped.
    pub crossed: bool,
    /// Occurrence key ids persist excluded **fail-secure** for carrying no
    /// usable encryption keys. Non-empty means a PARTIAL readability loss:
    /// the file crossed, and those parties cannot open it. Surfaced rather
    /// than dropped — a caller that does not look still gets the file, but a
    /// caller that does can say who is missing it and why.
    pub excluded: Vec<String>,
}

/// **Write a file into a room** — seal, author, cross.
///
/// 1. **Seal** at the room's cohort. Persist resolves the tier
///    (`InvisibleEncrypted` for self/family, the room DEK for a community)
///    and returns it; nothing here computes a tier.
/// 2. **Author** the row: dimension [`FILE_DIMENSION`], the pointer under
///    `content`, the sha cited in `evidence_refs` (CIRISEdge#646 — the
///    citation is what persist's index and the revocation walk find the row
///    by), and the room's cohort target when it has one.
/// 3. **Cross** it to the room's audience ([`ScopeRoom::widen_to`]).
///    Including for a self file: an authored row is local-tier and
///    replicates nowhere until it crosses, so skipping this is precisely
///    "correct here, invisible everywhere else".
///
/// Content above the 1 MiB inline bound is sealed as a **chunk DAG** rather
/// than refused (CIRISEdge#633, §6.7): same request, same `SealedContent`,
/// and the pointer's `stream_id` tells a reader which shape it got.
/// Sealed-and-readable-by-nobody is **refused** (`FileError::ReadableByNobody`):
/// crossing bytes no party can open — the author's own second device
/// included — is a success report for a permanent `NotGranted`. A PARTIAL
/// loss is not refused (one member without content-KEM keys must not block
/// everyone else, which is persist's fail-secure exclusion working as
/// designed) but it is reported, in [`PublishedFile::excluded`].
///
/// # Errors
/// [`FileError`], naming which of seal / readability / author / crossing
/// failed.
pub async fn publish(
    directory: &dyn FederationDirectory,
    store: &dyn GroupContentStore,
    signers: Signers<'_>,
    write: &FileWrite<'_>,
) -> Result<PublishedFile, FileError> {
    let author_key_id = signers.node.key_id.clone();
    // Persist's group slot per cohort: the community at `community`, the
    // OWNER at `self`, the family at `family` — which is exactly the id the
    // room names, so the seal and the projector cannot disagree about which
    // group these bytes belong to (`FSD/CONTENT_TRANSFER.md` §6.2).
    // **Shape follows size at exactly one boundary** (§6.7). CC 2.6.1.3
    // bounds a signed envelope at 1 MiB and persist's inline cap is the same
    // number for the same reason, so above it the bytes cannot ride inside
    // the row and become a sealed chunk DAG (CC 5.3.3.1). Both doors take
    // the same request and return the same `SealedContent`; the pointer's
    // `stream_id` is what tells a reader which it got.
    let req = SealRequest {
        cohort_scope: write.room.row_scope_token(),
        community_key_id: Some(write.room.content_group_id()),
        author_key_id: &author_key_id,
        asserted_at: write.asserted_at,
        field: ContentField::Body,
        plaintext: write.bytes,
        media_type: Some(write.media_type),
    };
    let chunked = write.bytes.len() > ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP;
    let sealed = if chunked {
        store.seal_chunked(req).await
    } else {
        store.seal(req).await
    }
    .map_err(|e| FileError::Seal {
        room: write.room.to_string(),
        detail: e.to_string(),
    })?;

    // Checked BEFORE the row is authored, so a file nobody can open never
    // becomes a row somebody has to revoke.
    if sealed.readable_by_nobody() {
        return Err(FileError::ReadableByNobody {
            room: write.room.to_string(),
            excluded: sealed.excluded.clone(),
        });
    }
    if !sealed.excluded.is_empty() {
        tracing::warn!(
            room = %write.room,
            granted = sealed.granted.len(),
            excluded = ?sealed.excluded,
            "file sealed with PARTIAL readability — these occurrences carry no usable \
             content-KEM keys and will read NotGranted (CC 3.3.6.1)"
        );
    }

    let row = file_row(signers.node, write, &sealed.pointer)
        .await
        .map_err(FileError::Row)?;
    directory
        .put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .map_err(|e| FileError::Author {
            attestation_id: row.attestation_id.clone(),
            detail: e.to_string(),
        })?;

    let crossing = share(
        directory,
        &row,
        write.room.widen_to(),
        CrossingBasis::ProducerAuthority,
        signers,
    )
    .await
    .map_err(|e| FileError::Cross {
        room: write.room.to_string(),
        detail: e,
    })?;

    let crossed = matches!(
        crossing.shared,
        Shared::Placed { .. } | Shared::AlreadyThere { .. }
    );
    if !crossed {
        // E5: a local-tier row is excluded from the federation stream, so a
        // parked crossing means this file has reached NOBODY — not the
        // owner's other devices, not this node's own drive listing.
        tracing::warn!(
            room = %write.room,
            attestation_id = %row.attestation_id,
            shared = ?crossing.shared,
            "file authored but NOT crossed — it is local-tier, so it is in no federation \
             stream and no drive until the actor signs (FSD/CONTENT_TRANSFER.md §6.9)"
        );
    }

    Ok(PublishedFile {
        row,
        pointer: sealed.pointer,
        tier: sealed.tier,
        shared: crossing.shared,
        crossed,
        granted: sealed.granted,
        excluded: sealed.excluded,
    })
}

/// The authored row: the same binding ceremony every edge producer uses,
/// with the file's members.
async fn file_row(
    author: &crate::identity::LocalSigner,
    write: &FileWrite<'_>,
    pointer: &BlobPointer,
) -> Result<Attestation, String> {
    use crate::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };
    use sha2::{Digest as _, Sha256};

    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(write.asserted_at);
    let mut envelope = serde_json::json!({
        "dimension": FILE_DIMENSION,
        crate::chat::FIELD_CONTENT: pointer,
    });
    if let Some(field) = write.room.cohort_target_field() {
        envelope[field] = serde_json::json!(write.room.content_group_id());
    }
    if let Some(name) = write.filename {
        envelope[FIELD_FILENAME] = serde_json::json!(name);
    }
    // Every producer cites (CIRISEdge#646): the row is found BY the bytes it
    // references, and an uncited row leaves the revocation walk's known set
    // incomplete.
    crate::chat::cite_evidence(&mut envelope, &pointer.content_sha256);

    let attestation_id = {
        let mut h = Sha256::new();
        h.update(FILE_DIMENSION.as_bytes());
        h.update(write.room.table_group_id().as_bytes());
        h.update(author_key_id.as_bytes());
        h.update(render_signed_instant(asserted_at).as_bytes());
        h.update(
            ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
                .map_err(|e| format!("canonicalize: {e}"))?,
        );
        format!("file-{}", &hex::encode(h.finalize())[..32])
    };
    let subjects = vec![author_key_id.to_owned()];
    // Authored at `self`, local tier — the producer's own copy. The audience
    // is decided by the crossing, never by the authored row.
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: author_key_id,
            attestation_type: "scores",
            attested_key_id: author_key_id,
            subject_key_ids: &subjects,
            cohort_scope: ciris_persist::federation::types::cohort_scope::SELF,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(author, &canonical, FILE_DIMENSION).await?;
    Ok(Attestation {
        attestation_id,
        attesting_key_id: author_key_id.to_owned(),
        attested_key_id: author_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: author_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: ciris_persist::federation::types::cohort_scope::SELF.to_owned(),
        tier: ciris_persist::federation::types::attestation_tier::LOCAL.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

/// A file as a reader sees it, before any byte moves.
///
/// Recognising the row is synchronous and total; opening it is neither. A
/// drive listing a thousand files pays for none of their bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// The row's id.
    pub attestation_id: String,
    /// Who wrote it.
    pub attesting_key_id: String,
    /// When.
    pub asserted_at: DateTime<Utc>,
    /// Its name, if it carries one.
    pub filename: Option<String>,
    /// What it is.
    pub media_type: Option<String>,
    /// The pointer at the bytes — the key plane.
    pub pointer: BlobPointer,
}

impl FileRow {
    /// Recognise a file row. `None` for anything else — a chat message, a
    /// key package, a row that cites no bytes.
    #[must_use]
    pub fn from_row(row: &Attestation) -> Option<Self> {
        let env = &row.attestation_envelope;
        if env.get("dimension").and_then(serde_json::Value::as_str) != Some(FILE_DIMENSION) {
            return None;
        }
        let pointer: BlobPointer =
            serde_json::from_value(env.get(crate::chat::FIELD_CONTENT)?.clone()).ok()?;
        Some(Self {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            asserted_at: row.asserted_at,
            filename: env
                .get(FIELD_FILENAME)
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            media_type: pointer.media_type.clone(),
            pointer,
        })
    }

    /// The bytes, or **why not** — `NotFetched` while the row is held and
    /// the bytes are not (the drive's "on another device"), `NotGranted`
    /// when this viewer's key does not open them. Two states, never one
    /// string (CIRISEdge#601).
    pub async fn open(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<Vec<u8>, UnopenedReason> {
        store
            .open(crate::group_content::OpenRequest {
                pointer: &self.pointer,
                author_key_id: &self.attesting_key_id,
                asserted_at: self.asserted_at,
                viewer_key_id,
            })
            .await
            .map_err(|e| UnopenedReason::from_store_error(&e))
    }
}

/// How many queries [`in_room`] will issue for one call before handing back
/// what it has.
///
/// A pure bound on **work per call**, not on correctness: reaching it is
/// reported in [`DrivePage::resume`] like any other partial page, so a
/// caller loops rather than mistaking it for the end of the room. It exists
/// because a node holding millions of rows this caller may see but this
/// room does not own would otherwise make one listing walk for minutes.
const MAX_LISTING_PAGES: usize = 64;

/// The largest backing query [`in_room`] will issue at once.
///
/// `limit` is the CALLER's number and may be large or accidental; the
/// backing page is edge's, and forwarding the former as the latter lets one
/// call ask the substrate to materialize an arbitrary result set. The chunk
/// is `min(still wanted, this)` — never more than is wanted, so the whole
/// chunk is always consumed and the resume cursor stays exact, and never
/// more than this, so no single query is unbounded.
const MAX_BACKING_PAGE: usize = 256;

/// One page of a drive listing.
///
/// `resume` is the whole contract: **`None` means the room is exhausted**,
/// and anything else means there is more — whether the walk stopped because
/// `limit` was reached or because it spent its page budget. A caller that
/// wants everything loops until `resume` is `None`; a caller that wanted one
/// screenful ignores it. Neither can mistake a short page for a small drive,
/// which a bare `Vec` could not express.
#[derive(Debug, Clone)]
#[must_use = "a drive page may be partial — check `resume` before treating it as the whole room"]
pub struct DrivePage {
    /// The files, newest first.
    pub files: Vec<FileRow>,
    /// Where to continue from, or `None` when nothing is left.
    pub resume: Option<ciris_persist::ceg::AttestationCursor>,
}

/// **The drive read** — up to `limit` of this room's file rows, newest
/// first, resumable (CIRISServer#615 §3).
///
/// Runs on persist's **gated** reader door (`Engine::list_attestations`,
/// CIRISPersist#891 / v46.4.0): the `cohort_scope` and `dimension_exact`
/// axes select server-side, and the §4.3 caller-visibility predicate runs
/// in the same query. Two things follow, and both are improvements on what
/// v29.5.0 shipped:
///
/// - **The limit bounds the answer, not the plane.** Before this, the only
///   door was `list_attestations_since` — persist's *replication* cursor —
///   so edge filtered client-side and `limit` bounded a global page; on a
///   busy node a drive showed too few files, and later pages were invisible
///   permanently rather than merely late.
/// - **The caller is gated by the substrate**, in one spelling, rather than
///   by a precondition the host had to remember. A caller naming another
///   person's identity gets their rows refused by the gate, not filtered by
///   a predicate edge wrote twice.
///
/// The filter can never WIDEN: persist composes the gate after it, so a
/// filter naming a room the caller is not in returns nothing (their I142).
///
/// Pass `after: None` for the newest page, then feed back
/// [`DrivePage::resume`] until it is `None`. Every page is consumed whole —
/// the query asks for exactly what is still wanted — so a resumed listing
/// never steps over a file.
///
/// # Targeted rooms are refused until CIRISPersist#893
///
/// `community` and `family` return [`FileError::DriveGateUnavailable`]. Not
/// a limitation of this function — the §4.3 gate's two targeted arms are
/// mutually unsatisfiable with AV-84 on the attestation plane: a
/// community/family row must name its PRODUCER in `attested_key_id` (the
/// write rule), and the read gate compares that column against the caller's
/// room set, so no member can read their own room's rows. Edge refuses
/// rather than returning the empty list the gate produces, because a
/// silently empty drive is the failure this whole arc exists to remove, and
/// rather than falling back to the ungated cursor, because a function that
/// takes a caller must not hand back rows it did not gate.
///
/// # Errors
/// [`FileError::Drive`] from the substrate;
/// [`FileError::DriveGateUnavailable`] for a targeted room.
pub async fn in_room(
    engine: &ciris_persist::Engine,
    room: &ScopeRoom,
    caller_occurrence_key_id: &str,
    limit: usize,
    after: Option<ciris_persist::ceg::AttestationCursor>,
) -> Result<DrivePage, FileError> {
    use ciris_persist::ceg::AttestationFilter;
    use ciris_persist::scope::CallerScope;

    if room.cohort_target_field().is_some() {
        return Err(FileError::DriveGateUnavailable {
            room: room.to_string(),
        });
    }

    let caller = caller_occurrence_key_id.to_owned();
    let admission = ciris_persist::scope::admission::build_caller_admission(engine, &caller)
        .await
        .map_err(|e| FileError::Drive {
            room: room.to_string(),
            detail: e.to_string(),
        })?;
    let scope = CallerScope::Authenticated { admission };

    let mut files: Vec<FileRow> = Vec::new();
    let mut cursor = after;
    for _ in 0..MAX_LISTING_PAGES {
        // Ask for EXACTLY what is still wanted, so the whole page is always
        // consumed and `next_cursor` means what it says.
        //
        // The alternative — a fixed 256-row page, stopping mid-page once
        // `limit` matches are collected — resumes from the END of a page
        // whose tail was never returned, so every remaining match in it is
        // skipped for good. Edge will not mint persist's cursor to work
        // around that either: a cursor edge builds is a second spelling of
        // persist's ordering, and it would page wrongly and silently the day
        // that ordering changed. Only cursors persist handed us are passed
        // back.
        let need = limit.saturating_sub(files.len());
        if need == 0 {
            break;
        }
        // Bounded BOTH ways: never more than is still wanted (so the page is
        // consumed whole and `next_cursor` is exact), never more than edge's
        // own page (so a huge `limit` cannot turn one call into an unbounded
        // scan).
        let chunk = need.min(MAX_BACKING_PAGE);
        let page = engine
            .list_attestations(
                {
                    // `#[non_exhaustive]` by design (a new axis must not break
                    // old consumers), so it is built from the default rather
                    // than a struct literal.
                    let mut f = AttestationFilter::default();
                    f.cohort_scope = Some(room.row_scope_token().to_owned());
                    f.dimension_exact = Some(FILE_DIMENSION.to_owned());
                    f
                },
                cursor,
                i64::try_from(chunk).unwrap_or(i64::MAX),
                scope.clone(),
            )
            .await
            .map_err(|e| FileError::Drive {
                room: room.to_string(),
                detail: e.to_string(),
            })?;
        for row in &page.items {
            // The gate answered "may this caller see it"; this answers "is it
            // THIS room's" — the pointer's owner slot for a self room. Kept
            // after the gate rather than trusted instead of it. It can DROP
            // rows, which is why a page yielding nothing is not evidence the
            // room is empty.
            if let Some(file) = belongs_to(room, row) {
                files.push(file);
            }
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(DrivePage {
        files,
        resume: cursor,
    })
}

/// Is `row` one of `room`'s files? See [`in_room`] for why the identity
/// check differs per kind.
fn belongs_to(room: &ScopeRoom, row: &Attestation) -> Option<FileRow> {
    if row.cohort_scope != room.row_scope_token() {
        return None;
    }
    let file = FileRow::from_row(row)?;
    let names_this_room = match room.cohort_target_field() {
        Some(field) => {
            row.attestation_envelope
                .get(field)
                .and_then(serde_json::Value::as_str)
                == Some(room.content_group_id())
        }
        // Self: the pointer's group slot carries the owner. Absent ⇒ skipped,
        // never shown — an unattributable self row must not appear in
        // somebody's drive.
        None => file.pointer.community_key_id == room.content_group_id(),
    };
    names_this_room.then_some(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pointer(sha: &str) -> BlobPointer {
        serde_json::from_value(serde_json::json!({
            "community_key_id": "alice-fed",
            "tier": "invisible_encrypted",
            "content_sha256": sha,
            "content_field": "body",
            "media_type": "image/jpeg",
        }))
        .expect("pointer")
    }

    fn row_with(dimension: &str, env: serde_json::Value) -> Attestation {
        let mut row = crate::blob_swarm::meaning::fixture::bare_row(
            ciris_persist::federation::types::cohort_scope::SELF,
        );
        row.attestation_envelope = env;
        row.attestation_envelope["dimension"] = serde_json::json!(dimension);
        row
    }

    #[test]
    fn a_file_row_is_recognised_by_its_dimension_and_its_pointer() {
        let sha = "aa".repeat(32);
        let row = row_with(
            FILE_DIMENSION,
            serde_json::json!({
                crate::chat::FIELD_CONTENT: pointer(&sha),
                FIELD_FILENAME: "boat.jpg",
            }),
        );
        let f = FileRow::from_row(&row).expect("a file row");
        assert_eq!(f.filename.as_deref(), Some("boat.jpg"));
        assert_eq!(f.media_type.as_deref(), Some("image/jpeg"));
        assert_eq!(f.pointer.content_sha256, sha);

        // A chat message is not a file, and a file row with no pointer is
        // not one either — both are `None`, never a half-built FileRow.
        assert!(FileRow::from_row(&row_with(
            crate::chat::CHAT_MESSAGE_DIMENSION,
            serde_json::json!({ crate::chat::FIELD_CONTENT: pointer(&sha) })
        ))
        .is_none());
        assert!(FileRow::from_row(&row_with(FILE_DIMENSION, serde_json::json!({}))).is_none());
    }

    /// CIRISEdge#657 review — a short page is a VALUE, not a log line.
    ///
    /// `belongs_to` drops rows the gate admitted that are not this room's,
    /// so a caller admitted to more than one self room can spend the page
    /// budget on the other room's newer rows before reaching this room's
    /// older ones. That is legitimate; returning a short `Vec` and warning
    /// about it is not, because a caller cannot branch on a WARN. `resume`
    /// makes the two cases distinguishable in the type.
    #[test]
    fn a_drive_page_says_whether_the_room_is_exhausted() {
        let exhausted = DrivePage {
            files: vec![],
            resume: None,
        };
        assert!(
            exhausted.resume.is_none(),
            "no files AND nothing left = the room really is empty"
        );
        // The shape a caller must be able to tell apart from the above: a
        // page that yielded nothing for THIS room but has not reached the
        // end — loop, do not conclude "empty".
        let more = DrivePage {
            files: vec![],
            resume: Some(ciris_persist::ceg::AttestationCursor {
                version: "v1".into(),
                last_asserted_at: chrono::DateTime::from_timestamp(1_767_225_296, 0).expect("ts"),
                last_attestation_id: "file-abc".into(),
            }),
        };
        assert!(more.resume.is_some());
    }

    /// §6.9 — the two columns that both say "self". A drive listing reads
    /// the federation stream, which persist's E5 invariant excludes
    /// local-tier rows from, so `belongs_to` never needs a tier check: an
    /// authored row cannot reach it. Pinned so a future listing that reads
    /// a different source remembers to exclude them itself.
    #[test]
    fn an_authored_row_and_a_crossed_row_are_the_same_shape_to_the_listing() {
        let sha = "ee".repeat(32);
        let authored = row_with(
            FILE_DIMENSION,
            serde_json::json!({ crate::chat::FIELD_CONTENT: pointer(&sha) }),
        );
        assert_eq!(
            authored.tier,
            ciris_persist::federation::types::attestation_tier::FEDERATION,
            "fixture note: `bare_row` is federation-tier, so this asserts the SHAPE match only"
        );
        let room = ScopeRoom::self_collective("alice-fed");
        assert!(
            belongs_to(&room, &authored).is_some(),
            "the listing matches on room facts, never on tier — the federation stream has \
             already excluded local-tier rows before this predicate runs (E5)"
        );
    }

    /// §6.7 — the bound still exists; what changed is what happens at it.
    ///
    /// `publish` seals above the inline bound as a chunk DAG rather than
    /// refusing (CIRISEdge#633), so this arm is unreachable from that door.
    /// It stays for a `GroupContentStore` that implements only `seal`, and
    /// its message names the shape rather than a missing door.
    #[test]
    fn the_inline_bound_names_the_shape_above_it() {
        let cap = ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP;
        let text = FileError::TooLargeForInline { size: cap + 1, cap }.to_string();
        assert!(
            text.contains("DAG"),
            "names the shape above the bound: {text}"
        );
        assert!(
            text.contains("CC 2.6.1.3"),
            "the bound is the ENVELOPE's, and saying so is what stops someone tuning it: {text}"
        );
    }

    /// CIRISEdge#646 review — a self listing must name ITS identity. A node
    /// that holds more than one identity's self rows (any server) would
    /// otherwise hand every identity's file metadata to every drive.
    #[test]
    fn a_self_listing_matches_the_identity_and_never_another_persons_rows() {
        let sha = "cc".repeat(32);
        let mine = row_with(
            FILE_DIMENSION,
            serde_json::json!({ crate::chat::FIELD_CONTENT: pointer(&sha) }),
        );
        let alice = ScopeRoom::self_collective("alice-fed");
        assert!(
            belongs_to(&alice, &mine).is_some(),
            "the pointer's group slot carries the owner at the self tier"
        );
        // Bob's drive must not show alice's file, though both rows are
        // `self`-scoped and both are files.
        assert!(belongs_to(&ScopeRoom::self_collective("bob-fed"), &mine).is_none());
        // A self row whose pointer names nobody is unattributable: skipped,
        // never shown in somebody's drive.
        let mut orphan = mine.clone();
        orphan.attestation_envelope[crate::chat::FIELD_CONTENT]["community_key_id"] =
            serde_json::json!("");
        assert!(belongs_to(&alice, &orphan).is_none());
    }

    /// A community or family listing matches on the envelope target the
    /// cohort's write gate reads — and a row of the WRONG cohort scope is
    /// not this room's file whatever it names.
    #[test]
    fn a_cohort_listing_matches_its_target_field_and_its_scope() {
        let sha = "dd".repeat(32);
        let mut fam = row_with(
            FILE_DIMENSION,
            serde_json::json!({
                crate::chat::FIELD_CONTENT: pointer(&sha),
                "family_key_id": "fam-7",
            }),
        );
        fam.cohort_scope = ciris_persist::federation::types::cohort_scope::FAMILY.to_owned();
        assert!(belongs_to(&ScopeRoom::family("fam-7"), &fam).is_some());
        assert!(belongs_to(&ScopeRoom::family("fam-8"), &fam).is_none());
        // Same row, read as a self room: the scope token disagrees, so it is
        // not that room's file even though a self room asks no target.
        assert!(belongs_to(&ScopeRoom::self_collective("alice-fed"), &fam).is_none());
    }

    /// The row a file door writes carries what each cohort's gate reads —
    /// and a self row carries no target, which is the shape that made the
    /// projector fall back to the author's identity (§6.2).
    #[tokio::test]
    async fn the_authored_row_carries_its_rooms_target_and_always_cites() {
        // Both halves: every edge signature is the full hybrid, no fallback
        // (CIRISEdge#425/#458) — a classical-only fixture cannot sign a row
        // the field would admit, so it must not be able to sign one here.
        let signer = crate::identity::LocalSigner::new(
            "node-a".to_owned(),
            std::sync::Arc::new(
                ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[7u8; 32], "node-a")
                    .expect("signer"),
            ),
            Some(std::sync::Arc::new(
                ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[8u8; 32], "node-a-pqc")
                    .expect("pqc half"),
            )),
        );
        let sha = "bb".repeat(32);
        let at = chrono::DateTime::from_timestamp(1_767_225_296, 0).expect("ts");
        for (room, expect_target) in [
            (
                ScopeRoom::community("room-1"),
                Some(("community_key_id", "room-1")),
            ),
            (ScopeRoom::family("fam-7"), Some(("family_key_id", "fam-7"))),
            (ScopeRoom::self_collective("alice-fed"), None),
        ] {
            let write = FileWrite {
                room: &room,
                bytes: b"bytes",
                media_type: "image/jpeg",
                filename: Some("boat.jpg"),
                asserted_at: at,
            };
            let row = file_row(&signer, &write, &pointer(&sha))
                .await
                .expect("authored row");
            let env = &row.attestation_envelope;
            match expect_target {
                Some((field, id)) => assert_eq!(
                    env.get(field).and_then(serde_json::Value::as_str),
                    Some(id),
                    "{room} must name its cohort target under {field}"
                ),
                None => assert!(
                    env.get("community_key_id").is_none() && env.get("family_key_id").is_none(),
                    "a self row names no cohort target: {env}"
                ),
            }
            let cited = env
                .get("evidence_refs")
                .and_then(serde_json::Value::as_array)
                .expect("every producer cites");
            assert!(cited.iter().any(|c| c.as_str() == Some(sha.as_str())));
            assert_eq!(
                row.cohort_scope,
                ciris_persist::federation::types::cohort_scope::SELF,
                "authored at self; the audience is the crossing's to decide"
            );
            assert_eq!(
                row.tier,
                ciris_persist::federation::types::attestation_tier::LOCAL,
                "local tier until it crosses — which is why publish() always crosses"
            );
            assert_eq!(
                FileRow::from_row(&row)
                    .expect("round trips")
                    .pointer
                    .content_sha256,
                sha
            );
        }
    }
}
