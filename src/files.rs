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
//!         codec: None,
//!         filename: Some("boat.jpg"),
//!         asserted_at: Utc::now(),
//!     },
//! ).await?;
//! ```
//!
//! The reader is the twin: [`in_room`] lists what a room holds and
//! [`FileRow::open`] resolves the bytes — with **row-held / bytes-absent**
//! as a first-class state ([`UnopenedReason::NotFetched`]), which is what a
//! drive shows as "on another device" (CIRISServer#615 §3). Whole is capped
//! at persist's 64 MiB whole-read bound; above it a file streams through
//! [`FileRow::chunks`] or is read by window through [`FileRow::open_range`],
//! and `open` refuses by name (CIRISEdge#737, §6.7.3).
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
use crate::group_content::{
    BlobPointer, ChunkLayout, ContentField, Description, GroupContentStore, OpenRequest,
    RedescribeRequest, SealRequest,
};
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

/// The envelope member carrying a rename's own instant (CIRISEdge#702,
/// `FSD/CONTENT_TRANSFER.md` §6.7.2). The row's `asserted_at` stays the
/// content claim's — the bytes' AAD names it — so the act signs its time here.
pub const FIELD_RENAMED_AT: &str = "renamed_at";

/// The `supersession_reason` a rename's `supersedes` carries.
pub const RENAME_REASON: &str = "rename";

/// A file to write into a room.
#[derive(Debug, Clone)]
pub struct FileWrite<'a> {
    /// Which room's members get it. The room decides the seal's tier, the
    /// row's cohort target and the crossing — all three from one value.
    pub room: &'a ScopeRoom,
    /// The plaintext. Sealed before it is stored; the bytes never ride the
    /// row.
    pub bytes: &'a [u8],
    /// What it is, so a reader knows before opening it. **Sealed with the
    /// bytes** at an encrypted tier (CIRISEdge#698): a party that cannot open
    /// the file cannot learn its type either.
    pub media_type: &'a str,
    /// The codec, when the media type alone does not say (sealed as
    /// `media_type` is).
    pub codec: Option<&'a str>,
    /// What to call it. Optional: a file is identified by its sha, and a
    /// name is a convenience for people. Sealed with the bytes at an
    /// encrypted tier; in clear on the row only at the plaintext tier.
    pub filename: Option<&'a str>,
    /// When the author asserts it — an AAD input, so it is not free.
    pub asserted_at: DateTime<Utc>,
}

/// A file to write into a room **from a reader** (CIRISEdge#744,
/// `FSD/CONTENT_TRANSFER.md` §6.7.4) — [`FileWrite`] with the plaintext
/// replaced by the length the reader will yield. The bytes come through
/// [`publish_stream`]'s reader, a chunk at a time.
#[derive(Debug, Clone)]
pub struct FileStreamWrite<'a> {
    /// As [`FileWrite::room`].
    pub room: &'a ScopeRoom,
    /// **Exactly what the reader will yield.** The shape follows it (inline
    /// at or below the bound, [`must_chunk`]; a chunk DAG above), and a
    /// reader yielding any other count is [`FileError::DeclaredLengthMismatch`].
    pub declared_len: u64,
    /// As [`FileWrite::media_type`].
    pub media_type: &'a str,
    /// As [`FileWrite::codec`].
    pub codec: Option<&'a str>,
    /// As [`FileWrite::filename`].
    pub filename: Option<&'a str>,
    /// As [`FileWrite::asserted_at`] — an AAD input.
    pub asserted_at: DateTime<Utc>,
}

impl<'a> FileStreamWrite<'a> {
    /// The streaming form of a slice write: the same members, the slice's
    /// length declared.
    #[must_use]
    pub fn of(write: &FileWrite<'a>) -> Self {
        Self {
            room: write.room,
            declared_len: write.bytes.len() as u64,
            media_type: write.media_type,
            codec: write.codec,
            filename: write.filename,
            asserted_at: write.asserted_at,
        }
    }
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

    /// **An author-only operation, and no signer in hand is the author**
    /// (CIRISEdge#675). The row's attester is `author`; the signers offered
    /// were `held`. For a person-authored row any of the owner's devices holds
    /// the person's key; a row a NODE authored (before #675, or by an
    /// agent-only node) can be retracted by that node or, through [`withdraw`]
    /// (CIRISEdge#941), by the node's single live owner.
    #[error(
        "{attestation_id} is authored by {author}; none of the signers in hand ({held:?}) is \
         its author, so an author-only operation cannot be signed (FSD/CONTENT_TRANSFER.md §6.7.0)"
    )]
    NotAuthor {
        /// The file row.
        attestation_id: String,
        /// The row's attester.
        author: String,
        /// The key ids of the signers offered.
        held: Vec<String>,
    },

    /// Building or writing the `withdraws` failed.
    #[error("withdraw {attestation_id}: {detail}")]
    Withdraw {
        /// The file row.
        attestation_id: String,
        /// What went wrong.
        detail: String,
    },

    /// **The bytes did not open** — held elsewhere (`NotFetched`, the
    /// drive's "on another device"), not granted, withdrawn, a seal that did
    /// not match: the drive's typed answer ([`UnopenedReason`],
    /// CIRISEdge#601), carried whole so a host keeps matching on
    /// [`UnopenedReason::kind`] through [`FileError::kind`].
    #[error("{0}")]
    Unopened(UnopenedReason),

    /// **Too big to hand over in one piece** (CIRISEdge#737,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.3). Persist's whole-read door caps a
    /// chunk DAG at `DAG_WHOLE_READ_CAP_BYTES` (64 MiB) — a file above it is
    /// never assembled whole inside a request handler — and this reader
    /// refuses BEFORE the substrate is asked, by name, pointing at the two
    /// doors that do serve it: [`FileRow::chunks`] streams the DAG one chunk
    /// at a time in `seq` order, [`FileRow::open_range`] reads a window.
    /// Raised by [`FileRow::open`] for a file whose size is above the cap,
    /// and by [`FileRow::open_range`] for a window (`len`) above it.
    #[error(
        "{attestation_id}: {bytes} bytes is above the {cap}-byte whole-read cap (persist \
         DAG_WHOLE_READ_CAP_BYTES); stream it — FileRow::chunks() yields the DAG's chunks in seq \
         order, FileRow::open_range(offset, len) reads a window (FSD/CONTENT_TRANSFER.md §6.7.3)"
    )]
    AboveWholeReadCap {
        /// The file row.
        attestation_id: String,
        /// What was asked for in one piece: the file's size (`open`) or the
        /// window's length (`open_range`).
        bytes: u64,
        /// The cap.
        cap: u64,
    },

    /// **The reader did not yield what the write declared** (CIRISEdge#744,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.4). Refused by name; nothing crosses:
    /// no manifest, no pointer, no `file:v1` row. The chunks a DAG write had
    /// already sealed are evicted (encrypted tier) before this returns.
    /// `read` is exact for a short reader and a lower bound (`> declared`)
    /// for a long one, which is stopped rather than drained.
    #[error(
        "declared {declared} bytes but the reader yielded {read}: nothing published, no row \
         (FSD/CONTENT_TRANSFER.md §6.7.4)"
    )]
    DeclaredLengthMismatch {
        /// What the write declared.
        declared: u64,
        /// What the reader produced (a lower bound when `> declared`).
        read: u64,
    },

    /// **The reader failed mid-stream** (CIRISEdge#744) — an I/O error from
    /// the caller's source, not a seal refusal. Nothing published, no row;
    /// written chunks are evicted as for [`Self::DeclaredLengthMismatch`].
    #[error("read the content for {room}: failed after {read} bytes: {detail}")]
    Read {
        /// The room the write was for.
        room: String,
        /// Bytes consumed before the failure.
        read: u64,
        /// The reader's error.
        detail: String,
    },

    /// **A range outside the file** (RFC 9110 §14.4; CIRISEdge#737): `offset`
    /// at or past the end, `offset + len` past the end, or `len == 0`. The
    /// end is never silently clamped — a caller that asked for `len` bytes
    /// gets exactly `len` or this. `size` is the file's plaintext size when
    /// the refusal could learn it (the pointer's, persist's, or the short
    /// answer's), so the caller can re-ask correctly.
    #[error(
        "{attestation_id}: range [{offset}, +{len}) is not satisfiable — {}",
        range_size_words(*.size)
    )]
    RangeNotSatisfiable {
        /// The file row.
        attestation_id: String,
        /// The first byte asked for.
        offset: u64,
        /// How many bytes were asked for.
        len: u64,
        /// The file's plaintext size, when known.
        size: Option<u64>,
    },
}

/// The size clause of a [`FileError::RangeNotSatisfiable`] message.
fn range_size_words(size: Option<u64>) -> String {
    size.map_or_else(
        || "an empty range is not a range".to_owned(),
        |s| format!("the file is {s} bytes"),
    )
}

impl From<UnopenedReason> for FileError {
    fn from(reason: UnopenedReason) -> Self {
        Self::Unopened(reason)
    }
}

impl FileError {
    /// Stable lower-case label for the arm, for logs, metrics and a host's
    /// status mapping. An [`Self::Unopened`] answers its reason's
    /// [`UnopenedReason::kind`] — `not_fetched`, `not_granted`, … — so a
    /// host that matched on those before CIRISEdge#737 matches on the same
    /// words now.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unopened(reason) => reason.kind(),
            Self::Seal { .. } => "seal",
            Self::ReadableByNobody { .. } => "readable_by_nobody",
            Self::Author { .. } => "author",
            Self::Cross { .. } => "cross",
            Self::Row(_) => "row",
            Self::Drive { .. } => "drive",
            Self::TooLargeForInline { .. } => "too_large_for_inline",
            Self::NotAuthor { .. } => "not_author",
            Self::Withdraw { .. } => "withdraw",
            Self::AboveWholeReadCap { .. } => "above_whole_read_cap",
            Self::RangeNotSatisfiable { .. } => "range_not_satisfiable",
            Self::DeclaredLengthMismatch { .. } => "declared_length_mismatch",
            Self::Read { .. } => "read",
        }
    }

    /// The reason the bytes did not open, when that is what this is.
    #[must_use]
    pub fn unopened(&self) -> Option<&UnopenedReason> {
        match self {
            Self::Unopened(reason) => Some(reason),
            _ => None,
        }
    }
}

/// **The largest file [`FileRow::open`] hands over whole, and the largest
/// window [`FileRow::open_range`] hands over** — persist's
/// `DAG_WHOLE_READ_CAP_BYTES` (64 MiB), re-exported so a host sizes its
/// buffers by the same number the refusal names (CIRISEdge#737, §6.7.3).
pub const WHOLE_READ_CAP_BYTES: u64 =
    ciris_persist::federation::chunk_dag_cascade::DAG_WHOLE_READ_CAP_BYTES;

/// **The window [`FileChunks`] walks a plaintext DAG in** — persist's
/// inline cap (1 MiB), the largest plaintext one chunk can hold, so every
/// item the iterator yields is at most one chunk's worth whatever the
/// producer's segment size was. A sealed DAG is walked by its manifest's
/// own chunk sizes instead (CIRISEdge#737, §6.7.3).
pub const STREAM_WINDOW_BYTES: u64 =
    ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP as u64;

/// **Who authors a file — the one choice** (CIRISEdge#675,
/// `FSD/CONTENT_TRANSFER.md` §6.7.0).
///
/// The actor (the person) when their signer is in hand, else this node — the
/// agent-only posture. The row's `attesting_key_id`, the content AAD's author
/// and the row id's preimage all read this one value, so the seal and the row
/// cannot name different authors.
#[must_use]
pub fn file_author(signers: Signers<'_>) -> &crate::identity::LocalSigner {
    signers.actor.unwrap_or(signers.node)
}

/// **Withdraw a file** (CC 2.3) — the drive's delete, signed by the row's
/// author (CIRISEdge#675), or by the owner of the node that authored it
/// (CIRISEdge#941).
///
/// The signer is [`FileRow::author_signer`]'s answer: for a person-authored
/// row, the person's key, which every device of the owner holds; for a
/// node-authored row, that node's — or, since persist v51 (CIRISPersist#941),
/// the actor in hand when it is that node's single live owner, from any of
/// their devices. The `withdraws` is persist's own
/// envelope ([`withdraws_attestation`](crate::replication::attestation_bind::withdraws_attestation)),
/// born federation-tier, written through `put_attestation` so persist's
/// authority gate (rule 1: issuer == the row's attester) decides.
///
/// # Errors
/// [`FileError::NotAuthor`] when no signer in hand is the author; otherwise
/// [`FileError::Withdraw`] naming the build or write failure.
pub async fn withdraw(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    reason: &str,
    asserted_at: DateTime<Utc>,
    signers: Signers<'_>,
) -> Result<Attestation, FileError> {
    let file = FileRow::from_row(row).ok_or_else(|| FileError::Withdraw {
        attestation_id: row.attestation_id.clone(),
        detail: "not a file row".to_owned(),
    })?;
    let signer = match file.author_signer(signers) {
        Ok(signer) => signer,
        Err(not_author) => node_owner_signer(directory, &file, signers)
            .await
            .ok_or(not_author)?,
    };
    let withdraws = crate::replication::attestation_bind::withdraws_attestation(
        row,
        reason,
        asserted_at,
        signer,
    )
    .await
    .map_err(|detail| FileError::Withdraw {
        attestation_id: row.attestation_id.clone(),
        detail,
    })?;
    directory
        .put_attestation(ciris_persist::federation::SignedAttestation {
            attestation: withdraws.clone(),
        })
        .await
        .map_err(|e| FileError::Withdraw {
            attestation_id: row.attestation_id.clone(),
            detail: e.to_string(),
        })?;
    Ok(withdraws)
}

/// **CIRISEdge#941 / CIRISPersist#941 (CC 3.4.7.3)** — the actor in hand, when
/// it is the single live owner of the NODE that authored `file`.
///
/// persist v51 lifts withdraws rule 1 to the producer's principal: a file a
/// node wrote before files were authored as the person (pre-#675/#708) is the
/// person's to retract from any device. This names the candidate; persist's
/// door stays the judge — it also requires an owner-binding over that node
/// asserted at or before the row, so a later owner of a used node retracts
/// nothing (that refusal surfaces as [`FileError::Withdraw`]). An ambiguous or
/// unresolvable owner is not a principal: `None`, and the caller keeps
/// [`FileError::NotAuthor`].
async fn node_owner_signer<'a>(
    directory: &dyn FederationDirectory,
    file: &FileRow,
    signers: Signers<'a>,
) -> Option<&'a crate::identity::LocalSigner> {
    let actor = signers.actor?;
    let owner = ciris_persist::federation::admission::owner_of(directory, &file.attesting_key_id)
        .await
        .ok()
        .flatten()?;
    (owner == actor.key_id).then_some(actor)
}

/// **Rename a file** (CIRISEdge#702, `FSD/CONTENT_TRANSFER.md` §6.7.2) — a
/// new row over the same bytes, and a `supersedes` retiring `replaces`.
///
/// No byte is written: the new row points at the SAME blob, and only its
/// description changes — re-sealed under the bytes' own DEK at an encrypted
/// tier ([`GroupContentStore::redescribe`]), in clear at the plaintext tier.
/// The new row keeps `old`'s author and `asserted_at` (the bytes' AAD names
/// both) and signs the act's own instant as [`FIELD_RENAMED_AT`]. It is
/// authored and crossed exactly as [`publish`] crosses; then — only once it
/// crossed — a `supersedes` by the same attester, born federation-tier like
/// [`withdraw`]'s `withdraws`, names `replaces` so every holder of the prior
/// retires it. A parked crossing leaves the prior live: `crossed: false`.
///
/// `new_name: None` makes the file nameless. `replaces` must name a file row
/// of `room`, by `old`'s attester, over `old`'s blob — normally
/// `old.attestation_id`, as [`in_room`] listed it.
///
/// **Author only.** [`FileRow::author_signer`], as withdraw — but NOT the
/// #941 owner fallback: a `supersedes` is by the same attester (CC 2), and
/// the bytes' AAD names the attester, so the owner of an authoring node has
/// [`withdraw`] + [`publish`], not rename.
///
/// [`PublishedFile::granted`] / [`PublishedFile::excluded`] are empty: a
/// rename grants nothing — the bytes' grants are the write's.
///
/// # Errors
/// [`FileError::NotAuthor`] when no signer in hand is `old`'s attester;
/// [`FileError::Row`] when `replaces` is not this file in this room;
/// [`FileError::Seal`] when the description cannot be re-sealed (including a
/// pointer that does not open under `old`'s binding); [`FileError::Author`]
/// when a row cannot be stored; [`FileError::Cross`] when the crossing fails.
pub async fn rename(
    directory: &dyn FederationDirectory,
    store: &dyn GroupContentStore,
    signers: Signers<'_>,
    room: &ScopeRoom,
    old: &FileRow,
    new_name: Option<&str>,
    replaces: &str,
) -> Result<PublishedFile, FileError> {
    let author = old.author_signer(signers)?;
    if new_name == Some("") {
        return Err(FileError::Row(format!(
            "rename {}: an empty name stands in for an absent one — pass None (§6.7.1)",
            old.attestation_id
        )));
    }

    let prior = replaced_row(directory, room, old, replaces).await?;
    let unresolved = unresolved_members(directory, room).await?;

    let pointer = store
        .redescribe(RedescribeRequest {
            pointer: &old.pointer,
            author_key_id: &old.attesting_key_id,
            asserted_at: old.asserted_at,
            name: new_name,
        })
        .await
        .map_err(|e| FileError::Seal {
            room: room.to_string(),
            detail: e.to_string(),
        })?;

    let renamed_at = Utc::now();
    let row = file_row_at(
        author,
        room,
        old.asserted_at,
        new_name,
        &pointer,
        Some(renamed_at),
        // The same bytes, the same stream, the same root (CIRISEdge#738).
        prior
            .attestation_envelope
            .get(crate::receipts::FIELD_STREAM_STH)
            .cloned(),
    )
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
        room.widen_to(),
        CrossingBasis::ProducerAuthority,
        signers,
    )
    .await
    .map_err(|e| FileError::Cross {
        room: room.to_string(),
        detail: e,
    })?;
    let crossed = matches!(
        crossing.shared,
        Shared::Placed { .. } | Shared::AlreadyThere { .. }
    );
    if crossed {
        let supersedes = rename_supersedes(&prior, &row.attestation_id, renamed_at, author)
            .await
            .map_err(FileError::Row)?;
        directory
            .put_attestation(ciris_persist::federation::SignedAttestation {
                attestation: supersedes.clone(),
            })
            .await
            .map_err(|e| FileError::Author {
                attestation_id: supersedes.attestation_id.clone(),
                detail: e.to_string(),
            })?;
    } else {
        tracing::warn!(
            %room,
            attestation_id = %row.attestation_id,
            replaces,
            shared = ?crossing.shared,
            "rename authored but NOT crossed — the prior stays live until the new row reaches \
             the room (FSD/CONTENT_TRANSFER.md §6.7.2)"
        );
    }

    Ok(PublishedFile {
        row,
        tier: pointer.tier,
        pointer,
        shared: crossing.shared,
        crossed,
        granted: Vec::new(),
        excluded: Vec::new(),
        unresolved,
    })
}

/// The row `replaces` names, when it is `old`'s file in `room` — a
/// replacement must replace its own: this room's file, this attester, this
/// blob (persist v42's rule for a config `supersedes`, applied here).
async fn replaced_row(
    directory: &dyn FederationDirectory,
    room: &ScopeRoom,
    old: &FileRow,
    replaces: &str,
) -> Result<Attestation, FileError> {
    let prior = directory
        .get_attestation(replaces)
        .await
        .map_err(|e| FileError::Row(format!("rename: read {replaces}: {e}")))?
        .ok_or_else(|| FileError::Row(format!("rename: {replaces} is not held here")))?;
    let names_this_file = belongs_to(room, &prior).is_some_and(|p| {
        p.attesting_key_id == old.attesting_key_id
            && p.pointer.content_sha256 == old.pointer.content_sha256
    });
    if !names_this_file {
        return Err(FileError::Row(format!(
            "rename {}: `replaces` {replaces} is not this file in {room} (same attester, same \
             blob) — a supersedes must replace its own",
            old.attestation_id
        )));
    }
    Ok(prior)
}

/// The `supersedes` a rename retires its prior with (CC 2:
/// `{references_attestation_id, supersession_reason, differs_in[]}`), plus
/// the replacement's id — the composer + separate replacement shape persist's
/// vocabulary sweep emits. Born federation-tier, like a `withdraws`: it must
/// reach every holder of the prior, and a room holds the prior's widening,
/// never the authored row.
async fn rename_supersedes(
    prior: &Attestation,
    replacement_attestation_id: &str,
    asserted_at: DateTime<Utc>,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, String> {
    use crate::replication::attestation_bind::{
        bind_attestation_envelope, truncate_to_substrate_resolution, AttestationColumns,
    };
    use ciris_persist::federation::envelope::paths;
    use ciris_persist::federation::types::{attestation_tier, attestation_type, cohort_scope};
    use sha2::{Digest as _, Sha256};

    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let issuer = signer.key_id.as_str();
    // Deterministic per (issuer, prior, replacement): a retry dedups, and two
    // devices renaming the same prior differently write two composers.
    let attestation_id = {
        let mut h = Sha256::new();
        for part in [issuer, &prior.attestation_id, replacement_attestation_id] {
            h.update(part.as_bytes());
            h.update([0]);
        }
        format!("supersedes-{}", &hex::encode(h.finalize())[..32])
    };
    let mut envelope = serde_json::json!({
        paths::REFERENCES_ATTESTATION_ID: prior.attestation_id,
        "supersession_reason": RENAME_REASON,
        paths::DIFFERS_IN: ["name"],
        "replacement_attestation_id": replacement_attestation_id,
    });
    let subjects: Vec<String> = Vec::new();
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: issuer,
            attestation_type: attestation_type::SUPERSEDES,
            attested_key_id: &prior.attesting_key_id,
            subject_key_ids: &subjects,
            cohort_scope: cohort_scope::FEDERATION,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(signer, &canonical, attestation_type::SUPERSEDES)
            .await?;
    Ok(Attestation {
        attestation_id,
        attesting_key_id: issuer.to_owned(),
        attested_key_id: prior.attesting_key_id.clone(),
        attestation_type: attestation_type::SUPERSEDES.to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: issuer.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
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
    /// **Family members this write reaches NO device of** (CIRISEdge#736):
    /// the family roster's `unresolved` members
    /// ([`crate::family_room::FamilyRoster::unresolved`]) at write time —
    /// active members whose owner binding to a node is not held here, so the
    /// row's send set holds none of their devices and no grant was wrapped to
    /// them. Named rather than skipped: the file reaches them only once a
    /// device of theirs is bound (and persist re-grants, §6.5). Always empty
    /// outside a family room.
    pub unresolved: Vec<String>,
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
    // ONE seal path (CIRISEdge#744): a slice is a reader that ends where the
    // slice does, and declares its own length.
    publish_stream(
        directory,
        store,
        signers,
        &FileStreamWrite::of(write),
        write.bytes,
    )
    .await
}

/// **Write a file into a room from a reader** — seal chunk by chunk, author,
/// cross (CIRISEdge#744, `FSD/CONTENT_TRANSFER.md` §6.7.4). [`publish`] is
/// this over a slice.
///
/// The shape follows `write.declared_len` at the one boundary [`publish`]
/// uses ([`must_chunk`]): at or below it the reader is read whole (≤ 1 MiB,
/// the inline bound) and sealed inline exactly as before; above it the store's
/// [`GroupContentStore::seal_chunked_stream`] reads `CHUNK_BYTES` at a time
/// and seals + writes each chunk as it arrives, so a 2 GiB file holds one
/// chunk in hand, never the file. The stream seals (manifest + descriptor)
/// only after the LAST chunk lands; the `file:v1` row is authored and
/// crosses only after that — so a row never names a partial file.
///
/// A reader yielding any count other than `declared_len` is
/// [`FileError::DeclaredLengthMismatch`]; a reader error is
/// [`FileError::Read`]. Neither leaves a manifest or a row, and the chunks a
/// DAG write had sealed are evicted at an encrypted tier (§6.7.4).
///
/// # Errors
/// As [`publish`], plus the two reader refusals above.
pub async fn publish_stream<R>(
    directory: &dyn FederationDirectory,
    store: &dyn GroupContentStore,
    signers: Signers<'_>,
    write: &FileStreamWrite<'_>,
    mut reader: R,
) -> Result<PublishedFile, FileError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    // CIRISEdge#675 — the person authors; the node co-signs at the crossing.
    let author = file_author(signers);
    // CIRISEdge#736 — who this write can NOT reach, read before a byte is
    // sealed, so an unreadable roster refuses the write rather than hiding it.
    let unresolved = unresolved_members(directory, write.room).await?;
    let sealed = seal_file(store, write, &author.key_id, &mut reader).await?;

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

    // CIRISEdge#738 (CC 5.3.3.3 / 5.3.3.6, §6.10) — every file is a stream
    // (a chunk DAG's, or an inline file's one-leaf log), and a stream's root
    // is published by its producer: the STH over the bytes just sealed,
    // through persist's anti-equivocation gate, carried on the row so it
    // reaches exactly the row's audience. The root is what a receiver's
    // delivery receipt names; without it no receipt can join.
    let stream_sth = publish_stream_sth(
        store,
        signers,
        write.room,
        write.asserted_at,
        &sealed.pointer,
    )
    .await?;
    let row = file_row_at(
        author,
        write.room,
        write.asserted_at,
        write.filename,
        &sealed.pointer,
        None,
        stream_sth,
    )
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

    warn_unresolved(write.room, &row.attestation_id, &unresolved);

    Ok(PublishedFile {
        row,
        pointer: sealed.pointer,
        tier: sealed.tier,
        shared: crossing.shared,
        crossed,
        granted: sealed.granted,
        excluded: sealed.excluded,
        unresolved,
    })
}

/// CIRISEdge#736 — the family roster's `unresolved` members for a write into
/// `room` (`FSD/CONTENT_TRANSFER.md` §6.4.1): the send set of a family row is
/// the roster's NODES, so a member with no node is outside it by
/// construction. Reported by name on the result, never a silent skip. Empty
/// outside a family room.
///
/// # Errors
/// [`FileError::Cross`] when the family's roster cannot be read — an unknown
/// family is refused by name, never answered with an empty audience.
async fn unresolved_members(
    directory: &dyn FederationDirectory,
    room: &ScopeRoom,
) -> Result<Vec<String>, FileError> {
    let ScopeRoom::Family { family_key_id } = room else {
        return Ok(Vec::new());
    };
    let lens = crate::contact::PersistLens::new(directory);
    crate::family_room::roster(directory, family_key_id, &lens)
        .await
        .map(|r| r.unresolved)
        .map_err(|detail| FileError::Cross {
            room: room.to_string(),
            detail,
        })
}

fn warn_unresolved(room: &ScopeRoom, attestation_id: &str, unresolved: &[String]) {
    if !unresolved.is_empty() {
        tracing::warn!(
            %room,
            attestation_id,
            unresolved = ?unresolved,
            "family file written with members no device of whom it reaches — their owner \
             binding is not held here; the row reaches them when a device of theirs is bound \
             (FSD/CONTENT_TRANSFER.md §6.4.1, CIRISEdge#736)"
        );
    }
}

/// The seal half of [`publish_stream`]: the shape by the DECLARED length, the
/// store's door for it, and the store's refusal mapped to the file's words.
async fn seal_file<R>(
    store: &dyn GroupContentStore,
    write: &FileStreamWrite<'_>,
    author_key_id: &str,
    reader: &mut R,
) -> Result<crate::group_content::SealedContent, FileError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    use crate::group_content::{GroupContentError, StreamSealRequest};
    let description = Some(Description {
        name: write.filename,
        format: write.media_type,
        codec: write.codec,
    });
    // Persist's group slot per cohort: the community at `community`, the
    // OWNER at `self`, the family at `family` — which is exactly the id the
    // room names, so the seal and the projector cannot disagree about which
    // group these bytes belong to (`FSD/CONTENT_TRANSFER.md` §6.2).
    // **Shape follows size at exactly one boundary** (§6.7). CC 2.6.1.3
    // bounds a signed envelope at 1 MiB and persist's inline cap is the same
    // number for the same reason, so above it the bytes cannot ride inside
    // the row and become a sealed chunk DAG (CC 5.3.3.1). Both doors return
    // the same `SealedContent`; the pointer's `stream_id` is what tells a
    // reader which it got. The DECLARED length decides, before a byte is
    // read — a reader that then disagrees is refused, never re-routed.
    let chunked = usize::try_from(write.declared_len).map_or(true, must_chunk);
    let seal_err = |e: GroupContentError| match e {
        GroupContentError::DeclaredLengthMismatch { declared, read } => {
            FileError::DeclaredLengthMismatch { declared, read }
        }
        GroupContentError::Reader { read, detail } => FileError::Read {
            room: write.room.to_string(),
            read,
            detail,
        },
        other => FileError::Seal {
            room: write.room.to_string(),
            detail: other.to_string(),
        },
    };
    Ok(if chunked {
        store
            .seal_chunked_stream(
                StreamSealRequest {
                    cohort_scope: write.room.row_scope_token(),
                    community_key_id: Some(write.room.content_group_id()),
                    author_key_id,
                    asserted_at: write.asserted_at,
                    field: ContentField::Body,
                    declared_len: write.declared_len,
                    // CIRISEdge#698 — the store seals this or writes it in
                    // clear by the tier persist resolves; this producer never
                    // chooses.
                    description,
                },
                reader,
            )
            .await
            .map_err(seal_err)?
    } else {
        // At or below the inline bound (≤ 1 MiB): read whole — and exactly
        // `declared_len`, so the inline shape is the one it always was.
        let bytes = read_declared(reader, write.declared_len)
            .await
            .map_err(seal_err)?;
        store
            .seal(SealRequest {
                cohort_scope: write.room.row_scope_token(),
                community_key_id: Some(write.room.content_group_id()),
                author_key_id,
                asserted_at: write.asserted_at,
                field: ContentField::Body,
                plaintext: &bytes,
                description,
            })
            .await
            .map_err(seal_err)?
    })
}

/// The authored row: the same binding ceremony every edge producer uses,
/// with the file's members. `publish_stream` calls [`file_row_at`] directly
/// (it holds no slice); this form stays for the unit tests.
#[cfg(test)]
async fn file_row(
    author: &crate::identity::LocalSigner,
    write: &FileWrite<'_>,
    pointer: &BlobPointer,
    stream_sth: Option<serde_json::Value>,
) -> Result<Attestation, String> {
    file_row_at(
        author,
        write.room,
        write.asserted_at,
        write.filename,
        pointer,
        None,
        stream_sth,
    )
    .await
}

/// **Publish the file's STH** (CIRISEdge#738, §6.10) and return the claim
/// the row carries — for every file: a chunk DAG's stream over its chunks,
/// an inline file's one-leaf log over its own address (CIRISPersist#953, see
/// [`crate::receipts`]). `None` only for a store with no stream log. The
/// stream's producer is the NODE (`signers.node`): it wrote the bytes.
///
/// # Errors
/// [`FileError::Seal`] — publishing the stream's root is part of sealing it.
async fn publish_stream_sth(
    store: &dyn GroupContentStore,
    signers: Signers<'_>,
    room: &ScopeRoom,
    asserted_at: DateTime<Utc>,
    pointer: &BlobPointer,
) -> Result<Option<serde_json::Value>, FileError> {
    let Some(log) = store.stream_log() else {
        return Ok(None);
    };
    let claim = crate::receipts::publish_file_sth(&*log, signers.node, pointer, asserted_at)
        .await
        .map_err(|detail| FileError::Seal {
            room: room.to_string(),
            detail: format!("stream STH: {detail}"),
        })?;
    serde_json::to_value(claim)
        .map(Some)
        .map_err(|e| FileError::Row(format!("stream STH claim: {e}")))
}

/// [`file_row`] over its parts. `renamed_at` is the rename act's own signed
/// instant (§6.7.2) — beside, never instead of, `asserted_at`, which stays
/// the content claim's because the bytes' AAD names it.
async fn file_row_at(
    author: &crate::identity::LocalSigner,
    room: &ScopeRoom,
    asserted_at: DateTime<Utc>,
    filename: Option<&str>,
    pointer: &BlobPointer,
    renamed_at: Option<DateTime<Utc>>,
    stream_sth: Option<serde_json::Value>,
) -> Result<Attestation, String> {
    use crate::replication::attestation_bind::{
        bind_attestation_envelope, render_signed_instant, truncate_to_substrate_resolution,
        AttestationColumns,
    };
    use sha2::{Digest as _, Sha256};

    let author_key_id = author.key_id.as_str();
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let mut envelope = serde_json::json!({
        "dimension": FILE_DIMENSION,
        crate::chat::FIELD_CONTENT: pointer,
    });
    if let Some(field) = room.cohort_target_field() {
        envelope[field] = serde_json::json!(room.content_group_id());
    }
    // One description (CIRISEdge#698 D4): a sealed pointer carries the name
    // inside its seal, so the row carries none in clear.
    if let (Some(name), None) = (filename, &pointer.sealed_descriptor) {
        envelope[FIELD_FILENAME] = serde_json::json!(name);
    }
    // In the id preimage, so a rename never collides with — and supersedes —
    // the row it renames, even to the same name.
    if let Some(at) = renamed_at {
        envelope[FIELD_RENAMED_AT] =
            serde_json::json!(render_signed_instant(truncate_to_substrate_resolution(at)));
    }
    // CIRISEdge#738 — the stream's producer-signed STH rides the row, so the
    // root reaches exactly the row's audience, signed under the row.
    if let Some(sth) = stream_sth {
        envelope[crate::receipts::FIELD_STREAM_STH] = sth;
    }
    // Every producer cites (CIRISEdge#646): the row is found BY the bytes it
    // references, and an uncited row leaves the revocation walk's known set
    // incomplete.
    crate::chat::cite_evidence(&mut envelope, &pointer.content_sha256);

    let attestation_id = {
        let mut h = Sha256::new();
        h.update(FILE_DIMENSION.as_bytes());
        h.update(room.table_group_id().as_bytes());
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

/// **Does `plaintext_len` bytes have to be a chunk DAG?** (CIRISEdge#687)
///
/// Persist's inline cap (`DEFAULT_INLINE_BYTES_CAP`) is enforced on the
/// STORED body, and an encrypted tier stores an `AtRestEnvelope` — the
/// plaintext plus `AT_REST_ENVELOPE_OVERHEAD` (magic ‖ nonce ‖ tag). Deciding
/// on the plaintext length let every file within one overhead of the cap
/// (1,048,541–1,048,576 bytes today) choose "inline" and then be refused by
/// the seal. The decision is made on the length persist will check, using
/// persist's own exported constant, never a literal.
///
/// Conservative for the plaintext tier: `publish` does not know the tier
/// before persist resolves it, so a plaintext-tier file within one overhead
/// of the cap is chunked when it could have been inline. That is correct
/// (the chunk door seals every tier) and costs one manifest; the reverse
/// error — choosing inline for a body persist will refuse — is the bug.
#[must_use]
pub fn must_chunk(plaintext_len: usize) -> bool {
    plaintext_len
        .saturating_add(ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD)
        > ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP
}

/// Read exactly `declared` bytes of an INLINE-sized write (≤ the inline
/// bound, so the buffer is at most 1 MiB), then probe one byte more: a
/// reader that ends early or runs on is refused by name, as the chunked path
/// refuses it (CIRISEdge#744).
async fn read_declared<R>(
    reader: &mut R,
    declared: u64,
) -> Result<Vec<u8>, crate::group_content::GroupContentError>
where
    R: tokio::io::AsyncRead + Unpin + Send,
{
    use crate::group_content::GroupContentError;
    use tokio::io::AsyncReadExt as _;
    let io = |read: u64, e: &std::io::Error| GroupContentError::Reader {
        read,
        detail: e.to_string(),
    };
    let cap = usize::try_from(declared)
        .map_err(|_| GroupContentError::DeclaredLengthMismatch { declared, read: 0 })?;
    let mut buf = vec![0u8; cap];
    let mut filled = 0usize;
    while filled < cap {
        match reader.read(&mut buf[filled..]).await {
            Ok(0) => {
                return Err(GroupContentError::DeclaredLengthMismatch {
                    declared,
                    read: filled as u64,
                })
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(filled as u64, &e)),
        }
    }
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe).await {
            Ok(0) => return Ok(buf),
            Ok(n) => {
                return Err(GroupContentError::DeclaredLengthMismatch {
                    declared,
                    read: declared + n as u64,
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(declared, &e)),
        }
    }
}

/// A file as a reader sees it, before any byte moves.
///
/// Recognising the row is synchronous and total; opening it is neither. A
/// drive listing a thousand files pays for none of their bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileRow {
    /// The row's id.
    pub attestation_id: String,
    /// Who wrote it — the PERSON (their fed-ID) for a file published with
    /// the actor's signer in hand, the node for an agent-only node or a row
    /// from before CIRISEdge#675. The node's custody co-scrub is on the row
    /// (`additional_scrubs`), not here.
    pub attesting_key_id: String,
    /// When.
    pub asserted_at: DateTime<Utc>,
    /// Its name, **in clear** — `None` on a sealed row (the name is inside
    /// [`BlobPointer::sealed_descriptor`]; [`Self::open_described`] opens it)
    /// and on a nameless file.
    pub filename: Option<String>,
    /// What it is, **in clear** — `None` on a sealed row, as `filename`.
    pub media_type: Option<String>,
    /// The codec, in clear, when the row names one (CIRISEdge#698).
    pub codec: Option<String>,
    /// The pointer at the bytes — the key plane.
    pub pointer: BlobPointer,
    /// Whether this row is live or retracted, as far as the listing that
    /// produced it can tell (CIRISEdge#693). [`FileRow::from_row`] and a
    /// `Live` listing always say [`FileLifecycle::Live`]; a listing that opts
    /// retracted rows back in ([`in_room_with`]) names each one.
    pub lifecycle: FileLifecycle,
}

/// A file row's retraction state (CIRISEdge#693).
///
/// Decided by the same predicate persist's `Live` listing uses to hide a row
/// — a structural composer of that kind referencing it, from the row's own
/// attester or admitted by the write door under a resolved rule
/// ([`retraction_counts`]; persist v51.2.0 / CIRISPersist#945, CIRISEdge#712)
/// — so a row marked `Live` here is exactly one a `Live` listing returns, and
/// a retracted one names which composer retracted it. If several apply, the
/// strongest wins: `Withdrawn`, then `Recanted`, then `Superseded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileLifecycle {
    /// Not retracted.
    Live,
    /// Retracted by a `withdraws` (CC 2.3): the author's, or one persist
    /// admitted from another principal — the authoring node's owner
    /// (CIRISEdge#941/#712), a subject, a delegate.
    Withdrawn,
    /// Retracted by a `recants`.
    Recanted,
    /// Replaced by a `supersedes` (a rename or a new version).
    Superseded,
}

impl FileRow {
    /// Recognise a file row. `None` for anything else — a chat message, a
    /// key package, a row that cites no bytes — and for a file row this
    /// reader refuses ([`Self::try_from_row`] names why).
    #[must_use]
    pub fn from_row(row: &Attestation) -> Option<Self> {
        match Self::try_from_row(row) {
            Ok(file) => Some(file),
            Err(NotAFile::OtherDimension | NotAFile::NoPointer) => None,
            Err(refused) => {
                tracing::warn!(
                    attestation_id = %row.attestation_id,
                    refusal = %refused,
                    "file row refused by the reader (CIRISEdge#698)"
                );
                None
            }
        }
    }

    /// Recognise a file row, **naming** a refusal.
    ///
    /// # Errors
    /// [`NotAFile::OtherDimension`] / [`NotAFile::NoPointer`] for rows that
    /// are not files; [`NotAFile::TwoDescriptions`] for a row carrying a
    /// `sealed_descriptor` beside a clear `media_type`, `codec` or `filename`
    /// (D4 — which one is true is unknowable, so neither is shown);
    /// [`NotAFile::NoDescription`] for a row with neither.
    pub fn try_from_row(row: &Attestation) -> Result<Self, NotAFile> {
        let env = &row.attestation_envelope;
        if env.get("dimension").and_then(serde_json::Value::as_str) != Some(FILE_DIMENSION) {
            return Err(NotAFile::OtherDimension);
        }
        let pointer: BlobPointer = env
            .get(crate::chat::FIELD_CONTENT)
            .and_then(|p| serde_json::from_value(p.clone()).ok())
            .ok_or(NotAFile::NoPointer)?;
        let filename = env
            .get(FIELD_FILENAME)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned);
        if pointer.sealed_descriptor.is_some() {
            let clear: Vec<&'static str> = [
                ("media_type", pointer.media_type.is_some()),
                ("codec", pointer.codec.is_some()),
                (FIELD_FILENAME, env.get(FIELD_FILENAME).is_some()),
            ]
            .into_iter()
            .filter_map(|(member, present)| present.then_some(member))
            .collect();
            if !clear.is_empty() {
                return Err(NotAFile::TwoDescriptions {
                    attestation_id: row.attestation_id.clone(),
                    clear,
                });
            }
        } else if pointer.media_type.is_none() {
            return Err(NotAFile::NoDescription {
                attestation_id: row.attestation_id.clone(),
            });
        }
        Ok(Self {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            asserted_at: row.asserted_at,
            filename,
            media_type: pointer.media_type.clone(),
            codec: pointer.codec.clone(),
            pointer,
            lifecycle: FileLifecycle::Live,
        })
    }

    /// **What the listing may say about this file** without opening it
    /// (CIRISEdge#698): the clear description, or [`Descriptor::Sealed`] —
    /// typed, never an empty string. [`Self::open_described`] is the only
    /// path to [`Descriptor::Opened`].
    #[must_use]
    pub fn descriptor(&self) -> Descriptor {
        match (&self.pointer.sealed_descriptor, &self.media_type) {
            (None, Some(format)) => Descriptor::Clear {
                format: format.clone(),
                codec: self.codec.clone(),
                name: self.filename.clone(),
            },
            // `try_from_row` refuses a row with neither, so a FileRow built
            // by it never reaches `(None, None)`; a hand-built one reads as
            // sealed — the side that shows nothing.
            (Some(_), _) | (None, None) => Descriptor::Sealed,
        }
    }

    /// **The signer that may perform an author-only operation on this file**
    /// — withdraw, replace, rename (CIRISEdge#675): whichever signer in hand
    /// IS the row's attester. A person-authored row answers the person's key
    /// (any of the owner's devices); a node-authored row answers only that
    /// node's key.
    ///
    /// # Errors
    /// [`FileError::NotAuthor`] naming the author and the signers offered.
    pub fn author_signer<'a>(
        &self,
        signers: Signers<'a>,
    ) -> Result<&'a crate::identity::LocalSigner, FileError> {
        signers
            .actor
            .into_iter()
            .chain(std::iter::once(signers.node))
            .find(|s| s.key_id == self.attesting_key_id)
            .ok_or_else(|| FileError::NotAuthor {
                attestation_id: self.attestation_id.clone(),
                author: self.attesting_key_id.clone(),
                held: signers
                    .actor
                    .into_iter()
                    .chain(std::iter::once(signers.node))
                    .map(|s| s.key_id.clone())
                    .collect(),
            })
    }

    /// The row's binding, as every read presents it: the pointer, the
    /// author and the instant off the row (the AAD inputs), and the viewer.
    fn open_request<'a>(&'a self, viewer_key_id: &'a str) -> OpenRequest<'a> {
        OpenRequest {
            pointer: &self.pointer,
            author_key_id: &self.attesting_key_id,
            asserted_at: self.asserted_at,
            viewer_key_id,
        }
    }

    /// The bytes, or **why not** — `NotFetched` while the row is held and
    /// the bytes are not (the drive's "on another device"), `NotGranted`
    /// when this viewer's key does not open them. Two states, never one
    /// string (CIRISEdge#601), carried as [`FileError::Unopened`].
    ///
    /// **Whole means whole, up to a cap** (CIRISEdge#737, §6.7.3). A chunk DAG
    /// above [`WHOLE_READ_CAP_BYTES`] (64 MiB) is refused here as
    /// [`FileError::AboveWholeReadCap`] — before persist is asked, so its own
    /// cap error is never what a caller sees — and is read through
    /// [`Self::chunks`] or [`Self::open_range`] instead. Below the cap this
    /// is the one read it always was. The size the decision reads is the
    /// pointer's (`size`, which the pull verified against the manifest); a
    /// sealed DAG whose pointer declares none is measured from its manifest.
    ///
    /// # Errors
    /// [`FileError::Unopened`] naming the [`UnopenedReason`];
    /// [`FileError::AboveWholeReadCap`] above the cap.
    pub async fn open(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<Vec<u8>, FileError> {
        if let Some(size) = self.dag_size(store, viewer_key_id).await? {
            if size > WHOLE_READ_CAP_BYTES {
                return Err(FileError::AboveWholeReadCap {
                    attestation_id: self.attestation_id.clone(),
                    bytes: size,
                    cap: WHOLE_READ_CAP_BYTES,
                });
            }
        }
        store
            .open(self.open_request(viewer_key_id))
            .await
            .map_err(|e| FileError::Unopened(UnopenedReason::from_store_error(&e)))
    }

    /// The plaintext size of a chunk DAG, for the whole-read decision:
    /// `None` for an inline file (always under the cap) and for a
    /// plaintext-tier DAG that declares no size (nothing to measure it by
    /// short of reading it; persist's own door then judges). A sealed DAG
    /// declaring none is measured from its manifest.
    async fn dag_size(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<Option<u64>, FileError> {
        if self.pointer.stream_id.is_none() {
            return Ok(None);
        }
        if let Some(size) = self.pointer.size {
            return Ok(Some(size));
        }
        if self.pointer.tier == CryptoTier::Plaintext {
            return Ok(None);
        }
        Ok(Some(self.layout(store, viewer_key_id).await?.total_size))
    }

    /// **A window of the file: `len` bytes from `offset`** (CIRISEdge#737,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.3) — persist's decrypting range read
    /// under the row's binding, the same AAD as [`Self::open`].
    ///
    /// A chunk DAG opens only the chunks the window covers, each under its
    /// own envelope and position-bound AAD, and seeks in O(covering chunks);
    /// an inline file is opened once and sliced. The descriptor is not
    /// touched — it is one object per file, opened by [`Self::describe`],
    /// never per window.
    ///
    /// **Exactly `len` bytes, or a refusal.** RFC 9110 clamps a range's end;
    /// this door does not: a window that runs past the end is
    /// [`FileError::RangeNotSatisfiable`] (naming the size), as is an
    /// `offset` at or past the end and a `len` of zero. A window longer than
    /// [`WHOLE_READ_CAP_BYTES`] is [`FileError::AboveWholeReadCap`]: the
    /// bound on what one call materializes is the same number for a window
    /// as for a whole file, and [`Self::chunks`] is the door for more.
    ///
    /// # Errors
    /// [`FileError::Unopened`] as [`Self::open`]; the two refusals above.
    pub async fn open_range(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>, FileError> {
        let refused = |size: Option<u64>| FileError::RangeNotSatisfiable {
            attestation_id: self.attestation_id.clone(),
            offset,
            len,
            size,
        };
        if len == 0 {
            return Err(refused(self.pointer.size));
        }
        if len > WHOLE_READ_CAP_BYTES {
            return Err(FileError::AboveWholeReadCap {
                attestation_id: self.attestation_id.clone(),
                bytes: len,
                cap: WHOLE_READ_CAP_BYTES,
            });
        }
        // The pointer's declared size, when it declares one: refused here
        // without a read. A pointer declaring none is judged by persist
        // (`start ≥ total`) and by the length that comes back.
        if let Some(size) = self.pointer.size {
            if offset >= size || len > size - offset {
                return Err(refused(Some(size)));
            }
        }
        let Some(end_inclusive) = offset.checked_add(len - 1) else {
            return Err(refused(self.pointer.size));
        };
        let got = store
            .open_range(self.open_request(viewer_key_id), offset, end_inclusive)
            .await
            .map_err(|e| match e {
                crate::group_content::GroupContentError::RangeNotSatisfiable { size, .. } => {
                    refused(Some(size))
                }
                other => FileError::Unopened(UnopenedReason::from_store_error(&other)),
            })?;
        // Persist clamped the end: the window ran past the file.
        if got.len() as u64 != len {
            return Err(refused(Some(offset.saturating_add(got.len() as u64))));
        }
        Ok(got)
    }

    /// **The chunk layout of a sealed DAG** (CIRISEdge#737): the manifest's
    /// chunks in `seq` order with their plaintext sizes and file offsets,
    /// opened for `viewer_key_id` under the row's binding as the bytes are.
    /// What [`Self::chunks`] walks; a host that wants `Content-Length` and
    /// the chunk count before streaming reads it once.
    ///
    /// # Errors
    /// [`FileError::Unopened`] as [`Self::open`]; an inline file or a
    /// plaintext-tier DAG has no sealed manifest and is refused by name
    /// (`Substrate`).
    pub async fn layout(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<ChunkLayout, FileError> {
        store
            .layout(self.open_request(viewer_key_id))
            .await
            .map_err(|e| FileError::Unopened(UnopenedReason::from_store_error(&e)))
    }

    /// **The file, one chunk at a time, in `seq` order** (CIRISEdge#737,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.3) — the reader for a file of any
    /// size, and the one [`FileError::AboveWholeReadCap`] points at.
    ///
    /// Nothing is read until the first [`FileChunks::next`]. A sealed DAG is
    /// walked by its manifest's layout: each item is exactly one of the
    /// producer's chunks, opened under its own at-rest envelope and
    /// position-bound AAD by persist's range door, so the whole file is never
    /// in memory at once — peak buffering is the item in hand plus persist's
    /// own copy of the chunk it is opening. A plaintext DAG has no per-chunk
    /// envelopes and is walked in [`STREAM_WINDOW_BYTES`] windows (one
    /// chunk's worth at most). An inline file is one item. The descriptor is
    /// not part of the walk: it is one object, [`Self::describe`] opens it.
    ///
    /// Every item is at most persist's inline cap (1 MiB) long. A refusal
    /// ends the walk: the item is `Err`, and `next` answers `None` after it.
    pub fn chunks<'a>(
        &'a self,
        store: &'a dyn GroupContentStore,
        viewer_key_id: &'a str,
    ) -> FileChunks<'a> {
        FileChunks {
            file: self,
            store,
            viewer_key_id,
            cursor: ChunkCursor::Start,
        }
    }

    /// **Where this file's bytes are, and who can open them** — the drive's
    /// custody view, persist's `Engine::blob_custody` (v51.1.0,
    /// CIRISPersist#942) through the same [`GroupContentStore`] every other
    /// read of this row goes through, so a host holds one handle and one
    /// error type ([`UnopenedReason`]) for the whole drive.
    ///
    /// It answers about the BLOB the pointer names — the same answer for
    /// every row over it, a rename's included (§6.7.2) — and reveals no
    /// description. `copies_observable: false` for `self`/`family` is by
    /// design (CC 5.2), never "no copies".
    ///
    /// # Errors
    /// [`UnopenedReason`] as [`Self::open`]: a viewer who cannot open the
    /// bytes is `NotGranted`.
    pub async fn custody(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<ciris_persist::federation::blob_custody::BlobCustody, UnopenedReason> {
        store
            .custody(&self.pointer, viewer_key_id)
            .await
            .map_err(|e| UnopenedReason::from_store_error(&e))
    }

    /// **Which nodes have received this file** (CIRISEdge#738, CC 5.3.3.6):
    /// every delivery receipt the author's store holds for the file's stream,
    /// as `(node, epoch, K, at)` ([`crate::receipts::Received`]). A receipt is
    /// proof of DELIVERY — the node holds bytes committing to all `K` chunks
    /// under the published root — never of consumption.
    ///
    /// Inline and chunked files alike ([`crate::receipts::receipt_stream_id`]);
    /// `at` is when the author's store took each receipt. Empty for a store
    /// with no stream log.
    ///
    /// # Errors
    /// The store read failed.
    pub async fn received_by(
        &self,
        store: &dyn GroupContentStore,
    ) -> Result<Vec<crate::receipts::Received>, String> {
        let (Some(stream_id), Some(log)) = (
            crate::receipts::receipt_stream_id(&self.pointer),
            store.stream_log(),
        ) else {
            return Ok(Vec::new());
        };
        crate::receipts::received_for(&*log, &stream_id).await
    }

    /// **The bytes and what they are, through one grant** (CIRISEdge#698,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.1): [`Self::open`] then
    /// [`Self::describe`]. `Ok` never carries [`Descriptor::Sealed`].
    ///
    /// Whole, so capped as [`Self::open`] is: above [`WHOLE_READ_CAP_BYTES`]
    /// a host calls [`Self::describe`] once and streams [`Self::chunks`].
    ///
    /// # Errors
    /// [`FileError`] as [`Self::open`]; a [`Self::describe`] refusal as
    /// [`FileError::Unopened`].
    pub async fn open_described(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<Opened, FileError> {
        let bytes = self.open(store, viewer_key_id).await?;
        let descriptor = self.describe(store, viewer_key_id).await?;
        Ok(Opened { bytes, descriptor })
    }

    /// **What the file is, without returning its bytes** (CIRISEdge#698;
    /// CIRISServer's drive listing, CIRISEdge#702).
    ///
    /// A clear row answers from its members ([`Descriptor::Clear`]). A sealed
    /// row opens ONLY its descriptor, under the row's AAD: persist v51's door
    /// authenticates the blob under the referencing row before the
    /// descriptor opens, so a pointer transplanted onto another row (D8) or
    /// moved to another blob (D3) is refused there — the row gate no longer
    /// needs the bytes returned. The door does read the blob to authenticate
    /// it, so a row whose bytes are not here is `NotFetched`, as `open` is.
    ///
    /// # Errors
    /// [`UnopenedReason`] as [`Self::open`]; a descriptor that fails its AAD
    /// is `SealMismatch` (or `Substrate` for persist's crypto-class refusal),
    /// never `NotGranted`, and one that opens to something other than
    /// `{name?, format, codec?}` is `MalformedRow`.
    pub async fn describe(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<Descriptor, UnopenedReason> {
        if self.pointer.sealed_descriptor.is_none() {
            return Ok(self.descriptor());
        }
        let jcs = store
            .open_descriptor(crate::group_content::OpenRequest {
                pointer: &self.pointer,
                author_key_id: &self.attesting_key_id,
                asserted_at: self.asserted_at,
                viewer_key_id,
            })
            .await
            .map_err(|e| UnopenedReason::from_store_error(&e))?;
        let opened: SealedDescription =
            serde_json::from_slice(&jcs).map_err(|e| UnopenedReason::MalformedRow {
                detail: format!(
                    "{}: the sealed descriptor opened to something other than \
                     {{name?, format, codec?}}: {e}",
                    self.attestation_id
                ),
            })?;
        if opened.name.as_deref() == Some("") {
            return Err(UnopenedReason::MalformedRow {
                detail: format!(
                    "{}: an empty name inside the seal — absent is omitted, never \"\"",
                    self.attestation_id
                ),
            });
        }
        Ok(Descriptor::Opened {
            format: opened.format,
            codec: opened.codec,
            name: opened.name,
        })
    }
}

/// The object inside a sealed descriptor.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SealedDescription {
    #[serde(default)]
    pub(crate) name: Option<String>,
    pub(crate) format: String,
    #[serde(default)]
    pub(crate) codec: Option<String>,
}

/// Why a row is not a readable file (CIRISEdge#698).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NotAFile {
    /// Not `file:v1`.
    #[error("not a file row")]
    OtherDimension,
    /// No readable pointer under `content`.
    #[error("a file row with no readable pointer")]
    NoPointer,
    /// A `sealed_descriptor` beside clear description members (D4).
    #[error(
        "{attestation_id}: two descriptions — a sealed descriptor beside clear {clear:?}; \
         refused, because which one is true cannot be known"
    )]
    TwoDescriptions {
        /// The row.
        attestation_id: String,
        /// The clear members found beside the seal.
        clear: Vec<&'static str>,
    },
    /// Neither a clear format nor a sealed descriptor.
    #[error("{attestation_id}: a file row with no description, sealed or clear")]
    NoDescription {
        /// The row.
        attestation_id: String,
    },
}

/// What a file is, as far as a given read can say (CIRISEdge#698).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    /// From the row's clear members — a plaintext-tier file, or a row from
    /// before #698.
    Clear {
        /// The media type.
        format: String,
        /// The codec, if named.
        codec: Option<String>,
        /// The name; `None` = the author gave none.
        name: Option<String>,
    },
    /// The sealed descriptor, opened with the bytes' key.
    Opened {
        /// The media type.
        format: String,
        /// The codec, if named.
        codec: Option<String>,
        /// The name; `None` = the author gave none (never `""`).
        name: Option<String>,
    },
    /// Sealed, and not opened by this read — the listing's word for a row
    /// held but not (yet) opened. Never an `Ok` of
    /// [`FileRow::open_described`].
    Sealed,
}

/// A file opened with its description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    /// The plaintext.
    pub bytes: Vec<u8>,
    /// What it is — `Clear` or `Opened`, never `Sealed`.
    pub descriptor: Descriptor,
}

/// **A file's chunks, in `seq` order, one at a time** — what
/// [`FileRow::chunks`] returns (CIRISEdge#737, §6.7.3).
///
/// A pull-based async iterator: [`Self::next`] reads exactly one item, so
/// the caller — an HTTP body writer, a hash — decides the pace and holds one
/// chunk. [`Self::into_stream`] is the same walk as a `futures::Stream`.
#[must_use = "nothing is read until `next` is called"]
pub struct FileChunks<'a> {
    file: &'a FileRow,
    store: &'a dyn GroupContentStore,
    viewer_key_id: &'a str,
    cursor: ChunkCursor,
}

/// Where a [`FileChunks`] walk is.
enum ChunkCursor {
    /// Nothing read yet: the first `next` decides the shape.
    Start,
    /// A sealed DAG: the manifest's chunks, `next` the index of the one to
    /// read.
    Sealed { layout: ChunkLayout, next: usize },
    /// A plaintext DAG: fixed windows from `offset`.
    Plain { offset: u64 },
    /// Finished, or stopped by a refusal.
    Done,
}

impl std::fmt::Debug for FileChunks<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileChunks")
            .field("attestation_id", &self.file.attestation_id)
            .field("viewer_key_id", &self.viewer_key_id)
            .finish_non_exhaustive()
    }
}

impl<'a> FileChunks<'a> {
    /// The next chunk: `Some(Ok(bytes))` in `seq` order, `Some(Err)` once
    /// on a refusal (after which the walk is over), `None` at the end.
    ///
    /// Every `Ok` item is non-empty and at most persist's inline cap (1 MiB)
    /// long: one producer chunk of a sealed DAG, one
    /// [`STREAM_WINDOW_BYTES`] window of a plaintext DAG, the whole of an
    /// inline file.
    pub async fn next(&mut self) -> Option<Result<Vec<u8>, FileError>> {
        loop {
            match std::mem::replace(&mut self.cursor, ChunkCursor::Done) {
                ChunkCursor::Done => return None,
                ChunkCursor::Start => {
                    if self.file.pointer.stream_id.is_none() {
                        // Inline: one chunk, the whole thing, under the cap
                        // by construction (CC 2.6.1.3).
                        return Some(self.file.open(self.store, self.viewer_key_id).await);
                    }
                    if self.file.pointer.tier == CryptoTier::Plaintext {
                        self.cursor = ChunkCursor::Plain { offset: 0 };
                        continue;
                    }
                    match self.file.layout(self.store, self.viewer_key_id).await {
                        Ok(layout) => self.cursor = ChunkCursor::Sealed { layout, next: 0 },
                        Err(e) => return Some(Err(e)),
                    }
                }
                ChunkCursor::Sealed { layout, next } => {
                    let extent = layout.chunks.get(next).copied()?;
                    if extent.size == 0 {
                        // A zero-length chunk holds no byte; persist's own
                        // range mapping skips it too (`slices_for_range`).
                        self.cursor = ChunkCursor::Sealed {
                            layout,
                            next: next + 1,
                        };
                        continue;
                    }
                    let item = self
                        .file
                        .open_range(self.store, self.viewer_key_id, extent.offset, extent.size)
                        .await;
                    if item.is_ok() {
                        self.cursor = ChunkCursor::Sealed {
                            layout,
                            next: next + 1,
                        };
                    }
                    return Some(item);
                }
                ChunkCursor::Plain { offset } => {
                    // The declared size ends the walk exactly; without one,
                    // persist's `start ≥ total` refusal does (only reachable
                    // when the size is a multiple of the window, or zero).
                    if let Some(size) = self.file.pointer.size {
                        if offset >= size {
                            return None;
                        }
                    }
                    let end_inclusive = offset.saturating_add(STREAM_WINDOW_BYTES - 1);
                    let item = self
                        .store
                        .open_range(
                            self.file.open_request(self.viewer_key_id),
                            offset,
                            end_inclusive,
                        )
                        .await;
                    return match item {
                        Ok(bytes) if bytes.is_empty() => None,
                        Ok(bytes) => {
                            if bytes.len() as u64 == STREAM_WINDOW_BYTES {
                                self.cursor = ChunkCursor::Plain {
                                    offset: offset + STREAM_WINDOW_BYTES,
                                };
                            }
                            Some(Ok(bytes))
                        }
                        Err(crate::group_content::GroupContentError::RangeNotSatisfiable {
                            ..
                        }) if self.file.pointer.size.is_none() => None,
                        Err(e) => Some(Err(FileError::Unopened(UnopenedReason::from_store_error(
                            &e,
                        )))),
                    };
                }
            }
        }
    }

    /// The same walk as a [`futures::Stream`].
    pub fn into_stream(self) -> impl futures::Stream<Item = Result<Vec<u8>, FileError>> + 'a {
        futures::stream::unfold(self, |mut chunks| async move {
            chunks.next().await.map(|item| (item, chunks))
        })
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
/// # Every room kind, one gate
///
/// `self`, `family`, `community` and `affiliations` all go through persist's
/// §4.3 read gate. Until persist v46.5.0 (CIRISPersist#893) the targeted
/// arms compared the row's PRODUCER against the caller's room set, so no
/// member could read their own room, and this function refused targeted
/// rooms by name rather than return the empty list the gate produced. V150's
/// `cohort_target` column keys the gate on the room the row names, and the
/// refusal went with its cause.
///
/// # Errors
/// [`FileError::Drive`] from the substrate.
pub async fn in_room(
    engine: &ciris_persist::Engine,
    room: &ScopeRoom,
    caller_occurrence_key_id: &str,
    limit: usize,
    after: Option<ciris_persist::ceg::AttestationCursor>,
) -> Result<DrivePage, FileError> {
    in_room_with(
        engine,
        room,
        caller_occurrence_key_id,
        limit,
        after,
        ciris_persist::ceg::LifecycleView::Live,
    )
    .await
}

/// [`in_room`] with persist's lifecycle axis exposed (CIRISEdge#693): the same
/// caller gate, the same [`belongs_to`], the same resumable paging — and
/// `lifecycle` selects which retracted rows come back.
/// `LifecycleView::IncludeWithdrawn` is the drive's history view: a withdrawn
/// file is listed and marked [`FileLifecycle::Withdrawn`], so a host can
/// answer "withdrawn" for an id the room once held and "never here" for one
/// it did not, instead of both reading as absent.
///
/// A `Live` listing costs nothing extra. Any other view reads each returned
/// row's composers once (`list_attestations_referencing`) to name its state —
/// bounded by `limit`.
///
/// # Errors
/// [`FileError::Drive`] from the substrate.
pub async fn in_room_with(
    engine: &ciris_persist::Engine,
    room: &ScopeRoom,
    caller_occurrence_key_id: &str,
    limit: usize,
    after: Option<ciris_persist::ceg::AttestationCursor>,
    lifecycle: ciris_persist::ceg::LifecycleView,
) -> Result<DrivePage, FileError> {
    use ciris_persist::ceg::AttestationFilter;
    use ciris_persist::scope::CallerScope;

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
                    f.lifecycle = lifecycle;
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
            if let Some(mut file) = belongs_to(room, row) {
                if lifecycle != ciris_persist::ceg::LifecycleView::Live {
                    file.lifecycle = lifecycle_of(engine, row, room).await?;
                }
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

/// The retraction state of one listed row — persist's `Live` hide rule, read
/// per row (v51.2.0, CIRISPersist#945): a structural composer of that kind
/// referencing it, from the row's own attester OR one the write door ADMITTED
/// under a resolved rule (`withdraws_admission_rule` set — a node owner's
/// withdraw of its node's row, CIRISEdge#941/#712; a subject's rule-2
/// revocation; a delegate's). A `supersedes` is a same-attester act (CC 2)
/// and never carries a rule, so for it the same-author check is the whole
/// rule. See [`FileLifecycle`].
async fn lifecycle_of(
    engine: &ciris_persist::Engine,
    row: &Attestation,
    room: &ScopeRoom,
) -> Result<FileLifecycle, FileError> {
    use ciris_persist::federation::precedence::references_attestation_id_from_envelope;
    use ciris_persist::federation::types::attestation_type;

    let composers = engine
        .federation_directory()
        .list_attestations_referencing(&row.attestation_id)
        .await
        .map_err(|e| FileError::Drive {
            room: room.to_string(),
            detail: format!("composers of {}: {e}", row.attestation_id),
        })?;
    let retracted_by = |kind: &str| {
        composers.iter().any(|c| {
            c.attestation_type == kind
                && retraction_counts(
                    &c.attesting_key_id,
                    &row.attesting_key_id,
                    c.withdraws_admission_rule,
                )
                && references_attestation_id_from_envelope(&c.attestation_envelope)
                    == Some(row.attestation_id.as_str())
        })
    };
    Ok(if retracted_by(attestation_type::WITHDRAWS) {
        FileLifecycle::Withdrawn
    } else if retracted_by(attestation_type::RECANTS) {
        FileLifecycle::Recanted
    } else if retracted_by(attestation_type::SUPERSEDES) {
        FileLifecycle::Superseded
    } else {
        FileLifecycle::Live
    })
}

/// **Does a composer signed by `composer` retract a row by `author`?** — the
/// predicate persist's every `Live` filter applies since v51.2.0
/// (CIRISPersist#945), mirrored so the history view names exactly the rows
/// the live view hides (CIRISEdge#712): the target's own author's retraction
/// counts, and so does one the write door admitted under a resolved rule
/// (`withdraws_admission_rule` is `Some`), whoever signed it. An unadmitted
/// cross-attester composer retracts nothing (CEG §6.1 rule 4).
#[must_use]
pub fn retraction_counts(composer: &str, author: &str, admission_rule: Option<u8>) -> bool {
    composer == author || admission_rule.is_some()
}

/// **Is `row` one of `room`'s files?** — edge's room rule, public so a host
/// that holds a row by id applies THIS rule rather than a copy of it
/// (CIRISEdge#693). [`in_room`] / [`in_room_with`] apply it after persist's
/// caller gate; it answers "is it this room's", never "may this caller see
/// it". Returns the recognised [`FileRow`] (lifecycle `Live` — the rule does
/// not read composers), or `None` for a row of another room, another scope,
/// or not a file. The identity check differs per room kind: a community /
/// family / affiliations row names its room in the cohort-target field; a
/// self row names its owner in the pointer's group slot.
#[must_use]
pub fn belongs_to(room: &ScopeRoom, row: &Attestation) -> Option<FileRow> {
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

    /// D4 (CIRISEdge#698) — one description: a sealed descriptor beside a
    /// clear `media_type`, `codec` or `filename` is refused BY NAME, each
    /// member on its own, and never listed.
    #[test]
    fn a_row_with_two_descriptions_is_refused() {
        let sha = "bb".repeat(32);
        let sealed = |extra: serde_json::Value| {
            let mut p = serde_json::json!({
                "community_key_id": "alice-fed",
                "tier": "invisible_encrypted",
                "content_sha256": sha,
                "content_field": "body",
                "sealed_descriptor": "c2VhbGVk",
                "size": 5,
            });
            for (k, v) in extra.as_object().expect("an object") {
                p[k] = v.clone();
            }
            p
        };
        let cases = [
            (
                serde_json::json!({ crate::chat::FIELD_CONTENT: sealed(serde_json::json!({"media_type": "image/jpeg"})) }),
                vec!["media_type"],
            ),
            (
                serde_json::json!({ crate::chat::FIELD_CONTENT: sealed(serde_json::json!({"codec": "h264"})) }),
                vec!["codec"],
            ),
            (
                serde_json::json!({
                    crate::chat::FIELD_CONTENT: sealed(serde_json::json!({})),
                    FIELD_FILENAME: "boat.jpg",
                }),
                vec![FIELD_FILENAME],
            ),
        ];
        for (env, named) in cases {
            let row = row_with(FILE_DIMENSION, env);
            match FileRow::try_from_row(&row) {
                Err(NotAFile::TwoDescriptions { clear, .. }) => assert_eq!(clear, named),
                other => panic!("two descriptions must be refused by name, got {other:?}"),
            }
            assert!(FileRow::from_row(&row).is_none(), "and never listed");
        }

        // The sealed row alone is a file, typed sealed.
        let row = row_with(
            FILE_DIMENSION,
            serde_json::json!({ crate::chat::FIELD_CONTENT: sealed(serde_json::json!({})) }),
        );
        let f = FileRow::try_from_row(&row).expect("one description");
        assert_eq!(f.descriptor(), Descriptor::Sealed);
        assert_eq!((f.filename, f.media_type, f.codec), (None, None, None));

        // Neither description: refused by name too.
        let bare = row_with(
            FILE_DIMENSION,
            serde_json::json!({ crate::chat::FIELD_CONTENT: {
                "community_key_id": "alice-fed",
                "tier": "invisible_encrypted",
                "content_sha256": sha,
                "content_field": "body",
            }}),
        );
        assert!(matches!(
            FileRow::try_from_row(&bare),
            Err(NotAFile::NoDescription { .. })
        ));
    }

    /// D5 (CIRISEdge#698) — read-compat: the v32 row shape (a clear filename
    /// and media type, no seal, no size) still lists, with a `Clear`
    /// descriptor. The vector is the exact pre-#698 pointer.
    #[test]
    fn a_v32_row_still_opens() {
        let sha = "cc".repeat(32);
        let row = row_with(
            FILE_DIMENSION,
            serde_json::json!({
                crate::chat::FIELD_CONTENT: {
                    "community_key_id": "alice-fed",
                    "tier": "invisible_encrypted",
                    "content_sha256": sha,
                    "content_field": "body",
                    "media_type": "image/jpeg",
                },
                FIELD_FILENAME: "boat.jpg",
            }),
        );
        let f = FileRow::from_row(&row).expect("a v32 file row lists");
        assert_eq!(
            f.descriptor(),
            Descriptor::Clear {
                format: "image/jpeg".into(),
                codec: None,
                name: Some("boat.jpg".into()),
            }
        );
        assert_eq!(f.pointer.size, None, "absent, never fabricated");
        assert_eq!(f.pointer.sealed_descriptor, None);
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
    /// CIRISEdge#687 — the shape is chosen on the length persist checks (the
    /// sealed envelope), not the plaintext. Pinned against persist's own
    /// constants so a change to the envelope moves the boundary with it.
    #[test]
    fn the_inline_decision_is_made_on_the_sealed_length() {
        let cap = ciris_persist::federation::blobs::DEFAULT_INLINE_BYTES_CAP;
        let overhead = ciris_persist::federation::at_rest_cascade::AT_REST_ENVELOPE_OVERHEAD;
        assert!(
            !must_chunk(cap - overhead),
            "the largest body whose envelope fits stays inline"
        );
        assert!(
            must_chunk(cap - overhead + 1),
            "one more byte and the envelope would exceed the cap"
        );
        assert!(
            must_chunk(cap),
            "a body AT the plaintext cap no longer rides inline (the #687 range)"
        );
        assert!(must_chunk(cap + 1));
        assert!(!must_chunk(0));
        assert!(
            !must_chunk(usize::MAX - 1) || must_chunk(usize::MAX),
            "saturates, never wraps"
        );
    }

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
                codec: None,
                filename: Some("boat.jpg"),
                asserted_at: at,
            };
            let row = file_row(&signer, &write, &pointer(&sha), None)
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

    // ── CIRISEdge#737 — the range reader and the chunk walk, on a fake
    // store with persist's range semantics (end clamped, `start ≥ total`
    // refused), so the arithmetic is pinned without a substrate. The
    // substrate witness is `tests/file_range_read_737.rs`.

    /// A store over one plaintext, answering `open_range` as persist does
    /// and `layout` as a sealed manifest of `chunk`-byte segments would.
    struct FakeStore {
        bytes: Vec<u8>,
        chunk: u64,
        stream_id: String,
        whole_opens: std::sync::atomic::AtomicUsize,
        /// The longest range one `open_range` was asked for.
        max_range: std::sync::atomic::AtomicU64,
    }

    impl FakeStore {
        fn new(bytes: Vec<u8>, chunk: u64) -> Self {
            Self {
                bytes,
                chunk,
                stream_id: "file-737".into(),
                whole_opens: std::sync::atomic::AtomicUsize::new(0),
                max_range: std::sync::atomic::AtomicU64::new(0),
            }
        }
        fn max_range(&self) -> u64 {
            self.max_range.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl GroupContentStore for FakeStore {
        async fn seal(
            &self,
            _req: SealRequest<'_>,
        ) -> Result<crate::group_content::SealedContent, crate::group_content::GroupContentError>
        {
            Err(crate::group_content::GroupContentError::Substrate(
                "read-only fake".into(),
            ))
        }
        async fn seal_chunked(
            &self,
            _req: SealRequest<'_>,
        ) -> Result<crate::group_content::SealedContent, crate::group_content::GroupContentError>
        {
            Err(crate::group_content::GroupContentError::Substrate(
                "read-only fake".into(),
            ))
        }
        async fn open(
            &self,
            _req: OpenRequest<'_>,
        ) -> Result<Vec<u8>, crate::group_content::GroupContentError> {
            self.whole_opens
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.bytes.clone())
        }
        async fn open_range(
            &self,
            req: OpenRequest<'_>,
            start: u64,
            end_inclusive: u64,
        ) -> Result<Vec<u8>, crate::group_content::GroupContentError> {
            let total = self.bytes.len() as u64;
            if start >= total {
                return Err(
                    crate::group_content::GroupContentError::RangeNotSatisfiable {
                        sha256_hex: req.pointer.content_sha256.clone(),
                        range_start: start,
                        size: total,
                    },
                );
            }
            let end = end_inclusive.min(total - 1);
            self.max_range
                .fetch_max(end - start + 1, std::sync::atomic::Ordering::SeqCst);
            let (s, e) = (
                usize::try_from(start).expect("fits"),
                usize::try_from(end).expect("fits"),
            );
            Ok(self.bytes[s..=e].to_vec())
        }
        async fn layout(
            &self,
            _req: OpenRequest<'_>,
        ) -> Result<ChunkLayout, crate::group_content::GroupContentError> {
            let total = self.bytes.len() as u64;
            let mut chunks = Vec::new();
            let mut offset = 0;
            while offset < total {
                let size = self.chunk.min(total - offset);
                chunks.push(crate::group_content::ChunkExtent {
                    seq: chunks.len() as u64,
                    offset,
                    size,
                });
                offset += size;
            }
            Ok(ChunkLayout {
                stream_id: self.stream_id.clone(),
                total_size: total,
                chunks,
            })
        }
    }

    fn body(len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| {
                u8::try_from(u32::try_from(i).expect("fits").wrapping_mul(2_654_435_761) >> 24)
                    .expect("byte")
            })
            .collect()
    }

    /// A file row over `pointer_json`, the members a read needs.
    fn file_over(pointer_json: &serde_json::Value) -> FileRow {
        let row = row_with(
            FILE_DIMENSION,
            serde_json::json!({ crate::chat::FIELD_CONTENT: pointer_json }),
        );
        FileRow::from_row(&row).expect("a file row")
    }

    fn sealed_dag(size: Option<u64>) -> FileRow {
        let mut p = serde_json::json!({
            "community_key_id": "alice-fed",
            "tier": "invisible_encrypted",
            "content_sha256": "cd".repeat(32),
            "content_field": "body",
            "stream_id": "file-737",
            "sealed_descriptor": "AAAA",
        });
        if let Some(s) = size {
            p["size"] = serde_json::json!(s);
        }
        file_over(&p)
    }

    fn plain_dag(size: Option<u64>) -> FileRow {
        let mut p = serde_json::json!({
            "community_key_id": "",
            "tier": "plaintext",
            "content_sha256": "ef".repeat(32),
            "content_field": "body",
            "stream_id": "file-737",
            "media_type": "video/mp4",
        });
        if let Some(s) = size {
            p["size"] = serde_json::json!(s);
        }
        file_over(&p)
    }

    /// Whole is capped by NAME, before the store is asked: a DAG above
    /// persist's whole-read cap answers `AboveWholeReadCap` pointing at the
    /// range reader; one at the cap opens as before.
    #[tokio::test]
    async fn open_above_the_whole_read_cap_is_refused_by_name_before_the_store_is_asked() {
        let store = FakeStore::new(body(16), 4);
        let over = sealed_dag(Some(WHOLE_READ_CAP_BYTES + 1));
        let err = over
            .open(&store, "viewer")
            .await
            .expect_err("above the cap");
        assert_eq!(
            err,
            FileError::AboveWholeReadCap {
                attestation_id: over.attestation_id.clone(),
                bytes: WHOLE_READ_CAP_BYTES + 1,
                cap: WHOLE_READ_CAP_BYTES,
            }
        );
        assert_eq!(err.kind(), "above_whole_read_cap");
        assert!(
            err.to_string().contains("FileRow::chunks()"),
            "the refusal points at the range reader: {err}"
        );
        assert_eq!(
            store.whole_opens.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "refused before the substrate is asked"
        );
        // At the cap exactly: the whole read.
        let at = sealed_dag(Some(WHOLE_READ_CAP_BYTES));
        assert_eq!(at.open(&store, "viewer").await.expect("whole"), body(16));
        // A sealed DAG declaring no size is measured from its manifest.
        let undeclared = sealed_dag(None);
        assert_eq!(
            undeclared.open(&store, "viewer").await.expect("16 bytes"),
            body(16)
        );
        // Inline never asks.
        let inline = file_over(&serde_json::json!({
            "community_key_id": "alice-fed",
            "tier": "invisible_encrypted",
            "content_sha256": "ab".repeat(32),
            "content_field": "body",
            "sealed_descriptor": "AAAA",
            "size": WHOLE_READ_CAP_BYTES + 1,
        }));
        assert_eq!(
            inline.open(&store, "viewer").await.expect("inline"),
            body(16)
        );
    }

    /// `open_range` hands over exactly `len` bytes or refuses by name — at
    /// every edge: first byte, a mid-chunk window, the last byte, a window
    /// across a chunk boundary, past the end, at the end, empty, and above
    /// the cap — with and without a declared size.
    #[tokio::test]
    async fn open_range_returns_exactly_len_or_refuses_by_name() {
        let plain = body(2500);
        let store = FakeStore::new(plain.clone(), 1000);
        for file in [
            sealed_dag(Some(2500)),
            sealed_dag(None),
            plain_dag(Some(2500)),
        ] {
            let read = |offset: u64, len: u64| file.open_range(&store, "viewer", offset, len);
            assert_eq!(read(0, 1).await.expect("first byte"), &plain[0..1]);
            assert_eq!(read(1100, 50).await.expect("mid-chunk"), &plain[1100..1150]);
            assert_eq!(read(2499, 1).await.expect("last byte"), &plain[2499..2500]);
            assert_eq!(
                read(999, 2).await.expect("across chunks 0|1"),
                &plain[999..1001]
            );
            assert_eq!(
                read(500, 2000).await.expect("across three chunks"),
                &plain[500..2500]
            );
            // Past the end: exactly len or a refusal that names the size —
            // never a clamped short answer.
            assert_eq!(
                read(2490, 11).await.expect_err("past the end"),
                FileError::RangeNotSatisfiable {
                    attestation_id: file.attestation_id.clone(),
                    offset: 2490,
                    len: 11,
                    size: Some(2500),
                }
            );
            assert!(matches!(
                read(2500, 1).await.expect_err("at the end"),
                FileError::RangeNotSatisfiable {
                    size: Some(2500),
                    ..
                }
            ));
            assert!(matches!(
                read(0, 0).await.expect_err("an empty range"),
                FileError::RangeNotSatisfiable { len: 0, .. }
            ));
            assert!(matches!(
                read(0, WHOLE_READ_CAP_BYTES + 1)
                    .await
                    .expect_err("a window above the cap"),
                FileError::AboveWholeReadCap { .. }
            ));
        }
    }

    /// The chunk walk of a sealed DAG follows the manifest's layout: one
    /// producer chunk per item, in order, the concatenation byte-identical,
    /// and no single ask larger than a chunk.
    #[tokio::test]
    async fn chunks_walks_a_sealed_dag_one_manifest_chunk_at_a_time() {
        use futures::StreamExt as _;
        let plain = body(2500);
        let store = FakeStore::new(plain.clone(), 1000);
        let file = sealed_dag(Some(2500));
        let mut walk = file.chunks(&store, "viewer");
        let mut sizes = Vec::new();
        let mut got = Vec::new();
        while let Some(item) = walk.next().await {
            let item = item.expect("a chunk");
            assert!(!item.is_empty());
            assert!(item.len() as u64 <= STREAM_WINDOW_BYTES);
            sizes.push(item.len());
            got.extend_from_slice(&item);
        }
        assert_eq!(
            sizes,
            vec![1000, 1000, 500],
            "the manifest's chunks, in seq order"
        );
        assert_eq!(got, plain, "byte-identical");
        assert_eq!(
            store.max_range(),
            1000,
            "never more than one chunk asked for"
        );
        assert_eq!(
            store.whole_opens.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "the walk never opens the whole"
        );
        // The stream form is the same walk.
        let streamed: Vec<usize> = file
            .chunks(&store, "viewer")
            .into_stream()
            .map(|i| i.expect("a chunk").len())
            .collect()
            .await;
        assert_eq!(streamed, vec![1000, 1000, 500]);
    }

    /// A plaintext DAG has no per-chunk envelopes: it is walked in
    /// `STREAM_WINDOW_BYTES` windows, to the declared size or — undeclared —
    /// to persist's end-of-content refusal, which is not an error.
    #[tokio::test]
    async fn chunks_walks_a_plaintext_dag_in_windows() {
        let w = usize::try_from(STREAM_WINDOW_BYTES).expect("fits");
        let plain = body(2 * w + w / 2);
        let store = FakeStore::new(plain.clone(), 256 * 1024);
        for file in [plain_dag(Some(plain.len() as u64)), plain_dag(None)] {
            let mut walk = file.chunks(&store, "viewer");
            let mut sizes = Vec::new();
            let mut got = Vec::new();
            while let Some(item) = walk.next().await {
                let item = item.expect("a window");
                sizes.push(item.len());
                got.extend_from_slice(&item);
            }
            assert_eq!(sizes, vec![w, w, w / 2]);
            assert_eq!(got, plain);
        }
        // An exact multiple of the window, undeclared: the walk ends on
        // persist's `start ≥ total`, with no error item.
        let exact = body(2 * w);
        let store = FakeStore::new(exact.clone(), 256 * 1024);
        let exact_file = plain_dag(None);
        let mut walk = exact_file.chunks(&store, "viewer");
        let mut n = 0;
        while let Some(item) = walk.next().await {
            assert_eq!(item.expect("a window").len(), w);
            n += 1;
        }
        assert_eq!(n, 2);
    }

    /// An inline file is one item — the whole of it.
    #[tokio::test]
    async fn chunks_of_an_inline_file_is_one_item() {
        let plain = body(300);
        let store = FakeStore::new(plain.clone(), 1000);
        let inline = file_over(&serde_json::json!({
            "community_key_id": "alice-fed",
            "tier": "invisible_encrypted",
            "content_sha256": "ab".repeat(32),
            "content_field": "body",
            "sealed_descriptor": "AAAA",
            "size": 300,
        }));
        let mut walk = inline.chunks(&store, "viewer");
        assert_eq!(walk.next().await.expect("one item").expect("opens"), plain);
        assert!(walk.next().await.is_none());
        // And its window is a slice of that one chunk.
        assert_eq!(
            inline
                .open_range(&store, "viewer", 100, 50)
                .await
                .expect("slice"),
            &plain[100..150]
        );
    }

    /// The old vocabulary survives the widening: an `Unopened` answers its
    /// reason's `kind`, so a host matching on `not_granted` still does.
    #[test]
    fn an_unopened_file_error_keeps_the_reasons_kind() {
        let e = FileError::from(UnopenedReason::NotGranted {
            detail: "no key".into(),
        });
        assert_eq!(e.kind(), "not_granted");
        assert_eq!(e.to_string(), "not_granted: no key");
        assert!(e.unopened().is_some());
    }
}
