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
use crate::group_content::{
    BlobPointer, ContentField, Description, GroupContentStore, RedescribeRequest, SealRequest,
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
}

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
    // CIRISEdge#675 — the person authors; the node co-signs at the crossing.
    let author = file_author(signers);
    let author_key_id = author.key_id.clone();
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
        // CIRISEdge#698 — the store seals this or writes it in clear by the
        // tier persist resolves; this producer never chooses.
        description: Some(Description {
            name: write.filename,
            format: write.media_type,
            codec: write.codec,
        }),
    };
    let chunked = must_chunk(write.bytes.len());
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

    let row = file_row(author, write, &sealed.pointer)
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
    file_row_at(
        author,
        write.room,
        write.asserted_at,
        write.filename,
        pointer,
        None,
    )
    .await
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
/// — a structural composer of that kind, from the row's own attester, that
/// references it — so a row marked `Live` here is exactly one a `Live`
/// listing returns, and a retracted one names which composer retracted it.
/// If several apply, the strongest wins: `Withdrawn`, then `Recanted`, then
/// `Superseded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileLifecycle {
    /// Not retracted.
    Live,
    /// Retracted by a `withdraws` (the author took it back; CC 2.3).
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

    /// **The bytes and what they are, through one grant** (CIRISEdge#698,
    /// `FSD/CONTENT_TRANSFER.md` §6.7.1): [`Self::open`] then
    /// [`Self::describe`]. `Ok` never carries [`Descriptor::Sealed`].
    ///
    /// # Errors
    /// [`UnopenedReason`] as [`Self::open`] and [`Self::describe`].
    pub async fn open_described(
        &self,
        store: &dyn GroupContentStore,
        viewer_key_id: &str,
    ) -> Result<Opened, UnopenedReason> {
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
/// per row: a structural composer of that kind, from the row's own attester,
/// referencing it (see [`FileLifecycle`]).
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
                && c.attesting_key_id == row.attesting_key_id
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
