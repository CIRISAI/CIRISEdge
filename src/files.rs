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
/// # Errors
/// The seal's refusal, the store's, or the crossing's, as a string naming
/// which of the three failed.
pub async fn publish(
    directory: &dyn FederationDirectory,
    store: &dyn GroupContentStore,
    signers: Signers<'_>,
    write: &FileWrite<'_>,
) -> Result<PublishedFile, String> {
    let author_key_id = signers.node.key_id.clone();
    // Persist's group slot per cohort: the community at `community`, the
    // OWNER at `self`, the family at `family` — which is exactly the id the
    // room names, so the seal and the projector cannot disagree about which
    // group these bytes belong to (`FSD/CONTENT_TRANSFER.md` §6.2).
    let sealed = store
        .seal(SealRequest {
            cohort_scope: write.room.row_scope_token(),
            community_key_id: Some(write.room.content_group_id()),
            author_key_id: &author_key_id,
            asserted_at: write.asserted_at,
            field: ContentField::Body,
            plaintext: write.bytes,
            media_type: Some(write.media_type),
        })
        .await
        .map_err(|e| format!("seal into {}: {e}", write.room))?;

    let row = file_row(signers.node, write, &sealed.pointer).await?;
    directory
        .put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .map_err(|e| format!("author {}: {e}", row.attestation_id))?;

    let crossing = share(
        directory,
        &row,
        write.room.widen_to(),
        CrossingBasis::ProducerAuthority,
        signers,
    )
    .await
    .map_err(|e| format!("cross into {}: {e}", write.room))?;

    Ok(PublishedFile {
        row,
        pointer: sealed.pointer,
        tier: sealed.tier,
        shared: crossing.shared,
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

/// **The drive read** — every file row this node holds for `room`, newest
/// last (CIRISServer#615 §3).
///
/// Filters on the room's own facts: the dimension, the row's cohort scope,
/// and the cohort target when the room has one. A self room's files are the
/// `self`-scoped file rows — which on a second device are exactly the ones
/// that arrived over the row plane, bytes or no bytes.
///
/// # Errors
/// The directory's, unchanged.
pub async fn in_room(
    directory: &dyn FederationDirectory,
    room: &ScopeRoom,
    limit: u32,
) -> Result<Vec<FileRow>, String> {
    let rows = directory
        .list_attestations_since(None, limit)
        .await
        .map_err(|e| format!("list files in {room}: {e}"))?;
    Ok(rows
        .into_iter()
        .map(|signed| signed.attestation)
        .filter(|row| row.cohort_scope == room.row_scope_token())
        .filter(|row| match room.cohort_target_field() {
            None => true,
            Some(field) => {
                row.attestation_envelope
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    == Some(room.content_group_id())
            }
        })
        .filter_map(|row| FileRow::from_row(&row))
        .collect())
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
