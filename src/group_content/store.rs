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
    #[error("not granted: this viewer holds no key for {sha256_hex}")]
    NotGranted {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
    },
    /// The bytes are not held here.
    #[error("not held: {sha256_hex}")]
    NotHeld {
        /// Hex at-rest sha the read targeted.
        sha256_hex: String,
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
    /// Anything else the substrate reported.
    #[error("substrate: {0}")]
    Substrate(String),
}

/// A request to seal content into a group's blob store.
#[derive(Debug, Clone)]
pub struct SealRequest<'a> {
    /// The cohort scope the content is written at — `community`,
    /// `affiliations`, `family`, `self`. Edge names the scope; **persist
    /// resolves the tier** and writes it on the row.
    pub cohort_scope: &'a str,
    /// The community whose DEK seals it. `None` for a commons write.
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
    /// So a reader knows what it has before opening it.
    pub media_type: Option<&'a str>,
}

/// The result of a seal — the pointer to put on the row, plus **who can
/// actually read it**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContent {
    /// Goes on the row in place of the content.
    pub pointer: BlobPointer,
    /// The community epoch this sealed under, for encrypted tiers.
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
    /// `true` when every intended recipient can read this.
    #[must_use]
    pub fn fully_readable(&self) -> bool {
        self.excluded.is_empty()
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
    /// Who is reading. persist authorizes against this before it decrypts.
    pub viewer_key_id: &'a str,
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

    /// Open content a row points at.
    ///
    /// # Errors
    /// [`GroupContentError::NotGranted`] when the viewer holds no key,
    /// [`GroupContentError::SealMismatch`] when the rebuilt AAD does not
    /// match, and the rest as documented.
    async fn open(&self, req: OpenRequest<'_>) -> Result<Vec<u8>, GroupContentError>;
}

/// Build the AAD for a seal request. Exposed so a test — or a second
/// implementation — cannot reach for a different spelling.
#[must_use]
pub fn aad_for_seal(req: &SealRequest<'_>) -> Vec<u8> {
    content_aad(req.author_key_id, req.asserted_at, req.field)
}

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
            content_sha256: "ab".repeat(32),
            content_field: field,
            media_type: None,
            stream_id: None,
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
            media_type: Some("text/plain"),
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

    #[test]
    fn fully_readable_is_false_when_anyone_was_excluded() {
        let base = SealedContent {
            pointer: pointer(ContentField::Body),
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
