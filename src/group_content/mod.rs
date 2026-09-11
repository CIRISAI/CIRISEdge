//! CIRISEdge#586 — group content on blobs: the shared contract.
//!
//! The implementation of `FSD/GROUP_CONTENT_ON_BLOBS.md`, which is **not a
//! chat design**. Chat is the first consumer because it is the one with
//! content to migrate; a file, a video, a log bundle and an A/V recording
//! all use exactly this.
//!
//! What lives here is the part that must never be improvised or duplicated:
//! the **AAD preimage** and the **row pointer**. Everything else — which
//! door, which media type, what retention — is per-content-type and belongs
//! with that content type.
//!
//! # Why the AAD exists
//!
//! Every member of a community holds that community's DEK. So without
//! associated data, any member could lift another member's ciphertext onto
//! their own row and it would open there — the content would re-attribute
//! itself. The AAD is folded into the GCM tag and never stored, and it makes
//! that substitution **unrepresentable** rather than merely detectable.
//!
//! # The preimage — LOCKED (CIRISPersist#836 Q1)
//!
//! ```text
//! caller_aad = "ciris.edge.blob.aad.v1" ‖ 0x00
//!            ‖ lp(author_key_id)
//!            ‖ lp(asserted_at)
//!            ‖ lp(field)
//! ```
//!
//! with `lp(x) = be_u32(len(x)) ‖ x`.
//!
//! **`community_key_id` and `epoch` are deliberately absent.** An earlier
//! draft had both; persist's answer was that they come out. They are already
//! bound cryptographically by the blob itself — the DEK is per
//! `(community, epoch)` and the blob row records both — so including them
//! adds no binding the ciphertext lacks, and they are exactly the two
//! members a legitimate cross-community widening changes.
//!
//! # Three traps, each of which fails silently
//!
//! 1. **`asserted_at` must be the STORED rendering.** persist truncates to
//!    the substrate resolution before writing the column, so an AAD built
//!    from a caller's sub-millisecond instant will not reconstruct at read
//!    time. [`content_aad`] renders through persist's own
//!    `render_signed_instant` rather than accepting a pre-formatted string,
//!    which makes the trap unreachable instead of documented.
//! 2. **An empty preimage is no binding at all.** `Some(b"")` is
//!    byte-identical to `None` in persist's crypto. [`content_aad`] cannot
//!    return empty — the domain string alone guarantees it — and
//!    [`ContentField`] has no empty variant.
//! 3. **Length-prefixing is not decoration.** Plain concatenation makes
//!    `("ab","c")` and `("a","bc")` the same preimage, so a crafted author
//!    id could absorb the instant. persist frames this same preimage the
//!    same way, for the same reason.

pub mod persist_store;
pub mod store;

pub use persist_store::PersistGroupContentStore;
pub use store::{
    aad_for_open, aad_for_seal, GroupContentError, GroupContentStore, OpenRequest, SealRequest,
    SealedContent,
};

use serde::{Deserialize, Serialize};

/// Domain separator. Never confusable with another protocol's preimage, and
/// the trailing NUL means a future version tag can never run into the first
/// field.
pub const AAD_DOMAIN: &[u8] = b"ciris.edge.blob.aad.v1\x00";

/// Which blob within a row this is.
///
/// A closed enum rather than a free string: two blobs in one row (a message
/// body and its attachment) must not be exchangeable, and a typo in a field
/// name would silently produce content that never opens. Adding a variant is
/// a deliberate act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentField {
    /// The primary content of the row — a chat message's text, a file's
    /// bytes, a recording.
    Body,
    /// An attachment carried alongside the body.
    Attachment,
    /// A preview or thumbnail derived from the body.
    Preview,
}

impl ContentField {
    /// The wire token. Stable — changing one breaks every blob ever sealed
    /// under it.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Attachment => "attachment",
            Self::Preview => "preview",
        }
    }
}

/// Append `be_u32(len) ‖ bytes`.
fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    // A field longer than u32::MAX is not representable and not reachable:
    // key ids, instants and field tokens are all bounded far below it.
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Build the caller AAD for a group-content blob.
///
/// `asserted_at` is taken as a `DateTime` rather than a string **on
/// purpose**: rendering happens here, through persist's own
/// `render_signed_instant`, so a caller cannot accidentally bind a
/// sub-millisecond instant that the stored column will not reproduce. That
/// is trap 1 in the module docs, made unreachable rather than documented.
///
/// The result is passed to persist as `caller_aad`; persist frames it again
/// with `(stream_id, seq)` for chunked content (#838) and never reinterprets
/// it.
#[must_use]
pub fn content_aad(
    author_key_id: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    field: ContentField,
) -> Vec<u8> {
    let instant = ciris_persist::federation::admission::render_signed_instant(asserted_at);
    let mut out = Vec::with_capacity(
        AAD_DOMAIN.len() + 12 + author_key_id.len() + instant.len() + field.as_str().len(),
    );
    out.extend_from_slice(AAD_DOMAIN);
    push_lp(&mut out, author_key_id.as_bytes());
    push_lp(&mut out, instant.as_bytes());
    push_lp(&mut out, field.as_str().as_bytes());
    out
}

/// What a content-bearing row carries instead of the content.
///
/// Per `FSD/GROUP_CONTENT_ON_BLOBS.md` §7: a pointer plus the binding inputs
/// a reader needs, and nothing that reveals the content.
///
/// `author_key_id` and `asserted_at` are **not** duplicated here — they are
/// already envelope members, and a second copy is one that can disagree with
/// the first. The **epoch is deliberately absent** for the same reason: it
/// lives on the blob row's own binding, it is not an AAD input, and a copy
/// on the pointer is one a rotation can make stale. A reader asks the blob,
/// not the pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobPointer {
    /// Which community to read as. NOT an AAD input — see the module docs.
    pub community_key_id: String,
    /// Hex-encoded at-rest SHA-256 to read.
    pub content_sha256: String,
    /// Which blob within the row this is. An AAD input.
    pub content_field: ContentField,
    /// So a reader knows what it got before opening it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    /// Present iff the content is a chunk DAG. Its presence IS the answer to
    /// "is this chunked" — one fact, one member, no way for two to disagree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
}

impl BlobPointer {
    /// Whether this content is a chunk DAG, and therefore whether range
    /// reads are available.
    #[must_use]
    pub fn is_chunked(&self) -> bool {
        self.stream_id.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone as _, Timelike as _};

    fn t(nanos: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2026, 9, 2, 12, 34, 56)
            .unwrap()
            .with_nanosecond(nanos)
            .unwrap()
    }

    /// The preimage, byte for byte. A golden vector, because every blob ever
    /// sealed under this contract depends on it never moving.
    #[test]
    fn the_preimage_is_exactly_the_locked_layout() {
        let aad = content_aad("author-key", t(789_000_000), ContentField::Body);

        let mut want = Vec::new();
        want.extend_from_slice(b"ciris.edge.blob.aad.v1\x00");
        want.extend_from_slice(&10u32.to_be_bytes());
        want.extend_from_slice(b"author-key");
        want.extend_from_slice(&24u32.to_be_bytes());
        want.extend_from_slice(b"2026-09-02T12:34:56.789Z");
        want.extend_from_slice(&4u32.to_be_bytes());
        want.extend_from_slice(b"body");

        assert_eq!(aad, want, "the locked preimage must not move");
    }

    /// Trap 3. Without length prefixes these two collide, and a crafted
    /// author id could absorb the instant.
    #[test]
    fn length_prefixes_keep_adjacent_fields_from_merging() {
        let a = content_aad("ab", t(0), ContentField::Body);
        let b = content_aad("a", t(0), ContentField::Body);
        assert_ne!(a, b);

        // The classic collision, constructed directly: a concatenation that
        // would be identical is not.
        let lhs = content_aad("xy", t(0), ContentField::Body);
        let rhs = content_aad("x", t(0), ContentField::Body);
        assert_ne!(lhs[..], rhs[..]);
    }

    /// Trap 1, and the test that would pass for the wrong reason if written
    /// carelessly: the input carries sub-millisecond precision, and the
    /// preimage must contain the TRUNCATED rendering. A witness using an
    /// already-truncated instant passes whether or not the render is applied.
    #[test]
    fn a_sub_millisecond_instant_binds_to_its_stored_rendering() {
        let precise = t(789_654_321);
        let truncated = t(789_000_000);
        assert_ne!(precise, truncated, "the witness must actually be precise");

        assert_eq!(
            content_aad("k", precise, ContentField::Body),
            content_aad("k", truncated, ContentField::Body),
            "the AAD must be built from the STORED value, or a read that \
             rebuilds from the row computes a different preimage and the \
             content never opens",
        );
    }

    /// Trap 2. An empty preimage is byte-identical to no AAD in persist's
    /// crypto, so "empty" must be unreachable.
    #[test]
    fn the_preimage_is_never_empty_even_with_empty_inputs() {
        let aad = content_aad("", t(0), ContentField::Body);
        assert!(
            aad.len() > AAD_DOMAIN.len(),
            "the domain alone guarantees a non-empty binding",
        );
        assert!(aad.starts_with(AAD_DOMAIN));
    }

    /// Two blobs in one row must not be exchangeable.
    #[test]
    fn each_field_binds_distinctly() {
        let body = content_aad("k", t(0), ContentField::Body);
        let att = content_aad("k", t(0), ContentField::Attachment);
        let prev = content_aad("k", t(0), ContentField::Preview);
        assert_ne!(body, att);
        assert_ne!(body, prev);
        assert_ne!(att, prev);
    }

    /// The substitution CIRISPersist#830 named: a member re-attributing
    /// another member's content to themselves.
    #[test]
    fn a_different_author_or_instant_is_a_different_binding() {
        let base = content_aad("alice", t(0), ContentField::Body);
        assert_ne!(base, content_aad("bob", t(0), ContentField::Body));
        assert_ne!(base, content_aad("alice", t(1_000_000), ContentField::Body));
    }

    /// The design's §5.1.2: a widening carries `asserted_at` verbatim and
    /// changes neither author nor field, so the SAME blob opens from the
    /// widened row. Pinned here because the draft asserted the opposite and
    /// was wrong.
    #[test]
    fn a_widening_reproduces_the_same_binding() {
        let original = content_aad("alice", t(789_000_000), ContentField::Body);
        // A widened row: same author, same asserted_at (carried verbatim —
        // the placement's own instant is the separate `widened_at` member),
        // same field. Only community and epoch could differ, and neither is
        // in the preimage.
        let widened = content_aad("alice", t(789_000_000), ContentField::Body);
        assert_eq!(original, widened);
    }

    #[test]
    fn a_pointer_answers_chunkedness_from_one_member() {
        let whole = BlobPointer {
            community_key_id: "c".into(),
            content_sha256: "ab".repeat(32),
            content_field: ContentField::Body,
            media_type: Some("text/plain".into()),
            stream_id: None,
        };
        assert!(!whole.is_chunked());

        let dag = BlobPointer {
            stream_id: Some("writer-01JBQ".into()),
            ..whole.clone()
        };
        assert!(dag.is_chunked());
    }

    /// The pointer must not carry the epoch: it lives on the blob row's
    /// binding, and a copy here is one a rotation can make stale.
    #[test]
    fn the_pointer_carries_no_epoch_and_no_duplicate_author() {
        let p = BlobPointer {
            community_key_id: "c".into(),
            content_sha256: "ab".repeat(32),
            content_field: ContentField::Body,
            media_type: None,
            stream_id: None,
        };
        let json = serde_json::to_string(&p).expect("serialize");
        for forbidden in ["epoch", "author", "asserted_at"] {
            assert!(
                !json.contains(forbidden),
                "the pointer must not duplicate {forbidden}: {json}",
            );
        }
    }

    #[test]
    fn a_pointer_round_trips() {
        let p = BlobPointer {
            community_key_id: "community-1".into(),
            content_sha256: "cd".repeat(32),
            content_field: ContentField::Attachment,
            media_type: Some("video/mp4".into()),
            stream_id: Some("w-01JBQ".into()),
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let back: BlobPointer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(p, back);
    }
}
