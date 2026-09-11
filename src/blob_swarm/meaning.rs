//! CIRISEdge#581/#586 — **the blob-meaning invariant**.
//!
//! > *"Blobs always have an attestation envelope that says what it is, or
//! > else we have no reason to touch it. No blobs without CEG
//! > envelopes/attestations signed by someone — that is an invalid state."*
//!
//! # What was wrong with the model
//!
//! [`ContentScope`] was a **parameter**. A caller said "this blob is
//! community content of room R" and the store gate believed it, because
//! there was nothing else to believe. Axis 2 of the gate — *are we in the
//! audience this content declares?* — therefore rested on an assertion the
//! caller made about bytes, and an assertion about bytes that nobody signed
//! is not a declaration, it is a preference.
//!
//! That is the same class edge already paid for at CIRISEdge#564: a
//! signature that proved authorship of a *string* read as authorship of the
//! *message*. Here it was worse — there was no signature in the frame at
//! all.
//!
//! # The fix: scope is a PROJECTION, not an input
//!
//! A blob does not describe itself. Bytes are bytes; the sha is an address,
//! not a claim. What says *what a blob is* is the **attestation that
//! references it** — a CEG row, signed, whose envelope names the blob's sha
//! and whose columns carry the cohort the author placed it in.
//!
//! [`BlobMeaning::project`] is the only way to obtain a [`ContentScope`] the
//! store gate will accept, and it takes an [`Attestation`]. So the gate can
//! no longer be handed a scope somebody made up: the type it consumes cannot
//! be built without a row that says the thing.
//!
//! # Why this is a cryptographic root and not a second claim
//!
//! Edge rows are bound before signing
//! ([`bind_attestation_envelope`](crate::replication::attestation_bind::bind_attestation_envelope)):
//! the columns are mirrored INTO the envelope and the canonicalized envelope
//! is what gets signed. The [`BlobPointer`] is a member of that envelope.
//!
//! So for a row whose signature verifies, the triple
//!
//! ```text
//! (content_sha256, cohort_scope, community_key_id)
//! ```
//!
//! is exactly what the author asserted — one signature over all three. An
//! attacker cannot move a sha onto a wider scope without re-signing as
//! somebody the audience gate would have to accept anyway. That is the
//! property axis 2 was missing.
//!
//! # `holds_bytes` is POSSESSION, and possession is not meaning
//!
//! The one distinction this module exists to make. persist's
//! `put_blob_scoped` auto-emits a `holds_bytes:sha256:*` row, so *every*
//! stored blob already has a signed attestation pointing at it. It is not
//! the one we mean:
//!
//! | | `holds_bytes` | a content row |
//! |---|---|---|
//! | says | "I have these bytes" | "these bytes are X, for Y" |
//! | `attesting_key_id` | the holder | the author |
//! | `attested_key_id` | **itself** | the author |
//! | `cohort_scope` | always `federation` | the content's actual cohort |
//!
//! Reading a `holds_bytes` row as meaning would classify **every** blob on
//! the node as commons content — the one default this stack must never
//! adopt, arrived at by accident. So the projection refuses it by name
//! ([`MeaningRefusal::PossessionIsNotMeaning`]) rather than falling through
//! to the `federation` arm its column would otherwise select.
//!
//! # Fail-closed, and what "closed" costs
//!
//! Every refusal here means the bytes are not admitted. That is the
//! invariant working: a blob nobody has said anything about is not content
//! we are short of context on, it is content we have **no reason to touch**.
//! There is deliberately no "unknown" [`ContentScope`] and no arm that
//! guesses.

use ciris_persist::federation::types::cohort_scope as ps;
use ciris_persist::federation::Attestation;

use super::scope::ContentScope;
use crate::group_content::BlobPointer;
use crate::CohortScope;

/// Why an attestation does not give a blob meaning.
///
/// Each arm is a different fact about the row, because each has a different
/// remedy: fetch the content row, verify the signature, or stop asking.
#[must_use = "a meaning refusal is the reason bytes are not admitted — book it, do not drop it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeaningRefusal {
    /// The row carries no signature at all. "Signed by someone" is the
    /// floor of the invariant, and an unsigned row clears no part of it.
    ///
    /// This is a STRUCTURAL check — it refuses a row with an empty
    /// signature column, not a row whose signature is wrong. Verifying
    /// against the signer's pubkey is the admission path's job and needs a
    /// directory; this function is pure so it can be tested at the exact
    /// inputs the field produces.
    Unsigned,
    /// The row is a `holds_bytes` possession claim. See the module docs:
    /// it proves someone has the bytes and says nothing about what they
    /// are, and its `federation` column would silently classify every blob
    /// on the node as commons.
    PossessionIsNotMeaning,
    /// The row is signed and is not a possession claim, but nothing in its
    /// envelope names THIS blob. A row about some other content cannot
    /// lend its scope to these bytes.
    DoesNotReference {
        /// The sha that was looked for, hex, for the log line.
        sha256_hex: String,
    },
    /// The row's `cohort_scope` column is a token edge has no mapping for.
    /// Refused rather than defaulted — a scope we cannot name is a scope we
    /// cannot honour.
    UnknownScope {
        /// The token as it appeared on the row.
        scope: String,
    },
    /// A scoped (non-commons) row must say WHICH group, because
    /// [`CohortScope`] names a kind and a node may belong to several. The
    /// pointer's `community_key_id` and the envelope's `community_key_id`
    /// were both absent or empty.
    GroupWithoutId {
        /// The scope token that required an id.
        scope: String,
    },
}

impl MeaningRefusal {
    /// Stable token for telemetry / structured logging.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::PossessionIsNotMeaning => "possession_is_not_meaning",
            Self::DoesNotReference { .. } => "does_not_reference",
            Self::UnknownScope { .. } => "unknown_scope",
            Self::GroupWithoutId { .. } => "group_without_id",
        }
    }
}

impl std::fmt::Display for MeaningRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsigned => write!(f, "the referencing row carries no signature"),
            Self::PossessionIsNotMeaning => write!(
                f,
                "a holds_bytes row is possession, not meaning — it says who has \
                 the bytes, never what they are"
            ),
            Self::DoesNotReference { sha256_hex } => {
                write!(f, "the row does not reference blob {sha256_hex}")
            }
            Self::UnknownScope { scope } => write!(f, "unmapped cohort_scope {scope:?}"),
            Self::GroupWithoutId { scope } => {
                write!(f, "scope {scope:?} names no group to belong to")
            }
        }
    }
}

impl std::error::Error for MeaningRefusal {}

/// **What a blob is**, projected from the signed row that says so.
///
/// Holding one of these is the proof the invariant demands: these bytes have
/// a CEG attestation, signed by a named party, that places them in a named
/// cohort. It is the only input the store gate accepts for its scope axis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobMeaning {
    scope: ContentScope,
    attesting_key_id: String,
    attestation_id: String,
    sha256: [u8; 32],
    media_type: Option<String>,
}

impl BlobMeaning {
    /// Project a blob's meaning out of the attestation that references it.
    ///
    /// # The steps, in the order they refuse
    ///
    /// 1. **signed by someone** — an empty signature column is refused
    ///    before anything else is read;
    /// 2. **not a possession claim** — `holds_bytes` is refused by name;
    /// 3. **references THIS blob** — the envelope must carry a
    ///    [`BlobPointer`] (or an `evidence_refs` entry) naming `blob_sha256`;
    /// 4. **the scope is one we can name**, and a scoped row names its
    ///    group.
    ///
    /// # Errors
    ///
    /// [`MeaningRefusal`], which names which of the four failed.
    pub fn project(row: &Attestation, blob_sha256: &[u8; 32]) -> Result<Self, MeaningRefusal> {
        // (1) Signed by someone. Note the AND: a signature with no key id
        // names nobody, and a key id with no signature proves nothing —
        // either alone is a row that clears no part of "signed by someone".
        if row.scrub_signature_classical.trim().is_empty() || row.scrub_key_id.trim().is_empty() {
            return Err(MeaningRefusal::Unsigned);
        }

        // (2) Possession is not meaning. Checked on BOTH the type prefix and
        // the envelope `kind`, because the two are written by different
        // producers (persist stamps the type; the envelope is what a peer
        // sends) and either one alone identifies the shape.
        let envelope_kind = row
            .attestation_envelope
            .get("kind")
            .and_then(serde_json::Value::as_str);
        if row.attestation_type.starts_with(HOLDS_BYTES_TYPE_PREFIX)
            || envelope_kind == Some(HOLDS_BYTES_KIND)
        {
            return Err(MeaningRefusal::PossessionIsNotMeaning);
        }

        // (3) It must name THIS blob.
        let sha_hex = hex::encode(blob_sha256);
        let pointer = find_pointer(&row.attestation_envelope, &sha_hex);
        let referenced =
            pointer.is_some() || references_as_evidence(&row.attestation_envelope, &sha_hex);
        if !referenced {
            return Err(MeaningRefusal::DoesNotReference {
                sha256_hex: sha_hex,
            });
        }

        // (4) The scope, from the COLUMN.
        //
        // Not from the envelope's row mirror, though both are signed. The
        // column is what the substrate filters and replicates on, and
        // persist's `RowMirror` check at admission is what binds the two —
        // so projecting from the mirror would classify by a field that, on
        // a row that has not been through admission yet, is free to
        // disagree with the one that actually decides where the row goes.
        let scope_token = row.cohort_scope.as_str();
        let group_id = || {
            pointer
                .as_ref()
                .and_then(|p| non_empty(&p.community_key_id))
                .or_else(|| {
                    row.attestation_envelope
                        .get(ENVELOPE_COMMUNITY_ID)
                        .and_then(serde_json::Value::as_str)
                        .and_then(non_empty)
                })
                .ok_or_else(|| MeaningRefusal::GroupWithoutId {
                    scope: scope_token.to_owned(),
                })
        };

        let scope = match scope_token {
            ps::FEDERATION => ContentScope::Federation,
            ps::SELF => ContentScope::Group {
                scope: CohortScope::SelfOnly,
                group_id: group_id()?,
            },
            ps::FAMILY => ContentScope::Group {
                scope: CohortScope::Family,
                group_id: group_id()?,
            },
            // `affiliations` is a community scope with a wider audience, not
            // a different KIND of group — both derive addresses from the
            // named community's exporter secret.
            ps::COMMUNITY | ps::AFFILIATIONS => {
                let id = group_id()?;
                ContentScope::Group {
                    scope: CohortScope::Cohort {
                        cohort_id: id.clone(),
                    },
                    group_id: id,
                }
            }
            other => {
                return Err(MeaningRefusal::UnknownScope {
                    scope: other.to_owned(),
                })
            }
        };

        Ok(Self {
            scope,
            attesting_key_id: row.attesting_key_id.clone(),
            attestation_id: row.attestation_id.clone(),
            sha256: *blob_sha256,
            media_type: pointer.and_then(|p| p.media_type),
        })
    }

    /// The cohort this content was placed in, by the party that signed it.
    #[must_use]
    pub fn scope(&self) -> &ContentScope {
        &self.scope
    }

    /// Who said so. The store gate does not use this — axis 1 is about the
    /// party the bytes arrive FROM, which is a different question — but a
    /// refusal that cannot name the author is a refusal nobody can act on.
    #[must_use]
    pub fn attesting_key_id(&self) -> &str {
        &self.attesting_key_id
    }

    /// The row this meaning came from, so a log line can be followed back.
    #[must_use]
    pub fn attestation_id(&self) -> &str {
        &self.attestation_id
    }

    /// The blob this meaning is about. Bound at projection, so a
    /// `BlobMeaning` can never be carried to a different blob.
    #[must_use]
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    /// What the author said the bytes are, if the pointer carried it.
    #[must_use]
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }
}

/// persist's `holds_bytes:sha256:<prefix>` attestation-type prefix.
const HOLDS_BYTES_TYPE_PREFIX: &str = "holds_bytes:";
/// The `kind` a `holds_bytes` envelope carries.
const HOLDS_BYTES_KIND: &str = "holds_bytes";
/// The envelope member a chat/content row puts its community on.
const ENVELOPE_COMMUNITY_ID: &str = crate::chat::FIELD_COMMUNITY_ID;

fn non_empty(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// Find a [`BlobPointer`] in the envelope that names `sha_hex`.
///
/// Scans the envelope's top-level members rather than looking under one
/// fixed key: the pointer field name is per-content-type (`content` for
/// chat, while a file or A/V row is free to carry several — a body, a
/// preview, an attachment). What makes a member a pointer is that it
/// PARSES as one and names this blob, which is a stronger test than a key
/// spelling anyway, and it means a new content type gets the invariant
/// without touching this function.
///
/// The scan is over the top level only. A pointer nested inside an
/// arbitrary sub-object is deliberately NOT found: recursing would let a
/// row grant meaning to bytes from a member it never meant as a reference,
/// and "somewhere in this JSON there is a matching hash" is not a
/// declaration about content.
fn find_pointer(envelope: &serde_json::Value, sha_hex: &str) -> Option<BlobPointer> {
    envelope
        .as_object()?
        .values()
        .filter(|v| v.is_object())
        .filter_map(|v| serde_json::from_value::<BlobPointer>(v.clone()).ok())
        .find(|p| p.content_sha256.eq_ignore_ascii_case(sha_hex))
}

/// Does an `evidence_refs` array name this blob?
///
/// The second reference shape, for rows that point at bytes without a
/// typed pointer — a manifest, an evidence bundle. It carries no scope of
/// its own, so the row's column is the whole answer for these.
fn references_as_evidence(envelope: &serde_json::Value, sha_hex: &str) -> bool {
    envelope
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|refs| {
            refs.iter()
                .filter_map(serde_json::Value::as_str)
                .any(|r| r.eq_ignore_ascii_case(sha_hex))
        })
}

/// Row fixtures shared by this module's tests and the store gate's.
///
/// There is deliberately **no** non-test constructor for [`BlobMeaning`]:
/// even a test reaches it through [`BlobMeaning::project`], so a fixture
/// that would not survive the invariant cannot be used to prove anything
/// about the gate behind it.
#[cfg(test)]
pub(crate) mod fixture {
    use super::*;

    /// A signed content row placing `sha` in `scope_token` / `group_id`.
    pub(crate) fn content_row(scope_token: &str, group_id: &str, sha: &[u8; 32]) -> Attestation {
        let mut row = bare_row(scope_token);
        row.attestation_envelope = serde_json::json!({
            "dimension": "chat.message",
            ENVELOPE_COMMUNITY_ID: group_id,
            "content": {
                "community_key_id": group_id,
                "tier": "plaintext",
                "content_sha256": hex::encode(sha),
                "content_field": "body",
                "media_type": "text/plain",
            },
        });
        row
    }

    /// A signed row with the columns filled and an empty envelope.
    pub(crate) fn bare_row(scope_token: &str) -> Attestation {
        let at = chrono::DateTime::from_timestamp(1_767_225_296, 0).expect("ts");
        Attestation {
            attestation_id: "row-1".into(),
            attesting_key_id: "alice".into(),
            attested_key_id: "alice".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: serde_json::json!({}),
            original_content_hash: "00".repeat(32),
            scrub_signature_classical: "sig".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "alice".into(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec!["alice".into()],
            withdraws_admission_rule: None,
            cohort_scope: scope_token.to_owned(),
            tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// The federation-scoped meaning of `sha`, for a gate test that only
    /// cares about the other axes.
    pub(crate) fn commons(sha: &[u8; 32]) -> BlobMeaning {
        let mut row = bare_row(ciris_persist::federation::types::cohort_scope::FEDERATION);
        row.attestation_envelope = serde_json::json!({ "evidence_refs": [hex::encode(sha)] });
        BlobMeaning::project(&row, sha).expect("a signed commons row names its blob")
    }

    /// The community-scoped meaning of `sha`.
    pub(crate) fn community(sha: &[u8; 32]) -> BlobMeaning {
        let row = content_row(
            ciris_persist::federation::types::cohort_scope::COMMUNITY,
            "g-1",
            sha,
        );
        BlobMeaning::project(&row, sha).expect("a signed community row names its blob")
    }

    /// The `self`-scoped meaning of `sha`.
    pub(crate) fn own(sha: &[u8; 32]) -> BlobMeaning {
        let row = content_row(
            ciris_persist::federation::types::cohort_scope::SELF,
            "g-1",
            sha,
        );
        BlobMeaning::project(&row, sha).expect("a signed self row names its blob")
    }

    /// The `family`-scoped meaning of `sha`.
    pub(crate) fn family(sha: &[u8; 32]) -> BlobMeaning {
        let row = content_row(
            ciris_persist::federation::types::cohort_scope::FAMILY,
            "g-1",
            sha,
        );
        BlobMeaning::project(&row, sha).expect("a signed family row names its blob")
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{bare_row, content_row};
    use super::*;

    const SHA: [u8; 32] = [9u8; 32];
    const OTHER: [u8; 32] = [8u8; 32];

    fn ps() -> &'static str {
        ciris_persist::federation::types::cohort_scope::COMMUNITY
    }

    /// The happy path, and the shape every content type gets.
    #[test]
    fn a_signed_content_row_gives_its_blob_a_scope() {
        let row = content_row(ps(), "room-7", &SHA);
        let m = BlobMeaning::project(&row, &SHA).expect("project");
        assert_eq!(
            m.scope(),
            &ContentScope::Group {
                scope: CohortScope::Cohort {
                    cohort_id: "room-7".into()
                },
                group_id: "room-7".into(),
            },
        );
        assert_eq!(m.attesting_key_id(), "alice");
        assert_eq!(m.sha256(), &SHA);
        assert_eq!(m.media_type(), Some("text/plain"));
    }

    /// **The invariant.** persist auto-emits a `holds_bytes` row for every
    /// blob it stores, so if possession counted as meaning, every blob on
    /// the node would classify as commons — the exact default this stack
    /// must never reach, arrived at by accident.
    #[test]
    fn a_holds_bytes_row_is_possession_and_never_meaning() {
        let real = ciris_persist::federation::blobs::holds_bytes_attestation_row(
            &SHA,
            "alice",
            "hb-1",
            chrono::DateTime::from_timestamp(1_767_225_296, 0).expect("ts"),
        );
        // It genuinely references the blob, and its column genuinely says
        // `federation` — so only the by-name refusal stands between this row
        // and a commons classification.
        assert!(
            references_as_evidence(&real.attestation_envelope, &hex::encode(SHA)),
            "fixture drift: the real holds_bytes row must reference the blob",
        );
        assert_eq!(
            real.cohort_scope,
            ciris_persist::federation::types::cohort_scope::FEDERATION,
        );

        let mut signed = real;
        signed.scrub_signature_classical = "sig".into();
        signed.scrub_key_id = "alice".into();
        assert_eq!(
            BlobMeaning::project(&signed, &SHA),
            Err(MeaningRefusal::PossessionIsNotMeaning),
        );
    }

    /// The same refusal when only the envelope `kind` identifies the shape —
    /// a peer sends the envelope, persist stamps the type, and either alone
    /// must be enough.
    #[test]
    fn a_holds_bytes_envelope_is_refused_on_kind_alone() {
        let mut row = bare_row(ciris_persist::federation::types::cohort_scope::FEDERATION);
        row.attestation_type = "scores".into();
        row.attestation_envelope = serde_json::json!({
            "kind": "holds_bytes",
            "evidence_refs": [hex::encode(SHA)],
        });
        assert_eq!(
            BlobMeaning::project(&row, &SHA),
            Err(MeaningRefusal::PossessionIsNotMeaning),
        );
    }

    /// A row about other content cannot lend this blob its scope.
    #[test]
    fn a_row_that_names_another_blob_does_not_reference_this_one() {
        let row = content_row(ps(), "room-7", &OTHER);
        assert_eq!(
            BlobMeaning::project(&row, &SHA),
            Err(MeaningRefusal::DoesNotReference {
                sha256_hex: hex::encode(SHA)
            }),
        );
    }

    /// "Signed by someone" is the floor. Both halves are required: a
    /// signature naming nobody and a name backing nothing each clear none
    /// of it.
    #[test]
    fn an_unsigned_row_says_nothing_however_well_formed() {
        for (sig, key) in [("", "alice"), ("sig", ""), ("", ""), ("   ", "alice")] {
            let mut row = content_row(ps(), "room-7", &SHA);
            row.scrub_signature_classical = sig.into();
            row.scrub_key_id = key.into();
            assert_eq!(
                BlobMeaning::project(&row, &SHA),
                Err(MeaningRefusal::Unsigned),
                "sig={sig:?} key={key:?}",
            );
        }
    }

    /// A scope token edge has no mapping for is refused, not defaulted.
    #[test]
    fn an_unmapped_scope_is_refused_rather_than_guessed() {
        let row = content_row("galactic", "room-7", &SHA);
        assert_eq!(
            BlobMeaning::project(&row, &SHA),
            Err(MeaningRefusal::UnknownScope {
                scope: "galactic".into()
            }),
        );
    }

    /// A scoped row must say WHICH group: `CohortScope` names a kind, and a
    /// node belongs to several.
    #[test]
    fn a_scoped_row_without_a_group_id_is_refused() {
        for scope in [
            ciris_persist::federation::types::cohort_scope::COMMUNITY,
            ciris_persist::federation::types::cohort_scope::FAMILY,
            ciris_persist::federation::types::cohort_scope::SELF,
            ciris_persist::federation::types::cohort_scope::AFFILIATIONS,
        ] {
            let mut row = bare_row(scope);
            row.attestation_envelope = serde_json::json!({
                "evidence_refs": [hex::encode(SHA)],
            });
            assert_eq!(
                BlobMeaning::project(&row, &SHA),
                Err(MeaningRefusal::GroupWithoutId {
                    scope: scope.to_owned()
                }),
                "{scope}",
            );
        }
    }

    /// Commons content needs no group and must not be refused for lacking
    /// one — `Federation` is reachable by construction.
    #[test]
    fn commons_content_needs_no_group_id() {
        let mut row = bare_row(ciris_persist::federation::types::cohort_scope::FEDERATION);
        row.attestation_envelope = serde_json::json!({
            "evidence_refs": [hex::encode(SHA)],
        });
        let m = BlobMeaning::project(&row, &SHA).expect("project");
        assert_eq!(m.scope(), &ContentScope::Federation);
    }

    /// `affiliations` is a wider community audience, not a different KIND
    /// of group: both derive from the named community.
    #[test]
    fn affiliations_projects_onto_the_named_community() {
        let row = content_row(
            ciris_persist::federation::types::cohort_scope::AFFILIATIONS,
            "room-7",
            &SHA,
        );
        let m = BlobMeaning::project(&row, &SHA).expect("project");
        assert_eq!(
            m.scope(),
            &ContentScope::Group {
                scope: CohortScope::Cohort {
                    cohort_id: "room-7".into()
                },
                group_id: "room-7".into(),
            },
        );
    }

    /// The pointer, not a key spelling, is what makes a member a reference —
    /// so a content type that names its pointer field something else gets
    /// the invariant without this function changing.
    #[test]
    fn a_pointer_under_any_field_name_is_found() {
        for field in ["content", "attachment", "preview_0", "recording"] {
            let mut row = bare_row(ps());
            row.attestation_envelope = serde_json::json!({
                crate::chat::FIELD_COMMUNITY_ID: "room-7",
                field: {
                    "community_key_id": "room-7",
                    "tier": "plaintext",
                    "content_sha256": hex::encode(SHA),
                    "content_field": "attachment",
                },
            });
            assert!(
                BlobMeaning::project(&row, &SHA).is_ok(),
                "pointer under {field:?} was not found",
            );
        }
    }

    /// A pointer buried in an arbitrary sub-object is NOT a reference. A row
    /// that happens to quote a hash somewhere has not declared anything
    /// about those bytes.
    #[test]
    fn a_nested_pointer_is_not_a_reference() {
        let mut row = bare_row(ps());
        row.attestation_envelope = serde_json::json!({
            crate::chat::FIELD_COMMUNITY_ID: "room-7",
            "quoted": {
                "their_row": {
                    "community_key_id": "room-7",
                    "tier": "plaintext",
                    "content_sha256": hex::encode(SHA),
                    "content_field": "body",
                },
            },
        });
        assert_eq!(
            BlobMeaning::project(&row, &SHA),
            Err(MeaningRefusal::DoesNotReference {
                sha256_hex: hex::encode(SHA)
            }),
        );
    }

    /// The meaning is bound to the blob it was projected for, so it cannot
    /// be carried onto different bytes.
    #[test]
    fn a_meaning_cannot_be_moved_to_another_blob() {
        let row = content_row(ps(), "room-7", &SHA);
        let m = BlobMeaning::project(&row, &SHA).expect("project");
        assert_eq!(m.sha256(), &SHA);
        assert_ne!(m.sha256(), &OTHER);
        // And the same row refuses to project for the other blob at all.
        assert!(BlobMeaning::project(&row, &OTHER).is_err());
    }

    /// Every refusal has a distinct telemetry token — a log that collapses
    /// two of these collapses two different remedies.
    #[test]
    fn refusal_kinds_are_distinct() {
        let all = [
            MeaningRefusal::Unsigned,
            MeaningRefusal::PossessionIsNotMeaning,
            MeaningRefusal::DoesNotReference {
                sha256_hex: String::new(),
            },
            MeaningRefusal::UnknownScope {
                scope: String::new(),
            },
            MeaningRefusal::GroupWithoutId {
                scope: String::new(),
            },
        ];
        let mut kinds: Vec<&str> = all.iter().map(MeaningRefusal::kind).collect();
        kinds.sort_unstable();
        let n = kinds.len();
        kinds.dedup();
        assert_eq!(kinds.len(), n, "two refusals share a telemetry token");
    }
}
