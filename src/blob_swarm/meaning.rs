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

use ciris_persist::federation::types::cohort_scope::{self as ps, CryptoTier};
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
    /// id comes, in order, from the pointer's `community_key_id`, the
    /// envelope's cohort target (persist's four aliases, `family_key_id`
    /// among them — CIRISPersist#887), and for a `self` row the author's
    /// identity the caller resolved (`FSD/CONTENT_TRANSFER.md` §6.2). None
    /// was present.
    GroupWithoutId {
        /// The scope token that required an id.
        scope: String,
    },
    /// The envelope names its cohort target under two aliases that
    /// disagree (persist `envelope_cohort_target`, PR #759). Refused
    /// rather than picking one: the row is malformed, and the group we
    /// would route to is the one the writer did not sign for.
    GroupIdAmbiguous {
        /// The scope token.
        scope: String,
        /// Persist's description of the disagreement.
        detail: String,
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
            Self::GroupIdAmbiguous { .. } => "group_id_ambiguous",
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
            Self::GroupIdAmbiguous { scope, detail } => {
                write!(f, "scope {scope:?} names its group ambiguously: {detail}")
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
    /// The typed pointer the row carried, when the reference was one (a
    /// chat row); `None` when the reference was an `evidence_refs` entry
    /// (a manifest). CIRISEdge#601 — the pull adopts through it: tier,
    /// field and sealed-under epoch are all the author's declared facts.
    pointer: Option<BlobPointer>,
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
        Self::project_with(row, blob_sha256, None)
    }

    /// [`Self::project`] with the author's **identity** in hand, which is
    /// what a `self`-placed row that names no community needs for its group
    /// id (`FSD/CONTENT_TRANSFER.md` §6.2, CIRISEdge#646): the self room is
    /// keyed by the identity (CC 3.3.6 `identity_key_id`), a function of the
    /// row's author that the caller resolves through the directory
    /// (`contact::resolve(author).fed_id`) — never a new signed field, so the
    /// installer and the projector compute one id from one fact. A `family`
    /// row needs nothing extra: its `family_key_id` rides the signed
    /// envelope (CIRISPersist#887) and is read through persist's own
    /// cohort-target reader, aliases and all.
    ///
    /// `author_identity` is consulted only for a `self` row with no
    /// community pointer and no envelope target; `None` there refuses
    /// `GroupWithoutId`, the honest answer for a caller that could not
    /// resolve the author.
    ///
    /// # Errors
    ///
    /// [`MeaningRefusal`], which names which check failed.
    pub fn project_with(
        row: &Attestation,
        blob_sha256: &[u8; 32],
        author_identity: Option<&str>,
    ) -> Result<Self, MeaningRefusal> {
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
        // The group id, in order: the pointer's community (the key plane
        // names it), then the envelope's cohort target through persist's OWN
        // reader — four aliases, first non-empty wins, a disagreement is
        // refused (CIRISPersist#887) — so `family_key_id` on a family row
        // and `community_key_id` on a community row are one code path.
        let envelope_target = || -> Result<Option<String>, MeaningRefusal> {
            ciris_persist::federation::admission::envelope_cohort_target(&row.attestation_envelope)
                .map(|t| t.and_then(non_empty))
                .map_err(|e| MeaningRefusal::GroupIdAmbiguous {
                    scope: scope_token.to_owned(),
                    detail: e.to_string(),
                })
        };
        let group_id = |fallback: Option<&str>| -> Result<String, MeaningRefusal> {
            if let Some(c) = pointer
                .as_ref()
                .and_then(|p| non_empty(&p.community_key_id))
            {
                return Ok(c);
            }
            if let Some(t) = envelope_target()? {
                return Ok(t);
            }
            fallback
                .and_then(non_empty)
                .ok_or_else(|| MeaningRefusal::GroupWithoutId {
                    scope: scope_token.to_owned(),
                })
        };

        let scope = match scope_token {
            ps::FEDERATION => ContentScope::Federation,
            // A self row's group is the self-collective: the author's
            // identity, resolved by the caller — unless the pointer names a
            // community, in which case the bytes are that room's (the
            // owner's own copy of a chat message) and the id is the room's.
            ps::SELF => ContentScope::Group {
                scope: CohortScope::SelfOnly,
                group_id: group_id(author_identity)?,
            },
            ps::FAMILY => ContentScope::Group {
                scope: CohortScope::Family,
                group_id: group_id(None)?,
            },
            // `affiliations` is a community scope with a wider audience, not
            // a different KIND of group — both derive addresses from the
            // named community's exporter secret.
            ps::COMMUNITY | ps::AFFILIATIONS => {
                let id = group_id(None)?;
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
            media_type: pointer.as_ref().and_then(|p| p.media_type.clone()),
            pointer,
        })
    }

    /// CIRISEdge#601 — every blob `row` references, in the two shapes
    /// [`Self::project`] accepts: a top-level [`BlobPointer`] object, or an
    /// `evidence_refs` entry that is a 64-hex sha. Deduplicated, in envelope
    /// order.
    ///
    /// A `holds_bytes` row returns **nothing**, by name: it references its
    /// blob too, but as possession, and a puller that fetched on possession
    /// claims would fetch every blob every peer announced. The full
    /// projection refuses it as `PossessionIsNotMeaning`; this pre-check
    /// keeps the apply path from cloning a row it would then refuse.
    ///
    /// Signature is NOT checked here — that is `project`'s job, per sha,
    /// and it runs before any byte moves. This is the cheap "should the
    /// apply path even hand this row to the puller" question.
    #[must_use]
    pub fn referenced_shas(row: &Attestation) -> Vec<[u8; 32]> {
        if row.attestation_type.starts_with(HOLDS_BYTES_TYPE_PREFIX)
            || row
                .attestation_envelope
                .get("kind")
                .and_then(serde_json::Value::as_str)
                == Some(HOLDS_BYTES_KIND)
        {
            return Vec::new();
        }
        let Some(obj) = row.attestation_envelope.as_object() else {
            return Vec::new();
        };
        let mut out: Vec<[u8; 32]> = Vec::new();
        let mut push = |hex_sha: &str| {
            if let Ok(bytes) = hex::decode(hex_sha) {
                if let Ok(arr) = <[u8; 32]>::try_from(bytes) {
                    if !out.contains(&arr) {
                        out.push(arr);
                    }
                }
            }
        };
        for v in obj.values().filter(|v| v.is_object()) {
            if let Ok(p) = serde_json::from_value::<BlobPointer>(v.clone()) {
                push(&p.content_sha256);
            }
        }
        if let Some(refs) = obj
            .get("evidence_refs")
            .and_then(serde_json::Value::as_array)
        {
            for r in refs.iter().filter_map(serde_json::Value::as_str) {
                push(r);
            }
        }
        out
    }

    /// The typed pointer this meaning was projected through, if the
    /// reference was one. `None` for an `evidence_refs` reference.
    #[must_use]
    pub fn pointer(&self) -> Option<&BlobPointer> {
        self.pointer.as_ref()
    }

    /// **The key plane** — the group whose secret sealed the bytes, from
    /// the POINTER (persist#878: `tier` / `community_key_id` / `epoch` are
    /// the pointer's; `cohort_scope` is the row's). This is the scope that
    /// answers *where the bytes are and who may hand them over*: the holder
    /// source, the scope-address route, and the store gate's TRUST axis.
    /// [`Self::scope`] (the placement) answers *who is party to the row*:
    /// the audience axis, the adopt disposition, the announce decision.
    ///
    /// The two differ on exactly one shape today: a row placed at `self`
    /// (the owner's own copy) whose pointer names a community — the bytes
    /// are the room's, sealed under the room's DEK, held by the room's
    /// members and reached on the room's derived address. Routing the
    /// owner's second device to a `self` table entry keyed by the room's id
    /// would ask for a group nobody installs; routing it to the room asks
    /// the members who hold it. For every other row the two coincide.
    #[must_use]
    pub fn key_plane(&self) -> ContentScope {
        match (&self.scope, self.pointer.as_ref()) {
            (
                ContentScope::Group {
                    scope: CohortScope::SelfOnly | CohortScope::Family,
                    ..
                },
                Some(p),
            ) if p.tier == CryptoTier::CommunityDek && !p.community_key_id.is_empty() => {
                ContentScope::Group {
                    scope: CohortScope::Cohort {
                        cohort_id: p.community_key_id.clone(),
                    },
                    group_id: p.community_key_id.clone(),
                }
            }
            _ => self.scope.clone(),
        }
    }

    /// The cohort this content was placed in, by the party that signed it —
    /// the row's placement. See [`Self::key_plane`] for which questions
    /// each facet answers.
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
#[cfg(test)]
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

/// Every blob this row REFERENCES — the inverse of [`BlobMeaning::project`],
/// over exactly the same two shapes and nothing else.
///
/// [`project`](BlobMeaning::project) answers "does this row give THESE bytes
/// meaning"; this answers "which bytes does this row give meaning to", for the
/// side that starts from the row — a `withdraws` landing against it
/// (CIRISEdge#606) needs to know which bytes just lost a reference. Same
/// top-level-only pointer scan, same `evidence_refs` read, so the two can
/// never disagree about what counts as a reference. A `holds_bytes` row is
/// possession and references nothing — the caller checks that by type, as
/// `project` does, before asking.
///
/// Entries that are not 64 lowercase-or-uppercase hex characters are
/// skipped: `evidence_refs` may carry other kinds of evidence, and a pointer
/// with a malformed hash is a row the store gate would refuse anyway.
#[must_use]
pub fn referenced_shas(envelope: &serde_json::Value) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    let mut push = |hex_str: &str| {
        if let Ok(bytes) = hex::decode(hex_str) {
            if let Ok(arr) = <[u8; 32]>::try_from(bytes.as_slice()) {
                if !out.contains(&arr) {
                    out.push(arr);
                }
            }
        }
    };
    if let Some(obj) = envelope.as_object() {
        for v in obj.values().filter(|v| v.is_object()) {
            if let Ok(p) = serde_json::from_value::<BlobPointer>(v.clone()) {
                push(&p.content_sha256);
            }
        }
    }
    if let Some(refs) = envelope
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
    {
        for r in refs.iter().filter_map(serde_json::Value::as_str) {
            push(r);
        }
    }
    out
}

/// Is this row a `holds_bytes` claim — possession, never a reference?
///
/// The same two checks [`BlobMeaning::project`] step (2) makes, exposed so
/// the revocation side asks the identical question.
#[must_use]
pub fn is_holds_bytes_row(row: &Attestation) -> bool {
    row.attestation_type.starts_with(HOLDS_BYTES_TYPE_PREFIX)
        || row
            .attestation_envelope
            .get("kind")
            .and_then(serde_json::Value::as_str)
            == Some(HOLDS_BYTES_KIND)
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
mod facets_646 {
    //! CIRISEdge#646 / `FSD/CONTENT_TRANSFER.md` §6.2 — the group-id rule
    //! for self and family rows, and the two facets (placement from the
    //! row, key plane from the pointer).
    use super::fixture::bare_row;
    use super::*;
    use ciris_persist::federation::types::cohort_scope as ps;

    const SHA: [u8; 32] = [9u8; 32];

    /// A row placed at `self` whose pointer names NO community: an
    /// `InvisibleEncrypted` blob of the owner's own.
    fn self_row() -> Attestation {
        let mut row = bare_row(ps::SELF);
        row.attestation_envelope = serde_json::json!({
            "dimension": "file:attachment:v1",
            "content": {
                "community_key_id": "",
                "tier": "invisible_encrypted",
                "content_sha256": hex::encode(SHA),
                "content_field": "body",
            },
        });
        row
    }

    #[test]
    fn a_self_row_without_a_community_projects_the_authors_identity_as_its_group() {
        let row = self_row();
        // The caller resolved the author (a node key) to the person it is
        // an occurrence of — that identity IS the self room's id.
        let m = BlobMeaning::project_with(&row, &SHA, Some("alice-fed")).expect("projects");
        assert_eq!(
            m.scope(),
            &ContentScope::Group {
                scope: CohortScope::SelfOnly,
                group_id: "alice-fed".to_owned(),
            }
        );
        assert_eq!(
            m.key_plane(),
            *m.scope(),
            "an invisible blob's key plane is its placement"
        );
        // Without the identity there is no group to name: refused by name,
        // never defaulted — the honest answer for an unresolved author.
        assert!(matches!(
            BlobMeaning::project(&row, &SHA),
            Err(MeaningRefusal::GroupWithoutId { scope }) if scope == ps::SELF
        ));
        assert!(matches!(
            BlobMeaning::project_with(&row, &SHA, Some("")),
            Err(MeaningRefusal::GroupWithoutId { .. })
        ));
    }

    #[test]
    fn a_family_row_reads_family_key_id_through_persists_cohort_target_reader() {
        let mut row = bare_row(ps::FAMILY);
        row.attestation_envelope = serde_json::json!({
            "dimension": "file:attachment:v1",
            "family_key_id": "fam-7",
            "content": {
                "community_key_id": "",
                "tier": "invisible_encrypted",
                "content_sha256": hex::encode(SHA),
                "content_field": "body",
            },
        });
        // No identity needed: the family's id rides the signed envelope
        // (CIRISPersist#887), under the canonical member.
        let m = BlobMeaning::project(&row, &SHA).expect("projects");
        assert_eq!(
            m.scope(),
            &ContentScope::Group {
                scope: CohortScope::Family,
                group_id: "fam-7".to_owned(),
            }
        );
        // Two populated aliases that disagree are refused by name — the
        // reader is persist's, so the rule is not re-spelled here.
        row.attestation_envelope["community_key_id"] = serde_json::json!("fam-8");
        assert!(matches!(
            BlobMeaning::project(&row, &SHA),
            Err(MeaningRefusal::GroupIdAmbiguous { scope, .. }) if scope == ps::FAMILY
        ));
    }

    #[test]
    fn the_key_plane_follows_the_pointer_and_the_placement_follows_the_row() {
        // The owner's OWN copy of a room message: placed at `self`, sealed
        // under the room's DEK. The placement stays `self` (audience,
        // adopt, announce are the row's); the key plane is the room
        // (holders, route, trust are the room's).
        let mut row = bare_row(ps::SELF);
        row.attestation_envelope = serde_json::json!({
            "dimension": "chat.message",
            "content": {
                "community_key_id": "room-1",
                "tier": "community_dek",
                "epoch": 3,
                "content_sha256": hex::encode(SHA),
                "content_field": "body",
            },
        });
        let m = BlobMeaning::project(&row, &SHA).expect("the pointer names the room");
        assert_eq!(
            m.scope(),
            &ContentScope::Group {
                scope: CohortScope::SelfOnly,
                group_id: "room-1".to_owned(),
            },
            "placement: the owner's own copy"
        );
        assert_eq!(
            m.key_plane(),
            ContentScope::Group {
                scope: CohortScope::Cohort {
                    cohort_id: "room-1".to_owned(),
                },
                group_id: "room-1".to_owned(),
            },
            "key plane: the room that sealed the bytes"
        );
        // A community row's two facets coincide.
        let c = super::fixture::community(&SHA);
        assert_eq!(c.key_plane(), *c.scope());
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{bare_row, content_row};
    use super::*;

    const SHA: [u8; 32] = [9u8; 32];
    const OTHER: [u8; 32] = [8u8; 32];

    /// CIRISEdge#601 — the apply path's pre-check finds both reference
    /// shapes, dedupes, and returns nothing for a possession claim.
    #[test]
    fn referenced_shas_finds_pointers_and_evidence_refs_and_never_possession() {
        // A typed pointer.
        let row = content_row(ps(), "g-1", &SHA);
        assert_eq!(BlobMeaning::referenced_shas(&row), vec![SHA]);

        // An evidence_refs entry, and a pointer to another blob, deduped
        // against a repeat of the first.
        let mut both = content_row(ps(), "g-1", &SHA);
        both.attestation_envelope["evidence_refs"] =
            serde_json::json!([hex::encode(OTHER), hex::encode(SHA)]);
        assert_eq!(BlobMeaning::referenced_shas(&both), vec![SHA, OTHER]);

        // Nothing referenced.
        assert!(BlobMeaning::referenced_shas(&bare_row(ps())).is_empty());

        // A holds_bytes row references its blob as POSSESSION; the pre-check
        // returns nothing, matching `project`'s `PossessionIsNotMeaning`.
        let mut holds = bare_row(ps());
        holds.attestation_type = format!("holds_bytes:sha256:{}", &hex::encode(SHA)[..16]);
        holds.attestation_envelope = serde_json::json!({ "evidence_refs": [hex::encode(SHA)] });
        assert!(BlobMeaning::referenced_shas(&holds).is_empty());
        let mut holds_by_kind = bare_row(ps());
        holds_by_kind.attestation_envelope =
            serde_json::json!({ "kind": "holds_bytes", "evidence_refs": [hex::encode(SHA)] });
        assert!(BlobMeaning::referenced_shas(&holds_by_kind).is_empty());

        // A malformed sha (wrong length) is not a reference.
        let mut short = bare_row(ps());
        short.attestation_envelope = serde_json::json!({ "evidence_refs": ["abcd"] });
        assert!(BlobMeaning::referenced_shas(&short).is_empty());
    }

    /// The projection keeps the pointer it came through, and none for an
    /// evidence_refs reference.
    #[test]
    fn project_retains_the_pointer_it_came_through() {
        let row = content_row(ps(), "g-1", &SHA);
        let m = BlobMeaning::project(&row, &SHA).expect("named");
        assert_eq!(
            m.pointer().map(|p| p.content_sha256.as_str()),
            Some(hex::encode(SHA).as_str())
        );
        let mut ev = bare_row(ps());
        ev.attestation_envelope = serde_json::json!({ ENVELOPE_COMMUNITY_ID: "g-1", "evidence_refs": [hex::encode(SHA)] });
        let m = BlobMeaning::project(&ev, &SHA).expect("named by evidence");
        assert!(m.pointer().is_none());
    }

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
        // v45.0.0 (CIRISPersist#871, AV-89) — the claim carries the blob's
        // byte length; any value serves a projection test that never stores.
        let real = ciris_persist::federation::blobs::holds_bytes_attestation_row(
            &SHA,
            "alice",
            "hb-1",
            chrono::DateTime::from_timestamp(1_767_225_296, 0).expect("ts"),
            42,
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
