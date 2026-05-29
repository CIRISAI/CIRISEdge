//! `KeyBoundaryScope` — wire-form scope slot for the `key_boundary`
//! invariant per FSD-002 §3.4 (D26 + CIRISEdge#38).
//!
//! # v0.16.0 — wire types only, no enforcement
//!
//! Today's `key_boundary` invariant in edge is **AV-17**: "no seed
//! bytes enter edge's heap" (see `docs/THREAT_MODEL.md` §AV-17). The
//! invariant is process-wide — the threat model says "edge's process
//! never holds a seed". v0.16.0 extends the wire shape to carry a
//! `{scope}` slot so future federation deployments can express
//! per-tenant / per-channel / per-cohort / per-data-class key isolation
//! WITHOUT a wire break.
//!
//! Per the v0.16.0 brief and FSD-002 §3.4, this cut lands the
//! WIRE-FORM PRIMITIVE only: serialize, parse, round-trip, document
//! the wire string. The actual ENFORCEMENT of scoping (binding
//! signatures to a scope, refusing cross-scope verify, etc.) is
//! v0.16.1+ scope and intentionally NOT touched here.
//!
//! # Wire form
//!
//! The slot is a string: `key_boundary:{scope}:no_seed_in_heap` where
//! `{scope}` is one of:
//!
//! - `process` — current default; AV-17 process-wide (backward compat).
//! - `tenant:{tenant_id}` — per-tenant key isolation (multi-tenancy).
//! - `channel:{channel_id}` — per-channel scoping.
//! - `cohort:{cohort_id}` — per-cohort scoping (federation sub-grouping).
//! - `data_class:{class}` — per-data-class scoping (IEEE Ch6 alignment).
//!
//! Legacy `key_boundary:no_seed_in_heap` (pre-v0.16.0) parses as
//! [`KeyBoundaryScope::Process`] — the AV-17 process-wide invariant.
//!
//! # Placement
//!
//! The scope rides on the envelope, NOT on the transport handshake.
//! Rationale: the envelope is the canonical signed object — every
//! transport carries it byte-equivalent — and future enforcement
//! (binding signatures to a scope at verify time) naturally lives on
//! the canonical-bytes path. Transport-handshake placement would
//! create per-transport divergence (HTTP / Reticulum / future LoRa
//! each would need their own slot encoding). See §6 of FSD-002 v1.4
//! and CIRISEdge#38 body.
//!
//! Scope-ID strings are wire-quoted with backslash-escaping to avoid
//! ambiguity with the `:` separator; see [`encode_scope_id`] /
//! [`decode_scope_id`] for the per-character rules.

use serde::{Deserialize, Serialize};

/// Prefix for the wire-shaped key-boundary invariant slot.
///
/// Full wire form: `{KEY_BOUNDARY_PREFIX}{scope_wire}{KEY_BOUNDARY_SUFFIX}`
/// where `scope_wire` is `KeyBoundaryScope::as_wire_string`.
pub const KEY_BOUNDARY_PREFIX: &str = "key_boundary:";

/// Suffix for the wire-shaped key-boundary invariant slot — the
/// AV-17 "no_seed_in_heap" tail. Pinned as a constant so a future
/// rename is a single-grep.
pub const KEY_BOUNDARY_SUFFIX: &str = ":no_seed_in_heap";

/// Legacy v0.15.x wire string — `key_boundary:no_seed_in_heap` with no
/// scope slot. Parses as [`KeyBoundaryScope::Process`] for backward
/// compatibility.
pub const LEGACY_NO_SEED_IN_HEAP: &str = "key_boundary:no_seed_in_heap";

/// Wire-shaped scope discriminator for the `key_boundary` invariant
/// per FSD-002 §3.4 + IEEE Ch6 (D26 + CIRISEdge#38).
///
/// [`Process`] is the default and matches the legacy v0.15.x wire
/// form (`key_boundary:no_seed_in_heap`); all other variants are new
/// at v0.16.0 and carry an opaque scope-id string. Edge does NOT
/// interpret the scope-id (the cohort enumeration, tenant directory,
/// data-class taxonomy etc. live in the policy tier consumers manage
/// — see MISSION.md §10 license-locked mission preservation).
///
/// Round-trip is via [`Self::as_wire_string`] and [`Self::from_wire_string`].
///
/// [`Process`]: KeyBoundaryScope::Process
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum KeyBoundaryScope {
    /// AV-17 process-wide invariant — current default behavior, the
    /// only variant pre-v0.16.0 deployments emit. Wire string:
    /// `key_boundary:process:no_seed_in_heap` (and the legacy
    /// `key_boundary:no_seed_in_heap` parses as this).
    #[default]
    Process,
    /// Per-tenant key isolation — `key_id` material is scoped to
    /// the given `tenant_id`. Wire string:
    /// `key_boundary:tenant:{tenant_id}:no_seed_in_heap`.
    Tenant {
        /// Opaque tenant identifier (edge does NOT interpret).
        tenant_id: String,
    },
    /// Per-channel scoping — wire string:
    /// `key_boundary:channel:{channel_id}:no_seed_in_heap`.
    Channel {
        /// Opaque channel identifier (edge does NOT interpret).
        channel_id: String,
    },
    /// Per-cohort scoping (federation sub-grouping). Wire string:
    /// `key_boundary:cohort:{cohort_id}:no_seed_in_heap`.
    Cohort {
        /// Opaque cohort identifier (edge does NOT interpret).
        cohort_id: String,
    },
    /// Per-data-class scoping per IEEE Ch6 alignment. Wire string:
    /// `key_boundary:data_class:{class}:no_seed_in_heap`.
    DataClass {
        /// Opaque data-class label (edge does NOT interpret).
        class: String,
    },
}

/// Errors raised by [`KeyBoundaryScope::from_wire_string`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyBoundaryParseError {
    /// String did not start with [`KEY_BOUNDARY_PREFIX`].
    #[error("key_boundary scope missing '{KEY_BOUNDARY_PREFIX}' prefix")]
    MissingPrefix,
    /// String did not end with [`KEY_BOUNDARY_SUFFIX`].
    #[error("key_boundary scope missing '{KEY_BOUNDARY_SUFFIX}' suffix")]
    MissingSuffix,
    /// Recognized scope kind (`tenant` / `channel` / `cohort` /
    /// `data_class`) but the trailing scope-id segment was absent.
    #[error("key_boundary scope '{kind}' requires an id segment")]
    MissingScopeId {
        /// The scope kind that was missing its id (e.g. `tenant`).
        kind: String,
    },
    /// Unknown scope-kind prefix.
    #[error("key_boundary unknown scope kind '{kind}'")]
    UnknownKind {
        /// The unrecognized kind token.
        kind: String,
    },
    /// Scope-id contained an unterminated backslash escape (an
    /// odd number of trailing backslashes).
    #[error("key_boundary scope id has dangling backslash escape")]
    DanglingEscape,
}

impl KeyBoundaryScope {
    /// Render the scope to its wire-form string per FSD-002 §3.4.
    /// Round-trips via [`Self::from_wire_string`].
    #[must_use]
    pub fn as_wire_string(&self) -> String {
        let body = match self {
            Self::Process => String::from("process"),
            Self::Tenant { tenant_id } => format!("tenant:{}", encode_scope_id(tenant_id)),
            Self::Channel { channel_id } => format!("channel:{}", encode_scope_id(channel_id)),
            Self::Cohort { cohort_id } => format!("cohort:{}", encode_scope_id(cohort_id)),
            Self::DataClass { class } => format!("data_class:{}", encode_scope_id(class)),
        };
        format!("{KEY_BOUNDARY_PREFIX}{body}{KEY_BOUNDARY_SUFFIX}")
    }

    /// Parse a wire-form `key_boundary:*` string into a typed scope.
    ///
    /// The legacy v0.15.x form `key_boundary:no_seed_in_heap` (no
    /// scope segment between prefix and suffix) parses as
    /// [`Self::Process`] for backward compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`KeyBoundaryParseError`] when the string is missing
    /// the canonical prefix / suffix, the scope kind is unknown, the
    /// scope-id is missing for a kind that requires one, or an
    /// unterminated backslash escape was encountered.
    pub fn from_wire_string(s: &str) -> Result<Self, KeyBoundaryParseError> {
        // Legacy backward-compat — pre-v0.16.0 emitted no scope slot.
        if s == LEGACY_NO_SEED_IN_HEAP {
            return Ok(Self::Process);
        }
        let rest = s
            .strip_prefix(KEY_BOUNDARY_PREFIX)
            .ok_or(KeyBoundaryParseError::MissingPrefix)?;
        let body = rest
            .strip_suffix(KEY_BOUNDARY_SUFFIX)
            .ok_or(KeyBoundaryParseError::MissingSuffix)?;

        // Body shape: `process` | `<kind>:<encoded_id>`. Split on the
        // FIRST raw (unescaped) `:` so the `<encoded_id>` may legally
        // contain escaped colons.
        let (kind, encoded_id_opt) = split_kind(body);
        match kind {
            "process" => {
                if encoded_id_opt.is_some() {
                    // `key_boundary:process:something:no_seed_in_heap` —
                    // unknown kind under the `process:` prefix.
                    return Err(KeyBoundaryParseError::UnknownKind {
                        kind: "process".to_string(),
                    });
                }
                Ok(Self::Process)
            }
            "tenant" => {
                let id = encoded_id_opt.ok_or(KeyBoundaryParseError::MissingScopeId {
                    kind: "tenant".to_string(),
                })?;
                Ok(Self::Tenant {
                    tenant_id: decode_scope_id(id)?,
                })
            }
            "channel" => {
                let id = encoded_id_opt.ok_or(KeyBoundaryParseError::MissingScopeId {
                    kind: "channel".to_string(),
                })?;
                Ok(Self::Channel {
                    channel_id: decode_scope_id(id)?,
                })
            }
            "cohort" => {
                let id = encoded_id_opt.ok_or(KeyBoundaryParseError::MissingScopeId {
                    kind: "cohort".to_string(),
                })?;
                Ok(Self::Cohort {
                    cohort_id: decode_scope_id(id)?,
                })
            }
            "data_class" => {
                let id = encoded_id_opt.ok_or(KeyBoundaryParseError::MissingScopeId {
                    kind: "data_class".to_string(),
                })?;
                Ok(Self::DataClass {
                    class: decode_scope_id(id)?,
                })
            }
            other => Err(KeyBoundaryParseError::UnknownKind {
                kind: other.to_string(),
            }),
        }
    }
}

/// Encode a scope-id string for embedding in the wire form. The
/// per-character rules:
///
/// - `\` (U+005C) → `\\`
/// - `:` (U+003A) → `\:`
/// - all other code points: passed through verbatim (including
///   whitespace and `/`).
///
/// Round-trips via [`decode_scope_id`]. Pinned as a `pub fn` so the
/// scope-id encoding is auditable / consumer-checkable.
#[must_use]
pub fn encode_scope_id(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str(r"\\"),
            ':' => out.push_str(r"\:"),
            _ => out.push(ch),
        }
    }
    out
}

/// Decode a wire-encoded scope-id string. Reverses [`encode_scope_id`].
///
/// # Errors
///
/// Returns [`KeyBoundaryParseError::DanglingEscape`] if the input ends
/// in an unterminated backslash escape.
pub fn decode_scope_id(s: &str) -> Result<String, KeyBoundaryParseError> {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some(esc) => out.push(esc),
                None => return Err(KeyBoundaryParseError::DanglingEscape),
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

/// Split `body` on the FIRST RAW (unescaped) `:` into `(kind, rest)`.
/// `rest` is None when no separator is present (the `process` case).
/// Backslash-escaped colons (`\:`) are NOT separators.
fn split_kind(body: &str) -> (&str, Option<&str>) {
    let bytes = body.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip the next byte (the escape target)
            b':' => {
                // Safe: ASCII `:` is single-byte and on a char boundary
                // since we only advance by escape-pair or single byte.
                return (&body[..i], Some(&body[i + 1..]));
            }
            _ => i += 1,
        }
    }
    (body, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_default_round_trips() {
        let s = KeyBoundaryScope::Process;
        assert_eq!(s.as_wire_string(), "key_boundary:process:no_seed_in_heap");
        assert_eq!(
            KeyBoundaryScope::from_wire_string(&s.as_wire_string()).unwrap(),
            s
        );
    }

    #[test]
    fn legacy_no_seed_in_heap_parses_as_process() {
        // v0.15.x wire form — must keep parsing as Process so a
        // consumer that pre-dates v0.16.0 keeps working byte-for-byte.
        assert_eq!(
            KeyBoundaryScope::from_wire_string(LEGACY_NO_SEED_IN_HEAP).unwrap(),
            KeyBoundaryScope::Process
        );
    }
}
