//! CIRISEdge#52 (v0.20.1) — multimedia tier transport.
//!
//! Implements the CEWP multimedia tier per
//! `CIRISNodeCore/FSD/MEDIA_SHARING.md`. The substrate (typed rows,
//! attestation index, ACL plumbing) ships in CIRISPersist v3.6.0;
//! this module adds the transport-surface gates and dispatch shims
//! the edge tier owns:
//!
//! 1. **Contribution `subject_kind` discriminator** — recognises [`ContributionSubjectKind::TakedownNotice`] and [`ContributionSubjectKind::KeyGrant`] inside `MessageType::ContributionSubmit` envelopes so the [`crate::edge`] dispatch sub-dispatch can route fast-path vs addressed-delivery semantics.
//! 2. **Fast-path `legal_basis` vocabulary** — [`FastPathLegalBasis`] pins the legal-compliance triggers (TVEC, GIFCT-CIP, NCMEC) that bump dispatch priority + emit a synthetic `FederationAnnouncement` to known holders. Matches the CIRISRegistry CEG 0.3 §5.6.8 LegalBasis enum.
//! 3. **`BlobBody::External` wire shape** — [`ExternalRefWithAcl`] is the `ContentBody` variant for external bytes (films, episodes, long-form video). Edge does NOT fetch the bytes; the consumer's client fetches directly from `external_uri`.
//! 4. **L1-as-CDN-edge opt-in** — operator-side `EdgeConfig::l1_cdn_edge_enabled` + `l1_cdn_edge_external_uri_base` let an L1 server pre-fetch external content and re-emit `holds_bytes` with the operator's own `external_ref`. v0.20.1 ships the wire shape + dispatch hook; the actual prefetch implementation is a stub ([`cdn_edge_prefetch_stub`]) — full bytes-fetching is a post-v1.0 follow-up.
//!
//! See [`MEDIA_SHARING.md`](../../../CIRISNodeCore/FSD/MEDIA_SHARING.md)
//! §2.6 (BlobBody::External), §2.7 (L1-as-CDN-edge), §5.2 (takedown
//! fast-path), §11 (legal_basis vocabulary).
//!
//! Threat-model anchor: `docs/THREAT_MODEL.md` AV-49.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per MEDIA_SHARING.md §5.2 + §11 — the `legal_basis` vocabulary that
/// triggers fast-path takedown propagation at the edge tier.
///
/// **Wire-string codec is `snake_case`** to match CIRISRegistry CEG
/// 0.3 §5.6.8 LegalBasis byte-equivalence. The enum is the typed
/// view; [`FastPathLegalBasis::from_wire`] / [`Self::as_str`] are the
/// codec.
///
/// New variants are additive — adding one here MUST also bump the
/// CEG version + persist's matching enum if a peer's substrate is to
/// recognise the new basis. Edge's `dispatch_inbound` matches on
/// wire-strings (not on the typed enum) so an unknown basis simply
/// falls through to the standard Contribution dispatch path — the
/// fast-path is opt-in per known basis, never a default.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FastPathLegalBasis {
    /// Terrorist Violent Extremism Content — 1-hour SLA per EU TCO/DSA.
    Tvec,
    /// Global Internet Forum to Counter Terrorism — Crisis Incident
    /// Protocol. Member orgs surface the basis for cross-platform
    /// takedown propagation.
    GifctCip,
    /// US National Center for Missing & Exploited Children categories.
    /// Wire string is `ncmec` (lowercased acronym, matches CEG §5.6.8).
    Ncmec,
}

impl FastPathLegalBasis {
    /// Wire-string codec — the value carried on the
    /// `Contribution.legal_basis` field. Mirrors the `serde(rename_all
    /// = "snake_case")` shape above; exposed as a `pub const fn` so
    /// the dispatcher can grep without pulling serde_json in for a
    /// single string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Tvec => "tvec",
            Self::GifctCip => "gifct_cip",
            Self::Ncmec => "ncmec",
        }
    }

    /// Inverse of [`Self::as_str`]. Returns `None` for any
    /// non-fast-path basis — by design, unknown bases fall through to
    /// standard dispatch (the fast-path is the explicit opt-in arm,
    /// not the default).
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "tvec" => Some(Self::Tvec),
            "gifct_cip" => Some(Self::GifctCip),
            "ncmec" => Some(Self::Ncmec),
            _ => None,
        }
    }
}

/// Whether the given `legal_basis` wire-string triggers the
/// [`crate::edge::dispatch_inbound`] fast-path arm. Pure helper —
/// `Some(b)` iff the value is in [`FastPathLegalBasis`].
#[must_use]
pub fn is_fast_path_legal_basis(legal_basis: &str) -> Option<FastPathLegalBasis> {
    FastPathLegalBasis::from_wire(legal_basis)
}

/// Per MEDIA_SHARING.md — the `subject_kind` discriminator on
/// Contribution payloads. Wire-string codec is `snake_case` (matches
/// the existing Contribution-body precedent in CIRISNodeCore SCHEMA).
///
/// Edge's dispatch routes by [`ContributionSubjectKind`] inside the
/// `MessageType::ContributionSubmit` arm; an unknown / unset
/// `subject_kind` falls through to the existing Contribution handler
/// path (the discriminator is additive — not a wire break for older
/// peers).
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ContributionSubjectKind {
    /// Takedown notice — high-priority dispatch when paired with a
    /// fast-path `legal_basis`; standard otherwise.
    TakedownNotice,
    /// Key grant — addressed delivery to `recipient_key_id`. Edge
    /// does NOT gossip-propagate KeyGrants (point-to-point).
    KeyGrant,
}

impl ContributionSubjectKind {
    /// Wire-string codec. Mirrors `serde(rename_all = "snake_case")`.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TakedownNotice => "takedown_notice",
            Self::KeyGrant => "key_grant",
        }
    }
}

/// Lightweight projection of the Contribution body fields edge's
/// transport-surface dispatch cares about. The full Contribution
/// envelope lives in `ciris-node-core`; edge does NOT re-derive its
/// schema, just probes a minimal subset of fields via `serde_json`'s
/// best-effort parse (all fields default to `None` when absent).
///
/// Used by [`crate::edge::dispatch_inbound`] to inspect `subject_kind`
/// without dragging in NodeCore's typed envelope.
#[derive(Deserialize, Debug, Clone, Default)]
pub struct ContributionDispatchProbe {
    /// `subject_kind` discriminator. `None` ⇒ legacy Contribution
    /// (pre-v0.20.1 wire shape); falls through to the existing
    /// handler dispatch.
    #[serde(default)]
    pub subject_kind: Option<String>,
    /// `legal_basis` wire-string. Inspected for the fast-path
    /// trigger when `subject_kind == "takedown_notice"`.
    #[serde(default)]
    pub legal_basis: Option<String>,
    /// `recipient_key_id` for addressed-delivery semantics
    /// (KeyGrant). When present, edge enforces point-to-point and
    /// does NOT gossip-propagate.
    #[serde(default)]
    pub recipient_key_id: Option<String>,
    /// `content_sha256` — when the Contribution carries a content
    /// pointer, the fast-path emits a `FederationAnnouncement` to
    /// known holders of this hash.
    #[serde(default)]
    pub content_sha256_hex: Option<String>,
    /// `blob_body` discriminator. When `Some("external")`, the
    /// L1-as-CDN-edge hook may opt in to prefetch the bytes.
    #[serde(default)]
    pub blob_body_kind: Option<String>,
    /// `external_uri` — only present when `blob_body_kind ==
    /// "external"`. The publisher's S3-class pointer.
    #[serde(default)]
    pub external_uri: Option<String>,
}

impl ContributionDispatchProbe {
    /// Parse the probe from a Contribution body's `RawValue` bytes.
    /// Returns the default ([`Self::default`] — all-`None`) on parse
    /// error rather than `Err` — the probe is best-effort
    /// observability over an opaque body, not a wire gate.
    #[must_use]
    pub fn from_body_bytes(bytes: &[u8]) -> Self {
        serde_json::from_slice(bytes).unwrap_or_default()
    }

    /// Typed view of [`Self::subject_kind`]. `None` for unset / unknown.
    #[must_use]
    pub fn typed_subject_kind(&self) -> Option<ContributionSubjectKind> {
        self.subject_kind.as_deref().and_then(|s| match s {
            "takedown_notice" => Some(ContributionSubjectKind::TakedownNotice),
            "key_grant" => Some(ContributionSubjectKind::KeyGrant),
            _ => None,
        })
    }

    /// Whether this Contribution rides the takedown fast-path —
    /// `subject_kind == "takedown_notice"` AND `legal_basis` resolves
    /// via [`is_fast_path_legal_basis`].
    #[must_use]
    pub fn fast_path_basis(&self) -> Option<FastPathLegalBasis> {
        if !matches!(
            self.typed_subject_kind(),
            Some(ContributionSubjectKind::TakedownNotice)
        ) {
            return None;
        }
        self.legal_basis
            .as_deref()
            .and_then(is_fast_path_legal_basis)
    }
}

/// Per MEDIA_SHARING.md §2.6 — `BlobBody::External` wire shape.
///
/// Carries the publisher's S3-class pointer + the signed ACL gate
/// the consumer's client uses to authorize the byte fetch. Edge does
/// **not** fetch the bytes (consumer's client fetches directly from
/// `external_uri`); this avoids edge-as-MitM concerns + bandwidth
/// amplification at the federation tier.
///
/// The wire-form rides as a sibling JSON shape inside the
/// `MessageType::ContentBody` envelope when the `body` field's
/// `kind == "external"` discriminator is set (v0.20.1 additive
/// variant — pre-v0.20.1 envelopes continue to deserialize as the
/// inline-bytes [`crate::messages::ContentBody`] shape).
///
/// Edge's content-fetch responder consults
/// [`crate::EdgeConfig::l1_cdn_edge_enabled`] to decide whether to
/// fetch the bytes locally on behalf of the consumer (L1-as-CDN-edge,
/// §2.7) or pass the pointer through verbatim (default — every mode).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExternalRefWithAcl {
    /// Publisher's S3-class URI. Consumer fetches the bytes directly
    /// from here using the [`Self::acl_signature`] as the bearer
    /// gate.
    pub external_uri: String,
    /// SHA-256 of the bytes hex-encoded. The publisher commits to
    /// this hash; the consumer's client verifies the fetched bytes
    /// against it before trusting them.
    pub external_sha256_hex: String,
    /// Publisher-signed ACL the consumer's client presents at byte
    /// fetch. Edge does NOT verify this signature (the consumer's
    /// client side does); the wire-form carries it verbatim from
    /// publisher to consumer.
    pub acl_signature: Vec<u8>,
    /// Wall-clock expiry of the ACL signature. Consumers MUST refuse
    /// to use the pointer after `acl_expiry` — the publisher's ACL
    /// is bounded by this stamp.
    pub acl_expiry: DateTime<Utc>,
}

impl ExternalRefWithAcl {
    /// JSON-shape `kind` discriminator inside the `ContentBody` wire
    /// envelope. Pinned as a `pub const` so the deserializer and the
    /// matcher in `dispatch_inbound` agree on a single source of
    /// truth.
    pub const WIRE_KIND: &'static str = "external";
}

/// L1-as-CDN-edge prefetch stub. Per MEDIA_SHARING.md §2.7, an L1
/// server may opt in to pre-fetch external content + re-emit
/// `holds_bytes` with its own `external_ref`. v0.20.1 locks the wire
/// shape + dispatch hook; the actual `HTTP GET` + persist re-emission
/// is deferred to a post-v1.0 cut.
///
/// **STUB at v0.20.1** — emits a `tracing::info!` event tagged
/// `edge.l1_cdn_edge.prefetch_stub` so operators can observe the
/// opt-in firing without the bytes-fetch implementation. Returns
/// immediately; the caller `tokio::spawn`s this so the dispatch path
/// stays non-blocking even when the full impl lands.
///
/// # Parameters
///
/// - `external_uri`: publisher's pointer (would be the `HTTP GET`
///   target in the full impl).
/// - `external_sha256_hex`: hash to verify the fetched bytes
///   against.
/// - `operator_base`: operator's S3-class base (would be the
///   re-publish target).
///
/// # Future impl
///
/// The wire-shape is locked at v0.20.1; the post-v1.0 cut wires:
/// (1) `reqwest`-driven `HTTP GET` against `external_uri`;
/// (2) SHA verification against `external_sha256_hex`;
/// (3) PUT to `{operator_base}/{sha256_hex}`;
/// (4) emit a fresh `holds_bytes:sha256:{hash}` attestation through
///     the existing federation evidence path.
#[allow(clippy::needless_pass_by_value)]
pub async fn cdn_edge_prefetch_stub(
    external_uri: String,
    external_sha256_hex: String,
    operator_base: String,
) {
    tracing::info!(
        event = "edge.l1_cdn_edge.prefetch_stub",
        external_uri = %external_uri,
        external_sha256_hex = %external_sha256_hex,
        operator_base = %operator_base,
        "L1-as-CDN-edge prefetch stub fired (full impl deferred post-v1.0); CIRISEdge#52",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_path_basis_codec_roundtrips() {
        for b in [
            FastPathLegalBasis::Tvec,
            FastPathLegalBasis::GifctCip,
            FastPathLegalBasis::Ncmec,
        ] {
            assert_eq!(FastPathLegalBasis::from_wire(b.as_str()), Some(b));
        }
        assert_eq!(FastPathLegalBasis::from_wire("dmca"), None);
        assert_eq!(FastPathLegalBasis::from_wire(""), None);
    }

    #[test]
    fn is_fast_path_legal_basis_known_returns_some() {
        assert!(is_fast_path_legal_basis("tvec").is_some());
        assert!(is_fast_path_legal_basis("gifct_cip").is_some());
        assert!(is_fast_path_legal_basis("ncmec").is_some());
    }

    #[test]
    fn is_fast_path_legal_basis_unknown_returns_none() {
        assert!(is_fast_path_legal_basis("dmca").is_none());
        assert!(is_fast_path_legal_basis("copyright").is_none());
        assert!(is_fast_path_legal_basis("").is_none());
    }

    #[test]
    fn contribution_subject_kind_codec() {
        assert_eq!(
            ContributionSubjectKind::TakedownNotice.as_str(),
            "takedown_notice"
        );
        assert_eq!(ContributionSubjectKind::KeyGrant.as_str(), "key_grant");
    }

    #[test]
    fn dispatch_probe_unknown_body_yields_default() {
        let probe = ContributionDispatchProbe::from_body_bytes(b"{}");
        assert!(probe.subject_kind.is_none());
        assert!(probe.legal_basis.is_none());
        assert!(probe.typed_subject_kind().is_none());
        assert!(probe.fast_path_basis().is_none());
    }

    #[test]
    fn dispatch_probe_malformed_body_yields_default() {
        let probe = ContributionDispatchProbe::from_body_bytes(b"not json");
        assert!(probe.subject_kind.is_none());
    }

    #[test]
    fn dispatch_probe_takedown_with_tvec_fast_path() {
        let body = br#"{"subject_kind":"takedown_notice","legal_basis":"tvec"}"#;
        let probe = ContributionDispatchProbe::from_body_bytes(body);
        assert_eq!(
            probe.typed_subject_kind(),
            Some(ContributionSubjectKind::TakedownNotice)
        );
        assert_eq!(probe.fast_path_basis(), Some(FastPathLegalBasis::Tvec));
    }

    #[test]
    fn dispatch_probe_takedown_with_dmca_no_fast_path() {
        let body = br#"{"subject_kind":"takedown_notice","legal_basis":"dmca"}"#;
        let probe = ContributionDispatchProbe::from_body_bytes(body);
        assert_eq!(
            probe.typed_subject_kind(),
            Some(ContributionSubjectKind::TakedownNotice)
        );
        assert_eq!(probe.fast_path_basis(), None);
    }

    #[test]
    fn dispatch_probe_key_grant_no_fast_path_even_with_tvec() {
        // Only takedown_notice can ride the fast-path; key_grant with
        // an arbitrary legal_basis stays on the standard arm.
        let body =
            br#"{"subject_kind":"key_grant","legal_basis":"tvec","recipient_key_id":"alice"}"#;
        let probe = ContributionDispatchProbe::from_body_bytes(body);
        assert_eq!(
            probe.typed_subject_kind(),
            Some(ContributionSubjectKind::KeyGrant)
        );
        assert_eq!(probe.fast_path_basis(), None);
        assert_eq!(probe.recipient_key_id.as_deref(), Some("alice"));
    }

    #[test]
    fn external_ref_wire_kind_locked() {
        assert_eq!(ExternalRefWithAcl::WIRE_KIND, "external");
    }
}
