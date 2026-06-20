//! `CohortScope` — wire-form scope discriminator for the federation's
//! locality dividend (CIRISEdge#48-A, v0.19.1).
//!
//! # Why this exists
//!
//! Per CIRISNodeCore FSD `FEDERATION_SCALING_MODEL.md` and the
//! CEG-organic replication discipline: replication is
//! `trust(source) ≥ threshold AND capacity_available` at every byte-
//! attempt; **locality** (`cohort_scope`) is structurally enforced —
//! self/family-scope content never emits `holds_bytes`, never crosses
//! to inter-host paths. The producer-side refusal at
//! `Edge::send` / `send_durable` / `send_mandatory` / `send_federation`
//! is the wire-format invariant the locality dividend depends on.
//!
//! v0.19.1 ships:
//!
//! - Producer-side refusal at outbound enqueue (`Edge::send_*`) —
//!   structural enforcement against `Delivery::{Mandatory, Federation}`
//!   regardless of cohort scope when the scope is `SelfOnly` or
//!   `Family`, and against `Delivery::{Ephemeral, Durable}` when the
//!   explicit recipient is not a family-cohort peer.
//! - Consumer-side symmetric check at `dispatch_inbound` — refuse
//!   inbound envelopes whose claimed cohort scope is `SelfOnly` /
//!   `Family` and whose sender is NOT recorded in the directory's
//!   cohort-membership map with the matching scope.
//!
//! The receiver-side trust short-circuit (#48-B) defers to v0.19.2
//! pending persist's `TrustScoring` trait.
//!
//! # Wire shape
//!
//! `cohort_scope` rides on [`crate::EdgeEnvelope`] as
//! `Option<CohortScope>` with `skip_serializing_if = "Option::is_none"`
//! so pre-v0.19.1 envelopes round-trip byte-equal and deserialize-
//! default to `None`. A `None` value is interpreted as `Public` — the
//! pre-v0.19.1 implicit behaviour. The wire serialization is the
//! `serde(tag = "kind")` form so consumers can pattern-match the
//! `kind` discriminant without re-parsing.
//!
//! Wire strings (snake_case via `serde(rename_all)`):
//!
//! - `Public` → `"public"`  — the default; content may cross any
//!   federation hop (subject to subscription / trust gates).
//! - `SelfOnly` → `"self"` — content is bounded to the originator's
//!   own enclosing federation; MUST NOT cross to inter-host paths.
//! - `Family` → `"family"` — content is bounded to peers in the
//!   originator's family cohort (operator-declared).
//! - `Cohort(String)` → `"cohort:{id}"` — content is bounded to peers
//!   in the named cohort.

use serde::{Deserialize, Serialize};

// v6.0.0 (CIRISEdge#175) — FSD §2.1 implementation note: edge
// resolves through persist's `crypto_tier()` rather than enumerating
// the 7-value lattice so future `affiliations` semantic changes flow
// without wire-format churn.
pub use ciris_persist::federation::types::cohort_scope::{
    crypto_tier as persist_crypto_tier, CryptoTier,
};

/// Wire-form cohort-scope discriminator for the federation's locality
/// dividend (CIRISEdge#48-A; FSD `FEDERATION_SCALING_MODEL.md`).
///
/// `Public` is the default — content with no declared cohort_scope is
/// interpreted as public. `SelfOnly` and `Family` are the structurally-
/// enforced locality variants: edge refuses outbound emissions to
/// federation-class / mandatory-class paths AND refuses point-to-point
/// emissions whose recipient is not authorized for the scope.
///
/// Round-trip lands in [`crate::EdgeEnvelope::cohort_scope`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum CohortScope {
    /// Default. Content may cross any federation hop (subject to
    /// subscription / trust gates at the application tier).
    #[default]
    Public,
    /// Originator's own enclosing federation only. Edge refuses any
    /// federation-class / mandatory-class fan-out AND any
    /// point-to-point emission to a non-self recipient.
    #[serde(rename = "self")]
    SelfOnly,
    /// Originator's family cohort only (operator-declared in the
    /// recipient's `policy_blob`). Edge refuses federation-class /
    /// mandatory-class fan-out AND point-to-point emissions to a
    /// non-family-cohort recipient.
    Family,
    /// Operator-declared cohort by id. Edge refuses
    /// federation-class / mandatory-class fan-out AND point-to-point
    /// emissions to a recipient not in the named cohort.
    Cohort {
        /// Opaque cohort identifier (edge does NOT interpret).
        cohort_id: String,
    },
}

impl CohortScope {
    /// Stable string-token for telemetry / structured logging.
    /// `Cohort(_)` collapses to the base token `"cohort"` (the id is
    /// carried separately when logged).
    #[must_use]
    pub fn kind_token(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::SelfOnly => "self",
            Self::Family => "family",
            Self::Cohort { .. } => "cohort",
        }
    }

    /// `true` for the locality variants whose producer-side outbound
    /// is structurally restricted (`SelfOnly`, `Family`, and `Cohort`).
    /// `Public` is `false` — public content may ride any path.
    #[must_use]
    pub fn is_restricted(&self) -> bool {
        !matches!(self, Self::Public)
    }

    /// `true` iff `recipient_scope` is compatible with this declared
    /// scope per the recipient-determination rules of CIRISEdge#48-A.
    /// A `Public` declared scope accepts any recipient; restricted
    /// scopes require the recipient's directory-recorded scope to
    /// match.
    ///
    /// Used by the consumer-side check at `dispatch_inbound` (where
    /// `self` is the sender's CLAIMED scope and `recipient_scope` is
    /// the directory-recorded scope) and by the producer-side
    /// recipient match (where `self` is the OUTBOUND scope and
    /// `recipient_scope` is the recipient's recorded scope).
    #[must_use]
    #[allow(
        clippy::match_same_arms,
        reason = "v0.19.4 — clippy 1.95 ratchet. The match deliberately \
                  enumerates each (sender, recipient) variant pair in \
                  documentation-pair order. Merging the `_ => false` \
                  fallthroughs would erase the per-variant rationale \
                  comments that document the cohort-scope wire-format \
                  invariant for downstream auditors."
    )]
    pub fn allows_recipient_scope(&self, recipient_scope: &CohortScope) -> bool {
        match (self, recipient_scope) {
            // Public content may go anywhere.
            (Self::Public, _) => true,
            // SelfOnly never crosses to a different identity; the
            // producer-side path filters by explicit recipient key
            // BEFORE reaching this check, so any positive answer here
            // is for the self-recipient case (which the caller routes
            // through a self-loopback short-circuit).
            (Self::SelfOnly, Self::SelfOnly) => true,
            (Self::SelfOnly, _) => false,
            // Family scope: recipient must be Family.
            (Self::Family, Self::Family) => true,
            (Self::Family, _) => false,
            // Cohort scope: recipient must be in the same named cohort.
            (Self::Cohort { cohort_id: a }, Self::Cohort { cohort_id: b }) => a == b,
            (Self::Cohort { .. }, _) => false,
        }
    }

    /// v6.0.0 (CIRISEdge#175, FSD §2.1) — resolve the at-rest crypto
    /// tier this scope corresponds to via persist v9.2.0's
    /// [`persist_crypto_tier`] (CC 4.4.3.2.1 lattice). Edge does NOT
    /// duplicate persist's closed-set match; this method is the
    /// single bridge so future `affiliations` semantic changes flow
    /// without wire-format churn.
    ///
    /// The mapping edge's enum → persist's 7-value string lattice:
    ///
    /// - [`Self::Public`] → `"federation"` (Commons-tier plaintext)
    /// - [`Self::SelfOnly`] → `"self"` (InvisibleEncrypted)
    /// - [`Self::Family`] → `"family"` (InvisibleEncrypted)
    /// - [`Self::Cohort`] → `"community"` with `cohort_subkind = None`
    ///   (CommunityDek tier)
    ///
    /// The `cohort_subkind: "infrastructure"` opt-out (which
    /// promotes community/affiliations to Commons-tier plaintext)
    /// is a downstream-of-edge concern owned by persist's admission
    /// path; edge's wire-format invariant continues to treat
    /// `Cohort{..}` as CommunityDek at this resolution layer.
    #[must_use]
    pub fn crypto_tier(&self) -> CryptoTier {
        match self {
            Self::Public => persist_crypto_tier("federation", None),
            Self::SelfOnly => persist_crypto_tier("self", None),
            Self::Family => persist_crypto_tier("family", None),
            Self::Cohort { .. } => persist_crypto_tier("community", None),
        }
    }

    /// v6.0.0 (CIRISEdge#175, FSD §3.2) — the §3.2 default
    /// cohort_scope flip: `cohort_scope` defaults to the smallest
    /// scope consistent with the publisher's stated audience
    /// context. **Federation scope is opt-in.**
    ///
    /// The §3.2 rule:
    /// - if a `community_id` is active → `Cohort { community_id }`
    /// - else if a family context is active → `Family`
    /// - else → `SelfOnly`
    ///
    /// Federation publication is NEVER the default; callers must
    /// pass `CohortScope::Public` explicitly to opt up to federation.
    #[must_use]
    pub fn default_for_audience(
        active_community_id: Option<&str>,
        in_family_context: bool,
    ) -> Self {
        if let Some(cid) = active_community_id {
            Self::Cohort {
                cohort_id: cid.to_string(),
            }
        } else if in_family_context {
            Self::Family
        } else {
            Self::SelfOnly
        }
    }
}

/// Operator-declared enforcement posture for cohort-scope refusal
/// (CIRISEdge#48-A). [`Strict`] is the default — wire-format
/// invariant, not optional. `WarnOnly` is a migration gradient for
/// operators staging the rollout; `Off` is the escape hatch for
/// testing / dev.
///
/// **Strict MUST be the default.** This is a wire-format invariant,
/// not a deployment knob; operators who need to migrate set
/// `WarnOnly` temporarily, production defaults to `Strict`.
///
/// [`Strict`]: CohortScopeEnforcement::Strict
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CohortScopeEnforcement {
    /// Reject violations with a typed [`crate::EdgeError`] variant.
    /// **The default.** Wire-format invariant per CIRISEdge#48-A.
    #[default]
    Strict,
    /// Log a `tracing::warn!` on every violation but allow the
    /// envelope through. Migration aid — operators may run their
    /// deployment in `WarnOnly` while they audit the produced
    /// telemetry, then flip to `Strict`.
    WarnOnly,
    /// No enforcement at all. Testing / dev only. Production
    /// deployments MUST NOT use this mode.
    Off,
}

impl CohortScopeEnforcement {
    /// Stable string-token for telemetry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::WarnOnly => "warn_only",
            Self::Off => "off",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_default_serializes_to_public_kind() {
        let s = CohortScope::Public;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"kind":"public"}"#);
        let back: CohortScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CohortScope::Public);
    }

    #[test]
    fn self_only_serializes_to_self_kind() {
        let s = CohortScope::SelfOnly;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"kind":"self"}"#);
        let back: CohortScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CohortScope::SelfOnly);
    }

    #[test]
    fn family_serializes_to_family_kind() {
        let s = CohortScope::Family;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"kind":"family"}"#);
        let back: CohortScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, CohortScope::Family);
    }

    #[test]
    fn cohort_serializes_with_id() {
        let s = CohortScope::Cohort {
            cohort_id: "alpha".into(),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"kind":"cohort","cohort_id":"alpha"}"#);
        let back: CohortScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn is_restricted_only_public_is_false() {
        assert!(!CohortScope::Public.is_restricted());
        assert!(CohortScope::SelfOnly.is_restricted());
        assert!(CohortScope::Family.is_restricted());
        assert!(CohortScope::Cohort {
            cohort_id: "x".into()
        }
        .is_restricted());
    }

    #[test]
    fn kind_token_stable() {
        assert_eq!(CohortScope::Public.kind_token(), "public");
        assert_eq!(CohortScope::SelfOnly.kind_token(), "self");
        assert_eq!(CohortScope::Family.kind_token(), "family");
        assert_eq!(
            CohortScope::Cohort {
                cohort_id: "x".into()
            }
            .kind_token(),
            "cohort"
        );
    }

    #[test]
    fn allows_recipient_public_accepts_any() {
        let pub_ = CohortScope::Public;
        assert!(pub_.allows_recipient_scope(&CohortScope::Public));
        assert!(pub_.allows_recipient_scope(&CohortScope::Family));
        assert!(pub_.allows_recipient_scope(&CohortScope::SelfOnly));
    }

    #[test]
    fn allows_recipient_family_only_family() {
        let fam = CohortScope::Family;
        assert!(fam.allows_recipient_scope(&CohortScope::Family));
        assert!(!fam.allows_recipient_scope(&CohortScope::Public));
        assert!(!fam.allows_recipient_scope(&CohortScope::SelfOnly));
        assert!(!fam.allows_recipient_scope(&CohortScope::Cohort {
            cohort_id: "x".into()
        }));
    }

    #[test]
    fn allows_recipient_cohort_id_match() {
        let a = CohortScope::Cohort {
            cohort_id: "alpha".into(),
        };
        let same = CohortScope::Cohort {
            cohort_id: "alpha".into(),
        };
        let other = CohortScope::Cohort {
            cohort_id: "beta".into(),
        };
        assert!(a.allows_recipient_scope(&same));
        assert!(!a.allows_recipient_scope(&other));
        assert!(!a.allows_recipient_scope(&CohortScope::Family));
    }

    #[test]
    fn enforcement_default_is_strict() {
        assert_eq!(
            CohortScopeEnforcement::default(),
            CohortScopeEnforcement::Strict
        );
    }

    #[test]
    fn enforcement_as_str_stable() {
        assert_eq!(CohortScopeEnforcement::Strict.as_str(), "strict");
        assert_eq!(CohortScopeEnforcement::WarnOnly.as_str(), "warn_only");
        assert_eq!(CohortScopeEnforcement::Off.as_str(), "off");
    }

    // ─── v6.0.0 (CIRISEdge#175) — FSD §2.1 / §3.2 surface ───────────

    #[test]
    fn crypto_tier_resolves_through_persist() {
        // FSD §2.1 implementation note — edge's enum maps onto
        // persist's CC 4.4.3.2.1 lattice through `crypto_tier()`.
        assert_eq!(
            CohortScope::SelfOnly.crypto_tier(),
            CryptoTier::InvisibleEncrypted
        );
        assert_eq!(
            CohortScope::Family.crypto_tier(),
            CryptoTier::InvisibleEncrypted
        );
        assert_eq!(
            CohortScope::Cohort {
                cohort_id: "alpha".into()
            }
            .crypto_tier(),
            CryptoTier::CommunityDek
        );
        assert_eq!(CohortScope::Public.crypto_tier(), CryptoTier::Plaintext);
    }

    #[test]
    fn default_for_audience_prefers_smallest_scope() {
        // §3.2 — community when group context is active
        assert_eq!(
            CohortScope::default_for_audience(Some("alpha"), false),
            CohortScope::Cohort {
                cohort_id: "alpha".into()
            }
        );
        // §3.2 — family when in family
        assert_eq!(
            CohortScope::default_for_audience(None, true),
            CohortScope::Family
        );
        // §3.2 — self when no group context
        assert_eq!(
            CohortScope::default_for_audience(None, false),
            CohortScope::SelfOnly
        );
        // Community wins over family when both signals fire
        assert_eq!(
            CohortScope::default_for_audience(Some("beta"), true),
            CohortScope::Cohort {
                cohort_id: "beta".into()
            }
        );
    }

    #[test]
    fn default_never_returns_public() {
        // §3.2 — federation is opt-in. The default flip MUST NEVER
        // return Public — that's the entire CC 1.13.3.4 protection.
        for (cid, fam) in [
            (Some("c"), true),
            (Some("c"), false),
            (None, true),
            (None, false),
        ] {
            let s = CohortScope::default_for_audience(cid, fam);
            assert_ne!(s, CohortScope::Public, "default MUST never be Public");
        }
    }
}
