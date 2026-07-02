//! Announce attestation — the authenticated transport-identity ↔
//! federation-key binding (CIRISEdge#15 / CIRISVerify#28 Phase 3).
//!
//! ## Why this exists (AV-42)
//!
//! A Reticulum destination is a **dedicated dual-key transport
//! identity** (`hash(x25519 ‖ ed25519)`), separate from the
//! federation Ed25519 signing key — the federation seed never enters
//! Leviculum (AV-17). v0.3.1's announce-driven discovery recorded
//! `key_id → destination` straight off the announce app-data:
//! trust-on-first-use. Any peer could announce `key_id=lens-steward`
//! paired with its own destination and intercept everything
//! `send("lens-steward", ..)` routes. That is **AV-42 — spoofed
//! transport-identity ↔ federation-key binding** (see
//! `docs/THREAT_MODEL.md` §4).
//!
//! ## The attestation
//!
//! The announce app-data carries an [`AnnounceAttestation`]: the
//! announcer's transport-identity pubkey, its federation `key_id`,
//! its federation Ed25519 pubkey, a rotation `epoch`, and a
//! **federation-key signature** over the canonical bytes of
//! `{transport_identity_pubkey, federation_key_id, epoch}`. The
//! signature is produced by the federation [`crate::LocalSigner`] —
//! the same Ed25519 key that signs federation envelopes — so it is
//! verifiable against the directory's `pubkey_ed25519_base64`.
//!
//! The binding becomes self-authenticating: the resolver roots the
//! federation key against persist's directory
//! (`root_binding`, CIRISPersist v1.12.0) and then verifies this
//! attestation signature against the now-directory-confirmed pubkey.
//! An announcer that does not hold `key_id`'s federation seed cannot
//! forge the signature; AV-42 closes.
//!
//! ## Canonical signing bytes (FSD §3.4)
//!
//! The signature covers [`AttestationPayload::canonical_bytes`] — a
//! deterministic, length-prefixed encoding of the three signed
//! fields. Length prefixes make the field boundaries unambiguous so
//! the encoding is injective (no two distinct field triples share a
//! byte string). The non-signed fields (`federation_pubkey_*`) are
//! verification *inputs*, not signed content — they are checked
//! against the directory, not trusted off the wire.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Domain-separation tag prepended to the canonical signing bytes.
/// Distinguishes an announce-attestation signature from a federation
/// envelope signature so a signature lifted from one context cannot
/// be replayed into the other.
const ATTESTATION_DOMAIN: &[u8] = b"ciris-edge/announce-attestation/v1";

/// The three signed fields of an [`AnnounceAttestation`], in the
/// canonical order the signature covers.
///
/// Construct via [`AttestationPayload::new`]; the federation key
/// signs [`Self::canonical_bytes`], and the receiver re-derives the
/// same bytes from the announce to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPayload<'a> {
    /// The announcer's 32-byte Reticulum transport-identity Ed25519
    /// public key (the ed25519 half of the dual-key identity — the
    /// half `ReticulumNode::connect` needs as the `signing_key`).
    pub transport_identity_pubkey: &'a [u8; 32],
    /// The announcer's federation `key_id` (`federation_keys.key_id`).
    pub federation_key_id: &'a str,
    /// The transport-identity rotation epoch. Monotonic per
    /// `federation_key_id`; an attestation for an older epoch than
    /// one already rooted is stale and the resolver ignores it.
    pub epoch: u64,
}

impl<'a> AttestationPayload<'a> {
    /// Construct a payload from its three signed fields.
    #[must_use]
    pub fn new(
        transport_identity_pubkey: &'a [u8; 32],
        federation_key_id: &'a str,
        epoch: u64,
    ) -> Self {
        Self {
            transport_identity_pubkey,
            federation_key_id,
            epoch,
        }
    }

    /// The exact bytes the federation key signs / a verifier checks.
    ///
    /// Layout (all integers big-endian):
    /// `DOMAIN ‖ len(pubkey):u64 ‖ pubkey ‖ len(key_id):u64 ‖ key_id ‖ epoch:u64`.
    /// Length prefixes make the encoding injective — distinct field
    /// triples never collide on a byte string, so a signature is
    /// bound to exactly one `(pubkey, key_id, epoch)`.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let key_id = self.federation_key_id.as_bytes();
        // Length prefixes are `u64` big-endian — wide enough that the
        // `usize → u64` widening is lossless on every supported
        // target (no truncation risk).
        let pubkey_len = self.transport_identity_pubkey.len() as u64;
        let key_id_len = key_id.len() as u64;
        let mut out = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 8 + 32 + 8 + key_id.len() + 8);
        out.extend_from_slice(ATTESTATION_DOMAIN);
        out.extend_from_slice(&pubkey_len.to_be_bytes());
        out.extend_from_slice(self.transport_identity_pubkey);
        out.extend_from_slice(&key_id_len.to_be_bytes());
        out.extend_from_slice(key_id);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out
    }
}

/// A federation-key-signed transport-identity binding, carried in the
/// Reticulum announce app-data.
///
/// The wire form is JSON (the announce app-data is an opaque byte
/// blob; JSON keeps it inspectable and forward-compatible). All byte
/// fields are base64-standard.
///
/// # Authentication
///
/// `signature` is **not** trusted on its own — it proves only that
/// whoever holds `federation_key_id`'s Ed25519 seed signed this
/// `(transport_identity_pubkey, federation_key_id, epoch)` triple.
/// The resolver still roots `federation_key_id` against the persist
/// directory (`root_binding`) and verifies `signature` against the
/// **directory-confirmed** pubkey — never against the
/// `federation_pubkey_ed25519_base64` carried here, which is a
/// claim. See [`crate::transport::reticulum`]'s cold-start path.
/// CIRISEdge#205 (CIRISVerify#28 Phase 4 / AV-42) — the enforcement
/// posture for the RNS §5.6.8.8.1.1 destination-hash consistency check on
/// the announce cold-start path. The federation binding (`key_id →
/// transport identity`) is ALWAYS enforced via `root_binding` + the
/// attestation signature; this knob governs the *additional* check that
/// the announce's own `destination_hash` recomputes from its identity
/// pubkeys (`ReceivedAnnounce::verify_destination_hash`).
///
/// **`Advisory` MUST be the default.** The flip to `RequireTransportBinding`
/// is a **dated fleet-floor coordination event** (CIRISVerify#28 Phase 4):
/// every federation repo must emit conformant transport bindings before
/// Edge enforces, or authentic peers get dropped. This is NOT a silent
/// default change — operators opt in once the floor is met. Mirrors the
/// [`crate::cohort_scope::CohortScopeEnforcement`] staged-rollout discipline.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportBindingEnforcement {
    /// Tolerate a missing/mismatched destination-hash binding — admit the
    /// announce (records the claimed hash). **The default** — current
    /// v-series behavior, no silent change.
    #[default]
    Advisory,
    /// Log a `tracing::warn!` on mismatch but still admit — migration aid
    /// while the fleet floor rolls out.
    WarnOnly,
    /// Drop an announce whose `destination_hash` does not recompute from
    /// its identity pubkeys — fail-secure (AV-42). The Phase-4 target,
    /// enabled only after the dated fleet-floor coordination event.
    RequireTransportBinding,
}

impl TransportBindingEnforcement {
    /// Stable string-token for telemetry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::WarnOnly => "warn_only",
            Self::RequireTransportBinding => "require_transport_binding",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnnounceAttestation {
    /// The announcer's 32-byte Reticulum transport-identity Ed25519
    /// public key, base64 standard.
    pub transport_identity_pubkey: String,
    /// The announcer's federation `key_id`.
    pub federation_key_id: String,
    /// The announcer's *claimed* federation Ed25519 public key,
    /// base64 standard. A verification input rooted against the
    /// directory — `root_binding`'s `claimed_pubkey_ed25519_base64`.
    pub federation_pubkey_ed25519_base64: String,
    /// Transport-identity rotation epoch (see
    /// [`AttestationPayload::epoch`]).
    pub epoch: u64,
    /// Ed25519 signature by the federation key over
    /// [`AttestationPayload::canonical_bytes`], base64 standard.
    pub signature: String,
}

/// Errors decoding / verifying an [`AnnounceAttestation`].
#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    /// The announce app-data was not valid attestation JSON.
    #[error("attestation parse: {0}")]
    Parse(String),
    /// A base64 field did not decode, or decoded to the wrong length.
    #[error("attestation field decode: {0}")]
    FieldDecode(String),
    /// The Ed25519 signature did not verify against the federation
    /// pubkey. AV-42 — a spoofed binding fails here.
    #[error("attestation signature verification failed")]
    SignatureMismatch,
}

impl AnnounceAttestation {
    /// Decode the 32-byte transport-identity pubkey.
    ///
    /// # Errors
    /// [`AttestationError::FieldDecode`] when the field is not
    /// base64 of exactly 32 bytes.
    pub fn transport_identity_pubkey_bytes(&self) -> Result<[u8; 32], AttestationError> {
        decode_fixed::<32>(&self.transport_identity_pubkey, "transport_identity_pubkey")
    }

    /// Serialize to announce app-data bytes (JSON).
    ///
    /// # Errors
    /// [`AttestationError::Parse`] if JSON serialization fails
    /// (effectively unreachable for this fixed shape).
    pub fn to_app_data(&self) -> Result<Vec<u8>, AttestationError> {
        serde_json::to_vec(self).map_err(|e| AttestationError::Parse(format!("serialize: {e}")))
    }

    /// Parse an [`AnnounceAttestation`] from announce app-data bytes.
    ///
    /// # Errors
    /// [`AttestationError::Parse`] when `app_data` is not valid
    /// attestation JSON — e.g. a v0.3.1 bare-`key_id` announce, or a
    /// non-attestation announce from an unrelated app.
    pub fn from_app_data(app_data: &[u8]) -> Result<Self, AttestationError> {
        serde_json::from_slice(app_data)
            .map_err(|e| AttestationError::Parse(format!("deserialize: {e}")))
    }

    /// Verify [`Self::signature`] over the canonical attestation
    /// bytes against `federation_pubkey_ed25519` — the **32-byte
    /// Ed25519 public key the persist directory confirmed for
    /// `federation_key_id`**, never the claim carried on the wire.
    ///
    /// On `Ok(())` the binding `federation_key_id → transport
    /// identity` is cryptographically attested by the federation key.
    ///
    /// # Errors
    /// - [`AttestationError::FieldDecode`] — a malformed base64 field.
    /// - [`AttestationError::SignatureMismatch`] — the signature did
    ///   not verify (AV-42: a spoofed announce is rejected here).
    pub fn verify_signature(
        &self,
        federation_pubkey_ed25519: &[u8; 32],
    ) -> Result<(), AttestationError> {
        use ciris_crypto::ClassicalVerifier;

        let transport_pubkey = self.transport_identity_pubkey_bytes()?;
        let signature = decode_fixed::<64>(&self.signature, "signature")?;

        let payload =
            AttestationPayload::new(&transport_pubkey, &self.federation_key_id, self.epoch);
        let canonical = payload.canonical_bytes();

        let verified = ciris_crypto::Ed25519Verifier::new()
            .verify(federation_pubkey_ed25519, &canonical, &signature)
            .map_err(|e| AttestationError::FieldDecode(format!("ed25519 verify: {e}")))?;

        if verified {
            Ok(())
        } else {
            Err(AttestationError::SignatureMismatch)
        }
    }
}

/// Decode a base64-standard field expected to be exactly `N` bytes.
fn decode_fixed<const N: usize>(b64: &str, field: &str) -> Result<[u8; N], AttestationError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| AttestationError::FieldDecode(format!("{field}: base64: {e}")))?;
    let arr: [u8; N] = raw.as_slice().try_into().map_err(|_| {
        AttestationError::FieldDecode(format!("{field}: expected {N} bytes, got {}", raw.len()))
    })?;
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::ClassicalSigner;

    /// A canonical-bytes encoding must be injective: distinct
    /// `(pubkey, key_id, epoch)` triples never collide.
    #[test]
    fn canonical_bytes_are_injective() {
        let pk_a = [0x11u8; 32];
        let pk_b = [0x22u8; 32];
        let a = AttestationPayload::new(&pk_a, "edge-key-a", 1).canonical_bytes();
        let b = AttestationPayload::new(&pk_b, "edge-key-a", 1).canonical_bytes();
        let c = AttestationPayload::new(&pk_a, "edge-key-b", 1).canonical_bytes();
        let d = AttestationPayload::new(&pk_a, "edge-key-a", 2).canonical_bytes();
        assert_ne!(a, b, "distinct pubkey must differ");
        assert_ne!(a, c, "distinct key_id must differ");
        assert_ne!(a, d, "distinct epoch must differ");
    }

    /// A length-prefixed encoding must not be confusable: the
    /// boundary between pubkey and key_id is unambiguous, so a
    /// `key_id` whose prefix matches another's cannot alias.
    #[test]
    fn canonical_bytes_resist_field_confusion() {
        let pk = [0x33u8; 32];
        // "ab" + "c"  vs  "a" + "bc" — without length prefixes a
        // naive concat would collide; with prefixes it must not.
        let x = AttestationPayload::new(&pk, "abc", 0).canonical_bytes();
        let y = AttestationPayload::new(&pk, "ab", 0).canonical_bytes();
        assert_ne!(x, y);
    }

    /// A legitimately signed attestation verifies; a tamper does not.
    #[test]
    fn signed_attestation_round_trips_and_rejects_tamper() {
        let signer = ciris_crypto::Ed25519Signer::random().unwrap();
        let fed_pubkey: [u8; 32] = signer.public_key().unwrap().try_into().unwrap();
        let transport_pubkey = [0x5au8; 32];

        let payload = AttestationPayload::new(&transport_pubkey, "edge-key-honest", 7);
        let sig = signer.sign(&payload.canonical_bytes()).unwrap();

        let att = AnnounceAttestation {
            transport_identity_pubkey: base64::engine::general_purpose::STANDARD
                .encode(transport_pubkey),
            federation_key_id: "edge-key-honest".to_string(),
            federation_pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD
                .encode(fed_pubkey),
            epoch: 7,
            signature: base64::engine::general_purpose::STANDARD.encode(&sig),
        };

        // Round-trip through app-data bytes.
        let bytes = att.to_app_data().unwrap();
        let parsed = AnnounceAttestation::from_app_data(&bytes).unwrap();
        assert_eq!(parsed, att);

        // Legitimate verify.
        parsed.verify_signature(&fed_pubkey).unwrap();

        // AV-42: a spoofed key_id (different signed content) fails.
        let mut spoofed = parsed.clone();
        spoofed.federation_key_id = "edge-key-victim".to_string();
        assert!(matches!(
            spoofed.verify_signature(&fed_pubkey),
            Err(AttestationError::SignatureMismatch)
        ));

        // AV-42: a flipped signature byte fails.
        let mut bad_sig = parsed.clone();
        let mut sig_bytes = sig.clone();
        sig_bytes[0] ^= 0xff;
        bad_sig.signature = base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
        assert!(matches!(
            bad_sig.verify_signature(&fed_pubkey),
            Err(AttestationError::SignatureMismatch)
        ));
    }

    /// A v0.3.1-style bare-`key_id` announce is not attestation JSON
    /// and parses to a typed error rather than a panic.
    #[test]
    fn legacy_bare_key_id_announce_is_rejected_cleanly() {
        let legacy = b"edge-key-legacy";
        assert!(matches!(
            AnnounceAttestation::from_app_data(legacy),
            Err(AttestationError::Parse(_))
        ));
    }

    #[test]
    fn transport_binding_enforcement_default_is_advisory() {
        // CIRISEdge#205 — the default MUST be Advisory (no silent flip);
        // the fleet-floor cutover to RequireTransportBinding is opt-in.
        assert_eq!(
            TransportBindingEnforcement::default(),
            TransportBindingEnforcement::Advisory
        );
    }

    #[test]
    fn transport_binding_enforcement_serde_and_token_round_trip() {
        for (variant, token) in [
            (TransportBindingEnforcement::Advisory, "advisory"),
            (TransportBindingEnforcement::WarnOnly, "warn_only"),
            (
                TransportBindingEnforcement::RequireTransportBinding,
                "require_transport_binding",
            ),
        ] {
            assert_eq!(variant.as_str(), token);
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, format!("\"{token}\""));
            let back: TransportBindingEnforcement = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }
}
