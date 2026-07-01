//! Identity binding — Reticulum address ↔ persist steward seed.
//!
//! Mission: bind the peer's network address to its persist-managed
//! cryptographic identity, with the seed never crossing the FFI
//! boundary. PoB §3.2: addressing IS identity — the Reticulum
//! destination is `sha256(public_key)[..16]`, computed from the same
//! key that signs `federation_keys` rows in persist.
//! ([`MISSION.md`](../../MISSION.md) §2 `identity/`.)
//!
//! The seed lives in persist's keyring (CIRISPersist v0.1.3+ AV-25
//! closure; OS-keyring backed by TPM / Secure Enclave / StrongBox
//! depending on tier). Edge holds `Arc<dyn HardwareSigner>` +
//! optional `Arc<dyn PqcSigner>` and calls into them for sign
//! operations. The seed bytes never enter edge's process memory;
//! AV-17 heap-scan property test enforces this empirically.

use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ciris_keyring::{HardwareSigner, PqcSigner};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::messages::{EdgeEnvelope, MessageType, SchemaVersion};

/// Edge's local signing identity — the process-bound wrapper around
/// ciris-keyring's classical and (optional) PQC signers. Used by
/// `Edge::send` and `Edge::send_durable` to assemble + sign outbound
/// envelopes.
///
/// Naming: "local" describes the wrapper's process scope; the
/// IDENTITY the keys represent (steward / agent / registry / edge per
/// `federation_keys.identity_type`) is a separate concept. Matches
/// persist v1.4.0's `steward_*→local_*` rename (CIRISPersist#51).
pub struct LocalSigner {
    /// Edge's `federation_keys.key_id` — embedded as `signing_key_id`
    /// on outbound envelopes.
    pub key_id: String,
    pub classical: Arc<dyn HardwareSigner>,
    /// `None` during hybrid-pending bootstrap; `Some` once the
    /// `pqc_completed_at` row is filled in.
    pub pqc: Option<Arc<dyn PqcSigner>>,
    /// CIRISEdge#31 — ratchet identifier surfaced via
    /// `current_ratchet_id`. Generated once at construction (the
    /// `KeyringSignerHandle` doesn't carry one); a `Default` `Uuid::nil()`
    /// is acceptable as a "no ratchet" sentinel while the substrate
    /// ratchet rotation cadence lands in v0.12+ (CIRISVerify#XX).
    pub ratchet_id: String,
    /// CIRISEdge#31 — last rotation timestamp. Defaults to construction
    /// time; updated when the ratchet rotates (no rotation surface in
    /// v0.11 — the field exists so `last_rotation_at` can return a
    /// stable value rather than `None`).
    pub last_rotation_at: DateTime<Utc>,
}

/// CIRISEdge#31 — Reticulum-shape identity hash. 16 bytes, computed as
/// `sha256(curve25519_pubkey || ed25519_pubkey)[..16]`. This matches
/// `RNS.Identity.hash()` for dual-key Reticulum identities.
///
/// For edge's federation identity (a `LocalSigner`) we DO NOT have a
/// Curve25519 half — the federation key is Ed25519 (signing) + ML-DSA-65
/// (PQC signing). So edge's "identity hash" is a federation-flavored
/// shape: `sha256(ed25519_pubkey || pqc_pubkey)[..16]` if PQC is
/// present, else `sha256(ed25519_pubkey)[..16]`. The shape MATCHES the
/// Reticulum primitive on byte width (16) but the input bytes differ
/// — the value is meaningful as a federation-identity fingerprint, not
/// as a Reticulum destination hash (the Reticulum destination hash
/// lives on the *transport identity*, a different key pair generated
/// by `src/transport/reticulum.rs`).
#[must_use]
pub fn federation_identity_hash(ed25519_pubkey: &[u8], pqc_pubkey: Option<&[u8]>) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(ed25519_pubkey);
    if let Some(pqc) = pqc_pubkey {
        hasher.update(pqc);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// CIRISEdge#31 — QR payload envelope for in-person trust exchange
/// (Briar meet-in-person pattern). Carries the operator-set display
/// name, federation `key_id`, the dual-key pubkeys, and a
/// federation-key signature over the canonical bytes proving the
/// payload was produced by the key it claims.
///
/// Wire format: serde_json. The bytes returned by
/// `export_qr_payload` are the canonical JSON — small enough (< 1 KiB
/// without PQC; ~3 KiB with ML-DSA-65 pubkey) to fit in a single
/// version-40 QR code. The consumer decodes the QR pixels back to
/// these bytes externally (PyZbar / native iOS/Android camera APIs);
/// `import_qr_payload` takes the already-decoded bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPayload {
    /// Wire format version. `1` for v0.11.0.
    pub version: u8,
    /// Federation `key_id` of the peer this payload represents.
    pub key_id: String,
    /// Operator-set display name; `None` if unset.
    pub display_name: Option<String>,
    /// Base64-encoded Ed25519 federation public key (32 bytes).
    pub pubkey_ed25519_base64: String,
    /// Base64-encoded ML-DSA-65 federation public key. `None` during
    /// hybrid-pending bootstrap; `Some` once PQC is provisioned.
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// Issuance timestamp — when the QR was minted. Consumers SHOULD
    /// reject payloads older than ~24h to limit replay surface.
    pub issued_at: DateTime<Utc>,
    /// Base64-encoded Ed25519 signature over the canonical
    /// `(version, key_id, display_name, pubkey_ed25519_base64,
    /// pubkey_ml_dsa_65_base64, issued_at)` serialization. The
    /// importer recovers the public key from `pubkey_ed25519_base64`
    /// and verifies this signature — TOFU per the Briar pattern (the
    /// importer trusts the in-person handoff; the signature proves
    /// the QR wasn't tampered with in transit).
    pub signature_ed25519_base64: String,
}

/// Compute the canonical signing bytes for a [`QrPayload`]. Serializes
/// every field EXCEPT `signature_ed25519_base64` as compact JSON in
/// declaration order. Both export and import use this function — a
/// single source of truth for the wire shape.
fn qr_payload_canonical_bytes(p: &QrPayload) -> Result<Vec<u8>, crate::EdgeError> {
    // We can't just `serde_json::to_vec` the whole thing — that would
    // include the signature field. Instead, build a stripped struct.
    #[derive(Serialize)]
    struct Canonical<'a> {
        version: u8,
        key_id: &'a str,
        display_name: Option<&'a str>,
        pubkey_ed25519_base64: &'a str,
        pubkey_ml_dsa_65_base64: Option<&'a str>,
        issued_at: DateTime<Utc>,
    }
    let canonical = Canonical {
        version: p.version,
        key_id: &p.key_id,
        display_name: p.display_name.as_deref(),
        pubkey_ed25519_base64: &p.pubkey_ed25519_base64,
        pubkey_ml_dsa_65_base64: p.pubkey_ml_dsa_65_base64.as_deref(),
        issued_at: p.issued_at,
    };
    serde_json::to_vec(&canonical)
        .map_err(|e| crate::EdgeError::Config(format!("qr canonical: {e}")))
}

impl LocalSigner {
    /// CIRISEdge#31 — build a `LocalSigner` with default values for
    /// the `ratchet_id` (fresh v4 UUID) and `last_rotation_at`
    /// (construction time). Use this in tests + tier-0 cohabitation
    /// glue where the signer fields are already in hand. The
    /// fully-constructed literal `LocalSigner { ... }` shape still
    /// works for callers that want to pin a specific ratchet id
    /// (rotation tests, deterministic property tests).
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        classical: Arc<dyn HardwareSigner>,
        pqc: Option<Arc<dyn PqcSigner>>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            classical,
            pqc,
            ratchet_id: Uuid::new_v4().to_string(),
            last_rotation_at: Utc::now(),
        }
    }

    /// Load an Edge signing identity from a seed directory via
    /// ciris-keyring — `ed25519.seed` (mandatory) + `ml_dsa_65.seed`
    /// (optional; engaged when present). CIRISEdge#13.
    ///
    /// Standalone counterpart to [`crate::EdgeBuilder::from_keyring_seed_dir`]:
    /// the builder bundles signer-load AND opens a fresh
    /// `FederationDirectorySqlite` + `EdgeOutboundQueueSqlite` against
    /// `db_path`. A consumer that already owns a persist `Engine` (the
    /// CIRIS 3.0 cohabitation case — one Engine, one pool) wants the
    /// signer-load half WITHOUT a second connection pool to the same
    /// DB file. This method delivers exactly that:
    ///
    /// ```ignore
    /// use std::sync::Arc;
    /// use ciris_edge::LocalSigner;
    /// // engine_backend: Arc<dyn VerifyDirectory + OutboundHandle>
    /// let signer = LocalSigner::from_keyring_seed_dir(
    ///     "edge-key-1",
    ///     "/etc/ciris/seeds".into(),
    /// ).await?;
    /// let edge = Edge::builder()
    ///     .directory(engine_backend.clone())
    ///     .queue(engine_backend)
    ///     .signer(Arc::new(signer))
    ///     .transport(...)
    ///     .build()?;
    /// ```
    ///
    /// Edge owns the seed-layout convention (`ed25519.seed`,
    /// `ml_dsa_65.seed`, `-pqc` key_id suffix); consumers reuse it
    /// rather than duplicating it. If the layout changes here,
    /// CIRISLensCore relay-mode and any other consumer track it
    /// automatically.
    pub async fn from_keyring_seed_dir(
        key_id: impl Into<String>,
        seed_dir: PathBuf,
    ) -> Result<Self, crate::EdgeError> {
        let key_id = key_id.into();
        let pqc_seed = seed_dir.join("ml_dsa_65.seed");
        let pqc_pair = pqc_seed
            .exists()
            .then(|| (Some(format!("{key_id}-pqc")), Some(pqc_seed)));
        let (pqc_key_id, pqc_key_path) = pqc_pair.unwrap_or((None, None));

        let config = ciris_keyring::LocalSeedConfig {
            key_id: key_id.clone(),
            key_path: seed_dir.join("ed25519.seed"),
            pqc_key_id,
            pqc_key_path,
        };
        let (classical, pqc) = ciris_keyring::load_local_seed(config)
            .await
            .map_err(|e| crate::EdgeError::Config(format!("load_local_seed: {e}")))?;

        Ok(LocalSigner {
            key_id,
            classical,
            pqc,
            ratchet_id: Uuid::new_v4().to_string(),
            last_rotation_at: Utc::now(),
        })
    }

    /// CIRISEdge#31 — fetch the dual-key federation pubkey bundle as
    /// raw bytes. Async because [`HardwareSigner::public_key`] is async
    /// (hardware-backed signers may round-trip to the secure enclave).
    /// Returns `(ed25519_bytes, pqc_bytes_or_empty)`. The PQC half is an
    /// empty `Vec` when `self.pqc` is `None` — the caller renders it as
    /// "PQC pending" rather than treating the empty vector as a valid
    /// short key.
    pub async fn federation_pubkeys(&self) -> Result<(Vec<u8>, Option<Vec<u8>>), crate::EdgeError> {
        let ed25519 = self
            .classical
            .public_key()
            .await
            .map_err(|e| crate::EdgeError::Persist(format!("classical public_key: {e}")))?;
        let pqc = if let Some(p) = self.pqc.as_ref() {
            Some(
                p.public_key()
                    .await
                    .map_err(|e| crate::EdgeError::Persist(format!("pqc public_key: {e}")))?,
            )
        } else {
            None
        };
        Ok((ed25519, pqc))
    }

    /// CIRISEdge#31 — compute the federation identity hash (16 bytes).
    /// Convenience over [`federation_identity_hash`]; resolves the
    /// pubkeys via [`Self::federation_pubkeys`].
    pub async fn identity_hash(&self) -> Result<[u8; 16], crate::EdgeError> {
        let (ed25519, pqc) = self.federation_pubkeys().await?;
        Ok(federation_identity_hash(&ed25519, pqc.as_deref()))
    }

    /// CIRISEdge#31 — build a [`QrPayload`] over `self`'s identity,
    /// signed by `self`'s Ed25519 federation key. Caller threads the
    /// operator-set `display_name` through (edge's [`crate::Edge`]
    /// owns the storage; this method is parameterized so the signer
    /// stays display-name-agnostic).
    pub async fn build_qr_payload(
        &self,
        display_name: Option<String>,
    ) -> Result<QrPayload, crate::EdgeError> {
        let (ed25519, pqc) = self.federation_pubkeys().await?;
        let mut payload = QrPayload {
            version: 1,
            key_id: self.key_id.clone(),
            display_name,
            pubkey_ed25519_base64: base64::engine::general_purpose::STANDARD.encode(&ed25519),
            pubkey_ml_dsa_65_base64: pqc
                .as_ref()
                .map(|p| base64::engine::general_purpose::STANDARD.encode(p)),
            issued_at: Utc::now(),
            signature_ed25519_base64: String::new(),
        };
        let canonical = qr_payload_canonical_bytes(&payload)?;
        let sig = self
            .classical
            .sign(&canonical)
            .await
            .map_err(|e| crate::EdgeError::Persist(format!("qr sign: {e}")))?;
        payload.signature_ed25519_base64 = base64::engine::general_purpose::STANDARD.encode(&sig);
        Ok(payload)
    }
}

/// CIRISEdge#31 — verify a received [`QrPayload`]'s self-signature.
/// Returns the parsed payload on success. Verification uses the
/// pubkey embedded in the payload (TOFU per the Briar pattern — the
/// in-person handoff is the trust anchor; the signature proves the
/// QR bytes weren't tampered with mid-transit between camera and
/// importer).
///
/// Returns [`crate::EdgeError::Verify`] when the signature fails to
/// verify; [`crate::EdgeError::Config`] for parse / encoding errors.
pub fn verify_qr_payload(payload: &QrPayload) -> Result<(), crate::EdgeError> {
    use ciris_crypto::{ClassicalVerifier, Ed25519Verifier};

    let canonical = qr_payload_canonical_bytes(payload)?;
    let pubkey_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.pubkey_ed25519_base64)
        .map_err(|e| crate::EdgeError::Config(format!("pubkey b64 decode: {e}")))?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&payload.signature_ed25519_base64)
        .map_err(|e| crate::EdgeError::Config(format!("sig b64 decode: {e}")))?;
    if pubkey_bytes.len() != 32 {
        return Err(crate::EdgeError::Config(format!(
            "qr pubkey must be 32 bytes (Ed25519), got {}",
            pubkey_bytes.len()
        )));
    }
    let verifier = Ed25519Verifier::new();
    let ok = verifier
        .verify(&pubkey_bytes, &canonical, &sig_bytes)
        .map_err(|e| crate::EdgeError::Config(format!("qr signature verify: {e}")))?;
    if !ok {
        return Err(crate::EdgeError::Config(
            "qr signature does not verify against embedded pubkey".into(),
        ));
    }
    Ok(())
}

/// Build an unsigned envelope around a typed message body. The
/// returned envelope has placeholder empty signatures; pass to
/// [`sign_envelope`] before transport.
pub fn build_envelope<M: Serialize>(
    message_type: MessageType,
    signing_key_id: &str,
    destination_key_id: &str,
    body: &M,
    in_reply_to: Option<[u8; 32]>,
) -> Result<EdgeEnvelope, crate::EdgeError> {
    let body_value = serde_json::to_value(body)
        .map_err(|e| crate::EdgeError::Config(format!("body serialize: {e}")))?;
    let body_raw = serde_json::value::to_raw_value(&body_value)
        .map_err(|e| crate::EdgeError::Config(format!("body raw: {e}")))?;

    Ok(EdgeEnvelope {
        edge_schema_version: SchemaVersion::V2_0_0,
        signing_key_id: signing_key_id.to_string(),
        destination_key_id: destination_key_id.to_string(),
        message_type,
        sent_at: Utc::now(),
        nonce: random_nonce(),
        body: body_raw,
        signature: String::new(),
        signature_pqc: None,
        in_reply_to,
        // v0.16.0 — wire-form fields default to None. Higher-level
        // builders may populate these before signing; the helper here
        // is intentionally neutral so v0.15.x callers continue
        // emitting byte-equal envelopes.
        testimonial_witness: None,
        key_boundary_scope: None,
        cohort_scope: None,
    })
}

/// Sign an envelope in-place. Computes canonical bytes via persist's
/// `canonicalize_envelope_for_signing` (CIRISPersist#7 closure),
/// signs with Ed25519 (mandatory) and ML-DSA-65 (when available).
pub async fn sign_envelope(
    signer: &LocalSigner,
    envelope: &mut EdgeEnvelope,
) -> Result<(), crate::EdgeError> {
    let envelope_value = serde_json::to_value(&*envelope)
        .map_err(|e| crate::EdgeError::Config(format!("envelope to_value: {e}")))?;
    let canonical = ciris_persist::prelude::canonicalize_envelope_for_signing(&envelope_value)
        .map_err(|e| crate::EdgeError::Config(format!("canonicalize: {e}")))?;

    // Ed25519 sign (mandatory; AV-9 P0 invariant on the inbound side
    // means every legit message must have one).
    let ed25519_sig_bytes = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| crate::EdgeError::Persist(format!("classical sign: {e}")))?;
    envelope.signature = base64::engine::general_purpose::STANDARD.encode(&ed25519_sig_bytes);

    // ML-DSA-65 sign (optional during hybrid-pending; required after).
    // Per persist's AV-33 bound-signature pattern: PQC signs
    // canonical_bytes || classical_sig (not just canonical_bytes) so
    // signature stripping doesn't degrade hybrid → classical-only.
    if let Some(pqc) = signer.pqc.as_ref() {
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed25519_sig_bytes);
        let pqc_sig_bytes = pqc
            .sign(&bound)
            .await
            .map_err(|e| crate::EdgeError::Persist(format!("pqc sign: {e}")))?;
        envelope.signature_pqc =
            Some(base64::engine::general_purpose::STANDARD.encode(&pqc_sig_bytes));
    }

    Ok(())
}

/// Generate a 16-byte cryptographically random nonce. Used for the
/// `(signing_key_id, nonce)` replay-window key (AV-3).
fn random_nonce() -> [u8; 16] {
    let uuid = Uuid::new_v4();
    *uuid.as_bytes()
}

/// Compute the body sha256 — single-source-of-truth via persist's
/// `body_sha256` helper. Used as the forensic join key + the
/// `in_reply_to` ACK match key (FSD/EDGE_OUTBOUND_QUEUE.md §5).
pub fn envelope_body_sha256(envelope: &EdgeEnvelope) -> [u8; 32] {
    ciris_persist::prelude::body_sha256(&envelope.body)
}
