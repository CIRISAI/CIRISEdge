//! CIRISEdge#599 — provisioning the content-encryption occurrence, so a node
//! can read the group content it writes.
//!
//! # The defect this closes
//!
//! persist's community-DEK cascade wraps the content key **per identity
//! OCCURRENCE**, not per roster member
//! (`community_dek::active_member_occurrences`):
//!
//! ```text
//! for member in &community.members {
//!     let occ = list_identity_occurrences_active(&member.key_id).await?;
//!     for o in occ { out.push((o.occurrence_key_id, o.encryption_pubkeys)); }
//! }
//! ```
//!
//! and the caller partitions exactly that list into `granted` / `excluded`.
//! So a roster member with **no** active occurrence contributes no wrap
//! target and appears in NEITHER list — invisible rather than excluded.
//!
//! Nothing in edge created one. A stock node therefore sealed community
//! content with `granted: []`: written, valid, pointed at by a well-formed
//! row, and readable by **nobody — including its author**. Measured by
//! CIRISServer while validating a release candidate (CIRISServer#590), and
//! `src/bin/edge_node.rs` had the same hole, presenting a viewer key naming
//! a row nothing registered.
//!
//! The chat suite was green throughout, because its fixture provisions the
//! occurrence. That is the shape of the bug: not an untested path, a tested
//! path with a precondition production never met.
//!
//! # Nothing here is new key material
//!
//! The content-enc keypair is **HKDF-derived from the identity's existing
//! Ed25519 seed** — [`ciris_keyring::self_enc_keys::SelfEncKeys`] for a
//! sealed identity, [`ciris_crypto::self_enc`] for a raw one. Same seed ⇒
//! same keypair on every open and every restore, which is what lets a
//! restored node keep the grants already wrapped to it.
//!
//! Three properties come from upstream rather than from here, and none of
//! them is edge's to re-decide:
//!
//! - **no second key home** — nothing is stored; the seed already exists;
//! - **CC §5.6.8.8.2 C4 separation** — `self_enc` HKDFs with per-scheme
//!   `info`, so the content x25519 is not the transport x25519;
//! - **no private byte leaves custody** — the sealed path derives in-process
//!   and scrubs; only public halves are returned.
//!
//! # Which door
//!
//! | shape | door |
//! |---|---|
//! | an app AND an agent under one identity | `Engine::self_at_login` — it co-admits both occurrences and runs the self-DEK cascade to them |
//! | a headless node, for its own owner | here: one content-only occurrence |
//!
//! This module is deliberately only the second. `self_at_login` also mints a
//! partnership grant/accept and an agent delegation, which a headless mesh
//! node has no counterparty for; calling it to get an occurrence would emit
//! three attestations nobody asked for.

use ciris_persist::federation::types::{EncryptionPubkeys, IdentityOccurrence};
use ciris_persist::federation::FederationDirectory;

/// What provisioning did — reported rather than returned as `()`, because
/// "already correct" and "just created" are different operational facts and
/// the third arm is a problem.
#[must_use = "provisioning reports drift, which is silent if dropped"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provisioned {
    /// The occurrence already existed carrying exactly these pubkeys.
    AlreadyCurrent,
    /// The occurrence was registered now.
    Created,
    /// An occurrence exists under this key id with **different** content
    /// pubkeys.
    ///
    /// Left alone rather than overwritten. The derivation is deterministic
    /// from the identity's seed, so a mismatch means the seed changed — and
    /// overwriting would silently orphan every grant already wrapped to the
    /// old keys, turning readable content unreadable at the next rotation.
    /// An operator has to decide that.
    Drifted,
}

/// The content-enc public halves for an identity holding a **raw** Ed25519
/// seed — the software-signer shape (the mesh harness, tests, a node whose
/// seed is not sealed).
///
/// The same derivation [`SelfEncKeys::enc_pubkeys`](ciris_keyring::self_enc_keys::SelfEncKeys::enc_pubkeys)
/// performs inside custody, over the same input, so a node that later moves
/// to a sealed seed derives the identical keypair and keeps its grants.
///
/// # Errors
/// ML-KEM-768 key generation failure.
pub fn enc_pubkeys_from_seed(ed25519_seed: &[u8; 32]) -> Result<EncryptionPubkeys, String> {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    // Only the PUBLIC halves leave this function; the secrets are scrubbed
    // before return, matching the custody path's motion even though this
    // input was never sealed.
    let (mut x_secret, x_public) = ciris_crypto::self_enc::derive_self_enc_x25519(ed25519_seed);
    x_secret.fill(0);
    let (mut dk_seed, ek) = ciris_crypto::self_enc::derive_self_enc_mlkem768(ed25519_seed)
        .map_err(|e| format!("ml-kem-768 derive: {e}"))?;
    dk_seed.fill(0);
    Ok(EncryptionPubkeys {
        x25519_base64: b64.encode(x_public),
        ml_kem_768_base64: b64.encode(ek),
    })
}

/// Register `occurrence_key_id` as a **content-only** occurrence of
/// `identity_key_id`, so the DEK cascade has a wrap target for that identity
/// on this node. Idempotent.
///
/// `occurrence_key_id` must already exist in `federation_keys` — an
/// occurrence is a key that acts for an identity, not a bare label, and the
/// column is a foreign key. For a node provisioning its own owner that is
/// the node's own federation key, which is registered by construction.
///
/// `transport_binding` is `None` by design: this is a DEK-cascade KEX
/// target, which is exactly the shape persist documents the trusted-local
/// door for. A transport binding would take the signature-gated door, which
/// exists to stop a PEER forging someone else's content keys — not a gate a
/// node needs against itself.
///
/// # Errors
/// Directory read or write failure.
pub async fn ensure_content_occurrence(
    directory: &dyn FederationDirectory,
    identity_key_id: &str,
    occurrence_key_id: &str,
    device_class: &str,
    enc: EncryptionPubkeys,
) -> Result<Provisioned, String> {
    let existing = directory
        .list_identity_occurrences_active(identity_key_id)
        .await
        .map_err(|e| format!("list occurrences for {identity_key_id}: {e}"))?;

    if let Some(found) = existing
        .iter()
        .find(|o| o.occurrence_key_id == occurrence_key_id)
    {
        return Ok(match found.encryption_pubkeys.as_ref() {
            Some(have) if *have == enc => Provisioned::AlreadyCurrent,
            _ => Provisioned::Drifted,
        });
    }

    directory
        .put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity_key_id.to_owned(),
            occurrence_key_id: occurrence_key_id.to_owned(),
            device_class: device_class.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: Some(enc),
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .map_err(|e| format!("register content occurrence {occurrence_key_id}: {e}"))?;
    Ok(Provisioned::Created)
}

/// [`ensure_content_occurrence`] with the pubkeys derived from a raw seed,
/// and the outcome LOGGED rather than returned silently.
///
/// The convenience a node start-up wants: one call, and a `Drifted` outcome
/// says so at WARN instead of being a value somebody dropped.
///
/// # Errors
/// Derivation or directory failure.
pub async fn provision_from_seed(
    directory: &dyn FederationDirectory,
    identity_key_id: &str,
    occurrence_key_id: &str,
    device_class: &str,
    ed25519_seed: &[u8; 32],
) -> Result<Provisioned, String> {
    let enc = enc_pubkeys_from_seed(ed25519_seed)?;
    let out = ensure_content_occurrence(
        directory,
        identity_key_id,
        occurrence_key_id,
        device_class,
        enc,
    )
    .await?;
    match out {
        Provisioned::Created => tracing::info!(
            identity = identity_key_id,
            occurrence = occurrence_key_id,
            "content occurrence registered — this node can now be granted community \
             content keys (CIRISEdge#599)"
        ),
        Provisioned::AlreadyCurrent => tracing::debug!(
            identity = identity_key_id,
            occurrence = occurrence_key_id,
            "content occurrence already current"
        ),
        Provisioned::Drifted => tracing::warn!(
            identity = identity_key_id,
            occurrence = occurrence_key_id,
            "content occurrence exists with DIFFERENT encryption pubkeys — the \
             derivation is deterministic from the identity seed, so the seed \
             changed. NOT overwritten: every grant already wrapped to the old \
             keys would be orphaned. Operator decision (CIRISEdge#599)"
        ),
    }
    Ok(out)
}
