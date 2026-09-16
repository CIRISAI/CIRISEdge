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
//! # Two occurrence classes — and a node needs the NODE class
//!
//! CIRISPersist v44.3.0 (#848) made the distinction load-bearing:
//!
//! | class | pubkeys come from | who decrypts | door |
//! |---|---|---|---|
//! | **node** | persist's sealed content-KEM identity (`load_or_init_content_kem_identity`, minted fresh, privates sealed under the content master) | **persist**, in `read_blob_as` | [`provision_engine_occurrence`] |
//! | **device** | `SelfEncKeys` / `self_enc` HKDF from the device's own seed | **the device**, in its own custody (`kex_respond`) | [`provision_from_seed`] |
//!
//! `read_blob_as` unwraps a grant with the node's content-KEM private pair
//! and nothing else, so a node can open exactly one occurrence's wraps: the
//! one whose pubkeys ARE that identity's, keyed by the engine's derived
//! signer id. A seed-derived occurrence on a node reads `NotGranted` forever
//! — the wrap exists, the node holds no key for it. That is the trap the
//! first cut of this module walked into, and why the device-class helpers
//! below are deprecated for node use.
//!
//! The same derived id is what persist admits a `key_grant` set FROM: the
//! emitter must resolve to a roster member, and a bare derived key resolves
//! to nobody. Registering it as an occurrence of the member is what makes
//! the node's seals emit at all.
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

use ciris_persist::federation::blobs::BlobStorage;
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

/// **Device class — not for a node that reads through `read_blob_as`.**
///
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
#[deprecated(
    since = "24.1.0",
    note = "device-class keys: persist's read door cannot decrypt for them (CIRISPersist#848); \
            a node reading through `read_blob_as` needs `provision_engine_occurrence`"
)]
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
#[deprecated(
    since = "24.1.0",
    note = "provisions a DEVICE-class occurrence a node cannot decrypt for (CIRISPersist#848); \
            use `provision_engine_occurrence`"
)]
#[allow(deprecated)]
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

/// Is `(identity_key_id, occurrence_key_id)` present on the **signed**
/// occurrence plane — the one a peer replicates from?
///
/// This is the only discriminator edge has between a row published through
/// the gated door and one written through the trusted-local door: both read
/// back from `list_identity_occurrences_active` as a bare
/// [`IdentityOccurrence`] with no signature, but only signed-put rows are
/// SERVED (`list_signed_identity_occurrences_since` — "signed-put rows
/// only"). A node whose row is absent here is invisible to every peer's
/// `key_grant` membership fold, which is CIRISPersist#851.
///
/// Walks the cursor to exhaustion rather than reading one page: the plane
/// carries every identity's occurrences on this node, and this node's own row
/// is not necessarily in the first page. Bounded by `MAX_PAGES` so a large or
/// adversarial plane cannot turn node start-up into an unbounded scan — the
/// bound failing closed means "republish", which is idempotent, not harmful.
///
/// # Errors
/// Directory failure.
async fn occurrence_is_on_signed_plane<B>(
    backend: &B,
    identity_key_id: &str,
    occurrence_key_id: &str,
) -> Result<bool, String>
where
    B: FederationDirectory,
{
    const PAGE: u32 = 256;
    const MAX_PAGES: usize = 64;

    let mut cursor: Option<(chrono::DateTime<chrono::Utc>, String)> = None;
    for _ in 0..MAX_PAGES {
        let page = backend
            .list_signed_identity_occurrences_since(cursor.clone(), PAGE)
            .await
            .map_err(|e| format!("list the signed occurrence plane: {e}"))?;
        if page.is_empty() {
            return Ok(false);
        }
        if page.iter().any(|served| {
            let o = &served.occurrence.identity_occurrence;
            o.identity_key_id == identity_key_id && o.occurrence_key_id == occurrence_key_id
        }) {
            return Ok(true);
        }
        let next = page
            .last()
            .map(ciris_persist::federation::ServedIdentityOccurrence::resume_pair);
        if next == cursor {
            // The cursor stopped advancing — stop rather than spin.
            return Ok(false);
        }
        cursor = next;
        if page.len() < PAGE as usize {
            return Ok(false);
        }
    }
    Ok(false)
}

/// **The node class.** Register this engine's own signing key as a
/// content-only occurrence of `identity_key_id`, carrying the pubkeys of the
/// node's sealed content-KEM identity — the one pair `read_blob_as` can
/// unwrap with (CIRISPersist#848).
///
/// Three things, idempotent together, and each is load-bearing:
///
/// 1. `me = engine.local_derived_key_id()` — the id persist stamps as
///    `attesting_key_id` on everything this engine emits, including the
///    `key_grant` set every encrypted seal now carries.
/// 2. `me` is registered in `federation_keys` (both pubkeys, via
///    `register_self_federation_key`) if it is not already — the occurrence
///    column is an FK, and the `holds_bytes` claim a seal emits points here.
/// 3. `me` becomes an occurrence of `identity_key_id` with
///    `load_or_init_content_kem_identity()`'s pubkeys. This is what makes
///    the node **both** an admissible emitter (persist resolves `me` → a
///    roster member) **and** a grant recipient it can actually decrypt for.
///
/// Returns `(me, outcome)`; `me` is the viewer key for every read on this
/// node. This is the pattern persist's own two-node witness uses
/// (`key_grant_invariants.rs`, I61).
///
/// # Errors
/// The derived id could not be computed, registration failed, the content-KEM
/// identity could not be loaded or minted, the occurrence could not be
/// published, or the directory write failed.
pub async fn provision_engine_occurrence<B>(
    engine: &ciris_persist::Engine,
    backend: &B,
    identity_key_id: &str,
    device_class: &str,
) -> Result<(String, Provisioned), String>
where
    B: FederationDirectory + BlobStorage,
{
    let me = engine
        .local_derived_key_id()
        .await
        .map_err(|e| format!("derive this engine's federation key id: {e}"))?;

    if backend
        .lookup_public_key(&me)
        .await
        .map_err(|e| format!("lookup {me}: {e}"))?
        .is_none()
    {
        engine
            .register_self_federation_key("node", &me, None, serde_json::json!({}), Vec::new())
            .await
            .map_err(|e| format!("register {me} as this node's federation key: {e}"))?;
    }

    let kem = backend
        .load_or_init_content_kem_identity()
        .await
        .map_err(|e| format!("load or mint the content-KEM identity: {e}"))?;
    let enc = EncryptionPubkeys {
        x25519_base64: kem.x25519_pubkey_b64,
        ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
    };

    // #851 / persist v44.4.0 §20.3 — the occurrence is PUBLISHED, not written
    // through the trusted-local door. A local-door row stores its signature
    // columns NULL and `list_signed_identity_occurrences_since` serves
    // signed-put rows only, so the row this node needs a far peer to hold —
    // the one `key_grant` admission folds the minter's membership over — had
    // no replicable form at all. `publish_self_occurrence` signs the
    // content-only envelope with this node's LocalSigner and admits it through
    // the GATED door, so it is born on the plane.
    //
    // # When this republishes, and when it deliberately does not
    //
    // The signed put is a last-signed-wins UPSERT on `(identity_key_id,
    // occurrence_key_id)`, and `publish_self_occurrence` builds its envelope
    // from scratch with `valid_until: null`. So a republish is not a no-op: it
    // overwrites whatever metadata the stored row carries. Three refusals
    // follow from that, each for a different reason:
    //
    //  * DRIFTED — different pubkeys. Never touched: a peer may already hold
    //    grants wrapped to the stored keys, and which one is authoritative is
    //    the operator's call, not ours.
    //  * ALREADY ON THE PLANE — a signed row is already replicable, so there
    //    is nothing to heal and re-signing would only bump `asserted_at` and
    //    re-advertise the row to every peer on every boot.
    //  * CARRIES AN EXPIRY — a `valid_until` is an operator-selected lifetime.
    //    `publish_self_occurrence` takes no expiry argument, so healing such a
    //    row would silently extend this node's grant membership past the
    //    moment the operator chose to end it. Refused and named instead.
    //
    // What remains is the case the heal exists for: a node upgrading from
    // v24.1.0, whose local-door row is invisible to the plane. Edge cannot
    // tell a local row from a signed one by reading it (both come back as a
    // bare `IdentityOccurrence`), so the discriminator is the plane itself.
    let existing = backend
        .list_identity_occurrences_active(identity_key_id)
        .await
        .map_err(|e| format!("list occurrences for {identity_key_id}: {e}"))?
        .into_iter()
        .find(|o| o.occurrence_key_id == me);

    let outcome = match &existing {
        Some(found) if found.encryption_pubkeys.as_ref() != Some(&enc) => Provisioned::Drifted,
        Some(_) => Provisioned::AlreadyCurrent,
        None => Provisioned::Created,
    };

    let publish = match &existing {
        // Drifted: never.
        Some(found) if found.encryption_pubkeys.as_ref() != Some(&enc) => false,
        Some(found) => {
            if occurrence_is_on_signed_plane(backend, identity_key_id, &me).await? {
                false
            } else if found.valid_until.is_some() {
                tracing::warn!(
                    identity = identity_key_id,
                    occurrence = %me,
                    valid_until = ?found.valid_until,
                    "this node's occurrence is NOT on the signed plane (a pre-v24.2.0 \
                     trusted-local row) but carries an expiry, and republishing would drop \
                     it — left as it is. A far peer cannot fold this node's key_grant sets \
                     until the row is re-issued WITH its expiry (CIRISPersist#851)"
                );
                false
            } else {
                true
            }
        }
        None => true,
    };

    if publish {
        engine
            .publish_self_occurrence(identity_key_id, device_class)
            .await
            .map_err(|e| {
                format!("publish this node's content-only occurrence {me} (CIRISPersist#851): {e}")
            })?;
    }
    match &outcome {
        Provisioned::Created => tracing::info!(
            identity = identity_key_id,
            occurrence = %me,
            "engine occurrence PUBLISHED — this node emits key_grant sets as a member, \
             decrypts the wraps addressed to it (CIRISPersist#848), and the row now rides \
             the signed occurrence plane so a far peer can fold it (CIRISPersist#851)"
        ),
        Provisioned::AlreadyCurrent => {
            tracing::debug!(
                identity = identity_key_id,
                occurrence = %me,
                republished = publish,
                "engine occurrence current"
            );
        }
        Provisioned::Drifted => tracing::warn!(
            identity = identity_key_id,
            occurrence = %me,
            "engine occurrence exists with DIFFERENT pubkeys than this node's content-KEM \
             identity — reads for it will be NotGranted. NOT overwritten: an operator decides \
             (CIRISPersist#848)"
        ),
    }
    Ok((me, outcome))
}
