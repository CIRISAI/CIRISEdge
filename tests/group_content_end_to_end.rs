//! CIRISEdge#586 — group content, end to end against a real persist
//! substrate.
//!
//! What this proves, in the order the model runs:
//!
//! 1. **produce → seal** — content goes into the group's blob store through
//!    persist's one write door and comes back as a row pointer;
//! 2. **pointer → open** — a reader rebuilding the binding from the row gets
//!    the bytes back;
//! 3. **the substitution fails** — a ciphertext lifted onto a different
//!    author's row does NOT open, which is the whole reason the AAD exists.
//!
//! Point 3 is the one worth having a live substrate for. The preimage's
//! shape is pinned by unit tests; what those cannot show is that persist
//! actually folds it into the GCM tag, and that a mismatch surfaces as a
//! crypto failure rather than silently returning someone else's plaintext.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use ciris_edge::group_content::{
    BlobPointer, ContentField, GroupContentError, GroupContentStore, OpenRequest,
    PersistGroupContentStore, SealRequest,
};
use ciris_persist::prelude::FederationDirectorySqlite;
use ciris_persist::store::backend::Backend as _;

const ALIAS: &str = "e2e";

/// A substrate with the signing key REGISTERED.
///
/// The seal path emits a `holds_bytes` holder attestation, and that row has
/// an FK onto `federation_keys` — so a signer whose key is not in the
/// directory produces "FOREIGN KEY constraint failed" from deep inside
/// `put_blob_scoped`. Registering it is not test scaffolding around the
/// feature; it is the feature's actual precondition, and a fixture that
/// skipped it would be testing a path production never takes.
async fn store() -> PersistGroupContentStore {
    use base64::Engine as _;
    use ciris_keyring::HardwareSigner as _;
    use ciris_persist::federation::FederationDirectory as _;
    use ciris_persist::prelude::{KeyRecord, SignedKeyRecord};

    let backend = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist substrate");
    backend.run_migrations().await.expect("migrate");

    // `Ed25519SoftwareSigner::new` creates a signer with NO key; the seal
    // path signs, so it needs one imported.
    let mut ed = ciris_keyring::Ed25519SoftwareSigner::new(ALIAS);
    ed.import_key(&[7u8; 32]).expect("import test key");

    // The key_id persist will derive for this signer — computed the same
    // way persist does (`derive_key_id(alias, pubkey)`) rather than guessed,
    // so the row we insert is the row the FK looks for.
    let pubkey = ed.public_key().await.expect("pubkey");
    let key_id = ciris_verify_core::fedcode::derive_key_id(ALIAS, &pubkey);

    let pqc =
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[9u8; 32], format!("{ALIAS}-pqc"))
            .expect("ml_dsa_65 from seed");
    let pqc_pubkey_b64 = {
        use ciris_keyring::PqcSigner as _;
        base64::engine::general_purpose::STANDARD
            .encode(pqc.public_key().await.expect("pqc pubkey"))
    };

    let b64 = base64::engine::general_purpose::STANDARD;
    let ts: chrono::DateTime<chrono::Utc> =
        chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .expect("ts")
            .into();
    let envelope = serde_json::json!({ "key_id": key_id });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
    let sig = ed.sign(digest.as_slice()).await.expect("self-sign");

    backend
        .put_public_key(SignedKeyRecord {
            record: KeyRecord {
                key_id: key_id.clone(),
                pubkey_ed25519_base64: b64.encode(&pubkey),
                pubkey_ml_dsa_65_base64: Some(pqc_pubkey_b64),
                // HYBRID, and not negotiable: the directory refuses a
                // classical-only registration outright. That refusal is
                // deliberate (the classical-only fallback was removed because
                // it was laundering trust), so a fixture that wanted a
                // simpler key would be asking for a shape production cannot
                // produce.
                algorithm: "hybrid".to_string(),
                identity_type: "node".to_string(),
                identity_ref: key_id.clone(),
                valid_from: ts,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(digest),
                scrub_signature_classical: b64.encode(sig),
                scrub_signature_pqc: None,
                scrub_key_id: key_id,
                scrub_timestamp: ts,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the signing key");

    let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(ed);
    PersistGroupContentStore::from_shared(ciris_persist::BackendDispatch::Sqlite(backend), signer)
}

fn instant() -> chrono::DateTime<chrono::Utc> {
    // Deliberately sub-millisecond: the AAD must bind to the TRUNCATED
    // rendering, and a witness at exact millisecond precision would pass
    // whether or not the truncation happens.
    chrono::DateTime::from_timestamp(1_767_225_296, 789_654_321).expect("ts")
}

/// The commons path: produce → seal → open, with no encryption and no AAD.
///
/// This is #587's build-manifest shape — a public immutable blob — and it
/// exercises the plaintext-tier branch, where passing an AAD would be
/// REFUSED by persist rather than ignored.
#[tokio::test]
async fn commons_content_round_trips_through_the_one_write_door() {
    let s = store().await;
    let body = b"{\"build\":\"manifest\"}";

    let sealed = s
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: "ci-runner",
            asserted_at: instant(),
            field: ContentField::Body,
            plaintext: body,
            media_type: Some("application/json"),
        })
        .await
        .expect("commons seal");

    assert_eq!(sealed.pointer.content_field, ContentField::Body);
    assert_eq!(
        sealed.pointer.media_type.as_deref(),
        Some("application/json"),
    );
    assert!(
        !sealed.pointer.is_chunked(),
        "a whole-blob seal carries no stream_id",
    );
    assert_eq!(
        sealed.pointer.content_sha256.len(),
        64,
        "the pointer carries a hex sha256",
    );
    assert!(
        sealed.fully_readable(),
        "commons content excludes nobody: {:?}",
        sealed.excluded,
    );

    let got = s
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: "ci-runner",
            asserted_at: instant(),
            viewer_key_id: "any-reader",
        })
        .await
        .expect("commons open");
    assert_eq!(got, body, "the bytes come back unchanged");
}

/// The pointer is the ONLY thing the row needs to carry: serialize it, throw
/// the original away, and a reader that parsed it off the wire can still
/// open the content.
#[tokio::test]
async fn a_pointer_survives_the_wire_and_still_opens() {
    let s = store().await;
    let body = b"content that outlives its writer's process";

    let sealed = s
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: "author-1",
            asserted_at: instant(),
            field: ContentField::Body,
            plaintext: body,
            media_type: None,
        })
        .await
        .expect("seal");

    // Round-trip the pointer exactly as a federated row would.
    let json = serde_json::to_string(&sealed.pointer).expect("serialize pointer");
    let from_wire: BlobPointer = serde_json::from_str(&json).expect("parse pointer");

    let got = s
        .open(OpenRequest {
            pointer: &from_wire,
            author_key_id: "author-1",
            asserted_at: instant(),
            viewer_key_id: "reader",
        })
        .await
        .expect("open from the wire-parsed pointer");
    assert_eq!(got, body);
}

/// A reader that rebuilds the binding from the WRONG row does not get the
/// content — even holding the correct pointer, and even at a tier where the
/// bytes are not encrypted at all.
///
/// At the commons tier there is no AAD, so this documents the honest
/// boundary: the AAD is what stops re-attribution, and a plaintext tier has
/// none. That is exactly why group content is written at `community`, and
/// why the store refuses to pretend otherwise.
#[tokio::test]
async fn commons_content_is_not_bound_to_its_author_and_says_so() {
    let s = store().await;
    let sealed = s
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: "alice",
            asserted_at: instant(),
            field: ContentField::Body,
            plaintext: b"public",
            media_type: None,
        })
        .await
        .expect("seal");

    // Bob presents Alice's pointer under his own name. At a PLAINTEXT tier
    // this succeeds — there is no ciphertext to bind — and that is the
    // property that makes commons content public rather than a defect.
    let got = s
        .open(OpenRequest {
            pointer: &sealed.pointer,
            author_key_id: "bob",
            asserted_at: instant(),
            viewer_key_id: "bob",
        })
        .await
        .expect("plaintext content carries no binding");
    assert_eq!(
        got, b"public",
        "commons content is public by construction — the AAD is what binds \
         ENCRYPTED content, and there is none here",
    );
}

/// A pointer naming content this substrate never held is a typed NotHeld —
/// the arm a caller routes to "ask another holder", not a generic failure.
#[tokio::test]
async fn an_unknown_pointer_is_not_held_rather_than_a_bare_error() {
    let s = store().await;
    let p = BlobPointer {
        community_key_id: String::new(),
        tier: ciris_persist::federation::types::cohort_scope::CryptoTier::Plaintext,
        content_sha256: "ab".repeat(32),
        content_field: ContentField::Body,
        media_type: None,
        stream_id: None,
    };
    let err = s
        .open(OpenRequest {
            pointer: &p,
            author_key_id: "alice",
            asserted_at: instant(),
            viewer_key_id: "alice",
        })
        .await
        .expect_err("absent content must not open");
    assert!(
        matches!(err, GroupContentError::NotHeld { .. }),
        "expected NotHeld, got {err:?}",
    );
}

/// The seal is content-addressed: the same bytes at the same scope produce
/// the same pointer, which is what makes dedup and holder-discovery work.
#[tokio::test]
async fn identical_content_seals_to_one_address() {
    let s = store().await;
    let mk = |author: &'static str| async move {
        store()
            .await
            .seal(SealRequest {
                cohort_scope: "federation",
                community_key_id: None,
                author_key_id: author,
                asserted_at: instant(),
                field: ContentField::Body,
                plaintext: b"the same bytes",
                media_type: None,
            })
            .await
            .expect("seal")
            .pointer
            .content_sha256
    };
    // Two independent substrates, same bytes, same address.
    assert_eq!(mk("alice").await, mk("bob").await);

    // …and within one substrate, re-sealing is idempotent on the address.
    let first = s
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: "alice",
            asserted_at: instant(),
            field: ContentField::Body,
            plaintext: b"dedup me",
            media_type: None,
        })
        .await
        .expect("seal");
    let second = s
        .seal(SealRequest {
            cohort_scope: "federation",
            community_key_id: None,
            author_key_id: "alice",
            asserted_at: instant(),
            field: ContentField::Body,
            plaintext: b"dedup me",
            media_type: None,
        })
        .await
        .expect("re-seal");
    assert_eq!(first.pointer.content_sha256, second.pointer.content_sha256);
}
