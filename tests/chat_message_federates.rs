//! A chat message, on real substrate: authored, shared with the room, read back.
//!
//! The room id is DERIVED from the two fed-IDs, so both ends compute it having
//! exchanged nothing — which is what lets a message be addressed to a room the
//! recipient has not created yet.
//!
//! Placement is the part worth pinning. A message is authored `self` and shared
//! to `community`; it is NEVER `federation`, because that tier is public
//! (lightnet) and a private message placed there is published rather than sent
//! (ciris.ai/contextual-integrity — `cohort_scope` is the visibility half of the
//! Recipient parameter).

use ciris_edge::chat;
use ciris_edge::replication::attestation_bind::{
    already_promoted_verdict, keep_local, publish, share, share_encrypted_privately, ClearCohort,
    EncryptedCohort, Shared, With,
};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend as _;
use sha2::Digest as _;
use std::sync::Arc;

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into()
}

fn signer(key_id: &str, seed: u8) -> ciris_edge::identity::LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).unwrap());
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
            .unwrap(),
    );
    ciris_edge::identity::LocalSigner::new(key_id, classical, Some(pqc))
}

async fn record(
    subject: &str,
    s: &ciris_edge::identity::LocalSigner,
    scrub: &ciris_edge::identity::LocalSigner,
    identity_type: &str,
) -> KeyRecord {
    let ed = b64(&s.classical.public_key().await.unwrap());
    let pqc = b64(&s.pqc.as_ref().unwrap().public_key().await.unwrap());
    let envelope = serde_json::json!({
        "key_id": subject,
        "identity_type": identity_type,
        "pubkey_ed25519_base64": ed,
        "pubkey_ml_dsa_65_base64": pqc,
    });
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).unwrap();
    let digest = sha2::Sha256::digest(&canonical);
    let (sig, sig_pqc) = ciris_edge::identity::sign_bound_hybrid(scrub, &canonical, "key record")
        .await
        .unwrap();
    KeyRecord {
        key_id: subject.to_owned(),
        pubkey_ed25519_base64: ed,
        pubkey_ml_dsa_65_base64: Some(pqc),
        algorithm: "hybrid".to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: subject.to_owned(),
        valid_from: ts(),
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: scrub.key_id.clone(),
        scrub_timestamp: ts(),
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// Alice's node, Alice, and Bob — the three identities a message needs.
async fn world() -> (
    Arc<SqliteBackend>,
    ciris_edge::identity::LocalSigner,
    ciris_edge::identity::LocalSigner,
) {
    let dir = FederationDirectorySqlite::open(":memory:").await.unwrap();
    dir.run_migrations().await.unwrap();
    let alice = signer("alice-fed", 1);
    let alice_node = signer("alice-node", 2);
    let bob = signer("bob-fed", 3);
    for (subject, s, scrub, ity) in [
        ("alice-fed", &alice, &alice, "user"),
        ("alice-node", &alice_node, &alice, "node"),
        ("bob-fed", &bob, &bob, "user"),
    ] {
        dir.put_public_key(SignedKeyRecord {
            record: record(subject, s, scrub, ity).await,
        })
        .await
        .expect("seed record");
    }
    (dir, alice_node, bob)
}

/// **The room is derived, order-free.** Both ends compute the same id from
/// public inputs, having exchanged nothing.
#[test]
fn both_ends_derive_the_same_room() {
    let a = chat::pair_community_key_id("alice-fed", "bob-fed");
    let b = chat::pair_community_key_id("bob-fed", "alice-fed");
    assert_eq!(a, b, "the room id must not depend on who asks");
    assert!(a.starts_with(chat::PAIR_COMMUNITY_PREFIX));
}

/// **A message is authored `self`, shared to `community`, and readable.**
#[tokio::test]
async fn a_message_is_authored_self_shared_to_the_room_and_read_back() {
    let (dir, alice_node, _bob) = world().await;

    let msg = chat::chat_message_attestation(
        "alice-node",
        "alice-fed",
        "bob-fed",
        "hello over the mesh",
        ts(),
        &alice_node,
    )
    .await
    .expect("build message");

    // Authored at SELF — not shareable yet, and emphatically not public.
    assert_eq!(
        msg.cohort_scope,
        ciris_persist::federation::types::cohort_scope::SELF,
        "a message must be authored at self and PROMOTED; authoring it public \
         would publish a private message rather than send it"
    );

    dir.put_attestation(SignedAttestation {
        attestation: msg.clone(),
    })
    .await
    .expect("persist must admit the message");

    let promoted = share_encrypted_privately(&*dir, &msg, EncryptedCohort::Community, &alice_node)
        .await
        .expect("share with the room");
    assert!(promoted, "the promotion must place the row");

    // Read back the way a client would: by room, off the plane.
    let room = chat::pair_community_key_id("alice-fed", "bob-fed");
    let seen = chat::messages_in_room(&*dir, &["alice-node".to_string()], &room)
        .await
        .expect("read the room");
    assert_eq!(seen.len(), 1, "one message in the room: {seen:?}");
    let m = &seen[0];
    assert_eq!(m.body, "hello over the mesh");
    assert_eq!(
        m.author_key_id, "alice-fed",
        "WHOSE WORDS — read from inside the signed envelope, so a relay cannot \
         rewrite it"
    );
    assert_eq!(
        m.attesting_key_id, "alice-node",
        "the NODE attests and signs, on the author's behalf"
    );
    assert_eq!(
        m.attestation_id, msg.attestation_id,
        "keyed on the SENDER's id — a value the receiver cannot manufacture, \
         which is what makes 'it arrived' checkable rather than assumed"
    );
}

/// A message for a DIFFERENT room is not in this one. The room filter is on
/// signed content, not on where the row came from.
#[tokio::test]
async fn a_message_for_another_room_does_not_appear_here() {
    let (dir, alice_node, _bob) = world().await;
    let msg = chat::chat_message_attestation(
        "alice-node",
        "alice-fed",
        "bob-fed",
        "for bob only",
        ts(),
        &alice_node,
    )
    .await
    .unwrap();
    dir.put_attestation(SignedAttestation {
        attestation: msg.clone(),
    })
    .await
    .unwrap();
    share_encrypted_privately(&*dir, &msg, EncryptedCohort::Community, &alice_node)
        .await
        .unwrap();

    let other_room = chat::pair_community_key_id("alice-fed", "carol-fed");
    let seen = chat::messages_in_room(&*dir, &["alice-node".to_string()], &other_room)
        .await
        .unwrap();
    assert!(seen.is_empty(), "wrong room must not match: {seen:?}");
}

/// The chat namespace is in the default consent prefixes — without it, messages
/// are authored, admitted locally, and never offered to the contact.
#[test]
fn the_default_grant_covers_the_chat_namespace() {
    assert!(
        ciris_edge::replication::attestation_bind::DEFAULT_CONSENT_PREFIXES
            .contains(&chat::CHAT_ATTESTATION_PREFIX),
        "a grant that does not cover `chat:` silently withholds every message"
    );
}

/// **The encrypted/clear split is persist's, not ours.**
///
/// `crypto_tier` is negative-default (CIRISPersist#188): only self/family and
/// community/affiliations encrypt, and everything else — including unknown
/// future scopes — falls through to plaintext. Restating that grouping in edge
/// would let the two drift, and the drift would be an API promising encryption
/// the substrate does not apply.
#[test]
fn every_encrypted_cohort_actually_encrypts_and_every_clear_one_does_not() {
    use ciris_persist::federation::types::cohort_scope::{crypto_tier, CryptoTier};

    for c in [
        EncryptedCohort::MyOwnDevices,
        EncryptedCohort::MyFamily,
        EncryptedCohort::Community,
        EncryptedCohort::Affiliations,
    ] {
        assert!(
            !matches!(crypto_tier(c.cohort_scope(), None), CryptoTier::Plaintext),
            "{c:?} is offered as ENCRYPTED but persist stores {} in the clear",
            c.cohort_scope()
        );
    }
    for c in [ClearCohort::Species, ClearCohort::Biosphere] {
        assert!(
            matches!(crypto_tier(c.cohort_scope(), None), CryptoTier::Plaintext),
            "{c:?} is offered as CLEAR; if persist now encrypts {}, the honest \
             move is to promote it into EncryptedCohort, not to keep calling it clear",
            c.cohort_scope()
        );
    }
}

/// **`self` and `family` are invisible; community is only filtered.**
///
/// Pinned because "only members can read it" and "nobody can tell it exists"
/// are different claims, and overclaiming the second asserts a privacy property
/// the wire does not provide.
#[test]
fn only_self_and_family_are_structurally_invisible() {
    for c in [EncryptedCohort::MyOwnDevices, EncryptedCohort::MyFamily] {
        assert!(
            c.is_structurally_invisible(),
            "{c:?} must emit no holds_bytes — withholding the discovery surface \
             IS the privacy primitive, and it is the locality dividend too"
        );
    }
    for c in [EncryptedCohort::Community, EncryptedCohort::Affiliations] {
        assert!(
            !c.is_structurally_invisible(),
            "{c:?} DOES emit holds_bytes; its property is cohort-filtered \
             visibility, not invisibility (CEG 0.8 §8.1.13.3)"
        );
    }
}

/// No shareable cohort is the world-readable tier — publishing is its own call.
#[test]
fn no_cohort_variant_is_the_public_tier() {
    use ciris_persist::federation::types::cohort_scope as cs;
    for scope in [
        EncryptedCohort::MyOwnDevices.cohort_scope(),
        EncryptedCohort::MyFamily.cohort_scope(),
        EncryptedCohort::Community.cohort_scope(),
        EncryptedCohort::Affiliations.cohort_scope(),
        ClearCohort::Species.cohort_scope(),
        ClearCohort::Biosphere.cohort_scope(),
    ] {
        assert_ne!(
            scope,
            cs::FEDERATION,
            "reaching the world-readable tier must require calling share_publicly"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// The one-verb surface — FSD_REPLICATION_DX §3 — pinned
// ═══════════════════════════════════════════════════════════════════

async fn authored(
    dir: &Arc<SqliteBackend>,
    alice_node: &ciris_edge::identity::LocalSigner,
    body: &str,
) -> ciris_persist::federation::Attestation {
    let msg = chat::chat_message_attestation(
        "alice-node",
        "alice-fed",
        "bob-fed",
        body,
        ts(),
        alice_node,
    )
    .await
    .unwrap();
    dir.put_attestation(SignedAttestation {
        attestation: msg.clone(),
    })
    .await
    .expect("admit");
    msg
}

/// `share` places once and is idempotent after — CC 5.3.2.4.2 made visible.
#[tokio::test]
async fn share_places_then_reports_already_there() {
    let (dir, alice_node, _bob) = world().await;
    let msg = authored(&dir, &alice_node, "once").await;

    let first = share(&*dir, &msg, With::Community, &alice_node)
        .await
        .unwrap();
    assert_eq!(first, Shared::Placed);

    // Re-read the row as stored (tier + scope moved) and share it again.
    let stored = dir
        .list_attestations_by("alice-node")
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.attestation_id == msg.attestation_id)
        .expect("stored row");
    assert_eq!(stored.tier, "federation");
    assert_eq!(stored.cohort_scope, "community");
    let again = share(&*dir, &stored, With::Community, &alice_node)
        .await
        .unwrap();
    assert_eq!(again, Shared::AlreadyThere, "idempotent, and it says so");
}

/// A row authored already-promoted at another cohort is REFUSED by name —
/// never the substrate's silent `Ok(false)`. The verdict is a pure function,
/// so it is provably decided before any directory is touched.
#[tokio::test]
async fn share_refuses_a_row_authored_already_promoted_elsewhere() {
    let (dir, alice_node, _bob) = world().await;
    let mut msg = chat::chat_message_attestation(
        "alice-node",
        "alice-fed",
        "bob-fed",
        "x",
        ts(),
        &alice_node,
    )
    .await
    .unwrap();
    // The authoring bug this catches: federation tier, but still `self`.
    msg.tier = "federation".to_owned();

    // The pure verdict, with no directory in sight.
    let verdict =
        already_promoted_verdict(&msg, "community").expect("a verdict, not a pass-through");
    let err = verdict.expect_err("different cohort ⇒ refusal");
    assert!(err.contains("AUTHORED at tier `federation`"), "{err}");
    assert!(err.contains("idempotent"), "{err}");
    // Same cohort ⇒ already there, not an error.
    assert_eq!(
        already_promoted_verdict(&msg, "self"),
        Some(Ok(Shared::AlreadyThere))
    );
    // Not promoted ⇒ no verdict, proceed.
    let mut local = msg.clone();
    local.tier = "local".to_owned();
    assert_eq!(already_promoted_verdict(&local, "community"), None);

    // And the verb itself surfaces the same refusal end-to-end.
    let err = share(&*dir, &msg, With::Community, &alice_node)
        .await
        .unwrap_err();
    assert!(err.contains("AUTHORED at tier `federation`"), "{err}");
}

/// `keep_local` accepts a local row and refuses a subject-side revocation
/// (CC 5.3.2.2) and an already-promoted row.
#[tokio::test]
async fn keep_local_is_a_true_statement_or_an_error() {
    let (dir, alice_node, _bob) = world().await;
    let msg = authored(&dir, &alice_node, "mine").await;
    keep_local(&msg).expect("a local producer-only row may stay local");

    let mut promoted = msg.clone();
    promoted.tier = "federation".to_owned();
    assert!(
        keep_local(&promoted).is_err(),
        "not local ⇒ not a true statement"
    );

    let mut revocation = msg.clone();
    revocation.attestation_type = "withdraws".to_owned();
    revocation.subject_key_ids = vec!["bob-fed".to_owned()];
    let err = keep_local(&revocation).unwrap_err();
    assert!(err.contains("CC 5.3.2.2"), "{err}");
}

/// `publish` lands the row at `federation` — and says it is placed.
#[tokio::test]
async fn publish_places_at_the_public_tier() {
    let (dir, alice_node, _bob) = world().await;
    let msg = authored(&dir, &alice_node, "public").await;
    assert_eq!(
        publish(&*dir, &msg, &alice_node).await.unwrap(),
        Shared::Placed
    );
    let stored = dir
        .list_attestations_by("alice-node")
        .await
        .unwrap()
        .into_iter()
        .find(|a| a.attestation_id == msg.attestation_id)
        .unwrap();
    assert_eq!(stored.cohort_scope, "federation");
    assert_eq!(stored.tier, "federation");
}

/// `With` answers encryption and invisibility FROM persist, for every variant.
#[test]
fn with_answers_both_questions_from_persist() {
    use ciris_persist::federation::types::cohort_scope::{
        crypto_tier, suppresses_holds_bytes, CryptoTier,
    };
    for w in [
        With::MyDevices,
        With::MyFamily,
        With::Community,
        With::Affiliations,
        With::Species,
        With::Biosphere,
    ] {
        let expect_enc = !matches!(crypto_tier(w.cohort_scope(), None), CryptoTier::Plaintext);
        assert_eq!(w.is_encrypted_at_rest(), expect_enc, "{w:?} encryption");
        assert_eq!(
            w.is_structurally_invisible(),
            suppresses_holds_bytes(w.cohort_scope()),
            "{w:?} invisibility"
        );
        assert_ne!(
            w.cohort_scope(),
            "federation",
            "{w:?} must not be the public tier"
        );
    }
    // The two facts the names exist to carry.
    assert!(
        !With::Species.is_encrypted_at_rest(),
        "species is Commons plaintext"
    );
    assert!(With::Community.is_encrypted_at_rest() && !With::Community.is_structurally_invisible());
    assert!(With::MyDevices.is_structurally_invisible());
}
