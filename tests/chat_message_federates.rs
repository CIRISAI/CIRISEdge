//! A chat message, on real substrate: authored by its ACTOR, shared with the
//! room, read back.
//!
//! The room id is DERIVED from the two fed-IDs, so both ends compute it having
//! exchanged nothing — which is what lets a message be addressed to a room the
//! recipient has not created yet.
//!
//! Two things are worth pinning here. Placement: a message is authored `self`
//! and shared to `community`; it is NEVER `federation`, because that tier is
//! public (lightnet) and a private message placed there is published rather
//! than sent. And custody: the AUTHOR signs the row at write and that
//! signature survives the crossing — the node only ever co-scrubs — because a
//! share is two operations (`enter_mesh` over the same bytes, then a
//! `supersedes` the actor signs at the wider audience), never a re-sign by the
//! fabric (CIRISPersist FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE).

use ciris_edge::chat;
use ciris_edge::replication::attestation_bind::{
    custody_for, describe_crossing, keep_local, publish, share, share_encrypted_privately,
    share_plan, Audience, ClearCohort, CrossingBasis, Custody, DataSubject, EncryptedCohort,
    MeshCrossingOutcome, RevocationAuthority, RoutesTo, SharePlan, Shared, Signers,
    TierPromotionCustody, With,
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

/// The three identities a message needs, and the room Alice and Bob share.
struct World {
    dir: Arc<SqliteBackend>,
    alice: ciris_edge::identity::LocalSigner,
    alice_node: ciris_edge::identity::LocalSigner,
    bob: ciris_edge::identity::LocalSigner,
    room: String,
}

impl World {
    fn signers(&self) -> Signers<'_> {
        Signers {
            node: &self.alice_node,
            actor: Some(&self.alice),
        }
    }
    fn room_with(&self) -> With {
        With::Community {
            community_key_id: self.room.clone(),
        }
    }
    async fn stored(&self, by: &str, id: &str) -> ciris_persist::federation::Attestation {
        self.dir
            .list_attestations_by(by)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.attestation_id == id)
            .unwrap_or_else(|| panic!("row {id} by {by} is stored"))
    }
}

async fn world() -> World {
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
    // The pair room, members the two HUMANS — both FOUNDERS, so both are
    // zero-hop moderators (§11.11) by construction: a `community` placement
    // is a membership claim the put door proves against the cohort the row
    // names (AV-45), and persist refuses to federate an unmoderated room.
    let room = chat::pair_community_key_id("alice-fed", "bob-fed");
    dir.put_community(
        chat::signed_pair_community("alice-fed", "bob-fed", ts(), &alice_node)
            .await
            .expect("sign the room"),
    )
    .await
    .expect("the pair room is admitted");
    World {
        dir,
        alice,
        alice_node,
        bob,
        room,
    }
}

/// Author a message as Alice (signed at write) and store it.
async fn authored(w: &World, body: &str) -> ciris_persist::federation::Attestation {
    let msg = chat::chat_message_attestation(&w.alice, "bob-fed", body, ts())
        .await
        .unwrap();
    w.dir
        .put_attestation(SignedAttestation {
            attestation: msg.clone(),
        })
        .await
        .expect("persist admits the message");
    msg
}

fn is_canonical_instant(s: &str) -> bool {
    // CC 2.6.2: `YYYY-MM-DDTHH:MM:SS.sssZ` — literal `Z`, exactly three digits.
    s.len() == 24
        && s.ends_with('Z')
        && s.as_bytes()[19] == b'.'
        && s[20..23].bytes().all(|b| b.is_ascii_digit())
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

/// **The author signs at write, the row is authored `self`, shared to the
/// room, and the author's signature survives — the node only co-scrubs.**
#[tokio::test]
// One witness, end to end: every property of the two rows a share leaves behind
// is asserted against the same crossing, so a regression cannot pass one half.
#[allow(clippy::too_many_lines)]
async fn the_author_signs_at_write_and_the_signature_survives_the_crossing() {
    let w = world().await;
    let msg = chat::chat_message_attestation(&w.alice, "bob-fed", "hello over the mesh", ts())
        .await
        .expect("build message");

    assert_eq!(msg.attesting_key_id, "alice-fed", "the ACTOR is the sender");
    assert_eq!(
        msg.scrub_key_id, "alice-fed",
        "signed at write by the actor"
    );
    assert!(!msg.scrub_signature_classical.is_empty());
    assert_eq!(
        msg.cohort_scope,
        ciris_persist::federation::types::cohort_scope::SELF,
        "authored at self and SHARED; authoring it public would publish a private \
         message rather than send it"
    );
    assert_eq!(msg.tier, "local");
    w.dir
        .put_attestation(SignedAttestation {
            attestation: msg.clone(),
        })
        .await
        .expect("persist admits the message");

    let crossing = share(
        &*w.dir,
        &msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .expect("share with the room");

    // TWO rows: the original entered the mesh at `self`; a supersedes at
    // `community` is what the peer receives.
    let MeshCrossingOutcome::Crossed(entered) = &crossing.entered else {
        panic!("entered: {:?}", crossing.entered)
    };
    assert_eq!(entered.attestation_id, msg.attestation_id);
    assert_eq!(entered.audience, Audience::SelfOnly);
    assert!(
        matches!(entered.custody, Custody::ActorSignedNodeCoScrubbed { .. }),
        "the row was signed by the actor at write, so the node CO-SCRUBS: {:?}",
        entered.custody
    );
    assert!(
        !entered.replicates.discoverable,
        "self: replicated, not advertised"
    );
    let Some(MeshCrossingOutcome::Crossed(widened)) = &crossing.widened else {
        panic!("widened: {:?}", crossing.widened)
    };
    assert_ne!(widened.attestation_id, msg.attestation_id, "a NEW row");
    assert_eq!(widened.audience, w.room_with().audience());
    assert_eq!(
        widened.custody,
        Custody::ActorSigned,
        "the actor signs the widening"
    );
    assert!(
        widened.replicates.discoverable,
        "community: served on discovery"
    );
    assert_eq!(
        crossing.shared,
        Shared::Placed {
            attestation_id: widened.attestation_id.clone()
        },
        "the id on the wire at the audience asked for is the widening's"
    );
    assert_eq!(
        crossing.routes_to,
        RoutesTo::CommunityMembers {
            community_key_id: w.room.clone()
        }
    );

    // The ORIGINAL, as stored: byte-identical, actor's base scrub intact, the
    // node's co-scrub appended with a canonical `cosigned_at`.
    let original = w.stored("alice-fed", &msg.attestation_id).await;
    assert_eq!(original.tier, "federation");
    assert_eq!(
        original.cohort_scope, "self",
        "enter_mesh never moves the scope"
    );
    // Same BYTES — compared canonically, because a sqlite round trip renders
    // `1.0` as `1` in the Value while JCS canonicalizes both identically.
    assert_eq!(
        ciris_persist::prelude::ceg_produce_canonicalize(&original.attestation_envelope).unwrap(),
        ciris_persist::prelude::ceg_produce_canonicalize(&msg.attestation_envelope).unwrap(),
        "same bytes"
    );
    assert_eq!(
        original.scrub_key_id, "alice-fed",
        "the fabric never replaced the actor"
    );
    assert_eq!(
        original.scrub_signature_classical,
        msg.scrub_signature_classical
    );
    assert_eq!(
        original.additional_scrubs.len(),
        1,
        "{:?}",
        original.additional_scrubs
    );
    let co = &original.additional_scrubs[0];
    assert_eq!(co.scrub_key_id, "alice-node");
    assert!(
        is_canonical_instant(co.cosigned_at.as_deref().unwrap()),
        "cosigned_at is CC 2.6.2 canonical: {:?}",
        co.cosigned_at
    );

    // The WIDENING, as stored: by the actor, referencing the original.
    let wide = w.stored("alice-fed", &widened.attestation_id).await;
    assert_eq!(wide.attestation_type, "supersedes");
    assert_eq!(wide.cohort_scope, "community");
    assert_eq!(wide.attesting_key_id, "alice-fed");
    assert_eq!(wide.scrub_key_id, "alice-fed");
    assert_eq!(
        wide.attestation_envelope["references_attestation_id"],
        serde_json::json!(msg.attestation_id)
    );

    // Read back the way a client would: by room, off the plane — ONE message,
    // the widening; the `self` copy is folded away.
    let seen = chat::messages_in_room(&*w.dir, &["alice-fed".to_string()], &w.room)
        .await
        .expect("read the room");
    assert_eq!(seen.len(), 1, "one message in the room: {seen:?}");
    let m = &seen[0];
    assert_eq!(m.body, "hello over the mesh");
    assert_eq!(m.author_key_id, "alice-fed", "WHOSE WORDS — the attester");
    assert_eq!(m.attesting_key_id, "alice-fed");
    assert_eq!(
        m.attestation_id, widened.attestation_id,
        "the row on the wire"
    );
    assert_eq!(m.widens.as_deref(), Some(msg.attestation_id.as_str()));
}

/// **Both members of a pair room are moderators, by construction.** Persist's
/// own `moderators_of` names each of them for the `moderate` duty — a zero-hop
/// appointment through the `founder` role — so the room can federate
/// (§11.11) without anyone having to appoint anyone.
#[tokio::test]
async fn both_members_of_the_pair_room_are_moderators() {
    let w = world().await;
    let room = chat::pair_community("alice-fed", "bob-fed", ts());
    assert!(
        room.members
            .iter()
            .all(|m| m.role.as_deref() == Some("founder")),
        "{:?}",
        room.members
    );
    let mods = ciris_persist::federation::admission::moderators_of(&*w.dir, &w.room, "moderate")
        .await
        .expect("moderators_of");
    for who in ["alice-fed", "bob-fed"] {
        assert!(mods.iter().any(|m| m == who), "{who} moderates: {mods:?}");
    }
}

/// A message for a DIFFERENT room is not in this one. The room filter is on
/// signed content, not on where the row came from.
#[tokio::test]
async fn a_message_for_another_room_does_not_appear_here() {
    let w = world().await;
    let msg = authored(&w, "for bob only").await;
    share_encrypted_privately(
        &*w.dir,
        &msg,
        EncryptedCohort::Community {
            community_key_id: w.room.clone(),
        },
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();

    let other_room = chat::pair_community_key_id("alice-fed", "carol-fed");
    let seen = chat::messages_in_room(&*w.dir, &["alice-fed".to_string()], &other_room)
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
        EncryptedCohort::MyFamily {
            family_key_id: "fam".into(),
        },
        EncryptedCohort::Community {
            community_key_id: "room".into(),
        },
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

/// **`self` and `family` are undiscoverable; community is only filtered.**
///
/// Pinned because "only members can read it" and "nobody can tell it exists"
/// are different claims, and overclaiming the second asserts a privacy property
/// the wire does not provide. Undiscoverable is NOT un-replicated.
#[test]
fn only_self_and_family_are_structurally_invisible() {
    for c in [
        EncryptedCohort::MyOwnDevices,
        EncryptedCohort::MyFamily {
            family_key_id: "fam".into(),
        },
    ] {
        assert!(
            c.is_structurally_invisible(),
            "{c:?} must emit no holds_bytes — withholding the discovery surface \
             IS the privacy primitive, and it is the locality dividend too"
        );
    }
    for c in [
        EncryptedCohort::Community {
            community_key_id: "room".into(),
        },
        EncryptedCohort::Affiliations,
    ] {
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
        EncryptedCohort::MyFamily {
            family_key_id: "fam".into(),
        }
        .cohort_scope(),
        EncryptedCohort::Community {
            community_key_id: "room".into(),
        }
        .cohort_scope(),
        EncryptedCohort::Affiliations.cohort_scope(),
        ClearCohort::Species.cohort_scope(),
        ClearCohort::Biosphere.cohort_scope(),
    ] {
        assert_ne!(
            scope,
            cs::FEDERATION,
            "reaching the world-readable tier must require calling publish"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
// The one-verb surface — FSD_REPLICATION_DX §3 — pinned
// ═══════════════════════════════════════════════════════════════════

/// `share` places once and is idempotent after — CC 5.3.2.4.2 and CEG §6.1
/// made visible, on BOTH rows a widening leaves behind.
#[tokio::test]
async fn share_places_then_reports_already_there() {
    let w = world().await;
    let msg = authored(&w, "once").await;

    let first = share(
        &*w.dir,
        &msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    let Shared::Placed {
        attestation_id: wide_id,
    } = &first.shared
    else {
        panic!("{:?}", first.shared)
    };

    // The widening, re-shared at the same audience: already there.
    let wide = w.stored("alice-fed", wide_id).await;
    assert_eq!(
        (wide.tier.as_str(), wide.cohort_scope.as_str()),
        ("federation", "community")
    );
    let again = share(
        &*w.dir,
        &wide,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    assert_eq!(
        again.shared,
        Shared::AlreadyThere {
            attestation_id: wide_id.clone()
        },
        "idempotent, and it says so"
    );
    assert_eq!(again.widened, None);

    // The ORIGINAL (now federation/self), shared to the room again: persist
    // deduplicates the second widening by the same attester — no third row.
    let original = w.stored("alice-fed", &msg.attestation_id).await;
    let third = share(
        &*w.dir,
        &original,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    assert_eq!(
        third.shared,
        Shared::AlreadyThere {
            attestation_id: msg.attestation_id.clone()
        }
    );
    assert!(
        matches!(
            third.widened,
            Some(MeshCrossingOutcome::AlreadyWidened { .. })
        ),
        "{:?}",
        third.widened
    );
    let rows = w.dir.list_attestations_by("alice-fed").await.unwrap();
    assert_eq!(
        rows.iter()
            .filter(|a| a.attestation_type == "supersedes")
            .count(),
        1,
        "exactly one widening: {rows:?}"
    );
}

/// The plan is a pure function of the row and the audience, so it is provably
/// decided before any directory is touched — and a narrowing is refused by
/// name, never silently no-op'd.
#[tokio::test]
async fn the_share_plan_is_decided_before_any_directory_and_refuses_a_narrowing() {
    let w = world().await;
    let msg = chat::chat_message_attestation(&w.alice, "bob-fed", "x", ts())
        .await
        .unwrap();
    let room = w.room_with().audience();

    assert_eq!(
        share_plan(&msg, &room).unwrap(),
        SharePlan::EnterThenWiden(room.clone()),
        "local self row → enter, then widen"
    );
    assert_eq!(
        share_plan(&msg, &Audience::SelfOnly).unwrap(),
        SharePlan::Enter,
        "local self row asked for self → tier crossing only"
    );
    let mut in_mesh = msg.clone();
    in_mesh.tier = "federation".to_owned();
    assert_eq!(
        share_plan(&in_mesh, &room).unwrap(),
        SharePlan::Widen(room.clone()),
        "a row already in the mesh is WIDENED, not refused — the FSD's two operations"
    );
    assert_eq!(
        share_plan(&in_mesh, &Audience::SelfOnly).unwrap(),
        SharePlan::AlreadyThere
    );
    let mut wide = in_mesh.clone();
    wide.cohort_scope = "community".to_owned();
    let err = share_plan(&wide, &Audience::SelfOnly).unwrap_err();
    assert!(err.contains("not strictly wider"), "{err}");

    // No dimension ⇒ not a claim ⇒ refused before anything moves.
    let mut bare = msg.clone();
    bare.attestation_envelope
        .as_object_mut()
        .unwrap()
        .remove("dimension");
    let e1 = share_plan(&bare, &room).unwrap_err();
    let e2 = share(
        &*w.dir,
        &bare,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap_err();
    assert!(e1.contains("no `dimension`"), "{e1}");
    assert!(e2.contains("no `dimension`"), "{e2}");

    // And end to end: the stored widening cannot be narrowed back to self.
    let stored_msg = authored(&w, "narrow").await;
    let placed = share(
        &*w.dir,
        &stored_msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    let Shared::Placed { attestation_id } = placed.shared else {
        panic!()
    };
    let stored_wide = w.stored("alice-fed", &attestation_id).await;
    let err = share(
        &*w.dir,
        &stored_wide,
        With::MyDevices,
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap_err();
    assert!(err.contains("not strictly wider"), "{err}");
}

/// `keep_local` accepts a local row and refuses a subject-side revocation
/// (CC 5.3.2.2) and an already-promoted row.
#[tokio::test]
async fn keep_local_is_a_true_statement_or_an_error() {
    let w = world().await;
    let msg = authored(&w, "mine").await;
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

/// `publish` lands a widening at `federation` — and says so, discoverable.
#[tokio::test]
async fn publish_places_at_the_public_tier() {
    let w = world().await;
    let msg = authored(&w, "public").await;
    let crossing = publish(&*w.dir, &msg, CrossingBasis::ProducerAuthority, w.signers())
        .await
        .unwrap();
    let Shared::Placed { attestation_id } = &crossing.shared else {
        panic!("{:?}", crossing.shared)
    };
    assert_eq!(crossing.ci.recipient_see, Audience::Federation);
    assert_eq!(crossing.routes_to, RoutesTo::Everyone);
    assert!(crossing.discoverable);
    let wide = w.stored("alice-fed", attestation_id).await;
    assert_eq!(wide.cohort_scope, "federation");
    assert_eq!(wide.tier, "federation");
    let original = w.stored("alice-fed", &msg.attestation_id).await;
    assert_eq!(
        (original.tier.as_str(), original.cohort_scope.as_str()),
        ("federation", "self"),
        "the original entered the mesh at its own scope and stays there"
    );
}

/// `With` answers encryption and invisibility FROM persist, for every variant.
#[test]
fn with_answers_both_questions_from_persist() {
    use ciris_persist::federation::types::cohort_scope::{
        crypto_tier, suppresses_holds_bytes, CryptoTier,
    };
    for w in [
        With::MyDevices,
        With::MyFamily {
            family_key_id: "fam".into(),
        },
        With::Community {
            community_key_id: "room".into(),
        },
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
        assert_eq!(w.audience().cohort_scope(), w.cohort_scope());
    }
    // The two facts the names exist to carry.
    assert!(
        !With::Species.is_encrypted_at_rest(),
        "species is Commons plaintext"
    );
    let room = With::Community {
        community_key_id: "room".into(),
    };
    assert!(room.is_encrypted_at_rest() && !room.is_structurally_invisible());
    assert!(With::MyDevices.is_structurally_invisible());
}

/// **All nine CC 4.5.1.1 axes ride the crossing**, derived from the row and
/// verified by persist — and the direct path describes the same row the same
/// way, differing only in where it is going.
#[tokio::test]
async fn the_nine_axes_are_stated_and_verified_at_the_crossing() {
    let w = world().await;
    let msg = authored(&w, "axes").await;

    let direct =
        describe_crossing(&msg, Audience::SelfOnly, CrossingBasis::ProducerAuthority).unwrap();
    let crossing = share(
        &*w.dir,
        &msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    let ci = &crossing.ci;
    assert_eq!(ci.sender, "alice-fed", "the sender IS the attester");
    assert_eq!(
        ci.data_subject,
        DataSubject::Keys {
            key_ids: vec!["alice-fed".into()]
        }
    );
    assert_eq!(ci.recipient_see, w.room_with().audience());
    assert_eq!(
        ci.recipient_revoke,
        RevocationAuthority::Subjects {
            key_ids: vec!["alice-fed".into()]
        },
        "revocation follows the subject"
    );
    assert_eq!(ci.recipient_receive, direct.recipient_receive);
    assert_eq!(ci.information_type, direct.information_type);
    assert_eq!(ci.transmission_principle, CrossingBasis::ProducerAuthority);
    assert_eq!(ci.temporal_lifecycle, direct.temporal_lifecycle);
    assert_eq!(ci.temporal_lifecycle.asserted_at, msg.asserted_at);
    assert_eq!(
        ci.content, direct.content,
        "the widening REUSES the content hash (CC 8.1.5)"
    );
    // Every axis but the audience is the row's own.
    assert_eq!(ci.sender, direct.sender);
    assert_eq!(ci.data_subject, direct.data_subject);
    assert_ne!(ci.recipient_see, direct.recipient_see);
}

/// **Custody is decided from the row** — edge's copy of persist's table: an
/// unsigned row waits for its actor (nothing to co-scrub), the actor in hand
/// signs, and the WRONG key in hand is refused rather than ignored.
#[tokio::test]
async fn custody_is_the_actors_or_it_waits() {
    let w = world().await;
    let signed = chat::chat_message_attestation(&w.alice, "bob-fed", "c", ts())
        .await
        .unwrap();
    let mut deferred = signed.clone();
    deferred.scrub_signature_classical.clear();
    deferred.scrub_signature_pqc = None;
    deferred.original_content_hash.clear();

    // Signed at write by the actor: the node co-scrubs, whether or not the
    // actor is still in hand.
    for actor in [Some(&w.alice), None] {
        let custody = custody_for(
            &signed,
            Signers {
                node: &w.alice_node,
                actor,
            },
        )
        .await
        .unwrap()
        .expect("a signed row always has a custody");
        let TierPromotionCustody::NodeCoScrub(scrub) = custody else {
            panic!("{custody:?}")
        };
        assert_eq!(scrub.scrub_key_id, "alice-node");
        assert!(is_canonical_instant(scrub.cosigned_at.as_deref().unwrap()));
    }
    // Deferred, actor absent: it WAITS — the fabric is never the only signer
    // of an actor's claim (W4).
    assert!(custody_for(
        &deferred,
        Signers {
            node: &w.alice_node,
            actor: None
        }
    )
    .await
    .unwrap()
    .is_none());
    // Deferred, actor in hand: the actor signs now.
    let custody = custody_for(&deferred, w.signers()).await.unwrap().unwrap();
    let TierPromotionCustody::ActorSigned(reseal) = custody else {
        panic!("{custody:?}")
    };
    assert_eq!(reseal.scrub_key_id, "alice-fed");
    assert_eq!(
        reseal.original_content_hash, signed.original_content_hash,
        "same bytes, same hash"
    );
    // Deferred, the WRONG key in hand: refused, not ignored (W5).
    let err = custody_for(
        &deferred,
        Signers {
            node: &w.alice_node,
            actor: Some(&w.bob),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("custody is not the actor"), "{err}");
}

/// **A widening needs the actor.** With only the node in hand, a row the
/// actor signed still ENTERS the mesh (co-scrubbed) but the widening waits —
/// typed, never a silent stay-local — and nothing is signed by the wrong key.
#[tokio::test]
async fn without_the_actor_the_row_enters_but_the_widening_waits() {
    let w = world().await;
    let msg = authored(&w, "waits").await;
    let crossing = share(
        &*w.dir,
        &msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        Signers {
            node: &w.alice_node,
            actor: None,
        },
    )
    .await
    .unwrap();
    assert!(
        matches!(crossing.entered, MeshCrossingOutcome::Crossed(_)),
        "{:?}",
        crossing.entered
    );
    assert!(
        matches!(
            crossing.widened,
            Some(MeshCrossingOutcome::AwaitingActor { .. })
        ),
        "{:?}",
        crossing.widened
    );
    assert!(
        matches!(crossing.shared, Shared::AwaitingActor { ref attestation_id, .. } if *attestation_id == msg.attestation_id),
        "{:?}",
        crossing.shared
    );
    let original = w.stored("alice-fed", &msg.attestation_id).await;
    assert_eq!(
        (original.tier.as_str(), original.cohort_scope.as_str()),
        ("federation", "self")
    );
    let rows = w.dir.list_attestations_by("alice-fed").await.unwrap();
    assert!(rows.iter().all(|a| a.attestation_type != "supersedes"));

    // The wrong actor is refused by name, not ignored.
    let err = share(
        &*w.dir,
        &original,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        Signers {
            node: &w.alice_node,
            actor: Some(&w.bob),
        },
    )
    .await
    .unwrap_err();
    assert!(err.contains("custody is not the actor"), "{err}");

    // The actor arrives: the widening completes, on the row as stored.
    let done = share(
        &*w.dir,
        &original,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    assert!(
        matches!(done.shared, Shared::Placed { .. }),
        "{:?}",
        done.shared
    );
}

/// **Every instant edge signs is CC 2.6.2 canonical** — `.sssZ`, on the
/// author's row and on the widening persist mints for it.
#[tokio::test]
async fn signed_instants_are_canonical() {
    let w = world().await;
    let msg = authored(&w, "when").await;
    let at = msg.attestation_envelope["asserted_at"].as_str().unwrap();
    assert!(is_canonical_instant(at), "{at}");
    assert!(!at.contains("+00:00"));
    let crossing = share(
        &*w.dir,
        &msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    let Shared::Placed { attestation_id } = &crossing.shared else {
        panic!()
    };
    let wide = w.stored("alice-fed", attestation_id).await;
    let at = wide.attestation_envelope["asserted_at"].as_str().unwrap();
    assert!(is_canonical_instant(at), "{at}");
    // The column agrees with the signed bytes at the substrate's resolution.
    let parsed: chrono::DateTime<chrono::Utc> =
        chrono::DateTime::parse_from_rfc3339(at).unwrap().into();
    assert_eq!(parsed, wide.asserted_at);
}
