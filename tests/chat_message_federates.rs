//! A chat message, on real substrate: authored by its ACTOR, sealed under the
//! room's key, shared with the room, read back and opened.
//!
//! The room id is DERIVED from the two fed-IDs, so both ends compute it having
//! exchanged nothing — which is what lets a message be addressed to a room the
//! recipient has not created yet.
//!
//! Three things are worth pinning here. Placement: a message is authored
//! `self` and shared to `community`; it is NEVER `federation`. Custody: the
//! AUTHOR signs the row at write (full hybrid, no fallback) and that signature
//! survives the crossing — the node only ever co-scrubs — because a share is
//! two operations (`enter_mesh` over the same bytes, then a `supersedes` the
//! actor signs at the wider audience). And the seal: community tier is
//! encrypted, so the body on the wire is ciphertext under the room's MLS
//! record secret, and the MLS handshake that produces that secret rides the
//! room as ordinary rows.

use ciris_edge::chat::{self, Body, PairRole, RoomKey};
use ciris_edge::mls::cohort_group::{
    key_package_from_bytes, key_package_to_bytes, mint_cohort_key_material,
};
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::replication::attestation_bind::{
    custody_for, describe_crossing, keep_local, publish, share, share_encrypted_privately,
    share_plan, Audience, ClearCohort, CrossingBasis, Custody, DataSubject, EncryptedCohort,
    MeshCrossingOutcome, RevocationAuthority, RoutesTo, SharePlan, Shared, Signers,
    TierPromotionCustody, With,
};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend as _;
use sha2::Digest as _;
use std::sync::Arc;

const BODY: &str = "hello over the mesh";

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

fn store(seed: &str) -> ScopeStateProvider {
    ScopeStateProvider::new(Arc::new(
        XChaChaKvStore::open_in_memory(seed.as_bytes()).unwrap(),
    ))
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

/// Alice and her node, Bob and his node, the room they share, and the room
/// key on BOTH sides — derived in-process through the real MLS handshake
/// (create → KeyPackage → add → Welcome → join).
struct World {
    dir: Arc<SqliteBackend>,
    alice: ciris_edge::identity::LocalSigner,
    alice_node: ciris_edge::identity::LocalSigner,
    bob: ciris_edge::identity::LocalSigner,
    bob_node: ciris_edge::identity::LocalSigner,
    room: String,
}

impl World {
    fn signers(&self) -> Signers<'_> {
        Signers {
            node: &self.alice_node,
            actor: Some(&self.alice),
        }
    }
    fn bobs_signers(&self) -> Signers<'_> {
        Signers {
            node: &self.bob_node,
            actor: Some(&self.bob),
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
    let bob_node = signer("bob-node", 4);
    for (subject, s, scrub, ity) in [
        ("alice-fed", &alice, &alice, "user"),
        ("alice-node", &alice_node, &alice, "node"),
        ("bob-fed", &bob, &bob, "user"),
        ("bob-node", &bob_node, &bob, "node"),
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
        bob_node,
        room,
    }
}

/// Author a message as Alice — content to the room's BLOB STORE, row signed
/// at write — and store the row.
async fn authored(w: &World, body: &str) -> ciris_persist::federation::Attestation {
    let store = content_store(w).await;
    let (msg, sealed) = chat::chat_message_attestation(&w.alice, "bob-fed", body, ts(), &store)
        .await
        .unwrap();
    assert!(
        sealed.fully_readable(),
        "a room member was excluded at write and could never read this: {:?}",
        sealed.excluded,
    );
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
/// public inputs, having exchanged nothing — and the same ROLE.
#[test]
fn both_ends_derive_the_same_room_and_opposite_roles() {
    let a = chat::pair_community_key_id("alice-fed", "bob-fed");
    let b = chat::pair_community_key_id("bob-fed", "alice-fed");
    assert_eq!(a, b, "the room id must not depend on who asks");
    assert!(a.starts_with(chat::PAIR_COMMUNITY_PREFIX));
    assert_eq!(PairRole::of("alice-fed", "bob-fed"), PairRole::Creator);
    assert_eq!(PairRole::of("bob-fed", "alice-fed"), PairRole::Joiner);
}

/// **The author signs at write (full hybrid), the body is SEALED, the row is
/// authored `self`, shared to the room, and the author's signature survives
/// — the node only co-scrubs. The far end opens it with ITS key.**
#[tokio::test]
// One witness, end to end: every property of the two rows a share leaves behind
// is asserted against the same crossing, so a regression cannot pass one half.
#[allow(clippy::too_many_lines)]
async fn the_author_signs_at_write_and_the_signature_survives_the_crossing() {
    let w = world().await;
    let store = content_store(&w).await;
    let (msg, _) = chat::chat_message_attestation(&w.alice, "bob-fed", BODY, ts(), &store)
        .await
        .expect("build message");

    assert_eq!(msg.attesting_key_id, "alice-fed", "the ACTOR is the sender");
    assert_eq!(
        msg.scrub_key_id, "alice-fed",
        "signed at write by the actor"
    );
    assert!(!msg.scrub_signature_classical.is_empty());
    assert!(
        msg.scrub_signature_pqc
            .as_deref()
            .is_some_and(|p| !p.is_empty()),
        "the FULL hybrid: ML-DSA-65 half present, no fallback"
    );
    assert_eq!(
        msg.cohort_scope,
        ciris_persist::federation::types::cohort_scope::SELF,
        "authored at self and SHARED; authoring it public would publish a private \
         message rather than send it"
    );
    assert_eq!(msg.tier, "local");
    // The wire carries a POINTER, never the text — the content itself never
    // touches the row.
    let wire = serde_json::to_string(&msg.attestation_envelope).unwrap();
    assert!(!wire.contains(BODY), "PLAINTEXT ON THE WIRE: {wire}");
    assert!(
        msg.attestation_envelope.get(chat::FIELD_CONTENT).is_some(),
        "the row must carry the blob pointer",
    );
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
    let stored_widening = w.stored("alice-fed", &widened.attestation_id).await;
    assert_eq!(stored_widening.attestation_type, "supersedes");
    assert_eq!(stored_widening.cohort_scope, "community");
    assert_eq!(stored_widening.attesting_key_id, "alice-fed");
    assert_eq!(stored_widening.scrub_key_id, "alice-fed");
    assert_eq!(
        stored_widening.attestation_envelope["references_attestation_id"],
        serde_json::json!(msg.attestation_id)
    );

    // Read back the way BOB would: by room, off the plane, opened with HIS
    // key — ONE message, the widening; the `self` copy is folded away.
    let seen = chat::messages_in_room(
        &*w.dir,
        &["alice-fed".to_string()],
        &w.room,
        &content_store(&w).await,
        &format!("{}-occ", w.bob.key_id),
    )
    .await
    .expect("read the room");
    assert_eq!(seen.len(), 1, "one message in the room: {seen:?}");
    let m = &seen[0];
    assert_eq!(
        m.body,
        Body::Text(BODY.to_owned()),
        "opened with the far end's copy of the room key"
    );
    assert_eq!(m.author_key_id, "alice-fed", "WHOSE WORDS — the attester");
    assert_eq!(m.attesting_key_id, "alice-fed");
    assert_eq!(
        m.attestation_id, widened.attestation_id,
        "the row on the wire"
    );
    assert_eq!(m.widens.as_deref(), Some(msg.attestation_id.as_str()));
    // No `epoch` on a ChatMessage any more: it meant "the MLS epoch the body
    // was sealed at", and the body seal is gone. Content's epoch is the
    // community DEK's, recorded on the BLOB row — a reader asks the blob,
    // not the pointer, precisely so a rotation cannot leave a stale copy on
    // the row (CIRISEdge#586 §7).
}

/// **The MLS handshake rides the room.** Bob's KeyPackage and Alice's
/// Welcome are ordinary community-scoped rows each of them signs; read back
/// through the room, the far end joins and both hold the same key.
#[tokio::test]
async fn the_mls_handshake_rides_the_room_as_signed_rows() {
    let w = world().await;
    let room = w.room.clone();

    // Bob (the joiner) mints and shares his KeyPackage.
    let (material, kp) = mint_cohort_key_material("bob-fed").unwrap();
    let kp_bytes = key_package_to_bytes(kp).unwrap();
    let kp_row = chat::key_package_attestation(&w.bob, "alice-fed", &kp_bytes, ts())
        .await
        .unwrap();
    assert_eq!(kp_row.attesting_key_id, "bob-fed");
    assert!(kp_row.scrub_signature_pqc.is_some(), "full hybrid");
    w.dir
        .put_attestation(SignedAttestation {
            attestation: kp_row.clone(),
        })
        .await
        .unwrap();
    let placed = share(
        &*w.dir,
        &kp_row,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.bobs_signers(),
    )
    .await
    .unwrap();
    assert!(matches!(placed.shared, Shared::Placed { .. }), "{placed:?}");

    // Alice (the creator) reads it off the room, admits Bob, shares the Welcome.
    let got = chat::key_package_from(&*w.dir, "bob-fed", &room)
        .await
        .unwrap()
        .expect("the KeyPackage row is in the room");
    assert_eq!(got, kp_bytes, "byte-exact through the row");
    let a = CohortGroup::create(store("alice-wire"), &room, "alice-fed", 16)
        .await
        .unwrap();
    let commit = a
        .add_member("bob-fed", key_package_from_bytes(&got).unwrap())
        .await
        .unwrap();
    let welcome = commit.welcome().unwrap().to_vec();
    let w_row = chat::welcome_attestation(&w.alice, "bob-fed", &welcome, commit.epoch(), ts())
        .await
        .unwrap();
    w.dir
        .put_attestation(SignedAttestation {
            attestation: w_row.clone(),
        })
        .await
        .unwrap();
    share(
        &*w.dir,
        &w_row,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();

    // Bob reads the Welcome off the room and joins.
    let (got_welcome, epoch) = chat::welcome_from(&*w.dir, "alice-fed", &room)
        .await
        .unwrap()
        .expect("the Welcome row is in the room");
    assert_eq!(got_welcome, welcome);
    assert_eq!(epoch, commit.epoch());
    let b = CohortGroup::join(store("bob-wire"), &room, material, &got_welcome, 16)
        .await
        .unwrap();

    // Both sides now hold the room's record secret at the same epoch.
    //
    // The old assertion here was "what Alice seals, Bob opens", through the
    // inline body seal. That seal is gone (CIRISEdge#586) — content lives in
    // the group's blob store and its binding is the AAD, exercised by
    // `a_pointer_copied_onto_another_authors_row_does_not_open` with a
    // positive control. What this test still proves, and is the only test
    // that does, is that the HANDSHAKE converges: both ends derived the same
    // group at the same epoch.
    assert_eq!(
        RoomKey::of(&a).await.unwrap().epoch(),
        RoomKey::of(&b).await.unwrap().epoch(),
        "both ends must land on the same MLS epoch",
    );
}

/// **A widening carries the CLAIM's instant** (persist v40.0.0 /
/// CIRISPersist#801) — the guarantee the seal now rests on. The widened row
/// is the only one a peer receives, so if its `asserted_at` were the
/// placement time (v39.0.0's behaviour) a key bound to the claim instant
/// would open the author's own `self` copy and nothing else. The placement's
/// own time is recorded separately, in the signed `widened_at`.
#[tokio::test]
async fn a_widening_carries_the_claims_instant_and_records_its_own() {
    let w = world().await;
    let msg = authored(&w, "when was this said").await;
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
        panic!("{:?}", crossing.shared)
    };
    let prior = w.stored("alice-fed", &msg.attestation_id).await;
    let widening = w.stored("alice-fed", attestation_id).await;

    let claim_at = prior.attestation_envelope["asserted_at"].as_str().unwrap();
    assert_eq!(
        widening.attestation_envelope["asserted_at"].as_str(),
        Some(claim_at),
        "the widening asserts the CLAIM's instant, verbatim"
    );
    assert_eq!(
        widening.asserted_at, prior.asserted_at,
        "and the column agrees"
    );
    let widened_at = widening.attestation_envelope["widened_at"]
        .as_str()
        .expect("the placement records its own signed instant");
    assert!(is_canonical_instant(widened_at), "{widened_at}");
    assert!(
        widened_at >= claim_at,
        "the placement cannot precede the claim: claim={claim_at} widened={widened_at}"
    );

    // Which is exactly what lets the far end open the row it actually gets.
    let seen = chat::messages_in_room(
        &*w.dir,
        &["alice-fed".to_string()],
        &w.room,
        &content_store(&w).await,
        &format!("{}-occ", w.bob.key_id),
    )
    .await
    .unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].body, Body::Text("when was this said".to_owned()));
    assert_eq!(seen[0].widens.as_deref(), Some(msg.attestation_id.as_str()));
}

/// **A forged `on_behalf_of_key_id` projects the ATTESTER, never the claim**
/// (CIRISEdge#564, reported by CIRISServer). The member sits inside the
/// attester's own signed envelope, so the signature proves only that the
/// attester wrote that string. Preferring it let any room member render text
/// under any key — including the reading node's owner.
#[tokio::test]
async fn a_forged_on_behalf_of_claim_projects_the_attester() {
    let w = world().await;
    // Bob emits into the room, claiming to speak for Alice.
    let mut row = {
        let store = content_store(&w).await;
        chat::chat_message_attestation(&w.bob, "alice-fed", "not alice's words", ts(), &store)
            .await
            .unwrap()
            .0
    };
    // A real forger signs the lie: the claim goes INSIDE the envelope and the
    // row is re-signed, so it is byte-consistent and persist admits it.
    // (Mutating after signing is refused by `PromotionMovedThePreimage` —
    // that is the substrate working, not the attack under test.)
    row.attestation_envelope.as_object_mut().unwrap().insert(
        chat::FIELD_ON_BEHALF_OF.to_owned(),
        serde_json::json!("alice-fed"),
    );
    let canonical =
        ciris_persist::prelude::ceg_produce_canonicalize(&row.attestation_envelope).unwrap();
    row.original_content_hash = hex::encode(sha2::Sha256::digest(&canonical));
    let (c, q) = ciris_edge::identity::sign_bound_hybrid(&w.bob, &canonical, "forged claim")
        .await
        .unwrap();
    row.scrub_signature_classical = c;
    row.scrub_signature_pqc = q;

    let m = chat::ChatMessage::from_row(&row, &w.room).expect("a chat row");
    assert_eq!(
        m.author_key_id, "bob-fed",
        "attribution is the ATTESTER — a producer-asserted member cannot outrank the \
         key persist verified the signature against"
    );
    assert_eq!(m.attesting_key_id, "bob-fed");
    assert_eq!(
        m.on_behalf_of_claim.as_deref(),
        Some("alice-fed"),
        "the claim is surfaced, clearly as a claim"
    );

    // And through the reader that CAN corroborate: bob-fed is a `user`, not a
    // node with alice-fed as its owner, so nothing is promoted.
    w.dir
        .put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .unwrap();
    share(
        &*w.dir,
        &row,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.bobs_signers(),
    )
    .await
    .unwrap();
    let seen = chat::messages_in_room(
        &*w.dir,
        &["bob-fed".to_string()],
        &w.room,
        &content_store(&w).await,
        &format!("{}-occ", w.bob.key_id),
    )
    .await
    .unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0].author_key_id, "bob-fed",
        "an unbacked claim promotes nothing"
    );
    assert_eq!(seen[0].on_behalf_of_claim.as_deref(), Some("alice-fed"));
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
    let seen = chat::messages_in_room(
        &*w.dir,
        &["alice-fed".to_string()],
        &other_room,
        &content_store(&w).await,
        &format!("{}-occ", w.bob.key_id),
    )
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
    for d in [
        chat::CHAT_MESSAGE_DIMENSION,
        chat::KEY_PACKAGE_DIMENSION,
        chat::WELCOME_DIMENSION,
    ] {
        assert!(
            d.starts_with(chat::CHAT_ATTESTATION_PREFIX),
            "{d} rides the same grant"
        );
    }
}

/// **The encrypted/clear split is persist's, not ours.**
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
            "{c:?} must emit no holds_bytes"
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
            "{c:?} DOES emit holds_bytes; its property is cohort-filtered visibility"
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
        assert_ne!(scope, cs::FEDERATION);
    }
}

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
        }
    );
    assert_eq!(again.widened, None);

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
    let msg = {
        let store = content_store(&w).await;
        chat::chat_message_attestation(&w.alice, "bob-fed", "x", ts(), &store)
            .await
            .unwrap()
            .0
    };
    let room = w.room_with().audience();

    assert_eq!(
        share_plan(&msg, &room).unwrap(),
        SharePlan::EnterThenWiden(room.clone())
    );
    assert_eq!(
        share_plan(&msg, &Audience::SelfOnly).unwrap(),
        SharePlan::Enter
    );
    let mut in_mesh = msg.clone();
    in_mesh.tier = "federation".to_owned();
    assert_eq!(
        share_plan(&in_mesh, &room).unwrap(),
        SharePlan::Widen(room.clone())
    );
    assert_eq!(
        share_plan(&in_mesh, &Audience::SelfOnly).unwrap(),
        SharePlan::AlreadyThere
    );
    let mut wide = in_mesh.clone();
    wide.cohort_scope = "community".to_owned();
    let err = share_plan(&wide, &Audience::SelfOnly).unwrap_err();
    assert!(err.contains("not strictly wider"), "{err}");

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
    assert!(keep_local(&promoted).is_err());

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
        ("federation", "self")
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
        assert_ne!(w.cohort_scope(), "federation");
        assert_eq!(w.audience().cohort_scope(), w.cohort_scope());
    }
    assert!(!With::Species.is_encrypted_at_rest());
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
        }
    );
    assert_eq!(ci.recipient_receive, direct.recipient_receive);
    assert_eq!(ci.information_type, direct.information_type);
    assert_eq!(ci.transmission_principle, CrossingBasis::ProducerAuthority);
    assert_eq!(ci.temporal_lifecycle, direct.temporal_lifecycle);
    assert_eq!(ci.temporal_lifecycle.asserted_at, msg.asserted_at);
    assert_eq!(
        ci.content, direct.content,
        "the widening REUSES the content hash"
    );
    assert_eq!(ci.sender, direct.sender);
    assert_eq!(ci.data_subject, direct.data_subject);
    assert_ne!(ci.recipient_see, direct.recipient_see);
}

/// **Custody is decided from the row** — edge's copy of persist's table.
#[tokio::test]
async fn custody_is_the_actors_or_it_waits() {
    let w = world().await;
    let signed = {
        let store = content_store(&w).await;
        chat::chat_message_attestation(&w.alice, "bob-fed", "c", ts(), &store)
            .await
            .unwrap()
            .0
    };
    let mut deferred = signed.clone();
    deferred.scrub_signature_classical.clear();
    deferred.scrub_signature_pqc = None;
    deferred.original_content_hash.clear();

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
    let custody = custody_for(&deferred, w.signers()).await.unwrap().unwrap();
    let TierPromotionCustody::ActorSigned(reseal) = custody else {
        panic!("{custody:?}")
    };
    assert_eq!(reseal.scrub_key_id, "alice-fed");
    assert_eq!(reseal.original_content_hash, signed.original_content_hash);
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
/// actor signed still ENTERS the mesh (co-scrubbed) but the widening waits.
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
    assert!(matches!(crossing.entered, MeshCrossingOutcome::Crossed(_)));
    assert!(matches!(
        crossing.widened,
        Some(MeshCrossingOutcome::AwaitingActor { .. })
    ));
    assert!(
        matches!(crossing.shared, Shared::AwaitingActor { ref attestation_id, .. } if *attestation_id == msg.attestation_id)
    );
    let original = w.stored("alice-fed", &msg.attestation_id).await;
    assert_eq!(
        (original.tier.as_str(), original.cohort_scope.as_str()),
        ("federation", "self")
    );
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

/// **Every instant edge signs is CC 2.6.2 canonical.**
#[tokio::test]
async fn signed_instants_are_canonical() {
    let w = world().await;
    let msg = authored(&w, "when").await;
    let at = msg.attestation_envelope["asserted_at"].as_str().unwrap();
    assert!(is_canonical_instant(at), "{at}");
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
    let parsed: chrono::DateTime<chrono::Utc> =
        chrono::DateTime::parse_from_rfc3339(at).unwrap().into();
    assert_eq!(parsed, wide.asserted_at);
}

/// **Both members of a pair room are moderators, by construction.**
#[tokio::test]
async fn both_members_of_the_pair_room_are_moderators() {
    let w = world().await;
    let room = chat::pair_community("alice-fed", "bob-fed", ts());
    assert!(room
        .members
        .iter()
        .all(|m| m.role.as_deref() == Some("founder")));
    let mods = ciris_persist::federation::admission::moderators_of(&*w.dir, &w.room, "moderate")
        .await
        .expect("moderators_of");
    for who in ["alice-fed", "bob-fed"] {
        assert!(mods.iter().any(|m| m == who), "{who} moderates: {mods:?}");
    }
}

/// **No classical-only signature, anywhere.** A signer without its ML-DSA-65
/// half is refused at the source, naming what was being signed.
#[tokio::test]
async fn a_classical_only_signer_is_refused_not_downgraded() {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[9u8; 32], "half").unwrap());
    let half = ciris_edge::identity::LocalSigner::new("half", classical, None);
    let err = ciris_edge::identity::sign_bound_hybrid(&half, b"bytes", "a row")
        .await
        .unwrap_err();
    assert!(err.contains("no fallback"), "{err}");
    // …and through the chat writer, where the refusal must come from the
    // SIGNING step.
    //
    // The signer has to be alice's identity minus its PQC half, not a
    // stranger's: content is sealed BEFORE the row is signed, and the seal
    // resolves the room as a real community. A stranger's key derives a
    // room that does not exist, so the call would fail at the community
    // lookup and never reach the signature check — passing while proving
    // nothing about classical-only signing.
    let w = world().await;
    let store = content_store(&w).await;
    let alice_classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[1u8; 32], "alice-fed").unwrap());
    let alice_half = ciris_edge::identity::LocalSigner::new("alice-fed", alice_classical, None);
    let err = chat::chat_message_attestation(&alice_half, "bob-fed", "x", ts(), &store)
        .await
        .unwrap_err();
    assert!(
        err.contains("ML-DSA-65"),
        "the refusal must name the missing PQC half, not a missing room: {err}",
    );
}

// ─── CIRISEdge#586: content in the group store, end to end ────────────

/// A `GroupContentStore` over the SAME substrate this world already uses,
/// so a row written through the blob door and the row plane that carries it
/// are looking at one database — which is what makes this the delivery
/// model rather than two halves that happen to agree.
async fn content_store(w: &World) -> ciris_edge::group_content::PersistGroupContentStore {
    use ciris_persist::federation::FederationDirectory as _;

    let signer: std::sync::Arc<dyn ciris_keyring::HardwareSigner> = w.alice_node.classical.clone();

    // The seal emits a `holds_bytes` attestation, whose FK is onto the key
    // persist DERIVES for this signer — `derive_key_id(alias, pubkey)` — not
    // onto the friendly name the world registers it under. In production
    // those are the same value because the derived id IS how a key id is
    // minted; in this world they are not, so the derived one is registered
    // here. Computing it the way persist does rather than assuming the
    // friendly name works is the difference between this passing and an
    // opaque "FOREIGN KEY constraint failed" from inside the door.
    let pubkey = signer.public_key().await.expect("pubkey");
    let derived = ciris_verify_core::fedcode::derive_key_id(signer.current_alias(), &pubkey);
    let pqc_b64 = {
        b64(&w
            .alice_node
            .pqc
            .as_ref()
            .expect("node pqc")
            .public_key()
            .await
            .expect("pqc pubkey"))
    };
    let envelope = serde_json::json!({ "key_id": derived });
    let canonical = serde_json::to_vec(&envelope).expect("serialize");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
    let sig = signer.sign(digest.as_slice()).await.expect("self-sign");
    w.dir
        .put_public_key(ciris_persist::prelude::SignedKeyRecord {
            record: ciris_persist::prelude::KeyRecord {
                key_id: derived.clone(),
                pubkey_ed25519_base64: b64(&pubkey),
                pubkey_ml_dsa_65_base64: Some(pqc_b64),
                algorithm: "hybrid".to_string(),
                identity_type: "node".to_string(),
                identity_ref: derived.clone(),
                valid_from: ts(),
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(digest),
                scrub_signature_classical: b64(&sig),
                scrub_signature_pqc: None,
                scrub_key_id: derived,
                scrub_timestamp: ts(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the engine's derived signing key");

    // The DEK cascade wraps the content key to every ACTIVE OCCURRENCE of
    // every roster member — `resolve_community_members` →
    // `list_identity_occurrences_active` → `encryption_pubkeys`. A room whose
    // members have no occurrence resolves to nobody, and the seal then
    // grants to nobody: readable by no one, including its author. That is
    // what `SealedContent::readable_by_nobody` names, and it is why the
    // roster machinery is the membership machinery rather than a lookup.
    for (member, signer_for) in [
        (w.alice.key_id.clone(), &w.alice),
        (w.bob.key_id.clone(), &w.bob),
    ] {
        put_kex_occurrence(&w.dir, &member, signer_for).await;
    }

    ciris_edge::group_content::PersistGroupContentStore::from_shared(
        ciris_persist::BackendDispatch::Sqlite(w.dir.clone()),
        w.dir.clone(),
        signer,
    )
}

/// Give `identity` a content-tier KEX occurrence with real hybrid KEM
/// pubkeys, through the trusted-local door.
///
/// `put_identity_occurrence_local` is the right door here and not a
/// shortcut: persist documents it for exactly this shape — a content-only
/// DEK-cascade KEX target, locally produced, never peer-received — so it
/// bypasses the signature gate that exists to stop a peer forging someone
/// else's content keys.
async fn put_kex_occurrence(
    dir: &Arc<SqliteBackend>,
    identity: &str,
    signer_for: &ciris_edge::identity::LocalSigner,
) {
    use ciris_persist::federation::FederationDirectory as _;

    // The occurrence's OWN key_id is an FK onto `federation_keys` — an
    // occurrence is a key that acts for an identity, not a bare label — so
    // it is registered before it can be pointed at.
    let occurrence = format!("{identity}-occ");
    dir.put_public_key(SignedKeyRecord {
        record: record(&occurrence, signer_for, signer_for, "node").await,
    })
    .await
    .expect("register the occurrence key");

    let (_, x_pub) = ciris_crypto::x25519::generate_ephemeral_keypair().expect("x25519");
    let (_, kem_pub) = ciris_crypto::ml_kem::generate_keypair().expect("ml-kem-768");

    dir.put_identity_occurrence_local(ciris_persist::federation::types::IdentityOccurrence {
        identity_key_id: identity.to_owned(),
        occurrence_key_id: occurrence,
        device_class: "server".to_owned(),
        hardware_attestation: None,
        asserted_at: ts(),
        valid_until: None,
        encryption_pubkeys: Some(ciris_persist::federation::types::EncryptionPubkeys {
            x25519_base64: b64(&x_pub),
            ml_kem_768_base64: b64(&kem_pub),
        }),
        // Content-only: no reticulum transport, which is precisely the shape
        // the trusted-local door is documented for.
        transport_binding: None,
        persist_row_hash: String::new(),
    })
    .await
    .expect("register a KEX occurrence");
}

/// **The delivery model, proven at the chat layer.**
///
/// Alice writes a message whose content goes to the room's blob store; the
/// row carries only a pointer. A reader recognises the row WITHOUT a room
/// key — there is none, which is what the migration accomplishes — and
/// opens the content by rebuilding the binding from the row's own attester
/// and instant.
#[tokio::test]
async fn a_chat_message_stores_its_content_as_a_group_blob_and_reads_back() {
    use ciris_edge::chat::{Body, ChatMessage};

    let w = world().await;
    let store = content_store(&w).await;
    let text = "the delivery model, proven";

    let (row, sealed) =
        ciris_edge::chat::chat_message_attestation(&w.alice, "bob-fed", text, ts(), &store)
            .await
            .expect("author a blob-backed chat message");

    // The row carries a pointer and NO inline body.
    let env = &row.attestation_envelope;
    assert!(
        env.get(ciris_edge::chat::FIELD_CONTENT).is_some(),
        "the row must carry the content pointer",
    );
    // There is no inline shape left to carry: the seal was deleted, not
    // deprecated (CIRISEdge#586). The pointer is the only content member.
    assert!(
        env.get("body").is_none() && env.get("sealed").is_none(),
        "a chat row carries a pointer and nothing that could open without one",
    );

    // Who can read it is reported, not left to be discovered later.
    assert!(
        sealed.fully_readable(),
        "a member was excluded at write and could never read this: {:?}",
        sealed.excluded,
    );

    // Read it back with NO room key.
    let mut msg = ChatMessage::from_row(&row, &w.room).expect("recognise the chat row");
    assert!(
        matches!(msg.body, Body::Pointer(_)),
        "recognition must not need the store: {:?}",
        msg.body,
    );

    // The reader's OCCURRENCE key — grants are wrapped per occurrence, so
    // the identity key would be refused as NotGranted despite full
    // membership.
    msg.resolve_content(&store, &format!("{}-occ", w.alice.key_id))
        .await;
    assert_eq!(
        msg.body,
        Body::Text(text.to_owned()),
        "content must open from the row's own author and instant alone",
    );
}

/// The substitution the AAD exists to prevent, at the chat layer: the same
/// pointer on a row attributed to a DIFFERENT author does not open.
///
/// This is the property that let chat retire its own seal. Without it, every
/// member of the room holds the DEK and could re-attribute anyone's message
/// to themselves simply by copying the pointer.
#[tokio::test]
async fn a_pointer_copied_onto_another_authors_row_does_not_open() {
    use ciris_edge::chat::{Body, ChatMessage};

    let w = world().await;
    let store = content_store(&w).await;

    let (alice_row, _) = ciris_edge::chat::chat_message_attestation(
        &w.alice,
        "bob-fed",
        "alice's words",
        ts(),
        &store,
    )
    .await
    .expect("alice authors");

    // Bob copies Alice's pointer onto a row he attests himself, at the same
    // instant — every other input identical, so the AUTHOR is the only
    // difference and the test cannot pass for another reason.
    let pointer = alice_row
        .attestation_envelope
        .get(ciris_edge::chat::FIELD_CONTENT)
        .expect("pointer")
        .clone();
    let mut stolen = alice_row.clone();
    stolen.attestation_id = "att-bob-stolen".to_owned();
    stolen.attesting_key_id = w.bob.key_id.clone();
    stolen.attestation_envelope = {
        let mut e = alice_row.attestation_envelope.clone();
        e.as_object_mut()
            .expect("object")
            .insert(ciris_edge::chat::FIELD_CONTENT.to_owned(), pointer);
        e
    };

    let mut msg = ChatMessage::from_row(&stolen, &w.room).expect("recognise the stolen row");
    msg.resolve_content(&store, &format!("{}-occ", w.bob.key_id))
        .await;

    match msg.body {
        Body::Unopened { reason } => assert!(
            // Name the ARM, not merely that a reason exists. `NotGranted`
            // here would mean the grant failed rather than the binding —
            // green for the wrong reason, and indistinguishable without
            // this.
            reason.contains("rebuilt AAD") || reason.contains("seal did not open"),
            "the refusal must be the SEAL failing to open, not a grant or \
             lookup problem — got: {reason}",
        ),
        other => panic!("a pointer on another author's row MUST NOT open — got {other:?}"),
    }
}
