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
//! encrypted, so the body on the wire is a pointer to a blob under persist's
//! community DEK, wrapped per member occurrence. The MLS handshake still
//! rides the room as ordinary rows — not to key the body (the pre-v24
//! `RoomKey` is deleted, CIRISEdge#604) but because the room's group is its
//! CC 5.4 addressing root, and both ends must come to stand on it.

use ciris_edge::chat::{self, Body, PairRole};
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
        &me_of(&w).await,
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
/// through the room, the far end joins and both stand on the same group at
/// the same epoch — the room's CC 5.4 addressing root (CIRISEdge#604).
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

    // Both sides now stand on the same group at the same epoch — the CC 5.4 root.
    //
    // The old assertion here was "what Alice seals, Bob opens", through the
    // inline body seal. That seal is gone (CIRISEdge#586) — content lives in
    // the group's blob store and its binding is the AAD, exercised by
    // `a_pointer_copied_onto_another_authors_row_does_not_open` with a
    // positive control. What this test still proves, and is the only test
    // that does, is that the HANDSHAKE converges: both ends derived the same
    // group at the same epoch.
    assert_eq!(
        a.epoch().await,
        b.epoch().await,
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
        &me_of(&w).await,
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
        &me_of(&w).await,
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
        &me_of(&w).await,
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
    content_store_maybe_provisioned(w, true).await
}

/// [`content_store`] with provisioning made OPTIONAL, so one test can be the
/// stock node — the state CIRISEdge#599 was measured in.
async fn content_store_maybe_provisioned(
    w: &World,
    provision: bool,
) -> ciris_edge::group_content::PersistGroupContentStore {
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
    let derived_for_binding = derived.clone();
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

    // The OWNER BINDING — alice the PERSON binds alice's NODE.
    //
    // persist v44.4.0 §20.2: a node publishes its own occurrence through the
    // GATED door, and `check_signer_acts_for` lifts a node key to an identity
    // only through a live owner-signed binding. Here the two are visibly
    // different keys (`alice-fed` the roster member, `alice-node-<fp>` the
    // engine), which is the production shape — a roster names persons and the
    // key on the wire is a node — so without this the engine cannot publish,
    // and before v44.4.0 nothing asked because the row went through the
    // trusted-local door and never reached the plane at all.
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        &w.alice.key_id,
        &derived_for_binding,
        ts(),
        &w.alice,
    )
    .await
    .expect("build alice's owner binding for her node");
    w.dir
        .put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: binding,
        })
        .await
        .expect("admit alice's owner binding");

    // The DEK cascade wraps the content key to every ACTIVE OCCURRENCE of
    // every roster member — `resolve_community_members` →
    // `list_identity_occurrences_active` → `encryption_pubkeys`. A room whose
    // members have no occurrence resolves to nobody, and the seal then
    // grants to nobody: readable by no one, including its author. That is
    // what `SealedContent::readable_by_nobody` names, and it is why the
    // roster machinery is the membership machinery rather than a lookup.
    // The seeds are the ones `signer()` built these identities from — the
    // content keypair derives from the SAME seed as the signing key, which
    // is the whole point of `SelfEncKeys`: no second key to provision, keep
    // coherent, or lose.
    if provision {
        for (member, signer_for, seed) in [
            (w.alice.key_id.clone(), &w.alice, 1u8),
            (w.bob.key_id.clone(), &w.bob, 3u8),
        ] {
            put_kex_occurrence(&w.dir, &member, signer_for, &[seed; 32]).await;
        }
    }

    // CIRISPersist#848 — the store must be HYBRID: every encrypted write now
    // emits the key_grant set as a federated attestation, and a
    // classical-only engine gets `AttestationEmissionFailed` at the first
    // community seal. `signer` (the classical half) is still what the
    // directory registered above.
    let _ = signer;
    let store = ciris_edge::group_content::PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(w.dir.clone()),
        w.dir.clone(),
        &w.alice_node,
    )
    .await
    .expect("hybrid content store");
    if provision {
        // The NODE-class occurrence (CIRISPersist#848): the engine's derived
        // key as an occurrence of alice, with the content-KEM identity's
        // pubkeys — the pair `read_blob_as` unwraps with, and what makes this
        // engine an admissible key_grant emitter for the room.
        let (_, outcome) = ciris_edge::content_occurrence::provision_engine_occurrence(
            store.engine(),
            &*w.dir,
            &w.alice.key_id,
            "server",
        )
        .await
        .expect("provision the engine's own occurrence");
        // `Created` on the first store over this world, `AlreadyCurrent` on
        // a second; `Drifted` would mean the engine's content-KEM identity
        // no longer matches its own occurrence — every read then NotGranted.
        assert_ne!(
            outcome,
            ciris_edge::content_occurrence::Provisioned::Drifted,
            "the engine's occurrence must carry its own content-KEM pubkeys",
        );
    }
    store
}

/// The viewer key for reads on THIS world's node: the engine's derived
/// signing key, i.e. its own occurrence (CIRISPersist#848). Bob has no
/// engine in this single-directory world; a reader that opens across nodes
/// is witnessed in `blob_federation_e2e` on two substrates, which is the
/// honest home for that claim (CIRISEdge#601 gap 3).
async fn me(store: &ciris_edge::group_content::PersistGroupContentStore) -> String {
    store
        .engine()
        .local_derived_key_id()
        .await
        .expect("derived key id")
}

/// [`me`] without a store in hand: the derived id is a function of the
/// SIGNER alone, so any engine over `alice_node` yields the same one.
async fn me_of(w: &World) -> String {
    let store = content_store(w).await;
    me(&store).await
}

#[allow(dead_code)]
async fn me_unused(store: &ciris_edge::group_content::PersistGroupContentStore) -> String {
    store
        .engine()
        .local_derived_key_id()
        .await
        .expect("derived key id")
}

/// Give `identity` a content-tier KEX occurrence — **through the same door
/// production uses**.
///
/// # CIRISEdge#599 — why this goes through `content_occurrence`
///
/// This fixture used to register the occurrence itself and mint the content
/// keypair with `generate_ephemeral_keypair` / `ml_kem::generate_keypair`.
/// It worked, and that was the problem: nothing in production performed the
/// equivalent, so the suite proved the feature works **given a precondition
/// nothing met**, and a stock node sealed community content with
/// `granted: []` — readable by nobody, including its author.
///
/// Routing the fixture through `content_occurrence::ensure_content_occurrence`
/// with `enc_pubkeys_from_seed` means every content test in this file now
/// exercises the production provisioning path and the production derivation.
/// A regression there reddens the whole suite instead of nothing.
///
/// The occurrence key stays DISTINCT from the identity key — a device acting
/// for a person, which is the shape the grants are wrapped for — and is
/// registered first because the column is an FK onto `federation_keys`.
// Bob's occurrence here is deliberately DEVICE-class (seed-derived): this
// single-directory world has no bob engine, so it is a second wrap target
// the cascade enumerates — which is what keeps `granted`/`excluded`
// non-trivial — and one no node in this world can open. Cross-node opens are
// witnessed in `blob_federation_e2e` on two substrates (CIRISEdge#601 gap 3).
#[allow(deprecated)]
async fn put_kex_occurrence(
    dir: &Arc<SqliteBackend>,
    identity: &str,
    signer_for: &ciris_edge::identity::LocalSigner,
    seed: &[u8; 32],
) {
    use ciris_persist::federation::FederationDirectory as _;

    let occurrence = format!("{identity}-occ");
    dir.put_public_key(SignedKeyRecord {
        record: record(&occurrence, signer_for, signer_for, "node").await,
    })
    .await
    .expect("register the occurrence key");

    // The SAME derivation `SelfEncKeys::enc_pubkeys` performs inside custody,
    // over the same input — deterministic, so this fixture's keys are the
    // keys a real node with this seed would present.
    let enc = ciris_edge::content_occurrence::enc_pubkeys_from_seed(seed)
        .expect("derive content-enc pubkeys");
    let outcome = ciris_edge::content_occurrence::ensure_content_occurrence(
        &**dir,
        identity,
        &occurrence,
        "server",
        enc,
    )
    .await
    .expect("provision the content occurrence");
    // `Created` on the first store, `AlreadyCurrent` on a second one built
    // over the same world — both fine, and the idempotence is the point.
    //
    // `Drifted` is the arm that matters: it would mean the derivation stopped
    // being deterministic from the seed, which on a real node silently
    // orphans every grant already wrapped to the old keys.
    assert_ne!(
        outcome,
        ciris_edge::content_occurrence::Provisioned::Drifted,
        "{identity}: the content keypair is no longer deterministic from its seed",
    );
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
    msg.resolve_content(&store, &me(&store).await).await;
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
    msg.resolve_content(&store, &me(&store).await).await;

    match msg.body {
        // Name the ARM, not merely that a reason exists. `NotGranted` here
        // would mean the grant failed rather than the binding — green for the
        // wrong reason. Since CIRISEdge#601 the arm IS the type: this used to
        // string-match persist's prose for "rebuilt AAD" / "seal did not
        // open", and a reworded message would have turned it green for
        // nothing.
        Body::Unopened {
            reason: ciris_edge::chat::UnopenedReason::SealMismatch { .. },
        } => {}
        Body::Unopened { reason } => panic!(
            "the refusal must be the SEAL failing to open, not a grant or lookup \
             problem — got {} ({reason})",
            reason.kind()
        ),
        other => panic!("a pointer on another author's row MUST NOT open — got {other:?}"),
    }
}

/// **CIRISEdge#599 — a write nobody can read is refused, loudly, at the door.**
///
/// The stock-node state: the room exists, the roster is right, the signers
/// are real, and no member has a content occurrence. The DEK cascade then
/// enumerates no wrap targets and seals with `granted: []`.
///
/// Every layer below reports success — the blob is written, the row would be
/// valid, the pointer would resolve — and the only symptom is
/// `Body::Unopened` on the author's own screen, forever. That is what
/// CIRISServer measured, and what 31 of their 33 chat tests stayed green
/// through.
///
/// So it fails HERE, while the caller still holds the plaintext, and the
/// message names the remedy rather than the symptom.
#[tokio::test]
async fn a_message_no_key_could_open_is_refused_before_it_is_sent() {
    let w = world().await;
    let store = content_store_maybe_provisioned(&w, false).await;

    let err = ciris_edge::chat::chat_message_attestation(
        &w.alice,
        "bob-fed",
        "words nobody could read",
        ts(),
        &store,
    )
    .await
    .expect_err("a message sealed to nobody must not be reported as sent");

    // Name the REASON, not merely that it failed — a seal error and a
    // grant-to-nobody are different findings with different remedies, and a
    // test that accepts any error would pass on the wrong one.
    assert!(
        err.contains("NO grants") && err.contains("OCCURRENCE"),
        "the refusal must say the content was granted to nobody and why — got: {err}",
    );
    assert!(
        err.contains("599"),
        "and point at the provisioning it needs — got: {err}",
    );
}

/// The positive control for the test above, and the proof that provisioning
/// is what makes the difference: the SAME world, the SAME message, with the
/// occurrences registered.
///
/// Without this, the refusal test would pass on a world where chat was
/// broken for some unrelated reason.
#[tokio::test]
async fn the_same_message_sends_once_the_occurrences_are_provisioned() {
    let w = world().await;
    let store = content_store_maybe_provisioned(&w, true).await;

    let (_row, sealed) = ciris_edge::chat::chat_message_attestation(
        &w.alice,
        "bob-fed",
        "words nobody could read",
        ts(),
        &store,
    )
    .await
    .expect("provisioned, so the cascade has wrap targets");

    assert!(
        !sealed.readable_by_nobody(),
        "the state the door refuses must be the state provisioning removes",
    );
    assert!(
        !sealed.granted.is_empty(),
        "and the grant set must be non-empty: {sealed:?}",
    );
}

// ─── CIRISEdge#608 — N-member rooms ──────────────────────────────────────

/// **The pair record is byte-identical over the general builder.**
///
/// Every pair room on the mesh is a DERIVED id whose far end re-derives the
/// same bytes independently; a changed byte in `pair_community` is a
/// `CommunityRosterFork` on every one of them. So the record the general
/// builder now produces for a pair is pinned against the shape the pair
/// builder produced before the general one existed — hand-built here, the
/// way it was written then.
#[test]
fn the_pair_room_is_byte_identical_over_the_general_builder() {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::{consensus_protocol, Community, CommunityMember};

    let (a, b) = ("zed-fed", "amy-fed"); // deliberately unsorted input
    let mut members = [a, b];
    members.sort_unstable();
    let before = Community {
        community_key_id: chat::pair_community_key_id(a, b),
        community_name: format!("{} <-> {}", members[0], members[1]),
        members: members
            .iter()
            .map(|k| CommunityMember {
                key_id: (*k).to_owned(),
                joined_at: ts(),
                role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
            })
            .collect(),
        founded_at: ts(),
        consensus_protocol: consensus_protocol::UNANIMOUS.to_owned(),
        policy_blob: None,
        persist_row_hash: String::new(),
    };
    let after = chat::pair_community(a, b, ts());
    assert_eq!(after, before, "the typed record must not have moved");
    let canon = |c: &Community| {
        ciris_persist::prelude::ceg_produce_canonicalize(&c.signing_envelope()).unwrap()
    };
    assert_eq!(
        canon(&after),
        canon(&before),
        "the SIGNED bytes must not have moved — this is what the far end re-derives",
    );
    // And the general builder refuses what the pair shape rules out.
    assert!(
        chat::community(
            "chat:room:v1:x",
            "no founder",
            &[("a", None)],
            "founder_only",
            ts()
        )
        .is_err(),
        "a roster with no founder has no authority root (CC 4.5.4)",
    );
    assert!(chat::community("chat:room:v1:x", "empty", &[], "founder_only", ts()).is_err(),);
    assert!(chat::community(
        "chat:room:v1:x",
        "dup",
        &[("a", Some(MEMBER_ROLE_FOUNDER)), ("a", None)],
        "founder_only",
        ts()
    )
    .is_err());
    assert!(chat::new_room_community_key_id().starts_with(chat::ROOM_COMMUNITY_PREFIX));
    assert_ne!(
        chat::new_room_community_key_id(),
        chat::new_room_community_key_id(),
        "an allocated id is fresh each time",
    );
}

/// One member's node in the three-node witness: its own substrate, its own
/// hybrid engine, its own PUBLISHED, owner-bound engine occurrence. Nothing
/// is shared with any other peer except what the test carries over.
struct Peer {
    dir: Arc<SqliteBackend>,
    store: ciris_edge::group_content::PersistGroupContentStore,
    /// The engine's derived key — this node's occurrence of its human, and
    /// the viewer key for every read here.
    me: String,
}

/// The same order `node()` in `blob_federation_e2e` uses, because the order
/// is load-bearing: register the derived key → owner binding → hybrid store
/// → publish the occurrence (the gated door checks the signer against the
/// identity's ACTIVE occurrences and its live owner binding).
async fn peer(humans: &[&ciris_edge::identity::LocalSigner], mine: (&str, u8)) -> Peer {
    let (human_id, seed) = mine;
    let dir = FederationDirectorySqlite::open(":memory:").await.unwrap();
    dir.run_migrations().await.unwrap();
    for h in humans {
        dir.put_public_key(SignedKeyRecord {
            record: record(&h.key_id, h, h, "user").await,
        })
        .await
        .expect("register a human");
    }
    let human = signer(human_id, seed);
    let ed_pub = human.classical.public_key().await.unwrap();
    let derived = ciris_verify_core::fedcode::derive_key_id(human_id, &ed_pub);
    let mut rec = record(&derived, &human, &human, "node").await;
    rec.identity_ref = derived.clone();
    dir.put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("register the engine's derived key");

    let identity = ciris_edge::identity::LocalSigner::new(
        derived.clone(),
        human.classical.clone(),
        human.pqc.clone(),
    );
    let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
        human_id,
        &derived,
        ts(),
        &human,
    )
    .await
    .expect("build the owner binding");
    dir.put_attestation_authored(SignedAttestation {
        attestation: binding,
    })
    .await
    .expect("admit the owner binding");

    let store = ciris_edge::group_content::PersistGroupContentStore::from_shared_hybrid(
        ciris_persist::BackendDispatch::Sqlite(dir.clone()),
        dir.clone(),
        &identity,
    )
    .await
    .expect("hybrid content store");
    let (me, _) = ciris_edge::content_occurrence::provision_engine_occurrence(
        store.engine(),
        &*dir,
        human_id,
        "server",
    )
    .await
    .expect("publish this node's engine occurrence");
    Peer { dir, store, me }
}

/// What the IdentityOccurrence / Attestation planes carry on a mesh, by
/// hand: `from`'s derived key, its owner binding, its published occurrence.
async fn carry_identity(from: &Peer, to: &Peer) {
    let rec = FederationDirectory::lookup_public_key(&*from.dir, &from.me)
        .await
        .unwrap()
        .expect("the engine registered its derived key");
    to.dir
        .put_public_key(SignedKeyRecord { record: rec })
        .await
        .expect("carry the derived key");
    for row in from.dir.list_attestations_since(None, 256).await.unwrap() {
        let att = row.attestation;
        if att.attested_key_id == from.me
            && ciris_persist::federation::admission::is_owner_binding_envelope(
                &att.attestation_envelope,
            )
        {
            to.dir
                .apply_replicated_attestation(SignedAttestation { attestation: att })
                .await
                .expect("carry the owner binding");
        }
    }
    let occ = from
        .dir
        .list_signed_identity_occurrences_since(None, 64)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.occurrence)
        .find(|o| o.identity_occurrence.occurrence_key_id == from.me)
        .expect("the occurrence is ON the signed plane (CIRISPersist#851)");
    to.dir
        .put_identity_occurrence(occ)
        .await
        .expect("admit the occurrence through the gated door");
}

/// What the Attestation cursor carries after a seal: every `key_grant:*`
/// row `from` emitted, admitted through `to`'s key-grant door.
async fn carry_key_grants(from: &Peer, to: &Peer) -> usize {
    use ciris_persist::federation::key_grant::{
        SignedKeyGrantSet, KEY_GRANT_ATTESTATION_TYPE_PREFIX,
    };
    let mut wraps = 0;
    for row in from.dir.list_attestations_since(None, 512).await.unwrap() {
        if row
            .attestation
            .attestation_type
            .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        {
            wraps += to
                .store
                .engine()
                .apply_replicated_key_grant(SignedKeyGrantSet {
                    attestation: row.attestation,
                })
                .await
                .expect("admit the key_grant set")
                .wraps_written;
        }
    }
    wraps
}

/// What a blob pull carries (CIRISEdge#601 is the hook; this is the hand
/// version the far-node test uses): the sealed envelope, served from
/// `from`'s disk and adopted on `to` at the author's declared binding.
async fn carry_bytes(
    from: &Peer,
    to: &Peer,
    room: &str,
    author: &str,
    sealed: &ciris_edge::group_content::SealedContent,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), ciris_persist::federation::BlobError> {
    use ciris_persist::federation::blobs::BlobBody;
    use ciris_persist::federation::{AdoptDisposition, BlobProvenance};
    let sha: [u8; 32] = hex::decode(&sealed.pointer.content_sha256)
        .unwrap()
        .try_into()
        .unwrap();
    let served = from
        .store
        .engine()
        .serve_blob_to_peer(&sha, &to.me)
        .await
        .expect("serve the sealed envelope");
    let BlobBody::Inline(envelope) = served else {
        panic!("a whole-blob seal is served inline");
    };
    let aad = ciris_edge::group_content::aad_for_open(&ciris_edge::group_content::OpenRequest {
        pointer: &sealed.pointer,
        author_key_id: author,
        asserted_at: at,
        viewer_key_id: &to.me,
    });
    to.store
        .engine()
        .adopt_sealed_blob(
            &envelope,
            BlobProvenance {
                // The MINTER is the author's engine (derived id), not the
                // friendly identity — memory trap 6.
                author_key_id: from.me.clone(),
                cohort_scope: "community".to_owned(),
                community_key_id: Some(room.to_owned()),
                epoch: sealed.epoch,
                tier: sealed.tier,
            },
            Some(&aad),
            AdoptDisposition::LocalOnly,
        )
        .await
        .map(|_| ())
}

/// Read a message the way a consumer does — `ChatMessage::resolve_content`
/// as `viewer` — and return what it became.
async fn read_as(
    peer: &Peer,
    row: &ciris_persist::federation::Attestation,
    room: &str,
    viewer: &str,
) -> Body {
    let mut msg = chat::ChatMessage::from_row(row, room).expect("a chat row for this room");
    msg.resolve_content(&peer.store, viewer).await;
    msg.body
}

/// **Three members, one node each; a fourth who is not on the roster; and a
/// removal that rotates the key.**
///
/// The roster is created ONCE with all three on it (that record replicates
/// cleanly — a later widening does not, see `community_roster`), the
/// crossings are the planes' shapes carried by hand, and the assertions are
/// the issue's: every member's body opens for every member; none for a
/// non-member; after one revocation the removed member reads `Unopened` for
/// every LATER message and still opens the EARLIER one — forward secrecy on
/// this axis is rotation, not recall (CC 4.5.12.1 Option A).
///
/// Mutation: skip the revocation and the "carol reads `Unopened` for the
/// later message" assertion fails — carol's occurrence is still on the
/// active roster, so alice's cascade wraps to it.
#[tokio::test]
#[allow(clippy::too_many_lines)] // three nodes, two messages, one revocation — in one place on purpose
async fn a_three_member_room_opens_for_every_member_and_rotates_on_removal() {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::consensus_protocol;

    let alice = signer("alice-fed", 1);
    let bob = signer("bob-fed", 3);
    let carol = signer("carol-fed", 5);
    let humans = [&alice, &bob, &carol];
    let a = peer(&humans, ("alice-fed", 1)).await;
    let b = peer(&humans, ("bob-fed", 3)).await;
    let c = peer(&humans, ("carol-fed", 5)).await;

    // ── The room, created once with its full roster, on every node ──
    let room = chat::new_room_community_key_id();
    let roster = chat::community(
        &room,
        "the trio",
        &[
            ("alice-fed", Some(MEMBER_ROLE_FOUNDER)),
            ("bob-fed", None),
            ("carol-fed", None),
        ],
        consensus_protocol::FOUNDER_ONLY,
        ts(),
    )
    .expect("alice is the founder");
    let signed_room = chat::signed_community(roster, &alice).await.expect("sign");
    for p in [&a, &b, &c] {
        p.dir
            .put_community(signed_room.clone())
            .await
            .expect("every node admits the same record");
        // persist's revocation table FKs the community id onto
        // `federation_keys` (see `community_roster`); persist's own fixtures
        // satisfy it by registering the community id as a key, and so does
        // this one. Throwaway material — nothing signs AS the room.
        p.dir
            .put_public_key(SignedKeyRecord {
                record: record(&room, &signer(&room, 9), &signer(&room, 9), "user").await,
            })
            .await
            .expect("register the room id as a key (persist fixture convention)");
    }
    // ── The planes: everyone knows everyone's engine ──
    for (from, to) in [(&a, &b), (&a, &c), (&b, &a), (&b, &c), (&c, &a), (&c, &b)] {
        carry_identity(from, to).await;
    }

    // ── Message 1: alice → the room ──
    let t1 = ts();
    let (row1, sealed1) = chat::chat_message_attestation_in(&alice, &room, "one", t1, &a.store)
        .await
        .expect("alice sends into the room by its id");
    assert!(
        sealed1.granted.contains(&b.me) && sealed1.granted.contains(&c.me),
        "the cascade wraps to every member's engine: {:?}",
        sealed1.granted,
    );
    for to in [&b, &c] {
        carry_key_grants(&a, to).await;
        carry_bytes(&a, to, &room, "alice-fed", &sealed1, t1)
            .await
            .expect("a member's node adopts the bytes");
    }
    for (p, who) in [(&a, "alice"), (&b, "bob"), (&c, "carol")] {
        assert_eq!(
            read_as(p, &row1, &room, &p.me).await,
            Body::Text("one".to_owned()),
            "{who} opens message 1",
        );
    }
    // A non-member: holds the row, the set and the bytes, has no wrap.
    assert!(
        matches!(
            read_as(&b, &row1, &room, "dave-fed-occ").await,
            Body::Unopened { .. }
        ),
        "a viewer nobody enumerated stays outside the boundary",
    );

    // ── The removal: alice (founder) revokes carol, on alice's node ──
    ciris_edge::community_roster::revoke_community_member(
        &*a.dir,
        &room,
        "carol-fed",
        chrono::Utc::now(),
        Some("asked to leave"),
        &[],
        &alice,
    )
    .await
    .expect("persist admits the founder's removal and rotates the epoch");
    // …and it replicates: the CommunityMembershipRevocation plane.
    for to in [&b, &c] {
        for rev in a
            .dir
            .list_signed_community_membership_revocations_since(None, 64)
            .await
            .unwrap()
        {
            to.dir
                .put_community_membership_revocation(rev.revocation)
                .await
                .expect("a peer admits the replicated revocation");
        }
    }

    // ── Message 2: sealed AFTER the removal ──
    let t2 = ts() + chrono::Duration::seconds(1);
    let (row2, sealed2) = chat::chat_message_attestation_in(&alice, &room, "two", t2, &a.store)
        .await
        .expect("alice sends again");
    let (e1, e2) = (
        sealed1.epoch.expect("a sealed tier carries an epoch"),
        sealed2.epoch.expect("a sealed tier carries an epoch"),
    );
    assert!(e2 > e1, "the removal rotated the epoch: {e1} → {e2}");
    assert!(
        sealed2.granted.contains(&b.me) && !sealed2.granted.contains(&c.me),
        "the new epoch wraps to the remaining member and not the removed one: {:?}",
        sealed2.granted,
    );
    carry_key_grants(&a, &b).await;
    carry_bytes(&a, &b, &room, "alice-fed", &sealed2, t2)
        .await
        .expect("bob's node adopts the bytes");
    assert_eq!(
        read_as(&b, &row2, &room, &b.me).await,
        Body::Text("two".to_owned()),
        "bob, still a member, opens message 2",
    );
    // Carol's node: the set carries no wrap for her, and persist REFUSES to
    // store the bytes at all — a node never holds content it is not party
    // to (persist #846 §4, `NotPartyTo`), and she is no longer party to the
    // room. Stronger than "cannot open": nothing lands.
    carry_key_grants(&a, &c).await;
    let refused = carry_bytes(&a, &c, &room, "alice-fed", &sealed2, t2).await;
    assert!(
        matches!(
            refused,
            Err(ciris_persist::federation::BlobError::NotPartyTo { .. })
        ),
        "carol's node refuses to hold bytes of a room she was removed from — got {refused:?}",
    );
    assert!(
        matches!(
            read_as(&c, &row2, &room, &c.me).await,
            Body::Unopened { .. }
        ),
        "carol, removed, reads Unopened for a message sealed after the removal",
    );
    assert_eq!(
        read_as(&c, &row1, &room, &c.me).await,
        Body::Text("one".to_owned()),
        "and still opens the message from before it — rotation, not recall (CC 4.5.12.1 Option A)",
    );
}
