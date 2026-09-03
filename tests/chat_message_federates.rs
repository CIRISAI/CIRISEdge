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
    /// Alice's copy of the room key.
    key_a: RoomKey,
    /// Bob's copy — what the far end opens with.
    key_b: RoomKey,
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

/// The in-process handshake: the room key as both people hold it.
async fn mls_pair(room: &str) -> (RoomKey, RoomKey) {
    let a = CohortGroup::create(store("alice"), room, "alice-fed", 16)
        .await
        .expect("create");
    let (material, kp) = mint_cohort_key_material("bob-fed").expect("mint");
    let kp = key_package_from_bytes(&key_package_to_bytes(kp).expect("kp bytes"))
        .expect("kp round-trips through the byte codec");
    let commit = a.add_member("bob-fed", kp).await.expect("add bob");
    let welcome = commit.welcome().expect("welcome").to_vec();
    let b = CohortGroup::join(store("bob"), room, material, &welcome, 16)
        .await
        .expect("join");
    (
        RoomKey::of(&a).await.unwrap(),
        RoomKey::of(&b).await.unwrap(),
    )
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
    let (key_a, key_b) = mls_pair(&room).await;
    World {
        dir,
        alice,
        alice_node,
        bob,
        bob_node,
        room,
        key_a,
        key_b,
    }
}

/// Author a message as Alice (sealed under her room key, signed at write)
/// and store it.
async fn authored(w: &World, body: &str) -> ciris_persist::federation::Attestation {
    let msg = chat::chat_message_attestation(&w.alice, "bob-fed", body, ts(), &w.key_a)
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
    let msg = chat::chat_message_attestation(&w.alice, "bob-fed", BODY, ts(), &w.key_a)
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
    // The wire carries CIPHERTEXT and a seal header, never the text.
    let wire = serde_json::to_string(&msg.attestation_envelope).unwrap();
    assert!(!wire.contains(BODY), "PLAINTEXT ON THE WIRE: {wire}");
    assert!(msg.attestation_envelope.get(chat::FIELD_SEALED).is_some());
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
    let seen = chat::messages_in_room(&*w.dir, &["alice-fed".to_string()], &w.room, &w.key_b)
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
    assert_eq!(m.epoch, Some(w.key_b.epoch()));
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

    // Same key on both sides: what Alice seals, Bob opens.
    let key_a = RoomKey::of(&a).await.unwrap();
    let key_b = RoomKey::of(&b).await.unwrap();
    let at = "2026-05-01T00:00:00.000Z";
    let (ct, sealed) = chat::seal_body(&key_a, &room, "alice-fed", at, "hi").unwrap();
    assert_eq!(
        chat::open_body(&key_b, &room, "alice-fed", at, &ct, &sealed).unwrap(),
        "hi"
    );
}

/// **The wrong key, a rotated epoch, or a ciphertext lifted onto another row
/// does not open** — and the widened row, which is all a peer receives, DOES.
#[tokio::test]
async fn a_wrong_key_epoch_or_context_does_not_open_the_body() {
    let w = world().await;
    let at = "2026-05-01T00:00:00.000Z";
    let (ct, sealed) = chat::seal_body(&w.key_a, &w.room, "alice-fed", at, BODY).unwrap();

    let stranger = RoomKey::from_parts([7u8; 32], w.key_a.epoch());
    let err = chat::open_body(&stranger, &w.room, "alice-fed", at, &ct, &sealed).unwrap_err();
    assert!(err.contains("open failed"), "{err}");

    let rotated = RoomKey::from_parts([0u8; 32], w.key_a.epoch() + 1);
    let err = chat::open_body(&rotated, &w.room, "alice-fed", at, &ct, &sealed).unwrap_err();
    assert!(err.contains("rotated"), "{err}");

    // Same key, but the ciphertext lifted onto another author's row, another
    // room, or the SAME author's row at a different instant (the binding
    // persist v40.0.0 made possible by carrying the claim's instant verbatim).
    let err = chat::open_body(&w.key_b, &w.room, "bob-fed", at, &ct, &sealed).unwrap_err();
    assert!(err.contains("open failed"), "{err}");
    let err = chat::open_body(&w.key_b, "another-room", "alice-fed", at, &ct, &sealed).unwrap_err();
    assert!(err.contains("open failed"), "{err}");
    let err = chat::open_body(
        &w.key_b,
        &w.room,
        "alice-fed",
        "2026-05-01T00:00:01.000Z",
        &ct,
        &sealed,
    )
    .unwrap_err();
    assert!(err.contains("open failed"), "{err}");

    // And the reader reports it rather than dropping it or lying: the
    // widened row, read with a stranger's key, is there and Unopened.
    let msg = authored(&w, "secret").await;
    share(
        &*w.dir,
        &msg,
        w.room_with(),
        CrossingBasis::ProducerAuthority,
        w.signers(),
    )
    .await
    .unwrap();
    let seen = chat::messages_in_room(&*w.dir, &["alice-fed".to_string()], &w.room, &stranger)
        .await
        .unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        matches!(seen[0].body, Body::Unopened { .. }),
        "{:?}",
        seen[0].body
    );
    assert!(
        seen[0].widens.is_some(),
        "the row a peer holds is the widening"
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
    let seen = chat::messages_in_room(&*w.dir, &["alice-fed".to_string()], &w.room, &w.key_b)
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
    let mut row =
        chat::chat_message_attestation(&w.bob, "alice-fed", "not alice's words", ts(), &w.key_b)
            .await
            .unwrap();
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

    let m = chat::ChatMessage::from_row(&row, &w.room, &w.key_b).expect("a chat row");
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
    let seen = chat::messages_in_room(&*w.dir, &["bob-fed".to_string()], &w.room, &w.key_b)
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
    let seen = chat::messages_in_room(&*w.dir, &["alice-fed".to_string()], &other_room, &w.key_b)
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
    let msg = chat::chat_message_attestation(&w.alice, "bob-fed", "x", ts(), &w.key_a)
        .await
        .unwrap();
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
    let signed = chat::chat_message_attestation(&w.alice, "bob-fed", "c", ts(), &w.key_a)
        .await
        .unwrap();
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
    let w = world().await;
    let err = chat::chat_message_attestation(&half, "bob-fed", "x", ts(), &w.key_a)
        .await
        .unwrap_err();
    assert!(err.contains("ML-DSA-65"), "{err}");
}
