//! CIRISEdge#805 item 6 — **a call is a CEG attestation whose data subjects are
//! its attendees**, on real persist v57 (`chat:call:v1`, CIRISPersist#1095).
//!
//! One row per attendee: each attendee, on joining, writes its OWN row (it is
//! the attester and the only subject), authored `self` and shared to the room
//! like a chat row. The attendee set is the UNION of the subjects over every
//! row of the call.
//!
//! - (a) three staggered joins: three rows, `attendees` grows 1, 2, 3, and a
//!   leaver (who writes nothing) stays;
//! - (b) two simultaneous joins: two rows, the union is right;
//! - (c) an outsider to the room is never a recipient of a call row, a member
//!   is (persist's `may_receive`), and the share routes to the room's members;
//! - (d) the row is the ACTOR's own: a row whose attester or subjects are not
//!   the actor is `CallError::ActorIsNotTheSubject` (what `Edge::join_call_as`
//!   asserts before a call starts, and the door before it writes);
//! - (e) a member removed from the room after joining stays an attendee.
//!
//! Requires `transport-reticulum` (the call module is Reticulum-gated):
//! `cargo test --features "transport-http transport-reticulum" --test av_call_record_805`

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use ciris_edge::chat;
use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::av_call::{
    attendance_of, call_id_for_room, call_id_hex, ensure_actor_is_subject, CallError, CallRecord,
    PersistCallRecord,
};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{FederationDirectory, SignedKeyRecord};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend as _;
use sha2::Digest as _;

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into()
}

fn signer(key_id: &str, seed: u8) -> LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).unwrap());
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
            .unwrap(),
    );
    LocalSigner::new(key_id, classical, Some(pqc))
}

async fn record(
    subject: &str,
    s: &LocalSigner,
    scrub: &LocalSigner,
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

/// A member: the human (the attendee) and its node (custody).
struct Member {
    human: Arc<LocalSigner>,
    node: Arc<LocalSigner>,
}

struct Room {
    dir: Arc<SqliteBackend>,
    room: String,
    alice: Member,
    bob: Member,
    carol: Member,
    dave: Member,
}

/// A room of alice (founder), bob and carol, joined by consent (#955) on one
/// substrate; dave is registered and outside it.
async fn room() -> Room {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::consensus_protocol;
    let dir = FederationDirectorySqlite::open(":memory:").await.unwrap();
    dir.run_migrations().await.unwrap();
    let mk = |name: &str, seed: u8| Member {
        human: Arc::new(signer(&format!("{name}-fed"), seed)),
        node: Arc::new(signer(&format!("{name}-node"), seed + 1)),
    };
    let (alice, bob, carol, dave) = (mk("alice", 1), mk("bob", 3), mk("carol", 5), mk("dave", 7));
    for m in [&alice, &bob, &carol, &dave] {
        dir.put_public_key(SignedKeyRecord {
            record: record(&m.human.key_id, &m.human, &m.human, "user").await,
        })
        .await
        .expect("register the human");
        dir.put_public_key(SignedKeyRecord {
            record: record(&m.node.key_id, &m.node, &m.human, "node").await,
        })
        .await
        .expect("register the node");
        // The node is its human's: the audience a room row reaches is its
        // members' NODES, resolved through this binding.
        let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
            &m.human.key_id,
            &m.node.key_id,
            ts(),
            &m.human,
        )
        .await
        .expect("owner binding");
        dir.put_attestation_authored(ciris_persist::federation::SignedAttestation {
            attestation: binding,
        })
        .await
        .expect("admit the owner binding");
    }
    let room = chat::new_room_community_key_id();
    let roster = chat::community(
        &room,
        "the call room",
        &[("alice-fed", Some(MEMBER_ROLE_FOUNDER))],
        consensus_protocol::FOUNDER_ONLY,
        ts(),
    )
    .expect("alice founds it");
    dir.put_community(
        chat::signed_community(roster, &alice.human)
            .await
            .expect("sign"),
    )
    .await
    .expect("admit the room");
    dir.put_public_key(SignedKeyRecord {
        record: record(&room, &signer(&room, 9), &signer(&room, 9), "user").await,
    })
    .await
    .expect("register the room id as a key (persist fixture convention)");
    for (m, who) in [(&bob, "bob-fed"), (&carol, "carol-fed")] {
        let proposal = ciris_edge::membership::propose(
            &*dir,
            ciris_edge::membership::GroupScope::Community,
            &room,
            who,
            None,
            chrono::Utc::now() + chrono::Duration::days(7),
            &alice.human,
        )
        .await
        .expect("alice proposes");
        ciris_edge::membership::reply(&*dir, &proposal.attestation_id, true, &m.human)
            .await
            .expect("the member accepts");
        assert!(ciris_edge::membership::widen(
            &*dir,
            ciris_edge::membership::GroupScope::Community,
            &room,
            who,
            None,
            ts(),
            &alice.human,
        )
        .await
        .expect("alice widens"));
    }
    Room {
        dir,
        room,
        alice,
        bob,
        carol,
        dave,
    }
}

fn door(r: &Room, m: &Member) -> PersistCallRecord {
    PersistCallRecord {
        directory: Arc::clone(&r.dir) as Arc<dyn FederationDirectory>,
        actor: Arc::clone(&m.human),
        node: Arc::clone(&m.node),
    }
}

/// **(a)** Three staggered joins: three rows, the set grows 1, 2, 3; each
/// row's only subject is its own attester; a leaver (who writes nothing)
/// stays an attendee; the start is the first row's.
#[tokio::test]
async fn staggered_joins_grow_the_attendee_set_and_a_leaver_stays() {
    let r = room().await;
    let call = call_id_for_room(&r.room);
    // Instants in the past: a placement never precedes the claim it places.
    let t0 = chrono::Utc::now() - chrono::Duration::seconds(30);
    let mut want: Vec<String> = Vec::new();
    for (i, m) in [&r.alice, &r.bob, &r.carol].into_iter().enumerate() {
        let d = door(&r, m);
        d.record_join(
            &r.room,
            call,
            t0 + chrono::Duration::seconds(i64::try_from(i).unwrap()),
        )
        .await
        .unwrap_or_else(|e| panic!("{}'s call row is admitted and shared: {e}", m.human.key_id));
        want.push(m.human.key_id.clone());
        want.sort();
        let a = d.attendance(&r.room, call).await.expect("read the call");
        assert_eq!(a.attendees, want, "after {} join(s)", i + 1);
        assert_eq!(a.rows, i + 1, "one row per attendee");
    }
    // Every row names exactly its own attester.
    let members: Vec<String> = ["alice-fed", "bob-fed", "carol-fed"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let rows = chat::rows_in_room(&*r.dir, &members, &r.room, chat::CALL_DIMENSION)
        .await
        .expect("rows");
    for row in &rows {
        assert_eq!(row.subject_key_ids, vec![row.attesting_key_id.clone()]);
        assert_eq!(chat::call_id_of(row), Some(call_id_hex(call).as_str()));
        // The ACTOR (the human) attends: attester and subject are the
        // human's key, never the node's.
        assert!(
            row.attesting_key_id.ends_with("-fed"),
            "{}",
            row.attesting_key_id
        );
    }
    // The node only co-signs: its scrub rides the authored row, appended.
    let authored = r
        .dir
        .list_attestations_by("alice-fed")
        .await
        .unwrap()
        .into_iter()
        .find(|a| {
            a.cohort_scope == "self"
                && ciris_persist::federation::admission::envelope_dimension(&a.attestation_envelope)
                    == Some(chat::CALL_DIMENSION)
        })
        .expect("alice's authored call row");
    assert_eq!(authored.subject_key_ids, vec!["alice-fed".to_owned()]);
    assert_eq!(
        authored.scrub_key_id, "alice-fed",
        "signed by the actor at write"
    );
    assert!(
        authored
            .additional_scrubs
            .iter()
            .any(|c| c.scrub_key_id == "alice-node"),
        "the node co-scrubs the crossing: {:?}",
        authored.additional_scrubs
    );
    // Bob leaves: leaving writes nothing, and his row stands.
    let a = door(&r, &r.carol)
        .attendance(&r.room, call)
        .await
        .expect("read");
    assert!(
        a.attendees.contains(&"bob-fed".to_owned()),
        "a leaver attended: {a:?}"
    );
    let started = a.started_at.expect("a start");
    assert!(
        started <= t0 + chrono::Duration::milliseconds(1),
        "the earliest row: {started}"
    );
}

/// **(b)** Two joins at once: two rows, no fork, the union.
#[tokio::test]
async fn simultaneous_joins_are_two_rows_and_the_union_holds() {
    let r = room().await;
    let call = call_id_for_room(&r.room);
    let (da, db) = (door(&r, &r.alice), door(&r, &r.bob));
    let now = chrono::Utc::now();
    let (x, y) = tokio::join!(
        da.record_join(&r.room, call, now),
        db.record_join(&r.room, call, now)
    );
    x.expect("alice's row");
    y.expect("bob's row");
    let a = door(&r, &r.carol)
        .attendance(&r.room, call)
        .await
        .expect("read");
    assert_eq!(
        a.attendees,
        vec!["alice-fed".to_owned(), "bob-fed".to_owned()]
    );
    assert_eq!(a.rows, 2);
    // Another call in the same room is another set.
    let other = ciris_edge::transport::av_call_key::CallId([0xEE; 32]);
    assert!(door(&r, &r.carol)
        .attendance(&r.room, other)
        .await
        .expect("read")
        .attendees
        .is_empty());
}

/// **(c)** Reach: the call row goes exactly where a chat row of the room
/// goes. An outsider receives neither copy; for every key, members and
/// outsider alike, persist's `may_receive` gives the call row the same
/// verdict as a chat row the same author placed in the same room.
#[tokio::test]
async fn an_outsider_receives_no_call_row() {
    use ciris_edge::replication::attestation_bind::{
        share, CrossingBasis, RoutesTo, Signers, With,
    };
    use ciris_persist::federation::replication_audience::may_receive;
    let r = room().await;
    let call = call_id_for_room(&r.room);
    let at = chrono::Utc::now() - chrono::Duration::seconds(5);
    door(&r, &r.alice)
        .record_join(&r.room, call, at)
        .await
        .expect("alice's row");
    // A chat row of the same room, placed the same way: the reach to match.
    let chat_row = chat::key_package_attestation_in(
        &r.alice.human,
        &ciris_edge::scope_room::ScopeRoom::community(r.room.clone()),
        b"a key package",
        at,
    )
    .await
    .expect("chat row");
    r.dir
        .put_attestation(ciris_persist::federation::SignedAttestation {
            attestation: chat_row.clone(),
        })
        .await
        .expect("admit the chat row");
    let crossing = share(
        &*r.dir,
        &chat_row,
        With::Community {
            community_key_id: r.room.clone(),
        },
        CrossingBasis::ProducerAuthority,
        Signers {
            node: &r.alice.node,
            actor: Some(&r.alice.human),
        },
    )
    .await
    .expect("share the chat row");
    assert_eq!(
        crossing.routes_to,
        RoutesTo::CommunityMembers {
            community_key_id: r.room.clone()
        }
    );
    let rows_of = |dim: &'static str| {
        let dir = Arc::clone(&r.dir);
        async move {
            dir.list_attestations_by("alice-fed")
                .await
                .unwrap()
                .into_iter()
                .filter(|a| {
                    ciris_persist::federation::admission::envelope_dimension(
                        &a.attestation_envelope,
                    ) == Some(dim)
                })
                .collect::<Vec<_>>()
        }
    };
    let call_rows = rows_of(chat::CALL_DIMENSION).await;
    let chat_rows = rows_of(chat::KEY_PACKAGE_DIMENSION).await;
    assert_eq!(
        call_rows.len(),
        2,
        "authored self, shared to the room: two rows"
    );
    for scope in ["self", "community"] {
        let call_row = call_rows
            .iter()
            .find(|a| a.cohort_scope == scope)
            .expect("call copy");
        let chat_row = chat_rows
            .iter()
            .find(|a| a.cohort_scope == scope)
            .expect("chat copy");
        for m in [&r.alice, &r.bob, &r.carol, &r.dave] {
            for key in [&m.human.key_id, &m.node.key_id] {
                let call_v = may_receive(&*r.dir, key, call_row).await.expect("verdict");
                let chat_v = may_receive(&*r.dir, key, chat_row).await.expect("verdict");
                assert_eq!(
                    call_v.allowed(),
                    chat_v.allowed(),
                    "{key} at {scope}: the call row reaches like a chat row ({call_v:?} vs \
                     {chat_v:?})"
                );
            }
        }
        for outsider in [&r.dave.human.key_id, &r.dave.node.key_id] {
            assert!(
                !may_receive(&*r.dir, outsider, call_row)
                    .await
                    .expect("verdict")
                    .allowed(),
                "{outsider} is outside the room and receives no call row ({scope})"
            );
        }
    }
}

/// The union is over every row: a reader that took one row would miss the
/// others (the union's own unit witness).
#[tokio::test]
async fn the_attendee_set_is_the_union_of_every_row() {
    let r = room().await;
    let call = call_id_for_room(&r.room);
    for m in [&r.alice, &r.bob, &r.carol] {
        door(&r, m)
            .record_join(&r.room, call, chrono::Utc::now())
            .await
            .expect("row");
    }
    let members: Vec<String> = ["alice-fed", "bob-fed", "carol-fed"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    let rows = chat::rows_in_room(&*r.dir, &members, &r.room, chat::CALL_DIMENSION)
        .await
        .expect("rows");
    let a = attendance_of(&rows, &call_id_hex(call));
    assert_eq!(a.attendees.len(), 3, "{a:?}");
}

/// **(e)** Attendance is by the CALL, never by who is in the room now: A, B
/// and C attend; B is then REMOVED from the room (persist's roster
/// revocation, signed by the founder). The call's attendees at A and at C
/// still include B — the data-subject record lists everyone who attended.
#[tokio::test]
async fn an_attendee_removed_from_the_room_stays_an_attendee() {
    let r = room().await;
    let call = call_id_for_room(&r.room);
    let at = chrono::Utc::now() - chrono::Duration::seconds(20);
    for m in [&r.alice, &r.bob, &r.carol] {
        door(&r, m)
            .record_join(&r.room, call, at)
            .await
            .expect("row");
    }
    ciris_edge::community_roster::revoke_community_member(
        &*r.dir,
        &r.room,
        "bob-fed",
        chrono::Utc::now() - chrono::Duration::seconds(1),
        Some("removed for the witness"),
        &["alice-fed"],
        &r.alice.human,
    )
    .await
    .expect("alice removes bob from the room");
    assert!(
        !ciris_persist::federation::is_active_community_member(&*r.dir, &r.room, "bob-fed")
            .await
            .unwrap(),
        "bob is no longer an active member of the room"
    );
    for m in [&r.alice, &r.carol] {
        let a = door(&r, m).attendance(&r.room, call).await.expect("read");
        assert_eq!(
            a.attendees,
            vec![
                "alice-fed".to_owned(),
                "bob-fed".to_owned(),
                "carol-fed".to_owned()
            ],
            "at {}: bob attended, and stays",
            m.human.key_id
        );
    }
}

/// **(d)** The call row is the actor's OWN: its attester and its only subject.
/// `ensure_actor_is_subject` is the guard `Edge::join_call_as` runs before a
/// call starts and `PersistCallRecord::record_join` runs before it writes;
/// each mismatch is refused by name.
#[tokio::test]
async fn a_call_row_that_is_not_the_actors_own_is_refused_by_name() {
    let r = room().await;
    let call = call_id_hex(call_id_for_room(&r.room));
    let row = chat::call_attestation_in(&r.alice.human, &r.room, &call, ts())
        .await
        .expect("alice's row");
    ensure_actor_is_subject("alice-fed", &row).expect("alice's row is alice's own");

    // Another actor attending on alice's row.
    let err = ensure_actor_is_subject("bob-fed", &row).expect_err("bob is not its subject");
    assert!(
        matches!(&err, CallError::ActorIsNotTheSubject { actor, attester, subjects }
            if actor == "bob-fed" && attester == "alice-fed" && subjects == &vec!["alice-fed".to_owned()]),
        "{err:?}"
    );
    // A row naming a second subject is no longer one attendee's row.
    let mut widened = row.clone();
    widened.subject_key_ids.push("bob-fed".to_owned());
    assert!(matches!(
        ensure_actor_is_subject("alice-fed", &widened),
        Err(CallError::ActorIsNotTheSubject { .. })
    ));
    // A row whose subject is the actor but whose attester is the NODE.
    let mut node_attested = row.clone();
    node_attested.attesting_key_id = "alice-node".to_owned();
    assert!(matches!(
        ensure_actor_is_subject("alice-fed", &node_attested),
        Err(CallError::ActorIsNotTheSubject { .. })
    ));
}
