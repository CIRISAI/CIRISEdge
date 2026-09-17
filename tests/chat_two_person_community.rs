//! The two-person chat flow, end to end, on real substrate.
//!
//! ```text
//!   Alice                                            Bob
//!   ─────                                            ───
//!   search "bob-fed" (or a nodeID) ──▶ contact found
//!   "add to contact book"
//!   send request to join a chat community ─────────▶  "request from Alice"
//!                                                     (+ optional note)
//!                                              accept ─┐
//!   "Chat with Bob"  ◀───────────────────── "Joined community with Alice"
//!                     both are moderators; membership is exactly {Alice, Bob}
//! ```
//!
//! `docs/CHAT_HARNESS_INTEGRATION.md` assigns the rungs: edge owns `Announce`
//! and `Discover`, the server owns `RequestContact`, `Consent`, `OpenChat` and
//! `SendMessage`. That split is about who exposes the API — every rung above
//! still stands on edge substrate, and this file proves the substrate holds so
//! the server can build on it without discovering the gaps itself.
//!
//! `tests/chat_harness_dx.rs` pins the documented call SHAPES (they exist and
//! typecheck). This walks the flow with real signatures and a real persist
//! directory — the questions a compile-pin cannot answer: does the lookup
//! actually resolve, is the community really two people on BOTH sides, is the
//! invitee a founder rather than a guest, and is the room the same record
//! from either end.
//!
//! The room is the persist `Community` record, and the conversation key is
//! persist's community DEK derived from it (CIRISEdge#604 retired chat's own
//! MLS group, whose exporter secret this file used to call "the conversation
//! key"). "Both sides derive the same key" is therefore witnessed where the
//! key lives: `tests/chat_message_federates.rs` seals and opens a body across
//! two stores; "the key moves when membership changes" is persist's rotation
//! on an admitted revocation (CIRISPersist#848 I63) and the revocation leg of
//! CIRISEdge#608.

use std::sync::Arc;

use ciris_edge::replication::attestation_bind::owner_binding_attestation;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::types::Community;
use ciris_persist::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend as _;
use sha2::Digest as _;

// ═══════════════════════════════════════════════════════════════════
// Fixtures — real keys, real rows. persist's admission is the oracle,
// so nothing here is faked.
// ═══════════════════════════════════════════════════════════════════

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .unwrap()
        .into()
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// One person: a hybrid signer, because the federation tier is PQC-mandatory
/// (CC 5.3.2.4.3.1) and a classical-only row is refused at admission.
fn signer(key_id: &str, seed: u8) -> ciris_edge::identity::LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).expect("ed25519"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
            .expect("ml-dsa-65"),
    );
    ciris_edge::identity::LocalSigner::new(key_id, classical, Some(pqc))
}

async fn pubkeys(s: &ciris_edge::identity::LocalSigner) -> (String, Option<String>) {
    let ed = b64(&s.classical.public_key().await.expect("ed pubkey"));
    let pqc = match s.pqc.as_ref() {
        Some(p) => Some(b64(&p.public_key().await.expect("pqc pubkey"))),
        None => None,
    };
    (ed, pqc)
}

async fn signed_record(
    subject: &str,
    keys: (String, Option<String>),
    scrub: &ciris_edge::identity::LocalSigner,
    scrub_key_id: &str,
    identity_type: &str,
) -> KeyRecord {
    let envelope = serde_json::json!({ "key_id": subject });
    let canonical = serde_json::to_vec(&envelope).unwrap();
    let digest = sha2::Sha256::digest(&canonical);
    let (sig, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(scrub, digest.as_slice(), "key record")
            .await
            .expect("sign");
    KeyRecord {
        key_id: subject.to_owned(),
        pubkey_ed25519_base64: keys.0,
        pubkey_ml_dsa_65_base64: keys.1,
        algorithm: "hybrid".to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: subject.to_owned(),
        valid_from: ts(),
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: scrub_key_id.to_owned(),
        scrub_timestamp: ts(),
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// A person and the node they own — the shape every real fleet has, and the
/// reason discovery resolves an identifier to a PERSON first.
struct Party {
    fed_id: String,
    node_id: String,
    signer: ciris_edge::identity::LocalSigner,
    node_signer: ciris_edge::identity::LocalSigner,
}

impl Party {
    fn new(name: &str, seed: u8) -> Self {
        let fed_id = format!("{name}-fed");
        let node_id = format!("{name}-node");
        Self {
            signer: signer(&fed_id, seed),
            node_signer: signer(&node_id, seed.wrapping_add(64)),
            fed_id,
            node_id,
        }
    }
}

/// A directory holding both parties as the mesh would after replication:
/// each person's `user` record, each node's `node` record, and the
/// owner-binding attestations that make `fedID -> their nodes` answerable.
async fn directory_of(parties: &[&Party]) -> Arc<SqliteBackend> {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open");
    dir.run_migrations().await.expect("migrate");
    for p in parties {
        for rec in [
            signed_record(
                &p.fed_id,
                pubkeys(&p.signer).await,
                &p.signer,
                &p.fed_id,
                "user",
            )
            .await,
            signed_record(
                &p.node_id,
                pubkeys(&p.node_signer).await,
                &p.signer,
                &p.fed_id,
                "node",
            )
            .await,
        ] {
            dir.put_public_key(SignedKeyRecord { record: rec })
                .await
                .expect("put_public_key");
        }
        let att = owner_binding_attestation(&p.fed_id, &p.node_id, ts(), &p.signer)
            .await
            .expect("build owner binding");
        dir.put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("owner binding must admit");
    }
    dir
}

// ═══════════════════════════════════════════════════════════════════
// Rung 2 — "search for a fedID or a NodeCode" → "Contact Found"
// ═══════════════════════════════════════════════════════════════════

/// A fedID resolves to the person and the nodes that reach them.
#[tokio::test]
async fn searching_a_fed_id_finds_the_person_and_their_nodes() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let dir = directory_of(&[&alice, &bob]).await;
    let lens = ciris_edge::contact::PersistLens::new(dir.as_ref());

    let found = ciris_edge::contact::resolve(&lens, &bob.fed_id)
        .await
        .expect("Bob's fedID must resolve — this is the 'Contact Found' moment");
    assert_eq!(found.fed_id, bob.fed_id);
    assert!(
        found.nodes.contains(&bob.node_id),
        "the contact must carry something ADDRESSABLE, or 'found' is a claim the \
         UI cannot act on: {:?}",
        found.nodes
    );
}

/// The other half of the same box: a **nodeID** resolves to its OWNER.
///
/// This is why the search field takes either. A node cannot consent and cannot
/// be a contact, so pasting a node identifier has to land on the person — and
/// the answer must be the SAME person a fedID search returns.
#[tokio::test]
async fn searching_a_node_id_resolves_to_the_same_person() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let dir = directory_of(&[&alice, &bob]).await;
    let lens = ciris_edge::contact::PersistLens::new(dir.as_ref());

    let via_node = ciris_edge::contact::resolve(&lens, &bob.node_id)
        .await
        .expect("a nodeID must resolve through its owner");
    let via_fed = ciris_edge::contact::resolve(&lens, &bob.fed_id)
        .await
        .expect("and so must the fedID");
    assert_eq!(
        via_node.fed_id, via_fed.fed_id,
        "both inputs must name the same person, or the contact book gets two \
         entries for one human"
    );
    assert_eq!(via_node.fed_id, bob.fed_id);
}

/// A stranger nobody has announced is NOT reported as found.
///
/// The stall is the honest answer, and it is self-resolving — the UI should say
/// "not found yet", never invent a contact.
#[tokio::test]
async fn searching_an_unknown_id_stalls_rather_than_inventing_a_contact() {
    let alice = Party::new("alice", 1);
    let dir = directory_of(&[&alice]).await;
    let lens = ciris_edge::contact::PersistLens::new(dir.as_ref());

    let stall = ciris_edge::contact::resolve(&lens, "mallory-fed")
        .await
        .expect_err("an unknown identifier must not resolve");
    assert!(
        stall.self_resolving(),
        "an unannounced stranger is 'not yet', not 'never': {stall:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════
// Rungs 4-5 — accept → "Joined community with X", exactly the two of
// them, both able to act
// ═══════════════════════════════════════════════════════════════════

/// Alice opens the community; Bob's node authors the SAME derived record.
///
/// Returns the room as each side holds it — two INDEPENDENT directories,
/// which is the real deployment shape. Sharing one would let a bug pass by
/// reading state the other node wrote. There is no handshake: the record is
/// derived from the two fed-IDs, so both ends author it having exchanged
/// nothing, and persist's `Community` admission is the oracle on each side.
async fn open_two_person_community(alice: &Party, bob: &Party) -> (Community, Community, String) {
    let community_id = ciris_edge::chat::pair_community_key_id(&alice.fed_id, &bob.fed_id);

    let dir_a = directory_of(&[alice, bob]).await;
    let dir_b = directory_of(&[alice, bob]).await;

    // Each side authors the room under ITS node's authority — the shape the
    // harness and the server both use. The bytes of the `Community` are the
    // same on both sides by derivation; only the authority signature differs.
    let row_a = ciris_edge::chat::signed_pair_community(
        &alice.fed_id,
        &bob.fed_id,
        ts(),
        &alice.node_signer,
    )
    .await
    .expect("alice's node signs the room");
    let row_b =
        ciris_edge::chat::signed_pair_community(&bob.fed_id, &alice.fed_id, ts(), &bob.node_signer)
            .await
            .expect("bob's node signs the room");
    dir_a
        .put_community(row_a)
        .await
        .expect("persist admits the room on alice's node");
    dir_b
        .put_community(row_b)
        .await
        .expect("persist admits the room on bob's node");

    let a = dir_a
        .lookup_community(&community_id)
        .await
        .expect("lookup")
        .expect("the room exists on alice's node");
    let b = dir_b
        .lookup_community(&community_id)
        .await
        .expect("lookup")
        .expect("the room exists on bob's node");
    (a, b, community_id)
}

/// The member key ids of a room, sorted — what every rung below compares.
fn member_ids(c: &Community) -> Vec<String> {
    let mut m: Vec<String> = c.members.iter().map(|m| m.key_id.clone()).collect();
    m.sort();
    m
}

/// "Joined community with Alice" — membership is EXACTLY the two of them, and
/// both sides agree on that.
#[tokio::test]
async fn the_community_is_exactly_the_two_of_them_on_both_sides() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let (a, b, _id) = open_two_person_community(&alice, &bob).await;

    for (who, room) in [("alice", &a), ("bob", &b)] {
        assert_eq!(
            room.members.len(),
            2,
            "{who} sees the wrong size — a 'chat with one person' that contains \
             three is a privacy failure, not a cosmetic one"
        );
        assert_eq!(
            member_ids(room),
            vec![alice.fed_id.clone(), bob.fed_id.clone()],
            "{who} sees the wrong membership"
        );
    }
    // The SAME record on both sides — id, name, roster, protocol, founding
    // instant. The DEK is derived from this record by persist, so two sides
    // that disagree here would derive two keys; agreeing here is what
    // "both sides stand on the same epoch" used to assert of the MLS group.
    assert_eq!(a, b, "the room must be the same record from either end");
}

/// **Both are moderators.** The concrete meaning: the INVITEE holds the same
/// authority root as the founder, not a guest's.
///
/// persist refuses to federate any content keyed on a community with no live
/// named moderator (CC 4.5.4 / §11.11), and a named moderator exists iff the
/// member is a steward-bound authority root — a `founder`. So the property is
/// in the RECORD: both members are `founder`, on both sides, and the protocol
/// is `unanimous` so nothing decides without both. The operational half —
/// a founder-signed membership change admitting — is the widen/revoke
/// producers of CIRISEdge#608, witnessed there against persist's door.
#[tokio::test]
async fn the_invitee_is_a_moderator_not_a_guest() {
    use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
    use ciris_persist::federation::types::consensus_protocol;
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let (a, b, _id) = open_two_person_community(&alice, &bob).await;

    for (who, room) in [("alice", &a), ("bob", &b)] {
        for m in &room.members {
            assert_eq!(
                m.role.as_deref(),
                Some(MEMBER_ROLE_FOUNDER),
                "{who}'s copy: {} must be a FOUNDER — a member without an authority \
                 root is a guest, and a room with only one founder has one moderator",
                m.key_id
            );
        }
        assert_eq!(
            room.consensus_protocol,
            consensus_protocol::UNANIMOUS,
            "{who}'s copy: two equals decide together or not at all"
        );
    }
}

/// "Chat with Y" — a two-person community names itself by THE OTHER MEMBER.
///
/// The display name is not a stored string; it is derived from membership, so
/// it cannot drift from who is actually in the room. Each side derives the
/// other, from the same group.
#[tokio::test]
async fn a_two_person_community_is_named_by_the_other_member() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let (a, b, _id) = open_two_person_community(&alice, &bob).await;

    let alice_sees = ciris_edge::contact::the_other_member(&member_ids(&a), &alice.fed_id);
    let bob_sees = ciris_edge::contact::the_other_member(&member_ids(&b), &bob.fed_id);

    assert_eq!(
        alice_sees.as_deref(),
        Some(bob.fed_id.as_str()),
        "Alice's list should read 'Chat with Bob'"
    );
    assert_eq!(
        bob_sees.as_deref(),
        Some(alice.fed_id.as_str()),
        "and Bob's should read 'Chat with Alice' — the same room, named from \
         each side"
    );
}

/// A group that is NOT two people has no such name, and says so.
///
/// The `None` is the point: a caller that unwraps a "the other member" on a
/// three-person room would show one participant's name for a group chat. The
/// type makes that a decision rather than an accident.
#[tokio::test]
async fn a_group_that_is_not_a_pair_has_no_other_member() {
    let members = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    assert_eq!(
        ciris_edge::contact::the_other_member(&members, "a"),
        None,
        "a three-person room is not 'Chat with X'"
    );
    assert_eq!(
        ciris_edge::contact::the_other_member(&["a".to_string()], "a"),
        None,
        "a room containing only yourself has no other member"
    );
    assert_eq!(
        ciris_edge::contact::the_other_member(&["a".to_string(), "b".to_string()], "z"),
        None,
        "a non-member gets no name — asking about a room you are not in is a \
         caller bug, not a lookup that should guess"
    );
}

// ═══════════════════════════════════════════════════════════════════
// The whole ladder, in order
// ═══════════════════════════════════════════════════════════════════

/// Search → found → open → named → the same record on both sides, in one pass.
///
/// The per-rung tests above can all pass while the sequence does not compose —
/// this is the walk a server implements, in the order it implements it.
#[tokio::test]
async fn the_whole_flow_composes_in_order() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let dir = directory_of(&[&alice, &bob]).await;
    let lens = ciris_edge::contact::PersistLens::new(dir.as_ref());

    // 1. Alice searches for Bob and finds a person she can reach.
    let found = ciris_edge::contact::resolve(&lens, &bob.fed_id)
        .await
        .expect("contact found");
    assert!(!found.nodes.is_empty(), "found, and addressable");

    // 2-3. Request + accept are the server's rungs; what edge owes them is
    // that the accepted contact is a resolvable person with nodes, which is
    // exactly `found` above.

    // 4. Open the community that carries the conversation — derived, not
    //    negotiated: the id is a hash of the two fed-IDs, never their text.
    let (a, b, community_id) = open_two_person_community(&alice, &bob).await;
    assert_eq!(
        community_id,
        ciris_edge::chat::pair_community_key_id(&bob.fed_id, &alice.fed_id),
        "the room's id is the same from either end"
    );

    // 5. Both see the same two-person room, named from each side.
    assert_eq!(a.members.len(), 2);
    assert_eq!(
        ciris_edge::contact::the_other_member(&member_ids(&a), &alice.fed_id).as_deref(),
        Some(bob.fed_id.as_str()),
        "Alice's room reads 'Chat with Bob'"
    );

    // 6. And they hold the same RECORD, so persist derives the same DEK on
    //    both sides and a message can actually cross — the crossing itself
    //    is `tests/chat_message_federates.rs`.
    assert_eq!(a, b, "the same room from either end");
}
