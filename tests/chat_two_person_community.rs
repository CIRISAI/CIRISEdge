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
//! typecheck). This walks the flow with real signatures, a real persist
//! directory, and real MLS — the questions a compile-pin cannot answer:
//! does the lookup actually resolve, is the community really two people, can
//! the invitee act as a peer rather than a guest, and do both sides derive the
//! same conversation key.

use std::sync::Arc;

use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::replication::attestation_bind::owner_binding_attestation;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
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

fn store() -> ScopeStateProvider {
    ScopeStateProvider::new(Arc::new(
        XChaChaKvStore::open_in_memory(b"two-person-chat-test").unwrap(),
    ))
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

/// Alice opens the community and admits Bob; Bob joins from the Welcome.
///
/// Returns both live groups — two INDEPENDENT stores, which is the real
/// deployment shape. Sharing one would let a bug pass by reading state the
/// other node wrote.
async fn open_two_person_community(
    alice: &Party,
    bob: &Party,
) -> (CohortGroup, CohortGroup, String) {
    let community_id = format!("chat-{}-{}", alice.fed_id, bob.fed_id);

    let a = CohortGroup::create(store(), &community_id, &alice.fed_id, 16)
        .await
        .expect("create the community");

    // Bob mints key material and hands over a KeyPackage — the invitee's half
    // of the handshake.
    let (material, kp) = mint_cohort_key_material(&bob.fed_id).expect("bob key material");
    let commit = a
        .add_member(&bob.fed_id, kp)
        .await
        .expect("admit Bob to the community");
    let welcome = commit
        .welcome()
        .expect("admitting a member yields a Welcome");

    let b = CohortGroup::join(store(), &community_id, material, welcome, 16)
        .await
        .expect("Bob joins from the Welcome");

    (a, b, community_id)
}

/// "Joined community with Alice" — membership is EXACTLY the two of them, and
/// both sides agree on that.
#[tokio::test]
async fn the_community_is_exactly_the_two_of_them_on_both_sides() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let (a, b, _id) = open_two_person_community(&alice, &bob).await;

    for (who, group) in [("alice", &a), ("bob", &b)] {
        assert_eq!(
            group.member_count().await,
            2,
            "{who} sees the wrong size — a 'chat with one person' that contains \
             three is a privacy failure, not a cosmetic one"
        );
        let mut members = group.member_key_ids().await;
        members.sort();
        assert_eq!(
            members,
            vec![alice.fed_id.clone(), bob.fed_id.clone()],
            "{who} sees the wrong membership"
        );
    }
    assert_eq!(
        a.epoch().await,
        b.epoch().await,
        "both sides must stand on the same epoch, or their keys diverge"
    );
}

/// **Both are moderators.** The concrete meaning: the INVITEE can change
/// membership, not just the founder.
///
/// MLS has no "owner" role — every member may commit — but that is a property
/// of the protocol, not evidence about this wiring. So Bob (who was invited)
/// performs a membership change and Alice (who created the group) applies it.
/// If the invitee were a guest, this is the assertion that would fail.
#[tokio::test]
async fn the_invitee_is_a_moderator_not_a_guest() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let (a, b, _id) = open_two_person_community(&alice, &bob).await;
    let carol = Party::new("carol", 3);

    // BOB — the invitee — adds a third party.
    let (_carol_material, carol_kp) =
        mint_cohort_key_material(&carol.fed_id).expect("carol key material");
    let commit = b.add_member(&carol.fed_id, carol_kp).await.expect(
        "the INVITEE must be able to change membership — that is what \
                 'both are mods' means operationally",
    );

    // And ALICE, the founder, accepts that change. Assert it APPLIED: a
    // `Deferred` outcome persists nothing and advances no epoch, so a test
    // that ignored this would pass while the membership change sat in a
    // holding pen.
    let applied = a
        .apply_remote_commit(commit.commit())
        .await
        .expect("the founder must accept the invitee's commit");
    assert!(
        matches!(applied, ciris_edge::mls::CommitApplyOutcome::Applied(_)),
        "the founder must MERGE the invitee's commit, not hold it: {applied:?}"
    );

    assert_eq!(a.member_count().await, 3);
    assert_eq!(
        a.epoch().await,
        b.epoch().await,
        "an applied commit must land both sides on the same epoch"
    );
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

    let alice_sees =
        ciris_edge::contact::the_other_member(&a.member_key_ids().await, &alice.fed_id);
    let bob_sees = ciris_edge::contact::the_other_member(&b.member_key_ids().await, &bob.fed_id);

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
// Rung 6 — the conversation key
// ═══════════════════════════════════════════════════════════════════

/// Both sides derive the SAME conversation secret, and it changes when
/// membership does.
///
/// This is what makes the room a room: messages are carried under a key both
/// parties hold and nobody else does. Deriving it independently on each side —
/// rather than one side sending it — is the property worth testing.
#[tokio::test]
async fn both_sides_derive_the_same_conversation_key() {
    let (alice, bob) = (Party::new("alice", 1), Party::new("bob", 2));
    let (a, b, _id) = open_two_person_community(&alice, &bob).await;

    let ka = a.destination_secret().await.expect("alice's secret");
    let kb = b.destination_secret().await.expect("bob's secret");
    assert_eq!(
        ka.as_bytes(),
        kb.as_bytes(),
        "the two sides must derive the same key or no message can be read"
    );

    // A membership change must move it — otherwise a removed member keeps
    // reading.
    let carol = Party::new("carol", 3);
    let (_m, kp) = mint_cohort_key_material(&carol.fed_id).unwrap();
    let commit = a.add_member(&carol.fed_id, kp).await.expect("add carol");
    let applied = b
        .apply_remote_commit(commit.commit())
        .await
        .expect("bob applies");
    assert!(
        matches!(applied, ciris_edge::mls::CommitApplyOutcome::Applied(_)),
        "the key only moves for a commit that actually merged: {applied:?}"
    );

    let after = a.destination_secret().await.expect("alice after");
    assert_ne!(
        ka.as_bytes(),
        after.as_bytes(),
        "the conversation key MUST move when membership changes"
    );
    assert_eq!(
        after.as_bytes(),
        b.destination_secret().await.unwrap().as_bytes(),
        "and both sides must still agree afterwards"
    );
}

// ═══════════════════════════════════════════════════════════════════
// The whole ladder, in order
// ═══════════════════════════════════════════════════════════════════

/// Search → found → open → named → keyed, in one pass.
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

    // 4. Open the community that carries the conversation.
    let (a, b, community_id) = open_two_person_community(&alice, &bob).await;
    assert!(
        community_id.contains(&alice.fed_id) && community_id.contains(&bob.fed_id),
        "the room's id should name its parties"
    );

    // 5. Both see the same two-person room, named from each side.
    assert_eq!(a.member_count().await, 2);
    assert_eq!(
        ciris_edge::contact::the_other_member(&a.member_key_ids().await, &alice.fed_id).as_deref(),
        Some(bob.fed_id.as_str()),
        "Alice's room reads 'Chat with Bob'"
    );

    // 6. And they hold the same key, so a message can actually cross.
    assert_eq!(
        a.destination_secret().await.unwrap().as_bytes(),
        b.destination_secret().await.unwrap().as_bytes()
    );
}
