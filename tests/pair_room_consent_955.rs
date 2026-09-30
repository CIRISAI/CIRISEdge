//! **persist v52.0.0 (CIRISPersist#955, CIRISConstitution#133) — nobody joins a
//! room without their own consent, across two real nodes.**
//!
//! Two SQLite substrates, each with its own replication bridge, sharing
//! nothing but what the test hands across (the bridges' apply doors and serve
//! reads, never a direct `put` on the far side):
//!
//! 1. Alice's node opens the pair room with Bob: the room is founded with
//!    Alice ALONE, and a proposal offers Bob `founder`.
//! 2. The proposal reaches Bob's node; Bob's node accepts for Bob.
//! 3. The acceptance reaches Alice's node, whose bridge — carrying a
//!    `MembershipWidener` for Alice — widens the roster on arrival.
//! 4. The widening reaches Bob's node. Both nodes read Bob as a founder.
//! 5. A room row authored by Bob is refused by Alice's node before the
//!    widening and admitted after it.
//! 6. Carol declines a proposal into her own pair room: she stays out, and a
//!    later widening naming her is refused BY NAME (`membership_declined`,
//!    terminal).

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::chat;
use ciris_edge::membership::{self, GroupScope, MembershipWidener};
use ciris_edge::replication::bridge::FederationDirectoryReplicationBridge;
use ciris_edge::replication::directory::ReplicationDirectory as _;
use ciris_edge::replication::protocol::EnvelopeKind;
use ciris_edge::replication::summary::ApplyOutcome;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .expect("ts")
        .into()
}

/// One hybrid keypair from a seed, as an edge signer under `key_id`.
fn signer(key_id: &str, seed: u8) -> ciris_edge::identity::LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).expect("ed25519"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
            .expect("ml-dsa-65"),
    );
    ciris_edge::identity::LocalSigner::new(key_id, classical, Some(pqc))
}

async fn record(s: &ciris_edge::identity::LocalSigner, identity_type: &str) -> KeyRecord {
    let ed = B64.encode(s.classical.public_key().await.expect("ed pubkey"));
    let pqc = B64.encode(
        s.pqc
            .as_ref()
            .expect("hybrid")
            .public_key()
            .await
            .expect("pqc pubkey"),
    );
    let envelope = serde_json::json!({ "key_id": s.key_id });
    let canonical = serde_json::to_vec(&envelope).expect("json");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(&canonical);
    let (sig, sig_pqc) =
        ciris_edge::identity::sign_bound_hybrid(s, digest.as_slice(), "key record")
            .await
            .expect("sign");
    KeyRecord {
        key_id: s.key_id.clone(),
        pubkey_ed25519_base64: ed,
        pubkey_ml_dsa_65_base64: Some(pqc),
        algorithm: "hybrid".to_owned(),
        identity_type: identity_type.to_owned(),
        identity_ref: s.key_id.clone(),
        valid_from: ts(),
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: s.key_id.clone(),
        scrub_timestamp: ts(),
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: None,
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// A person and the node they own.
struct Party {
    person: Arc<ciris_edge::identity::LocalSigner>,
    node: Arc<ciris_edge::identity::LocalSigner>,
}

fn party(name: &str, seed: u8) -> Party {
    Party {
        person: Arc::new(signer(&format!("{name}-fed"), seed)),
        node: Arc::new(signer(&format!("{name}-node"), seed.wrapping_add(0x40))),
    }
}

/// One node's substrate: every party's person and node key registered, and
/// every owner binding held (what the Key and Attestation planes carry).
async fn substrate(parties: &[&Party]) -> Arc<SqliteBackend> {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open");
    dir.run_migrations().await.expect("migrate");
    for p in parties {
        dir.put_public_key(SignedKeyRecord {
            record: record(&p.person, "user").await,
        })
        .await
        .expect("register person");
        dir.put_public_key(SignedKeyRecord {
            record: record(&p.node, "node").await,
        })
        .await
        .expect("register node");
    }
    for p in parties {
        let binding = ciris_edge::replication::attestation_bind::owner_binding_attestation(
            &p.person.key_id,
            &p.node.key_id,
            ts(),
            &p.person,
        )
        .await
        .expect("owner binding");
        dir.put_attestation(SignedAttestation {
            attestation: binding,
        })
        .await
        .expect("admit owner binding");
    }
    dir
}

/// A node's bridge: `me` is its node key; `widener` the persons it widens for.
fn bridge(
    dir: &Arc<SqliteBackend>,
    me: &Party,
    widener: Option<MembershipWidener>,
) -> FederationDirectoryReplicationBridge {
    let publish = vec![me.node.key_id.clone(), me.person.key_id.clone()];
    FederationDirectoryReplicationBridge::new(
        dir.clone() as Arc<dyn FederationDirectory>,
        Arc::new(Vec::<String>::new),
    )
    .with_local_key_id(Some(me.node.key_id.clone()))
    .with_self_provider(Some(Arc::new(move || publish.clone())))
    .with_membership_widener(widener)
}

async fn deliver_row(
    to: &FederationDirectoryReplicationBridge,
    row: &Attestation,
    from: &Party,
) -> ApplyOutcome {
    to.apply_envelope_bytes(
        EnvelopeKind::Attestation,
        &serde_json::to_vec(row).expect("wire"),
        Some(&from.node.key_id),
    )
    .await
}

/// Carry every `kind` envelope `from` serves to `to`'s apply door, byte-exact.
async fn carry_plane(
    from: &FederationDirectoryReplicationBridge,
    to: &FederationDirectoryReplicationBridge,
    kind: EnvelopeKind,
) -> Vec<ApplyOutcome> {
    let mut out = Vec::new();
    for r in from.list_envelope_refs(kind).await {
        let bytes = from
            .fetch_envelope_bytes(kind, &r.envelope_hash)
            .await
            .expect("an advertised envelope is fetchable");
        out.push(to.apply_envelope_bytes(kind, &bytes, None).await);
    }
    out
}

async fn roster(dir: &SqliteBackend, room: &str) -> Vec<(String, Option<String>)> {
    let mut m: Vec<(String, Option<String>)> = dir
        .active_community_members(room)
        .await
        .expect("roster")
        .into_iter()
        .map(|m| (m.key_id, m.role))
        .collect();
    m.sort();
    m
}

/// A federation-tier `chat:message:v1` row in `room`, authored and signed by
/// `author` — the placement AV-45 judges by the author's membership.
async fn room_row(room: &str, author: &ciris_edge::identity::LocalSigner) -> Attestation {
    use ciris_persist::federation::attestation_emit;
    let mut extra = serde_json::Map::new();
    extra.insert("community_key_id".into(), room.into());
    extra.insert("score".into(), 1.0.into());
    let envelope = ciris_persist::federation::envelope::EnvelopeCore {
        dimension: Some(chat::CHAT_MESSAGE_DIMENSION.to_owned()),
        extra,
        ..Default::default()
    };
    let mut input = ciris_persist::federation::EmitAttestationInput::with_envelope(
        "scores",
        envelope,
        "community",
    );
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, &author.key_id, chrono::Utc::now())
            .expect("stamp");
    let sig = ciris_edge::identity::sign_hybrid_raw(author, &canonical, "room row")
        .await
        .expect("sign");
    attestation_emit::assemble(author.key_id.clone(), &canonical, sig, input)
        .expect("assemble")
        .0
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole flow, in order, on purpose
async fn a_pair_room_is_joined_by_proposal_acceptance_and_widening_across_two_nodes() {
    let alice = party("alice", 0x11);
    let bob = party("bob", 0x22);
    let dir_a = substrate(&[&alice, &bob]).await;
    let dir_b = substrate(&[&alice, &bob]).await;
    let bridge_a = bridge(
        &dir_a,
        &alice,
        Some(MembershipWidener::new(vec![Arc::clone(&alice.person)])),
    );
    let bridge_b = bridge(&dir_b, &bob, None);

    // 1. Alice's node opens the room: founded with Alice alone, Bob proposed.
    let opened = chat::open_pair_room(
        &*dir_a,
        &alice.person.key_id,
        &bob.person.key_id,
        ts(),
        chrono::Utc::now() + chrono::Duration::days(7),
        &alice.node,
    )
    .await
    .expect("open the pair room");
    assert!(opened.founded);
    let room = opened.room.clone();
    let proposal = opened.proposal.clone().expect("bob is proposed");
    assert_eq!(
        roster(&dir_a, &room).await,
        [(
            alice.person.key_id.clone(),
            Some(MEMBER_ROLE_FOUNDER.into())
        )],
        "the founding record lists its opener alone"
    );
    // Idempotent: a second open returns the same live proposal.
    let again = chat::open_pair_room(
        &*dir_a,
        &alice.person.key_id,
        &bob.person.key_id,
        ts(),
        chrono::Utc::now() + chrono::Duration::days(7),
        &alice.node,
    )
    .await
    .expect("re-open");
    assert!(!again.founded);
    assert_eq!(
        again.proposal.map(|p| p.attestation_id),
        Some(proposal.attestation_id.clone())
    );

    // A room row from Bob is refused before he is a member.
    let early = room_row(&room, &bob.person).await;
    assert!(
        !deliver_row(&bridge_a, &early, &bob).await.is_admitted(),
        "bob is not a member yet"
    );

    // 2. The room record and the proposal reach Bob's node through its doors.
    assert!(carry_plane(&bridge_a, &bridge_b, EnvelopeKind::Community)
        .await
        .iter()
        .all(ApplyOutcome::is_admitted));
    assert!(
        deliver_row(&bridge_b, &proposal, &alice)
            .await
            .is_admitted(),
        "the proposal is admitted on the invitee's node"
    );
    let pending = chat::pair_proposal_for(&*dir_b, &bob.person.key_id, &alice.person.key_id)
        .await
        .expect("inbox")
        .expect("bob's node holds the proposal naming him");
    assert_eq!(pending.role.as_deref(), Some(MEMBER_ROLE_FOUNDER));
    assert_eq!(pending.group_key_id, room);
    let acceptance = chat::accept_pair_proposal(
        &*dir_b,
        &pending.proposal.attestation_id,
        &bob.node, // a device acting for its person
    )
    .await
    .expect("bob's node accepts for bob");
    assert!(
        chat::pair_proposal_for(&*dir_b, &bob.person.key_id, &alice.person.key_id)
            .await
            .expect("inbox")
            .is_none()
    );

    // 3. The acceptance reaches Alice's node; its bridge widens on arrival.
    assert!(deliver_row(&bridge_a, &acceptance, &bob)
        .await
        .is_admitted());
    let mut want = vec![
        (
            alice.person.key_id.clone(),
            Some(MEMBER_ROLE_FOUNDER.into()),
        ),
        (bob.person.key_id.clone(), Some(MEMBER_ROLE_FOUNDER.into())),
    ];
    want.sort();
    assert_eq!(
        roster(&dir_a, &room).await,
        want,
        "alice's node widened bob in as a founder"
    );
    // A re-applied acceptance widens nothing twice.
    let _ = deliver_row(&bridge_a, &acceptance, &bob).await;
    assert_eq!(roster(&dir_a, &room).await, want);

    // 4. The widening reaches Bob's node: both read Bob as a founder.
    let applied = carry_plane(
        &bridge_a,
        &bridge_b,
        EnvelopeKind::CommunityMembershipWidening,
    )
    .await;
    assert_eq!(applied.len(), 1, "one widening");
    assert!(applied[0].is_admitted(), "{:?}", applied[0]);
    assert_eq!(roster(&dir_b, &room).await, want, "bob's node reads it too");

    // 5. A room row from Bob is admitted now.
    let late = room_row(&room, &bob.person).await;
    let outcome = deliver_row(&bridge_a, &late, &bob).await;
    assert!(outcome.is_admitted(), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declined_proposal_leaves_the_invitee_out_and_refuses_a_later_widening_by_name() {
    let alice = party("alice", 0x11);
    let carol = party("carol", 0x33);
    let dir_a = substrate(&[&alice, &carol]).await;
    let dir_c = substrate(&[&alice, &carol]).await;
    let bridge_a = bridge(
        &dir_a,
        &alice,
        Some(MembershipWidener::new(vec![Arc::clone(&alice.person)])),
    );
    let bridge_c = bridge(&dir_c, &carol, None);

    let opened = chat::open_pair_room(
        &*dir_a,
        &alice.person.key_id,
        &carol.person.key_id,
        ts(),
        chrono::Utc::now() + chrono::Duration::days(7),
        &alice.node,
    )
    .await
    .expect("open");
    let proposal = opened.proposal.expect("carol proposed");
    assert!(deliver_row(&bridge_c, &proposal, &alice)
        .await
        .is_admitted());
    let decline = chat::decline_pair_proposal(&*dir_c, &proposal.attestation_id, &carol.node)
        .await
        .expect("carol declines");
    assert!(deliver_row(&bridge_a, &decline, &carol).await.is_admitted());
    assert_eq!(
        roster(&dir_a, &opened.room).await,
        [(
            alice.person.key_id.clone(),
            Some(MEMBER_ROLE_FOUNDER.into())
        )],
        "a decline widens nothing"
    );
    let err = membership::widen(
        &*dir_a,
        GroupScope::Community,
        &opened.room,
        &carol.person.key_id,
        Some(MEMBER_ROLE_FOUNDER),
        chrono::Utc::now(),
        &alice.person,
    )
    .await
    .expect_err("a widening after a decline is refused");
    assert_eq!(err.rule(), Some(membership::RULE_DECLINED), "{err}");
    assert!(!err.is_retryable(), "a decline is terminal");
    // And once declined, the proposal is gone from carol's inbox.
    assert!(
        chat::pair_proposal_for(&*dir_c, &carol.person.key_id, &alice.person.key_id)
            .await
            .expect("inbox")
            .is_none()
    );
}
