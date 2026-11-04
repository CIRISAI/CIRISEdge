//! **v44 carriage witness (CIRISConstitution#198 §5; FSD
//! `QUORUM_AND_PENDING_DECISIONS.md` §2): edge carries the rows and their
//! cosignatures, and persist's door gives the SAME verdict on every node.**
//!
//! Four SQLite substrates, each behind its own replication bridge. They share
//! nothing but what the test carries between the bridges' serve reads and
//! apply doors. Edge evaluates no quorum here: each node's own persist door
//! decides, under the room's `consensus_protocol`.
//!
//! 1. **A room of one grows by the founder's proposal plus the newcomer's
//!    acceptance.** K accepts on K's node; the acceptance crosses to the
//!    founder's node, whose widener offers the founder's one voice. That is
//!    enough in a room of one: the acceptance is the second voice (CC
//!    3.1.3.2). The landed widening crosses back, K is seated on every node,
//!    and the decision-row event marks the pair complete.
//! 2. **Enough voices land at once, on every node.** In a `majority` room of
//!    three, two cosignatures seat a fourth member. The cosigned row is
//!    admitted wherever it is carried, and the cosignatures arrive
//!    byte-identical (C2).
//! 3. **A short set lands nowhere.** One voice of three is refused by every
//!    node's door.
//! 4. **Carriage that strips a cosignature changes the outcome** (the
//!    mutation): the stripped row is refused on the node it reaches, and the
//!    intact one is admitted.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_edge::community_roster::{assemble, cosign, cosign_all, RosterEvent};
use ciris_edge::decision_rows::{decision_rows_since, DecisionRowKind};
use ciris_edge::membership::{self, GroupScope, MembershipWidener};
use ciris_edge::replication::bridge::FederationDirectoryReplicationBridge;
use ciris_edge::replication::directory::ReplicationDirectory as _;
use ciris_edge::replication::protocol::EnvelopeKind;
use ciris_edge::replication::summary::ApplyOutcome;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
use ciris_persist::federation::types::consensus_protocol;
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
        .expect("ts")
        .into()
}

fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
    ts() + chrono::Duration::seconds(secs)
}

fn signer(label: &str, seed: u8) -> ciris_edge::identity::LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], label).expect("ed25519"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{label}-pqc"))
            .expect("ml-dsa-65"),
    );
    let pubkey = futures::executor::block_on(classical.public_key()).expect("ed pubkey");
    let key_id = ciris_verify_core::fedcode::derive_key_id(label, &pubkey);
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

/// One node: its substrate (every party's keys and owner bindings held) and
/// its bridge.
struct Node {
    dir: Arc<SqliteBackend>,
    // Boxed: the fixtures pass `[Node; 4]` by value.
    bridge: Box<FederationDirectoryReplicationBridge>,
}

async fn node(me: &Party, all: &[&Party], widener: Option<MembershipWidener>) -> Node {
    let dir = FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open");
    dir.run_migrations().await.expect("migrate");
    for p in all {
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
    for p in all {
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
    let publish = vec![me.node.key_id.clone(), me.person.key_id.clone()];
    let bridge = FederationDirectoryReplicationBridge::new(
        dir.clone() as Arc<dyn FederationDirectory>,
        Arc::new(Vec::<String>::new),
    )
    .with_local_key_id(Some(me.node.key_id.clone()))
    .with_self_provider(Some(Arc::new(move || publish.clone())))
    .with_membership_widener(widener);
    Node {
        dir,
        bridge: Box::new(bridge),
    }
}

/// The room, founded by `founder` alone under `protocol`, held on every node
/// (the record is the same signed object everywhere).
async fn found_room(founder: &Party, protocol: &str, nodes: &[&Node]) -> String {
    let room = ciris_edge::chat::new_room_community_key_id();
    let record = ciris_edge::chat::community(
        &room,
        "the room",
        &[(&founder.person.key_id, Some(MEMBER_ROLE_FOUNDER))],
        protocol,
        ts(),
    )
    .expect("record");
    let signed = ciris_edge::chat::signed_community(record, &founder.person)
        .await
        .expect("sign");
    for n in nodes {
        n.dir
            .put_community(signed.clone())
            .await
            .expect("persist admits the room");
    }
    room
}

/// The rows `from` serves that satisfy `pred`, as wire bytes, in serve order.
async fn served(
    from: &FederationDirectoryReplicationBridge,
    pred: impl Fn(&Attestation) -> bool,
) -> Vec<(Attestation, Vec<u8>)> {
    let kind = EnvelopeKind::Attestation;
    let mut out = Vec::new();
    for r in from.list_envelope_refs(kind).await {
        let bytes = from
            .fetch_envelope_bytes(kind, &r.envelope_hash)
            .await
            .expect("an advertised envelope is fetchable");
        let Ok(row) = serde_json::from_slice::<Attestation>(&bytes) else {
            continue;
        };
        if pred(&row) {
            out.push((row, bytes));
        }
    }
    out
}

fn dimension(row: &Attestation) -> &str {
    row.attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

fn in_room(room: &str) -> impl Fn(&Attestation) -> bool + '_ {
    move |row| {
        row.attestation_envelope
            .get("community_key_id")
            .and_then(serde_json::Value::as_str)
            == Some(room)
            && (dimension(row).starts_with("membership:") || dimension(row).starts_with("group:"))
    }
}

/// Carry every membership/roster row of `room` from `from` to `to`, twice
/// over (a row refused retryably because its dependency had not crossed yet
/// is admitted on the second pass). Returns the last pass's outcomes.
async fn carry_room(
    from: &FederationDirectoryReplicationBridge,
    to: &FederationDirectoryReplicationBridge,
    room: &str,
) -> Vec<ApplyOutcome> {
    let rows = served(from, in_room(room)).await;
    let mut last = Vec::new();
    for _pass in 0..2 {
        last.clear();
        for (_, bytes) in &rows {
            last.push(
                to.apply_envelope_bytes(EnvelopeKind::Attestation, bytes, None)
                    .await,
            );
        }
    }
    last
}

async fn active(dir: &SqliteBackend, room: &str) -> Vec<String> {
    let mut m: Vec<String> = dir
        .active_community_members(room)
        .await
        .expect("roster")
        .into_iter()
        .map(|m| m.key_id)
        .collect();
    m.sort();
    m
}

fn sorted(keys: &[&Party]) -> Vec<String> {
    let mut v: Vec<String> = keys.iter().map(|p| p.person.key_id.clone()).collect();
    v.sort();
    v
}

/// `who` consents on the room's founding node: a proposal by `by`, accepted
/// by `who` (setup: both rows written where the founder's history is built).
async fn consent(dir: &SqliteBackend, room: &str, by: &Party, who: &Party) {
    let p = membership::propose(
        dir,
        GroupScope::Community,
        room,
        &who.person.key_id,
        None,
        chrono::Utc::now() + chrono::Duration::days(7),
        &by.person,
    )
    .await
    .expect("proposal");
    membership::reply(dir, &p.attestation_id, true, &who.person)
        .await
        .expect("acceptance");
}

/// **1. A room of one grows by proposal + acceptance, carried across nodes,
/// and lands on every node.** The event on the founder's node marks the
/// pair complete (`RosterLanded` naming the proposal).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_room_of_one_grows_by_proposal_and_acceptance_on_every_node() {
    let alice = party("alice", 0x11);
    let kay = party("kay", 0x22);
    let all = [&alice, &kay];
    let a = node(
        &alice,
        &all,
        Some(MembershipWidener::new(vec![Arc::clone(&alice.person)])),
    )
    .await;
    let k = node(&kay, &all, None).await;
    let room = found_room(&alice, consensus_protocol::MAJORITY, &[&a, &k]).await;
    let mut events = a.bridge.subscribe_decision_rows();

    // The founder proposes on her node; the proposal crosses to K's node.
    let proposal = membership::propose(
        &*a.dir,
        GroupScope::Community,
        &room,
        &kay.person.key_id,
        None,
        chrono::Utc::now() + chrono::Duration::days(7),
        &alice.person,
    )
    .await
    .expect("propose");
    let landed = k
        .bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(&proposal).expect("wire"),
            Some(&alice.node.key_id),
        )
        .await;
    assert!(
        landed.is_admitted(),
        "the invitee's node holds the proposal: {landed:?}"
    );

    // K accepts on K's node; the acceptance crosses to the founder's node,
    // whose widener offers the founder's one voice.
    let acceptance = membership::reply(&*k.dir, &proposal.attestation_id, true, &kay.person)
        .await
        .expect("K accepts");
    let back = a
        .bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(&acceptance).expect("wire"),
            Some(&kay.node.key_id),
        )
        .await;
    assert!(back.is_admitted(), "{back:?}");
    assert_eq!(active(&a.dir, &room).await, sorted(&[&alice, &kay]));

    // The landed widening crosses back: K is seated on K's node too.
    let outcomes = carry_room(&a.bridge, &k.bridge, &room).await;
    assert!(!outcomes.is_empty());
    assert_eq!(
        active(&k.dir, &room).await,
        sorted(&[&alice, &kay]),
        "persist lands K on every node: {outcomes:?}"
    );

    // The event stream named the reply AND the landed widening, the latter
    // carrying the proposal it completes.
    let mut seen = Vec::new();
    while let Ok(e) = events.try_recv() {
        seen.push(e);
    }
    assert!(
        seen.iter()
            .any(|e| e.kind == DecisionRowKind::MembershipReply
                && e.proposal_id.as_deref() == Some(proposal.attestation_id.as_str())),
        "{seen:?}"
    );
    assert!(
        seen.iter().any(|e| e.kind == DecisionRowKind::RosterLanded
            && e.scope_id.as_deref() == Some(room.as_str())
            && e.proposal_id.as_deref() == Some(proposal.attestation_id.as_str())),
        "the widening marks the pair complete: {seen:?}"
    );

    // A rebuild from any event's cursor names the same rows.
    let from = seen.first().expect("an event").cursor.clone();
    let (rebuilt, _) = decision_rows_since(&*a.dir, Some(from), 1000)
        .await
        .expect("rebuild");
    for e in &seen {
        assert!(
            rebuilt.iter().any(|r| r.attestation_id == e.attestation_id),
            "the cursor rebuild covers {e:?}"
        );
    }
}

/// A `majority` room of three (alice, bob, carol) on four nodes, with dave
/// consented and his acceptance carried everywhere. Returns the parties,
/// nodes and room.
async fn room_of_three_plus_dave() -> ([Party; 4], [Node; 4], String) {
    let alice = party("alice", 0x11);
    let bob = party("bob", 0x22);
    let carol = party("carol", 0x33);
    let dave = party("dave", 0x44);
    let all = [&alice, &bob, &carol, &dave];
    let na = node(&alice, &all, None).await;
    let nb = node(&bob, &all, None).await;
    let nc = node(&carol, &all, None).await;
    let nd = node(&dave, &all, None).await;
    let room = found_room(&alice, consensus_protocol::MAJORITY, &[&na, &nb, &nc, &nd]).await;
    // History on alice's node: bob (one voice of one), carol (two of two).
    consent(&na.dir, &room, &alice, &bob).await;
    assert!(ciris_edge::community_roster::widen_community(
        &*na.dir,
        &room,
        &bob.person.key_id,
        None,
        at(1),
        &[&alice.person],
    )
    .await
    .expect("bob"));
    consent(&na.dir, &room, &alice, &carol).await;
    assert!(ciris_edge::community_roster::widen_community(
        &*na.dir,
        &room,
        &carol.person.key_id,
        None,
        at(2),
        &[&alice.person, &bob.person],
    )
    .await
    .expect("carol"));
    consent(&na.dir, &room, &alice, &dave).await;
    for n in [&nb, &nc, &nd] {
        carry_room(&na.bridge, &n.bridge, &room).await;
    }
    for n in [&na, &nb, &nc] {
        assert_eq!(
            active(&n.dir, &room).await,
            sorted(&[&alice, &bob, &carol]),
            "the room of three on every member's node"
        );
    }
    ([alice, bob, carol, dave], [na, nb, nc, nd], room)
}

/// **2–4. Two voices of three land at once on every node, byte-identical;
/// one voice lands nowhere; a stripped cosignature is refused where it is
/// carried.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole flow, in order, on purpose
async fn a_cosigned_widening_lands_alike_everywhere_and_a_short_set_nowhere() {
    let ([alice, bob, carol, dave], [na, nb, nc, nd], room) =
        Box::pin(room_of_three_plus_dave()).await;
    let event = RosterEvent::widening(&room, &dave.person.key_id, None, at(3));

    // 3. One voice of three: every node's door refuses it, alike.
    for n in [&na, &nb, &nc] {
        let err = assemble(
            &*n.dir,
            &event,
            vec![cosign(&event, &alice.person).await.expect("sign")],
        )
        .await
        .expect_err("one voice of three never seats under majority");
        assert!(
            err.contains(ciris_persist::federation::ROSTER_CONSENSUS_INSUFFICIENT),
            "{err}"
        );
        assert!(!active(&n.dir, &room).await.contains(&dave.person.key_id));
    }

    // 2. Two voices, each made with its own pen, assembled on bob's node.
    let voices = vec![
        cosign(&event, &bob.person).await.expect("bob, on his node"),
        cosign(&event, &carol.person).await.expect("carol, on hers"),
    ];
    let before = chrono::Utc::now();
    let mut events = nb.bridge.subscribe_decision_rows();
    assert!(assemble(&*nb.dir, &event, voices)
        .await
        .expect("persist admits two of three"));
    let reported = nb
        .bridge
        .note_local_writes_since(before, None)
        .await
        .expect("scan");
    assert!(
        reported
            .iter()
            .any(|r| r.kind == DecisionRowKind::RosterLanded
                && r.scope_id.as_deref() == Some(room.as_str())),
        "the local write is reported: {reported:?}"
    );
    assert!(events.try_recv().is_ok(), "and emitted on the stream");

    let rows = served(&nb.bridge, |r| {
        in_room(&room)(r) && dimension(r).starts_with("membership:widening:")
    })
    .await;
    let (dave_row, dave_bytes) = rows
        .iter()
        .find(|(r, _)| {
            r.attestation_envelope
                .to_string()
                .contains(&dave.person.key_id)
        })
        .cloned()
        .expect("bob's node serves dave's widening");

    // 4. The mutation: strip one cosignature in carriage. Carol's node
    // refuses the stripped row; dave is not seated there.
    let mut stripped: serde_json::Value = serde_json::from_slice(&dave_bytes).expect("json");
    let scrubs = stripped
        .get_mut("additional_scrubs")
        .and_then(serde_json::Value::as_array_mut)
        .expect("the cosigned row carries additional_scrubs");
    assert_eq!(scrubs.len(), 1, "one cosignature beside the authority");
    scrubs.clear();
    let refused = nc
        .bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(&stripped).expect("wire"),
            Some(&bob.node.key_id),
        )
        .await;
    assert!(
        !refused.is_admitted(),
        "a stripped cosign is refused: {refused:?}"
    );
    assert!(!active(&nc.dir, &room).await.contains(&dave.person.key_id));

    // The intact row lands on every node, and every node serves it with the
    // same cosignatures it was signed with (C2).
    for n in [&na, &nc, &nd] {
        let outcome = n
            .bridge
            .apply_envelope_bytes(
                EnvelopeKind::Attestation,
                &dave_bytes,
                Some(&bob.node.key_id),
            )
            .await;
        assert!(
            matches!(outcome, ApplyOutcome::Admitted | ApplyOutcome::Duplicate),
            "{outcome:?}"
        );
    }
    let want = sorted(&[&alice, &bob, &carol, &dave]);
    for n in [&na, &nb, &nc, &nd] {
        assert_eq!(
            active(&n.dir, &room).await,
            want,
            "the same verdict on every node"
        );
        let again = served(&n.bridge, |r| r.attestation_id == dave_row.attestation_id).await;
        let (_, bytes) = again.first().expect("every node serves the landed row");
        let theirs: serde_json::Value = serde_json::from_slice(bytes).expect("json");
        let ours: serde_json::Value = serde_json::from_slice(&dave_bytes).expect("json");
        assert_eq!(
            theirs.get("additional_scrubs"),
            ours.get("additional_scrubs"),
            "cosignatures travel unaltered"
        );
    }

    // A second assembly of the same event elsewhere is the door's no-op: one
    // row, not two.
    let voices = cosign_all(&event, &[&alice.person, &carol.person])
        .await
        .expect("sign");
    assert!(!assemble(&*na.dir, &event, voices).await.expect("no-op"));
    assert_eq!(
        na.dir
            .list_community_membership_widenings_for(&room)
            .await
            .expect("list")
            .iter()
            .filter(|w| w.member_key_id == dave.person.key_id)
            .count(),
        1,
        "concurrent assembly yields one row"
    );
}
