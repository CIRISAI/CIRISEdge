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
//! 5. **A duty is an appointment** (persist v61.0.2): a plain member's
//!    moderation act and takedown are refused everywhere, a founder's and a
//!    delegate's pass, and a delegate's act that outran its appointment lands
//!    with it.
//! 6. **A `unanimous` removal is every other member**; at two nobody is
//!    removable and resignation is the exit.
//! 7. **A moderator's removal that outran its appointment lands with it.**
//! 8. **Rule 0:** one signer never withdraws a cosigned row.

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
use ciris_edge::replication::refusal_backoff::RetryDisposition;
use ciris_edge::replication::summary::ApplyOutcome;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::admission::DelegationTermBounds;
use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
use ciris_persist::federation::attestation_emit;
use ciris_persist::federation::envelope::EnvelopeCore;
use ciris_persist::federation::types::{attestation_type, cohort_scope, consensus_protocol};
use ciris_persist::federation::{
    Attestation, EmitAttestationInput, FederationDirectory, SignedAttestation,
};
use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::Digest as _;

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

// ── Duties are appointments (persist v61.0.2, CIRISPersist#1195) ─────────────

/// One row, signed by `pen` through persist's own emit recipe.
async fn signed_row(
    mut input: EmitAttestationInput,
    pen: &ciris_edge::identity::LocalSigner,
) -> Attestation {
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, &pen.key_id, chrono::Utc::now())
            .expect("stamp");
    let sig = ciris_edge::identity::sign_hybrid_raw(pen, &canonical, "witness row")
        .await
        .expect("sign");
    attestation_emit::assemble(pen.key_id.clone(), &canonical, sig, input)
        .expect("assemble")
        .0
}

/// The edge a host signs to appoint: `Engine::add_moderator`'s shape, a
/// `delegates_to` keyed by its recipient, at `federation`, under a term.
async fn appoint(by: &Party, to: &Party, duty: &str) -> Attestation {
    let mut envelope = ciris_persist::federation::delegates_to_envelope(
        &to.person.key_id,
        &[duty.to_owned()],
        true,
    );
    DelegationTermBounds::until(chrono::Utc::now() + chrono::Duration::days(90))
        .stamp(&mut envelope);
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::DELEGATES_TO,
        EnvelopeCore::from_value(envelope).expect("object"),
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(to.person.key_id.clone());
    signed_row(input, &by.person).await
}

/// A moderation act on `target` in `room`: the row CIRISServer's
/// `emit_moderation_event` puts on the mesh.
async fn moderation_act(by: &Party, room: &str, target: &Party, tag: &str) -> Attestation {
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        EnvelopeCore::from_value(serde_json::json!({
            "dimension": "moderation:conduct:v1",
            "community_id": room,
            "allegation_type": "conduct",
            "payload": { "tag": tag },
        }))
        .expect("object"),
        cohort_scope::FEDERATION,
    );
    input.attested_key_id = Some(target.person.key_id.clone());
    input.subject_key_ids = vec![target.person.key_id.clone()];
    signed_row(input, &by.person).await
}

/// `author`'s row in `room` binding `sha`, the envelope naming the room by
/// `member`.
async fn content_row(author: &Party, room: &str, member: &str, sha: &str) -> Attestation {
    let mut envelope = serde_json::json!({
        "dimension": "content:established:v1",
        "score": 1.0,
        "confidence": 1.0,
        "evidence_refs": [sha],
    });
    envelope[member] = room.into();
    signed_row(
        EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            EnvelopeCore::from_value(envelope).expect("object"),
            cohort_scope::COMMUNITY,
        ),
        &author.person,
    )
    .await
}

/// A `takedown_notice:dmca512:v1` row signed by `by` over `sha`.
async fn takedown_notice(by: &Party, sha: &str) -> Attestation {
    let basis = "dmca512";
    let mut input = EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        EnvelopeCore::from_value(serde_json::json!({
            "dimension": ciris_persist::federation::takedown_tombstone::notice_dimension(basis),
            "score": -1.0,
            "confidence": 1.0,
            "subject_kind": "takedown_notice",
            "content_sha256": sha,
            "claimant_key_id": by.person.key_id,
            "legal_basis": basis,
            "jurisdiction": "US",
            "good_faith_statement": "good faith",
            "claim_text": "claim",
        }))
        .expect("object"),
        cohort_scope::FEDERATION,
    );
    input.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(30));
    signed_row(input, &by.person).await
}

/// `who` joins `room` on `founding`'s node: consent, then every seated voice.
async fn seat(
    founding: &Node,
    room: &str,
    founder: &Party,
    seated: &[&Party],
    who: &Party,
    n: i64,
) {
    consent(&founding.dir, room, founder, who).await;
    let pens: Vec<&ciris_edge::identity::LocalSigner> = seated.iter().map(|p| &*p.person).collect();
    assert!(ciris_edge::community_roster::widen_community(
        &*founding.dir,
        room,
        &who.person.key_id,
        None,
        at(n),
        &pens,
    )
    .await
    .expect("every seated voice seats a member"));
}

async fn apply(to: &Node, row: &Attestation, from: &Party) -> ApplyOutcome {
    to.bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &serde_json::to_vec(row).expect("wire"),
            Some(&from.node.key_id),
        )
        .await
}

#[track_caller]
fn refused_as(outcome: &ApplyOutcome, token: &str) -> RetryDisposition {
    let ApplyOutcome::Refused { reason, retry, .. } = outcome else {
        panic!("expected a refusal naming {token}: {outcome:?}");
    };
    assert!(reason.contains(token), "expected {token}: {reason}");
    *retry
}

async fn held(n: &Node, row: &Attestation) -> bool {
    n.dir
        .get_attestation(&row.attestation_id)
        .await
        .expect("read")
        .is_some()
}

/// A room of seven under `protocol` on three nodes: alice founds it; mo and
/// tess are seated and will be appointed; bob, carol and dave stay plain
/// members; zoe authors the content, which makes her its subject and so a
/// takedown holder in her own right.
struct DutyRoom {
    alice: Party,
    bob: Party,
    carol: Party,
    dave: Party,
    mo: Party,
    tess: Party,
    zoe: Party,
    nodes: [Node; 3],
    room: String,
}

async fn duty_room(protocol: &str) -> DutyRoom {
    let alice = party("alice", 0x11);
    let bob = party("bob", 0x22);
    let carol = party("carol", 0x33);
    let dave = party("dave", 0x44);
    let mo = party("mo", 0x55);
    let tess = party("tess", 0x66);
    let zoe = party("zoe", 0x77);
    let all = [&alice, &bob, &carol, &dave, &mo, &tess, &zoe];
    let na = node(&alice, &all, None).await;
    let nb = node(&bob, &all, None).await;
    let nm = node(&mo, &all, None).await;
    let room = found_room(&alice, protocol, &[&na, &nb, &nm]).await;
    for (i, who) in all[1..].iter().copied().enumerate() {
        let n = i64::try_from(i + 1).expect("a small room");
        seat(&na, &room, &alice, &all[..=i], who, n).await;
    }
    for n in [&nb, &nm] {
        carry_room(&na.bridge, &n.bridge, &room).await;
        assert_eq!(
            active(&n.dir, &room).await.len(),
            7,
            "{protocol}: the room lands on every node"
        );
    }
    DutyRoom {
        alice,
        bob,
        carol,
        dave,
        mo,
        tess,
        zoe,
        nodes: [na, nb, nm],
        room,
    }
}

const DUTY_REFUSED: &str = "federation_delegated_scope_unauthorized";
const TAKEDOWN_REFUSED: &str = "takedown_unauthorised";

/// **5. A duty is an appointment, at every protocol, on every node** (persist
/// v61.0.2, CIRISPersist#1195; CC 4.5.4, 4.5.13). Each plain member of a room
/// of seven signs for the room and holds no duty: their moderation act and their
/// takedown are refused by every node's door and not held. The founder's pass.
/// A delegate's pass exactly where the appointment is held, and an act that
/// outran its appointment lands when the appointment does, because the refusal
/// is transient at the carriage layer. A delegated duty confers no other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the whole flow, per protocol, on purpose
async fn a_duty_is_an_appointment_at_every_protocol_on_every_node() {
    use ciris_persist::federation::admission::{
        community_authority_set_for, moderators_of, DELEGATION_SCOPE_MODERATE,
        DELEGATION_SCOPE_REVIEW, DELEGATION_SCOPE_TAKEDOWN,
    };
    for protocol in [
        consensus_protocol::MAJORITY,
        consensus_protocol::UNANIMOUS,
        // M is absolute, and a room edge founds has one signer: a larger M
        // could not seat its second member. One voice signing for the room is
        // also the sharpest case for "a signer holds no duty".
        "quorum:1/4",
    ] {
        let r = Box::pin(duty_room(protocol)).await;
        let room = r.room.as_str();
        let [na, nb, nm] = &r.nodes;
        let plain = [&r.bob, &r.carol, &r.dave];
        let sha = hex::encode(sha2::Sha256::digest(protocol.as_bytes()));
        let content = content_row(&r.zoe, room, "community_id", &sha).await;
        for n in &r.nodes {
            let bound = apply(n, &content, &r.zoe).await;
            assert!(
                matches!(bound, ApplyOutcome::Admitted | ApplyOutcome::Duplicate),
                "{protocol}: {bound:?}"
            );
        }

        // Who may sign is a different question, and it is unchanged.
        let record = na.dir.lookup_community(room).await.unwrap().unwrap();
        let signers = community_authority_set_for(&*na.dir, &record)
            .await
            .unwrap();
        for duty in [
            DELEGATION_SCOPE_MODERATE,
            DELEGATION_SCOPE_TAKEDOWN,
            DELEGATION_SCOPE_REVIEW,
        ] {
            assert_eq!(
                moderators_of(&*na.dir, room, duty).await.unwrap(),
                vec![r.alice.person.key_id.clone()],
                "{protocol}/{duty}: the founder alone, before any appointment"
            );
        }

        // Every plain member, on every node.
        for who in plain {
            assert!(signers.contains(&who.person.key_id), "{protocol}: a signer");
            let act = moderation_act(who, room, &r.tess, "plain").await;
            let notice = takedown_notice(who, &sha).await;
            for n in &r.nodes {
                refused_as(&apply(n, &act, who).await, DUTY_REFUSED);
                refused_as(&apply(n, &notice, who).await, TAKEDOWN_REFUSED);
                assert!(
                    !held(n, &act).await,
                    "{protocol}: a refused act is not held"
                );
                assert!(!held(n, &notice).await, "{protocol}: nor a refused notice");
            }
        }

        // The founder's pass on every node.
        let act = moderation_act(&r.alice, room, &r.tess, "founder").await;
        let notice = takedown_notice(&r.alice, &sha).await;
        for n in &r.nodes {
            assert!(apply(n, &act, &r.alice).await.is_admitted(), "{protocol}");
            assert!(
                apply(n, &notice, &r.alice).await.is_admitted(),
                "{protocol}"
            );
        }

        // A plain member's own edge roots nothing.
        let forged = appoint(&r.bob, &r.mo, DELEGATION_SCOPE_MODERATE).await;
        let _ = nb
            .dir
            .put_attestation(SignedAttestation {
                attestation: forged,
            })
            .await;
        let act = moderation_act(&r.mo, room, &r.tess, "self-appointed").await;
        refused_as(&apply(nb, &act, &r.mo).await, DUTY_REFUSED);

        // The appointments exist only on the founder's node so far, and the
        // delegates' acts outrun them to bob's node.
        let moderate = appoint(&r.alice, &r.mo, DELEGATION_SCOPE_MODERATE).await;
        let takedown = appoint(&r.alice, &r.tess, DELEGATION_SCOPE_TAKEDOWN).await;
        for row in [&moderate, &takedown] {
            assert!(apply(na, row, &r.alice).await.is_admitted(), "{protocol}");
        }
        let act = moderation_act(&r.mo, room, &r.tess, "delegated").await;
        let notice = takedown_notice(&r.tess, &sha).await;
        assert!(apply(na, &act, &r.mo).await.is_admitted(), "{protocol}");
        assert!(
            apply(na, &notice, &r.tess).await.is_admitted(),
            "{protocol}"
        );
        for n in [nb, nm] {
            assert_eq!(
                refused_as(&apply(n, &act, &r.mo).await, DUTY_REFUSED),
                RetryDisposition::Transient,
                "{protocol}: the next round re-offers it"
            );
            assert_eq!(
                refused_as(&apply(n, &notice, &r.tess).await, TAKEDOWN_REFUSED),
                RetryDisposition::Transient,
                "{protocol}: a notice waits for its appointment, it is not parked"
            );
        }
        for n in [nb, nm] {
            for row in [&moderate, &takedown] {
                assert!(apply(n, row, &r.alice).await.is_admitted(), "{protocol}");
            }
            assert!(apply(n, &act, &r.mo).await.is_admitted(), "{protocol}");
            assert!(apply(n, &notice, &r.tess).await.is_admitted(), "{protocol}");
        }

        // A delegated duty confers no other.
        let notice = takedown_notice(&r.mo, &sha).await;
        for n in &r.nodes {
            refused_as(&apply(n, &notice, &r.mo).await, TAKEDOWN_REFUSED);
        }
        let act = moderation_act(&r.tess, room, &r.bob, "takedown-only").await;
        for n in &r.nodes {
            refused_as(&apply(n, &act, &r.tess).await, DUTY_REFUSED);
        }
    }
}

/// **The room member a chat row names is the member a takedown reads.** Edge
/// names the room `community_key_id` on every row it writes, persist's
/// canonical cohort target, and `takedown_tombstone::content_binding` reads
/// `community_id` alone. So content in a room binds no community, and the
/// room's own founder holds no takedown over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "fails on persist v61.0.2: content_binding reads `community_id` only"]
async fn a_founder_can_take_down_what_a_chat_row_binds_into_the_room() {
    let r = Box::pin(duty_room(consensus_protocol::MAJORITY)).await;
    let [na, ..] = &r.nodes;
    let sha = hex::encode(sha2::Sha256::digest(b"a chat blob"));
    let row = content_row(&r.zoe, &r.room, ciris_edge::chat::FIELD_COMMUNITY_ID, &sha).await;
    assert!(apply(na, &row, &r.zoe).await.is_admitted());
    let notice = takedown_notice(&r.alice, &sha).await;
    let outcome = apply(na, &notice, &r.alice).await;
    assert!(outcome.is_admitted(), "{outcome:?}");
}

/// **6. A `unanimous` removal is every other member, and at two nobody is
/// removable** (persist v61.0.2, CIRISPersist#1192; CC 3.1.3.2). One founder
/// cannot remove the other; the removed member's own signature is a
/// resignation, the only exit at two. At three and four one short is refused
/// on every node and the full set of others lands, without the removed member.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_unanimous_removal_is_every_other_member_and_at_two_nobody_is_removable() {
    use ciris_edge::chat::pair_community;
    let alice = party("alice", 0x11);
    let bob = party("bob", 0x22);
    let carol = party("carol", 0x33);
    let dave = party("dave", 0x44);
    let all = [&alice, &bob, &carol, &dave];
    let a = node(&alice, &all, None).await;
    let b = node(&bob, &all, None).await;

    // Two founders: the pair room's end state, and the shape it signs.
    let opened = ciris_edge::chat::open_pair_room(
        &*a.dir,
        &alice.person.key_id,
        &bob.person.key_id,
        ts(),
        chrono::Utc::now() + chrono::Duration::days(7),
        &alice.person,
    )
    .await
    .expect("the pair room");
    let proposal = opened.proposal.expect("bob is proposed");
    let pair = opened.room;
    assert_eq!(
        pair_community(&alice.person.key_id, &bob.person.key_id, ts()).consensus_protocol,
        consensus_protocol::UNANIMOUS
    );
    membership::reply(&*a.dir, &proposal.attestation_id, true, &bob.person)
        .await
        .expect("bob accepts");
    assert!(ciris_edge::community_roster::widen_community(
        &*a.dir,
        &pair,
        &bob.person.key_id,
        Some(MEMBER_ROLE_FOUNDER),
        at(1),
        &[&alice.person],
    )
    .await
    .expect("the acceptance is the second voice"));
    let removal = RosterEvent::revocation(&pair, &bob.person.key_id, at(2), None, &[]);
    let err = assemble(
        &*a.dir,
        &removal,
        vec![cosign(&removal, &alice.person).await.expect("sign")],
    )
    .await
    .expect_err("at two, one voice is no majority");
    assert!(
        err.contains(ciris_persist::federation::ROSTER_CONSENSUS_INSUFFICIENT),
        "{err}"
    );
    assert_eq!(active(&a.dir, &pair).await, sorted(&[&alice, &bob]));
    // Resignation is the exit, and it needs no one else.
    let resignation = RosterEvent::revocation(&pair, &bob.person.key_id, at(3), None, &[]);
    assert!(assemble(
        &*a.dir,
        &resignation,
        vec![cosign(&resignation, &bob.person).await.expect("sign")],
    )
    .await
    .expect("a member leaves on their own signature"));
    assert_eq!(active(&a.dir, &pair).await, sorted(&[&alice]));

    // Three, then four.
    let room = found_room(&alice, consensus_protocol::UNANIMOUS, &[&a, &b]).await;
    seat(&a, &room, &alice, &[&alice], &bob, 1).await;
    seat(&a, &room, &alice, &[&alice, &bob], &carol, 2).await;
    seat(&a, &room, &alice, &[&alice, &bob, &carol], &dave, 3).await;
    carry_room(&a.bridge, &b.bridge, &room).await;
    assert_eq!(active(&b.dir, &room).await, sorted(&all));

    // Four: two of the three others is one short, three is every other.
    let removal = RosterEvent::revocation(&room, &dave.person.key_id, at(4), None, &[]);
    let short = cosign_all(&removal, &[&alice.person, &bob.person])
        .await
        .expect("sign");
    let err = assemble(&*a.dir, &removal, short)
        .await
        .expect_err("one other short");
    assert!(
        err.contains(ciris_persist::federation::ROSTER_CONSENSUS_INSUFFICIENT),
        "{err}"
    );
    let every_other = cosign_all(&removal, &[&alice.person, &bob.person, &carol.person])
        .await
        .expect("sign");
    assert!(assemble(&*a.dir, &removal, every_other)
        .await
        .expect("every other member removes, and the removed one is not a voice"));

    // Three: the same on the smaller roster.
    let removal = RosterEvent::revocation(&room, &carol.person.key_id, at(5), None, &[]);
    assert!(assemble(
        &*a.dir,
        &removal,
        cosign_all(&removal, &[&alice.person, &bob.person])
            .await
            .expect("sign"),
    )
    .await
    .expect("two others of three remove the third"));

    // The rows carry, and the same roster lands on the other node.
    let outcomes = carry_room(&a.bridge, &b.bridge, &room).await;
    assert_eq!(
        active(&b.dir, &room).await,
        sorted(&[&alice, &bob]),
        "{outcomes:?}"
    );
}

/// **7. A seated moderator's removal waits for its appointment.** The founder
/// appoints mo and mo removes dave alone on the founder's node. On a node that
/// has not held the appointment yet the row reads as a short set: the refusal
/// must be transient, or a good removal sits out the terminal schedule while
/// the roster reads differently on two nodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_moderators_removal_that_outran_its_appointment_lands_with_it() {
    use ciris_persist::federation::admission::DELEGATION_SCOPE_MODERATE;
    let r = Box::pin(duty_room(consensus_protocol::MAJORITY)).await;
    let [na, nb, _] = &r.nodes;
    let room = r.room.as_str();
    let edge = appoint(&r.alice, &r.mo, DELEGATION_SCOPE_MODERATE).await;
    assert!(apply(na, &edge, &r.alice).await.is_admitted());
    let removal = RosterEvent::revocation(
        room,
        &r.dave.person.key_id,
        chrono::Utc::now(),
        Some("by the moderator"),
        &[],
    );
    assert!(assemble(
        &*na.dir,
        &removal,
        vec![cosign(&removal, &r.mo.person).await.expect("sign")],
    )
    .await
    .expect("a named moderator has standing alone"));
    let rows = served(&na.bridge, |row| {
        dimension(row).starts_with("membership:removal:")
    })
    .await;
    let (_, bytes) = rows.first().expect("the removal is served");
    let early = nb
        .bridge
        .apply_envelope_bytes(EnvelopeKind::Attestation, bytes, Some(&r.mo.node.key_id))
        .await;
    assert_eq!(
        refused_as(
            &early,
            ciris_persist::federation::ROSTER_CONSENSUS_INSUFFICIENT
        ),
        RetryDisposition::Transient,
        "{early:?}"
    );
    assert!(active(&nb.dir, room).await.contains(&r.dave.person.key_id));
    assert!(apply(nb, &edge, &r.alice).await.is_admitted());
    let landed = nb
        .bridge
        .apply_envelope_bytes(EnvelopeKind::Attestation, bytes, Some(&r.mo.node.key_id))
        .await;
    assert!(landed.is_admitted(), "{landed:?}");
    assert_eq!(active(&nb.dir, room).await, active(&na.dir, room).await);
}

/// **8. Rule 0: one signer does not withdraw a cosigned row** (CC 2.4.1.1).
/// Each of the row's two cosigners, the founder who did not sign and the
/// member it seated each offer a lone `withdraws` of a cosigned widening. Each
/// is refused where it is carried, and the row, its cosignatures and the seat
/// stand on every node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_signer_never_withdraws_a_cosigned_row() {
    let ([alice, bob, carol, dave], [na, nb, nc, nd], room) =
        Box::pin(room_of_three_plus_dave()).await;
    let event = RosterEvent::widening(&room, &dave.person.key_id, None, at(3));
    let voices = vec![
        cosign(&event, &bob.person).await.expect("bob"),
        cosign(&event, &carol.person).await.expect("carol"),
    ];
    assert!(assemble(&*nb.dir, &event, voices)
        .await
        .expect("two of three"));
    let is_dave = |r: &Attestation| {
        dimension(r).starts_with("membership:widening:")
            && r.attestation_envelope
                .to_string()
                .contains(&dave.person.key_id)
    };
    let rows = served(&nb.bridge, |r| in_room(&room)(r) && is_dave(r)).await;
    let (row, bytes) = rows.first().cloned().expect("the widening is served");
    for n in [&na, &nc, &nd] {
        let landed = n
            .bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some(&bob.node.key_id))
            .await;
        assert!(landed.is_admitted(), "{landed:?}");
    }
    assert!(!row.additional_scrubs.is_empty(), "a cosigned row");

    let want = sorted(&[&alice, &bob, &carol, &dave]);
    for signer in [&alice, &bob, &carol, &dave] {
        let mut input = EmitAttestationInput::with_envelope(
            attestation_type::WITHDRAWS,
            EnvelopeCore::from_value(
                ciris_persist::federation::replication::withdraws_attestation_envelope(
                    &row.attestation_id,
                    &row.attestation_type,
                ),
            )
            .expect("object"),
            cohort_scope::FEDERATION,
        );
        input.attested_key_id = Some(row.attested_key_id.clone());
        let lone = signed_row(input, &signer.person).await;
        for n in [&na, &nb, &nc, &nd] {
            // By the tally: a refusal for anything else would witness nothing.
            refused_as(
                &apply(n, &lone, signer).await,
                ciris_persist::federation::ROSTER_CONSENSUS_INSUFFICIENT,
            );
            assert_eq!(active(&n.dir, &room).await, want, "the seat stands");
            let still = n
                .dir
                .get_attestation(&row.attestation_id)
                .await
                .expect("read")
                .expect("the row stands");
            assert_eq!(still.additional_scrubs, row.additional_scrubs);
        }
    }
}
