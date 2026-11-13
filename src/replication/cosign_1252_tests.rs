//! **persist 61.3.0 / CIRISPersist#1252 adopted: the cosign rows, the act ref,
//! held-equivalent settles and the unheld-target `withdraws`.**
//!
//! Over real sqlite directories and the real bridge, in a `majority` room of
//! three (alice, bob, carol) seating dave by a cosigned widening:
//!
//! 1. **Decision rows** — a `cosign:pending:v1` row is a `CosignPending`
//!    decision row scoped to its room; a `cosign:signature:v1` row is a
//!    `CosignSignature` naming the held event (its quorum key).
//! 2. **The act ref** — a cosigned row admitted through the choke is in the
//!    holdings index under persist's `attestation_wire_hash`, the ref a 61.3+
//!    peer advertises, so the receive diff does not want it again.
//! 3. **Held-equivalent** — the same act offered under another ref (a 61.2
//!    peer's `sha256(bytes)`, another subset's bytes) settles once and is then
//!    never wanted again, with no store read on the diff.
//! 4. **Unheld target** — a cosigned `withdraws` whose target is not held
//!    parks on the target; the target's arrival releases it and the
//!    withdrawal then lands.
//!
//! `cargo test --lib cosign_1252`

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER;
use ciris_persist::federation::types::{consensus_protocol, Attestation, SignedAttestation};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::{KeyRecord, SignedKeyRecord};
use ciris_persist::store::sqlite::SqliteBackend;

use super::holdings_index_971_tests::{bridge_with, index_on};
use crate::community_roster::{assemble, cosign, RosterEvent};
use crate::decision_rows::{DecisionCursor, DecisionRowKind, DecisionRowRef};
use crate::membership::{self, GroupScope};
use crate::replication::directory::ReplicationDirectory as _;
use crate::replication::summary::ApplyOutcome;
use crate::replication::wire_ref::{envelope_ref, plain_ref};
use crate::replication::{EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge};

const KIND: EnvelopeKind = EnvelopeKind::Attestation;

fn ts() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::hours(1)
}

fn signer(label: &str, seed: u8) -> crate::identity::LocalSigner {
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], label).expect("ed25519"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{label}-pqc"))
            .expect("ml-dsa-65"),
    );
    let pubkey = futures::executor::block_on(classical.public_key()).expect("ed pubkey");
    let key_id = ciris_verify_core::fedcode::derive_key_id(label, &pubkey);
    crate::identity::LocalSigner::new(key_id, classical, Some(pqc))
}

async fn record(s: &crate::identity::LocalSigner, identity_type: &str) -> KeyRecord {
    use sha2::Digest as _;
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
    let digest = sha2::Sha256::digest(&canonical);
    let (sig, sig_pqc) = crate::identity::sign_bound_hybrid(s, digest.as_slice(), "key record")
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
    person: crate::identity::LocalSigner,
    node: crate::identity::LocalSigner,
}

fn party(name: &str, seed: u8) -> Party {
    Party {
        person: signer(&format!("{name}-fed-1252"), seed),
        node: signer(&format!("{name}-node-1252"), seed.wrapping_add(0x40)),
    }
}

/// One node's store: every party's keys and owner bindings held.
async fn store(all: &[&Party]) -> Arc<SqliteBackend> {
    let dir = Arc::new(
        SqliteBackend::open_in_memory()
            .await
            .expect("in-memory store"),
    );
    ciris_persist::prelude::Backend::run_migrations(&*dir)
        .await
        .expect("migrate");
    for p in all {
        for (s, t) in [(&p.person, "user"), (&p.node, "node")] {
            dir.put_public_key(SignedKeyRecord {
                record: record(s, t).await,
            })
            .await
            .expect("register");
        }
        let binding = crate::replication::attestation_bind::owner_binding_attestation(
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

/// A bridge over `dir` for `me`, holdings index ON.
fn bridge(dir: &Arc<SqliteBackend>, me: &Party) -> Arc<FederationDirectoryReplicationBridge> {
    bridge_with(
        Arc::clone(dir) as Arc<dyn FederationDirectory>,
        &me.node.key_id,
        vec![me.node.key_id.clone(), me.person.key_id.clone()],
        index_on(),
        None,
    )
}

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

fn dimension(row: &Attestation) -> &str {
    row.attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
}

/// Every room row `dir` holds, as served bytes, in serve order.
async fn room_rows(dir: &SqliteBackend, room: &str) -> Vec<(Attestation, Vec<u8>)> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = dir
            .list_attestations_since(cursor.clone(), 500)
            .await
            .expect("page");
        let Some(last) = page.last() else { break };
        cursor = Some(last.resume_pair());
        for s in &page {
            let row = s.attestation.clone();
            if row
                .attestation_envelope
                .get("community_key_id")
                .and_then(serde_json::Value::as_str)
                == Some(room)
                && (dimension(&row).starts_with("membership:")
                    || dimension(&row).starts_with("group:"))
            {
                let bytes = serde_json::to_vec(&row).expect("wire");
                out.push((row, bytes));
            }
        }
        if page.len() < 500 {
            break;
        }
    }
    out
}

/// A `majority` room of three, founded by alice, with dave's admission
/// consented, held on every store passed.
struct Room {
    alice: Party,
    bob: Party,
    carol: Party,
    dave: Party,
    room: String,
    event: RosterEvent,
}

fn parties() -> [Party; 4] {
    [
        party("alice", 0x11),
        party("bob", 0x22),
        party("carol", 0x33),
        party("dave", 0x44),
    ]
}

/// `n` stores, each holding every party's keys and owner bindings.
async fn stores(p: &[Party; 4], n: usize) -> Vec<Arc<SqliteBackend>> {
    let all: Vec<&Party> = p.iter().collect();
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(store(&all).await);
    }
    out
}

async fn room_of_three(
    p: [Party; 4],
    stores: &[&Arc<SqliteBackend>],
    founder_store: &SqliteBackend,
) -> Room {
    let [alice, bob, carol, dave] = p;
    let room = crate::chat::new_room_community_key_id();
    let rec = crate::chat::community(
        &room,
        "the room",
        &[(&alice.person.key_id, Some(MEMBER_ROLE_FOUNDER))],
        consensus_protocol::MAJORITY,
        ts(),
    )
    .expect("record");
    let signed = crate::chat::signed_community(rec, &alice.person)
        .await
        .expect("sign");
    founder_store
        .put_community(signed.clone())
        .await
        .expect("room");
    consent(founder_store, &room, &alice, &bob).await;
    assert!(crate::community_roster::widen_community(
        founder_store,
        &room,
        &bob.person.key_id,
        None,
        ts() + chrono::Duration::seconds(1),
        &[&alice.person],
    )
    .await
    .expect("bob"));
    consent(founder_store, &room, &alice, &carol).await;
    assert!(crate::community_roster::widen_community(
        founder_store,
        &room,
        &carol.person.key_id,
        None,
        ts() + chrono::Duration::seconds(2),
        &[&alice.person, &bob.person],
    )
    .await
    .expect("carol"));
    consent(founder_store, &room, &alice, &dave).await;
    // The room's history, carried to every other store.
    let history = room_rows(founder_store, &room).await;
    for s in stores {
        s.put_community(signed.clone()).await.expect("room");
        for _pass in 0..2 {
            for (row, _) in &history {
                let _ = s
                    .apply_replicated_attestation(SignedAttestation {
                        attestation: row.clone(),
                    })
                    .await;
            }
        }
    }
    let event = RosterEvent::widening(
        &room,
        &dave.person.key_id,
        None,
        ts() + chrono::Duration::seconds(3),
    );
    Room {
        alice,
        bob,
        carol,
        dave,
        room,
        event,
    }
}

/// Dave's assembled widening as `dir` serves it, after assembling it there
/// from bob's and carol's voices.
async fn assembled(dir: &SqliteBackend, r: &Room) -> (Attestation, Vec<u8>) {
    assembled_by(dir, r, &[&r.bob, &r.carol]).await
}

/// Dave's widening assembled on `dir` from `by`'s voices (another sufficient
/// subset is another row of the same act).
async fn assembled_by(dir: &SqliteBackend, r: &Room, by: &[&Party]) -> (Attestation, Vec<u8>) {
    let mut voices = Vec::new();
    for p in by {
        voices.push(cosign(&r.event, &p.person).await.expect("voice"));
    }
    assert!(
        assemble(dir, &r.event, voices).await.expect("assemble"),
        "two of three seat dave"
    );
    room_rows(dir, &r.room)
        .await
        .into_iter()
        .find(|(row, _)| {
            dimension(row).starts_with("membership:widening:")
                && row
                    .attestation_envelope
                    .to_string()
                    .contains(&r.dave.person.key_id)
        })
        .expect("the store serves dave's widening")
}

/// **1. The cosign rows are decision rows.** A held event's `cosign:pending`
/// row is a `CosignPending` decision on its room, named by its quorum key; a
/// cosignature row is a `CosignSignature` whose proposal is that quorum key.
/// Red before: neither family classified (no decision row at all).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cosign_rows_are_decision_rows_on_their_room_1252() {
    use ciris_persist::federation::cosign;
    use ciris_persist::federation::group_plane::group_signed_of_row;
    let p = parties();
    let s = stores(&p, 1).await;
    let a = Arc::clone(&s[0]);
    let r = room_of_three(p, &[], &a).await;
    let (row, _) = assembled(&a, &r).await;
    let signed = group_signed_of_row(&row)
        .expect("a group row")
        .expect("decodes");
    let pending = cosign::pending_row(&signed).expect("pending row");
    let cos = signed.cosignatures();
    let signature = cosign::signature_row(&signed, &cos[0]).expect("signature row");
    let at = DecisionCursor::at_or_before(chrono::Utc::now());
    let p = DecisionRowRef::of_row(&pending, at.clone()).expect("a decision row");
    assert_eq!(p.kind, DecisionRowKind::CosignPending);
    assert_eq!(p.scope_id.as_deref(), Some(r.room.as_str()));
    assert_eq!(p.kind.as_str(), "cosign_pending");
    let s = DecisionRowRef::of_row(&signature, at).expect("a decision row");
    assert_eq!(s.kind, DecisionRowKind::CosignSignature);
    assert_eq!(s.scope_id.as_deref(), Some(r.room.as_str()));
    assert_eq!(
        s.proposal_id.as_deref(),
        Some(pending.attestation_id.as_str()),
        "a cosignature names the held event by its quorum key"
    );
}

/// **2. A cosigned row is held under its act ref.** Admitted through the
/// choke, it is in the holdings index under persist's `attestation_wire_hash`
/// (the index persist keeps), so a 61.3+ peer's advertisement of it is not
/// wanted. Red before: the write-through inserted `sha256(bytes)`, so the act
/// ref stayed wanted every round.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cosigned_row_is_held_under_its_act_ref_1252() {
    let p = parties();
    let s = stores(&p, 2).await;
    let (a, b) = (Arc::clone(&s[0]), Arc::clone(&s[1]));
    let r = room_of_three(p, &[&b], &a).await;
    let (row, bytes) = assembled(&a, &r).await;
    let act = ciris_persist::federation::wire_index::attestation_wire_hash(&row);
    assert_ne!(act, plain_ref(&bytes), "precondition: a cosigned row");
    assert_eq!(envelope_ref(KIND, &bytes), act, "edge's one ref rule");
    let nb = bridge(&b, &r.bob);
    // Boot the set before the row lands, so only the write-through can add it.
    let _ = nb.holdings_want(KIND, &[]).await;
    let outcome = nb
        .apply_envelope_bytes(KIND, &bytes, Some(&r.alice.node.key_id))
        .await;
    assert_eq!(outcome, ApplyOutcome::Admitted);
    let set = nb.holdings_index_set(KIND).expect("the set answers");
    assert!(set.contains(&act), "held under the act ref");
    assert!(
        !set.contains(&plain_ref(&bytes)),
        "and not under a ref persist's index does not hold"
    );
    let offered = [EnvelopeRef {
        envelope_hash: act,
        seq: 0,
    }];
    assert!(
        nb.holdings_want(KIND, &offered).await.is_empty(),
        "a 61.3+ peer's offer of the act is not wanted"
    );
}

/// **3. The same act offered under another ref settles once, then is never
/// wanted again.** b holds the act as assembled on a; c assembled the same act
/// itself (other ML-DSA bytes, another row id). Offered by a 61.2 peer under
/// `sha256(bytes)`, both the held row's bytes and c's: each is wanted once,
/// applied (`Duplicate` / `HeldEquivalent`), and from then on taken out of the
/// diff, lever on and off. Red before: both stayed wanted every round.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_act_offered_under_another_ref_is_wanted_once_1252() {
    let p = parties();
    let s = stores(&p, 3).await;
    let (a, b, c) = (Arc::clone(&s[0]), Arc::clone(&s[1]), Arc::clone(&s[2]));
    let r = room_of_three(p, &[&b, &c], &a).await;
    let (_, held_bytes) = assembled(&a, &r).await;
    let (other, other_bytes) = assembled_by(&c, &r, &[&r.bob, &r.alice]).await;
    assert_ne!(other_bytes, held_bytes, "precondition: another assembly");
    assert_eq!(
        envelope_ref(KIND, &other_bytes),
        envelope_ref(KIND, &held_bytes),
        "the same act"
    );
    for lever in [true, false] {
        let config = crate::replication::BridgeConfig {
            holdings_index: lever,
            ..crate::replication::BridgeConfig::default()
        };
        let nb = bridge_with(
            Arc::clone(&b) as Arc<dyn FederationDirectory>,
            &r.bob.node.key_id,
            vec![r.bob.node.key_id.clone()],
            config,
            None,
        );
        if lever {
            let outcome = nb
                .apply_envelope_bytes(KIND, &held_bytes, Some(&r.alice.node.key_id))
                .await;
            assert_eq!(outcome, ApplyOutcome::Admitted);
        }
        // A 61.2 peer's refs: the bytes' own hashes.
        let old_held = plain_ref(&held_bytes);
        let old_other = plain_ref(&other_bytes);
        let offered: Vec<EnvelopeRef> = [old_held, old_other]
            .into_iter()
            .map(|h| EnvelopeRef {
                envelope_hash: h,
                seq: 0,
            })
            .collect();
        let mut want = nb.holdings_want(KIND, &offered).await;
        want.sort_unstable();
        let mut both = vec![old_held, old_other];
        both.sort_unstable();
        assert_eq!(want, both, "lever {lever}: first sight, both wanted");
        for bytes in [&held_bytes, &other_bytes] {
            let outcome = nb
                .apply_envelope_bytes(KIND, bytes, Some(&r.carol.node.key_id))
                .await;
            assert_eq!(
                outcome,
                ApplyOutcome::Duplicate,
                "lever {lever}: the act is held"
            );
        }
        for round in 0..3 {
            assert!(
                nb.holdings_want(KIND, &offered).await.is_empty(),
                "lever {lever}, round {round}: neither old ref is wanted again"
            );
        }
        assert_eq!(nb.held_equivalent_refs(), 2, "lever {lever}");
        let _ = other.attestation_id;
    }
}

/// A `withdraws` of `target` by `primary`, co-signed by `cosigners` over the
/// same canonical envelope, placed where its target is (CC 2.4.1.1 rule 0: a
/// group's retraction of a cosigned act).
async fn cosigned_withdraws(
    primary: &crate::identity::LocalSigner,
    cosigners: &[&crate::identity::LocalSigner],
    target: &Attestation,
) -> Attestation {
    use sha2::Digest as _;
    let asserted_at =
        ciris_persist::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
    let attestation_id = format!("withdraws-1252-{}", target.attestation_id);
    let mut envelope = ciris_persist::federation::replication::withdraws_attestation_envelope(
        &target.attestation_id,
        &target.attestation_type,
    );
    if let Some(obj) = envelope.as_object_mut() {
        obj.insert(
            ciris_persist::federation::envelope::paths::WITHDRAWAL_REASON.to_owned(),
            serde_json::json!("cosign witness"),
        );
        for k in [
            ciris_persist::federation::group_plane::GROUP_KIND_MEMBER,
            "family_key_id",
            "community_key_id",
        ] {
            if let Some(v) = target.attestation_envelope.get(k) {
                obj.insert(k.to_owned(), v.clone());
            }
        }
    }
    let subjects: Vec<String> = Vec::new();
    crate::replication::attestation_bind::bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &crate::replication::attestation_bind::AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: &primary.key_id,
            attestation_type: "withdraws",
            attested_key_id: &primary.key_id,
            subject_key_ids: &subjects,
            cohort_scope: &target.cohort_scope,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("jcs");
    let (classical, pqc) = crate::identity::sign_bound_hybrid(primary, &canonical, "withdraws")
        .await
        .expect("sign");
    let mut additional_scrubs = Vec::new();
    for c in cosigners {
        let (cl, pq) = crate::identity::sign_bound_hybrid(c, &canonical, "withdraws cosign")
            .await
            .expect("cosign");
        additional_scrubs.push(ciris_persist::federation::types::ScrubSig {
            scrub_key_id: c.key_id.clone(),
            scrub_signature_classical: cl,
            scrub_signature_pqc: pq,
            cosigned_at: None,
        });
    }
    Attestation {
        attestation_id,
        attesting_key_id: primary.key_id.clone(),
        attested_key_id: primary.key_id.clone(),
        attestation_type: "withdraws".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(sha2::Sha256::digest(&canonical)),
        scrub_signature_classical: classical,
        scrub_signature_pqc: pqc,
        scrub_key_id: primary.key_id.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: target.cohort_scope.clone(),
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs,
    }
}

/// **4. A cosigned `withdraws` whose target is not held parks on the target,
/// and the target's arrival releases it.** b holds the room but not dave's
/// widening; the group's retraction of it arrives first: persist refuses it
/// `withdraws_target_unheld` (retryable), edge parks it on the target row.
/// The widening then lands, which releases the park and re-asks; the
/// retraction now lands too. Red before: the refusal was an unclassified
/// transient (no park, no release), re-asked on the short ladder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdraws_waits_for_its_target_and_lands_after_it_1252() {
    let p = parties();
    let s = stores(&p, 2).await;
    let (a, b) = (Arc::clone(&s[0]), Arc::clone(&s[1]));
    let r = room_of_three(p, &[&b], &a).await;
    let (row, bytes) = assembled(&a, &r).await;
    // Seated, dave makes the room four: a majority retraction is three voices.
    let w = cosigned_withdraws(&r.bob.person, &[&r.carol.person, &r.alice.person], &row).await;
    let w_bytes = serde_json::to_vec(&w).expect("wire");
    let nb = bridge(&b, &r.bob);
    let refused = nb
        .apply_envelope_bytes(KIND, &w_bytes, Some(&r.alice.node.key_id))
        .await;
    assert_eq!(
        refused.awaits_row(),
        Some(row.attestation_id.as_str()),
        "refused while its target is unheld, waiting on it: {refused:?}"
    );
    assert_eq!(nb.parked_on_signer_len(), 1, "parked on the target row");
    let releases = nb.signer_releases();
    assert_eq!(
        nb.apply_envelope_bytes(KIND, &bytes, Some(&r.alice.node.key_id))
            .await,
        ApplyOutcome::Admitted,
        "the target lands"
    );
    assert_eq!(
        nb.signer_releases(),
        releases + 1,
        "its arrival released the parked withdraws"
    );
    assert_eq!(nb.parked_on_signer_len(), 0);
    let landed = nb
        .apply_envelope_bytes(KIND, &w_bytes, Some(&r.alice.node.key_id))
        .await;
    assert!(
        matches!(landed, ApplyOutcome::Admitted | ApplyOutcome::Duplicate),
        "the withdrawal now lands on b: {landed:?}"
    );
    assert!(
        b.get_attestation(&w.attestation_id)
            .await
            .expect("read")
            .is_some(),
        "b holds the retraction, so it serves it to the room's members"
    );
    let _ = &r.dave;
}
