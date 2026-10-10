//! **CIRISEdge#858 fix 7 — persist v54.1.0's typed refusals (CIRISPersist#1042
//! and #1044, with the #1042 follow-ups in 02c2b27d) reach the park as types,
//! not as guesses.**
//!
//! Before v54.1.0 an unregistered signer and a signature that does not verify
//! were one token, so every signature refusal was transient and the park
//! guessed the missing signer from the bytes. Two consequences: a row whose
//! missing key was a CO-signer was never parked (the bytes name the held
//! attester), and an invalid SELF-scrubbed Key parked on its own key id, which
//! only its own admit could release.
//!
//! The witness is the real bridge and its apply choke over an in-memory sqlite
//! directory. Each test fails with its mapping reverted:
//!
//! | test | mapping | fails before because |
//! |---|---|---|
//! | (1) | `AttesterKeyUnknown` ⇒ park on `attesting_key_id` | the bytes name the held attester, so nothing parks on the absent co-signer |
//! | (2) | `FederationTierUnverified` ⇒ terminal | a forged signature rides the transient ladder |
//! | (3) | key plane `unverifiable_signature` ⇒ terminal | the invalid self-scrubbed Key parks on itself |
//! | (4) | `ReplicatedKeyOutcome::InvalidReplaced` ⇒ admitted | the replacement does not count as an admit |
//! | (5) | `SignatureInvalid` ⇒ terminal | a forged occurrence rides the transient ladder |
//! | (6) | `SignerDoesNotActFor` ⇒ indexed on the held signer | the row is never indexed, so its binding releases nothing |
//! | (7) | the same, bounded | a never-bound signer is re-asked on the transient ladder forever |
//!
//! Beside these: `AttesterKeyUnknown` naming an EMPTY key id is not a park
//! (defence: persist 02c2b27d no longer emits it), and the typed
//! `authority_acts_by_quorum` licensure refusal and `AccordProposalNonceReused`
//! are pinned terminal in
//! `bridge::tests::a_quorum_authority_licence_and_a_reused_accord_nonce_are_terminal`.
//!
//! `cargo test --lib typed_refusal_858`

// The fixtures read as the issue's letters (P, N, C, K).
#![allow(clippy::many_single_char_names)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_persist::federation::types::ScrubSig;
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::prelude::SignedKeyRecord;
use ciris_persist::store::sqlite::SqliteBackend;
use sha2::Digest as _;

use super::park_fresh_858_tests::{hold, occurrence, substrate, Ident};
use crate::replication::refusal_backoff::TRANSIENT_CAP;
use crate::replication::summary::ApplyOutcome;
use crate::replication::{
    BridgeConfig, EnvelopeKind, FederationDirectoryReplicationBridge, ReplicationDirectory as _,
    RetryDisposition,
};

const PEER: &str = "peer-858-fix7";

fn sha(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

fn bridge(dir: &Arc<SqliteBackend>) -> Arc<FederationDirectoryReplicationBridge> {
    Arc::new(FederationDirectoryReplicationBridge::with_config(
        Arc::clone(dir) as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    ))
}

/// `owner`'s signed binding of `node`, and the canonical bytes it signed.
async fn binding(owner: &Ident, node: &Ident) -> (Attestation, Vec<u8>) {
    let att = crate::replication::attestation_bind::owner_binding_attestation(
        owner.key_id(),
        node.key_id(),
        chrono::Utc::now(),
        &owner.signer(),
    )
    .await
    .expect("build the binding");
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&att.attestation_envelope)
        .expect("canonicalize");
    (att, canonical)
}

fn wire(att: Attestation) -> Vec<u8> {
    serde_json::to_vec(&SignedAttestation { attestation: att }).expect("encode")
}

/// The disposition of a refusal, or a panic naming what came back instead.
fn disposition(outcome: &ApplyOutcome) -> RetryDisposition {
    match outcome {
        ApplyOutcome::Refused { retry, .. } => *retry,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

/// A point past every transient window: a row still suppressed here is on
/// the terminal schedule (a park or a terminal refusal), not the ladder.
fn past_transient_ladder() -> Instant {
    Instant::now() + TRANSIENT_CAP + Duration::from_secs(60)
}

/// (1) A co-signer this node has not met. persist names it
/// (`AttesterKeyUnknown { attesting_key_id: C }`); the row parks on C, not on
/// the held attester P the bytes name, and C's Key through the choke releases
/// it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_co_signer_parks_the_row_on_that_co_signer_and_its_key_releases_it() {
    let p = Ident::mint("person-p-fix7a", "user", 0x51).await;
    let n = Ident::mint("node-n-fix7a", "node", 0x52).await;
    let c = Ident::mint("person-c-fix7a", "user", 0x53).await;
    let f = substrate().await;
    hold(&f, &p).await;
    hold(&f, &n).await;
    let (mut att, canonical) = binding(&p, &n).await;
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&c.signer(), &canonical, "co-scrub")
        .await
        .expect("co-sign");
    att.additional_scrubs.push(ScrubSig {
        scrub_key_id: c.key_id().to_owned(),
        scrub_signature_classical: ed,
        scrub_signature_pqc: pqc,
        cosigned_at: None,
    });
    let bytes = wire(att);
    let h = sha(&bytes);
    let b = bridge(&f);

    let outcome = b
        .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some(PEER))
        .await;
    assert_eq!(
        disposition(&outcome),
        RetryDisposition::Transient,
        "{outcome:?}"
    );
    assert_eq!(
        outcome.awaits_signer(),
        Some(c.key_id()),
        "the refusal carries the co-signer persist named: {outcome:?}"
    );
    let backoff = b.refusal_backoff_for_test();
    assert_eq!(
        backoff.parked_on(c.key_id()),
        1,
        "parked on the ABSENT co-signer persist named; the bytes name only P, which is \
         held, so the untyped park parks nothing (CIRISEdge#858 fix 7)"
    );
    assert_eq!(backoff.parked_on(p.key_id()), 0);
    assert!(backoff.suppressed_at(EnvelopeKind::Attestation, &h, past_transient_ladder()));

    let key = b
        .apply_envelope_bytes(EnvelopeKind::Key, &c.signed_key_bytes(), Some(PEER))
        .await;
    assert!(key.is_admitted(), "C's Key admits: {key:?}");
    assert_eq!(
        b.signer_releases(),
        1,
        "C's Key releases the row parked on it"
    );
    assert!(!b.retry_suppressed(EnvelopeKind::Attestation, &h));
    let again = b
        .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some(PEER))
        .await;
    assert!(again.is_admitted(), "the re-offered row admits: {again:?}");
}

/// (2) A forged attestation signature: a signer this node holds, a signature
/// by another key. persist refuses `FederationTierUnverified`; that is
/// terminal, never parked and never on the transient ladder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_attestation_signature_is_terminal_and_never_parked() {
    let p = Ident::mint("person-p-fix7b", "user", 0x61).await;
    let n = Ident::mint("node-n-fix7b", "node", 0x62).await;
    let forger = Ident::mint("person-x-fix7b", "user", 0x63).await;
    let f = substrate().await;
    hold(&f, &p).await;
    hold(&f, &n).await;
    let (mut att, canonical) = binding(&p, &n).await;
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&forger.signer(), &canonical, "forgery")
        .await
        .expect("forge");
    att.scrub_signature_classical = ed;
    att.scrub_signature_pqc = pqc;
    let bytes = wire(att);
    let b = bridge(&f);

    let outcome = b
        .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some(PEER))
        .await;
    let ApplyOutcome::Refused { reason, .. } = &outcome else {
        panic!("a forged signature is refused, got {outcome:?}");
    };
    assert!(
        reason.contains("federation_federation_tier_unverified"),
        "precondition: persist's verdict is FederationTierUnverified: {reason}"
    );
    assert_eq!(
        disposition(&outcome),
        RetryDisposition::Terminal,
        "a signature refused against a held signer is a function of the bytes \
         (CIRISEdge#858 fix 7): {reason}"
    );
    assert_eq!(outcome.awaits_signer(), None);
    assert_eq!(b.rows_parked_on_signer(), 0, "never parked");
    assert!(
        b.refusal_backoff_for_test().suppressed_at(
            EnvelopeKind::Attestation,
            &sha(&bytes),
            past_transient_ladder()
        ),
        "terminal from the first refusal: not re-asked on the transient ladder"
    );
}

/// (3) An invalid SELF-scrubbed Key: its scrub signatures cover other bytes.
/// persist v54.1.0 refuses `unverifiable_signature` only for a signature
/// checked and refused (the unregistered scrubber is `attester_key_unknown`
/// now), so it is terminal, and the row is not parked on its own key id,
/// which only its own admit could release.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_self_scrubbed_key_is_terminal_not_parked_on_itself() {
    let k = Ident::mint("person-k-fix7c", "user", 0x71).await;
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&k.signer(), b"other bytes", "other")
        .await
        .expect("sign other bytes");
    let mut record = k.record.clone();
    assert_eq!(
        record.scrub_key_id, record.key_id,
        "precondition: self-scrubbed"
    );
    record.scrub_signature_classical = ed;
    record.scrub_signature_pqc = pqc;
    let bytes = serde_json::to_vec(&SignedKeyRecord { record }).expect("encode");
    let f = substrate().await;
    let b = bridge(&f);

    let outcome = b
        .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some(PEER))
        .await;
    let ApplyOutcome::Refused { reason, .. } = &outcome else {
        panic!("an invalid Key is refused, got {outcome:?}");
    };
    assert!(
        reason.contains("unverifiable_signature"),
        "precondition: persist's token is unverifiable_signature: {reason}"
    );
    assert_eq!(
        disposition(&outcome),
        RetryDisposition::Terminal,
        "{reason}"
    );
    assert_eq!(
        b.refusal_backoff_for_test().parked_on(k.key_id()),
        0,
        "an invalid self-scrubbed Key must not park on itself (CIRISEdge#858 fix 7)"
    );
    assert_eq!(b.rows_parked_on_signer(), 0);
}

/// (4) A stored Key row that fails verification, replaced by its holder's
/// re-signed record (`InvalidReplaced`): an admit, and it releases the rows
/// parked on that key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invalid_replaced_key_is_admitted_and_releases_the_rows_parked_on_it() {
    let k = Ident::mint("person-k-fix7d", "user", 0x81).await;
    let n = Ident::mint("node-n-fix7d", "node", 0x82).await;
    let f = substrate().await;
    hold(&f, &n).await;
    let b = bridge(&f);

    // K's binding of N, while K is absent here: parked on K.
    let (att, _) = binding(&k, &n).await;
    let row = wire(att);
    let h = sha(&row);
    let first = b
        .apply_envelope_bytes(EnvelopeKind::Attestation, &row, Some(PEER))
        .await;
    assert_eq!(first.awaits_signer(), Some(k.key_id()), "{first:?}");
    assert_eq!(b.refusal_backoff_for_test().parked_on(k.key_id()), 1);

    // A failing K row lands LOCALLY (the legacy fallback's raw door): its
    // scrub signatures cover other bytes. No choke, so no release.
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&k.signer(), b"owner binding", "other")
        .await
        .expect("sign other bytes");
    let mut failing = k.record.clone();
    failing.scrub_signature_classical = ed;
    failing.scrub_signature_pqc = pqc;
    f.put_public_key(SignedKeyRecord { record: failing })
        .await
        .expect("the raw door stores an unverified row");
    assert_eq!(b.refusal_backoff_for_test().parked_on(k.key_id()), 1);

    // The holder's valid record through the choke replaces it.
    let key = b
        .apply_envelope_bytes(EnvelopeKind::Key, &k.signed_key_bytes(), Some(PEER))
        .await;
    assert!(
        key.is_admitted(),
        "InvalidReplaced is an admission: the held row changed (CIRISPersist#1044): {key:?}"
    );
    assert_eq!(
        b.signer_releases(),
        1,
        "the replacement releases the row parked on K"
    );
    assert!(!b.retry_suppressed(EnvelopeKind::Attestation, &h));
    let again = b
        .apply_envelope_bytes(EnvelopeKind::Attestation, &row, Some(PEER))
        .await;
    assert!(
        again.is_admitted(),
        "the binding admits against K's replaced row: {again:?}"
    );
}

/// (5) A bare `SignatureInvalid` is TERMINAL. persist 02c2b27d moved its
/// signer-acts-for arm out to `SignerDoesNotActFor` (see (6)), and what is left
/// is a function of the bytes on every door: a forged occurrence signature
/// against a held attester. Not parked, not on the transient ladder.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_forged_occurrence_signature_is_terminal() {
    let p = Ident::mint("person-p-fix7e", "user", 0x91).await;
    let n = Ident::mint("node-n-fix7e", "node", 0x92).await;
    let forger = Ident::mint("person-x-fix7e", "user", 0x93).await;
    let f = substrate().await;
    hold(&f, &p).await;
    hold(&f, &n).await;
    let mut occ = occurrence(p.key_id(), n.key_id(), &p).await;
    let other = occurrence(p.key_id(), n.key_id(), &forger).await;
    occ.signature = other.signature;
    let bytes = serde_json::to_vec(&occ).expect("encode");
    let b = bridge(&f);

    let outcome = b
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &bytes, Some(PEER))
        .await;
    let ApplyOutcome::Refused { reason, .. } = &outcome else {
        panic!("a forged occurrence is refused, got {outcome:?}");
    };
    assert!(
        reason.contains("federation_signature_invalid"),
        "precondition: persist's verdict is SignatureInvalid: {reason}"
    );
    assert_eq!(
        disposition(&outcome),
        RetryDisposition::Terminal,
        "SignatureInvalid is terminal on every door once acts-for left it: {reason}"
    );
    assert_eq!(outcome.awaits_signer(), None);
    assert_eq!(outcome.awaits_acts_for(), None);
    assert_eq!(b.rows_parked_on_signer(), 0, "never parked");
    assert!(
        b.refusal_backoff_for_test()
            .suppressed_at(KIND_OCC, &sha(&bytes), past_transient_ladder()),
        "terminal from the first refusal"
    );
}

const KIND_OCC: EnvelopeKind = EnvelopeKind::IdentityOccurrence;

/// U's occurrence of P, attested by U, on a node that holds both Keys but not
/// P's binding of U: persist refuses `SignerDoesNotActFor { attesting_key_id:
/// U, identity_key_id: P }`.
async fn unbound_occurrence(tag: &str, seed: u8) -> (Ident, Ident, Arc<SqliteBackend>, Vec<u8>) {
    let p = Ident::mint(&format!("person-p-{tag}"), "user", seed).await;
    let u = Ident::mint(&format!("node-u-{tag}"), "node", seed + 1).await;
    let f = substrate().await;
    hold(&f, &p).await;
    hold(&f, &u).await;
    let occ = occurrence(p.key_id(), u.key_id(), &u).await;
    let bytes = serde_json::to_vec(&occ).expect("encode");
    (p, u, f, bytes)
}

/// (6) `SignerDoesNotActFor` is indexed on the HELD signer persist named, and
/// the owner binding that makes it act for the identity releases the row,
/// which then admits (the #776 shape, now typed).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signer_not_acting_for_is_indexed_on_it_and_its_binding_releases_it() {
    let (p, u, f, bytes) = unbound_occurrence("fix7f", 0xa1).await;
    let h = sha(&bytes);
    let b = bridge(&f);

    let outcome = b.apply_envelope_bytes(KIND_OCC, &bytes, Some(PEER)).await;
    let ApplyOutcome::Refused { reason, .. } = &outcome else {
        panic!("an unbound signer's occurrence is refused, got {outcome:?}");
    };
    assert!(
        reason.contains("federation_signer_not_acting_for"),
        "precondition: persist's verdict is SignerDoesNotActFor: {reason}"
    );
    assert_eq!(
        disposition(&outcome),
        RetryDisposition::Transient,
        "{reason}"
    );
    assert_eq!(outcome.awaits_acts_for(), Some(u.key_id()), "{outcome:?}");
    assert_eq!(
        outcome.awaits_signer(),
        None,
        "U's Key is held: nothing to fetch"
    );
    let backoff = b.refusal_backoff_for_test();
    assert_eq!(
        backoff.parked_on(u.key_id()),
        1,
        "indexed on the held signer persist named (the #858 index)"
    );

    // P's binding of U, through the choke, makes U act for P.
    let (binding_att, _) = binding(&p, &u).await;
    let bound = b
        .apply_envelope_bytes(EnvelopeKind::Attestation, &wire(binding_att), Some(PEER))
        .await;
    assert!(bound.is_admitted(), "P's binding of U admits: {bound:?}");
    assert_eq!(
        b.signer_releases(),
        1,
        "the binding releases the row indexed on U"
    );
    assert!(!b.retry_suppressed(KIND_OCC, &h));
    let again = b.apply_envelope_bytes(KIND_OCC, &bytes, Some(PEER)).await;
    assert!(
        again.is_admitted(),
        "the re-offered occurrence admits: {again:?}"
    );
}

/// `attester`'s signed route for `occurrence`'s identity: the shape persist's
/// CHANGELOG names for a signer that will never be bound, "a peer asserting a
/// victim's route".
async fn route_for(occurrence: &Ident, attester: &Ident) -> Vec<u8> {
    use ciris_persist::federation::self_at_login::{
        BindingProvenance, SignedTransportDestination, TransportDestination,
    };
    use ciris_verify_core::transport_binding::TransportBindingSignature;
    let row = TransportDestination {
        occurrence_key_id: occurrence.key_id().to_owned(),
        transport_kind: "reticulum".to_owned(),
        destination: "ab".repeat(16),
        asserted_at: ciris_persist::federation::admission::truncate_to_substrate_resolution(
            chrono::Utc::now(),
        ),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0xbb; 32],
        )),
        transport_x25519_pubkey_base64: Some(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            [0xcc; 32],
        )),
        binding_provenance: BindingProvenance::Rooted,
        epoch: 1,
        retired_at: None,
    };
    let envelope = serde_json::to_value(&row).expect("route row serializes");
    let canonical =
        ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canonicalize");
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&attester.signer(), &canonical, "route")
        .await
        .expect("sign the route");
    serde_json::to_vec(&SignedTransportDestination {
        attesting_key_id: attester.key_id().to_owned(),
        transport_destination: row,
        signed_envelope: envelope,
        signature: TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: pqc,
        },
    })
    .expect("encode")
}

/// (7) A signer that is NEVER bound gets the same retryable token, and the
/// index bounds it. Driven on the route door, where only the typed arm indexes
/// (the occurrence plane also has the untyped held-signer fallback). The first
/// refusal waits the first transient window (`TRANSIENT_BASE`, 20 s); the
/// second moves the row to the terminal schedule (`TERMINAL_BASE`, 1800 s,
/// doubling to the 6 h `TERMINAL_CAP`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_never_bound_signer_settles_on_the_terminal_schedule_after_two_offers() {
    use crate::replication::refusal_backoff::{TERMINAL_BASE, TRANSIENT_BASE};
    const TD: EnvelopeKind = EnvelopeKind::TransportDestination;
    let victim = Ident::mint("node-v-fix7g", "node", 0xb1).await;
    let x = Ident::mint("node-x-fix7g", "node", 0xb2).await;
    let f = substrate().await;
    hold(&f, &victim).await;
    hold(&f, &x).await;
    let bytes = route_for(&victim, &x).await;
    let h = sha(&bytes);
    let b = bridge(&f);
    let backoff = b.refusal_backoff_for_test();

    let first = b.apply_envelope_bytes(TD, &bytes, Some(PEER)).await;
    let ApplyOutcome::Refused { reason, .. } = &first else {
        panic!("a route by a signer that does not act for it is refused, got {first:?}");
    };
    assert!(
        reason.contains("federation_signer_not_acting_for"),
        "precondition: persist's verdict is SignerDoesNotActFor: {reason}"
    );
    assert_eq!(first.awaits_acts_for(), Some(x.key_id()), "{first:?}");
    assert_eq!(
        backoff.parked_on(x.key_id()),
        1,
        "indexed on the held signer"
    );
    let t1 = Instant::now();
    assert!(
        backoff.suppressed_at(
            TD,
            &h,
            t1 + TRANSIENT_BASE.saturating_sub(Duration::from_secs(5))
        ),
        "refusal 1: inside the first transient window"
    );
    assert!(
        !backoff.suppressed_at(TD, &h, t1 + TRANSIENT_BASE + Duration::from_secs(5)),
        "refusal 1: re-asked after the first transient window (the binding may land)"
    );

    // The second offer of the same bytes; X is still bound to nothing.
    let second = b.apply_envelope_bytes(TD, &bytes, Some(PEER)).await;
    assert_eq!(second.awaits_acts_for(), Some(x.key_id()), "{second:?}");
    let t2 = Instant::now();
    assert!(
        backoff.suppressed_at(
            TD,
            &h,
            t2 + TERMINAL_BASE.saturating_sub(Duration::from_secs(60))
        ),
        "refusal 2: on the TERMINAL schedule — a never-bound signer is not re-asked on \
         the transient ladder (CIRISEdge#858)"
    );
    assert!(
        !backoff.suppressed_at(TD, &h, t2 + TERMINAL_BASE + Duration::from_secs(60)),
        "refusal 2: the terminal window is bounded, never infinite"
    );
    assert_eq!(
        backoff.parked_on(x.key_id()),
        1,
        "still indexed: a binding releases it"
    );
}
