//! CIRISEdge#169 — host serve-path tests.
//!
//! Two disciplines this repo learned the hard way and applies here:
//!
//! * **Both sides asserted.** Every refusal test is paired with an
//!   admission on the same node, so a serve path that refused
//!   *everything* could not pass.
//! * **One bound per fixture.** Every ceiling test starts from
//!   [`generous`] — limits set high enough that nothing else can fire —
//!   and lowers exactly the field under test. A test that passed because
//!   a neighbouring default was already safe would prove nothing, which
//!   is the trap that has bitten this repo repeatedly.

use super::*;
use leviculum_lxmf::constants::{LXMF_OVERHEAD, STAMP_SIZE};
use leviculum_lxmf::msgpack;

const A: DestinationHash16 = [0xAA; DESTINATION_LENGTH];
const B: DestinationHash16 = [0xBB; DESTINATION_LENGTH];
const C: DestinationHash16 = [0xCC; DESTINATION_LENGTH];

/// Ciphertext length that clears `LXMF_OVERHEAD` with room to spare.
const CIPHER_LEN: usize = 200;

/// What one parked fixture message costs the byte budget.
///
/// Spelled out rather than inlined because it is easy to get wrong in a
/// way that makes a ceiling test pass for the wrong reason: the stored
/// value is the VERBATIM unstamped LXMF payload, which already begins with
/// its own 16-byte destination hash, and on top of that the mailbox is
/// keyed by (destination, transient ID).
const fn entry_cost() -> usize {
    ENTRY_OVERHEAD_BYTES + DESTINATION_LENGTH + CIPHER_LEN
}

/// Limits under which NO bound can fire. Each ceiling test lowers exactly
/// one field, so the assertion can only be explained by that field.
fn generous() -> LxmfServeLimits {
    LxmfServeLimits {
        max_request_bytes: 1 << 20,
        max_upload_bytes: 1 << 20,
        max_ids_per_request: 4096,
        max_store_bytes: 1 << 20,
        max_messages_per_destination: 4096,
        max_destinations: 4096,
        max_messages_per_response: 4096,
        max_response_bytes: 1 << 20,
        retention: Duration::from_secs(3600),
        // 0 keeps the fixtures fast; the stamp bound has its own test that
        // runs at a real non-zero cost.
        stamp_cost: 0,
    }
}

fn roster(dests: &[DestinationHash16]) -> BTreeSet<DestinationHash16> {
    dests.iter().copied().collect()
}

fn node(dests: &[DestinationHash16], limits: LxmfServeLimits) -> LxmfServeNode {
    LxmfServeNode::new(PropagationAudience::Roster(roster(dests)), limits)
}

/// `destination_hash || ciphertext` — the unstamped LXMF shape a
/// propagation node indexes. `tag` varies the ciphertext so distinct
/// messages get distinct transient IDs.
fn unstamped(dest: DestinationHash16, tag: u8, cipher_len: usize) -> Vec<u8> {
    let mut v = dest.to_vec();
    v.extend(std::iter::repeat_n(tag, cipher_len));
    v
}

/// A real upload envelope, stamped at `cost` by the SAME generator a field
/// client uses — field provenance, not a convenient hand-built stamp.
fn upload_at_cost(dest: DestinationHash16, tag: u8, cipher_len: usize, cost: u8) -> Vec<u8> {
    let payload = unstamped(dest, tag, cipher_len);
    let stamp = crate::transport::lxmf_propagation::LxmfPropagationClient::new()
        .generate_propagation_stamp(&payload, cost)
        .expect("stamp generation");
    PropagationUpload::single(1.0, payload, stamp).encode()
}

/// An upload envelope stamped at cost 0 (the `generous` fixture).
fn upload(dest: DestinationHash16, tag: u8) -> Vec<u8> {
    upload_at_cost(dest, tag, CIPHER_LEN, 0)
}

fn transient_of(dest: DestinationHash16, tag: u8, cipher_len: usize) -> TransientId {
    leviculum_core::crypto::full_hash(&unstamped(dest, tag, cipher_len))
}

fn admitted(result: &ServeResult) -> (TransientId, DestinationHash16) {
    match result.outcome {
        ServeOutcome::Admitted {
            transient_id,
            destination,
        } => (transient_id, destination),
        ref other => panic!("expected Admitted, got {other:?}"),
    }
}

fn responded(result: &ServeResult) -> &[u8] {
    match result.outcome {
        ServeOutcome::Respond(ref bytes) => bytes,
        ref other => panic!("expected Respond, got {other:?}"),
    }
}

fn listed(result: &ServeResult) -> Vec<TransientId> {
    match MessageListResponse::decode(responded(result)).expect("list response decodes") {
        MessageListResponse::TransientIds(ids) => ids,
        MessageListResponse::Error(e) => panic!("expected ids, got peer error {e:?}"),
    }
}

fn downloaded(result: &ServeResult) -> Vec<Vec<u8>> {
    match MessageGetResponse::decode(responded(result)).expect("get response decodes") {
        MessageGetResponse::Messages(m) => m,
        MessageGetResponse::Error(e) => panic!("expected messages, got peer error {e:?}"),
    }
}

fn has_notice(result: &ServeResult, reason: WithholdReason) -> bool {
    result.notices.iter().any(|n| n.reason == reason)
}

fn count_notice(result: &ServeResult, reason: WithholdReason) -> usize {
    result.notices.iter().filter(|n| n.reason == reason).count()
}

fn list_request() -> Vec<u8> {
    MessageGetRequest::list().encode().expect("list encodes")
}

fn get_request(wants: Vec<TransientId>) -> Vec<u8> {
    MessageGetRequest {
        wants: Some(wants),
        haves: None,
        transfer_limit_kb: None,
    }
    .encode()
    .expect("get encodes")
}

fn ack_request(haves: Vec<TransientId>) -> Vec<u8> {
    MessageGetRequest::acknowledge(haves)
        .encode()
        .expect("ack encodes")
}

// ─────────────────────────────────────────────────────────────────────
// The headline pair: admits well-formed, refuses malformed
// ─────────────────────────────────────────────────────────────────────

/// The serve path admits a well-formed upload AND refuses a malformed one
/// **on the same node**, so it cannot pass by refusing everything.
#[test]
fn admits_well_formed_upload_and_refuses_malformed_one() {
    let n = node(&[A], generous());
    let t0 = Instant::now();

    let good = n.serve_upload(&upload(A, 0x01), t0);
    let (id, dest) = admitted(&good);
    assert_eq!(dest, A);
    assert_eq!(id, transient_of(A, 0x01, CIPHER_LEN));
    assert!(good.notices.is_empty(), "a clean admit emits no notices");
    assert_eq!(n.pending_for(&A), 1);

    // Malformed: not a msgpack upload envelope at all.
    let bad = n.serve_upload(&[0x00, 0x01, 0x02], t0);
    assert_eq!(
        bad.refused_reason(),
        Some(WithholdReason::LxmfWireUnparseable)
    );
    // The refusal did not disturb the admitted message.
    assert_eq!(n.pending_for(&A), 1, "a refusal must not evict good mail");
}

/// The full happy path over the real leviculum-lxmf wire: upload → list →
/// download → acknowledge, with the served ciphertext byte-identical to
/// what was uploaded (the node never rewraps, and holds no key to decrypt).
#[test]
fn round_trip_upload_list_download_acknowledge() {
    let n = node(&[A], generous());
    let t0 = Instant::now();
    let payload = unstamped(A, 0x07, CIPHER_LEN);

    let (id, _) = admitted(&n.serve_upload(&upload(A, 0x07), t0));

    let list = n.serve_get(Some(A), &list_request(), t0);
    assert_eq!(listed(&list), vec![id]);

    let got = n.serve_get(Some(A), &get_request(vec![id]), t0);
    assert_eq!(
        downloaded(&got),
        vec![payload],
        "served bytes must be the uploaded ciphertext, verbatim"
    );

    let ack = n.serve_get(Some(A), &ack_request(vec![id]), t0);
    assert!(listed(&ack).is_empty(), "acknowledge purges");
    assert_eq!(n.pending_for(&A), 0);
    assert_eq!(n.destination_count(), 0, "an emptied mailbox is reclaimed");
    assert_eq!(n.stored_bytes(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// Recipient scoping — the contextual-integrity core
// ─────────────────────────────────────────────────────────────────────

/// B cannot download A's mail, and the probe is REPORTED rather than
/// silently omitted. A's message survives.
#[test]
fn a_requester_cannot_download_another_destinations_mail() {
    let n = node(&[A, B], generous());
    let t0 = Instant::now();
    let (a_id, _) = admitted(&n.serve_upload(&upload(A, 0x11), t0));

    // Sanity: A really can fetch it — so the refusal below is scoping, not
    // a node that serves nobody.
    assert_eq!(
        downloaded(&n.serve_get(Some(A), &get_request(vec![a_id]), t0)).len(),
        1
    );

    let probe = n.serve_get(Some(B), &get_request(vec![a_id]), t0);
    assert!(
        downloaded(&probe).is_empty(),
        "B must receive none of A's messages"
    );
    assert!(
        has_notice(&probe, WithholdReason::LxmfMailboxScopeMismatch),
        "a cross-recipient probe must be reported, not silently omitted"
    );
    assert_eq!(n.pending_for(&A), 1, "A's mail is untouched");
}

/// B cannot PURGE A's mail by acknowledging its transient ID — the
/// censorship lever the per-destination index closes.
#[test]
fn a_requester_cannot_acknowledge_away_another_destinations_mail() {
    let n = node(&[A, B], generous());
    let t0 = Instant::now();
    let (a_id, _) = admitted(&n.serve_upload(&upload(A, 0x22), t0));

    let attack = n.serve_get(Some(B), &ack_request(vec![a_id]), t0);
    assert!(
        has_notice(&attack, WithholdReason::LxmfMailboxScopeMismatch),
        "a foreign acknowledge must be reported"
    );
    assert_eq!(
        n.pending_for(&A),
        1,
        "A's mail must survive B's acknowledge"
    );

    // And A can still collect it — the message was never damaged.
    assert_eq!(
        downloaded(&n.serve_get(Some(A), &get_request(vec![a_id]), t0)).len(),
        1
    );
}

/// A list response contains only the requester's own mail.
#[test]
fn list_is_scoped_to_the_requesters_own_mailbox() {
    let n = node(&[A, B], generous());
    let t0 = Instant::now();
    let (a_id, _) = admitted(&n.serve_upload(&upload(A, 0x31), t0));
    let (b_id, _) = admitted(&n.serve_upload(&upload(B, 0x32), t0));
    assert_ne!(a_id, b_id);

    assert_eq!(
        listed(&n.serve_get(Some(A), &list_request(), t0)),
        vec![a_id]
    );
    assert_eq!(
        listed(&n.serve_get(Some(B), &list_request(), t0)),
        vec![b_id]
    );
}

/// An ordinary miss (nobody holds the ID) is NOT reported as a scope
/// mismatch — otherwise routine races would drown the attack signal.
#[test]
fn an_unheld_transient_id_is_a_miss_not_a_scope_mismatch() {
    let n = node(&[A], generous());
    let t0 = Instant::now();
    admitted(&n.serve_upload(&upload(A, 0x41), t0));

    let miss = n.serve_get(Some(A), &get_request(vec![[0x99; 32]]), t0);
    assert!(downloaded(&miss).is_empty());
    assert!(
        !has_notice(&miss, WithholdReason::LxmfMailboxScopeMismatch),
        "an ID nobody holds is an absence, not a cross-recipient probe"
    );
}

// ─────────────────────────────────────────────────────────────────────
// Audience — default OFF, explicit roster, both legs
// ─────────────────────────────────────────────────────────────────────

/// The default posture carries nobody's mail, on both legs, and says so.
#[test]
fn the_default_posture_serves_nobody_and_names_the_refusal() {
    assert_eq!(
        PropagationAudience::default(),
        PropagationAudience::Disabled
    );
    let n = LxmfServeNode::disabled();
    let t0 = Instant::now();

    let up = n.serve_upload(&upload(A, 0x51), t0);
    assert_eq!(
        up.refused_reason(),
        Some(WithholdReason::LxmfPropagationDisabled)
    );
    let get = n.serve_get(Some(A), &list_request(), t0);
    assert_eq!(
        get.refused_reason(),
        Some(WithholdReason::LxmfPropagationDisabled)
    );
    assert_eq!(n.stored_bytes(), 0);
}

/// Roster is checked on BOTH legs: an off-roster recipient's upload is
/// refused, and an off-roster requester's `/get` is refused — while the
/// rostered destination works, so the roster is a filter, not a wall.
#[test]
fn the_roster_gates_both_the_upload_recipient_and_the_get_requester() {
    let n = node(&[A], generous());
    let t0 = Instant::now();

    admitted(&n.serve_upload(&upload(A, 0x61), t0));

    let off_roster_upload = n.serve_upload(&upload(C, 0x62), t0);
    assert_eq!(
        off_roster_upload.refused_reason(),
        Some(WithholdReason::LxmfDestinationNotServed)
    );
    assert_eq!(n.destination_count(), 1, "no mailbox minted for C");

    let off_roster_get = n.serve_get(Some(C), &list_request(), t0);
    assert_eq!(
        off_roster_get.refused_reason(),
        Some(WithholdReason::LxmfDestinationNotServed)
    );
}

/// An unidentified link gets no mail — there is no answer to "whose
/// mailbox is this".
#[test]
fn an_unidentified_requester_is_refused() {
    let n = node(&[A], generous());
    let t0 = Instant::now();
    admitted(&n.serve_upload(&upload(A, 0x71), t0));

    let anon = n.serve_get(None, &list_request(), t0);
    assert_eq!(
        anon.refused_reason(),
        Some(WithholdReason::LxmfRequesterUnidentified)
    );
    // Identified, the same request succeeds.
    assert_eq!(listed(&n.serve_get(Some(A), &list_request(), t0)).len(), 1);
}

// ─────────────────────────────────────────────────────────────────────
// Bounds, each exercised AT its ceiling and one step past it
// ─────────────────────────────────────────────────────────────────────

/// `max_request_bytes`: a body exactly at the ceiling passes the size gate
/// (and is then judged on its content); one byte over is refused by the
/// size gate itself. The two different reasons prove the boundary is where
/// it is claimed to be.
#[test]
fn max_request_bytes_admits_at_the_ceiling_and_refuses_one_over() {
    let mut limits = generous();
    limits.max_request_bytes = 64;
    let n = node(&[A], limits);
    let t0 = Instant::now();

    let at = n.serve_get(Some(A), &[0xFFu8; 64], t0);
    assert_eq!(
        at.refused_reason(),
        Some(WithholdReason::LxmfWireUnparseable),
        "exactly at the ceiling must reach the decoder, not the size gate"
    );

    let over = n.serve_get(Some(A), &[0xFFu8; 65], t0);
    assert_eq!(
        over.refused_reason(),
        Some(WithholdReason::LxmfFrameOversized)
    );

    // And a real request under the ceiling still works.
    assert!(listed(&n.serve_get(Some(A), &list_request(), t0)).is_empty());
}

/// `max_upload_bytes`: same boundary discipline on the upload leg.
#[test]
fn max_upload_bytes_admits_at_the_ceiling_and_refuses_one_over() {
    let body = upload(A, 0x81);
    let mut limits = generous();
    limits.max_upload_bytes = body.len();
    let n = node(&[A], limits);
    let t0 = Instant::now();

    // Exactly at the ceiling: admitted.
    admitted(&n.serve_upload(&body, t0));

    // One byte over the ceiling: refused by the size gate.
    let over = n.serve_upload(&vec![0x00u8; body.len() + 1], t0);
    assert_eq!(
        over.refused_reason(),
        Some(WithholdReason::LxmfFrameOversized)
    );
}

/// `max_ids_per_request`: `wants` + `haves` are counted together, so the
/// ceiling cannot be doubled by splitting a request across both fields.
#[test]
fn max_ids_per_request_counts_wants_and_haves_together() {
    let mut limits = generous();
    limits.max_ids_per_request = 2;
    let n = node(&[A], limits);
    let t0 = Instant::now();

    let at = n.serve_get(Some(A), &get_request(vec![[1u8; 32], [2u8; 32]]), t0);
    assert!(
        at.refused_reason().is_none(),
        "two IDs is exactly the ceiling"
    );

    let over = n.serve_get(
        Some(A),
        &get_request(vec![[1u8; 32], [2u8; 32], [3u8; 32]]),
        t0,
    );
    assert_eq!(
        over.refused_reason(),
        Some(WithholdReason::LxmfFrameOversized)
    );

    // Split across both fields: 2 wants + 1 have is still 3.
    let split = MessageGetRequest {
        wants: Some(vec![[1u8; 32], [2u8; 32]]),
        haves: Some(vec![[3u8; 32]]),
        transfer_limit_kb: None,
    }
    .encode()
    .expect("encodes");
    assert_eq!(
        n.serve_get(Some(A), &split, t0).refused_reason(),
        Some(WithholdReason::LxmfFrameOversized),
        "the ceiling must not be doubled by splitting across wants and haves"
    );
}

/// `max_store_bytes`: the byte budget counts KEY bytes as well as
/// ciphertext (the upstream `MemoryLxmfStorage` lesson), and a submission
/// landing exactly on the budget is admitted while the next is refused.
#[test]
fn max_store_bytes_admits_exactly_at_the_budget_and_refuses_past_it() {
    let entry = entry_cost();
    let mut limits = generous();
    limits.max_store_bytes = entry * 2;
    let n = node(&[A], limits);
    let t0 = Instant::now();

    admitted(&n.serve_upload(&upload(A, 0x91), t0));
    admitted(&n.serve_upload(&upload(A, 0x92), t0));
    assert_eq!(
        n.stored_bytes(),
        entry * 2,
        "accounting must include the destination hash and transient ID"
    );

    let over = n.serve_upload(&upload(A, 0x93), t0);
    assert_eq!(over.refused_reason(), Some(WithholdReason::LxmfMailboxFull));
    assert_eq!(n.pending_for(&A), 2, "refuse, never evict to admit");
}

/// `max_messages_per_destination`: full means refused, and — the security
/// property — the messages already parked are NOT evicted to make room.
#[test]
fn max_messages_per_destination_refuses_rather_than_evicting() {
    let mut limits = generous();
    limits.max_messages_per_destination = 2;
    let n = node(&[A], limits);
    let t0 = Instant::now();

    let (first, _) = admitted(&n.serve_upload(&upload(A, 0xA1), t0));
    admitted(&n.serve_upload(&upload(A, 0xA2), t0));

    let over = n.serve_upload(&upload(A, 0xA3), t0);
    assert_eq!(over.refused_reason(), Some(WithholdReason::LxmfMailboxFull));
    assert_eq!(n.pending_for(&A), 2);
    assert!(
        listed(&n.serve_get(Some(A), &list_request(), t0)).contains(&first),
        "the OLDEST message must survive: evicting it would let an attacker \
         flush a victim's mailbox with junk uploads"
    );
}

/// A repeat upload of an already-parked message is idempotent: it is not
/// charged against the depth cap, so a full mailbox still accepts a retry.
#[test]
fn a_repeat_upload_is_idempotent_at_the_depth_ceiling() {
    let mut limits = generous();
    limits.max_messages_per_destination = 2;
    let n = node(&[A], limits);
    let t0 = Instant::now();

    admitted(&n.serve_upload(&upload(A, 0xB1), t0));
    admitted(&n.serve_upload(&upload(A, 0xB2), t0));
    // At the ceiling — but this is a re-send of one already held.
    admitted(&n.serve_upload(&upload(A, 0xB1), t0));
    assert_eq!(n.pending_for(&A), 2);
    assert_eq!(n.stored_bytes(), entry_cost() * 2);
}

/// `max_destinations`: the ceiling bounds NEW mailboxes; an existing
/// destination keeps working once the ceiling is reached.
#[test]
fn max_destinations_bounds_new_mailboxes_only() {
    let mut limits = generous();
    limits.max_destinations = 2;
    let n = node(&[A, B, C], limits);
    let t0 = Instant::now();

    admitted(&n.serve_upload(&upload(A, 0xC1), t0));
    admitted(&n.serve_upload(&upload(B, 0xC2), t0));
    assert_eq!(n.destination_count(), 2);

    let third = n.serve_upload(&upload(C, 0xC3), t0);
    assert_eq!(
        third.refused_reason(),
        Some(WithholdReason::LxmfMailboxFull)
    );
    assert_eq!(
        n.destination_count(),
        2,
        "a refused upload mints no mailbox"
    );

    // An already-known destination is unaffected by the destination cap.
    admitted(&n.serve_upload(&upload(A, 0xC4), t0));
    assert_eq!(n.pending_for(&A), 2);
}

/// `max_messages_per_response`: the response is truncated at the ceiling
/// and the held-back messages are REPORTED (they are withheld, not missing).
#[test]
fn max_messages_per_response_truncates_at_the_ceiling_and_reports() {
    let mut limits = generous();
    limits.max_messages_per_response = 1;
    let n = node(&[A], limits);
    let t0 = Instant::now();
    let (id1, _) = admitted(&n.serve_upload(&upload(A, 0xD1), t0));
    let (id2, _) = admitted(&n.serve_upload(&upload(A, 0xD2), t0));

    let got = n.serve_get(Some(A), &get_request(vec![id1, id2]), t0);
    assert_eq!(downloaded(&got).len(), 1, "truncated at the ceiling");
    assert_eq!(
        count_notice(&got, WithholdReason::LxmfFrameOversized),
        1,
        "the held-back message must be reported, not silently dropped"
    );
    // Nothing was consumed: both are still parked for a follow-up request.
    assert_eq!(n.pending_for(&A), 2);
}

/// `max_response_bytes`: one message exactly fills the budget; the second
/// is withheld and reported.
#[test]
fn max_response_bytes_admits_exactly_one_full_budget_and_reports_the_rest() {
    let msg_len = DESTINATION_LENGTH + CIPHER_LEN;
    let mut limits = generous();
    limits.max_response_bytes = msg_len;
    let n = node(&[A], limits);
    let t0 = Instant::now();
    let (id1, _) = admitted(&n.serve_upload(&upload(A, 0xE1), t0));
    let (id2, _) = admitted(&n.serve_upload(&upload(A, 0xE2), t0));

    let got = n.serve_get(Some(A), &get_request(vec![id1, id2]), t0);
    assert_eq!(
        downloaded(&got).len(),
        1,
        "a message landing exactly on the byte budget is served"
    );
    assert_eq!(count_notice(&got, WithholdReason::LxmfFrameOversized), 1);

    // Raising the budget by one message admits both — proving the previous
    // truncation was the byte budget and not some other ceiling.
    let mut wider = generous();
    wider.max_response_bytes = msg_len * 2;
    let n2 = node(&[A], wider);
    admitted(&n2.serve_upload(&upload(A, 0xE1), t0));
    admitted(&n2.serve_upload(&upload(A, 0xE2), t0));
    assert_eq!(
        downloaded(&n2.serve_get(Some(A), &get_request(vec![id1, id2]), t0)).len(),
        2
    );
}

/// `retention`: a message is retained one instant short of the window and
/// evicted exactly at it — and the eviction is reported.
#[test]
fn retention_evicts_exactly_at_the_window_and_reports_it() {
    let mut limits = generous();
    limits.retention = Duration::from_secs(60);
    let n = node(&[A], limits);
    let t0 = Instant::now();
    admitted(&n.serve_upload(&upload(A, 0xF1), t0));

    // One nanosecond short of the window: still held, nothing reported.
    let just_under = n.sweep(
        (t0 + Duration::from_secs(60))
            .checked_sub(Duration::from_nanos(1))
            .expect("one nanosecond before the window"),
    );
    assert!(just_under.is_empty());
    assert_eq!(n.pending_for(&A), 1);

    // Exactly at the window: evicted, and loudly.
    let at = n.sweep(t0 + Duration::from_secs(60));
    assert_eq!(at.len(), 1);
    assert_eq!(at[0].reason, WithholdReason::LxmfRetentionExpired);
    assert_eq!(at[0].destination, Some(A));
    assert_eq!(n.pending_for(&A), 0);
    assert_eq!(n.stored_bytes(), 0, "eviction must reclaim the byte budget");
    assert_eq!(n.destination_count(), 0, "and the destination budget");
}

/// Retention is enforced on the request paths too, not only on an explicit
/// sweep — so an expired message is never served.
#[test]
fn an_expired_message_is_never_served() {
    let mut limits = generous();
    limits.retention = Duration::from_secs(60);
    let n = node(&[A], limits);
    let t0 = Instant::now();
    let (id, _) = admitted(&n.serve_upload(&upload(A, 0xF2), t0));

    // Before expiry it is served.
    assert_eq!(
        downloaded(&n.serve_get(Some(A), &get_request(vec![id]), t0)).len(),
        1
    );

    let later = t0 + Duration::from_secs(60);
    let got = n.serve_get(Some(A), &get_request(vec![id]), later);
    assert!(downloaded(&got).is_empty(), "expired mail is not served");
    assert!(
        has_notice(&got, WithholdReason::LxmfRetentionExpired),
        "the request path must report the eviction it performed"
    );
}

/// `stamp_cost`: a stamp below the advertised cost is refused with the
/// protocol's own signalling packet, and a REAL stamp at that cost is
/// admitted — so the gate is a price, not a wall.
#[test]
fn stamp_below_advertised_cost_is_refused_and_a_real_stamp_is_admitted() {
    let cost = 8u8;
    let mut limits = generous();
    limits.stamp_cost = cost;
    let n = node(&[A], limits);
    let t0 = Instant::now();

    // A stamp must be PROVEN under cost, not assumed to be. A stamp
    // generated at cost 0 clears cost 8 by chance about one time in 256,
    // which made an earlier version of this test flaky — so the fixture is
    // searched with the node's OWN validator and verified before use.
    let payload = unstamped(A, 0x01, CIPHER_LEN);
    let transient = leviculum_core::crypto::full_hash(&payload);
    let dud = (0u8..=255)
        .map(|seed| [seed; STAMP_SIZE])
        .find(|candidate| !n.stamp_clears_cost(&transient, candidate))
        .expect("some 32-byte stamp fails to clear cost 8");
    let understamped = PropagationUpload::single(1.0, payload.clone(), dud).encode();

    let refused = n.serve_upload(&understamped, t0);
    assert_eq!(
        refused.refused_reason(),
        Some(WithholdReason::LxmfStampBelowCost)
    );
    assert_eq!(n.pending_for(&A), 0, "spam must not reach storage");
    match refused.outcome {
        ServeOutcome::Refused {
            response: Some(ref bytes),
            ..
        } => assert_eq!(
            PropagationSignal::decode(bytes).expect("signal decodes"),
            PropagationSignal::InvalidStamp,
            "the refusal must be the protocol's own signalling packet"
        ),
        ref other => panic!("expected a signalled refusal, got {other:?}"),
    }

    // The same payload, stamped at the advertised cost, is admitted.
    let paid = upload_at_cost(A, 0x01, CIPHER_LEN, cost);
    admitted(&n.serve_upload(&paid, t0));
    assert_eq!(n.pending_for(&A), 1);
}

// ─────────────────────────────────────────────────────────────────────
// Wire-shape refusals
// ─────────────────────────────────────────────────────────────────────

/// A well-formed MULTI-message upload is the node-to-node `/offer` sync
/// form, which edge does not serve. It is reported as its own reason, NOT
/// folded into "malformed" — the operator's remedy is different.
#[test]
fn a_multi_message_upload_is_reported_as_the_unsupported_offer_form() {
    let n = node(&[A], generous());
    let t0 = Instant::now();

    // `[timestamp, [stamped_a, stamped_b]]` — the peer-sync wire shape.
    let stamped = |tag: u8| {
        let mut v = unstamped(A, tag, CIPHER_LEN);
        v.extend_from_slice(&[0u8; STAMP_SIZE]);
        v
    };
    let (m1, m2) = (stamped(0x01), stamped(0x02));
    let mut body = Vec::new();
    msgpack::array(&mut body, 2);
    msgpack::f64(&mut body, 1.0);
    msgpack::array(&mut body, 2);
    msgpack::bin(&mut body, &m1);
    msgpack::bin(&mut body, &m2);

    let refused = n.serve_upload(&body, t0);
    assert_eq!(
        refused.refused_reason(),
        Some(WithholdReason::LxmfPeerSyncUnsupported),
        "a peer /offer upload is a message for an endpoint we do not serve, \
         not a malformed one"
    );

    // The singleton form on the same node IS admitted.
    admitted(&n.serve_upload(&upload(A, 0x03), t0));
}

/// Structural pin: a payload short enough to make the destination hash
/// unreadable can never reach that code path, because
/// `PropagationUpload::decode` already guarantees
/// `unstamped.len() > LXMF_OVERHEAD` — exactly
/// `PropagatedMessage::from_unstamped_bytes`'s precondition. If leviculum
/// ever relaxes one guard without the other, this fails rather than edge
/// silently gaining an unreachable-turned-reachable branch.
#[test]
fn decode_success_implies_readable_destination() {
    for cipher_len in [0usize, 1, 95, 96, 97, LXMF_OVERHEAD, LXMF_OVERHEAD + 1, 200] {
        let payload = unstamped(A, 0x01, cipher_len);
        let body = PropagationUpload::single(1.0, payload.clone(), [0u8; STAMP_SIZE]).encode();
        if let Ok(decoded) = PropagationUpload::decode(&body) {
            assert!(
                PropagatedMessage::from_unstamped_bytes(decoded.unstamped_lxmf()).is_ok(),
                "decode accepted a {cipher_len}-byte ciphertext whose destination \
                 hash is unreadable — the two guards have drifted apart",
            );
        }
    }
}

/// A too-short upload is refused as malformed rather than parked.
#[test]
fn a_too_short_upload_is_refused() {
    let n = node(&[A], generous());
    let t0 = Instant::now();
    let short = PropagationUpload::single(1.0, vec![0x01; 8], [0u8; STAMP_SIZE]).encode();
    assert_eq!(
        n.serve_upload(&short, t0).refused_reason(),
        Some(WithholdReason::LxmfWireUnparseable)
    );
    assert_eq!(n.stored_bytes(), 0);
}

// ─────────────────────────────────────────────────────────────────────
// Contextual integrity + refusal-reply shape
// ─────────────────────────────────────────────────────────────────────

/// Every serve-path refusal names the commitment it defends, and the
/// attribution comes from `parameter_of` alone — never a second table.
#[test]
fn every_serve_path_reason_is_attributed_to_its_commitment() {
    let expected = [
        (
            WithholdReason::LxmfPropagationDisabled,
            CiParameter::TransmissionPrinciple,
        ),
        (
            WithholdReason::LxmfDestinationNotServed,
            CiParameter::Recipient,
        ),
        (
            WithholdReason::LxmfRequesterUnidentified,
            CiParameter::Sender,
        ),
        (
            WithholdReason::LxmfMailboxScopeMismatch,
            CiParameter::Recipient,
        ),
        (
            WithholdReason::LxmfStampBelowCost,
            CiParameter::TransmissionPrinciple,
        ),
        (
            WithholdReason::LxmfWireUnparseable,
            CiParameter::InformationType,
        ),
        (
            WithholdReason::LxmfPeerSyncUnsupported,
            CiParameter::InformationType,
        ),
        (
            WithholdReason::LxmfFrameOversized,
            CiParameter::TransmissionPrinciple,
        ),
        (
            WithholdReason::LxmfMailboxFull,
            CiParameter::TransmissionPrinciple,
        ),
        (
            WithholdReason::LxmfRetentionExpired,
            CiParameter::TransmissionPrinciple,
        ),
    ];
    for (reason, parameter) in expected {
        let notice = Notice::new(reason, "test", None);
        assert_eq!(notice.parameter(), parameter, "{}", reason.as_str());
        assert_eq!(
            notice.delivery(),
            Delivery::withheld(reason),
            "the notice's delivery must come from parameter_of, not a copy",
        );
    }
}

/// Every `/get` refusal carries a decodable `PeerError` reply, so a client
/// learns why rather than timing out; upload refusals carry a reply only
/// where the protocol defines one.
#[test]
fn get_refusals_carry_a_decodable_peer_error() {
    let n = node(&[A], generous());
    let t0 = Instant::now();
    let cases = [
        n.serve_get(None, &list_request(), t0),
        n.serve_get(Some(C), &list_request(), t0),
        n.serve_get(Some(A), &[0xFF, 0xFE], t0),
        LxmfServeNode::disabled().serve_get(Some(A), &list_request(), t0),
    ];
    for case in &cases {
        let ServeOutcome::Refused {
            response: Some(ref bytes),
            reason,
            ..
        } = case.outcome
        else {
            panic!("expected a refusal with a reply, got {:?}", case.outcome);
        };
        assert!(
            matches!(
                MessageListResponse::decode(bytes),
                Ok(MessageListResponse::Error(_))
            ),
            "{} must answer with a decodable PeerError",
            reason.as_str(),
        );
    }
}

/// Every refusal also pushes its own notice, so the ledger sees the
/// refusal even when the caller only forwards the wire reply.
#[test]
fn every_refusal_emits_a_matching_notice() {
    let n = node(&[A], generous());
    let t0 = Instant::now();
    for case in [
        n.serve_get(None, &list_request(), t0),
        n.serve_get(Some(C), &list_request(), t0),
        n.serve_upload(&upload(C, 0x01), t0),
        n.serve_upload(&[0x00], t0),
    ] {
        let reason = case.refused_reason().expect("refusal");
        assert!(
            has_notice(&case, reason),
            "{} must appear in notices, not only in the outcome",
            reason.as_str(),
        );
    }
}

// ── The roster rule: cohort membership, not RNS transit eligibility ──

/// The propagation roster is COHORT MEMBERSHIP — self, family, and the
/// communities this node is in — and deliberately NOT the RNS transit rule.
///
/// Reusing `resolve_transit_eligibility` here would admit any trust-anchored
/// node self-offering `infra:transport`. That bar is proportionate to "carries
/// ciphertext and forgets"; it is not proportionate to "holds your mailbox and
/// knows when you check it". See `PropagationAudience`'s docs for the full
/// reasoning.
#[test]
fn the_roster_is_cohort_membership_and_admits_only_members() {
    use crate::cohort_scope::CohortScope;
    use crate::scope_addressing::{ScopeAddressTable, StubDeriver};
    use std::sync::Arc;

    let family = CohortScope::Family;
    let table = ScopeAddressTable::new(Arc::new(StubDeriver));
    table
        .install_group(&family, "kin", 1, &[7u8; 32], &["me", "sibling"])
        .expect("install");

    let audience = PropagationAudience::from_cohort_membership(
        &table,
        &[(family.clone(), "kin".to_owned())],
        &|_, _| vec!["me".to_owned(), "sibling".to_owned()],
    );

    for member in ["me", "sibling"] {
        let addr = table.send_address(&family, "kin", member).expect("addr");
        assert!(
            audience.serves(addr.as_bytes()),
            "{member} is in the cohort, so this node holds mail for them",
        );
    }

    // The half the transit rule would get wrong: a stranger sharing a trust
    // root passes `infra:transport` and must still fail here.
    assert!(
        !audience.serves(&[0x5a; DESTINATION_LENGTH]),
        "a non-member destination must not be served",
    );
}

/// An empty membership collapses to `Disabled` rather than an armed-but-empty
/// roster: there must be no state in which a node believes it is carrying mail
/// and is not.
#[test]
fn an_empty_membership_collapses_to_disabled() {
    use crate::scope_addressing::{ScopeAddressTable, StubDeriver};
    use std::sync::Arc;

    let table = ScopeAddressTable::new(Arc::new(StubDeriver));
    let audience = PropagationAudience::from_cohort_membership(&table, &[], &|_, _| Vec::new());
    assert_eq!(audience, PropagationAudience::Disabled);
    assert!(!audience.serves(&[0u8; DESTINATION_LENGTH]));
}
