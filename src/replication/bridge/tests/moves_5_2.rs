//! **CC 5.2 — what moves to a peer** (`CLM-moves-requested-required-appropriate`).
//!
//! A row moves when it is requested, or required, and appropriate, never
//! because it is federation-tier. Every witness reads the production advertise
//! (`list_envelope_refs_for_peer`) over a store with a history in it, and each
//! fails on the walk it replaced, where a consented peer was offered every
//! federation row oldest first.
use super::*;
use crate::replication::counting_directory_930::CountingDirectory;

const LOCAL: &str = "moves-node";
const CONTACT: &str = "moves-contact";
const SEAT: &str = "moves-seat";
const THIRD: &str = "moves-third";
/// Rows of history, and the page that reads them.
const HISTORY: usize = 40;
const PAGE: u32 = 8;
/// Rounds that walk all of it, a page a round.
const WALK_ROUNDS: u32 = 7;
/// Rounds a store-read count runs over.
const ROUNDS: usize = 10;

fn page_bridge(backend: &Arc<SqliteBackend>) -> FederationDirectoryReplicationBridge {
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort: CohortProvider = Arc::new(|| vec![LOCAL.to_owned()]);
    FederationDirectoryReplicationBridge::with_config(
        dir,
        cohort,
        BridgeConfig {
            sweep_page_rows: PAGE,
            tip_margin: Duration::from_hours(1),
            ..BridgeConfig::default()
        },
    )
    .with_local_key_id(Some(LOCAL.to_owned()))
}

async fn fixture() -> Arc<SqliteBackend> {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[
            (LOCAL, identity_type::NODE),
            (CONTACT, identity_type::NODE),
            (SEAT, identity_type::NODE),
            (THIRD, identity_type::NODE),
        ],
    )
    .await;
    backend
}

/// One federation-scoped `scores` row. Returns its id.
async fn row(backend: &SqliteBackend, author: &str, about: &str, dimension: &str) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": author,
        "attested_key_id": about,
        "attestation_type": "scores",
        "dimension": dimension,
    });
    seed_raw_attestation(backend, &id, author, about, "scores", envelope).await;
    id
}

/// A composer of `target` by `author`, of `kind`. Returns its id.
async fn composer(
    backend: &SqliteBackend,
    author: &str,
    about: &str,
    kind: &str,
    target: &str,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": author,
        "attested_key_id": about,
        "attestation_type": kind,
        "kind": kind,
        "references_attestation_id": target,
        "references_attestation_type": "scores",
    });
    seed_raw_attestation(backend, &id, author, about, kind, envelope).await;
    id
}

/// A contact's grant: this node's `consent:replication` naming it, for `prefixes`.
async fn grant(backend: &SqliteBackend, peer: &str, prefixes: &[&str]) -> String {
    seed_common_root(backend, &[LOCAL, peer]).await;
    let id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": LOCAL,
        "attested_key_id": peer,
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": { "grants": "transfer", "attestation_prefixes": prefixes },
    });
    seed_raw_attestation(backend, &id, LOCAL, peer, "scores", envelope).await;
    id
}

async fn history(backend: &SqliteBackend) -> Vec<String> {
    let mut ids = Vec::new();
    for _ in 0..HISTORY {
        ids.push(row(backend, THIRD, THIRD, "observation:reachability:v1").await);
    }
    ids
}

async fn offer(bridge: &FederationDirectoryReplicationBridge, peer: &str) -> Vec<EnvelopeRef> {
    bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
        .await
}

async fn offers(
    backend: &SqliteBackend,
    bridge: &FederationDirectoryReplicationBridge,
    peer: &str,
    id: &str,
) -> bool {
    let hash = hash_of(backend, id).await;
    offer(bridge, peer)
        .await
        .iter()
        .any(|r| r.envelope_hash == hash)
}

/// The field case: a new contact, a large store, a fresh grant at the tip. The
/// grant is first in the very first offer, and no history is offered at all.
#[tokio::test]
async fn a_fresh_grant_moves_first_and_history_is_not_offered() {
    let backend = fixture().await;
    let past = history(&backend).await;
    let fresh = grant(&backend, CONTACT, &["trace:"]).await;
    let bridge = page_bridge(&backend);

    let refs = offer(&bridge, CONTACT).await;
    let hash = hash_of(&backend, &fresh).await;
    assert_eq!(
        refs.first().map(|r| r.envelope_hash),
        Some(hash),
        "the grant leads the first offer, ahead of any walk: {refs:?}"
    );
    assert_eq!(
        refs.first().map(|r| r.seq),
        Some(REQUIRED_ROW_SEQ),
        "and the push, which goes oldest seq first, sends it first too"
    );
    for id in &past {
        let old = hash_of(&backend, id).await;
        assert!(
            !refs.iter().any(|r| r.envelope_hash == old),
            "a third party's federation row is not offered to a contact"
        );
    }
    // The walk still reads the plane, and offers none of it across its rounds.
    let mut waiting = 0;
    for _ in 0..WALK_ROUNDS {
        let round = offer(&bridge, CONTACT).await;
        waiting += bridge
            .last_advertise_round
            .lock()
            .expect("the round summary")
            .as_ref()
            .map_or(0, |r| r.awaits_request);
        for id in &past {
            let old = hash_of(&backend, id).await;
            assert!(
                !round.iter().any(|r| r.envelope_hash == old),
                "a contact's offer stays the required rows, round after round"
            );
        }
    }
    assert!(
        waiting > 0,
        "the rows the walk passed are counted, not silent"
    );
}

/// The row the server's contact flow turns on: a contact's grant to us, carried
/// by a node that holds it (`inbound_chat_grants` reads it for request-seen and
/// mutual). It reaches the peer it names in the first offer, over history, on
/// the attested-key read, and this node holds no grant of its own for the peer.
#[tokio::test]
async fn a_contacts_grant_reaches_the_peer_it_names_ahead_of_history() {
    let backend = fixture().await;
    history(&backend).await;
    seed_common_root(&backend, &[LOCAL, THIRD, CONTACT]).await;
    let theirs = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": theirs,
        "attesting_key_id": THIRD,
        "attested_key_id": CONTACT,
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": {
            "grants": "transfer",
            "attestation_prefixes": ["chat:", "ownership:", "self:delegates_to:"],
        },
    });
    seed_raw_attestation(&backend, &theirs, THIRD, CONTACT, "scores", envelope).await;
    let bridge = page_bridge(&backend);

    let refs = offer(&bridge, CONTACT).await;
    let hash = hash_of(&backend, &theirs).await;
    let held = refs.iter().find(|r| r.envelope_hash == hash);
    assert_eq!(
        held.map(|r| r.seq),
        Some(REQUIRED_ROW_SEQ),
        "offered in the first round as a required row: {refs:?}"
    );
}

/// A contact grant names a person, signed by a person, and the two nodes are
/// how they are reached (#524): the grant leads the offer to the named person's
/// node.
#[tokio::test]
async fn a_person_named_grant_reaches_that_persons_node_first() {
    let backend = fixture().await;
    history(&backend).await;
    register_fixture_keys(
        &backend,
        &[
            ("moves-us", identity_type::USER),
            ("moves-them", identity_type::USER),
        ],
    )
    .await;
    for (owner, node, class) in [
        ("moves-us", LOCAL, "laptop"),
        ("moves-them", CONTACT, "phone"),
    ] {
        seed_owner_binding(&backend, owner, node).await;
        seed_device_occurrence(&backend, owner, node, class).await;
    }
    seed_common_root(&backend, &["moves-us", "moves-them"]).await;
    let grant = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": grant,
        "attesting_key_id": "moves-us",
        "attested_key_id": "moves-them",
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": {
            "grants": "transfer",
            "attestation_prefixes": ["chat:", "ownership:", "self:delegates_to:"],
        },
    });
    seed_raw_attestation(
        &backend,
        &grant,
        "moves-us",
        "moves-them",
        "scores",
        envelope,
    )
    .await;
    let bridge = page_bridge(&backend);

    let refs = offer(&bridge, CONTACT).await;
    let hash = hash_of(&backend, &grant).await;
    assert_eq!(
        refs.iter().find(|r| r.envelope_hash == hash).map(|r| r.seq),
        Some(REQUIRED_ROW_SEQ),
        "the person-named grant moves ahead of any walk: {refs:?}"
    );
}

/// A row addressed to the contact never waits behind history either.
#[tokio::test]
async fn a_contacts_own_row_moves_ahead_of_the_walk() {
    let backend = fixture().await;
    history(&backend).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let about = row(&backend, THIRD, CONTACT, "observation:reachability:v1").await;
    let own = row(&backend, CONTACT, THIRD, "observation:reachability:v1").await;
    let bridge = page_bridge(&backend);

    for id in [&about, &own] {
        assert!(
            offers(&backend, &bridge, CONTACT, id).await,
            "the first round's page of the walk holds no such row"
        );
    }
}

/// A grant moves the class it names and nothing else (CC 3.3.7), and it is a
/// grant of the node's own rows.
#[tokio::test]
async fn a_grant_moves_the_class_it_names_and_nothing_else() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["observation:"]).await;
    let named = row(&backend, LOCAL, LOCAL, "observation:reachability:v1").await;
    let other = row(&backend, LOCAL, LOCAL, "provenance:note:v1").await;
    let relayed = row(&backend, THIRD, THIRD, "observation:reachability:v1").await;
    let bridge = page_bridge(&backend);

    assert!(offers(&backend, &bridge, CONTACT, &named).await);
    assert!(
        !offers(&backend, &bridge, CONTACT, &other).await,
        "a class the grant does not name stays here"
    );
    assert!(
        !offers(&backend, &bridge, CONTACT, &relayed).await,
        "the grant is of this node's own rows, not a mirror of its corpus"
    );
}

/// A session claim at the commons reaches no contact (CC 5.2: its community's
/// cohort, never everyone), whoever placed it there.
#[tokio::test]
async fn a_session_claim_is_not_offered_across_the_commons() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let claim = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": claim,
        "attesting_key_id": THIRD,
        "attested_key_id": THIRD,
        "attestation_type": "scores",
        "dimension": "session:claim:v1",
        "community_id": "moves-room",
        "session_id": "moves-session",
        "claimed_at": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        "valid_until": (Utc::now() + chrono::Duration::hours(1))
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
    });
    seed_raw_attestation(&backend, &claim, THIRD, THIRD, "scores", envelope).await;
    let bridge = page_bridge(&backend);

    assert!(!offers(&backend, &bridge, CONTACT, &claim).await);
}

/// **Requested.** What is not offered is still served to the peer that asks:
/// the fetch twin answers for a row no offer named.
#[tokio::test]
async fn a_row_not_offered_is_served_to_the_peer_that_asks() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let third = row(&backend, THIRD, THIRD, "observation:reachability:v1").await;
    let bridge = page_bridge(&backend);

    assert!(!offers(&backend, &bridge, CONTACT, &third).await);
    let hash = hash_of(&backend, &third).await;
    assert!(
        bridge
            .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hash, Some(CONTACT))
            .await
            .is_some(),
        "asking is the peer's own pull: the gate is on the unasked offer only"
    );
}

/// What is offered unasked is the live state; a superseded row moves on
/// request, by the contact's Pull for its own subject and by hash.
#[tokio::test]
async fn a_superseded_row_is_served_on_request_and_never_offered() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let old = row(&backend, CONTACT, THIRD, "observation:reachability:v1").await;
    let new = composer(&backend, CONTACT, THIRD, "supersedes", &old).await;
    let bridge = page_bridge(&backend);

    let refs = offer(&bridge, CONTACT).await;
    let (old_hash, new_hash) = (hash_of(&backend, &old).await, hash_of(&backend, &new).await);
    assert!(
        !refs.iter().any(|r| r.envelope_hash == old_hash),
        "the superseded row is not the live state: {refs:?}"
    );
    assert!(
        refs.iter().any(|r| r.envelope_hash == new_hash),
        "its successor is"
    );
    let pulled = bridge
        .subject_holdings(EnvelopeKind::Attestation, CONTACT, Some(CONTACT))
        .await;
    assert!(
        pulled.iter().any(|r| r.envelope_hash == old_hash),
        "the contact's Pull for itself is a request, and lists it"
    );
    assert!(bridge
        .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &old_hash, Some(CONTACT))
        .await
        .is_some());
}

/// A superseding row by anyone but the row's author does not take it off the
/// offer: that would let a stranger silence a row.
#[tokio::test]
async fn a_foreign_supersede_does_not_retire_a_row() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let held = row(&backend, THIRD, CONTACT, "observation:reachability:v1").await;
    composer(&backend, SEAT, SEAT, "supersedes", &held).await;
    let bridge = page_bridge(&backend);

    assert!(offers(&backend, &bridge, CONTACT, &held).await);
}

/// The tombstones are of the consent-free set: a holder of a copy must hear.
#[tokio::test]
async fn a_tombstone_moves_to_a_contact() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let target = row(&backend, THIRD, THIRD, "observation:reachability:v1").await;
    let tombstone = composer(&backend, THIRD, THIRD, "withdraws", &target).await;
    let bridge = page_bridge(&backend);

    assert!(offers(&backend, &bridge, CONTACT, &tombstone).await);
    assert!(!offers(&backend, &bridge, CONTACT, &target).await);
}

/// **Serve seats walk the commons among themselves**, oldest first and in
/// full: the same store, the same grant shape, and a contact beside it is
/// offered none of it.
#[tokio::test]
async fn two_seats_walk_the_commons_and_a_contact_beside_them_does_not() {
    let backend = fixture().await;
    let past = history(&backend).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    grant(&backend, SEAT, &["trace:"]).await;
    let bridge = page_bridge(&backend).with_recognised_seats(seats(&[LOCAL, SEAT]));

    let mut walked = HashSet::new();
    for round in 0..WALK_ROUNDS {
        let refs = offer(&bridge, SEAT).await;
        if round == 0 {
            assert!(
                refs.len() <= PAGE as usize,
                "a page a round, as ever: {}",
                refs.len()
            );
            assert_eq!(
                refs.first().map(|r| r.envelope_hash),
                Some(hash_of(&backend, &past[0]).await),
                "the walk is oldest first, no required read ahead of it"
            );
        }
        walked.extend(refs.into_iter().map(|r| r.envelope_hash));
    }
    for id in &past {
        assert!(
            walked.contains(&hash_of(&backend, id).await),
            "a seat is offered the whole commons"
        );
    }
    assert!(!offers(&backend, &bridge, CONTACT, &past[0]).await);
}

/// A seat that has lost its seat is a node: the roster is the active one, so a
/// #377 tombstone ends the walk.
#[tokio::test]
async fn a_withdrawn_seat_is_not_walked_with() {
    let backend = fixture().await;
    let past = history(&backend).await;
    grant(&backend, SEAT, &["trace:"]).await;
    backend
        .record_canonical_withdrawal(SEAT, None, "digest")
        .await
        .expect("record the tombstone");
    let bridge = page_bridge(&backend).with_recognised_seats(seats(&[LOCAL, SEAT]));

    assert!(!offers(&backend, &bridge, SEAT, &past[0]).await);
}

/// A person's own nodes are not contacts: a grant between them keeps the walk.
#[tokio::test]
async fn an_owners_own_node_is_not_a_contact() {
    let backend = fixture().await;
    register_fixture_keys(&backend, &[("moves-owner", identity_type::USER)]).await;
    seed_owner_binding(&backend, "moves-owner", LOCAL).await;
    seed_owner_binding(&backend, "moves-owner", CONTACT).await;
    seed_device_occurrence(&backend, "moves-owner", LOCAL, "laptop").await;
    seed_device_occurrence(&backend, "moves-owner", CONTACT, "phone").await;
    seed_common_root(&backend, &["moves-owner"]).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let third = row(&backend, THIRD, THIRD, "observation:reachability:v1").await;
    let bridge = page_bridge(&backend);

    let hash = hash_of(&backend, &third).await;
    let mut walked = false;
    for _ in 0..4 {
        walked |= offer(&bridge, CONTACT)
            .await
            .iter()
            .any(|r| r.envelope_hash == hash);
    }
    assert!(walked, "the walk reaches it, a page a round");
}

/// **A round lost after listing leaves its rows for the next round.** The
/// watermark moved at the listing, so they waited for the re-sweep to come round:
/// on a plane of pages, a whole cycle. A round that ends well moves on.
#[tokio::test]
async fn a_lost_round_leaves_its_rows_for_the_next_round() {
    let backend = fixture().await;
    history(&backend).await;
    grant(&backend, SEAT, &["trace:"]).await;
    let bridge = page_bridge(&backend).with_recognised_seats(seats(&[LOCAL, SEAT]));
    let kind = EnvelopeKind::Attestation;

    let first = offer(&bridge, SEAT).await;
    assert!(!first.is_empty());
    bridge.round_ended(SEAT, kind, true);
    assert_eq!(
        offer(&bridge, SEAT).await,
        first,
        "the same rows, in the next round and not the re-sweep"
    );
    bridge.round_ended(SEAT, kind, false);
    let next = offer(&bridge, SEAT).await;
    assert_ne!(next, first, "a round that completed moves on");
    assert!(!next.iter().any(|r| first.contains(r)));
}

/// A peer that always fails does not pin the walk on one page: past the bound
/// the watermark moves as it would have, and a completed round earns it back.
#[tokio::test]
async fn a_peer_that_always_fails_does_not_list_one_page_for_ever() {
    let backend = fixture().await;
    history(&backend).await;
    grant(&backend, SEAT, &["trace:"]).await;
    let bridge = page_bridge(&backend).with_recognised_seats(seats(&[LOCAL, SEAT]));
    let kind = EnvelopeKind::Attestation;

    let first = offer(&bridge, SEAT).await;
    for _ in 0..MAX_ROUND_RESTORES {
        bridge.round_ended(SEAT, kind, true);
        assert_eq!(offer(&bridge, SEAT).await, first);
    }
    bridge.round_ended(SEAT, kind, true);
    let moved = offer(&bridge, SEAT).await;
    assert_ne!(moved, first, "the bound passed: the walk goes on");

    bridge.round_ended(SEAT, kind, false);
    let page = offer(&bridge, SEAT).await;
    bridge.round_ended(SEAT, kind, true);
    assert_eq!(
        offer(&bridge, SEAT).await,
        page,
        "a success resets the bound"
    );
}

/// A bridge whose contacts start at the tip now.
fn tip_bridge(backend: &Arc<SqliteBackend>) -> FederationDirectoryReplicationBridge {
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort: CohortProvider = Arc::new(|| vec![LOCAL.to_owned()]);
    FederationDirectoryReplicationBridge::with_config(
        dir,
        cohort,
        BridgeConfig {
            sweep_page_rows: PAGE,
            tip_margin: Duration::ZERO,
            ..BridgeConfig::default()
        },
    )
    .with_local_key_id(Some(LOCAL.to_owned()))
}

/// **Among contacts there is no diff walk, in the read path too.** A store of
/// history and rounds on rounds: a contact costs a head read past the tip each
/// round and one page of history, not a page a round.
#[tokio::test]
async fn a_contacts_rounds_do_not_read_the_plane() {
    let backend = fixture().await;
    let past = history(&backend).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let bridge = tip_bridge(&backend);

    let mut read = 0;
    for _ in 0..20 {
        let refs = offer(&bridge, CONTACT).await;
        assert!(!refs.is_empty(), "the required rows still move");
        let round = bridge
            .last_advertise_round
            .lock()
            .expect("the round summary")
            .clone()
            .expect("a round ran");
        read += round.listed - round.offered.min(round.listed);
    }
    assert!(
        read <= 2 * PAGE as usize,
        "one page of history in the whole run, not one a round: {read} rows read past the \
         required ones"
    );
    assert!(!offers(&backend, &bridge, CONTACT, &past[0]).await);
}

/// A row written after the contact's first round is a new row, in the next
/// round, and two seats still walk.
#[tokio::test]
async fn a_new_row_for_a_contact_is_read_from_the_tip() {
    let backend = fixture().await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let bridge = tip_bridge(&backend);
    offer(&bridge, CONTACT).await;

    let id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": THIRD,
        "attested_key_id": THIRD,
        "attestation_type": "withdraws",
        "kind": "withdraws",
        "references_attestation_id": "gone",
        "references_attestation_type": "scores",
    });
    seed_raw_attestation(&backend, &id, THIRD, THIRD, "withdraws", envelope).await;
    assert!(
        offers(&backend, &bridge, CONTACT, &id).await,
        "a tombstone written now reaches the contact in its next round, by no index"
    );
}

/// **An invitation does not wait for a walk.** It names its invitee only in
/// `subject_key_ids`, which no index reads: the field's 233 s to keyed. Written
/// long before the contact's first round, it still leads the offer.
#[tokio::test]
async fn an_invitation_moves_ahead_of_the_walk() {
    let backend = fixture().await;
    register_fixture_keys(&backend, &[("moves-founder", identity_type::USER)]).await;
    seed_owner_binding(&backend, "moves-founder", LOCAL).await;
    seed_device_occurrence(&backend, "moves-founder", LOCAL, "laptop").await;
    seed_common_root(&backend, &["moves-founder", CONTACT]).await;
    let room = crate::chat::pair_community("moves-founder", CONTACT, Utc::now());
    let group = room.community_key_id.clone();
    backend
        .put_community(sign_community_fixture("moves-founder", room))
        .await
        .expect("the room");
    history(&backend).await;
    let invitation = crate::membership::propose(
        &*backend,
        crate::membership::GroupScope::Community,
        &group,
        CONTACT,
        None,
        Utc::now() + chrono::Duration::days(1),
        &fixture_local_signer("moves-founder"),
    )
    .await
    .expect("the invitation");
    let bridge = tip_bridge(&backend);

    let hash = hash_of(&backend, &invitation.attestation_id).await;
    let refs = offer(&bridge, CONTACT).await;
    assert!(
        refs.iter().any(|r| r.envelope_hash == hash),
        "in the first offer, with the tip already past it: {refs:?}"
    );
}

/// The inbox a host polls for a pair room reads the room's index, not the plane.
#[tokio::test]
async fn a_pair_rooms_proposal_is_read_by_its_room() {
    let backend = fixture().await;
    register_fixture_keys(&backend, &[("moves-founder", identity_type::USER)]).await;
    let room = crate::chat::pair_community("moves-founder", CONTACT, Utc::now());
    let group = room.community_key_id.clone();
    backend
        .put_community(sign_community_fixture("moves-founder", room))
        .await
        .expect("the room");
    let invitation = crate::membership::propose(
        &*backend,
        crate::membership::GroupScope::Community,
        &group,
        CONTACT,
        None,
        Utc::now() + chrono::Duration::days(1),
        &fixture_local_signer("moves-founder"),
    )
    .await
    .expect("the invitation");
    let counting = CountingDirectory::new(Arc::clone(&backend) as Arc<dyn FederationDirectory>);

    let found = crate::membership::pending_proposal_in(&counting, CONTACT, &group)
        .await
        .expect("read")
        .expect("the proposal");
    assert_eq!(found.proposal.attestation_id, invitation.attestation_id);
    assert_eq!(counting.count("list_attestations_since"), 0);
}

/// A bridge that reads through a counter of every store call.
fn counted_bridge(
    backend: &Arc<SqliteBackend>,
    history_every: Duration,
) -> (CountingDirectory, FederationDirectoryReplicationBridge) {
    let counting = CountingDirectory::new(Arc::clone(backend) as Arc<dyn FederationDirectory>);
    let dir: Arc<dyn FederationDirectory> = Arc::new(counting.clone());
    let cohort: CohortProvider = Arc::new(|| vec![LOCAL.to_owned()]);
    let bridge = FederationDirectoryReplicationBridge::with_config(
        dir,
        cohort,
        BridgeConfig {
            sweep_page_rows: PAGE,
            tip_margin: Duration::ZERO,
            history_page_every: history_every,
            ..BridgeConfig::default()
        },
    )
    .with_local_key_id(Some(LOCAL.to_owned()));
    (counting, bridge)
}

/// **A row naming the peer only in `subject_key_ids`, written before it
/// connects, arrives on the first round.** A third party's invitation: no `to`
/// index reads it, it is past the tip, and it is nobody's row here. persist's
/// subject read (v61.0.5 #1225) carries it, read from the head and not from
/// the tip, with no page of history due.
#[tokio::test]
async fn a_row_written_before_the_peer_connects_arrives() {
    let backend = fixture().await;
    register_fixture_keys(&backend, &[("moves-founder", identity_type::USER)]).await;
    seed_common_root(&backend, &["moves-founder", LOCAL, CONTACT]).await;
    let room = crate::chat::pair_community("moves-founder", CONTACT, Utc::now());
    let group = room.community_key_id.clone();
    backend
        .put_community(sign_community_fixture("moves-founder", room))
        .await
        .expect("the room");
    let invitation = crate::membership::propose(
        &*backend,
        crate::membership::GroupScope::Community,
        &group,
        CONTACT,
        None,
        Utc::now() + chrono::Duration::days(1),
        &fixture_local_signer("moves-founder"),
    )
    .await
    .expect("the invitation");
    assert_ne!(
        invitation.attested_key_id, CONTACT,
        "no `to` index holds it"
    );
    history(&backend).await;
    let (counting, bridge) = counted_bridge(&backend, Duration::from_hours(1));

    let hash = hash_of(&backend, &invitation.attestation_id).await;
    let first = offer(&bridge, CONTACT).await;
    assert!(
        first.iter().any(|r| r.envelope_hash == hash),
        "in the first offer, with the tip past it and no history page due: {first:?}"
    );
    assert!(
        counting.count("list_attestations_naming_by_dimension") >= 1,
        "read by its subject"
    );
}

/// **The store's side of a contact's round.** Counted at the directory, not by
/// edge: past the first round a contact costs one plane read a round, however
/// large the plane, and a bounded handful of indexed reads.
#[tokio::test]
async fn a_contacts_round_costs_a_bounded_count_of_store_reads() {
    let backend = fixture().await;
    history(&backend).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    let (counting, bridge) = counted_bridge(&backend, Duration::from_hours(1));
    for _ in 0..2 {
        offer(&bridge, CONTACT).await;
    }
    counting.reset();
    for _ in 0..ROUNDS {
        offer(&bridge, CONTACT).await;
    }
    let reads = counting.total();
    eprintln!(
        "store reads in {ROUNDS} rounds: {reads}: {:?}",
        counting.counts()
    );
    assert_eq!(
        counting.count("list_attestations_since"),
        ROUNDS,
        "one read past the tip a round, and no page of history"
    );
    assert_eq!(
        counting.count("list_attestations_naming_by_dimension"),
        ROUNDS,
        "one subject read a round for a peer with one principal and no flood"
    );
    assert!(
        reads / ROUNDS <= 65,
        "a round's store reads stay a small constant: {} a round",
        reads / ROUNDS
    );
}

/// **A peer back from a long sleep gets what names it on its first round**, on
/// a store past one page, past the margin: its invitation, a contact's grant and
/// that grant's `withdraws`.
#[tokio::test]
async fn a_peer_back_from_offline_gets_what_names_it_on_the_first_round() {
    let backend = fixture().await;
    register_fixture_keys(&backend, &[("moves-founder", identity_type::USER)]).await;
    seed_owner_binding(&backend, "moves-founder", LOCAL).await;
    seed_device_occurrence(&backend, "moves-founder", LOCAL, "laptop").await;
    seed_common_root(&backend, &["moves-founder", CONTACT, THIRD]).await;
    let room = crate::chat::pair_community("moves-founder", CONTACT, Utc::now());
    let group = room.community_key_id.clone();
    backend
        .put_community(sign_community_fixture("moves-founder", room))
        .await
        .expect("the room");
    let invitation = crate::membership::propose(
        &*backend,
        crate::membership::GroupScope::Community,
        &group,
        CONTACT,
        None,
        Utc::now() + chrono::Duration::days(1),
        &fixture_local_signer("moves-founder"),
    )
    .await
    .expect("the invitation");
    let contacts_grant = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": contacts_grant,
        "attesting_key_id": THIRD,
        "attested_key_id": CONTACT,
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": { "grants": "transfer", "attestation_prefixes": ["chat:"] },
    });
    seed_raw_attestation(
        &backend,
        &contacts_grant,
        THIRD,
        CONTACT,
        "scores",
        envelope,
    )
    .await;
    let withdrawn = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": withdrawn,
        "attesting_key_id": SEAT,
        "attested_key_id": CONTACT,
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": { "grants": "transfer", "attestation_prefixes": ["chat:"] },
    });
    seed_raw_attestation(&backend, &withdrawn, SEAT, CONTACT, "scores", envelope).await;
    let retraction = composer(&backend, SEAT, SEAT, "withdraws", &withdrawn).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    history(&backend).await;
    let bridge = tip_bridge(&backend);

    let refs = offer(&bridge, CONTACT).await;
    for (what, id) in [
        ("invitation", &invitation.attestation_id),
        ("contact's grant", &contacts_grant),
        ("another's withdraws", &retraction),
    ] {
        let hash = hash_of(&backend, id).await;
        assert!(
            refs.iter().any(|r| r.envelope_hash == hash),
            "{what} in the first offer"
        );
    }
}

/// A pair room with `CONTACT` in it, founded by `moves-founder`, whose record
/// is on the group plane. Returns its key id.
async fn room_with_contact(backend: &Arc<SqliteBackend>) -> String {
    register_fixture_keys(
        backend,
        &[
            ("moves-founder", identity_type::USER),
            ("moves-member", identity_type::USER),
        ],
    )
    .await;
    for (owner, node, class) in [
        ("moves-founder", LOCAL, "laptop"),
        ("moves-member", CONTACT, "phone"),
    ] {
        seed_owner_binding(backend, owner, node).await;
        seed_device_occurrence(backend, owner, node, class).await;
    }
    seed_common_root(backend, &["moves-founder", "moves-member"]).await;
    let room = fixture_community_founded("moves-room", "moves-founder", "moves-member");
    backend
        .put_community(sign_community_fixture("moves-founder", room))
        .await
        .expect("the room");
    "moves-room".to_owned()
}

/// **A new member's roster moves ahead of history**, by the group's index: on a
/// store past one page, past the margin, the record is in the first offer. It
/// is read once, when the peer's groups change.
#[tokio::test]
async fn a_new_members_roster_moves_on_the_first_round() {
    use ciris_persist::federation::attestation_query::AttestationQuery;
    use ciris_persist::federation::group_plane::GROUP_ROSTER_DIMENSION;
    let backend = fixture().await;
    let group = room_with_contact(&backend).await;
    grant(&backend, CONTACT, &["trace:"]).await;
    history(&backend).await;
    let roster = AttestationQuery::to(&group, REQUIRED_READ_PAGE)
        .dimension(GROUP_ROSTER_DIMENSION)
        .pages()
        .next(&*backend)
        .await
        .expect("read")
        .and_then(|page| page.into_iter().next())
        .expect("the record is a row");
    let (counting, bridge) = counted_bridge(&backend, Duration::from_hours(1));

    let hash = hash_of(&backend, &roster.attestation_id).await;
    assert!(
        offer(&bridge, CONTACT)
            .await
            .iter()
            .any(|r| r.envelope_hash == hash),
        "the record leads, with the tip past it and no history page due"
    );
    counting.reset();
    offer(&bridge, CONTACT).await;
    assert_eq!(
        counting.count("list_targeted_by_dimension_prefix"),
        0,
        "the group read runs when the peer's groups change, not every round"
    );
}

/// **A key grant naming the peer is on the required read.** It is a `scores`
/// row on the `key_grant:` dimensions, attested to its recipient; a member with
/// no wrap sits in a room it cannot read. The query is checked against persist's
/// own predicate over the row's shape: storing a wrap needs a real epoch mint,
/// which the put door refuses from a fixture.
#[test]
fn a_key_grant_is_on_the_required_read() {
    use ciris_persist::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
    let row = KeyGrantRow {
        axis: KeyGrantAxis::Epoch {
            community_key_id: "moves-room".to_owned(),
            minter_key_id: LOCAL.to_owned(),
            epoch: 1,
        },
        wrap: ciris_persist::federation::blobs::GrantWrap {
            recipient_key_id: CONTACT.to_owned(),
            wrapped_dek: "d3JhcA==".to_owned(),
            wrap_algorithm: "ml-kem-768".to_owned(),
        },
    };
    let mut stored: Attestation = serde_json::from_value(serde_json::json!({
        "attestation_id": "wrap",
        "attesting_key_id": LOCAL,
        "attested_key_id": CONTACT,
        "attestation_type": "scores",
        "weight": null,
        "asserted_at": "2026-05-01T00:00:00Z",
        "expires_at": null,
        "attestation_envelope": {},
        "original_content_hash": "",
        "scrub_signature_classical": "",
        "scrub_signature_pqc": null,
        "scrub_key_id": LOCAL,
        "scrub_timestamp": "2026-05-01T00:00:00Z",
        "pqc_completed_at": null,
        "persist_row_hash": "",
        "subject_key_ids": [],
        "withdraws_admission_rule": null,
        "cohort_scope": "community",
        "tier": "federation",
        "promoted_at": null,
        "additional_scrubs": []
    }))
    .expect("the row's columns");
    stored.attestation_envelope = row.envelope();
    assert!(FederationDirectoryReplicationBridge::key_grants_to(CONTACT).admits(&stored));
    stored.attested_key_id = THIRD.to_owned();
    assert!(!FederationDirectoryReplicationBridge::key_grants_to(CONTACT).admits(&stored));
}
