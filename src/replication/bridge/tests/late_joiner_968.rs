//! CIRISEdge#968 — **a late joiner gets the group's history.**
//!
//! A room's history is written before a member joins, so every round before
//! the join withholds it and the joiner's watermark passes it. A contact gets
//! no walk (CC 5.2), only a page of history now and then, so on the server's
//! rig the history reached the joiner oldest first behind every other family,
//! about 726 s after the accept. These witnesses read the production advertise
//! (`list_envelope_refs_for_peer`) and fail without the join backfill.
use super::*;
use crate::replication::counting_directory_930::CountingDirectory;

const LOCAL: &str = "node-alice-a";
const JOINER: &str = "node-carol";
const ROOM: &str = "chat-room";
/// Rows of unrelated history written before the room's, so a page of
/// history (the only other way a contact reads the past) cannot reach them.
const FILLER: usize = 40;
const PAGE: u32 = 8;

/// The local node's bridge: alice's laptop, carol's node a consent peer, its
/// contacts starting at the tip, and no page of history due for an hour.
fn bridge(dir: Arc<dyn FederationDirectory>) -> FederationDirectoryReplicationBridge {
    let cohort: CohortProvider = Arc::new(|| vec![JOINER.to_owned()]);
    let publish: Vec<String> = vec![LOCAL.into(), "person-alice".into()];
    let selector: CohortProvider = Arc::new(move || publish.clone());
    FederationDirectoryReplicationBridge::with_config(
        dir,
        cohort,
        BridgeConfig {
            sweep_page_rows: PAGE,
            tip_margin: Duration::ZERO,
            history_page_every: Duration::from_hours(1),
            ..BridgeConfig::default()
        },
    )
    .with_local_key_id(Some(LOCAL.into()))
    .with_self_provider(Some(selector))
}

/// The room, founded by `room-authority` with alice in it; carol is not.
async fn room(backend: &Arc<SqliteBackend>) {
    backend
        .put_community(sign_community_fixture(
            "room-authority",
            fixture_community_founded(ROOM, "room-authority", "person-alice"),
        ))
        .await
        .expect("the room, without carol");
}

/// `n` rows alice wrote in the room. Returns their ids.
async fn said_in_room(backend: &SqliteBackend, n: usize) -> Vec<String> {
    let mut ids = Vec::with_capacity(n);
    for _ in 0..n {
        let id = uuid::Uuid::new_v4().to_string();
        seed_scoped_attestation(
            backend,
            &id,
            "person-alice",
            "person-alice",
            "scores",
            "community",
            serde_json::json!({
                "dimension": crate::chat::CHAT_MESSAGE_DIMENSION,
                "community_id": ROOM,
            }),
        )
        .await;
        ids.push(id);
    }
    ids
}

/// Unrelated federation rows, older than the room's history.
async fn filler(backend: &SqliteBackend) {
    for _ in 0..FILLER {
        let id = uuid::Uuid::new_v4().to_string();
        seed_raw_attestation(
            backend,
            &id,
            "node-stranger",
            "node-stranger",
            "scores",
            serde_json::json!({
                "id": id,
                "attesting_key_id": "node-stranger",
                "attested_key_id": "node-stranger",
                "attestation_type": "scores",
                "dimension": "observation:reachability:v1",
            }),
        )
        .await;
    }
}

/// Carol joins: alice proposes, carol accepts, and the room's two members
/// widen the roster under its `unanimous` protocol.
async fn carol_joins(backend: &Arc<SqliteBackend>) {
    fixture_consent(
        &**backend,
        crate::membership::GroupScope::Community,
        ROOM,
        "person-alice",
        "person-carol",
        None,
    )
    .await;
    let authority = fixture_local_signer("room-authority");
    let alice = fixture_local_signer("person-alice");
    let widened = crate::membership::widen_cosigned(
        &**backend,
        crate::membership::GroupScope::Community,
        ROOM,
        "person-carol",
        None,
        Utc::now(),
        &[&authority, &alice],
    )
    .await
    .expect("the roster widens to carol");
    assert!(widened, "carol was not a member before");
}

async fn offered(
    bridge: &FederationDirectoryReplicationBridge,
    backend: &SqliteBackend,
    ids: &[String],
) -> Vec<bool> {
    let refs = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(JOINER))
        .await;
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let hash = hash_of(backend, id).await;
        out.push(refs.iter().any(|r| r.envelope_hash == hash));
    }
    out
}

/// **The field case.** The room's history is written, the joiner's node is a
/// contact whose rounds start at the tip, and then the joiner is admitted. The
/// next round offers the whole history, with the tip past it and no page of
/// history due. Without the backfill none of it is offered.
#[tokio::test]
async fn a_late_joiner_is_offered_the_rooms_history_on_the_round_after_it_joins() {
    let backend = audience_backend().await;
    room(&backend).await;
    filler(&backend).await;
    let history = said_in_room(&backend, 12).await;
    let bridge = bridge(backend.clone());

    // Before the join: carol is not in the room, so nothing of it moves.
    assert!(
        offered(&bridge, &backend, &history)
            .await
            .iter()
            .all(|o| !o),
        "a non-member is offered none of the room's history"
    );

    carol_joins(&backend).await;
    let after = offered(&bridge, &backend, &history).await;
    assert!(
        after.iter().all(|o| *o),
        "every row of the room's history in the first round after the join: {after:?}"
    );
}

/// **Bounded, and paced by rounds, not by the store.** A history longer than
/// one backfill page reaches the joiner a page a round: each round reads one
/// page of the history families and no more, and the backfill ends once the
/// families are read to their end.
#[tokio::test]
async fn the_backfill_reads_one_page_a_round_and_then_stops() {
    let backend = audience_backend().await;
    room(&backend).await;
    let history = said_in_room(&backend, GROUP_BACKFILL_PAGE as usize + 20).await;
    let counting = CountingDirectory::new(Arc::clone(&backend) as Arc<dyn FederationDirectory>);
    let bridge = bridge(Arc::new(counting.clone()));
    offered(&bridge, &backend, &history[..1]).await;
    carol_joins(&backend).await;

    counting.reset();
    let first = offered(&bridge, &backend, &history).await;
    assert_eq!(
        counting.count("list_attestations_since_by_prefixes"),
        1,
        "one page a round"
    );
    let first_count = first.iter().filter(|o| **o).count();
    assert!(
        first_count >= 1 && first_count < history.len(),
        "the first page is a page, not the whole history: {first_count} of {}",
        history.len()
    );

    let second = offered(&bridge, &backend, &history).await;
    let missing: Vec<usize> = (0..history.len())
        .filter(|i| !first[*i] && !second[*i])
        .collect();
    assert!(
        missing.is_empty(),
        "the rest on the next round: rows offered in neither round {missing:?}"
    );

    counting.reset();
    for _ in 0..3 {
        offered(&bridge, &backend, &history[..1]).await;
    }
    assert_eq!(
        counting.count("list_attestations_since_by_prefixes"),
        0,
        "a finished backfill reads nothing more"
    );
}

/// **A peer first seen in a group is not backfilled.** The first read of a
/// peer's groups is its baseline: a restart, or a peer evicted from the cursor
/// map, does not start a scan of every group's history for every peer. Its
/// history is the re-sweep's, as before.
#[tokio::test]
async fn a_peer_first_seen_already_in_the_group_starts_no_backfill() {
    let backend = audience_backend().await;
    room(&backend).await;
    let history = said_in_room(&backend, 4).await;
    carol_joins(&backend).await;
    let counting = CountingDirectory::new(Arc::clone(&backend) as Arc<dyn FederationDirectory>);
    let bridge = bridge(Arc::new(counting.clone()));
    for _ in 0..3 {
        offered(&bridge, &backend, &history).await;
    }
    assert_eq!(
        counting.count("list_attestations_since_by_prefixes"),
        0,
        "no backfill for a baseline"
    );
}

fn key() -> (String, EnvelopeKind) {
    (JOINER.to_owned(), EnvelopeKind::Attestation)
}

fn set(groups: &[&str]) -> BTreeSet<String> {
    groups.iter().map(|g| (*g).to_owned()).collect()
}

fn position(id: &str) -> ciris_persist::federation::types::ServePosition {
    ciris_persist::federation::types::ServePosition::new(Utc::now(), id)
}

/// The state machine, pure.
#[test]
fn a_join_after_the_baseline_starts_a_backfill_of_that_group_only() {
    let mut c = SweepCursors::default();
    let k = key();
    assert!(
        c.groups_changed(&k, &set(&["g1"])),
        "the baseline is a change"
    );
    assert!(c.join_backfill(&k).is_none(), "but backfills nothing");
    assert!(!c.groups_changed(&k, &set(&["g1"])));
    assert!(c.groups_changed(&k, &set(&["g1", "g2"])));
    let b = c.join_backfill(&k).expect("a join starts one");
    assert_eq!(b.groups, set(&["g2"]), "only the group joined");
    assert_eq!(b.since, None, "from the beginning");
}

#[test]
fn a_peer_with_no_groups_at_first_sight_is_backfilled_when_it_joins_one() {
    let mut c = SweepCursors::default();
    let k = key();
    assert!(!c.groups_changed(&k, &set(&[])), "no groups: no change");
    assert!(c.groups_changed(&k, &set(&["g1"])));
    assert_eq!(
        c.join_backfill(&k).map(|b| b.groups),
        Some(set(&["g1"])),
        "the empty first read was the baseline"
    );
}

#[test]
fn the_backfill_advances_finishes_and_ignores_a_page_from_before_a_restart() {
    let mut c = SweepCursors::default();
    let k = key();
    c.groups_changed(&k, &set(&[]));
    c.groups_changed(&k, &set(&["g1"]));
    let first = c.join_backfill(&k).expect("started");
    assert!(!c.join_backfill_read(&k, first.generation, Some(position("a"))));
    assert_eq!(
        c.join_backfill(&k)
            .and_then(|b| b.since)
            .map(|p| p.attestation_id),
        Some("a".to_owned()),
        "resumes after the page"
    );

    // Another join restarts from the beginning, with both groups.
    c.groups_changed(&k, &set(&["g1", "g2"]));
    let restarted = c.join_backfill(&k).expect("still running");
    assert_eq!(restarted.groups, set(&["g1", "g2"]));
    assert_eq!(restarted.since, None);
    assert_ne!(restarted.generation, first.generation);

    // A page read under the old generation moves nothing.
    assert!(!c.join_backfill_read(&k, first.generation, None));
    assert!(c.join_backfill(&k).is_some(), "a stale page cannot end it");
    assert!(!c.join_backfill_read(&k, first.generation, Some(position("z"))));
    assert_eq!(c.join_backfill(&k).and_then(|b| b.since), None);

    assert!(
        c.join_backfill_read(&k, restarted.generation, None),
        "the end of the families finishes it"
    );
    assert!(c.join_backfill(&k).is_none());
}

#[test]
fn leaving_a_group_drops_it_from_the_backfill() {
    let mut c = SweepCursors::default();
    let k = key();
    c.groups_changed(&k, &set(&[]));
    c.groups_changed(&k, &set(&["g1", "g2"]));
    c.groups_changed(&k, &set(&["g2"]));
    assert_eq!(c.join_backfill(&k).map(|b| b.groups), Some(set(&["g2"])));
    c.groups_changed(&k, &set(&[]));
    assert!(c.join_backfill(&k).is_none(), "no group left to backfill");
}

/// **The page keeps what is placed in a joined group, and nothing else.** The
/// serve gates are still the authority on what moves; this is what the
/// backfill hands them, read straight from it.
#[tokio::test]
async fn a_backfill_page_keeps_only_the_joined_groups_rows() {
    let backend = audience_backend().await;
    room(&backend).await;
    let history = said_in_room(&backend, 3).await;
    // Another room alice is in, whose history carol has no claim to.
    backend
        .put_community(sign_community_fixture(
            "room-authority",
            fixture_community_founded("other-room", "room-authority", "person-alice"),
        ))
        .await
        .expect("a second room");
    let mut elsewhere = Vec::new();
    for _ in 0..3 {
        let id = uuid::Uuid::new_v4().to_string();
        seed_scoped_attestation(
            &backend,
            &id,
            "person-alice",
            "person-alice",
            "scores",
            "community",
            serde_json::json!({
                "dimension": crate::chat::CHAT_MESSAGE_DIMENSION,
                "community_id": "other-room",
            }),
        )
        .await;
        elsewhere.push(id);
    }
    let bridge = bridge(backend.clone());
    let k = key();
    if let Ok(mut c) = bridge.sweep_cursors.lock() {
        c.groups_changed(&k, &set(&[]));
        c.groups_changed(&k, &set(&[ROOM]));
    }
    let kept: BTreeSet<String> = bridge
        .group_history_backfill(&k)
        .await
        .into_iter()
        .map(|a| a.attestation_id)
        .collect();
    let want: BTreeSet<String> = history.iter().cloned().collect();
    assert_eq!(kept, want, "the joined room's rows, and only those");
    assert!(elsewhere.iter().all(|id| !kept.contains(id)));
}
