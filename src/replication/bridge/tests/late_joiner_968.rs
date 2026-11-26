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
        .group_history_backfill(&k, &HashSet::new(), &BTreeMap::new())
        .await
        .into_iter()
        .map(|a| a.attestation_id)
        .collect();
    let want: BTreeSet<String> = history.iter().cloned().collect();
    assert_eq!(kept, want, "the joined room's rows, and only those");
    assert!(elsewhere.iter().all(|id| !kept.contains(id)));
}

/// CIRISEdge#1029 F1 — an MLS handshake row placed in the room, as `chat.rs`
/// writes one: `mls_bytes` (base64), and on a Welcome `mls_epoch` and
/// `mls_for_key_id` (the joiner, named in the body only); a Commit `mls_epoch`,
/// the epoch it advanced to. `pad` bytes of
/// handshake stand in for a PQC-sized ratchet tree.
async fn handshake_row(
    backend: &SqliteBackend,
    author: &str,
    dimension: &str,
    welcome_for: Option<(&str, u64)>,
    pad: usize,
) -> String {
    use base64::Engine as _;
    let id = uuid::Uuid::new_v4().to_string();
    let mut envelope = serde_json::json!({
        "dimension": dimension,
        "community_id": ROOM,
        "mls_bytes": base64::engine::general_purpose::STANDARD.encode(vec![0x5a; pad]),
    });
    if let Some((recipient, epoch)) = welcome_for {
        // A Commit carries the epoch it advanced to and names nobody.
        if dimension != crate::chat::COMMIT_DIMENSION {
            envelope["mls_for_key_id"] = serde_json::json!(recipient);
        }
        envelope["mls_epoch"] = serde_json::json!(epoch);
    }
    seed_scoped_attestation(
        backend,
        &id,
        author,
        author,
        "scores",
        "community",
        envelope,
    )
    .await;
    id
}

/// The room's handshake history before carol: for each earlier member, a
/// KeyPackage, alice's Welcome for it, and alice's Commit adding it, each
/// PQC-sized. Over [`crate::replication::session::PROACTIVE_PUSH_BUDGET_BYTES`]
/// in all, as at N = 12. Returns (KeyPackages, Welcomes, Commits).
async fn handshake_history(backend: &SqliteBackend) -> (Vec<String>, Vec<String>, Vec<String>) {
    const MEMBERS: u64 = 10;
    const PAD: usize = 24 * 1024;
    let (mut kps, mut welcomes, mut commits) = (Vec::new(), Vec::new(), Vec::new());
    for n in 1..=MEMBERS {
        let member = format!("person-member-{n}");
        // A KeyPackage is written by a member of the room (persist's write
        // scope); alice's devices stand in for the members who joined.
        kps.push(
            handshake_row(
                backend,
                "person-alice",
                crate::chat::KEY_PACKAGE_DIMENSION,
                None,
                PAD / 4,
            )
            .await,
        );
        welcomes.push(
            handshake_row(
                backend,
                "person-alice",
                crate::chat::WELCOME_DIMENSION,
                Some((&member, n)),
                PAD,
            )
            .await,
        );
        commits.push(
            handshake_row(
                backend,
                "person-alice",
                crate::chat::COMMIT_DIMENSION,
                Some((&member, n)),
                PAD,
            )
            .await,
        );
    }
    (kps, welcomes, commits)
}

/// The envelopes one round's proactive push carries to carol, as the
/// production session builds it over this bridge.
async fn first_push(bridge: FederationDirectoryReplicationBridge) -> Vec<Attestation> {
    use crate::replication::directory::DirectoryStateAdapter;
    use crate::replication::session::{ReplicationOutcome, Session, SessionRole};
    let provider = DirectoryStateAdapter::new(Arc::new(bridge)).with_peer(JOINER);
    let mut session = Session::new(SessionRole::Initiator, EnvelopeKind::Attestation)
        .with_proactive_publish(true);
    let msgs = match session.start_round(&provider).await {
        ReplicationOutcome::Send(msgs) | ReplicationOutcome::SendAndComplete { msgs, .. } => msgs,
        other => panic!("a round opens with a send: {other:?}"),
    };
    msgs.into_iter()
        .filter_map(|m| match m {
            crate::replication::protocol::ReplicationMessage::Deliver(d) => Some(d.envelopes),
            _ => None,
        })
        .flatten()
        .map(|bytes| serde_json::from_slice::<Attestation>(&bytes).expect("a pushed row"))
        .collect()
}

/// CIRISEdge#1029 F1 — **the joiner's own Welcome leads the push, past a
/// handshake backlog larger than the budget, and the backlog it can never use
/// is not offered.** Field (12-person star): the founder's push to the joiner
/// is oldest-first and stops at 256 KiB, the Welcome was the newest room row
/// behind every other member's KeyPackage, ten earlier Welcomes and ten
/// Commits, and reached the joiner four rounds (160 s) after it was placed.
/// Red before: the Welcome is not in the first push.
#[tokio::test]
async fn the_joiners_welcome_leads_the_push_past_a_backlog_over_the_budget_1029() {
    let backend = audience_backend().await;
    room(&backend).await;
    let (kps, welcomes, commits) = handshake_history(&backend).await;
    let history = said_in_room(&backend, 3).await;
    let bridge = bridge(backend.clone());
    // The baseline: carol is not in the room yet.
    offered(&bridge, &backend, &history[..1]).await;
    carol_joins(&backend).await;
    // carol's KeyPackage reached alice, and alice placed carol's Welcome.
    // (Her own row is hers to hold: the session's diff, not the backfill,
    // decides whether it goes back to her.)
    let _own_kp = handshake_row(
        &backend,
        "person-carol",
        crate::chat::KEY_PACKAGE_DIMENSION,
        None,
        4096,
    )
    .await;
    let welcome = handshake_row(
        &backend,
        "person-alice",
        crate::chat::WELCOME_DIMENSION,
        Some(("person-carol", 11)),
        24 * 1024,
    )
    .await;

    let pushed: BTreeSet<String> = first_push(bridge)
        .await
        .into_iter()
        .map(|a| a.attestation_id)
        .collect();
    assert!(
        pushed.contains(&welcome),
        "the joiner's Welcome is in the first push ({} rows pushed)",
        pushed.len()
    );
    let unusable: Vec<&String> = kps
        .iter()
        .chain(&welcomes)
        .chain(&commits)
        .filter(|id| pushed.contains(*id))
        .collect();
    assert!(
        unusable.is_empty(),
        "other members' KeyPackages and Welcomes, and Commits below the joiner's epoch, are \
         not the joiner's backfill: {unusable:?}"
    );
    assert!(
        history.iter().all(|id| pushed.contains(id)),
        "the room's history still moves"
    );
}

/// CIRISEdge#1029 F1 — **a Welcome placed after the join's backfill is a
/// required row for its joiner.** In the field the backfill was offered at the
/// join (01:39:58) and the Welcome placed two minutes later; it then reached
/// the joiner only after the rows the hub's listing put ahead of it. Required,
/// it is listed at the required `seq`, which the push carries first. Red
/// before: the Welcome is listed (by the head) at its admission `seq`.
#[tokio::test]
async fn a_welcome_placed_after_the_backfill_is_required_for_its_joiner_1029() {
    let backend = audience_backend().await;
    room(&backend).await;
    let history = said_in_room(&backend, 3).await;
    let bridge = bridge(backend.clone());
    offered(&bridge, &backend, &history[..1]).await;
    carol_joins(&backend).await;
    assert!(
        offered(&bridge, &backend, &history)
            .await
            .iter()
            .all(|o| *o),
        "the backfill round"
    );
    let welcome = handshake_row(
        &backend,
        "person-alice",
        crate::chat::WELCOME_DIMENSION,
        Some(("person-carol", 4)),
        2048,
    )
    .await;
    let hash = hash_of(&backend, &welcome).await;
    let refs = bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(JOINER))
        .await;
    let listed = refs
        .iter()
        .find(|r| r.envelope_hash == hash)
        .expect("the Welcome is listed to its joiner");
    assert_eq!(
        listed.seq, REQUIRED_ROW_SEQ,
        "the joiner's Welcome is a required row, ahead of every walked row"
    );
}

/// The joiner's listing, `n` times, for the read counts below.
async fn listings(bridge: &FederationDirectoryReplicationBridge, n: usize) {
    for _ in 0..n {
        let _ = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(JOINER))
            .await;
    }
}

/// CIRISEdge#1029 F1 — **the Welcome read is bounded and costs a group
/// nobody is joining nothing.** Each listing of a watched join reads the
/// room's Welcomes once; once the joiner's is found it is read in
/// `1 + WELCOME_FOUND_LISTINGS` listings and never again, a watch that never
/// finds one ends after `WELCOME_WATCH_LISTINGS`, and a member that joined
/// nothing (the baseline) is never read for. Counted on the targeted door
/// alone after the join round (whose roster read uses the same door).
#[tokio::test]
async fn the_welcome_read_stops_once_found_or_spent_and_costs_a_settled_member_nothing_1029() {
    const DOOR: &str = "list_targeted_by_dimension_prefix";
    // A member since the baseline: no join, no read.
    let backend = audience_backend().await;
    room(&backend).await;
    carol_joins(&backend).await;
    let counting = CountingDirectory::new(Arc::clone(&backend) as Arc<dyn FederationDirectory>);
    let settled = bridge(Arc::new(counting.clone()));
    listings(&settled, 1).await;
    counting.reset();
    listings(&settled, 10).await;
    assert_eq!(
        counting.count(DOOR),
        0,
        "a member that joined nothing is read for nothing"
    );

    // A join whose Welcome is placed after the join round.
    let backend = audience_backend().await;
    room(&backend).await;
    let counting = CountingDirectory::new(Arc::clone(&backend) as Arc<dyn FederationDirectory>);
    let found = bridge(Arc::new(counting.clone()));
    listings(&found, 1).await;
    carol_joins(&backend).await;
    listings(&found, 1).await;
    handshake_row(
        &backend,
        "person-alice",
        crate::chat::WELCOME_DIMENSION,
        Some(("person-carol", 4)),
        512,
    )
    .await;
    counting.reset();
    listings(&found, 10).await;
    assert_eq!(
        counting.count(DOOR),
        1 + WELCOME_FOUND_LISTINGS as usize,
        "found, then offered a bounded number of listings more, then never read again"
    );

    // A join whose Welcome never comes.
    let backend = audience_backend().await;
    room(&backend).await;
    let counting = CountingDirectory::new(Arc::clone(&backend) as Arc<dyn FederationDirectory>);
    let spent = bridge(Arc::new(counting.clone()));
    listings(&spent, 1).await;
    carol_joins(&backend).await;
    listings(&spent, 1).await;
    counting.reset();
    listings(&spent, WELCOME_WATCH_LISTINGS as usize + 10).await;
    assert_eq!(
        counting.count(DOOR),
        WELCOME_WATCH_LISTINGS as usize - 1,
        "the watch's own listings and no more (the join round spent one)"
    );
}

/// CIRISEdge#1029 F1 — **the Welcome read is credited to its own site** in
/// persist's per-caller read counters (`crate::read_caller`), so a hub's join
/// cost is visible apart from the group rows' and the history's. Real
/// `SqliteBackend`; persist's counters are process-wide, so a delta. Red
/// before: credited `edge.advertise.groups`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_welcome_read_is_credited_to_its_own_read_site_1029() {
    let key = "list_targeted_by_dimension_prefix:edge.advertise.welcomes.reads";
    let reads = || {
        crate::observability::persist_reads_snapshot()
            .get(key)
            .copied()
            .unwrap_or(0)
    };
    let backend = audience_backend().await;
    room(&backend).await;
    let bridge = bridge(backend.clone());
    listings(&bridge, 1).await;
    carol_joins(&backend).await;
    let before = reads();
    listings(&bridge, 2).await;
    assert!(
        reads() > before,
        "the watched join's Welcome read is credited {key}"
    );
}
