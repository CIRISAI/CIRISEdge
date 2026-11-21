//! **45.1.9 (attribution) — every memoised read says why it read.**
//!
//! The bridge's hot-path memos driven through each of their reasons, the
//! counters asserted by label: the consent send set (in the `advertise`
//! family), the owner-binding memo, the announce memo and the own-set memo.
//! Each witness checks the memo's reads sum to the reads the store served.
//! The size gauges the same paths set (`structure_sizes`) are asserted
//! alongside, and the advertise watermarks' and the store-feed inboxes'
//! gauges have their own witnesses.
//!
//! `cargo test --lib attribution_1019x`
use super::*;
use crate::observability as obs;
use std::sync::atomic::Ordering;
use std::time::Duration as StdDuration;

/// An instant `by` in the past: an entry stamped with it is expired.
fn ago(by: StdDuration) -> Instant {
    Instant::now()
        .checked_sub(by)
        .expect("the monotonic clock is past the memo TTLs")
}

/// A bridge over `backend` as `node-a`, counting into `metrics`.
fn counted(
    backend: &Arc<SqliteBackend>,
    metrics: &obs::EdgeMetrics,
) -> FederationDirectoryReplicationBridge {
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort_cb: CohortProvider = Arc::new(Vec::new);
    FederationDirectoryReplicationBridge::with_config(dir, cohort_cb, BridgeConfig::default())
        .with_local_key_id(Some("node-a".to_owned()))
        .with_metrics(Some(metrics.clone()))
}

fn memo(m: &obs::EdgeMetrics, label: &str) -> u64 {
    m.memo_reads().get(label).copied().unwrap_or(0)
}

fn advertise(m: &obs::EdgeMetrics, label: &str) -> u64 {
    m.advertise().get(label).copied().unwrap_or(0)
}

fn size(m: &obs::EdgeMetrics, label: &str) -> Option<u64> {
    m.structure_sizes().get(label).copied()
}

/// The consent send set: a first read is `miss`, then a `hit`; a memo past
/// its TTL reads as `expired`; a door that drops a live memo makes the next
/// read `invalidated` (every door: a local write and an ownership event);
/// a door that drops a memo already expired leaves `expired`. The reads by
/// cause sum to the reads the store served, and the send set's gauges carry
/// the set the memo holds.
#[tokio::test]
async fn the_send_set_reads_say_why_attribution_1019x() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    for key_id in ["node-a", "node-home"] {
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(key_id, identity_type::AGENT),
            })
            .await
            .expect("seed key");
    }
    seed_consent_membership(&backend, "node-a", "node-home").await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    let read = |label| advertise(&m, label);

    let set = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(read(obs::ADVERTISE_SEND_SET_READ_MISS), 1, "never filled");
    assert_eq!(
        size(&m, obs::STRUCTURE_SIZE_SEND_SET_NAMED),
        Some(u64::try_from(set.len()).unwrap()),
        "the gauge is the set the memo holds"
    );
    assert!(set.len() >= 1, "the grant names node-home");
    assert_eq!(
        size(&m, obs::STRUCTURE_SIZE_SEND_SET_OWNER_ROUTED),
        Some(u64::try_from(set.owner_routed_len()).unwrap())
    );

    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(read(obs::ADVERTISE_SEND_SET_LOOKUP_HIT), 1);

    let aged = |b: &FederationDirectoryReplicationBridge| {
        let mut memo = b.consent_memo.lock().unwrap();
        let (set, _) = memo.clone().expect("filled");
        *memo = Some((
            set,
            ago(CONSENT_SEND_SET_MEMO_TTL + StdDuration::from_secs(1)),
        ));
    };
    aged(&bridge);
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(read(obs::ADVERTISE_SEND_SET_EXPIRED), 1, "the TTL");

    bridge.invalidate_send_set_memos("host_kick");
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(
        read(obs::ADVERTISE_SEND_SET_READ_INVALIDATED),
        1,
        "a local write dropped it live"
    );

    bridge.invalidate_owner_memo("node-zed");
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(
        read(obs::ADVERTISE_SEND_SET_READ_INVALIDATED),
        2,
        "an ownership event dropped it live"
    );

    aged(&bridge);
    bridge.invalidate_send_set_memos("host_kick");
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(
        read(obs::ADVERTISE_SEND_SET_EXPIRED),
        2,
        "dropped after it had expired: the read was the TTL's"
    );
    assert_eq!(read(obs::ADVERTISE_SEND_SET_READ_MISS), 1);
    assert_eq!(
        read(obs::ADVERTISE_SEND_SET_READ_MISS)
            + read(obs::ADVERTISE_SEND_SET_EXPIRED)
            + read(obs::ADVERTISE_SEND_SET_READ_INVALIDATED),
        u64::try_from(bridge.consent_set_reads.load(Ordering::SeqCst)).unwrap(),
        "every read the store served, each under one cause"
    );
    assert_eq!(read(obs::ADVERTISE_SEND_SET_LOOKUP_JOINED), 0);
}

/// Eight concurrent lookups of an expired send set: the one read is `ttl`
/// and the seven that waited on it are `joined`, not reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_send_set_lookups_join_the_one_read_attribution_1019x() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    bridge
        .probes
        .read_probe
        .delay_ms
        .store(50, Ordering::SeqCst);
    *bridge.consent_memo.lock().unwrap() = Some((
        ResolvedPeerSet::from_consent_peers(Vec::new()),
        ago(CONSENT_SEND_SET_MEMO_TTL + StdDuration::from_secs(1)),
    ));
    futures::future::join_all((0..8).map(|_| bridge.resolved_peer_set("node-a"))).await;
    assert_eq!(bridge.consent_set_reads.load(Ordering::SeqCst), 1);
    assert_eq!(advertise(&m, obs::ADVERTISE_SEND_SET_EXPIRED), 1);
    assert_eq!(advertise(&m, obs::ADVERTISE_SEND_SET_LOOKUP_JOINED), 7);
    assert_eq!(advertise(&m, obs::ADVERTISE_SEND_SET_LOOKUP_HIT), 0);
}

/// The owner-binding memo: `miss`, `hit`, `ttl`, then `invalidated` by a
/// keyed ownership event and by a whole drop (a local write), and `miss`
/// again for a node never asked. Its size gauge follows each change.
#[tokio::test]
async fn the_owner_memo_reads_say_why_attribution_1019x() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[
            ("person-bob", identity_type::USER),
            ("node-bob", identity_type::NODE),
        ],
    )
    .await;
    seed_owner_binding(&backend, "person-bob", "node-bob").await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    let bob = OwnerLookup::Owner("person-bob".to_owned());

    assert_eq!(bridge.owner_of_cached("node-bob").await, bob);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_MISS), 1);
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_OWNER_MEMO), Some(1));
    assert_eq!(bridge.owner_of_cached("node-bob").await, bob);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_HIT), 1);

    bridge.owner_cache.lock().unwrap().put(
        "node-bob",
        Some("person-bob".to_owned()),
        ago(OWNER_BINDING_MEMO_TTL + StdDuration::from_secs(1)),
    );
    assert_eq!(bridge.owner_of_cached("node-bob").await, bob);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_TTL), 1);

    bridge.invalidate_owner_memo("node-bob");
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_OWNER_MEMO), Some(0));
    assert_eq!(bridge.owner_of_cached("node-bob").await, bob);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_INVALIDATED), 1, "keyed drop");

    bridge.invalidate_send_set_memos("host_kick");
    assert_eq!(bridge.owner_of_cached("node-bob").await, bob);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_INVALIDATED), 2, "whole drop");

    bridge.owner_of_cached("node-zed").await;
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_MISS), 2, "never asked");
    assert_eq!(
        memo(&m, obs::MEMO_READ_OWNER_MISS)
            + memo(&m, obs::MEMO_READ_OWNER_TTL)
            + memo(&m, obs::MEMO_READ_OWNER_INVALIDATED),
        u64::try_from(bridge.owner_reads.load(Ordering::SeqCst)).unwrap(),
        "every walk the store served, each under one cause"
    );
}

/// Eight concurrent lookups of one expired owner binding: one `ttl` read,
/// seven `joined`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_owner_lookups_join_the_one_walk_attribution_1019x() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[
            ("person-bob", identity_type::USER),
            ("node-bob", identity_type::NODE),
        ],
    )
    .await;
    seed_owner_binding(&backend, "person-bob", "node-bob").await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    bridge
        .probes
        .read_probe
        .delay_ms
        .store(50, Ordering::SeqCst);
    bridge.owner_cache.lock().unwrap().put(
        "node-bob",
        Some("person-bob".to_owned()),
        ago(OWNER_BINDING_MEMO_TTL + StdDuration::from_secs(1)),
    );
    let before = bridge.owner_reads.load(Ordering::SeqCst);
    futures::future::join_all((0..8).map(|_| bridge.owner_of_cached("node-bob"))).await;
    assert_eq!(bridge.owner_reads.load(Ordering::SeqCst) - before, 1);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_TTL), 1);
    assert_eq!(memo(&m, obs::MEMO_READ_OWNER_JOINED), 7);
}

/// The announce memo (identity-row reach) and the own-set memo: `miss`,
/// `hit`, `ttl`, `invalidated` (an occurrence's `forget_reach`, and a whole
/// drop), each with its size gauge.
#[tokio::test]
async fn the_announce_and_own_set_reads_say_why_attribution_1019x() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    register_fixture_keys(
        &backend,
        &[
            ("person-bob", identity_type::USER),
            ("node-bob", identity_type::NODE),
        ],
    )
    .await;
    seed_owner_binding(&backend, "person-bob", "node-bob").await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);

    // The announce memo, on the owned node.
    let reach = bridge.identity_row_reach("node-bob").await;
    assert_ne!(reach, IdentityRowReach::Unresolved, "a memoized answer");
    assert_eq!(memo(&m, obs::MEMO_READ_ANNOUNCE_MISS), 1);
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_ANNOUNCE_MEMO), Some(1));
    bridge.identity_row_reach("node-bob").await;
    assert_eq!(memo(&m, obs::MEMO_READ_ANNOUNCE_HIT), 1);
    bridge.announce_cache.lock().unwrap().insert(
        "node-bob".to_owned(),
        (
            ago(OWNER_BINDING_MEMO_TTL + StdDuration::from_secs(1)),
            reach.clone(),
        ),
    );
    bridge.identity_row_reach("node-bob").await;
    assert_eq!(memo(&m, obs::MEMO_READ_ANNOUNCE_TTL), 1);
    bridge.forget_reach("node-bob");
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_ANNOUNCE_MEMO), Some(0));
    bridge.identity_row_reach("node-bob").await;
    assert_eq!(memo(&m, obs::MEMO_READ_ANNOUNCE_INVALIDATED), 1, "keyed");
    bridge.invalidate_send_set_memos("host_kick");
    bridge.identity_row_reach("node-bob").await;
    assert_eq!(memo(&m, obs::MEMO_READ_ANNOUNCE_INVALIDATED), 2, "whole");
    assert_eq!(
        memo(&m, obs::MEMO_READ_ANNOUNCE_MISS)
            + memo(&m, obs::MEMO_READ_ANNOUNCE_TTL)
            + memo(&m, obs::MEMO_READ_ANNOUNCE_INVALIDATED),
        u64::try_from(bridge.announce_reads()).unwrap(),
        "every walk, each under one cause"
    );

    // The own-set memo, on the person.
    bridge.own_set_of("person-bob").await.expect("own set");
    assert_eq!(memo(&m, obs::MEMO_READ_OWN_SET_MISS), 1);
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_OWN_SET_MEMO), Some(1));
    bridge.own_set_of("person-bob").await.expect("own set");
    assert_eq!(memo(&m, obs::MEMO_READ_OWN_SET_HIT), 1);
    {
        let mut memo = bridge.own_set_cache.lock().unwrap();
        let (_, own) = memo.get("person-bob").cloned().expect("memoized");
        memo.insert(
            "person-bob".to_owned(),
            (ago(OWNER_BINDING_MEMO_TTL + StdDuration::from_secs(1)), own),
        );
    }
    bridge.own_set_of("person-bob").await.expect("own set");
    assert_eq!(memo(&m, obs::MEMO_READ_OWN_SET_TTL), 1);
    bridge.forget_reach("node-zed");
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_OWN_SET_MEMO), Some(0));
    bridge.own_set_of("person-bob").await.expect("own set");
    assert_eq!(memo(&m, obs::MEMO_READ_OWN_SET_INVALIDATED), 1);
    let _ = bridge.own_set_of("person-zed").await;
    assert_eq!(memo(&m, obs::MEMO_READ_OWN_SET_MISS), 2, "never asked");
}

/// The advertise watermarks' gauge: set on every insert, held at the cap.
#[test]
fn the_sweep_cursor_gauge_follows_its_inserts_attribution_1019x() {
    let m = obs::EdgeMetrics::new();
    let mut c = SweepCursors {
        size_gauge: Some(m.clone()),
        ..SweepCursors::default()
    };
    let key = |i: usize| (format!("node-{i}"), EnvelopeKind::Attestation);
    c.head(&key(0));
    c.head(&key(1));
    c.head(&key(0));
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_SWEEP_CURSORS), Some(2));
    for i in 2..MAX_TRACKED_SWEEP_CURSORS + 5 {
        c.head(&key(i));
    }
    assert_eq!(
        size(&m, obs::STRUCTURE_SIZE_SWEEP_CURSORS),
        Some(u64::try_from(MAX_TRACKED_SWEEP_CURSORS).unwrap()),
        "an eviction at the cap pairs with each insert"
    );
}

/// The four store-feed inbox gauges: a drain that queues rows sets them, a
/// take empties the one it takes, a failed drain zeroes all four.
#[tokio::test]
async fn the_feed_inbox_gauges_follow_the_inboxes_attribution_1019x() {
    use crate::replication::key_plane_memo::KeyPlaneRead;
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    let mut feed = crate::replication::store_feed::FeedState::default();
    let row = withdraws_row("node-a", "some-attestation");
    feed.distribute(&row);
    feed.distribute(&row);
    let taken = bridge.take_feed_inbox(&mut feed, Some(KeyPlaneRead::Revocation));
    assert_eq!(taken.rows.len(), 2, "a withdraws row may dirty every plane");
    let inbox = |r: KeyPlaneRead| size(&m, obs::STRUCTURE_SIZE_FEED_INBOX[r.index()]);
    assert_eq!(inbox(KeyPlaneRead::Revocation), Some(0), "taken");
    assert_eq!(inbox(KeyPlaneRead::KeyRecord), Some(2));
    feed.fail();
    bridge.gauge_feed_inboxes(&feed);
    for r in KeyPlaneRead::ALL {
        assert_eq!(inbox(r), Some(0), "{r:?}: a failed drain empties it");
    }
}

/// A `withdraws` row by `author` naming `target`: the row every key-plane
/// inbox keeps.
fn withdraws_row(author: &str, target: &str) -> ciris_persist::federation::types::Attestation {
    let mut row = att_with_dimension(None);
    row.attesting_key_id = author.to_owned();
    row.attestation_type = ciris_persist::federation::types::attestation_type::WITHDRAWS.to_owned();
    row.attested_key_id = target.to_owned();
    row
}

/// The park index's signer gauge: set where the refusal memory changes.
#[tokio::test]
async fn the_parked_signer_gauge_counts_signers_attribution_1019x() {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    for (i, signer) in ["signer-x", "signer-x", "signer-y"].iter().enumerate() {
        bridge
            .park_on_absent_key(
                EnvelopeKind::TransportDestination,
                [u8::try_from(i).unwrap(); 32],
                signer,
                Some("canonical"),
            )
            .await;
    }
    assert_eq!(bridge.refusal_backoff.parked_signers(), 2);
    bridge.book_refusal_memory();
    assert_eq!(size(&m, obs::STRUCTURE_SIZE_PARKED_SIGNERS), Some(2));
}
