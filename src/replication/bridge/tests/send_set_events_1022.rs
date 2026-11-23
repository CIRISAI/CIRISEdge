//! **CIRISEdge#1022 — an idle send-set memo costs zero store reads, and every
//! door that can change the set drops it.**
//!
//! The consent send set used to re-derive itself from the whole consent and
//! owner history every 10 s, with nothing changed (the canonical: ~19k rows a
//! read, several reads a minute, zero invalidations). Its freshness is now the
//! events; the TTL is a five-minute backstop for what only the clock changes.
//! A replicated or feed-drained row drops a memo at once when it is at least
//! [`CONSENT_SEND_SET_EVENT_FLOOR`] old, and marks a younger one dirty so it
//! lapses at the floor: a busy seat never reads faster than the old TTL did.
//! Each witness counts the reads the store served for the set
//! (`consent_set_reads`) and the `advertise_send_set_*` causes.
//!
//! `cargo test --lib send_set_events_1022`
use super::*;
use crate::observability as obs;
use std::sync::atomic::Ordering;
use std::time::Duration as StdDuration;

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

/// Make the memo `by` old, as if that much idle time had passed.
fn age_memo(b: &FederationDirectoryReplicationBridge, by: StdDuration) {
    let mut memo = b.consent_memo.lock().unwrap();
    let (set, _) = memo.clone().expect("filled");
    *memo = Some((
        set,
        Instant::now()
            .checked_sub(by)
            .expect("the monotonic clock is past the backstop"),
    ));
}

fn reads(b: &FederationDirectoryReplicationBridge) -> usize {
    b.consent_set_reads.load(Ordering::SeqCst)
}

fn advertise(m: &obs::EdgeMetrics, label: &str) -> u64 {
    m.advertise().get(label).copied().unwrap_or(0)
}

/// Past the event floor: a row landing now drops the memo at once.
fn past_floor() -> StdDuration {
    CONSENT_SEND_SET_EVENT_FLOOR + StdDuration::from_secs(1)
}

/// A `consent:replication:v1` grant by `node-a` naming `peer`, as it arrives
/// on the wire.
fn wire_grant(peer: &str) -> Vec<u8> {
    let id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": "node-a",
        "attested_key_id": peer,
        "attestation_type": "scores",
        "dimension": "consent:replication:v1",
        "payload": {
            "grants": "transfer",
            "attestation_prefixes": ["trace:"],
        },
    });
    let row = build_federation_attestation(&id, "node-a", peer, "scores", envelope);
    serde_json::to_vec(&row).expect("serialize grant")
}

async fn seeded() -> Arc<SqliteBackend> {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    for key_id in ["node-a", "node-home", "node-new", "node-wire"] {
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(key_id, identity_type::AGENT),
            })
            .await
            .expect("seed key");
    }
    seed_consent_membership(&backend, "node-a", "node-home").await;
    // The held rows predate the first read by more than the commit margin
    // `feed_row_moves_send_set` allows (an admission stamped just before a
    // read began may commit after it), as a running store's history does.
    tokio::time::sleep(StdDuration::from_millis(1_100)).await;
    backend
}

/// Idle: minutes of rounds (each one a memo lookup and a serve-cursor feed
/// drain, as a round's advertise and holdings ask do) read the set ONCE, the
/// first time; the pre-#1022 TTL would have re-read it at every 10 s mark.
/// Past the five-minute backstop it reads once more, under `expired`.
#[tokio::test]
async fn idle_minutes_cost_no_send_set_reads_1022() {
    let backend = seeded().await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 1, "the first resolve reads");
    for idle_s in [11, 30, 60, 120, 180, 240, 299] {
        age_memo(&bridge, StdDuration::from_secs(idle_s));
        bridge
            .catch_up_attestation_feed(Instant::now(), None)
            .await
            .expect("feed drain");
        bridge.resolved_peer_set("node-a").await.expect("send set");
        assert_eq!(reads(&bridge), 1, "{idle_s} s idle: the memo answered");
    }
    assert_eq!(
        m.advertise()
            .get(obs::ADVERTISE_SEND_SET_INVALIDATED)
            .copied()
            .unwrap_or(0),
        0,
        "nothing changed, so nothing invalidated"
    );
    age_memo(
        &bridge,
        CONSENT_SEND_SET_MEMO_TTL + StdDuration::from_secs(1),
    );
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 2, "the backstop re-reads once");
    assert_eq!(
        m.advertise()
            .get(obs::ADVERTISE_SEND_SET_EXPIRED)
            .copied()
            .unwrap_or(0),
        1
    );
}

/// A host write that reports itself through no door (written straight into
/// the store) reaches the memo through the serve-cursor feed: the next drain
/// drops it, and the next resolve reads a set that names the new peer.
#[tokio::test]
async fn a_door_less_host_write_drops_the_memo_at_the_next_feed_drain_1022() {
    let backend = seeded().await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    let before = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert!(before.recipient("node-new").is_none());
    // The feed's cursor is placed before the write, as a running bridge's is.
    bridge
        .catch_up_attestation_feed(Instant::now(), None)
        .await
        .expect("feed drain");
    age_memo(&bridge, past_floor());
    seed_consent_membership(&backend, "node-a", "node-new").await;
    bridge.mark_feed_dirty();
    bridge
        .catch_up_attestation_feed(Instant::now(), None)
        .await
        .expect("feed drain");
    let after = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 2, "the drain dropped the memo; one re-read");
    assert!(
        after.recipient("node-new").is_some(),
        "the new grant's peer is in the set"
    );
    // A drain that finds only rows the memo already reflects drops nothing.
    bridge.mark_feed_dirty();
    bridge
        .catch_up_attestation_feed(Instant::now(), None)
        .await
        .expect("feed drain");
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(
        reads(&bridge),
        2,
        "rows admitted before the read move nothing"
    );
}

/// A content-plane row (a chat message) moves no send set: its arrival
/// through the feed drops nothing.
#[tokio::test]
async fn a_content_row_moves_no_send_set_1022() {
    let backend = seeded().await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    bridge.resolved_peer_set("node-a").await.expect("send set");
    bridge
        .catch_up_attestation_feed(Instant::now(), None)
        .await
        .expect("feed drain");
    let id = uuid::Uuid::new_v4().to_string();
    let envelope = serde_json::json!({
        "id": id,
        "attesting_key_id": "node-a",
        "attested_key_id": "node-home",
        "attestation_type": "scores",
        "dimension": crate::chat::CHAT_MESSAGE_DIMENSION,
        "payload": { "text": "hello" },
    });
    seed_raw_attestation(&backend, &id, "node-a", "node-home", "scores", envelope).await;
    bridge.mark_feed_dirty();
    bridge
        .catch_up_attestation_feed(Instant::now(), None)
        .await
        .expect("feed drain");
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 1, "a chat row is content, not consent");
}

/// A consent grant that arrives ON THE WIRE and is admitted drops a memo
/// past the event floor on the apply choke, before any feed drain.
#[tokio::test]
async fn a_replicated_consent_grant_drops_the_memo_on_admission_1022() {
    let backend = seeded().await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    seed_common_root(&backend, &["node-a", "node-wire"]).await;
    let before = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert!(before.recipient("node-wire").is_none());
    age_memo(&bridge, past_floor());
    let outcome = bridge
        .apply_envelope_bytes(
            EnvelopeKind::Attestation,
            &wire_grant("node-wire"),
            Some("node-wire"),
        )
        .await;
    assert!(outcome.is_admitted(), "the grant is admitted: {outcome:?}");
    let after = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 2, "admission dropped the memo; one re-read");
    assert!(after.recipient("node-wire").is_some());
    assert_eq!(advertise(&m, obs::ADVERTISE_SEND_SET_READ_INVALIDATED), 1);
}

/// A row that lands on a memo YOUNGER than the floor marks it dirty: the memo
/// answers until it reaches the floor (as the old 10 s TTL did), then the next
/// resolve reads once, counted `invalidated`, and the new peer is in the set.
/// A burst of rows inside the window is one invalidation and one read.
#[tokio::test]
async fn rows_on_a_young_memo_cost_one_read_at_the_floor_1022() {
    let backend = seeded().await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    seed_common_root(&backend, &["node-a", "node-wire", "node-new"]).await;
    bridge.resolved_peer_set("node-a").await.expect("send set");
    for peer in ["node-wire", "node-new"] {
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire_grant(peer), Some(peer))
            .await;
        assert!(outcome.is_admitted(), "the grant is admitted: {outcome:?}");
    }
    let held = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 1, "under the floor the memo still answers");
    assert!(held.recipient("node-wire").is_none());
    assert_eq!(
        advertise(&m, obs::ADVERTISE_SEND_SET_INVALIDATED),
        1,
        "two rows on one memo are one invalidation"
    );
    age_memo(&bridge, CONSENT_SEND_SET_EVENT_FLOOR);
    let after = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 2, "the dirty memo lapsed at the floor");
    assert!(after.recipient("node-wire").is_some());
    assert!(after.recipient("node-new").is_some());
    assert_eq!(advertise(&m, obs::ADVERTISE_SEND_SET_READ_INVALIDATED), 1);
    assert_eq!(advertise(&m, obs::ADVERTISE_SEND_SET_EXPIRED), 0);
    // The re-read memo is clean: idle again, it holds to the backstop.
    age_memo(&bridge, StdDuration::from_mins(2));
    bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 2, "the new memo is not dirty");
}

/// The host's own write is not floored: a kick drops a memo of any age at
/// once (CIRISEdge#968, the first-contact lesson).
#[tokio::test]
async fn a_host_kick_drops_a_young_memo_at_once_1022() {
    let backend = seeded().await;
    let m = obs::EdgeMetrics::new();
    let bridge = counted(&backend, &m);
    bridge.resolved_peer_set("node-a").await.expect("send set");
    seed_consent_membership(&backend, "node-a", "node-new").await;
    bridge.invalidate_send_set_memos("host_kick");
    let after = bridge.resolved_peer_set("node-a").await.expect("send set");
    assert_eq!(reads(&bridge), 2);
    assert!(after.recipient("node-new").is_some());
}

/// The classifier: content planes are skipped, the four structural types
/// always count, and an unknown dimension counts.
#[test]
fn the_send_set_row_classifier_1022() {
    let row = |ty: &str, dim: Option<&str>| {
        let mut a = build_federation_attestation(
            "x",
            "a",
            "b",
            ty,
            match dim {
                Some(d) => serde_json::json!({ "dimension": d }),
                None => serde_json::json!({}),
            },
        );
        a.attestation_type = ty.to_owned();
        a
    };
    let moves = FederationDirectoryReplicationBridge::row_may_move_send_set;
    for d in [
        "consent:replication:v1",
        "group:roster:v1",
        "membership:removal:v1",
        "identity:occurrence:v1",
        "key:record:v1",
        "ownership:responsible_party:node:v1",
        "some:future:plane:v1",
    ] {
        assert!(moves(&row("scores", Some(d))), "{d}");
    }
    assert!(moves(&row("scores", None)), "no dimension counts");
    for d in [
        "trace:complete:v1",
        "trace_summary:day:v1",
        crate::chat::CHAT_MESSAGE_DIMENSION,
        "delivery_receipt:s:v1",
        "key_grant:epoch:v1",
        "custody:ack:v1",
        "session:claim:v1",
        "ledger:x:v1",
        "settlement:x:v1",
    ] {
        assert!(!moves(&row("scores", Some(d))), "{d}");
    }
    for ty in ["withdraws", "recants", "supersedes", "delegates_to"] {
        assert!(moves(&row(ty, Some("chat:message:v1"))), "{ty}");
    }
}
