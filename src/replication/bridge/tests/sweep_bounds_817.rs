//! **CIRISEdge#817 — v40 sweeps re-read full author histories under
//! concurrency.** The witnesses for the bridge's two halves of the fix:
//!
//! - item 1: the consent send-set memo and the owner-of memo are
//!   single-flight, so N concurrent callers of an EXPIRED entry cost ONE
//!   persist read;
//! - item 2: the membership-plane audience read (`may_receive_group_plane`,
//!   on the advertise and its fetch twin) and the send-set read behind
//!   `resolve_attestation_recipient` run under the advertise sweep permit,
//!   so at most `advertise_sweep_permits` of them are in flight at once.
//!
//! The in-memory directory never yields, so concurrent callers would
//! serialise and every bound would hold vacuously. The bridge's test-only
//! [`ReadProbe`](super::super::ReadProbe) holds each probed read for a fixed
//! delay before it runs, which makes the callers genuinely overlap, and
//! records the in-flight high-water mark.
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration as StdDuration;

const PROBE_DELAY_MS: u64 = 50;

fn bridge_with_permits(
    backend: &Arc<MemoryBackend>,
    cohort: &[&str],
    permits: usize,
) -> FederationDirectoryReplicationBridge {
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort: Vec<String> = cohort.iter().map(|s| (*s).to_string()).collect();
    let cohort_cb: CohortProvider = Arc::new(move || cohort.clone());
    let bridge = FederationDirectoryReplicationBridge::with_config(
        dir,
        cohort_cb,
        BridgeConfig {
            advertise_sweep_permits: permits,
            ..BridgeConfig::default()
        },
    )
    .with_local_key_id(Some("node-a".to_owned()));
    bridge
        .read_probe
        .delay_ms
        .store(PROBE_DELAY_MS, Ordering::SeqCst);
    bridge
}

/// An instant `by` in the past: an entry stamped with it is expired.
fn ago(by: StdDuration) -> Instant {
    Instant::now()
        .checked_sub(by)
        .expect("the monotonic clock is past the memo TTLs")
}

/// **Item 1, the consent memo.** Eight peers' sweeps resolve their
/// recipient while the send-set memo is EXPIRED: one persist read serves all
/// eight, every one of them gets the same answer, the memo is refilled, and
/// the next call inside the TTL reads nothing. Fails on v40.0.3, where each
/// of the eight missed and re-read the send-set (8 reads).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_send_set_is_reread_once_for_every_concurrent_sweep_817() {
    let backend = Arc::new(MemoryBackend::new());
    let bridge = bridge_with_permits(&backend, &[], 2);
    *bridge.consent_memo.lock().unwrap() = Some((
        ResolvedPeerSet::from_consent_peers(Vec::new()),
        ago(CONSENT_SEND_SET_MEMO_TTL + StdDuration::from_secs(1)),
    ));
    let peers: Vec<String> = (0..8).map(|i| format!("node-peer-{i}")).collect();
    let got = futures::future::join_all(
        peers
            .iter()
            .map(|p| bridge.resolve_attestation_recipient(p)),
    )
    .await;
    assert_eq!(
        bridge.consent_set_reads.load(Ordering::SeqCst),
        1,
        "eight concurrent sweeps over an expired send-set cost ONE read"
    );
    for (p, r) in peers.iter().zip(&got) {
        assert_eq!(
            r.as_ref().map(ResolvedRecipient::as_str),
            Some(p.as_str()),
            "each sweep still resolves its own recipient (first contact here)"
        );
    }
    let (_, refilled_at) = bridge
        .consent_memo
        .lock()
        .unwrap()
        .clone()
        .expect("the flight refilled the memo");
    assert!(
        refilled_at.elapsed() < CONSENT_SEND_SET_MEMO_TTL,
        "the refill is stamped when its read landed"
    );
    assert!(bridge.resolved_peer_set("node-a").await.is_some());
    assert_eq!(
        bridge.consent_set_reads.load(Ordering::SeqCst),
        1,
        "inside the TTL the memo serves; nothing is re-read"
    );
}

/// **Item 1, the owner memo.** Eight concurrent `owner_of` lookups of one
/// node whose memo entry has EXPIRED walk persist once, and all eight get the
/// walk's answer. Fails on v40.0.3 (8 walks).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_owner_binding_is_walked_once_for_every_concurrent_caller_817() {
    let backend = Arc::new(MemoryBackend::new());
    register_fixture_keys(
        &backend,
        &[
            ("person-bob", identity_type::USER),
            ("node-bob", identity_type::NODE),
        ],
    )
    .await;
    seed_owner_binding(&backend, "person-bob", "node-bob").await;
    let bridge = bridge_with_permits(&backend, &[], 2);
    bridge.owner_cache.lock().unwrap().put(
        "node-bob",
        Some("person-bob".to_owned()),
        ago(OWNER_BINDING_MEMO_TTL + StdDuration::from_secs(1)),
    );
    let before = bridge.owner_reads.load(Ordering::SeqCst);
    let got = futures::future::join_all((0..8).map(|_| bridge.owner_of_cached("node-bob"))).await;
    assert_eq!(
        bridge.owner_reads.load(Ordering::SeqCst) - before,
        1,
        "eight concurrent lookups of an expired owner-binding cost ONE walk"
    );
    assert!(
        got.iter()
            .all(|o| *o == OwnerLookup::Owner("person-bob".to_owned())),
        "every caller gets the walk's answer: {got:?}"
    );
    assert_eq!(
        bridge.owner_of_cached("node-bob").await,
        OwnerLookup::Owner("person-bob".to_owned())
    );
    assert_eq!(
        bridge.owner_reads.load(Ordering::SeqCst) - before,
        1,
        "the refilled entry serves inside the TTL"
    );
}

/// **Item 1 — an ownership event during a flight is not answered by the
/// pre-event read.** A walk is in flight when an owner-binding lands (the
/// apply path's invalidation): a lookup made after the event walks afresh
/// instead of joining the stale walk.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_invalidation_mid_flight_starts_a_fresh_walk_817() {
    let backend = Arc::new(MemoryBackend::new());
    let bridge = Arc::new(bridge_with_permits(&backend, &[], 2));
    let before = bridge.owner_reads.load(Ordering::SeqCst);
    let stale = {
        let bridge = Arc::clone(&bridge);
        tokio::spawn(async move { bridge.owner_of_cached("node-bob").await })
    };
    while bridge.owner_reads.load(Ordering::SeqCst) == before {
        tokio::task::yield_now().await;
    }
    bridge.invalidate_owner_memo("node-bob");
    assert_eq!(
        bridge.owner_of_cached("node-bob").await,
        OwnerLookup::Unowned
    );
    assert_eq!(
        bridge.owner_reads.load(Ordering::SeqCst) - before,
        2,
        "the post-event lookup walked on its own"
    );
    assert_eq!(stale.await.unwrap(), OwnerLookup::Unowned);
}

/// **Item 2 — the membership-plane and send-set reads are bounded by the
/// sweep permits.** `advertise_sweep_permits = 2`; eight peers at once each
/// (a) advertise the Family plane (its `may_receive_group_plane` runs inside
/// the page permit), (b) fetch the family record by hash (the fetch twin's
/// `may_receive_group_plane`, which ran under no permit), and (c) resolve
/// their attestation recipient with the send-set memo empty (the
/// `consent_peers_by_principals` read, which ran under no permit). At most two
/// of those reads are ever in flight together. Fails on v40.0.3: the eight
/// fetches' reads all overlap (and with the fetch permit alone, the send-set
/// read still makes a third).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn group_plane_and_send_set_reads_are_bounded_by_the_sweep_permits_817() {
    let backend = Arc::new(MemoryBackend::new());
    register_fixture_keys(
        &backend,
        &[
            ("person-p", identity_type::USER),
            ("person-l", identity_type::USER),
        ],
    )
    .await;
    backend
        .put_family(sign_family_fixture(
            "person-p",
            fixture_family_founded("f-817", "person-p", "person-l"),
        ))
        .await
        .expect("seed the family");
    let bridge = bridge_with_permits(&backend, &["person-p"], 2);
    let refs = bridge.list_envelope_refs(EnvelopeKind::Family).await;
    assert_eq!(refs.len(), 1, "the family record is held");
    let hash = refs[0].envelope_hash;
    let reads_before = bridge.read_probe.group_plane_reads.load(Ordering::SeqCst);
    let peers: Vec<String> = (0..8).map(|i| format!("node-peer-{i}")).collect();
    let work = peers.iter().map(|p| {
        let bridge = &bridge;
        async move {
            let p = p.as_str();
            tokio::join!(
                bridge.list_envelope_refs_for_peer(EnvelopeKind::Family, Some(p)),
                bridge.fetch_envelope_bytes_for_peer(EnvelopeKind::Family, &hash, Some(p)),
                bridge.resolve_attestation_recipient(p),
            )
        }
    });
    tokio::time::timeout(StdDuration::from_secs(60), futures::future::join_all(work))
        .await
        .expect("no sweep deadlocks on the permit");
    assert_eq!(
        bridge.read_probe.group_plane_reads.load(Ordering::SeqCst) - reads_before,
        16,
        "every advertise and every fetch put the family to persist"
    );
    assert_eq!(
        bridge.consent_set_reads.load(Ordering::SeqCst),
        1,
        "the eight recipients shared one send-set read"
    );
    let max = bridge.read_probe.max_in_flight.load(Ordering::SeqCst);
    assert!(
        max <= 2,
        "with 2 permits and 8 concurrent peers at most 2 membership-plane / send-set \
         reads are in flight at once; saw {max}"
    );
    assert_eq!(max, 2, "the bound is reached, not a serialisation");
    assert_eq!(bridge.read_probe.in_flight.load(Ordering::SeqCst), 0);
}

/// **Item 2 — no deadlock at one permit.** The send-set read now takes a
/// permit, and the attestation sweep takes one per page after it: with
/// `permits = 1` the recipient resolution must release before the first
/// page acquires.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_send_set_permit_does_not_re_enter_the_gate_817() {
    let backend = Arc::new(MemoryBackend::new());
    let bridge = bridge_with_permits(&backend, &[], 1);
    bridge.read_probe.delay_ms.store(0, Ordering::SeqCst);
    let peers: Vec<String> = (0..4).map(|i| format!("node-peer-{i}")).collect();
    tokio::time::timeout(
        StdDuration::from_secs(30),
        futures::future::join_all(peers.iter().map(|p| {
            let bridge = &bridge;
            async move {
                bridge.consent_memo.lock().unwrap().take();
                bridge
                    .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(p))
                    .await;
            }
        })),
    )
    .await
    .expect("one permit: the recipient read and the sweep pages take it in turn");
}

/// The attesting key of a fetched Attestation's wire bytes.
fn author_of(bytes: &[u8]) -> String {
    let v: serde_json::Value = serde_json::from_slice(bytes).expect("attestation json");
    let inner = v.get("attestation").unwrap_or(&v);
    inner["attesting_key_id"]
        .as_str()
        .expect("attesting_key_id")
        .to_owned()
}

/// **Item 4 — one Deliver walks the trust root ONCE, and a revocation between
/// two Delivers is seen by the second.** A Rooted peer in the send set fetches
/// a third party's five rows (and the rest of what it is offered) in one
/// Deliver's batch: `rooted_with` walks once, where the fetch twin used to
/// walk once per row (2.75 s a row at the harness's full scale, 96% of its
/// sweep). Then the peer withdraws its acceptance of the root, and the NEXT
/// Deliver walks again, finds it no longer Rooted, and withholds the third
/// party's rows: nothing of the first batch's verdict survived it. Fails on
/// v40.1.0 with one walk per fetched row.
#[tokio::test]
async fn one_deliver_walks_the_trust_root_once_and_the_next_sees_a_revocation_817() {
    let local = "local-node";
    let producer = "producer";
    let peer = "rooted-peer";
    let backend = Arc::new(MemoryBackend::new());
    register_fixture_keys(
        &backend,
        &[
            (local, identity_type::USER),
            (producer, identity_type::USER),
            (peer, identity_type::NODE),
        ],
    )
    .await;
    for _ in 0..5 {
        seed_advertised_attestation(&backend, producer).await;
    }
    seed_common_root(&backend, &[local]).await;
    let scope = serde_json::json!(["infra:attest", "infra:serve"]);
    let peer_accepts = seed_acceptance_edge(&backend, peer, "root-r", &scope).await;
    seed_consent_membership_unrooted(&backend, local, peer).await;
    let bridge =
        bridge_over(&backend, &[local, producer, peer]).with_local_key_id(Some(local.to_owned()));

    let offered = bridge.list_attestations_for_peer(Some(peer)).await;
    let walks = || bridge.rooted_walks.load(Ordering::SeqCst);

    let before = walks();
    let mut batch = crate::replication::FetchBatch::new();
    let mut first = Vec::new();
    for r in &offered {
        first.push(
            bridge
                .fetch_envelope_bytes_for_peer_in(
                    EnvelopeKind::Attestation,
                    &r.envelope_hash,
                    Some(peer),
                    &mut batch,
                )
                .await,
        );
    }
    drop(batch);
    let from_producer: Vec<usize> = first
        .iter()
        .enumerate()
        .filter(|(_, b)| b.as_deref().is_some_and(|b| author_of(b) == producer))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        from_producer.len(),
        5,
        "the Rooted peer is served the third party's five rows in one Deliver"
    );
    assert_eq!(
        walks() - before,
        1,
        "one Deliver of {} rows walks the trust root once",
        offered.len()
    );

    // Between the Delivers: the peer withdraws its acceptance of the root.
    seed_withdraws(&backend, peer, &peer_accepts).await;
    let before = walks();
    let mut batch = crate::replication::FetchBatch::new();
    for &i in &from_producer {
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer_in(
                    EnvelopeKind::Attestation,
                    &offered[i].envelope_hash,
                    Some(peer),
                    &mut batch,
                )
                .await
                .is_none(),
            "the next Deliver sees the withdrawal: no longer Rooted, the third party's \
             row is withheld"
        );
    }
    assert_eq!(walks() - before, 1, "the next Deliver walked afresh, once");
}
