//! **CIRISEdge#971 — the holdings index equals persist's content-hash index,
//! and the receive diff stops draining it.**
//!
//! Over real sqlite directories and the real bridge:
//!
//! - **membership** (condition b) — after writes through every door that
//!   reaches the index this fixture can drive (the key door, the occurrence
//!   door, the revocation door, the route door, a route supersession,
//!   `put_attestation`, the replicated-attestation door for a `withdraws` and
//!   a carrier, and the replication choke), the set equals a full drain of
//!   the index EXACTLY, on both planes, with no audit having run;
//! - **lockstep** (condition c) — a row admitted through the replication
//!   choke is inserted by the write-through under the hash the index holds;
//! - **idle** — 100 Summaries on every covered plane against a booted set
//!   read the store zero times (no drain, and inside the probe spacing no
//!   cursor probe either);
//! - **local write** — a row written straight to the store is not wanted
//!   once the host reports it, and inside the spacing an unreported one is
//!   wanted (the stated bound: a `Duplicate`, never a missed row); with
//!   spacing zero the cursor alone sees it;
//! - **audit, both directions** — a hash the index lost is wanted again after
//!   the audit (`drift_extra`), and a hash no feed saw is added by it
//!   (`drift_missing`);
//! - **differential** — over random sequences through every door the fixture
//!   drives, local and replicated, the set and the want equal the index's at
//!   every step, with no audit;
//! - **fallback** (condition d) — while the cursor probe fails, every ask
//!   answers from the drain; once it recovers, from the set;
//! - **convergence** — two nodes converge on every covered plane, and a second
//!   round applies nothing;
//! - **concurrency** — many peers' diffs during a boot drain and during audits
//!   all see a whole set.
//!
//! `cargo test --lib holdings_index_971`

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use ciris_persist::federation::types::SignedAttestation;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;

use super::counting_directory_930::CountingDirectory;

/// A probe spacing no test outlives: "inside the spacing" is then
/// deterministic, and only a dirt mark makes the feed probe.
const NO_TEST_OUTLIVES: Duration = Duration::from_secs(3600);
use super::holdings_index::Status;
use super::key_plane_v59_tests::{round, NodeA};
use super::park_fresh_858_tests::{hold, Ident};
use crate::observability as obs;
use crate::replication::{
    BridgeConfig, EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};

/// The covered session planes, one per persist index plus every key plane.
const COVERED: [EnvelopeKind; 6] = [
    EnvelopeKind::Attestation,
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::Revocation,
    EnvelopeKind::IdentityOccurrenceRevocation,
    EnvelopeKind::TransportDestination,
];

fn bridge_with(
    dir: Arc<dyn FederationDirectory>,
    me: &str,
    publish: Vec<String>,
    config: BridgeConfig,
    metrics: Option<obs::EdgeMetrics>,
) -> Arc<FederationDirectoryReplicationBridge> {
    let cohort = publish.clone();
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            dir,
            Arc::new(move || cohort.clone()),
            config,
        )
        .with_local_key_id(Some(me.to_owned()))
        .with_self_provider(Some(Arc::new(move || publish.clone())))
        .with_metrics(metrics),
    )
}

fn subjects(a: &NodeA) -> Vec<String> {
    [&a.p, &a.n, &a.k]
        .into_iter()
        .map(|id| id.key_id().to_owned())
        .collect()
}

/// A full drain of persist's index for `kind`, read straight from the store:
/// the reference every witness compares the set against.
async fn index_drain(dir: &dyn FederationDirectory, kind: &str) -> HashSet<[u8; 32]> {
    let mut out = HashSet::new();
    let mut after: Option<String> = None;
    loop {
        let page = dir
            .list_wire_hashes_since(kind, after.as_deref(), 1024)
            .await
            .expect("index page");
        for hex_hash in &page {
            let bytes = hex::decode(hex_hash).expect("hex");
            out.insert(<[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes"));
        }
        if page.len() < 1024 {
            return out;
        }
        after = page.last().cloned();
    }
}

fn refs_of(hashes: &HashSet<[u8; 32]>) -> Vec<EnvelopeRef> {
    hashes
        .iter()
        .map(|h| EnvelopeRef {
            envelope_hash: *h,
            seq: 0,
        })
        .collect()
}

fn counter(metrics: &obs::EdgeMetrics, label: &str) -> u64 {
    metrics.holdings_index().get(label).copied().unwrap_or(0)
}

/// A route for `node` at `epoch`, hybrid-signed by the node (the shape of the
/// v59 fixture's route, with a destination that changes with the epoch so a
/// supersession changes the bytes).
async fn route_at(
    node: &Ident,
    epoch: u64,
) -> ciris_persist::federation::self_at_login::SignedTransportDestination {
    use base64::Engine as _;
    use ciris_persist::federation::self_at_login::{
        BindingProvenance, SignedTransportDestination, TransportDestination,
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let row = TransportDestination {
        occurrence_key_id: node.key_id().to_owned(),
        transport_kind: "reticulum".to_owned(),
        destination: format!("{:02x}", 0xa0 + epoch).repeat(16),
        asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("millis"),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(b64.encode([0xbb; 32])),
        transport_x25519_pubkey_base64: Some(b64.encode([0xcc; 32])),
        binding_provenance: BindingProvenance::Rooted,
        epoch,
        retired_at: None,
    };
    let envelope = serde_json::to_value(&row).expect("route");
    let canonical = ciris_verify_core::jcs::canonicalize(&envelope).expect("jcs");
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&node.signer(), &canonical, "route")
        .await
        .expect("sign");
    SignedTransportDestination {
        attesting_key_id: node.key_id().to_owned(),
        transport_destination: row,
        signed_envelope: envelope,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: pqc,
        },
    }
}

/// P binds `node` to itself through `put_attestation` (a federation-tier
/// owner binding, the authoring door every producer row takes).
async fn bind(dir: &SqliteBackend, owner: &Ident, node: &Ident) {
    let row = crate::replication::attestation_bind::owner_binding_attestation(
        owner.key_id(),
        node.key_id(),
        chrono::Utc::now(),
        &owner.signer(),
    )
    .await
    .expect("build the binding");
    dir.put_attestation(SignedAttestation { attestation: row })
        .await
        .expect("admit the binding");
}

/// Ask the diff for every covered plane, once.
async fn ask_all(bridge: &FederationDirectoryReplicationBridge) {
    for kind in COVERED {
        let _ = bridge.holdings_want(kind, &[]).await;
    }
}

/// **Membership (b).** Writes through every door this fixture reaches, before
/// AND after the boot drain, at a page of 2 so the boot drain is many pages;
/// then the set equals the index exactly on both planes, and no audit ran
/// (the equality is the feeds', not a repair's).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_set_equals_a_full_drain_through_every_door_971() {
    let a = NodeA::build("mem971", 0x51).await; // key, occurrence, revocation, route doors
    a.withdraw_occurrence().await; // replicated-attestation door
    a.carrier_revoking_node_occurrence(a.k.key_id()).await; // the carrier
    bind(&a.dir, &a.p, &a.n).await; // put_attestation
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            sweep_page_rows: 2,
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    ask_all(&bridge).await;
    for kind in [
        EnvelopeKind::Attestation,
        EnvelopeKind::TransportDestination,
    ] {
        assert_eq!(bridge.holdings_index_status(kind), Some(Status::Ready));
    }
    assert!(
        counter(&metrics, obs::HOLDINGS_BOOTS[0]) == 1
            && counter(&metrics, obs::HOLDINGS_BOOTS[1]) == 1,
        "one boot per plane: {:?}",
        metrics.holdings_index()
    );

    // After the boot: a new key, its binding, a route for it and a
    // supersession of N's route — every one through a store door, none
    // through the bridge's apply.
    let m = Ident::mint("node-m-mem971", "node", 0x5a).await;
    hold(&a.dir, &m).await;
    bind(&a.dir, &a.p, &m).await;
    a.dir
        .put_signed_transport_destination(&route_at(&m, 1).await)
        .await
        .expect("M's route");
    a.dir
        .put_signed_transport_destination(&route_at(&a.n, 2).await)
        .await
        .expect("N's route, superseded");
    // The host reports its writes: its kick reaches this door, which marks
    // the feed dirty (the spacing is otherwise longer than this test).
    bridge.invalidate_send_set_memos("host_kick");
    ask_all(&bridge).await;

    for (kind, index) in [
        (EnvelopeKind::Attestation, "Attestation"),
        (EnvelopeKind::TransportDestination, "TransportDestination"),
    ] {
        let set = bridge.holdings_index_set(kind).expect("ready");
        let drained = index_drain(&*a.dir, index).await;
        assert!(!drained.is_empty(), "{index}: not vacuous");
        assert_eq!(
            set.difference(&drained).count() + drained.difference(&set).count(),
            0,
            "{index}: the set is the index exactly (set ∖ index {:?}, index ∖ set {:?})",
            set.difference(&drained).collect::<Vec<_>>(),
            drained.difference(&set).collect::<Vec<_>>()
        );
    }
    assert_eq!(
        counter(&metrics, obs::HOLDINGS_AUDITS[0]) + counter(&metrics, obs::HOLDINGS_AUDITS[1]),
        0,
        "no audit ran: the equality is the feeds' own"
    );
    assert!(
        counter(&metrics, obs::HOLDINGS_FEED_INSERTS[0]) >= 2
            && counter(&metrics, obs::HOLDINGS_FEED_INSERTS[1]) >= 2,
        "the post-boot rows came in through the cursor feeds: {:?}",
        metrics.holdings_index()
    );
}

/// **Lockstep (c).** B boots on an empty store, then takes every covered
/// plane from A through the replication choke. Each admitted row is inserted
/// by the write-through, from the delivered bytes; B's set then equals B's
/// own index exactly, so the hash edge computes for the bytes is the hash
/// persist indexed for the row, for every kind delivered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_written_through_hash_is_the_index_hash_971() {
    let a = NodeA::build("lock971a", 0x61).await;
    a.withdraw_occurrence().await;
    a.carrier_revoking_node_occurrence(a.k.key_id()).await;
    bind(&a.dir, &a.p, &a.n).await;
    let b_dir = super::park_fresh_858_tests::substrate().await;
    for id in [&a.p, &a.n, &a.k] {
        hold(&b_dir, id).await;
    }
    let b_me = Ident::mint("node-b-lock971", "node", 0x6a).await;
    hold(&b_dir, &b_me).await;
    let metrics = obs::EdgeMetrics::new();
    let bridge_a = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig::default(),
        None,
    );
    let bridge_b = bridge_with(
        Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
        b_me.key_id(),
        vec![b_me.key_id().to_owned()],
        BridgeConfig::default(),
        Some(metrics.clone()),
    );
    for kind in COVERED {
        round(kind, &bridge_a, a.n.key_id(), &bridge_b, b_me.key_id()).await;
    }
    assert!(
        counter(&metrics, obs::HOLDINGS_WRITE_THROUGH[0]) >= 4
            && counter(&metrics, obs::HOLDINGS_WRITE_THROUGH[1]) >= 1,
        "rows on both planes were admitted through the choke: {:?}",
        metrics.holdings_index()
    );
    for (kind, index) in [
        (EnvelopeKind::Attestation, "Attestation"),
        (EnvelopeKind::TransportDestination, "TransportDestination"),
    ] {
        let set = bridge_b.holdings_index_set(kind).expect("ready");
        let drained = index_drain(&*b_dir, index).await;
        assert_eq!(
            set, drained,
            "{index}: every written-through hash is the hash persist indexed"
        );
    }
}

/// **Idle.** A booted set answers 100 Summaries on every covered plane with
/// ZERO store reads: no index drain, and inside the probe spacing with no
/// door marking the feed dirty, no cursor probe either (Eric, 2026-11-09:
/// an idle round costs no store read).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_summaries_drain_the_index_zero_times_971() {
    let a = NodeA::build("idle971", 0x71).await;
    let counting = CountingDirectory::new(Arc::clone(&a.dir) as Arc<dyn FederationDirectory>);
    let bridge = bridge_with(
        Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        None,
    );
    ask_all(&bridge).await;
    let held = refs_of(&index_drain(&*a.dir, "Attestation").await);
    let routes = refs_of(&index_drain(&*a.dir, "TransportDestination").await);
    counting.reset();
    for _ in 0..100 {
        for kind in COVERED {
            let offered = if kind == EnvelopeKind::TransportDestination {
                &routes
            } else {
                &held
            };
            let want = bridge.holdings_want(kind, offered).await;
            assert!(want.is_empty(), "{kind:?}: every offered hash is held");
        }
    }
    assert_eq!(
        counting.total(),
        0,
        "600 idle Summaries read the store zero times: {:?}",
        counting.counts()
    );
}

/// **A local write is not re-fetched.** A row written straight to the store
/// after the boot: with the host's report (the door its kick reaches) it is
/// held by the next diff at once; unreported and inside the spacing it is
/// wanted (the stated bound: a `Duplicate`, never a row missed); with spacing
/// zero the cursor alone sees it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_direct_store_write_is_not_wanted_971() {
    let a = NodeA::build("local971", 0x81).await;
    let spaced = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        None,
    );
    let unspaced = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            feed_probe_spacing: Duration::ZERO,
            ..BridgeConfig::default()
        },
        None,
    );
    ask_all(&spaced).await;
    ask_all(&unspaced).await;
    let before = index_drain(&*a.dir, "Attestation").await;
    bind(&a.dir, &a.p, &a.n).await;
    let after = index_drain(&*a.dir, "Attestation").await;
    let new: Vec<EnvelopeRef> = refs_of(&after.difference(&before).copied().collect());
    assert!(!new.is_empty(), "the binding is indexed");
    assert_eq!(
        spaced
            .holdings_want(EnvelopeKind::Attestation, &new)
            .await
            .len(),
        new.len(),
        "unreported, inside the spacing: wanted (a Duplicate at worst)"
    );
    assert!(
        unspaced
            .holdings_want(EnvelopeKind::Attestation, &new)
            .await
            .is_empty(),
        "spacing zero: the cursor sees a row whichever door wrote it"
    );
    spaced.invalidate_send_set_memos("host_kick");
    assert!(
        spaced
            .holdings_want(EnvelopeKind::Attestation, &new)
            .await
            .is_empty(),
        "reported: held at once"
    );
}

/// **Audit, the missing direction.** A row no feed saw (written straight to
/// the store, unreported, inside the spacing) is added to the set by the next
/// audit, counted as `drift_missing`, and is never wanted after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_audit_adds_a_hash_no_feed_saw_971() {
    let a = NodeA::build("miss971", 0x8b).await;
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            holdings_audit_every: Duration::ZERO,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    ask_all(&bridge).await;
    let before = index_drain(&*a.dir, "Attestation").await;
    bind(&a.dir, &a.p, &a.n).await;
    let after = index_drain(&*a.dir, "Attestation").await;
    let new: Vec<[u8; 32]> = after.difference(&before).copied().collect();
    assert_eq!(new.len(), 1, "one new binding");
    // Audit due on every ask (cadence zero): it reconciles to the index.
    let want = bridge
        .holdings_want(
            EnvelopeKind::Attestation,
            &refs_of(&new.iter().copied().collect()),
        )
        .await;
    assert!(want.is_empty(), "the audit's drain holds it");
    assert_eq!(counter(&metrics, obs::HOLDINGS_DRIFT_MISSING[0]), 1);
    assert!(
        bridge
            .holdings_index_set(EnvelopeKind::Attestation)
            .expect("ready: one hash is inside the tolerance")
            .contains(&new[0]),
        "the audit added it to the set"
    );
}

/// **Audit.** A hash the index lost (a purge, emulated by the counting
/// directory hiding it from the index read) stays in the set until the
/// audit, which removes it, counts it as `drift_extra`, and the next diff
/// wants it again, exactly as the pre-v45 drain would.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_audit_removes_a_hash_the_index_lost_971() {
    let a = NodeA::build("audit971", 0x91).await;
    let counting = CountingDirectory::new(Arc::clone(&a.dir) as Arc<dyn FederationDirectory>);
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_with(
        Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            holdings_audit_every: Duration::ZERO,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    ask_all(&bridge).await;
    let held = index_drain(&*a.dir, "Attestation").await;
    let lost = *held.iter().next().expect("a held row");
    counting.hide_wire_hash(&hex::encode(lost));
    let lost_ref = refs_of(&std::iter::once(lost).collect());
    // Audit due on every ask (cadence zero): this ask reconciles and answers
    // from its own drain, which no longer holds the hash.
    let want = bridge
        .holdings_want(EnvelopeKind::Attestation, &lost_ref)
        .await;
    assert_eq!(want, vec![lost], "the audit's drain does not hold it");
    assert_eq!(counter(&metrics, obs::HOLDINGS_DRIFT_EXTRA[0]), 1);
    assert!(
        !bridge
            .holdings_index_set(EnvelopeKind::Attestation)
            .expect("ready: one hash is inside the tolerance")
            .contains(&lost),
        "the audit removed it from the set"
    );
}

/// **Fallback (d).** While the cursor probe fails, the set is not vouched for:
/// every ask marks the plane suspect and answers from a drain of the index
/// (the pre-v45 read, so the answer is right and the cost is the old one). The
/// first ask after the probe recovers answers from the set again, with no drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_probe_answers_from_the_drain_until_it_recovers_971() {
    let a = NodeA::build("fall971", 0xa1).await;
    let counting = CountingDirectory::new(Arc::clone(&a.dir) as Arc<dyn FederationDirectory>);
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_with(
        Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        // Spacing zero: every ask probes, so every ask meets the failure.
        BridgeConfig {
            feed_probe_spacing: Duration::ZERO,
            ..BridgeConfig::default()
        },
        Some(metrics.clone()),
    );
    ask_all(&bridge).await;
    assert_eq!(
        bridge.holdings_index_status(EnvelopeKind::Attestation),
        Some(Status::Ready)
    );
    let held = refs_of(&index_drain(&*a.dir, "Attestation").await);
    counting.fail_cursor_reads(true);
    for ask in 0..2 {
        let drains = counting.count("list_wire_hashes_since");
        let want = bridge.holdings_want(EnvelopeKind::Attestation, &held).await;
        assert!(want.is_empty(), "ask {ask}: the drain's answer is right");
        assert!(
            counting.count("list_wire_hashes_since") > drains,
            "ask {ask}: a plane whose probe failed answered from a drain"
        );
    }
    assert_eq!(counter(&metrics, obs::HOLDINGS_FEED_FAILURES[0]), 2);
    counting.fail_cursor_reads(false);
    let drains = counting.count("list_wire_hashes_since");
    let want = bridge.holdings_want(EnvelopeKind::Attestation, &held).await;
    assert!(want.is_empty());
    assert_eq!(
        counting.count("list_wire_hashes_since"),
        drains,
        "a recovered probe answers from the set, without a drain"
    );
}

/// **Convergence.** Two nodes converge on every covered plane over the set,
/// and a second round admits nothing: no held row is wanted again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_converge_and_stay_converged_971() {
    let a = NodeA::build("conv971", 0xb1).await;
    a.withdraw_occurrence().await;
    let b_dir = super::park_fresh_858_tests::substrate().await;
    for id in [&a.p, &a.n, &a.k] {
        hold(&b_dir, id).await;
    }
    let b_me = Ident::mint("node-b-conv971", "node", 0xba).await;
    hold(&b_dir, &b_me).await;
    let metrics = obs::EdgeMetrics::new();
    let bridge_a = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig::default(),
        None,
    );
    let bridge_b = bridge_with(
        Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
        b_me.key_id(),
        vec![b_me.key_id().to_owned()],
        BridgeConfig::default(),
        Some(metrics.clone()),
    );
    for kind in COVERED {
        round(kind, &bridge_a, a.n.key_id(), &bridge_b, b_me.key_id()).await;
    }
    let admitted = metrics.snapshot();
    for kind in COVERED {
        round(kind, &bridge_a, a.n.key_id(), &bridge_b, b_me.key_id()).await;
    }
    let again = metrics.snapshot();
    assert_eq!(
        admitted.replication_applied_total, again.replication_applied_total,
        "the second round applied nothing"
    );
    assert_eq!(
        counter(&metrics, obs::HOLDINGS_DUPLICATE_UNHELD[0])
            + counter(&metrics, obs::HOLDINGS_DUPLICATE_UNHELD[1]),
        0,
        "and fetched nothing the store already held"
    );
}

/// **Concurrency.** 32 peers' diffs race the boot drain and then repeated
/// audits (cadence zero). Every answer equals the diff against the index:
/// no ask ever saw a partial set.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_diffs_never_see_a_partial_set_971() {
    let a = NodeA::build("conc971", 0xc1).await;
    a.withdraw_occurrence().await;
    bind(&a.dir, &a.p, &a.n).await;
    let bridge = bridge_with(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig {
            sweep_page_rows: 2,
            holdings_audit_every: Duration::ZERO,
            ..BridgeConfig::default()
        },
        None,
    );
    let held = index_drain(&*a.dir, "Attestation").await;
    let mut offered = refs_of(&held);
    let absent = [0x5au8; 32];
    offered.push(EnvelopeRef {
        envelope_hash: absent,
        seq: 0,
    });
    let offered = Arc::new(offered);
    let mut joins = Vec::new();
    for _ in 0..32 {
        let b = Arc::clone(&bridge);
        let offered = Arc::clone(&offered);
        joins.push(tokio::spawn(async move {
            let mut answers = Vec::new();
            for _ in 0..4 {
                answers.push(b.holdings_want(EnvelopeKind::Attestation, &offered).await);
            }
            answers
        }));
    }
    for j in joins {
        for want in j.await.expect("join") {
            assert_eq!(want, vec![absent], "only the hash nobody holds is wanted");
        }
    }
}

/// splitmix64: the differential's deterministic op stream (no `rand` dep).
fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The set, and the want over `offered`, equal the index's on both planes.
async fn assert_index_equal(
    bridge: &FederationDirectoryReplicationBridge,
    dir: &dyn FederationDirectory,
    offered_extra: &[[u8; 32]],
    step: &str,
) {
    for (kind, index) in [
        (EnvelopeKind::Attestation, "Attestation"),
        (EnvelopeKind::TransportDestination, "TransportDestination"),
    ] {
        let drained = index_drain(dir, index).await;
        let mut offered: Vec<EnvelopeRef> = refs_of(&drained);
        offered.extend(offered_extra.iter().map(|h| EnvelopeRef {
            envelope_hash: *h,
            seq: 0,
        }));
        let mut want = bridge.holdings_want(kind, &offered).await;
        want.sort_unstable();
        let mut expected: Vec<[u8; 32]> = offered_extra
            .iter()
            .filter(|h| !drained.contains(*h))
            .copied()
            .collect();
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(want, expected, "{step} {index}: the want is the index's");
        let set = bridge
            .holdings_index_set(kind)
            .expect("ready: no audit, no failure");
        assert_eq!(set, drained, "{step} {index}: the set is the index");
    }
}

/// **Differential.** Over three seeded random sequences, each step one door:
/// a key admitted locally, an owner binding through `put_attestation`, a
/// route or its supersession, or rows authored at a peer and replicated in
/// through the choke on every covered plane (a key, a binding, a route, a
/// route supersession, a `withdraws`, a carrier). After EVERY step the set
/// equals a full drain of the index on both planes and the want over the
/// index's hashes plus foreign ones equals the index's diff, with no audit
/// (cadence an hour) and spacing zero, so every door is caught by a feed and
/// never by a repair. Mutation targets (each must turn this red): the
/// write-through's upsert, the Attestation feed's upsert, the route feed's
/// upsert, the head-start cursor (a pre-boot record rewritten keeps its old
/// hash).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // one op table
async fn the_set_tracks_the_index_through_random_door_sequences_971() {
    for (run, base) in [(0u64, 0x10u8), (1, 0x50), (2, 0x90)] {
        let a = NodeA::build(&format!("diff971a{run}"), base).await;
        let b_dir = super::park_fresh_858_tests::substrate().await;
        for id in [&a.p, &a.n, &a.k] {
            hold(&b_dir, id).await;
        }
        let b_me = Ident::mint(&format!("node-b-diff971-{run}"), "node", base + 3).await;
        hold(&b_dir, &b_me).await;
        let bridge_a = bridge_with(
            Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
            a.n.key_id(),
            subjects(&a),
            BridgeConfig::default(),
            None,
        );
        let mut b_publish = vec![b_me.key_id().to_owned()];
        b_publish.extend(subjects(&a));
        let bridge_b = bridge_with(
            Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
            b_me.key_id(),
            b_publish,
            BridgeConfig {
                feed_probe_spacing: Duration::ZERO,
                holdings_audit_every: NO_TEST_OUTLIVES,
                sweep_page_rows: 3,
                ..BridgeConfig::default()
            },
            None,
        );
        // Boot B's set on what it holds, then take A's rows once.
        ask_all(&bridge_b).await;
        for kind in COVERED {
            round(kind, &bridge_a, a.n.key_id(), &bridge_b, b_me.key_id()).await;
        }
        let foreign = [[0xeeu8; 32], [0xefu8; 32]];
        assert_index_equal(&bridge_b, &*b_dir, &foreign, &format!("run {run} boot")).await;

        let mut rng = 0x5eed_0000_u64 + run;
        let mut next_seed = base + 4;
        let mut local: Vec<Ident> = Vec::new();
        let mut bound: Vec<bool> = Vec::new();
        let mut epoch = 10u64;
        let mut withdrew = false;
        for step in 0..10 {
            let op = splitmix(&mut rng) % 5;
            let label = format!("run {run} step {step} op {op}");
            match op {
                // A key admitted at B through the key door.
                0 => {
                    let m = Ident::mint(&format!("node-m-diff971-{run}-{step}"), "node", next_seed)
                        .await;
                    next_seed += 1;
                    hold(&b_dir, &m).await;
                    local.push(m);
                    bound.push(false);
                }
                // An owner binding at B through `put_attestation`.
                1 => {
                    if let Some(i) = bound.iter().position(|b| !b) {
                        bind(&b_dir, &a.p, &local[i]).await;
                        bound[i] = true;
                    }
                }
                // A route at B, or its supersession.
                2 => {
                    if let Some(m) = local
                        .get(usize::try_from(splitmix(&mut rng)).unwrap_or(0) % local.len().max(1))
                    {
                        epoch += 1;
                        b_dir
                            .put_signed_transport_destination(&route_at(m, epoch).await)
                            .await
                            .expect("route at B");
                    }
                }
                // Rows authored at A, replicated in through the choke.
                3 => {
                    let x = Ident::mint(&format!("node-x-diff971-{run}-{step}"), "node", next_seed)
                        .await;
                    next_seed += 1;
                    hold(&a.dir, &x).await;
                    bind(&a.dir, &a.p, &x).await;
                    epoch += 1;
                    a.dir
                        .put_signed_transport_destination(&route_at(&x, epoch).await)
                        .await
                        .expect("route at A");
                    epoch += 1;
                    a.dir
                        .put_signed_transport_destination(&route_at(&a.n, epoch).await)
                        .await
                        .expect("A supersedes N's route");
                    for kind in COVERED {
                        round(kind, &bridge_a, a.n.key_id(), &bridge_b, b_me.key_id()).await;
                    }
                }
                // A `withdraws` and a carrier at A, replicated in.
                _ => {
                    if !withdrew {
                        a.withdraw_occurrence().await;
                        a.carrier_revoking_node_occurrence(a.k.key_id()).await;
                        withdrew = true;
                        for kind in COVERED {
                            round(kind, &bridge_a, a.n.key_id(), &bridge_b, b_me.key_id()).await;
                        }
                    }
                }
            }
            assert_index_equal(&bridge_b, &*b_dir, &foreign, &label).await;
        }
    }
}
