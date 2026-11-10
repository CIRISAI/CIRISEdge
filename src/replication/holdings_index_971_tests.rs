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
//! - **differential** — in `holdings_doors_971_tests`, over every door of
//!   the door table (`super::holdings_index` module docs);
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
pub(super) const NO_TEST_OUTLIVES: Duration = Duration::from_secs(3600);
use super::holdings_index::Status;
use super::key_plane_v59_tests::{round, NodeA};
use super::park_fresh_858_tests::{hold, Ident};
use crate::observability as obs;
use crate::replication::{
    BridgeConfig, EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};

/// The covered session planes, one per persist index plus every key plane.
pub(super) const COVERED: [EnvelopeKind; 6] = [
    EnvelopeKind::Attestation,
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::Revocation,
    EnvelopeKind::IdentityOccurrenceRevocation,
    EnvelopeKind::TransportDestination,
];

pub(super) fn bridge_with(
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
pub(super) async fn index_drain(dir: &dyn FederationDirectory, kind: &str) -> HashSet<[u8; 32]> {
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

pub(super) fn refs_of(hashes: &HashSet<[u8; 32]>) -> Vec<EnvelopeRef> {
    hashes
        .iter()
        .map(|h| EnvelopeRef {
            envelope_hash: *h,
            seq: 0,
        })
        .collect()
}

pub(super) fn counter(metrics: &obs::EdgeMetrics, label: &str) -> u64 {
    metrics.holdings_index().get(label).copied().unwrap_or(0)
}

/// A route for `node` at `epoch`, hybrid-signed by the node (the shape of the
/// v59 fixture's route, with a destination that changes with the epoch so a
/// supersession changes the bytes).
pub(super) async fn route_at(
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
pub(super) async fn bind(dir: &SqliteBackend, owner: &Ident, node: &Ident) {
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
pub(super) async fn ask_all(bridge: &FederationDirectoryReplicationBridge) {
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
pub(super) fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// The set, and the want over `offered`, equal the index's on both planes.
pub(super) async fn assert_index_equal(
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

/// **Warm-up (condition 4).** The walk from the head of the log runs in the
/// background, never inside a peer's ask. With the warm-up's head reads held
/// at a gate, a Summary on each covered plane is answered at once, from the
/// pre-v45 drain (counted `fallback_unbooted`), and does NOT boot the set
/// itself (no `boots` until the warm-up does it). Once the gate opens the
/// warm-up boots both planes, `ready_after_ms` is set, and the next ask is
/// answered from the set. Mutants: the walk run inline in the ask (the ask
/// waits at the gate and the timeout fires), `begin_warm` removed (the ask
/// boots the set: `boots` moves before the gate opens).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_ask_waits_on_the_warm_up_and_none_boots_the_set_before_it_971() {
    /// An ask that does not wait returns long before this; an event bound.
    const ANSWERED_WITHIN: Duration = Duration::from_secs(30);
    let a = NodeA::build("warm971", 0xd1).await;
    let counting = Arc::new(CountingDirectory::new(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>
    ));
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_with(
        Arc::clone(&counting) as Arc<dyn FederationDirectory>,
        a.n.key_id(),
        subjects(&a),
        BridgeConfig::default(),
        Some(metrics.clone()),
    );
    counting.close_head_reads();
    let warm = {
        let bridge = Arc::clone(&bridge);
        tokio::spawn(async move { bridge.warm_holdings_index().await })
    };
    counting.a_head_read_is_held().await;
    for kind in COVERED {
        let held = index_drain(
            &*a.dir,
            super::holdings_index::IndexPlane::of_kind(kind)
                .expect("covered")
                .index_kind(),
        )
        .await;
        let mut offered = refs_of(&held);
        offered.push(EnvelopeRef {
            envelope_hash: [0xee; 32],
            seq: 0,
        });
        let want = tokio::time::timeout(ANSWERED_WITHIN, bridge.holdings_want(kind, &offered))
            .await
            .unwrap_or_else(|_| panic!("{kind:?}: an ask waited on the warm-up"));
        assert_eq!(want, vec![[0xee; 32]], "{kind:?}: the drain's answer");
    }
    for slot in 0..2 {
        assert_eq!(
            counter(&metrics, obs::HOLDINGS_BOOTS[slot]),
            0,
            "no ask booted the set while the warm-up runs"
        );
        assert!(counter(&metrics, obs::HOLDINGS_FALLBACK_UNBOOTED[slot]) >= 1);
    }
    counting.open_head_reads();
    warm.await.expect("the warm-up ends");
    for slot in 0..2 {
        assert_eq!(
            counter(&metrics, obs::HOLDINGS_BOOTS[slot]),
            1,
            "the warm-up booted it"
        );
        assert!(
            metrics
                .holdings_index_gauge()
                .contains_key(obs::HOLDINGS_GAUGE_READY_AFTER_MS[slot]),
            "ready_after_ms is set"
        );
    }
    for kind in [
        EnvelopeKind::Attestation,
        EnvelopeKind::TransportDestination,
    ] {
        assert_eq!(bridge.holdings_index_status(kind), Some(Status::Ready));
        let before = counter(
            &metrics,
            obs::HOLDINGS_ANSWERS_SET[usize::from(kind == EnvelopeKind::TransportDestination)],
        );
        let _ = bridge.holdings_want(kind, &[]).await;
        assert_eq!(
            counter(
                &metrics,
                obs::HOLDINGS_ANSWERS_SET[usize::from(kind == EnvelopeKind::TransportDestination,)]
            ),
            before + 1,
            "{kind:?}: answered from the set once warm"
        );
    }
}

/// **Every counter this branch adds or relies on is in the exported map, by
/// name.** The map is `EdgeMetricsBundle::flatten()`, the projection a host
/// exports whole (CIRISServer's `/v1/federation/metrics` builds its body by
/// hand from chosen bundle fields and does not carry these families today;
/// that is the server's to add, and its own test's to prove). Each label is
/// booked once through the setter production uses, then read back by its
/// flattened name. A label renamed, dropped from its family, or booked into a
/// family `flatten` does not project fails here.
#[test]
fn every_counter_this_branch_adds_is_exported_by_name_971() {
    let m = obs::EdgeMetrics::new();
    let key_plane = [
        obs::KEY_PLANE_LISTINGS,
        obs::KEY_PLANE_SWEEPS,
        obs::KEY_PLANE_SUBJECT_READS,
        obs::KEY_PLANE_MEMO_HITS,
        obs::KEY_PLANE_READ_FAILURES,
        obs::KEY_PLANE_SWEEP_MS,
        obs::KEY_PLANE_PROBE_READS,
        obs::KEY_PLANE_PROBE_ROWS,
        obs::KEY_PLANE_PROBE_FAILURES,
        obs::KEY_PLANE_INVALIDATED,
        obs::KEY_PLANE_REBUILDS,
        obs::KEY_PLANE_REBUILDS_FIRST,
        obs::KEY_PLANE_REBUILDS_TTL,
        obs::KEY_PLANE_FORGOTTEN,
        obs::KEY_PLANE_INBOX_OVERFLOWS,
        obs::KEY_PLANE_PLANE_DIRT,
        obs::KEY_PLANE_PROBES_SPACED,
        obs::KEY_PLANE_FEED_DIRTY_MARKS,
    ];
    let sites = [
        obs::SWEEP_PERMIT_HOLDINGS_INDEX,
        obs::SWEEP_PERMIT_HOLDINGS_ROWS,
        obs::SWEEP_PERMIT_PLANE_PAGE,
        obs::SWEEP_PERMIT_ACCORD_EVIDENCE,
        obs::SWEEP_PERMIT_SUBJECT_PULL,
        obs::SWEEP_PERMIT_ANNOUNCED_TESTIMONY,
        obs::SWEEP_PERMIT_KEY_PLANE_SUBJECT,
        obs::SWEEP_PERMIT_FEED_ATTESTATION,
        obs::SWEEP_PERMIT_FEED_ROUTE,
        obs::SWEEP_PERMIT_SEND_SET,
        obs::SWEEP_PERMIT_ADVERTISE_PAGE,
        obs::SWEEP_PERMIT_ADVERTISE_REQUIRED,
        obs::SWEEP_PERMIT_HOLDINGS_WARM,
        obs::SWEEP_PERMIT_OTHER,
    ];
    let mut holdings: Vec<&'static str> = [
        obs::HOLDINGS_ANSWERS_SET,
        obs::HOLDINGS_ANSWERS_DRAIN,
        obs::HOLDINGS_FALLBACK_UNBOOTED,
        obs::HOLDINGS_FALLBACK_SUSPECT,
        obs::HOLDINGS_BOOTS,
        obs::HOLDINGS_AUDITS,
        obs::HOLDINGS_DRAIN_FAILURES,
        obs::HOLDINGS_DRAIN_MS,
        obs::HOLDINGS_DRIFT_MISSING,
        obs::HOLDINGS_DRIFT_EXTRA,
        obs::HOLDINGS_SUSPECT_AUDITS,
        obs::HOLDINGS_WRITE_THROUGH,
        obs::HOLDINGS_FEED_INSERTS,
        obs::HOLDINGS_DUPLICATE_UNHELD,
        obs::HOLDINGS_FEED_PROBES,
        obs::HOLDINGS_FEED_COALESCED,
        obs::HOLDINGS_FEED_FAILURES,
        obs::HOLDINGS_WARM_ROWS,
        obs::HOLDINGS_WARM_FAILURES,
    ]
    .into_iter()
    .flatten()
    .collect();
    holdings.extend([
        obs::STALE_ROUTE_MARKED,
        obs::STALE_ROUTE_SUPPRESSED,
        obs::STALE_ROUTE_EVICTED,
        obs::STALE_ROUTE_CLEARED,
    ]);
    let mut gauges: Vec<&'static str> = [
        obs::HOLDINGS_GAUGE_SIZE,
        obs::HOLDINGS_GAUGE_STATUS,
        obs::HOLDINGS_GAUGE_SOURCE,
        obs::HOLDINGS_GAUGE_LAST_DRAIN_MS,
        obs::HOLDINGS_GAUGE_READY_AFTER_MS,
    ]
    .into_iter()
    .flatten()
    .collect();
    gauges.extend([
        obs::HOLDINGS_GAUGE_ENABLED,
        obs::HOLDINGS_GAUGE_STALE_ROUTE_SIZE,
    ]);
    let advertise = [
        obs::ADVERTISE_SEND_SET_MEMO_HIT,
        obs::ADVERTISE_SEND_SET_READ,
        obs::ADVERTISE_SEND_SET_INVALIDATED,
        obs::ADVERTISE_SEND_SET_DROPPED_LIVE,
        obs::ADVERTISE_SEND_SET_EXPIRED,
    ];
    for label in key_plane {
        m.add_key_plane_sweep(label, 1);
    }
    for site in sites {
        m.inc_sweep_permit(site);
    }
    for label in &holdings {
        m.add_holdings_index(label, 1);
    }
    for label in &gauges {
        m.set_holdings_index_gauge(label, 7);
    }
    for label in advertise {
        m.inc_advertise(label);
    }
    let flat = m.snapshot().flatten();
    let mut missing = Vec::new();
    let mut expect = |name: String, present: bool| {
        if !present {
            missing.push(name);
        }
    };
    for label in key_plane {
        let name = format!("key_plane_sweep.{label}");
        expect(name.clone(), flat.counters.get(&name) == Some(&1));
    }
    for site in sites {
        let name = format!("sweep_permits.{site}");
        expect(name.clone(), flat.counters.get(&name) == Some(&1));
    }
    for label in &holdings {
        let name = format!("holdings_index.{label}");
        expect(name.clone(), flat.counters.get(&name) == Some(&1));
    }
    for label in &gauges {
        let name = format!("holdings_index_gauge.{label}");
        let got = flat
            .counters
            .get(&name)
            .map(|v| *v as f64)
            .or(flat.gauges.get(&name).copied());
        expect(name.clone(), got == Some(7.0));
    }
    for label in advertise {
        let name = format!("advertise.{label}");
        expect(name.clone(), flat.counters.get(&name) == Some(&1));
    }
    assert!(
        missing.is_empty(),
        "not in the exported map by name: {missing:?}"
    );
}
