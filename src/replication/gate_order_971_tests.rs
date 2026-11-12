//! **CIRISEdge#971 — the advertise asks the audience gate's reach half first,
//! and offers exactly what it offered before.**
//!
//! v45 runs the reach half of the audience gate (from memory) before the gates
//! that read the store: author quarantine, the accord relay, the serve
//! capability and the producer's recipient capability. Over real sqlite
//! directories and the real bridge:
//!
//! - **agreement** — for every peer of the fixture (a consent-included peer, a
//!   first-contact peer that authored rows here, a first-contact peer that did
//!   not, a person key, and an id the store has never seen), the Attestation
//!   offer in the v45 order equals the offer in the pre-v45 order
//!   (`set_early_reach_check(false)`), on fresh bridges so no watermark is
//!   shared;
//! - **cost** — for a first-contact peer whose required rows are all refused,
//!   the v45 order reads no consent grant and issues fewer attestation queries
//!   than the old order, which paid both per row before refusing.
//!
//! `cargo test --lib gate_order_971`

use std::collections::BTreeSet;
use std::sync::Arc;

use ciris_persist::federation::types::SignedAttestation;
use ciris_persist::federation::FederationDirectory;

use super::counting_directory_930::CountingDirectory;
use super::key_plane_v59_tests::NodeA;
use super::park_fresh_858_tests::{hold, Ident};
use crate::replication::{
    BridgeConfig, EnvelopeKind, FederationDirectoryReplicationBridge, ReplicationDirectory,
};

struct Fixture {
    a: NodeA,
    local: Ident,
    consented: Ident,
}

/// NodeA's store (P, N, K, with N's `withdraws` and a carrier), plus this
/// node L, a peer M that L's own consent grant names, P's owner binding of N
/// and P's owner binding of L.
async fn fixture(tag: &str, seed: u8) -> Fixture {
    let a = NodeA::build(tag, seed).await;
    a.withdraw_occurrence().await;
    a.carrier_revoking_node_occurrence(a.k.key_id()).await;
    let local = Ident::mint(&format!("node-l-{tag}"), "node", seed.wrapping_add(8)).await;
    let consented = Ident::mint(&format!("node-m-{tag}"), "node", seed.wrapping_add(9)).await;
    hold(&a.dir, &local).await;
    hold(&a.dir, &consented).await;
    // `NodeA::build` announces N itself; this adds P's binding of L.
    let row = crate::replication::attestation_bind::owner_binding_attestation(
        a.p.key_id(),
        local.key_id(),
        chrono::Utc::now(),
        &a.p.signer(),
    )
    .await
    .expect("binding");
    a.dir
        .put_attestation(SignedAttestation { attestation: row })
        .await
        .expect("admit binding");
    let grant = crate::replication::attestation_bind::replication_consent_attestation(
        local.key_id(),
        consented.key_id(),
        &["identity:", "key:", "trust:", "consent:"],
        chrono::Utc::now(),
        &local.signer(),
    )
    .await
    .expect("grant");
    a.dir
        .put_attestation(SignedAttestation { attestation: grant })
        .await
        .expect("admit grant");
    Fixture {
        a,
        local,
        consented,
    }
}

fn bridge_over(
    dir: Arc<dyn FederationDirectory>,
    local: &str,
    early: bool,
) -> FederationDirectoryReplicationBridge {
    bridge_with(dir, local, early, BridgeConfig::default())
}

fn bridge_with(
    dir: Arc<dyn FederationDirectory>,
    local: &str,
    early: bool,
    config: BridgeConfig,
) -> FederationDirectoryReplicationBridge {
    let me = vec![local.to_owned()];
    let cohort = me.clone();
    let b = FederationDirectoryReplicationBridge::with_config(
        dir,
        Arc::new(move || cohort.clone()),
        config,
    )
    .with_local_key_id(Some(local.to_owned()))
    .with_self_provider(Some(Arc::new(move || me.clone())));
    b.set_early_reach_check(early);
    b
}

async fn offer(bridge: &FederationDirectoryReplicationBridge, peer: &str) -> BTreeSet<[u8; 32]> {
    bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
        .await
        .into_iter()
        .map(|r| r.envelope_hash)
        .collect()
}

/// **Agreement.** The offer is the same set in both orders, for every peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_offer_is_the_same_in_both_gate_orders_971() {
    let f = fixture("agree971", 0x21).await;
    let dir = Arc::clone(&f.a.dir) as Arc<dyn FederationDirectory>;
    let peers = [
        f.consented.key_id().to_owned(),
        f.a.n.key_id().to_owned(),
        f.a.k.key_id().to_owned(),
        f.a.p.key_id().to_owned(),
        "node-never-seen-agree971".to_owned(),
    ];
    let mut any_offered = false;
    for peer in &peers {
        let old = offer(
            &bridge_over(Arc::clone(&dir), f.local.key_id(), false),
            peer,
        )
        .await;
        let new = offer(&bridge_over(Arc::clone(&dir), f.local.key_id(), true), peer).await;
        any_offered |= !new.is_empty();
        assert_eq!(
            new, old,
            "peer {peer}: the v45 order offers exactly the old set"
        );
    }
    assert!(
        any_offered,
        "the matrix is not vacuous: some peer is offered rows"
    );
}

/// **Cost.** For a first-contact peer (N authored rows here; no grant names
/// it), the old order paid the producer consent-grant read and the
/// quarantine query per row before refusing; the v45 order refuses from
/// memory first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_first_contact_peer_costs_no_gate_reads_971() {
    let f = fixture("cost971", 0x31).await;
    let peer = f.a.n.key_id().to_owned();
    let mut counts = Vec::new();
    for early in [false, true] {
        let counting = CountingDirectory::new(Arc::clone(&f.a.dir) as Arc<dyn FederationDirectory>);
        let bridge = bridge_over(
            Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
            f.local.key_id(),
            early,
        );
        let _ = offer(&bridge, &peer).await;
        counts.push(counting);
    }
    let (old, new) = (&counts[0], &counts[1]);
    eprintln!(
        "old order: {:?}\nv45 order: {:?}",
        old.counts(),
        new.counts()
    );
    // Counted under the gate's own caller label: the required read's egress
    // grants (`live_egress_grants_by_principals` for this node's key and its
    // owner, under `edge.advertise.required`) are the same method, read once
    // per listing in both orders and for no row.
    let gate = crate::read_caller::Site::GateCapability.label();
    eprintln!(
        "list_live_consent_grants_by callers: old {:?}, v45 {:?}",
        old.callers_of("list_live_consent_grants_by"),
        new.callers_of("list_live_consent_grants_by")
    );
    assert!(
        old.count_under("list_live_consent_grants_by", gate) > 0,
        "the fixture exercises the producer's consent-grant gate in the old order"
    );
    assert_eq!(
        new.count_under("list_live_consent_grants_by", gate),
        0,
        "no consent-grant read for rows the reach refuses"
    );
    assert!(
        new.count("execute_attestation_query") < old.count("execute_attestation_query"),
        "the per-row quarantine query is gone (old {}, new {})",
        old.count("execute_attestation_query"),
        new.count("execute_attestation_query")
    );
}

/// **CIRISEdge#971 commit 4 — the narrowed required read offers the same.**
/// For every peer, the offer with a first-contact peer's own rows read only in
/// the shapes its reach can carry equals the offer with all of them read, and
/// the first-contact peer that authored rows here is refused fewer of them.
/// The fixture zeroes `tip_margin` so its fresh rows sit behind the tip, the
/// case the narrowing exists for; production's 1 min tip margin is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_narrowed_first_contact_read_offers_the_same_971() {
    use crate::observability::{EdgeMetrics, WithholdReason};
    let f = fixture("narrow971", 0x41).await;
    // The shared fixture's rows authored by N are all about N (two `scores`
    // rows with N as their subject), so the to-N page reads them in both arms
    // and the narrowing has nothing to remove. A row N authored about another
    // node, outside the first-contact shapes, is what the narrowing stops
    // reading: N's owner binding of K.
    let about_k = crate::replication::attestation_bind::owner_binding_attestation(
        f.a.n.key_id(),
        f.a.k.key_id(),
        chrono::Utc::now(),
        &f.a.n.signer(),
    )
    .await
    .expect("N's binding of K");
    f.a.dir
        .put_attestation(SignedAttestation {
            attestation: about_k,
        })
        .await
        .expect("admit N's binding of K");
    let dir = Arc::clone(&f.a.dir) as Arc<dyn FederationDirectory>;
    let peers = [
        f.consented.key_id().to_owned(),
        f.a.n.key_id().to_owned(),
        f.a.k.key_id().to_owned(),
        f.a.p.key_id().to_owned(),
        "node-never-seen-narrow971".to_owned(),
    ];
    for peer in &peers {
        let mut offers = Vec::new();
        let mut refused = Vec::new();
        for narrow in [false, true] {
            let metrics = EdgeMetrics::new();
            let b = bridge_over(Arc::clone(&dir), f.local.key_id(), true)
                .with_metrics(Some(metrics.clone()));
            b.set_narrow_first_contact_read(narrow);
            offers.push(offer(&b, peer).await);
            refused.push(metrics.withholds(WithholdReason::RecipientNotInSendSet));
        }
        assert_eq!(
            offers[1], offers[0],
            "peer {peer}: the narrowed read offers the same"
        );
        assert!(refused[1] <= refused[0], "peer {peer}: never more refusals");
    }
    // N authored its key-plane rows and the carrier here: the full read paid a
    // refusal for each, the narrowed one does not read them. A peer with no
    // walk reads new rows from `tip_margin` behind now, so with the default
    // margin the fixture's rows, written seconds ago, are on the head page in
    // both arms and the required read's narrowing is hidden. Zero margin puts
    // them behind the tip, as on a seat where they are older than a minute:
    // the case the narrowing is for, read every round by the required read.
    let mut refused = Vec::new();
    for narrow in [false, true] {
        let metrics = EdgeMetrics::new();
        let config = BridgeConfig {
            tip_margin: std::time::Duration::ZERO,
            ..BridgeConfig::default()
        };
        let b = bridge_with(Arc::clone(&dir), f.local.key_id(), true, config)
            .with_metrics(Some(metrics.clone()));
        b.set_narrow_first_contact_read(narrow);
        let _ = offer(&b, f.a.n.key_id()).await;
        refused.push(metrics.withholds(WithholdReason::RecipientNotInSendSet));
    }
    assert!(
        refused[1] < refused[0],
        "the first-contact author is refused fewer rows (full {}, narrowed {})",
        refused[0],
        refused[1]
    );
}
