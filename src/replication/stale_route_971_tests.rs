//! **CIRISEdge#971 — a route older than the one held is fetched once, not
//! every round.**
//!
//! Over a real sqlite directory and the real bridge, B holds N's route at
//! epoch 2 and is offered N's route at epoch 1:
//!
//! - **r1** — the old hash is wanted (B does not hold those bytes), is
//!   delivered, and the apply reports `Duplicate` (the stale arm) and marks it;
//! - **r2** — the old hash is NOT wanted: the mark survives the `Duplicate`
//!   that `remember_outcome` clears the refusal memory on, and a second
//!   delivery of the same bytes keeps it;
//! - **r3** — N's route at epoch 3 is a different hash, is wanted, and is
//!   admitted: the mark is per hash, never per record.
//!
//! `cargo test --lib stale_route_971`

use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;

use super::holdings_index_971_tests::index_on;
use super::park_fresh_858_tests::{hold, substrate, Ident};
use super::summary::ApplyOutcome;
use crate::replication::{
    BridgeConfig, EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};

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

fn wire(
    route: &ciris_persist::federation::self_at_login::SignedTransportDestination,
) -> (Vec<u8>, EnvelopeRef) {
    use sha2::{Digest as _, Sha256};
    let bytes = serde_json::to_vec(route).expect("wire");
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    (
        bytes,
        EnvelopeRef {
            envelope_hash: hash,
            seq: 0,
        },
    )
}

/// The `want` a round computes: the diff, minus what the refusal memories
/// suppress (exactly `Session::on_summary`'s two steps).
async fn want(
    bridge: &FederationDirectoryReplicationBridge,
    offered: &[EnvelopeRef],
) -> Vec<[u8; 32]> {
    let mut want = bridge
        .holdings_want(EnvelopeKind::TransportDestination, offered)
        .await;
    want.retain(|h| !bridge.retry_suppressed(EnvelopeKind::TransportDestination, h));
    want
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_route_is_fetched_once_not_every_round_971() {
    let n = Ident::mint("node-n-stale971", "node", 0xd1).await;
    let dir = substrate().await;
    hold(&dir, &n).await;
    let e1 = route_at(&n, 1).await;
    let e2 = route_at(&n, 2).await;
    dir.put_signed_transport_destination(&e2)
        .await
        .expect("B holds N's route at epoch 2");
    let bridge = Arc::new(FederationDirectoryReplicationBridge::with_config(
        Arc::clone(&dir) as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        index_on(),
    ));
    let (old_bytes, old_ref) = wire(&e1);

    // r1 — wanted, delivered, stale.
    assert_eq!(
        want(&bridge, std::slice::from_ref(&old_ref)).await,
        vec![old_ref.envelope_hash],
        "r1: B does not hold the old bytes"
    );
    let r1 = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &old_bytes, None)
        .await;
    assert_eq!(r1, ApplyOutcome::Duplicate, "r1: the stale arm");

    // r2 — not wanted, and a second delivery keeps the mark.
    assert!(
        want(&bridge, std::slice::from_ref(&old_ref))
            .await
            .is_empty(),
        "r2: the mark survived the Duplicate's remember_outcome"
    );
    let again = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &old_bytes, None)
        .await;
    assert_eq!(again, ApplyOutcome::Duplicate);
    assert!(
        want(&bridge, std::slice::from_ref(&old_ref))
            .await
            .is_empty(),
        "r2: still marked after the bytes were pushed again"
    );

    // r3 — a newer route is a new hash: wanted and admitted.
    let e3 = route_at(&n, 3).await;
    let (new_bytes, new_ref) = wire(&e3);
    assert_eq!(
        want(&bridge, &[old_ref.clone(), new_ref.clone()]).await,
        vec![new_ref.envelope_hash],
        "r3: only the newer route is wanted"
    );
    let r3 = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &new_bytes, None)
        .await;
    assert!(r3.is_admitted(), "r3: admitted, got {r3:?}");
    assert!(
        want(&bridge, &[old_ref, new_ref]).await.is_empty(),
        "r3: the new route is held (write-through) and the old one stays marked"
    );
}

/// A bridge over `dir` (through a counting directory, so a test can make the
/// index lose a hash) that never audits on its own, warmed.
async fn counted_bridge(
    dir: &Arc<ciris_persist::store::sqlite::SqliteBackend>,
    metrics: &crate::observability::EdgeMetrics,
) -> (
    Arc<FederationDirectoryReplicationBridge>,
    super::counting_directory_930::CountingDirectory,
) {
    let counting = super::counting_directory_930::CountingDirectory::new(
        Arc::clone(dir) as Arc<dyn FederationDirectory>
    );
    let bridge = Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
            Arc::new(Vec::new),
            BridgeConfig {
                feed_probe_spacing: std::time::Duration::ZERO,
                holdings_audit_every: std::time::Duration::from_hours(1),
                ..index_on()
            },
        )
        .with_metrics(Some(metrics.clone())),
    );
    bridge.warm_holdings_index().await;
    (bridge, counting)
}

fn holdings(metrics: &crate::observability::EdgeMetrics, label: &str) -> u64 {
    metrics.holdings_index().get(label).copied().unwrap_or(0)
}

/// **The mark ends when the held route leaves the index.** B holds N's route
/// at epoch 2, r1 marks the epoch-1 bytes stale; then the epoch-2 entry
/// leaves the index (persist has no door that does this to a route today, so
/// the witness makes the index lose the hash, as a foreign rebuild would) and
/// the audit finds it (`drift_extra`). Every mark is dropped
/// (`stale_route.cleared`), and the next round wants the epoch-1 bytes again.
/// With `drop_stale_marks_on_route_removal` removed, the last want is empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_route_leaving_the_index_ends_every_stale_mark_971() {
    use crate::observability as obs;
    let n = Ident::mint("node-n-stale971b", "node", 0xd3).await;
    let dir = substrate().await;
    hold(&dir, &n).await;
    let e1 = route_at(&n, 1).await;
    let e2 = route_at(&n, 2).await;
    dir.put_signed_transport_destination(&e2)
        .await
        .expect("B holds epoch 2");
    let metrics = obs::EdgeMetrics::new();
    let (bridge, counting) = counted_bridge(&dir, &metrics).await;
    let (old_bytes, old_ref) = wire(&e1);
    let (_, held_ref) = wire(&e2);
    let r1 = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &old_bytes, None)
        .await;
    assert_eq!(r1, ApplyOutcome::Duplicate, "the stale arm marks it");
    assert_eq!(holdings(&metrics, obs::STALE_ROUTE_MARKED), 1);
    assert!(want(&bridge, std::slice::from_ref(&old_ref))
        .await
        .is_empty());
    assert_eq!(holdings(&metrics, obs::STALE_ROUTE_SUPPRESSED), 1);

    counting.hide_wire_hash(&hex::encode(held_ref.envelope_hash));
    bridge.holdings_audit_due_now();
    let _ = bridge
        .holdings_want(EnvelopeKind::TransportDestination, &[])
        .await;
    assert_eq!(holdings(&metrics, obs::HOLDINGS_DRIFT_EXTRA[1]), 1);
    assert_eq!(holdings(&metrics, obs::STALE_ROUTE_CLEARED), 1);
    assert_eq!(
        want(&bridge, std::slice::from_ref(&old_ref)).await,
        vec![old_ref.envelope_hash],
        "the older route is wanted again"
    );
}

/// **Eviction at the cap.** [`super::bridge::STALE_ROUTE_MARKS`] + 1 distinct
/// stale hashes: the first is evicted (front-drop) and is wanted once more,
/// every other mark still suppresses, `stale_route.evicted` is 1 and the size
/// gauge is the cap. Nothing else changes: the refusal memory's
/// `retry_suppressions` stays 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_mark_past_the_cap_evicts_the_oldest_once_971() {
    use crate::observability as obs;
    let dir = substrate().await;
    let metrics = obs::EdgeMetrics::new();
    let (bridge, _counting) = counted_bridge(&dir, &metrics).await;
    let cap = super::bridge::STALE_ROUTE_MARKS;
    let refs: Vec<EnvelopeRef> = (0..=cap)
        .map(|i| {
            let bytes = format!("stale-route-971-{i}").into_bytes();
            bridge.mark_stale_route(&bytes);
            wire_bytes(&bytes)
        })
        .collect();
    assert_eq!(
        holdings(&metrics, obs::STALE_ROUTE_MARKED),
        u64::try_from(cap + 1).expect("fits")
    );
    assert_eq!(holdings(&metrics, obs::STALE_ROUTE_EVICTED), 1);
    assert_eq!(
        metrics
            .holdings_index_gauge()
            .get(obs::HOLDINGS_GAUGE_STALE_ROUTE_SIZE)
            .copied(),
        Some(u64::try_from(cap).expect("fits"))
    );
    let wanted = want(&bridge, &refs).await;
    assert_eq!(
        wanted,
        vec![refs[0].envelope_hash],
        "only the evicted mark is wanted"
    );
    assert_eq!(
        bridge.retry_suppressions(),
        0,
        "the refusal memory is untouched"
    );
}

fn wire_bytes(bytes: &[u8]) -> EnvelopeRef {
    use sha2::{Digest as _, Sha256};
    EnvelopeRef {
        envelope_hash: Sha256::digest(bytes).into(),
        seq: 0,
    }
}
