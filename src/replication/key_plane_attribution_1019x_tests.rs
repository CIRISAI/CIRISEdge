//! **45.1.9 (attribution) — every key-plane subject read says why it read**,
//! over a real sqlite directory and the real bridge.
//!
//! On the Revocation plane: a first listing reads each subject as `miss`; an
//! idle listing is all `hit`; past the TTL each re-read is `ttl`; after a
//! revocation the cursor sees, the subjects its dirt dropped re-read as
//! `invalidated`. At every step the plane's three read labels sum to its
//! subject reads.
//!
//! `cargo test --lib attribution_1019x`

use std::sync::Arc;
use std::time::Duration;

use ciris_persist::federation::types::SignedRevocation;
use ciris_persist::federation::FederationDirectory;

use super::key_plane_memo::{KeyPlaneRead, MEMO_TTL};
use super::key_plane_v59_tests::{self_revocation, NodeA};
use super::park_fresh_858_tests::{hold, Ident};
use crate::observability as obs;
use crate::replication::{
    BridgeConfig, EnvelopeKind, FederationDirectoryReplicationBridge, ReplicationDirectory,
};

fn reads(m: &obs::EdgeMetrics, label: &str) -> u64 {
    m.memo_reads().get(label).copied().unwrap_or(0)
}

fn subject_reads(m: &obs::EdgeMetrics) -> u64 {
    m.key_plane_sweep()
        .get(obs::KEY_PLANE_SUBJECT_READS)
        .copied()
        .unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_key_plane_read_says_why_attribution_1019x() {
    let a = NodeA::build("att1019", 0xa1).await;
    let s = Ident::mint("own-att1019", "node", 0xaf).await;
    let e = Ident::mint("held-att1019-e", "node", 0xae).await;
    hold(&a.dir, &s).await;
    hold(&a.dir, &e).await;
    let own = vec![s.key_id().to_owned()];
    let mut cohort = Vec::new();
    for i in 0..4u8 {
        let id = Ident::mint(&format!("held-att1019-{i}"), "node", 0xb0 + i).await;
        hold(&a.dir, &id).await;
        cohort.push(id.key_id().to_owned());
    }
    cohort.push(a.k.key_id().to_owned());
    cohort.push(e.key_id().to_owned());
    let subjects = u64::try_from(own.len() + cohort.len()).unwrap();
    let metrics = obs::EdgeMetrics::new();
    let own_cb = own.clone();
    let b = FederationDirectoryReplicationBridge::with_config(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        Arc::new(move || cohort.clone()),
        BridgeConfig {
            feed_probe_spacing: Duration::from_hours(1),
            ..BridgeConfig::default()
        },
    )
    .with_self_provider(Some(Arc::new(move || own_cb.clone())))
    .with_metrics(Some(metrics.clone()));
    let slot = KeyPlaneRead::Revocation.index();
    let (hit, miss, ttl, invalidated) = (
        obs::MEMO_READ_KEY_PLANE_HIT[slot],
        obs::MEMO_READ_KEY_PLANE_MISS[slot],
        obs::MEMO_READ_KEY_PLANE_TTL[slot],
        obs::MEMO_READ_KEY_PLANE_INVALIDATED[slot],
    );
    let summed = |m: &obs::EdgeMetrics| reads(m, miss) + reads(m, ttl) + reads(m, invalidated);

    // 1. First listing: never read.
    b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(reads(&metrics, miss), subjects);
    assert_eq!(summed(&metrics), subject_reads(&metrics));

    // 2. Idle: answered from the memo (its listing cache).
    b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(reads(&metrics, hit), subjects);
    assert_eq!(summed(&metrics), subject_reads(&metrics), "no read");

    // 3. Past the TTL: each subject re-read for its age.
    b.age_key_plane_memo(KeyPlaneRead::Revocation, MEMO_TTL)
        .await;
    b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(reads(&metrics, ttl), subjects);
    assert_eq!(reads(&metrics, miss), subjects, "no new miss");
    assert_eq!(summed(&metrics), subject_reads(&metrics));

    // 4. A revocation the cursor sees: what its dirt dropped re-reads as
    // invalidated, never as a miss.
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    b.invalidate_send_set_memos("host_kick");
    b.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert!(reads(&metrics, invalidated) >= 1, "the dirt's subjects");
    assert_eq!(reads(&metrics, miss), subjects, "no new miss");
    assert_eq!(summed(&metrics), subject_reads(&metrics));
}
