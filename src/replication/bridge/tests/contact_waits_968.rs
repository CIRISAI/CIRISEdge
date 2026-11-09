//! **CIRISEdge#968 (wait B) — a consent grant the host writes is in the very
//! next round's send set.**
//!
//! Server's docker rig: the node memoized its send set 56 ms before its host
//! wrote the consent grant to a new contact. The memo lives 10 s and only an
//! APPLIED ownership or revocation event dropped it, so the round the host
//! kicked for the grant read the old set and withheld the KeyPackage as
//! `reach=first_contact`; nothing asked again for 35 s.
//!
//! The witnesses read the production door the advertise and every fetch go
//! through (`resolve_attestation_recipient`) over a real store, and drive the
//! production host doors (a kick, `note_local_write`, the release hooks) on a
//! running runtime.
//!
//! `cargo test --lib contact_waits_968`
use super::*;
use crate::replication::resolved_state::Reach;

const LOCAL: &str = "contact-968-node";
const CONTACT: &str = "contact-968-peer";

async fn reach(bridge: &FederationDirectoryReplicationBridge) -> Reach {
    bridge
        .resolve_attestation_recipient(CONTACT)
        .await
        .expect("a peer is always at least a first-contact recipient")
        .reach()
}

/// **The witness.** Before the grant the contact is a first-contact stranger.
/// The host writes the grant; the memo still holds the old set (the field's
/// 56 ms). The host's kick drops the memos, and the next round mints the
/// contact a CONSENT recipient, which is what lets the KeyPackage move. With
/// the consent-memo drop removed from `invalidate_send_set_memos`, the last
/// read is still `FirstContact`, and this fails.
#[tokio::test]
async fn a_local_consent_grant_is_in_the_next_rounds_send_set_968() {
    let keys = [(LOCAL, identity_type::NODE), (CONTACT, identity_type::NODE)];
    let cohort: Vec<String> = keys.iter().map(|(k, _)| (*k).to_string()).collect();
    let (backend, bridge, metrics) = make_metered_bridge(&cohort);
    let bridge = bridge.with_local_key_id(Some(LOCAL.to_string()));
    register_fixture_keys(&backend, &keys).await;

    assert_eq!(reach(&bridge).await, Reach::FirstContact, "no grant yet");

    // The host writes the grant locally: no apply event fires.
    seed_consent_membership(&backend, LOCAL, CONTACT).await;
    assert_eq!(
        reach(&bridge).await,
        Reach::FirstContact,
        "the memo still serves the set read before the grant (the field's staleness)"
    );

    // The host's kick, as `ReplicationRuntime::round_now` makes it.
    bridge.invalidate_send_set_memos("host_kick");
    assert_eq!(
        reach(&bridge).await,
        Reach::Consent,
        "the round the kick fires reads the grant it was fired for"
    );
    assert_eq!(bridge.send_set_invalidations(), 1);
    assert_eq!(
        metrics
            .advertise()
            .get(crate::observability::ADVERTISE_SEND_SET_INVALIDATED)
            .copied(),
        Some(1),
        "the invalidation is counted"
    );
}

/// A transport that goes nowhere: the doors under test act on the bridge.
struct Nowhere;

#[async_trait::async_trait]
impl crate::transport::Transport for Nowhere {
    fn id(&self) -> crate::transport::TransportId {
        crate::transport::TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        _envelope_bytes: &[u8],
    ) -> Result<crate::transport::TransportSendOutcome, crate::transport::TransportError> {
        Ok(crate::transport::TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<crate::transport::InboundFrame>,
    ) -> Result<(), crate::transport::TransportError> {
        Ok(())
    }
}

/// **The class.** Every door a host reports a local write through drops the
/// send-set memos: a kick to one peer, a kick to all, a sync, a noted local
/// write, and both release hooks. Removing the call from any one of them
/// fails the count at that step.
#[tokio::test]
async fn every_host_local_write_door_drops_the_send_set_memos_968() {
    use crate::replication::runtime::{ReplicationRuntime, ReplicationRuntimeConfig};
    use crate::replication::scheduler::SchedulerConfig;
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let directory: Arc<dyn FederationDirectory> = backend;
    let config = ReplicationRuntimeConfig {
        enable_bundle_bootstrap_peers: false,
        scheduler: SchedulerConfig {
            cadence: Duration::from_secs(3600),
            round_timeout: Duration::from_millis(200),
            ..SchedulerConfig::default()
        },
        local_key_id: Some(LOCAL.to_string()),
        ..ReplicationRuntimeConfig::default()
    };
    let mut rt = ReplicationRuntime::start(
        directory,
        Arc::new(Nowhere),
        vec![crate::replication::ReplicationPeer {
            peer_key_id: CONTACT.to_string(),
            kind: EnvelopeKind::Key,
        }],
        config,
        None,
    )
    .await;
    let bridge = rt.bridge();
    let mut expected = bridge.send_set_invalidations();

    rt.round_now(CONTACT).await.expect("kick one");
    expected += 1;
    assert_eq!(bridge.send_set_invalidations(), expected, "round_now");

    rt.round_now_all().await.expect("kick all");
    expected += 1;
    assert_eq!(bridge.send_set_invalidations(), expected, "round_now_all");

    let _ = rt
        .sync_and_await(CONTACT, Duration::from_millis(1), || async { true })
        .await;
    expected += 1;
    assert_eq!(bridge.send_set_invalidations(), expected, "sync_and_await");

    let _ = rt.note_local_writes_since(chrono::Utc::now()).await;
    expected += 1;
    assert_eq!(
        bridge.send_set_invalidations(),
        expected,
        "note_local_writes_since"
    );

    let _ = rt.release_signer("some-key");
    expected += 1;
    assert_eq!(bridge.send_set_invalidations(), expected, "release_signer");

    let _ = rt.release_bound_signer(EnvelopeKind::Attestation, b"{}");
    expected += 1;
    assert_eq!(
        bridge.send_set_invalidations(),
        expected,
        "release_bound_signer"
    );

    rt.shutdown().await;
}
