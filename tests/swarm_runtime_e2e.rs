//! v5.2.0 (CIRISEdge#143) — end-to-end swarm-runtime smoke.
//!
//! Two peers (alice + bob); alice publishes a fountain holding claim
//! and bob observes it via [`FountainSwarmRuntime::register_observed_claim`].
//! Asserts:
//!
//! 1. Alice's publisher fires a `send` to the cohort.
//! 2. Bob's converger ticks and observes the claim in the map.
//! 3. The runtime shuts down cleanly.
//!
//! The wire shape between peers is currently
//! `FountainHoldingClaim::canonical_bytes` — the substrate's domain-
//! tagged bytes. A future cut adds a wire-tier
//! `MessageType::FountainHoldingClaim` discriminator and re-uses
//! `dispatch_inbound`'s verify path; for v5.2.0 the integration test
//! drives `register_observed_claim` directly, simulating what the
//! verify-path-aware dispatch hook will do.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use ciris_edge::holonomic::swarm_rarity::FountainHoldingClaim;
use ciris_edge::swarm::{
    FountainHoldingsSource, FountainSwarmRuntime, HeldFountainContent, NoopFountainHoldingsSource,
    SwarmRuntimeConfig,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::MemoryBackend;

#[derive(Default)]
struct RecordingTransport {
    sends: std::sync::Mutex<Vec<(String, Vec<u8>)>>,
}
#[async_trait]
impl Transport for RecordingTransport {
    fn id(&self) -> TransportId {
        TransportId::HTTP
    }
    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        self.sends
            .lock()
            .unwrap()
            .push((destination_key_id.to_string(), envelope_bytes.to_vec()));
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError> {
        unimplemented!("e2e doesn't drive listen")
    }
}

struct VecHoldings(Vec<HeldFountainContent>);
#[async_trait]
impl FountainHoldingsSource for VecHoldings {
    async fn list_held_fountain_content(
        &self,
    ) -> Result<Vec<HeldFountainContent>, ciris_edge::swarm::FountainEvictError> {
        Ok(self.0.clone())
    }
}

#[tokio::test]
async fn two_peer_publish_and_observe_roundtrip() {
    // Alice — has held content. Publishes claims; bob is the cohort.
    let alice_holdings: Arc<dyn FountainHoldingsSource> =
        Arc::new(VecHoldings(vec![HeldFountainContent {
            content_id: "shard-X".into(),
            corpus_kind: "fountain-corpus".into(),
            symbol_ids: vec![1, 2, 3],
        }]));
    let alice_tx = Arc::new(RecordingTransport::default());
    // v7.0.0 (CIRISEdge#194): the v5.2.0 `FountainTierEvict` +
    // `FountainEvictHardDelete` adapter args collapse onto persist
    // v10.0.0's `FederationDirectory` (#270). MemoryBackend's evict
    // methods are no-ops on unknown content (`Ok(0)`), exactly the
    // shape this smoke test needs.
    let alice_directory: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
    let alice_cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> =
        Arc::new(|| vec!["bob".to_string()]);
    let mut alice = FountainSwarmRuntime::start(
        SwarmRuntimeConfig {
            publish_cadence: Duration::from_millis(20),
            observe_cadence: Duration::from_millis(50),
            ..Default::default()
        },
        alice_holdings,
        alice_directory,
        alice_tx.clone() as Arc<dyn Transport>,
        alice_cohort,
        "alice".to_string(),
        None,
    );

    // Bob — no held content; observes alice's claim. Cohort is
    // empty (bob is the listener, not the publisher).
    let bob_holdings: Arc<dyn FountainHoldingsSource> = Arc::new(NoopFountainHoldingsSource);
    let bob_tx: Arc<dyn Transport> = Arc::new(RecordingTransport::default());
    let bob_directory: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
    let bob_cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
    let mut bob = FountainSwarmRuntime::start(
        SwarmRuntimeConfig {
            publish_cadence: Duration::from_millis(20),
            observe_cadence: Duration::from_millis(20),
            ..Default::default()
        },
        bob_holdings,
        bob_directory,
        bob_tx,
        bob_cohort,
        "bob".to_string(),
        None,
    );

    // Let alice publish at least once.
    tokio::time::sleep(Duration::from_millis(80)).await;

    let alice_sends = alice_tx.sends.lock().unwrap().clone();
    assert!(
        alice_sends.iter().any(|(dst, _)| dst == "bob"),
        "alice's publisher must have shipped at least one envelope to bob; got {alice_sends:?}"
    );

    // Simulate the inbound dispatch path: bob's edge would call
    // `register_observed_claim` on the verified body. We do that
    // directly here (the wire-level MessageType wiring lands in a
    // follow-up cut once the discriminator is approved).
    bob.register_observed_claim(FountainHoldingClaim::new(
        "alice",
        "shard-X",
        vec![1, 2, 3],
        1_700_000_000,
    ))
    .await;

    // Let bob's converger run.
    tokio::time::sleep(Duration::from_millis(80)).await;

    let observed = bob.observed_handle();
    let g = observed.read().await;
    let inner = format!("{g:?}");
    assert!(
        inner.contains("shard-X"),
        "bob's observed map must contain shard-X; got {inner}"
    );
    drop(g);

    alice.shutdown().await;
    bob.shutdown().await;
}
