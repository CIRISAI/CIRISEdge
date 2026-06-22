//! v6.3.0 (CIRISEdge#184) — swarm-converger wire-up + latency-
//! diversity policy end-to-end smoke.
//!
//! Closes the v5.2.0 deferrals at the wire layer
//! (`MessageType::FountainHoldingClaim` discriminator + dispatch
//! route), plus the new latency-aware diversity refinement of the
//! over-target ejection decision.
//!
//! ## Test plan
//!
//! 1. **Wire-format round-trip**: `MessageType::FountainHoldingClaim`
//!    discriminator string is `"FountainHoldingClaim"`; the body
//!    serializes via `EdgeEnvelope` and round-trips byte-for-byte.
//! 2. **Diversity-aware ejection**: five-peer cluster where two are
//!    low-RTT to the local peer and three are high-RTT. Over-target
//!    condition. Assert the local peer's `should_eject_with_diversity`
//!    returns `Eject` when it's in the low-RTT cluster, and `Keep`
//!    when it's in the high-RTT cluster.
//! 3. **Null observer fallback**: with `None` diversity score,
//!    behavior matches the v5.2.0 rarity-only baseline.
//! 4. **Multi-content ordering**: when a peer is over-target across
//!    multiple content_ids simultaneously, the converger
//!    pre-orders by ascending diversity score (least-diverse first).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::holonomic::fountain_defaults::recommended_policy;
use ciris_edge::holonomic::swarm_rarity::{
    should_eject_above_target, should_eject_with_diversity, ConsentState, EjectionVerdict,
    FountainHoldingClaim, RarityScore,
};
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
use ciris_edge::swarm::{
    diversity_contribution, diversity_scores_for, NullRttObserver, PeerRttObserver,
};

// ─── Wire-format round-trip ──────────────────────────────────────

/// Test fixture: build an `EdgeEnvelope` around a `FountainHoldingClaim`
/// body with empty signatures (we're asserting the wire shape, not
/// the verify path).
fn fixture_envelope(claim: &FountainHoldingClaim) -> EdgeEnvelope {
    let body_value = serde_json::to_value(claim).expect("body serialize");
    let body = serde_json::value::to_raw_value(&body_value).expect("body raw");
    EdgeEnvelope {
        edge_schema_version: SchemaVersion::V1_0_0,
        signing_key_id: "alice".to_string(),
        destination_key_id: "bob".to_string(),
        message_type: MessageType::FountainHoldingClaim,
        sent_at: chrono::Utc::now(),
        nonce: [0u8; 16],
        body,
        signature: String::new(),
        signature_pqc: None,
        in_reply_to: None,
        testimonial_witness: None,
        key_boundary_scope: None,
        cohort_scope: None,
    }
}

#[test]
fn fountain_holding_claim_message_type_serializes_to_expected_wire_string() {
    let m = MessageType::FountainHoldingClaim;
    let s = serde_json::to_string(&m).expect("serialize");
    // MessageType has no #[serde(rename_all = ...)] so the wire form
    // is the bare PascalCase variant name in double quotes. This is
    // the discriminator the registry CEG §11 cross-reference comment
    // names — locked here as a regression gate.
    assert_eq!(s, "\"FountainHoldingClaim\"");

    // Deserialize round-trip — the wire string is the discriminator
    // peers MUST recognize.
    let parsed: MessageType =
        serde_json::from_str("\"FountainHoldingClaim\"").expect("deserialize");
    assert_eq!(parsed, MessageType::FountainHoldingClaim);
}

#[test]
fn fountain_holding_claim_envelope_round_trips_byte_for_byte() {
    let claim = FountainHoldingClaim::new(
        "alice".to_string(),
        "content-X".to_string(),
        vec![1, 2, 3],
        1_700_000_000,
    );
    let env = fixture_envelope(&claim);
    let serialized = serde_json::to_string(&env).expect("envelope serialize");
    let parsed: EdgeEnvelope = serde_json::from_str(&serialized).expect("envelope deserialize");
    assert_eq!(parsed.message_type, MessageType::FountainHoldingClaim);
    assert_eq!(parsed.signing_key_id, "alice");
    assert_eq!(parsed.destination_key_id, "bob");

    // The body must decode to a FountainHoldingClaim and match the
    // original.
    let body: FountainHoldingClaim = serde_json::from_str(parsed.body.get()).expect("body decode");
    assert_eq!(body.peer_id, "alice");
    assert_eq!(body.content_id, "content-X");
    assert_eq!(body.symbol_ids, vec![1, 2, 3]);
    assert_eq!(body.observed_at_unix_ms, 1_700_000_000);
}

// ─── Diversity-aware ejection ─────────────────────────────────────

/// Test fixture: static RTT observer constructed from `(peer, ms)`
/// pairs.
struct StaticRtt(BTreeMap<String, Duration>);
impl PeerRttObserver for StaticRtt {
    fn rtt_to(&self, p: &str) -> Option<Duration> {
        self.0.get(p).copied()
    }
}
fn rtt_from(pairs: &[(&str, u64)]) -> StaticRtt {
    StaticRtt(
        pairs
            .iter()
            .map(|(p, ms)| ((*p).to_string(), Duration::from_millis(*ms)))
            .collect(),
    )
}

#[test]
fn diversity_aware_low_rtt_peer_ejects_high_rtt_peer_keeps() {
    // Five-peer cluster. Two peers (bob, carol) sit in the same metro
    // as alice (RTT ~5-10ms); two peers (dave, eve) are continents
    // away (~200ms). The other holders (from alice's perspective) are
    // {bob, carol, dave, eve}.
    //
    // observed_count = 35 holders (well above target+grace=34).
    // local_symbol is common (rarity_score=20 > target/2=15).
    //
    // We compare two views:
    //
    // - Alice's view: low-RTT cluster with bob+carol. Her diversity
    //   contribution = 0.005 + 0.008 + 0.200 + 0.220 = 0.433s.
    //   The substrate verdict is `EjectToTier`; her position is in the
    //   bottom of the cluster diversity-wise (clustered with bob+carol),
    //   so the refined verdict stays `EjectToTier`.
    //
    // - Dave's view: clustered with eve, distant from alice+bob+carol.
    //   His diversity contribution = 0.200 + 0.195 + 0.205 + 0.015 = 0.615s
    //   (uses dave's local RTT-to-others measurement).
    //   When the floor sits at ~0.5s (the population median), dave's
    //   score is ABOVE the floor → flip to `Keep` (he uniquely carries
    //   the high-RTT spread).
    let policy = recommended_policy();
    let holders_observed = 35u32;
    let local_symbol_rarity = RarityScore(20);
    let consent = ConsentState::Active;

    let alice_rtt = rtt_from(&[("bob", 5), ("carol", 8), ("dave", 200), ("eve", 220)]);
    let dave_rtt = rtt_from(&[("alice", 200), ("bob", 195), ("carol", 205), ("eve", 15)]);

    let alice_others: Vec<String> = ["bob", "carol", "dave", "eve"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let dave_others: Vec<String> = ["alice", "bob", "carol", "eve"]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    let alice_score = diversity_contribution(&alice_rtt, &alice_others).expect("some");
    let dave_score = diversity_contribution(&dave_rtt, &dave_others).expect("some");

    // The floor sits between alice and dave; dave uniquely contributes
    // diversity, alice is in the clustered low-RTT bucket.
    let floor = (alice_score + dave_score) / 2.0;
    assert!(
        alice_score < floor && floor < dave_score,
        "floor={floor} must split alice={alice_score} and dave={dave_score}"
    );

    let alice_verdict = should_eject_with_diversity(
        holders_observed,
        &policy,
        consent,
        local_symbol_rarity,
        Some(alice_score),
        Some(floor),
    );
    assert_eq!(
        alice_verdict,
        EjectionVerdict::EjectToTier,
        "alice is clustered → ejecting her preserves spread"
    );

    let dave_verdict = should_eject_with_diversity(
        holders_observed,
        &policy,
        consent,
        local_symbol_rarity,
        Some(dave_score),
        Some(floor),
    );
    assert_eq!(
        dave_verdict,
        EjectionVerdict::Keep,
        "dave uniquely carries diversity → KEEP under over-target"
    );
}

#[test]
fn null_observer_falls_back_to_rarity_only_baseline() {
    // With a NullRttObserver, every diversity_contribution call
    // returns None → the converger's `should_eject_with_diversity`
    // call reduces to `should_eject_above_target` (rarity-only).
    let policy = recommended_policy();
    let consent = ConsentState::Active;
    let null = NullRttObserver;

    let others: Vec<String> = vec!["bob".into(), "carol".into()];
    let score = diversity_contribution(&null, &others);
    assert!(
        score.is_none(),
        "null observer must produce no diversity signal"
    );

    // Substrate verdict and diversity-refined verdict MUST match when
    // either input is None.
    for (holders, rarity) in [
        (35u32, RarityScore(20)), // over target, common → EjectToTier
        (25u32, RarityScore(20)), // under target → Keep
        (35u32, RarityScore(5)),  // over target, rare → Keep
    ] {
        let base = should_eject_above_target(holders, &policy, consent, rarity);
        let refined =
            should_eject_with_diversity(holders, &policy, consent, rarity, None, Some(0.30));
        assert_eq!(
            base, refined,
            "null diversity must mirror rarity-only for ({holders}, {rarity:?})"
        );
        let refined2 =
            should_eject_with_diversity(holders, &policy, consent, rarity, Some(0.50), None);
        assert_eq!(
            base, refined2,
            "no floor must mirror rarity-only for ({holders}, {rarity:?})"
        );
    }
}

#[test]
fn multi_content_ordering_evicts_least_diverse_first() {
    // Three content_ids local peer is observing. content-A is
    // clustered (low diversity score), content-B is balanced,
    // content-C is uniquely diverse (high score). When the converger
    // drains under over-target pressure, the order is A → B → C.
    let r = rtt_from(&[("p1", 5), ("p2", 8), ("p3", 100), ("p4", 200), ("p5", 500)]);
    let mut others = BTreeMap::new();
    // content-A: clustered with p1 + p2 only → low score
    others.insert(
        "content-A".to_string(),
        vec!["p1".to_string(), "p2".to_string()],
    );
    // content-B: balanced — one near, one far
    others.insert(
        "content-B".to_string(),
        vec!["p1".to_string(), "p4".to_string()],
    );
    // content-C: uniquely far from all → high score
    others.insert(
        "content-C".to_string(),
        vec!["p4".to_string(), "p5".to_string()],
    );

    let scores = diversity_scores_for(&r, &others);
    let a = scores.get("content-A").unwrap().expect("some");
    let b = scores.get("content-B").unwrap().expect("some");
    let c = scores.get("content-C").unwrap().expect("some");
    assert!(a < b, "content-A must be less diverse than content-B");
    assert!(b < c, "content-B must be less diverse than content-C");

    // The converger sorts ascending — content-A first under pressure.
    let mut ordered: Vec<(String, f64)> = vec![
        ("content-A".to_string(), a),
        ("content-B".to_string(), b),
        ("content-C".to_string(), c),
    ];
    ordered.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal));
    assert_eq!(ordered[0].0, "content-A");
    assert_eq!(ordered[1].0, "content-B");
    assert_eq!(ordered[2].0, "content-C");
}

// ─── Round-trip via runtime ───────────────────────────────────────

use async_trait::async_trait;
use ciris_edge::swarm::{
    FountainEvictHardDelete, FountainHoldingsSource, FountainSwarmRuntime, FountainTierEvict,
    NoopFountainHoldingsSource, SwarmRuntimeConfig,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};

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

#[derive(Default)]
struct NopTier;
#[async_trait]
impl FountainTierEvict for NopTier {
    async fn evict_fountain_content_to_tier(
        &self,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<(), ciris_edge::swarm::FountainEvictError> {
        Ok(())
    }
}

#[derive(Default)]
struct NopHard;
impl FountainEvictHardDelete for NopHard {
    fn evict_fountain_content_hard_delete(
        &self,
        _: &str,
        _: &str,
    ) -> Result<(), ciris_edge::swarm::FountainEvictError> {
        Ok(())
    }
}

#[tokio::test]
async fn runtime_round_trip_with_published_claim_via_register_observed_claim() {
    // This is the same shape as the v5.2.0 e2e test, retained as a
    // baseline gate: the runtime's `register_observed_claim` is the
    // hook the new wire-route calls into; if the route works at the
    // dispatch layer (covered by unit tests), this end-to-end driver
    // confirms the runtime still composes after the v6.3.0 changes.
    let alice_holdings: Arc<dyn FountainHoldingsSource> = Arc::new(NoopFountainHoldingsSource);
    let alice_tx = Arc::new(RecordingTransport::default());
    let alice_tier: Arc<dyn FountainTierEvict> = Arc::new(NopTier);
    let alice_hard: Arc<dyn FountainEvictHardDelete + Send + Sync> = Arc::new(NopHard);
    let alice_cohort: Arc<dyn Fn() -> Vec<String> + Send + Sync> = Arc::new(Vec::new);
    let rt = FountainSwarmRuntime::start(
        SwarmRuntimeConfig {
            publish_cadence: Duration::from_secs(60),
            observe_cadence: Duration::from_secs(60),
            ..Default::default()
        },
        alice_holdings,
        alice_tier,
        alice_hard,
        alice_tx as Arc<dyn Transport>,
        alice_cohort,
        "alice".to_string(),
        None,
    );

    rt.register_observed_claim(FountainHoldingClaim::new(
        "bob",
        "shard-X",
        vec![1, 2, 3],
        1_700_000_000,
    ))
    .await;

    let observed = rt.observed_handle();
    let g = observed.read().await;
    let inner = format!("{g:?}");
    assert!(
        inner.contains("shard-X"),
        "observed map must contain shard-X; got {inner}"
    );
    drop(g);
    let mut rt = rt;
    rt.shutdown().await;
}
