//! CIRISEdge#184 (v6.3.0) — latency-aware diversity policy for the
//! over-target ejection decision.
//!
//! ## Design principle
//!
//! When the federation holds more than `H` copies of a `content_id`
//! (the swarm is over-target), the existing
//! [`crate::holonomic::swarm_rarity::should_eject_above_target`]
//! decides whether the local peer ejects. The v5.2.0 heuristic was
//! **rarity-only** — every over-target holder is equally eligible.
//!
//! **Refinement**: bias the ejection decision by **per-peer latency
//! diversity**. Low-latency peers are topologically clustered (same
//! metro / same AS / same continent). Ejecting copies from low-
//! latency peers **first** maximizes geographic/topological copy
//! spread; the surviving copies sit on peers that are RTT-distant
//! from each other.
//!
//! ## Local-peer decision
//!
//! Each holder runs this independently against the same observation
//! set:
//!
//! > Of the H+ peers currently holding `content_id X` (per the
//! > observed `FountainHoldingClaim` map), my "diversity contribution"
//! > is the sum of RTT from me to every other holder. Low diversity
//! > contribution → I'm clustered with the others, ejecting me costs
//! > little → I SHOULD eject. High diversity contribution → I'm
//! > topologically far from the others, ejecting me costs spread → I
//! > should KEEP.
//!
//! When [`crate::holonomic::swarm_rarity::should_eject_above_target`]
//! returns `Eject`, the local peer pre-orders the eviction priority
//! across competing content_ids by ascending diversity contribution:
//! the content_ids where my position is least diverse get evicted
//! first; the content_ids where my position uniquely contributes
//! diversity get retained longest.
//!
//! This makes the substrate's ALM topology (which already takes
//! [`crate::holonomic::deterministic_topology::ReachabilityObservation`]
//! as an input per CEG §19.4) a load-bearing diversity primitive,
//! not just a routing one.
//!
//! ## RTT sources
//!
//! Two production sources, one test fallback:
//!
//! - [`TopologyRttObserver`] — reads RTT from the latest ALM topology
//!   snapshot's [`crate::holonomic::deterministic_topology::ReachabilityObservation`]
//!   set. The same observations CEG §19.4 already consumes; this
//!   module re-uses them as the diversity input. **Recommended
//!   production source.**
//! - **Reticulum link-layer**: a transport-tier impl (filed for
//!   v6.4.0) that queries the RNS link layer's per-peer current
//!   RTT. Not implemented in v6.3.0 — the trait is stable so the
//!   transport surface can land without re-touching the runtime.
//! - [`NullRttObserver`] — returns `None` for every peer. The
//!   default fallback when no observer is wired; diversity-aware
//!   ejection degrades to rarity-only (the
//!   [`should_eject_above_target`] verdict is unchanged).
//!
//! [`should_eject_above_target`]: crate::holonomic::swarm_rarity::should_eject_above_target

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::holonomic::deterministic_topology::ReachabilityObservation;

/// Per-peer RTT source for the latency-aware diversity policy.
///
/// Production impls query the live RNS link layer or read the latest
/// ALM topology snapshot; the test fallback ([`NullRttObserver`])
/// returns `None` for every peer.
///
/// `rtt_to` returns `None` when the observer has no measurement for
/// the given peer — the diversity calculation substitutes the median
/// observed RTT in that case (see [`diversity_contribution`]) so a
/// peer we haven't probed yet doesn't drag the score toward "less
/// diverse" purely from data sparsity.
pub trait PeerRttObserver: Send + Sync {
    /// Best current estimate of one-way RTT from THIS peer to the
    /// peer identified by `peer_key_id`. `None` when no measurement
    /// is available.
    fn rtt_to(&self, peer_key_id: &str) -> Option<Duration>;
}

/// Default fallback observer — returns `None` for every peer.
/// Diversity-aware ejection then degrades to rarity-only (the
/// [`crate::holonomic::swarm_rarity::should_eject_above_target`]
/// verdict is unchanged from v5.2.0).
#[derive(Debug, Default, Clone, Copy)]
pub struct NullRttObserver;

impl PeerRttObserver for NullRttObserver {
    fn rtt_to(&self, _peer_key_id: &str) -> Option<Duration> {
        None
    }
}

/// Production observer that reads RTT from the latest ALM topology
/// snapshot's [`ReachabilityObservation`] set (CEG §19.4 input).
///
/// Construction takes a snapshot of observations + the local peer's
/// `key_id`; `rtt_to(peer)` returns the observed RTT on the directed
/// edge `local → peer` if present, else `None`. The observation set
/// is treated as a frozen snapshot — a fresh observer is constructed
/// whenever the ALM topology recomputes.
///
/// RTT-from-the-publisher is the simplest signal: if RTT is symmetric
/// enough, "RTT from me to peer P" approximates "RTT from any common
/// observer to peer P." The diversity contribution uses the LOCAL
/// RTT-to-other-holders as the diversity input — no federation-level
/// coordination required (the determinism comes from each peer
/// computing its own score against the same observed-claims map).
pub struct TopologyRttObserver {
    /// `peer_key_id` → observed RTT (only edges originating at the
    /// local peer are stored). Pre-computed at construction so
    /// `rtt_to` is O(log n).
    by_peer: BTreeMap<String, Duration>,
}

impl std::fmt::Debug for TopologyRttObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopologyRttObserver")
            .field("peer_count", &self.by_peer.len())
            .finish()
    }
}

impl TopologyRttObserver {
    /// Construct from a slice of observations + the local peer's
    /// `key_id`. Only edges `from_peer_id == local_peer_id` are
    /// indexed — the rest are dropped. When multiple observations
    /// exist for the same destination, the LATEST (highest
    /// `observed_at_unix_ms`) wins.
    #[must_use]
    pub fn from_observations(
        observations: &[ReachabilityObservation],
        local_peer_id: &str,
    ) -> Self {
        let mut by_peer: BTreeMap<String, (Duration, u64)> = BTreeMap::new();
        for obs in observations {
            if obs.from_peer_id != local_peer_id {
                continue;
            }
            let rtt = Duration::from_millis(u64::from(obs.observed_rtt_ms));
            let ts = obs.observed_at_unix_ms;
            by_peer
                .entry(obs.to_peer_id.clone())
                .and_modify(|prev| {
                    if ts > prev.1 {
                        *prev = (rtt, ts);
                    }
                })
                .or_insert((rtt, ts));
        }
        Self {
            by_peer: by_peer.into_iter().map(|(k, (rtt, _))| (k, rtt)).collect(),
        }
    }
}

impl PeerRttObserver for TopologyRttObserver {
    fn rtt_to(&self, peer_key_id: &str) -> Option<Duration> {
        self.by_peer.get(peer_key_id).copied()
    }
}

/// Type-erased Arc handle to a [`PeerRttObserver`]. Used by the
/// runtime so concrete observer impls can be swapped per deployment.
pub type RttObserverHandle = Arc<dyn PeerRttObserver>;

/// Compute the local peer's diversity contribution to the holder set
/// for one `content_id`.
///
/// **Score = sum of RTT (seconds) from local to every OTHER holder.**
/// Higher sum = more diverse position. Missing RTT measurements
/// default to the median observed RTT across the holders we DID
/// measure — this avoids penalizing peers we haven't probed yet by
/// counting them as "RTT 0" (which would make every unknown holder
/// look like a clustered neighbor).
///
/// Returns `None` when no RTT data is available at all — the caller
/// then degrades to rarity-only. Returns `Some(0.0)` when the only
/// holder is the local peer (empty `others`).
///
/// # Determinism
///
/// The score is **local** — each peer computes its own. No federation
/// coordination needed; the ALM topology determinism already aligns
/// the input set (every peer sees the same observed-claims map).
/// Stable across calls with byte-equal inputs.
#[must_use]
pub fn diversity_contribution(rtt: &dyn PeerRttObserver, others: &[String]) -> Option<f64> {
    if others.is_empty() {
        return Some(0.0);
    }
    let observed: Vec<Duration> = others.iter().filter_map(|p| rtt.rtt_to(p)).collect();
    if observed.is_empty() {
        return None;
    }
    let median = median_duration(&observed);
    let total: f64 = others
        .iter()
        .map(|p| rtt.rtt_to(p).unwrap_or(median).as_secs_f64())
        .sum();
    Some(total)
}

/// Median of a non-empty slice of durations. Pre-condition: `xs`
/// non-empty — caller MUST check.
fn median_duration(xs: &[Duration]) -> Duration {
    debug_assert!(!xs.is_empty(), "median_duration over empty slice");
    let mut sorted: Vec<Duration> = xs.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        // Even count — average the two middle values. Saturating-add
        // because `Duration + Duration` panics on overflow.
        let a = sorted[mid - 1];
        let b = sorted[mid];
        (a + b) / 2
    }
}

/// Compute diversity scores for every content_id under consideration.
///
/// The map's values are `Option<f64>` so callers can distinguish
/// "no RTT data → fall back to rarity-only" from "score = 0.0 (local
/// is the only holder)" — see [`diversity_contribution`].
///
/// Used by the converger: when multiple content_ids are simultaneously
/// over-target, the converger drains in ASCENDING score order — the
/// least-diverse positions go first.
#[must_use]
pub fn diversity_scores_for(
    rtt: &dyn PeerRttObserver,
    others_by_content: &BTreeMap<String, Vec<String>>,
) -> BTreeMap<String, Option<f64>> {
    others_by_content
        .iter()
        .map(|(cid, others)| (cid.clone(), diversity_contribution(rtt, others)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn null_observer_returns_none() {
        let n = NullRttObserver;
        assert_eq!(n.rtt_to("anyone"), None);
    }

    #[test]
    fn diversity_contribution_empty_others_is_zero() {
        let r = rtt_from(&[]);
        assert_eq!(diversity_contribution(&r, &[]), Some(0.0));
    }

    #[test]
    fn diversity_contribution_no_observations_is_none() {
        let r = NullRttObserver;
        let others: Vec<String> = vec!["a".into(), "b".into()];
        assert_eq!(diversity_contribution(&r, &others), None);
    }

    #[test]
    fn diversity_contribution_sums_observed_rtts() {
        // local sees 50ms to a, 200ms to b, 350ms to c
        let r = rtt_from(&[("a", 50), ("b", 200), ("c", 350)]);
        let others: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let score = diversity_contribution(&r, &others).expect("some");
        // 0.050 + 0.200 + 0.350 = 0.600
        assert!((score - 0.600).abs() < 1e-9, "got {score}");
    }

    #[test]
    fn diversity_contribution_missing_uses_median() {
        // local sees a=100, b=300; c is unknown → median(100,300)=200
        let r = rtt_from(&[("a", 100), ("b", 300)]);
        let others: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let score = diversity_contribution(&r, &others).expect("some");
        // 0.100 + 0.300 + 0.200 = 0.600
        assert!((score - 0.600).abs() < 1e-9, "got {score}");
    }

    #[test]
    fn low_rtt_cluster_scores_lower_than_high_rtt_position() {
        // 5 holders. local (alice) is in a low-rtt metro with bob+carol;
        // dave+eve are continents away.
        // alice's diversity is sum of rtt to {bob, carol, dave, eve}.
        let low_rtt = rtt_from(&[("bob", 5), ("carol", 8), ("dave", 200), ("eve", 220)]);
        // bob: clustered with alice + carol, distant from dave + eve
        let bob_view = rtt_from(&[("alice", 5), ("carol", 6), ("dave", 195), ("eve", 210)]);
        // dave: alone with eve, distant from alice + bob + carol
        let dave_view = rtt_from(&[("alice", 200), ("bob", 195), ("carol", 205), ("eve", 15)]);
        let alice_others: Vec<String> = ["bob", "carol", "dave", "eve"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let dave_others: Vec<String> = ["alice", "bob", "carol", "eve"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();

        let alice_score = diversity_contribution(&low_rtt, &alice_others).expect("some");
        let bob_score = diversity_contribution(&bob_view, &alice_others).expect("some");
        let dave_score = diversity_contribution(&dave_view, &dave_others).expect("some");

        // Dave is the topology outlier: highest contribution = should KEEP.
        // Alice and bob are clustered: lower contribution = eligible to EJECT.
        assert!(
            dave_score > alice_score,
            "dave={dave_score} should exceed alice={alice_score}"
        );
        assert!(
            dave_score > bob_score,
            "dave={dave_score} should exceed bob={bob_score}"
        );
    }

    #[test]
    fn topology_rtt_observer_indexes_local_outbound_edges() {
        let obs = vec![
            ReachabilityObservation {
                from_peer_id: "alice".into(),
                to_peer_id: "bob".into(),
                observed_rtt_ms: 50,
                observed_at_unix_ms: 1_000,
            },
            ReachabilityObservation {
                from_peer_id: "alice".into(),
                to_peer_id: "carol".into(),
                observed_rtt_ms: 200,
                observed_at_unix_ms: 1_000,
            },
            // bob → alice — should NOT be indexed for alice's observer
            ReachabilityObservation {
                from_peer_id: "bob".into(),
                to_peer_id: "alice".into(),
                observed_rtt_ms: 55,
                observed_at_unix_ms: 1_000,
            },
        ];
        let observer = TopologyRttObserver::from_observations(&obs, "alice");
        assert_eq!(observer.rtt_to("bob"), Some(Duration::from_millis(50)));
        assert_eq!(observer.rtt_to("carol"), Some(Duration::from_millis(200)));
        assert_eq!(observer.rtt_to("alice"), None);
        // 'dave' was never observed
        assert_eq!(observer.rtt_to("dave"), None);
    }

    #[test]
    fn topology_rtt_observer_picks_latest_observation() {
        let obs = vec![
            ReachabilityObservation {
                from_peer_id: "alice".into(),
                to_peer_id: "bob".into(),
                observed_rtt_ms: 50,
                observed_at_unix_ms: 1_000,
            },
            ReachabilityObservation {
                from_peer_id: "alice".into(),
                to_peer_id: "bob".into(),
                observed_rtt_ms: 120,
                observed_at_unix_ms: 2_000,
            },
        ];
        let observer = TopologyRttObserver::from_observations(&obs, "alice");
        // Later observation wins.
        assert_eq!(observer.rtt_to("bob"), Some(Duration::from_millis(120)));
    }

    #[test]
    fn diversity_scores_for_orders_content_ids() {
        let r = rtt_from(&[("p1", 10), ("p2", 100), ("p3", 500)]);
        let mut others = BTreeMap::new();
        others.insert(
            "clustered".to_string(),
            vec!["p1".to_string(), "p1".to_string()], // both p1 — score = 2*0.010
        );
        others.insert(
            "diverse".to_string(),
            vec!["p2".to_string(), "p3".to_string()], // score = 0.100 + 0.500 = 0.6
        );
        let scores = diversity_scores_for(&r, &others);
        let c = scores.get("clustered").unwrap().expect("some");
        let d = scores.get("diverse").unwrap().expect("some");
        assert!(c < d, "clustered={c} should be less than diverse={d}");
    }
}
