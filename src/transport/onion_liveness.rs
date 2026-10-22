//! CC 5.4.6 item 4 (steward, 2026-10-22) — **the liveness fold**: the
//! per-node, counts-only answer to "is the tier available NOW", beside the
//! fold-determined deal that answers "who is in each layer this period".
//!
//! The deal ([`super::onion_layers::deal_layers`]) reads slow fold facts; a
//! relay that went to sleep ten minutes ago still satisfies every one of
//! them. Availability therefore needs a second input, measured by this node
//! about the relays the deal gave it: for each dealt relay, the age of the
//! newest *verified* evidence that it answers (a completed shaped-link
//! handshake to it, a route answer, a forwarded onion packet acknowledged by
//! the next hop, a self-addressed probe that came back). The fold follows
//! [`crate::holonomic::converged_view`]: numbers only, never an identity; an
//! unread or unarmed plane is *unknown*, never zero.
//!
//! `available = the deal's floor ∧ ≥ MIN_ANSWERING relays per layer with
//! evidence younger than the window`. The deal is identical on every node
//! (a function of the fold); this answer is this node's own and MAY differ
//! between nodes. That is the property split the steward ruled: the deal
//! must not depend on local observation, the availability answer may.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::onion_layers::{LayerDeal, LAYERS, LAYER_FLOOR};

/// How many relays per layer must have answered within the window for the
/// tier to be available on this node (CC 5.4.6 item 4, "≥ 3 answering").
pub const MIN_ANSWERING: usize = LAYER_FLOOR;
/// Default evidence window: one rendezvous period.
pub const DEFAULT_LIVENESS_WINDOW: Duration = Duration::from_secs(3600);

/// What proved a relay answers. Each is an event this node already observes
/// on its own links; none is a wire-supplied claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LivenessEvidence {
    /// A shaped link to the relay completed its handshake and shaping offer.
    ShapedLinkUp,
    /// The relay answered a pre-seal route request (`CTKA`).
    RouteAnswered,
    /// A packet this node sent through the relay was acknowledged by the hop after it.
    ForwardAcknowledged,
    /// A self-addressed probe through the relay came back.
    ProbeReturned,
}

/// One layer's liveness, counts only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayerLiveness {
    /// Relays the deal put in this layer.
    pub dealt: usize,
    /// Of those, relays with evidence younger than the window.
    pub answering: usize,
    /// Age of the newest evidence among the layer's relays, if any.
    pub newest_evidence_age: Option<Duration>,
}

/// The availability answer for one period on one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Availability {
    /// The period the deal was computed for.
    pub period: u64,
    /// The deal's own floor (fold-determined, identical on every node).
    pub floor_holds: bool,
    /// Per layer, dealt and answering (this node's own measurement).
    pub layers: [LayerLiveness; LAYERS],
    /// `floor_holds ∧ every layer has ≥ MIN_ANSWERING answering`.
    pub available: bool,
    /// Why not, by name, when unavailable.
    pub reason: Option<&'static str>,
}

/// The liveness ledger: per relay key id, the newest evidence and its
/// instant. Key ids live only inside this map as keys; nothing returns them.
#[derive(Debug, Default)]
pub struct LivenessFold {
    newest: HashMap<String, (LivenessEvidence, Instant)>,
}

impl LivenessFold {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record evidence about `relay` at `at` (the newest wins).
    pub fn observe_at(&mut self, relay: &str, kind: LivenessEvidence, at: Instant) {
        match self.newest.get(relay) {
            Some((_, prev)) if *prev >= at => {}
            _ => {
                self.newest.insert(relay.to_owned(), (kind, at));
            }
        }
    }

    /// Record evidence now.
    pub fn observe(&mut self, relay: &str, kind: LivenessEvidence) {
        self.observe_at(relay, kind, Instant::now());
    }

    /// Drop evidence older than `window` (bounds the ledger).
    pub fn prune(&mut self, now: Instant, window: Duration) {
        self.newest
            .retain(|_, (_, at)| now.saturating_duration_since(*at) <= window);
    }

    /// Relays with any evidence (for the ledger's size).
    #[must_use]
    pub fn len(&self) -> usize {
        self.newest.len()
    }

    /// Whether the ledger is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.newest.is_empty()
    }

    /// The availability answer at `now` for `deal`, with evidence younger
    /// than `window` counting as answering.
    #[must_use]
    pub fn availability_at(
        &self,
        deal: &LayerDeal,
        now: Instant,
        window: Duration,
    ) -> Availability {
        let mut layers = [LayerLiveness::default(); LAYERS];
        for (l, members) in deal.layers.iter().enumerate() {
            let mut answering = 0usize;
            let mut newest: Option<Duration> = None;
            for key in members {
                if let Some((_, at)) = self.newest.get(key) {
                    let age = now.saturating_duration_since(*at);
                    if age <= window {
                        answering += 1;
                    }
                    newest = Some(newest.map_or(age, |n| n.min(age)));
                }
            }
            layers[l] = LayerLiveness {
                dealt: members.len(),
                answering,
                newest_evidence_age: newest,
            };
        }
        let answering_ok = layers.iter().all(|l| l.answering >= MIN_ANSWERING);
        let available = deal.available && answering_ok;
        let reason = if available {
            None
        } else if !deal.available {
            Some("onion_tier_unavailable_floor")
        } else {
            Some("onion_tier_unavailable_liveness")
        };
        Availability {
            period: deal.period,
            floor_holds: deal.available,
            layers,
            available,
            reason,
        }
    }

    /// [`Self::availability_at`] now, over the default window.
    #[must_use]
    pub fn availability(&self, deal: &LayerDeal) -> Availability {
        self.availability_at(deal, Instant::now(), DEFAULT_LIVENESS_WINDOW)
    }
}

#[cfg(test)]
mod tests {
    use super::super::onion_layers::{deal_layers, RelayCandidate};
    use super::*;

    fn node(id: &str, seat: bool) -> RelayCandidate {
        RelayCandidate {
            key_id: id.to_owned(),
            is_seat: seat,
            relay_standing: false,
            row_live: true,
            announced: true,
            hop_key_valid: true,
            opted_out: false,
            owner_bound_under_bundle_root: true,
        }
    }

    fn nine() -> Vec<RelayCandidate> {
        let mut v: Vec<_> = (0..3).map(|i| node(&format!("seat{i}"), true)).collect();
        v.extend((0..6).map(|i| node(&format!("n{i}"), false)));
        v
    }

    /// Availability is the floor AND three answering per layer; the floor
    /// alone is not enough, and a layer with two answering names liveness.
    #[test]
    fn available_needs_the_floor_and_three_answering_per_layer() {
        let deal = deal_layers(&nine(), 3, 2);
        assert!(deal.available);
        let now = Instant::now();
        let mut fold = LivenessFold::new();
        let a = fold.availability_at(&deal, now, Duration::from_secs(600));
        assert!(!a.available);
        assert_eq!(a.reason, Some("onion_tier_unavailable_liveness"));
        assert!(a.floor_holds);
        for l in deal.layers.iter().flatten() {
            fold.observe_at(l, LivenessEvidence::ShapedLinkUp, now);
        }
        let a = fold.availability_at(&deal, now, Duration::from_secs(600));
        assert!(a.available, "{a:?}");
        assert!(a.layers.iter().all(|l| l.dealt == 3 && l.answering == 3));
        // One relay in layer 0 goes quiet past the window: liveness fails there.
        let quiet = deal.layers[0][0].clone();
        let stale = now
            .checked_sub(Duration::from_secs(700))
            .expect("the test clock is past its first 700 s");
        let mut fold2 = LivenessFold::new();
        for l in deal.layers.iter().flatten() {
            let at = if *l == quiet { stale } else { now };
            fold2.observe_at(l, LivenessEvidence::ShapedLinkUp, at);
        }
        let a = fold2.availability_at(&deal, now, Duration::from_secs(600));
        assert!(!a.available);
        assert_eq!(a.layers[0].answering, 2);
        assert_eq!(a.reason, Some("onion_tier_unavailable_liveness"));
    }

    /// The floor's name wins when the deal itself is thin.
    #[test]
    fn a_thin_deal_names_the_floor() {
        let deal = deal_layers(&nine()[..4], 3, 2);
        assert!(!deal.available);
        let now = Instant::now();
        let mut fold = LivenessFold::new();
        for l in deal.layers.iter().flatten() {
            fold.observe_at(l, LivenessEvidence::RouteAnswered, now);
        }
        let a = fold.availability_at(&deal, now, Duration::from_secs(600));
        assert!(!a.available);
        assert_eq!(a.reason, Some("onion_tier_unavailable_floor"));
    }

    /// The property split: two nodes with the same rows deal the same layers
    /// and may still answer availability differently, each from its own
    /// evidence; the ledger prunes and never returns an identity.
    #[test]
    fn same_deal_different_liveness_is_allowed_and_counts_only() {
        let rows = nine();
        let mut shuffled = rows.clone();
        shuffled.reverse();
        let d1 = deal_layers(&rows, 9, 2);
        let d2 = deal_layers(&shuffled, 9, 2);
        assert_eq!(d1, d2);
        let now = Instant::now();
        let mut fold_a = LivenessFold::new();
        let fold_b = LivenessFold::new();
        for l in d1.layers.iter().flatten() {
            fold_a.observe_at(l, LivenessEvidence::ForwardAcknowledged, now);
        }
        assert!(
            fold_a
                .availability_at(&d1, now, Duration::from_secs(60))
                .available
        );
        assert!(
            !fold_b
                .availability_at(&d2, now, Duration::from_secs(60))
                .available
        );
        fold_a.prune(now + Duration::from_secs(120), Duration::from_secs(60));
        assert!(fold_a.is_empty());
        let dbg = format!(
            "{:?}",
            fold_b.availability_at(&d2, now, Duration::from_secs(60))
        );
        assert!(
            !dbg.contains("seat0") && !dbg.contains("n0"),
            "counts only: {dbg}"
        );
    }
}
