//! The transport relay tier (`FSD/CIRIS_MESH.md` §1, §3, §4; ALM stage 2).
//!
//! **Roster relays before the canonical.** A link to a peer that cannot be
//! direct rides a relayed path. leviculum's path table holds ONE next hop per
//! destination, chosen by hop count and announce recency, so left alone the
//! canonical (the transport node every NAT'd node dials out to) wins the
//! announce race and carries everyone (§2.2). With leviculum v0.33's relay
//! table (leviculum#91: every relay a destination was heard through) edge
//! chooses instead:
//!
//! 1. **direct** if a one-hop path exists (R1; the punch is `direct_path`);
//! 2. **a roster relay**: a relay the destination was heard through whose
//!    node shares a room with this node or is a consented contact (the same
//!    standing a direct link needs, `direct_standing`), tried in R2 order —
//!    fewest hops, then a seeded draw among equals so diallers spread
//!    instead of herding onto one relay — each with ONE establish attempt
//!    (`connect_via` with a budget: edge owns the failover);
//! 3. **the canonical last**: the default path-table dial, exactly as before.
//!
//! The roster tier is a separate tier, never scored against the canonical
//! (R2). Relays the destination was heard through that are neither roster
//! nor the default path are not eligible (E1/E2: a relay sees the pair's
//! traffic metadata, so only a party already consented to may carry it).
//!
//! **A relay's C2 admission** ([`ForwardAdmission`], leviculum#93): the rule
//! leviculum consults, under its node lock, for every link request this node
//! would forward for others. It answers from its own ledger only (it never
//! calls into the node): admit (with per-link byte and packet token buckets
//! when configured) while the forwarded-link count is within `commit_fraction`
//! of the measured or configured capacity, refuse beyond it, and refuse every
//! new link at service tier ≥ 1 (§7.2 Admit-close) except to destinations
//! exempted as never-shed (L-A3). A background refresh reads
//! `forwarded_links()` once a second, retires closed links from the ledger and
//! measures the forwarded rates (the `load_ledger`'s transit entries and the
//! ladder's `edge:transit_pps` signal).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Mutex;

use leviculum_core::forward_meter::{ForwardDecision, ForwardRequest, ForwardedLink};
use leviculum_core::relay_routes::RelayRoute;

use crate::load_ladder::ServiceTier;
use crate::transport::realtime_av_alm::controller::{JitterSource, SplitMix64};

/// One roster relay a destination was heard through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidate {
    /// The relay's transport id.
    pub relay: [u8; 16],
    /// The interface it was heard on.
    pub interface_index: usize,
    /// Hops to the destination through it.
    pub hops: u8,
    /// The relay node's key id (a roster member or consented contact).
    pub key_id: String,
}

/// **R2 order.** The roster relays among `routes`, fewest hops first and a
/// seeded draw among equal hops (herd resistance: diallers with the same
/// view spread over equivalent relays). `roster_key` maps a relay's
/// transport id to its key id when it is eligible (shares a room or is a
/// consented contact), `None` otherwise; ineligible relays are dropped. The
/// default path (the canonical) is NOT in the result: it is the last tier,
/// taken by the caller's plain dial when this list is exhausted.
pub fn roster_relays_first(
    routes: &[RelayRoute],
    roster_key: impl Fn(&[u8; 16]) -> Option<String>,
    seed: u64,
) -> Vec<RelayCandidate> {
    let mut rng = SplitMix64(seed);
    let mut v: Vec<(u8, u64, RelayCandidate)> = routes
        .iter()
        .filter_map(|r| {
            roster_key(&r.relay).map(|key_id| {
                (
                    r.hops,
                    rng.next_u64(),
                    RelayCandidate {
                        relay: r.relay,
                        interface_index: r.interface_index,
                        hops: r.hops,
                        key_id,
                    },
                )
            })
        })
        .collect();
    v.sort_by_key(|(h, draw, _)| (*h, *draw));
    let mut seen = HashSet::new();
    v.into_iter()
        .filter(|(_, _, c)| seen.insert(c.relay))
        .map(|(_, _, c)| c)
        .collect()
}

/// A transport node's forwarding admission knobs.
#[derive(Debug, Clone, PartialEq)]
pub struct ForwardAdmissionConfig {
    /// Per-link payload byte cap each way (`None`: uncapped).
    pub per_link_bytes_per_s: Option<u32>,
    /// Per-link packet cap each way (`None`: uncapped).
    pub per_link_packets_per_s: Option<u32>,
    /// Forwarding capacity in packets/s (configured; `None`: unknown).
    pub capacity_pps: Option<u64>,
    /// Most forwarded links at once (`None`: unbounded).
    pub max_links: Option<usize>,
    /// The commitment ceiling against capacity (C2: 0.65).
    pub commit_fraction: f64,
    /// Close admission to new forwarded links at service tier ≥ 1.
    pub admit_close_on_tier: bool,
}

impl Default for ForwardAdmissionConfig {
    fn default() -> Self {
        Self {
            per_link_bytes_per_s: None,
            per_link_packets_per_s: None,
            capacity_pps: None,
            max_links: None,
            commit_fraction: 0.65,
            admit_close_on_tier: true,
        }
    }
}

/// What the forwarding admission counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardCounts {
    /// Links admitted.
    pub admitted: u64,
    /// Refused: over capacity (`relay_capacity`).
    pub refused_capacity: u64,
    /// Refused: admission closed by the service tier (`load_refuse:admit_closed`).
    pub refused_closed: u64,
    /// Forwarded links in the ledger now.
    pub live: u64,
}

/// One forwarded link's measured cost (a `load_ledger` transit entry).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ForwardCost {
    /// The link.
    pub link_id: [u8; 16],
    /// Payload bits/s, both directions.
    pub bps: f64,
    /// Packets/s, both directions.
    pub pps: f64,
}

/// The forwarded load at one refresh.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ForwardLoad {
    /// Total packets/s forwarded.
    pub pps: f64,
    /// Total bits/s forwarded.
    pub bps: f64,
    /// `pps ÷ capacity_pps` (0 when capacity is unknown): the ladder's
    /// `edge:transit_pps` input.
    pub pps_ratio: f64,
    /// The costliest links, most packets/s first.
    pub top: Vec<ForwardCost>,
}

#[derive(Debug, Default)]
struct FwdState {
    tier: ServiceTier,
    live: BTreeMap<[u8; 16], u64>,
    order: u64,
    exempt: HashSet<[u8; 16]>,
    last: HashMap<[u8; 16], (u64, u64, u64)>,
    counts: ForwardCounts,
}

/// C2 for the links this node forwards for others (see the module docs).
#[derive(Debug)]
pub struct ForwardAdmission {
    cfg: ForwardAdmissionConfig,
    state: Mutex<FwdState>,
}

/// How many costliest links a refresh reports.
pub const TOP_N: usize = 10;

impl ForwardAdmission {
    /// A fresh admission at tier 0.
    #[must_use]
    pub fn new(cfg: ForwardAdmissionConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(FwdState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FwdState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The service tier (Admit-close at ≥ 1).
    pub fn set_tier(&self, tier: ServiceTier) {
        self.lock().tier = tier;
    }

    /// Never refuse links to `destination` (L-A3: own devices, owner).
    pub fn exempt_destination(&self, destination: [u8; 16]) {
        self.lock().exempt.insert(destination);
    }

    /// The counters.
    #[must_use]
    pub fn counts(&self) -> ForwardCounts {
        let s = self.lock();
        ForwardCounts {
            live: s.live.len() as u64,
            ..s.counts
        }
    }

    /// Most links the configured capacity commits to, if bounded.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn link_limit(&self) -> Option<usize> {
        let by_pps = match (self.cfg.capacity_pps, self.cfg.per_link_packets_per_s) {
            (Some(cap), Some(per)) if per > 0 => {
                Some((self.cfg.commit_fraction * cap as f64 / f64::from(per)).floor() as usize)
            }
            _ => None,
        };
        match (by_pps, self.cfg.max_links) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// **The hook's decision.** Runs under leviculum's node lock: reads and
    /// writes only this admission's own state.
    pub fn decide(&self, req: &ForwardRequest) -> ForwardDecision {
        let limit = self.link_limit();
        let mut s = self.lock();
        let admit = ForwardDecision::Admit {
            max_bytes_per_s: self.cfg.per_link_bytes_per_s,
            max_packets_per_s: self.cfg.per_link_packets_per_s,
        };
        if s.live.contains_key(&req.link_id) {
            return admit;
        }
        if !s.exempt.contains(&req.destination_hash) {
            if self.cfg.admit_close_on_tier && !s.tier.admits_new_relay_work() {
                s.counts.refused_closed += 1;
                return ForwardDecision::Refuse;
            }
            if limit.is_some_and(|l| s.live.len() >= l) {
                s.counts.refused_capacity += 1;
                return ForwardDecision::Refuse;
            }
        }
        s.order += 1;
        let order = s.order;
        s.live.insert(req.link_id, order);
        s.counts.admitted += 1;
        admit
    }

    /// Fold a `forwarded_links()` reading taken at `now_ms`: retire closed
    /// links from the ledger and measure the forwarded rates.
    #[allow(clippy::cast_precision_loss)]
    pub fn refresh(&self, links: &[ForwardedLink], now_ms: u64) -> ForwardLoad {
        let mut s = self.lock();
        let present: HashSet<[u8; 16]> = links.iter().map(|l| l.link_id).collect();
        s.live.retain(|id, _| present.contains(id));
        s.last.retain(|id, _| present.contains(id));
        let mut load = ForwardLoad::default();
        let mut costs = Vec::with_capacity(links.len());
        for l in links {
            let bytes = l.toward_destination.bytes + l.toward_initiator.bytes;
            let packets = l.toward_destination.packets + l.toward_initiator.packets;
            if let Some((b0, p0, t0)) = s.last.get(&l.link_id).copied() {
                let dt = now_ms.saturating_sub(t0).max(1) as f64 / 1_000.0;
                let bps = bytes.saturating_sub(b0) as f64 * 8.0 / dt;
                let pps = packets.saturating_sub(p0) as f64 / dt;
                load.bps += bps;
                load.pps += pps;
                costs.push(ForwardCost {
                    link_id: l.link_id,
                    bps,
                    pps,
                });
            }
            s.last.insert(l.link_id, (bytes, packets, now_ms));
        }
        costs.sort_by(|a, b| b.pps.total_cmp(&a.pps).then(b.bps.total_cmp(&a.bps)));
        costs.truncate(TOP_N);
        load.top = costs;
        load.pps_ratio = self
            .cfg
            .capacity_pps
            .filter(|c| *c > 0)
            .map_or(0.0, |c| load.pps / c as f64);
        load
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use leviculum_core::forward_meter::DirectionCount;

    fn route(relay: u8, hops: u8) -> RelayRoute {
        RelayRoute {
            relay: [relay; 16],
            interface_index: usize::from(relay),
            hops,
            heard_at_ms: 0,
            expires_ms: u64::MAX,
        }
    }

    fn req(link: u8, dest: u8) -> ForwardRequest {
        ForwardRequest {
            link_id: [link; 16],
            destination_hash: [dest; 16],
            from_interface: 0,
            to_interface: 1,
            hops: 1,
            remaining_hops: 1,
        }
    }

    #[test]
    fn roster_relays_come_first_fewest_hops_and_others_are_ineligible() {
        // 1, 2: roster; 3: a stranger's transport node; the canonical is
        // never in the list (it is the caller's default dial, last).
        let routes = [route(3, 1), route(2, 3), route(1, 2)];
        let roster = |r: &[u8; 16]| (r[0] != 3).then(|| format!("member-{}", r[0]));
        let c = roster_relays_first(&routes, roster, 7);
        assert_eq!(c.iter().map(|c| c.relay[0]).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn equal_hop_roster_relays_spread_across_diallers() {
        let routes: Vec<RelayRoute> = (1..=4).map(|r| route(r, 2)).collect();
        let roster = |r: &[u8; 16]| Some(format!("m{}", r[0]));
        let mut firsts = std::collections::BTreeMap::new();
        for seed in 0..400u64 {
            *firsts
                .entry(roster_relays_first(&routes, roster, seed)[0].relay[0])
                .or_insert(0u32) += 1;
        }
        assert_eq!(
            firsts.len(),
            4,
            "every equivalent relay is somebody's first"
        );
        assert!(firsts.values().all(|&n| n >= 60), "{firsts:?}");
    }

    #[test]
    fn admission_closes_at_tier_one_but_never_for_exempt_destinations() {
        let a = ForwardAdmission::new(ForwardAdmissionConfig::default());
        assert!(matches!(
            a.decide(&req(1, 1)),
            ForwardDecision::Admit { .. }
        ));
        a.set_tier(ServiceTier::AudioAndFiles);
        a.exempt_destination([9; 16]);
        assert_eq!(a.decide(&req(2, 2)), ForwardDecision::Refuse);
        assert!(matches!(
            a.decide(&req(3, 9)),
            ForwardDecision::Admit { .. }
        ));
        // An admitted link is never refused on a repeat request.
        assert!(matches!(
            a.decide(&req(1, 1)),
            ForwardDecision::Admit { .. }
        ));
        let c = a.counts();
        assert_eq!((c.admitted, c.refused_closed, c.live), (2, 1, 2));
    }

    #[test]
    fn capacity_bounds_links_at_the_commit_fraction_with_token_buckets() {
        let a = ForwardAdmission::new(ForwardAdmissionConfig {
            per_link_packets_per_s: Some(100),
            per_link_bytes_per_s: Some(7_000),
            capacity_pps: Some(1_000),
            ..ForwardAdmissionConfig::default()
        });
        let mut admitted = 0;
        for l in 0..20u8 {
            if let ForwardDecision::Admit {
                max_bytes_per_s,
                max_packets_per_s,
            } = a.decide(&req(l, l))
            {
                assert_eq!(
                    (max_bytes_per_s, max_packets_per_s),
                    (Some(7_000), Some(100))
                );
                admitted += 1;
            }
        }
        assert_eq!(admitted, 6, "0.65 × 1000 pps ÷ 100 pps per link");
        assert_eq!(a.counts().refused_capacity, 14);
        // Closing links frees the ledger.
        let none: Vec<ForwardedLink> = Vec::new();
        let _ = a.refresh(&none, 1_000);
        assert_eq!(a.counts().live, 0);
        assert!(matches!(
            a.decide(&req(50, 50)),
            ForwardDecision::Admit { .. }
        ));
    }

    #[test]
    fn refresh_measures_rates_and_ranks_the_costliest() {
        let a = ForwardAdmission::new(ForwardAdmissionConfig {
            capacity_pps: Some(1_000),
            ..ForwardAdmissionConfig::default()
        });
        let link = |id: u8, packets: u64, bytes: u64| ForwardedLink {
            link_id: [id; 16],
            destination_hash: [id; 16],
            initiator_interface: 0,
            destination_interface: 1,
            toward_destination: DirectionCount {
                bytes,
                packets,
                dropped_over_cap: 0,
            },
            toward_initiator: DirectionCount::default(),
            admitted_at_ms: 0,
            last_forwarded_ms: 0,
            decision: ForwardDecision::ADMIT,
        };
        let _ = a.refresh(&[link(1, 0, 0), link(2, 0, 0)], 0);
        let load = a.refresh(&[link(1, 300, 30_000), link(2, 100, 1_000)], 1_000);
        assert!((load.pps - 400.0).abs() < 1e-6);
        assert!((load.pps_ratio - 0.4).abs() < 1e-6);
        assert_eq!(load.top[0].link_id, [1; 16]);
    }
}
