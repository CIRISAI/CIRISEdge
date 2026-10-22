//! CC 5.4.6 item 4 (rc10 `89e6915`; `CLM-onion-layer-deal`) — **the layer
//! deal**: who relays onion traffic in a period and which of the three layers
//! each relay sits in, as a pure function of the fold. No coordinator assigns
//! layers: two nodes holding the same rows deal the same layers.
//!
//! Inputs are what the fold says about each node ([`RelayCandidate`]); the
//! membership predicate ([`is_relay`]) and the deal ([`deal_layers`]) never
//! read arrival order, clocks other than the period, or anything local. The
//! period is the rendezvous period, `floor(unix_seconds / 3600)` on the
//! global clock (CC 3.1.4). `H` is SHA-256 over a domain tag, the key id and
//! the period, big-endian ([`deal_hash`]).
//!
//! The cap and the floor are CC's: in each layer the non-seat relays number
//! at most `⌈c × seats_in_layer⌉` (`c` a steward setting, default 2), and a
//! layer with fewer than three members makes the tier unavailable for the
//! period. Relays past the cap wait for the next period's deal; rotation by
//! period gives them their turn.
//!
//! `FSD/ONION_ROUTING.md` is the design this implements; the unit witnesses
//! below run it over the CSD/4 catalogue topologies T0–T19.

use sha2::{Digest, Sha256};

/// The number of layers (CC 5.4.6 item 4: exactly three hops, one per layer).
pub const LAYERS: usize = 3;
/// The floor: fewer members than this in any layer ⇒ the tier is unavailable
/// for the period (CC 5.4.6 item 4).
pub const LAYER_FLOOR: usize = 3;
/// The default cap factor `c` (CC 5.4.6 item 4; a steward setting).
pub const DEFAULT_CAP_FACTOR: u32 = 2;
/// The rendezvous period length (CC 3.1.4: `floor(unix_seconds / 3600)`).
pub const PERIOD_SECONDS: u64 = 3600;
/// Domain tag of the deal hash (edge's own; CC fixes `H(key_id ‖ period)`).
pub const DEAL_HASH_DOMAIN: &[u8] = b"ciris:onion:layer-deal:v1";

/// What the fold says about one node, read at deal time. Every field is a
/// fold fact (CC 5.4.6 item 4), none is local state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // the CC's five membership legs, each one fold fact, named
pub struct RelayCandidate {
    /// The node's occurrence key id (the signed `transport_destination` row's attester).
    pub key_id: String,
    /// The node holds a serve seat in the genesis bundle (a canonical).
    pub is_seat: bool,
    /// CC 5.4.6 item 4 (steward, 2026-10-22) — the identity carries a
    /// steward-conferred `infra:relay` standing (an accord-plane role on an
    /// owner-bound, bundle-rooted identity): seat-like in the cap's
    /// denominator, so the steward grows the layers by conferring. Not a
    /// seat: it is dealt among the others and owes no seat conformance.
    pub relay_standing: bool,
    /// Its current signed `transport_destination` row is live (not retired).
    pub row_live: bool,
    /// The node is announced (CC 5.3; an unannounced relay is unreachable).
    pub announced: bool,
    /// The row carries a valid X-Wing hop key (in-row separation held at
    /// admission; the cross-row rule held at use — CC 3.3.6.2).
    pub hop_key_valid: bool,
    /// The row carries `onion_relay: { opt_out: true }` (CC 3.3.6.2).
    pub opted_out: bool,
    /// The identity is owner-bound under a trust root in the bundle's charter set.
    pub owner_bound_under_bundle_root: bool,
}

impl RelayCandidate {
    /// Seat-like for the cap: a serve seat or a conferred relay standing.
    #[must_use]
    pub const fn seat_like(&self) -> bool {
        self.is_seat || self.relay_standing
    }
}

/// The rendezvous period of a unix time.
#[must_use]
pub const fn period_of(unix_seconds: u64) -> u64 {
    unix_seconds / PERIOD_SECONDS
}

/// CC 5.4.6 item 4 — the membership predicate: a relay for the period iff
/// its row is live and announced, carries a valid hop key and no opt-out
/// marker, and its identity is owner-bound under a bundle root. (Shaped layer
/// links are checked at use, on the link, not here.)
#[must_use]
pub fn is_relay(c: &RelayCandidate) -> bool {
    c.row_live && c.announced && c.hop_key_valid && !c.opted_out && c.owner_bound_under_bundle_root
}

/// Why a seat is out of conformance with CC 5.4.6 item 1, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeatViolation {
    /// `seat_opted_out`: a serve seat carries the opt-out marker.
    OptedOut,
    /// `seat_without_hop_key`: a serve seat has no valid hop key.
    WithoutHopKey,
}

impl SeatViolation {
    /// The stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OptedOut => "seat_opted_out",
            Self::WithoutHopKey => "seat_without_hop_key",
        }
    }
}

/// CC 5.4.6 item 1 — a seat's conformance: `None` for a conforming seat or a
/// non-seat; the marker is named before the missing key when both hold.
#[must_use]
pub fn seat_violation(c: &RelayCandidate) -> Option<SeatViolation> {
    if !c.is_seat {
        return None;
    }
    if c.opted_out {
        return Some(SeatViolation::OptedOut);
    }
    if !c.hop_key_valid {
        return Some(SeatViolation::WithoutHopKey);
    }
    None
}

/// `H(key_id ‖ period)`: SHA-256 over the domain tag, the key id's UTF-8
/// bytes and the period as eight big-endian bytes.
#[must_use]
pub fn deal_hash(key_id: &str, period: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DEAL_HASH_DOMAIN);
    h.update(key_id.as_bytes());
    h.update(period.to_be_bytes());
    h.finalize().into()
}

/// One period's layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerDeal {
    /// The period dealt.
    pub period: u64,
    /// The three layers, each the key ids dealt into it, in deal order.
    pub layers: [Vec<String>; LAYERS],
    /// Relays held back by the cap this period (they wait for the next deal).
    pub capped: Vec<String>,
    /// Whether every layer meets the floor: `false` ⇒ the tier is unavailable
    /// for the period and the client says so.
    pub available: bool,
}

impl LayerDeal {
    /// The layer `key_id` sits in, if dealt.
    #[must_use]
    pub fn layer_of(&self, key_id: &str) -> Option<usize> {
        self.layers
            .iter()
            .position(|l| l.iter().any(|k| k == key_id))
    }

    /// Members per layer.
    #[must_use]
    pub fn sizes(&self) -> [usize; LAYERS] {
        [
            self.layers[0].len(),
            self.layers[1].len(),
            self.layers[2].len(),
        ]
    }
}

/// CC 5.4.6 item 4 — **the deal**, once per period: the relays
/// ([`is_relay`]) sorted by `H(key_id ‖ period)`, the seat-like first (serve
/// seats and conferred `infra:relay` standings, [`RelayCandidate::seat_like`])
/// and then the others, dealt round-robin across the three layers, seat-like
/// first; in each layer the others are capped at `⌈cap_factor × seat_like_in_layer⌉`
/// (relays past the cap wait for the next period); a layer with fewer than
/// [`LAYER_FLOOR`] members makes the deal unavailable. A pure function of its
/// inputs: `candidates` may come in any order, with duplicates by key id
/// removed (the fold holds one current row per node).
#[must_use]
pub fn deal_layers(candidates: &[RelayCandidate], period: u64, cap_factor: u32) -> LayerDeal {
    let mut seen = std::collections::HashSet::new();
    let mut relays: Vec<&RelayCandidate> = candidates
        .iter()
        .filter(|c| is_relay(c))
        .filter(|c| seen.insert(c.key_id.as_str()))
        .collect();
    // Seats first, then by the hash; the key id breaks a (practically
    // impossible) hash tie so the order is total.
    relays.sort_by_cached_key(|c| {
        (
            !c.seat_like(),
            deal_hash(&c.key_id, period),
            c.key_id.clone(),
        )
    });
    let mut layers: [Vec<String>; LAYERS] = Default::default();
    let mut seats_in: [usize; LAYERS] = [0; LAYERS];
    let mut non_seats_in: [usize; LAYERS] = [0; LAYERS];
    let mut capped = Vec::new();
    let mut next = 0usize;
    for c in &relays {
        if c.seat_like() {
            layers[next].push(c.key_id.clone());
            seats_in[next] += 1;
            next = (next + 1) % LAYERS;
        }
    }
    // Non-seats continue the round-robin from where the seats left off, so a
    // layer with fewer seats is not systematically favoured or starved.
    for c in &relays {
        if c.seat_like() {
            continue;
        }
        // Find the next layer (round-robin) with cap room; none ⇒ capped.
        let mut placed = false;
        for step in 0..LAYERS {
            let l = (next + step) % LAYERS;
            let cap = usize::try_from(cap_factor)
                .unwrap_or(usize::MAX)
                .saturating_mul(seats_in[l]);
            if non_seats_in[l] < cap {
                layers[l].push(c.key_id.clone());
                non_seats_in[l] += 1;
                next = (l + 1) % LAYERS;
                placed = true;
                break;
            }
        }
        if !placed {
            capped.push(c.key_id.clone());
        }
    }
    let available = layers.iter().all(|l| l.len() >= LAYER_FLOOR);
    LayerDeal {
        period,
        layers,
        capped,
        available,
    }
}

#[cfg(test)]
mod tests {
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

    /// The CSD/4 catalogue topologies T0–T19 (CIRISConstitution
    /// `formal/cewp_node/catalog/`, catalogue version 3): `(id, canonicals,
    /// announced non-canonical nodes, unannounced nodes)`. Every node is
    /// owner-bound in the catalogue except where noted by `unowned`.
    const CATALOGUE: &[(&str, usize, usize, usize)] = &[
        ("T0", 0, 0, 1),
        ("T1", 1, 2, 0),
        ("T2", 1, 2, 1),
        ("T3", 1, 4, 0),
        ("T4", 1, 3, 0),
        ("T5", 1, 3, 0),
        ("T6", 1, 2, 0),
        ("T7", 1, 1, 0),
        ("T8", 1, 2, 0),
        ("T9", 2, 3, 0),
        ("T10", 1, 1, 2),
        ("T11", 1, 1, 2),
        ("T12", 1, 2, 0),
        ("T13", 1, 1, 0),
        ("T14", 1, 2, 0),
        ("T15", 1, 7, 0),
        ("T16", 1, 1, 0),
        ("T17", 1, 2, 0),
        ("T18", 1, 2, 0),
        ("T19", 1, 2, 0),
    ];

    fn topology(entry: &(&str, usize, usize, usize)) -> Vec<RelayCandidate> {
        let (id, seats, announced, unannounced) = *entry;
        let mut v = Vec::new();
        for i in 0..seats {
            v.push(node(&format!("{id}-C{i}"), true));
        }
        for i in 0..announced {
            v.push(node(&format!("{id}-N{i}"), false));
        }
        for i in 0..unannounced {
            let mut n = node(&format!("{id}-U{i}"), false);
            n.announced = false;
            v.push(n);
        }
        v
    }

    /// CLM-onion-layer-deal — two nodes holding the same rows deal identical
    /// layers, whatever order the rows arrived in, over every catalogue
    /// topology and across periods; and the cap and the floor hold on every
    /// deal.
    #[test]
    fn two_nodes_holding_the_same_rows_deal_identical_layers_over_the_catalogue() {
        for entry in CATALOGUE {
            let a = topology(entry);
            let mut b = a.clone();
            b.reverse();
            b.rotate_left(1);
            for period in [0u64, 1, 496_000, u64::MAX / PERIOD_SECONDS] {
                for c in [1u32, 2, 3] {
                    let da = deal_layers(&a, period, c);
                    let db = deal_layers(&b, period, c);
                    assert_eq!(
                        da, db,
                        "{} period {period} c {c}: the deal is a function of the fold",
                        entry.0
                    );
                    // The cap: non-seats in a layer ≤ c × seats in that layer.
                    for l in 0..LAYERS {
                        let seats = da.layers[l].iter().filter(|k| k.contains("-C")).count();
                        let non = da.layers[l].len() - seats;
                        assert!(
                            non <= c as usize * seats,
                            "{} layer {l}: {non} non-seats over {seats} seats at c={c}",
                            entry.0
                        );
                    }
                    // The floor.
                    assert_eq!(da.available, da.sizes().iter().all(|&n| n >= LAYER_FLOOR));
                    // Unannounced nodes are never dealt; every relay is dealt or capped.
                    let relays = a.iter().filter(|x| is_relay(x)).count();
                    let dealt: usize = da.sizes().iter().sum();
                    assert_eq!(dealt + da.capped.len(), relays, "{}", entry.0);
                    assert!(!da.layers.iter().flatten().any(|k| k.contains("-U")));
                }
            }
        }
    }

    /// The catalogue is too small for the tier everywhere (one seat caps each
    /// layer at ≤ 1 + c and only one layer gets the seat): the floor says so,
    /// by design, on all twenty topologies at c = 2.
    #[test]
    fn the_floor_makes_the_tier_unavailable_on_every_catalogue_topology() {
        for entry in CATALOGUE {
            let d = deal_layers(&topology(entry), 7, DEFAULT_CAP_FACTOR);
            assert!(!d.available, "{}: {:?}", entry.0, d.sizes());
        }
    }

    /// Nine seats fill three layers at the floor with no non-seats; with
    /// non-seats the cap admits up to 2 × seats per layer and the rest wait,
    /// rotating across periods.
    #[test]
    fn the_cap_admits_two_per_seat_per_layer_and_rotates_the_rest() {
        let mut v: Vec<_> = (0..3).map(|i| node(&format!("seat{i}"), true)).collect();
        v.extend((0..20).map(|i| node(&format!("n{i}"), false)));
        let d = deal_layers(&v, 100, 2);
        assert_eq!(d.sizes(), [3, 3, 3], "{:?}", d.sizes());
        assert_eq!(d.capped.len(), 20 - 6);
        assert!(d.available);
        let d2 = deal_layers(&v, 101, 2);
        assert_ne!(d.layers, d2.layers, "the deal rotates by period");
        let dealt1: std::collections::HashSet<_> = d.layers.iter().flatten().collect();
        let dealt2: std::collections::HashSet<_> = d2.layers.iter().flatten().collect();
        assert_ne!(dealt1, dealt2, "a capped relay gets a turn");
        // c = 1 halves the room; c = 3 widens it.
        assert_eq!(deal_layers(&v, 100, 1).sizes(), [2, 2, 2]);
        assert_eq!(deal_layers(&v, 100, 3).sizes(), [4, 4, 4]);
    }

    /// CC 5.4.6 item 4 (steward 2026-10-22) — a conferred `infra:relay`
    /// standing counts in the cap's denominator: three seats and three
    /// standings deal [6, 6, 6] at c = 2 where three seats alone deal [3, 3, 3];
    /// a standing is dealt as seat-like but is not a seat (no seat violation).
    #[test]
    fn a_conferred_relay_standing_counts_in_the_caps_denominator() {
        let mut v: Vec<_> = (0..3).map(|i| node(&format!("seat{i}"), true)).collect();
        v.extend((0..30).map(|i| node(&format!("n{i}"), false)));
        assert_eq!(deal_layers(&v, 5, 2).sizes(), [3, 3, 3]);
        for i in 0..3 {
            let mut st = node(&format!("standing{i}"), false);
            st.relay_standing = true;
            assert_eq!(seat_violation(&st), None);
            v.push(st);
        }
        let d = deal_layers(&v, 5, 2);
        assert_eq!(d.sizes(), [6, 6, 6], "{:?}", d.sizes());
        assert_eq!(d.capped.len(), 30 - 12);
        // Seat-like members land on both passes' first slots: each layer has
        // exactly two seat-like members (round-robin over six).
        for l in &d.layers {
            let seat_like = l
                .iter()
                .filter(|k| k.starts_with("seat") || k.starts_with("standing"))
                .count();
            assert_eq!(seat_like, 2);
        }
    }

    /// Membership: each predicate leg excludes on its own; a seat's violations
    /// are named.
    #[test]
    fn membership_legs_and_seat_violations() {
        let base = node("x", false);
        assert!(is_relay(&base));
        for (leg, mutate) in [
            (
                "row_live",
                Box::new(|c: &mut RelayCandidate| c.row_live = false)
                    as Box<dyn Fn(&mut RelayCandidate)>,
            ),
            (
                "announced",
                Box::new(|c: &mut RelayCandidate| c.announced = false),
            ),
            (
                "hop_key_valid",
                Box::new(|c: &mut RelayCandidate| c.hop_key_valid = false),
            ),
            (
                "opted_out",
                Box::new(|c: &mut RelayCandidate| c.opted_out = true),
            ),
            (
                "owner_bound",
                Box::new(|c: &mut RelayCandidate| c.owner_bound_under_bundle_root = false),
            ),
        ] {
            let mut c = base.clone();
            mutate(&mut c);
            assert!(!is_relay(&c), "{leg} alone excludes");
        }
        let mut seat = node("s", true);
        assert_eq!(seat_violation(&seat), None);
        seat.hop_key_valid = false;
        assert_eq!(seat_violation(&seat), Some(SeatViolation::WithoutHopKey));
        seat.opted_out = true;
        assert_eq!(seat_violation(&seat), Some(SeatViolation::OptedOut));
        assert_eq!(seat_violation(&node("n", false)), None);
        assert_eq!(period_of(3_599), 0);
        assert_eq!(period_of(3_600), 1);
    }
}
