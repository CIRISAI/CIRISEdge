//! CC 5.4.6 items 2 and 4 — **the sender's route** (FSD/ONION_ROUTING.md §7):
//! one relay per layer, chosen uniformly among the layer's ANSWERING members
//! of this period's deal (never the sender itself), and the publication
//! packet built over them with an exponential mixing delay per hop.
//!
//! The deal says who; this node's liveness says whether now. A route is never
//! built over a layer with fewer than three answering relays: that is the
//! tier being unavailable, by name, not a thin route.

use super::packet::{self, Entropy, HopKey, HopSpec, OnionError, RoutingBlock, FLAG_FINAL};
use super::tokens;
use crate::transport::onion_layers::{LayerDeal, LAYERS};
use crate::transport::onion_liveness::MIN_ANSWERING;

/// Resolves a dealt relay's key id to its identity destination hash and its
/// hop key ([`crate::onion::hop_key::hop_key_for`]).
pub type HopResolver<'a> = dyn Fn(&str) -> Option<([u8; 16], HopKey)> + Sync + 'a;

/// One hop of a chosen route, resolved for building.
#[derive(Debug, Clone)]
pub struct RouteHop {
    /// The relay's key id.
    pub key_id: String,
    /// Its identity destination hash (where the previous hop sends).
    pub dest: [u8; 16],
    /// Its hop key ([`crate::onion::hop_key::hop_key_for`]).
    pub key: HopKey,
}

/// A uniform index below `n` (rejection sampling over u32).
fn uniform(n: usize, rng: &mut dyn Entropy) -> Result<usize, OnionError> {
    let n32 = u32::try_from(n).map_err(|_| OnionError::Malformed("layer too large"))?;
    if n32 == 0 {
        return Err(OnionError::Malformed("empty layer"));
    }
    let zone = u32::MAX - (u32::MAX % n32);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b)?;
        let v = u32::from_be_bytes(b);
        if v < zone {
            return Ok((v % n32) as usize);
        }
    }
}

/// Choose the three relays: one per layer, uniformly among that layer's
/// members for which `answering` holds, never `own_key_id`.
///
/// # Errors
/// [`tokens::UNAVAILABLE_FLOOR`] when the deal is thin;
/// [`tokens::UNAVAILABLE_LIVENESS`] when a layer has fewer than three
/// answering candidates; an entropy failure as [`tokens::ROUTE_FAILED`].
pub fn pick_route(
    deal: &LayerDeal,
    own_key_id: &str,
    answering: &dyn Fn(&str) -> bool,
    rng: &mut dyn Entropy,
) -> Result<[String; LAYERS], &'static str> {
    if !deal.available {
        return Err(tokens::UNAVAILABLE_FLOOR);
    }
    let mut out: [String; LAYERS] = Default::default();
    for (l, members) in deal.layers.iter().enumerate() {
        let candidates: Vec<&String> = members
            .iter()
            .filter(|k| k.as_str() != own_key_id && answering(k))
            .collect();
        if candidates.len() < MIN_ANSWERING {
            return Err(tokens::UNAVAILABLE_LIVENESS);
        }
        let i = uniform(candidates.len(), rng).map_err(|_| tokens::ROUTE_FAILED)?;
        out[l].clone_from(candidates[i]);
    }
    Ok(out)
}

/// An exponential mixing delay with mean `mean_ms`, clamped to what a
/// routing block carries and a relay honours.
///
/// # Errors
/// An entropy failure.
pub fn mix_delay_ms(mean_ms: u32, rng: &mut dyn Entropy) -> Result<u16, OnionError> {
    let mut b = [0u8; 8];
    rng.fill(&mut b)?;
    // U in (0, 1]: the top 53 bits, never zero.
    #[allow(clippy::cast_precision_loss)]
    let u = ((u64::from_be_bytes(b) >> 11) + 1) as f64 / (1u64 << 53) as f64;
    let d = -f64::from(mean_ms) * u.ln();
    let cap = super::relay::MAX_HOLD_DELAY
        .as_millis()
        .min(u128::from(u16::MAX));
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let ms = d.min(cap as f64).max(0.0) as u16;
    Ok(ms)
}

/// The publication packet over `route` (CC 5.4.6 item 2): each hop names the
/// next hop's destination; the last stores. `period` is the rendezvous period.
///
/// # Errors
/// [`packet::build_packet_with`]'s.
pub fn build_publication(
    route: &[RouteHop; LAYERS],
    payload: &[u8],
    period: u64,
    mix_mean_delay_ms: u32,
    rng: &mut dyn Entropy,
) -> Result<Vec<u8>, OnionError> {
    #[allow(clippy::cast_possible_truncation)] // the period's low 32 bits, by design
    let period32 = period as u32;
    let mut hops = Vec::with_capacity(LAYERS);
    for (i, hop) in route.iter().enumerate() {
        let last = i + 1 == LAYERS;
        hops.push(HopSpec {
            key: hop.key.clone(),
            block: RoutingBlock {
                next_dest: if last { [0; 16] } else { route[i + 1].dest },
                flags: if last { FLAG_FINAL } else { 0 },
                delay_ms: if last {
                    0
                } else {
                    mix_delay_ms(mix_mean_delay_ms, rng)?
                },
                period: period32,
            },
        });
    }
    packet::build_packet_with(&hops, payload, rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::packet::{FixedEntropy, HopSecret};
    use crate::onion::relay::{OnionRelay, RelayAction};
    use crate::transport::onion_layers::{deal_layers, RelayCandidate};
    use std::collections::HashMap;

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

    #[test]
    fn a_route_takes_one_answering_relay_per_layer_and_never_the_sender() {
        let nine: Vec<_> = (0..9).map(|i| node(&format!("s{i}"), true)).collect();
        let deal = deal_layers(&nine, 3, 2);
        let mut rng = FixedEntropy::new(b"route", 4096);
        let all = |_: &str| true;
        let r = pick_route(&deal, "nobody", &all, &mut rng).unwrap();
        for (l, k) in r.iter().enumerate() {
            assert_eq!(deal.layer_of(k), Some(l));
        }
        // The sender in a layer of three leaves two: the tier is unavailable
        // to it rather than routed thin.
        let me = deal.layers[0][0].clone();
        assert_eq!(
            pick_route(&deal, &me, &all, &mut rng).unwrap_err(),
            tokens::UNAVAILABLE_LIVENESS
        );
        let silent = |_: &str| false;
        assert_eq!(
            pick_route(&deal, "nobody", &silent, &mut rng).unwrap_err(),
            tokens::UNAVAILABLE_LIVENESS
        );
        let thin = deal_layers(&nine[..2], 3, 2);
        assert_eq!(
            pick_route(&thin, "nobody", &all, &mut rng).unwrap_err(),
            tokens::UNAVAILABLE_FLOOR
        );
    }

    #[test]
    fn mixing_delays_are_exponential_around_the_mean_and_clamped() {
        let mut rng = FixedEntropy::new(b"delay", 8 * 4000);
        let ds: Vec<u16> = (0..4000)
            .map(|_| mix_delay_ms(2000, &mut rng).unwrap())
            .collect();
        let mean = ds.iter().map(|&d| f64::from(d)).sum::<f64>() / 4000.0;
        assert!((1800.0..2200.0).contains(&mean), "mean {mean}");
        assert!(ds.iter().all(|&d| u128::from(d) <= 60_000));
    }

    /// **The 3-hop loopback round trip, forced available.** Nine seat relays
    /// (a deal that passes the floor), every one answering; a sender picks a
    /// route over the deal, builds the publication, and the packet crosses
    /// three in-process relays, each on a link marked shaped; the exit stores
    /// the payload. The same packet offered on an unshaped link is refused at
    /// the first hop. (Over-the-wire RNS loopback is owed with persist 61.0.1,
    /// when a node can publish its own hop key.)
    #[test]
    fn a_publication_crosses_three_relays_end_to_end_when_forced_available() {
        let ids: Vec<String> = (0..9).map(|i| format!("relay{i}")).collect();
        let cands: Vec<_> = ids.iter().map(|k| node(k, true)).collect();
        let period = 496_000u64;
        let deal = deal_layers(&cands, period, 2);
        assert!(deal.available);
        let mut secrets: HashMap<String, HopSecret> = HashMap::new();
        let mut dest_of: HashMap<String, [u8; 16]> = HashMap::new();
        for (i, k) in ids.iter().enumerate() {
            let n = u8::try_from(i + 1).unwrap();
            secrets.insert(k.clone(), HopSecret::from_xwing_seed(&[n; 32]).unwrap());
            dest_of.insert(k.clone(), [n; 16]);
        }
        let mut rng = FixedEntropy::new(b"loopback", 64 * 1024);
        let pick = pick_route(&deal, "publisher", &|_: &str| true, &mut rng).unwrap();
        let route: [RouteHop; 3] = std::array::from_fn(|l| RouteHop {
            key_id: pick[l].clone(),
            dest: dest_of[&pick[l]],
            key: secrets[&pick[l]].public().clone(),
        });
        let payload = b"an anonymous federation-scope row".to_vec();
        let pkt = build_publication(&route, &payload, period, 2000, &mut rng).unwrap();

        let relays: HashMap<[u8; 16], OnionRelay> = ids
            .iter()
            .map(|k| {
                let n = dest_of[k][0];
                (
                    dest_of[k],
                    OnionRelay::new(HopSecret::from_xwing_seed(&[n; 32]).unwrap(), None),
                )
            })
            .collect();
        assert_eq!(
            relays[&route[0].dest]
                .accept(&pkt, false, period)
                .unwrap_err(),
            tokens::UNSHAPED_LINK
        );
        let mut at = route[0].dest;
        let mut cur = pkt;
        let mut hops = 0;
        let stored = loop {
            hops += 1;
            match relays[&at]
                .accept(&cur, true, period)
                .expect("accepted on a shaped link")
            {
                RelayAction::Forward {
                    next_dest, packet, ..
                } => {
                    at = next_dest;
                    cur = packet;
                }
                RelayAction::Store { payload } => break payload,
                RelayAction::Mailbox { .. } => panic!("not a delivery"),
            }
        };
        assert_eq!(hops, 3);
        assert_eq!(at, route[2].dest);
        assert_eq!(stored, payload);
    }
}
