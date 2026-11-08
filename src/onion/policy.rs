//! CC 5.4.6 items 1 and 4 — **when this node uses the tier and when it
//! relays**, as pure functions the runtime and the FFI status read.
//!
//! - The tier is ACTIVE on a node only when its operator opted in
//!   ([`OnionPolicy::enabled`], off by default in v44) AND the deal and the
//!   liveness fold report it available ([`tier_decision`]).
//! - An active node relays for others by default ([`relay_decision`]),
//!   unless the device policy says not now (a phone relays only on Wi-Fi
//!   while charging; FSD/CIRIS_MESH.md §3.2; the user may override either
//!   way), the operator opted a non-seat node out, or it has no valid hop
//!   key. A serve seat may not opt out (CC 5.4.6 item 1).
//! - Relaying happens only over shaped layer links: the relay step refuses an
//!   unshaped link before anything else (`crate::onion::relay`).

use crate::transport::link_shaping::{DeviceKind, DeviceState};
use crate::transport::onion_layers::DEFAULT_CAP_FACTOR;
use crate::transport::onion_liveness::Availability;

use super::tokens;

/// The operator's onion settings. Every default is the dormant v44 posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPolicy {
    /// The publisher's opt-in: this node runs the tier (uses it, and relays
    /// once it is available). Off by default.
    pub enabled: bool,
    /// The operator's relay opt-out (honoured for a non-seat node only).
    pub relay_opt_out: bool,
    /// This node holds a serve seat.
    pub is_seat: bool,
    /// `onion.cap_factor` (CC 5.4.6 item 4; relieve-never-expand).
    pub cap_factor: u32,
    /// `onion.mix_mean_delay_ms`: the sender's mean per-hop mixing delay.
    pub mix_mean_delay_ms: u32,
}

impl Default for OnionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            relay_opt_out: false,
            is_seat: false,
            cap_factor: DEFAULT_CAP_FACTOR,
            mix_mean_delay_ms: 2000,
        }
    }
}

/// CC 5.4.6 item 1 device policy: servers and home nodes relay; a phone
/// relays only on an unmetered network while charging; the user's override
/// wins either way.
#[must_use]
pub fn device_relays(d: &DeviceState) -> bool {
    if let Some(o) = d.relay_override {
        return o;
    }
    match d.kind {
        DeviceKind::Server | DeviceKind::Home => true,
        DeviceKind::Phone => d.unmetered && d.charging,
    }
}

/// **Relay offering is on**: this node offers to carry for others, whether or
/// not the tier has run here yet. It is the owner's setting on the device
/// policy ([`device_relays`], `FSD/CIRIS_MESH.md` §3.2), less the operator's
/// opt-out, which a seat does not have. It is also the consent to be referred:
/// a node reports free shaped slots only while this holds
/// ([`crate::transport::shaping_referral`]). A client-only node has nothing to
/// offer, whatever its state or the user's override
/// ([`DeviceState::client_only`]).
///
/// **A node that activated the tier offers nothing** (CC 5.4.6 rc17,
/// `CLM-referred-peer-is-proxy`): it holds its anonymous identity alone, and a
/// proxy is an offering node under its public identity, so a public route at
/// the same address would hand the anonymous identity's guard the name behind
/// it. The rule attaches to the operator's opt-in ([`OnionPolicy::enabled`]),
/// not to the tier being available this period: a node does not go back to
/// proxying because its layers fell under the floor. It still relays onion
/// packets ([`relay_decision`]); that is the tier's own carrying, not this
/// offer. A person who wants both runs two nodes.
#[must_use]
pub fn relay_offering(p: &OnionPolicy, d: &DeviceState) -> bool {
    !p.enabled && !d.client_only && device_relays(d) && (p.is_seat || !p.relay_opt_out)
}

/// Whether the tier is active on this node: `Ok` or the reason, by token.
///
/// # Errors
/// [`tokens::NOT_OPTED_IN`], or the availability's own reason
/// ([`tokens::UNAVAILABLE_FLOOR`] / [`tokens::UNAVAILABLE_LIVENESS`]).
pub fn tier_decision(
    policy: &OnionPolicy,
    availability: &Availability,
) -> Result<(), &'static str> {
    if !policy.enabled {
        return Err(tokens::NOT_OPTED_IN);
    }
    if !availability.available {
        return Err(availability.reason.unwrap_or(tokens::UNAVAILABLE_FLOOR));
    }
    Ok(())
}

/// Whether this node relays for others now: `Ok` or the reason, by token.
///
/// # Errors
/// [`tokens::RELAY_DORMANT`] (the tier is not active here),
/// [`tokens::NO_VALID_HOP_KEY`], [`tokens::RELAY_OPTED_OUT`] (non-seat
/// only), [`tokens::RELAY_DEVICE_POLICY`].
pub fn relay_decision(
    policy: &OnionPolicy,
    device: &DeviceState,
    tier_active: bool,
    has_valid_hop_key: bool,
) -> Result<(), &'static str> {
    if !tier_active {
        return Err(tokens::RELAY_DORMANT);
    }
    if !has_valid_hop_key {
        return Err(tokens::NO_VALID_HOP_KEY);
    }
    if policy.is_seat {
        // A serve seat MAY NOT opt out (CC 5.4.6 item 1); seats are servers.
        return Ok(());
    }
    if policy.relay_opt_out {
        return Err(tokens::RELAY_OPTED_OUT);
    }
    if !device_relays(device) {
        return Err(tokens::RELAY_DEVICE_POLICY);
    }
    Ok(())
}

/// Below [`tokens::SMALL_SET_PER_LAYER`] answering relays in any layer the
/// client says the set is small.
#[must_use]
pub fn small_set(a: &Availability) -> bool {
    a.layers
        .iter()
        .any(|l| l.answering < tokens::SMALL_SET_PER_LAYER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::onion_layers::{deal_layers, RelayCandidate};
    use crate::transport::onion_liveness::{LivenessEvidence, LivenessFold};

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

    /// The v44 dormancy: the default policy is not opted in, whatever the
    /// deal says; opted in, the tier waits on the floor (one seat, as the
    /// canonical bundle has today) and then on liveness, by name.
    #[test]
    fn the_tier_is_dormant_by_default_and_needs_three_per_layer() {
        let one_seat: Vec<_> = std::iter::once(node("seat0", true))
            .chain((0..20).map(|i| node(&format!("n{i}"), false)))
            .collect();
        let fold = LivenessFold::new();
        let thin = fold.availability(&deal_layers(&one_seat, 7, 2));
        assert_eq!(
            tier_decision(&OnionPolicy::default(), &thin),
            Err(tokens::NOT_OPTED_IN)
        );
        let on = OnionPolicy {
            enabled: true,
            ..OnionPolicy::default()
        };
        assert_eq!(tier_decision(&on, &thin), Err(tokens::UNAVAILABLE_FLOOR));

        let nine: Vec<_> = (0..9).map(|i| node(&format!("s{i}"), true)).collect();
        let deal = deal_layers(&nine, 7, 2);
        assert_eq!(
            tier_decision(&on, &fold.availability(&deal)),
            Err(tokens::UNAVAILABLE_LIVENESS)
        );
        let mut fold = LivenessFold::new();
        for k in deal.layers.iter().flatten() {
            fold.observe(k, LivenessEvidence::ShapedLinkUp);
        }
        let a = fold.availability(&deal);
        assert_eq!(tier_decision(&on, &a), Ok(()));
        assert!(
            small_set(&a),
            "three per layer is a small set, and the client says so"
        );
    }

    /// CC 5.4.6 item 1 — relaying is on once the tier runs; a phone relays
    /// only on Wi-Fi while charging unless the user overrides; a seat cannot
    /// opt out; no hop key, no relaying.
    #[test]
    fn relaying_follows_the_tier_the_device_and_the_seat_rule() {
        let p = OnionPolicy {
            enabled: true,
            ..OnionPolicy::default()
        };
        let server = DeviceState::of(DeviceKind::Server);
        assert_eq!(
            relay_decision(&p, &server, false, true),
            Err(tokens::RELAY_DORMANT)
        );
        assert_eq!(relay_decision(&p, &server, true, true), Ok(()));
        assert_eq!(
            relay_decision(&p, &server, true, false),
            Err(tokens::NO_VALID_HOP_KEY)
        );
        let mut phone = DeviceState::of(DeviceKind::Phone);
        assert_eq!(
            relay_decision(&p, &phone, true, true),
            Ok(()),
            "Wi-Fi and charging"
        );
        phone.charging = false;
        assert_eq!(
            relay_decision(&p, &phone, true, true),
            Err(tokens::RELAY_DEVICE_POLICY)
        );
        phone.charging = true;
        phone.unmetered = false;
        assert_eq!(
            relay_decision(&p, &phone, true, true),
            Err(tokens::RELAY_DEVICE_POLICY)
        );
        phone.relay_override = Some(true);
        assert_eq!(
            relay_decision(&p, &phone, true, true),
            Ok(()),
            "the user overrides"
        );
        let home = DeviceState {
            relay_override: Some(false),
            ..DeviceState::of(DeviceKind::Home)
        };
        assert_eq!(
            relay_decision(&p, &home, true, true),
            Err(tokens::RELAY_DEVICE_POLICY)
        );
        let opted = OnionPolicy {
            relay_opt_out: true,
            ..p.clone()
        };
        assert_eq!(
            relay_decision(&opted, &server, true, true),
            Err(tokens::RELAY_OPTED_OUT)
        );
        let seat = OnionPolicy {
            is_seat: true,
            ..opted
        };
        assert_eq!(
            relay_decision(&seat, &server, true, true),
            Ok(()),
            "a seat cannot opt out"
        );
    }

    /// E14 — a client-only node offers nothing, on Wi-Fi while charging and
    /// with the user's override on. A relay-capable node of phone class keeps
    /// the device rule, for when phones can relay.
    #[test]
    fn a_client_only_node_never_offers_relay() {
        let p = OnionPolicy::default();
        let mut phone = DeviceState::of(DeviceKind::Phone);
        assert!(phone.client_only, "every v44 phone");
        assert!(phone.unmetered && phone.charging);
        assert!(!relay_offering(&p, &phone));
        phone.relay_override = Some(true);
        assert!(!relay_offering(&p, &phone));

        let mut capable = DeviceState::of(DeviceKind::Phone);
        capable.client_only = false;
        assert!(relay_offering(&p, &capable), "Wi-Fi while charging");
        assert!(!relay_offering(&p, &capable.with_network(false, true)));
        assert!(!relay_offering(&p, &capable.with_network(true, false)));
        assert!(relay_offering(&p, &DeviceState::of(DeviceKind::Home)));
    }

    /// CC 5.4.6 rc17 `CLM-referred-peer-is-proxy` — **a node that activated
    /// the tier proxies nothing**: with the opt-in on, no device, override,
    /// seat or availability makes it offer relay, and turning the opt-in off
    /// gives the offer back.
    #[test]
    fn an_onion_enabled_node_never_offers_relay() {
        let on = OnionPolicy {
            enabled: true,
            ..OnionPolicy::default()
        };
        let mut forced = DeviceState::of(DeviceKind::Server);
        forced.relay_override = Some(true);
        for d in [
            DeviceState::of(DeviceKind::Server),
            DeviceState::of(DeviceKind::Home),
            forced,
        ] {
            assert!(relay_offering(&OnionPolicy::default(), &d), "{d:?}");
            assert!(!relay_offering(&on, &d), "{d:?}");
            let seat = OnionPolicy {
                is_seat: true,
                ..on.clone()
            };
            assert!(!relay_offering(&seat, &d), "a seat too: {d:?}");
        }
        // It still relays onion packets once the tier is active.
        assert_eq!(
            relay_decision(&on, &DeviceState::of(DeviceKind::Server), true, true),
            Ok(())
        );
    }
}
