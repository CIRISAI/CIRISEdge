//! The node's Anonymous Tier state, as the transport and the FFI read it:
//! the operator's policy, the device state, this period's deal and the
//! liveness fold, the relay (when this node relays), refusal counters, and
//! the exit queue. Every decision is one of the pure functions of
//! [`super::policy`]; this type only holds their inputs.
//!
//! **Anonymous mode confines a node to the row plane** (CC 5.4.3 rc16, Eric
//! 2026-11-02): while the tier is ACTIVE here the node starts and joins no
//! call and no stream ([`OnionRuntime::media_allowed`],
//! [`tokens::ANONYMOUS_NO_MEDIA`]). The client shows
//! [`OnionStatus::confines_media`] at opt-in.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};

use super::policy::{relay_decision, small_set, tier_decision, OnionPolicy};
use super::relay::{OnionRelay, RelayAction};
use super::tokens;
use crate::transport::link_shaping::DeviceState;
use crate::transport::onion_layers::{LayerDeal, LAYERS};
use crate::transport::onion_liveness::{Availability, LivenessEvidence, LivenessFold};

/// How many stored publications wait for persist's exit door.
pub const EXIT_QUEUE_BOUND: usize = 64;

/// What the client shows about the tier (counts only, never an identity).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)] // each a separate fact the client shows
pub struct OnionStatus {
    /// The operator opted in.
    pub enabled: bool,
    /// The tier is active here (opted in and available).
    pub active: bool,
    /// Why not, by token.
    pub reason: Option<&'static str>,
    /// Members per layer on this period's deal.
    pub dealt: [usize; LAYERS],
    /// Answering per layer (this node's own measure).
    pub answering: [usize; LAYERS],
    /// This node relays for others now.
    pub relaying: bool,
    /// Why it does not relay, by token.
    pub relay_reason: Option<&'static str>,
    /// Below ten answering in some layer: the client says the set is small.
    pub small_set: bool,
    /// Where the hop key is read from (`transit_kex_pubkeys` until persist
    /// CIRISPersist#1181, then `onion_hop_pubkeys`).
    pub hop_key_source: &'static str,
    /// While active, this node is confined to the row plane: no call, no
    /// stream. Always true: the client shows it at opt-in.
    pub confines_media: bool,
}

#[derive(Debug, Default)]
struct State {
    deal: Option<LayerDeal>,
    liveness: LivenessFold,
    relay: Option<Arc<OnionRelay>>,
}

/// The node's tier.
#[derive(Debug)]
pub struct OnionRuntime {
    own_key_id: String,
    policy: RwLock<OnionPolicy>,
    device: RwLock<DeviceState>,
    state: Mutex<State>,
    counters: Mutex<HashMap<&'static str, u64>>,
    exits: Mutex<VecDeque<Vec<u8>>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl OnionRuntime {
    /// A dormant tier (policy default: not opted in).
    #[must_use]
    pub fn new(own_key_id: impl Into<String>, device: DeviceState) -> Self {
        Self {
            own_key_id: own_key_id.into(),
            policy: RwLock::new(OnionPolicy::default()),
            device: RwLock::new(device),
            state: Mutex::new(State::default()),
            counters: Mutex::new(HashMap::new()),
            exits: Mutex::new(VecDeque::new()),
        }
    }

    /// The operator's policy.
    #[must_use]
    pub fn policy(&self) -> OnionPolicy {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replace the operator's policy (the opt-in switch).
    pub fn set_policy(&self, p: OnionPolicy) {
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = p;
    }

    /// The device state.
    #[must_use]
    pub fn device(&self) -> DeviceState {
        *self
            .device
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Replace the device state (the host reports it).
    pub fn set_device(&self, d: DeviceState) {
        *self
            .device
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = d;
    }

    /// Whether this node's relay offering is on
    /// ([`super::policy::relay_offering`]).
    #[must_use]
    pub fn relay_offering(&self) -> bool {
        super::policy::relay_offering(&self.policy(), &self.device())
    }

    /// Install this period's deal (computed from the fold).
    pub fn install_deal(&self, deal: LayerDeal) {
        lock(&self.state).deal = Some(deal);
    }

    /// Install (or remove) this node's relay: its hop secret(s).
    pub fn set_relay(&self, relay: Option<OnionRelay>) {
        lock(&self.state).relay = relay.map(Arc::new);
    }

    /// Record liveness evidence about a relay.
    pub fn observe(&self, relay: &str, kind: LivenessEvidence) {
        lock(&self.state).liveness.observe(relay, kind);
    }

    /// Whether `relay` answered within the window (for route choice).
    #[must_use]
    pub fn answering(&self, relay: &str) -> bool {
        let st = lock(&self.state);
        let Some(deal) = st.deal.as_ref() else {
            return false;
        };
        let single = LayerDeal {
            period: deal.period,
            layers: [vec![relay.to_owned()], Vec::new(), Vec::new()],
            capped: Vec::new(),
            available: true,
        };
        st.liveness.availability(&single).layers[0].answering == 1
    }

    /// The availability answer now (no deal yet ⇒ the floor fails).
    #[must_use]
    pub fn availability(&self) -> Availability {
        let st = lock(&self.state);
        let empty = LayerDeal {
            period: 0,
            layers: Default::default(),
            capped: Vec::new(),
            available: false,
        };
        st.liveness.availability(st.deal.as_ref().unwrap_or(&empty))
    }

    /// The deal installed, if any.
    #[must_use]
    pub fn deal(&self) -> Option<LayerDeal> {
        lock(&self.state).deal.clone()
    }

    /// Whether the tier is active on this node, or why not.
    ///
    /// # Errors
    /// [`tier_decision`]'s tokens.
    pub fn tier(&self) -> Result<(), &'static str> {
        tier_decision(&self.policy(), &self.availability())
    }

    /// Whether this node relays for others now, or why not.
    ///
    /// # Errors
    /// [`relay_decision`]'s tokens.
    pub fn relaying(&self) -> Result<(), &'static str> {
        let has_key = lock(&self.state).relay.is_some();
        relay_decision(&self.policy(), &self.device(), self.tier().is_ok(), has_key)
    }

    /// **Anonymous mode is row-plane only**: `Err` while the tier is active.
    ///
    /// # Errors
    /// [`tokens::ANONYMOUS_NO_MEDIA`].
    pub fn media_allowed(&self) -> Result<(), &'static str> {
        if self.tier().is_ok() {
            return Err(tokens::ANONYMOUS_NO_MEDIA);
        }
        Ok(())
    }

    /// The peers whose links this node shapes for the tier: as a relay, the
    /// members of the layers next to its own; as a publisher only, layer 1
    /// (its first hops). Empty while the tier is not active.
    #[must_use]
    pub fn layer_peers(&self) -> HashSet<String> {
        if self.tier().is_err() {
            return HashSet::new();
        }
        let relaying = self.relaying().is_ok();
        let st = lock(&self.state);
        let Some(deal) = st.deal.as_ref() else {
            return HashSet::new();
        };
        let mut out: HashSet<String> = deal.layers[0].iter().cloned().collect();
        if relaying {
            if let Some(l) = deal.layer_of(&self.own_key_id) {
                if l > 0 {
                    out.extend(deal.layers[l - 1].iter().cloned());
                }
                if l + 1 < LAYERS {
                    out.extend(deal.layers[l + 1].iter().cloned());
                }
            }
        }
        out.remove(&self.own_key_id);
        out
    }

    /// Count a refusal or an outcome by token.
    pub fn count(&self, token: &'static str) {
        *lock(&self.counters).entry(token).or_insert(0) += 1;
    }

    /// The counters, by token.
    #[must_use]
    pub fn counters(&self) -> HashMap<&'static str, u64> {
        lock(&self.counters).clone()
    }

    /// An onion packet that arrived on a link: relay it, or say why not. A
    /// node whose tier is not running refuses before any cryptography.
    ///
    /// `link_shaped` is transport state, not a caller's claim: the one
    /// production call site (`handle_onion_frame` in
    /// `src/transport/reticulum.rs`) derives it from
    /// `ctx.shapers.is_shaped(link_id)`, the transport's own shaping table for
    /// the link the frame arrived on, which a peer cannot set by saying so.
    /// That frame has already passed the receiver order
    /// (`ReceiverOrder::admit`, CIRISEdge#947) when its link keyed: only a
    /// keyed link's sealed frame opens to reach here. The tests pass both
    /// values deliberately.
    ///
    /// # Errors
    /// [`relay_decision`]'s tokens, then the relay's.
    pub fn accept_inbound(
        &self,
        pkt: &[u8],
        link_shaped: bool,
        now_period: u64,
    ) -> Result<RelayAction, &'static str> {
        let out = self.relaying().and_then(|()| {
            let relay = lock(&self.state)
                .relay
                .clone()
                .ok_or(tokens::NO_VALID_HOP_KEY)?;
            relay.accept(pkt, link_shaped, now_period)
        });
        if let Err(t) = out {
            self.count(t);
        }
        out
    }

    /// A stored publication waits for persist's exit door (bounded; the
    /// oldest goes first).
    pub fn push_exit(&self, payload: Vec<u8>) {
        let mut q = lock(&self.exits);
        if q.len() >= EXIT_QUEUE_BOUND {
            q.pop_front();
        }
        q.push_back(payload);
        drop(q);
        self.count(tokens::EXIT_PENDING_PERSIST);
    }

    /// Take the waiting publications.
    #[must_use]
    pub fn take_exits(&self) -> Vec<Vec<u8>> {
        lock(&self.exits).drain(..).collect()
    }

    /// The client's view.
    #[must_use]
    pub fn status(&self) -> OnionStatus {
        let a = self.availability();
        let tier = self.tier();
        let relay = self.relaying();
        OnionStatus {
            enabled: self.policy().enabled,
            active: tier.is_ok(),
            reason: tier.err(),
            dealt: std::array::from_fn(|l| a.layers[l].dealt),
            answering: std::array::from_fn(|l| a.layers[l].answering),
            relaying: relay.is_ok(),
            relay_reason: relay.err(),
            small_set: small_set(&a),
            hop_key_source: super::hop_key::HOP_KEY_SOURCE.member(),
            confines_media: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion::packet::HopSecret;
    use crate::transport::link_shaping::DeviceKind;
    use crate::transport::onion_layers::{deal_layers, RelayCandidate};

    fn node(id: &str) -> RelayCandidate {
        RelayCandidate {
            key_id: id.to_owned(),
            is_seat: true,
            relay_standing: false,
            row_live: true,
            announced: true,
            hop_key_valid: true,
            opted_out: false,
            owner_bound_under_bundle_root: true,
        }
    }

    fn forced_available(rt: &OnionRuntime, me: &str) {
        let mut ids: Vec<String> = (0..8).map(|i| format!("s{i}")).collect();
        ids.push(me.to_owned());
        let deal = deal_layers(&ids.iter().map(|k| node(k)).collect::<Vec<_>>(), 5, 2);
        assert!(deal.available);
        for k in deal.layers.iter().flatten() {
            rt.observe(k, LivenessEvidence::ShapedLinkUp);
        }
        rt.install_deal(deal);
    }

    /// v44 ships DORMANT: a fresh runtime is not opted in, relays nothing
    /// (refusing before any crypto), names no layer neighbours, and leaves
    /// calls and streams alone.
    #[test]
    fn the_v44_runtime_is_dormant() {
        let rt = OnionRuntime::new("me", DeviceState::of(DeviceKind::Server));
        forced_available(&rt, "me");
        rt.set_relay(Some(OnionRelay::new(
            HopSecret::from_xwing_seed(&[1; 32]).unwrap(),
            None,
        )));
        assert_eq!(rt.tier(), Err(tokens::NOT_OPTED_IN));
        assert_eq!(
            rt.accept_inbound(b"x", true, 5).unwrap_err(),
            tokens::RELAY_DORMANT
        );
        assert!(rt.layer_peers().is_empty());
        assert_eq!(rt.media_allowed(), Ok(()));
        let st = rt.status();
        assert!(!st.active && !st.relaying && st.confines_media);
        assert_eq!(st.hop_key_source, "transit_kex_pubkeys");
        assert_eq!(rt.counters()[tokens::RELAY_DORMANT], 1);
    }

    /// CIRISEdge#955 — a full replay set refuses by name and the runtime
    /// counts it like every other refusal (and the replay of an admitted
    /// packet stays a replay).
    #[test]
    fn a_full_replay_set_is_refused_and_counted_by_name() {
        use crate::onion::packet::{build_packet, HopSpec, RoutingBlock, FLAG_FINAL};
        let rt = OnionRuntime::new("me", DeviceState::of(DeviceKind::Server));
        rt.set_policy(OnionPolicy {
            enabled: true,
            ..OnionPolicy::default()
        });
        forced_available(&rt, "me");
        let secret = || HopSecret::from_xwing_seed(&[1; 32]).unwrap();
        rt.set_relay(Some(OnionRelay::new(secret(), None).with_replay_bound(1)));
        let pkt = || {
            build_packet(
                &[HopSpec {
                    key: secret().public().clone(),
                    block: RoutingBlock {
                        next_dest: [0; 16],
                        flags: FLAG_FINAL,
                        delay_ms: 0,
                        period: 5,
                    },
                }],
                b"p",
            )
            .unwrap()
        };
        let (a, b) = (pkt(), pkt());
        assert!(matches!(
            rt.accept_inbound(&a, true, 5),
            Ok(RelayAction::Store { .. })
        ));
        assert_eq!(
            rt.accept_inbound(&b, true, 5).unwrap_err(),
            tokens::REPLAY_SET_FULL
        );
        assert_eq!(rt.accept_inbound(&a, true, 5).unwrap_err(), tokens::REPLAY);
        let c = rt.counters();
        assert_eq!(c[tokens::REPLAY_SET_FULL], 1);
        assert_eq!(c[tokens::REPLAY], 1);
    }

    /// Opted in and available: the node relays (on shaped links only), its
    /// adjacent layers become layer peers, and **anonymous mode refuses
    /// calls and streams** by name until the tier stops.
    #[test]
    fn an_active_tier_relays_shapes_its_layers_and_refuses_media() {
        let rt = OnionRuntime::new("me", DeviceState::of(DeviceKind::Server));
        rt.set_policy(OnionPolicy {
            enabled: true,
            ..OnionPolicy::default()
        });
        assert_eq!(rt.tier(), Err(tokens::UNAVAILABLE_FLOOR), "no deal yet");
        assert_eq!(rt.media_allowed(), Ok(()));
        forced_available(&rt, "me");
        assert_eq!(rt.tier(), Ok(()));
        assert_eq!(rt.relaying(), Err(tokens::NO_VALID_HOP_KEY));
        rt.set_relay(Some(OnionRelay::new(
            HopSecret::from_xwing_seed(&[1; 32]).unwrap(),
            None,
        )));
        assert_eq!(rt.relaying(), Ok(()));
        assert_eq!(rt.media_allowed(), Err(tokens::ANONYMOUS_NO_MEDIA));
        assert_eq!(
            rt.accept_inbound(b"x", false, 5).unwrap_err(),
            tokens::UNSHAPED_LINK
        );
        let peers = rt.layer_peers();
        let deal = rt.deal().unwrap();
        let mine = deal.layer_of("me").unwrap();
        assert!(!peers.contains("me"));
        for (l, members) in deal.layers.iter().enumerate() {
            let adjacent = l == 0 || l + 1 == mine || l == mine + 1;
            for k in members.iter().filter(|k| *k != "me") {
                assert_eq!(peers.contains(k), adjacent, "layer {l} member {k}");
            }
        }
        // A phone off its charger stops relaying, keeps publishing.
        let mut phone = DeviceState::of(DeviceKind::Phone);
        phone.charging = false;
        rt.set_device(phone);
        assert_eq!(rt.relaying(), Err(tokens::RELAY_DEVICE_POLICY));
        assert_eq!(
            rt.layer_peers(),
            deal.layers[0]
                .iter()
                .filter(|k| *k != "me")
                .cloned()
                .collect()
        );
    }
}
