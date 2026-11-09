//! The Anonymous Tier's stable refusal tokens (metric labels, log `reason`
//! fields, the FFI status `reason`). CC-registered names come first; the
//! rest are edge's own (FSD/ONION_ROUTING.md §11) and are submitted beside the
//! packet in `docs/onion_packet_wire.md` §7.

// ─── CC 5.4.6 item 4 (registered) ───
/// The deal leaves a layer under three members this period.
pub const UNAVAILABLE_FLOOR: &str = "onion_tier_unavailable_floor";
/// The deal holds, but fewer than three relays per layer answered within the period.
pub const UNAVAILABLE_LIVENESS: &str = "onion_tier_unavailable_liveness";

// ─── edge: the tier on this node ───
/// The operator has not opted this node into the tier (the v44 default).
pub const NOT_OPTED_IN: &str = "onion_tier_not_opted_in";
/// A relay step on a node whose tier is not running.
pub const RELAY_DORMANT: &str = "onion_relay_dormant";
/// The device policy keeps this node from relaying (a phone not on Wi-Fi and
/// charging, CC 5.4.6 item 1).
pub const RELAY_DEVICE_POLICY: &str = "onion_relay_device_policy";
/// The operator opted this non-seat node out of relaying.
pub const RELAY_OPTED_OUT: &str = "onion_relay_opted_out";
/// No valid hop key: none held, or one equal to another key on the node's
/// occurrence (CC 3.3.6.2, use-time separation).
pub const NO_VALID_HOP_KEY: &str = "onion_no_valid_hop_key";

// ─── edge: the relay step ───
/// An onion packet on an unshaped link (CC 5.4.6 items 4–5: an unshaped link
/// carries no onion packet). Checked before any cryptography.
pub const UNSHAPED_LINK: &str = "onion_unshaped_link";
/// The packet's period is neither this period nor the last.
pub const PERIOD_MISMATCH: &str = "onion_period_mismatch";
/// This hop's encapsulation was already seen within two periods.
pub const REPLAY: &str = "onion_replay";
/// CIRISEdge#955 — this period's replay set already holds its bound of tags
/// (`relay::REPLAY_BOUND`); a new packet is refused, no held tag is evicted
/// (CC 5.3.3.5 E1 rule 9: a hold refuses on overflow by name, never trims).
pub const REPLAY_SET_FULL: &str = "onion_replay_set_full";
/// The relay already holds its bound of packets waiting out their delay.
pub const HOLD_DEFERRED: &str = "onion_hold_deferred";
/// A packet forwarded onto the next hop's shaped link (an outcome, counted).
pub const FORWARDED: &str = "onion_forwarded";
/// A packet this node published onto its first hop's shaped link (counted).
pub const PUBLISHED: &str = "onion_published";
/// No shaped link to the next hop.
pub const NEXT_HOP_UNROUTABLE: &str = "onion_next_hop_unroutable";
/// A final hop's publication has nowhere to go yet: persist has no
/// `pseudonym` identity type or rendezvous gate (CIRISPersist#1149).
pub const EXIT_PENDING_PERSIST: &str = "onion_exit_pending_persist";

// ─── edge: the sender ───
/// The sender's link to its first hop is not shaped.
pub const FIRST_HOP_UNSHAPED: &str = "onion_first_hop_unshaped";
/// A route could not be built (a dealt relay's hop key missing or invalid).
pub const ROUTE_FAILED: &str = "onion_route_failed";

/// Below this many answering relays in some layer the client says the
/// anonymity set is small (CC 5.4.6 items 4 and 8). Not a refusal.
pub const SMALL_SET_PER_LAYER: usize = 10;

// ─── edge: anonymous mode is row-plane only (CC 5.4.3 rc16) ───
/// A call or a stream on a node whose Anonymous Tier is active: a peer in
/// anonymous mode is confined to the row plane.
pub const ANONYMOUS_NO_MEDIA: &str = "onion_anonymous_no_media";
