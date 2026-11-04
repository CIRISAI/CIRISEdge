//! CC 5.4.3 **link shaping** (rc10, `CLM-link-shaping`; CIRISEdge 43.2).
//!
//! A shaped link carries constant-size frames (the link's channel payload
//! MDU) at Poisson times in BOTH directions, whatever either end has to say:
//! real frames when the per-link budget admits one and the queue holds one,
//! cover frames otherwise. A wire observer sees the same stream whether the
//! link is idle or busy; what remains visible is that the link exists and
//! when it was set up, which the CC states. Shaping is a LINK property,
//! negotiated right after the transit KEX in each side's first sealed
//! frame (the `SHAP` offer, [`ShapingOffer`]): the two offers resolve to one
//! agreement by a pure function both ends compute ([`agree`]), so no third
//! message is needed. Either side offering `off` leaves the link unshaped;
//! a node that requires shaped links closes it by name instead. There is
//! never a half-shaped link.
//!
//! Budget classes (`server`, `home`, `phone-wifi`, `phone-cellular`, `off`)
//! name a per-link byte rate; the frame rate λ follows from the agreed frame
//! size. ρ (the real share the budget admits per window) and W (the window)
//! are steward knobs; their defaults come from the measured model (edge's
//! `shaping_measure_e1` harness, 2026-10-22). Only identity-plane links are
//! shaped: audio and video never enter the shaper (they are a burst a GPA
//! can see regardless, CC 5.3.3.2), nor do scoped links.
//!
//! The data path: every outbound edge frame on a shaped link is cut into
//! `CFRG` fragments sized to the shaped frame body and queued on the link's
//! [`LinkShaper`]; the Resource lane is not used on a shaped link (a
//! Resource's parts are leviculum-paced, not Poisson). Each emitted frame is
//! a [`ShapedFrame`] (`SHPF` ‖ kind ‖ length ‖ body ‖ zero pad) sealed under
//! the link's keys. The receiver unwraps after the seal opens: cover is
//! dropped and counted; a real body routes exactly as a Channel frame does.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::emission::{BudgetMeter, BudgetState, PoissonScheduler, ScopeKey};

/// The offer frame's tag.
pub const OFFER_MAGIC: [u8; 4] = *b"SHAP";
/// The shaped frame's tag.
pub const FRAME_MAGIC: [u8; 4] = *b"SHPF";
/// Offer and frame framing version.
pub const SHAPING_VERSION: u8 = 1;
/// `SHAP` ‖ version ‖ class ‖ frame_bytes u16 ‖ rate_milli u32 ‖ rho_milli u16 ‖ window_s u32.
pub const OFFER_LEN: usize = 4 + 1 + 1 + 2 + 4 + 2 + 4;
/// `SHPF` ‖ version ‖ kind ‖ body length u16.
pub const FRAME_HEADER_LEN: usize = 4 + 1 + 1 + 2;
const KIND_COVER: u8 = 0x00;
const KIND_REAL: u8 = 0x01;
/// Several bodies in one frame, each `u16 len ‖ body` (v44; sent only to a
/// peer that announced [`capability_body`]).
const KIND_MULTI: u8 = 0x02;
/// The in-band capability body each end queues on a fresh shaped link:
/// `SHCP` ‖ version. A peer that knows it enables multi-body frames toward
/// the sender; a 43.x peer routes it to its envelope parser and drops it.
pub const CAP_MAGIC: [u8; 4] = *b"SHCP";
/// The capability body's version.
pub const CAP_VERSION: u8 = 1;
/// The least frame rate an offer encodes (`rate_milli` 1). Not a floor on
/// the link: under [`ShapedSharePolicy::DivideNoFloor`] a share runs however
/// small, down to this.
pub const MIN_LAMBDA: f64 = 0.001;
/// The longest budget window an offer may name (one day). `agree` takes the
/// longer of the two windows, so an unbounded one would let a peer switch the
/// budget off on its own link.
pub const MAX_WINDOW_S: u32 = 86_400;
/// The smallest frame worth shaping (a `CFRG` header and some body).
pub const MIN_FRAME_BYTES: u16 = 96;

/// A budget class: a per-link byte rate a node can afford on every shaped
/// link it holds, and how a host names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BudgetClass {
    /// No shaping offered.
    Off = 0,
    /// Metered data, battery: ~350 B/s per link.
    PhoneCellular = 1,
    /// Battery, unmetered: ~1.4 KB/s per link.
    PhoneWifi = 2,
    /// A home uplink: ~2.8 KB/s per link.
    Home = 3,
    /// A server: ~7 KB/s per link.
    Server = 4,
    /// Not a class: the answer to a shaping peer a node at its bound cannot
    /// shape (`link_shaping_home_elsewhere`). `off` for the agreement; the
    /// link closes. A 43.x peer reads it as a malformed class and closes too.
    HomeElsewhere = 5,
    /// CC 5.4.3 rc17 **the `seat` class** (`CLM-seat-class`): offered only on
    /// a link whose two ends both hold a serve seat, proved from the signed
    /// roster and never self-declared; 33,000 B/s, ρ 0.5, W 600 s; its budget
    /// sits outside the eight. On the wire it is the `server` byte with the
    /// higher rate ([`Self::wire_byte`]), so a 43.x peer or a non-seat takes
    /// the lower of the two offers and the link runs at the non-seat's class.
    Seat = 6,
}

/// CC 5.4.3 rc17 — the `seat` row: byte budget per link.
pub const SEAT_BYTES_PER_S: u32 = 33_000;
/// CC 5.4.3 rc17 — the `seat` row: ρ × 1000.
pub const SEAT_RHO_MILLI: u16 = 500;
/// CC 5.4.3 rc17 — the `seat` row: W in seconds.
pub const SEAT_WINDOW_S: u32 = 600;

impl BudgetClass {
    /// The default per-link byte rate of the class (steward knobs may
    /// override; `Off` is zero).
    #[must_use]
    pub const fn default_bytes_per_s(self) -> u32 {
        match self {
            Self::Off | Self::HomeElsewhere => 0,
            Self::Seat => SEAT_BYTES_PER_S,
            Self::PhoneCellular => 350,
            Self::PhoneWifi => 1400,
            Self::Home => 2800,
            Self::Server => 7000,
        }
    }

    /// The stable token (config value, log field, metric label).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::HomeElsewhere => "home-elsewhere",
            Self::Seat => "seat",
            Self::PhoneCellular => "phone-cellular",
            Self::PhoneWifi => "phone-wifi",
            Self::Home => "home",
            Self::Server => "server",
        }
    }

    /// Parse a config token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" | "" | "none" => Some(Self::Off),
            "phone-cellular" | "cellular" => Some(Self::PhoneCellular),
            "phone-wifi" | "wifi" | "phone" => Some(Self::PhoneWifi),
            "home" => Some(Self::Home),
            "server" => Some(Self::Server),
            "seat" => Some(Self::Seat),
            _ => None,
        }
    }

    /// The class byte on the wire: a seat offer travels as `server` (its
    /// rate field carries the tier), so no peer meets an unknown byte.
    #[must_use]
    pub const fn wire_byte(self) -> u8 {
        match self {
            Self::Seat => Self::Server as u8,
            other => other as u8,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Off,
            1 => Self::PhoneCellular,
            2 => Self::PhoneWifi,
            3 => Self::Home,
            4 => Self::Server,
            5 => Self::HomeElsewhere,
            _ => return None,
        })
    }
}

/// This node's shaping policy (config; PyO3/UniFFI mirror it).
#[derive(Debug, Clone, PartialEq)]
pub struct ShapingPolicy {
    /// The class this node offers. `Off` shapes nothing; it is the library's
    /// unconfigured state, not a fleet default: a host names its class, and
    /// the fleet defaults are [`FLEET_DEFAULTS`] (on for `server`, the person's
    /// choice elsewhere).
    pub class: BudgetClass,
    /// The per-link byte rate for `class` (default
    /// [`BudgetClass::default_bytes_per_s`]).
    pub bytes_per_s: u32,
    /// ρ: the real share of a shaped stream the budget admits per window.
    pub rho: f64,
    /// W: the budget window.
    pub window: Duration,
    /// The node-wide cap on the sum of agreed shaped rates, in bytes/s.
    pub node_cap_bytes_per_s: u32,
    /// Close an identity link whose peer offers `off` (or no offer) instead
    /// of running it unshaped.
    pub require_shaped_links: bool,
    /// Which identity links are offered the class: every one, or only this
    /// node's onion layer links (CC 5.4.6 item 4: the tier's activation turns
    /// shaping on for the layer links while the fleet default governs the
    /// rest). See [`FLEET_DEFAULTS`] for which classes shape every link by
    /// default.
    pub scope: ShapingScope,
    /// How the node cap is shared among the shaped links
    /// ([`ShapedSharePolicy`]). One line changes the default.
    pub share: ShapedSharePolicy,
    /// How many of the eight are kept from other peers while onion layer
    /// neighbours named here still have no shaped link
    /// ([`LinkShapers::set_layer_peers`]). Within the eight, never beside them;
    /// zero in effect on a node that does not run the tier.
    pub layer_reserve_links: u32,
}

/// CC 5.4.3 rc17 — **the bound** (`CLM-shaped-link-bound-refuse`): "a node
/// runs at most eight shaped links, each at the full rate of its class; a
/// further peer that offers shaping is refused a row link and told to home
/// elsewhere, and is offered an unshaped bulk link where one exists". The
/// default is [`Self::BoundedWithFloor`]; switching it is the one line in
/// [`ShapingPolicy::for_class`].
///
/// Displacement (`CLM-shaped-link-displacement`) is CIRISEdge#939: until it
/// lands a higher-class newcomer at a full node is refused, not given a slot.
///
/// **The bound is a refusal, never a diluted link.** Every link runs at the
/// one negotiated rate both ways, the class rate, onion layer links included.
/// A layer link counts within the eight; a `seat` link sits outside them. So
/// that a layer neighbour is not shut out by whoever came first, the links
/// other peers may take stop short of the eight by the layer neighbours still
/// waiting, up to [`ShapingPolicy::layer_reserve_links`]
/// ([`LinkShapers::at_bound_for`]); nothing is ever taken from a running link.
///
/// **The accepted leak.** A refused peer still gets an unshaped bulk link
/// (files and calls keep working), and that link is observable: an observer
/// learns the node is at its bound, and the peer's bulk crosses in the clear
/// shape a Resource has. Prior art (Tarzan, Herd) homes the extra peer
/// elsewhere instead; until homing lands (CIRISEdge#935) the spill is the
/// trade-off, and it is bounded: at most one unshaped link per refused peer,
/// never a row link run unshaped.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ShapedSharePolicy {
    /// Every shaping peer is shaped at `cap ÷ shaped links`, however small,
    /// as a local adjustment under the agreed offer. **Not conformant with
    /// CC 5.4.3 rc17** ("refuses rather than run a shaped link below its
    /// class"); kept as the non-default arm, for comparison only.
    DivideNoFloor,
    /// At most `max_links` shaped links, each at `floor_bytes_per_s` (the
    /// class rate); past the bound a shaping peer is REFUSED for rows
    /// (`link_shaping_home_elsewhere`), never run unshaped, and keeps its
    /// unshaped bulk link.
    BoundedWithFloor {
        /// Shaped links at most (eight; `seat` links are outside them).
        max_links: u32,
        /// Each shaped link's rate.
        floor_bytes_per_s: u32,
    },
}

/// Which identity links a node offers shaping on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapingScope {
    /// Every identity link (the fleet default for `server`, `home`,
    /// `phone-wifi`).
    AllIdentityLinks,
    /// Only the onion layer links (the tier's own requirement, CC 5.4.6
    /// item 4); every other link is offered `off`.
    LayerLinksOnly,
}

/// **THE fleet-default table** (CC 5.4.3 rc16; Eric as steward, 2026-11-02,
/// final): per budget class, whether shaping is on for EVERY identity link
/// by default, and what that costs. Shaping is on by default for `server`
/// only; `home`, `phone-wifi` and `phone-cellular` shape every link only when
/// the person opts in ([`DeviceState::shaping_opt_in`]). Whatever the row
/// says, a node running the Anonymous Tier shapes its layer links
/// ([`ShapingScope::LayerLinksOnly`]). Changing a default is a one-line
/// change here; the witness
/// `the_fleet_default_is_on_for_server_only_and_opt_in_elsewhere` reads it.
///
/// **Latency is the other cost** (CC 5.4.3 "the choice is explained before it
/// is made"): a shaped link moves real bytes at ρ of its rate, 3.5 KB/s per
/// peer at `server`, one frame per [`BudgetClass`] gap (2.3 s `server`, 5.8 s
/// `home`, 11.6 s `phone-wifi`, 47 s `phone-cellular`); a row waits about one
/// gap, a reply two or three, and first contact or catch-up several times
/// longer than unshaped (measured: a four-node bootstrap's rounds p90 35 s,
/// p99 165 s against 53 s for the whole bootstrap unshaped). The client shows
/// both columns at opt-in (`docs/LINK_SHAPING_COST.md`).
///
/// The cost columns are what a client shows at the moment of choosing: a
/// shaped link always runs at its class rate (cover fills what real traffic
/// leaves), each way, so at the eight-link node cap a month (30 days) costs
/// `rate × 8 × 2,592,000 s` each way (`docs/LINK_SHAPING_COST.md`).
pub const FLEET_DEFAULTS: [FleetDefault; 5] = [
    // seat <-> seat only (both proved from the signed roster); outside the eight
    FleetDefault {
        class: BudgetClass::Seat,
        on_by_default: true,
        gb_month_per_link_each_way: 85.5,
        gb_month_at_cap_each_way: 684.3,
    },
    // class                         on by default   GB/month/link  GB/month at cap (each way)
    FleetDefault {
        class: BudgetClass::Server,
        on_by_default: true,
        gb_month_per_link_each_way: 18.1,
        gb_month_at_cap_each_way: 145.2,
    },
    FleetDefault {
        class: BudgetClass::Home,
        on_by_default: false,
        gb_month_per_link_each_way: 7.3,
        gb_month_at_cap_each_way: 58.1,
    },
    FleetDefault {
        class: BudgetClass::PhoneWifi,
        on_by_default: false,
        gb_month_per_link_each_way: 3.6,
        gb_month_at_cap_each_way: 29.0,
    },
    FleetDefault {
        class: BudgetClass::PhoneCellular,
        on_by_default: false,
        gb_month_per_link_each_way: 0.9,
        gb_month_at_cap_each_way: 7.3,
    },
];

/// One row of [`FLEET_DEFAULTS`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FleetDefault {
    /// The class.
    pub class: BudgetClass,
    /// Shaping on every identity link without the person opting in.
    pub on_by_default: bool,
    /// One shaped link for a month, each way, in GB (10⁹ bytes).
    pub gb_month_per_link_each_way: f64,
    /// The eight-link cap for a month, each way, in GB.
    pub gb_month_at_cap_each_way: f64,
}

/// The [`FLEET_DEFAULTS`] row for `class` (`None` for `off`).
#[must_use]
pub fn fleet_default_row(class: BudgetClass) -> Option<&'static FleetDefault> {
    FLEET_DEFAULTS.iter().find(|r| r.class == class)
}

/// CC 5.4.3 rc16 **two planes** — the message types that are bulk by kind:
/// content and blob/DAG chunk bodies, and the fetches that ask for them (so
/// the answer finds an unshaped reverse path to ride back on, even to a peer
/// it cannot dial). The WIRE spellings of `crate::messages::MessageType`
/// (serde's default: the variant name), pinned to serde's own output by
/// `bulk_classes_are_the_wire_spelling_of_their_message_types`.
pub const BULK_MESSAGE_TYPES: [&str; 4] = [
    "ContentFetch",
    "ContentBody",
    "BlobChunkFetch",
    "BlobChunkBody",
];

/// CC 5.4.3 rc16 two planes — the largest message a shaped link carries,
/// whatever its type (Eric, 2026-11-04). The shaped link is for small rows:
/// at the `server` class a link's real budget is ρ × 7,000 B/s = 3.5 KB/s, so
/// 64 KiB already takes about 20 s, the most a row should wait. The window
/// budget ([`Agreement::reach_frames`], 2.1 MB at `server`) is NOT this limit:
/// a message that fits it can still take ten minutes. One constant; a larger
/// message rides the bulk plane.
pub const SHAPED_ROW_MAX_BYTES: usize = 64 * 1024;

/// Whether an outbound envelope belongs on the bulk plane whatever link it
/// was offered: bulk by kind ([`is_bulk_class`]) or over
/// [`SHAPED_ROW_MAX_BYTES`].
#[must_use]
pub fn is_bulk_payload(envelope: &[u8]) -> bool {
    envelope.len() > SHAPED_ROW_MAX_BYTES || is_bulk_class(envelope)
}

/// Whether an outbound envelope is bulk by kind ([`BULK_MESSAGE_TYPES`]).
/// Reads only the envelope's head: `message_type` serializes before the body
/// (`crate::messages::EdgeEnvelope`), so a megabyte body is never scanned.
#[must_use]
pub fn is_bulk_class(envelope: &[u8]) -> bool {
    const KEY: &[u8] = b"\"message_type\":\"";
    let head = &envelope[..envelope.len().min(1024)];
    let Some(at) = head.windows(KEY.len()).position(|w| w == KEY) else {
        return false;
    };
    let rest = &head[at + KEY.len()..];
    let Some(end) = rest.iter().position(|&b| b == b'"') else {
        return false;
    };
    BULK_MESSAGE_TYPES
        .iter()
        .any(|t| t.as_bytes() == &rest[..end])
}

/// The default number of the eight kept for waiting layer neighbours.
pub const DEFAULT_LAYER_RESERVE_LINKS: u32 = 4;

/// How many links' worth of the class budget the node cap is (CC 5.4.3).
pub const NODE_CAP_LINKS: u32 = 8;

/// What kind of device a node runs on, for its shaping class and its relay
/// policy (CC 5.4.3 classes; CC 5.4.6 item 1 device policy;
/// FSD/CIRIS_MESH.md §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// A server or a serve seat.
    Server,
    /// A home node (an always-on machine on a home uplink).
    Home,
    /// A phone: its class follows the network it is on.
    Phone,
}

impl DeviceKind {
    /// Parse a host token.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "server" => Some(Self::Server),
            "home" | "desktop" => Some(Self::Home),
            "phone" | "mobile" => Some(Self::Phone),
            _ => None,
        }
    }

    /// The stable token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Home => "home",
            Self::Phone => "phone",
        }
    }

    /// The kind a build assumes before its host says otherwise: a phone on
    /// iOS and Android, else a home node (the cheaper of the two always-on
    /// classes; a server host names itself).
    #[must_use]
    pub const fn platform_default() -> Self {
        if cfg!(any(target_os = "ios", target_os = "android")) {
            Self::Phone
        } else {
            Self::Home
        }
    }
}

/// The device facts a host reports (the mobile/UniFFI surface,
/// `shaping_set_device_state`). They change at runtime: Wi-Fi ↔ cellular,
/// plugged in ↔ on battery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // four independent host facts, each named
pub struct DeviceState {
    /// The device kind.
    pub kind: DeviceKind,
    /// On an unmetered network (Wi-Fi, Ethernet). A phone that is not is on
    /// cellular. Ignored for servers and home nodes.
    pub unmetered: bool,
    /// On external power.
    pub charging: bool,
    /// The person opted into shaping every identity link at their class
    /// (`home`, `phone-wifi`; [`FLEET_DEFAULTS`]). A person's choice, not a
    /// network fact: it is kept when the device moves between Wi-Fi and
    /// cellular ([`Self::with_network`]). A phone chooses each network
    /// separately ([`Self::shaping_opt_in_cellular`]).
    pub shaping_opt_in: bool,
    /// The same choice for `phone-cellular`, its own class with its own cost:
    /// a person can shape on Wi-Fi and not on cellular (`FSD/PRIVACY_MODES.md`
    /// E17). A move to cellular with this off renegotiates to off, and the
    /// move back restores Wi-Fi shaping.
    pub shaping_opt_in_cellular: bool,
    /// A client-only node: it dials and listens for nothing, so it has no slot
    /// to give and is never referred, whatever its network, power or relay
    /// override (`FSD/PRIVACY_MODES.md` E14). Every v44 phone is one
    /// ([`Self::of`]). Off, a phone-class node follows the device policy.
    pub client_only: bool,
    /// The user's relay override, either way (CC 5.4.6 item 1: "the user MAY
    /// override the policy either way"). `None` follows the device policy.
    pub relay_override: Option<bool>,
}

impl DeviceState {
    /// A device of `kind` in its usual state (unmetered, powered, no
    /// overrides). A phone's real state comes from its host.
    #[must_use]
    pub const fn of(kind: DeviceKind) -> Self {
        Self {
            kind,
            unmetered: true,
            charging: true,
            shaping_opt_in: false,
            shaping_opt_in_cellular: false,
            client_only: matches!(kind, DeviceKind::Phone),
            relay_override: None,
        }
    }

    /// Whether the person opted in at the class this device is on now.
    #[must_use]
    pub const fn opted_in_here(&self) -> bool {
        match self.budget_class() {
            BudgetClass::PhoneCellular => self.shaping_opt_in_cellular,
            _ => self.shaping_opt_in,
        }
    }

    /// The same device after a network or power change: the person's
    /// opt-ins and relay override are kept, whatever class the move lands on.
    #[must_use]
    pub const fn with_network(self, unmetered: bool, charging: bool) -> Self {
        Self {
            unmetered,
            charging,
            ..self
        }
    }

    /// The budget class the device offers (CC 5.4.3): a server's and a home
    /// node's own; a phone's follows its network.
    #[must_use]
    pub const fn budget_class(&self) -> BudgetClass {
        match self.kind {
            DeviceKind::Server => BudgetClass::Server,
            DeviceKind::Home => BudgetClass::Home,
            DeviceKind::Phone if self.unmetered => BudgetClass::PhoneWifi,
            DeviceKind::Phone => BudgetClass::PhoneCellular,
        }
    }
}

impl Default for ShapingPolicy {
    fn default() -> Self {
        Self::for_class(BudgetClass::Off)
    }
}

impl ShapingPolicy {
    /// The policy for `class` with the measured defaults (the ρ / W grid of
    /// 2026-10-22, `tests/shaping_measure_e1.rs::m4_rho_window_grid`): ρ = 0.5
    /// everywhere (the real load of the maintenance planes stays well under
    /// half of λ, and a peer never attributes more than half the stream as
    /// real); W = 600 s, except 3600 s for `phone-cellular`, whose λ is so
    /// low that a 600 s window admits only 75–260 real frames and a knee-loaded
    /// link takes minutes to recover. Node cap = eight links' worth.
    #[must_use]
    pub fn for_class(class: BudgetClass) -> Self {
        let bytes_per_s = class.default_bytes_per_s();
        let window = Duration::from_secs(if class == BudgetClass::PhoneCellular {
            3600
        } else {
            600
        });
        Self {
            class,
            bytes_per_s,
            rho: 0.5,
            window,
            node_cap_bytes_per_s: bytes_per_s.saturating_mul(NODE_CAP_LINKS),
            require_shaped_links: false,
            scope: ShapingScope::AllIdentityLinks,
            // THE share policy default (Eric, 2026-11-04). The other arm is
            // `ShapedSharePolicy::DivideNoFloor`.
            share: ShapedSharePolicy::BoundedWithFloor {
                max_links: NODE_CAP_LINKS,
                floor_bytes_per_s: bytes_per_s,
            },
            layer_reserve_links: DEFAULT_LAYER_RESERVE_LINKS,
        }
    }

    /// **The fleet default for `class`** ([`FLEET_DEFAULTS`]): every identity
    /// link when the class is on by default, else the layer links only (so a
    /// node running the tier still shapes them). `off` stays off.
    #[must_use]
    pub fn fleet_default(class: BudgetClass) -> Self {
        let mut p = Self::for_class(class);
        if !fleet_default_row(class).is_some_and(|r| r.on_by_default) {
            p.scope = ShapingScope::LayerLinksOnly;
        }
        p
    }

    /// The fleet default for a device in its current state, widened to every
    /// identity link when the person opted in at that class
    /// ([`DeviceState::opted_in_here`]).
    #[must_use]
    pub fn for_device(d: &DeviceState) -> Self {
        let mut p = Self::fleet_default(d.budget_class());
        if d.opted_in_here() {
            p.scope = ShapingScope::AllIdentityLinks;
        }
        p
    }

    /// Whether this node offers shaping at all (on some link).
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.class != BudgetClass::Off && self.bytes_per_s > 0
    }

    /// Whether a link is offered this node's class: a layer link whenever
    /// shaping is enabled, any other identity link only under
    /// [`ShapingScope::AllIdentityLinks`].
    #[must_use]
    pub fn offers_on(&self, layer_link: bool) -> bool {
        self.enabled() && (layer_link || self.scope == ShapingScope::AllIdentityLinks)
    }

    /// Bytes one shaped link costs each way over a 30-day month at the
    /// class rate (cover and real together: a shaped link always runs at λ).
    #[must_use]
    pub fn monthly_bytes_per_link(&self) -> u64 {
        u64::from(self.bytes_per_s) * 30 * 86_400
    }
}

/// One side's offer: what it can afford on THIS link, right now.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ShapingOffer {
    /// The class (informational beyond `Off`; the rate is what binds).
    pub class: BudgetClass,
    /// The frame size this side will send and accept: its channel payload
    /// MDU on the link.
    pub frame_bytes: u16,
    /// λ × 1000, frames per second this side can afford here (after its
    /// node-wide cap). Zero with `class == Off`.
    pub rate_milli: u32,
    /// ρ × 1000.
    pub rho_milli: u16,
    /// W in seconds.
    pub window_s: u32,
}

impl ShapingOffer {
    /// The refusal of a shaping peer at the bound (`off` on the wire, with
    /// its reason; [`ShapedSharePolicy::BoundedWithFloor`]).
    #[must_use]
    pub const fn home_elsewhere() -> Self {
        Self {
            class: BudgetClass::HomeElsewhere,
            frame_bytes: 0,
            rate_milli: 0,
            rho_milli: 0,
            window_s: 0,
        }
    }

    /// Whether this offer shapes (neither `off` nor a refusal).
    #[must_use]
    pub const fn shapes(&self) -> bool {
        !matches!(self.class, BudgetClass::Off | BudgetClass::HomeElsewhere)
    }

    /// The `seat` class's offer on a seat-to-seat link (CC 5.4.3 rc17): the
    /// table's row at the link's frame, whatever this node's own settings.
    #[must_use]
    pub fn seat(frame_bytes: usize) -> Self {
        let frame = u16::try_from(frame_bytes.min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
        if frame < MIN_FRAME_BYTES {
            return Self::off();
        }
        let lambda = f64::from(SEAT_BYTES_PER_S) / f64::from(frame);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rate_milli = (lambda * 1000.0).round().max(1.0) as u32;
        Self {
            class: BudgetClass::Seat,
            frame_bytes: frame,
            rate_milli,
            rho_milli: SEAT_RHO_MILLI,
            window_s: SEAT_WINDOW_S,
        }
    }

    /// The `off` offer.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            class: BudgetClass::Off,
            frame_bytes: 0,
            rate_milli: 0,
            rho_milli: 0,
            window_s: 0,
        }
    }

    /// Build this node's offer for a link whose channel payload MDU is
    /// `frame_bytes`: the class rate, whatever the node's other links.
    ///
    /// The node-wide cap is deliberately NOT in the offer. An offer is an upper
    /// bound for the link's life, and the cap is divided across the links a
    /// node holds now ([`LinkShapers::rebalance`]), which changes as peers
    /// come and go; quoting today's share would pin a link low for good, and
    /// quoting nothing left would be `off`, leaving a shaping peer unshaped.
    /// A slow rate is quoted as it is ([`MIN_LAMBDA`] at the least), never
    /// turned off.
    #[must_use]
    pub fn from_policy(policy: &ShapingPolicy, frame_bytes: usize) -> Self {
        if !policy.enabled() {
            return Self::off();
        }
        let frame = u16::try_from(frame_bytes.min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
        if frame < MIN_FRAME_BYTES {
            return Self::off();
        }
        let lambda = (f64::from(policy.bytes_per_s) / f64::from(frame)).max(MIN_LAMBDA);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rate_milli = (lambda * 1000.0).round().max(1.0) as u32;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let rho_milli = (policy.rho.clamp(0.01, 1.0) * 1000.0).round() as u16;
        Self {
            class: policy.class,
            frame_bytes: frame,
            rate_milli,
            rho_milli,
            window_s: u32::try_from(policy.window.as_secs().max(1)).unwrap_or(u32::MAX),
        }
    }

    /// Encode as the `SHAP` frame.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(OFFER_LEN);
        out.extend_from_slice(&OFFER_MAGIC);
        out.push(SHAPING_VERSION);
        out.push(self.class.wire_byte());
        out.extend_from_slice(&self.frame_bytes.to_be_bytes());
        out.extend_from_slice(&self.rate_milli.to_be_bytes());
        out.extend_from_slice(&self.rho_milli.to_be_bytes());
        out.extend_from_slice(&self.window_s.to_be_bytes());
        out
    }

    /// Decode a `SHAP` frame.
    ///
    /// # Errors
    /// [`ShapingError::NotAnOffer`] / [`ShapingError::Malformed`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ShapingError> {
        if !is_offer(bytes) {
            return Err(ShapingError::NotAnOffer);
        }
        if bytes.len() != OFFER_LEN {
            return Err(ShapingError::Malformed("offer length"));
        }
        if bytes[4] != SHAPING_VERSION {
            return Err(ShapingError::Malformed("offer version"));
        }
        let class = BudgetClass::from_byte(bytes[5]).ok_or(ShapingError::Malformed("class"))?;
        let be16 = |i: usize| u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        let be32 =
            |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        let offer = Self {
            class,
            frame_bytes: be16(6),
            rate_milli: be32(8),
            rho_milli: be16(12),
            window_s: be32(14),
        };
        if offer.shapes()
            && (offer.rate_milli == 0
                || offer.frame_bytes < MIN_FRAME_BYTES
                || offer.rho_milli == 0
                || offer.rho_milli > 1000
                || offer.window_s == 0
                || offer.window_s > MAX_WINDOW_S)
        {
            return Err(ShapingError::Malformed("offer values"));
        }
        Ok(offer)
    }
}

/// Whether `bytes` is a `SHAP` offer.
#[must_use]
pub fn is_offer(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == OFFER_MAGIC
}

/// The capability body: `SHCP` ‖ version ‖ the free slots this node reports,
/// zero when its relay offering is off ([`LinkShapers::reported_slots`]).
/// It is queued on a fresh shaped link, and on every shaped link when the free
/// slots change ([`LinkShapers::free_slots`]). It rides inside the constant
/// frames, never in the fixed-length `SHAP` offer, so a 43.x peer is
/// unaffected. A report is a hint ([`crate::transport::shaping_referral`]).
#[must_use]
pub fn capability_body(free_slots: u8) -> Vec<u8> {
    let mut v = CAP_MAGIC.to_vec();
    v.push(CAP_VERSION);
    v.push(free_slots);
    v
}

/// Whether a real body is a peer's capability announcement.
#[must_use]
pub fn is_capability_body(body: &[u8]) -> bool {
    body.len() == CAP_MAGIC.len() + 2 && body[..4] == CAP_MAGIC
}

/// The free slots a capability body reports.
#[must_use]
pub fn capability_free_slots(body: &[u8]) -> Option<u8> {
    is_capability_body(body).then(|| body[CAP_MAGIC.len() + 1])
}

/// Whether `bytes` is a `SHPF` shaped frame.
#[must_use]
pub fn is_shaped_frame(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == FRAME_MAGIC
}

/// What two offers resolve to; both ends compute it from the same inputs.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Agreement {
    /// Frames per second on the link, each way.
    pub lambda: f64,
    /// The frame size, each way.
    pub frame_bytes: u16,
    /// ρ.
    pub rho: f64,
    /// W.
    pub window: Duration,
}

impl Agreement {
    /// CC 5.4.3 rc16 **two planes** — the most real frames one message may
    /// take on this link: the real-frame budget of one window,
    /// `ceil(ρ·λ·W)` (and never more than the queue holds). A message within
    /// it is a row (a post, a message, a reaction, a small image) and rides
    /// the shaped row plane; one beyond it is bulk and is refused at the
    /// shaper by name ([`ShapingError::BulkBeyondReach`]): bulk and live
    /// media ride unshaped links of their own and make no shaping claim.
    /// (The queue's own bound is a separate, retryable refusal.)
    #[must_use]
    pub fn reach_frames(&self) -> usize {
        self.reach_frames_at(self.lambda)
    }

    /// [`Self::reach_frames`] at a frame rate other than the agreed one.
    #[must_use]
    pub fn reach_frames_at(&self, lambda: f64) -> usize {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let r = (self.rho * lambda * self.window.as_secs_f64())
            .ceil()
            .max(1.0) as usize;
        r
    }

    /// Bytes per second this agreement costs each way.
    #[must_use]
    pub fn bytes_per_s(&self) -> u32 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let b = (self.lambda * f64::from(self.frame_bytes)).round() as u32;
        b
    }
}

/// The negotiation: `None` when either side is `off` (the link runs
/// unshaped); otherwise the lower rate, the smaller frame, the smaller ρ and
/// the longer W — each the more conservative of the two.
#[must_use]
pub fn agree(a: &ShapingOffer, b: &ShapingOffer) -> Option<Agreement> {
    if !a.shapes() || !b.shapes() {
        return None;
    }
    let frame_bytes = a.frame_bytes.min(b.frame_bytes);
    // Both rates were quoted at each side's own frame size; re-quote the
    // byte budget at the agreed frame so the smaller frame does not
    // silently cost the larger budget.
    let bytes = |o: &ShapingOffer| f64::from(o.rate_milli) / 1000.0 * f64::from(o.frame_bytes);
    let lambda = bytes(a).min(bytes(b)) / f64::from(frame_bytes);
    let rho = f64::from(a.rho_milli.min(b.rho_milli)) / 1000.0;
    let window = Duration::from_secs(u64::from(a.window_s.max(b.window_s)));
    Some(Agreement {
        lambda,
        frame_bytes,
        rho,
        window,
    })
}

/// Why shaping was refused or a frame dropped. Named and counted.
#[derive(Debug, thiserror::Error)]
pub enum ShapingError {
    /// The frame in the offer's place is not an offer.
    #[error("not a shaping offer")]
    NotAnOffer,
    /// A malformed offer or shaped frame.
    #[error("shaping framing: {0}")]
    Malformed(&'static str),
    /// The peer offered `off` and this node requires shaped links.
    #[error("the peer offers no shaping and this node requires shaped links")]
    UnshapedPeer,
    /// A shaping peer past this node's bound, or this node past the peer's:
    /// the row link is refused, never run unshaped; bulk still has its own
    /// unshaped link ([`ShapedSharePolicy::BoundedWithFloor`]).
    #[error(
        "a shaping peer past the shaped-link bound: homed elsewhere (link_shaping_home_elsewhere)"
    )]
    HomeElsewhere,
    /// A shaped frame on an unshaped link, or a bare frame on a shaped one.
    #[error("a frame of the wrong kind for this link's shaping state: {0}")]
    WrongKind(&'static str),
    /// The link's queue is full: the caller defers and retries.
    #[error("the shaped link's queue is full ({0} frames)")]
    QueueFull(usize),
    /// A body larger than the shaped frame carries.
    #[error("a {0}-byte body does not fit a {1}-byte shaped frame")]
    BodyTooLarge(usize, usize),
    /// A message of more frames than the link's real-frame budget for one
    /// window: bulk, which never rides the shaped row plane.
    #[error("a {0}-frame message is beyond the shaped link's reach of {1} frames (bulk rides an unshaped link)")]
    BulkBeyondReach(usize, usize),
}

impl ShapingError {
    /// The `link_shaping` metric label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        use crate::observability as o;
        match self {
            Self::NotAnOffer | Self::Malformed(_) | Self::BodyTooLarge(..) => {
                o::LINK_SHAPING_REFUSED_MALFORMED
            }
            Self::UnshapedPeer => o::LINK_SHAPING_REFUSED_UNSHAPED_PEER,
            Self::HomeElsewhere => o::LINK_SHAPING_HOME_ELSEWHERE,
            Self::WrongKind(_) => o::LINK_SHAPING_DROPPED_WRONG_KIND,
            Self::QueueFull(_) => o::LINK_SHAPING_QUEUE_DEFERRED,
            Self::BulkBeyondReach(..) => o::LINK_SHAPING_BULK_REFUSED,
        }
    }
}

/// A shaped frame's body, once unwrapped.
#[derive(Debug, PartialEq, Eq)]
pub enum ShapedFrame {
    /// A cover frame: nothing inside.
    Cover,
    /// A real frame carrying `body` (a whole frame or one `CFRG` fragment).
    Real(Vec<u8>),
    /// A real frame carrying several bodies (v44 coalescing).
    Many(Vec<Vec<u8>>),
}

/// The body bytes one shaped frame of `frame_bytes` carries.
#[must_use]
pub fn body_capacity(frame_bytes: u16) -> usize {
    usize::from(frame_bytes).saturating_sub(FRAME_HEADER_LEN)
}

/// Wrap `body` (or cover) as one `frame_bytes`-sized frame.
///
/// # Errors
/// [`ShapingError::BodyTooLarge`].
pub fn wrap(
    frame_bytes: u16,
    body: Option<&[u8]>,
    pad: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, ShapingError> {
    let cap = body_capacity(frame_bytes);
    let body_len = body.map_or(0, <[u8]>::len);
    if body_len > cap {
        return Err(ShapingError::BodyTooLarge(
            body_len,
            usize::from(frame_bytes),
        ));
    }
    let mut out = vec![0u8; usize::from(frame_bytes)];
    out[..4].copy_from_slice(&FRAME_MAGIC);
    out[4] = SHAPING_VERSION;
    out[5] = if body.is_some() {
        KIND_REAL
    } else {
        KIND_COVER
    };
    #[allow(clippy::cast_possible_truncation)]
    let len = body_len as u16;
    out[6..8].copy_from_slice(&len.to_be_bytes());
    if let Some(b) = body {
        out[FRAME_HEADER_LEN..FRAME_HEADER_LEN + b.len()].copy_from_slice(b);
    }
    // The pad is random: a cover frame's plaintext never repeats, so even a
    // key compromise does not expose which frames were cover.
    pad(&mut out[FRAME_HEADER_LEN + body_len..]);
    Ok(out)
}

/// Wrap several bodies as one `frame_bytes`-sized multi frame: the inner
/// framing is `u16 len ‖ body` repeated; the header's length is the inner
/// total.
///
/// # Errors
/// [`ShapingError::BodyTooLarge`] when they do not fit together.
pub fn wrap_multi(
    frame_bytes: u16,
    bodies: &[Vec<u8>],
    pad: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, ShapingError> {
    let cap = body_capacity(frame_bytes);
    let inner: usize = bodies.iter().map(|b| 2 + b.len()).sum();
    if inner > cap || bodies.iter().any(|b| b.len() > usize::from(u16::MAX)) {
        return Err(ShapingError::BodyTooLarge(inner, usize::from(frame_bytes)));
    }
    let mut out = vec![0u8; usize::from(frame_bytes)];
    out[..4].copy_from_slice(&FRAME_MAGIC);
    out[4] = SHAPING_VERSION;
    out[5] = KIND_MULTI;
    #[allow(clippy::cast_possible_truncation)]
    let len = inner as u16;
    out[6..8].copy_from_slice(&len.to_be_bytes());
    let mut at = FRAME_HEADER_LEN;
    for b in bodies {
        #[allow(clippy::cast_possible_truncation)]
        let l = b.len() as u16;
        out[at..at + 2].copy_from_slice(&l.to_be_bytes());
        out[at + 2..at + 2 + b.len()].copy_from_slice(b);
        at += 2 + b.len();
    }
    pad(&mut out[at..]);
    Ok(out)
}

/// Unwrap one shaped frame.
///
/// # Errors
/// [`ShapingError::Malformed`] / [`ShapingError::WrongKind`].
pub fn unwrap(bytes: &[u8]) -> Result<ShapedFrame, ShapingError> {
    if !is_shaped_frame(bytes) {
        return Err(ShapingError::WrongKind("not a shaped frame"));
    }
    if bytes.len() < FRAME_HEADER_LEN || bytes[4] != SHAPING_VERSION {
        return Err(ShapingError::Malformed("shaped frame header"));
    }
    let len = usize::from(u16::from_be_bytes([bytes[6], bytes[7]]));
    if FRAME_HEADER_LEN + len > bytes.len() {
        return Err(ShapingError::Malformed("shaped frame length"));
    }
    match bytes[5] {
        KIND_COVER => Ok(ShapedFrame::Cover),
        KIND_REAL => Ok(ShapedFrame::Real(
            bytes[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len].to_vec(),
        )),
        KIND_MULTI => {
            let inner = &bytes[FRAME_HEADER_LEN..FRAME_HEADER_LEN + len];
            let mut bodies = Vec::new();
            let mut at = 0usize;
            while at < inner.len() {
                if at + 2 > inner.len() {
                    return Err(ShapingError::Malformed("multi frame body length"));
                }
                let l = usize::from(u16::from_be_bytes([inner[at], inner[at + 1]]));
                if at + 2 + l > inner.len() {
                    return Err(ShapingError::Malformed("multi frame body"));
                }
                bodies.push(inner[at + 2..at + 2 + l].to_vec());
                at += 2 + l;
            }
            Ok(ShapedFrame::Many(bodies))
        }
        _ => Err(ShapingError::Malformed("shaped frame kind")),
    }
}

/// What the shaper hands the sender on each timer fire.
#[derive(Debug)]
pub enum Emission {
    /// Send this frame (already wrapped; the caller seals it). `real` says
    /// whether it carries a body (for the ledger only; the wire cannot tell).
    Frame {
        /// The wrapped, padded frame.
        bytes: Vec<u8>,
        /// Real (a queued body) or cover.
        real: bool,
        /// The highest body ticket the frame carries (0 for cover): the
        /// sender reports it as sent ([`LinkShaper::note_sent`]).
        ticket: u64,
    },
    /// The link is gone.
    Stopped,
}

/// The dial's end of an offer: whether the link came out shaped, or the
/// refusal the peer's answer earned.
pub type OfferAnswerRx = tokio::sync::oneshot::Receiver<Result<bool, ShapingError>>;
type OfferAnswerTx = tokio::sync::oneshot::Sender<Result<bool, ShapingError>>;
/// How long a dialler waits for the peer's offer after sending its own.
pub const OFFER_ANSWER_BUDGET: Duration = Duration::from_secs(10);

/// One shaped link's sender-side state: the queue of real bodies, the
/// Poisson timer and the budget meter.
pub struct LinkShaper {
    agreement: Agreement,
    queue: Mutex<VecDeque<(u64, Vec<u8>)>>,
    queue_cap: usize,
    /// The peer announced multi-body frames ([`capability_body`]).
    coalesce: std::sync::atomic::AtomicBool,
    notify: Notify,
    poisson: PoissonScheduler,
    scope: ScopeKey,
    budget: BudgetMeter,
    real: AtomicU64,
    cover: AtomicU64,
    /// Bodies ever queued, in FIFO order: a body's ticket is this count once
    /// it is queued ([`Self::enqueue_bulk_fallback`]).
    accepted: AtomicU64,
    /// Real frames the link really took ([`Self::note_real_sent`]). Serial and
    /// The highest ticket among the bodies the link really took
    /// ([`Self::note_sent`]); FIFO with `accepted`, so a ticket at or below
    /// it has left this node.
    last_sent: AtomicU64,
    /// This sender's frame rate now (`f64` bits): the agreed λ, or lower when
    /// the node's cap is divided across more links ([`Self::set_share`]).
    lambda_now: AtomicU64,
    /// When the shaper was installed ([`Self::in_transition`]).
    installed: std::time::Instant,
    stopped: std::sync::atomic::AtomicBool,
    /// When the next frame is due, as an absolute instant (see
    /// [`Self::next_emission`]).
    next_due: Mutex<Option<tokio::time::Instant>>,
}

impl std::fmt::Debug for LinkShaper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkShaper")
            .field("agreement", &self.agreement)
            .field("queued", &self.queued())
            .finish_non_exhaustive()
    }
}

impl LinkShaper {
    /// A shaper for `link` under `agreement`, holding at most `queue_cap`
    /// bodies.
    #[must_use]
    pub fn new(link: [u8; 16], agreement: Agreement, queue_cap: usize) -> Self {
        Self::with_scheduler(link, agreement, queue_cap, PoissonScheduler::new())
    }

    /// [`Self::new`] on a seeded timer (tests: a deterministic frame stream).
    #[must_use]
    pub fn new_seeded(
        link: [u8; 16],
        agreement: Agreement,
        queue_cap: usize,
        seed: [u8; 32],
    ) -> Self {
        Self::with_scheduler(
            link,
            agreement,
            queue_cap,
            PoissonScheduler::from_seed(seed),
        )
    }

    fn with_scheduler(
        link: [u8; 16],
        agreement: Agreement,
        queue_cap: usize,
        poisson: PoissonScheduler,
    ) -> Self {
        let scope = ScopeKey::community(format!("link:{}", hex::encode(link)));
        poisson.set_rate(scope.clone(), agreement.lambda);
        let budget = BudgetMeter::new();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let target =
            (agreement.rho * agreement.lambda * agreement.window.as_secs_f64()).ceil() as u32;
        budget.configure(scope.clone(), target.max(1), agreement.window);
        Self {
            agreement,
            queue: Mutex::new(VecDeque::new()),
            queue_cap,
            coalesce: std::sync::atomic::AtomicBool::new(false),
            notify: Notify::new(),
            poisson,
            scope,
            budget,
            real: AtomicU64::new(0),
            cover: AtomicU64::new(0),
            accepted: AtomicU64::new(0),
            last_sent: AtomicU64::new(0),
            lambda_now: AtomicU64::new(agreement.lambda.to_bits()),
            installed: std::time::Instant::now(),
            stopped: std::sync::atomic::AtomicBool::new(false),
            next_due: Mutex::new(None),
        }
    }

    /// The instant the next frame is due: the previous frame's due instant
    /// plus one Poisson interval.
    ///
    /// The timer used to sleep each interval relative to the moment it woke.
    /// A late wake (a starved runtime, a busy phone) then delayed every later
    /// frame too, so a window emitted fewer than λ·W frames while the real
    /// budget stayed the nominal `ceil(ρ·λ·W)`, and the real share on the wire
    /// rose above ρ: 0.35–0.39 at ρ = 0.25 on one core (CIRISEdge#905).
    /// Deadlines on the Poisson process's own arrival times catch up after a
    /// late wake, so the window emits its λ·W frames and the budget's share
    /// holds. A stall longer than one window is not repaid with a burst of
    /// cover: the schedule restarts from `now`.
    fn schedule_next(&self, wait: Duration, now: tokio::time::Instant) -> tokio::time::Instant {
        let mut next = self
            .next_due
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let from = match *next {
            Some(prev) if now.saturating_duration_since(prev) <= self.agreement.window => prev,
            _ => now,
        };
        let due = from + wait;
        *next = Some(due);
        due
    }

    /// The agreement in force.
    #[must_use]
    pub fn agreement(&self) -> &Agreement {
        &self.agreement
    }

    /// Bodies waiting.
    #[must_use]
    pub fn queued(&self) -> usize {
        self.queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Real and cover frames emitted so far.
    #[must_use]
    pub fn emitted(&self) -> (u64, u64) {
        (
            self.real.load(Ordering::Relaxed),
            self.cover.load(Ordering::Relaxed),
        )
    }

    /// Queue the bodies of one frame (each at most [`body_capacity`]), all
    /// or none.
    ///
    /// # Errors
    /// [`ShapingError::QueueFull`] (the caller defers), [`ShapingError::BodyTooLarge`].
    pub fn enqueue(&self, bodies: Vec<Vec<u8>>) -> Result<u64, ShapingError> {
        let reach = self.reach_frames_now();
        if bodies.len() > reach {
            return Err(ShapingError::BulkBeyondReach(bodies.len(), reach));
        }
        self.enqueue_within_queue(bodies)
    }

    /// The mean gap between this sender's frames now (`1 / λ`).
    #[must_use]
    pub fn frame_gap(&self) -> Duration {
        Duration::from_secs_f64(1.0 / self.lambda_now().max(MIN_LAMBDA))
    }

    /// How long to allow for `frames` queued bodies to leave: the Poisson
    /// p99 of that many gaps (about 4.74 gaps for one; `frames + 4.74 × √frames`
    /// for many), plus a margin, plus the window when the ρ budget cannot
    /// admit them before it rolls; never more than [`ROW_LEAVE_MAX`] or
    /// [`ROW_LEAVE_MAX_GAPS`] gaps, the larger (a sender that waited that long
    /// retracts and retries). The bound a sender waits before calling a queued
    /// row undelivered ([`Self::ticket_left`]).
    #[must_use]
    pub fn leave_budget(&self, frames: usize) -> Duration {
        #[allow(clippy::cast_precision_loss)]
        let n = frames.max(1) as f64;
        let gaps = n + 4.74 * n.sqrt();
        let mut d = self.frame_gap().mul_f64(gaps) + Duration::from_secs(5);
        if frames > usize::try_from(self.real_remaining()).unwrap_or(usize::MAX) {
            d += self.agreement.window;
        }
        d.min(ROW_LEAVE_MAX.max(self.frame_gap().mul_f64(ROW_LEAVE_MAX_GAPS)))
    }

    /// Whether every body up to `ticket` has left this node.
    #[must_use]
    pub fn ticket_left(&self, ticket: u64) -> bool {
        self.last_sent.load(Ordering::Acquire) >= ticket
    }

    /// This sender's frame rate now.
    #[must_use]
    pub fn lambda_now(&self) -> f64 {
        f64::from_bits(self.lambda_now.load(Ordering::Acquire))
    }

    /// Bytes per second this sender emits on the link now.
    #[must_use]
    pub fn bytes_per_s_now(&self) -> f64 {
        self.lambda_now() * f64::from(self.agreement.frame_bytes)
    }

    /// One window's real-frame budget at this sender's rate now.
    #[must_use]
    pub fn reach_frames_now(&self) -> usize {
        self.agreement.reach_frames_at(self.lambda_now())
    }

    /// Apply this link's share of the node cap: a LOCAL, downward adjustment.
    /// The agreement stays the upper bound for the link's life, and this
    /// sender runs at `min(agreed λ, share)`, down to [`MIN_LAMBDA`]. No frame crosses the wire for it, so a peer joining costs the
    /// other links nothing, and a share rises again when peers leave. The two
    /// directions of a link can then differ, which shows only each sender's
    /// own link count, never its traffic. The real budget follows the rate,
    /// and keeps the window's counts ([`BudgetMeter::set_target`]).
    pub fn set_share(&self, bytes_per_s: f64) {
        let lambda = (bytes_per_s / f64::from(self.agreement.frame_bytes))
            .min(self.agreement.lambda)
            .max(MIN_LAMBDA);
        if lambda.to_bits() == self.lambda_now.swap(lambda.to_bits(), Ordering::AcqRel) {
            return;
        }
        self.poisson.set_rate(self.scope.clone(), lambda);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let target =
            (self.agreement.rho * lambda * self.agreement.window.as_secs_f64()).ceil() as u32;
        self.budget.set_target(&self.scope, target.max(1));
    }

    /// Whether the link is still inside the switch to shaped. The two ends
    /// cannot install their shapers at one instant: a frame the peer sent
    /// bare just before it installed can land just after this end did. That
    /// is a race of the handshake, not a half-shaped link, so it is delivered;
    /// past [`OFFER_ANSWER_BUDGET`] a bare frame is refused as ever.
    #[must_use]
    pub fn in_transition(&self) -> bool {
        self.installed.elapsed() < OFFER_ANSWER_BUDGET
    }

    /// The emission task's report: the frame carrying bodies up to `ticket`
    /// was taken by the link.
    pub fn note_sent(&self, ticket: u64) {
        self.last_sent.fetch_max(ticket, Ordering::AcqRel);
    }

    /// The peer announced multi-body frames: pack from here.
    pub fn enable_coalescing(&self) {
        self.coalesce.store(true, Ordering::Release);
    }

    /// Whether this sender packs several bodies per frame.
    #[must_use]
    pub fn coalescing(&self) -> bool {
        self.coalesce.load(Ordering::Acquire)
    }

    /// Take back the queued bodies with tickets in `lo..=hi` that have not
    /// left yet (a sender giving up its wait, so a retry does not send them
    /// twice). Returns how many were removed.
    pub fn retract(&self, lo: u64, hi: u64) -> usize {
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = q.len();
        q.retain(|(t, _)| *t < lo || *t > hi);
        before - q.len()
    }

    /// Real frames this window's budget still admits.
    #[must_use]
    pub fn real_remaining(&self) -> u32 {
        match self.budget.query(&self.scope) {
            BudgetState::UnderBudget { real_remaining, .. } => real_remaining,
            BudgetState::OverBudget { .. } | BudgetState::Unconfigured => 0,
        }
    }

    /// Whether the shaper was stopped (its link closed or was renegotiated).
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// The queue's free room, in bodies.
    #[must_use]
    pub fn room(&self) -> usize {
        self.queue_cap.saturating_sub(self.queued())
    }

    /// CC 5.4.3 rc16 two planes — the LAST-RESORT bulk path: queue part of a
    /// bulk message on this shaped link without the reach check, for a peer
    /// no unshaped link can exist to (a NAT'd peer this node cannot dial).
    /// The shaper still paces every body at the agreed λ under the ρ budget,
    /// so the link stays constant-size and constant-rate; the message is only
    /// slow. The caller feeds it in pieces as [`Self::room`] allows. Returns
    /// the last body's ticket: it has left this node once [`Self::real_sent`]
    /// reaches it.
    ///
    /// # Errors
    /// As [`Self::enqueue`], less the reach refusal.
    pub fn enqueue_bulk_fallback(&self, bodies: Vec<Vec<u8>>) -> Result<u64, ShapingError> {
        self.enqueue_within_queue(bodies)
    }

    fn enqueue_within_queue(&self, bodies: Vec<Vec<u8>>) -> Result<u64, ShapingError> {
        let cap = body_capacity(self.agreement.frame_bytes);
        if let Some(b) = bodies.iter().find(|b| b.len() > cap) {
            return Err(ShapingError::BodyTooLarge(
                b.len(),
                usize::from(self.agreement.frame_bytes),
            ));
        }
        let mut q = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if q.len() + bodies.len() > self.queue_cap {
            return Err(ShapingError::QueueFull(self.queue_cap));
        }
        let count = u64::try_from(bodies.len()).unwrap_or(u64::MAX);
        let first = self.accepted.fetch_add(count, Ordering::AcqRel) + 1;
        for (ticket, b) in (first..).zip(bodies) {
            q.push_back((ticket, b));
        }
        drop(q);
        self.notify.notify_one();
        Ok(first + count - 1)
    }

    /// Stop the timer loop (the link closed).
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// Wait one Poisson interval, then produce the next frame: the head real
    /// body when the budget admits one, else cover.
    pub async fn next_emission(&self) -> Emission {
        if self.stopped.load(Ordering::Relaxed) {
            return Emission::Stopped;
        }
        let wait = self
            .poisson
            .next_interval(&self.scope)
            .unwrap_or(Duration::from_secs(1));
        let due = self.schedule_next(wait, tokio::time::Instant::now());
        tokio::select! {
            () = tokio::time::sleep_until(due) => {}
            () = self.notify.notified() => {
                if self.stopped.load(Ordering::Relaxed) {
                    return Emission::Stopped;
                }
                // A new body changes nothing about WHEN the next frame goes:
                // the timer is the timer. Finish the interval.
                tokio::time::sleep_until(due).await;
            }
        }
        if self.stopped.load(Ordering::Relaxed) {
            return Emission::Stopped;
        }
        let under = matches!(
            self.budget.query(&self.scope),
            BudgetState::UnderBudget { .. }
        );
        // One frame: the head body, or, toward a peer that announced
        // multi-body frames, as many heads as fit (v44 coalescing: a 200 B
        // control message no longer spends a whole 16 KB slot).
        let mut bodies: Vec<(u64, Vec<u8>)> = Vec::new();
        if under {
            let cap = body_capacity(self.agreement.frame_bytes);
            let pack = self.coalescing();
            let mut q = self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut used = 0usize;
            while let Some((_, b)) = q.front() {
                let need = if pack { 2 + b.len() } else { b.len() };
                if !bodies.is_empty() && (!pack || used + need > cap) {
                    break;
                }
                used += need;
                bodies.push(q.pop_front().expect("front seen"));
            }
        }
        let real = !bodies.is_empty();
        let ticket = bodies.iter().map(|(t, _)| *t).max().unwrap_or(0);
        let mut pad = |buf: &mut [u8]| self.poisson.fill_bytes(buf);
        let frame = if bodies.len() > 1 {
            self.budget.record_real(&self.scope);
            self.real.fetch_add(1, Ordering::Relaxed);
            let bs: Vec<Vec<u8>> = bodies.into_iter().map(|(_, b)| b).collect();
            wrap_multi(self.agreement.frame_bytes, &bs, &mut pad)
        } else if let Some((_, b)) = bodies.pop() {
            self.budget.record_real(&self.scope);
            self.real.fetch_add(1, Ordering::Relaxed);
            wrap(self.agreement.frame_bytes, Some(&b), &mut pad)
        } else {
            self.budget.record_cover(&self.scope);
            self.cover.fetch_add(1, Ordering::Relaxed);
            wrap(self.agreement.frame_bytes, None, &mut pad)
        };
        match frame {
            Ok(bytes) => Emission::Frame {
                bytes,
                real,
                ticket,
            },
            // Unreachable: enqueue bounded every body to the capacity.
            Err(_) => Emission::Stopped,
        }
    }
}

/// `FSD/PRIVACY_MODES.md` §2.4: the 95th percentile of an exponential wait, in
/// mean gaps (`ln 20`).
const P95_GAPS: f64 = 2.995_732_273_553_991;

/// The frame a figure is stated at while this node holds no shaped link: a TCP
/// link's channel payload (`FSD/TRANSPORT_TIERS_MODEL.md` §1), the largest a
/// link runs at, "so a stated cost never understates the served one" (CC 5.4.3).
pub const REFERENCE_FRAME_BYTES: u16 = 16_272;

/// What a class costs a person, computed from the policy that governs it
/// (`FSD/PRIVACY_MODES.md` §2.4, the §6.6 placeholders): raw values, which the
/// client formats. Nothing here is read from a table.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ShapingFigures {
    /// The class token.
    pub class: &'static str,
    /// The byte rate per link.
    pub bytes_per_s: u32,
    /// The node-wide cap on the sum of rates.
    pub node_cap_bytes_per_s: u32,
    /// ρ.
    pub rho: f64,
    /// W, in seconds.
    pub window_s: u64,
    /// The frame these are stated at.
    pub frame_bytes: u16,
    /// `gap_s`: the mean wait for a row, the frame over the rate.
    pub gap_s: f64,
    /// `gap_p95_s`: the 95th percentile of that wait.
    pub gap_p95_s: f64,
    /// `gb_month_link`: one link for 30 days, each way, in GB (10⁹ bytes).
    pub gb_month_link: f64,
    /// `gb_month_cap`: the node cap for 30 days, each way, in GB.
    pub gb_month_cap: f64,
    /// `file_1mb_s`: 1 MB by the slow path, sustained, at ρ × rate.
    pub file_1mb_s: f64,
    /// `file_10mb_s`: 10 MB by the slow path.
    pub file_10mb_s: f64,
}

impl ShapingFigures {
    /// The figures of `policy` at `frame_bytes`. `None` while it shapes
    /// nothing, which has no cost to state.
    #[must_use]
    pub fn of(policy: &ShapingPolicy, frame_bytes: u16) -> Option<Self> {
        const MONTH_S: f64 = 2_592_000.0;
        const GB: f64 = 1e9;
        if !policy.enabled() {
            return None;
        }
        let rate = f64::from(policy.bytes_per_s);
        let gap_s = f64::from(frame_bytes) / rate;
        let real = policy.rho * rate;
        Some(Self {
            class: policy.class.as_str(),
            bytes_per_s: policy.bytes_per_s,
            node_cap_bytes_per_s: policy.node_cap_bytes_per_s,
            rho: policy.rho,
            window_s: policy.window.as_secs(),
            frame_bytes,
            gap_s,
            gap_p95_s: gap_s * P95_GAPS,
            gb_month_link: rate * MONTH_S / GB,
            gb_month_cap: f64::from(policy.node_cap_bytes_per_s) * MONTH_S / GB,
            file_1mb_s: 1e6 / real,
            file_10mb_s: 1e7 / real,
        })
    }
}

/// One shaped link as it runs now (`FSD/PRIVACY_MODES.md` E8): the agreement
/// both ends computed and this sender's rate under it.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct ShapedLinkStatus {
    /// The peer's key id, when the handshake attributed the link.
    pub peer: Option<String>,
    /// A `seat` link, outside the bound.
    pub seat: bool,
    /// This node dialled it.
    pub dialled_here: bool,
    /// The agreed frame.
    pub frame_bytes: u16,
    /// The agreed rate.
    pub agreed_bytes_per_s: u32,
    /// This sender's rate now, at or below the agreed one.
    pub bytes_per_s: f64,
    /// The mean frame gap now.
    pub gap_s: f64,
    /// The 95th percentile of that wait.
    pub gap_p95_s: f64,
    /// The agreed ρ.
    pub rho: f64,
    /// The agreed W, in seconds.
    pub window_s: u64,
    /// Real frames one window admits at the rate now.
    pub real_frames_per_window: usize,
}

/// One peer's shaping, as far as this node knows it (§3.1, E8).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct PeerShaping {
    /// The peer's key id.
    pub peer: String,
    /// Whether it shapes: `None` until it has answered an offer here. A peer
    /// at its bound shapes; a peer that left an offer unanswered does not.
    pub shapes: Option<bool>,
    /// It holds a shaped link here now.
    pub shaped_now: bool,
    /// The mean gap of its fastest shaped link, while it holds one.
    pub gap_s: Option<f64>,
}

/// **The typed status a host reads** (`FSD/PRIVACY_MODES.md` §6.6, E8): every
/// value is read from the running shaper, policy or tier when asked.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)] // each a separate fact a host reads
pub struct ShapingStatus {
    /// The class this node offers: the link class the client cannot know.
    pub class: &'static str,
    /// It offers shaping on some link.
    pub enabled: bool,
    /// Every identity link is offered it, not only the layer links.
    pub all_links: bool,
    /// An unshaped identity link is refused.
    pub require_shaped_links: bool,
    /// The byte rate per link in force.
    pub bytes_per_s: u32,
    /// The node-wide cap in force.
    pub node_cap_bytes_per_s: u32,
    /// What the class in force costs, at the largest agreed frame, or
    /// [`REFERENCE_FRAME_BYTES`] with no shaped link. `None` when off.
    pub figures: Option<ShapingFigures>,
    /// The figures of each class this device runs at: both networks on a
    /// phone (the `_cellular` set of §6.6), the one class elsewhere.
    pub device_figures: Vec<ShapingFigures>,
    /// `figures` came from a live agreement, not the reference frame.
    pub frame_agreed: bool,
    /// The service tier (0, 1, 2).
    pub service_tier: u8,
    /// Admit-close is on: no new shaped link for a non-obligation peer.
    pub admit_closed: bool,
    /// Shaped links now.
    pub shaped_links: usize,
    /// Those that count toward the bound (all but `seat` links).
    pub counted_links: usize,
    /// The bound, when the share policy has one.
    pub max_links: Option<u32>,
    /// The slots a new peer could take now.
    pub free_slots: u8,
    /// What this node tells its shaped peers it has.
    pub reported_slots: u8,
    /// Slots kept for onion layer neighbours.
    pub layer_held_slots: u32,
    /// This node's relay offering is on.
    pub relay_offering: bool,
    /// Each shaped link, by peer.
    pub links: Vec<ShapedLinkStatus>,
    /// Every peer with a known shaping fact, by key id.
    pub peers: Vec<PeerShaping>,
    /// `relays_answering`: relays answering across the three layers, by this
    /// node's own measure. `None` until a layer deal is installed, when there
    /// is no measure: the client shows the line without the count (§6.2).
    pub relays_answering: Option<u32>,
    /// The Anonymous Tier, counts only, with `confines_media`.
    pub onion: crate::onion::runtime::OnionStatus,
}

/// The node's shaped links and its node-wide cap.
#[derive(Debug)]
pub struct LinkShapers {
    /// The policy in force; replaced at runtime by [`Self::set_policy`] (a
    /// phone moving between Wi-Fi and cellular, or plugging in).
    policy: std::sync::RwLock<ShapingPolicy>,
    /// This node's onion layer neighbours by key id (empty unless the node
    /// runs the Anonymous Tier): their links are offered shaping under any
    /// scope, count within the eight, and may take any of them.
    layer_peers: Mutex<std::collections::HashSet<String>>,
    /// The peer each offered or shaped link goes to, when known.
    link_peer: Mutex<HashMap<[u8; 16], String>>,
    /// CC 5.4.3 rc16 two planes — the BULK links this node dialled: identity
    /// links on which no shaping is ever offered, carrying bulk and nothing
    /// else this node chooses.
    bulk: Mutex<std::collections::HashSet<[u8; 16]>>,
    /// Whether the floors have the total past the cap ([`Self::rebalance`]).
    over_cap: std::sync::atomic::AtomicBool,
    /// The free slots each shaped peer last reported, by key id: a hint for
    /// referrals, gone with the peer's last link.
    peer_free: Mutex<HashMap<String, u8>>,
    /// Whether this node reports its free slots to its shaped peers.
    reports_capacity: std::sync::atomic::AtomicBool,
    /// This node's relay offering is on ([`Self::set_relay_offering`]).
    relay_offering: std::sync::atomic::AtomicBool,
    /// The free slots last reported.
    last_reported: std::sync::atomic::AtomicU32,
    /// Referral frames still arriving, by link.
    referral_parts: Mutex<HashMap<[u8; 16], crate::transport::av_transit_handshake::Reassembler>>,
    /// Whole referrals waiting for the refusal they precede, by link.
    referrals: Mutex<HashMap<[u8; 16], crate::transport::shaping_referral::ReferralFrame>>,
    /// The serve seats, from the signed genesis bundle (`serve_nodes`).
    seats: Mutex<std::collections::HashSet<String>>,
    /// This node is one of them.
    own_seat: std::sync::atomic::AtomicBool,
    /// Test seam: key-id prefixes that are seats (the harness's nodes are not
    /// in any signed bundle).
    seat_prefixes: Mutex<Vec<String>>,
    links: Mutex<HashMap<[u8; 16], Arc<LinkShaper>>>,
    /// Links this node sent an offer on, with that offer.
    offered: Mutex<HashMap<[u8; 16], ShapingOffer>>,
    /// Dials waiting for the peer's answer ([`Self::begin_offer`]).
    pending: Mutex<HashMap<[u8; 16], OfferAnswerTx>>,
    queue_cap: usize,
    /// The service tier in force (`FSD/PRIVACY_MODES.md` §6.12).
    tier: std::sync::atomic::AtomicU8,
    /// The shaped links a peer dialled here, by the order they were admitted:
    /// what tier 2 may close, newest first. A link this node dialled is not
    /// here: it carries this node's own rows and a close would only redial.
    admitted: Mutex<HashMap<[u8; 16], u64>>,
    /// Admissions so far.
    admissions: std::sync::atomic::AtomicU64,
    /// What each peer's last offer said: whether it shapes. Survives its
    /// links, and holds at most [`PEER_SHAPING_FACTS_MAX`] peers.
    peer_shapes: Mutex<HashMap<String, bool>>,
    /// What a shed lever reads at decision time. Absent: nothing is shed.
    obligations: std::sync::RwLock<Option<Arc<dyn crate::load_ladder::PeerObligations>>>,
    /// Woken when tier 2 is in force.
    shed_wake: tokio::sync::Notify,
}

/// Peers whose shaping fact is held, at most. Past it a newcomer takes the
/// place of an arbitrary peer, whose fact returns with its next offer.
pub const PEER_SHAPING_FACTS_MAX: usize = 4096;

/// The most a sender waits for a queued row to leave a shaped link before it
/// retracts the bodies and reports a retryable timeout: bounded so a
/// saturated link (a window's budget spent) does not hold a dispatcher or a
/// round gate for the whole window.
pub const ROW_LEAVE_MAX: Duration = Duration::from_secs(60);

/// The longest a sender waits, in the link's own gaps, where that is more than
/// [`ROW_LEAVE_MAX`]: the p99 of a 64 KiB row (five frames, `5 + 4.74 × √5`
/// gaps) with a margin. At `server` the 60 s rules; at the 47 s `phone-cellular`
/// gap a fixed 60 s lost one single-frame row in four and nearly every full one,
/// and their retries did not converge (`FSD/PRIVACY_MODES.md` E7).
pub const ROW_LEAVE_MAX_GAPS: f64 = 16.0;

/// How many frames of a bulk message may wait in a shaped link's queue at once
/// on the slow path. The queue is one FIFO, so this is how far a row can be
/// behind a file: a few gaps, never the whole file (`FSD/PRIVACY_MODES.md` E3,
/// "a row behind a file is a starved row").
pub const SLOW_PATH_QUEUED_MAX: usize = 4;

/// How long a finished bulk fallback is remembered, so a retry that lost its
/// wait does not send the whole message again.
pub const BULK_FALLBACK_DONE_TTL: Duration = Duration::from_secs(600);

/// The outcome of one bulk fallback: `Ok`, or why it stopped.
pub type BulkFallbackResult = Option<Result<(), String>>;

/// CC 5.4.3 rc16 two planes — the bulk fallbacks in progress, by envelope
/// digest. A fallback takes minutes and its callers do not all wait that long:
/// a responder cancels at 60 s, and a durable claim can expire and dispatch the
/// same row again. So a transfer runs detached and single-flight: a cancelled
/// wait abandons the wait, not the transfer, and a second send of the same
/// envelope joins it instead of queueing the bytes twice.
#[derive(Debug, Default)]
pub struct BulkFallbacks {
    running: Mutex<HashMap<[u8; 32], tokio::sync::watch::Receiver<BulkFallbackResult>>>,
    finished: Mutex<HashMap<[u8; 32], std::time::Instant>>,
}

impl BulkFallbacks {
    /// Whether this envelope finished within [`BULK_FALLBACK_DONE_TTL`].
    #[must_use]
    pub fn recently_finished(&self, digest: &[u8; 32]) -> bool {
        let mut done = self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        done.retain(|_, at| at.elapsed() < BULK_FALLBACK_DONE_TTL);
        done.contains_key(digest)
    }

    /// Join the transfer of `digest`, or start one: a returned sender means
    /// this caller owns the transfer and reports to it.
    pub fn join_or_start(
        &self,
        digest: [u8; 32],
    ) -> (
        tokio::sync::watch::Receiver<BulkFallbackResult>,
        Option<tokio::sync::watch::Sender<BulkFallbackResult>>,
    ) {
        let mut running = self
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(rx) = running.get(&digest) {
            return (rx.clone(), None);
        }
        let (tx, rx) = tokio::sync::watch::channel(None);
        running.insert(digest, rx.clone());
        (rx, Some(tx))
    }

    /// The transfer of `digest` ended. A failed one is forgotten, so the
    /// retry starts it again.
    pub fn finish(&self, digest: &[u8; 32], ok: bool) {
        self.running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(digest);
        if ok {
            self.finished
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(*digest, std::time::Instant::now());
        }
    }
}

/// Default bound on a shaped link's queue, in bodies.
pub const DEFAULT_QUEUE_CAP: usize = 4096;

impl LinkShapers {
    /// A table under `policy`.
    #[must_use]
    pub fn new(policy: ShapingPolicy) -> Self {
        Self {
            policy: std::sync::RwLock::new(policy),
            layer_peers: Mutex::new(std::collections::HashSet::new()),
            link_peer: Mutex::new(HashMap::new()),
            bulk: Mutex::new(std::collections::HashSet::new()),
            over_cap: std::sync::atomic::AtomicBool::new(false),
            peer_free: Mutex::new(HashMap::new()),
            reports_capacity: std::sync::atomic::AtomicBool::new(false),
            relay_offering: std::sync::atomic::AtomicBool::new(false),
            last_reported: std::sync::atomic::AtomicU32::new(u32::MAX),
            referral_parts: Mutex::new(HashMap::new()),
            referrals: Mutex::new(HashMap::new()),
            seats: Mutex::new(std::collections::HashSet::new()),
            own_seat: std::sync::atomic::AtomicBool::new(false),
            seat_prefixes: Mutex::new(Vec::new()),
            links: Mutex::new(HashMap::new()),
            offered: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            queue_cap: DEFAULT_QUEUE_CAP,
            tier: std::sync::atomic::AtomicU8::new(0),
            admitted: Mutex::new(HashMap::new()),
            admissions: std::sync::atomic::AtomicU64::new(0),
            peer_shapes: Mutex::new(HashMap::new()),
            obligations: std::sync::RwLock::new(None),
            shed_wake: tokio::sync::Notify::new(),
        }
    }

    /// Install the read a shed lever makes ([`Self::obligation_of`]).
    pub fn set_obligations(&self, reader: Arc<dyn crate::load_ladder::PeerObligations>) {
        *self
            .obligations
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(reader);
    }

    /// What this node owes `peer` now, read at the moment a lever acts. A link
    /// no handshake attributed, or a node with no reader, is
    /// [`PeerObligation::Unresolved`], and nothing is shed on that.
    ///
    /// [`PeerObligation::Unresolved`]: crate::load_ladder::PeerObligation::Unresolved
    pub async fn obligation_of(&self, peer: Option<&str>) -> crate::load_ladder::PeerObligation {
        let reader = self
            .obligations
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match (reader, peer) {
            (Some(reader), Some(peer)) => reader.obligation_of(peer).await,
            _ => crate::load_ladder::PeerObligation::Unresolved,
        }
    }

    /// **Admit-close** (`FSD/PRIVACY_MODES.md` §6.12): whether `theirs`, an
    /// offer on a link `peer` dialled, is refused for load. The refusal goes
    /// out as one at the bound does, with referrals.
    pub async fn load_refuses(&self, peer: Option<&str>, theirs: &ShapingOffer) -> bool {
        !self.service_tier().admits_new_shaped_links()
            && theirs.shapes()
            && self.offers_to(peer)
            && !self.obligation_of(peer).await.keeps_shaped_link()
    }

    /// **B-pause on the slow path** (§6.12): whether a transfer to `peer`
    /// over a shaped link waits now. The row does not.
    pub async fn slow_path_paused(&self, peer: &str) -> bool {
        self.service_tier().pauses_bulk() && !self.obligation_of(Some(peer)).await.keeps_slow_path()
    }

    /// The newest shaped link tier 2 closes now, if any: every candidate's
    /// peer is read when it comes up, so standing a peer gained a moment ago
    /// counts. `None` at any other tier.
    pub async fn next_shed(&self) -> Option<[u8; 16]> {
        for (link, peer) in self.shed_candidates() {
            if !self
                .obligation_of(peer.as_deref())
                .await
                .keeps_shaped_link()
            {
                return self.service_tier().closes_shaped_links().then_some(link);
            }
        }
        None
    }

    /// Resolves when tier 2 is (or has just been) put in force.
    pub async fn shed_woken(&self) {
        self.shed_wake.notified().await;
    }

    /// `FSD/PRIVACY_MODES.md` §6.12 — the service tier changed. Nothing here
    /// touches a shaper: cover is not shed, and a link runs at its class or
    /// closes. Tier 1 and above report zero slots, and the zero goes out now
    /// so peers stop referring this node.
    pub fn set_service_tier(&self, tier: crate::load_ladder::ServiceTier) {
        self.tier.store(tier.as_u8(), Ordering::Release);
        self.report_capacity();
        if tier.closes_shaped_links() {
            self.shed_wake.notify_one();
        }
    }

    /// The service tier in force.
    #[must_use]
    pub fn service_tier(&self) -> crate::load_ladder::ServiceTier {
        crate::load_ladder::ServiceTier::from_u8(self.tier.load(Ordering::Acquire))
    }

    /// The links tier 2 may close, newest first, with their peers: the shaped
    /// links peers dialled here. Who keeps one is the caller's question
    /// ([`crate::load_ladder::PeerObligation`]), asked when it closes.
    #[must_use]
    pub fn shed_candidates(&self) -> Vec<([u8; 16], Option<String>)> {
        let peers = self.link_peer_map();
        let links = self.links();
        let mut admitted: Vec<([u8; 16], u64)> = self
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(l, _)| links.contains_key(*l))
            .map(|(l, n)| (*l, *n))
            .collect();
        admitted.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        admitted
            .into_iter()
            .map(|(l, _)| (l, peers.get(&l).cloned()))
            .collect()
    }

    /// Record what `peer` offered, bounded.
    fn note_peer_shapes(&self, peer: &str, shapes: bool) {
        let mut facts = self
            .peer_shapes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if facts.len() >= PEER_SHAPING_FACTS_MAX && !facts.contains_key(peer) {
            let evicted = facts.keys().next().cloned();
            if let Some(k) = evicted {
                facts.remove(&k);
            }
        }
        facts.insert(peer.to_owned(), shapes);
    }

    /// What this node knows of `peer`'s shaping (`FSD/PRIVACY_MODES.md` §3.1,
    /// E8), from what `peer` itself offered and the links held now.
    #[must_use]
    pub fn peer_shaping(&self, peer: &str) -> PeerShaping {
        let gap = self.gap_to_peer(peer);
        let shapes = gap.is_some().then_some(true).or_else(|| {
            self.peer_shapes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get(peer)
                .copied()
        });
        PeerShaping {
            peer: peer.to_owned(),
            shapes,
            shaped_now: gap.is_some(),
            gap_s: gap.map(|g| g.as_secs_f64()),
        }
    }

    /// [`Self::peer_shaping`] of every peer with a known fact or a shaped
    /// link, sorted by key id.
    #[must_use]
    pub fn peers_shaping(&self) -> Vec<PeerShaping> {
        let mut keys: std::collections::BTreeSet<String> = self
            .peer_shapes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect();
        let peers = self.link_peer_map();
        keys.extend(
            self.links()
                .keys()
                .filter_map(|l| peers.get(l))
                .map(Clone::clone),
        );
        keys.iter().map(|k| self.peer_shaping(k)).collect()
    }

    /// Each shaped link as it runs now: agreed values, read from its shaper.
    #[must_use]
    pub fn links_status(&self) -> Vec<ShapedLinkStatus> {
        let peers = self.link_peer_map();
        let admitted: std::collections::HashSet<[u8; 16]> = self
            .admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .collect();
        let shapers: Vec<([u8; 16], Arc<LinkShaper>)> = self
            .links()
            .iter()
            .map(|(l, s)| (*l, Arc::clone(s)))
            .collect();
        let mut out: Vec<ShapedLinkStatus> = shapers
            .iter()
            .map(|(l, s)| {
                let a = s.agreement();
                let peer = peers.get(l).cloned();
                let gap_s = s.frame_gap().as_secs_f64();
                ShapedLinkStatus {
                    seat: self.is_seat_link(peer.as_deref()),
                    peer,
                    dialled_here: !admitted.contains(l),
                    frame_bytes: a.frame_bytes,
                    agreed_bytes_per_s: a.bytes_per_s(),
                    bytes_per_s: s.bytes_per_s_now(),
                    gap_s,
                    gap_p95_s: gap_s * P95_GAPS,
                    rho: a.rho,
                    window_s: a.window.as_secs(),
                    real_frames_per_window: s.reach_frames_now(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.peer.cmp(&b.peer));
        out
    }

    /// The bound in force, when the share policy has one.
    #[must_use]
    pub fn max_links(&self) -> Option<u32> {
        match self.policy().share {
            ShapedSharePolicy::BoundedWithFloor { max_links, .. } => Some(max_links),
            ShapedSharePolicy::DivideNoFloor => None,
        }
    }

    /// Links that count toward the bound (all but `seat` links).
    #[must_use]
    pub fn counted_link_count(&self) -> usize {
        self.counted_links()
    }

    /// Whether this node's relay offering is on, as the slots report reads it.
    #[must_use]
    pub fn relay_offering(&self) -> bool {
        self.relay_offering.load(Ordering::Acquire)
    }

    /// The policy in force (a snapshot: it may change at runtime).
    #[must_use]
    pub fn policy(&self) -> ShapingPolicy {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Replace the policy at runtime. A shaped link the new policy can no
    /// longer carry (its agreed rate is above the new per-link rate, shaping
    /// is now off, or the link is no longer offered under the new scope) is
    /// stopped and forgotten here and returned for the caller to CLOSE: a
    /// link is never left half-shaped, and a closed link is redialled and
    /// renegotiated under the new policy. A link that still fits keeps its
    /// agreement (an upgrade applies to links offered from now on).
    pub fn set_policy(&self, policy: ShapingPolicy) -> Vec<[u8; 16]> {
        let layer = self.layer_peer_set();
        let peers = self.link_peer_map();
        let mut close = Vec::new();
        {
            let mut links = self.links();
            links.retain(|link, shaper| {
                let is_layer = peers.get(link).is_some_and(|p| layer.contains(p));
                let keep = policy.offers_on(is_layer)
                    && shaper.agreement().bytes_per_s() <= policy.bytes_per_s.saturating_add(1);
                if !keep {
                    shaper.stop();
                    close.push(*link);
                }
                keep
            });
        }
        for link in &close {
            self.offered().remove(link);
            self.pending().remove(link);
            self.link_peer().remove(link);
            self.admitted
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(link);
        }
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
        self.rebalance();
        close
    }

    /// Name this node's onion layer neighbours (empty: the tier is not
    /// running here, and none of the eight is held).
    pub fn set_layer_peers(&self, peers: std::collections::HashSet<String>) {
        *self
            .layer_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = peers;
        self.rebalance();
    }

    fn layer_peer_set(&self) -> std::collections::HashSet<String> {
        self.layer_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn link_peer(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], String>> {
        self.link_peer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn link_peer_map(&self) -> HashMap<[u8; 16], String> {
        self.link_peer().clone()
    }

    /// Name the serve seats (the genesis bundle's `serve_nodes`) and whether
    /// this node is one. A seat-to-seat link is offered the seat tier.
    pub fn set_seats(&self, seats: std::collections::HashSet<String>, own: bool) {
        *self
            .seats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = seats;
        self.own_seat.store(own, Ordering::Release);
        self.rebalance();
    }

    /// Test seam — seats by key-id prefix ([`Self::set_seats`] for production).
    #[doc(hidden)]
    pub fn set_seat_prefixes(&self, prefixes: Vec<String>, own: bool) {
        *self
            .seat_prefixes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = prefixes;
        self.own_seat.store(own, Ordering::Release);
        self.rebalance();
    }

    /// Whether a link to `peer` is a seat-to-seat link.
    #[must_use]
    pub fn is_seat_link(&self, peer: Option<&str>) -> bool {
        self.own_seat.load(Ordering::Acquire) && peer.is_some_and(|p| self.is_seat(p))
    }

    /// Whether `peer` holds a serve seat, on the signed roster.
    #[must_use]
    pub fn is_seat(&self, peer: &str) -> bool {
        self.seats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(peer)
            || self
                .seat_prefixes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(|x| peer.starts_with(x.as_str()))
    }

    /// Whether `peer` holds a shaped link here.
    #[must_use]
    pub fn peer_is_shaped(&self, peer: &str) -> bool {
        self.gap_to_peer(peer).is_some()
    }

    /// The mean frame gap of the fastest shaped link to `peer`, if any: what a
    /// round's waits are paced by ([`crate::transport::Transport::pacing_gap`]).
    #[must_use]
    pub fn gap_to_peer(&self, peer: &str) -> Option<Duration> {
        let links = self.links();
        self.link_peer()
            .iter()
            .filter(|(_, p)| p.as_str() == peer)
            .filter_map(|(l, _)| links.get(l))
            .map(|s| s.frame_gap())
            .min()
    }

    /// Whether `peer` is one of this node's layer neighbours.
    #[must_use]
    pub fn is_layer_peer(&self, peer: Option<&str>) -> bool {
        peer.is_some_and(|p| {
            self.layer_peers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(p)
        })
    }

    /// Whether this node offers shaping on a link to `peer` at all (the
    /// dialler sends no offer when it does not).
    #[must_use]
    pub fn offers_to(&self, peer: Option<&str>) -> bool {
        self.policy().offers_on(self.is_layer_peer(peer))
    }

    /// How many of the eight are kept from other peers now: the layer
    /// neighbours with no shaped link yet, up to
    /// [`ShapingPolicy::layer_reserve_links`]. Zero while the tier is not
    /// running here.
    #[must_use]
    pub fn layer_held_slots(&self) -> u32 {
        let layer = self.layer_peer_set();
        if layer.is_empty() {
            return 0;
        }
        let peers = self.link_peer_map();
        let shaped: std::collections::HashSet<String> = self
            .links()
            .keys()
            .filter_map(|l| peers.get(l).cloned())
            .collect();
        let waiting = layer.iter().filter(|p| !shaped.contains(*p)).count();
        u32::try_from(waiting)
            .unwrap_or(u32::MAX)
            .min(self.policy().layer_reserve_links)
    }

    /// Apply the share policy to every shaped link. Under the default each
    /// link runs at the class rate, so this changes nothing on a live link;
    /// under [`ShapedSharePolicy::DivideNoFloor`] the cap divides. A `seat`
    /// link keeps its agreed rate, outside either. Run whenever a link or the
    /// policy changes ([`LinkShaper::set_share`]).
    pub fn rebalance(&self) {
        let policy = self.policy();
        let peers = self.link_peer_map();
        let links: Vec<([u8; 16], Arc<LinkShaper>)> = self
            .links()
            .iter()
            .map(|(l, s)| (*l, Arc::clone(s)))
            .collect();
        let is_seat = |l: &[u8; 16]| peers.get(l).is_some_and(|p| self.is_seat_link(Some(p)));
        let counted = links.iter().filter(|(l, _)| !is_seat(l)).count();
        let cap = f64::from(policy.node_cap_bytes_per_s);
        let class = f64::from(policy.bytes_per_s);
        #[allow(clippy::cast_precision_loss)] // a link count
        let share = match policy.share {
            ShapedSharePolicy::DivideNoFloor => cap / counted.max(1) as f64,
            ShapedSharePolicy::BoundedWithFloor {
                floor_bytes_per_s, ..
            } => f64::from(floor_bytes_per_s),
        };
        for (l, shaper) in &links {
            if is_seat(l) {
                shaper.set_share(f64::from(shaper.agreement().bytes_per_s()));
            } else {
                shaper.set_share(share.min(class));
            }
        }
        let total = self.effective_total();
        let over = total > cap + 1.0 && !links.is_empty();
        if over != self.over_cap.swap(over, Ordering::AcqRel) && over {
            tracing::warn!(
                links = links.len(),
                total_bytes_per_s = total,
                node_cap_bytes_per_s = policy.node_cap_bytes_per_s,
                "the shaped links' rates pass the node cap (CC 5.4.3)"
            );
        }
        self.report_capacity();
    }

    /// The slots a new peer could take here now: the bound less the links and
    /// the slots held for layer neighbours. Zero outside the default arm,
    /// which has no bound to report against, and zero at tier 1 and above:
    /// Admit-close takes no new link from a peer it owes nothing
    /// (`FSD/PRIVACY_MODES.md` §6.12), so no slot is on offer.
    #[must_use]
    pub fn free_slots(&self) -> u8 {
        if !self.service_tier().admits_new_shaped_links() {
            return 0;
        }
        let ShapedSharePolicy::BoundedWithFloor { max_links, .. } = self.policy().share else {
            return 0;
        };
        let used = u32::try_from(self.counted_links()).unwrap_or(u32::MAX);
        let room = max_links
            .saturating_sub(self.layer_held_slots())
            .saturating_sub(used);
        u8::try_from(room).unwrap_or(u8::MAX)
    }

    /// Start reporting free slots to shaped peers (the transport does, once).
    pub fn enable_capacity_reports(&self) {
        self.reports_capacity.store(true, Ordering::Release);
    }

    /// This node's relay offering turned on or off
    /// ([`crate::onion::policy::relay_offering`]). Off reports nothing from
    /// here on, and the zero goes out now so peers stop referring this node.
    pub fn set_relay_offering(&self, on: bool) {
        self.relay_offering.store(on, Ordering::Release);
        self.report_capacity();
    }

    /// What this node reports to its shaped peers: the free slots while its
    /// relay offering is on, zero (no claim) otherwise.
    #[must_use]
    pub fn reported_slots(&self) -> u8 {
        if self.relay_offering.load(Ordering::Acquire) {
            self.free_slots()
        } else {
            0
        }
    }

    /// Tell every shaped peer what this node reports, when it changed.
    fn report_capacity(&self) {
        if !self.reports_capacity.load(Ordering::Acquire) {
            return;
        }
        let free = self.reported_slots();
        if self.last_reported.swap(u32::from(free), Ordering::AcqRel) == u32::from(free) {
            return;
        }
        let shapers: Vec<Arc<LinkShaper>> = self.links().values().map(Arc::clone).collect();
        for shaper in shapers {
            // choke-ok: a report is a hint; a full queue carries the next one.
            let _ = shaper.enqueue(vec![capability_body(free)]);
        }
    }

    /// The peer on `link` reported `free` slots.
    pub fn note_peer_capacity(&self, link: [u8; 16], free: u8) {
        if let Some(peer) = self.link_peer().get(&link).cloned() {
            self.peer_capacity().insert(peer, free);
        }
    }

    /// The free slots `peer` last reported.
    #[must_use]
    pub fn peer_free_slots(&self, peer: &str) -> Option<u8> {
        self.peer_capacity().get(peer).copied()
    }

    fn peer_capacity(&self) -> std::sync::MutexGuard<'_, HashMap<String, u8>> {
        self.peer_free
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The shaped peers to consider referring a refused peer to, best first
    /// ([`crate::transport::shaping_referral::rank_referrals`]).
    #[must_use]
    pub fn referral_candidates<S: std::hash::BuildHasher>(
        &self,
        excluded: &std::collections::HashSet<String, S>,
    ) -> Vec<crate::transport::shaping_referral::ReferralCandidate> {
        let reported: Vec<(String, u8)> = self
            .peer_capacity()
            .iter()
            .map(|(p, f)| (p.clone(), *f))
            .collect();
        let candidates = reported
            .into_iter()
            .map(
                |(key_id, free_slots)| crate::transport::shaping_referral::ReferralCandidate {
                    seat: self.is_seat(&key_id),
                    key_id,
                    free_slots,
                },
            )
            .collect();
        crate::transport::shaping_referral::rank_referrals(
            candidates,
            excluded,
            &mut rand::thread_rng(),
        )
    }

    /// `peer` was handed out first in a referral: one slot fewer in the local
    /// hint until it next reports, so unequal capacity does not herd either.
    pub fn note_referred(&self, peer: &str) {
        if let Some(free) = self.peer_capacity().get_mut(peer) {
            *free = free.saturating_sub(1);
        }
    }

    /// A referral frame arrived on `link`. Taken only while this node waits on
    /// its offer's answer; anything else is dropped. `false` is a frame that
    /// could not be read.
    pub fn accept_referral_part(&self, link: [u8; 16], part: &[u8]) -> bool {
        use crate::transport::shaping_referral::{decode_referrals, referral_reassembler};
        if !self.pending().contains_key(&link) {
            return true;
        }
        let mut parts = self
            .referral_parts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match parts
            .entry(link)
            .or_insert_with(referral_reassembler)
            .push(part)
        {
            Ok(None) => true,
            Ok(Some(body)) => {
                parts.remove(&link);
                drop(parts);
                let Ok(frame) = decode_referrals(&body) else {
                    return false;
                };
                self.referrals
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(link, frame);
                true
            }
            Err(_) => {
                parts.remove(&link);
                false
            }
        }
    }

    /// The referral that came with `link`'s refusal.
    #[must_use]
    pub fn take_referrals(
        &self,
        link: [u8; 16],
    ) -> Option<crate::transport::shaping_referral::ReferralFrame> {
        self.referrals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&link)
    }

    /// Shaped links that count toward the bound: all but `seat` links.
    fn counted_links(&self) -> usize {
        let peers = self.link_peer_map();
        self.links()
            .keys()
            .filter(|l| !peers.get(*l).is_some_and(|p| self.is_seat_link(Some(p))))
            .count()
    }

    /// CC 5.4.3 rc17 — whether a shaped link to `peer` would pass the bound.
    /// A layer neighbour may take any of the eight; any other peer stops
    /// short by [`Self::layer_held_slots`]. A `seat` link is never at the
    /// bound.
    #[must_use]
    pub fn at_bound_for(&self, peer: Option<&str>) -> bool {
        let policy = self.policy();
        let ShapedSharePolicy::BoundedWithFloor { max_links, .. } = policy.share else {
            return false;
        };
        if self.is_seat_link(peer) {
            return false;
        }
        let held = if self.is_layer_peer(peer) {
            0
        } else {
            self.layer_held_slots()
        };
        let room = usize::try_from(max_links.saturating_sub(held)).unwrap_or(usize::MAX);
        self.counted_links() >= room
    }

    /// [`Self::at_bound_for`] for a peer of no standing here.
    #[must_use]
    pub fn at_bound(&self) -> bool {
        self.at_bound_for(None)
    }

    /// The responder's answer to `theirs` on `link` to `peer`: this node's
    /// offer, or the refusal when `theirs` shapes and this node is at its
    /// bound ([`Self::at_bound_for`]). The dialler learns the same at
    /// [`Self::peer_offer`], after offering.
    #[must_use]
    pub fn offer_for_answer(
        &self,
        link: [u8; 16],
        frame_bytes: usize,
        peer: Option<&str>,
        theirs: &ShapingOffer,
    ) -> ShapingOffer {
        if theirs.shapes() && self.offers_to(peer) && self.at_bound_for(peer) {
            return self.refusal_for(link, peer);
        }
        self.offer_for(link, frame_bytes, peer)
    }

    /// Record the refusal of a shaping peer on `link`, at the bound or under
    /// Admit-close, and return it. [`Self::peer_offer`] answers the rest.
    #[must_use]
    pub fn refusal_for(&self, link: [u8; 16], peer: Option<&str>) -> ShapingOffer {
        if let Some(p) = peer {
            self.link_peer().insert(link, p.to_owned());
        }
        let refusal = ShapingOffer::home_elsewhere();
        self.offered().insert(link, refusal);
        refusal
    }

    /// Bytes per second this node's shaped links under the bound emit now,
    /// summed (`seat` links have their own budget and are not counted).
    #[must_use]
    pub fn effective_total(&self) -> f64 {
        let peers = self.link_peer_map();
        self.links()
            .iter()
            .filter(|(l, _)| !peers.get(*l).is_some_and(|p| self.is_seat_link(Some(p))))
            .map(|(_, s)| s.bytes_per_s_now())
            .sum()
    }

    fn links(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], Arc<LinkShaper>>> {
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn offered(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], ShapingOffer>> {
        self.offered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], OfferAnswerTx>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The dialler is about to send its offer on `link`: the receiver
    /// resolves when the peer's offer is resolved against it
    /// ([`Self::peer_offer`]), or closes when the link is forgotten.
    pub fn begin_offer(&self, link: [u8; 16]) -> OfferAnswerRx {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending().insert(link, tx);
        rx
    }

    /// Whether this node already sent an offer on `link`.
    #[must_use]
    pub fn has_offered(&self, link: [u8; 16]) -> bool {
        self.offered().contains_key(&link)
    }

    /// The peer never answered within the budget: the link stays unshaped
    /// for good. A late offer is answered `off` (the peer, if it installed a
    /// shaper on its answer, will refuse our bare frames and close the link:
    /// a lost answer never leaves a half-shaped link).
    pub fn offer_unanswered(&self, link: [u8; 16]) {
        self.offered().insert(link, ShapingOffer::off());
        self.pending().remove(&link);
        let peer = self.link_peer().get(&link).cloned();
        if let Some(p) = peer {
            self.note_peer_shapes(&p, false);
        }
    }

    /// This node's offer for `link` to `peer` (recorded as sent): the class
    /// rate on any link the policy offers on ([`ShapingOffer::from_policy`]).
    /// **The cap limits rate, not whether:** past eight links the link is
    /// still offered shaping, and takes its share once shaped
    /// ([`Self::rebalance`]). `off` only where the policy offers nothing.
    #[must_use]
    pub fn offer_for(
        &self,
        link: [u8; 16],
        frame_bytes: usize,
        peer: Option<&str>,
    ) -> ShapingOffer {
        let policy = self.policy();
        let offer = if policy.enabled() && self.is_seat_link(peer) {
            ShapingOffer::seat(frame_bytes)
        } else if policy.offers_on(self.is_layer_peer(peer)) {
            ShapingOffer::from_policy(&policy, frame_bytes)
        } else {
            ShapingOffer::off()
        };
        if let Some(p) = peer {
            self.link_peer().insert(link, p.to_owned());
        }
        self.offered().insert(link, offer);
        offer
    }

    /// Record this node's `off` offer for `link` (a link that is never shaped,
    /// whatever the policy: a scoped or A/V link).
    pub fn offer_off_for(&self, link: [u8; 16]) -> ShapingOffer {
        let off = ShapingOffer::off();
        self.offered().insert(link, off);
        off
    }

    /// The peer's offer arrived for `link`: resolve it against ours. `Ok(Some)`
    /// installs the shaper; `Ok(None)` leaves the link unshaped; `Err` is a
    /// refusal the caller closes the link for.
    ///
    /// # Errors
    /// [`ShapingError::UnshapedPeer`] under `require_shaped_links`.
    pub fn peer_offer(
        &self,
        link: [u8; 16],
        theirs: &ShapingOffer,
    ) -> Result<Option<Arc<LinkShaper>>, ShapingError> {
        // The offer stays recorded (as `off`) so a second offer on the link
        // is never answered twice.
        let ours = self
            .offered()
            .insert(link, ShapingOffer::off())
            .unwrap_or_else(ShapingOffer::off);
        let peer = self.link_peer().get(&link).cloned();
        if let Some(p) = peer.as_deref() {
            // A refusal comes from a node that shapes and has no room.
            self.note_peer_shapes(
                p,
                theirs.shapes() || theirs.class == BudgetClass::HomeElsewhere,
            );
        }
        let refused = ours.class == BudgetClass::HomeElsewhere
            || theirs.class == BudgetClass::HomeElsewhere
            || (ours.shapes() && theirs.shapes() && self.at_bound_for(peer.as_deref()));
        let out = match agree(&ours, theirs) {
            _ if refused => Err(ShapingError::HomeElsewhere),
            Some(agreement) => {
                let shaper = Arc::new(LinkShaper::new(link, agreement, self.queue_cap));
                self.links().insert(link, Arc::clone(&shaper));
                if !self.pending().contains_key(&link) {
                    let n = self.admissions.fetch_add(1, Ordering::AcqRel);
                    self.admitted
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .insert(link, n);
                }
                self.rebalance();
                Ok(Some(shaper))
            }
            None if self.policy().require_shaped_links && ours.shapes() => {
                Err(ShapingError::UnshapedPeer)
            }
            None => Ok(None),
        };
        if let Some(tx) = self.pending().remove(&link) {
            // choke-ok: a dial that stopped waiting closed the link.
            let _ = tx.send(match &out {
                Ok(s) => Ok(s.is_some()),
                Err(ShapingError::HomeElsewhere) => Err(ShapingError::HomeElsewhere),
                Err(_) => Err(ShapingError::UnshapedPeer),
            });
        }
        out
    }

    /// The shaper of `link`, when shaped.
    #[must_use]
    pub fn get(&self, link: [u8; 16]) -> Option<Arc<LinkShaper>> {
        self.links().get(&link).cloned()
    }

    /// Whether `link` is shaped.
    #[must_use]
    pub fn is_shaped(&self, link: [u8; 16]) -> bool {
        self.links().contains_key(&link)
    }

    /// Whether this node sent an offer on `link` that is still unanswered.
    #[must_use]
    pub fn awaiting_answer(&self, link: [u8; 16]) -> bool {
        self.offered().get(&link).is_some_and(ShapingOffer::shapes)
    }

    /// The link closed: stop and forget its shaper.
    pub fn forget(&self, link: &[u8; 16]) {
        if let Some(s) = self.links().remove(link) {
            s.stop();
        }
        self.admitted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
        self.offered().remove(link);
        self.pending().remove(link);
        let peer = self.link_peer().remove(link);
        if let Some(peer) = peer {
            let held = self.link_peer().values().any(|p| *p == peer);
            if !held {
                self.peer_capacity().remove(&peer);
            }
        }
        self.referral_parts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
        self.referrals
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
        self.bulk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
        self.rebalance();
    }

    /// Mark `link` as a bulk-plane link (dialled with no shaping offer).
    pub fn mark_bulk(&self, link: [u8; 16]) {
        self.bulk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(link);
    }

    /// Whether `link` is a bulk-plane link this node dialled.
    #[must_use]
    pub fn is_bulk(&self, link: [u8; 16]) -> bool {
        self.bulk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&link)
    }

    /// CC 5.4.3 rc16 **two planes** — whether `envelope` must leave `link`
    /// for an unshaped bulk link: `link` is shaped AND the envelope is bulk
    /// ([`is_bulk_payload`]) or beyond one window's real-frame budget
    /// ([`Agreement::reach_frames`], which a tiny budget can put below
    /// [`SHAPED_ROW_MAX_BYTES`]). An unshaped link carries anything.
    #[must_use]
    pub fn needs_bulk_plane(&self, link: [u8; 16], envelope: &[u8]) -> bool {
        let Some(shaper) = self.get(link) else {
            return false;
        };
        if is_bulk_payload(envelope) {
            return true;
        }
        let cap = body_capacity(shaper.agreement().frame_bytes);
        crate::transport::frame_fragment::fragment(envelope, cap)
            .map_or(true, |f| f.len() > shaper.reach_frames_now())
    }

    /// Shaped links now.
    #[must_use]
    pub fn shaped_count(&self) -> usize {
        self.links().len()
    }

    /// The shaped links' ids.
    #[must_use]
    pub fn shaped_links(&self) -> Vec<[u8; 16]> {
        self.links().keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(class: BudgetClass, frame: u16, bytes: u32, rho: f64, w: u32) -> ShapingOffer {
        let p = ShapingPolicy {
            class,
            bytes_per_s: bytes,
            rho,
            window: Duration::from_secs(u64::from(w)),
            node_cap_bytes_per_s: u32::MAX,
            require_shaped_links: false,
            scope: ShapingScope::AllIdentityLinks,
            share: ShapedSharePolicy::DivideNoFloor,
            layer_reserve_links: DEFAULT_LAYER_RESERVE_LINKS,
        };
        ShapingOffer::from_policy(&p, usize::from(frame))
    }

    #[test]
    fn an_offer_round_trips() {
        let o = offer(BudgetClass::Home, 400, 2800, 0.5, 600);
        assert_eq!(o.rate_milli, 7000);
        let back = ShapingOffer::decode(&o.encode()).expect("decodes");
        assert_eq!(back, o);
        assert_eq!(
            ShapingOffer::decode(&ShapingOffer::off().encode()).unwrap(),
            ShapingOffer::off()
        );
        assert!(matches!(
            ShapingOffer::decode(b"CTKX"),
            Err(ShapingError::NotAnOffer)
        ));
        let mut bad = o.encode();
        bad[12..14].copy_from_slice(&2000u16.to_be_bytes());
        assert!(matches!(
            ShapingOffer::decode(&bad),
            Err(ShapingError::Malformed(_))
        ));
        let mut long = o.encode();
        long[14..18].copy_from_slice(&(MAX_WINDOW_S + 1).to_be_bytes());
        assert!(
            matches!(ShapingOffer::decode(&long), Err(ShapingError::Malformed(_))),
            "a window past one day is refused"
        );
    }

    #[test]
    fn agreement_is_the_conservative_of_the_two_and_symmetric() {
        let a = offer(BudgetClass::Server, 1400, 7000, 0.8, 600);
        let b = offer(BudgetClass::PhoneWifi, 400, 1400, 0.5, 60);
        let ab = agree(&a, &b).expect("shaped");
        let ba = agree(&b, &a).expect("shaped");
        assert_eq!(ab, ba);
        assert_eq!(ab.frame_bytes, 400);
        assert!((ab.lambda - 3.5).abs() < 1e-6, "{}", ab.lambda);
        assert!((ab.rho - 0.5).abs() < 1e-9);
        assert_eq!(ab.window, Duration::from_secs(600));
        assert!(agree(&a, &ShapingOffer::off()).is_none());
        assert!(agree(&ShapingOffer::off(), &b).is_none());
    }

    #[test]
    fn a_half_shaped_link_is_unshaped_or_refused_by_policy() {
        let link = [7u8; 16];
        let lenient = LinkShapers::new(ShapingPolicy::for_class(BudgetClass::Home));
        let _ = lenient.offer_for(link, 400, None);
        assert!(lenient
            .peer_offer(link, &ShapingOffer::off())
            .unwrap()
            .is_none());
        assert!(!lenient.is_shaped(link));
        let mut strict_policy = ShapingPolicy::for_class(BudgetClass::Home);
        strict_policy.require_shaped_links = true;
        let strict = LinkShapers::new(strict_policy);
        let _ = strict.offer_for(link, 400, None);
        assert!(matches!(
            strict.peer_offer(link, &ShapingOffer::off()),
            Err(ShapingError::UnshapedPeer)
        ));
        // A node that offers nothing never refuses: it is the one that is off.
        let off = LinkShapers::new(ShapingPolicy::default());
        let o = off.offer_for(link, 400, None);
        assert_eq!(o.class, BudgetClass::Off);
        assert!(off
            .peer_offer(link, &offer(BudgetClass::Home, 400, 2800, 0.5, 600))
            .unwrap()
            .is_none());
    }

    fn shaped_links(t: &LinkShapers, n: u8, prefix: &str, base: u8) {
        let peer = offer(BudgetClass::Server, 400, 7000, 0.5, 600);
        for i in 0..n {
            let link = [base + i; 16];
            let o = t.offer_for(link, 400, Some(&format!("{prefix}{i}")));
            assert_ne!(o.class, BudgetClass::Off, "{prefix}{i} is offered shaping");
            t.peer_offer(link, &peer).unwrap().expect("shaped");
        }
    }

    /// **The default arm** ([`ShapedSharePolicy::BoundedWithFloor`], Eric
    /// 2026-11-04): eight shaped links each at the full class rate, summing
    /// to the cap; the ninth shaping peer is REFUSED by name on both sides
    /// (the responder answers `home-elsewhere`; a dialler at its bound refuses
    /// at the answer), never run unshaped; a peer whose offer is `off` is not
    /// a shaping peer and gets its ordinary unshaped link. Mutation: run the
    /// ninth link instead of refusing → this fails.
    #[test]
    fn at_the_bound_a_ninth_shaping_peer_is_refused_and_an_off_peer_is_not() {
        let p = ShapingPolicy::fleet_default(BudgetClass::Server);
        let cap = f64::from(p.node_cap_bytes_per_s);
        let t = LinkShapers::new(p);
        shaped_links(&t, 8, "g", 10);
        for i in 0..8u8 {
            let s = t.get([10 + i; 16]).expect("a link");
            assert!(
                (s.bytes_per_s_now() - 7000.0).abs() < 1.0,
                "full class rate"
            );
        }
        assert!((t.effective_total() - cap).abs() < 8.0);
        assert!(t.at_bound());
        let peer = offer(BudgetClass::Server, 400, 7000, 0.5, 600);
        let ours = t.offer_for_answer([100u8; 16], 400, Some("ninth"), &peer);
        assert_eq!(ours.class, BudgetClass::HomeElsewhere);
        assert!(matches!(
            t.peer_offer([100u8; 16], &peer),
            Err(ShapingError::HomeElsewhere)
        ));
        assert!(
            !t.is_shaped([100u8; 16]),
            "never run unshaped either: refused"
        );
        assert_eq!(
            ShapingError::HomeElsewhere.label(),
            crate::observability::LINK_SHAPING_HOME_ELSEWHERE
        );
        let o = t.offer_for([101u8; 16], 400, Some("tenth"));
        assert!(
            o.shapes(),
            "a dialler offers; the bound is decided at the answer"
        );
        assert!(matches!(
            t.peer_offer([101u8; 16], &peer),
            Err(ShapingError::HomeElsewhere)
        ));
        let _ = t.offer_for([102u8; 16], 400, Some("refuser"));
        assert!(matches!(
            t.peer_offer([102u8; 16], &ShapingOffer::home_elsewhere()),
            Err(ShapingError::HomeElsewhere)
        ));
        let ours = t.offer_for_answer([103u8; 16], 400, Some("quiet"), &ShapingOffer::off());
        assert!(ours.shapes());
        assert!(t
            .peer_offer([103u8; 16], &ShapingOffer::off())
            .unwrap()
            .is_none());
        assert_eq!(t.shaped_count(), 8);
        t.forget(&[10u8; 16]);
        assert!(!t.at_bound());
        let _ = t.offer_for([104u8; 16], 400, Some("next"));
        t.peer_offer([104u8; 16], &peer).unwrap().expect("shaped");
        assert!((t.effective_total() - cap).abs() < 8.0);
        let back = ShapingOffer::decode(&ShapingOffer::home_elsewhere().encode()).unwrap();
        assert_eq!(back.class, BudgetClass::HomeElsewhere);
        assert!(agree(&back, &peer).is_none());
    }

    /// **The other arm** ([`ShapedSharePolicy::DivideNoFloor`]): a server at
    /// eight links takes a ninth shaping peer, the link IS shaped, and the
    /// links' rates still sum to the cap. A peer leaving gives its share back.
    #[test]
    fn under_divide_no_floor_a_ninth_shaping_peer_is_shaped_and_the_links_share_the_cap() {
        let mut p = ShapingPolicy::fleet_default(BudgetClass::Server);
        p.share = ShapedSharePolicy::DivideNoFloor;
        let cap = f64::from(p.node_cap_bytes_per_s);
        let t = LinkShapers::new(p);
        shaped_links(&t, 8, "g", 10);
        assert_eq!(t.shaped_count(), 8);
        assert!(
            (t.effective_total() - cap).abs() < 8.0,
            "{}",
            t.effective_total()
        );
        shaped_links(&t, 1, "ninth", 100);
        assert_eq!(t.shaped_count(), 9, "the ninth peer's link IS shaped");
        assert!(
            t.effective_total() <= cap + 1.0,
            "{} over {cap}",
            t.effective_total()
        );
        let any = t.get([10u8; 16]).expect("a link");
        assert!((any.bytes_per_s_now() - cap / 9.0).abs() < 1.0);
        assert!(
            any.agreement().bytes_per_s() >= 7000,
            "the agreement is the bound, untouched"
        );
        t.forget(&[100u8; 16]);
        t.forget(&[10u8; 16]);
        assert_eq!(t.shaped_count(), 7);
        let back = t.get([11u8; 16]).expect("a link");
        assert!(
            (back.bytes_per_s_now() - 7000.0).abs() < 1.0,
            "the share rises back"
        );
    }

    /// No floor anywhere a shaping peer could be turned off: a cellular class
    /// on a 16 KB frame is quoted at its true rate (one frame per 46 s), and
    /// under `DivideNoFloor` a hundred links each take a hundredth of the cap
    /// and the sum stays under it.
    #[test]
    fn a_slow_rate_is_quoted_not_refused_and_divide_no_floor_keeps_the_sum_under_the_cap() {
        let cell = ShapingPolicy::for_class(BudgetClass::PhoneCellular);
        let o = ShapingOffer::from_policy(&cell, 16_272);
        assert!(o.shapes(), "350 B/s on a 16 KB frame is quoted, not off");
        assert_eq!(o.rate_milli, 22);
        let mut p = ShapingPolicy::fleet_default(BudgetClass::Server);
        p.share = ShapedSharePolicy::DivideNoFloor;
        let cap = f64::from(p.node_cap_bytes_per_s);
        let t = LinkShapers::new(p);
        let peer = offer(BudgetClass::Server, 16_272, 7000, 0.5, 600);
        for i in 0..100u8 {
            let _ = t.offer_for([i; 16], 16_272, Some(&format!("p{i}")));
            t.peer_offer([i; 16], &peer).unwrap().expect("shaped");
            assert!(t.effective_total() <= cap + 1.0, "{} links", i + 1);
        }
        assert_eq!(t.shaped_count(), 100);
        let per_link = t.get([0u8; 16]).expect("a link").bytes_per_s_now();
        assert!(
            (per_link - 560.0).abs() < 1.0,
            "a hundredth of the cap: {per_link}"
        );
    }

    #[test]
    fn frames_are_one_size_and_cover_is_told_from_real_only_inside() {
        let mut pad = |b: &mut [u8]| b.iter_mut().for_each(|x| *x = 0xAB);
        let real = wrap(400, Some(b"hello"), &mut pad).unwrap();
        let cover = wrap(400, None, &mut pad).unwrap();
        assert_eq!(real.len(), 400);
        assert_eq!(cover.len(), 400);
        assert_eq!(unwrap(&real).unwrap(), ShapedFrame::Real(b"hello".to_vec()));
        assert_eq!(unwrap(&cover).unwrap(), ShapedFrame::Cover);
        assert!(matches!(
            wrap(100, Some(&[0u8; 100]), &mut pad),
            Err(ShapingError::BodyTooLarge(..))
        ));
        assert!(matches!(
            unwrap(b"CFRG...."),
            Err(ShapingError::WrongKind(_))
        ));
    }

    #[tokio::test]
    async fn the_shaper_emits_real_under_budget_then_cover_and_stops() {
        let agreement = Agreement {
            lambda: 200.0,
            frame_bytes: 200,
            rho: 0.5,
            window: Duration::from_secs(1),
        };
        let s = LinkShaper::new([9u8; 16], agreement, 16);
        s.enqueue(vec![b"a".to_vec(), b"b".to_vec()]).unwrap();
        let mut reals = 0;
        let mut covers = 0;
        for _ in 0..40 {
            match s.next_emission().await {
                Emission::Frame { bytes, real, .. } => match unwrap(&bytes).unwrap() {
                    ShapedFrame::Real(_) => {
                        assert!(real);
                        reals += 1;
                    }
                    ShapedFrame::Cover => {
                        assert!(!real);
                        covers += 1;
                    }
                    ShapedFrame::Many(_) => panic!("no coalescing was announced"),
                },
                Emission::Stopped => panic!("not stopped"),
            }
        }
        assert_eq!(reals, 2, "both bodies went, once each");
        assert_eq!(covers, 38);
        assert!(matches!(
            s.enqueue(vec![vec![0u8; 300]]),
            Err(ShapingError::BodyTooLarge(..))
        ));
        assert!(matches!(
            s.enqueue(vec![vec![0u8; 10]; 17]),
            Err(ShapingError::QueueFull(16))
        ));
        s.stop();
        assert!(matches!(s.next_emission().await, Emission::Stopped));
    }

    fn peer_offer_at(class: BudgetClass) -> ShapingOffer {
        offer(class, 400, class.default_bytes_per_s(), 0.5, 600)
    }

    /// Eric's fleet default (2026-11-02, final): shaping ON by default for
    /// `server` only; `home`, `phone-wifi` and `phone-cellular` shape every
    /// link only when the person opts in; every class shapes its layer links.
    /// The CC 5.4.3 table's values ride with each class, and the cost
    /// columns match the rate.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn the_fleet_default_is_on_for_server_only_and_opt_in_elsewhere() {
        for (kind, unmetered, class, general) in [
            (DeviceKind::Server, true, BudgetClass::Server, true),
            (DeviceKind::Home, true, BudgetClass::Home, false),
            (DeviceKind::Phone, true, BudgetClass::PhoneWifi, false),
            (DeviceKind::Phone, false, BudgetClass::PhoneCellular, false),
        ] {
            let mut d = DeviceState::of(kind);
            d.unmetered = unmetered;
            let p = ShapingPolicy::for_device(&d);
            assert_eq!(p.class, class);
            assert!(p.enabled());
            assert_eq!(
                p.offers_on(false),
                general,
                "{class:?} general links by default"
            );
            assert!(p.offers_on(true), "{class:?} always shapes its layer links");
            assert!((p.rho - 0.5).abs() < 1e-9);
            let w = if class == BudgetClass::PhoneCellular {
                3600
            } else {
                600
            };
            assert_eq!(p.window, Duration::from_secs(w));
            assert_eq!(p.node_cap_bytes_per_s, class.default_bytes_per_s() * 8);
            let t = LinkShapers::new(p);
            let o = t.offer_for([1u8; 16], 400, Some("stranger"));
            assert_eq!(o.class == BudgetClass::Off, !general, "{class:?}");
            // The person opts in: every class, cellular included, shapes all.
            d.shaping_opt_in = true;
            d.shaping_opt_in_cellular = true;
            assert!(
                ShapingPolicy::for_device(&d).offers_on(false),
                "{class:?} opted in"
            );
            // The table's cost columns follow the rate (within rounding).
            let row = fleet_default_row(class).expect("a row per class");
            #[allow(clippy::cast_precision_loss)]
            let per_link = ShapingPolicy::for_class(class).monthly_bytes_per_link() as f64 / 1e9;
            assert!(
                (row.gb_month_per_link_each_way - per_link).abs() < 0.06,
                "{class:?}"
            );
            assert!(
                (row.gb_month_at_cap_each_way - per_link * 8.0).abs() < 0.1,
                "{class:?}"
            );
        }
        assert_eq!(
            FLEET_DEFAULTS
                .iter()
                .filter(|r| r.on_by_default)
                .map(|r| r.class)
                .collect::<Vec<_>>(),
            vec![BudgetClass::Seat, BudgetClass::Server]
        );
        assert_eq!(
            ShapingPolicy::for_class(BudgetClass::Server).share,
            ShapedSharePolicy::BoundedWithFloor {
                max_links: NODE_CAP_LINKS,
                floor_bytes_per_s: 7000
            },
            "the default share policy (Eric, 2026-11-04)"
        );
        assert!(!ShapingPolicy::fleet_default(BudgetClass::Off).enabled());
        // The library default stays off: a host names its class.
        assert!(!ShapingPolicy::default().enabled());
        assert_eq!(
            ShapingPolicy::for_class(BudgetClass::Server).monthly_bytes_per_link(),
            18_144_000_000
        );
        assert_eq!(
            ShapingPolicy::for_class(BudgetClass::PhoneCellular).monthly_bytes_per_link(),
            907_200_000
        );
    }

    /// The policy changes at runtime. A person who opted in on Wi-Fi moves
    /// to cellular: the opt-in is kept (cellular is opted in too, Eric
    /// 2026-11-02), and links whose agreed rate is above the cellular rate
    /// close (to be redialled under the new class, never half-shaped) while a
    /// link already at the cellular rate stays. A person who did NOT opt in
    /// keeps only the layer link. Shaping off closes everything.
    #[test]
    fn a_class_change_at_runtime_keeps_the_opt_in_and_closes_what_no_longer_fits() {
        let mut wifi = DeviceState::of(DeviceKind::Phone);
        wifi.charging = false;
        wifi.shaping_opt_in = true;
        wifi.shaping_opt_in_cellular = true;
        let cell_peer = peer_offer_at(BudgetClass::PhoneCellular);
        let build = |d: &DeviceState| {
            let t = LinkShapers::new(ShapingPolicy::for_device(d));
            t.set_layer_peers(["relay-a".to_owned()].into_iter().collect());
            let _ = t.offer_for([1u8; 16], 400, Some("friend"));
            t.peer_offer([1u8; 16], &cell_peer)
                .unwrap()
                .expect("shaped");
            let _ = t.offer_for([2u8; 16], 400, Some("relay-a"));
            t.peer_offer([2u8; 16], &cell_peer)
                .unwrap()
                .expect("shaped");
            let _ = t.offer_for([3u8; 16], 400, Some("other"));
            t.peer_offer([3u8; 16], &peer_offer_at(BudgetClass::Server))
                .unwrap()
                .expect("shaped");
            assert_eq!(t.shaped_count(), 3);
            t
        };
        let t = build(&wifi);
        let cell = wifi.with_network(false, false);
        assert!(
            cell.shaping_opt_in && cell.shaping_opt_in_cellular,
            "a network change keeps the person's choices"
        );
        let closed = t.set_policy(ShapingPolicy::for_device(&cell));
        assert_eq!(
            closed,
            vec![[3u8; 16]],
            "only the link above the cellular rate closes"
        );
        assert!(t.is_shaped([1u8; 16]) && t.is_shaped([2u8; 16]));
        assert_eq!(t.policy().class, BudgetClass::PhoneCellular);
        assert_eq!(
            t.offer_for([4u8; 16], 400, Some("friend")).class,
            BudgetClass::PhoneCellular,
            "opted in on cellular: general links are still offered"
        );
        // Back on Wi-Fi: nothing closes, general links offered at the Wi-Fi class.
        assert!(t.set_policy(ShapingPolicy::for_device(&wifi)).is_empty());
        assert_eq!(
            t.offer_for([5u8; 16], 400, Some("friend")).class,
            BudgetClass::PhoneWifi
        );

        // Not opted in: the move to cellular leaves only the layer link.
        // This is Wi-Fi-only shaping (E17): the Wi-Fi choice stands, and the
        // move back restores it.
        let mut quiet = wifi;
        quiet.shaping_opt_in_cellular = false;
        let t = build(&quiet);
        let cellular = quiet.with_network(false, false);
        assert!(cellular.shaping_opt_in && !cellular.shaping_opt_in_cellular);
        let mut closed = t.set_policy(ShapingPolicy::for_device(&cellular));
        closed.sort_unstable();
        assert_eq!(closed, vec![[1u8; 16], [3u8; 16]]);
        assert!(t.is_shaped([2u8; 16]), "the layer link stays shaped");
        assert_eq!(
            t.offer_for([6u8; 16], 400, Some("friend")).class,
            BudgetClass::Off,
            "on cellular, not opted in: general links are offered nothing"
        );
        assert!(t.set_policy(ShapingPolicy::for_device(&quiet)).is_empty());
        assert_eq!(
            t.offer_for([7u8; 16], 400, Some("friend")).class,
            BudgetClass::PhoneWifi,
            "back on Wi-Fi: restored"
        );
        // Turning shaping off closes every shaped link.
        assert_eq!(t.set_policy(ShapingPolicy::default()), vec![[2u8; 16]]);
        assert_eq!(t.shaped_count(), 0);
    }

    /// CC 5.4.3 rc16 two planes — the bulk classes are read off the
    /// envelope head; rows are not bulk; and a payload needs the bulk plane
    /// only when its link is shaped.
    #[test]
    fn bulk_is_classified_by_kind_and_only_leaves_a_shaped_link() {
        use crate::messages::MessageType as M;
        // The exact bytes the field produces: the envelope the edge builds
        // (field order and serde spelling of the real `EdgeEnvelope`).
        let env = |t: M| {
            let mut v = serde_json::json!({
                "edge_schema_version": crate::messages::SchemaVersion::default(),
                "signing_key_id": "a",
                "destination_key_id": "b",
                "message_type": t,
            })
            .to_string()
            .into_bytes();
            // serde_json::json! sorts keys; the edge's struct order puts
            // `message_type` before `body` and the signatures: append those.
            v.pop();
            v.extend_from_slice(br#","body":{"x":1},"signature":"s"}"#);
            v
        };
        for t in [
            M::ContentFetch,
            M::ContentBody,
            M::BlobChunkFetch,
            M::BlobChunkBody,
        ] {
            assert!(is_bulk_class(&env(t.clone())), "{t:?}");
        }
        for t in [
            M::AttestationGossip,
            M::OpaqueRequest,
            M::ContentMiss,
            M::BlobChunkMiss,
        ] {
            assert!(!is_bulk_class(&env(t.clone())), "{t:?}");
        }
        assert!(!is_bulk_class(b"not json at all"));
        let t = LinkShapers::new(ShapingPolicy::for_class(BudgetClass::Server));
        let link = [3u8; 16];
        assert!(
            !t.needs_bulk_plane(link, &env(M::BlobChunkBody)),
            "unshaped: carries anything"
        );
        let _ = t.offer_for(link, 1400, None);
        t.peer_offer(link, &offer(BudgetClass::Server, 1400, 7000, 0.5, 600))
            .unwrap()
            .expect("shaped");
        assert!(t.needs_bulk_plane(link, &env(M::BlobChunkBody)));
        assert!(
            !t.needs_bulk_plane(link, &env(M::AttestationGossip)),
            "a row stays"
        );
        assert!(
            t.needs_bulk_plane(link, &vec![b'r'; 3_000_000]),
            "beyond reach"
        );
        t.mark_bulk([4u8; 16]);
        assert!(t.is_bulk([4u8; 16]));
        t.forget(&[4u8; 16]);
        assert!(!t.is_bulk([4u8; 16]));
    }

    /// One constant decides: over 64 KiB is bulk whatever the type, and the
    /// window budget does not. Two sends of one envelope are one transfer;
    /// a failed one can start again and a finished one is not re-sent.
    #[test]
    fn the_row_limit_and_the_fallback_single_flight() {
        assert!(!is_bulk_payload(&vec![b'r'; SHAPED_ROW_MAX_BYTES]));
        assert!(is_bulk_payload(&vec![b'r'; SHAPED_ROW_MAX_BYTES + 1]));
        let f = BulkFallbacks::default();
        let (_, owner) = f.join_or_start([1; 32]);
        assert!(owner.is_some());
        assert!(f.join_or_start([1; 32]).1.is_none(), "a retry joins it");
        f.finish(&[1; 32], false);
        assert!(!f.recently_finished(&[1; 32]));
        assert!(f.join_or_start([1; 32]).1.is_some(), "a failure restarts");
        f.finish(&[1; 32], true);
        assert!(
            f.recently_finished(&[1; 32]),
            "a finished one is not re-sent"
        );
    }

    /// CC 5.4.3 rc17 `CLM-seat-class`: the table's row exactly (33,000 B/s,
    /// ρ 0.5, W 600 s), offered only to a proved seat by a proved seat; a seat
    /// beside a non-seat runs at the non-seat's class; a seat link sits
    /// outside the eight; nothing a peer says makes it a seat.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn a_seat_shapes_a_proved_seat_at_the_seat_row_outside_the_eight() {
        let p = ShapingPolicy::fleet_default(BudgetClass::Server);
        let t = LinkShapers::new(p);
        t.set_seats(
            ["seat-b".to_owned(), "me".to_owned()].into_iter().collect(),
            true,
        );
        let o = t.offer_for([1u8; 16], 16_272, Some("seat-b"));
        assert_eq!(o.class, BudgetClass::Seat);
        assert_eq!((o.rho_milli, o.window_s), (500, 600));
        assert_eq!(o.rate_milli, 2028, "33,000 B/s at 16,272 B");
        assert_eq!(
            o.encode()[5],
            BudgetClass::Server as u8,
            "the wire byte is server"
        );
        let back = ShapingOffer::decode(&o.encode()).unwrap();
        assert_eq!(back.class, BudgetClass::Server);
        assert_eq!(back.rate_milli, 2028);
        let a = agree(&o, &back).expect("seat to seat");
        assert!(
            (i64::from(a.bytes_per_s()) - 33_000).abs() <= 2,
            "{}",
            a.bytes_per_s()
        );
        let normal = t.offer_for([2u8; 16], 16_272, Some("home-node"));
        assert_eq!(normal.class, BudgetClass::Server);
        assert_eq!(normal.rate_milli, 430, "7000 B/s at 16,272 B");
        let mixed = agree(&o, &normal).expect("seat to non-seat");
        assert!(mixed.lambda < 0.5, "the lower of the two: {}", mixed.lambda);
        t.peer_offer([1u8; 16], &back)
            .unwrap()
            .expect("seat link shaped");
        shaped_links(&t, 8, "g", 10);
        assert!(t.at_bound());
        assert!(!t.at_bound_for(Some("seat-b")), "outside the eight");
        assert_eq!(t.shaped_count(), 9);
        assert!(
            t.effective_total() <= 8.0 * 7000.0 + 8.0,
            "{}",
            t.effective_total()
        );
        let seat_rate = t.get([1u8; 16]).unwrap().bytes_per_s_now();
        assert!((seat_rate - 33_000.0).abs() < 3.0, "{seat_rate}");
        let u = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        u.set_seats(["seat-b".to_owned()].into_iter().collect(), false);
        let o = u.offer_for([3u8; 16], 16_272, Some("seat-b"));
        assert_eq!((o.class, o.rate_milli), (BudgetClass::Server, 430));
        assert_eq!(BudgetClass::parse("seat"), Some(BudgetClass::Seat));
    }

    /// A node reports its free slots when they change, inside the frames; the
    /// report tracks links, layer holds included, and a peer's report goes
    /// with its last link.
    #[test]
    fn free_slots_follow_the_links_and_a_report_goes_with_its_peer() {
        let t = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        assert_eq!(t.free_slots(), 8);
        shaped_links(&t, 3, "g", 10);
        assert_eq!(t.free_slots(), 5);
        t.set_layer_peers((0..2).map(|i| format!("L{i}")).collect());
        assert_eq!(t.free_slots(), 3, "two held for waiting layer neighbours");
        t.note_peer_capacity([10u8; 16], 4);
        assert_eq!(t.peer_free_slots("g0"), Some(4));
        t.forget(&[10u8; 16]);
        assert_eq!(t.peer_free_slots("g0"), None);
    }

    /// Eric 2026-11-04 — **offering relay is the consent to be referred.** A
    /// node with its offering off reports zero, so a peer never ranks it; a
    /// phone that loses Wi-Fi reports zero at once, on the running link.
    #[test]
    fn a_node_reports_slots_only_while_its_relay_offering_is_on() {
        let r = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        r.enable_capacity_reports();
        shaped_links(&r, 1, "g", 10);
        assert_eq!(r.reported_slots(), 0, "off until the host says otherwise");
        let idle = r.get([10u8; 16]).expect("a link").room();
        r.set_relay_offering(true);
        assert_eq!(r.reported_slots(), 7);
        let link = r.get([10u8; 16]).expect("a link");
        assert_eq!(link.room(), idle - 1, "the report went out on the link");
        r.set_relay_offering(false);
        assert_eq!(r.reported_slots(), 0);
        assert_eq!(link.room(), idle - 2, "and so did the zero");

        // The peer's side: a zero report takes the node out of the ranking.
        let t = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        shaped_links(&t, 1, "phone", 10);
        t.note_peer_capacity([10u8; 16], 4);
        let none = std::collections::HashSet::<String>::new();
        assert_eq!(t.referral_candidates(&none).len(), 1);
        t.note_peer_capacity([10u8; 16], 0);
        assert!(t.referral_candidates(&none).is_empty());
    }

    /// **The herding check:** ten refused peers spread across the referrals.
    /// Four nodes tie on free slots: nobody is first more than three times,
    /// because a node handed out first loses a slot in the local hint.
    #[test]
    fn ten_refused_peers_spread_across_the_referrals() {
        let t = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        shaped_links(&t, 4, "g", 10);
        for l in 10..14u8 {
            t.note_peer_capacity([l; 16], 3);
        }
        let mut firsts: HashMap<String, u32> = HashMap::new();
        for i in 0..10 {
            let excluded: std::collections::HashSet<String> =
                [format!("refused-{i}")].into_iter().collect();
            let ranked = t.referral_candidates(&excluded);
            let first = ranked[0].key_id.clone();
            t.note_referred(&first);
            *firsts.entry(first).or_insert(0) += 1;
        }
        assert_eq!(firsts.len(), 4, "{firsts:?}");
        assert!(firsts.values().all(|n| *n <= 3), "{firsts:?}");
    }

    /// E7 — the wait follows the link's own gap: a full row can leave at every
    /// class, and a fast link keeps the 60 s bound.
    #[test]
    fn a_full_row_has_time_to_leave_at_every_class() {
        let shaper = |bytes: u32| {
            let o = offer(BudgetClass::Server, 16_272, bytes, 0.5, 3600);
            LinkShaper::new([1u8; 16], agree(&o, &o).expect("agreed"), 8)
        };
        let server = shaper(7_000);
        assert!(server.leave_budget(5) <= ROW_LEAVE_MAX);
        assert_eq!(
            server.leave_budget(50),
            ROW_LEAVE_MAX,
            "a fast link keeps 60 s"
        );
        let cellular = shaper(350);
        let p99 = cellular.frame_gap().mul_f64(5.0 + 4.74 * 5f64.sqrt());
        assert!(
            cellular.leave_budget(5) >= p99,
            "{:?} < {p99:?}",
            cellular.leave_budget(5)
        );
    }

    /// **The viability rule** (FSD/TRANSPORT_TIERS_MODEL.md): a five-plane
    /// bootstrap round is five requests then five replies; on a seeded pair
    /// of shapers it completes inside its λ-derived interval (7.75 gaps) in
    /// at least 95 of 100 rounds WITH coalescing, and in well under 95
    /// without (one body per frame: ten frames, about ten gaps). Paused
    /// time: the Poisson stream is the seed's.
    #[tokio::test(start_paused = true)]
    async fn a_five_plane_round_fits_the_lambda_derived_interval_with_coalescing() {
        async fn drain(s: &LinkShaper, ticket: u64) {
            loop {
                match s.next_emission().await {
                    Emission::Frame {
                        real, ticket: t, ..
                    } => {
                        if real {
                            s.note_sent(t);
                        }
                        if s.ticket_left(ticket) {
                            break;
                        }
                    }
                    Emission::Stopped => panic!("stopped"),
                }
            }
        }
        async fn rounds_within(coalesce: bool) -> usize {
            let agreement = Agreement {
                lambda: 50.0,
                frame_bytes: 1400,
                rho: 0.9,
                window: Duration::from_secs(10),
            };
            let a = LinkShaper::new_seeded([1u8; 16], agreement, 256, [7u8; 32]);
            let b = LinkShaper::new_seeded([2u8; 16], agreement, 256, [9u8; 32]);
            if coalesce {
                a.enable_coalescing();
                b.enable_coalescing();
            }
            let interval = a.frame_gap().mul_f64(7.75);
            let mut ok = 0;
            for _ in 0..100 {
                let started = tokio::time::Instant::now();
                let t = a.enqueue((0..5u8).map(|i| vec![i; 200]).collect()).unwrap();
                drain(&a, t).await;
                let t = b.enqueue((0..5u8).map(|i| vec![i; 200]).collect()).unwrap();
                drain(&b, t).await;
                if started.elapsed() <= interval {
                    ok += 1;
                }
            }
            ok
        }
        let with = rounds_within(true).await;
        let without = rounds_within(false).await;
        assert!(
            with >= 95,
            "with coalescing: {with} of 100 inside 7.75 gaps"
        );
        assert!(
            without < 95,
            "one per frame: {without} of 100 inside 7.75 gaps"
        );
    }

    /// v44 coalescing: a multi frame round-trips, is one frame size, and a
    /// shaper whose peer announced the capability packs the queue into one
    /// frame (the measured crawl: 55–220 B control bodies at one per 16 KB
    /// frame); without the announcement it sends one body per frame. Tickets
    /// and retraction: the frame's ticket is its highest body's, and a
    /// retracted range never leaves.
    #[tokio::test]
    async fn a_peer_that_announced_coalescing_gets_many_bodies_per_frame() {
        let mut pad = |b: &mut [u8]| b.iter_mut().for_each(|x| *x = 0xCD);
        let bodies: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 200]).collect();
        let f = wrap_multi(1400, &bodies, &mut pad).unwrap();
        assert_eq!(f.len(), 1400);
        assert_eq!(unwrap(&f).unwrap(), ShapedFrame::Many(bodies.clone()));
        assert!(is_capability_body(&capability_body(5)));
        assert_eq!(capability_free_slots(&capability_body(5)), Some(5));
        let agreement = Agreement {
            lambda: 200.0,
            frame_bytes: 1400,
            rho: 0.9,
            window: Duration::from_secs(1),
        };
        let s = LinkShaper::new([3u8; 16], agreement, 64);
        let last = s
            .enqueue((0..20u8).map(|i| vec![i; 200]).collect())
            .unwrap();
        assert_eq!(last, 20);
        // Not announced: one body per frame.
        let Emission::Frame {
            bytes,
            real,
            ticket,
        } = s.next_emission().await
        else {
            panic!("stopped")
        };
        assert!(real);
        assert_eq!(ticket, 1);
        assert!(matches!(unwrap(&bytes).unwrap(), ShapedFrame::Real(_)));
        // Announced: six 200 B bodies (6 × 202 ≤ 1392) in the next frame.
        s.enable_coalescing();
        let Emission::Frame { bytes, ticket, .. } = s.next_emission().await else {
            panic!("stopped")
        };
        match unwrap(&bytes).unwrap() {
            ShapedFrame::Many(got) => assert_eq!(got.len(), 6),
            other => panic!("{other:?}"),
        }
        assert_eq!(ticket, 7);
        s.note_sent(ticket);
        assert!(s.ticket_left(7) && !s.ticket_left(8));
        assert_eq!(s.queued(), 13);
        assert_eq!(s.retract(15, 20), 6, "the unsent tail is taken back");
        assert_eq!(s.queued(), 7);
        assert_eq!(s.retract(1, 7), 0, "nothing of what left is in the queue");
    }

    /// The classifier's spellings ARE serde's: each bulk class is the JSON
    /// string `MessageType` serializes to, so a rename on either side fails
    /// here instead of silently routing bulk onto the shaped link.
    #[test]
    fn bulk_classes_are_the_wire_spelling_of_their_message_types() {
        use crate::messages::MessageType as M;
        let wire: Vec<String> = [
            M::ContentFetch,
            M::ContentBody,
            M::BlobChunkFetch,
            M::BlobChunkBody,
        ]
        .iter()
        .map(|t| {
            serde_json::to_value(t)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
        assert_eq!(wire, BULK_MESSAGE_TYPES.map(str::to_owned).to_vec());
    }

    /// CC 5.4.3 rc16 **two planes**: a shaped link carries rows, never bulk.
    /// A message within one window's real-frame budget is queued; one beyond
    /// it (a large blob) is refused by name and never queued, so a blob
    /// cannot ride the shaped row plane. At the server class a row of up to
    /// about 2 MB fits (ρ·rate·W = 0.5 × 7000 × 600 B).
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn a_shaped_link_carries_rows_and_refuses_bulk_by_name() {
        let ours = ShapingPolicy::for_class(BudgetClass::Server);
        let t = LinkShapers::new(ours);
        let _ = t.offer_for([1u8; 16], 1400, None);
        let s = t
            .peer_offer([1u8; 16], &offer(BudgetClass::Server, 1400, 7000, 0.5, 600))
            .unwrap()
            .expect("shaped");
        let reach = s.agreement().reach_frames();
        assert_eq!(reach, 1500, "0.5 × 5 frames/s × 600 s");
        let body = body_capacity(1400);
        assert!(reach * body > 2_000_000 && reach * body < 2_200_000);
        s.enqueue(vec![vec![1u8; body]; 40])
            .expect("a row (a small image) rides");
        let e = s.enqueue(vec![vec![1u8; body]; reach + 1]).unwrap_err();
        assert!(matches!(e, ShapingError::BulkBeyondReach(n, r) if n == reach + 1 && r == reach));
        assert_eq!(e.label(), crate::observability::LINK_SHAPING_BULK_REFUSED);
        assert_eq!(s.queued(), 40, "nothing of the bulk message was queued");
    }

    /// CC 5.4.3 rc17 — **layer links count within the eight**, each at the
    /// class rate, and the bound is first come only among equals: while layer
    /// neighbours wait, other peers stop short of the eight by up to
    /// `layer_reserve_links`; a layer neighbour may take any of the eight; a
    /// ninth link of any kind is refused; a `seat` layer link takes no slot.
    /// With no layer peers (the tier not running) nothing is held.
    #[test]
    fn layer_links_take_slots_within_the_eight_at_the_class_rate() {
        let p = ShapingPolicy::fleet_default(BudgetClass::Server);
        let t = LinkShapers::new(p.clone());
        shaped_links(&t, 8, "g", 10);
        assert_eq!(t.layer_held_slots(), 0);
        assert!(t.at_bound());

        let t = LinkShapers::new(p);
        let peer = offer(BudgetClass::Server, 400, 7000, 0.5, 600);
        t.set_layer_peers((0..6).map(|i| format!("L{i}")).collect());
        assert_eq!(t.layer_held_slots(), 4);
        shaped_links(&t, 4, "g", 10);
        assert!(
            t.at_bound_for(Some("g-late")),
            "four are held for the layer"
        );
        assert!(!t.at_bound_for(Some("L0")));
        shaped_links(&t, 4, "L", 100);
        assert_eq!(t.shaped_count(), 8);
        for l in [10u8, 100, 103] {
            let s = t.get([l; 16]).expect("a link");
            assert!(
                (s.bytes_per_s_now() - 7000.0).abs() < 1.0,
                "the class rate, undiluted"
            );
        }
        assert!(
            t.at_bound_for(Some("L4")),
            "a ninth link is refused, layer or not"
        );
        let ours = t.offer_for_answer([120u8; 16], 400, Some("L4"), &peer);
        assert_eq!(ours.class, BudgetClass::HomeElsewhere);
        // A departure: the waiting layer neighbour goes first.
        t.forget(&[10u8; 16]);
        assert!(
            t.at_bound_for(Some("g-late")),
            "held for the two still waiting"
        );
        assert!(!t.at_bound_for(Some("L4")));
        // A seat-to-seat layer link takes no slot.
        t.set_seats(["L5".to_owned()].into_iter().collect(), true);
        let o = t.offer_for([121u8; 16], 16_272, Some("L5"));
        assert_eq!(o.class, BudgetClass::Seat);
        assert!(!t.at_bound_for(Some("L5")));
        t.peer_offer([121u8; 16], &ShapingOffer::decode(&o.encode()).unwrap())
            .unwrap()
            .expect("seat link");
        assert!(t.effective_total() <= 8.0 * 7000.0 + 8.0);
    }

    /// What a node owes each peer, as the production read answers it.
    #[derive(Debug, Default)]
    struct Owed(Mutex<HashMap<String, crate::load_ladder::PeerObligation>>);

    impl Owed {
        fn set(&self, peer: &str, o: crate::load_ladder::PeerObligation) {
            self.0.lock().unwrap().insert(peer.to_owned(), o);
        }
    }

    #[async_trait::async_trait]
    impl crate::load_ladder::PeerObligations for Arc<Owed> {
        async fn obligation_of(&self, peer: &str) -> crate::load_ladder::PeerObligation {
            self.0
                .lock()
                .unwrap()
                .get(peer)
                .copied()
                .unwrap_or(crate::load_ladder::PeerObligation::Ordinary)
        }
    }

    fn shedding(class: BudgetClass) -> (LinkShapers, Arc<Owed>) {
        let t = LinkShapers::new(ShapingPolicy::fleet_default(class));
        let owed = Arc::new(Owed::default());
        t.set_obligations(Arc::new(Arc::clone(&owed)));
        (t, owed)
    }

    fn shaping_peer() -> ShapingOffer {
        offer(BudgetClass::Server, 400, 7000, 0.5, 600)
    }

    /// §6.12 tier 1: a peer owed nothing is refused; every peer a tier leaves
    /// alone is admitted, and so is one the read could not place. Tier 0
    /// refuses nobody, and a peer that does not shape is no shaped link.
    /// Mutation: drop any exemption, or never refuse → this fails.
    #[tokio::test]
    async fn tier_one_refuses_only_a_peer_owed_nothing() {
        use crate::load_ladder::{PeerObligation as O, ServiceTier as T};
        let (t, owed) = shedding(BudgetClass::Server);
        owed.set("device", O::OwnDevice);
        owed.set("seat", O::Seat);
        owed.set("contact", O::SendSet);
        owed.set("unread", O::Unresolved);
        let them = shaping_peer();
        assert!(!t.load_refuses(Some("stranger"), &them).await, "tier 0");
        t.set_service_tier(T::AudioAndFiles);
        assert!(t.load_refuses(Some("stranger"), &them).await);
        for keeps in ["device", "seat", "contact", "unread"] {
            assert!(!t.load_refuses(Some(keeps), &them).await, "{keeps}");
        }
        assert!(
            !t.load_refuses(None, &them).await,
            "an unattributed link is unresolved"
        );
        assert!(
            !t.load_refuses(Some("stranger"), &ShapingOffer::off()).await,
            "a peer that does not shape keeps its ordinary link"
        );
        t.set_service_tier(T::ChatAndContacts);
        assert!(t.load_refuses(Some("stranger"), &them).await, "tier 2 too");
        let plain = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        plain.set_service_tier(T::ChatAndContacts);
        assert!(
            !plain.load_refuses(Some("stranger"), &them).await,
            "with no read installed nothing is shed"
        );
    }

    /// The refusal is the bound's: `home-elsewhere` on the wire, and
    /// [`LinkShapers::peer_offer`] installs nothing.
    #[test]
    fn a_load_refusal_is_the_bounds_refusal_and_installs_nothing() {
        let (t, _) = shedding(BudgetClass::Server);
        let link = [40u8; 16];
        let refusal = t.refusal_for(link, Some("stranger"));
        assert_eq!(refusal.class, BudgetClass::HomeElsewhere);
        assert!(matches!(
            t.peer_offer(link, &shaping_peer()),
            Err(ShapingError::HomeElsewhere)
        ));
        assert!(!t.is_shaped(link));
        assert_eq!(t.free_slots(), 8, "a refused peer holds no slot");
    }

    /// §6.12 tier 1 **reports zero slots**, at once and on the wire, whatever
    /// room the node has; the slots return with the tier. Mutation: leave
    /// `free_slots` alone at tier 1 → this fails.
    #[test]
    fn tier_one_reports_zero_slots_at_once_and_the_slots_return_with_the_tier() {
        use crate::load_ladder::ServiceTier as T;
        let (t, _) = shedding(BudgetClass::Server);
        t.enable_capacity_reports();
        t.set_relay_offering(true);
        shaped_links(&t, 1, "g", 10);
        assert_eq!(t.reported_slots(), 7);
        let link = t.get([10u8; 16]).expect("a link");
        let idle = link.room();
        t.set_service_tier(T::AudioAndFiles);
        assert_eq!(t.free_slots(), 0);
        assert_eq!(t.reported_slots(), 0);
        assert_eq!(link.room(), idle - 1, "the zero went out on the link");
        t.set_service_tier(T::ChatAndContacts);
        assert_eq!(t.reported_slots(), 0);
        assert_eq!(link.room(), idle - 1, "no change, no report");
        t.set_service_tier(T::FullOps);
        assert_eq!(t.free_slots(), 7);
        assert_eq!(
            link.room(),
            idle - 2,
            "and the slots went out with the tier"
        );
    }

    /// §6.12 tier 2: newest first, one peer at a time, and never a peer a
    /// tier leaves alone, however new. The read comes when the link comes up.
    /// Mutation: drop the owner's or the seat's exemption, reverse the order,
    /// or never shed → this fails.
    #[tokio::test]
    async fn tier_two_closes_the_newest_link_of_a_peer_owed_nothing() {
        use crate::load_ladder::{PeerObligation as O, ServiceTier as T};
        let (t, owed) = shedding(BudgetClass::Server);
        // Admitted in this order; the protected are the newest.
        shaped_links(&t, 2, "old", 10);
        shaped_links(&t, 2, "new", 20);
        shaped_links(&t, 1, "device", 30);
        shaped_links(&t, 1, "seat", 40);
        shaped_links(&t, 1, "contact", 50);
        shaped_links(&t, 1, "unread", 60);
        owed.set("device0", O::OwnDevice);
        owed.set("seat0", O::Seat);
        owed.set("contact0", O::SendSet);
        owed.set("unread0", O::Unresolved);
        assert_eq!(t.next_shed().await, None, "tier 0 closes nothing");
        t.set_service_tier(T::AudioAndFiles);
        assert_eq!(t.next_shed().await, None, "nor does tier 1");
        t.set_service_tier(T::ChatAndContacts);
        let mut closed = Vec::new();
        while let Some(link) = t.next_shed().await {
            closed.push(link[0]);
            t.forget(&link);
        }
        assert_eq!(closed, vec![21, 20, 11, 10], "newest first");
        assert_eq!(t.shaped_count(), 4, "the protected links stand");
        // Standing lost a moment ago is read now, not at the tier change.
        owed.set("seat0", O::Ordinary);
        assert_eq!(t.next_shed().await, Some([40u8; 16]));
        t.set_service_tier(T::AudioAndFiles);
        assert_eq!(t.next_shed().await, None, "the tier fell");
    }

    /// A link this node dialled carries this node's own rows, and a close
    /// would only redial it: tier 2 leaves it, as it leaves a home a refused
    /// node found through a referral.
    #[tokio::test]
    async fn tier_two_leaves_a_link_this_node_dialled() {
        use crate::load_ladder::ServiceTier as T;
        let (t, _) = shedding(BudgetClass::Server);
        let link = [70u8; 16];
        let answer = t.begin_offer(link);
        let _ = t.offer_for(link, 400, Some("home"));
        t.peer_offer(link, &shaping_peer())
            .unwrap()
            .expect("shaped");
        assert!(answer.await.unwrap().unwrap());
        t.set_service_tier(T::ChatAndContacts);
        assert_eq!(t.next_shed().await, None);
        let s = t.links_status();
        assert!(s[0].dialled_here);
        assert!(t.is_shaped(link));
    }

    /// **Cover is not shed** (§6.12, CC 5.4.3): no tier moves a shaper's rate
    /// or budget, on a link that stays. Mutation: thin the rate at tier 2 →
    /// this fails.
    #[tokio::test(start_paused = true)]
    async fn no_tier_moves_a_shapers_rate_and_cover_goes_on() {
        use crate::load_ladder::ServiceTier as T;
        let (t, owed) = shedding(BudgetClass::Server);
        owed.set("g0", crate::load_ladder::PeerObligation::OwnDevice);
        shaped_links(&t, 1, "g", 10);
        let s = t.get([10u8; 16]).expect("a link");
        let before = (s.lambda_now(), s.bytes_per_s_now(), s.reach_frames_now());
        let now = || (s.lambda_now(), s.bytes_per_s_now(), s.reach_frames_now());
        for tier in [T::AudioAndFiles, T::ChatAndContacts] {
            t.set_service_tier(tier);
            assert_eq!(now(), before, "{tier:?}");
            // A close elsewhere rebalances: the tier must not enter there.
            t.rebalance();
            assert_eq!(now(), before, "{tier:?} rebalanced");
        }
        assert_eq!(s.queued(), 0, "nothing real is waiting");
        assert!(matches!(
            s.next_emission().await,
            Emission::Frame { real: false, .. }
        ));
    }

    /// §6.12, §7.2: B-pause spares the owner's devices alone. A seat and a
    /// contact keep their links and their files wait; a read that failed
    /// pauses nothing, and tiers 0 and 1 pause nothing.
    #[tokio::test]
    async fn the_slow_path_pauses_at_tier_two_for_all_but_the_owners_devices() {
        use crate::load_ladder::{PeerObligation as O, ServiceTier as T};
        let (t, owed) = shedding(BudgetClass::Server);
        owed.set("device", O::OwnDevice);
        owed.set("seat", O::Seat);
        owed.set("contact", O::SendSet);
        owed.set("unread", O::Unresolved);
        for tier in [T::FullOps, T::AudioAndFiles] {
            t.set_service_tier(tier);
            assert!(!t.slow_path_paused("stranger").await, "{tier:?}");
        }
        t.set_service_tier(T::ChatAndContacts);
        for paused in ["stranger", "seat", "contact"] {
            assert!(t.slow_path_paused(paused).await, "{paused}");
        }
        for runs in ["device", "unread"] {
            assert!(!t.slow_path_paused(runs).await, "{runs}");
        }
    }

    /// E8: the figures are the policy's arithmetic, §2.4's values at the class
    /// rates and something else at any other rate: a table restated would
    /// not move. Off has no cost to state.
    #[test]
    fn the_figures_follow_the_policy_not_a_table() {
        let home = ShapingPolicy::for_class(BudgetClass::Home);
        let f = ShapingFigures::of(&home, REFERENCE_FRAME_BYTES).expect("home shapes");
        assert_eq!(f.class, "home");
        assert!((f.gap_s - 5.81).abs() < 0.01, "{}", f.gap_s);
        assert!((f.gap_p95_s - 17.4).abs() < 0.1, "{}", f.gap_p95_s);
        assert!((f.gb_month_link - 7.26).abs() < 0.01, "{}", f.gb_month_link);
        assert!((f.gb_month_cap - 58.06).abs() < 0.01, "{}", f.gb_month_cap);
        assert!((f.file_1mb_s - 714.3).abs() < 0.1, "{}", f.file_1mb_s);
        assert!((f.file_10mb_s - 7142.9).abs() < 0.1, "{}", f.file_10mb_s);

        let mut doubled = home.clone();
        doubled.bytes_per_s *= 2;
        doubled.node_cap_bytes_per_s *= 2;
        let g = ShapingFigures::of(&doubled, REFERENCE_FRAME_BYTES).unwrap();
        assert!((g.gap_s - f.gap_s / 2.0).abs() < 1e-9);
        assert!((g.gb_month_cap - f.gb_month_cap * 2.0).abs() < 1e-9);
        assert!((g.file_1mb_s - f.file_1mb_s / 2.0).abs() < 1e-9);
        let small = ShapingFigures::of(&home, 3_254).unwrap();
        assert!(
            (small.gap_s - f.gap_s / 5.0).abs() < 0.01,
            "a fifth at the base frame"
        );
        assert!(ShapingFigures::of(&ShapingPolicy::default(), 400).is_none());
    }

    /// E8: a peer's shaping is what the peer said. Unknown until it answers;
    /// a link makes it known and known outlives the link; `off` and silence
    /// say no; a refusal says yes, because a node with no room shapes.
    #[test]
    fn a_peers_shaping_is_what_the_peer_said() {
        let t = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        assert_eq!(t.peer_shaping("g0").shapes, None);
        shaped_links(&t, 1, "g", 10);
        let p = t.peer_shaping("g0");
        assert_eq!((p.shapes, p.shaped_now), (Some(true), true));
        assert!(p.gap_s.is_some_and(|g| g > 0.0));
        t.forget(&[10u8; 16]);
        let p = t.peer_shaping("g0");
        assert_eq!((p.shapes, p.shaped_now, p.gap_s), (Some(true), false, None));

        let _ = t.offer_for([11u8; 16], 400, Some("bare"));
        t.peer_offer([11u8; 16], &ShapingOffer::off()).unwrap();
        assert_eq!(t.peer_shaping("bare").shapes, Some(false));

        let _ = t.offer_for([12u8; 16], 400, Some("old"));
        t.offer_unanswered([12u8; 16]);
        assert_eq!(t.peer_shaping("old").shapes, Some(false));

        let _ = t.offer_for([13u8; 16], 400, Some("full"));
        assert!(t
            .peer_offer([13u8; 16], &ShapingOffer::home_elsewhere())
            .is_err());
        assert_eq!(t.peer_shaping("full").shapes, Some(true));

        let seen: Vec<String> = t.peers_shaping().into_iter().map(|p| p.peer).collect();
        assert_eq!(seen, vec!["bare", "full", "g0", "old"]);
    }

    #[test]
    fn peer_shaping_facts_are_bounded() {
        let t = LinkShapers::new(ShapingPolicy::fleet_default(BudgetClass::Server));
        for i in 0..PEER_SHAPING_FACTS_MAX + 3 {
            t.note_peer_shapes(&format!("p{i}"), true);
        }
        assert_eq!(t.peers_shaping().len(), PEER_SHAPING_FACTS_MAX);
    }
}
