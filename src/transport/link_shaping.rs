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
/// Below one frame per this many seconds an offer is `off`: a slower stream
/// shapes nothing worth the link.
pub const MIN_FRAME_INTERVAL: Duration = Duration::from_secs(10);
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
}

impl BudgetClass {
    /// The default per-link byte rate of the class (steward knobs may
    /// override; `Off` is zero).
    #[must_use]
    pub const fn default_bytes_per_s(self) -> u32 {
        match self {
            Self::Off => 0,
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
            _ => None,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Off,
            1 => Self::PhoneCellular,
            2 => Self::PhoneWifi,
            3 => Self::Home,
            4 => Self::Server,
            _ => return None,
        })
    }
}

/// This node's shaping policy (config; PyO3/UniFFI mirror it).
#[derive(Debug, Clone, PartialEq)]
pub struct ShapingPolicy {
    /// The class offered on every identity link. `Off` (the default) shapes
    /// nothing.
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
    /// How many links' worth of the node cap is held back for onion layer
    /// neighbours that do not yet have a shaped link (CIRISEdge v44): a
    /// first-come link to anyone else cannot take the share a layer link
    /// needs. Reserved only while layer peers are named
    /// ([`LinkShapers::set_layer_peers`]), so a node that does not run the
    /// tier reserves nothing.
    pub layer_reserve_links: u32,
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
/// The cost columns are what a client shows at the moment of choosing: a
/// shaped link always runs at its class rate (cover fills what real traffic
/// leaves), each way, so at the eight-link node cap a month (30 days) costs
/// `rate × 8 × 2,592,000 s` each way (`docs/LINK_SHAPING_COST.md`).
pub const FLEET_DEFAULTS: [FleetDefault; 4] = [
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

/// The default share of the node cap held for layer neighbours: half of the
/// eight links' worth.
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
    /// (`home`, `phone-wifi`, `phone-cellular` are opt-in; [`FLEET_DEFAULTS`]).
    /// A person's choice, not a network fact: it is kept when the device moves
    /// between Wi-Fi and cellular ([`Self::with_network`]).
    pub shaping_opt_in: bool,
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
            relay_override: None,
        }
    }

    /// The same device after a network or power change: the person's
    /// opt-in and relay override are kept, whatever class the move lands on.
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
    /// identity link when the person opted in (any class, cellular included).
    #[must_use]
    pub fn for_device(d: &DeviceState) -> Self {
        let mut p = Self::fleet_default(d.budget_class());
        if d.shaping_opt_in {
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
    /// `frame_bytes`, with `remaining_cap` bytes/s left under the node cap.
    #[must_use]
    pub fn from_policy(policy: &ShapingPolicy, frame_bytes: usize, remaining_cap: u32) -> Self {
        if !policy.enabled() {
            return Self::off();
        }
        let frame = u16::try_from(frame_bytes.min(usize::from(u16::MAX))).unwrap_or(u16::MAX);
        if frame < MIN_FRAME_BYTES {
            return Self::off();
        }
        let bytes = policy.bytes_per_s.min(remaining_cap);
        let lambda = f64::from(bytes) / f64::from(frame);
        if lambda < 1.0 / MIN_FRAME_INTERVAL.as_secs_f64() {
            return Self::off();
        }
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
        out.push(self.class as u8);
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
        if class != BudgetClass::Off
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
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let r = (self.rho * self.lambda * self.window.as_secs_f64())
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
    if a.class == BudgetClass::Off || b.class == BudgetClass::Off {
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
    queue: Mutex<VecDeque<Vec<u8>>>,
    queue_cap: usize,
    notify: Notify,
    poisson: PoissonScheduler,
    scope: ScopeKey,
    budget: BudgetMeter,
    real: AtomicU64,
    cover: AtomicU64,
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
        let poisson = PoissonScheduler::new();
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
            notify: Notify::new(),
            poisson,
            scope,
            budget,
            real: AtomicU64::new(0),
            cover: AtomicU64::new(0),
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
    pub fn enqueue(&self, bodies: Vec<Vec<u8>>) -> Result<(), ShapingError> {
        let reach = self.agreement.reach_frames();
        if bodies.len() > reach {
            return Err(ShapingError::BulkBeyondReach(bodies.len(), reach));
        }
        self.enqueue_within_queue(bodies)
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
    /// slow. The caller feeds it in pieces as [`Self::room`] allows.
    ///
    /// # Errors
    /// As [`Self::enqueue`], less the reach refusal.
    pub fn enqueue_bulk_fallback(&self, bodies: Vec<Vec<u8>>) -> Result<(), ShapingError> {
        self.enqueue_within_queue(bodies)
    }

    fn enqueue_within_queue(&self, bodies: Vec<Vec<u8>>) -> Result<(), ShapingError> {
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
        q.extend(bodies);
        drop(q);
        self.notify.notify_one();
        Ok(())
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
        let body = if under {
            self.queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
        } else {
            None
        };
        let real = body.is_some();
        let mut pad = |buf: &mut [u8]| self.poisson.fill_bytes(buf);
        let frame = if let Some(b) = body {
            self.budget.record_real(&self.scope);
            self.real.fetch_add(1, Ordering::Relaxed);
            wrap(self.agreement.frame_bytes, Some(&b), &mut pad)
        } else {
            self.budget.record_cover(&self.scope);
            self.cover.fetch_add(1, Ordering::Relaxed);
            wrap(self.agreement.frame_bytes, None, &mut pad)
        };
        match frame {
            Ok(bytes) => Emission::Frame { bytes, real },
            // Unreachable: enqueue bounded every body to the capacity.
            Err(_) => Emission::Stopped,
        }
    }
}

/// The node's shaped links and its node-wide cap.
#[derive(Debug)]
pub struct LinkShapers {
    /// The policy in force; replaced at runtime by [`Self::set_policy`] (a
    /// phone moving between Wi-Fi and cellular, or plugging in).
    policy: std::sync::RwLock<ShapingPolicy>,
    /// This node's onion layer neighbours by key id (empty unless the node
    /// runs the Anonymous Tier): their links are offered shaping under any
    /// scope and draw on the reserve.
    layer_peers: Mutex<std::collections::HashSet<String>>,
    /// The peer each offered or shaped link goes to, when known.
    link_peer: Mutex<HashMap<[u8; 16], String>>,
    /// CC 5.4.3 rc16 two planes — the BULK links this node dialled: identity
    /// links on which no shaping is ever offered, carrying bulk and nothing
    /// else this node chooses.
    bulk: Mutex<std::collections::HashSet<[u8; 16]>>,
    links: Mutex<HashMap<[u8; 16], Arc<LinkShaper>>>,
    /// Links this node sent an offer on, with that offer.
    offered: Mutex<HashMap<[u8; 16], ShapingOffer>>,
    /// Dials waiting for the peer's answer ([`Self::begin_offer`]).
    pending: Mutex<HashMap<[u8; 16], OfferAnswerTx>>,
    queue_cap: usize,
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
            links: Mutex::new(HashMap::new()),
            offered: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            queue_cap: DEFAULT_QUEUE_CAP,
        }
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
        }
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = policy;
        close
    }

    /// Name this node's onion layer neighbours (empty: the tier is not
    /// running here, and nothing is reserved).
    pub fn set_layer_peers(&self, peers: std::collections::HashSet<String>) {
        *self
            .layer_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = peers;
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

    /// Bytes/s of the node cap held back for layer neighbours that have no
    /// shaped link yet: `min(layer_reserve_links, unshaped layer peers) ×
    /// the class rate`.
    #[must_use]
    pub fn layer_reserve(&self) -> u32 {
        let policy = self.policy();
        let layer = self.layer_peer_set();
        if layer.is_empty() {
            return 0;
        }
        let shaped_peers: std::collections::HashSet<String> = {
            let links = self.links();
            self.link_peer()
                .iter()
                .filter(|(l, _)| links.contains_key(*l))
                .map(|(_, p)| p.clone())
                .collect()
        };
        let waiting = layer.iter().filter(|p| !shaped_peers.contains(*p)).count();
        let n = u32::try_from(waiting)
            .unwrap_or(u32::MAX)
            .min(policy.layer_reserve_links);
        n.saturating_mul(policy.bytes_per_s)
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
    }

    /// Bytes/s still free under the node cap.
    #[must_use]
    pub fn remaining_cap(&self) -> u32 {
        let used: u32 = self
            .links()
            .values()
            .map(|s| s.agreement.bytes_per_s())
            .fold(0u32, u32::saturating_add);
        self.policy().node_cap_bytes_per_s.saturating_sub(used)
    }

    /// This node's offer for `link` to `peer` (recorded as sent). A layer
    /// neighbour's link is offered under any scope and may use the whole
    /// remaining cap; any other link is offered only under
    /// [`ShapingScope::AllIdentityLinks`] and only what is left after the
    /// layer reserve ([`Self::layer_reserve`]).
    #[must_use]
    pub fn offer_for(
        &self,
        link: [u8; 16],
        frame_bytes: usize,
        peer: Option<&str>,
    ) -> ShapingOffer {
        let policy = self.policy();
        let layer = self.is_layer_peer(peer);
        let offer = if policy.offers_on(layer) {
            let room = if layer {
                self.remaining_cap()
            } else {
                self.remaining_cap().saturating_sub(self.layer_reserve())
            };
            ShapingOffer::from_policy(&policy, frame_bytes, room)
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
        let out = match agree(&ours, theirs) {
            Some(agreement) => {
                let shaper = Arc::new(LinkShaper::new(link, agreement, self.queue_cap));
                self.links().insert(link, Arc::clone(&shaper));
                Ok(Some(shaper))
            }
            None if self.policy().require_shaped_links && ours.class != BudgetClass::Off => {
                Err(ShapingError::UnshapedPeer)
            }
            None => Ok(None),
        };
        if let Some(tx) = self.pending().remove(&link) {
            // choke-ok: a dial that stopped waiting closed the link.
            let _ = tx.send(match &out {
                Ok(s) => Ok(s.is_some()),
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
        self.offered()
            .get(&link)
            .is_some_and(|o| o.class != BudgetClass::Off)
    }

    /// The link closed: stop and forget its shaper.
    pub fn forget(&self, link: &[u8; 16]) {
        if let Some(s) = self.links().remove(link) {
            s.stop();
        }
        self.offered().remove(link);
        self.pending().remove(link);
        self.link_peer().remove(link);
        self.bulk
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
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
    /// by kind ([`is_bulk_class`]) or beyond one window's real-frame budget
    /// ([`Agreement::reach_frames`]). An unshaped link carries anything.
    #[must_use]
    pub fn needs_bulk_plane(&self, link: [u8; 16], envelope: &[u8]) -> bool {
        let Some(shaper) = self.get(link) else {
            return false;
        };
        if is_bulk_class(envelope) {
            return true;
        }
        let cap = body_capacity(shaper.agreement().frame_bytes);
        crate::transport::frame_fragment::fragment(envelope, cap)
            .map_or(true, |f| f.len() > shaper.agreement().reach_frames())
    }

    /// Shaped links now.
    #[must_use]
    pub fn shaped_count(&self) -> usize {
        self.links().len()
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
            layer_reserve_links: DEFAULT_LAYER_RESERVE_LINKS,
        };
        ShapingOffer::from_policy(&p, usize::from(frame), u32::MAX)
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

    #[test]
    fn the_node_cap_bounds_the_sum_of_agreed_rates() {
        let mut p = ShapingPolicy::for_class(BudgetClass::Home);
        p.node_cap_bytes_per_s = 4000;
        let t = LinkShapers::new(p);
        let peer = offer(BudgetClass::Server, 400, 7000, 0.5, 600);
        let o1 = t.offer_for([1u8; 16], 400, None);
        assert_eq!(o1.rate_milli, 7000, "2800 B/s at 400 B");
        t.peer_offer([1u8; 16], &peer).unwrap().expect("shaped");
        let o2 = t.offer_for([2u8; 16], 400, None);
        assert_eq!(o2.rate_milli, 3000, "1200 B/s left under the cap");
        t.peer_offer([2u8; 16], &peer).unwrap().expect("shaped");
        let o3 = t.offer_for([3u8; 16], 400, None);
        assert_eq!(
            o3.class,
            BudgetClass::Off,
            "nothing left: off, never a trickle"
        );
        t.forget(&[1u8; 16]);
        assert!(t.remaining_cap() >= 2800);
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
                Emission::Frame { bytes, real } => match unwrap(&bytes).unwrap() {
                    ShapedFrame::Real(_) => {
                        assert!(real);
                        reals += 1;
                    }
                    ShapedFrame::Cover => {
                        assert!(!real);
                        covers += 1;
                    }
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
            vec![BudgetClass::Server]
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
            cell.shaping_opt_in,
            "a network change keeps the person's choice"
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
        let mut quiet = wifi;
        quiet.shaping_opt_in = false;
        let t = build(&DeviceState {
            shaping_opt_in: true,
            ..quiet
        });
        let mut closed = t.set_policy(ShapingPolicy::for_device(&quiet.with_network(false, false)));
        closed.sort_unstable();
        assert_eq!(closed, vec![[1u8; 16], [3u8; 16]]);
        assert!(t.is_shaped([2u8; 16]), "the layer link stays shaped");
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

    /// The cap is no longer first come, first served: with layer peers named,
    /// their share of the eight links' worth is held back, so general links
    /// stop at four and the layer neighbours still get shaped links; with no
    /// layer peers (the tier not running) nothing is reserved.
    #[test]
    fn the_cap_reserves_room_for_layer_neighbours() {
        let p = ShapingPolicy::for_class(BudgetClass::Home);
        let peer = peer_offer_at(BudgetClass::Server);
        // Not running the tier: eight general links fill the cap.
        let t = LinkShapers::new(p.clone());
        for i in 0..8u8 {
            let o = t.offer_for([i; 16], 400, Some(&format!("g{i}")));
            assert_ne!(o.class, BudgetClass::Off, "general link {i}");
            t.peer_offer([i; 16], &peer).unwrap().expect("shaped");
        }
        assert_eq!(
            t.offer_for([9u8; 16], 400, Some("g9")).class,
            BudgetClass::Off
        );

        // Running it with six layer peers: four links' worth is held.
        let t = LinkShapers::new(p);
        t.set_layer_peers((0..6).map(|i| format!("L{i}")).collect());
        assert_eq!(t.layer_reserve(), 4 * 2800);
        let mut general = 0;
        for i in 0..8u8 {
            let o = t.offer_for([i; 16], 400, Some(&format!("g{i}")));
            if o.class != BudgetClass::Off {
                t.peer_offer([i; 16], &peer).unwrap().expect("shaped");
                general += 1;
            }
        }
        assert_eq!(general, 4, "general links stop at the reserve");
        for i in 0..4u8 {
            let link = [100 + i; 16];
            let o = t.offer_for(link, 400, Some(&format!("L{i}")));
            assert_ne!(
                o.class,
                BudgetClass::Off,
                "layer link {i} gets its reserved share"
            );
            t.peer_offer(link, &peer).unwrap().expect("shaped");
        }
        assert_eq!(t.remaining_cap(), 0);
        // Two layer peers still wait: their share stays held against any
        // general link that frees room, never handed to a stranger.
        assert_eq!(t.layer_reserve(), 2 * 2800);
        t.forget(&[0u8; 16]);
        assert_eq!(
            t.offer_for([50u8; 16], 400, Some("g-late")).class,
            BudgetClass::Off,
            "a freed general slot goes to the waiting layer peers first"
        );
        assert_ne!(
            t.offer_for([104u8; 16], 400, Some("L4")).class,
            BudgetClass::Off
        );
    }
}
