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
            node_cap_bytes_per_s: bytes_per_s.saturating_mul(8),
            require_shaped_links: false,
        }
    }

    /// Whether this node offers shaping at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.class != BudgetClass::Off && self.bytes_per_s > 0
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
                || offer.window_s == 0)
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
        }
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
        tokio::select! {
            () = tokio::time::sleep(wait) => {}
            () = self.notify.notified() => {
                if self.stopped.load(Ordering::Relaxed) {
                    return Emission::Stopped;
                }
                // A new body changes nothing about WHEN the next frame goes:
                // the timer is the timer. Finish the interval.
                tokio::time::sleep(wait).await;
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
    policy: ShapingPolicy,
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
            policy,
            links: Mutex::new(HashMap::new()),
            offered: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            queue_cap: DEFAULT_QUEUE_CAP,
        }
    }

    /// The policy in force.
    #[must_use]
    pub fn policy(&self) -> &ShapingPolicy {
        &self.policy
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
        self.policy.node_cap_bytes_per_s.saturating_sub(used)
    }

    /// This node's offer for `link` (recorded as sent).
    #[must_use]
    pub fn offer_for(&self, link: [u8; 16], frame_bytes: usize) -> ShapingOffer {
        let offer = ShapingOffer::from_policy(&self.policy, frame_bytes, self.remaining_cap());
        self.offered().insert(link, offer);
        offer
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
            None if self.policy.require_shaped_links && ours.class != BudgetClass::Off => {
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
        let _ = lenient.offer_for(link, 400);
        assert!(lenient
            .peer_offer(link, &ShapingOffer::off())
            .unwrap()
            .is_none());
        assert!(!lenient.is_shaped(link));
        let mut strict_policy = ShapingPolicy::for_class(BudgetClass::Home);
        strict_policy.require_shaped_links = true;
        let strict = LinkShapers::new(strict_policy);
        let _ = strict.offer_for(link, 400);
        assert!(matches!(
            strict.peer_offer(link, &ShapingOffer::off()),
            Err(ShapingError::UnshapedPeer)
        ));
        // A node that offers nothing never refuses: it is the one that is off.
        let off = LinkShapers::new(ShapingPolicy::default());
        let o = off.offer_for(link, 400);
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
        let o1 = t.offer_for([1u8; 16], 400);
        assert_eq!(o1.rate_milli, 7000, "2800 B/s at 400 B");
        t.peer_offer([1u8; 16], &peer).unwrap().expect("shaped");
        let o2 = t.offer_for([2u8; 16], 400);
        assert_eq!(o2.rate_milli, 3000, "1200 B/s left under the cap");
        t.peer_offer([2u8; 16], &peer).unwrap().expect("shaped");
        let o3 = t.offer_for([3u8; 16], 400);
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
}
