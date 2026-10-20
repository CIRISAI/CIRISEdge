//! CC 5.3.3.5 E1 — **every byte edge sends over an RNS link rides under a
//! hybrid transit seal.**
//!
//! Each link runs the CC 3.3.6.2 transit KEX
//! ([`crate::transport::av_transit_handshake`], verify's
//! `ciris_crypto::transit_kex`: X25519 + ML-KEM-768) ONCE, as its first
//! frame, and every edge frame after it, in both directions and on every
//! lane (Channel messages, Resources, requests and responses), is sealed
//! under the keys it yields and bound to the link's 16-byte id. This module
//! holds that per-link state for the Reticulum transport and is the only
//! place a frame is sealed or opened.
//!
//! # Enforced at once
//!
//! There is no advisory mode, no flag and no compat path: a peer that does
//! not run the seal gets nothing.
//!
//! - **Dialler (initiator).** Resolves the dialled node's pair (Rooted only)
//!   BEFORE dialling; no pair means no dial. Once the link is up it sends
//!   the handshake as the first frame ([`LinkSeals::initiate`]) and installs
//!   its keys only after the last part is out
//!   ([`LinkSeals::install_initiator`]); [`LinkSeals::seal`] refuses every
//!   send before that. A frame that arrives before its own handshake went
//!   out is refused ([`SealRefusal::FrameBeforeKeys`]): the responder may not
//!   speak first.
//! - **Responder.** A link a peer dialled is [`LinkSeals::begin_responder`]
//!   at establishment (or at its first frame, when the establishment event
//!   was lost). Until a valid handshake completes it delivers NOTHING upward
//!   and the seal refuses every send. A non-`CTKX` first frame, a missing
//!   handshake (budget expiry, [`LinkSeals::expire`]), an oversize
//!   declaration, a bad or classical-only suite, and a failed respond are
//!   each a named refusal ([`SealRefusal::label`]), after which the link is
//!   closed. There is never a plaintext edge frame in either direction.
//!
//! # The claim and the first-contact carve-out
//!
//! The KEX authenticates only the responder; the handshake's initiator id is
//! a claim ([`LinkSeals::claimed_initiator`]). The transport holds it to the
//! link's attributed peer on every inbound frame. A link whose initiator is
//! UNATTRIBUTED (an unowned fresh device has no attribution) may still
//! complete the seal, and may then carry only the first-contact plane; any
//! other frame on it is refused ([`SealRefusal::FirstContactOnly`]).
//! Confidentiality holds either way: only the authenticated responder can
//! derive the keys. The initiator is unowned but never anonymous
//! (CLM-first-contact-seal-key-bound): the request must be signed by, and
//! introduce, the handshake's initiator key ([`admit_unattributed_frame`]).
//!
//! # The seal
//!
//! ```text
//! frame = version(1) ‖ counter u64_be ‖ AES-256-GCM(k_dir, nonce, aad, plaintext) ‖ tag(16)
//! k_dir = HKDF-SHA256(ikm = transit key for this direction, salt = link_id,
//!                     info = "CIRIS-E1-LINK-SEAL-V1")
//! nonce = lane(1) ‖ 0x000000 ‖ counter u64_be
//! aad   = version ‖ lane ‖ link_id
//! ```
//!
//! Each direction has its own key, each lane its own counter that only ever
//! increases, and the lane is in the nonce, so a `(key, nonce)` pair never
//! repeats. The key is derived under a label of its own, so it is never the
//! raw transit key A/V's outer seal uses (`realtime_av::seal_av_outer`), and
//! the two layers never share a `(key, nonce)` either. The receiver keeps a
//! replay window per lane ([`REPLAY_WINDOW`]); a counter already seen, or
//! older than the window, is dropped by name.
//!
//! **A frame that fails to open closes the link.** The Channel under it is
//! reliable and sequenced and RNS already authenticates the link, so a frame
//! that fails its tag is not loss: it is a peer keyed differently from us (a
//! stale `link_id`, leviculum#86 / CIRISEdge#867, where every later frame
//! would fail the same way) or bytes that were never the peer's. Neither
//! leaves a link worth keeping; closing it makes the dialler re-dial, which
//! is a new link, a new id and a fresh KEX. A replayed or out-of-window
//! counter on a frame that DID open is only dropped: it carries a valid tag,
//! so the peer holds the keys, and a window overrun under reordering is not
//! an attack worth a teardown.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciris_crypto::transit_kex::TransitRole;
use ciris_persist::federation::self_at_login::TransitKexPair;
use zeroize::Zeroizing;

use crate::transport::av_transit_handshake::{self, AvHandshakeError, LinkTransit, Reassembler};
use crate::transport::transit_kex_custody::TransitKexSecret;
use crate::transport::transit_kex_peer::PeerTransitResolver;
use crate::verify::RootingDirectory;

/// The seal's framing version.
pub const SEAL_VERSION: u8 = 0x01;

/// Bytes of header on a sealed frame (version, counter).
pub const SEAL_HEADER_LEN: usize = 1 + 8;

/// The AEAD tag.
pub const SEAL_TAG_LEN: usize = 16;

/// What the seal adds to every frame. Every place that sizes a Channel
/// message leaves room for it (`reticulum::channel_payload_mdu`), so a sealed
/// frame never exceeds the link's Channel limit.
pub const SEAL_OVERHEAD: usize = SEAL_HEADER_LEN + SEAL_TAG_LEN;

/// How far behind the highest counter seen on a lane a frame may still be
/// accepted (once).
pub const REPLAY_WINDOW: u64 = 128;

/// HKDF info for the per-direction seal key.
const SEAL_KEY_INFO: &[u8] = b"CIRIS-E1-LINK-SEAL-V1";

/// Bound on the test wire tap (frames kept).
const TAP_CAP: usize = 4096;

/// The test wire tap: `(link, frame as sent)`, oldest first.
type WireTap = Vec<([u8; 16], Vec<u8>)>;

/// Most opened frames held on one link while its identity is unproven.
pub const HELD_FRAMES_MAX: usize = 32;

/// Most opened bytes held on one link while its identity is unproven.
pub const HELD_BYTES_MAX: usize = 256 * 1024;

/// How long an ordinary frame on a peer-dialled link waits for the link's
/// attribution before the first-contact carve-out judges the link as
/// unattributed ([`LinkSeals::hold_for_attribution`]).
pub const ATTRIBUTION_HOLD_BUDGET: Duration = Duration::from_secs(5);

/// Opened frames waiting for their link's identity or attribution:
/// `(is_resource, plaintext)` in arrival order, and their total size.
#[derive(Debug, Default)]
struct Held {
    frames: Vec<(bool, Vec<u8>)>,
    bytes: usize,
    /// Set while the frames wait for the link's ATTRIBUTION: when the wait
    /// began, and the refusal the carve-out gives if it runs out.
    awaiting: Option<(Instant, SealRefusal)>,
}

/// Which of a link's carriers a frame rides. Each has its own counter and
/// replay window, because they are not ordered with each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// A Channel message (`LinkHandle::send` / `try_send`).
    Channel = 1,
    /// A Resource transfer.
    Resource = 2,
    /// A link request's data.
    Request = 3,
    /// A link response's data.
    Response = 4,
}

impl Lane {
    const fn index(self) -> usize {
        self as usize - 1
    }

    /// leviculum's request/response API carries exactly ONE msgpack value
    /// (it asserts it), so a sealed request or response rides as a msgpack
    /// `bin` holding the sealed frame; the caller's own msgpack value is the
    /// plaintext inside.
    const fn is_msgpack(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }
}

/// Wrap `frame` as one msgpack `bin` value.
fn msgpack_bin(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(frame.len() + 5);
    if let Ok(n) = u8::try_from(frame.len()) {
        out.push(0xc4);
        out.push(n);
    } else if let Ok(n) = u16::try_from(frame.len()) {
        out.push(0xc5);
        out.extend_from_slice(&n.to_be_bytes());
    } else {
        out.push(0xc6);
        out.extend_from_slice(&u32::try_from(frame.len()).unwrap_or(u32::MAX).to_be_bytes());
    }
    out.extend_from_slice(frame);
    out
}

/// The frame inside one msgpack `bin` value, or `None` for anything else.
fn msgpack_unbin(value: &[u8]) -> Option<&[u8]> {
    let (&tag, rest) = value.split_first()?;
    let (len, body) = match tag {
        0xc4 => (usize::from(*rest.first()?), rest.get(1..)?),
        0xc5 => (
            usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?)),
            rest.get(2..)?,
        ),
        0xc6 => (
            usize::try_from(u32::from_be_bytes(rest.get(..4)?.try_into().ok()?)).ok()?,
            rest.get(4..)?,
        ),
        _ => return None,
    };
    (body.len() == len).then_some(body)
}

/// Why a frame or a link was refused at the seal. Every variant is named and
/// counted under [`Self::label`].
#[derive(Debug, thiserror::Error)]
pub enum SealRefusal {
    /// The handshake was refused (framing, suite, KEX, claim, budget).
    #[error(transparent)]
    Handshake(AvHandshakeError),
    /// CC 3.2 (f) — a pairing-pinned transit pair was refused before any dial
    /// (wrong length, bound to another node, ...).
    #[error("pairing-pinned transit pair refused: {0}")]
    PinRejected(String),
    /// A frame arrived on a link this node dialled before its own handshake
    /// had gone out.
    #[error("a frame arrived on a link this node dialled before its handshake went out")]
    FrameBeforeKeys,
    /// A sealed frame did not open.
    #[error(
        "a sealed frame failed to open on this link (wrong key or link, tampered, or truncated)"
    )]
    OpenFailed,
    /// A send on a link with no keys.
    #[error("the link has no transit keys; nothing is sent in the clear (CC 5.3.3.5 E1)")]
    Unsealed,
    /// A non-first-contact frame on a link whose initiator is unattributed.
    #[error(
        "the link's initiator is unattributed; only first contact may ride it \
         (CC 5.3.3.5 E1 carve-out)"
    )]
    FirstContactOnly,
    /// A first-contact request on an unattributed link signed by, or
    /// introducing, a key other than the handshake's initiator key.
    #[error(
        "first-contact request signed by {signer} (key record {record:?}) on a link whose \
         handshake initiator is {claimed}; the three must be one key \
         (CLM-first-contact-seal-key-bound)"
    )]
    FirstContactSignerMismatch {
        /// The handshake's initiator key id.
        claimed: String,
        /// The request's `signing_key_id`.
        signer: String,
        /// The carried key record's `key_id`, if any.
        record: Option<String>,
    },
}

impl SealRefusal {
    /// The `link_seal` metric label.
    #[must_use]
    pub fn label(&self) -> &'static str {
        use crate::observability as o;
        match self {
            Self::Handshake(e) => e.label(),
            Self::PinRejected(_) => o::LINK_SEAL_REFUSED_PIN,
            Self::FrameBeforeKeys => o::LINK_SEAL_REFUSED_FRAME_BEFORE_KEYS,
            Self::OpenFailed => o::LINK_SEAL_REFUSED_OPEN_FAILED,
            Self::Unsealed => o::LINK_SEAL_REFUSED_UNSEALED_SEND,
            Self::FirstContactOnly => o::LINK_SEAL_REFUSED_FIRST_CONTACT_ONLY,
            Self::FirstContactSignerMismatch { .. } => o::LINK_SEAL_REFUSED_FIRST_CONTACT_SIGNER,
        }
    }
}

/// What [`LinkSeals::inbound`] made of one received frame.
#[derive(Debug)]
pub enum Inbound {
    /// A handshake part, buffered. Nothing to deliver.
    Pending,
    /// The handshake completed and was answered: the link is sealed from now
    /// on. `claimed` is the initiator the handshake names (a claim the
    /// caller holds to the link's attribution). Nothing to deliver.
    Keyed {
        /// The handshake's `initiator_key_id`.
        claimed: String,
    },
    /// A sealed frame, opened.
    Open(Vec<u8>),
    /// Dropped by name; the link stays.
    Drop(&'static str),
    /// Refused by name; the caller closes the link.
    Refuse(SealRefusal),
    /// The link was already refused and is closing: dropped without a
    /// second count.
    Closed,
}

/// Highest counter seen plus a bitmap of the [`REPLAY_WINDOW`] below it.
#[derive(Debug, Default, Clone, Copy)]
struct ReplayWindow {
    highest: Option<u64>,
    /// Bit `i` set ⇔ `highest - i` was accepted.
    seen: u128,
}

impl ReplayWindow {
    /// Accept `c` once, or refuse it.
    fn accept(&mut self, c: u64) -> bool {
        let Some(h) = self.highest else {
            self.highest = Some(c);
            self.seen = 1;
            return true;
        };
        if c > h {
            let shift = c - h;
            self.seen = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.seen << shift
            };
            self.seen |= 1;
            self.highest = Some(c);
            return true;
        }
        let back = h - c;
        if back >= REPLAY_WINDOW {
            return false;
        }
        let bit = 1u128 << back;
        if self.seen & bit != 0 {
            return false;
        }
        self.seen |= bit;
        true
    }
}

/// One sealed link's keys and counters.
pub struct SealedLink {
    link_id: [u8; 16],
    transit: LinkTransit,
    seal_key: Zeroizing<[u8; 32]>,
    open_key: Zeroizing<[u8; 32]>,
    next: [AtomicU64; 4],
    windows: Mutex<[ReplayWindow; 4]>,
    /// The handshake's claimed initiator, on a link this node RESPONDED on.
    claimed_initiator: Option<String>,
    /// CC 3.2 (f) — keyed from a pairing-pinned pair: this link carries the
    /// first-contact plane only, through [`LinkSeals::seal_first_contact`].
    pinned: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for SealedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedLink")
            .field("link_id", &hex::encode(self.link_id))
            .field("role", &self.transit.role())
            .field("claimed_initiator", &self.claimed_initiator)
            .finish_non_exhaustive()
    }
}

fn derive_seal_key(transit_key: &[u8; 32], link_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let okm = Zeroizing::new(
        ciris_crypto::kdf::hkdf_sha256(transit_key, link_id, SEAL_KEY_INFO, 32)
            .expect("HKDF-SHA256 expands 32 bytes"),
    );
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&okm);
    k
}

fn nonce(lane: Lane, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = lane as u8;
    n[4..].copy_from_slice(&counter.to_be_bytes());
    n
}

fn aad(lane: Lane, link_id: &[u8; 16]) -> [u8; 18] {
    let mut a = [0u8; 18];
    a[0] = SEAL_VERSION;
    a[1] = lane as u8;
    a[2..].copy_from_slice(link_id);
    a
}

impl SealedLink {
    fn new(link_id: [u8; 16], transit: LinkTransit, claimed_initiator: Option<String>) -> Self {
        Self {
            link_id,
            seal_key: derive_seal_key(&transit.seal_key(), &link_id),
            open_key: derive_seal_key(&transit.open_key(), &link_id),
            transit,
            next: Default::default(),
            windows: Mutex::new([ReplayWindow::default(); 4]),
            claimed_initiator,
            pinned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Seal one frame on `lane`.
    fn seal(&self, lane: Lane, plaintext: &[u8]) -> Vec<u8> {
        let counter = self.next[lane.index()].fetch_add(1, Ordering::Relaxed);
        let ct = ciris_crypto::aes_gcm::encrypt_aad(
            &self.seal_key,
            &nonce(lane, counter),
            &aad(lane, &self.link_id),
            plaintext,
        )
        .expect("AES-256-GCM seals any input under a 32-byte key");
        let mut out = Vec::with_capacity(SEAL_HEADER_LEN + ct.len());
        out.push(SEAL_VERSION);
        out.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&ct);
        out
    }

    /// Open one frame received on `lane`.
    fn open(&self, lane: Lane, frame: &[u8]) -> Inbound {
        if frame.len() < SEAL_OVERHEAD || frame[0] != SEAL_VERSION {
            return Inbound::Refuse(SealRefusal::OpenFailed);
        }
        let mut be = [0u8; 8];
        be.copy_from_slice(&frame[1..SEAL_HEADER_LEN]);
        let counter = u64::from_be_bytes(be);
        let Ok(plain) = ciris_crypto::aes_gcm::decrypt_aad(
            &self.open_key,
            &nonce(lane, counter),
            &aad(lane, &self.link_id),
            &frame[SEAL_HEADER_LEN..],
        ) else {
            return Inbound::Refuse(SealRefusal::OpenFailed);
        };
        // The window moves only for a frame that opened, so forged counters
        // cannot push real frames out of it.
        let fresh = self
            .windows
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)[lane.index()]
        .accept(counter);
        if fresh {
            Inbound::Open(plain)
        } else {
            Inbound::Drop(crate::observability::LINK_SEAL_DROPPED_REPLAY)
        }
    }
}

enum State {
    /// This node dialled; its handshake has not gone out yet.
    Initiating,
    /// A peer dialled; its handshake has not completed.
    Awaiting(Reassembler),
    /// Keys installed.
    Sealed(Arc<SealedLink>),
    /// Refused; the link is closing. Kept so a frame still in flight is not
    /// counted again or taken for a new link.
    Refused,
}

/// The Reticulum transport's per-link seal table. See the module docs.
pub struct LinkSeals {
    links: Mutex<HashMap<[u8; 16], State>>,
    secret: TransitKexSecret,
    local_key_id: String,
    resolver: PeerTransitResolver,
    /// Test seam: every frame handed to leviculum on any link, as sent.
    tap: Mutex<Option<WireTap>>,
    /// Opened frames on peer-dialled links whose identity is not yet proven
    /// ([`Self::hold`]) or whose attribution has not landed yet
    /// ([`Self::hold_for_attribution`]).
    held: Mutex<HashMap<[u8; 16], Held>>,
}

impl std::fmt::Debug for LinkSeals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkSeals")
            .field("local_key_id", &self.local_key_id)
            .finish_non_exhaustive()
    }
}

impl LinkSeals {
    /// A table keyed by this node's static transit keys, answering
    /// handshakes as `local_key_id` (the occurrence key id it is dialled
    /// by).
    #[must_use]
    pub fn new(secret: TransitKexSecret, local_key_id: impl Into<String>) -> Self {
        Self {
            links: Mutex::new(HashMap::new()),
            secret,
            local_key_id: local_key_id.into(),
            resolver: PeerTransitResolver::new(),
            tap: Mutex::new(None),
            held: Mutex::new(HashMap::new()),
        }
    }

    fn links(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 16], State>> {
        self.links
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// This node's static transit keys (the pair it publishes).
    #[must_use]
    pub fn secret(&self) -> &TransitKexSecret {
        &self.secret
    }

    /// The dialled node's transit pair (Rooted only), read BEFORE the dial:
    /// a node that publishes none cannot be keyed, so it is never dialled.
    ///
    /// # Errors
    /// [`AvHandshakeError::PairLookup`] (no directory, or a directory fault)
    /// or [`AvHandshakeError::NoTransitPair`].
    pub async fn resolve_pair(
        &self,
        rooting: Option<&dyn RootingDirectory>,
        peer: &str,
    ) -> Result<TransitKexPair, AvHandshakeError> {
        let Some(rooting) = rooting else {
            return Err(AvHandshakeError::PairLookup {
                peer: peer.to_owned(),
                detail: "no rooting directory is wired".to_owned(),
            });
        };
        self.resolver
            .resolve(rooting, peer)
            .await
            .map_err(|detail| AvHandshakeError::PairLookup {
                peer: peer.to_owned(),
                detail,
            })?
            .ok_or_else(|| AvHandshakeError::NoTransitPair {
                peer: peer.to_owned(),
            })
    }

    /// A dial to `peer` was refused for want of its pair; `true` the first
    /// time since its pair last resolved
    /// ([`PeerTransitResolver::note_no_pair_refusal`]).
    pub fn note_no_pair_refusal(&self, peer: &str) -> bool {
        self.resolver.note_no_pair_refusal(peer)
    }

    /// Record a link this node dialled, before it can establish: no frame on
    /// it is delivered, and nothing is sent on it, until
    /// [`Self::install_initiator`].
    pub fn begin_initiator(&self, link: [u8; 16]) {
        self.links().insert(link, State::Initiating);
    }

    /// Build the dialler's handshake for `link` against `pair`, claiming
    /// `claimed_initiator` (this node's occurrence key id outside tests),
    /// cut to `frame_limit`. Keys are returned, not installed: install them
    /// once every frame is out.
    ///
    /// # Errors
    /// The construction's refusal.
    pub fn initiate(
        &self,
        link: [u8; 16],
        claimed_initiator: &str,
        peer: &str,
        pair: &TransitKexPair,
        frame_limit: usize,
    ) -> Result<(Vec<Vec<u8>>, LinkTransit), AvHandshakeError> {
        av_transit_handshake::initiate(&link, claimed_initiator, peer, pair, frame_limit)
    }

    /// Install the dialler's keys: the link is sealed from now on.
    pub fn install_initiator(&self, link: [u8; 16], transit: LinkTransit) {
        self.links().insert(
            link,
            State::Sealed(Arc::new(SealedLink::new(link, transit, None))),
        );
    }

    /// CC 3.2 (f) — mark a link this node keyed from a pairing-pinned pair:
    /// from now on [`Self::seal`] refuses it and only
    /// [`Self::seal_first_contact`] seals on it. `false` when the link is not
    /// keyed.
    pub fn pin_first_contact_only(&self, link: [u8; 16]) -> bool {
        match self.links().get(&link) {
            Some(State::Sealed(s)) => {
                s.pinned.store(true, Ordering::Relaxed);
                true
            }
            _ => false,
        }
    }

    /// CC 3.2 (f) — whether `link` was keyed from a pairing-pinned pair.
    #[must_use]
    pub fn is_pinned(&self, link: [u8; 16]) -> bool {
        matches!(self.links().get(&link), Some(State::Sealed(s)) if s.pinned.load(Ordering::Relaxed))
    }

    /// Record a link a peer dialled, awaiting its handshake. `true` only when
    /// the link was not known before (the caller then starts its budget).
    pub fn begin_responder(&self, link: [u8; 16]) -> bool {
        let mut links = self.links();
        if links.contains_key(&link) {
            return false;
        }
        links.insert(link, State::Awaiting(Reassembler::new()));
        true
    }

    /// One frame received on `link` over `lane`. `we_dialled` is whether
    /// this node opened the link (its connect-time record).
    /// Only the Channel carries a handshake; any other lane is
    /// [`Self::open`].
    pub fn inbound(&self, link: [u8; 16], lane: Lane, bytes: &[u8], we_dialled: bool) -> Inbound {
        if lane != Lane::Channel {
            return self.open(link, lane, bytes);
        }
        let mut links = self.links();
        let state = match links.get_mut(&link) {
            Some(s) => s,
            None if we_dialled => {
                links.insert(link, State::Refused);
                return Inbound::Refuse(SealRefusal::FrameBeforeKeys);
            }
            None => links
                .entry(link)
                .or_insert_with(|| State::Awaiting(Reassembler::new())),
        };
        match state {
            State::Refused => Inbound::Closed,
            State::Initiating => {
                *state = State::Refused;
                Inbound::Refuse(SealRefusal::FrameBeforeKeys)
            }
            State::Sealed(sealed) => {
                let sealed = Arc::clone(sealed);
                drop(links);
                let out = sealed.open(lane, bytes);
                if matches!(out, Inbound::Refuse(_)) {
                    self.refuse(link);
                }
                out
            }
            State::Awaiting(reasm) => {
                let answered = match reasm.push(bytes) {
                    Ok(None) => return Inbound::Pending,
                    Ok(Some(hs)) => {
                        av_transit_handshake::respond(&hs, &link, &self.local_key_id, &self.secret)
                    }
                    Err(e) => Err(e),
                };
                match answered {
                    Ok((transit, claimed)) => {
                        *state = State::Sealed(Arc::new(SealedLink::new(
                            link,
                            transit,
                            Some(claimed.clone()),
                        )));
                        Inbound::Keyed { claimed }
                    }
                    Err(e) => {
                        *state = State::Refused;
                        Inbound::Refuse(SealRefusal::Handshake(e))
                    }
                }
            }
        }
    }

    /// Seal one frame for `link` on `lane`.
    ///
    /// # Errors
    /// [`SealRefusal::Unsealed`] when the link has no keys (not keyed yet,
    /// refused, or unknown): nothing is ever sent in the clear.
    pub fn seal(
        &self,
        link: [u8; 16],
        lane: Lane,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SealRefusal> {
        let sealed = match self.links().get(&link) {
            Some(State::Sealed(s)) => Arc::clone(s),
            _ => return Err(SealRefusal::Unsealed),
        };
        // CC 3.2 (f) — a pairing-pinned link carries first contact only, and
        // only through `seal_first_contact`: no other send path can use it.
        if sealed.pinned.load(Ordering::Relaxed) {
            return Err(SealRefusal::FirstContactOnly);
        }
        Ok(self.seal_with(link, &sealed, lane, plaintext))
    }

    /// CC 3.2 (f) — seal one first-contact frame on a pairing-pinned link.
    /// Only a link marked by [`Self::pin_first_contact_only`] takes it.
    ///
    /// # Errors
    /// [`SealRefusal::Unsealed`] for a link with no keys or one that is not
    /// pinned.
    pub fn seal_first_contact(
        &self,
        link: [u8; 16],
        lane: Lane,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SealRefusal> {
        let sealed = match self.links().get(&link) {
            Some(State::Sealed(s)) if s.pinned.load(Ordering::Relaxed) => Arc::clone(s),
            _ => return Err(SealRefusal::Unsealed),
        };
        Ok(self.seal_with(link, &sealed, lane, plaintext))
    }

    fn seal_with(
        &self,
        link: [u8; 16],
        sealed: &SealedLink,
        lane: Lane,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut frame = sealed.seal(lane, plaintext);
        if lane.is_msgpack() {
            frame = msgpack_bin(&frame);
        }
        self.tap_frame(link, &frame);
        frame
    }

    /// Open one sealed frame received on `link` outside the Channel (a
    /// Resource, a request, a response): there is no handshake on those
    /// lanes, so a link with no keys is refused.
    ///
    /// On a link a peer dialled whose handshake is still being answered the
    /// frame is DROPPED by name rather than refused: those lanes ride another
    /// event plane than the Channel, so a dialler's first Resource can reach
    /// the event loop ahead of its last handshake part. Nothing is delivered
    /// either way, and the budget still closes a link whose handshake never
    /// comes.
    pub fn open(&self, link: [u8; 16], lane: Lane, frame: &[u8]) -> Inbound {
        // The guard is held for the whole match: refuse in place, never
        // through `self.refuse` (which takes the lock again).
        let sealed = {
            let mut links = self.links();
            match links.get(&link) {
                Some(State::Sealed(s)) => Arc::clone(s),
                Some(State::Refused) => return Inbound::Closed,
                Some(State::Awaiting(_)) => {
                    return Inbound::Drop(crate::observability::LINK_SEAL_DROPPED_BEFORE_KEYS);
                }
                _ => {
                    links.insert(link, State::Refused);
                    return Inbound::Refuse(SealRefusal::Unsealed);
                }
            }
        };
        let frame = if lane.is_msgpack() {
            let Some(f) = msgpack_unbin(frame) else {
                self.refuse(link);
                return Inbound::Refuse(SealRefusal::OpenFailed);
            };
            f
        } else {
            frame
        };
        let out = sealed.open(lane, frame);
        if matches!(out, Inbound::Refuse(_)) {
            self.refuse(link);
        }
        out
    }

    /// The link's transit keys (A/V's outer seal uses them) and, on a link
    /// this node responded on, the handshake's claimed initiator.
    #[must_use]
    pub fn transit(&self, link: [u8; 16]) -> Option<(LinkTransit, Option<String>)> {
        match self.links().get(&link) {
            Some(State::Sealed(s)) => Some((s.transit.clone(), s.claimed_initiator.clone())),
            _ => None,
        }
    }

    /// The claimed initiator of a link this node RESPONDED on; `None` on a
    /// link it dialled (the KEX authenticated that peer) or one not sealed.
    #[must_use]
    pub fn claimed_initiator(&self, link: [u8; 16]) -> Option<String> {
        match self.links().get(&link) {
            Some(State::Sealed(s)) if s.transit.role() == TransitRole::Responder => {
                s.claimed_initiator.clone()
            }
            _ => None,
        }
    }

    /// Whether this table holds any state for `link` (keyed, awaiting,
    /// initiating or refused).
    #[must_use]
    pub fn knows(&self, link: [u8; 16]) -> bool {
        self.links().contains_key(&link)
    }

    /// Whether `link` carries keys.
    #[must_use]
    pub fn is_sealed(&self, link: [u8; 16]) -> bool {
        matches!(self.links().get(&link), Some(State::Sealed(_)))
    }

    /// The responder's budget ran out: `true` (and the link marked refused)
    /// when it was still awaiting its handshake.
    pub fn expire(&self, link: [u8; 16]) -> bool {
        let mut links = self.links();
        match links.get_mut(&link) {
            Some(s @ State::Awaiting(_)) => {
                *s = State::Refused;
                true
            }
            _ => false,
        }
    }

    /// Mark `link` refused: nothing more is sealed for it or opened on it.
    pub fn refuse(&self, link: [u8; 16]) {
        self.links().insert(link, State::Refused);
    }

    /// Forget a closed link (its keys and anything held for it).
    pub fn forget(&self, link: &[u8; 16]) {
        self.links().remove(link);
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(link);
    }

    /// Hold one OPENED frame on a link a peer dialled whose remote identity
    /// leviculum has not proven yet. The dialler identifies the link before it
    /// keys it, but the identify and the Channel ride separately, so its first
    /// sealed frames (its on-link announce, then data) can reach this end
    /// first; judged then, the link would read as unattributed and the
    /// first-contact carve-out would refuse a frame that is not. Held frames
    /// are replayed in order once the identity is proven ([`Self::take_held`]).
    /// Bounded by [`HELD_FRAMES_MAX`] / [`HELD_BYTES_MAX`] per link: `false`
    /// when this frame does not fit (the caller drops it by name).
    pub fn hold(&self, link: [u8; 16], is_resource: bool, plaintext: Vec<u8>) -> bool {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let h = held.entry(link).or_default();
        if h.frames.len() >= HELD_FRAMES_MAX || h.bytes + plaintext.len() > HELD_BYTES_MAX {
            return false;
        }
        h.bytes += plaintext.len();
        h.frames.push((is_resource, plaintext));
        true
    }

    /// Everything held for `link`, oldest first, and nothing held after.
    pub fn take_held(&self, link: [u8; 16]) -> Vec<(bool, Vec<u8>)> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&link)
            .map(|h| h.frames)
            .unwrap_or_default()
    }

    /// Hold one frame the first-contact carve-out would refuse (`refusal`)
    /// on a peer-dialled link whose identity is proven but which no peer
    /// binding names YET. Attribution lags the identify whenever the
    /// dialler's binding lands after its link does (its announce is still in
    /// the cold-start worker, or its on-link announce refreshed a binding the
    /// identify had already missed), and an unattributed link is judged as
    /// first contact. So the frame waits, at most [`ATTRIBUTION_HOLD_BUDGET`]
    /// from the first such frame and within the hold's bounds, for the link to
    /// attribute; it is replayed then ([`Self::take_held`]), or the link is
    /// refused with the first `refusal` once the budget is spent
    /// ([`Self::attribution_expired`]).
    ///
    /// # Errors
    /// The link's first refusal (else `refusal`) when the frame does not
    /// fit: everything held is discarded and the caller refuses the link now.
    pub fn hold_for_attribution(
        &self,
        link: [u8; 16],
        plaintext: Vec<u8>,
        refusal: SealRefusal,
    ) -> Result<(), SealRefusal> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let h = held.entry(link).or_default();
        if h.frames.len() >= HELD_FRAMES_MAX || h.bytes + plaintext.len() > HELD_BYTES_MAX {
            let first = h.awaiting.take().map(|(_, first)| first);
            held.remove(&link);
            return Err(first.unwrap_or(refusal));
        }
        h.bytes += plaintext.len();
        h.frames.push((false, plaintext));
        h.awaiting.get_or_insert_with(|| (Instant::now(), refusal));
        Ok(())
    }

    /// Whether any link's held frames wait for attribution.
    #[must_use]
    pub fn any_awaiting_attribution(&self) -> bool {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|h| h.awaiting.is_some())
    }

    /// The links whose held frames wait for attribution.
    #[must_use]
    pub fn awaiting_attribution(&self) -> Vec<[u8; 16]> {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, h)| h.awaiting.is_some())
            .map(|(link, _)| *link)
            .collect()
    }

    /// Whether `link`'s held frames wait for attribution.
    #[must_use]
    pub fn awaits_attribution(&self, link: [u8; 16]) -> bool {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&link)
            .is_some_and(|h| h.awaiting.is_some())
    }

    /// `link`'s carve-out refusal once its attribution wait has run past
    /// [`ATTRIBUTION_HOLD_BUDGET`] at `now`; its held frames are discarded.
    /// `None` while the wait has budget left, or when nothing waits.
    pub fn attribution_expired(&self, link: [u8; 16], now: Instant) -> Option<SealRefusal> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let since = held.get(&link)?.awaiting.as_ref()?.0;
        if now.saturating_duration_since(since) < ATTRIBUTION_HOLD_BUDGET {
            return None;
        }
        held.remove(&link)?.awaiting.map(|(_, refusal)| refusal)
    }

    /// Test seam: start (or stop and clear) recording every frame handed to
    /// leviculum.
    pub fn set_tap(&self, on: bool) {
        *self
            .tap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = on.then(Vec::new);
    }

    /// Test seam: the recorded frames, oldest first.
    #[must_use]
    pub fn tapped(&self) -> WireTap {
        self.tap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .unwrap_or_default()
    }

    /// Record one frame as sent (sealed frames and handshake parts).
    pub fn tap_frame(&self, link: [u8; 16], frame: &[u8]) {
        let mut tap = self
            .tap
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(t) = tap.as_mut() {
            if t.len() < TAP_CAP {
                t.push((link, frame.to_vec()));
            }
        }
    }
}

/// CC 3.2 adding-a-device (f) — **the owner node's transit pair as the
/// owner's device-join pairing payload carries it**, for an offline or
/// LAN-only first contact where the fresh device has no Rooted route for the
/// node (CLM-pairing-payload-transit-pin).
///
/// Edge does not own the pairing payload: the device-join pairing code / QR
/// is the host's (CIRISServer's device-join flow), and a verify fedcode is
/// far too small for a 1184-byte ML-KEM key. This is the minimal edge-side
/// shape the host must carry inside its payload and hand to
/// `ReticulumTransport::send_first_contact_pinned`; the owner node mints it
/// with `ReticulumTransport::pairing_transit_pin`.
///
/// It is a PIN, never a route: it keys exactly one link, to `node_key_id`,
/// for the first-contact plane only. It is held in memory for that link, never
/// written to the directory, and never resolvable as Rooted
/// (`transit_kex_pair_for` never sees it). All of CC 3.2 (e)'s key-bound rules
/// apply on the link it keys.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PairingTransitPin {
    /// The owner node's occurrence key id: the only node this pin may dial.
    pub node_key_id: String,
    /// The node's transit X25519 public key, base64 (32 bytes).
    pub x25519_base64: String,
    /// The node's transit ML-KEM-768 public key, base64 (1184 bytes).
    pub ml_kem_768_base64: String,
}

impl PairingTransitPin {
    /// The pin for `node_key_id`'s published pair.
    #[must_use]
    pub fn new(node_key_id: impl Into<String>, pair: &TransitKexPair) -> Self {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        Self {
            node_key_id: node_key_id.into(),
            x25519_base64: b64.encode(pair.x25519),
            ml_kem_768_base64: b64.encode(&pair.ml_kem_768[..]),
        }
    }

    /// The pinned pair, for a dial to `dialled` and nothing else.
    ///
    /// Checks the STRUCTURE: the binding to the dialled node, both key
    /// lengths, and in-row separation against `other_keys` (the dialled
    /// node's keys this device holds), by persist's `check_transit_kex_pair`.
    ///
    /// # Errors
    /// [`SealRefusal::PinRejected`].
    pub fn pair_for(
        &self,
        dialled: &str,
        other_keys: &ciris_persist::federation::self_at_login::TransitKexOtherKeys,
    ) -> Result<TransitKexPair, SealRefusal> {
        use base64::Engine as _;
        use ciris_persist::federation::self_at_login::{
            TRANSIT_KEX_ML_KEM_768_LEN, TRANSIT_KEX_X25519_LEN,
        };
        if self.node_key_id != dialled {
            return Err(SealRefusal::PinRejected(format!(
                "the pin is bound to {}, not to the dialled node {dialled}",
                self.node_key_id
            )));
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let x = b64
            .decode(&self.x25519_base64)
            .map_err(|e| SealRefusal::PinRejected(format!("x25519: {e}")))?;
        let k = b64
            .decode(&self.ml_kem_768_base64)
            .map_err(|e| SealRefusal::PinRejected(format!("ml_kem_768: {e}")))?;
        let x25519 = <[u8; TRANSIT_KEX_X25519_LEN]>::try_from(x.as_slice()).map_err(|_| {
            SealRefusal::PinRejected(format!("x25519 is {} bytes, not 32", x.len()))
        })?;
        let ml_kem_768 = Box::<[u8; TRANSIT_KEX_ML_KEM_768_LEN]>::try_from(k.into_boxed_slice())
            .map_err(|k| {
                SealRefusal::PinRejected(format!("ml_kem_768 is {} bytes, not 1184", k.len()))
            })?;
        let pair = TransitKexPair { x25519, ml_kem_768 };
        // CC 3.3.6.2 in-row key separation, persist's rule (CIRISPersist#1106),
        // over what a device holds of the dialled node: (b) its transport
        // identity from its announce; (a) its federation signing keys only when
        // the device holds the node's key record (empty for a fresh device).
        ciris_persist::federation::self_at_login::check_transit_kex_pair(&pair, other_keys)
            .map_err(|r| {
                SealRefusal::PinRejected(format!(
                    "the pinned pair reuses one of the node's own keys: {} (CC 3.3.6.2)",
                    r.as_str()
                ))
            })?;
        Ok(pair)
    }
}

/// CC 3.2 (f) — the first-contact plane both ways on a pairing-pinned link:
/// the request the device sends and the response it is answered with.
#[must_use]
pub fn is_first_contact_plane(bytes: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Peek {
        message_type: crate::messages::MessageType,
    }
    serde_json::from_slice::<Peek>(bytes).is_ok_and(|p| {
        matches!(
            p.message_type,
            crate::messages::MessageType::OpaqueRequest
                | crate::messages::MessageType::OpaqueResponse
        )
    })
}

/// What a first-contact request names about its sender: the envelope's
/// signer and, when it carries one, the key record's `key_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstContactSender {
    /// The envelope's `signing_key_id`: the key that signed the request.
    pub signer: String,
    /// The key the request introduces (its `key:record:v1` row's key id,
    /// `OpaqueRequestWire::carried_key_id`), when it introduces one.
    pub record_key_id: Option<String>,
}

/// The first-contact plane (`FSD/FIRST_CONTACT.md` §2.2): an
/// `OpaqueRequest` envelope, which is how an unowned device asks to join (the
/// server's device-join kind `0x0000_0002`) or makes any other first contact.
/// The only frame class an unattributed initiator's sealed link may carry.
/// `None` for every other frame.
#[must_use]
pub fn first_contact_sender(bytes: &[u8]) -> Option<FirstContactSender> {
    #[derive(serde::Deserialize)]
    struct Peek {
        message_type: crate::messages::MessageType,
        signing_key_id: String,
        body: Option<Box<serde_json::value::RawValue>>,
    }
    let p = serde_json::from_slice::<Peek>(bytes).ok()?;
    if p.message_type != crate::messages::MessageType::OpaqueRequest {
        return None;
    }
    // persist v59 — the introduced key is the `key:record:v1` row's, through
    // the wire type's ONE accessor the first-contact door reads too.
    let record_key_id = p
        .body
        .and_then(|b| serde_json::from_str::<crate::messages::OpaqueRequestWire>(b.get()).ok())
        .and_then(|w| w.carried_key_id());
    Some(FirstContactSender {
        signer: p.signing_key_id,
        record_key_id,
    })
}

/// CLM-first-contact-seal-key-bound (CC 3.2 adding-a-device (e), CC 5.3.3.5
/// E1) — the first-contact initiator is UNOWNED but never ANONYMOUS. On a
/// sealed link whose initiator has no attribution, a frame is admitted only
/// if it is a first-contact request whose signer, and whose carried key
/// record, are the handshake's initiator key `claimed`: the key that opened
/// the sealed link, the key that signed the request, and the key the
/// matching code is derived from
/// ([`crate::first_contact::first_contact_matching_code`]) are one key.
///
/// # Errors
/// [`SealRefusal::FirstContactOnly`] for any other plane;
/// [`SealRefusal::FirstContactSignerMismatch`] for a request signed by (or
/// introducing) another key.
pub fn admit_unattributed_frame(claimed: &str, bytes: &[u8]) -> Result<(), SealRefusal> {
    let sender = first_contact_sender(bytes).ok_or(SealRefusal::FirstContactOnly)?;
    let record_matches = sender
        .record_key_id
        .as_deref()
        .map_or(true, |k| k == claimed);
    if sender.signer == claimed && record_matches {
        Ok(())
    } else {
        Err(SealRefusal::FirstContactSignerMismatch {
            claimed: claimed.to_owned(),
            signer: sender.signer,
            record: sender.record_key_id,
        })
    }
}

#[cfg(test)]
#[path = "link_seal/tests.rs"]
mod tests;
