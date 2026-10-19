//! CC 5.3.3.5 E1 / CC 3.3.6.2 — the hybrid transit KEX every RNS link runs
//! as its FIRST frame: the handshake, its framing, and the keys by role.
//!
//! The construction is CIRISVerify#309's [`ciris_crypto::transit_kex`]. This
//! module is pure and synchronous: it builds the dialler's handshake frames,
//! reassembles them at the dialled end, answers them, and checks the claim.
//! [`crate::transport::link_seal`] runs it on every link, inbound and
//! outbound, before any edge frame is sent or delivered, and seals every
//! frame after it under the keys it yields. (It began as the A/V hop's KEX,
//! CIRISEdge#805; A/V's outer seal now uses the link's keys, so a link runs
//! one KEX, not two.)
//!
//! # Roles
//!
//! The **dialler is always the initiator** (verify's rule). Before it dials
//! it resolves the dialled node's static transit pair (Rooted only, persist's
//! `transit_kex_pair_for`, by the id it dials); once the link is established
//! it runs [`initiate`] and sends the frames as the link's FIRST messages.
//! A dialled node with no usable pair cannot be keyed: the dial is refused by
//! name ([`AvHandshakeError::NoTransitPair`]) and never made. There is no
//! classical fallback and no caller-supplied key (E1 forbids it).
//!
//! The **dialled end is the responder**. It reassembles the handshake
//! ([`Reassembler`]) and runs [`respond`] under its own transit keys. The
//! KEX authenticates only the responder (verify's module docs), so the
//! handshake's `initiator_key_id` is a CLAIM: [`check_claim`] holds it to the
//! peer the link itself is attributed to (#393). The link layer applies it
//! wherever that attribution is known; see `link_seal` for the first-contact
//! carve-out (an unattributed initiator).
//!
//! # Keys by role
//!
//! [`LinkTransit::seal_key`] / [`LinkTransit::open_key`] pick
//! `TransitKeys::seal_key(role)` / `open_key(role)`: each end seals what it
//! SENDS and opens what it RECEIVES. These raw keys are what A/V's outer seal
//! uses; the link seal derives its own keys from them under a distinct label
//! (`link_seal`), so the two layers never share a `(key, nonce)`.
//!
//! # `link_id`
//!
//! The KEX binds the 16-byte RNS `link_id`. An end that reports a stale id
//! (leviculum#86, CIRISEdge#867) derives different keys from its peer, so
//! every sealed frame fails to open and the link is closed; the dialler
//! re-dials, which is a new link, a new id and a new handshake.
//!
//! # Framing: N parts, length-headed, bounded
//!
//! A handshake is about 1.2 KB under the current suite and larger under a
//! future one, and a link may run at the base MTU (a Channel message of about
//! 400 B). So the handshake rides as N Channel messages, sized to the link's
//! Channel limit, with no fixed count:
//!
//! ```text
//! start:        "CTKX" ‖ version(1) ‖ 0x00 ‖ total_len u32_be ‖ bytes[1..]
//! continuation: "CTKX" ‖ version(1) ‖ 0x01 ‖ bytes[1..]
//! ```
//!
//! The receiver refuses a declared length over [`MAX_HANDSHAKE_BYTES`] at the
//! START frame, before buffering anything, and never holds more than the
//! declared length; a frame past it or a budget overrun ([`HANDSHAKE_BUDGET`])
//! is a named refusal.
//!
//! **Telling handshake frames from sealed frames is positional, and the tag
//! makes a mistake loud.** The dialler's first messages are the handshake and
//! nothing precedes them: it sends no edge frame until every part is out, and
//! the link's Channel is sequenced, so the responder reads exactly the
//! handshake's frames, by its declared length, before anything else. The
//! responder never sends a handshake and sends nothing until it has answered
//! one. A frame in the handshake's place without the `"CTKX"` tag (a peer
//! that skipped the KEX) is refused by name
//! ([`AvHandshakeError::NotAHandshake`]) rather than misparsed. One handshake
//! per link: a re-key is a re-dial.

use std::time::Duration;

use ciris_crypto::transit_kex::{
    self, TransitHandshake, TransitKexError, TransitRole, LINK_ID_LEN, TRANSIT_KEY_LEN,
};
use ciris_persist::federation::self_at_login::TransitKexPair;
use zeroize::Zeroizing;

use crate::transport::transit_kex_custody::TransitKexSecret;

/// The tag every handshake frame opens with.
pub const HANDSHAKE_MAGIC: [u8; 4] = *b"CTKX";

/// The framing version this build speaks.
pub const HANDSHAKE_FRAME_VERSION: u8 = 1;

const KIND_START: u8 = 0x00;
const KIND_CONTINUATION: u8 = 0x01;

/// Bytes of framing on the START frame (tag, version, kind, `u32` length).
pub const START_HEADER_LEN: usize = 4 + 1 + 1 + 4;

/// Bytes of framing on a continuation frame (tag, version, kind).
pub const CONTINUATION_HEADER_LEN: usize = 4 + 1 + 1;

/// The most handshake bytes a responder will reassemble. Verify's current
/// suite is about 1.2 KB; this leaves room for a larger one (ML-KEM-1024's
/// ciphertext alone is 1568 B) without letting a peer make us buffer more.
pub const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;

/// How long either end spends on the handshake before refusing it: the
/// dialler on sending it, the responder on receiving all of it.
pub const HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

/// Why a link's transit KEX was refused. Every variant is a named refusal:
/// the link is closed (or never dialled) and no key is installed.
#[derive(Debug, thiserror::Error)]
pub enum AvHandshakeError {
    /// The dialled node publishes no usable transit KEX pair (no live Rooted
    /// binding carrying one, two disagreeing, or one reusing its keys): it
    /// cannot be keyed (CC 3.3.6.2).
    #[error(
        "{peer} publishes no usable transit KEX pair, so no link to it can be sealed \
         (CC 3.3.6.2); refused, never keyed any other way (CC 5.3.3.5 E1)"
    )]
    NoTransitPair {
        /// The dialled peer.
        peer: String,
    },
    /// The dialled node's pair could not be read.
    #[error("cannot read {peer}'s transit KEX pair: {detail}")]
    PairLookup {
        /// The dialled peer.
        peer: String,
        /// The directory's error, or that there is no directory.
        detail: String,
    },
    /// The handshake names a construction other than the hybrid suite: a
    /// classical-only or unknown suite. Never answered.
    #[error("transit KEX handshake names a suite other than the hybrid one; refused")]
    Suite,
    /// The construction refused (bad key id, low-order point, malformed
    /// body, ...).
    #[error("transit KEX: {0}")]
    Kex(TransitKexError),
    /// The handshake was addressed to another responder key.
    #[error("transit KEX handshake addressed to another responder key")]
    ResponderMismatch,
    /// The handshake's claimed initiator is not the peer the link proves.
    #[error(
        "transit KEX handshake claims initiator {claimed} but the link is attributed to \
         {proven}; refused, no key installed"
    )]
    ClaimMismatch {
        /// `initiator_key_id` from the handshake.
        claimed: String,
        /// The link's #393-attributed peer.
        proven: String,
    },
    /// A frame in the handshake's place does not carry the handshake tag.
    #[error("first frame on the link is not a transit KEX handshake frame")]
    NotAHandshake,
    /// A handshake frame of a framing version this build does not speak.
    #[error("transit KEX handshake framing version {0} is not supported")]
    UnsupportedVersion(u8),
    /// The framing is wrong (a continuation first, a second start, an empty
    /// part, a part past the declared length).
    #[error("transit KEX handshake framing: {0}")]
    Malformed(&'static str),
    /// The declared length is over [`MAX_HANDSHAKE_BYTES`] (or zero).
    #[error("transit KEX handshake declares {declared} bytes; at most {max} are reassembled")]
    TooLarge {
        /// The length the START frame declared.
        declared: usize,
        /// [`MAX_HANDSHAKE_BYTES`].
        max: usize,
    },
    /// The handshake did not complete within [`HANDSHAKE_BUDGET`].
    #[error("transit KEX handshake did not complete within {0:?}")]
    Timeout(Duration),
    /// The handshake could not be sent.
    #[error("transit KEX handshake send failed: {0}")]
    Send(String),
    /// The link's id is not the 16-byte RNS link id the KEX binds.
    #[error("link id is {0} bytes; the transit KEX binds a 16-byte RNS link id")]
    LinkIdLength(usize),
}

impl AvHandshakeError {
    /// The `link_seal` metric label this refusal counts under.
    #[must_use]
    pub fn label(&self) -> &'static str {
        use crate::observability as o;
        match self {
            Self::NoTransitPair { .. } => o::LINK_SEAL_REFUSED_NO_PAIR,
            Self::PairLookup { .. } => o::LINK_SEAL_REFUSED_LOOKUP,
            Self::Suite => o::LINK_SEAL_REFUSED_SUITE,
            Self::Kex(_) | Self::LinkIdLength(_) => o::LINK_SEAL_REFUSED_KEX,
            Self::ResponderMismatch => o::LINK_SEAL_REFUSED_RESPONDER_MISMATCH,
            Self::ClaimMismatch { .. } => o::LINK_SEAL_REFUSED_CLAIM_MISMATCH,
            Self::NotAHandshake => o::LINK_SEAL_REFUSED_NOT_A_HANDSHAKE,
            Self::UnsupportedVersion(_) | Self::Malformed(_) => o::LINK_SEAL_REFUSED_MALFORMED,
            Self::TooLarge { .. } => o::LINK_SEAL_REFUSED_TOO_LARGE,
            Self::Timeout(_) => o::LINK_SEAL_REFUSED_TIMEOUT,
            Self::Send(_) => o::LINK_SEAL_REFUSED_SEND,
        }
    }
}

impl From<TransitKexError> for AvHandshakeError {
    fn from(e: TransitKexError) -> Self {
        match e {
            TransitKexError::ResponderMismatch => Self::ResponderMismatch,
            TransitKexError::WrongIdentifier => Self::Suite,
            other => Self::Kex(other),
        }
    }
}

/// One link's transit keys, held by the end that ran the handshake in
/// `role`. Zeroized on drop.
#[derive(Clone)]
pub struct LinkTransit {
    seal: Zeroizing<[u8; TRANSIT_KEY_LEN]>,
    open: Zeroizing<[u8; TRANSIT_KEY_LEN]>,
    role: TransitRole,
}

impl std::fmt::Debug for LinkTransit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkTransit")
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl LinkTransit {
    fn from_keys(keys: &transit_kex::TransitKeys, role: TransitRole) -> Self {
        Self {
            seal: Zeroizing::new(*keys.seal_key(role)),
            open: Zeroizing::new(*keys.open_key(role)),
            role,
        }
    }

    /// This end's role on the link.
    #[must_use]
    pub fn role(&self) -> TransitRole {
        self.role
    }

    /// The key this end SEALS outbound frames with: an
    /// [`AvSubscriberLink`](crate::transport::realtime_av_dispatcher::AvSubscriberLink)'s
    /// `transit_key`.
    #[must_use]
    pub fn seal_key(&self) -> [u8; 32] {
        *self.seal
    }

    /// The key this end OPENS inbound frames with: an
    /// [`AvInboundLink`](crate::transport::realtime_av_dispatcher::AvInboundLink)'s
    /// `transit_key`.
    #[must_use]
    pub fn open_key(&self) -> [u8; 32] {
        *self.open
    }
}

/// The 16-byte RNS link id the KEX binds.
///
/// # Errors
/// [`AvHandshakeError::LinkIdLength`] for any other length.
pub fn kex_link_id(link_id: &[u8]) -> Result<[u8; LINK_ID_LEN], AvHandshakeError> {
    <[u8; LINK_ID_LEN]>::try_from(link_id)
        .map_err(|_| AvHandshakeError::LinkIdLength(link_id.len()))
}

/// Split `handshake` into frames of at most `frame_limit` bytes.
///
/// # Errors
/// [`AvHandshakeError::TooLarge`] for an empty handshake or one over
/// [`MAX_HANDSHAKE_BYTES`]; [`AvHandshakeError::Send`] when `frame_limit`
/// leaves no room for a byte after the START header.
pub fn fragment(handshake: &[u8], frame_limit: usize) -> Result<Vec<Vec<u8>>, AvHandshakeError> {
    if handshake.is_empty() || handshake.len() > MAX_HANDSHAKE_BYTES {
        return Err(AvHandshakeError::TooLarge {
            declared: handshake.len(),
            max: MAX_HANDSHAKE_BYTES,
        });
    }
    if frame_limit <= START_HEADER_LEN {
        return Err(AvHandshakeError::Send(format!(
            "the link's Channel carries {frame_limit} B, too few for a handshake frame"
        )));
    }
    let total = u32::try_from(handshake.len()).map_err(|_| AvHandshakeError::TooLarge {
        declared: handshake.len(),
        max: MAX_HANDSHAKE_BYTES,
    })?;
    let first = handshake.len().min(frame_limit - START_HEADER_LEN);
    let mut frames = Vec::new();
    let mut start = Vec::with_capacity(START_HEADER_LEN + first);
    start.extend_from_slice(&HANDSHAKE_MAGIC);
    start.push(HANDSHAKE_FRAME_VERSION);
    start.push(KIND_START);
    start.extend_from_slice(&total.to_be_bytes());
    start.extend_from_slice(&handshake[..first]);
    frames.push(start);
    for part in handshake[first..].chunks(frame_limit - CONTINUATION_HEADER_LEN) {
        let mut f = Vec::with_capacity(CONTINUATION_HEADER_LEN + part.len());
        f.extend_from_slice(&HANDSHAKE_MAGIC);
        f.push(HANDSHAKE_FRAME_VERSION);
        f.push(KIND_CONTINUATION);
        f.extend_from_slice(part);
        frames.push(f);
    }
    Ok(frames)
}

/// Reassembles one handshake from its frames, holding at most the declared
/// length, which is at most [`MAX_HANDSHAKE_BYTES`].
#[derive(Debug, Default)]
pub struct Reassembler {
    expected: Option<usize>,
    buf: Vec<u8>,
}

impl Reassembler {
    /// A reassembler waiting for a START frame.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held so far.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Take one frame. `Ok(Some(bytes))` is the complete handshake.
    ///
    /// # Errors
    /// Every [`AvHandshakeError`] framing refusal; after one, the
    /// reassembler is spent.
    pub fn push(&mut self, b: &[u8]) -> Result<Option<Vec<u8>>, AvHandshakeError> {
        if b.len() < CONTINUATION_HEADER_LEN || b[..4] != HANDSHAKE_MAGIC {
            return Err(AvHandshakeError::NotAHandshake);
        }
        if b[4] != HANDSHAKE_FRAME_VERSION {
            return Err(AvHandshakeError::UnsupportedVersion(b[4]));
        }
        let data = match (b[5], self.expected) {
            (KIND_START, None) => {
                let Some(len) = b.get(CONTINUATION_HEADER_LEN..START_HEADER_LEN) else {
                    return Err(AvHandshakeError::Malformed(
                        "start frame shorter than its header",
                    ));
                };
                let mut be = [0u8; 4];
                be.copy_from_slice(len);
                let declared = usize::try_from(u32::from_be_bytes(be)).unwrap_or(usize::MAX);
                if declared == 0 || declared > MAX_HANDSHAKE_BYTES {
                    return Err(AvHandshakeError::TooLarge {
                        declared,
                        max: MAX_HANDSHAKE_BYTES,
                    });
                }
                self.expected = Some(declared);
                self.buf.reserve_exact(declared);
                &b[START_HEADER_LEN..]
            }
            (KIND_START, Some(_)) => {
                return Err(AvHandshakeError::Malformed("a second start frame"));
            }
            (KIND_CONTINUATION, None) => {
                return Err(AvHandshakeError::Malformed(
                    "a continuation before the start",
                ));
            }
            (KIND_CONTINUATION, Some(_)) => &b[CONTINUATION_HEADER_LEN..],
            _ => return Err(AvHandshakeError::Malformed("unknown frame kind")),
        };
        if data.is_empty() {
            return Err(AvHandshakeError::Malformed("an empty part"));
        }
        let expected = self.expected.unwrap_or(0);
        if self.buf.len() + data.len() > expected {
            return Err(AvHandshakeError::Malformed(
                "a part past the declared length",
            ));
        }
        self.buf.extend_from_slice(data);
        Ok((self.buf.len() == expected).then(|| std::mem::take(&mut self.buf)))
    }
}

/// Dialler side: run the link's KEX against the dialled node's `pair` and
/// cut the handshake into frames of at most `frame_limit` bytes (the link's
/// Channel limit), to be sent in order as the link's first messages.
///
/// `own_key_id` is the identity this node's links are attributed to;
/// `peer_key_id` is the node dialled.
///
/// # Errors
/// [`AvHandshakeError`] on a KEX refusal or a `frame_limit` too small for a
/// frame.
pub fn initiate(
    link_id: &[u8],
    own_key_id: &str,
    peer_key_id: &str,
    pair: &TransitKexPair,
    frame_limit: usize,
) -> Result<(Vec<Vec<u8>>, LinkTransit), AvHandshakeError> {
    let link_id = kex_link_id(link_id)?;
    let (hs, keys) = transit_kex::initiate(
        &link_id,
        own_key_id,
        peer_key_id,
        &pair.x25519,
        &pair.ml_kem_768[..],
    )?;
    let frames = fragment(&hs.to_bytes(), frame_limit)?;
    Ok((
        frames,
        LinkTransit::from_keys(&keys, TransitRole::Initiator),
    ))
}

/// Dialled side: answer a reassembled handshake under this node's transit
/// keys as `local_key_id`. Returns the responder's keys and the handshake's
/// CLAIMED initiator, which the caller must hold to the link's attributed
/// peer ([`check_claim`]) before trusting it.
///
/// # Errors
/// [`AvHandshakeError`]: a wrong suite, a malformed body, a responder
/// mismatch, or any other KEX refusal.
pub fn respond(
    bytes: &[u8],
    link_id: &[u8],
    local_key_id: &str,
    secret: &TransitKexSecret,
) -> Result<(LinkTransit, String), AvHandshakeError> {
    let link_id = kex_link_id(link_id)?;
    let hs = TransitHandshake::from_bytes(bytes)?;
    let keys = transit_kex::respond(
        &link_id,
        local_key_id,
        secret.x25519_private(),
        secret.ml_kem_768_dk_seed(),
        &secret.pair().ml_kem_768[..],
        &hs,
    )?;
    Ok((
        LinkTransit::from_keys(&keys, TransitRole::Responder),
        hs.initiator_key_id().to_owned(),
    ))
}

/// The KEX authenticates only the responder: the initiator's id is a CLAIM,
/// held here to `proven`, the peer the link itself is attributed to.
///
/// # Errors
/// [`AvHandshakeError::ClaimMismatch`].
pub fn check_claim(claimed: &str, proven: &str) -> Result<(), AvHandshakeError> {
    if claimed == proven {
        Ok(())
    } else {
        Err(AvHandshakeError::ClaimMismatch {
            claimed: claimed.to_owned(),
            proven: proven.to_owned(),
        })
    }
}

#[cfg(test)]
#[path = "av_transit_handshake/tests.rs"]
mod tests;
