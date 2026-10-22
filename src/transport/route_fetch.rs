//! CC 5.3.3.5 E1, the **pre-seal route fetch** (steward ruling 2026-10-21,
//! CIRISConstitution#172; `CLM-pre-seal-route-fetch`).
//!
//! Two strangers on a bare mesh hold only each other's announce, and an
//! announce cannot carry a post-quantum transit pair. A dialler that holds
//! no pair authenticated to the node it means to reach (no Rooted binding,
//! no copy of that node's own hybrid-signed route row, no pairing pin) opens
//! the link and sends, as its FIRST frame, a **route request** (`CTKR`)
//! naming the dialled key. The responder answers with its own hybrid-signed
//! `transport_destination` row (`CTKA`, the [`fragment_tagged`] framing)
//! and nothing else; the dialler verifies the row under the
//! `CLM-seal-authenticated-pair` rule (signer = the dialled key, the #1103
//! fingerprint, the in-row separation, persist's signature gate) and only
//! then runs the `CTKX` handshake. The row is public and self-authenticating
//! (an announce already makes the node public; a relay would hand the same
//! row over), so the round trip discloses nothing an announce does not.
//!
//! The answer carries the responder's `key:record:v1` row as well when the
//! dialler said it does not hold the key: a stranger cannot verify a
//! hybrid signature without the signer's public record, and that record is
//! the same public, self-signed row the key plane replicates to everyone.
//! The dialler admits it through persist's key door (proof of possession,
//! fingerprint) before the route row is read.
//!
//! Receiver order at the responder, BEFORE any directory read: one request
//! per link, a node-wide rate ([`RouteRequestLimiter`]), only its own key
//! answered. The responder serves nothing and buffers nothing until the
//! seal completes; a link whose first frame is anything else is refused and
//! closed (as every non-handshake first frame already is). Where no
//! responder can be reached, the pairing pin (CC 3.2 (f)) is the failover.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ciris_persist::federation::self_at_login::SignedTransportDestination;
use ciris_persist::federation::Attestation;
use serde::{Deserialize, Serialize};

use super::av_transit_handshake::{fragment_tagged, AvHandshakeError, Reassembler};

/// The route request's 4-byte tag.
pub const ROUTE_REQUEST_MAGIC: [u8; 4] = *b"CTKR";
/// The route answer's 4-byte tag (START/CONTINUATION framing under it).
pub const ROUTE_ANSWER_MAGIC: [u8; 4] = *b"CTKA";
/// The request/answer framing version.
pub const ROUTE_FRAME_VERSION: u8 = 1;
/// A request is one frame: tag, version, flags, key id.
const REQUEST_HEADER_LEN: usize = 4 + 1 + 1;
/// The longest key id a request names.
pub const MAX_REQUEST_KEY_ID_BYTES: usize = 256;
/// The largest answer reassembled: a signed route row (~6 KB) and, when
/// carried, a hybrid `key:record:v1` row (~17 KB), with headroom.
pub const MAX_ROUTE_ANSWER_BYTES: usize = 48 * 1024;
/// How long a dialler waits for the answer, and how long a responder's
/// handshake budget runs from a request it answered: the answer is up to
/// [`MAX_ROUTE_ANSWER_BYTES`] over the link's Channel, and the dialler's
/// handshake follows it.
pub const ROUTE_FETCH_BUDGET: Duration = Duration::from_secs(30);
/// The dialler already holds the dialled key's record: no key row needed.
const FLAG_HOLDS_KEY_RECORD: u8 = 0x01;
/// Node-wide: at most this many route requests admitted per
/// [`ROUTE_REQUEST_WINDOW`], counted before anything is read or verified.
pub const ROUTE_REQUESTS_PER_WINDOW: u32 = 32;
/// The node-wide rate window.
pub const ROUTE_REQUEST_WINDOW: Duration = Duration::from_secs(10);

/// The dialler's first frame: which key it means to reach, and whether it
/// already holds that key's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRequest {
    /// The dialled occurrence key id.
    pub key_id: String,
    /// `true`: the answer need not carry the `key:record:v1` row.
    pub holds_key_record: bool,
}

/// The responder's answer: its own hybrid-signed route row, and its key
/// record row when the request said the dialler lacks it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteAnswer {
    /// The responder's own `transport_destination` row, transit pair on it.
    pub route: SignedTransportDestination,
    /// The responder's `key:record:v1` row, when asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_record_row: Option<Attestation>,
}

/// Why a route fetch was refused, on either end. Every variant is named and
/// counted under [`Self::label`]; the link is closed.
#[derive(Debug, thiserror::Error)]
pub enum RouteFetchError {
    /// A request frame that does not parse.
    #[error("route request malformed: {0}")]
    MalformedRequest(&'static str),
    /// A request of a framing version this build does not speak.
    #[error("route request framing version {0} is not supported")]
    UnsupportedVersion(u8),
    /// A second request on the link, or one over the node-wide rate: refused
    /// before anything is read.
    #[error("route request refused by the receiver order (per link once; node-wide rate)")]
    RateLimited,
    /// The request names a key that is not this node's.
    #[error("route request names {asked}; this node answers only for {ours}")]
    NotOurs {
        /// The key the request named.
        asked: String,
        /// This node's occurrence key id.
        ours: String,
    },
    /// This node holds no live signed route row of its own carrying a pair.
    #[error("no own signed route row with a transit pair to answer with: {0}")]
    Unavailable(String),
    /// The answer's framing or size was refused.
    #[error("route answer framing: {0}")]
    Answer(AvHandshakeError),
    /// The answer reassembled but is not a route answer.
    #[error("route answer is not a signed route row")]
    AnswerNotARow,
    /// The answer's row is not the dialled node's own: refused, never stored.
    #[error("route answer signed by {signer} for {subject}; the dialled key is {dialled}")]
    SignedByAnotherKey {
        /// The row's attesting key.
        signer: String,
        /// The row's occurrence key.
        subject: String,
        /// The key the dial meant to reach.
        dialled: String,
    },
    /// The carried key record was refused at persist's key door.
    #[error("route answer's key record refused: {0}")]
    KeyRecordRefused(String),
    /// The row did not pass persist's authenticated admission or the
    /// `CLM-seal-authenticated-pair` checks.
    #[error("route answer's row did not authenticate a pair: {0}")]
    Unverified(String),
    /// No answer within [`ROUTE_FETCH_BUDGET`].
    #[error("no route answer within {0:?}")]
    Timeout(Duration),
    /// The link closed before an answer (the responder refused the request).
    #[error("the link closed before a route answer arrived")]
    LinkClosed,
    /// A request or answer frame could not be sent.
    #[error("route fetch send failed: {0}")]
    Send(String),
}

impl RouteFetchError {
    /// The `link_seal` metric label this refusal counts under.
    #[must_use]
    pub fn label(&self) -> &'static str {
        use crate::observability as o;
        match self {
            Self::MalformedRequest(_) | Self::UnsupportedVersion(_) => {
                o::LINK_SEAL_REFUSED_ROUTE_REQUEST
            }
            Self::RateLimited => o::LINK_SEAL_REFUSED_ROUTE_RATE_LIMITED,
            Self::NotOurs { .. } => o::LINK_SEAL_REFUSED_ROUTE_NOT_OURS,
            Self::Unavailable(_) => o::LINK_SEAL_REFUSED_ROUTE_UNAVAILABLE,
            Self::Answer(_) | Self::AnswerNotARow => o::LINK_SEAL_REFUSED_ROUTE_ANSWER,
            Self::SignedByAnotherKey { .. } => o::LINK_SEAL_REFUSED_ROUTE_ANSWER_SIGNER,
            Self::KeyRecordRefused(_) | Self::Unverified(_) => {
                o::LINK_SEAL_REFUSED_ROUTE_ANSWER_UNVERIFIED
            }
            Self::Timeout(_) => o::LINK_SEAL_REFUSED_ROUTE_TIMEOUT,
            Self::LinkClosed => o::LINK_SEAL_REFUSED_ROUTE_CLOSED,
            Self::Send(_) => o::LINK_SEAL_REFUSED_ROUTE_SEND,
        }
    }
}

/// Whether `bytes` carry the route request tag.
#[must_use]
pub fn is_route_request(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ROUTE_REQUEST_MAGIC
}

/// Whether `bytes` carry the route answer tag.
#[must_use]
pub fn is_route_answer(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == ROUTE_ANSWER_MAGIC
}

/// Encode a request as one frame.
#[must_use]
pub fn encode_request(req: &RouteRequest) -> Vec<u8> {
    let key = req.key_id.as_bytes();
    let mut out = Vec::with_capacity(REQUEST_HEADER_LEN + key.len());
    out.extend_from_slice(&ROUTE_REQUEST_MAGIC);
    out.push(ROUTE_FRAME_VERSION);
    out.push(if req.holds_key_record {
        FLAG_HOLDS_KEY_RECORD
    } else {
        0
    });
    out.extend_from_slice(key);
    out
}

/// Decode a request frame.
///
/// # Errors
/// [`RouteFetchError::MalformedRequest`] / [`RouteFetchError::UnsupportedVersion`].
pub fn decode_request(bytes: &[u8]) -> Result<RouteRequest, RouteFetchError> {
    if !is_route_request(bytes) || bytes.len() <= REQUEST_HEADER_LEN {
        return Err(RouteFetchError::MalformedRequest(
            "not a route request, or one naming no key",
        ));
    }
    if bytes[4] != ROUTE_FRAME_VERSION {
        return Err(RouteFetchError::UnsupportedVersion(bytes[4]));
    }
    let flags = bytes[5];
    if flags & !FLAG_HOLDS_KEY_RECORD != 0 {
        return Err(RouteFetchError::MalformedRequest("unknown request flags"));
    }
    let key = &bytes[REQUEST_HEADER_LEN..];
    if key.len() > MAX_REQUEST_KEY_ID_BYTES {
        return Err(RouteFetchError::MalformedRequest("key id too long"));
    }
    let key_id = std::str::from_utf8(key)
        .map_err(|_| RouteFetchError::MalformedRequest("key id is not UTF-8"))?;
    if key_id.chars().any(char::is_control) {
        return Err(RouteFetchError::MalformedRequest(
            "key id carries control characters",
        ));
    }
    Ok(RouteRequest {
        key_id: key_id.to_owned(),
        holds_key_record: flags & FLAG_HOLDS_KEY_RECORD != 0,
    })
}

/// Encode an answer as `CTKA` frames of at most `frame_limit` bytes.
///
/// # Errors
/// The framing's ([`AvHandshakeError::TooLarge`] past
/// [`MAX_ROUTE_ANSWER_BYTES`], a `frame_limit` too small), or a row that
/// does not serialise.
pub fn encode_answer(
    answer: &RouteAnswer,
    frame_limit: usize,
) -> Result<Vec<Vec<u8>>, RouteFetchError> {
    let body = serde_json::to_vec(answer)
        .map_err(|e| RouteFetchError::Unavailable(format!("answer does not serialise: {e}")))?;
    fragment_tagged(
        ROUTE_ANSWER_MAGIC,
        MAX_ROUTE_ANSWER_BYTES,
        &body,
        frame_limit,
    )
    .map_err(RouteFetchError::Answer)
}

/// A reassembler for `CTKA` frames.
#[must_use]
pub fn answer_reassembler() -> Reassembler {
    Reassembler::tagged(ROUTE_ANSWER_MAGIC, MAX_ROUTE_ANSWER_BYTES)
}

/// Decode a reassembled answer.
///
/// # Errors
/// [`RouteFetchError::AnswerNotARow`].
pub fn decode_answer(bytes: &[u8]) -> Result<RouteAnswer, RouteFetchError> {
    serde_json::from_slice(bytes).map_err(|_| RouteFetchError::AnswerNotARow)
}

/// The node-wide receiver order: a sliding window of admitted requests.
/// Checked before a request is parsed past its tag.
#[derive(Debug)]
pub struct RouteRequestLimiter {
    cap: AtomicU32,
    recent: Mutex<VecDeque<Instant>>,
}

impl Default for RouteRequestLimiter {
    fn default() -> Self {
        Self::new(ROUTE_REQUESTS_PER_WINDOW)
    }
}

impl RouteRequestLimiter {
    /// A limiter admitting `cap` requests per [`ROUTE_REQUEST_WINDOW`].
    #[must_use]
    pub fn new(cap: u32) -> Self {
        Self {
            cap: AtomicU32::new(cap),
            recent: Mutex::new(VecDeque::new()),
        }
    }

    /// Change the cap (a test knob; the fleet value is the default).
    pub fn set_cap(&self, cap: u32) {
        self.cap.store(cap, Ordering::Relaxed);
    }

    /// Admit one request now, or refuse it.
    pub fn admit(&self) -> bool {
        self.admit_at(Instant::now())
    }

    fn admit_at(&self, now: Instant) -> bool {
        let cap = self.cap.load(Ordering::Relaxed) as usize;
        let mut recent = self
            .recent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while recent
            .front()
            .is_some_and(|t| now.duration_since(*t) >= ROUTE_REQUEST_WINDOW)
        {
            recent.pop_front();
        }
        if recent.len() >= cap {
            return false;
        }
        recent.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_round_trips_and_names_whether_the_key_is_held() {
        for holds in [false, true] {
            let req = RouteRequest {
                key_id: "node-abc-0123456789abcdef".to_owned(),
                holds_key_record: holds,
            };
            let bytes = encode_request(&req);
            assert!(is_route_request(&bytes));
            assert!(!is_route_answer(&bytes));
            assert_eq!(decode_request(&bytes).expect("decodes"), req);
        }
    }

    #[test]
    fn a_malformed_request_is_refused_by_name() {
        assert!(matches!(
            decode_request(b"CTKX\x01\x00abc"),
            Err(RouteFetchError::MalformedRequest(_))
        ));
        assert!(matches!(
            decode_request(b"CTKR\x01\x00"),
            Err(RouteFetchError::MalformedRequest(_))
        ));
        assert!(matches!(
            decode_request(b"CTKR\x02\x00abc"),
            Err(RouteFetchError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            decode_request(b"CTKR\x01\x80abc"),
            Err(RouteFetchError::MalformedRequest(_))
        ));
        assert!(matches!(
            decode_request(b"CTKR\x01\x00a\nb"),
            Err(RouteFetchError::MalformedRequest(_))
        ));
        let long = [b"CTKR\x01\x00".as_slice(), &[b'a'; 257]].concat();
        assert!(matches!(
            decode_request(&long),
            Err(RouteFetchError::MalformedRequest(_))
        ));
    }

    #[test]
    fn the_answer_framing_reassembles_under_its_own_tag_and_refuses_the_handshakes() {
        let body = vec![0x5au8; 3000];
        let frames = fragment_tagged(ROUTE_ANSWER_MAGIC, MAX_ROUTE_ANSWER_BYTES, &body, 400)
            .expect("frames");
        assert!(frames.len() > 7);
        assert!(frames.iter().all(|f| is_route_answer(f) && f.len() <= 400));
        let mut r = answer_reassembler();
        let mut out = None;
        for f in &frames {
            out = r.push(f).expect("part");
        }
        assert_eq!(out.expect("complete"), body);
        // A CTKX part is not an answer part, and the other way round.
        let mut r = answer_reassembler();
        assert!(matches!(
            r.push(&super::super::av_transit_handshake::fragment(&[1u8; 10], 400).unwrap()[0]),
            Err(AvHandshakeError::NotAHandshake)
        ));
        let mut hs = Reassembler::new();
        assert!(matches!(
            hs.push(&frames[0]),
            Err(AvHandshakeError::NotAHandshake)
        ));
    }

    #[test]
    fn an_answer_over_the_cap_is_refused() {
        let body = vec![1u8; MAX_ROUTE_ANSWER_BYTES + 1];
        assert!(matches!(
            fragment_tagged(ROUTE_ANSWER_MAGIC, MAX_ROUTE_ANSWER_BYTES, &body, 400),
            Err(AvHandshakeError::TooLarge { .. })
        ));
    }

    #[test]
    fn the_limiter_admits_cap_per_window_then_refuses_until_the_window_slides() {
        let l = RouteRequestLimiter::new(2);
        let t0 = Instant::now();
        assert!(l.admit_at(t0));
        assert!(l.admit_at(t0 + Duration::from_secs(1)));
        assert!(!l.admit_at(t0 + Duration::from_secs(2)));
        assert!(l.admit_at(t0 + ROUTE_REQUEST_WINDOW + Duration::from_millis(1)));
        l.set_cap(0);
        assert!(!l.admit_at(t0 + ROUTE_REQUEST_WINDOW + Duration::from_secs(20)));
    }
}
