//! **Range fingerprints, step A: the construction, the wire, and the passive
//! receiver half** (`docs/design/RANGE_FINGERPRINTS.md`; the bytes are
//! `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.4.2).
//!
//! This module is PURE: no directory, no transport, no clock (every `now` is
//! passed in). The bridge owns one [`RfReceiver`] and feeds it what a Session
//! already computed.
//!
//! What step A ships, and nothing more:
//!
//! - the `"a":1` construction (`e(x) = SHA-256(tag‖salt‖x)`, summed mod 2^256
//!   with the count, closed by the node hash), with the FSD's known-answer
//!   vectors as tests;
//! - the nested, leniently parsed `rf` members of `Summary` and `Diff`
//!   ([`RfSummary`], [`RfDiff`]) and the compact `rh` / `wh` / `xh` / `eb`
//!   DECODE ([`decode_compact_hashes`], [`decode_compact_body`]);
//! - the receiver: the listed mirror `M_B(A)` per `(peer, plane)` (design
//!   §3.2), with settled-only insertion (R21), `lc` replacement ordered by `sid`,
//!   the public-plane holdings seed (R24), the salt acceptance rules and the
//!   rebuild bucket (§6.4, R16), the node caps, and the answers (`m` / `s` /
//!   `l` / `u`) bound to the Summary's `(sid, st)` (R10, R17).
//!
//! This node never SENDS a fingerprint in step A. It answers them, and it says
//! that it answers them (the markers, [`RfSummary::marker`], [`RfDiff::marker`]).
//!
//! ## The receiver's set, as built here
//!
//! `T_B(A) = settled_B ∩ M_B(A)` (design §2.4). An id A lists enters the
//! mirror only when it is settled at this node:
//!
//! - **held**: it is not in the receive diff, and not merely held as an
//!   equivalent — it stays;
//! - **provisional**: not wanted for a reason that ends — a refusal in backoff
//!   (#544), a hash-first known hash (#552), a #1252 held-equivalent. It stays
//!   exactly as long as that reason holds: every provisional member is asked
//!   again ([`RxInput::still_settled`]) before any sum, so `T_B ⊆ settled_B`
//!   holds at every compare, not merely within some window;
//! - **wanted**: it waits in `pending` and enters when it is admitted from that
//!   peer ([`RfReceiver::note_settled`]). A fake id is never admitted, so it
//!   never takes a mirror slot (R21, N6). Pending ids have their own node-wide
//!   budget and expire, so they can never push an honest pair to `u:"cap"`.
//!
//! On the removal planes (`Revocation`, `IdentityOccurrenceRevocation`) the
//! settled set is the holdings only (R13): a refused, known or equivalent
//! revocation never enters, so a range holding one never matches.
//!
//! The safety rule needs only `T_B ⊆ settled_B`; every rule here leans toward a
//! smaller `T_B` (a listing) rather than a larger one (a hidden row).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use super::protocol::{EnvelopeKind, EnvelopeRef};

/// The `rf` protocol version this build speaks.
pub const RF_VERSION: u8 = 1;
/// `"a":1`, the salted modular sum. `"a":2` is reserved (ristretto255).
pub const ALG_SALTED_SUM: u8 = 1;
/// The element tag, 16 bytes.
pub const ELEM_TAG: &[u8; 16] = b"CIRIS-RF-v1/elem";
/// The node tag, 16 bytes.
pub const NODE_TAG: &[u8; 16] = b"CIRIS-RF-v1/node";
/// The salt-tag tag, 15 bytes.
pub const SALT_TAG_TAG: &[u8; 15] = b"CIRIS-RF-v1/tag";

/// A range listed with at most this many rows is answered `list` (design §2.3).
pub const RF_LIST_ROWS: u64 = 16;
/// A receiver evaluates at most this many nodes in `n` (design §6.4); `lc`
/// names ranges that also stand as nodes, so it is held to the same bound.
pub const RX_MAX_NODES: usize = 64;
/// A receiver honours at most this many parked ranges (`pk`), the sender's
/// `RF_MAX_PARKED` (design §2.6, R24).
pub const RX_MAX_PARKED: usize = 64;
/// A receiver evaluates at most this many split records (`c`); the 16
/// children inside each count only here (re-review N5).
pub const RX_MAX_SPLITS: usize = 16;
/// The longest prefix: 32 bytes in hex.
pub const MAX_PREFIX_LEN: usize = 64;
/// A new salt under the same `ep` is accepted only this long after the last.
pub const RF_SALT_MIN_AGE: Duration = Duration::from_mins(10);
/// Rebuild bucket: capacity.
pub const RF_REBUILD_TOKENS: f64 = 3.0;
/// Rebuild bucket: one token back per this long.
pub const RF_REBUILD_REFILL: Duration = Duration::from_mins(20);
/// Mirror cap per `(peer, plane)` (design §3.2).
pub const RF_MIRROR_CAP_PAIR: usize = 262_144;
/// Mirror cap node-wide, in ids. An id is a 32-byte hash in a `BTreeSet`,
/// about 55 bytes with the tree's own overhead, so 458,752 ids are ~24 MiB;
/// with [`RF_PENDING_CAP_NODE`] and the bucket sums the receiver stays near
/// the design's 32 MiB node-wide in REAL bytes, not only in payload.
pub const RF_MIRROR_CAP_NODE: usize = 458_752;
/// Pending (listed, wanted, not yet admitted) ids kept per `(peer, plane)`.
pub const RF_PENDING_CAP_PAIR: usize = 4_096;
/// Pending ids kept node-wide. A budget of their own: a peer listing made-up
/// ids fills at most this, never the mirror's (N6, witness 33).
pub const RF_PENDING_CAP_NODE: usize = 65_536;
/// A pending id that was not admitted within this long is forgotten: its
/// Deliver was lost or deferred, and it enters on its next listing instead.
pub const RF_PENDING_TTL: Duration = Duration::from_mins(5);
/// Peers whose receiver state is kept; past it the least recently heard is
/// forgotten, which costs that peer one descent, never a row.
pub const RF_MAX_PEERS: usize = 1_024;
/// Below this many ids a mirror keeps no bucket sums and sums on demand (at
/// most this many hashes a node), so a peer with a handful of rows costs no
/// 10 KiB array.
pub const RF_SUMS_MIN_IDS: usize = 1_024;
/// `lc` ordering memory per `(peer, plane)`; past it the oldest entry is
/// dropped and its `sid` becomes a floor no older `lc` may pass.
pub const RF_LC_MEMORY: usize = 64;
/// Match-feed memory per `(peer, plane)`: the fingerprint last booked per
/// matched prefix (design §5.7: once per change).
pub const RF_FED_MEMORY: usize = 64;

// ─── The construction ───────────────────────────────────────────────────

/// A 256-bit sum mod 2^256 and a count: what one range's fingerprint closes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Acc {
    limbs: [u64; 4],
    count: u64,
}

impl Acc {
    fn limb(e: &[u8; 32], i: usize) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&e[i * 8..i * 8 + 8]);
        u64::from_le_bytes(b)
    }

    /// Add one element value (little-endian 256-bit).
    pub fn add(&mut self, e: &[u8; 32]) {
        let mut carry = false;
        for i in 0..4 {
            let (s1, c1) = self.limbs[i].overflowing_add(Self::limb(e, i));
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            self.limbs[i] = s2;
            carry = c1 || c2;
        }
        self.count = self.count.wrapping_add(1);
    }

    /// Subtract one element value.
    pub fn sub(&mut self, e: &[u8; 32]) {
        let mut borrow = false;
        for i in 0..4 {
            let (d1, b1) = self.limbs[i].overflowing_sub(Self::limb(e, i));
            let (d2, b2) = d1.overflowing_sub(u64::from(borrow));
            self.limbs[i] = d2;
            borrow = b1 || b2;
        }
        self.count = self.count.wrapping_sub(1);
    }

    /// Fold another accumulator in.
    pub fn merge(&mut self, other: &Acc) {
        let mut carry = false;
        for i in 0..4 {
            let (s1, c1) = self.limbs[i].overflowing_add(other.limbs[i]);
            let (s2, c2) = s1.overflowing_add(u64::from(carry));
            self.limbs[i] = s2;
            carry = c1 || c2;
        }
        self.count = self.count.wrapping_add(other.count);
    }

    /// The sum, little-endian.
    #[must_use]
    pub fn sum_le(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&self.limbs[i].to_le_bytes());
        }
        out
    }

    /// The count.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// `e(x) = SHA-256(ELEM_TAG ‖ salt ‖ x)`.
#[must_use]
pub fn elem(salt: &[u8; 32], x: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ELEM_TAG);
    h.update(salt);
    h.update(x);
    h.finalize().into()
}

/// The node fingerprint of one range (16 bytes).
#[must_use]
pub fn node_fp(plane: &str, prefix: &str, acc: &Acc) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(NODE_TAG);
    h.update([u8::try_from(plane.len()).unwrap_or(u8::MAX)]);
    h.update(plane.as_bytes());
    h.update([u8::try_from(prefix.len()).unwrap_or(u8::MAX)]);
    h.update(prefix.as_bytes());
    h.update(acc.sum_le());
    h.update(acc.count().to_be_bytes());
    let d: [u8; 32] = h.finalize().into();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// The salt tag `st`: `SHA-256(SALT_TAG_TAG ‖ salt)[0..4]`.
#[must_use]
pub fn salt_tag(salt: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(SALT_TAG_TAG);
    h.update(salt);
    let d: [u8; 32] = h.finalize().into();
    [d[0], d[1], d[2], d[3]]
}

/// Is `prefix` a valid range name: lowercase hex, at most 64 characters.
#[must_use]
pub fn valid_prefix(prefix: &str) -> bool {
    prefix.len() <= MAX_PREFIX_LEN
        && prefix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn nibble(x: &[u8; 32], i: usize) -> u8 {
    let b = x[i / 2];
    if i.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0x0f
    }
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

/// Does the hash `x` lie in the range `prefix` (its lowercase hex starts with it)?
#[must_use]
pub fn in_prefix(x: &[u8; 32], prefix: &str) -> bool {
    prefix
        .bytes()
        .enumerate()
        .all(|(i, c)| nibble(x, i) == hex_val(c))
}

/// The inclusive low bound and exclusive high bound (`None` = to the end) of
/// a prefix's range in hash order. `prefix` must be [`valid_prefix`].
#[must_use]
pub fn prefix_bounds(prefix: &str) -> ([u8; 32], Option<[u8; 32]>) {
    let nibbles: Vec<u8> = prefix.bytes().map(hex_val).collect();
    let pack = |nib: &[u8]| -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, v) in nib.iter().enumerate() {
            if i.is_multiple_of(2) {
                out[i / 2] |= v << 4;
            } else {
                out[i / 2] |= v;
            }
        }
        out
    };
    let lo = pack(&nibbles);
    // hi = the prefix + 1 as a hex number of its own length; past "ff…f" the
    // range runs to the end.
    let mut inc = nibbles;
    let mut i = inc.len();
    loop {
        if i == 0 {
            return (lo, None);
        }
        i -= 1;
        if inc[i] == 0x0f {
            inc[i] = 0;
        } else {
            inc[i] += 1;
            return (lo, Some(pack(&inc)));
        }
    }
}

/// The range of `prefix` within a sorted set.
fn range_of<'a>(
    set: &'a BTreeSet<[u8; 32]>,
    prefix: &str,
) -> std::collections::btree_set::Range<'a, [u8; 32]> {
    use std::ops::Bound::{Excluded, Included, Unbounded};
    let (lo, hi) = prefix_bounds(prefix);
    match hi {
        Some(hi) => set.range((Included(lo), Excluded(hi))),
        None => set.range((Included(lo), Unbounded)),
    }
}

/// `a` is newer than `b` in wrapping `u32` sequence order.
#[must_use]
pub fn sid_newer(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1u32 << 31)
}

// ─── The wire ───────────────────────────────────────────────────────────

/// `rf` members a reader could not parse or could not read (an unknown `v`
/// or `a`, a malformed salt or prefix): design §2.5, `rf_parse_failed`.
pub static RF_PARSE_FAILED: AtomicU64 = AtomicU64::new(0);
/// Compact members a reader could not decode.
pub static RF_COMPACT_DECODE_FAILED: AtomicU64 = AtomicU64::new(0);

/// Lenient `rf` parsing: a shape this build does not understand reads as no
/// `rf`, counted, never as a failed message (design §2.5, finding 14).
pub(crate) fn lenient<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let v: Option<serde_json::Value> = Option::deserialize(d)?;
    Ok(v.and_then(|v| {
        serde_json::from_value::<T>(v)
            .inspect_err(|_| {
                RF_PARSE_FAILED.fetch_add(1, Ordering::Relaxed);
            })
            .ok()
    }))
}

/// One fingerprint node: `[prefix, count, fp_hex]`.
pub type WireNode = (String, u64, String);
/// One packed split record: `[parent, [16 counts], 16 × 32 hex]`.
pub type WireSplit = (String, Vec<u64>, String);

/// The `rf` member of a `Summary` (FSD §3.4.2), or a marker (`v`, `ep`, `e`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RfSummary {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ep: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub salt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub n: Vec<WireNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub c: Vec<WireSplit>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lc: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pk: Vec<String>,
    /// Set by the receiving registry, never on the wire: this Summary arrived
    /// over a transport that is not confidential, so its salt is exposed and
    /// is never used (design §6.4, N7).
    #[serde(skip)]
    pub transport_refused: bool,
}

impl RfSummary {
    /// A marker: "I answer RF", with this node's epoch and, when `compact`,
    /// "I decode the compact encoding".
    #[must_use]
    pub fn marker(ep: &str, compact: bool) -> Self {
        Self {
            v: RF_VERSION,
            ep: Some(ep.to_owned()),
            e: compact.then_some(1),
            ..Self::default()
        }
    }

    /// Does this member carry fingerprints (a salt), not just a marker?
    #[must_use]
    pub fn is_fingerprinted(&self) -> bool {
        self.salt.is_some()
    }
}

/// The `rf` member of a `Diff` (FSD §3.4.2): an answer, or a marker.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RfDiff {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ep: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub st: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub m: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub s: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub l: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub u: Option<String>,
}

impl RfDiff {
    /// A marker on a Diff.
    #[must_use]
    pub fn marker(ep: &str, compact: bool) -> Self {
        Self {
            v: RF_VERSION,
            ep: Some(ep.to_owned()),
            e: compact.then_some(1),
            ..Self::default()
        }
    }
}

/// The reasons a receiver answers `u` (design §2.5; FSD §3.4.2's five tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unable {
    /// The holdings index for the plane is not `Ready` (R8).
    Unbooted,
    /// A salt change refused (same `ep`, too soon), or a Summary under a salt
    /// this plane has already moved past.
    Salt,
    /// The Summary exceeds the node caps, or the mirror is at its cap.
    Cap,
    /// The rebuild bucket is exhausted.
    Busy,
    /// The salt arrived over a non-confidential transport.
    Transport,
}

impl Unable {
    /// The wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Unbooted => "unbooted",
            Self::Salt => "salt",
            Self::Cap => "cap",
            Self::Busy => "busy",
            Self::Transport => "transport",
        }
    }
}

/// base64url, no padding: the compact encoding's alphabet (design §12.3).
fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// Decode a compact hash list (`rh` / `wh` / `xh`): base64url of n × 32
/// bytes. A malformed member decodes to nothing, counted.
#[must_use]
pub fn decode_compact_hashes(s: &str) -> Vec<[u8; 32]> {
    match b64().decode(s.as_bytes()) {
        Ok(bytes) if bytes.len().is_multiple_of(32) => bytes
            .chunks_exact(32)
            .map(|c| {
                let mut h = [0u8; 32];
                h.copy_from_slice(c);
                h
            })
            .collect(),
        _ => {
            RF_COMPACT_DECODE_FAILED.fetch_add(1, Ordering::Relaxed);
            Vec::new()
        }
    }
}

/// Encode a hash list in the compact form (tests, and step B's sender).
#[must_use]
pub fn encode_compact_hashes(hashes: &[[u8; 32]]) -> String {
    let flat: Vec<u8> = hashes.iter().flatten().copied().collect();
    b64().encode(flat)
}

/// Decode one compact body (`eb`). A malformed body decodes to nothing,
/// counted.
#[must_use]
pub fn decode_compact_body(s: &str) -> Option<Vec<u8>> {
    let out = b64().decode(s.as_bytes()).ok();
    if out.is_none() {
        RF_COMPACT_DECODE_FAILED.fetch_add(1, Ordering::Relaxed);
    }
    out
}

/// Encode one body in the compact form (tests, and step B's sender).
#[must_use]
pub fn encode_compact_body(body: &[u8]) -> String {
    b64().encode(body)
}

/// Decode a 32-byte salt from its wire form.
#[must_use]
pub fn decode_salt(s: &str) -> Option<[u8; 32]> {
    let bytes = b64().decode(s.as_bytes()).ok()?;
    bytes.try_into().ok()
}

/// Encode a salt (tests, and step B's sender).
#[must_use]
pub fn encode_salt(salt: &[u8; 32]) -> String {
    b64().encode(salt)
}

/// This process's random 64-bit epoch, drawn once from the OS CSPRNG
/// (design §6.4). It is no secret: it rides in every marker.
#[must_use]
pub fn process_epoch() -> &'static str {
    static EP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    EP.get_or_init(|| {
        use rand::RngCore as _;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b64().encode(b)
    })
}

/// Range fingerprints (design §6.4, R6, re-review N7, final review B1): is a
/// frame that arrived over `transport` confidential end to end, so its salt
/// may be used?
///
/// - Reticulum (`reticulum-rs`, `leviculum`): yes. Every frame on every lane
///   is E1-sealed.
/// - HTTP: only when the operator declares the listener confidential with
///   [`HTTP_LISTENER_CONFIDENTIAL_ENV`]. The inbound `TransportId` is `http`
///   for plain and TLS listeners alike, so every HTTP inbound is refused
///   unless declared; telling a TLS listener from a plain one inbound is
///   CIRISEdge#1027.
/// - Everything else (packet radio, serial, I2P, anything new): no. The
///   default is the refusal.
#[must_use]
pub fn inbound_is_confidential(transport: crate::transport::TransportId) -> bool {
    use crate::transport::TransportId;
    transport == TransportId::RETICULUM_RS
        || transport == TransportId::LEVICULUM
        || (transport == TransportId::HTTP && http_listener_confidential())
}

/// Mark an inbound message by the confidentiality of the transport it came
/// over (R6): a salted RF Summary that arrived over a non-confidential one is
/// flagged so its salt is never used, and the receiver answers
/// `u:"transport"`. Everything else is left exactly as it arrived.
pub fn mark_inbound_transport(msg: &mut super::protocol::ReplicationMessage, confidential: bool) {
    if confidential {
        return;
    }
    if let super::protocol::ReplicationMessage::Summary(sm) = msg {
        if let Some(rf) = sm.rf.as_mut() {
            rf.transport_refused = rf.is_fingerprinted();
        }
    }
}

/// The operator flag declaring this node's HTTP listener confidential (it sits
/// behind a TLS front end the operator runs, or terminates TLS itself). `1`,
/// `on` or `true` declares it; anything else, or unset, does not. Read once.
pub const HTTP_LISTENER_CONFIDENTIAL_ENV: &str = "CIRIS_EDGE_HTTP_LISTENER_CONFIDENTIAL";

fn http_listener_confidential() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| std::env::var(HTTP_LISTENER_CONFIDENTIAL_ENV).is_ok_and(|v| flag_on(&v)))
}

/// `1`, `on` or `true`, any case, surrounding space ignored.
#[must_use]
pub(crate) fn flag_on(v: &str) -> bool {
    matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "on" | "true")
}

// ─── The receiver ───────────────────────────────────────────────────────

/// What the bridge hands the receiver for one inbound fingerprinted Summary.
pub struct RxInput<'a> {
    pub peer: &'a str,
    pub kind: EnvelopeKind,
    pub rf: &'a RfSummary,
    pub refs: &'a [EnvelopeRef],
    /// The receive diff before refusal suppression and hash-first learning
    /// (after the #1252 held-equivalent filter).
    pub raw_want: &'a HashSet<[u8; 32]>,
    /// The want this node actually sends.
    pub final_want: &'a HashSet<[u8; 32]>,
    /// Is this id held only as a #1252 equivalent of another ref? Such an id
    /// is settled provisionally, never as a holding.
    pub held_equivalent: &'a dyn Fn(&[u8; 32]) -> bool,
    /// Is a PROVISIONAL member still not wanted (its refusal still in backoff,
    /// its known hash still known, its equivalent still remembered)? Asked of
    /// every provisional member before any sum, so `T_B ⊆ settled_B` holds
    /// exactly at compare time.
    pub still_settled: &'a dyn Fn(&[u8; 32]) -> bool,
    /// Whether the plane's holdings index may answer (`Ready`). Otherwise the
    /// answer is `u:"unbooted"` (R8).
    pub ready: bool,
    /// This node's holdings on the plane, offered for the restart seed (R24)
    /// when [`RfReceiver::wants_seed`] said so; `None` otherwise.
    pub seed: Option<&'a [[u8; 32]]>,
    /// Whether a match-feed consumer exists on this node (the known-hash
    /// holder map is non-empty): only then are matched ids materialised.
    pub feed: bool,
    /// The effective page (a `list` answer is never given above it).
    pub page: u64,
    pub now: Instant,
}

/// What one answer did, for the counters.
#[allow(clippy::struct_excessive_bools)] // one flag per counter label, independent
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RxFlags {
    /// The `rf` member could not be read: the Diff carries a plain marker.
    pub not_understood: bool,
    /// The answer was `u`, and why.
    pub unable: Option<Unable>,
    /// `u:"cap"` because a mirror reached its cap (`rf_mirror_capped`).
    pub mirror_capped: bool,
    /// A new salt was accepted (`rf_salt_changes_received`).
    pub salt_changed: bool,
    /// A bucket rebuild ran over the mirror (`rf_peersums_built`, receiver).
    pub rebuilt: bool,
    /// Ids the restart seed put into the mirror.
    pub seeded: usize,
}

/// The receiver's answer, and the match feed's receiver-side events.
#[derive(Debug, Default)]
pub struct RxAnswer {
    pub diff: RfDiff,
    /// `(prefix, ids)` for each `match` this answer gave whose compared set
    /// changed since it was last booked: the compared snapshot `T_B ∩ p − H`
    /// (design §5.7, R3). Empty unless [`RxInput::feed`].
    pub matched: Vec<(String, Vec<[u8; 32]>)>,
    pub flags: RxFlags,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settle {
    /// Held: enters and stays.
    Held,
    /// Not wanted for a reason that ends: enters, re-checked before every sum.
    Provisional,
    /// Wanted: pending until admitted from this peer.
    Wanted,
    /// Not wanted and not held, on a removal plane (R13): never enters.
    Skip,
}

/// The removal planes, where the settled set is the holdings only (R13).
#[must_use]
pub fn is_removal_plane(kind: EnvelopeKind) -> bool {
    matches!(
        kind,
        EnvelopeKind::Revocation | EnvelopeKind::IdentityOccurrenceRevocation
    )
}

/// The planes whose rows are listed with no per-peer filter, so a receiver may
/// seed its mirror from its own holdings after a restart (design §3.2, R24).
#[must_use]
pub fn is_public_seed_plane(kind: EnvelopeKind) -> bool {
    matches!(
        kind,
        EnvelopeKind::Key | EnvelopeKind::Revocation | EnvelopeKind::IdentityOccurrenceRevocation
    )
}

/// The bucket sums of one mirror under one accepted salt.
#[derive(Debug)]
struct Sums {
    generation: u64,
    salt: [u8; 32],
    buckets: Box<[Acc; 256]>,
}

#[derive(Debug, Default)]
struct PlaneRx {
    /// `M_B(A)`: ids the peer listed that this node settled.
    ids: BTreeSet<[u8; 32]>,
    /// The members settled only provisionally.
    provisional: HashSet<[u8; 32]>,
    /// Listed and wanted, not yet admitted, with when they are forgotten.
    pending: HashMap<[u8; 32], Instant>,
    /// The salt generation this plane is answered under.
    generation: Option<u64>,
    /// Level-2 bucket sums over `ids` (only past [`RF_SUMS_MIN_IDS`]).
    sums: Option<Sums>,
    /// The `sid` of the last `lc` applied per prefix, and the floor below
    /// which no `lc` applies (the newest `sid` ever dropped from the map).
    lc_sids: HashMap<String, u32>,
    lc_floor: Option<u32>,
    /// The fingerprint last booked into the match feed per prefix.
    fed: HashMap<String, [u8; 16]>,
    /// The restart seed was considered under the current `ep`.
    seed_tried: bool,
}

impl PlaneRx {
    fn bucket(x: &[u8; 32]) -> usize {
        usize::from(x[0])
    }

    fn insert(&mut self, x: [u8; 32]) -> bool {
        if !self.ids.insert(x) {
            return false;
        }
        if let Some(s) = self.sums.as_mut() {
            s.buckets[Self::bucket(&x)].add(&elem(&s.salt, &x));
        }
        true
    }

    fn remove(&mut self, x: &[u8; 32]) -> bool {
        self.provisional.remove(x);
        if !self.ids.remove(x) {
            return false;
        }
        if let Some(s) = self.sums.as_mut() {
            s.buckets[Self::bucket(x)].sub(&elem(&s.salt, x));
        }
        true
    }

    /// Bring the bucket sums to `(generation, salt)`: built when the mirror is
    /// large enough to need them, dropped when it is not. Returns whether a
    /// full salted pass ran.
    fn ensure_sums(&mut self, generation: u64, salt: &[u8; 32]) -> bool {
        self.generation = Some(generation);
        if self.ids.len() < RF_SUMS_MIN_IDS {
            self.sums = None;
            return false;
        }
        if self
            .sums
            .as_ref()
            .is_some_and(|s| s.generation == generation)
        {
            return false;
        }
        let mut buckets: Box<[Acc; 256]> = Box::new([Acc::default(); 256]);
        for x in &self.ids {
            buckets[Self::bucket(x)].add(&elem(salt, x));
        }
        self.sums = Some(Sums {
            generation,
            salt: *salt,
            buckets,
        });
        true
    }

    /// The sum of `ids ∩ prefix` under `salt`, from the buckets when they
    /// cover the prefix, else hashed.
    fn base(&self, salt: &[u8; 32], prefix: &str) -> Acc {
        let mut acc = Acc::default();
        let sums = self.sums.as_ref().filter(|s| s.salt == *salt);
        match (prefix.len(), sums) {
            (0, Some(s)) => s.buckets.iter().for_each(|a| acc.merge(a)),
            (1, Some(s)) => {
                let first = usize::from(hex_val(prefix.as_bytes()[0])) << 4;
                s.buckets[first..first + 16]
                    .iter()
                    .for_each(|a| acc.merge(a));
            }
            (2, Some(s)) => {
                let (lo, _) = prefix_bounds(prefix);
                acc.merge(&s.buckets[usize::from(lo[0])]);
            }
            _ => {
                for x in range_of(&self.ids, prefix) {
                    acc.add(&elem(salt, x));
                }
            }
        }
        acc
    }

    /// The accumulator of `ids ∩ prefix`, minus the head rows and minus every
    /// parked range (FSD §3.4.2's `S`). `pk` is normalised: no entry lies
    /// inside another.
    fn acc(&self, salt: &[u8; 32], prefix: &str, head: &[[u8; 32]], pk: &[String]) -> Acc {
        // A node inside (or equal to) a parked range sums nothing.
        if pk.iter().any(|p| prefix.starts_with(p.as_str())) {
            return Acc::default();
        }
        let nested: Vec<&String> = pk
            .iter()
            .filter(|p| p.len() > prefix.len() && p.starts_with(prefix))
            .collect();
        let mut acc = self.base(salt, prefix);
        for x in head {
            if in_prefix(x, prefix) && !nested.iter().any(|p| in_prefix(x, p)) {
                acc.sub(&elem(salt, x));
            }
        }
        for p in nested {
            for x in range_of(&self.ids, p) {
                acc.sub(&elem(salt, x));
            }
        }
        acc
    }

    /// The compared ids of a node: `ids ∩ prefix − H − pk`.
    fn ids_in(&self, prefix: &str, head: &HashSet<[u8; 32]>, pk: &[String]) -> Vec<[u8; 32]> {
        range_of(&self.ids, prefix)
            .filter(|x| !head.contains(*x) && !pk.iter().any(|p| in_prefix(x, p)))
            .copied()
            .collect()
    }

    /// May an `lc` of `prefix` at `sid` replace its range?
    fn lc_applies(&self, prefix: &str, sid: u32) -> bool {
        self.lc_floor.is_none_or(|f| sid_newer(sid, f))
            && self
                .lc_sids
                .get(prefix)
                .is_none_or(|last| sid_newer(sid, *last))
    }

    fn lc_record(&mut self, prefix: &str, sid: u32) {
        if !self.lc_sids.contains_key(prefix) && self.lc_sids.len() >= RF_LC_MEMORY {
            // Drop the oldest; nothing older than it may apply from now on.
            let oldest = self
                .lc_sids
                .iter()
                .min_by(|a, b| {
                    if sid_newer(*a.1, *b.1) {
                        std::cmp::Ordering::Greater
                    } else if a.1 == b.1 {
                        std::cmp::Ordering::Equal
                    } else {
                        std::cmp::Ordering::Less
                    }
                })
                .map(|(p, s)| (p.clone(), *s));
            if let Some((p, s)) = oldest {
                self.lc_sids.remove(&p);
                if self.lc_floor.is_none_or(|f| sid_newer(s, f)) {
                    self.lc_floor = Some(s);
                }
            }
        }
        self.lc_sids.insert(prefix.to_owned(), sid);
    }

    /// A new `ep`: the sender restarted, and its `sid`s start afresh.
    fn new_epoch(&mut self) {
        self.lc_sids.clear();
        self.lc_floor = None;
        self.seed_tried = false;
    }
}

#[derive(Debug)]
struct PeerRx {
    /// The salt in use, and the one before it (a plane the sender has not yet
    /// moved to the new salt is still answered under the old), each with its
    /// generation.
    current: Option<([u8; 32], u64)>,
    previous: Option<([u8; 32], u64)>,
    ep: Option<String>,
    salt_at: Option<Instant>,
    tokens: f64,
    tokens_at: Option<Instant>,
    last_seen: Instant,
    planes: HashMap<EnvelopeKind, PlaneRx>,
}

impl PeerRx {
    fn new(now: Instant) -> Self {
        Self {
            current: None,
            previous: None,
            ep: None,
            salt_at: None,
            tokens: RF_REBUILD_TOKENS,
            tokens_at: None,
            last_seen: now,
            planes: HashMap::new(),
        }
    }

    fn refill(&mut self, now: Instant) {
        if let Some(at) = self.tokens_at {
            let gained =
                now.saturating_duration_since(at).as_secs_f64() / RF_REBUILD_REFILL.as_secs_f64();
            self.tokens = (self.tokens + gained).min(RF_REBUILD_TOKENS);
        }
        self.tokens_at = Some(now);
    }

    fn ids(&self) -> usize {
        self.planes.values().map(|p| p.ids.len()).sum()
    }

    fn pending(&self) -> usize {
        self.planes.values().map(|p| p.pending.len()).sum()
    }
}

/// The receiver half (design §3.2, §6.4). One per node, behind the bridge's
/// lock. Every answer runs inside one call, so a rebuild never waits on
/// another: at most one runs node-wide, within the design's two slots.
#[derive(Debug, Default)]
pub struct RfReceiver {
    peers: HashMap<String, PeerRx>,
    /// Ids held in every mirror together (the node-wide mirror cap).
    mirror_total: usize,
    /// Pending ids node-wide (their own budget).
    pending_total: usize,
    /// The salt generation counter.
    next_generation: u64,
}

/// One `(peer, plane)` mirror's size, for tests and gauges.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MirrorStats {
    pub ids: usize,
    pub provisional: usize,
    pub pending: usize,
}

impl RfReceiver {
    /// A receiver with nothing learned.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ids held in every mirror (`rf_mirror_ids`).
    #[must_use]
    pub fn mirror_total(&self) -> usize {
        self.mirror_total
    }

    /// Pending ids node-wide.
    #[must_use]
    pub fn pending_total(&self) -> usize {
        self.pending_total
    }

    /// Peers with receiver state.
    #[must_use]
    pub fn peers(&self) -> usize {
        self.peers.len()
    }

    /// One `(peer, plane)` mirror's size.
    #[must_use]
    pub fn mirror_stats(&self, peer: &str, kind: EnvelopeKind) -> MirrorStats {
        self.peers
            .get(peer)
            .and_then(|p| p.planes.get(&kind))
            .map_or_else(MirrorStats::default, |m| MirrorStats {
                ids: m.ids.len(),
                provisional: m.provisional.len(),
                pending: m.pending.len(),
            })
    }

    /// Does `(peer, plane)` hold `x` in its mirror?
    #[must_use]
    pub fn mirror_contains(&self, peer: &str, kind: EnvelopeKind, x: &[u8; 32]) -> bool {
        self.peers
            .get(peer)
            .and_then(|p| p.planes.get(&kind))
            .is_some_and(|m| m.ids.contains(x))
    }

    /// Should the bridge offer its holdings for the restart seed on this
    /// Summary (design §3.2, R24)? Only on a public plane, only into an empty
    /// mirror, and once per sender `ep`, so the holdings are read at most once
    /// per peer session, never every round.
    #[must_use]
    pub fn wants_seed(&self, peer: &str, kind: EnvelopeKind) -> bool {
        is_public_seed_plane(kind)
            && self
                .peers
                .get(peer)
                .and_then(|p| p.planes.get(&kind))
                .is_none_or(|m| m.ids.is_empty() && !m.seed_tried)
    }

    /// A row from `peer` on `kind` was admitted or found held: a pending id
    /// enters the mirror (R21). `refs` are the refs the body may have been
    /// listed under (its act ref and its plain ref). Returns whether one did.
    pub fn note_settled(&mut self, peer: &str, kind: EnvelopeKind, refs: &[[u8; 32]]) -> bool {
        let Some(plane) = self
            .peers
            .get_mut(peer)
            .and_then(|p| p.planes.get_mut(&kind))
        else {
            return false;
        };
        let mut entered = false;
        for x in refs {
            if plane.pending.remove(x).is_none() {
                continue;
            }
            self.pending_total = self.pending_total.saturating_sub(1);
            if plane.ids.len() < RF_MIRROR_CAP_PAIR
                && self.mirror_total < RF_MIRROR_CAP_NODE
                && plane.insert(*x)
            {
                self.mirror_total += 1;
                entered = true;
            }
        }
        entered
    }

    /// Forget a peer (evicted, or its key revoked or rotated).
    pub fn forget_peer(&mut self, peer: &str) {
        if let Some(p) = self.peers.remove(peer) {
            self.mirror_total = self.mirror_total.saturating_sub(p.ids());
            self.pending_total = self.pending_total.saturating_sub(p.pending());
        }
    }

    /// The peer's entry, making room by forgetting the least recently heard
    /// peer when the table is full.
    fn peer_entry(&mut self, peer: &str, now: Instant) -> &mut PeerRx {
        if !self.peers.contains_key(peer) && self.peers.len() >= RF_MAX_PEERS {
            let stalest = self
                .peers
                .iter()
                .min_by_key(|(_, p)| p.last_seen)
                .map(|(k, _)| k.clone());
            if let Some(k) = stalest {
                self.forget_peer(&k);
            }
        }
        let p = self
            .peers
            .entry(peer.to_owned())
            .or_insert_with(|| PeerRx::new(now));
        p.last_seen = now;
        p
    }

    /// Answer one fingerprinted Summary (design §2.3-§2.6, §3.2, §6.4).
    #[allow(clippy::too_many_lines)] // one answer: guards, salt, mirror, nodes
    pub fn answer(&mut self, input: &RxInput<'_>) -> RxAnswer {
        let rf = input.rf;
        let mut out = RxAnswer {
            diff: RfDiff {
                v: RF_VERSION,
                ep: Some(process_epoch().to_owned()),
                e: Some(1),
                ..RfDiff::default()
            },
            ..RxAnswer::default()
        };
        // ── A member this build cannot read is no `rf` (design §2.5): the
        //    Diff carries the plain marker, and the sender reads that as a
        //    downgrade, never as an answer.
        let salt = rf.salt.as_deref().and_then(decode_salt);
        let readable = rf.v == RF_VERSION
            && rf.a == Some(ALG_SALTED_SUM)
            && rf.sid.is_some()
            && salt.is_some()
            && rf.n.iter().all(|(p, _, _)| valid_prefix(p))
            && rf.c.iter().all(|(p, counts, fps)| {
                valid_prefix(p)
                    && p.len() < MAX_PREFIX_LEN
                    && counts.len() == 16
                    && fps.len() == 16 * 32
                    && fps
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            && rf.lc.iter().all(|p| valid_prefix(p))
            && rf.pk.iter().all(|p| valid_prefix(p));
        let (Some(salt), Some(sid), true) = (salt, rf.sid, readable) else {
            RF_PARSE_FAILED.fetch_add(1, Ordering::Relaxed);
            out.flags.not_understood = true;
            return out;
        };
        out.diff.sid = Some(sid);
        out.diff.st = Some(hex::encode(salt_tag(&salt)));
        let unable = |out: &mut RxAnswer, why: Unable| {
            out.diff.u = Some(why.token().to_owned());
            out.diff.m.clear();
            out.diff.s.clear();
            out.diff.l.clear();
            out.matched.clear();
            out.flags.unable = Some(why);
        };
        // ── The transport first: a salt we may not use is not looked at again.
        if rf.transport_refused {
            unable(&mut out, Unable::Transport);
            return out;
        }
        if rf.n.len() > RX_MAX_NODES
            || rf.lc.len() > RX_MAX_NODES
            || rf.pk.len() > RX_MAX_PARKED
            || rf.c.len() > RX_MAX_SPLITS
        {
            unable(&mut out, Unable::Cap);
            return out;
        }
        if !input.ready {
            unable(&mut out, Unable::Unbooted);
            return out;
        }
        // ── Salt acceptance (design §6.4, R16).
        let now = input.now;
        let next_generation = self.next_generation;
        let peer = self.peer_entry(input.peer, now);
        peer.refill(now);
        let new_ep = peer.ep.is_some() && rf.ep.is_some() && peer.ep != rf.ep;
        let generation = match (peer.current, peer.previous) {
            (Some((s, g)), _) if s == salt => g,
            (_, Some((s, g))) if s == salt => g,
            (current, _) => {
                let accept = current.is_none()
                    || new_ep
                    || peer
                        .salt_at
                        .is_some_and(|at| now.saturating_duration_since(at) >= RF_SALT_MIN_AGE);
                if !accept {
                    unable(&mut out, Unable::Salt);
                    return out;
                }
                if peer.tokens < 1.0 {
                    unable(&mut out, Unable::Busy);
                    return out;
                }
                peer.tokens -= 1.0;
                peer.previous = current;
                peer.current = Some((salt, next_generation));
                peer.salt_at = Some(now);
                out.flags.salt_changed = true;
                next_generation
            }
        };
        if out.flags.salt_changed {
            self.next_generation += 1;
        }
        let peer = self.peers.get_mut(input.peer).expect("entered above");
        if rf.ep.is_some() && peer.ep != rf.ep {
            // A restarted sender (or the first we hear of it): its `sid`s
            // start afresh, so no older ordering applies.
            peer.ep.clone_from(&rf.ep);
            peer.planes.values_mut().for_each(PlaneRx::new_epoch);
        }
        let plane = peer.planes.entry(input.kind).or_default();
        if plane.generation.is_some_and(|g| g > generation) {
            // This plane already moved past that salt: an old Summary.
            unable(&mut out, Unable::Salt);
            return out;
        }
        let mirror_total = &mut self.mirror_total;
        let pending_total = &mut self.pending_total;
        // ── Provisional members whose reason ended leave, before any sum;
        //    pending ids past their time are forgotten.
        let ended: Vec<[u8; 32]> = plane
            .provisional
            .iter()
            .filter(|x| !(input.still_settled)(x))
            .copied()
            .collect();
        for x in ended {
            if plane.remove(&x) {
                *mirror_total = mirror_total.saturating_sub(1);
            }
        }
        let before = plane.pending.len();
        plane.pending.retain(|_, until| now < *until);
        *pending_total = pending_total.saturating_sub(before - plane.pending.len());
        // ── The restart seed (R24): holdings only, into an empty mirror, under
        //    the half rule, once per `ep`.
        if let Some(holdings) = input.seed {
            if is_public_seed_plane(input.kind) && plane.ids.is_empty() && !plane.seed_tried {
                plane.seed_tried = true;
                let root_count = rf.n.iter().find(|(p, _, _)| p.is_empty()).map(|n| n.1);
                let half = u64::try_from(holdings.len() / 2).unwrap_or(u64::MAX);
                if root_count.is_some_and(|c| c >= half) {
                    let room =
                        RF_MIRROR_CAP_PAIR.min(RF_MIRROR_CAP_NODE.saturating_sub(*mirror_total));
                    for x in holdings.iter().take(room) {
                        if plane.insert(*x) {
                            *mirror_total += 1;
                            out.flags.seeded += 1;
                        }
                    }
                }
            }
        }
        // ── Mirror maintenance (R21; `lc` ordered by `sid`).
        let removal = is_removal_plane(input.kind);
        let settle = |x: &[u8; 32]| -> Settle {
            if !input.raw_want.contains(x) {
                if !(input.held_equivalent)(x) {
                    Settle::Held
                } else if removal {
                    Settle::Skip
                } else {
                    Settle::Provisional
                }
            } else if input.final_want.contains(x) {
                Settle::Wanted
            } else if removal {
                Settle::Skip
            } else {
                Settle::Provisional
            }
        };
        let applied_lc: Vec<&String> = rf.lc.iter().filter(|p| plane.lc_applies(p, sid)).collect();
        for p in &applied_lc {
            let keep: HashSet<[u8; 32]> = input
                .refs
                .iter()
                .map(|r| r.envelope_hash)
                .filter(|x| {
                    in_prefix(x, p) && matches!(settle(x), Settle::Held | Settle::Provisional)
                })
                .collect();
            let gone: Vec<[u8; 32]> = range_of(&plane.ids, p)
                .filter(|x| !keep.contains(*x))
                .copied()
                .collect();
            for x in gone {
                if plane.remove(&x) {
                    *mirror_total = mirror_total.saturating_sub(1);
                }
            }
            let before = plane.pending.len();
            plane.pending.retain(|x, _| !in_prefix(x, p));
            *pending_total = pending_total.saturating_sub(before - plane.pending.len());
            plane.lc_record(p, sid);
        }
        // Ranges named in an `lc` older than one already applied teach
        // nothing: their ids could be ones A has since stopped offering.
        let stale_lc: Vec<&String> = rf.lc.iter().filter(|p| !applied_lc.contains(p)).collect();
        let mut capped = false;
        for r in input.refs {
            let x = r.envelope_hash;
            if stale_lc.iter().any(|p| in_prefix(&x, p)) {
                continue;
            }
            match settle(&x) {
                Settle::Skip => {}
                Settle::Wanted => {
                    if plane.pending.len() < RF_PENDING_CAP_PAIR
                        && *pending_total < RF_PENDING_CAP_NODE
                        && !plane.ids.contains(&x)
                        && plane.pending.insert(x, now + RF_PENDING_TTL).is_none()
                    {
                        *pending_total += 1;
                    }
                }
                s @ (Settle::Held | Settle::Provisional) => {
                    if !plane.ids.contains(&x) {
                        if plane.ids.len() >= RF_MIRROR_CAP_PAIR
                            || *mirror_total >= RF_MIRROR_CAP_NODE
                        {
                            capped = true;
                            continue;
                        }
                        plane.insert(x);
                        *mirror_total += 1;
                    }
                    if s == Settle::Provisional {
                        plane.provisional.insert(x);
                    } else {
                        plane.provisional.remove(&x);
                    }
                }
            }
        }
        if capped {
            out.flags.mirror_capped = true;
            unable(&mut out, Unable::Cap);
            return out;
        }
        out.flags.rebuilt = plane.ensure_sums(generation, &salt);
        // ── The answers. H = this Summary's head rows (refs under no `lc`);
        //    only those in the mirror change a sum.
        let head_set: HashSet<[u8; 32]> = input
            .refs
            .iter()
            .map(|r| r.envelope_hash)
            .filter(|x| !rf.lc.iter().any(|p| in_prefix(x, p)))
            .collect();
        let head: Vec<[u8; 32]> = head_set
            .iter()
            .filter(|x| plane.ids.contains(*x))
            .copied()
            .collect();
        // `pk` normalised: duplicates and ranges inside another parked range
        // removed, so nothing is subtracted twice.
        let mut pk: Vec<String> = rf.pk.clone();
        pk.sort();
        pk.dedup();
        let pk: Vec<String> = pk
            .iter()
            .filter(|p| {
                !pk.iter()
                    .any(|q| q.len() < p.len() && p.starts_with(q.as_str()))
            })
            .cloned()
            .collect();
        let plane_name = input.kind.as_wire_str();
        let mut nodes: Vec<(String, u64, String)> = rf.n.clone();
        for (parent, counts, fps) in &rf.c {
            for (i, count) in counts.iter().enumerate() {
                let digit = char::from_digit(u32::try_from(i).unwrap_or(0), 16).unwrap_or('0');
                nodes.push((
                    format!("{parent}{digit}"),
                    *count,
                    fps[i * 32..i * 32 + 32].to_owned(),
                ));
            }
        }
        for (prefix, count_a, fp_a) in nodes {
            let acc = plane.acc(&salt, &prefix, &head, &pk);
            let fp_b = node_fp(plane_name, &prefix, &acc);
            if hex::encode(fp_b) == fp_a {
                if input.feed && plane.fed.get(&prefix) != Some(&fp_b) {
                    if plane.fed.len() >= RF_FED_MEMORY {
                        plane.fed.clear();
                    }
                    plane.fed.insert(prefix.clone(), fp_b);
                    out.matched
                        .push((prefix.clone(), plane.ids_in(&prefix, &head_set, &pk)));
                }
                out.diff.m.push(prefix);
            } else if count_a > input.page {
                out.diff.s.push(prefix);
            } else if count_a <= RF_LIST_ROWS || acc.count() <= count_a / 2 {
                out.diff.l.push(prefix);
            } else {
                out.diff.s.push(prefix);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests;
