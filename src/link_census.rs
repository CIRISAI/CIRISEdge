//! CIRISEdge#1025 items 1, 2 and 4, and item 3's top-N — **what a seat's links
//! and peers look like**, for sizing the canonical.
//!
//! - **`links_active{transport:direction}`**: the established Reticulum links
//!   right now, by the medium they ride (the [`WireTransport`] tokens the wire
//!   ledger uses) and by which end opened them. A link that moves onto a
//!   punched direct interface moves from its base medium to `udp-direct`, and
//!   back when it falls back. Set from the transport's one link-direction
//!   record on every establish, close and direct move; never computed on a
//!   scrape.
//! - **`distinct_peers_1h` / `distinct_peers_24h`**: how many distinct
//!   authenticated peers had a link to this node in the last hour and day, from
//!   a HyperLogLog per time bucket ([`HllWindow`]): 12 five-minute buckets for
//!   the hour, 24 hourly buckets for the day, merged by register max on read.
//!   The input is the peer's key id under a per-process secret hash; the key id
//!   itself is never kept, exported or logged.
//! - **`top_peers_by_bytes`**: the [`TOP_PEERS_EXPORTED`] heaviest peers by
//!   wire bytes since process start, from a Space-Saving sketch
//!   ([`TopPeers`], [`TOP_PEERS_TRACKED`] counters) fed from the E1 seal's
//!   byte attribution (`crate::transport::link_seal`). A bounded LIST in the
//!   bundle, keyed by the same salted hash, never a metric label
//!   (WORKLOAD_ATTRIBUTION A8). The salt is random per process and never
//!   leaves it, so an entry cannot be followed across a restart or matched
//!   between two nodes.
//! - **`link_duration_seconds{class:cause}`**: established → closed, by the
//!   close cause the direction counters already use
//!   ([`LinkCloseCause`]) and the `peer_activity` class the link came up
//!   under, `dialled` for a link this node opened, or `unidentified` for an
//!   inbound link no peer identified on.
//!
//! # Cost
//!
//! Per packet: one relaxed `fetch_add` on the link's own tally, taken under
//! the seal lock every frame already takes. Per link per node tick (1 s): the
//! tally is drained into the sketch under a short lock, and the peer is marked
//! seen in the HyperLogLogs once per five-minute bucket. Per link event: one
//! histogram observation and a fixed array copy.
//!
//! # Bounds
//!
//! | Family | Cardinality | Memory |
//! |---|---|---|
//! | `links_active` | 20 keys (10 transports × 2 directions) | 320 B per transport instance |
//! | `distinct_peers_*` | 2 gauges | 36 × 4096 B = 144 KiB of registers |
//! | `top_peers_by_bytes` | at most 10 entries | 64 counters × 32 B = 2 KiB |
//! | `link_duration_seconds` | at most 104 label sets (8 classes × 13 causes) × 8 buckets | 104 × 80 B ≈ 8 KiB |
//!
//! The HyperLogLog's standard error is `1.04 / sqrt(4096)` ≈ 1.6 % (a 3σ
//! bound of ±4.9 %); below ~10,000 peers its linear-counting branch is close
//! to exact. Space-Saving with 64 counters holds every peer whose bytes
//! exceed 1/64 of all peer-attributed bytes, each over-counted by at most
//! that (reported as `error_bytes`).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use parking_lot::RwLock;

use crate::observability::{HistogramSnapshot, LinkCloseCause, PEER_CLASSES};
use crate::telemetry::AtomicHistogram;
use crate::wire_bytes::WireTransport;

/// `link_duration_seconds` bucket bounds: 1 s, 5 s, 30 s, 2 min, 10 min,
/// 1 h, 6 h, then `+Inf`.
pub const LINK_DURATION_BUCKETS: &[f64] = &[1.0, 5.0, 30.0, 120.0, 600.0, 3_600.0, 21_600.0];

/// The `class` half of a `link_duration_seconds` key: the `peer_activity`
/// class an inbound link came up under; `dialled` for a link this node
/// dialled (`peer_activity` classes only links a peer identified to this
/// node); `unidentified` for an inbound link no peer was identified on.
pub const LINK_DURATION_CLASSES: [&str; 8] = [
    PEER_CLASSES[0],
    PEER_CLASSES[1],
    PEER_CLASSES[2],
    PEER_CLASSES[3],
    PEER_CLASSES[4],
    PEER_CLASSES[5],
    "dialled",
    "unidentified",
];
/// The `dialled` slot of [`LINK_DURATION_CLASSES`].
pub const LINK_CLASS_DIALLED: usize = 6;
/// The `unidentified` slot of [`LINK_DURATION_CLASSES`].
pub const LINK_CLASS_UNIDENTIFIED: usize = 7;

/// The transports a Reticulum link can ride: every [`WireTransport`] but
/// `http`, which has no links.
pub const LINK_TRANSPORTS: [WireTransport; 10] = [
    WireTransport::Tcp,
    WireTransport::Udp,
    WireTransport::UdpDirect,
    WireTransport::I2p,
    WireTransport::Lora,
    WireTransport::Serial,
    WireTransport::Ble,
    WireTransport::Auto,
    WireTransport::Local,
    WireTransport::Other,
];

/// Every `links_active` key, `transport:direction`, present from the first
/// snapshot.
pub const LINKS_ACTIVE_KEYS: [&str; 20] = [
    "tcp:inbound",
    "tcp:outbound",
    "udp:inbound",
    "udp:outbound",
    "udp-direct:inbound",
    "udp-direct:outbound",
    "i2p:inbound",
    "i2p:outbound",
    "lora:inbound",
    "lora:outbound",
    "serial:inbound",
    "serial:outbound",
    "ble:inbound",
    "ble:outbound",
    "auto:inbound",
    "auto:outbound",
    "local:inbound",
    "local:outbound",
    "other:inbound",
    "other:outbound",
];

/// Established links by `[transport][direction]` (`0` inbound, `1`
/// outbound), indexed by [`WireTransport`].
pub type LinksActive = [[u64; 2]; WireTransport::COUNT];

/// HyperLogLog precision: 2^12 registers.
pub const HLL_PRECISION: u32 = 12;
/// Registers per HyperLogLog.
pub const HLL_REGISTERS: usize = 1 << HLL_PRECISION;
/// The hour's buckets: 12 of five minutes.
pub const HOUR_BUCKETS: usize = 12;
/// One hour-window bucket, in seconds.
pub const HOUR_BUCKET_SECS: u64 = 300;
/// The day's buckets: 24 of an hour.
pub const DAY_BUCKETS: usize = 24;
/// One day-window bucket, in seconds.
pub const DAY_BUCKET_SECS: u64 = 3_600;

/// Space-Saving counters kept.
pub const TOP_PEERS_TRACKED: usize = 64;
/// Entries `top_peers_by_bytes` exports.
pub const TOP_PEERS_EXPORTED: usize = 10;

/// One HyperLogLog: [`HLL_REGISTERS`] six-bit ranks in bytes.
#[derive(Clone)]
pub struct Hll {
    regs: Box<[u8; HLL_REGISTERS]>,
}

impl std::fmt::Debug for Hll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hll")
            .field("estimate", &self.estimate())
            .finish_non_exhaustive()
    }
}

impl Default for Hll {
    fn default() -> Self {
        Self {
            regs: Box::new([0; HLL_REGISTERS]),
        }
    }
}

impl Hll {
    /// Add one 64-bit hash: the top [`HLL_PRECISION`] bits pick the register,
    /// the rest give the rank.
    pub fn insert(&mut self, hash: u64) {
        let idx = usize::try_from(hash >> (64 - HLL_PRECISION)).unwrap_or(0);
        let rest = hash << HLL_PRECISION;
        let rank = if rest == 0 {
            64 - HLL_PRECISION + 1
        } else {
            rest.leading_zeros() + 1
        };
        let rank = u8::try_from(rank).unwrap_or(u8::MAX);
        if self.regs[idx] < rank {
            self.regs[idx] = rank;
        }
    }

    /// Fold `other` into `self` (register max): the union's sketch.
    pub fn merge(&mut self, other: &Self) {
        for (a, b) in self.regs.iter_mut().zip(other.regs.iter()) {
            if *a < *b {
                *a = *b;
            }
        }
    }

    fn clear(&mut self) {
        self.regs.fill(0);
    }

    /// The cardinality estimate: the HyperLogLog raw estimate, with linear
    /// counting below 2.5 m (where it is far closer to exact). 64-bit hashes
    /// need no large-range correction.
    #[must_use]
    pub fn estimate(&self) -> u64 {
        #[allow(clippy::cast_precision_loss)]
        let m = HLL_REGISTERS as f64;
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for r in self.regs.iter() {
            sum += (-f64::from(*r)).exp2();
            if *r == 0 {
                zeros += 1;
            }
        }
        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let raw = alpha * m * m / sum;
        #[allow(clippy::cast_precision_loss)]
        let estimate = if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        };
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let n = estimate.round().max(0.0) as u64;
        n
    }
}

/// A rolling window of HyperLogLogs: `len` buckets of `span_secs` each, the
/// window read as the union of the current bucket and the `len - 1` before
/// it. A bucket is cleared when time comes back round to its slot.
#[derive(Debug, Clone)]
pub struct HllWindow {
    span_secs: u64,
    buckets: Vec<Hll>,
    /// The absolute bucket number each slot holds, plus one (`0`: empty).
    tags: Vec<u64>,
}

impl HllWindow {
    /// `len` buckets of `span_secs` seconds.
    #[must_use]
    pub fn new(len: usize, span_secs: u64) -> Self {
        Self {
            span_secs: span_secs.max(1),
            buckets: vec![Hll::default(); len.max(1)],
            tags: vec![0; len.max(1)],
        }
    }

    fn slot(&self, bucket: u64) -> usize {
        let len = self.buckets.len() as u64;
        usize::try_from(bucket % len).unwrap_or(0)
    }

    /// Count `hash` as seen at `now_secs` (seconds since the census began).
    pub fn insert(&mut self, now_secs: u64, hash: u64) {
        let bucket = now_secs / self.span_secs;
        let s = self.slot(bucket);
        if self.tags[s] != bucket + 1 {
            self.buckets[s].clear();
            self.tags[s] = bucket + 1;
        }
        self.buckets[s].insert(hash);
    }

    /// The distinct hashes seen in the window ending at `now_secs`.
    #[must_use]
    pub fn estimate(&self, now_secs: u64) -> u64 {
        let bucket = now_secs / self.span_secs;
        let len = self.buckets.len() as u64;
        let mut union = Hll::default();
        for (h, tag) in self.buckets.iter().zip(&self.tags) {
            if *tag == 0 {
                continue;
            }
            let b = tag - 1;
            if b <= bucket && bucket - b < len {
                union.merge(h);
            }
        }
        union.estimate()
    }
}

/// One Space-Saving counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Counter {
    hash: u64,
    bytes_in: u64,
    bytes_out: u64,
    /// The count the evicted counter had when this peer took its place: the
    /// most this entry can be over-counted by.
    error: u64,
}

impl Counter {
    fn total(&self) -> u64 {
        self.bytes_in
            .saturating_add(self.bytes_out)
            .saturating_add(self.error)
    }
}

/// A weighted Space-Saving sketch over salted peer hashes: at most `cap`
/// counters. A peer not held takes the smallest counter's place and inherits
/// its total as `error`.
#[derive(Debug, Clone)]
pub struct TopPeers {
    cap: usize,
    counters: Vec<Counter>,
}

impl TopPeers {
    /// A sketch of at most `cap` counters.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            counters: Vec::with_capacity(cap.max(1)),
        }
    }

    /// How many counters are held (never more than the cap).
    #[must_use]
    pub fn len(&self) -> usize {
        self.counters.len()
    }

    /// Whether nothing has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }

    /// Add `bytes_in` and `bytes_out` to `hash`'s counter.
    pub fn record(&mut self, hash: u64, bytes_in: u64, bytes_out: u64) {
        if bytes_in == 0 && bytes_out == 0 {
            return;
        }
        if let Some(c) = self.counters.iter_mut().find(|c| c.hash == hash) {
            c.bytes_in = c.bytes_in.saturating_add(bytes_in);
            c.bytes_out = c.bytes_out.saturating_add(bytes_out);
            return;
        }
        let fresh = Counter {
            hash,
            bytes_in,
            bytes_out,
            error: 0,
        };
        if self.counters.len() < self.cap {
            self.counters.push(fresh);
            return;
        }
        let Some((at, min)) = self
            .counters
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| c.total())
            .map(|(i, c)| (i, c.total()))
        else {
            return;
        };
        self.counters[at] = Counter {
            error: min,
            ..fresh
        };
    }

    /// The `n` heaviest counters, heaviest first.
    #[must_use]
    pub fn top(&self, n: usize) -> Vec<TopPeerBytes> {
        let mut all = self.counters.clone();
        all.sort_by(|a, b| b.total().cmp(&a.total()).then(a.hash.cmp(&b.hash)));
        all.into_iter()
            .take(n)
            .map(|c| TopPeerBytes {
                peer: format!("{:016x}", c.hash),
                bytes_in: c.bytes_in,
                bytes_out: c.bytes_out,
                error_bytes: c.error,
            })
            .collect()
    }
}

/// One `top_peers_by_bytes` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopPeerBytes {
    /// The peer's key id under this process's secret salt, 16 hex digits.
    /// Stable for one process; unrelated across restarts and between nodes.
    pub peer: String,
    /// Wire bytes received from the peer since its counter was taken.
    pub bytes_in: u64,
    /// Wire bytes sent to the peer since its counter was taken.
    pub bytes_out: u64,
    /// The most `bytes_in + bytes_out` under-reads the peer by; equally, the
    /// most the entry's rank over-states it. 0 for a peer held from its first
    /// byte.
    pub error_bytes: u64,
}

/// A link's running byte tally toward its authenticated peer, held by the
/// seal table and drained into [`LinkCensus`] on the node tick.
#[derive(Debug)]
pub struct PeerTally {
    hash: u64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    /// The hour-window bucket (plus one) the peer was last marked seen in.
    seen_bucket: AtomicU64,
}

impl PeerTally {
    /// A tally for the peer whose salted hash is `hash`.
    #[must_use]
    pub fn new(hash: u64) -> Self {
        Self {
            hash,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            seen_bucket: AtomicU64::new(0),
        }
    }

    /// The salted peer hash.
    #[must_use]
    pub fn hash(&self) -> u64 {
        self.hash
    }

    /// Count `bytes` received from the peer. One relaxed add.
    pub fn add_in(&self, bytes: u64) {
        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Count `bytes` sent to the peer. One relaxed add.
    pub fn add_out(&self, bytes: u64) {
        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// The two distinct-peer windows.
#[derive(Debug)]
struct Distinct {
    hour: HllWindow,
    day: HllWindow,
}

/// The census: one per [`EdgeMetrics`](crate::observability::EdgeMetrics)
/// bag, shared by every clone of it.
pub struct LinkCensus {
    epoch: Instant,
    /// The per-process secret: 32 bytes from the OS at start, never exported.
    salt: zeroize::Zeroizing<[u8; 32]>,
    links_active: RwLock<HashMap<u64, LinksActive>>,
    durations: Box<[AtomicHistogram]>,
    distinct: Mutex<Distinct>,
    top: Mutex<TopPeers>,
}

impl std::fmt::Debug for LinkCensus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkCensus")
            .field("links_active", &self.links_active())
            .finish_non_exhaustive()
    }
}

impl Default for LinkCensus {
    fn default() -> Self {
        use rand::RngCore as _;
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        Self::with_salt(salt)
    }
}

impl LinkCensus {
    /// A census under `salt`. Production draws it from the OS
    /// ([`Default`]); a fixed salt makes a test's hashes repeatable.
    #[must_use]
    pub fn with_salt(salt: [u8; 32]) -> Self {
        Self {
            epoch: Instant::now(),
            salt: zeroize::Zeroizing::new(salt),
            links_active: RwLock::new(HashMap::new()),
            durations: (0..LINK_DURATION_CLASSES.len() * LinkCloseCause::COUNT)
                .map(|_| AtomicHistogram::default())
                .collect(),
            distinct: Mutex::new(Distinct {
                hour: HllWindow::new(HOUR_BUCKETS, HOUR_BUCKET_SECS),
                day: HllWindow::new(DAY_BUCKETS, DAY_BUCKET_SECS),
            }),
            top: Mutex::new(TopPeers::new(TOP_PEERS_TRACKED)),
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl LinkCensus {
    fn now_secs(&self) -> u64 {
        self.epoch.elapsed().as_secs()
    }

    /// `key_id` under this process's secret salt: the first 8 bytes of
    /// SHA-256(salt ‖ key id). The only form a peer takes inside the census.
    /// Once per link, never per packet.
    #[must_use]
    pub fn peer_hash(&self, key_id: &str) -> u64 {
        use sha2::Digest as _;
        let mut d = sha2::Sha256::new();
        d.update(b"CIRIS-edge-link-census/v1");
        d.update(self.salt.as_slice());
        d.update(key_id.as_bytes());
        let out = d.finalize();
        let mut first = [0u8; 8];
        first.copy_from_slice(&out[..8]);
        u64::from_be_bytes(first)
    }

    /// One transport instance's established links, `[transport][direction]`.
    pub fn set_links_active(&self, source: u64, active: LinksActive) {
        self.links_active.write().insert(source, active);
    }

    /// `links_active`, every [`LINKS_ACTIVE_KEYS`] key present, summed over
    /// the transport instances that reported.
    #[must_use]
    pub fn links_active(&self) -> BTreeMap<String, u64> {
        let mut sum: LinksActive = [[0; 2]; WireTransport::COUNT];
        for per in self.links_active.read().values() {
            for (row, add) in sum.iter_mut().zip(per) {
                row[0] = row[0].saturating_add(add[0]);
                row[1] = row[1].saturating_add(add[1]);
            }
        }
        let mut out = BTreeMap::new();
        for t in LINK_TRANSPORTS {
            let row = sum[t as usize];
            out.insert(format!("{}:inbound", t.as_str()), row[0]);
            out.insert(format!("{}:outbound", t.as_str()), row[1]);
        }
        out
    }

    /// An established link closed under `cause` after `lifetime`, having come
    /// up under class slot `class` of [`LINK_DURATION_CLASSES`].
    pub fn observe_link_lifetime(&self, class: usize, cause: LinkCloseCause, lifetime: Duration) {
        let c = class.min(LINK_DURATION_CLASSES.len() - 1);
        let at = c * LinkCloseCause::COUNT + cause.index();
        if let Some(h) = self.durations.get(at) {
            h.observe(LINK_DURATION_BUCKETS, lifetime);
        }
    }

    /// `link_duration_seconds`, keyed `class:cause`; a label set nothing
    /// closed under is absent.
    #[must_use]
    pub fn link_duration_seconds(&self) -> HashMap<String, HistogramSnapshot> {
        let mut out = HashMap::new();
        for (c, class) in LINK_DURATION_CLASSES.iter().enumerate() {
            for cause in LinkCloseCause::ALL {
                let h = &self.durations[c * LinkCloseCause::COUNT + cause.index()];
                let snap = h.snapshot(LINK_DURATION_BUCKETS);
                if snap.count > 0 {
                    out.insert(format!("{class}:{}", cause.as_str()), snap);
                }
            }
        }
        out
    }

    /// Mark the peer hashed `hash` seen now.
    pub fn note_peer_seen(&self, hash: u64) {
        self.note_peer_seen_at(self.now_secs(), hash);
    }

    fn note_peer_seen_at(&self, now_secs: u64, hash: u64) {
        let mut d = lock(&self.distinct);
        d.hour.insert(now_secs, hash);
        d.day.insert(now_secs, hash);
    }

    /// Mark a tally's peer seen, at most once per hour-window bucket.
    pub fn note_tally_seen(&self, tally: &PeerTally) {
        let now = self.now_secs();
        let bucket = now / HOUR_BUCKET_SECS + 1;
        if tally.seen_bucket.swap(bucket, Ordering::Relaxed) != bucket {
            self.note_peer_seen_at(now, tally.hash);
        }
    }

    /// Move a tally's bytes into the top-N sketch and mark its peer seen.
    pub fn drain_tally(&self, tally: &PeerTally) {
        let bytes_in = tally.bytes_in.swap(0, Ordering::Relaxed);
        let bytes_out = tally.bytes_out.swap(0, Ordering::Relaxed);
        if bytes_in != 0 || bytes_out != 0 {
            lock(&self.top).record(tally.hash, bytes_in, bytes_out);
        }
        self.note_tally_seen(tally);
    }

    /// `distinct_peers_1h`.
    #[must_use]
    pub fn distinct_peers_1h(&self) -> u64 {
        lock(&self.distinct).hour.estimate(self.now_secs())
    }

    /// `distinct_peers_24h`.
    #[must_use]
    pub fn distinct_peers_24h(&self) -> u64 {
        lock(&self.distinct).day.estimate(self.now_secs())
    }

    /// `top_peers_by_bytes`: the [`TOP_PEERS_EXPORTED`] heaviest.
    #[must_use]
    pub fn top_peers_by_bytes(&self) -> Vec<TopPeerBytes> {
        lock(&self.top).top(TOP_PEERS_EXPORTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed, well-mixed 64-bit hash of `i` (splitmix64), so every count
    /// here is the same on every run.
    fn h(i: u64) -> u64 {
        let mut z = i.wrapping_add(0x9e37_79b9_7f4a_7c15);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn hashes(range: std::ops::Range<u64>) -> Vec<u64> {
        range.map(h).collect()
    }

    #[test]
    fn a_hyperloglog_is_near_exact_small_and_within_its_bound_large() {
        for n in [0u64, 1, 12, 70, 135, 1_000] {
            let mut s = Hll::default();
            for x in hashes(0..n) {
                s.insert(x);
                s.insert(x); // a repeat is not a new peer
            }
            let e = s.estimate();
            // Linear counting: sigma = sqrt(m (e^t - t - 1)), t = n/m; 3.5 %
            // is past 3 sigma for every n here.
            assert!(e.abs_diff(n) <= 1 + n * 35 / 1_000, "{n} read {e}");
        }
        // 3 sigma of 1.04 / sqrt(4096).
        for n in [20_000u64, 100_000] {
            let mut s = Hll::default();
            for x in hashes(0..n) {
                s.insert(x);
            }
            let e = s.estimate();
            #[allow(clippy::cast_precision_loss)]
            let rel = (e as f64 - n as f64).abs() / n as f64;
            assert!(rel <= 0.049, "{n} read {e} ({rel})");
        }
    }

    #[test]
    fn a_merge_is_the_union_not_the_sum() {
        let mut a = Hll::default();
        let mut b = Hll::default();
        for x in hashes(0..300) {
            a.insert(x);
        }
        for x in hashes(200..500) {
            b.insert(x);
        }
        a.merge(&b);
        assert!(a.estimate().abs_diff(500) <= 6, "{}", a.estimate());
    }

    #[test]
    fn the_hour_window_rolls_its_buckets_and_merges_what_is_inside() {
        let mut w = HllWindow::new(HOUR_BUCKETS, HOUR_BUCKET_SECS);
        // 40 peers in the first five minutes, 30 more (10 of them the same)
        // half an hour on.
        for x in hashes(0..40) {
            w.insert(10, x);
        }
        for x in hashes(30..60) {
            w.insert(1_800, x);
        }
        assert!(w.estimate(1_800).abs_diff(60) <= 2);
        // Just inside the hour of the first bucket: both still count.
        assert!(w.estimate(3_599).abs_diff(60) <= 2);
        // The first bucket is out of the window at 60 min: the 30 remain.
        assert!(w.estimate(3_600).abs_diff(30) <= 1);
        // A long idle: nothing remains, and a slot reused is cleared first.
        assert_eq!(w.estimate(3_600 * 5), 0);
        w.insert(3_600 * 5, h(9));
        assert_eq!(w.estimate(3_600 * 5), 1);
    }

    #[test]
    fn the_day_window_keeps_24_hours_of_peers() {
        let mut w = HllWindow::new(DAY_BUCKETS, DAY_BUCKET_SECS);
        for hour in 0..30u64 {
            for x in hashes(hour * 10..hour * 10 + 10) {
                w.insert(hour * 3_600 + 5, x);
            }
        }
        // At hour 29 the window is hours 6..=29: 24 hours of 10 peers.
        let e = w.estimate(29 * 3_600 + 10);
        assert!(e.abs_diff(240) <= 3, "{e}");
    }

    #[test]
    fn the_census_counts_a_peer_seen_on_many_links_once() {
        let c = LinkCensus::with_salt([7; 32]);
        let a = c.peer_hash("node-a");
        for _ in 0..5 {
            c.note_peer_seen(a);
        }
        c.note_peer_seen(c.peer_hash("node-b"));
        assert_eq!(c.distinct_peers_1h(), 2);
        assert_eq!(c.distinct_peers_24h(), 2);
    }

    #[test]
    fn space_saving_finds_the_heavy_hitters_and_stays_bounded() {
        let mut s = TopPeers::new(TOP_PEERS_TRACKED);
        let heavy: Vec<u64> = hashes(0..5);
        let light: Vec<u64> = hashes(1_000..11_000);
        // 10,000 light peers of 100 B each, interleaved with 5 heavy peers
        // of 1 MB (+i) each, so ~6 MB in all and each heavy one is 1/6.
        let mut heavy_i = 0usize;
        for (i, l) in light.iter().enumerate() {
            s.record(*l, 60, 40);
            if i % 2_000 == 0 {
                for (k, hh) in heavy.iter().enumerate() {
                    s.record(*hh, 100_000 + k as u64, 100_000);
                }
                heavy_i += 1;
            }
            assert!(s.len() <= TOP_PEERS_TRACKED);
        }
        assert_eq!(heavy_i, 5);
        let top = s.top(TOP_PEERS_EXPORTED);
        assert_eq!(top.len(), TOP_PEERS_EXPORTED);
        let first: Vec<String> = top.iter().take(5).map(|t| t.peer.clone()).collect();
        for hh in &heavy {
            assert!(
                first.contains(&format!("{hh:016x}")),
                "{hh:x} not in {first:?}"
            );
        }
        // A heavy peer's in/out are lower bounds; their sum plus the error is
        // at least what it sent.
        for t in top.iter().take(5) {
            assert!(t.bytes_in + t.bytes_out + t.error_bytes >= 5 * 200_000);
            assert!(t.bytes_out <= 5 * 100_000);
        }
        // The heaviest is first.
        assert_eq!(top[0].peer, format!("{:016x}", heavy[4]));
    }

    #[test]
    fn a_new_peer_inherits_the_smallest_count_as_its_error() {
        let mut s = TopPeers::new(2);
        s.record(1, 10, 0);
        s.record(2, 30, 0);
        s.record(3, 5, 0);
        let top = s.top(2);
        assert_eq!(top[0].peer, format!("{:016x}", 2));
        assert_eq!(top[1].peer, format!("{:016x}", 3));
        assert_eq!((top[1].bytes_in, top[1].error_bytes), (5, 10));
        s.record(9, 0, 0);
        assert_eq!(s.len(), 2, "nothing recorded for an empty tally");
    }

    #[test]
    fn the_salt_differs_between_censuses_so_entries_never_correlate() {
        let a = LinkCensus::default();
        let b = LinkCensus::default();
        assert_eq!(a.peer_hash("node-x"), a.peer_hash("node-x"));
        assert_ne!(a.peer_hash("node-x"), b.peer_hash("node-x"));
        let t = PeerTally::new(a.peer_hash("node-x"));
        t.add_out(7);
        a.drain_tally(&t);
        let top = a.top_peers_by_bytes();
        assert_eq!(top.len(), 1);
        assert!(!top[0].peer.contains("node-x"));
        assert_ne!(top[0].peer, format!("{:016x}", b.peer_hash("node-x")));
        assert_eq!(top[0].bytes_out, 7);
        // A drained tally starts again from zero.
        a.drain_tally(&t);
        assert_eq!(a.top_peers_by_bytes()[0].bytes_out, 7);
    }

    #[test]
    fn link_lifetimes_land_in_their_buckets_under_class_and_cause() {
        let c = LinkCensus::default();
        c.observe_link_lifetime(3, LinkCloseCause::PeerClosed, Duration::from_millis(400));
        c.observe_link_lifetime(3, LinkCloseCause::PeerClosed, Duration::from_secs(4));
        c.observe_link_lifetime(
            LINK_CLASS_UNIDENTIFIED,
            LinkCloseCause::Stale,
            Duration::from_hours(2),
        );
        c.observe_link_lifetime(5, LinkCloseCause::LocalTeardown, Duration::from_hours(24));
        let d = c.link_duration_seconds();
        assert_eq!(d.len(), 3, "{:?}", d.keys());
        let fc = &d["first_contact:peer_closed"];
        let b: Vec<(String, u64)> = fc.buckets();
        assert_eq!(b[0], ("1".to_string(), 1));
        assert_eq!(b[1], ("5".to_string(), 2));
        assert_eq!(fc.count, 2);
        let st = &d["unidentified:stale"];
        assert_eq!(st.buckets()[4].1, 0, "not within 10 min");
        assert_eq!(st.buckets()[5].1, 0, "not within 1 h");
        assert_eq!(st.buckets()[6].1, 1, "within 6 h");
        let lt = &d["unknown:local_teardown"];
        assert_eq!(lt.buckets()[6].1, 0, "past 6 h");
        assert_eq!(lt.buckets()[7], ("+Inf".to_string(), 1));
        assert_eq!(LINK_DURATION_BUCKETS.len() + 1, 8);
    }

    #[test]
    fn links_active_lists_every_key_and_sums_its_sources() {
        let c = LinkCensus::default();
        let mut a: LinksActive = [[0; 2]; WireTransport::COUNT];
        a[WireTransport::Tcp as usize] = [3, 1];
        let mut b: LinksActive = [[0; 2]; WireTransport::COUNT];
        b[WireTransport::Tcp as usize] = [1, 0];
        b[WireTransport::UdpDirect as usize] = [0, 2];
        c.set_links_active(1, a);
        c.set_links_active(2, b);
        let got = c.links_active();
        let keys: Vec<&str> = got.keys().map(String::as_str).collect();
        let mut want = LINKS_ACTIVE_KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(keys, want);
        assert_eq!(got["tcp:inbound"], 4);
        assert_eq!(got["tcp:outbound"], 1);
        assert_eq!(got["udp-direct:outbound"], 2);
        assert_eq!(got["udp:inbound"], 0);
    }
}
