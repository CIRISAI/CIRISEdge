//! v45.1.7 — a live call's per-leg telemetry rows
//! ([`crate::telemetry::call_legs`]).
//!
//! Accumulation rides state the call already keeps: the send side in each
//! leg's congestion entry (taken under the lock `note_leg_outcomes` already
//! holds), the receive side in the reorder loop's own maps, published here
//! once a second. Rows are built when the bundle is read.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::telemetry::call_legs::{CallLegRow, CallLegSource, Direction, MediaKind};
use crate::transport::realtime_av::{
    stream_label, StreamId, CODEC_AV1_SVC, CODEC_JPEG_XS, CODEC_MDC, CODEC_OPAQUE,
    CODEC_TEMPORAL_LAYERED,
};

use super::{call_id_hex, CallState, LegPath, Shared};

/// How often the reorder loop publishes what it accumulated.
pub(super) const RX_PUBLISH_EVERY: Duration = Duration::from_secs(1);
/// A stream (or an own stream on a leg) unheard this long has no row: it
/// ended, or its layer is no longer sent.
pub(super) const LEG_STALE_AFTER: Duration = Duration::from_secs(10);
/// A rate is re-measured at most this often, so a fast poller reads a
/// steady number.
const RATE_MIN_SPAN: Duration = Duration::from_secs(1);

/// One leg's congestion streaks and shed flag (ALM C5), and what this node
/// sent on it per own (stream, codec class): bytes, first and last send.
#[derive(Debug, Default)]
pub(super) struct LegCong {
    pub(super) congested: u32,
    pub(super) clean: u32,
    pub(super) shed: bool,
    pub(super) tx: HashMap<(StreamId, u8), TxBytes>,
}

/// One own (stream, class) on a leg: bytes sent, first and last send.
pub(super) type TxBytes = (u64, Instant, Instant);

/// What the reorder loop accumulates per heard (stream, codec class).
#[derive(Debug)]
pub(super) struct RxAcc {
    publisher: String,
    bytes: u64,
    since: Instant,
    last: Instant,
    jitter_ms: f64,
    last_transit_ms: Option<i64>,
}

impl RxAcc {
    pub(super) fn new(publisher: &str, at: Instant) -> Self {
        Self {
            publisher: publisher.to_owned(),
            bytes: 0,
            since: at,
            last: at,
            jitter_ms: 0.0,
            last_transit_ms: None,
        }
    }

    /// One copy arrived at `arrival_ms` (UNIX ms), signed at `source_ms`: the
    /// RFC 3550 §6.4.1 estimator, `J += (|D| − J) / 16`.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_wrap)]
    pub(super) fn on_arrival(&mut self, at: Instant, arrival_ms: u64, source_ms: u64) {
        self.last = self.last.max(at);
        let transit = arrival_ms as i64 - source_ms as i64;
        if let Some(prev) = self.last_transit_ms {
            let d = (transit - prev).unsigned_abs() as f64;
            self.jitter_ms += (d - self.jitter_ms) / 16.0;
        }
        self.last_transit_ms = Some(transit);
    }

    /// One chunk released in order (deduped): its bytes count.
    pub(super) fn on_released(&mut self, len: usize) {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
    }
}

/// One copy heard (before the reorder window): its arrival, for jitter.
pub(super) fn note_arrival(rx: &mut HashMap<(StreamId, u8), RxAcc>, h: &super::Heard) {
    let f = &h.frame;
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let waited = u64::try_from(h.at.elapsed().as_millis()).unwrap_or(0);
    rx.entry((f.stream, f.codec_id))
        .or_insert_with(|| RxAcc::new(&f.publisher, h.at))
        .on_arrival(h.at, wall.saturating_sub(waited), f.source_ts_ms);
}

/// The receive side as last published, per (stream, codec class).
#[derive(Debug, Clone)]
pub(super) struct RxLeg {
    publisher: String,
    bytes: u64,
    since: Instant,
    last: Instant,
    jitter_ms: f64,
    lost: u64,
    skipped: u64,
    depth: u64,
}

/// The reorder loop's per-second publish: `acc` with the window's and the
/// reassembly's per-stream counts. Streams unheard for [`LEG_STALE_AFTER`]
/// are dropped from `acc` too.
pub(super) fn publish_rx(
    shared: &Shared,
    acc: &mut HashMap<(StreamId, u8), RxAcc>,
    window: &mut super::ReorderWindow,
    frames: &super::frame::Reassemblers,
    now: Instant,
) {
    acc.retain(|_, a| now.saturating_duration_since(a.last) < LEG_STALE_AFTER);
    let stats: HashMap<StreamId, (BTreeMap<u8, u64>, usize)> = window
        .take_stream_stats()
        .into_iter()
        .map(|(s, k, d)| (s, (k, d)))
        .collect();
    let out: HashMap<(StreamId, u8), RxLeg> = acc
        .iter()
        .map(|(&(stream, class), a)| {
            let (skipped, depth) = stats
                .get(&stream)
                .map_or((0, 0), |(k, d)| (k.get(&class).copied().unwrap_or(0), *d));
            (
                (stream, class),
                RxLeg {
                    publisher: a.publisher.clone(),
                    bytes: a.bytes,
                    since: a.since,
                    last: a.last,
                    jitter_ms: a.jitter_ms,
                    lost: frames.lost_of(stream, class),
                    skipped,
                    depth: u64::try_from(depth).unwrap_or(u64::MAX),
                },
            )
        })
        .collect();
    *Shared::lock(&shared.rx_legs) = out;
}

/// The codec a row names: the binding's registered token for the class when
/// it named one, else the class's own name. Never a peer-chosen string.
pub(super) fn codec_token(
    map: Option<&crate::transport::av_chunk_auth::CodecMap>,
    class: u8,
) -> &'static str {
    if let Some(known) = map.and_then(|m| {
        m.entries()
            .iter()
            .find(|(c, _)| *c == class)
            .and_then(|(_, t)| t.known())
    }) {
        return known.as_str();
    }
    match class {
        CODEC_AV1_SVC => "av1_svc",
        CODEC_JPEG_XS => "jpeg_xs",
        CODEC_MDC => "mdc",
        CODEC_TEMPORAL_LAYERED => "temporal_layered",
        CODEC_OPAQUE => "opaque",
        _ => "unknown",
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RateMemo {
    at: Instant,
    bytes: u64,
    bps: f64,
}

/// What a row's rate memo is keyed by: member, stream, class, direction.
pub(super) type RateKey = (String, StreamId, u8, bool);

/// `bytes` so far since `since`, as bits per second over the span since the
/// last measure at least [`RATE_MIN_SPAN`] ago (the first measure: since
/// `since`).
#[allow(clippy::cast_precision_loss)]
fn rate(
    memo: &mut HashMap<RateKey, RateMemo>,
    key: RateKey,
    bytes: u64,
    since: Instant,
    now: Instant,
) -> f64 {
    let bps = |db: u64, dt: Duration| {
        let secs = dt.as_secs_f64().max(0.001);
        (db as f64) * 8.0 / secs
    };
    if let Some(m) = memo.get_mut(&key) {
        let dt = now.saturating_duration_since(m.at);
        if dt >= RATE_MIN_SPAN {
            m.bps = bps(bytes.saturating_sub(m.bytes), dt);
            m.at = now;
            m.bytes = bytes;
        }
        return m.bps;
    }
    let v = bps(bytes, now.saturating_duration_since(since));
    memo.insert(
        key,
        RateMemo {
            at: now,
            bytes,
            bps: v,
        },
    );
    v
}

impl Shared {
    /// The link a member's leg rides here: the one it dialled to this node
    /// (which carries its stream), else this node's own leg to it.
    fn link_to(&self, member: &str) -> Option<[u8; 16]> {
        Shared::lock(&self.in_links)
            .iter()
            .find(|(_, p)| p.as_str() == member)
            .map(|(l, _)| *l)
            .or_else(|| Shared::lock(&self.out_legs).get(member).map(|l| l.link_id))
    }

    fn rtt_of(&self, link: &[u8; 16]) -> f64 {
        self.transport
            .av_link_stats(link)
            .and_then(|st| st.srtt_ms)
            .unwrap_or(0.0)
    }

    fn kind_of(&self, stream: StreamId, class: u8, own_primary: StreamId, own: bool) -> MediaKind {
        let share = if own {
            stream != own_primary
        } else {
            Shared::lock(&self.share_streams).contains(&stream)
        };
        if share {
            MediaKind::Share
        } else if class == CODEC_OPAQUE {
            MediaKind::Audio
        } else {
            MediaKind::Video
        }
    }
}

impl CallLegSource for Shared {
    #[allow(clippy::too_many_lines)] // one row builder per direction, straight-line
    fn call_leg_rows(&self) -> Vec<CallLegRow> {
        if self.ended.load(Ordering::Relaxed)
            || matches!(*Shared::lock(&self.state), CallState::Ended(_))
        {
            return Vec::new();
        }
        let now = Instant::now();
        let call = call_id_hex(self.id);
        let own_primary = self.stream();
        let mut rows = Vec::new();
        let mut memo = Shared::lock(&self.leg_rates);
        let mut seen: Vec<RateKey> = Vec::new();

        // Send: this node's own streams, on each leg it dialled.
        let legs: Vec<(String, [u8; 16], bool)> = Shared::lock(&self.out_legs)
            .iter()
            .map(|(m, l)| (m.clone(), l.link_id, l.media.uses_datagrams()))
            .collect();
        for (member, link, datagrams) in legs {
            let Some((path, _)) = self.transport.av_link_path(&link) else {
                continue;
            };
            if path == LegPath::Gone {
                continue;
            }
            let tx: Vec<((StreamId, u8), TxBytes)> = {
                let mut cong = Shared::lock(&self.leg_cong);
                let Some(c) = cong.get_mut(&member) else {
                    continue;
                };
                c.tx.retain(|_, (_, _, last)| {
                    now.saturating_duration_since(*last) < LEG_STALE_AFTER
                });
                c.tx.iter().map(|(k, v)| (*k, *v)).collect()
            };
            let rtt_ms = self.rtt_of(&link);
            for ((stream, class), (bytes, since, _)) in tx {
                let key = (member.clone(), stream, class, true);
                let bitrate_bps = rate(&mut memo, key.clone(), bytes, since, now);
                seen.push(key);
                let codec_map = if stream == own_primary {
                    self.opts.codecs
                } else {
                    None
                };
                rows.push(CallLegRow {
                    room: self.room.clone(),
                    call: call.clone(),
                    member: member.clone(),
                    stream: stream_label(stream),
                    kind: self.kind_of(stream, class, own_primary, true),
                    direction: Direction::Send,
                    relayed: path == LegPath::Relayed,
                    relay_key_id: None,
                    transport: if datagrams { "datagram" } else { "channel" },
                    punched: path == LegPath::DirectUdp,
                    rtt_ms,
                    bitrate_bps,
                    frames_lost: None,
                    frames_skipped: None,
                    jitter_ms: None,
                    reorder_window: None,
                    codec: codec_token(codec_map.as_ref(), class),
                });
            }
        }

        // Receive: each member's streams as they reach this node.
        let rx: Vec<((StreamId, u8), RxLeg)> = Shared::lock(&self.rx_legs)
            .iter()
            .filter(|(_, l)| now.saturating_duration_since(l.last) < LEG_STALE_AFTER)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        let parents: HashMap<StreamId, Option<String>> = Shared::lock(&self.alm)
            .parents()
            .into_iter()
            .map(|p| (p.stream, p.primary))
            .collect();
        for ((stream, class), leg) in rx {
            if leg.publisher == self.own {
                continue;
            }
            let relay = parents
                .get(&stream)
                .cloned()
                .flatten()
                .filter(|p| *p != leg.publisher);
            let carrier = relay.as_deref().unwrap_or(&leg.publisher);
            let Some(link) = self.link_to(carrier) else {
                continue;
            };
            let Some((path, _)) = self.transport.av_link_path(&link) else {
                continue;
            };
            if path == LegPath::Gone {
                continue;
            }
            let datagrams = self
                .transport
                .av_link_datagram_stats(&link)
                .is_some_and(|d| d.received > 0);
            let key = (leg.publisher.clone(), stream, class, false);
            let bitrate_bps = rate(&mut memo, key.clone(), leg.bytes, leg.since, now);
            seen.push(key);
            rows.push(CallLegRow {
                room: self.room.clone(),
                call: call.clone(),
                member: leg.publisher.clone(),
                stream: stream_label(stream),
                kind: self.kind_of(stream, class, own_primary, false),
                direction: Direction::Recv,
                relayed: relay.is_some() || path == LegPath::Relayed,
                relay_key_id: relay,
                transport: if datagrams { "datagram" } else { "channel" },
                punched: path == LegPath::DirectUdp,
                rtt_ms: self.rtt_of(&link),
                bitrate_bps,
                frames_lost: Some(leg.lost),
                frames_skipped: Some(leg.skipped),
                jitter_ms: Some(leg.jitter_ms),
                reorder_window: Some(leg.depth),
                codec: codec_token(self.auth.codecs_of(stream).as_ref(), class),
            });
        }
        memo.retain(|k, _| seen.contains(k));
        drop(memo);
        // No lock nests the auth's: read the set, then drop what is unbound.
        let held: Vec<StreamId> = Shared::lock(&self.share_streams).iter().copied().collect();
        let dead: Vec<StreamId> = held
            .into_iter()
            .filter(|s| !self.auth.is_bound(*s))
            .collect();
        if !dead.is_empty() {
            Shared::lock(&self.share_streams).retain(|s| !dead.contains(s));
        }
        rows
    }
}
