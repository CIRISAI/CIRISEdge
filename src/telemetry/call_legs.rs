//! v45.1.7 — per-leg call telemetry: what one live call's legs are doing now,
//! for the call screen's "?" panel and an operator, served by the host as OTLP
//! (`ciris.edge.call.*`, [`CALL_LEG_INSTRUMENTS`]).
//!
//! # The privacy decision
//!
//! These series name a room, a call and the member at the other end of a leg.
//! That is the third exception to the bundle's "no peer in a label" rule
//! ([`LabelValues::CallLeg`](super::LabelValues::CallLeg)), and it is bounded
//! three ways:
//!
//! - **operator-only**, as every non-liveness field;
//! - **live only**: a row exists while its call is live and its leg is up.
//!   Nothing is remembered past the leg: the rows are read from the call's
//!   own state when the bundle is read, so a leg that ends, or a call that
//!   ends, has no series in the next snapshot;
//! - **capped** at [`CALL_LEG_ROWS_MAX`] rows per snapshot, the rest counted in
//!   `call_legs_overflow`.
//!
//! Key ids name members, as they do elsewhere in telemetry. No address, IP or
//! port is ever an attribute: the path is a token (`direct` or `relayed`), the
//! carrier is a token, and a relay is named by its key id.
//!
//! # The hot path
//!
//! Nothing here runs per chunk. A call accumulates in state it already locks
//! (the per-leg congestion entry on send, the reorder loop's own maps on
//! receive, published once a second), and [`CallLegSource::call_leg_rows`]
//! reads that state when the bundle is read.

use std::sync::{Mutex, PoisonError, Weak};

use super::Kind;

/// The most rows (one per member, stream and media kind) one snapshot
/// carries across every live call. A row is at most nine series.
pub const CALL_LEG_ROWS_MAX: usize = 64;

/// Every per-leg instrument: its OTLP name, kind, UCUM unit and what it says.
pub const CALL_LEG_INSTRUMENTS: &[(&str, Kind, &str, &str)] = &[
    (CALL_PATH, Kind::Gauge, "1", "1 per live leg; `path` direct or relayed, `relay.key_id` (empty unless a member relay carries it), `transport` (the carrier: datagram or channel), `punched`, `nat.local_type` and `nat.peer_type` (`unknown` on 45.1.x)."),
    (CALL_RTT, Kind::Gauge, "ms", "The leg link's smoothed RTT."),
    (CALL_BITRATE, Kind::Gauge, "bit/s", "Media bits per second on the leg, `direction` send or recv, counted at one layer both ways: each chunk's plaintext payload (never its wire form), since the last reading at least a second ago."),
    (CALL_FRAMES_LOST, Kind::Counter, "{frame}", "Frames of a framed stream never received (gaps in `frame_seq`)."),
    (CALL_FRAMES_SKIPPED, Kind::Counter, "{chunk}", "Chunks the reorder window gave up waiting for."),
    (CALL_JITTER, Kind::Gauge, "ms", "RFC 3550 interarrival jitter against the publisher's signed source timestamp."),
    (CALL_REORDER_WINDOW, Kind::Gauge, "{chunk}", "The most chunks the reorder window held for the stream in the last second."),
    (CALL_CODEC, Kind::Gauge, "1", "1, with `codec` the stream's registered codec for the media kind, or its class."),
];

/// `ciris.edge.call.path`.
pub const CALL_PATH: &str = "ciris.edge.call.path";
/// `ciris.edge.call.rtt`.
pub const CALL_RTT: &str = "ciris.edge.call.rtt";
/// `ciris.edge.call.bitrate`.
pub const CALL_BITRATE: &str = "ciris.edge.call.bitrate";
/// `ciris.edge.call.frames_lost`.
pub const CALL_FRAMES_LOST: &str = "ciris.edge.call.frames_lost";
/// `ciris.edge.call.frames_skipped`.
pub const CALL_FRAMES_SKIPPED: &str = "ciris.edge.call.frames_skipped";
/// `ciris.edge.call.jitter`.
pub const CALL_JITTER: &str = "ciris.edge.call.jitter";
/// `ciris.edge.call.reorder_window`.
pub const CALL_REORDER_WINDOW: &str = "ciris.edge.call.reorder_window";
/// `ciris.edge.call.codec`.
pub const CALL_CODEC: &str = "ciris.edge.call.codec";

/// The attributes every per-leg series carries.
pub const CALL_LEG_COMMON_ATTRIBUTES: &[&str] = &[
    "ciris.room.id",
    "ciris.call.id",
    "ciris.call.member",
    "ciris.call.stream_id",
    "ciris.media.kind",
];

/// What a stream's frames are, for `ciris.media.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MediaKind {
    /// The opaque (`0xFF`) class of a camera stream.
    Audio,
    /// Any other class of a camera stream.
    Video,
    /// A share stream (`Call::add_stream`), whatever its class.
    Share,
}

impl MediaKind {
    /// The attribute value.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Share => "share",
        }
    }
}

/// Which way a row's media moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// This node's own stream, to the member.
    Send,
    /// The member's stream, to this node.
    Recv,
}

impl Direction {
    /// The attribute value.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Recv => "recv",
        }
    }
}

/// One leg row: a member, one stream and one media kind, as a call reports it.
/// [`CallLegRow::series`] renders it.
#[derive(Debug, Clone, PartialEq)]
pub struct CallLegRow {
    /// The room (its community key id).
    pub room: String,
    /// The call (`call_id_hex`).
    pub call: String,
    /// The member at the other end.
    pub member: String,
    /// The stream (hex).
    pub stream: String,
    /// What it carries.
    pub kind: MediaKind,
    /// Which way.
    pub direction: Direction,
    /// Whether a forwarder carries it (a member relay or a transport hop).
    pub relayed: bool,
    /// The member relay that forwards it, when one does.
    pub relay_key_id: Option<String>,
    /// The carrier token: `datagram` or `channel`.
    pub transport: &'static str,
    /// Whether the link rides a punched direct path.
    pub punched: bool,
    /// The link's smoothed RTT (ms), 0 before one is measured.
    pub rtt_ms: f64,
    /// Bits per second.
    pub bitrate_bps: f64,
    /// Receive rows only: frames never received.
    pub frames_lost: Option<u64>,
    /// Receive rows only: chunks skipped.
    pub frames_skipped: Option<u64>,
    /// Receive rows only: jitter (ms).
    pub jitter_ms: Option<f64>,
    /// Receive rows only: the reorder window's depth (chunks).
    pub reorder_window: Option<u64>,
    /// The codec token.
    pub codec: &'static str,
}

/// One series, ready for an OTLP data point.
#[derive(Debug, Clone, PartialEq)]
pub struct CallLegSeries {
    /// Its OTLP name (one of [`CALL_LEG_INSTRUMENTS`]).
    pub name: &'static str,
    /// Gauge or counter.
    pub kind: Kind,
    /// Its UCUM unit.
    pub unit: &'static str,
    /// Its attributes: the common five first, then the instrument's own.
    pub attributes: Vec<(&'static str, String)>,
    /// The value now.
    pub value: f64,
}

/// NAT classification: leviculum 0.34 has none, so 45.1.x says so.
pub const NAT_UNKNOWN: &str = "unknown";

fn unit_of(name: &str) -> &'static str {
    CALL_LEG_INSTRUMENTS
        .iter()
        .find(|(n, ..)| *n == name)
        .map_or("1", |(_, _, u, _)| u)
}

fn kind_of(name: &str) -> Kind {
    CALL_LEG_INSTRUMENTS
        .iter()
        .find(|(n, ..)| *n == name)
        .map_or(Kind::Gauge, |(_, k, ..)| *k)
}

impl CallLegRow {
    /// The row's series, in [`CALL_LEG_INSTRUMENTS`] order; a send row has no
    /// receive-side series.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // counts far below 2^52
    pub fn series(&self) -> Vec<CallLegSeries> {
        let common: Vec<(&'static str, String)> = vec![
            ("ciris.room.id", self.room.clone()),
            ("ciris.call.id", self.call.clone()),
            ("ciris.call.member", self.member.clone()),
            ("ciris.call.stream_id", self.stream.clone()),
            ("ciris.media.kind", self.kind.token().to_owned()),
        ];
        let one = |name: &'static str, extra: Vec<(&'static str, String)>, value: f64| {
            let mut attributes = common.clone();
            attributes.extend(extra);
            CallLegSeries {
                name,
                kind: kind_of(name),
                unit: unit_of(name),
                attributes,
                value,
            }
        };
        let direction = || vec![("direction", self.direction.token().to_owned())];
        let mut out = vec![
            one(
                CALL_PATH,
                vec![
                    (
                        "path",
                        if self.relayed { "relayed" } else { "direct" }.to_owned(),
                    ),
                    (
                        "relay.key_id",
                        self.relay_key_id.clone().unwrap_or_default(),
                    ),
                    ("transport", self.transport.to_owned()),
                    ("punched", self.punched.to_string()),
                    ("nat.local_type", NAT_UNKNOWN.to_owned()),
                    ("nat.peer_type", NAT_UNKNOWN.to_owned()),
                    ("direction", self.direction.token().to_owned()),
                ],
                1.0,
            ),
            one(CALL_RTT, direction(), self.rtt_ms),
            one(CALL_BITRATE, direction(), self.bitrate_bps),
        ];
        if let Some(v) = self.frames_lost {
            out.push(one(CALL_FRAMES_LOST, Vec::new(), v as f64));
        }
        if let Some(v) = self.frames_skipped {
            out.push(one(CALL_FRAMES_SKIPPED, Vec::new(), v as f64));
        }
        if let Some(v) = self.jitter_ms {
            out.push(one(CALL_JITTER, Vec::new(), v));
        }
        if let Some(v) = self.reorder_window {
            out.push(one(CALL_REORDER_WINDOW, Vec::new(), v as f64));
        }
        out.push(one(
            CALL_CODEC,
            vec![
                ("codec", self.codec.to_owned()),
                ("direction", self.direction.token().to_owned()),
            ],
            1.0,
        ));
        out
    }
}

/// A live call that reports its legs.
pub trait CallLegSource: Send + Sync {
    /// The call's rows now; empty once it ended.
    fn call_leg_rows(&self) -> Vec<CallLegRow>;
}

/// The live calls of one telemetry bag.
#[derive(Default)]
pub struct CallLegRegistry {
    calls: Mutex<Vec<Weak<dyn CallLegSource>>>,
}

impl std::fmt::Debug for CallLegRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallLegRegistry").finish_non_exhaustive()
    }
}

impl CallLegRegistry {
    /// A call joined: it reports while it lives.
    pub fn register(&self, call: Weak<dyn CallLegSource>) {
        let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
        calls.retain(|w| w.strong_count() > 0);
        calls.push(call);
    }

    /// Every live call's rows, at most `max`, sorted, and how many were left
    /// out. The registry's lock is not held while a call is read.
    #[must_use]
    pub fn rows(&self, max: usize) -> (Vec<CallLegRow>, u64) {
        let live: Vec<_> = {
            let mut calls = self.calls.lock().unwrap_or_else(PoisonError::into_inner);
            calls.retain(|w| w.strong_count() > 0);
            calls.iter().filter_map(Weak::upgrade).collect()
        };
        let mut rows: Vec<CallLegRow> = live.iter().flat_map(|c| c.call_leg_rows()).collect();
        rows.sort_by(|a, b| {
            (&a.room, &a.member, &a.stream, a.kind).cmp(&(&b.room, &b.member, &b.stream, b.kind))
        });
        let over = rows.len().saturating_sub(max);
        rows.truncate(max);
        (rows, u64::try_from(over).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Fixed(Vec<CallLegRow>);
    impl CallLegSource for Fixed {
        fn call_leg_rows(&self) -> Vec<CallLegRow> {
            self.0.clone()
        }
    }

    fn row(member: usize, direction: Direction) -> CallLegRow {
        CallLegRow {
            room: "room-key".into(),
            call: "ab".repeat(16),
            member: format!("member-{member:03}"),
            stream: "cd".repeat(16),
            kind: MediaKind::Video,
            direction,
            relayed: false,
            relay_key_id: None,
            transport: "channel",
            punched: false,
            rtt_ms: 12.0,
            bitrate_bps: 1000.0,
            frames_lost: (direction == Direction::Recv).then_some(1),
            frames_skipped: (direction == Direction::Recv).then_some(2),
            jitter_ms: (direction == Direction::Recv).then_some(3.0),
            reorder_window: (direction == Direction::Recv).then_some(4),
            codec: "h264",
        }
    }

    /// Past the cap, rows are left out and counted, never grown.
    #[test]
    fn the_rows_are_capped_and_the_rest_counted() {
        let reg = CallLegRegistry::default();
        let a: Arc<dyn CallLegSource> =
            Arc::new(Fixed((0..50).map(|i| row(i, Direction::Recv)).collect()));
        let b: Arc<dyn CallLegSource> =
            Arc::new(Fixed((50..90).map(|i| row(i, Direction::Send)).collect()));
        reg.register(Arc::downgrade(&a));
        reg.register(Arc::downgrade(&b));
        let (rows, over) = reg.rows(CALL_LEG_ROWS_MAX);
        assert_eq!(rows.len(), CALL_LEG_ROWS_MAX);
        assert_eq!(over, 90 - CALL_LEG_ROWS_MAX as u64);
        drop(b);
        let (rows, over) = reg.rows(CALL_LEG_ROWS_MAX);
        assert_eq!(
            (rows.len(), over),
            (50, 0),
            "a dropped call reports nothing"
        );
        drop(a);
        assert_eq!(reg.rows(CALL_LEG_ROWS_MAX), (Vec::new(), 0));
        assert!(
            reg.calls.lock().unwrap().is_empty(),
            "dead calls are pruned"
        );
    }

    /// Every series carries the common five, a receive row has all eight
    /// instruments, a send row has no receive-side series.
    #[test]
    fn a_row_renders_every_instrument_with_the_common_attributes() {
        let recv = row(1, Direction::Recv).series();
        let names: Vec<&str> = recv.iter().map(|s| s.name).collect();
        let all: Vec<&str> = CALL_LEG_INSTRUMENTS.iter().map(|(n, ..)| *n).collect();
        assert_eq!(names, all);
        for s in &recv {
            for (i, key) in CALL_LEG_COMMON_ATTRIBUTES.iter().enumerate() {
                assert_eq!(s.attributes[i].0, *key, "{}", s.name);
            }
        }
        let send = row(1, Direction::Send).series();
        let names: Vec<&str> = send.iter().map(|s| s.name).collect();
        assert_eq!(names, [CALL_PATH, CALL_RTT, CALL_BITRATE, CALL_CODEC]);
    }

    /// Every instrument is a dotted `ciris.edge.call.*` name with its own
    /// catalogue row (field `call_legs`, label `CallLeg`, operator-only), of
    /// the same kind; and every `call_legs` row is an instrument.
    #[test]
    fn every_instrument_is_a_catalogue_row_and_back() {
        use super::super::{Exposure, LabelValues, TELEMETRY_CATALOGUE};
        for (name, kind, ..) in CALL_LEG_INSTRUMENTS {
            assert!(name.starts_with("ciris.edge.call."), "{name}");
            let row = TELEMETRY_CATALOGUE
                .iter()
                .find(|s| s.name == *name)
                .unwrap_or_else(|| panic!("{name} has no catalogue row"));
            assert_eq!(row.field, "call_legs", "{name}");
            assert_eq!(row.kind, *kind, "{name}");
            assert_eq!(row.exposure, Exposure::OperatorOnly, "{name}");
            assert_eq!(
                row.label,
                Some(("ciris.call.member", LabelValues::CallLeg)),
                "{name}"
            );
        }
        let rows = TELEMETRY_CATALOGUE
            .iter()
            .filter(|s| s.field == "call_legs")
            .count();
        assert_eq!(rows, CALL_LEG_INSTRUMENTS.len());
    }
}
