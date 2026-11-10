//! The host call API — CIRISEdge#805 items 5–6 (`FSD/AV_CALL_API.md`).
//!
//! **A call is a room's set of live streams.** [`Call::join`] (and its
//! host-facing twin `Edge::join_call`) starts THIS node's stream in a room's
//! call; the other members' streams arrive on [`Call::frames`]. There is no
//! call row and no ring for an in-room call: joining is membership (§7).
//!
//! # Keys (§3.2, §5)
//!
//! The call's MLS group IS the room's ([`CohortGroup`]). Each stream's epoch
//! DEK is `stream_epoch_dek(room, stream, epoch)`; the call's epoch is the
//! room's, and every Add and every Remove the room commits rolls every live
//! stream: a new DEK and `chunk_seq` back to 0 (#846). The publisher
//! underneath is item 2's [`KeptAvPublisher`] in its ROOM-keyed form, so
//! every epoch move passes through the keep layer.
//!
//! # Transport
//!
//! Every hop rides a SEALED link (CC 5.3.3.5 E1, [`crate::transport::link_seal`]):
//! the link layer runs the transit KEX as every link's first frame, and the
//! hop's outer seal uses that link's keys; the call holds no key of its own
//! for the hop. Each publisher DIALS every other member's call
//! address and sends its stream on the link it dialled (it is the KEX
//! initiator there); every member ACCEPTS the links others dial to it (the
//! responder, after the claim check) and reads their streams. The first frame
//! after the handshake on a publisher's link is a [`STREAM_HELLO_MAGIC`] frame
//! naming its stream, so a receiver attributes each stream to the member that
//! publishes it and tells a stream's own copy from a relayed one.
//!
//! # The ALM mesh (stage 2)
//!
//! A call runs the closed-loop ALM controller ([`crate::transport::realtime_av_alm::controller`]):
//! every member SUBSCRIBES to every other member's stream through a parent it
//! chose (C4: the publisher itself, or a member relay that forwards the
//! stream), and every forwarder ADMITS before it sends (C2). The control
//! frames (C3 `CALM`: caps, subscribe, unsubscribe, admit, refuse, shed,
//! offer) ride the A/V links themselves, capability-gated per peer: a peer
//! that never said `CAPS` is served as before (the full stream, and the
//! legacy first-hand relay). With [`CallOptions::relay`] this node OFFERS to
//! forward the streams it receives; it then sends a stream only to the
//! members it admitted for it, which replaces the old flood. When a member
//! cannot reach another directly (hard NAT, a failed punch, no direct path),
//! the publisher simply never offers there, and the roster members that hear
//! it are the candidates: roster relays before any canonical, organically.
//!
//! Media rides timed Channel frames to peers whose leviculum takes them
//! (leviculum#94: never retransmitted or delivered stale); the inbound queue
//! drops media older than [`MEDIA_STALE_BUDGET`] by age, and a leg that stays
//! congested is shed to the base layer until it runs clean (C5).
//!
//! # Source authentication
//!
//! Every member can derive every stream's DEK, so the inner seal alone cannot
//! say WHO sealed a chunk. Each chunk therefore carries its publisher's
//! signature under a per-epoch chunk key, and the key is bound to the stream
//! by the publisher's hybrid federation signature
//! ([`crate::transport::av_chunk_auth`]). A receiver, and a relay before it
//! forwards, drops any chunk that does not verify under its stream's bound
//! key; a relay forwards only chunks whose verified publisher is the peer it
//! heard them from. The publisher sends its binding on every leg after the
//! stream hello, at every roll and every
//! [`crate::transport::av_chunk_auth::BINDING_REANNOUNCE`]; a relay forwards
//! the bindings it verifies.
//!
//! # Frames (§4)
//!
//! [`Call::frames`] dedupes the two legs on `(stream, epoch, chunk_seq)` and
//! releases each stream in `(epoch, chunk_seq)` order through a bounded
//! reorder window ([`ReorderWindow`]) sized against the measured gap between
//! a chunk's first and second copies, clamped to
//! [`REORDER_WINDOW_MIN`]..=[`REORDER_WINDOW_MAX`]. The window never waits
//! out loss: a chunk still missing at its deadline is skipped and counted.
//!
//! # Not in this release (say so, don't half-build)
//!
//! - `ring` / ad-hoc ephemeral communities (item 6's ring path, §7);
//! - item 3, the author ADOPTING its ciphertext for storage and reconnect;
//! - kept streams (A5), `StreamEpochRotationRequired` handling (A6) and
//!   `RecordingRootMismatch`: they wait on CIRISPersist#1067/#1068/#1069.
//!   [`CallOptions::keep`] = `Kept` is refused at once as
//!   [`CallEvent::KeepRefused`] (`keep_deferred_cirispersist_1067`) and the
//!   call goes on live and unkept (A12's shape);
//! - in-band live STHs (A9's live half): they need a wire frame type beside
//!   the chunks that a receiver can tell apart from a chunk mid-stream, which
//!   this cut does not define;
//! - the epoch's terminator (`seal_av_terminator`, #846 part 2): it does not
//!   exist on this base. A leaver's signed end rides the v2 stream key
//!   binding instead (`end`, v45; [`Call::leave_with`]).

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc, Mutex};

use crate::cohort_scope::CohortScope;
use crate::mls::CohortGroup;
use crate::scope_lifecycle::{ScopeGroupSnapshot, ScopeLifecycle};
use crate::transport::av_call_key::{stream_epoch_dek, CallId};
use crate::transport::av_chunk_auth::{
    collides_with_binding_part, AvAuthRefusal, BindingAssembler, BindingOutcome, ChunkAuth,
    ChunkSigner, Part, StreamKeyBinding, StreamKeyVerifier, BINDING_REANNOUNCE, CHUNK_TRAILER_LEN,
};
use crate::transport::av_keep::{
    AvKeep, AvKeepTarget, KeepOutcome, KeptAvPublisher, StreamDekRegistrar,
};
use crate::transport::av_sink::AvArrival;
use crate::transport::realtime_av::{
    open_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, ReceiverLayerPolicy, SealedAvChunk,
    StreamId, AV_CHUNK_WIRE_OVERHEAD,
};
use crate::transport::realtime_av_alm::controller::wire::{
    collides_with_control_frame, decode as decode_c3, is_control_frame, is_periodic, WireFrame,
};
use crate::transport::realtime_av_dispatcher::{
    open_hop_outer, AvDispatcherError, AvLinkReceiver as _, AvLinkSender as _, AvSubscriberLink,
    HopGap, LegSend, LinkIdGuard,
};
use crate::transport::reticulum::ReticulumTransport;

#[path = "av_call/alm.rs"]
mod alm;
#[path = "av_call/frame.rs"]
pub mod frame;
pub use alm::{AlmCounts, AlmParents};

/// ALM C5 — media older than this in the inbound queue is dropped by age
/// (oldest first) before it is opened: twice [`REORDER_WINDOW_MAX`], past
/// which the reorder window would skip it anyway.
pub const MEDIA_STALE_BUDGET: Duration = Duration::from_millis(800);
/// ALM C5 — consecutive congested sends before a leg is shed to the base
/// layer.
const LEG_SHED_AFTER: u32 = 3;
/// ALM C5 — consecutive clean sends before a shed leg is restored.
const LEG_RESTORE_AFTER: u32 = 50;
/// ALM C3 — how long a must-arrive frame is retried against a congested link.
const C3_RESEND_BUDGET: Duration = Duration::from_secs(2);
/// ALM C3 — the pause between those retries.
const C3_RESEND_PAUSE: Duration = Duration::from_millis(25);

/// The tag of the frame a publisher sends first on its own link, after the
/// transit KEX: `"CHLO" ‖ version ‖ stream_id[32]`.
pub const STREAM_HELLO_MAGIC: [u8; 4] = *b"CHLO";
const STREAM_HELLO_VERSION: u8 = 1;
const STREAM_HELLO_LEN: usize = 4 + 1 + 32;

/// The reorder window's floor.
pub const REORDER_WINDOW_MIN: Duration = Duration::from_millis(40);
/// The reorder window's ceiling.
pub const REORDER_WINDOW_MAX: Duration = Duration::from_millis(400);
/// The relay-versus-direct gap the window assumes before it has measured one.
const REORDER_GAP_PRIOR: Duration = Duration::from_millis(50);

/// How often a live call checks its room's epoch and its legs.
const WATCH_TICK: Duration = Duration::from_millis(250);
/// A failed dial to a member is retried after this, doubling to
/// [`DIAL_BACKOFF_MAX`].
const DIAL_BACKOFF_MIN: Duration = Duration::from_secs(1);
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(8);
/// How long a publisher's link may take to name its stream.
const HELLO_BUDGET: Duration = Duration::from_secs(10);

// ─── public types ───────────────────────────────────────────────────

/// How this node takes part in a call (§4).
#[derive(Debug, Clone, Copy)]
pub struct CallOptions {
    /// Item 2's keep for THIS node's stream (C1). `Kept` is refused today
    /// (CIRISPersist#1067) as [`CallEvent::KeepRefused`]; the call goes on
    /// live and unkept.
    pub keep: AvKeep,
    /// This node forwards the streams it hears first-hand to the other
    /// members.
    pub relay: bool,
    /// The layer cap every member's leg starts at.
    pub default_policy: ReceiverLayerPolicy,
    /// The codecs this node's stream carries, one per layer class, for its v2
    /// stream key binding (CC 5.3.3.2.1: the binding names them, fixed for
    /// the stream's life; `{0x04: h264, 0xFF: opus}` for a phone's audio and
    /// video). A chunk of a class the map does not name is refused by every
    /// receiver. `None`: v1 bindings only, which name no codec.
    pub codecs: Option<crate::transport::av_chunk_auth::CodecMap>,
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            keep: AvKeep::Unkept,
            relay: false,
            default_policy: ReceiverLayerPolicy::UNCAPPED,
            codecs: None,
        }
    }
}

/// One frame to publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// The codec discriminator (`realtime_av::CODEC_*`).
    pub codec_id: u8,
    /// The SVC layer.
    pub layer: ChunkLayer,
    /// The frame's plaintext.
    pub bytes: Vec<u8>,
}

impl Frame {
    /// A codec-opaque base-layer frame.
    #[must_use]
    pub fn opaque(bytes: Vec<u8>) -> Self {
        Self {
            codec_id: crate::transport::realtime_av::CODEC_OPAQUE,
            layer: ChunkLayer::BASE,
            bytes,
        }
    }
}

/// One frame another member published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedFrame {
    /// The member whose stream it is (the stream's own link names it); for a
    /// stream heard only through a relay before its own link named it, the
    /// relay it came through.
    pub publisher: String,
    /// The stream.
    pub stream: StreamId,
    /// The room epoch it was sealed in.
    pub epoch: Epoch,
    /// Its epoch-local sequence number.
    pub chunk_seq: ChunkSeq,
    /// Its codec.
    pub codec_id: u8,
    /// Its layer.
    pub layer: ChunkLayer,
    /// The plaintext (a framed stream's video: the whole reassembled frame,
    /// the fragment markers removed).
    pub bytes: Vec<u8>,
    /// v45 (Eric 2026-11-10) — on a framed stream, the frame's per-class
    /// counter from its marker (`frame_seq`, from 0 per (stream, codec
    /// class)): a gap is a lost frame of that class. `None` for audio and
    /// for an unframed stream.
    pub frame_seq: Option<u32>,
    /// v45 — the publisher's source timestamp (UNIX ms) its chunk trailer
    /// signs, verified with it: the lip-sync clock. A reassembled frame
    /// carries its first fragment's, as it carries its first fragment's
    /// `chunk_seq`.
    pub source_ts_ms: u64,
}

/// What one publish did on one member's leg.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegOutcome {
    /// The link's Channel took the frame.
    Delivered,
    /// Backpressure: dropped for this leg, never queued (#591).
    Congested,
    /// Larger than this leg's Channel (#720).
    TooLarge,
    /// The member's layer policy is below the frame's layer.
    FilteredByPolicy,
    /// The leg's link was gone; it is re-dialled.
    Gone,
    /// Any other send failure.
    Failed(String),
}

/// What [`Call::publish`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReport {
    /// The epoch the frame was sealed in.
    pub epoch: Epoch,
    /// Its sequence number.
    pub chunk_seq: ChunkSeq,
    /// One outcome per member leg (for a fragmented frame, the leg's first
    /// failure, or `Delivered` when every fragment went).
    pub legs: Vec<(String, LegOutcome)>,
    /// v45 — how many chunks the frame took (1 unless a framed stream
    /// split it; `chunk_seq` is the first).
    pub fragments: u16,
}

impl PublishReport {
    /// Legs that delivered.
    #[must_use]
    pub fn delivered(&self) -> usize {
        self.legs
            .iter()
            .filter(|(_, o)| *o == LegOutcome::Delivered)
            .count()
    }

    /// Legs that were congested.
    #[must_use]
    pub fn congested(&self) -> usize {
        self.legs
            .iter()
            .filter(|(_, o)| *o == LegOutcome::Congested)
            .count()
    }
}

/// Why a call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndCause {
    /// This node left ([`Call::leave`]).
    HungUp,
    /// This node is no longer a member of the room.
    Revoked,
    /// An ad-hoc call's community expired (not in this release).
    Expired,
}

/// Where a call stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallState {
    /// Publishing and receiving.
    Live,
    /// The room's epoch moved and the call's addresses did not: live links
    /// carry on, new dials cannot reach this node at the new epoch.
    Degraded {
        /// The epoch the addresses failed at.
        epoch: u64,
        /// Why.
        reason: String,
    },
    /// Ended.
    Ended(EndCause),
}

/// A typed call event (§5, §8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallEvent {
    /// The keep layer refused keeping this node's stream; the call stays live
    /// and unkept from `epoch`.
    KeepRefused {
        /// The epoch keeping stopped at.
        epoch: u64,
        /// The refusal's kind token.
        reason: &'static str,
    },
    /// The room's epoch moved: every live stream rolled.
    EpochRolled {
        /// The epoch before.
        from: u64,
        /// The epoch now.
        to: u64,
    },
    /// A member joined the room (and so the call's reach).
    MemberJoined {
        /// Its key id.
        key_id: String,
    },
    /// A member left the room.
    MemberLeft {
        /// Its key id.
        key_id: String,
    },
    /// The call's addresses could not follow the room's epoch.
    Stranded {
        /// The epoch.
        epoch: u64,
        /// Why.
        reason: String,
    },
    /// A key attended the call (its row arrived).
    AttendeeJoined {
        /// Its key id.
        key_id: String,
    },
    /// This attendee's call row was refused. Fired once; the call stays live
    /// and edge never fakes a row.
    RecordRefused {
        /// The refusal.
        reason: String,
    },
    /// `FSD/CIRIS_MESH.md` §6.5 — this node hears `publisher` only on the
    /// canonical tier, audio only (the canonical never relays video).
    VideoUnavailable {
        /// Whose video is paused here.
        publisher: String,
        /// `relay_canonical_audio_only`.
        reason: &'static str,
    },
    /// A member path serves `publisher`'s full stream again.
    VideoRestored {
        /// Whose video resumed.
        publisher: String,
    },
    /// `FSD/CIRIS_MESH.md` §7 — this node's service tier changed: at 1 it
    /// stops carrying others' video and takes no new relay work; at 2 it
    /// sheds relayed audio and this node's own call is audio only.
    LoadTier {
        /// `0`, `1` or `2`.
        tier: u8,
    },
    /// v45 — an attendee's stream left the call: once per (attendee,
    /// stream). `Left` and `Backgrounded` come only from the attendee's own
    /// signed end of its stream; `Removed` from the room's MLS group dropping
    /// its key; `Lost` from every leg to it gone and its stream silent past
    /// [`ATTENDEE_LOST_AFTER`] with no signed end seen. A replacement
    /// ([`CallEvent::StreamReplaced`]) is not a leave.
    AttendeeLeft {
        /// The attendee.
        key_id: String,
        /// Its stream that ended.
        stream: StreamId,
        /// Why.
        cause: LeaveCause,
        /// Its signed end named a `final_seq` this node never received up
        /// to: the tail was dropped on the way (counted
        /// `av_call_stream_truncated`).
        truncated: bool,
    },
    /// v45 — `publisher`'s stream's first verified binding installed: its
    /// keys are in hand and its `kind` (CC reading, rc18: 0 media, 1 share;
    /// an unknown value renders as media) says how to lay it out. Not
    /// presence: an attendee is one whose chunks arrive. A replacement's new
    /// stream is [`CallEvent::StreamReplaced`] instead.
    StreamAdded {
        /// The publisher.
        publisher: String,
        /// The stream.
        stream: StreamId,
        /// Its signed kind (`0` for a v1 binding).
        kind: u8,
    },
    /// v45 — one of `publisher`'s streams ended, signed, while it attends
    /// with another, or with `end = 3` ("this stream ended", a share stopped
    /// with `Call::end_stream`) on any of its streams: the stream's tile
    /// goes, the attendee stays. A leave (`end` 1 or 2) on its last stream
    /// is [`CallEvent::AttendeeLeft`] instead.
    StreamEnded {
        /// The publisher.
        publisher: String,
        /// Its stream that ended.
        stream: StreamId,
        /// Why, as its signed end says.
        cause: LeaveCause,
        /// As [`CallEvent::AttendeeLeft`]'s.
        truncated: bool,
    },
    /// v45 — `publisher` replaced its stream in place (`Call::replace_stream`
    /// there): `new` carries on what `old` was, with no leave. Only from the
    /// publisher's signed `replaces` on `new`'s binding.
    StreamReplaced {
        /// The publisher.
        publisher: String,
        /// Its stream that ended.
        old: StreamId,
        /// The stream in its place.
        new: StreamId,
    },
}

/// Why an attendee left ([`CallEvent::AttendeeLeft`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LeaveCause {
    /// It said so, signed: it left the call.
    Left,
    /// It said so, signed: its app went to the background.
    Backgrounded,
    /// Its key left the room's MLS group.
    Removed,
    /// Every leg to it went away and its stream went silent past
    /// [`ATTENDEE_LOST_AFTER`], with no signed end.
    Lost,
    /// v45 — its signed `end = 3`: this stream ended and nothing more (a
    /// share stopped). Only ever on [`CallEvent::StreamEnded`].
    Ended,
}

impl LeaveCause {
    /// The stable token: `left`, `backgrounded`, `removed`, `lost`, `ended`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Backgrounded => "backgrounded",
            Self::Removed => "removed",
            Self::Lost => "lost",
            Self::Ended => "ended",
        }
    }
}

impl From<crate::transport::av_chunk_auth::SignedEnd> for LeaveCause {
    fn from(e: crate::transport::av_chunk_auth::SignedEnd) -> Self {
        match e {
            crate::transport::av_chunk_auth::SignedEnd::Left => Self::Left,
            crate::transport::av_chunk_auth::SignedEnd::Backgrounded => Self::Backgrounded,
            crate::transport::av_chunk_auth::SignedEnd::Ended => Self::Ended,
        }
    }
}

/// How long an attendee with no leg and a silent stream waits before it is
/// `Lost`: the depth-0 parent `Down` bound (`down_silence_ms`, 5 s).
pub const ATTENDEE_LOST_AFTER: Duration = Duration::from_secs(5);

/// The safety net on a replacement's make-before-break: the switch waits for
/// every leg's Channel to prove the new stream's binding delivered (that
/// message itself, by its sequence, with media still in flight behind it;
/// a datagram leg's Channel included), and goes at
/// this ceiling only for a leg that never does (counted
/// `replace_switch_unconfirmed`).
pub const REPLACE_SWITCH_CEILING: Duration = Duration::from_secs(3);

/// The safety net on a leave: each leg closes once its Channel proved the
/// signed end delivered, and at this ceiling only when it never does (counted
/// `end_flush_unconfirmed`).
pub const END_FLUSH_CEILING: Duration = Duration::from_secs(2);

/// How often a delivery wait reads the legs' Channel stats.
const DELIVERY_POLL: Duration = Duration::from_millis(10);

/// The call's view of who attends with which stream (v45).
#[derive(Debug, Default)]
struct Attendance {
    /// Each attendee's live streams, oldest first, from its verified
    /// bindings (v45: a camera and its shares).
    streams: HashMap<String, Vec<StreamId>>,
    /// Attendees this node verified a chunk of on a stream that has since
    /// ended: presence carried to the attendee's last stream's end.
    heard: std::collections::HashSet<String>,
    /// v45 — an attendee whose every stream ended with `end = 3` (still
    /// attending, by reachability): the last of them, for its eventual
    /// `AttendeeLeft`.
    last_ended: HashMap<String, StreamId>,
    /// `(attendee, stream)` pairs that have ended (left or replaced): each
    /// fires once.
    ended: std::collections::HashSet<(String, StreamId)>,
    /// Since when no leg to the attendee has been up.
    unlinked_since: HashMap<String, Instant>,
    /// Signed ends verified but not yet settled, with when each landed: the
    /// truncation verdict waits [`END_VERDICT_AFTER`] for tail chunks still
    /// in flight.
    ending: Vec<(StreamKeyBinding, Instant)>,
}

/// v45 — how long after a signed end lands its truncation verdict waits:
/// the longest reorder window, so a tail chunk up to `final_seq` that the
/// window would still have played is not reported missing.
pub const END_VERDICT_AFTER: Duration = REORDER_WINDOW_MAX;

impl Attendance {
    /// One installed (so verified) binding's word on attendance, from its
    /// signed fields only:
    /// - a signed `end`: the attendee left, for that cause;
    /// - a signed `replaces` of a stream the same publisher's verified
    ///   binding named (`old_publisher`): the old stream replaced in place,
    ///   with no leave;
    /// - anything else: one of the attendee's live streams (a second
    ///   concurrent stream without `replaces`, a share, ends nothing).
    ///
    /// This node's own bindings (`own`) say nothing here.
    /// `present`: this node verified a chunk of `b.stream` (a binding alone is
    /// no presence); `truncated`: its signed end's tail never fully arrived.
    fn on_bound(
        &mut self,
        own: &str,
        b: &StreamKeyBinding,
        old_publisher: Option<&str>,
        present: bool,
        truncated: bool,
    ) -> Vec<CallEvent> {
        if b.publisher == own {
            return Vec::new();
        }
        if let Some(end) = b.end {
            return self
                .left(&b.publisher, b.stream, end.into(), present, truncated)
                .into_iter()
                .collect();
        }
        if let Some(old) = b.replaces.filter(|old| *old != b.stream) {
            if old_publisher == Some(b.publisher.as_str()) {
                let live = self.streams.entry(b.publisher.clone()).or_default();
                match live.iter().position(|s| *s == old) {
                    Some(i) => live[i] = b.stream,
                    None if !live.contains(&b.stream) => live.push(b.stream),
                    None => {}
                }
                if self.ended.insert((b.publisher.clone(), old)) {
                    return vec![CallEvent::StreamReplaced {
                        publisher: b.publisher.clone(),
                        old,
                        new: b.stream,
                    }];
                }
                return Vec::new();
            }
        }
        if !self.ended.contains(&(b.publisher.clone(), b.stream)) {
            let live = self.streams.entry(b.publisher.clone()).or_default();
            if !live.contains(&b.stream) {
                live.push(b.stream);
                self.last_ended.remove(&b.publisher);
                return vec![CallEvent::StreamAdded {
                    publisher: b.publisher.clone(),
                    stream: b.stream,
                    kind: b.kind,
                }];
            }
        }
        Vec::new()
    }

    /// Hold `b`'s signed end until its verdict is due ([`Self::due_ends`]).
    fn defer_end(&mut self, b: &StreamKeyBinding, now: Instant) {
        self.ending.push((b.clone(), now));
    }

    /// The held ends whose verdict is due at `now`, oldest first.
    fn due_ends(&mut self, now: Instant) -> Vec<StreamKeyBinding> {
        let (due, wait): (Vec<_>, Vec<_>) = std::mem::take(&mut self.ending)
            .into_iter()
            .partition(|(_, at)| now.duration_since(*at) >= END_VERDICT_AFTER);
        self.ending = wait;
        due.into_iter().map(|(b, _)| b).collect()
    }

    /// `key_id`'s `stream` ended for `cause` (its signed end): the event the
    /// first time only. While the attendee has another live stream (a share
    /// beside the camera, or the camera beside a share) it is
    /// [`CallEvent::StreamEnded`], for a stream this node heard; its last
    /// stream's end is [`CallEvent::AttendeeLeft`], for an attendee this node
    /// heard on any of its streams (`present`: this stream's chunks
    /// arrived): an attendee is one whose chunks arrived, never one a
    /// binding alone names. A stream never heard is still marked ended, so it
    /// never fires later.
    fn left(
        &mut self,
        key_id: &str,
        stream: StreamId,
        cause: LeaveCause,
        present: bool,
        truncated: bool,
    ) -> Option<CallEvent> {
        let first = self.ended.insert((key_id.to_owned(), stream));
        let mut last = true;
        if let Some(live) = self.streams.get_mut(key_id) {
            live.retain(|s| *s != stream);
            last = live.is_empty();
        }
        if !first {
            return None;
        }
        if present {
            self.heard.insert(key_id.to_owned());
        }
        // CC (rc18 reading): 1 and 2 are a leave only on the member's last
        // stream; `end = 3` is the stream's end and never a leave, even on
        // the last one: presence is reachability, never "no streams", so the
        // member stays (with no live stream) until it leaves, is lost or is
        // removed.
        if last && cause != LeaveCause::Ended {
            self.streams.remove(key_id);
            self.unlinked_since.remove(key_id);
            self.last_ended.remove(key_id);
            return self.heard.remove(key_id).then(|| CallEvent::AttendeeLeft {
                key_id: key_id.to_owned(),
                stream,
                cause,
                truncated,
            });
        }
        if last {
            self.last_ended.insert(key_id.to_owned(), stream);
        }
        present.then(|| CallEvent::StreamEnded {
            publisher: key_id.to_owned(),
            stream,
            cause,
            truncated,
        })
    }

    /// v45 — every live stream of `key_id` ended at once, for `cause`
    /// (`Lost`, `Removed`: no signed end): one [`CallEvent::AttendeeLeft`],
    /// naming its oldest stream (the camera, as a rule), if this node heard
    /// it on any (`present` per stream) and something was still live.
    fn leave_all(
        &mut self,
        key_id: &str,
        cause: LeaveCause,
        present: impl Fn(StreamId) -> bool,
    ) -> Option<CallEvent> {
        let live = self.streams.remove(key_id)?;
        self.unlinked_since.remove(key_id);
        let last_ended = self.last_ended.remove(key_id);
        let mut oldest = None;
        for s in live {
            if self.ended.insert((key_id.to_owned(), s)) {
                if present(s) {
                    self.heard.insert(key_id.to_owned());
                }
                oldest.get_or_insert(s);
            }
        }
        // A member whose streams all ended (`end = 3`) still attends: its
        // loss or removal names the last of them.
        let stream = oldest.or(last_ended)?;
        self.heard.remove(key_id).then(|| CallEvent::AttendeeLeft {
            key_id: key_id.to_owned(),
            stream,
            cause,
            truncated: false,
        })
    }
}

/// A replacement minted and bound, waiting for its bindings' delivery.
struct PendingReplace {
    own_key: OwnChunkKey,
    dek: crate::transport::realtime_av::EpochDek,
    /// Every leg proved the bindings delivered (or the ceiling passed).
    ready: Arc<AtomicBool>,
}

/// Why a call verb was refused (§8).
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// This node is not a member of the room's MLS group.
    #[error("{key_id} is not a member of room {room}'s MLS group")]
    NotARoomMember {
        /// The key that tried.
        key_id: String,
        /// The room.
        room: String,
    },
    /// The room's group holds this key but persist holds no ACTIVE membership
    /// for it: no consented (#955) membership stands behind it.
    #[error("{key_id} holds no active, consented membership of room {room} (#955)")]
    ConsentMissing {
        /// The key.
        key_id: String,
        /// The room.
        room: String,
    },
    /// The room's MLS state cannot be opened.
    #[error("room {room}'s MLS group is unavailable: {detail}")]
    RoomGroupUnavailable {
        /// The room.
        room: String,
        /// Why.
        detail: String,
    },
    /// A frame over the budget, refused BEFORE the seal: no `chunk_seq` and
    /// no nonce were consumed.
    #[error("frame of {bytes} B is over the call's budget of {budget} B")]
    FrameTooLarge {
        /// The frame's size.
        bytes: usize,
        /// [`Call::chunk_plaintext_budget`].
        budget: usize,
    },
    /// No member leg reports a Channel limit yet.
    #[error("no member leg is up yet: the call has no frame budget")]
    NoBudget,
    /// The call's addresses could not follow the room's epoch.
    #[error("the call is stranded at room epoch {epoch}: {reason}")]
    Stranded {
        /// The epoch.
        epoch: u64,
        /// Why.
        reason: String,
    },
    /// The call ended.
    #[error("the call ended ({0:?})")]
    CallEnded(EndCause),
    /// The attendee's call row would not name the actor as its attester and
    /// ONLY subject (item 6: one row per attendee, attester = subject). The
    /// join is refused before anything starts; no row is written.
    #[error(
        "the call row is not the actor's own: actor {actor}, attester {attester}, subjects \
         {subjects:?} (CIRISEdge#805 item 6)"
    )]
    ActorIsNotTheSubject {
        /// The key the call attends as.
        actor: String,
        /// The row's attester.
        attester: String,
        /// The row's subjects.
        subjects: Vec<String>,
    },
    /// The transport, the addressing plane or the media runtime refused.
    #[error("call plumbing: {0}")]
    Plumbing(String),
    /// CC 5.4.3 rc16 — this node is in anonymous mode (its Anonymous Tier is
    /// active): a peer in anonymous mode is confined to the row plane, so it
    /// starts and joins no call and no stream. Refused before anything starts.
    #[error("this node is in anonymous mode: no call and no stream (onion_anonymous_no_media)")]
    AnonymousMode,
    /// v45 — the stream named is not one this node publishes in the call
    /// (never added, or already ended).
    #[error("stream {0} is not one this node publishes in the call")]
    UnknownStream(String),
    /// v45 — one more own stream would pass the room's per-publisher bound
    /// ([`MAX_OWN_STREAMS`]): end one first.
    #[error("this node already publishes {0} streams in the call, the most it may")]
    TooManyStreams(usize),
    /// v45 — the frame's run of chunks would pass the epoch's 2³²
    /// `chunk_seq` ceiling: refused before any seal; the epoch rolls first.
    #[error("{fragments} chunks from chunk_seq {next} pass the epoch's 2^32 ceiling; the epoch must roll first")]
    ChunkSeqExhausted {
        /// The epoch's next `chunk_seq`.
        next: u64,
        /// The chunks the frame needs.
        fragments: usize,
    },
}

/// v45 — the most streams one node publishes in a call at once: the camera
/// and up to two shares. A receiver holds a publisher's four newest bound
/// streams ([`crate::transport::av_chunk_auth`]); one place is kept for a
/// replacement's overlap (the old stream stays bound until its tail plays).
pub const MAX_OWN_STREAMS: usize = 3;

/// v45 — one of this node's other own streams (`Call::add_stream`): its own
/// sealing session (stream id, epoch DEK, chunk counter, kept like the
/// primary) and chunk key with its bindings. Its chunks ride the primary
/// publisher's legs, so it has no legs of its own.
struct ShareStream {
    publisher: Publisher,
    key: OwnChunkKey,
}

/// Item 6 — a call row is its attendee's own: `actor` is its attester and its
/// ONLY subject. Anything else is [`CallError::ActorIsNotTheSubject`].
///
/// # Errors
/// [`CallError::ActorIsNotTheSubject`].
pub fn ensure_actor_is_subject(
    actor: &str,
    row: &ciris_persist::federation::Attestation,
) -> Result<(), CallError> {
    if row.attesting_key_id == actor
        && row.subject_key_ids.len() == 1
        && row.subject_key_ids[0] == actor
    {
        return Ok(());
    }
    Err(CallError::ActorIsNotTheSubject {
        actor: actor.to_owned(),
        attester: row.attesting_key_id.clone(),
        subjects: row.subject_key_ids.clone(),
    })
}

/// What a call did, returned by [`Call::leave`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSummary {
    /// The call.
    pub id: CallId,
    /// This node's stream.
    pub stream: StreamId,
    /// The room epochs this stream published in.
    pub epochs: Vec<u64>,
    /// Frames this node published.
    pub frames_published: u64,
    /// Frames delivered on `frames()`.
    pub frames_received: u64,
    /// Chunks the reorder window skipped past their deadline.
    pub frames_skipped: u64,
    /// Duplicate copies dropped (the two-leg overlap).
    pub duplicates: u64,
}

/// Whether a key is an active member of a room, by persist's roster.
#[async_trait::async_trait]
pub trait RoomRoster: Send + Sync {
    /// Is `key_id` on `room`'s ACTIVE roster?
    ///
    /// # Errors
    /// The roster could not be read.
    async fn is_active_member(&self, room: &str, key_id: &str) -> Result<bool, String>;
}

#[async_trait::async_trait]
impl<F: ciris_persist::federation::FederationDirectory + ?Sized> RoomRoster for F {
    async fn is_active_member(&self, room: &str, key_id: &str) -> Result<bool, String> {
        ciris_persist::federation::is_active_community_member(self, room, key_id)
            .await
            .map_err(|e| e.to_string())
    }
}

/// **Who a room's leaves call through** (44.1): the owner binding between a
/// node and the person it serves, as persist resolves it. A room's MLS leaves
/// may be nodes (each node is its own leaf) or persons (the server mints room
/// key material as the owner, so no node is a leaf). A call is carried by
/// nodes, so each person leaf is expanded to the nodes it is the single live
/// owner of. Persist builds `nodes_owned_by` from `owner_of`
/// (`n ∈ nodes_owned_by(P) ⟺ owner_of(n) == P`, an ambiguous owner is
/// skipped), so a node is a call member only through a verified binding,
/// never through a claim on the wire.
#[async_trait::async_trait]
pub trait CallOwners: Send + Sync {
    /// The single live owner of `node`, if any (an ambiguous or unreadable
    /// owner is `None`: fail closed).
    async fn owner_of(&self, node: &str) -> Option<String>;

    /// Every node `person` is the single live owner of.
    ///
    /// # Errors
    /// The directory could not be read.
    async fn nodes_owned_by(&self, person: &str) -> Result<Vec<String>, String>;
}

#[async_trait::async_trait]
impl<F: ciris_persist::federation::FederationDirectory + ?Sized> CallOwners for F {
    async fn owner_of(&self, node: &str) -> Option<String> {
        ciris_persist::federation::admission::owner_of(self, node)
            .await
            .ok()
            .flatten()
    }

    async fn nodes_owned_by(&self, person: &str) -> Result<Vec<String>, String> {
        ciris_persist::federation::admission::nodes_owned_by(self, person)
            .await
            .map_err(|e| e.to_string())
    }
}

/// **The call's members**: the room's leaves, each person leaf replaced by
/// the nodes it owns (in leaf order, deduplicated). A leaf that owns no node
/// is a node (or a person with no bound node yet) and stands as itself. Every
/// membership check of the call reads this set: the join, the inbound link,
/// a stream key binding's publisher, the ALM roster, the roll's departures.
async fn call_members(leaves: &[String], owners: &dyn CallOwners) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::with_capacity(leaves.len());
    for leaf in leaves {
        let nodes = owners
            .nodes_owned_by(leaf)
            .await
            .map_err(|e| format!("the nodes of {leaf}: {e}"))?;
        if nodes.is_empty() {
            if !out.contains(leaf) {
                out.push(leaf.clone());
            }
            continue;
        }
        for n in nodes {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    Ok(out)
}

// ─── the call row (item 6: a call is an attestation of its attendees) ──

/// Who attended a call, as its rows say (`chat::CALL_DIMENSION`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallAttendance {
    /// Every key that attended: the UNION of the subjects of every row of the
    /// call, sorted and deduped. A leaver stays: its row stands.
    pub attendees: Vec<String>,
    /// The earliest `asserted_at` among the call's rows (derived, never a
    /// field anyone rewrites).
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    /// How many rows the set was read from.
    pub rows: usize,
}

/// The call-row door: write this attendee's row, read the call's rows.
#[async_trait::async_trait]
pub trait CallRecord: Send + Sync {
    /// The key this node attends as: the row's attester and only subject.
    fn attendee(&self) -> &str;

    /// Write and share this attendee's row for `call` in `room`.
    ///
    /// # Errors
    /// The row was refused (by persist, or by the share).
    async fn record_join(
        &self,
        room: &str,
        call: CallId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), String>;

    /// The call's attendance, read from its rows.
    ///
    /// # Errors
    /// The read failed.
    async fn attendance(&self, room: &str, call: CallId) -> Result<CallAttendance, String>;
}

/// The call-row door over persist: the attendee's row is authored `self` by
/// `actor` and shared to the room (two rows, like any chat row), so it
/// reaches exactly the room's members. The read is by the CALL: the room's
/// `community`-placed `chat:call:v1` rows (persist's `(cohort_scope,
/// cohort_target)` index), then this call's, folding withdrawals. Never by
/// current membership, so an attendee who left the room stays a subject.
pub struct PersistCallRecord {
    /// The node's directory.
    pub directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
    /// The attendee: the attester of its row (the human's signer, or the
    /// node's when the node attends as itself).
    pub actor: Arc<crate::identity::LocalSigner>,
    /// This node: custody for the crossing.
    pub node: Arc<crate::identity::LocalSigner>,
}

/// The `call_id` member's spelling of a call: lowercase hex.
#[must_use]
pub fn call_id_hex(call: CallId) -> String {
    hex::encode(call.0)
}

#[async_trait::async_trait]
impl CallRecord for PersistCallRecord {
    fn attendee(&self) -> &str {
        &self.actor.key_id
    }

    async fn record_join(
        &self,
        room: &str,
        call: CallId,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), String> {
        use crate::replication::attestation_bind::{share, CrossingBasis, Signers, With};
        let row =
            crate::chat::call_attestation_in(&self.actor, room, &call_id_hex(call), at).await?;
        ensure_actor_is_subject(&self.actor.key_id, &row).map_err(|e| e.to_string())?;
        self.directory
            .put_attestation(ciris_persist::federation::SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .map_err(|e| format!("put call row: {e}"))?;
        share(
            self.directory.as_ref(),
            &row,
            With::Community {
                community_key_id: room.to_owned(),
            },
            CrossingBasis::ProducerAuthority,
            Signers {
                node: &self.node,
                actor: Some(&self.actor),
            },
        )
        .await
        .map(|_| ())
        .map_err(|e| format!("share call row: {e}"))
    }

    async fn attendance(&self, room: &str, call: CallId) -> Result<CallAttendance, String> {
        use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
        use ciris_persist::federation::types::{attestation_type as ty, cohort_scope};
        // By the CALL, never by who is in the room now: the room's
        // federation-tier rows placed at `community` for this room under
        // `chat:call:v1` (persist's `(cohort_scope, cohort_target)` index),
        // then this call's. An attendee who later LEFT THE ROOM is still read.
        let rows = self
            .directory
            .list_targeted_by_dimension_prefix(
                &[cohort_scope::COMMUNITY],
                room,
                crate::chat::CALL_DIMENSION,
            )
            .await
            .map_err(|e| format!("call rows of {room}: {e}"))?;
        let call_hex = call_id_hex(call);
        let mut of_call: Vec<ciris_persist::federation::Attestation> = rows
            .into_iter()
            .filter(|r| crate::chat::call_id_of(r) == Some(call_hex.as_str()))
            .collect();
        // An attendee may withdraw its OWN row (CC 1c): fold each attester's
        // withdrawals, bounded to the call's own attesters.
        let attesters: std::collections::BTreeSet<String> =
            of_call.iter().map(|r| r.attesting_key_id.clone()).collect();
        let mut withdrawn = std::collections::BTreeSet::new();
        for who in &attesters {
            let mut pages = AttestationQuery::by(who, FOLD_PAGE)
                .types(&[ty::WITHDRAWS, ty::RECANTS])
                .pages();
            while let Some(page) = crate::read_caller::scoped(
                crate::read_caller::Site::AvCall,
                pages.next(self.directory.as_ref()),
            )
            .await
            .map_err(|e| format!("withdrawals by {who}: {e}"))?
            {
                withdrawn.extend(page.into_iter().filter_map(|a| {
                    a.attestation_envelope
                        .get(ciris_persist::federation::envelope::paths::REFERENCES_ATTESTATION_ID)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                }));
            }
        }
        of_call.retain(|r| !withdrawn.contains(&r.attestation_id));
        Ok(attendance_of(&of_call, &call_hex))
    }
}

/// **The attendee set is the UNION** of the subjects of every row of the
/// call: union commutes, so concurrent joins never fork it, and a leaver's
/// row keeps it in.
#[must_use]
pub fn attendance_of(
    rows: &[ciris_persist::federation::Attestation],
    call_hex: &str,
) -> CallAttendance {
    let of_call: Vec<&ciris_persist::federation::Attestation> = rows
        .iter()
        .filter(|r| crate::chat::call_id_of(r) == Some(call_hex))
        .collect();
    let mut attendees: Vec<String> = of_call
        .iter()
        .flat_map(|r| {
            if r.subject_key_ids.is_empty() {
                vec![r.attesting_key_id.clone()]
            } else {
                r.subject_key_ids.clone()
            }
        })
        .collect();
    attendees.sort();
    attendees.dedup();
    CallAttendance {
        attendees,
        started_at: of_call.iter().map(|r| r.asserted_at).min(),
        rows: of_call.len(),
    }
}

/// Everything a call runs on.
pub struct CallDeps {
    /// The room's MLS group (its current epoch keys the call).
    pub room_group: CohortGroup,
    /// persist's roster.
    pub roster: Arc<dyn RoomRoster>,
    /// The owner bindings that carry a person leaf's call on its nodes
    /// (persist's directory).
    pub owners: Arc<dyn CallOwners>,
    /// The Reticulum transport.
    pub transport: Arc<ReticulumTransport>,
    /// The addressing lifecycle the transport listens through.
    pub lifecycle: Arc<ScopeLifecycle>,
    /// The keep door (never reached while kept streams are deferred).
    pub registrar: Arc<dyn StreamDekRegistrar>,
    /// The node's event bus, for the keep layer's refusal event.
    pub events: Option<Arc<crate::events::EventBus>>,
    /// The node's metrics.
    pub metrics: Option<crate::observability::EdgeMetrics>,
    /// The call-row door (item 6). `None`: this node writes no call row and
    /// knows only the attendees it hears.
    pub record: Option<Arc<dyn CallRecord>>,
    /// This node's federation signer: it binds the stream's chunk keys. Its
    /// key id must be the node's (the stream's publisher).
    pub signer: Arc<crate::identity::LocalSigner>,
    /// Verifies the other publishers' bindings (persist's directory).
    pub verifier: Arc<dyn StreamKeyVerifier>,
    /// The node's service ladder (`FSD/CIRIS_MESH.md` §7): the call reads
    /// its tier every watch tick and reports its own load signals. `None`:
    /// tier 0 always.
    pub load: Option<Arc<crate::load_ladder::SharedLadder>>,
}

// ─── identifiers ────────────────────────────────────────────────────

/// `SHA-256("ciris-edge:call:v1" ‖ utf8(community_key_id))` (§3.1).
#[must_use]
pub fn call_id_for_room(community_key_id: &str) -> CallId {
    let mut h = Sha256::new();
    h.update(b"ciris-edge:call:v1");
    h.update(community_key_id.as_bytes());
    CallId(h.finalize().into())
}

/// `SHA-256("ciris-edge:call-stream:v2" ‖ room ‖ publisher ‖ join_nonce)`
/// (§3.1): a fresh `join_nonce` per join, so a call never reuses a stream.
#[must_use]
pub fn call_stream_id(community_key_id: &str, publisher: &str, join_nonce: &[u8; 32]) -> StreamId {
    let mut h = Sha256::new();
    h.update(b"ciris-edge:call-stream:v2");
    h.update(community_key_id.as_bytes());
    h.update(publisher.as_bytes());
    h.update(join_nonce);
    StreamId(h.finalize().into())
}

/// The call's addressing group: the room's call, in the A/V namespace, so
/// its links are on the A/V plane and its addresses never collide with the
/// room's own.
#[must_use]
pub fn call_group_id(call: CallId) -> String {
    crate::av_addressing::stream_group_id(StreamId(call.0))
}

fn encode_hello(stream: StreamId) -> Vec<u8> {
    let mut out = Vec::with_capacity(STREAM_HELLO_LEN);
    out.extend_from_slice(&STREAM_HELLO_MAGIC);
    out.push(STREAM_HELLO_VERSION);
    out.extend_from_slice(&stream.0);
    out
}

fn decode_hello(bytes: &[u8]) -> Option<StreamId> {
    if bytes.len() != STREAM_HELLO_LEN
        || bytes[..4] != STREAM_HELLO_MAGIC
        || bytes[4] != STREAM_HELLO_VERSION
    {
        return None;
    }
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes[5..]);
    Some(StreamId(id))
}

// ─── the reorder window ─────────────────────────────────────────────

/// What the reorder window counted.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReorderCounts {
    /// Frames released in order.
    pub released: u64,
    /// Chunks skipped: still missing at their deadline.
    pub skipped: u64,
    /// Second copies dropped.
    pub duplicates: u64,
    /// Copies that arrived after their slot was released or skipped.
    pub late: u64,
    /// v45 — frames of a framed stream dropped whole (a fragment the window
    /// gave up on, a marker refused, a framing that never became known):
    /// never handed out partial or unframed.
    pub frames_dropped: u64,
    /// v45 — frames being reassembled now (at most one per stream).
    pub frames_open: u64,
}

/// One stream's window.
struct StreamWindow {
    next: Option<(u64, u64)>,
    /// Nothing released yet: a gap before the first release is the prefix
    /// this node joined after (or the first chunk still on its slower leg),
    /// waited for like any gap but not counted as a skip.
    started: bool,
    buf: BTreeMap<(u64, u64), (Instant, ReceivedFrame)>,
    /// When each recently released key was first seen (for the gap).
    released_at: VecDeque<((u64, u64), Instant)>,
    gap_ewma: Duration,
}

impl StreamWindow {
    fn new() -> Self {
        Self {
            next: None,
            started: false,
            buf: BTreeMap::new(),
            released_at: VecDeque::new(),
            gap_ewma: REORDER_GAP_PRIOR,
        }
    }

    fn window(&self) -> Duration {
        (self.gap_ewma * 2).clamp(REORDER_WINDOW_MIN, REORDER_WINDOW_MAX)
    }

    fn observe_gap(&mut self, gap: Duration) {
        // Fast attack, slow decay, as a jitter buffer: a slower second leg
        // must widen the window before its next copies come due, or they
        // arrive past their deadline while a symmetric average catches up.
        self.gap_ewma = if gap > self.gap_ewma {
            (self.gap_ewma + gap * 3) / 4
        } else {
            (self.gap_ewma * 3 + gap) / 4
        };
    }
}

/// **The per-stream reorder window over the two-leg dedupe** (§4, A8).
///
/// Each stream releases in `(epoch, chunk_seq)` order. A copy of a chunk
/// already buffered or released is a duplicate (the two-leg overlap) and
/// feeds the measured gap between a chunk's copies; the window is twice that
/// gap, clamped to [`REORDER_WINDOW_MIN`]..=[`REORDER_WINDOW_MAX`]. When the
/// next chunk is missing, the window waits for it until the earliest
/// buffered chunk is a window old, then skips it and counts the skip: it
/// never waits out loss. Memory is bounded by what arrives inside one window.
pub struct ReorderWindow {
    streams: HashMap<StreamId, StreamWindow>,
    counts: ReorderCounts,
}

impl Default for ReorderWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReorderWindow {
    /// An empty window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            counts: ReorderCounts::default(),
        }
    }

    /// The counters so far.
    #[must_use]
    pub fn counts(&self) -> ReorderCounts {
        self.counts
    }

    /// `stream`'s current window.
    #[must_use]
    pub fn window_for(&self, stream: StreamId) -> Duration {
        self.streams
            .get(&stream)
            .map_or(REORDER_GAP_PRIOR * 2, StreamWindow::window)
    }

    /// Take one opened frame that arrived at `now`; returns the frames now
    /// releasable, in order.
    pub fn push(&mut self, frame: ReceivedFrame, now: Instant) -> Vec<ReceivedFrame> {
        let key = (frame.epoch.0, frame.chunk_seq.0);
        let stream = frame.stream;
        let w = self.streams.entry(stream).or_insert_with(StreamWindow::new);
        // A stream starts at chunk 0 of the epoch it is first heard in:
        // chunk_seq is epoch-local (#846), so a first copy at `k > 0` waits a
        // window for 0..k (still on a slower leg), then skips past them.
        let next = *w.next.get_or_insert((key.0, 0));
        if key < next {
            match w.released_at.iter().find(|(k, _)| *k == key) {
                Some((_, first)) => {
                    let gap = now.saturating_duration_since(*first);
                    w.observe_gap(gap);
                    self.counts.duplicates += 1;
                }
                None => self.counts.late += 1,
            }
            return Vec::new();
        }
        if let Some((first, _)) = w.buf.get(&key) {
            let gap = now.saturating_duration_since(*first);
            w.observe_gap(gap);
            self.counts.duplicates += 1;
            return Vec::new();
        }
        w.buf.insert(key, (now, frame));
        self.drain(stream, now)
    }

    /// Release what is in order for `stream`, and skip a missing chunk whose
    /// deadline passed.
    fn drain(&mut self, stream: StreamId, now: Instant) -> Vec<ReceivedFrame> {
        let mut out = Vec::new();
        let Some(w) = self.streams.get_mut(&stream) else {
            return out;
        };
        while let Some(next) = w.next {
            let Some((&head, &(first_seen, _))) = w.buf.iter().next() else {
                break;
            };
            if head != next {
                // The next chunk is missing: wait for it, up to the window.
                if now.saturating_duration_since(first_seen) < w.window() {
                    break;
                }
                let skipped = if head.0 == next.0 {
                    head.1.saturating_sub(next.1)
                } else {
                    1
                };
                if w.started {
                    self.counts.skipped += skipped;
                }
                w.next = Some(head);
                continue;
            }
            if let Some((seen, frame)) = w.buf.remove(&head) {
                w.started = true;
                w.released_at.push_back((head, seen));
                if w.released_at.len() > 512 {
                    w.released_at.pop_front();
                }
                self.counts.released += 1;
                out.push(frame);
            }
            w.next = Some((head.0, head.1 + 1));
        }
        out
    }

    /// Release everything whose deadline passed by `now`, every stream.
    pub fn tick(&mut self, now: Instant) -> Vec<ReceivedFrame> {
        let streams: Vec<StreamId> = self.streams.keys().copied().collect();
        let mut out = Vec::new();
        for s in streams {
            out.extend(self.drain(s, now));
        }
        out
    }

    /// The earliest instant a buffered gap times out, if any.
    #[must_use]
    pub fn next_deadline(&self) -> Option<Instant> {
        self.streams
            .values()
            .filter_map(|w| {
                let (&head, &(first_seen, _)) = w.buf.iter().next()?;
                (Some(head) != w.next).then(|| first_seen + w.window())
            })
            .min()
    }
}

// ─── the receive keys ───────────────────────────────────────────────

/// The DEKs a receiver holds: `(stream, epoch)` → DEK, derived from the room
/// group while that epoch is the room's current one, kept for the current
/// and the previous epoch (chunks in flight across a roll), dropped (and
/// zeroized) after.
struct KeyRing {
    room_group: CohortGroup,
    held: StdMutex<HashMap<(StreamId, u64), Arc<EpochDek>>>,
}

impl KeyRing {
    async fn dek(&self, stream: StreamId, epoch: Epoch) -> Option<Arc<EpochDek>> {
        if let Some(d) = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(stream, epoch.0))
        {
            return Some(Arc::clone(d));
        }
        // Derivable only at the room's CURRENT epoch: a member who left
        // cannot reach the new epoch, a member who joined never had the old.
        let dek = Arc::new(
            stream_epoch_dek(&self.room_group, stream, epoch)
                .await
                .ok()?,
        );
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.retain(|(_, e), _| e.saturating_add(1) >= epoch.0);
        held.insert((stream, epoch.0), Arc::clone(&dek));
        Some(dek)
    }
}

// ─── arrivals routing ───────────────────────────────────────────────

/// Routes a transport's peer-opened A/V links to the call whose addressing
/// group they were dialled in. One per transport
/// ([`ReticulumTransport::av_call_router`]); it owns the transport's A/V
/// arrivals.
pub struct CallRouter {
    calls: StdMutex<HashMap<String, mpsc::Sender<AvArrival>>>,
    unrouted: AtomicU64,
}

impl std::fmt::Debug for CallRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallRouter").finish_non_exhaustive()
    }
}

impl CallRouter {
    /// Start routing `arrivals`.
    pub(crate) fn start(mut arrivals: mpsc::Receiver<AvArrival>) -> Arc<Self> {
        let router = Arc::new(Self {
            calls: StdMutex::new(HashMap::new()),
            unrouted: AtomicU64::new(0),
        });
        let r = Arc::clone(&router);
        tokio::spawn(async move {
            while let Some(arrival) = arrivals.recv().await {
                let group = arrival
                    .address
                    .as_ref()
                    .map(|a| a.group().group_id().to_owned());
                let tx = group.as_ref().and_then(|g| {
                    r.calls
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(g)
                        .cloned()
                });
                if let Some(tx) = tx {
                    let _ = tx.send(arrival).await;
                } else {
                    r.unrouted.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        peer = %arrival.peer.as_str(),
                        group = ?group,
                        "A/V link for no live call on this node — dropped (CIRISEdge#805)"
                    );
                }
            }
        });
        router
    }

    fn register(&self, group: &str) -> mpsc::Receiver<AvArrival> {
        let (tx, rx) = mpsc::channel(64);
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(group.to_owned(), tx);
        rx
    }

    fn unregister(&self, group: &str) {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(group);
    }

    /// Links that arrived for no live call.
    #[must_use]
    pub fn unrouted(&self) -> u64 {
        self.unrouted.load(Ordering::Relaxed)
    }
}

// ─── the call ───────────────────────────────────────────────────────

type Publisher = KeptAvPublisher<Arc<dyn StreamDekRegistrar>>;

/// A leg this node dialled to a member, carrying its stream.
/// What carries one leg's link ([`Call::leg_info`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegPath {
    /// A punched direct UDP path (CIRISEdge#805 item 8, leviculum#70).
    DirectUdp,
    /// The one-hop interface the link rides (TCP or another), no forwarder.
    Interface,
    /// A forwarder carries it: a member relay or the canonical (no punched
    /// interface, more than one hop).
    Relayed,
    /// leviculum no longer holds the link.
    Gone,
}

impl LegPath {
    /// The stable token: `direct_udp`, `interface`, `relayed`, `gone`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::DirectUdp => "direct_udp",
            Self::Interface => "interface",
            Self::Relayed => "relayed",
            Self::Gone => "gone",
        }
    }
}

/// One leg as [`Call::leg_info`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegInfo {
    /// The member the leg goes to.
    pub member: String,
    /// What carries it.
    pub path: LegPath,
    /// The link's MDU (bytes).
    pub link_mdu: usize,
    /// The most plaintext one Channel message carries (bytes).
    pub channel_limit: usize,
    /// The most plaintext one media message carries on this leg: the
    /// datagram limit on a datagram leg, else the Channel limit.
    pub media_limit: usize,
    /// The largest frame plaintext this leg carries (the media limit less a
    /// chunk's wire overhead and its source signature).
    pub frame_budget: usize,
    /// Whether media rides datagrams on it (leviculum#102).
    pub datagrams: bool,
}

#[derive(Debug, Clone)]
struct OutLeg {
    link_id: [u8; 16],
    /// The Channel limit when the leg came up: the budget's fallback once
    /// leviculum no longer reports the link.
    channel_limit: usize,
    /// The leg's media settings: timed, and (leviculum#102) whether media
    /// rides datagrams, which sets the carrier the budget follows.
    media: Arc<crate::transport::realtime_av_runtime::MediaTtl>,
}

/// One copy of a frame, on its way to the reorder window.
struct Heard {
    frame: ReceivedFrame,
    at: Instant,
}

struct Shared {
    room: String,
    own: String,
    scope: CohortScope,
    group_id: String,
    opts: CallOptions,
    room_group: CohortGroup,
    transport: Arc<ReticulumTransport>,
    lifecycle: Arc<ScopeLifecycle>,
    publisher: Mutex<Publisher>,
    keys: KeyRing,
    out_legs: StdMutex<HashMap<String, OutLeg>>,
    dialling: StdMutex<HashMap<String, Instant>>,
    backoff: StdMutex<HashMap<String, Duration>>,
    in_links: StdMutex<HashMap<[u8; 16], String>>,
    policies: StdMutex<HashMap<String, ReceiverLayerPolicy>>,
    members: StdMutex<Vec<String>>,
    /// The leaves [`call_members`] last resolved, and what they resolved to:
    /// a binding re-reads the owner bindings only when the leaves moved.
    resolved: StdMutex<(Vec<String>, Vec<String>)>,
    /// The owner bindings a person leaf's nodes are members through.
    owners: Arc<dyn CallOwners>,
    heard_tx: mpsc::Sender<Heard>,
    events_tx: mpsc::Sender<CallEvent>,
    state: StdMutex<CallState>,
    epochs: StdMutex<Vec<u64>>,
    ended: AtomicBool,
    published: AtomicU64,
    metrics: Option<crate::observability::EdgeMetrics>,
    /// When the join began: `ciris.edge.call.setup.duration`.
    setup_began: std::time::Instant,
    /// The setup has ended, one way or the other.
    setup_done: AtomicBool,
    /// The call's end has been booked.
    summary_done: AtomicBool,
    /// The C3 members this call last told the node's gauge of.
    c3_reported: AtomicU64,
    /// Test seam: hold every relayed copy this long before forwarding it.
    test_relay_delay_ms: AtomicU64,
    /// Test seam: withhold every `n`th own chunk (`chunk_seq % n == 0`) from
    /// the named member's leg (simulated loss on the direct leg).
    test_withhold: StdMutex<Option<(String, u64)>>,
    /// Test seam: withhold every `n`th FORWARDED chunk (`chunk_seq % n ==
    /// 0`) from the named child's leg (loss on a relay's downstream leg).
    test_withhold_forward: StdMutex<Option<(String, u64)>>,
    /// The call-row door, if any.
    record: Option<Arc<dyn CallRecord>>,
    /// The key this node attends as.
    attendee: String,
    /// Attendees already announced on `events()`.
    attendees_known: StdMutex<std::collections::BTreeSet<String>>,
    /// The one `RecordRefused` has fired.
    record_refused: AtomicBool,
    id: CallId,
    /// The federation signer that binds this stream's chunk keys.
    signer: Arc<crate::identity::LocalSigner>,
    /// Verifies other publishers' bindings.
    verifier: Arc<dyn StreamKeyVerifier>,
    /// This node's stream, its chunk key for the publisher's current epoch,
    /// and its bindings. Replaced only under the publisher lock, at the roll
    /// and at `Call::replace_stream`.
    own_key: StdMutex<OwnChunkKey>,
    /// v45 — who attends with which stream; what `AttendeeLeft` fires from.
    attendance: StdMutex<Attendance>,
    /// v45 — a `replace_stream` waiting for its bindings' delivery.
    pending_replace: StdMutex<Option<PendingReplace>>,
    /// v45 (Eric 2026-11-10) — the next `frame_seq` per (own stream, codec
    /// class, layer) of a framed stream, from 0 for the stream's life (an
    /// epoch roll does not restart it; a replacement is a new stream, from
    /// 0); taken only once a frame sealed.
    frame_seqs: StdMutex<HashMap<(StreamId, u8, ChunkLayer), u32>>,
    /// v45 — frames lost per codec class at this receiver (gaps in
    /// `frame_seq`), as the reorder loop's reassembly last counted them.
    frames_lost: Arc<StdMutex<BTreeMap<(u8, (u8, u8, u8)), u64>>>,
    /// v45 — the receive view: bumped whenever what this node is sent may
    /// change (its own layer request, a parent's shed or decision), so a
    /// layer it was not being sent for a while is never booked as lost.
    layer_view: AtomicU64,
    /// v45 — the camera (primary) stream ended while a share went on
    /// (`Call::end_stream_as`): it takes no more frames, and its bindings
    /// are no longer announced.
    primary_ended: AtomicBool,
    /// v45 — this node's other own streams (`Call::add_stream`), by stream.
    /// Lock order: the primary publisher first, then this; never the other
    /// way.
    shares: Mutex<BTreeMap<StreamId, ShareStream>>,
    /// What a share's publisher is made with: the primary's registrar and
    /// event bus.
    registrar: Arc<dyn StreamDekRegistrar>,
    av_events: Option<Arc<crate::events::EventBus>>,
    /// The other streams' bound chunk keys.
    auth: ChunkAuth,
    /// ALM stage 2 — the call's controller state (C1–C7 over C3).
    alm: StdMutex<alm::AlmState>,
    /// ALM C3 — the sender half of each link a member dialled to this node
    /// (the reverse direction carries this node's control frames to it when
    /// this node has no leg of its own to that member).
    in_senders:
        StdMutex<HashMap<String, Arc<crate::transport::realtime_av_runtime::LeviculumAvSender>>>,
    /// ALM C5 — each out-leg's media TTLs (set once its peer takes timed frames).
    leg_ttl: StdMutex<HashMap<String, Arc<crate::transport::realtime_av_runtime::MediaTtl>>>,
    /// ALM C5 — each out-leg's congestion streaks and whether it is shed to
    /// the base layer: `(congested, clean, shed)`.
    leg_cong: StdMutex<HashMap<String, (u32, u32, bool)>>,
    /// ALM C5 — the oldest frame age seen in the inbound queues this window
    /// (ms), for the ladder's `edge:av_queue_age` signal.
    queue_age_ms: AtomicU64,
    /// The node's service ladder, if any.
    load: Option<Arc<crate::load_ladder::SharedLadder>>,
    /// Test seam: every pump holds its next frame until this instant (a
    /// stalled consumer, so queued media ages).
    test_stall_until: StdMutex<Option<Instant>>,
    /// Test seam: this many must-arrive C3 frames fail their FIRST send, as
    /// a congested link refuses them (their resends are untouched).
    test_fail_c3: AtomicU64,
}

/// This node's stream (it changes only at `Call::replace_stream`), its chunk
/// key at one epoch, and its binding's encodings.
struct OwnChunkKey {
    signer: ChunkSigner,
    /// The v1 binding (every peer).
    wire: Arc<Vec<u8>>,
    /// The v2 binding (codec map, `replaces`), when the host declared codecs
    /// or the stream replaced another (only to peers with `CAP_BINDING_V2`).
    wire_v2: Option<Arc<Vec<u8>>>,
    /// The stream.
    stream: StreamId,
    /// The nonce the stream id was derived from (its binding names it).
    join_nonce: [u8; 32],
    /// The stream this one replaced in place, if any: every epoch's v2
    /// binding says so, signed.
    replaces: Option<StreamId>,
    /// The stream's codec map (fixed for its life).
    codecs: Option<crate::transport::av_chunk_auth::CodecMap>,
    /// v45 — its signed kind (0 media, 1 share).
    kind: u8,
    /// v45 — its signed framing (from the codec map, [`framing_for`]).
    framing: u8,
}

/// Mint this stream's chunk key for `epoch` and bind it: a v1 binding, and a
/// v2 one when there is a codec map or a replacement to state.
#[allow(clippy::too_many_arguments)]
async fn mint_own_key(
    signer: &crate::identity::LocalSigner,
    room: &str,
    join_nonce: [u8; 32],
    stream: StreamId,
    epoch: Epoch,
    codecs: Option<crate::transport::av_chunk_auth::CodecMap>,
    replaces: Option<StreamId>,
    kind: u8,
) -> Result<OwnChunkKey, CallError> {
    let framing = framing_for(codecs);
    let key =
        ChunkSigner::generate(stream, epoch).map_err(|e| CallError::Plumbing(e.to_string()))?;
    let binding = StreamKeyBinding::sign(signer, room, join_nonce, stream, epoch, key.public())
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
    // v45 — every stream signs a v2 binding (its framing, even 0), so a v2
    // receiver never has to guess a chunk's layout.
    let wire_v2 = {
        Some(Arc::new(
            StreamKeyBinding::sign_v2(
                signer,
                room,
                join_nonce,
                stream,
                epoch,
                key.public(),
                Some(crate::transport::av_chunk_auth::V2Members {
                    codecs,
                    replaces,
                    end: None,
                    final_seq: None,
                    kind,
                    framing,
                }),
            )
            .await
            .map_err(|e| CallError::Plumbing(e.to_string()))?
            .to_bytes(),
        ))
    };
    Ok(OwnChunkKey {
        signer: key,
        wire: Arc::new(binding.to_bytes()),
        wire_v2,
        stream,
        join_nonce,
        replaces,
        codecs,
        kind,
        framing,
    })
}

/// v45 (CC reading, rc18) — a stream's framing from its codec map: framed
/// ([`FRAMING_FRAGMENTS`]) when it names a class other than audio (`0xFF`),
/// so its video is split to the call's budget; an audio-only or map-less
/// stream is not.
///
/// [`FRAMING_FRAGMENTS`]: crate::transport::av_chunk_auth::FRAMING_FRAGMENTS
fn framing_for(codecs: Option<crate::transport::av_chunk_auth::CodecMap>) -> u8 {
    use crate::transport::av_chunk_auth::{FRAMING_FRAGMENTS, FRAMING_NONE};
    match codecs {
        Some(m)
            if m.entries()
                .iter()
                .any(|(class, _)| *class != crate::transport::realtime_av::CODEC_OPAQUE) =>
        {
            FRAMING_FRAGMENTS
        }
        _ => FRAMING_NONE,
    }
}

/// The publisher's signed end of its stream at the current epoch, under the
/// current chunk key (v45): a v2 binding with `end` set, the one thing a
/// receiver turns into `AttendeeLeft { Left | Backgrounded }`.
async fn sign_end(
    shared: &Shared,
    end: crate::transport::av_chunk_auth::SignedEnd,
) -> Result<Arc<Vec<u8>>, CallError> {
    // The last chunk_seq this epoch sealed: 5.3.3.1's terminator's job.
    let final_seq = shared
        .publisher
        .lock()
        .await
        .next_chunk_seq()
        .0
        .checked_sub(1)
        .unwrap_or(crate::transport::av_chunk_auth::FINAL_SEQ_NONE);
    let k = Shared::lock(&shared.own_key);
    let fields = EndFields::of(&k);
    drop(k);
    sign_end_fields(shared, fields, final_seq, end).await
}

/// What a signed end restates of a stream's current binding.
struct EndFields {
    stream: StreamId,
    join_nonce: [u8; 32],
    key: [u8; 32],
    epoch: Epoch,
    replaces: Option<StreamId>,
    codecs: Option<crate::transport::av_chunk_auth::CodecMap>,
    kind: u8,
    framing: u8,
}

impl EndFields {
    fn of(k: &OwnChunkKey) -> Self {
        Self {
            stream: k.stream,
            join_nonce: k.join_nonce,
            key: k.signer.public(),
            epoch: k.signer.epoch(),
            replaces: k.replaces,
            codecs: k.codecs,
            kind: k.kind,
            framing: k.framing,
        }
    }
}

/// v45 — the signed end of the stream `k` binds (a share's), its tail at
/// `final_seq`.
async fn sign_end_of(
    shared: &Shared,
    k: &OwnChunkKey,
    final_seq: u64,
    end: crate::transport::av_chunk_auth::SignedEnd,
) -> Result<Arc<Vec<u8>>, CallError> {
    sign_end_fields(shared, EndFields::of(k), final_seq, end).await
}

async fn sign_end_fields(
    shared: &Shared,
    f: EndFields,
    final_seq: u64,
    end: crate::transport::av_chunk_auth::SignedEnd,
) -> Result<Arc<Vec<u8>>, CallError> {
    let b = StreamKeyBinding::sign_v2(
        &shared.signer,
        &shared.room,
        f.join_nonce,
        f.stream,
        f.epoch,
        f.key,
        Some(crate::transport::av_chunk_auth::V2Members {
            codecs: f.codecs,
            replaces: f.replaces,
            end: Some(end),
            final_seq: Some(final_seq),
            kind: f.kind,
            framing: f.framing,
        }),
    )
    .await
    .map_err(|e| CallError::Plumbing(e.to_string()))?;
    Ok(Arc::new(b.to_bytes()))
}

impl Shared {
    fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// This node's stream now.
    fn stream(&self) -> StreamId {
        Self::lock(&self.own_key).stream
    }

    fn emit(&self, event: CallEvent) {
        if self.events_tx.try_send(event).is_err() {
            tracing::debug!("call event dropped: the events receiver is full or gone");
        }
    }

    fn count(&self, label: &'static str) {
        if let Some(m) = &self.metrics {
            m.inc_av_plane(label);
        }
    }

    /// The first frame heard ends this call's setup.
    fn note_first_frame(&self) {
        use crate::telemetry::CallSetupOutcome;
        if !self.setup_done.swap(true, Ordering::Relaxed) {
            if let Some(m) = &self.metrics {
                m.telemetry
                    .observe_call_setup(CallSetupOutcome::FirstFrame, self.setup_began.elapsed());
            }
        }
    }

    /// The call is over: one summary line, with the decision log's hash and
    /// counts, so a field failure can be matched to a replay. No room, no
    /// peers. Called on every way a call ends; the first call counts.
    fn book_end(&self, cause: &str) {
        use crate::telemetry::CallSetupOutcome;
        use crate::transport::realtime_av_alm::controller::DecisionKind as K;
        if self.summary_done.swap(true, Ordering::Relaxed) {
            return;
        }
        let setup_open = !self.setup_done.swap(true, Ordering::Relaxed);
        if let Some(m) = &self.metrics {
            if setup_open {
                m.telemetry
                    .observe_call_setup(CallSetupOutcome::Ended, self.setup_began.elapsed());
            }
            m.telemetry
                .call_ended(self.c3_reported.swap(0, Ordering::Relaxed));
        }
        let a = Self::lock(&self.alm);
        tracing::info!(
            target: "edge.call.ended",
            cause,
            c7_hash = %a.log_hash(),
            decisions = a.log_len(),
            failovers = a.log_count(K::Failover),
            switches = a.log_count(K::Switch),
            frames_published = self.published.load(Ordering::Relaxed),
            forwarded = a.counts.forwarded,
            stale_dropped = a.counts.stale_dropped,
            offers_refused = a.counts.offers_refused,
            "call ended"
        );
    }
}

/// A live call: this node's stream in a room's call, and every other
/// member's (§4).
pub struct Call {
    id: CallId,
    shared: Arc<Shared>,
    router: Arc<CallRouter>,
    frames_rx: Option<mpsc::Receiver<ReceivedFrame>>,
    events_rx: Option<mpsc::Receiver<CallEvent>>,
    counts: Arc<StdMutex<ReorderCounts>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for Call {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Call")
            .field("room", &self.shared.room)
            .field("stream", &self.shared.stream())
            .finish_non_exhaustive()
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        self.shared.ended.store(true, Ordering::Relaxed);
        self.shared.book_end("dropped");
        self.router.unregister(&self.shared.group_id);
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Call {
    /// **Join the room's call** (§4): start this node's stream. Joining is
    /// presence, not admission (§3.3): this node must already be an active,
    /// consented member of the room and of its MLS group.
    ///
    /// # Errors
    /// [`CallError::NotARoomMember`], [`CallError::ConsentMissing`],
    /// [`CallError::RoomGroupUnavailable`], [`CallError::Plumbing`].
    #[allow(clippy::too_many_lines)] // one linear join sequence; `Shared` is built in place
    pub async fn join(
        room: &str,
        own_key_id: &str,
        deps: CallDeps,
        opts: CallOptions,
    ) -> Result<Self, CallError> {
        let CallDeps {
            room_group,
            roster,
            owners,
            transport,
            lifecycle,
            registrar,
            events,
            metrics,
            record,
            signer,
            verifier,
            load,
        } = deps;
        if signer.key_id != own_key_id {
            return Err(CallError::Plumbing(format!(
                "the signer that binds this stream's chunk keys is {}, not the publisher {own_key_id}",
                signer.key_id
            )));
        }
        let attendee = record
            .as_ref()
            .map_or_else(|| own_key_id.to_owned(), |r| r.attendee().to_owned());
        let (leaves_at_join, members) = admit(
            room,
            own_key_id,
            &attendee,
            &room_group,
            roster.as_ref(),
            owners.as_ref(),
        )
        .await?;
        let id = call_id_for_room(room);
        let group_id = call_group_id(id);
        let scope = CohortScope::Cohort {
            cohort_id: room.to_owned(),
        };
        let share_registrar = Arc::clone(&registrar);
        let share_events = events.clone();
        let (stream, join_nonce, epoch, publisher, keep) =
            start_stream(room, own_key_id, &room_group, opts.keep, registrar, events).await?;
        let own_key = mint_own_key(
            &signer,
            room,
            join_nonce,
            stream,
            epoch,
            opts.codecs,
            None,
            crate::transport::av_chunk_auth::STREAM_KIND_MEDIA,
        )
        .await?;

        // Addresses: the call's group, from the room's destination secret at
        // the room's epoch, for the room's members.
        let snapshot = room_snapshot(&room_group, &group_id, &members).await?;
        lifecycle
            .install(&scope, &snapshot)
            .map_err(|e| CallError::Plumbing(format!("call addresses: {e}")))?;

        let router = transport
            .av_call_router()
            .map_err(|e| CallError::Plumbing(e.to_string()))?;
        let arrivals = router.register(&group_id);

        let members_for_alm = members.clone();
        let alm_seed = {
            let mut b = [0u8; 8];
            ciris_crypto::random::fill(&mut b)
                .map_err(|e| CallError::Plumbing(format!("ALM seed: {e}")))?;
            u64::from_le_bytes(b)
        };
        let (heard_tx, heard_rx) = mpsc::channel::<Heard>(1024);
        let (frames_tx, frames_rx) = mpsc::channel::<ReceivedFrame>(256);
        let (events_tx, events_rx) = mpsc::channel::<CallEvent>(64);
        let caps_withheld = transport.av_caps_withheld_for_test();
        let layer_requests = transport.av_layer_requests_enabled();
        let shared = Arc::new(Shared {
            room: room.to_owned(),
            own: own_key_id.to_owned(),
            scope,
            group_id,
            opts,
            room_group: room_group.clone(),
            transport,
            lifecycle,
            publisher: Mutex::new(publisher),
            keys: KeyRing {
                room_group,
                held: StdMutex::new(HashMap::new()),
            },
            out_legs: StdMutex::new(HashMap::new()),
            dialling: StdMutex::new(HashMap::new()),
            backoff: StdMutex::new(HashMap::new()),
            in_links: StdMutex::new(HashMap::new()),
            policies: StdMutex::new(HashMap::new()),
            members: StdMutex::new(members.clone()),
            resolved: StdMutex::new((leaves_at_join, members)),
            owners,
            heard_tx,
            events_tx,
            state: StdMutex::new(CallState::Live),
            epochs: StdMutex::new(vec![epoch.0]),
            ended: AtomicBool::new(false),
            published: AtomicU64::new(0),
            metrics,
            test_relay_delay_ms: AtomicU64::new(0),
            test_withhold: StdMutex::new(None),
            test_withhold_forward: StdMutex::new(None),
            record,
            attendee,
            attendees_known: StdMutex::new(std::collections::BTreeSet::new()),
            record_refused: AtomicBool::new(false),
            id,
            signer,
            verifier,
            own_key: StdMutex::new(own_key),
            attendance: StdMutex::new(Attendance::default()),
            pending_replace: StdMutex::new(None),
            frame_seqs: StdMutex::new(HashMap::new()),
            frames_lost: Arc::new(StdMutex::new(BTreeMap::new())),
            layer_view: AtomicU64::new(0),
            primary_ended: AtomicBool::new(false),
            shares: Mutex::new(BTreeMap::new()),
            registrar: share_registrar,
            av_events: share_events,
            auth: ChunkAuth::new(room),
            alm: StdMutex::new({
                let mut a =
                    alm::AlmState::new(own_key_id, stream, &members_for_alm, opts.relay, alm_seed);
                a.withhold_caps(caps_withheld);
                a.set_layer_requests(layer_requests);
                a
            }),
            in_senders: StdMutex::new(HashMap::new()),
            leg_ttl: StdMutex::new(HashMap::new()),
            leg_cong: StdMutex::new(HashMap::new()),
            queue_age_ms: AtomicU64::new(0),
            load,
            setup_began: std::time::Instant::now(),
            setup_done: AtomicBool::new(false),
            summary_done: AtomicBool::new(false),
            c3_reported: AtomicU64::new(0),
            test_stall_until: StdMutex::new(None),
            test_fail_c3: AtomicU64::new(0),
        });
        if let KeepOutcome::Refused(refused) = keep {
            shared.emit(CallEvent::KeepRefused {
                epoch: refused.epoch,
                reason: refused.kind,
            });
        }
        if let Some(m) = &shared.metrics {
            m.telemetry.call_began();
        }
        tracing::info!(
            room = %room,
            stream = %crate::transport::realtime_av::stream_label(stream),
            epoch = epoch.0,
            relay = opts.relay,
            "CALL JOINED: this node's stream is live in the room's call (CIRISEdge#805 item 5)"
        );

        Shared::lock(&shared.attendees_known).insert(shared.attendee.clone());
        write_call_row(&shared).await;

        let counts = Arc::new(StdMutex::new(ReorderCounts::default()));
        let tasks = vec![
            tokio::spawn(accept_loop(Arc::clone(&shared), arrivals)),
            tokio::spawn(reorder_loop(
                Arc::clone(&shared),
                heard_rx,
                frames_tx,
                Arc::clone(&counts),
            )),
            tokio::spawn(watch_loop(Arc::clone(&shared))),
        ];
        reconcile_legs(&shared);
        Ok(Self {
            id,
            shared,
            router,
            frames_rx: Some(frames_rx),
            events_rx: Some(events_rx),
            counts,
            tasks,
        })
    }

    /// The call's handle.
    #[must_use]
    pub fn id(&self) -> CallId {
        self.id
    }

    /// The room.
    #[must_use]
    pub fn room(&self) -> &str {
        &self.shared.room
    }

    /// This node's stream.
    #[must_use]
    pub fn stream(&self) -> StreamId {
        self.shared.stream()
    }

    /// The call's epoch: the room's, as this stream last rolled to it.
    pub async fn epoch(&self) -> Epoch {
        self.shared.publisher.lock().await.epoch()
    }

    /// The largest frame plaintext every member leg carries (#720), or
    /// `None` before any leg is up: each leg's media limit less the chunk's
    /// wire overhead and its source signature.
    ///
    /// The limit is read from the link NOW, so it follows the link's MDU (on
    /// a punched path the probed one, leviculum#104) rather than the 500-byte
    /// base a leg used to be born at: the datagram limit on a leg whose peer
    /// takes datagrams (leviculum#102), else the Channel limit. A leg only
    /// ever moves from the Channel to datagrams, whose limit is the larger,
    /// so a frame sized to an earlier budget still fits.
    #[must_use]
    pub fn chunk_plaintext_budget(&self) -> Option<usize> {
        let legs: Vec<OutLeg> = Shared::lock(&self.shared.out_legs)
            .values()
            .cloned()
            .collect();
        legs.iter()
            .map(|l| {
                let limit = self.shared.transport.av_link_limits(&l.link_id).map_or(
                    l.channel_limit,
                    |(channel, datagram)| {
                        if l.media.uses_datagrams() {
                            datagram
                        } else {
                            channel
                        }
                    },
                );
                limit.saturating_sub(AV_CHUNK_WIRE_OVERHEAD + CHUNK_TRAILER_LEN)
            })
            .min()
    }

    /// The codec map `stream`'s verified v2 binding named on this node, or
    /// `None` when only v1 bindings (or none) came.
    #[must_use]
    pub fn stream_codecs(
        &self,
        stream: StreamId,
    ) -> Option<crate::transport::av_chunk_auth::CodecMap> {
        self.shared.auth.codecs_of(stream)
    }

    /// What the chunk source authentication counted on this node: chunks
    /// verified, forged and unbound, bindings installed and refused.
    #[must_use]
    pub fn chunk_auth_counts(&self) -> crate::transport::av_chunk_auth::ChunkAuthCounts {
        self.shared.auth.counts()
    }

    /// ALM stage 2 — every other member's stream with the parents this node
    /// chose for it (the publisher itself, or a member relay).
    #[must_use]
    pub fn alm_parents(&self) -> Vec<AlmParents> {
        Shared::lock(&self.shared.alm).parents()
    }

    /// ALM stage 2 — who holds a commitment on this node's own stream.
    #[must_use]
    pub fn alm_own_children(
        &self,
    ) -> Vec<(String, crate::transport::realtime_av_alm::controller::Role)> {
        Shared::lock(&self.shared.alm).own_children()
    }

    /// ALM stage 2 — who this node forwards `stream` to (admitted, or
    /// draining after a make-before-break shed).
    #[must_use]
    pub fn alm_relay_children(
        &self,
        stream: StreamId,
    ) -> Vec<(String, crate::transport::realtime_av_alm::controller::Role)> {
        Shared::lock(&self.shared.alm).relay_children(stream)
    }

    /// `FSD/CIRIS_MESH.md` §7.4 — the call's `load_ledger` A/V rows: bits/s
    /// committed to this node's own stream and to the streams it relays.
    #[must_use]
    pub fn alm_committed(&self) -> (u64, u64) {
        Shared::lock(&self.shared.alm).committed()
    }

    /// ALM stage 2 — what the controller counted on this call.
    #[must_use]
    pub fn alm_counts(&self) -> AlmCounts {
        Shared::lock(&self.shared.alm).counts.clone()
    }

    /// ALM C7 — the decision log's chained hash, record count and rendered
    /// tail (a field failure replays from it).
    #[must_use]
    pub fn alm_log(&self) -> (String, u64, String) {
        let a = Shared::lock(&self.shared.alm);
        (a.log_hash(), a.log_len(), a.log_tail())
    }

    /// ALM C7 — decision-log records of one kind.
    #[must_use]
    pub fn alm_log_count(
        &self,
        kind: crate::transport::realtime_av_alm::controller::DecisionKind,
    ) -> u64 {
        Shared::lock(&self.shared.alm).log_count(kind)
    }

    /// ALM — the members that said they speak C3.
    #[must_use]
    pub fn alm_c3_peers(&self) -> Vec<String> {
        let a = Shared::lock(&self.shared.alm);
        Shared::lock(&self.shared.members)
            .iter()
            .filter(|m| a.speaks_c3(m))
            .cloned()
            .collect()
    }

    /// `FSD/CIRIS_MESH.md` §7 — the service tier this call runs at.
    #[must_use]
    pub fn service_tier(&self) -> crate::load_ladder::ServiceTier {
        Shared::lock(&self.shared.alm).tier()
    }

    /// Every leg this node has, with what carries it (a punched direct UDP
    /// path, a forwarder, or the one-hop interface it rides), its link MDU,
    /// its media limit (the datagram limit on a datagram leg, else the
    /// Channel limit) and the frame budget that limit implies. Sorted by
    /// member. A leg whose link leviculum no longer holds reads
    /// [`LegPath::Gone`] with zeros.
    #[must_use]
    pub fn leg_info(&self) -> Vec<LegInfo> {
        let legs: Vec<(String, OutLeg)> = Shared::lock(&self.shared.out_legs)
            .iter()
            .map(|(m, l)| (m.clone(), l.clone()))
            .collect();
        let mut v: Vec<LegInfo> = legs
            .into_iter()
            .map(|(member, l)| {
                let datagrams = l.media.uses_datagrams();
                let path = self.shared.transport.av_link_path(&l.link_id);
                let limits = self.shared.transport.av_link_limits(&l.link_id);
                let (path, link_mdu) = path.unwrap_or((LegPath::Gone, 0));
                let (channel_limit, media_limit) =
                    limits.map_or((0, 0), |(c, d)| (c, if datagrams { d } else { c }));
                LegInfo {
                    member,
                    path,
                    link_mdu,
                    channel_limit,
                    media_limit,
                    frame_budget: media_limit
                        .saturating_sub(AV_CHUNK_WIRE_OVERHEAD + CHUNK_TRAILER_LEN),
                    datagrams,
                }
            })
            .collect();
        v.sort_by(|a, b| a.member.cmp(&b.member));
        v
    }

    /// v45 — ask this node's parents for `stream` (the publisher, or the
    /// member relay this node hears it through) for at most `cap`
    /// (`(spatial, temporal, quality)` maxima; `None` withdraws). The cap
    /// rides the tree's own SUBSCRIBE (CC 5.3.3.4): the current primary gets
    /// a re-SUBSCRIBE now, and every later SUBSCRIBE carries it, only to a
    /// parent whose `CAPS` say it takes one (the host's lever, off by
    /// default). Codec-opaque (audio) chunks pass every cap; there is no
    /// audio-only cap (it would go below the base cell, CC 5.3.3.2.4).
    /// Returns whether a SUBSCRIBE went out now.
    pub async fn request_layers(&self, stream: StreamId, cap: Option<ReceiverLayerPolicy>) -> bool {
        self.shared.layer_view.fetch_add(1, Ordering::AcqRel);
        let out = Shared::lock(&self.shared.alm).request_layers(stream, cap);
        let sent = !out.is_empty();
        send_alm(&self.shared, out).await;
        sent
    }

    /// leviculum#102 — whether this node's media to `member` rides unordered
    /// datagrams (the member's `CAPS` said it takes them), or `None` when no
    /// leg to it is up.
    #[must_use]
    pub fn leg_uses_datagrams(&self, member: &str) -> Option<bool> {
        Shared::lock(&self.shared.out_legs)
            .get(member)
            .map(|l| l.media.uses_datagrams())
    }

    /// Test seam — the link of this node's leg to `member`, when one is up.
    #[doc(hidden)]
    #[must_use]
    pub fn leg_link_for_test(&self, member: &str) -> Option<[u8; 16]> {
        Shared::lock(&self.shared.out_legs)
            .get(member)
            .map(|l| l.link_id)
    }

    /// The members this node has a leg to.
    #[must_use]
    pub fn legs(&self) -> Vec<String> {
        let mut v: Vec<String> = Shared::lock(&self.shared.out_legs)
            .keys()
            .cloned()
            .collect();
        v.sort();
        v
    }

    /// **Seal once and fan out** (§4). Rolls first if the room's epoch moved
    /// (never seals under a stale epoch), then refuses a frame over the budget
    /// BEFORE sealing: no `chunk_seq` and no nonce are consumed by a refused
    /// frame.
    ///
    /// # Errors
    /// [`CallError::CallEnded`], [`CallError::NoBudget`],
    /// [`CallError::FrameTooLarge`], [`CallError::Plumbing`].
    pub async fn publish(&mut self, frame: Frame) -> Result<PublishReport, CallError> {
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        roll_if_moved(&self.shared).await?;
        apply_pending_replace(&self.shared, false).await?;
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        if self.shared.primary_ended.load(Ordering::Acquire) {
            return Err(CallError::UnknownStream(hex::encode(
                self.shared.stream().0,
            )));
        }
        let budget = self.chunk_plaintext_budget().ok_or(CallError::NoBudget)?;
        let mut publisher = self.shared.publisher.lock().await;
        let (stream, framing) = {
            let k = Shared::lock(&self.shared.own_key);
            (k.stream, k.framing)
        };
        let fseq = next_frame_seq(&self.shared, stream, &frame);
        let pieces = frame_pieces(&frame, framing, budget, fseq)?;
        // The source signature, under this epoch's chunk key (swapped only
        // under this same lock, at the roll).
        let sealed = {
            let k = Shared::lock(&self.shared.own_key);
            seal_pieces(&mut publisher, &k.signer, &frame, &pieces)?
        };
        took_frame_seq(&self.shared, stream, &frame, framing, fseq);
        let epoch = publisher.epoch();
        let chunk_seq = sealed[0].0;
        let withhold = Shared::lock(&self.shared.test_withhold).clone();
        let legs = send_pieces(
            &self.shared,
            &mut publisher,
            stream,
            &frame,
            &pieces,
            &sealed,
            withhold.as_ref(),
        )
        .await?;
        drop(publisher);
        Ok(PublishReport {
            epoch,
            chunk_seq,
            legs,
            fragments: u16::try_from(sealed.len()).unwrap_or(u16::MAX),
        })
    }

    /// Every other member's frames, deduped across legs and in
    /// `(epoch, chunk_seq)` order per stream (§4). Once: the call owns one
    /// frame stream.
    pub fn frames(&mut self) -> Option<mpsc::Receiver<ReceivedFrame>> {
        self.frames_rx.take()
    }

    /// Typed call events (§5, §8). Once.
    pub fn events(&mut self) -> Option<mpsc::Receiver<CallEvent>> {
        self.events_rx.take()
    }

    /// Cap what this node sends `subscriber` (its own stream and, as a relay,
    /// the streams it forwards) at `policy`.
    ///
    /// # Errors
    /// [`CallError::NotARoomMember`] when `subscriber` is not in the room.
    pub async fn set_layer_policy(
        &mut self,
        subscriber: &str,
        policy: ReceiverLayerPolicy,
    ) -> Result<(), CallError> {
        if !Shared::lock(&self.shared.members)
            .iter()
            .any(|m| m == subscriber)
        {
            return Err(CallError::NotARoomMember {
                key_id: subscriber.to_owned(),
                room: self.shared.room.clone(),
            });
        }
        Shared::lock(&self.shared.policies).insert(subscriber.to_owned(), policy);
        self.shared
            .publisher
            .lock()
            .await
            .dispatcher_mut()
            .set_layer_policy(&subscriber.to_owned(), policy);
        Ok(())
    }

    /// Test seam: the next chunk's epoch-local sequence number.
    #[doc(hidden)]
    pub async fn next_chunk_seq_for_test(&self) -> ChunkSeq {
        self.shared
            .publisher
            .lock()
            .await
            .publisher()
            .next_chunk_seq()
    }

    /// Test seam: hold every copy this node relays for `delay`.
    #[doc(hidden)]
    pub fn delay_relay_for_test(&self, delay: Duration) {
        self.shared.test_relay_delay_ms.store(
            u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Test seam: stall every inbound pump for `d` (a consumer that falls
    /// behind, so queued media ages past [`MEDIA_STALE_BUDGET`]).
    #[doc(hidden)]
    pub fn stall_inbound_for_test(&self, d: Duration) {
        *Shared::lock(&self.shared.test_stall_until) = Some(Instant::now() + d);
    }

    /// Test seam: the next `n` must-arrive C3 frames this node sends fail their
    /// first attempt, as a congested link refuses them.
    #[doc(hidden)]
    pub fn fail_next_c3_for_test(&self, n: u64) {
        self.shared.test_fail_c3.store(n, Ordering::Relaxed);
    }

    /// Test seam: send one encoded C3 frame to `member` through the call's own
    /// C3 path, whatever this node would itself say (a member that lies).
    #[doc(hidden)]
    pub async fn send_c3_for_test(&self, member: &str, frame: Vec<u8>) {
        send_alm(
            &self.shared,
            vec![alm::Outgoing {
                to: member.to_owned(),
                frame,
            }],
        )
        .await;
    }

    /// Test seam: re-send this stream's binding on every leg now, as the
    /// periodic re-announce does.
    #[doc(hidden)]
    pub async fn reannounce_for_test(&self) {
        reannounce(&self.shared).await;
    }

    /// Test seam: withhold every `every`th own chunk from `member`'s leg.
    #[doc(hidden)]
    pub fn withhold_from_for_test(&self, member: &str, every: u64) {
        *Shared::lock(&self.shared.test_withhold) = Some((member.to_owned(), every));
    }

    /// Test seam: withhold every `every`th chunk this node FORWARDS from
    /// `member`'s leg (`0` stops it).
    #[doc(hidden)]
    pub fn withhold_forward_for_test(&self, member: &str, every: u64) {
        *Shared::lock(&self.shared.test_withhold_forward) = Some((member.to_owned(), every));
    }

    /// Test seam: close this node's leg to `member` and leave it down, as a
    /// path that really died: nothing re-dials it.
    #[doc(hidden)]
    pub async fn close_leg_for_test(&self, member: &str) {
        Shared::lock(&self.shared.dialling)
            .insert(member.to_owned(), Instant::now() + Duration::from_hours(1));
        let link = Shared::lock(&self.shared.out_legs)
            .get(member)
            .map(|l| l.link_id);
        if let Some(link) = link {
            let _ = self.shared.transport.link_teardown(&link).await;
        }
    }

    /// **Who attended** (item 6): the union of the subjects of every row of
    /// this call, plus this node's own attendance. A leaver stays.
    pub async fn attendees(&self) -> Vec<String> {
        self.attendance().await.attendees
    }

    /// [`Self::attendees`] with the call's start (its earliest row).
    pub async fn attendance(&self) -> CallAttendance {
        let mut a = match &self.shared.record {
            Some(r) => r
                .attendance(&self.shared.room, self.id)
                .await
                .unwrap_or_default(),
            None => CallAttendance::default(),
        };
        if !a.attendees.contains(&self.shared.attendee) {
            a.attendees.push(self.shared.attendee.clone());
            a.attendees.sort();
        }
        a
    }

    /// Where the call stands.
    #[must_use]
    pub fn state(&self) -> CallState {
        Shared::lock(&self.shared.state).clone()
    }

    /// v45 (Eric 2026-11-10) — frames this node never handed out, per (codec
    /// class, layer `(s, t, q)`): gaps in the framed streams' `frame_seq` on
    /// layers this node was being sent at both ends of the gap. A base-layer
    /// entry (`(0, 0, 0)`) is a freeze until the next keyframe. Audio (`0xFF`)
    /// is concealed by time and never counted here.
    #[must_use]
    pub fn frames_lost_by_layer(&self) -> BTreeMap<(u8, (u8, u8, u8)), u64> {
        Shared::lock(&self.shared.frames_lost).clone()
    }

    /// The reorder window's counters so far.
    #[must_use]
    pub fn reorder_counts(&self) -> ReorderCounts {
        *Shared::lock(&self.counts)
    }

    /// v45 — **publish a second stream** beside the camera (a desktop or
    /// window share; CC reading (rc17): a share is a second stream with no
    /// `replaces`). It has its own join nonce and stream id, its own sealing
    /// session (epoch DEK, chunk counter), chunk key and v1/v2 bindings, and
    /// its own codec map (`None`: none, v1 only). Its bindings go out on every
    /// leg before this returns, so its first chunk never beats its key. ALM
    /// takes it as a parent-0 admission of its own: its subscribers and its
    /// shedding are apart from the camera's. Publish on it with
    /// [`Self::publish_on`], end it with [`Self::end_stream`]. At most
    /// [`MAX_OWN_STREAMS`] own streams at once.
    ///
    /// # Errors
    /// [`CallError::CallEnded`]; [`CallError::TooManyStreams`];
    /// [`CallError::RoomGroupUnavailable`] when the stream's DEK cannot be
    /// derived; [`CallError::Plumbing`].
    pub async fn add_stream(
        &self,
        codecs: Option<crate::transport::av_chunk_auth::CodecMap>,
    ) -> Result<StreamId, CallError> {
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        roll_if_moved(&self.shared).await?;
        let shared = &self.shared;
        // Lock order: the primary publisher, then the shares. Under both, no
        // roll lands between the binding and the share's first chunk.
        let mut publisher = shared.publisher.lock().await;
        let mut shares = shared.shares.lock().await;
        let own = 1 + shares.len();
        if own >= MAX_OWN_STREAMS {
            return Err(CallError::TooManyStreams(own));
        }
        let (join_nonce, stream) = fresh_stream(&shared.room, &shared.own)?;
        let epoch = publisher.epoch();
        let dek = stream_epoch_dek(&shared.room_group, stream, epoch)
            .await
            .map_err(|e| CallError::RoomGroupUnavailable {
                room: shared.room.clone(),
                detail: e.to_string(),
            })?;
        let (share, keep) = KeptAvPublisher::create_room_keyed(
            stream,
            &shared.room,
            epoch,
            dek,
            shared.opts.keep,
            AvKeepTarget {
                cohort_scope: "community".to_owned(),
                group_key_id: shared.room.clone(),
            },
            Arc::clone(&shared.registrar),
            shared.av_events.clone(),
        )
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
        let key = mint_own_key(
            &shared.signer,
            &shared.room,
            join_nonce,
            stream,
            epoch,
            codecs,
            None,
            crate::transport::av_chunk_auth::STREAM_KIND_SHARE,
        )
        .await?;
        send_bindings_on(shared, &mut publisher, &key.wire, key.wire_v2.as_ref()).await;
        shares.insert(
            stream,
            ShareStream {
                publisher: share,
                key,
            },
        );
        drop(shares);
        drop(publisher);
        Shared::lock(&shared.alm).add_own_stream(stream);
        tracing::info!(
            stream = %crate::transport::realtime_av::stream_label(stream),
            "CALL STREAM ADDED: this node publishes a second stream (v45)"
        );
        if let KeepOutcome::Refused(r) = keep {
            shared.emit(CallEvent::KeepRefused {
                epoch: r.epoch,
                reason: r.kind,
            });
        }
        Ok(stream)
    }

    /// v45 — [`Self::publish`] on one of this node's own streams: the
    /// primary (`self.stream()`, the same as `publish`) or a share
    /// ([`Self::add_stream`]).
    ///
    /// # Errors
    /// As [`Self::publish`]; [`CallError::UnknownStream`] for a stream this
    /// node does not publish.
    pub async fn publish_on(
        &mut self,
        stream: StreamId,
        frame: Frame,
    ) -> Result<PublishReport, CallError> {
        if stream == self.shared.stream() {
            return self.publish(frame).await;
        }
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        roll_if_moved(&self.shared).await?;
        let budget = self.chunk_plaintext_budget().ok_or(CallError::NoBudget)?;
        // Lock order: the primary, then the shares. Sealed and signed under
        // the shares lock (a roll swaps a share's epoch and key together
        // under it), sent under the primary's.
        let mut publisher = self.shared.publisher.lock().await;
        let (pieces, sealed, epoch) = {
            let mut shares = self.shared.shares.lock().await;
            let share = shares
                .get_mut(&stream)
                .ok_or_else(|| CallError::UnknownStream(hex::encode(stream.0)))?;
            let to = publisher.epoch();
            if share.publisher.epoch() < to {
                if let KeepOutcome::Refused(r) =
                    roll_share(&self.shared, &mut publisher, share, to).await?
                {
                    self.shared.emit(CallEvent::KeepRefused {
                        epoch: r.epoch,
                        reason: r.kind,
                    });
                }
            }
            let fseq = next_frame_seq(&self.shared, stream, &frame);
            let pieces = frame_pieces(&frame, share.key.framing, budget, fseq)?;
            let sealed = seal_pieces(&mut share.publisher, &share.key.signer, &frame, &pieces)?;
            took_frame_seq(&self.shared, stream, &frame, share.key.framing, fseq);
            (pieces, sealed, share.publisher.epoch())
        };
        let chunk_seq = sealed[0].0;
        let legs = send_pieces(
            &self.shared,
            &mut publisher,
            stream,
            &frame,
            &pieces,
            &sealed,
            None,
        )
        .await?;
        drop(publisher);
        Ok(PublishReport {
            epoch,
            chunk_seq,
            legs,
            fragments: u16::try_from(sealed.len()).unwrap_or(u16::MAX),
        })
    }

    /// v45 — **end one share** ([`Self::add_stream`]) and only it: its
    /// signed end (a v2 binding with `end = 3`, "this stream ended", never a
    /// leave, and `final_seq`) goes to every leg
    /// that parses v2, and the share stops. The camera and the call carry on;
    /// a receiver reads [`CallEvent::StreamEnded`], never `AttendeeLeft`,
    /// while the member has another stream. The primary ends only with the
    /// call ([`Self::leave_with`]). Returns once every leg proved the end
    /// delivered (or [`END_FLUSH_CEILING`] passed, counted).
    ///
    /// # Errors
    /// [`CallError::CallEnded`]; [`CallError::UnknownStream`] for the primary
    /// or a stream this node does not publish; [`CallError::Plumbing`].
    pub async fn end_stream(&self, stream: StreamId) -> Result<(), CallError> {
        self.end_stream_as(stream, crate::transport::av_chunk_auth::SignedEnd::Ended)
            .await
    }

    /// v45 — [`Self::end_stream`] saying `why`. For a share, any value. For
    /// the camera (the primary), only while a share is live: a phone sharing
    /// its screen backgrounds its camera (`Backgrounded`, `end = 2`), which a
    /// receiver reads as [`CallEvent::StreamEnded`] for the camera while the
    /// share plays on (a leave value counts as a leave only on a member's
    /// last stream). The camera then takes no more frames ([`Self::publish`]
    /// is [`CallError::UnknownStream`]); the call ends with [`Self::leave`].
    ///
    /// # Errors
    /// As [`Self::end_stream`]; [`CallError::UnknownStream`] for the camera
    /// with no share live, or already ended.
    pub async fn end_stream_as(
        &self,
        stream: StreamId,
        why: crate::transport::av_chunk_auth::SignedEnd,
    ) -> Result<(), CallError> {
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        let wire = if stream == self.shared.stream() {
            let live_share = !self.shared.shares.lock().await.is_empty();
            if !live_share || self.shared.primary_ended.load(Ordering::Acquire) {
                return Err(CallError::UnknownStream(hex::encode(stream.0)));
            }
            // Under the publisher lock (sign_end takes it for final_seq), no
            // camera chunk follows the end.
            let wire = sign_end(&self.shared, why).await?;
            self.shared.primary_ended.store(true, Ordering::Release);
            wire
        } else {
            let mut shares = self.shared.shares.lock().await;
            let share = shares
                .get(&stream)
                .ok_or_else(|| CallError::UnknownStream(hex::encode(stream.0)))?;
            let final_seq = share
                .publisher
                .next_chunk_seq()
                .0
                .checked_sub(1)
                .unwrap_or(crate::transport::av_chunk_auth::FINAL_SEQ_NONE);
            let wire = sign_end_of(&self.shared, &share.key, final_seq, why).await?;
            shares.remove(&stream);
            Shared::lock(&self.shared.alm).remove_own_stream(stream);
            wire
        };
        let not_v2 = legs_without_binding_v2(&self.shared).await;
        send_binding_paced(&self.shared, &wire, &not_v2, None).await;
        let legs: Vec<[u8; 16]> = {
            let not_v2: std::collections::HashSet<&String> = not_v2.iter().collect();
            Shared::lock(&self.shared.out_legs)
                .iter()
                .filter(|(m, _)| !not_v2.contains(m))
                .map(|(_, l)| l.link_id)
                .collect()
        };
        let marks = channel_marks(&self.shared, &legs);
        let unconfirmed = await_delivered(&self.shared, &marks, END_FLUSH_CEILING).await;
        for _ in 0..unconfirmed {
            self.shared
                .count(crate::observability::AV_CALL_END_FLUSH_UNCONFIRMED);
        }
        tracing::info!(
            stream = %crate::transport::realtime_av::stream_label(stream),
            ?why,
            unconfirmed,
            "CALL STREAM ENDED: one own stream stopped, the call carries on (v45)"
        );
        Ok(())
    }

    /// v45 — every stream this node publishes in the call: the primary
    /// first, then the shares.
    pub async fn streams(&self) -> Vec<StreamId> {
        let mut out = vec![self.shared.stream()];
        out.extend(self.shared.shares.lock().await.keys().copied());
        out
    }

    /// v45 — **replace this node's stream in place** (a codec change, say):
    /// a fresh join nonce and stream within the same membership, bound first
    /// and switched to once every leg's Channel proved them delivered
    /// (ceiling [`REPLACE_SWITCH_CEILING`]; make-before-break: the old
    /// stream carries on meanwhile), then the old one stops. Its v2 binding
    /// says `replaces: <old>` under the publisher's signature, the only way a
    /// receiver learns it ([`CallEvent::StreamReplaced`], no leave). `codecs`
    /// is the new stream's map (`None`: the old one's). The four-newest-
    /// streams rule bounds it at receivers. Returns the new stream.
    ///
    /// # Errors
    /// [`CallError::CallEnded`]; [`CallError::RoomGroupUnavailable`] when the
    /// new stream's DEK cannot be derived; [`CallError::Plumbing`].
    pub async fn replace_stream(
        &mut self,
        codecs: Option<crate::transport::av_chunk_auth::CodecMap>,
    ) -> Result<StreamId, CallError> {
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        let shared = Arc::clone(&self.shared);
        // One replacement at a time: a second one first lands the first.
        apply_pending_replace(&shared, true).await?;
        let mut publisher = shared.publisher.lock().await;
        let epoch = publisher.epoch();
        let (old, codecs) = {
            let k = Shared::lock(&shared.own_key);
            (k.stream, codecs.or(k.codecs))
        };
        let (join_nonce, stream) = fresh_stream(&shared.room, &shared.own)?;
        let dek = stream_epoch_dek(&shared.room_group, stream, epoch)
            .await
            .map_err(|e| CallError::RoomGroupUnavailable {
                room: shared.room.clone(),
                detail: e.to_string(),
            })?;
        let own_key = mint_own_key(
            &shared.signer,
            &shared.room,
            join_nonce,
            stream,
            epoch,
            codecs,
            Some(old),
            crate::transport::av_chunk_auth::STREAM_KIND_MEDIA,
        )
        .await?;
        // Make: every leg that parses v2 learns the new stream's `replaces`
        // and framing first, then every leg its key (v1), before its first
        // chunk.
        let wire = Arc::clone(&own_key.wire);
        let wire_v2 = own_key.wire_v2.clone();
        send_bindings_on(&shared, &mut publisher, &wire, wire_v2.as_ref()).await;
        drop(publisher);
        // Break, once every leg's Channel proved the bindings delivered (the
        // old stream publishing meanwhile): publish and the watch tick
        // switch when `ready` is set.
        let ready = Arc::new(AtomicBool::new(false));
        *Shared::lock(&shared.pending_replace) = Some(PendingReplace {
            own_key,
            dek,
            ready: Arc::clone(&ready),
        });
        let legs: Vec<[u8; 16]> = Shared::lock(&shared.out_legs)
            .values()
            .map(|l| l.link_id)
            .collect();
        let marks = channel_marks(&shared, &legs);
        let s = Arc::clone(&shared);
        tokio::spawn(async move {
            let unconfirmed = await_delivered(&s, &marks, REPLACE_SWITCH_CEILING).await;
            for _ in 0..unconfirmed {
                s.count(crate::observability::AV_CALL_REPLACE_SWITCH_UNCONFIRMED);
            }
            ready.store(true, Ordering::Release);
            let _ = apply_pending_replace(&s, false).await;
        });
        Ok(stream)
    }

    /// **Hang up** (§7: an in-room hang-up writes nothing): the signed end of this
    /// node's stream (`Left`, see [`Self::leave_with`]), then close its legs,
    /// stop listening at the call's addresses, end.
    ///
    /// # Errors
    /// [`CallError::CallEnded`] when it already ended.
    pub async fn leave(self) -> Result<CallSummary, CallError> {
        self.leave_with(crate::transport::av_chunk_auth::SignedEnd::Left)
            .await
    }

    /// v45 — [`Self::leave`], saying why: the publisher's signed end of its
    /// stream (a v2 binding with `end`, the one thing a receiver turns into
    /// [`CallEvent::AttendeeLeft`] `Left` / `Backgrounded`) goes to every leg
    /// whose peer parses v2 bindings, then the legs close. A peer that does
    /// not parse v2 sees the attendee `Lost` once [`ATTENDEE_LOST_AFTER`]
    /// passes.
    ///
    /// # Errors
    /// As [`Self::leave`].
    pub async fn leave_with(
        mut self,
        why: crate::transport::av_chunk_auth::SignedEnd,
    ) -> Result<CallSummary, CallError> {
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        // v45 — each share ends first (`end = 3`), then the primary with the
        // leave's own value: a receiver reads the shares as `StreamEnded` and
        // the last stream as `AttendeeLeft`.
        let mut share_ends = Vec::new();
        let shares = std::mem::take(&mut *self.shared.shares.lock().await);
        // With the camera already ended, the last share carries the leave.
        let camera_ended = self.shared.primary_ended.load(Ordering::Acquire);
        let last = shares.keys().next_back().copied();
        for (stream, share) in shares {
            let final_seq = share
                .publisher
                .next_chunk_seq()
                .0
                .checked_sub(1)
                .unwrap_or(crate::transport::av_chunk_auth::FINAL_SEQ_NONE);
            let ended = if camera_ended && Some(stream) == last {
                why
            } else {
                crate::transport::av_chunk_auth::SignedEnd::Ended
            };
            match sign_end_of(&self.shared, &share.key, final_seq, ended).await {
                Ok(w) => share_ends.push(w),
                Err(e) => tracing::warn!(
                    stream = %crate::transport::realtime_av::stream_label(stream),
                    error = %e,
                    "call: a share's signed end could not be made"
                ),
            }
        }
        let primary_end = if self.shared.primary_ended.load(Ordering::Acquire) {
            None
        } else {
            Some(sign_end(&self.shared, why).await)
        };
        match primary_end.unwrap_or_else(|| Ok(Arc::new(Vec::new()))) {
            Ok(wire) => {
                let not_v2 = legs_without_binding_v2(&self.shared).await;
                for w in &share_ends {
                    send_binding_paced(&self.shared, w, &not_v2, None).await;
                }
                if !wire.is_empty() {
                    send_binding_paced(&self.shared, &wire, &not_v2, None).await;
                }
                // Close once each leg's Channel proved the end delivered (a
                // datagram leg's too: the end rides its Channel).
                let legs: Vec<[u8; 16]> = {
                    let not_v2: std::collections::HashSet<&String> = not_v2.iter().collect();
                    Shared::lock(&self.shared.out_legs)
                        .iter()
                        .filter(|(m, _)| !not_v2.contains(m))
                        .map(|(_, l)| l.link_id)
                        .collect()
                };
                let marks = channel_marks(&self.shared, &legs);
                let unconfirmed = await_delivered(&self.shared, &marks, END_FLUSH_CEILING).await;
                for _ in 0..unconfirmed {
                    self.shared
                        .count(crate::observability::AV_CALL_END_FLUSH_UNCONFIRMED);
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "call: the signed end of this stream could not be made; peers will read \
                 the attendee as lost"
            ),
        }
        *Shared::lock(&self.shared.state) = CallState::Ended(EndCause::HungUp);
        self.shared.ended.store(true, Ordering::Relaxed);
        self.shared.book_end("hung_up");
        self.router.unregister(&self.shared.group_id);
        let legs: Vec<[u8; 16]> = Shared::lock(&self.shared.out_legs)
            .drain()
            .map(|(_, l)| l.link_id)
            .collect();
        let ins: Vec<[u8; 16]> = Shared::lock(&self.shared.in_links)
            .drain()
            .map(|(l, _)| l)
            .collect();
        for l in legs.iter().chain(ins.iter()) {
            let _ = self.shared.transport.link_teardown(l).await;
        }
        let _ = self
            .shared
            .lifecycle
            .leave(&self.shared.scope, &self.shared.group_id);
        for t in self.tasks.drain(..) {
            t.abort();
        }
        let counts = self.reorder_counts();
        tracing::info!(
            room = %self.shared.room,
            published = self.shared.published.load(Ordering::Relaxed),
            "CALL LEFT: this node's stream ended (CIRISEdge#805 item 5)"
        );
        Ok(CallSummary {
            id: self.id,
            stream: self.shared.stream(),
            epochs: Shared::lock(&self.shared.epochs).clone(),
            frames_published: self.shared.published.load(Ordering::Relaxed),
            frames_received: counts.released,
            frames_skipped: counts.skipped,
            duplicates: counts.duplicates,
        })
    }
}

/// §3.3 — joining is presence, not admission: `own_key_id` must be a call
/// member ([`call_members`]: a leaf of the room's MLS group itself, or a node
/// whose verified owner is one), the attendee it acts for must be itself or
/// that owner (a node acts only for its own owner), and the room member it
/// is in the room as must be on persist's active roster. Returns the room's
/// leaves and the call's members.
async fn admit(
    room: &str,
    own_key_id: &str,
    attendee: &str,
    room_group: &CohortGroup,
    roster: &dyn RoomRoster,
    owners: &dyn CallOwners,
) -> Result<(Vec<String>, Vec<String>), CallError> {
    let not_member = |key_id: &str| CallError::NotARoomMember {
        key_id: key_id.to_owned(),
        room: room.to_owned(),
    };
    let leaves = room_group.member_key_ids().await;
    let members =
        call_members(&leaves, owners)
            .await
            .map_err(|detail| CallError::RoomGroupUnavailable {
                room: room.to_owned(),
                detail,
            })?;
    if !members.iter().any(|m| m == own_key_id) {
        return Err(not_member(own_key_id));
    }
    let own_leaf = leaves.iter().any(|m| m == own_key_id);
    // The owner is read only when it is needed, and only persist's binding
    // answers it: an attendee is never taken at its word.
    let owner = if own_leaf && attendee == own_key_id {
        None
    } else {
        owners.owner_of(own_key_id).await
    };
    if !own_leaf && !owner.as_ref().is_some_and(|o| leaves.contains(o)) {
        return Err(not_member(own_key_id));
    }
    if attendee != own_key_id && owner.as_deref() != Some(attendee) {
        // The node would act for a person it is not bound to.
        return Err(not_member(attendee));
    }
    // The roster names the room's member: the attendee, or (a node attending
    // as itself in a room whose leaf is its owner) that owner.
    let principal = if attendee == own_key_id && !own_leaf {
        owner.as_deref().unwrap_or(attendee)
    } else {
        attendee
    };
    let active = roster
        .is_active_member(room, principal)
        .await
        .map_err(|detail| CallError::RoomGroupUnavailable {
            room: room.to_owned(),
            detail: format!("active roster unreadable: {detail}"),
        })?;
    if !active {
        return Err(CallError::ConsentMissing {
            key_id: principal.to_owned(),
            room: room.to_owned(),
        });
    }
    Ok((leaves, members))
}

/// Mint this join's stream (a fresh nonce: a call never reuses a stream) and
/// its room-keyed publisher at the room's current epoch.
async fn start_stream(
    room: &str,
    own_key_id: &str,
    room_group: &CohortGroup,
    keep: AvKeep,
    registrar: Arc<dyn StreamDekRegistrar>,
    events: Option<Arc<crate::events::EventBus>>,
) -> Result<(StreamId, [u8; 32], Epoch, Publisher, KeepOutcome), CallError> {
    let mut join_nonce = [0u8; 32];
    // A stream id whose first bytes read as a binding part or a C3 frame
    // would be taken for one by every receiver: draw again (odds 2^-40 a
    // draw each).
    let stream = loop {
        ciris_crypto::random::fill(&mut join_nonce)
            .map_err(|e| CallError::Plumbing(format!("join nonce: {e}")))?;
        let stream = call_stream_id(room, own_key_id, &join_nonce);
        if !collides_with_binding_part(stream) && !collides_with_control_frame(stream) {
            break stream;
        }
    };
    let epoch = Epoch(room_group.epoch().await);
    let dek = stream_epoch_dek(room_group, stream, epoch)
        .await
        .map_err(|e| CallError::RoomGroupUnavailable {
            room: room.to_owned(),
            detail: e.to_string(),
        })?;
    let (publisher, outcome) = KeptAvPublisher::create_room_keyed(
        stream,
        room,
        epoch,
        dek,
        keep,
        AvKeepTarget {
            cohort_scope: "community".to_owned(),
            group_key_id: room.to_owned(),
        },
        registrar,
        events,
    )
    .await
    .map_err(|e| CallError::Plumbing(e.to_string()))?;
    Ok((stream, join_nonce, epoch, publisher, outcome))
}

/// v45 — `wire` (v1) on every leg of `publisher`, and `wire_v2` on every
/// leg whose peer parses v2.
async fn send_bindings_on(
    shared: &Arc<Shared>,
    publisher: &mut Publisher,
    wire: &Arc<Vec<u8>>,
    wire_v2: Option<&Arc<Vec<u8>>>,
) {
    // CC rc18 — v2 FIRST on every leg that takes it, so its framing is in
    // hand before the epoch's first chunk; then v1 on every leg (a v2 relay
    // keeps it for its v1 children).
    if let Some(v2) = wire_v2 {
        let not_v2 = {
            let legs = publisher.dispatcher_mut().subscriber_ids();
            let a = Shared::lock(&shared.alm);
            legs.into_iter()
                .filter(|l| !a.sends_binding_v2_to(l))
                .collect::<Vec<_>>()
        };
        publisher
            .dispatcher_mut()
            .send_control_report(&not_v2, &|limit| StreamKeyBinding::parts(v2, limit))
            .await;
    }
    publisher
        .dispatcher_mut()
        .send_control_report(&[], &|limit| StreamKeyBinding::parts(wire, limit))
        .await;
}

/// v45 — roll one share to epoch `to`: its new DEK and chunk key, bound on
/// every leg of the primary `publisher` (whose lock the caller holds)
/// before the share's first chunk of `to`. A failure leaves it where it was.
async fn roll_share(
    shared: &Arc<Shared>,
    publisher: &mut Publisher,
    share: &mut ShareStream,
    to: Epoch,
) -> Result<KeepOutcome, CallError> {
    let stream = share.key.stream;
    let dek = stream_epoch_dek(&shared.room_group, stream, to)
        .await
        .map_err(|e| CallError::RoomGroupUnavailable {
            room: shared.room.clone(),
            detail: e.to_string(),
        })?;
    let key = mint_own_key(
        &shared.signer,
        &shared.room,
        share.key.join_nonce,
        stream,
        to,
        share.key.codecs,
        None,
        share.key.kind,
    )
    .await?;
    let keep = share
        .publisher
        .roll_room_epoch(to, dek)
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
    share.key = key;
    send_bindings_on(
        shared,
        publisher,
        &share.key.wire,
        share.key.wire_v2.as_ref(),
    )
    .await;
    Ok(keep)
}

/// v45 — the `frame_seq` the next framed frame of `stream`'s (codec class,
/// layer) takes (from 0). The caller holds the lock that seals the stream.
fn next_frame_seq(shared: &Shared, stream: StreamId, frame: &Frame) -> u32 {
    Shared::lock(&shared.frame_seqs)
        .get(&(stream, frame.codec_id, frame.layer))
        .copied()
        .unwrap_or(0)
}

/// v45 — a framed frame sealed with `fseq`: the class's next is one more
/// (audio and unframed frames carry none).
fn took_frame_seq(shared: &Shared, stream: StreamId, frame: &Frame, framing: u8, fseq: u32) {
    if framing == crate::transport::av_chunk_auth::FRAMING_FRAGMENTS
        && frame.codec_id != crate::transport::realtime_av::CODEC_OPAQUE
    {
        Shared::lock(&shared.frame_seqs)
            .insert((stream, frame.codec_id, frame.layer), fseq.wrapping_add(1));
    }
}

/// v45 — the plaintexts `frame` is sealed as: itself, on an unframed
/// stream or for audio (`0xFF`), within `budget`; otherwise its marked
/// fragments ([`frame::split`]) of at most `budget` bytes each. Refused
/// before anything is sealed when it does not fit.
fn frame_pieces(
    frame: &Frame,
    framing: u8,
    budget: usize,
    frame_seq: u32,
) -> Result<Vec<Vec<u8>>, CallError> {
    let framed = framing == crate::transport::av_chunk_auth::FRAMING_FRAGMENTS
        && frame.codec_id != crate::transport::realtime_av::CODEC_OPAQUE;
    if !framed {
        if frame.bytes.len() > budget {
            return Err(CallError::FrameTooLarge {
                bytes: frame.bytes.len(),
                budget,
            });
        }
        return Ok(vec![frame.bytes.clone()]);
    }
    frame::split(&frame.bytes, budget, frame_seq).ok_or(CallError::FrameTooLarge {
        bytes: frame.bytes.len(),
        budget: frame::max_frame_len(budget),
    })
}

/// v45 — seal and sign every piece of one frame, consecutive `chunk_seq`s
/// in the publisher's current epoch (the caller holds the lock the roll
/// takes, so a frame never straddles an epoch). A run that would pass the
/// epoch's 2³² `chunk_seq` ceiling is refused before the first seal: the
/// epoch rolls first.
fn seal_pieces(
    publisher: &mut Publisher,
    signer: &ChunkSigner,
    frame: &Frame,
    pieces: &[Vec<u8>],
) -> Result<Vec<(ChunkSeq, crate::transport::realtime_av::InnerSealed)>, CallError> {
    let next = publisher.next_chunk_seq().0;
    let run = u64::try_from(pieces.len()).unwrap_or(u64::MAX);
    if next.saturating_add(run) > u64::from(u32::MAX) + 1 {
        return Err(CallError::ChunkSeqExhausted {
            next,
            fragments: pieces.len(),
        });
    }
    pieces
        .iter()
        .map(|p| {
            let (seq, inner) = publisher
                .seal_next(p, frame.codec_id, frame.layer)
                .map_err(|e| CallError::Plumbing(e.to_string()))?;
            let inner = signer
                .sign(&inner)
                .map_err(|e| CallError::Plumbing(e.to_string()))?;
            Ok((seq, inner))
        })
        .collect()
}

/// v45 — send one frame's sealed pieces in order. A leg that fails one
/// fragment (congested, too large, gone) gets none of the rest: a partial
/// frame is worth nothing. Each leg's outcome is its first failure, or
/// `Delivered`. `withhold`: the test seam's `(member, every)`.
async fn send_pieces(
    shared: &Arc<Shared>,
    publisher: &mut Publisher,
    stream: StreamId,
    frame: &Frame,
    pieces: &[Vec<u8>],
    sealed: &[(ChunkSeq, crate::transport::realtime_av::InnerSealed)],
    withhold: Option<&(String, u64)>,
) -> Result<Vec<(String, LegOutcome)>, CallError> {
    let mut outcome: BTreeMap<String, LegOutcome> = BTreeMap::new();
    for (piece, (seq, inner)) in pieces.iter().zip(sealed) {
        let mut exclude: Vec<String> = outcome
            .iter()
            .filter(|(_, o)| **o != LegOutcome::Delivered)
            .map(|(p, _)| p.clone())
            .collect();
        // Only once the window has measured a gap (two rounds in): before
        // that it runs on its prior, which this seam is not testing.
        if let Some((peer, n)) = withhold {
            if *n > 0 && seq.0 >= 2 * n && seq.0 % n == 0 {
                exclude.push(peer.clone());
            }
        }
        let legs = send_own_chunk(
            shared,
            publisher,
            stream,
            inner,
            (piece.len(), frame.codec_id, frame.layer),
            exclude,
        )
        .await?;
        for (peer, o) in legs {
            match outcome.get(&peer) {
                Some(prev) if *prev != LegOutcome::Delivered => {}
                _ => {
                    outcome.insert(peer, o);
                }
            }
        }
    }
    Ok(outcome.into_iter().collect())
}

/// One own chunk, sealed and signed, out on the primary publisher's legs
/// (v45: the primary's or a share's; a share has no legs of its own). ALM:
/// `stream` goes only to the members that hold a commitment on it (a
/// standby: base/audio only), to C3 members still choosing, and to every
/// pre-C3 peer as before; at service tier 2 this node's own call is audio
/// only (§7.2). `exclude`: legs left out up front (a test seam's).
async fn send_own_chunk(
    shared: &Arc<Shared>,
    publisher: &mut Publisher,
    stream: StreamId,
    inner: &crate::transport::realtime_av::InnerSealed,
    (plaintext_len, codec_id, layer): (usize, u8, ChunkLayer),
    mut exclude: Vec<String>,
) -> Result<Vec<(String, LegOutcome)>, CallError> {
    let base_or_audio = is_base_or_audio(codec_id, layer);
    let wire_len = u64::try_from(plaintext_len + AV_CHUNK_WIRE_OVERHEAD + CHUNK_TRAILER_LEN)
        .unwrap_or(u64::MAX);
    let legs_now = publisher.dispatcher_mut().subscriber_ids();
    {
        let alm = Shared::lock(&shared.alm);
        if alm.tier().own_call_audio_only() && !base_or_audio {
            exclude.clone_from(&legs_now);
        } else {
            exclude.extend(alm.own_exclude_on(stream, &legs_now, base_or_audio));
        }
        // v45 — a child that asked for less gets less.
        exclude.extend(alm.layer_exclude(stream, &legs_now, codec_id, layer));
    }
    let report = publisher
        .dispatcher_mut()
        .relay_inner_report(inner, &exclude)
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
    note_leg_outcomes(shared, publisher.dispatcher_mut(), &report, wire_len);
    Shared::lock(&shared.alm).on_own_published_on(stream, wire_len, base_or_audio);
    shared.published.fetch_add(1, Ordering::Relaxed);
    Ok(report
        .into_iter()
        .map(|(peer, leg)| {
            let outcome = leg_outcome(leg);
            if outcome == LegOutcome::Gone {
                Shared::lock(&shared.out_legs).remove(&peer);
                Shared::lock(&shared.alm).on_child_link_down(&peer);
            }
            (peer, outcome)
        })
        .collect())
}

fn leg_outcome(leg: LegSend) -> LegOutcome {
    match leg {
        LegSend::Sent => LegOutcome::Delivered,
        LegSend::FilteredByPolicy => LegOutcome::FilteredByPolicy,
        LegSend::Gone => LegOutcome::Gone,
        LegSend::Failed(AvDispatcherError::Congested) => LegOutcome::Congested,
        LegSend::Failed(AvDispatcherError::ChunkTooLarge(_)) => LegOutcome::TooLarge,
        LegSend::Failed(e) => LegOutcome::Failed(e.to_string()),
    }
}

/// The call's addressing snapshot: its members at the room's epoch, under
/// the call's destination secret ([`crate::transport::av_call_key::call_destination_secret`]).
async fn room_snapshot(
    room_group: &CohortGroup,
    group_id: &str,
    members: &[String],
) -> Result<ScopeGroupSnapshot, CallError> {
    let secret =
        room_group
            .destination_secret()
            .await
            .map_err(|e| CallError::RoomGroupUnavailable {
                room: group_id.to_owned(),
                detail: e.to_string(),
            })?;
    // The call's own secret, never the room's: the room installs its
    // addresses for the same members at the same epoch.
    let destination_secret =
        crate::transport::av_call_key::call_destination_secret(secret.as_bytes(), group_id)
            .map_err(|e| CallError::Plumbing(format!("call destination secret: {e:?}")))?;
    Ok(ScopeGroupSnapshot {
        group_id: group_id.to_owned(),
        epoch: room_group.epoch().await,
        members: members.to_vec(),
        destination_secret,
    })
}

/// The call's members at the room's CURRENT leaves (a binding may arrive
/// before this node's roll): the last resolution while the leaves are
/// unchanged, a fresh one when they moved. A failed read answers with the
/// members the call last rolled to.
async fn current_members(shared: &Shared) -> Vec<String> {
    let leaves = shared.room_group.member_key_ids().await;
    {
        let memo = Shared::lock(&shared.resolved);
        if memo.0 == leaves {
            return memo.1.clone();
        }
    }
    match call_members(&leaves, shared.owners.as_ref()).await {
        Ok(members) => {
            *Shared::lock(&shared.resolved) = (leaves, members.clone());
            members
        }
        Err(detail) => {
            tracing::warn!(room = %shared.room, %detail, "call: the members' owner bindings are unreadable");
            Shared::lock(&shared.members).clone()
        }
    }
}

/// **The roll** (§3.2, A3): when the room's epoch moved, every live stream
/// rolls (a new DEK, `chunk_seq` 0, through the keep layer), the call's
/// addresses follow the room, departed members' legs close and joined
/// members are dialled.
async fn roll_if_moved(shared: &Arc<Shared>) -> Result<(), CallError> {
    let room_epoch = shared.room_group.epoch().await;
    // A replacement waiting out its overlap was minted at the epoch about to
    // end: switch to it first, so the roll rolls the new stream.
    if room_epoch > shared.publisher.lock().await.epoch().0 {
        apply_pending_replace(shared, true).await?;
    }
    let mut publisher = shared.publisher.lock().await;
    let from = publisher.epoch().0;
    if room_epoch <= from {
        return Ok(());
    }
    // The call's members at the new epoch, re-resolved: a removed person's
    // nodes leave with them, and an owner binding withdrawn since the last
    // epoch takes its node out. A read failure leaves the stream where it
    // was, to roll on the next try.
    let leaves = shared.room_group.member_key_ids().await;
    let members = call_members(&leaves, shared.owners.as_ref())
        .await
        .map_err(|detail| CallError::RoomGroupUnavailable {
            room: shared.room.clone(),
            detail,
        })?;
    *Shared::lock(&shared.resolved) = (leaves, members.clone());
    if !members.iter().any(|m| *m == shared.own) {
        *Shared::lock(&shared.state) = CallState::Ended(EndCause::Revoked);
        shared.book_end("revoked");
        return Err(CallError::CallEnded(EndCause::Revoked));
    }
    let to = Epoch(room_epoch);
    let (stream, join_nonce, replaces, codecs) = {
        let k = Shared::lock(&shared.own_key);
        (k.stream, k.join_nonce, k.replaces, k.codecs)
    };
    let dek = stream_epoch_dek(&shared.room_group, stream, to)
        .await
        .map_err(|e| CallError::RoomGroupUnavailable {
            room: shared.room.clone(),
            detail: e.to_string(),
        })?;
    // The new epoch's chunk key, bound BEFORE the roll: a failure leaves the
    // stream where it was, to roll on the next try.
    let own_key = mint_own_key(
        &shared.signer,
        &shared.room,
        join_nonce,
        stream,
        to,
        codecs,
        replaces,
        crate::transport::av_chunk_auth::STREAM_KIND_MEDIA,
    )
    .await?;
    let keep = publisher
        .roll_room_epoch(to, dek)
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
    let wire = Arc::clone(&own_key.wire);
    let wire_v2 = own_key.wire_v2.clone();
    *Shared::lock(&shared.own_key) = own_key;
    // Departed members: no more of this stream for them.
    let before: Vec<String> = Shared::lock(&shared.members).clone();
    let left: Vec<String> = before
        .iter()
        .filter(|m| !members.contains(m))
        .cloned()
        .collect();
    let joined: Vec<String> = members
        .iter()
        .filter(|m| !before.contains(m) && **m != shared.own)
        .cloned()
        .collect();
    for m in &left {
        publisher.remove_subscriber(m);
    }
    // Every remaining leg learns the new key before the epoch's first chunk:
    // the v2 binding (codec, framing) first to a leg that takes it, then v1.
    // An ended camera's keys are not announced.
    if !shared.primary_ended.load(Ordering::Acquire) {
        send_bindings_on(shared, &mut publisher, &wire, wire_v2.as_ref()).await;
    }
    // v45 — every share rolls with the primary, bound on every leg before
    // its first chunk of the epoch. One that fails here rolls at its next
    // publish.
    let mut share_keeps = Vec::new();
    {
        let mut shares = shared.shares.lock().await;
        for share in shares.values_mut() {
            match roll_share(shared, &mut publisher, share, to).await {
                Ok(keep) => share_keeps.push(keep),
                Err(e) => tracing::warn!(
                    stream = %crate::transport::realtime_av::stream_label(share.key.stream),
                    error = %e,
                    "call share: not rolled with the primary; retried at its next chunk"
                ),
            }
        }
    }
    drop(publisher);
    for keep in share_keeps {
        if let KeepOutcome::Refused(r) = keep {
            shared.emit(CallEvent::KeepRefused {
                epoch: r.epoch,
                reason: r.kind,
            });
        }
    }
    Shared::lock(&shared.members).clone_from(&members);
    Shared::lock(&shared.alm).set_members(&members);
    Shared::lock(&shared.epochs).push(room_epoch);
    close_departed(shared, &left).await;
    readdress(shared, room_epoch, &members).await;
    shared.emit(CallEvent::EpochRolled {
        from,
        to: room_epoch,
    });
    for m in left {
        // v45 — its key left the room's MLS group: its streams left the call.
        attendee_left(shared, &m, LeaveCause::Removed);
        shared.emit(CallEvent::MemberLeft { key_id: m });
    }
    for m in joined {
        shared.emit(CallEvent::MemberJoined { key_id: m });
    }
    if let KeepOutcome::Refused(r) = keep {
        shared.emit(CallEvent::KeepRefused {
            epoch: r.epoch,
            reason: r.kind,
        });
    }
    tracing::info!(
        room = %shared.room,
        from,
        to = room_epoch,
        "CALL ROLLED: the room's epoch moved; new stream DEK, chunk_seq 0 (CIRISEdge#805 A3)"
    );
    reconcile_legs(shared);
    Ok(())
}

/// Close every link to or from a member who left the room.
async fn close_departed(shared: &Arc<Shared>, left: &[String]) {
    let mut closing = Vec::new();
    {
        let mut legs = Shared::lock(&shared.out_legs);
        for m in left {
            if let Some(l) = legs.remove(m) {
                closing.push(l.link_id);
            }
        }
    }
    Shared::lock(&shared.in_links).retain(|link, peer| {
        if left.contains(peer) {
            closing.push(*link);
            false
        } else {
            true
        }
    });
    Shared::lock(&shared.in_senders).retain(|peer, _| !left.contains(peer));
    Shared::lock(&shared.leg_ttl).retain(|peer, _| !left.contains(peer));
    for l in closing {
        let _ = shared.transport.link_teardown(&l).await;
    }
}

/// Move the call's addresses to the room's new epoch; a failure strands the
/// call (Degraded) without stopping its live links.
async fn readdress(shared: &Arc<Shared>, room_epoch: u64, members: &[String]) {
    let outcome = match room_snapshot(&shared.room_group, &shared.group_id, members).await {
        Ok(snapshot) => shared
            .lifecycle
            .advance(&shared.scope, &snapshot, Instant::now())
            .map(|_| ())
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(reason) = outcome {
        *Shared::lock(&shared.state) = CallState::Degraded {
            epoch: room_epoch,
            reason: reason.clone(),
        };
        shared.emit(CallEvent::Stranded {
            epoch: room_epoch,
            reason,
        });
    }
}

/// Dial every member this node has no leg to (and is not already dialling,
/// and has not just failed to reach).
fn reconcile_legs(shared: &Arc<Shared>) {
    if shared.ended.load(Ordering::Relaxed) {
        return;
    }
    let members: Vec<String> = Shared::lock(&shared.members).clone();
    let now = Instant::now();
    for m in members {
        if m == shared.own || Shared::lock(&shared.out_legs).contains_key(&m) {
            continue;
        }
        {
            let mut dialling = Shared::lock(&shared.dialling);
            if dialling.get(&m).is_some_and(|until| *until > now) {
                continue;
            }
            dialling.insert(m.clone(), now + Duration::from_hours(1));
        }
        let s = Arc::clone(shared);
        tokio::spawn(async move {
            let ok = dial_leg(&s, &m).await;
            let mut dialling = Shared::lock(&s.dialling);
            if ok {
                dialling.remove(&m);
                Shared::lock(&s.backoff).remove(&m);
            } else {
                let mut backoff = Shared::lock(&s.backoff);
                let b = backoff
                    .get(&m)
                    .map_or(DIAL_BACKOFF_MIN, |b| (*b * 2).min(DIAL_BACKOFF_MAX));
                backoff.insert(m.clone(), b);
                dialling.insert(m, Instant::now() + b);
            }
        });
    }
}

/// Dial `member`'s call address, name this stream on the new link, and put
/// the link on the publisher's roster with its seal key.
#[allow(clippy::too_many_lines)] // one linear dial: address, link, hello, bindings, roster, C3 reader
async fn dial_leg(shared: &Arc<Shared>, member: &str) -> bool {
    let Some(address) =
        shared
            .lifecycle
            .table()
            .send_address(&shared.scope, &shared.group_id, member)
    else {
        return false;
    };
    let link = match shared.transport.open_av_link(member, &address).await {
        Ok(l) => l,
        Err(e) => {
            tracing::debug!(peer = %member, error = %e, "call leg: dial failed (will retry)");
            return false;
        }
    };
    if shared.ended.load(Ordering::Relaxed) {
        let _ = shared.transport.link_teardown(&link.link_id).await;
        return false;
    }
    let Some(channel_limit) = link.sender.channel_limit() else {
        return false;
    };
    // The stream hello: the link's first message after the transit KEX.
    let hello = encode_hello(shared.stream());
    let deadline = tokio::time::Instant::now() + HELLO_BUDGET;
    if let Err(e) = send_patiently(&link.sender, &hello, deadline).await {
        tracing::debug!(peer = %member, error = %e, "call leg: hello not sent");
        let _ = shared.transport.link_teardown(&link.link_id).await;
        return false;
    }
    let policy = Shared::lock(&shared.policies)
        .get(member)
        .copied()
        .unwrap_or(shared.opts.default_policy);
    let seal_key = link.transit.seal_key();
    let link_id = link.link_id;
    let media_ttl = link.sender.media_ttl();
    let leg_inbound = link.inbound;
    {
        // Under the publisher lock, so no roll lands between the binding and
        // the leg joining the roster: the stream's current binding (and, for a
        // relay, every binding it holds but the member's own), then the leg.
        let mut publisher = shared.publisher.lock().await;
        // v1 only: the member's CAPS (whether it takes v2) have not come
        // yet. Its v2 bindings follow its CAPS (`send_v2_bindings_to`).
        let mut wires: Vec<Arc<Vec<u8>>> = Some(Arc::clone(&Shared::lock(&shared.own_key).wire))
            .filter(|_| !shared.primary_ended.load(Ordering::Acquire))
            .into_iter()
            .collect();
        // v45 — and every share's.
        wires.extend(
            shared
                .shares
                .lock()
                .await
                .values()
                .map(|s| Arc::clone(&s.key.wire)),
        );
        if shared.opts.relay {
            wires.extend(shared.auth.bindings_except(member, false));
        }
        for wire in &wires {
            let parts = StreamKeyBinding::parts(wire, Some(channel_limit));
            if parts.is_empty() {
                tracing::warn!(
                    peer = %member,
                    channel_limit,
                    "call leg: the link is too small to carry a stream key binding"
                );
                let _ = shared.transport.link_teardown(&link_id).await;
                return false;
            }
            for part in &parts {
                if let Err(e) = send_patiently(&link.sender, part, deadline).await {
                    tracing::debug!(peer = %member, error = %e, "call leg: binding not sent");
                    let _ = shared.transport.link_teardown(&link_id).await;
                    return false;
                }
            }
        }
        if let Err(e) = publisher.add_subscriber(AvSubscriberLink {
            subscriber: member.to_owned(),
            transit_key: seal_key,
            link_id: link_id.to_vec(),
            outbound_send: Box::new(link.sender),
        }) {
            tracing::warn!(peer = %member, error = %e, "call leg: not added");
            return false;
        }
        publisher
            .dispatcher_mut()
            .set_layer_policy(&member.to_owned(), policy);
        // The binding parts just filled the link's Channel window: the leg
        // settles, so the first chunks retry rather than drop.
        publisher.dispatcher_mut().settle(&member.to_owned());
    }
    Shared::lock(&shared.out_legs).insert(
        member.to_owned(),
        OutLeg {
            link_id,
            channel_limit,
            media: Arc::clone(&media_ttl),
        },
    );
    // ALM C5 — media to a peer that takes timed frames rides them; one that
    // takes datagrams (leviculum#102) gets them instead.
    {
        let a = Shared::lock(&shared.alm);
        if a.takes_timed(member) {
            media_ttl.set(alm::AUDIO_TTL, alm::VIDEO_TTL);
        }
        // The host's lever (`set_av_datagrams_enabled`) gates a NEW leg only.
        if a.takes_datagrams(member) && shared.transport.av_datagrams_enabled() {
            media_ttl.set_datagrams();
        }
    }
    Shared::lock(&shared.leg_ttl).insert(member.to_owned(), media_ttl);
    Shared::lock(&shared.leg_cong).remove(member);
    // ALM C3 — the responder's frames ride this leg's reverse direction.
    tokio::spawn(out_leg_reader(
        Arc::clone(shared),
        member.to_owned(),
        link_id,
        leg_inbound,
    ));
    tracing::info!(
        peer = %member,
        link = %hex::encode(link_id),
        channel_limit,
        "call leg UP: this node's stream rides a keyed link to the member (CIRISEdge#805)"
    );
    true
}

/// Send one control frame on a fresh leg, waiting out backpressure until
/// `deadline`.
async fn send_patiently(
    sender: &crate::transport::realtime_av_runtime::LeviculumAvSender,
    bytes: &[u8],
    deadline: tokio::time::Instant,
) -> Result<(), AvDispatcherError> {
    loop {
        match sender.send(bytes).await {
            Ok(()) => return Ok(()),
            Err(AvDispatcherError::Congested) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Accept every link a member dials to this node's call addresses.
async fn accept_loop(shared: Arc<Shared>, mut arrivals: mpsc::Receiver<AvArrival>) {
    while let Some(arrival) = arrivals.recv().await {
        let s = Arc::clone(&shared);
        tokio::spawn(async move { serve_inbound(s, arrival).await });
    }
}

/// One member's link to this node: the transit KEX (with the claim check),
/// the stream hello, then the pump.
async fn serve_inbound(shared: Arc<Shared>, arrival: AvArrival) {
    // A refusal is named and counted by the transport.
    let Ok(accepted) = shared.transport.accept_av_arrival(arrival).await else {
        return;
    };
    let peer = accepted.arrival.peer.as_str().to_owned();
    let link_id = accepted.arrival.link_id;
    if !Shared::lock(&shared.members).contains(&peer) {
        tracing::warn!(peer = %peer, "call: a link from a non-member — closed");
        let _ = shared.transport.link_teardown(&link_id).await;
        return;
    }
    let open_key = accepted.transit.open_key();
    let crate::transport::av_sink::AvArrival {
        inbound, sender, ..
    } = accepted.arrival;
    let hello = tokio::time::timeout(HELLO_BUDGET, inbound.recv_frame()).await;
    let Some(own_stream) = hello
        .ok()
        .and_then(Result::ok)
        .and_then(|f| (f.dropped_before == 0).then_some(f.bytes))
        .and_then(|b| decode_hello(&b))
    else {
        tracing::warn!(peer = %peer, "call: the link named no stream — closed");
        let _ = shared.transport.link_teardown(&link_id).await;
        return;
    };
    Shared::lock(&shared.in_links).insert(link_id, peer.clone());
    // ALM C3 — the responder speaks first, on the reverse direction of the
    // link it accepted: a pre-C3 dialler never reads that direction, so the
    // CAPS frame is harmless there, and a C3 dialler answers with its own.
    let sender = Arc::new(sender);
    let caps = {
        let mut alm = Shared::lock(&shared.alm);
        alm.note_publisher(own_stream, &peer);
        alm.caps_frame(shared.transport.av_datagrams_enabled())
    };
    Shared::lock(&shared.in_senders).insert(peer.clone(), Arc::clone(&sender));
    let deadline = tokio::time::Instant::now() + HELLO_BUDGET;
    if send_patiently(&sender, &caps, deadline).await.is_ok() {
        shared.count(crate::observability::ALM_C3_SENT);
    }
    pump(&shared, &peer, own_stream, link_id, &open_key, inbound).await;
    Shared::lock(&shared.in_links).remove(&link_id);
    // C6: the member's frames reached this node only on this link.
    if !Shared::lock(&shared.in_links).values().any(|p| *p == peer) {
        Shared::lock(&shared.alm).on_parent_link_down(&peer);
    }
    let mut senders = Shared::lock(&shared.in_senders);
    if senders.get(&peer).is_some_and(|s| Arc::ptr_eq(s, &sender)) {
        senders.remove(&peer);
    }
}

/// Whether a chunk is base-layer or codec-opaque (audio): what a standby
/// child, a shed leg and a tier-2 own call still carry.
fn is_base_or_audio(codec_id: u8, layer: ChunkLayer) -> bool {
    codec_id == crate::transport::realtime_av::CODEC_OPAQUE || layer == ChunkLayer::BASE
}

/// C1 and C5 on one fan-out's report: every leg's outcome feeds the egress
/// meter, and a leg that stays congested is shed to the base layer until it
/// runs clean (the host's own policy is the cap it is restored to).
fn note_leg_outcomes(
    shared: &Arc<Shared>,
    dispatcher: &mut crate::transport::realtime_av_dispatcher::AvDispatcher,
    report: &[(String, LegSend)],
    wire_len: u64,
) {
    // leviculum#102 — a datagram carries no delivery proof: what such a leg
    // accepted is all the uplink meter can know it delivered.
    // Lock order: `leg_ttl`, then `alm`, then `leg_cong` (nothing takes
    // `leg_ttl` while holding `alm`).
    let ttl = Shared::lock(&shared.leg_ttl);
    let mut alm = Shared::lock(&shared.alm);
    let mut cong = Shared::lock(&shared.leg_cong);
    for (peer, leg) in report {
        let e = cong.entry(peer.clone()).or_insert((0, 0, false));
        match leg {
            LegSend::Sent => {
                alm.on_sent(peer, wire_len);
                if ttl.get(peer).is_some_and(|t| t.uses_datagrams()) {
                    alm.on_delivered(wire_len);
                }
                e.0 = 0;
                e.1 = e.1.saturating_add(1);
                if e.2 && e.1 >= LEG_RESTORE_AFTER {
                    e.2 = false;
                    let host = Shared::lock(&shared.policies)
                        .get(peer)
                        .copied()
                        .unwrap_or(shared.opts.default_policy);
                    dispatcher.set_layer_policy(peer, host);
                    shared.count(crate::observability::AV_LEG_RESTORED);
                }
            }
            LegSend::Failed(AvDispatcherError::Congested) => {
                shared.count(crate::observability::AV_CHUNK_DROPPED_CONGESTED);
                alm.on_dropped(wire_len);
                e.1 = 0;
                e.0 = e.0.saturating_add(1);
                if !e.2 && e.0 >= LEG_SHED_AFTER {
                    e.2 = true;
                    dispatcher.set_layer_policy(peer, ReceiverLayerPolicy::BLINKING_DOT);
                    alm.counts.legs_shed_to_base += 1;
                    shared.count(crate::observability::AV_LEG_SHED_TO_BASE);
                }
            }
            _ => {}
        }
    }
}

/// Send ALM C3 frames: on this node's own leg to the member when it has
/// one, else on the reverse direction of the member's link to this node.
/// Never to a member that has not said it speaks C3.
async fn send_alm(shared: &Arc<Shared>, out: Vec<alm::Outgoing>) {
    for o in out {
        if !Shared::lock(&shared.alm).speaks_c3(&o.to) {
            continue;
        }
        let refused_by_seam = !is_periodic(&o.frame)
            && shared
                .test_fail_c3
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok();
        if refused_by_seam {
            let s = Arc::clone(shared);
            tokio::spawn(async move { resend_c3(&s, o).await });
            continue;
        }
        let sent = shared
            .publisher
            .lock()
            .await
            .dispatcher_mut()
            .send_control_to(&o.to, &o.frame)
            .await;
        let ok = if let Some(LegSend::Sent) = sent {
            true
        } else {
            let sender = Shared::lock(&shared.in_senders).get(&o.to).cloned();
            match sender {
                Some(s) => crate::transport::realtime_av_dispatcher::AvLinkSender::send(
                    s.as_ref(),
                    &o.frame,
                )
                .await
                .is_ok(),
                None => false,
            }
        };
        if ok {
            Shared::lock(&shared.alm).counts.c3_sent += 1;
            shared.count(crate::observability::ALM_C3_SENT);
        } else if is_periodic(&o.frame) {
            // The next offer replaces it.
            shared.count(crate::observability::ALM_C3_SEND_FAILED);
        } else {
            // Everything else changes state on one side only: it must arrive,
            // and it must not hold up the pump or the watch tick waiting.
            let s = Arc::clone(shared);
            tokio::spawn(async move { resend_c3(&s, o).await });
        }
    }
}

/// Retry a C3 frame a congested link refused, until [`C3_RESEND_BUDGET`]
/// (shorter than a subscriber's request timeout, so a late answer still
/// counts). Each try is one send: the publisher lock is never held to wait.
async fn resend_c3(shared: &Arc<Shared>, o: alm::Outgoing) {
    let deadline = tokio::time::Instant::now() + C3_RESEND_BUDGET;
    while tokio::time::Instant::now() < deadline && !shared.ended.load(Ordering::Relaxed) {
        tokio::time::sleep(C3_RESEND_PAUSE).await;
        let sent = shared
            .publisher
            .lock()
            .await
            .dispatcher_mut()
            .send_control_to(&o.to, &o.frame)
            .await;
        let mut ok = matches!(sent, Some(LegSend::Sent));
        if !ok {
            let sender = Shared::lock(&shared.in_senders).get(&o.to).cloned();
            if let Some(s) = sender {
                ok = crate::transport::realtime_av_dispatcher::AvLinkSender::send(
                    s.as_ref(),
                    &o.frame,
                )
                .await
                .is_ok();
            }
        }
        if ok {
            Shared::lock(&shared.alm).counts.c3_sent += 1;
            shared.count(crate::observability::ALM_C3_SENT);
            shared.count(crate::observability::ALM_C3_RESENT);
            return;
        }
    }
    shared.count(crate::observability::ALM_C3_SEND_FAILED);
}

/// One C3 frame from `peer`. A dialler hearing the responder's CAPS on its
/// own leg answers with its own (`reply_caps`); a peer that takes timed
/// frames gets its media timed from now on.
async fn handle_c3(shared: &Arc<Shared>, peer: &str, bytes: &[u8], reply_caps: bool) {
    let rtt = leg_rtt_ms(shared, peer);
    let (out, reply, timed, datagrams, binding_v2) = {
        let mut a = Shared::lock(&shared.alm);
        match decode_c3(bytes, peer) {
            Ok(WireFrame::Caps(c)) => {
                let first = a.on_caps(peer, c);
                (
                    Vec::new(),
                    (first && reply_caps)
                        .then(|| a.caps_frame(shared.transport.av_datagrams_enabled())),
                    first && a.takes_timed(peer),
                    first && a.takes_datagrams(peer) && shared.transport.av_datagrams_enabled(),
                    first && a.sends_binding_v2_to(peer),
                )
            }
            Ok(WireFrame::Control(cf)) => {
                // What this node is sent may change: a new receive view, so a
                // layer it stops (or starts) being sent is never a loss.
                if matches!(
                    cf.msg,
                    crate::transport::realtime_av_alm::controller::ControlMsg::Shed { .. }
                        | crate::transport::realtime_av_alm::controller::ControlMsg::Decision(_)
                ) {
                    shared.layer_view.fetch_add(1, Ordering::AcqRel);
                }
                (a.on_control(peer, cf, rtt), None, false, false, false)
            }
            Err(e) => {
                a.note_malformed(e);
                (Vec::new(), None, false, false, false)
            }
        }
    };
    // The peer parses v2 bindings: it gets the ones that name the codec.
    if binding_v2 {
        let s = Arc::clone(shared);
        let p = peer.to_owned();
        tokio::spawn(async move { send_v2_bindings_to(&s, &p).await });
    }
    if timed || datagrams {
        if let Some(ttl) = Shared::lock(&shared.leg_ttl).get(peer) {
            if timed {
                ttl.set(alm::AUDIO_TTL, alm::VIDEO_TTL);
            }
            // leviculum#102 — the peer said it takes datagrams: this node's
            // media to it rides them from now on.
            if datagrams {
                ttl.set_datagrams();
            }
        }
    }
    if let Some(caps) = reply {
        let _ = shared
            .publisher
            .lock()
            .await
            .dispatcher_mut()
            .send_control_to(&peer.to_owned(), &caps)
            .await;
    }
    send_alm(shared, out).await;
}

/// The smoothed RTT of this node's link to `peer` (its own leg, else the
/// member's link to it), or 0 when unmeasured.
fn leg_rtt_ms(shared: &Arc<Shared>, peer: &str) -> f64 {
    let link = Shared::lock(&shared.out_legs)
        .get(peer)
        .map(|l| l.link_id)
        .or_else(|| {
            Shared::lock(&shared.in_links)
                .iter()
                .find(|(_, p)| p.as_str() == peer)
                .map(|(l, _)| *l)
        });
    link.and_then(|l| shared.transport.av_link_stats(&l))
        .and_then(|st| st.srtt_ms)
        .unwrap_or(0.0)
}

/// The reverse direction of a leg this node dialled: the responder's C3
/// frames (its CAPS first). Nothing else rides it.
async fn out_leg_reader(
    shared: Arc<Shared>,
    peer: String,
    link_id: [u8; 16],
    inbound: crate::transport::realtime_av_runtime::PumpReceiver,
) {
    while let Ok(f) = inbound.recv_frame().await {
        if shared.ended.load(Ordering::Relaxed) {
            return;
        }
        if is_control_frame(&f.bytes) {
            handle_c3(&shared, &peer, &f.bytes, true).await;
        }
    }
    // The leg's link closed: unless a fresh leg replaced it, the member holds
    // no commitment here any more.
    let replaced = Shared::lock(&shared.out_legs)
        .get(&peer)
        .is_some_and(|l| l.link_id != link_id);
    if !replaced {
        Shared::lock(&shared.out_legs).remove(&peer);
        Shared::lock(&shared.alm).on_child_link_down(&peer);
    }
}

#[allow(clippy::too_many_lines)] // one linear per-frame sequence: part, open, source check, relay, deliver
async fn pump(
    shared: &Arc<Shared>,
    peer: &str,
    own_stream: StreamId,
    link_id: [u8; 16],
    open_key: &[u8; 32],
    inbound: crate::transport::realtime_av_runtime::PumpReceiver,
) {
    let mut next_seq: u64 = 0;
    let mut gap = HopGap::default();
    let mut stale_skipped: u64 = 0;
    let mut guard = LinkIdGuard::default();
    let mut bindings = BindingAssembler::default();
    while let Ok(frame) = inbound.recv_frame().await {
        if shared.ended.load(Ordering::Relaxed) {
            break;
        }
        let stall = *Shared::lock(&shared.test_stall_until);
        if let Some(until) = stall.filter(|u| *u > Instant::now()) {
            tokio::time::sleep_until(tokio::time::Instant::from_std(until)).await;
        }
        let at = Instant::now();
        // A part carries no hop counter: the drops it reports stay pending for
        // the next chunk.
        let dropped = gap.report(frame.dropped_before);
        // ALM C3 — a control frame takes no hop counter either.
        if is_control_frame(&frame.bytes) {
            handle_c3(shared, peer, &frame.bytes, false).await;
            continue;
        }
        // ALM C5 — media past its budget is dropped by AGE, oldest first,
        // before it costs an open: it took a hop counter on the sender, so
        // the next frame's open skips it like any reported drop.
        if let Some(queued) = frame.queued_at {
            let age = queued.elapsed();
            shared.queue_age_ms.fetch_max(
                u64::try_from(age.as_millis()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            if age > MEDIA_STALE_BUDGET && !BindingAssembler::is_part(&frame.bytes) {
                let _ = gap.report(1);
                stale_skipped += 1;
                Shared::lock(&shared.alm).counts.stale_dropped += 1;
                shared.count(crate::observability::AV_FRAME_STALE_DROPPED);
                continue;
            }
        }
        let frame_len = u64::try_from(frame.bytes.len()).unwrap_or(u64::MAX);
        match bindings.push(&frame.bytes) {
            Part::NotAPart => {}
            Part::Incomplete => continue,
            Part::Malformed => {
                let refusal = AvAuthRefusal::BindingPartMalformed;
                shared.count(crate::observability::AV_CALL_BINDING_REFUSED);
                shared.count(refusal.as_str());
                tracing::debug!(peer = %peer, reason = %refusal, "call: a binding part was refused");
                continue;
            }
            Part::Complete(wire) => {
                take_binding(shared, peer, &wire).await;
                continue;
            }
        }
        let Ok(sealed) = SealedAvChunk::from_bytes(&frame.bytes) else {
            shared.count(crate::observability::AV_CALL_FRAME_UNOPENED);
            continue;
        };
        let Some((opened_at, inner)) =
            open_hop_outer(&sealed, open_key, &link_id, next_seq, dropped)
        else {
            shared.count(crate::observability::AV_CALL_FRAME_UNOPENED);
            if guard.unopened() {
                guard.report_mismatch("call pump", &link_id, shared.metrics.as_ref());
                let _ = shared.transport.link_teardown(&link_id).await;
                break;
            }
            continue;
        };
        guard.opened();
        gap.resolved();
        // What the sender put on this link and never reached this node. The
        // counter is dense over what it sent: it advances past nothing its
        // layer policy filtered or its link refused, so this is loss within
        // the policy in force. This node's own age drops took counters too,
        // and those are its own lag, not the path's.
        let hop_lost = opened_at
            .wrapping_sub(next_seq)
            .saturating_sub(std::mem::take(&mut stale_skipped));
        next_seq = opened_at.wrapping_add(1);
        let signed = inner;
        let stream = signed.stream_id();
        // The source check, before anything else is done with the chunk: it
        // must verify under the key bound to its (stream, epoch), so only the
        // stream's publisher can have made it.
        let (publisher, inner, source_ms) = match shared.auth.check_timed(&signed) {
            Ok(checked) => checked,
            Err(e) => {
                let refusal = e.refusal();
                shared.count(if e.is_forged() {
                    crate::observability::AV_CALL_FRAME_FORGED
                } else {
                    crate::observability::AV_CALL_FRAME_UNBOUND
                });
                shared.count(refusal.as_str());
                tracing::debug!(
                    peer = %peer,
                    reason = %refusal,
                    stream = %crate::transport::realtime_av::stream_label(stream),
                    epoch = signed.epoch().0,
                    chunk_seq = signed.chunk_seq().0,
                    "call: a chunk not proven its stream's publisher's — dropped, not relayed"
                );
                continue;
            }
        };
        // C1, receiver side: this path delivered this chunk.
        let base_or_audio = is_base_or_audio(signed.codec_id(), signed.layer());
        shared.note_first_frame();
        Shared::lock(&shared.alm).on_chunk(
            stream,
            peer,
            signed.epoch().0,
            signed.chunk_seq().0,
            frame_len,
            source_ms,
            base_or_audio,
            hop_lost,
        );
        // Forward as an admitted media parent (ALM), and first-hand copies to
        // pre-C3 members when this node relays (the legacy relay). The
        // signature travels with the chunk.
        let job = ForwardJob {
            stream,
            link_stream: own_stream,
            publisher: publisher.to_string(),
            base_or_audio,
        };
        let delay = shared.test_relay_delay_ms.load(Ordering::Relaxed);
        if delay == 0 {
            forward(shared, &signed, peer, &job).await;
        } else {
            let (s, i, p) = (Arc::clone(shared), signed.clone(), peer.to_owned());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(delay)).await;
                forward(&s, &i, &p, &job).await;
            });
        }
        let Some(dek) = shared.keys.dek(stream, inner.epoch()).await else {
            shared.count(crate::observability::AV_CALL_FRAME_NO_KEY);
            continue;
        };
        let Ok(bytes) = open_av_inner(&inner, &dek) else {
            shared.count(crate::observability::AV_CALL_FRAME_UNOPENED);
            continue;
        };
        let heard = Heard {
            frame: ReceivedFrame {
                publisher: publisher.to_string(),
                stream,
                epoch: inner.epoch(),
                chunk_seq: inner.chunk_seq(),
                codec_id: inner.codec_id(),
                layer: inner.layer(),
                bytes,
                frame_seq: None,
                source_ts_ms: source_ms,
            },
            at,
        };
        if shared.heard_tx.send(heard).await.is_err() {
            break;
        }
    }
}

/// A stream key binding completed on `peer`'s link: verify and install it
/// (the hybrid check runs once per binding, never per chunk). A relay forwards
/// a binding it heard first-hand from its publisher to every other leg.
async fn take_binding(shared: &Arc<Shared>, peer: &str, wire: &[u8]) {
    let members = current_members(shared).await;
    let mut installed = false;
    let binding = match shared
        .auth
        .accept_binding(wire, &members, shared.verifier.as_ref())
        .await
    {
        BindingOutcome::Installed(b) => {
            installed = true;
            shared.count(crate::observability::AV_CALL_BINDING_INSTALLED);
            tracing::info!(
                peer = %peer,
                publisher = %b.publisher,
                stream = %crate::transport::realtime_av::stream_label(b.stream),
                epoch = b.epoch.0,
                "call: a stream's chunk key is bound by its publisher's hybrid signature"
            );
            b
        }
        BindingOutcome::Known(b) => b,
        BindingOutcome::Refused(e) => {
            let refusal = e.refusal();
            shared.count(crate::observability::AV_CALL_BINDING_REFUSED);
            shared.count(refusal.as_str());
            tracing::warn!(
                peer = %peer,
                reason = %refusal,
                error = %e,
                "call: a stream key binding was refused"
            );
            return;
        }
    };
    // The one signed statement of who publishes a stream: what an OFFER
    // claiming depth 0 is checked against.
    Shared::lock(&shared.alm).note_bound_publisher(binding.stream, &binding.publisher);
    if installed {
        on_bound(shared, &binding);
    }
    if shared.opts.relay && (installed || binding.publisher == peer) {
        let mut except = vec![peer.to_owned(), binding.publisher.clone()];
        // A v2 binding goes only to the legs that take v2.
        if binding.version() == crate::transport::av_chunk_auth::BINDING_VERSION_V2 {
            except.extend(legs_without_binding_v2(shared).await);
        }
        let wire = Arc::new(wire.to_vec());
        if installed {
            // Before the chunks it keys, which this pump forwards next.
            send_binding_paced(shared, &wire, &except, None).await;
        } else {
            // A publisher's periodic re-send passing through: never in the
            // way of the chunks queued behind it on this pump.
            let s = Arc::clone(shared);
            tokio::spawn(async move {
                send_binding_paced(&s, &wire, &except, Some(REANNOUNCE_PART_GAP)).await;
            });
        }
    }
}

/// The wait between a periodic re-announce's parts. Sent back to back, about
/// ten Channel messages per leg fill the window every
/// [`BINDING_REANNOUNCE`]: media is refused, the RTT spikes, and its smoothed
/// value reads as queue delay for seconds. The egress meter takes that for
/// the uplink, on a schedule, so a measured ceiling never goes stale. A
/// binding nobody lost can arrive half a second later.
pub const REANNOUNCE_PART_GAP: Duration = Duration::from_millis(50);

/// Send a binding's parts on every leg but `except`, ONE PART PER HOLD of the
/// publisher lock. A binding is about ten Channel messages on a base-MTU link;
/// sent whole, it holds every publish and forward for the entire burst, and
/// the chunks behind it miss their reorder deadlines. Between parts the media
/// path runs (its legs are settling, so a chunk retries the window instead of
/// being dropped), for `gap` when nobody is waiting on this binding.
async fn send_binding_paced(
    shared: &Arc<Shared>,
    wire: &Arc<Vec<u8>>,
    except: &[String],
    gap: Option<Duration>,
) {
    for i in 0.. {
        let more = AtomicBool::new(false);
        shared
            .publisher
            .lock()
            .await
            .dispatcher_mut()
            .send_control_report(except, &|limit| {
                let part = StreamKeyBinding::parts(wire, limit).into_iter().nth(i);
                if part.is_some() {
                    more.store(true, Ordering::Relaxed);
                }
                part.into_iter().collect()
            })
            .await;
        if !more.load(Ordering::Relaxed) {
            return;
        }
        match gap {
            Some(gap) => tokio::time::sleep(gap).await,
            None => tokio::task::yield_now().await,
        }
    }
}

/// Re-send this stream's current binding on every leg (a receiver whose
/// inbound queue dropped a part gets it again).
async fn reannounce(shared: &Arc<Shared>) {
    let (wire, wire_v2) = {
        let k = Shared::lock(&shared.own_key);
        (Arc::clone(&k.wire), k.wire_v2.clone())
    };
    // v45 — and every share's (the shares lock is let go before any send);
    // an ended camera's no more.
    let camera_live = !shared.primary_ended.load(Ordering::Acquire);
    let mut v1: Vec<Arc<Vec<u8>>> = Some(wire).filter(|_| camera_live).into_iter().collect();
    let mut v2: Vec<Arc<Vec<u8>>> = wire_v2.filter(|_| camera_live).into_iter().collect();
    {
        let shares = shared.shares.lock().await;
        for share in shares.values() {
            v1.push(Arc::clone(&share.key.wire));
            v2.extend(share.key.wire_v2.clone());
        }
    }
    // v2 first (CC rc18), then v1.
    if !v2.is_empty() {
        let not_v2 = legs_without_binding_v2(shared).await;
        for w in &v2 {
            send_binding_paced(shared, w, &not_v2, Some(REANNOUNCE_PART_GAP)).await;
        }
    }
    for w in &v1 {
        send_binding_paced(shared, w, &[], Some(REANNOUNCE_PART_GAP)).await;
    }
}

/// v45 — each of `links`' Channel watermark now: its newest message's
/// sequence. Taken right after a message went out on them, it is at or
/// after that message's own (media sent since only makes the wait a little
/// longer, never short). A link with no Channel carried nothing to prove
/// and has no mark; a link leviculum no longer holds is gone.
fn channel_marks(shared: &Arc<Shared>, links: &[[u8; 16]]) -> Vec<([u8; 16], u16)> {
    links
        .iter()
        .filter_map(|l| {
            let seq = shared.transport.av_link_stats(l)?.last_sent_seq?;
            Some((*l, seq))
        })
        .collect()
}

/// v45 — wait until each marked link's Channel proved delivered the
/// message at its mark and everything before it
/// ([`AvLinkStats::delivered_through`], a per-message proof that later
/// traffic in flight does not hide), or `ceiling` passes. Returns how many
/// never did. A link leviculum no longer holds is gone, not unconfirmed.
///
/// [`AvLinkStats::delivered_through`]: crate::transport::alm_link::AvLinkStats::delivered_through
async fn await_delivered(
    shared: &Arc<Shared>,
    marks: &[([u8; 16], u16)],
    ceiling: Duration,
) -> usize {
    let deadline = tokio::time::Instant::now() + ceiling;
    let mut pending: Vec<([u8; 16], u16)> = marks.to_vec();
    loop {
        pending.retain(|(l, seq)| {
            shared
                .transport
                .av_link_stats(l)
                .is_some_and(|st| !st.delivered_through(*seq))
        });
        if pending.is_empty() || tokio::time::Instant::now() >= deadline {
            return pending.len();
        }
        tokio::time::sleep(DELIVERY_POLL).await;
    }
}

/// The legs whose peer has not said it parses a v2 binding.
async fn legs_without_binding_v2(shared: &Arc<Shared>) -> Vec<String> {
    let legs = shared
        .publisher
        .lock()
        .await
        .dispatcher_mut()
        .subscriber_ids();
    let a = Shared::lock(&shared.alm);
    legs.into_iter()
        .filter(|l| !a.sends_binding_v2_to(l))
        .collect()
}

/// `peer` just said it parses v2 bindings: send it this stream's v2 binding
/// and, as a relay, every held v2 binding but its own (it had v1 only).
async fn send_v2_bindings_to(shared: &Arc<Shared>, peer: &str) {
    let mut wires: Vec<Arc<Vec<u8>>> = Shared::lock(&shared.own_key)
        .wire_v2
        .clone()
        .filter(|_| !shared.primary_ended.load(Ordering::Acquire))
        .into_iter()
        .collect();
    wires.extend(
        shared
            .shares
            .lock()
            .await
            .values()
            .filter_map(|s| s.key.wire_v2.clone()),
    );
    if shared.opts.relay {
        wires.extend(
            shared
                .auth
                .bindings_except(peer, true)
                .into_iter()
                .filter(|w| {
                    StreamKeyBinding::version_of(w)
                        == Some(crate::transport::av_chunk_auth::BINDING_VERSION_V2)
                }),
        );
    }
    if wires.is_empty() {
        return;
    }
    let others: Vec<String> = shared
        .publisher
        .lock()
        .await
        .dispatcher_mut()
        .subscriber_ids()
        .into_iter()
        .filter(|l| l != peer)
        .collect();
    for w in &wires {
        send_binding_paced(shared, w, &others, None).await;
    }
}

/// What [`forward`] needs to know about one chunk.
struct ForwardJob {
    stream: StreamId,
    /// The stream the link's hello named (its peer's own).
    link_stream: StreamId,
    /// The chunk's verified publisher.
    publisher: String,
    base_or_audio: bool,
}

/// Forward one verified chunk heard from `from`: to the children this node
/// ADMITTED for its stream (ALM; only what arrives from this node's own
/// parent, once each), and — when this node relays — first-hand copies to
/// pre-C3 members (the legacy relay). Never back to `from` or the publisher.
async fn forward(
    shared: &Arc<Shared>,
    inner: &crate::transport::realtime_av::InnerSealed,
    from: &str,
    job: &ForwardJob,
) {
    let mut publisher = shared.publisher.lock().await;
    let legs = publisher.dispatcher_mut().subscriber_ids();
    let mut targets: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    {
        let mut alm = Shared::lock(&shared.alm);
        if let Some(ex) = alm.forward_exclude(
            job.stream,
            inner.epoch().0,
            inner.chunk_seq().0,
            from,
            &job.publisher,
            &legs,
            job.base_or_audio,
        ) {
            targets.extend(legs.iter().filter(|l| !ex.contains(l)).cloned());
            // v45 — a child that asked for less gets less.
            for l in alm.layer_exclude(job.stream, &legs, inner.codec_id(), inner.layer()) {
                targets.remove(&l);
            }
        }
        if shared.opts.relay && job.stream == job.link_stream && job.publisher == from {
            targets.extend(
                legs.iter()
                    .filter(|l| l.as_str() != from && !alm.speaks_c3(l))
                    .cloned(),
            );
        }
    }
    if let Some((peer, n)) = Shared::lock(&shared.test_withhold_forward).as_ref() {
        let seq = inner.chunk_seq().0;
        if *n > 0 && seq >= 2 * n && seq % n == 0 {
            targets.remove(peer);
        }
    }
    if targets.is_empty() {
        return;
    }
    let exclude: Vec<String> = legs.into_iter().filter(|l| !targets.contains(l)).collect();
    let wire_len =
        u64::try_from(inner.inner_ciphertext().len() + AV_CHUNK_WIRE_OVERHEAD).unwrap_or(u64::MAX);
    if let Ok(report) = publisher
        .dispatcher_mut()
        .relay_inner_report(inner, &exclude)
        .await
    {
        note_leg_outcomes(shared, publisher.dispatcher_mut(), &report, wire_len);
        let sent = report
            .iter()
            .filter(|(_, leg)| matches!(leg, LegSend::Sent))
            .count();
        Shared::lock(&shared.alm).counts.forwarded += sent as u64;
        for _ in 0..sent {
            shared.count(crate::observability::AV_CALL_RELAYED);
        }
    }
}

/// v45 — how long a released chunk waits for its stream's v2 binding (its
/// framing) before it is dropped: the longest reorder window.
pub const FRAMING_HOLD: Duration = REORDER_WINDOW_MAX;

/// v45 (CC rc18) — what this receiver knows of `(stream, epoch)`'s framing:
/// its v2 binding's when installed. With only v1 held it is unframed only
/// when no v2 can be coming, decided from facts this node authenticates
/// itself (CC's condition): its own capability (it does not advertise
/// `CAP_BINDING_V2`, so none is sent to it), or `CAPS` that arrived on this
/// node's own link whose far end is the publisher, link-attributed under E1
/// (`alm.caps` is keyed by the link's peer, never by a relay's word), and
/// lack the bit. Otherwise the chunk waits. A drop here is the receiver's
/// alone: counted, never sent to the publisher, never a reason to evict the
/// stream (its binding and audio stand).
fn framing_state_of(
    shared: &Shared,
    stream: StreamId,
    epoch: Epoch,
    publisher: &str,
) -> frame::FramingState {
    if let Some(f) = shared.auth.v2_framing(stream, epoch) {
        return frame::FramingState::Known(f);
    }
    let a = Shared::lock(&shared.alm);
    if !a.advertises_binding_v2() || a.known_without_binding_v2(publisher) {
        frame::FramingState::Known(crate::transport::av_chunk_auth::FRAMING_NONE)
    } else {
        frame::FramingState::Pending
    }
}

async fn reorder_loop(
    shared: Arc<Shared>,
    mut heard: mpsc::Receiver<Heard>,
    frames: mpsc::Sender<ReceivedFrame>,
    counts: Arc<StdMutex<ReorderCounts>>,
) {
    let mut window = ReorderWindow::new();
    // v45 — a framed stream's fragments become whole frames here, past the
    // window (a missing fragment is a missing chunk: the window waited for
    // it by chunk_seq first).
    let mut frames_of = frame::Reassemblers::default();
    let mut sweep = 0u64;
    // CC rc18 — a chunk released while only its stream's v1 binding is held,
    // and a v2 one may follow, waits (bounded) and is never parsed unframed.
    let mut gate = frame::FramingGate::default();
    let framing_state =
        |f: &ReceivedFrame| framing_state_of(&shared, f.stream, f.epoch, &f.publisher);
    loop {
        let next = match (window.next_deadline(), gate.next_deadline(FRAMING_HOLD)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let released = match next {
            Some(deadline) => {
                tokio::select! {
                    h = heard.recv() => match h {
                        Some(h) => window.push(h.frame, h.at),
                        None => return,
                    },
                    () = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        window.tick(Instant::now())
                    }
                }
            }
            None => match heard.recv().await {
                Some(h) => window.push(h.frame, h.at),
                None => return,
            },
        };
        let mut whole = Vec::with_capacity(released.len());
        let mut dropped = 0u64;
        sweep = sweep.wrapping_add(1);
        if sweep.is_multiple_of(256) {
            for r in frames_of.retain(|st| shared.auth.is_bound(st)) {
                dropped += 1;
                shared.count(r.token());
            }
        }
        let now = Instant::now();
        let mut ready = Vec::new();
        for f in released {
            let st = framing_state(&f);
            ready.extend(gate.admit(f, st, now));
        }
        let (late, unknown) = gate.tick(now, FRAMING_HOLD, framing_state);
        ready.extend(late);
        for _ in 0..unknown {
            dropped += 1;
            shared.count(frame::FrameRefusal::FramingUnknown.token());
        }
        frames_of.set_view(shared.layer_view.load(Ordering::Acquire));
        for (f, framing) in ready {
            let out = frames_of.push(f, framing);
            for r in out.refused {
                dropped += 1;
                shared.count(r.token());
            }
            whole.extend(out.frame);
        }
        {
            let mut c = counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = c.frames_dropped;
            *c = window.counts();
            c.frames_dropped = before + dropped;
            c.frames_open = u64::try_from(frames_of.open()).unwrap_or(u64::MAX);
            drop(c);
            *Shared::lock(&shared.frames_lost) = frames_of.lost_by_layer();
        }
        for f in whole {
            if frames.send(f).await.is_err() {
                return;
            }
        }
    }
}

/// How often (in watch ticks) a call reads its rows for new attendees.
const ATTENDANCE_EVERY_TICKS: u64 = 4;

/// [`BINDING_REANNOUNCE`] in watch ticks.
fn reannounce_ticks() -> u64 {
    u64::try_from(BINDING_REANNOUNCE.as_millis() / WATCH_TICK.as_millis())
        .unwrap_or(1)
        .max(1)
}

/// Write this attendee's call row. A refusal fires `RecordRefused` once and
/// the call carries on; nothing is faked.
async fn write_call_row(shared: &Arc<Shared>) {
    let Some(record) = &shared.record else {
        return;
    };
    let at = chrono::Utc::now();
    if let Err(reason) = record.record_join(&shared.room, shared.id, at).await {
        shared.count(crate::observability::AV_CALL_RECORD_REFUSED);
        if !shared.record_refused.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                room = %shared.room,
                reason = %reason,
                "call row REFUSED — the call stays live; no row is faked (tracked: CIRISEdge#805 item 6)"
            );
            shared.emit(CallEvent::RecordRefused { reason });
        }
    }
}

/// Announce attendees whose rows arrived since the last read.
async fn announce_attendees(shared: &Arc<Shared>) {
    let Some(record) = &shared.record else {
        return;
    };
    let Ok(a) = record.attendance(&shared.room, shared.id).await else {
        return;
    };
    let fresh: Vec<String> = {
        let mut known = Shared::lock(&shared.attendees_known);
        a.attendees
            .into_iter()
            .filter(|k| known.insert(k.clone()))
            .collect()
    };
    for key_id in fresh {
        shared.emit(CallEvent::AttendeeJoined { key_id });
    }
}

/// Follow the room: roll when its epoch moves, keep every member's leg up.
async fn watch_loop(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(WATCH_TICK);
    let mut n: u64 = 0;
    let mut sent_expired: HashMap<[u8; 16], LegCounters> = HashMap::new();
    loop {
        tick.tick().await;
        if shared.ended.load(Ordering::Relaxed) {
            return;
        }
        n = n.wrapping_add(1);
        if n.is_multiple_of(ATTENDANCE_EVERY_TICKS) {
            announce_attendees(&shared).await;
        }
        if n.is_multiple_of(reannounce_ticks()) {
            let s = Arc::clone(&shared);
            tokio::spawn(async move { reannounce(&s).await });
        }
        if let Err(CallError::CallEnded(_)) = roll_if_moved(&shared).await {
            return;
        }
        reconcile_legs(&shared);
        let _ = apply_pending_replace(&shared, false).await;
        alm_tick(&shared, &mut sent_expired).await;
        settle_ends(&shared);
        check_lost(&shared);
    }
}

/// A fresh join nonce and the stream id it derives, drawn again on the
/// (2^-40) chance its first bytes read as a binding part or a C3 frame.
fn fresh_stream(room: &str, own_key_id: &str) -> Result<([u8; 32], StreamId), CallError> {
    let mut join_nonce = [0u8; 32];
    loop {
        ciris_crypto::random::fill(&mut join_nonce)
            .map_err(|e| CallError::Plumbing(format!("join nonce: {e}")))?;
        let stream = call_stream_id(room, own_key_id, &join_nonce);
        if !collides_with_binding_part(stream) && !collides_with_control_frame(stream) {
            return Ok((join_nonce, stream));
        }
    }
}

/// v45 — switch to a minted replacement once its overlap passed (or at
/// once, `force`): the publisher publishes the new stream from its next
/// chunk, and the old one stops.
async fn apply_pending_replace(shared: &Arc<Shared>, force: bool) -> Result<(), CallError> {
    let due = Shared::lock(&shared.pending_replace)
        .as_ref()
        .is_some_and(|p| force || p.ready.load(Ordering::Acquire));
    if !due {
        return Ok(());
    }
    let mut publisher = shared.publisher.lock().await;
    let Some(p) = Shared::lock(&shared.pending_replace).take() else {
        return Ok(());
    };
    let new = p.own_key.stream;
    let keep = publisher
        .replace_room_stream(new, p.dek)
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
    let old = std::mem::replace(&mut *Shared::lock(&shared.own_key), p.own_key).stream;
    Shared::lock(&shared.alm).replace_own_stream(new);
    drop(publisher);
    tracing::info!(
        old = %crate::transport::realtime_av::stream_label(old),
        new = %crate::transport::realtime_av::stream_label(new),
        "CALL STREAM REPLACED: this node now publishes the new stream (v45)"
    );
    if let KeepOutcome::Refused(r) = keep {
        shared.emit(CallEvent::KeepRefused {
            epoch: r.epoch,
            reason: r.kind,
        });
    }
    Ok(())
}

/// v45 — one installed binding's word on attendance (see
/// [`Attendance::on_bound`]), its events emitted. Another attendee's signed
/// end waits for its verdict ([`settle_ends`]).
fn on_bound(shared: &Arc<Shared>, b: &StreamKeyBinding) {
    if b.end.is_some() && b.publisher != shared.own {
        Shared::lock(&shared.attendance).defer_end(b, Instant::now());
        return;
    }
    let old_publisher = b.replaces.and_then(|old| {
        Shared::lock(&shared.alm)
            .bound_publisher_of(old)
            .map(str::to_owned)
    });
    let present = shared.auth.heard(b.stream);
    let truncated = b.end.is_some() && settle_truncation(shared, b.stream);
    let events = Shared::lock(&shared.attendance).on_bound(
        &shared.own,
        b,
        old_publisher.as_deref(),
        present,
        truncated,
    );
    for e in events {
        if let CallEvent::StreamReplaced { old, new, .. } = &e {
            Shared::lock(&shared.alm).forget_replaced_stream(*old, *new);
        }
        tracing::info!(event = ?e, "call: attendance (v45)");
        shared.emit(e);
    }
}

/// v45 — the truncation verdict on `stream`'s signed end, counted.
fn settle_truncation(shared: &Arc<Shared>, stream: StreamId) -> bool {
    let truncated = shared.auth.settle_end(stream);
    if truncated {
        shared.count(crate::observability::AV_CALL_STREAM_TRUNCATED);
    }
    truncated
}

/// v45 — every held signed end whose verdict is due: the attendee left,
/// truncated only if a chunk up to its `final_seq` is still missing once
/// [`END_VERDICT_AFTER`] passed (presence too is read then, so a stream
/// whose first chunks came in that window still counts as heard).
fn settle_ends(shared: &Arc<Shared>) {
    let due = Shared::lock(&shared.attendance).due_ends(Instant::now());
    for b in due {
        let present = shared.auth.heard(b.stream);
        let truncated = settle_truncation(shared, b.stream);
        let events =
            Shared::lock(&shared.attendance).on_bound(&shared.own, &b, None, present, truncated);
        for e in events {
            tracing::info!(event = ?e, "call: attendance (v45)");
            shared.emit(e);
        }
    }
}

/// v45 — every stream of `key_id` left the call for `cause`: once.
fn attendee_left(shared: &Arc<Shared>, key_id: &str, cause: LeaveCause) {
    let e = Shared::lock(&shared.attendance).leave_all(key_id, cause, |s| shared.auth.heard(s));
    if let Some(e) = e {
        tracing::info!(event = ?e, "call: attendance (v45)");
        shared.emit(e);
    }
}

/// v45 — `Lost`: an attendee with no leg up (neither this node's leg to it
/// nor its link to this node) for [`ATTENDEE_LOST_AFTER`], whose streams
/// have all been silent on every path that long, and no signed end seen.
fn check_lost(shared: &Arc<Shared>) {
    let now = Instant::now();
    let attendees: Vec<(String, Vec<StreamId>)> = Shared::lock(&shared.attendance)
        .streams
        .iter()
        .map(|(k, s)| (k.clone(), s.clone()))
        .collect();
    let bound_ms = u64::try_from(ATTENDEE_LOST_AFTER.as_millis()).unwrap_or(u64::MAX);
    for (key, streams) in attendees {
        let linked = Shared::lock(&shared.out_legs).contains_key(&key)
            || Shared::lock(&shared.in_links).values().any(|p| *p == key);
        let since = {
            let mut a = Shared::lock(&shared.attendance);
            if linked {
                a.unlinked_since.remove(&key);
                continue;
            }
            *a.unlinked_since.entry(key.clone()).or_insert(now)
        };
        if now.duration_since(since) < ATTENDEE_LOST_AFTER {
            continue;
        }
        let silent = {
            let a = Shared::lock(&shared.alm);
            streams.iter().all(|s| {
                a.stream_last_activity_ms(*s)
                    .is_none_or(|t| a.now_ms().saturating_sub(t) >= bound_ms)
            })
        };
        if silent {
            attendee_left(shared, &key, LeaveCause::Lost);
        }
    }
}

/// One ALM watch tick (stage 2): refresh C1's sender-side inputs from the
/// legs' link stats (queueing delay; timed frames that expired unconfirmed
/// count as drops), apply the service tier, run every selector and
/// admission (C2/C4/C6, the decision log), send the C3 frames they produced,
/// and report this call's load signals to the ladder.
/// One leg's cumulative leviculum counters as the last watch tick read them:
/// timed frames expired unconfirmed, and bytes the link proved delivered.
#[derive(Debug, Clone, Copy)]
struct LegCounters {
    expired: u64,
    delivered: u64,
}

async fn alm_tick(shared: &Arc<Shared>, sent_expired: &mut HashMap<[u8; 16], LegCounters>) {
    let legs: Vec<(String, [u8; 16])> = Shared::lock(&shared.out_legs)
        .iter()
        .map(|(p, l)| (p.clone(), l.link_id))
        .collect();
    for (peer, link) in &legs {
        let stats = shared.transport.av_link_stats(link);
        let expired = shared.transport.av_link_expired(link).sender;
        let delivered = stats.map_or(0, |st| st.bytes_delivered);
        let read = LegCounters { expired, delivered };
        let before = sent_expired.insert(*link, read).unwrap_or(read);
        let mut a = Shared::lock(&shared.alm);
        if let Some(st) = stats {
            a.set_leg_queue_ms(peer, st.queue_delay_ms());
        }
        // §5.1: what the link proved delivered is the uplink meter's rate.
        // A datagram leg proves nothing; its sends count as they leave
        // (`note_leg_outcomes`).
        a.on_delivered(delivered.saturating_sub(before.delivered));
        for _ in before.expired..expired {
            // An expired frame never reached the peer: a drop on this uplink.
            a.on_dropped(1_000);
        }
    }
    sent_expired.retain(|l, _| legs.iter().any(|(_, x)| x == l));
    let tier = shared
        .load
        .as_ref()
        .map_or(crate::load_ladder::ServiceTier::FullOps, |l| l.tier());
    let c3_legs: Vec<String> = {
        let members = Shared::lock(&shared.members).clone();
        let outs = Shared::lock(&shared.out_legs);
        let ins = Shared::lock(&shared.in_senders);
        let a = Shared::lock(&shared.alm);
        members
            .into_iter()
            .filter(|m| (outs.contains_key(m) || ins.contains_key(m)) && a.speaks_c3(m))
            .collect()
    };
    let (out, events, labels, gaps, commit) = {
        let mut a = Shared::lock(&shared.alm);
        let mut out = a.set_tier(tier);
        out.extend(a.tick(&c3_legs));
        a.book_decisions();
        (
            out,
            std::mem::take(&mut a.events),
            std::mem::take(&mut a.labels),
            std::mem::take(&mut a.gaps),
            a.relay_commit_ratio(),
        )
    };
    for l in labels {
        shared.count(l);
    }
    if let Some(m) = &shared.metrics {
        for (cause, gap) in gaps {
            m.telemetry.observe_failover_gap(cause, gap);
        }
        let now = c3_legs.len() as u64;
        let before = shared.c3_reported.swap(now, Ordering::Relaxed);
        m.telemetry.move_c3_peers(before, now);
    }
    for e in events {
        shared.emit(e);
    }
    if let Some(load) = &shared.load {
        load.report(crate::load_ladder::EdgeLoadSignals {
            relay_commit_ratio: commit,
            av_queue_age_ms: shared.queue_age_ms.swap(0, Ordering::Relaxed),
            transit_pps_ratio: 0.0,
        });
    }
    send_alm(shared, out).await;
}

#[cfg(test)]
#[path = "av_call/tests.rs"]
mod tests;
