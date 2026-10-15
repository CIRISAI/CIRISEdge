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
//! Every hop is a per-link transit KEX ([`crate::transport::av_transit_handshake`]);
//! there is no other key path. Each publisher DIALS every other member's call
//! address and sends its stream on the link it dialled (it is the KEX
//! initiator there); every member ACCEPTS the links others dial to it (the
//! responder, after the claim check) and reads their streams. The first frame
//! after the handshake on a publisher's link is a [`STREAM_HELLO_MAGIC`] frame
//! naming its stream, so a receiver attributes each stream to the member that
//! publishes it and tells a stream's own copy from a relayed one.
//!
//! With [`CallOptions::relay`], this node also forwards every stream it hears
//! FIRST-HAND to every other member (never back to its publisher, never a
//! relayed copy, so relays never loop), under each member's layer policy
//! ([`Call::set_layer_policy`]): a member then hears a stream on two legs.
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
//!   exist on this base.

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
use crate::transport::av_keep::{
    AvKeep, AvKeepTarget, KeepOutcome, KeptAvPublisher, StreamDekRegistrar,
};
use crate::transport::av_sink::AvArrival;
use crate::transport::realtime_av::{
    open_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, ReceiverLayerPolicy, SealedAvChunk,
    StreamId, AV_CHUNK_WIRE_OVERHEAD,
};
use crate::transport::realtime_av_dispatcher::{
    open_hop_outer, AvDispatcherError, AvLinkReceiver as _, AvLinkSender as _, AvSubscriberLink,
    HopGap, LegSend, LinkIdGuard,
};
use crate::transport::reticulum::ReticulumTransport;

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
}

impl Default for CallOptions {
    fn default() -> Self {
        Self {
            keep: AvKeep::Unkept,
            relay: false,
            default_policy: ReceiverLayerPolicy::UNCAPPED,
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
    /// The plaintext.
    pub bytes: Vec<u8>,
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
    /// One outcome per member leg.
    pub legs: Vec<(String, LegOutcome)>,
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
    /// The transport, the addressing plane or the media runtime refused.
    #[error("call plumbing: {0}")]
    Plumbing(String),
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

/// Everything a call runs on.
pub struct CallDeps {
    /// The room's MLS group (its current epoch keys the call).
    pub room_group: CohortGroup,
    /// persist's roster.
    pub roster: Arc<dyn RoomRoster>,
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
        // EWMA, alpha = 1/4.
        self.gap_ewma = (self.gap_ewma * 3 + gap) / 4;
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
        loop {
            let Some(next) = w.next else { break };
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
                match tx {
                    Some(tx) => {
                        let _ = tx.send(arrival).await;
                    }
                    None => {
                        r.unrouted.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(
                            peer = %arrival.peer.as_str(),
                            group = ?group,
                            "A/V link for no live call on this node — dropped (CIRISEdge#805)"
                        );
                    }
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
#[derive(Debug, Clone)]
struct OutLeg {
    link_id: [u8; 16],
    channel_limit: usize,
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
    stream: StreamId,
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
    stream_publishers: StdMutex<HashMap<StreamId, String>>,
    policies: StdMutex<HashMap<String, ReceiverLayerPolicy>>,
    members: StdMutex<Vec<String>>,
    heard_tx: mpsc::Sender<Heard>,
    events_tx: mpsc::Sender<CallEvent>,
    state: StdMutex<CallState>,
    epochs: StdMutex<Vec<u64>>,
    ended: AtomicBool,
    published: AtomicU64,
    metrics: Option<crate::observability::EdgeMetrics>,
    /// Test seam: hold every relayed copy this long before forwarding it.
    test_relay_delay_ms: AtomicU64,
    /// Test seam: withhold every `n`th own chunk (`chunk_seq % n == 0`) from
    /// the named member's leg (simulated loss on the direct leg).
    test_withhold: StdMutex<Option<(String, u64)>>,
}

impl Shared {
    fn lock<T>(m: &StdMutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
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
            .field("stream", &self.shared.stream)
            .finish_non_exhaustive()
    }
}

impl Drop for Call {
    fn drop(&mut self) {
        self.shared.ended.store(true, Ordering::Relaxed);
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
    pub async fn join(
        room: &str,
        own_key_id: &str,
        deps: CallDeps,
        opts: CallOptions,
    ) -> Result<Self, CallError> {
        let CallDeps {
            room_group,
            roster,
            transport,
            lifecycle,
            registrar,
            events,
            metrics,
        } = deps;
        let members = room_group.member_key_ids().await;
        if !members.iter().any(|m| m == own_key_id) {
            return Err(CallError::NotARoomMember {
                key_id: own_key_id.to_owned(),
                room: room.to_owned(),
            });
        }
        let active = roster
            .is_active_member(room, own_key_id)
            .await
            .map_err(|detail| CallError::RoomGroupUnavailable {
                room: room.to_owned(),
                detail: format!("active roster unreadable: {detail}"),
            })?;
        if !active {
            return Err(CallError::ConsentMissing {
                key_id: own_key_id.to_owned(),
                room: room.to_owned(),
            });
        }

        let id = call_id_for_room(room);
        let group_id = call_group_id(id);
        let scope = CohortScope::Cohort {
            cohort_id: room.to_owned(),
        };
        let mut join_nonce = [0u8; 32];
        ciris_crypto::random::fill(&mut join_nonce)
            .map_err(|e| CallError::Plumbing(format!("join nonce: {e}")))?;
        let stream = call_stream_id(room, own_key_id, &join_nonce);
        let epoch = Epoch(room_group.epoch().await);
        let dek = stream_epoch_dek(&room_group, stream, epoch)
            .await
            .map_err(|e| CallError::RoomGroupUnavailable {
                room: room.to_owned(),
                detail: e.to_string(),
            })?;
        let (publisher, keep) = KeptAvPublisher::create_room_keyed(
            stream,
            room,
            epoch,
            dek,
            opts.keep,
            AvKeepTarget {
                cohort_scope: "community".to_owned(),
                group_key_id: room.to_owned(),
            },
            registrar,
            events,
        )
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;

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

        let (heard_tx, heard_rx) = mpsc::channel::<Heard>(1024);
        let (frames_tx, frames_rx) = mpsc::channel::<ReceivedFrame>(256);
        let (events_tx, events_rx) = mpsc::channel::<CallEvent>(64);
        let shared = Arc::new(Shared {
            room: room.to_owned(),
            own: own_key_id.to_owned(),
            scope,
            group_id,
            stream,
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
            stream_publishers: StdMutex::new(HashMap::new()),
            policies: StdMutex::new(HashMap::new()),
            members: StdMutex::new(members),
            heard_tx,
            events_tx,
            state: StdMutex::new(CallState::Live),
            epochs: StdMutex::new(vec![epoch.0]),
            ended: AtomicBool::new(false),
            published: AtomicU64::new(0),
            metrics,
            test_relay_delay_ms: AtomicU64::new(0),
            test_withhold: StdMutex::new(None),
        });
        if let KeepOutcome::Refused(refused) = keep {
            shared.emit(CallEvent::KeepRefused {
                epoch: refused.epoch,
                reason: refused.kind,
            });
        }
        tracing::info!(
            room = %room,
            stream = %crate::transport::realtime_av::stream_label(stream),
            epoch = epoch.0,
            relay = opts.relay,
            "CALL JOINED: this node's stream is live in the room's call (CIRISEdge#805 item 5)"
        );

        let counts = Arc::new(StdMutex::new(ReorderCounts::default()));
        let tasks = vec![
            tokio::spawn(accept_loop(Arc::clone(&shared), arrivals)),
            tokio::spawn(reorder_loop(heard_rx, frames_tx, Arc::clone(&counts))),
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
        self.shared.stream
    }

    /// The call's epoch: the room's, as this stream last rolled to it.
    pub async fn epoch(&self) -> Epoch {
        self.shared.publisher.lock().await.epoch()
    }

    /// The largest frame plaintext every member leg carries (#720), or
    /// `None` before any leg is up.
    #[must_use]
    pub fn chunk_plaintext_budget(&self) -> Option<usize> {
        Shared::lock(&self.shared.out_legs)
            .values()
            .map(|l| l.channel_limit.saturating_sub(AV_CHUNK_WIRE_OVERHEAD))
            .min()
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
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        let budget = self.chunk_plaintext_budget().ok_or(CallError::NoBudget)?;
        if frame.bytes.len() > budget {
            return Err(CallError::FrameTooLarge {
                bytes: frame.bytes.len(),
                budget,
            });
        }
        let mut publisher = self.shared.publisher.lock().await;
        let (chunk_seq, inner) = publisher
            .seal_next(&frame.bytes, frame.codec_id, frame.layer)
            .map_err(|e| CallError::Plumbing(e.to_string()))?;
        let epoch = publisher.epoch();
        let withhold: Vec<String> = Shared::lock(&self.shared.test_withhold)
            .as_ref()
            .filter(|(_, n)| *n > 0 && chunk_seq.0 % n == 0)
            .map(|(peer, _)| vec![peer.clone()])
            .unwrap_or_default();
        let report = publisher
            .dispatcher_mut()
            .relay_inner_report(&inner, &withhold)
            .await
            .map_err(|e| CallError::Plumbing(e.to_string()))?;
        drop(publisher);
        self.shared.published.fetch_add(1, Ordering::Relaxed);
        let legs = report
            .into_iter()
            .map(|(peer, leg)| {
                let outcome = leg_outcome(leg);
                if outcome == LegOutcome::Gone {
                    Shared::lock(&self.shared.out_legs).remove(&peer);
                }
                (peer, outcome)
            })
            .collect();
        Ok(PublishReport {
            epoch,
            chunk_seq,
            legs,
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

    /// Test seam: withhold every `every`th own chunk from `member`'s leg.
    #[doc(hidden)]
    pub fn withhold_from_for_test(&self, member: &str, every: u64) {
        *Shared::lock(&self.shared.test_withhold) = Some((member.to_owned(), every));
    }

    /// Where the call stands.
    #[must_use]
    pub fn state(&self) -> CallState {
        Shared::lock(&self.shared.state).clone()
    }

    /// The reorder window's counters so far.
    #[must_use]
    pub fn reorder_counts(&self) -> ReorderCounts {
        *Shared::lock(&self.counts)
    }

    /// **Hang up** (§7: an in-room hang-up writes nothing): close this
    /// node's legs, stop listening at the call's addresses, end.
    ///
    /// # Errors
    /// [`CallError::CallEnded`] when it already ended.
    pub async fn leave(mut self) -> Result<CallSummary, CallError> {
        if let CallState::Ended(cause) = self.state() {
            return Err(CallError::CallEnded(cause));
        }
        *Shared::lock(&self.shared.state) = CallState::Ended(EndCause::HungUp);
        self.shared.ended.store(true, Ordering::Relaxed);
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
            stream: self.shared.stream,
            epochs: Shared::lock(&self.shared.epochs).clone(),
            frames_published: self.shared.published.load(Ordering::Relaxed),
            frames_received: counts.released,
            frames_skipped: counts.skipped,
            duplicates: counts.duplicates,
        })
    }
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
    Ok(ScopeGroupSnapshot {
        group_id: group_id.to_owned(),
        epoch: room_group.epoch().await,
        members: members.to_vec(),
        destination_secret: *secret.as_bytes(),
    })
}

/// **The roll** (§3.2, A3): when the room's epoch moved, every live stream
/// rolls (a new DEK, `chunk_seq` 0, through the keep layer), the call's
/// addresses follow the room, departed members' legs close and joined
/// members are dialled.
async fn roll_if_moved(shared: &Arc<Shared>) -> Result<(), CallError> {
    let room_epoch = shared.room_group.epoch().await;
    let mut publisher = shared.publisher.lock().await;
    let from = publisher.epoch().0;
    if room_epoch <= from {
        return Ok(());
    }
    let members = shared.room_group.member_key_ids().await;
    if !members.iter().any(|m| *m == shared.own) {
        *Shared::lock(&shared.state) = CallState::Ended(EndCause::Revoked);
        return Err(CallError::CallEnded(EndCause::Revoked));
    }
    let to = Epoch(room_epoch);
    let dek = stream_epoch_dek(&shared.room_group, shared.stream, to)
        .await
        .map_err(|e| CallError::RoomGroupUnavailable {
            room: shared.room.clone(),
            detail: e.to_string(),
        })?;
    let keep = publisher
        .roll_room_epoch(to, dek)
        .await
        .map_err(|e| CallError::Plumbing(e.to_string()))?;
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
    drop(publisher);
    *Shared::lock(&shared.members) = members.clone();
    Shared::lock(&shared.epochs).push(room_epoch);
    let mut closing = Vec::new();
    {
        let mut legs = Shared::lock(&shared.out_legs);
        for m in &left {
            if let Some(l) = legs.remove(m) {
                closing.push(l.link_id);
            }
        }
    }
    {
        let mut ins = Shared::lock(&shared.in_links);
        ins.retain(|link, peer| {
            if left.contains(peer) {
                closing.push(*link);
                false
            } else {
                true
            }
        });
    }
    for l in closing {
        let _ = shared.transport.link_teardown(&l).await;
    }
    match room_snapshot(&shared.room_group, &shared.group_id, &members).await {
        Ok(snapshot) => {
            if let Err(e) = shared
                .lifecycle
                .advance(&shared.scope, &snapshot, Instant::now())
            {
                *Shared::lock(&shared.state) = CallState::Degraded {
                    epoch: room_epoch,
                    reason: e.to_string(),
                };
                shared.emit(CallEvent::Stranded {
                    epoch: room_epoch,
                    reason: e.to_string(),
                });
            }
        }
        Err(e) => {
            *Shared::lock(&shared.state) = CallState::Degraded {
                epoch: room_epoch,
                reason: e.to_string(),
            };
        }
    }
    shared.emit(CallEvent::EpochRolled {
        from,
        to: room_epoch,
    });
    for m in left {
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
            dialling.insert(m.clone(), now + Duration::from_secs(3600));
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
    let hello = encode_hello(shared.stream);
    let deadline = tokio::time::Instant::now() + HELLO_BUDGET;
    loop {
        match link.sender.send(&hello).await {
            Ok(()) => break,
            Err(AvDispatcherError::Congested) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(e) => {
                tracing::debug!(peer = %member, error = %e, "call leg: hello not sent");
                let _ = shared.transport.link_teardown(&link.link_id).await;
                return false;
            }
        }
    }
    let policy = Shared::lock(&shared.policies)
        .get(member)
        .copied()
        .unwrap_or(shared.opts.default_policy);
    let seal_key = link.transit.seal_key();
    let link_id = link.link_id;
    {
        let mut publisher = shared.publisher.lock().await;
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
    }
    Shared::lock(&shared.out_legs).insert(
        member.to_owned(),
        OutLeg {
            link_id,
            channel_limit,
        },
    );
    tracing::info!(
        peer = %member,
        link = %hex::encode(link_id),
        channel_limit,
        "call leg UP: this node's stream rides a keyed link to the member (CIRISEdge#805)"
    );
    true
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
    let accepted = match shared.transport.accept_av_arrival(arrival).await {
        Ok(a) => a,
        Err(_) => return, // refused by name and counted by the transport
    };
    let peer = accepted.arrival.peer.as_str().to_owned();
    let link_id = accepted.arrival.link_id;
    if !Shared::lock(&shared.members).iter().any(|m| *m == peer) {
        tracing::warn!(peer = %peer, "call: a link from a non-member — closed");
        let _ = shared.transport.link_teardown(&link_id).await;
        return;
    }
    let inbound = accepted.arrival.inbound;
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
    Shared::lock(&shared.stream_publishers).insert(own_stream, peer.clone());
    Shared::lock(&shared.in_links).insert(link_id, peer.clone());
    let open_key = accepted.transit.open_key();
    pump(&shared, &peer, own_stream, link_id, &open_key, inbound).await;
    Shared::lock(&shared.in_links).remove(&link_id);
}

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
    let mut guard = LinkIdGuard::default();
    while let Ok(frame) = inbound.recv_frame().await {
        if shared.ended.load(Ordering::Relaxed) {
            break;
        }
        let at = Instant::now();
        let dropped = gap.report(frame.dropped_before);
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
        next_seq = opened_at.wrapping_add(1);
        let stream = inner.stream_id();
        // First-hand copies only are relayed: never a relayed copy, never
        // back to its publisher.
        if shared.opts.relay && stream == own_stream {
            let delay = shared.test_relay_delay_ms.load(Ordering::Relaxed);
            if delay == 0 {
                relay(shared, &inner, peer).await;
            } else {
                let (s, i, p) = (Arc::clone(shared), inner.clone(), peer.to_owned());
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    relay(&s, &i, &p).await;
                });
            }
        }
        let Some(dek) = shared.keys.dek(stream, inner.epoch()).await else {
            shared.count(crate::observability::AV_CALL_FRAME_NO_KEY);
            continue;
        };
        let Ok(bytes) = open_av_inner(&inner, &dek) else {
            shared.count(crate::observability::AV_CALL_FRAME_UNOPENED);
            continue;
        };
        let publisher = Shared::lock(&shared.stream_publishers)
            .get(&stream)
            .cloned()
            .unwrap_or_else(|| peer.to_owned());
        let heard = Heard {
            frame: ReceivedFrame {
                publisher,
                stream,
                epoch: inner.epoch(),
                chunk_seq: inner.chunk_seq(),
                codec_id: inner.codec_id(),
                layer: inner.layer(),
                bytes,
            },
            at,
        };
        if shared.heard_tx.send(heard).await.is_err() {
            break;
        }
    }
}

/// Forward a first-hand chunk to every member but its publisher, under each
/// member's layer policy.
async fn relay(
    shared: &Arc<Shared>,
    inner: &crate::transport::realtime_av::InnerSealed,
    publisher_peer: &str,
) {
    let mut publisher = shared.publisher.lock().await;
    if let Ok(report) = publisher
        .dispatcher_mut()
        .relay_inner_report(inner, &[publisher_peer.to_owned()])
        .await
    {
        for (_, leg) in report {
            if matches!(leg, LegSend::Sent) {
                shared.count(crate::observability::AV_CALL_RELAYED);
            }
        }
    }
}

async fn reorder_loop(
    mut heard: mpsc::Receiver<Heard>,
    frames: mpsc::Sender<ReceivedFrame>,
    counts: Arc<StdMutex<ReorderCounts>>,
) {
    let mut window = ReorderWindow::new();
    loop {
        let released = match window.next_deadline() {
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
        *counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = window.counts();
        for f in released {
            if frames.send(f).await.is_err() {
                return;
            }
        }
    }
}

/// Follow the room: roll when its epoch moves, keep every member's leg up.
async fn watch_loop(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(WATCH_TICK);
    loop {
        tick.tick().await;
        if shared.ended.load(Ordering::Relaxed) {
            return;
        }
        if let Err(CallError::CallEnded(_)) = roll_if_moved(&shared).await {
            return;
        }
        reconcile_legs(&shared);
    }
}

#[cfg(test)]
#[path = "av_call/tests.rs"]
mod tests;
