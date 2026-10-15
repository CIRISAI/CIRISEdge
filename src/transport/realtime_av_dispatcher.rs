//! Layer-2 wire-driver for the realtime A/V publisher / relay / subscriber
//! paths (CIRISEdge#155, Gap 1).
//!
//! ## What this module closes
//!
//! The Layer-1 primitives ([`super::realtime_av`] +
//! [`super::realtime_av_relay`]) produce the per-subscriber sealed wire
//! bytes but stop at the byte boundary: `RelayNode::forward` returns
//! `Vec<RelayForwardOut>` and explicitly defers "the actual outbound
//! enqueue onto each subscriber's RNS Link" to Layer 2. Today a fabric
//! node consuming those primitives has to hand-roll the
//! publisher→relay→subscriber wire path itself.
//!
//! [`AvDispatcher`] is that wire path. It composes the existing seal /
//! open primitives with caller-supplied byte-stream send/recv handles,
//! drives the per-link `link_seq` counters, and surfaces reconstructed
//! plaintext chunks to the subscriber side. A fabric node *relays*
//! rather than *re-implements transport*.
//!
//! ## The transport seam
//!
//! The dispatcher does NOT depend on leviculum / reticulum-core. It
//! talks to the transport through two object-safe traits —
//! [`AvLinkSender`] + [`AvLinkReceiver`] — that the caller implements
//! over whatever async byte-stream their transport provides (an RNS
//! Link, an HTTP body channel, an in-memory mpsc in tests). This keeps
//! the dispatcher feature-agnostic: it compiles and runs identically
//! for the HTTP and Reticulum transports.
//!
//! ## Crypto invariant carried through
//!
//! The three roles map onto the Layer-1 crypto tiers exactly:
//!
//! - **Publisher** holds the [`EpochDek`]; it inner-seals once (caller
//!   side) and the dispatcher outer-seals per subscriber.
//! - **Relay** holds NO `EpochDek` — `epoch_dek` MUST be `None` for the
//!   relay role. It opens the inbound outer AEAD with the inbound
//!   transit key, recovers the still-E2E-sealed [`InnerSealed`], and
//!   re-seals per downstream subscriber. It never sees plaintext.
//! - **Subscriber** holds the `EpochDek`; it opens both AEAD layers and
//!   recovers plaintext.
//!
//! The relay's no-DEK posture is enforced at construction:
//! [`AvDispatcher::relay_chunk`] never consults `epoch_dek`, and a
//! `Relay`-role dispatcher constructed WITH an `epoch_dek` is a caller
//! error the publisher/subscriber paths still reject structurally (they
//! require the DEK).

use std::collections::HashMap;

use tokio::sync::mpsc;

use super::realtime_av::{
    open_av_chunk, open_av_outer, seal_av_outer, ChunkSeq, Epoch, EpochDek, InnerSealed,
    SealedAvChunk, StreamId,
};

/// Federation-key identifier for a subscriber — the same identifier
/// space as [`super::realtime_av_relay::PeerKeyId`] (the federation
/// `key_id`, not the RNS identity hash). Defined here as an alias so
/// the dispatcher stays ungated: the relay module is behind the
/// `_reticulum-module` feature, but this Layer-2 wire-driver compiles
/// for every transport.
pub type PeerKeyId = String;

/// CIRISEdge#720 — an A/V wire frame larger than the link Channel will carry.
///
/// A link-Channel send accepts `link_mdu − CHANNEL_ENVELOPE_HEADER_SIZE`
/// bytes (the #716 six-byte margin: 425 on a base-MTU 500 link). Anything
/// larger is refused by leviculum as `TooLarge` and folded into a generic
/// `LinkFailed` on the way out, which is how an oversized chunk used to
/// read as [`AvDispatcherError::SendFailed`]. A sender that knows its
/// link's limit checks BEFORE handing the bytes over and refuses with
/// this, so the producer learns the one thing it can act on — cut the
/// chunk smaller — instead of seeing a link failure that is not one.
///
/// Nothing was handed to the transport: the refusal is final for this
/// frame and says nothing about the link's health.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkTooLarge {
    /// The wire frame the caller tried to send (sealed chunk, both AEAD
    /// layers, header included).
    pub frame_bytes: usize,
    /// The most this link's Channel carries in one message.
    pub channel_limit: usize,
}

impl std::fmt::Display for ChunkTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "A/V frame of {} bytes exceeds the link Channel's {}-byte payload limit \
             (link MDU minus the Channel envelope header, CIRISEdge#720/#716) — cut the \
             chunk smaller; it was NOT sent",
            self.frame_bytes, self.channel_limit
        )
    }
}

/// Errors the dispatcher surface can return.
#[derive(thiserror::Error, Debug)]
pub enum AvDispatcherError {
    /// A caller-supplied [`AvLinkSender::send`] failed. Carries the
    /// transport's own error string — the dispatcher is transport-blind
    /// so it cannot type the underlying cause.
    #[error("transport send failed: {0}")]
    SendFailed(String),
    /// CIRISEdge#591 / leviculum#66 — the link REFUSED the bytes because it
    /// is applying backpressure (leviculum's `Busy` / `PacingDelay`, which
    /// is Reticulum's `Channel.is_ready_to_send()` surfaced as an error).
    ///
    /// **This is not a failure and must not be handled as one.** Nothing
    /// was handed to the transport, nothing was lost, and nothing is wrong
    /// with the frame — the caller is expected to defer via
    /// [`crate::transport::av_backpressure::PeerBackoff`] rather than
    /// retry at rate or drop. Conflating it with [`Self::SendFailed`] is
    /// how a producer ends up generating into a peer that is shedding
    /// everything it sends, which is the field failure #591 opens with.
    ///
    /// Carries no timing deliberately. leviculum's `PacingDelay` reports a
    /// `ready_at_ms` on ITS monotonic clock, and edge has no access to that
    /// clock's `now` — comparing it against edge's own `Instant` would be a
    /// cross-clock bug that reads as a tuning problem. The schedule is
    /// edge's, computed from Reticulum's curve.
    #[error("link is applying backpressure (leviculum#66); defer, do not retry at rate")]
    Congested,
    /// CIRISEdge#720 — the frame is larger than the link's Channel carries.
    /// Refused before the transport saw it; see [`ChunkTooLarge`]. Like
    /// [`Self::Congested`] and unlike [`Self::SendFailed`], nothing left
    /// the process.
    #[error("{0}")]
    ChunkTooLarge(ChunkTooLarge),
    /// A caller-supplied [`AvLinkReceiver::recv`] failed.
    #[error("transport recv failed: {0}")]
    RecvFailed(String),
    /// CIRISEdge#866 — the `(transit key, link_id)` pair is already live
    /// under another subscriber. Two live counters under one pair would
    /// repeat outer nonces, so the admission is refused and nothing
    /// changes. See [`crate::transport::realtime_av::LinkSeqLedger`].
    #[error(
        "transit key + link_id already live for another subscriber ({0}); refused (CIRISEdge#866)"
    )]
    TransitPairInUse(PeerKeyId),
    /// An AEAD open failed — either the inbound outer layer (relay /
    /// subscriber) or the inner layer (subscriber). Most commonly a
    /// wrong transit key or a `link_seq` desync.
    #[error("AEAD open failed: {0}")]
    OpenFailed(String),
    /// The outer re-seal failed during fan-out.
    #[error("relay forward failed: {0}")]
    ForwardFailed(String),
    /// CIRISEdge#805 item 8 — the link is gone (closed by its peer or
    /// reaped): nothing was sent and nothing ever will be on it. Distinct from
    /// [`Self::SendFailed`] so a fan-out can PRUNE the subscriber rather than
    /// fail every later chunk on it (a subscriber that dropped its relay leg
    /// closes the link on purpose).
    #[error("the link is gone: {0}")]
    LinkGone(String),
    /// An endpoint role (publisher or subscriber) was constructed
    /// without an `epoch_dek`. Structural guard for the relay-vs-
    /// endpoint role split: endpoints inner-seal / inner-open under
    /// the DEK; a subscriber with no DEK silently black-holes every
    /// received frame, which v4.6.2 (Codex P2.1) rejects at
    /// construction. The error name preserves backward source
    /// compatibility; it now applies to both endpoint roles.
    #[error("endpoint role (publisher/subscriber) requires epoch_dek; none provided")]
    PublisherMissingEpochDek,
    /// A subscriber-tier mutation referenced a subscriber the dispatcher
    /// has no downstream link for.
    #[error("subscriber not found: {0:?}")]
    SubscriberNotFound(PeerKeyId),
}

/// CIRISEdge#867 — how many frames a link may fail to open, from its FIRST
/// frame on, before it is judged to run under a different `link_id` than
/// the one this end seals and opens with.
pub const LINK_ID_MISMATCH_FRAMES: u32 = 8;

/// CIRISEdge#867 — tells a link sealed under another `link_id` from a link
/// with a bad frame or two.
///
/// leviculum (Codeberg #66, CIRISAI/leviculum#86) can report a stale
/// `link_id` on the initiator after a link-establishment retry: the wire id
/// changed, the handle kept the original. The outer nonce, and the coming
/// per-hop transit key, are bound to `link_id`, so every frame on such a
/// link fails its tag. Without this guard that is silent, unbounded media
/// loss. The signature is exact: a link that has NEVER opened a frame and
/// has now failed [`LINK_ID_MISMATCH_FRAMES`] in a row. A link that opened
/// even one frame shares this end's `link_id`, and a later failure there
/// is a bad frame, never a mismatch.
///
/// The receive loop ends the link's subscription on a mismatch. On the
/// leg path, that is the relay leg ending, and leg choice asks the host to
/// rejoin (re-dial), which gets a new link and a new id. The real fix
/// reads the WIRE id from leviculum (`wire_link_id`, leviculum v0.32).
#[derive(Debug, Default)]
pub struct LinkIdGuard {
    opened: bool,
    unopened: u32,
}

impl LinkIdGuard {
    /// A frame opened: this link shares our `link_id` for good.
    pub fn opened(&mut self) {
        self.opened = true;
    }

    /// A frame failed to open at every candidate counter. Returns `true`
    /// when that makes the link a `link_id` mismatch.
    pub fn unopened(&mut self) -> bool {
        if self.opened {
            return false;
        }
        self.unopened = self.unopened.saturating_add(1);
        self.unopened >= LINK_ID_MISMATCH_FRAMES
    }

    /// Frames failed so far without a single open.
    #[must_use]
    pub fn unopened_count(&self) -> u32 {
        self.unopened
    }

    /// Log (and count, where `metrics` is in reach) the end of a link judged
    /// a `link_id` mismatch. `role` names the loop that ended it.
    pub(crate) fn report_mismatch(
        &self,
        role: &str,
        link_id: &[u8],
        metrics: Option<&crate::observability::EdgeMetrics>,
    ) {
        if let Some(m) = metrics {
            m.inc_av_plane(crate::observability::AV_LINK_ID_MISMATCH);
        }
        tracing::error!(
            role,
            link = %hex::encode(link_id),
            unopened = self.unopened,
            "AV: no frame on this link has ever opened — link_id mismatch \
             (leviculum#86); the link is ENDED so it is re-dialled (CIRISEdge#867)"
        );
    }
}

/// Open a hop's outer AEAD at the first counter in
/// [`hop_counter_candidates`] that authenticates, returning the counter
/// it opened at and the still-E2E-sealed inner chunk. `None` when no
/// candidate opens (a corrupt, foreign or replayed frame): the caller
/// skips the frame and keeps its counter.
#[must_use]
pub fn open_hop_outer(
    sealed: &SealedAvChunk,
    transit_key: &[u8; 32],
    link_id: &[u8],
    next_link_seq: u64,
    dropped_before: u64,
) -> Option<(u64, InnerSealed)> {
    open_at_first_counter(next_link_seq, dropped_before, |c| {
        open_av_outer(sealed, transit_key, link_id, c).ok()
    })
}

/// The role a dispatcher instance plays in the A/V wire path. Selects
/// which Layer-1 crypto tier the inbound/outbound paths drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvRole {
    /// Holds the [`EpochDek`]; inner-seals (caller) then outer-seals per
    /// subscriber. Drives [`AvDispatcher::publish_inner`].
    Publisher,
    /// Holds NO `EpochDek`; opens the inbound outer AEAD and re-seals
    /// per downstream subscriber. Drives [`AvDispatcher::relay_chunk`].
    Relay,
    /// Holds the `EpochDek`; opens both AEAD layers to recover
    /// plaintext. Drives [`AvDispatcher::spawn_subscriber_loop`].
    Subscriber,
}

/// The async byte-stream send half the caller plugs in over their
/// Reticulum Link (or any transport). Object-safe so the dispatcher can
/// hold a heterogeneous roster of `Box<dyn AvLinkSender>`.
#[async_trait::async_trait]
pub trait AvLinkSender: Send + Sync + 'static {
    /// Enqueue `bytes` onto the outbound link.
    ///
    /// Returns [`AvDispatcherError::SendFailed`] on transport error, and
    /// [`AvDispatcherError::Congested`] when the link refused the bytes
    /// under backpressure — a distinction the caller MUST preserve
    /// (CIRISEdge#591). An implementation over a transport that offers both
    /// a refusing and an absorbing send is required to use the refusing
    /// one: absorbing the condition here makes it unobservable to every
    /// layer above, which is exactly the defect leviculum#66 documents.
    async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError>;
}

/// The async byte-stream recv half the caller plugs in. `recv` resolves
/// to the next inbound wire frame, or [`AvDispatcherError::RecvFailed`]
/// on transport error / closed link.
#[async_trait::async_trait]
pub trait AvLinkReceiver: Send + Sync + 'static {
    /// Pull the next inbound wire frame.
    async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError>;

    /// Pull the next inbound wire frame together with how many frames the
    /// transport DROPPED on this link immediately before it.
    ///
    /// A hop's outer nonce is a dense per-link counter that is not on the
    /// wire, so a frame dropped below the dispatcher (an overflowing
    /// inbound queue — CIRISEdge#805's never-block drop policy) would
    /// otherwise desync every later frame on the hop. A receiver that
    /// drops reports the count here and the open loops skip the counter
    /// past it ([`hop_counter_candidates`]). The default reports no gap,
    /// which is exact for a receiver that never drops.
    async fn recv_frame(&self) -> Result<InboundWireFrame, AvDispatcherError> {
        Ok(InboundWireFrame {
            dropped_before: 0,
            bytes: self.recv().await?,
        })
    }
}

/// One inbound wire frame and the drops that preceded it (see
/// [`AvLinkReceiver::recv_frame`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundWireFrame {
    /// Frames the transport dropped on this link since the previous frame
    /// it delivered.
    pub dropped_before: u64,
    /// The frame.
    pub bytes: Vec<u8>,
}

/// Extra hop-counter values an open loop tries PAST the reported gap.
///
/// The reported gap is exact for drops the receiver made, but a counter
/// can also be burned on the SEND side without a frame (a relay leg whose
/// caller's send was refused after `RelayNode::forward` advanced it). This
/// slack recovers up to this many such burned counters beyond the gap.
pub const HOP_COUNTER_RESYNC_SLACK: u64 = 8;

/// The most AEAD opens one frame can cost, WHATEVER the reported gap: the
/// counter past the gap, the expected counter, and the slack past the gap
/// ([`hop_counter_candidates`]). A junk frame after a burst of a thousand
/// drops costs exactly this many opens, not a thousand.
pub const HOP_COUNTER_MAX_OPENS: u64 = HOP_COUNTER_RESYNC_SLACK + 2;

/// The hop counters an open loop tries for a frame, most likely first, and
/// never more than [`HOP_COUNTER_MAX_OPENS`] of them:
///
/// 1. `skipped = next + dropped_before` — the counter past the frames the
///    receiver itself dropped;
/// 2. `next` — the expected counter, for a gap report that over-counted (a
///    dropped JUNK frame never took a counter, so the next real frame is
///    still at `next`);
/// 3. `skipped + 1 ..= skipped + SLACK` — counters burned on the send side.
///
/// The counters strictly between `next` and `skipped` are NOT tried: they
/// belong to frames the receiver dropped, which are gone and never come
/// back. Never a counter below `next`, so a replayed frame never opens.
pub fn hop_counter_candidates(next: u64, dropped_before: u64) -> impl Iterator<Item = u64> {
    let skipped = next.saturating_add(dropped_before);
    let expected = (skipped != next).then_some(next);
    std::iter::once(skipped)
        .chain(expected)
        .chain((1..=HOP_COUNTER_RESYNC_SLACK).map_while(move |k| skipped.checked_add(k)))
}

/// The drop report a hop has not yet resolved (Codex on #813).
///
/// A receiver reports the frames it dropped ONCE, on the next frame it
/// queues, and then resets its own count. If that frame cannot be parsed or
/// opened — a junk frame from the peer, a corrupt one — the report must
/// survive it: discarding it leaves the next real frame reporting zero while
/// the sender's counter is past the slack, and every later frame on the hop
/// then fails authentication. So an open loop folds each frame's report in
/// here and spends it only when a frame authenticates.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HopGap {
    pending: u64,
}

impl HopGap {
    /// Fold in the drops reported with the frame just received; the gap to
    /// try this frame at.
    pub fn report(&mut self, dropped_before: u64) -> u64 {
        self.pending = self.pending.saturating_add(dropped_before);
        self.pending
    }

    /// A frame authenticated: the gap is resolved.
    pub fn resolved(&mut self) {
        self.pending = 0;
    }

    /// The gap still unresolved.
    #[must_use]
    pub const fn pending(&self) -> u64 {
        self.pending
    }
}

/// Open a frame at the first of its [`hop_counter_candidates`] that
/// authenticates: the counter it opened at and what `open` returned. The
/// one place both open loops (subscriber, relay) pick a counter, so the
/// [`HOP_COUNTER_MAX_OPENS`] bound holds for both.
pub fn open_at_first_counter<T>(
    next_link_seq: u64,
    dropped_before: u64,
    mut open: impl FnMut(u64) -> Option<T>,
) -> Option<(u64, T)> {
    hop_counter_candidates(next_link_seq, dropped_before).find_map(|c| open(c).map(|t| (c, t)))
}

/// One downstream subscriber link the dispatcher fans out onto. The
/// `transit_key` + `link_id` are the per-(subscriber, stream) outer-AEAD
/// state established out-of-band via the hybrid PQC KEX; the dispatcher
/// owns the monotonic `link_seq` counter internally.
pub struct AvSubscriberLink {
    /// Federation `key_id` of the subscriber — same identifier space as
    /// [`super::realtime_av_relay::PeerKeyId`].
    pub subscriber: PeerKeyId,
    /// Per-link outer-AEAD transit key (32B AES-256-GCM key).
    pub transit_key: [u8; 32],
    /// The `link_id` fed to [`super::realtime_av::derive_outer_nonce`].
    /// Convention matches the relay surface: the subscriber's `key_id`
    /// bytes.
    pub link_id: Vec<u8>,
    /// Caller-plugged outbound byte-stream handle.
    pub outbound_send: Box<dyn AvLinkSender>,
}

/// One inbound link the dispatcher pulls from. The `transit_key` +
/// `link_id` are the per-link outer-AEAD state for THIS hop — for a
/// relay, the upstream transit key; for a subscriber, the
/// relay→subscriber (or publisher→subscriber) transit key.
pub struct AvInboundLink {
    /// Per-link inbound outer-AEAD transit key (32B).
    pub transit_key: [u8; 32],
    /// `link_id` for the inbound outer-nonce derivation.
    pub link_id: Vec<u8>,
    /// Caller-plugged inbound byte-stream handle.
    pub inbound_recv: Box<dyn AvLinkReceiver>,
}

/// Construction config for an [`AvDispatcher`].
pub struct AvDispatcherConfig {
    /// The stream this dispatcher drives.
    pub stream_id: StreamId,
    /// The role this instance plays — selects the crypto tier.
    pub local_role: AvRole,
    /// The epoch DEK. `Some` for [`AvRole::Publisher`] /
    /// [`AvRole::Subscriber`]; MUST be `None` for [`AvRole::Relay`]
    /// (the relay holds no DEK — structural invariant).
    pub epoch_dek: Option<[u8; 32]>,
    /// Downstream subscriber links the dispatcher fans out onto
    /// (publisher / relay roles). Empty for a pure subscriber.
    pub initial_subscribers: Vec<AvSubscriberLink>,
    /// Inbound links the dispatcher pulls from (relay / subscriber
    /// roles). Empty for a pure publisher.
    pub inbound_links: Vec<AvInboundLink>,
}

/// A plaintext chunk reconstructed on the subscriber side, surfaced over
/// the [`AvDispatcher::spawn_subscriber_loop`] channel.
#[derive(Debug, Clone)]
pub struct ReconstructedChunk {
    pub stream_id: StreamId,
    pub epoch: Epoch,
    pub chunk_seq: ChunkSeq,
    pub plaintext: Vec<u8>,
}

/// Per-downstream-subscriber outbound state held by the dispatcher.
struct OutboundState {
    transit_key: [u8; 32],
    link_id: Vec<u8>,
    next_link_seq: u64,
    sender: Box<dyn AvLinkSender>,
}

/// Wire-driver for realtime A/V publisher / relay / subscriber paths.
///
/// Owns:
/// - the per-link outbound state (transit key + `link_id` + monotonic
///   `link_seq` + the caller's [`AvLinkSender`]) for each downstream
///   subscriber
/// - the inbound links (relay / subscriber roles)
/// - the stream's `EpochDek` (publisher / subscriber roles only — never
///   the relay)
///
/// An async receiver loop ([`Self::spawn_subscriber_loop`]) pumps
/// inbound bytes through `open_av_chunk` and surfaces reconstructed
/// chunks; the publisher / relay paths
/// ([`Self::publish_inner`] / [`Self::relay_chunk`]) pump outbound.
///
/// CIRISEdge#155 closure. Fabric nodes use this directly instead of
/// re-implementing the wire path.
pub struct AvDispatcher {
    stream_id: StreamId,
    local_role: AvRole,
    epoch_dek: Option<EpochDek>,
    /// Downstream subscriber roster, keyed by `key_id`. Insertion order
    /// is irrelevant — fan-out visits every entry.
    subscribers: HashMap<PeerKeyId, OutboundState>,
    /// Inbound links, consumed by [`Self::spawn_subscriber_loop`].
    inbound_links: Vec<AvInboundLink>,
    /// CIRISEdge#866 — where each retired `(transit key, link_id)` pair's
    /// counter stopped; a re-admission resumes it, never restarts it.
    link_seqs: crate::transport::realtime_av::LinkSeqLedger,
}

impl AvDispatcher {
    /// Build a dispatcher from its config.
    ///
    /// # Errors
    ///
    /// Returns [`AvDispatcherError::PublisherMissingEpochDek`] if a
    /// [`AvRole::Publisher`] OR [`AvRole::Subscriber`] is constructed
    /// without an `epoch_dek` — the publisher path cannot inner-seal
    /// without the DEK, and a subscriber without a DEK silently
    /// black-holes every received frame in `spawn_subscriber_loop`
    /// (the inner-open call would fail and the frame would be skipped
    /// per the per-frame resilience policy). v4.6.2 (Codex P2.1)
    /// surfaces this at construction so the misconfiguration is
    /// caught immediately instead of producing a silently-dropping
    /// stream.
    ///
    /// A [`AvRole::Relay`] with an `epoch_dek` is accepted but the
    /// DEK is dropped on construction: the relay never holds one,
    /// structurally (the field stays `None`).
    pub fn new(config: AvDispatcherConfig) -> Result<Self, AvDispatcherError> {
        if matches!(config.local_role, AvRole::Publisher | AvRole::Subscriber)
            && config.epoch_dek.is_none()
        {
            return Err(AvDispatcherError::PublisherMissingEpochDek);
        }
        // Structural invariant: the relay never holds a DEK. Even if the
        // caller passed one, drop it on the floor — `relay_chunk` never
        // reads it, and keeping it would weaken the no-plaintext story.
        let epoch_dek = match config.local_role {
            AvRole::Relay => None,
            AvRole::Publisher | AvRole::Subscriber => config.epoch_dek.map(EpochDek::from_bytes),
        };

        let mut subscribers: HashMap<PeerKeyId, OutboundState> =
            HashMap::with_capacity(config.initial_subscribers.len());
        for link in config.initial_subscribers {
            // CIRISEdge#866 — two initial subscribers on one pair would run
            // two counters from 0 under one key.
            if crate::transport::realtime_av::LinkSeqLedger::live_conflict(
                &link.transit_key,
                &link.link_id,
                subscribers
                    .iter()
                    .filter(|(who, _)| **who != link.subscriber)
                    .map(|(_, st)| (&st.transit_key, st.link_id.as_slice())),
            ) {
                return Err(AvDispatcherError::TransitPairInUse(link.subscriber));
            }
            subscribers.insert(
                link.subscriber,
                OutboundState {
                    transit_key: link.transit_key,
                    link_id: link.link_id,
                    next_link_seq: 0,
                    sender: link.outbound_send,
                },
            );
        }

        Ok(Self {
            stream_id: config.stream_id,
            local_role: config.local_role,
            epoch_dek,
            subscribers,
            inbound_links: config.inbound_links,
            link_seqs: crate::transport::realtime_av::LinkSeqLedger::default(),
        })
    }

    /// The stream this dispatcher drives.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// The role this dispatcher plays.
    #[must_use]
    pub fn role(&self) -> AvRole {
        self.local_role
    }

    /// Number of downstream subscriber links currently registered.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }

    /// Publisher path: outer-seal a caller-supplied (already inner-
    /// sealed) chunk per subscriber and enqueue each onto its outbound
    /// link.
    ///
    /// The `inner` is the publisher's E2E-sealed chunk (produced by the
    /// caller via [`super::realtime_av::seal_av_inner`] under the epoch
    /// DEK). For each downstream subscriber the dispatcher calls
    /// [`seal_av_outer`] with that subscriber's per-link transit key +
    /// monotonic `link_seq`, then sends the resulting [`SealedAvChunk`]
    /// wire bytes via the subscriber's [`AvLinkSender`].
    ///
    /// The per-link `link_seq` advances only after a successful seal —
    /// a send failure does NOT roll the counter back (the bytes were
    /// sealed and may have hit the wire), but a seal failure leaves the
    /// counter idle so the next attempt reuses the same `link_seq`
    /// without a nonce-reuse hazard.
    ///
    /// # Errors
    ///
    /// - [`AvDispatcherError::ForwardFailed`] if [`seal_av_outer`]
    ///   fails for any subscriber.
    /// - [`AvDispatcherError::SendFailed`] (propagated) if a transport
    ///   send fails. Every subscriber is attempted first; the first
    ///   error is returned after the whole roster (CIRISEdge#805 item 8).
    ///   A subscriber whose link is gone ([`AvDispatcherError::LinkGone`])
    ///   is pruned from the roster, not reported.
    pub async fn publish_inner(&mut self, inner: InnerSealed) -> Result<(), AvDispatcherError> {
        self.fan_out(&inner).await
    }

    /// Relay path: open the inbound outer AEAD with the inbound link's
    /// transit key, recover the still-E2E-sealed [`InnerSealed`], then
    /// fan out per downstream subscriber.
    ///
    /// The relay holds NO `EpochDek`; this method works at the outer-AEAD
    /// layer only. The inner ciphertext is byte-identical from the
    /// inbound wire through to each downstream [`SealedAvChunk`] — the
    /// relay never sees plaintext.
    ///
    /// `inbound_link_id` + `inbound_link_seq` are the per-link state for
    /// the UPSTREAM hop the chunk arrived on — the caller tracks these
    /// against the inbound link it received `sealed` from.
    ///
    /// # Errors
    ///
    /// - [`AvDispatcherError::OpenFailed`] if [`open_av_outer`] fails
    ///   (wrong inbound transit key / `link_seq` desync / tampered
    ///   ciphertext).
    /// - [`AvDispatcherError::ForwardFailed`] / `SendFailed` on the
    ///   downstream fan-out, as [`Self::publish_inner`].
    pub async fn relay_chunk(
        &mut self,
        sealed: SealedAvChunk,
        inbound_transit_key: &[u8; 32],
        inbound_link_id: &[u8],
        inbound_link_seq: u64,
    ) -> Result<(), AvDispatcherError> {
        let inner = open_av_outer(
            &sealed,
            inbound_transit_key,
            inbound_link_id,
            inbound_link_seq,
        )
        .map_err(|e| AvDispatcherError::OpenFailed(e.to_string()))?;
        self.fan_out(&inner).await
    }

    /// Relay path for a chunk whose outer layer the caller already opened
    /// ([`open_hop_outer`]): fan the recovered [`InnerSealed`] out to every
    /// downstream subscriber. Split from [`Self::relay_chunk`] so a pump can
    /// advance its inbound counter on the OPEN, independent of whether the
    /// downstream fan-out then succeeds — an opened frame consumed its
    /// counter whatever happens after.
    ///
    /// # Errors
    ///
    /// As [`Self::publish_inner`].
    pub async fn relay_inner(&mut self, inner: InnerSealed) -> Result<(), AvDispatcherError> {
        self.fan_out(&inner).await
    }

    /// Shared outer-seal-and-send fan-out used by both the publisher and
    /// relay paths. Visits every downstream subscriber, seals with its
    /// per-link state, advances its `link_seq`, and sends.
    async fn fan_out(&mut self, inner: &InnerSealed) -> Result<(), AvDispatcherError> {
        // CIRISEdge#805 item 8 — EVERY subscriber is attempted. This
        // loop used to return on the first refusal, so one congested or closed
        // downstream link starved every subscriber after it in (random)
        // HashMap order. The first error is still returned, after the loop;
        // a subscriber whose link is GONE is pruned, not reported.
        let mut first_err: Option<AvDispatcherError> = None;
        let mut gone: Vec<PeerKeyId> = Vec::new();
        for (subscriber, state) in &mut self.subscribers {
            let link_seq = state.next_link_seq;
            let sealed = seal_av_outer(inner, &state.transit_key, &state.link_id, link_seq)
                .map_err(|e| AvDispatcherError::ForwardFailed(e.to_string()))?;
            // The counter advances iff the bytes may have reached the wire.
            // A seal failure (above) and a send the link REFUSED before
            // taking anything — backpressure (#591) or a frame larger than
            // its Channel (#720) — leave it idle: the refused ciphertext
            // never left the process, so re-using its nonce for the next
            // frame discloses nothing, and burning it would desync the
            // receiver's dense counter for the rest of the hop. A send that
            // failed any other way is ambiguous (the bytes may be out), so
            // its counter is spent — a nonce that might have been emitted is
            // never used twice.
            match state.sender.send(&sealed.to_bytes()).await {
                Ok(()) => state.next_link_seq = state.next_link_seq.wrapping_add(1),
                Err(AvDispatcherError::LinkGone(why)) => {
                    tracing::info!(
                        subscriber = %subscriber,
                        why = %why,
                        "AV fan-out: a subscriber's link is gone — pruned (CIRISEdge#805 item 8)"
                    );
                    gone.push(subscriber.clone());
                }
                Err(e @ (AvDispatcherError::Congested | AvDispatcherError::ChunkTooLarge(_))) => {
                    first_err.get_or_insert(e);
                }
                Err(e) => {
                    state.next_link_seq = state.next_link_seq.wrapping_add(1);
                    first_err.get_or_insert(e);
                }
            }
        }
        for subscriber in &gone {
            self.subscribers.remove(subscriber);
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Subscriber-side receive loop. Spawns an async task per inbound
    /// link that pulls wire frames, decodes the [`SealedAvChunk`], opens
    /// both AEAD layers via [`open_av_chunk`] (outer transit key + inner
    /// epoch DEK), and surfaces each reconstructed plaintext chunk over
    /// the returned mpsc receiver.
    ///
    /// The loop is resilient to per-frame errors: a transport recv
    /// failure or an AEAD open failure on one frame is skipped (the
    /// chunk is dropped, not propagated) and the loop continues. The
    /// loop terminates only when the inbound link is permanently closed
    /// — surfaced as a recv error after the channel receiver is itself
    /// dropped, or when the mpsc receiver the caller holds is dropped
    /// (the `send` then fails and the task exits).
    ///
    /// The subscriber tracks its own per-link anti-replay `link_seq`,
    /// incremented once per successfully-opened chunk (mirrors the
    /// relay's dense admitted-only counter).
    ///
    /// Returns an empty receiver immediately if this dispatcher holds no
    /// `epoch_dek` (a relay-role dispatcher has no subscriber path) —
    /// the spawned tasks are still created but every frame fails to open
    /// and is skipped.
    pub fn spawn_subscriber_loop(&mut self) -> mpsc::Receiver<ReconstructedChunk> {
        self.spawn_subscriber_loop_counted(None)
    }

    /// [`Self::spawn_subscriber_loop`], counting a `link_id` mismatch
    /// ([`LinkIdGuard`], CIRISEdge#867) on `metrics`.
    pub(crate) fn spawn_subscriber_loop_counted(
        &mut self,
        metrics: Option<&crate::observability::EdgeMetrics>,
    ) -> mpsc::Receiver<ReconstructedChunk> {
        let (tx, rx) = mpsc::channel::<ReconstructedChunk>(64);
        // Take ownership of the inbound links — the loop consumes them.
        let inbound = std::mem::take(&mut self.inbound_links);
        let dek_bytes = self.epoch_dek.as_ref().map(|d| *d.as_bytes());

        for link in inbound {
            let tx = tx.clone();
            let metrics = metrics.cloned();
            tokio::spawn(async move {
                let dek = dek_bytes.map(EpochDek::from_bytes);
                let mut next_link_seq: u64 = 0;
                let mut gap = HopGap::default();
                let mut guard = LinkIdGuard::default();
                loop {
                    // A permanently-closed link surfaces as a recv error;
                    // exit the loop. A transient error also lands here —
                    // the resilient contract is "drop the frame and stop
                    // pulling from a dead link", since the caller's
                    // transport owns reconnection.
                    let Ok(frame) = link.inbound_recv.recv_frame().await else {
                        break;
                    };
                    // The drop report rides THIS frame; it is kept until a
                    // frame authenticates, whatever happens to this one.
                    let dropped_before = gap.report(frame.dropped_before);
                    // Malformed wire — skip this frame, keep pulling.
                    let Ok(sealed) = SealedAvChunk::from_bytes(&frame.bytes) else {
                        continue;
                    };
                    let Some(dek) = dek.as_ref() else {
                        // No DEK in scope (relay role mis-driven as a
                        // subscriber). Skip — nothing to open with.
                        continue;
                    };
                    // AEAD open failed at every candidate counter — skip
                    // this frame WITHOUT advancing the anti-replay counter,
                    // so a single corrupt / duplicate frame doesn't desync
                    // the keystream for subsequent good frames. A frame the
                    // transport dropped before this one moves the counter
                    // past it (CIRISEdge#805), never below `next_link_seq`.
                    let Some((used, plaintext)) =
                        open_at_first_counter(next_link_seq, dropped_before, |c| {
                            open_av_chunk(&sealed, &link.transit_key, &link.link_id, c, dek).ok()
                        })
                    else {
                        if guard.unopened() {
                            // CIRISEdge#867 — never opened a frame: this
                            // link runs under another link_id. End it so
                            // the leg is re-dialled instead of starving.
                            guard.report_mismatch("subscriber", &link.link_id, metrics.as_ref());
                            break;
                        }
                        continue;
                    };
                    guard.opened();
                    next_link_seq = used.wrapping_add(1);
                    gap.resolved();
                    let chunk = ReconstructedChunk {
                        stream_id: sealed.stream_id,
                        epoch: sealed.epoch,
                        chunk_seq: sealed.chunk_seq,
                        plaintext,
                    };
                    // If the caller dropped the receiver, the stream is
                    // over — exit the task.
                    if tx.send(chunk).await.is_err() {
                        break;
                    }
                }
            });
        }

        rx
    }

    /// Add a downstream subscriber mid-stream. Idempotent on `subscriber`:
    /// re-adding replaces the outbound state.
    ///
    /// CIRISEdge#866 — the `link_seq` counter belongs to the
    /// `(transit key, link_id)` pair, not to this admission. A pair this
    /// dispatcher sealed under before (dropped, or replaced, and admitted
    /// again) resumes where it stopped. A new pair starts at 0. Restarting
    /// a used pair at 0 would repeat outer nonces under one GCM key.
    ///
    /// # Errors
    ///
    /// [`AvDispatcherError::TransitPairInUse`] if the pair is already live
    /// under ANOTHER subscriber; nothing changes.
    pub fn add_subscriber(&mut self, link: AvSubscriberLink) -> Result<(), AvDispatcherError> {
        if crate::transport::realtime_av::LinkSeqLedger::live_conflict(
            &link.transit_key,
            &link.link_id,
            self.subscribers
                .iter()
                .filter(|(who, _)| **who != link.subscriber)
                .map(|(_, st)| (&st.transit_key, st.link_id.as_slice())),
        ) {
            return Err(AvDispatcherError::TransitPairInUse(link.subscriber));
        }
        if let Some(old) = self.subscribers.remove(&link.subscriber) {
            self.link_seqs
                .retire(&old.transit_key, &old.link_id, old.next_link_seq);
        }
        let next_link_seq = self.link_seqs.resume(&link.transit_key, &link.link_id);
        self.subscribers.insert(
            link.subscriber,
            OutboundState {
                transit_key: link.transit_key,
                link_id: link.link_id,
                next_link_seq,
                sender: link.outbound_send,
            },
        );
        Ok(())
    }

    /// Remove a downstream subscriber mid-stream. Drops its outbound
    /// state (transit key + sender) and keeps only where its pair's
    /// counter stopped, as a hash (CIRISEdge#866). No-op if the subscriber
    /// was not registered.
    pub fn remove_subscriber(&mut self, subscriber: &PeerKeyId) {
        if let Some(old) = self.subscribers.remove(subscriber) {
            // CIRISEdge#866 — remember where the pair stopped.
            self.link_seqs
                .retire(&old.transit_key, &old.link_id, old.next_link_seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(seed: u8) -> StreamId {
        StreamId([seed; 32])
    }

    fn dek_bytes() -> [u8; 32] {
        [0x77u8; 32]
    }

    #[test]
    fn relay_role_drops_supplied_epoch_dek() {
        // A Relay constructed WITH a DEK must not retain it — the
        // structural no-plaintext invariant.
        let d = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(1),
            local_role: AvRole::Relay,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: vec![],
            inbound_links: vec![],
        })
        .expect("relay ctor");
        assert!(d.epoch_dek.is_none(), "relay must not hold an EpochDek");
    }

    #[test]
    fn publisher_without_dek_errors() {
        let r = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(1),
            local_role: AvRole::Publisher,
            epoch_dek: None,
            initial_subscribers: vec![],
            inbound_links: vec![],
        });
        assert!(matches!(
            r,
            Err(AvDispatcherError::PublisherMissingEpochDek)
        ));
    }

    /// **v4.6.2 (Codex P2.1)** — a subscriber with no `epoch_dek` would
    /// have silently black-holed every received frame in the loop
    /// (inner-open fails → per-frame resilience skips it). v4.6.2
    /// rejects this at construction time.
    #[test]
    fn subscriber_without_dek_errors() {
        let r = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(1),
            local_role: AvRole::Subscriber,
            epoch_dek: None,
            initial_subscribers: vec![],
            inbound_links: vec![],
        });
        assert!(matches!(
            r,
            Err(AvDispatcherError::PublisherMissingEpochDek)
        ));
    }

    // ── CIRISEdge#805 / #720 — the hop counter around refusals and drops ──

    use crate::transport::realtime_av::{seal_av_inner, ChunkLayer, CODEC_OPAQUE};

    /// A sender with a Channel limit: refuses larger frames as
    /// `ChunkTooLarge` (nothing sent), forwards the rest.
    struct LimitedSender {
        limit: usize,
        tx: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl AvLinkSender for LimitedSender {
        async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError> {
            if bytes.len() > self.limit {
                return Err(AvDispatcherError::ChunkTooLarge(ChunkTooLarge {
                    frame_bytes: bytes.len(),
                    channel_limit: self.limit,
                }));
            }
            self.tx
                .send(bytes.to_vec())
                .map_err(|e| AvDispatcherError::SendFailed(e.to_string()))
        }
    }

    fn inner(dek: &EpochDek, seq: u64, len: usize) -> InnerSealed {
        seal_av_inner(
            &vec![0x42; len],
            dek,
            stream(7),
            Epoch(1),
            ChunkSeq(seq),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner seal")
    }

    /// #720 at the 500-byte MTU: a frame over the 425-byte Channel limit is
    /// refused by NAME, and it burns no hop counter — the next frame that
    /// fits opens at link_seq 0, so the subscriber's dense counter never
    /// desyncs over a refusal.
    #[tokio::test]
    async fn an_oversized_frame_is_refused_by_name_and_burns_no_counter() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let transit = [0x21u8; 32];
        let mut d = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(7),
            local_role: AvRole::Publisher,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: vec![AvSubscriberLink {
                subscriber: "sub".to_owned(),
                transit_key: transit,
                link_id: b"sub".to_vec(),
                outbound_send: Box::new(LimitedSender { limit: 425, tx }),
            }],
            inbound_links: vec![],
        })
        .expect("publisher");
        match d.publish_inner(inner(&dek, 0, 400)).await {
            Err(AvDispatcherError::ChunkTooLarge(r)) => {
                assert_eq!(r.channel_limit, 425);
                assert!(r.frame_bytes > 425, "{r:?}");
            }
            other => panic!("expected ChunkTooLarge, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "nothing was sent");
        d.publish_inner(inner(&dek, 1, 64)).await.expect("fits");
        let wire = rx.try_recv().expect("sent");
        let sealed = SealedAvChunk::from_bytes(&wire).expect("parse");
        assert!(
            open_av_chunk(&sealed, &transit, b"sub", 0, &dek).is_ok(),
            "the first frame that went out is link_seq 0"
        );
    }

    /// A sender that always refuses with `err`.
    struct RefusingSender {
        err: fn() -> AvDispatcherError,
    }

    #[async_trait::async_trait]
    impl AvLinkSender for RefusingSender {
        async fn send(&self, _bytes: &[u8]) -> Result<(), AvDispatcherError> {
            Err((self.err)())
        }
    }

    fn publisher_over(subscribers: Vec<AvSubscriberLink>) -> AvDispatcher {
        AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(8),
            local_role: AvRole::Publisher,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: subscribers,
            inbound_links: vec![],
        })
        .expect("publisher")
    }

    fn healthy(name: &str, tx: mpsc::UnboundedSender<Vec<u8>>) -> AvSubscriberLink {
        AvSubscriberLink {
            subscriber: name.to_owned(),
            transit_key: [0x31; 32],
            link_id: name.as_bytes().to_vec(),
            outbound_send: Box::new(LimitedSender { limit: 4096, tx }),
        }
    }

    fn refusing(name: &str, err: fn() -> AvDispatcherError) -> AvSubscriberLink {
        AvSubscriberLink {
            subscriber: name.to_owned(),
            transit_key: [0x32; 32],
            link_id: name.as_bytes().to_vec(),
            outbound_send: Box::new(RefusingSender { err }),
        }
    }

    /// CIRISEdge#805 item 8 — a subscriber whose link is gone is
    /// pruned, and the others still get every chunk, in any roster order.
    #[tokio::test]
    async fn a_gone_link_is_pruned_and_starves_nobody() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut d = publisher_over(vec![
            refusing("gone", || AvDispatcherError::LinkGone("closed".to_owned())),
            healthy("ok", tx),
        ]);
        d.publish_inner(inner(&dek, 0, 64))
            .await
            .expect("a pruned link is no error");
        assert!(rx.try_recv().is_ok(), "the healthy subscriber got it");
        assert_eq!(d.subscriber_count(), 1, "the gone one was pruned");
        d.publish_inner(inner(&dek, 1, 64)).await.expect("again");
        assert!(rx.try_recv().is_ok());
    }

    /// CIRISEdge#805 item 8 — one congested subscriber does not stop the
    /// fan-out: every other subscriber gets the chunk, and the refusal is
    /// still reported. Order-proof: the roster is a HashMap, so a regression
    /// to return-on-first-error is caught only when the congested one is not
    /// iterated last; sixteen fresh rosters of eight healthy subscribers each
    /// (each with its own hash seed) make a lucky green negligible.
    #[tokio::test]
    async fn one_congested_subscriber_does_not_starve_the_rest() {
        let dek = EpochDek::from_bytes(dek_bytes());
        for _ in 0..16 {
            let mut receivers = Vec::new();
            let mut roster = vec![refusing("busy", || AvDispatcherError::Congested)];
            for i in 0..8 {
                let (tx, rx) = mpsc::unbounded_channel();
                roster.push(healthy(&format!("ok-{i}"), tx));
                receivers.push(rx);
            }
            let mut d = publisher_over(roster);
            assert!(matches!(
                d.publish_inner(inner(&dek, 0, 64)).await,
                Err(AvDispatcherError::Congested)
            ));
            for rx in &mut receivers {
                assert!(rx.try_recv().is_ok(), "every healthy subscriber got it");
            }
            assert_eq!(d.subscriber_count(), 9, "congestion prunes nobody");
        }
    }

    #[test]
    fn hop_counter_candidates_try_the_reported_gap_first_and_never_go_back() {
        let c: Vec<u64> = hop_counter_candidates(10, 3).collect();
        assert_eq!(c[0], 13, "past the reported drops first");
        assert_eq!(c[1], 10, "then the expected counter");
        assert!(
            !c.contains(&11) && !c.contains(&12),
            "the dropped frames' counters are gone"
        );
        assert!(c.iter().all(|x| *x >= 10), "never below next: no replay");
        assert_eq!(
            *c.iter().max().expect("non-empty"),
            13 + HOP_COUNTER_RESYNC_SLACK
        );
        let z: Vec<u64> = hop_counter_candidates(4, 0).collect();
        assert_eq!(z[0], 4);
        assert_eq!(
            z.len(),
            usize::try_from(HOP_COUNTER_RESYNC_SLACK).expect("small") + 1
        );
    }

    /// The review's bound (#813): after a burst of 1000 reported drops, a JUNK
    /// frame (opens at no counter) costs at most `SLACK + 2` AEAD opens —
    /// never one per dropped frame — and the legitimate post-gap frame still
    /// opens, on the first try, through the seam both open loops use.
    #[test]
    fn a_junk_frame_after_a_thousand_drops_costs_at_most_slack_plus_two_opens() {
        let mut opens = 0u64;
        let junk = open_at_first_counter(5, 1000, |_| {
            opens += 1;
            None::<()>
        });
        assert!(junk.is_none());
        assert!(opens <= HOP_COUNTER_MAX_OPENS, "{opens} opens");
        assert_eq!(opens, HOP_COUNTER_MAX_OPENS);

        let dek = EpochDek::from_bytes(dek_bytes());
        let transit = [0x41u8; 32];
        let sealed = seal_av_outer(&inner(&dek, 9, 32), &transit, b"me", 1005).expect("outer");
        let mut opens = 0u64;
        let legit = open_at_first_counter(5, 1000, |c| {
            opens += 1;
            open_av_chunk(&sealed, &transit, b"me", c, &dek).ok()
        });
        assert_eq!(legit.map(|(c, _)| c), Some(1005), "opens past the gap");
        assert_eq!(opens, 1, "the first candidate");
    }

    /// A receiver that replays scripted frames, each with its drop report.
    struct Scripted {
        rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<InboundWireFrame>>,
    }

    #[async_trait::async_trait]
    impl AvLinkReceiver for Scripted {
        async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
            self.recv_frame().await.map(|f| f.bytes)
        }
        async fn recv_frame(&self) -> Result<InboundWireFrame, AvDispatcherError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| AvDispatcherError::RecvFailed("closed".into()))
        }
    }

    /// CIRISEdge#805 — the never-block inbound policy drops frames; the
    /// subscriber skips its hop counter past a REPORTED drop, and past a
    /// small unreported one (a counter burned on the send side), instead of
    /// failing every later frame on the hop.
    #[tokio::test]
    async fn the_subscriber_resyncs_past_dropped_frames() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let transit = [0x31u8; 32];
        let wire = |chunk_seq: u64, link_seq: u64| {
            seal_av_outer(&inner(&dek, chunk_seq, 32), &transit, b"me", link_seq)
                .expect("outer")
                .to_bytes()
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let mut d = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(7),
            local_role: AvRole::Subscriber,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: vec![],
            inbound_links: vec![AvInboundLink {
                transit_key: transit,
                link_id: b"me".to_vec(),
                inbound_recv: Box::new(Scripted {
                    rx: tokio::sync::Mutex::new(rx),
                }),
            }],
        })
        .expect("subscriber");
        let mut out = d.spawn_subscriber_loop();
        // link_seq 0; then 1–2 dropped by the transport and REPORTED; then
        // 4 with no report (3 burned on the send side).
        for (chunk_seq, link_seq, dropped_before) in [(0, 0, 0), (3, 3, 2), (5, 5, 0)] {
            tx.send(InboundWireFrame {
                dropped_before,
                bytes: wire(chunk_seq, link_seq),
            })
            .expect("feed");
        }
        for want in [0u64, 3, 5] {
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), out.recv())
                .await
                .expect("in time")
                .expect("open");
            assert_eq!(got.chunk_seq, ChunkSeq(want));
        }
    }

    /// Codex on #813: the drop report rides ONE frame. If that frame is junk
    /// — unparseable, or parseable but opening at no counter — the report
    /// must survive it, or the next real frame (reporting zero) is past the
    /// slack and the hop fails authentication forever. Both junk shapes,
    /// each carrying a gap larger than the slack reaches.
    #[tokio::test]
    async fn a_junk_frame_does_not_swallow_the_drop_report() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let transit = [0x51u8; 32];
        let wire = |chunk_seq: u64, link_seq: u64| {
            seal_av_outer(&inner(&dek, chunk_seq, 32), &transit, b"me", link_seq)
                .expect("outer")
                .to_bytes()
        };
        let big_gap = HOP_COUNTER_RESYNC_SLACK + 4;
        // Parseable (header-sized) but sealed under nothing this hop knows.
        let opaque_junk = vec![0xEE; 200];
        let (tx, rx) = mpsc::unbounded_channel();
        let mut d = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(7),
            local_role: AvRole::Subscriber,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: vec![],
            inbound_links: vec![AvInboundLink {
                transit_key: transit,
                link_id: b"me".to_vec(),
                inbound_recv: Box::new(Scripted {
                    rx: tokio::sync::Mutex::new(rx),
                }),
            }],
        })
        .expect("subscriber");
        let mut out = d.spawn_subscriber_loop();
        let after_first = 1 + big_gap;
        let after_second = after_first + 1 + big_gap;
        for (dropped_before, bytes) in [
            (0, wire(0, 0)),
            // 12 dropped, reported on an UNPARSEABLE frame.
            (big_gap, b"junk".to_vec()),
            (0, wire(1, after_first)),
            // 12 more, reported on a parseable frame that opens nowhere.
            (big_gap, opaque_junk),
            (0, wire(2, after_second)),
        ] {
            tx.send(InboundWireFrame {
                dropped_before,
                bytes,
            })
            .expect("feed");
        }
        for want in 0..3u64 {
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), out.recv())
                .await
                .unwrap_or_else(|_| panic!("chunk {want}: the hop lost its drop report"))
                .expect("open");
            assert_eq!(got.chunk_seq, ChunkSeq(want));
        }
    }

    #[test]
    fn a_hop_gap_accumulates_until_resolved() {
        let mut g = HopGap::default();
        assert_eq!(g.report(3), 3);
        assert_eq!(g.report(0), 3, "a frame with no report keeps the old one");
        assert_eq!(g.report(2), 5);
        g.resolved();
        assert_eq!(g.pending(), 0);
    }

    /// Subscriber WITH a DEK still constructs (the inverse of the
    /// rejection test — pin the happy path).
    #[test]
    fn subscriber_with_dek_constructs() {
        let r = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(1),
            local_role: AvRole::Subscriber,
            epoch_dek: Some([0x44u8; 32]),
            initial_subscribers: vec![],
            inbound_links: vec![],
        });
        assert!(r.is_ok());
    }

    /// The `link_seq` a wire frame was sealed under, found by opening it.
    fn sealed_at(wire: &[u8], key: &[u8; 32], link_id: &[u8], dek: &EpochDek) -> u64 {
        let sealed = SealedAvChunk::from_bytes(wire).expect("parse");
        (0..64)
            .find(|c| open_av_chunk(&sealed, key, link_id, *c, dek).is_ok())
            .expect("the frame opens at some link_seq under its key and link")
    }

    /// CIRISEdge#866 — re-admitting a subscriber with the same transit key
    /// and link (after a remove, and by a replacing add) resumes its outer
    /// counter: across three admissions no `(key, link_id, link_seq)` is
    /// ever sealed twice, and the sequence the receiver sees stays dense.
    #[tokio::test]
    async fn readmission_on_the_same_pair_never_repeats_an_outer_nonce_866() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut d = publisher_over(vec![healthy("sub", tx.clone())]);
        let key = [0x31u8; 32];
        let mut seen = std::collections::BTreeSet::new();
        let mut chunk = 0u64;
        for round in 0..3 {
            match round {
                1 => {
                    d.remove_subscriber(&"sub".to_owned());
                    d.add_subscriber(healthy("sub", tx.clone()))
                        .expect("re-admit after a remove");
                }
                2 => d
                    .add_subscriber(healthy("sub", tx.clone()))
                    .expect("re-admit by a replacing add"),
                _ => {}
            }
            for _ in 0..3 {
                d.publish_inner(inner(&dek, chunk, 64))
                    .await
                    .expect("publish");
                chunk += 1;
                let wire = rx.try_recv().expect("sent");
                let at = sealed_at(&wire, &key, b"sub", &dek);
                assert!(
                    seen.insert(at),
                    "round {round}: link_seq {at} sealed twice under one key and link"
                );
            }
        }
        assert_eq!(seen, (0..9).collect(), "dense across re-admissions");
    }

    /// CIRISEdge#866 — a NEW transit key on the same link is a new pair and
    /// starts at 0.
    #[tokio::test]
    async fn a_new_key_on_the_same_link_starts_its_own_counter_866() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut d = publisher_over(vec![healthy("sub", tx.clone())]);
        d.publish_inner(inner(&dek, 0, 64)).await.expect("publish");
        let _ = rx.try_recv().expect("sent");
        d.remove_subscriber(&"sub".to_owned());
        let mut fresh = healthy("sub", tx);
        fresh.transit_key = [0x55; 32];
        d.add_subscriber(fresh).expect("a new key");
        d.publish_inner(inner(&dek, 1, 64)).await.expect("publish");
        let wire = rx.try_recv().expect("sent");
        assert_eq!(sealed_at(&wire, &[0x55; 32], b"sub", &dek), 0);
    }

    /// CIRISEdge#866 — the same pair live under two subscribers is refused,
    /// at an add and at construction, and the roster is unchanged.
    #[test]
    fn a_pair_live_under_another_subscriber_is_refused_866() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let twin = |tx: mpsc::UnboundedSender<Vec<u8>>| {
            let mut l = healthy("b", tx);
            l.link_id = b"a".to_vec();
            l
        };
        let mut d = publisher_over(vec![healthy("a", tx.clone())]);
        assert!(matches!(
            d.add_subscriber(twin(tx.clone())),
            Err(AvDispatcherError::TransitPairInUse(who)) if who == "b"
        ));
        assert_eq!(d.subscriber_count(), 1, "nothing changed");
        let built = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(8),
            local_role: AvRole::Publisher,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: vec![healthy("a", tx.clone()), twin(tx)],
            inbound_links: vec![],
        });
        assert!(matches!(built, Err(AvDispatcherError::TransitPairInUse(_))));
    }

    /// A subscriber loop over one scripted link that opens with `link_id`.
    fn scripted_subscriber(
        link_id: &[u8],
    ) -> (
        mpsc::UnboundedSender<InboundWireFrame>,
        mpsc::Receiver<ReconstructedChunk>,
    ) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut d = AvDispatcher::new(AvDispatcherConfig {
            stream_id: stream(7),
            local_role: AvRole::Subscriber,
            epoch_dek: Some(dek_bytes()),
            initial_subscribers: vec![],
            inbound_links: vec![AvInboundLink {
                transit_key: [0x31; 32],
                link_id: link_id.to_vec(),
                inbound_recv: Box::new(Scripted {
                    rx: tokio::sync::Mutex::new(rx),
                }),
            }],
        })
        .expect("subscriber");
        (tx, d.spawn_subscriber_loop())
    }

    fn frame_on(link_id: &[u8], chunk_seq: u64, link_seq: u64) -> InboundWireFrame {
        let dek = EpochDek::from_bytes(dek_bytes());
        InboundWireFrame {
            dropped_before: 0,
            bytes: seal_av_outer(&inner(&dek, chunk_seq, 32), &[0x31; 32], link_id, link_seq)
                .expect("outer")
                .to_bytes(),
        }
    }

    /// CIRISEdge#867 — the guard: a link that never opened is a mismatch at
    /// exactly `LINK_ID_MISMATCH_FRAMES` failures; a link that opened once
    /// never is.
    #[test]
    fn a_link_that_never_opens_is_a_link_id_mismatch_867() {
        let mut g = LinkIdGuard::default();
        for _ in 1..LINK_ID_MISMATCH_FRAMES {
            assert!(!g.unopened());
        }
        assert!(
            g.unopened(),
            "the Nth unopened frame from the first is a mismatch"
        );
        let mut g = LinkIdGuard::default();
        g.opened();
        for _ in 0..10 * LINK_ID_MISMATCH_FRAMES {
            assert!(!g.unopened(), "a link that opened once shares our link_id");
        }
    }

    /// CIRISEdge#867 — the peer seals under the WIRE link_id while this end
    /// holds a stale one (leviculum#86): no frame opens, and the loop ENDS
    /// the link after `LINK_ID_MISMATCH_FRAMES` instead of starving forever.
    #[tokio::test]
    async fn a_stale_link_id_ends_the_link_instead_of_starving_867() {
        let (tx, mut out) = scripted_subscriber(b"stale");
        for i in 0..u64::from(LINK_ID_MISMATCH_FRAMES) {
            tx.send(frame_on(b"wire", i, i)).expect("feed");
        }
        let ended = tokio::time::timeout(std::time::Duration::from_secs(5), out.recv())
            .await
            .expect("the loop answers in time");
        assert!(ended.is_none(), "the link is ended, not left silent");
    }

    /// CIRISEdge#867 — a link that opened a frame shares our link_id: any
    /// number of foreign frames after that are dropped one by one, and the
    /// link keeps delivering.
    #[tokio::test]
    async fn junk_after_a_good_frame_never_ends_the_link_867() {
        let (tx, mut out) = scripted_subscriber(b"me");
        tx.send(frame_on(b"me", 0, 0)).expect("feed");
        for i in 0..4 * u64::from(LINK_ID_MISMATCH_FRAMES) {
            tx.send(frame_on(b"other", 100 + i, i)).expect("feed");
        }
        tx.send(frame_on(b"me", 1, 1)).expect("feed");
        for want in [0u64, 1] {
            let got = tokio::time::timeout(std::time::Duration::from_secs(5), out.recv())
                .await
                .expect("in time")
                .expect("still open");
            assert_eq!(got.chunk_seq, ChunkSeq(want));
        }
    }

    /// CIRISEdge#867 item 3 — `link_seq` is edge's own u64 per direction,
    /// never a Channel u16 sequence: the counter runs past 65535 and the
    /// frames open there.
    #[tokio::test]
    async fn link_seq_is_a_u64_past_the_u16_boundary_867() {
        let dek = EpochDek::from_bytes(dek_bytes());
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut d = publisher_over(vec![healthy("sub", tx)]);
        d.subscribers.get_mut("sub").expect("sub").next_link_seq = u64::from(u16::MAX);
        for chunk in 0..2 {
            d.publish_inner(inner(&dek, chunk, 64))
                .await
                .expect("publish");
        }
        let key = [0x31u8; 32];
        let first = SealedAvChunk::from_bytes(&rx.try_recv().expect("sent")).expect("parse");
        let second = SealedAvChunk::from_bytes(&rx.try_recv().expect("sent")).expect("parse");
        assert!(open_av_chunk(&first, &key, b"sub", u64::from(u16::MAX), &dek).is_ok());
        assert!(
            open_av_chunk(&second, &key, b"sub", u64::from(u16::MAX) + 1, &dek).is_ok(),
            "65536, not a wrap to 0"
        );
        assert!(open_av_chunk(&second, &key, b"sub", 0, &dek).is_err());
    }
}
