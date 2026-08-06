//! Realtime A/V mesh integrating runtime — "the spine" (CIRISEdge#155,
//! Gap 3).
//!
//! ## What this module closes
//!
//! The Layer-1 crypto ([`super::realtime_av`]), the Layer-2 wire driver
//! ([`super::realtime_av_dispatcher`]), the MLS group-key holder
//! ([`super::realtime_av_session`]), and the ALM parent planner
//! ([`super::realtime_av_alm`]) are each unit-tested but *dormant*: no
//! production caller wires them into one live end-to-end stream. This
//! module is that caller. It composes the primitives into three role
//! objects — [`AvPublisher`], [`AvRelay`], [`AvSubscriber`] — that a
//! fabric node drives to run ONE stream glass-to-glass:
//! publisher → relay → subscriber, one parent.
//!
//! ```text
//!   AvSession (MLS)         AvDispatcher (Publisher)      chunk source
//!      │  epoch DEK  ───────────►  seal_av_inner  ──►  publish_inner  ──►  wire
//!      ▼                                                                    │
//!   AvPublisher                                                             ▼
//!                                                             AvDispatcher (Relay, no DEK)
//!                                                               relay_chunk (open outer,
//!                                                                re-seal per subscriber) ─► wire
//!                                                                                            │
//!   AlmJoinPlanner::plan ─► primary parent ─► dial ─► AvInboundLink ──────────────────────► ▼
//!                                                             AvDispatcher (Subscriber)
//!                                                               spawn_subscriber_loop ─► ReconstructedChunk
//! ```
//!
//! ## The transport seam (real RNS vs the trait seam)
//!
//! Every role talks to the wire through the dispatcher's object-safe
//! [`AvLinkSender`] / [`AvLinkReceiver`] seam — the runtime is
//! transport-blind exactly as the dispatcher is. Two implementations of
//! that seam ship here:
//!
//! - **Real RNS** — [`LeviculumAvSender`] wraps
//!   [`leviculum_std::driver::ReticulumNode::link_handle`] +
//!   [`leviculum_std::driver::LinkHandle::send`] (the pacing-absorbing
//!   Channel packet path — the same `send_on_link` core the reverse-path
//!   reply rides in [`super::reticulum`]). [`LinkDataPump`] owns a node's
//!   [`leviculum_std::driver::EventReceiver`] and demultiplexes
//!   [`leviculum_core::NodeEvent::LinkDataReceived`] /
//!   [`leviculum_core::NodeEvent::MessageReceived`] per `LinkId` into
//!   per-link inbound queues, each surfaced as a [`PumpReceiver`]. Gated
//!   behind `_reticulum-module` (the leviculum dependency).
//! - **Trait seam** — any caller-supplied [`AvLinkSender`] /
//!   [`AvLinkReceiver`] (an in-memory `mpsc` in tests, an HTTP body
//!   channel, …). The whole spine runs identically over it, which is how
//!   `tests/realtime_av_spine_e2e.rs` proves the glass-to-glass byte path
//!   without standing up two live RNS nodes.
//!
//! ## Crypto invariant carried through
//!
//! The relay role NEVER holds the epoch DEK — [`AvRelay`] constructs its
//! dispatcher with `AvRole::Relay`, which drops any supplied DEK
//! structurally ([`AvDispatcher::new`]). The relay opens only the outer
//! (hop-tier) AEAD and re-seals per downstream subscriber; the inner
//! E2E ciphertext is byte-identical from the publisher's `seal_av_inner`
//! through to each subscriber's `open_av_chunk`. Only [`AvPublisher`] and
//! [`AvSubscriber`] hold the MLS-derived [`EpochDek`].
//!
//! ## Instrumentation (CIRISEdge#423–#429 arc)
//!
//! Every join / subscribe / relay / deliver / rekey decision emits a
//! loud structured `tracing` record carrying `(peer, stream, chunk_seq)`
//! where they apply. No pump path takes a silent `continue` / early
//! return — a malformed inbound frame, a send failure, or a desynced
//! counter is always surfaced at `warn!` before the frame is skipped, so
//! a drop can never read as absence-of-work.
//!
//! ## MVP scope vs stretch
//!
//! - **MVP (here)** — one stream, one parent, publisher → relay →
//!   subscriber; MLS supplies the epoch DEK for the inner seal/open; ALM
//!   picks the parent from a signed-capacity pool.
//! - **Stretch (not here)** — multi-parent dedup/heal
//!   ([`super::realtime_av_alm::MultiParentSubscription`]),
//!   rekey-on-membership rebuild of a live subscriber loop, real codec
//!   framing + fragmentation of oversized chunks, and the live two-node
//!   RNS loopback exercising [`LeviculumAvSender`] / [`LinkDataPump`].

use tokio::sync::mpsc;

use super::realtime_av::{
    seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, RealtimeAvError, SealedAvChunk, StreamId,
    CODEC_OPAQUE,
};
use super::realtime_av_alm::{
    AlmJoinError, AlmJoinPlanner, JoinPlan, ParentCandidate, TransitGate,
};
use super::realtime_av_dispatcher::{
    AvDispatcher, AvDispatcherConfig, AvDispatcherError, AvInboundLink, AvRole, AvSubscriberLink,
    PeerKeyId, ReconstructedChunk,
};
use super::realtime_av_session::{AvSession, AvSessionError, EpochRekeyArtifacts, RosterDelta};
use crate::transport::realtime_av::ReceiverLayerPolicy;
// CIRISEdge#331 (CC-5.4.4) — admitting a published joiner now signs the Welcome
// with the inviter's long-term ML-DSA-65 federation identity, so the spine must
// thread that signer (+ the invitee's kex + the inviter's pk_id) into the admit.
use crate::transport::federation_session::PeerKexPubkeys;
use crate::transport::realtime_av_mls::Member;
use ciris_crypto::MlDsa65Signer;

/// Errors the runtime spine can surface. Each variant wraps the
/// underlying layer's error so a caller can pattern-match on the tier
/// that refused (crypto seal, wire dispatch, MLS rekey, ALM planning)
/// without stringly-typing.
#[derive(thiserror::Error, Debug)]
pub enum AvRuntimeError {
    /// A Layer-2 wire-dispatch step failed (seal / send / open).
    #[error("dispatcher: {0}")]
    Dispatcher(#[from] AvDispatcherError),
    /// An MLS session step failed (create / rekey / welcome).
    #[error("session: {0}")]
    Session(#[from] AvSessionError),
    /// The inner AEAD seal failed at the publisher.
    #[error("inner seal: {0}")]
    Seal(#[from] RealtimeAvError),
    /// ALM parent selection found no feasible parent.
    #[error("parent selection: {0}")]
    Join(#[from] AlmJoinError),
}

/// Short, stable, whitespace-free stream tag for structured tracing.
/// The first 4 bytes of the [`StreamId`] hex — enough to disambiguate
/// concurrent streams in a log without dumping 32 bytes per line (which
/// would break Stage-6 event-log tokenisation).
#[must_use]
fn stream_tag(stream_id: StreamId) -> String {
    let b = stream_id.0;
    format!("{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
}

// ─── Publisher role ─────────────────────────────────────────────────

/// The publisher spine for one stream.
///
/// Owns the MLS [`AvSession`] (the epoch DEK source) and a
/// `Publisher`-role [`AvDispatcher`]. Each [`Self::publish_chunk`] call
/// inner-seals the plaintext under the current epoch DEK
/// ([`seal_av_inner`]) then hands the [`super::realtime_av::InnerSealed`]
/// to the dispatcher, which outer-seals per downstream subscriber and
/// enqueues the wire bytes.
///
/// The dispatcher's DEK is vestigial for the publish path (`publish_inner`
/// never consults it — only the caller-side inner-seal does), so a
/// membership rekey ([`Self::admit_joiner`]) only swaps this struct's own
/// [`EpochDek`] + epoch counter; the dispatcher is untouched.
pub struct AvPublisher {
    stream_id: StreamId,
    session: AvSession,
    epoch: Epoch,
    /// Current epoch's MLS-derived DEK. Replaced on rekey.
    dek: EpochDek,
    dispatcher: AvDispatcher,
    /// Monotonic chunk sequence across the publisher's life. The inner
    /// nonce binds `(stream, epoch, chunk_seq)`, so this need not reset
    /// on an epoch bump — a fresh epoch already re-domains the nonce.
    next_chunk_seq: u64,
}

impl AvPublisher {
    /// Create a stream: mint a fresh MLS group with `initial_members`,
    /// derive the initial epoch DEK from its exporter secret, and stand
    /// up the publisher dispatcher over `subscribers`.
    ///
    /// `own_key_id` is the local publisher's CIRIS `key_id` (the MLS
    /// group creator). Every member undergoes the HNDL (ML-KEM-768)
    /// pre-check inside [`AvSession::create`].
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Session`] if the MLS create fails (e.g. a member
    /// lacks ML-KEM-768); [`AvRuntimeError::Dispatcher`] if the publisher
    /// dispatcher rejects its config.
    pub fn create(
        stream_id: StreamId,
        own_key_id: &str,
        initial_members: Vec<Member>,
        subscribers: Vec<AvSubscriberLink>,
    ) -> Result<Self, AvRuntimeError> {
        let (session, dek) = AvSession::create(stream_id, own_key_id, initial_members)?;
        Self::from_session(stream_id, session, dek, subscribers)
    }

    /// Build a publisher from an already-established [`AvSession`] + its
    /// current epoch DEK. Use this when the session was created elsewhere
    /// (e.g. a joiner that became a member and now publishes).
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Dispatcher`] if the publisher dispatcher rejects
    /// its config.
    pub fn from_session(
        stream_id: StreamId,
        session: AvSession,
        dek: EpochDek,
        subscribers: Vec<AvSubscriberLink>,
    ) -> Result<Self, AvRuntimeError> {
        let epoch = session.epoch();
        let dispatcher = AvDispatcher::new(AvDispatcherConfig {
            stream_id,
            local_role: AvRole::Publisher,
            epoch_dek: Some(*dek.as_bytes()),
            initial_subscribers: subscribers,
            inbound_links: Vec::new(),
        })?;
        tracing::info!(
            stream = %stream_tag(stream_id),
            epoch = epoch.0,
            subscribers = dispatcher.subscriber_count(),
            "AV publisher room created (MLS epoch DEK wired)"
        );
        Ok(Self {
            stream_id,
            session,
            epoch,
            dek,
            dispatcher,
            next_chunk_seq: 0,
        })
    }

    /// The stream this publisher drives.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Current epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Downstream subscriber count.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.dispatcher.subscriber_count()
    }

    /// Inner-seal `plaintext` under the current epoch DEK and fan it out
    /// to every downstream subscriber. Returns the [`ChunkSeq`] the chunk
    /// was stamped with.
    ///
    /// `codec_id` + `layer` ride the clear chunk header (they are NOT
    /// AEAD inputs); pass [`CODEC_OPAQUE`] + [`ChunkLayer::BASE`] for the
    /// substrate default. For an opaque test producer this is the whole
    /// codec story; real codec framing is stretch.
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Seal`] on inner-seal failure;
    /// [`AvRuntimeError::Dispatcher`] on outer-seal / transport-send
    /// failure (fan-out stops at the first failing subscriber).
    pub async fn publish_chunk(
        &mut self,
        plaintext: &[u8],
        codec_id: u8,
        layer: ChunkLayer,
    ) -> Result<ChunkSeq, AvRuntimeError> {
        let seq = ChunkSeq(self.next_chunk_seq);
        let inner = seal_av_inner(
            plaintext,
            &self.dek,
            self.stream_id,
            self.epoch,
            seq,
            codec_id,
            layer,
        )?;
        tracing::info!(
            stream = %stream_tag(self.stream_id),
            epoch = self.epoch.0,
            chunk_seq = seq.0,
            bytes = plaintext.len(),
            subscribers = self.dispatcher.subscriber_count(),
            "AV publish: inner-sealed, fanning out"
        );
        self.dispatcher.publish_inner(inner).await?;
        self.next_chunk_seq = self.next_chunk_seq.wrapping_add(1);
        Ok(seq)
    }

    /// Publish an opaque chunk with the substrate default codec + layer.
    /// Thin wrapper over [`Self::publish_chunk`] for a test producer.
    ///
    /// # Errors
    ///
    /// As [`Self::publish_chunk`].
    pub async fn publish_opaque(&mut self, plaintext: &[u8]) -> Result<ChunkSeq, AvRuntimeError> {
        self.publish_chunk(plaintext, CODEC_OPAQUE, ChunkLayer::BASE)
            .await
    }

    /// Register a downstream subscriber mid-stream (its outer keystream
    /// starts at `link_seq` 0 — a fresh transit key).
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Dispatcher`] — infallible today, reserved.
    pub fn add_subscriber(&mut self, link: AvSubscriberLink) -> Result<(), AvRuntimeError> {
        let sub = link.subscriber.clone();
        self.dispatcher.add_subscriber(link)?;
        tracing::info!(
            stream = %stream_tag(self.stream_id),
            peer = %sub,
            "AV publisher: subscriber added"
        );
        Ok(())
    }

    /// Drop a downstream subscriber mid-stream.
    pub fn remove_subscriber(&mut self, subscriber: &PeerKeyId) {
        self.dispatcher.remove_subscriber(subscriber);
        tracing::info!(
            stream = %stream_tag(self.stream_id),
            peer = %subscriber,
            "AV publisher: subscriber removed"
        );
    }

    /// Admit a joiner who published its own KeyPackage: roll the MLS
    /// epoch, adopt the new DEK for subsequent [`Self::publish_chunk`]
    /// calls, and return the [`EpochRekeyArtifacts`] (Commit for existing
    /// members, Welcome for the joiner) for the caller to distribute.
    ///
    /// This is the rekey-on-membership entry point; the joiner derives
    /// the SAME `new_dek` from `welcome_bytes` via
    /// [`AvSession::process_welcome`] (RFC 9420 §8.5 epoch-deterministic
    /// exporter), so it can immediately open chunks sealed post-join.
    /// Rebuilding a live SUBSCRIBER loop under the new DEK is stretch —
    /// this rotates the PUBLISHER side.
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Session`] if the MLS add fails.
    pub fn admit_joiner(
        &mut self,
        key_id: &str,
        joiner_key_package: openmls::prelude::KeyPackage,
        // CIRISEdge#331 — the invitee's kex pubkeys, and the inviter's long-term
        // ML-DSA-65 federation signer + its directory pk_id, so the emitted Welcome
        // carries a verifiable inviter signature (no TOFU on the joiner side).
        invitee_kex: &PeerKexPubkeys,
        inviter_signer: &MlDsa65Signer,
        inviter_pk_id: &str,
    ) -> Result<EpochRekeyArtifacts, AvRuntimeError> {
        let artifacts = self.session.admit_published_joiner(
            key_id,
            joiner_key_package,
            invitee_kex,
            inviter_signer,
            inviter_pk_id,
        )?;
        // Copy the bytes into a fresh DEK so the returned artifacts keep
        // their `new_dek` for the caller's records; we rotate to our own
        // copy.
        self.dek = EpochDek::from_bytes(*artifacts.new_dek.as_bytes());
        self.epoch = artifacts.new_epoch;
        tracing::info!(
            stream = %stream_tag(self.stream_id),
            peer = %key_id,
            epoch = self.epoch.0,
            welcomes = artifacts.welcome_bytes.len(),
            "AV publisher REKEY: joiner admitted, epoch rotated"
        );
        Ok(artifacts)
    }

    /// Roll the MLS epoch for a non-Add-published membership change
    /// (Leave / local Join / Batch / Replace) and adopt the new DEK.
    /// Returns the wire artifacts for distribution.
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Session`] on any MLS rekey failure (e.g. an
    /// HNDL breach in a batch, or an empty batch).
    pub fn advance_epoch(
        &mut self,
        delta: RosterDelta,
    ) -> Result<EpochRekeyArtifacts, AvRuntimeError> {
        let artifacts = self.session.advance_epoch(delta)?;
        self.dek = EpochDek::from_bytes(*artifacts.new_dek.as_bytes());
        self.epoch = artifacts.new_epoch;
        tracing::info!(
            stream = %stream_tag(self.stream_id),
            epoch = self.epoch.0,
            welcomes = artifacts.welcome_bytes.len(),
            "AV publisher REKEY: epoch advanced"
        );
        Ok(artifacts)
    }
}

// ─── Relay role ─────────────────────────────────────────────────────

/// The relay (SFU forward) spine for one stream.
///
/// Owns a `Relay`-role [`AvDispatcher`] — NO epoch DEK, structurally.
/// [`Self::spawn_pump`] drives a self-contained forward loop: pull sealed
/// wire bytes from one upstream [`AvInboundLink`], open the inbound outer
/// AEAD, and re-seal per downstream subscriber via
/// [`AvDispatcher::relay_chunk`]. The inner ciphertext is never touched.
pub struct AvRelay {
    stream_id: StreamId,
    dispatcher: AvDispatcher,
}

impl AvRelay {
    /// Build a relay over its downstream subscriber links. The relay
    /// holds no DEK; `AvRole::Relay` drops any DEK at construction.
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Dispatcher`] if the relay dispatcher rejects its
    /// config.
    pub fn new(
        stream_id: StreamId,
        downstream: Vec<AvSubscriberLink>,
    ) -> Result<Self, AvRuntimeError> {
        let dispatcher = AvDispatcher::new(AvDispatcherConfig {
            stream_id,
            local_role: AvRole::Relay,
            epoch_dek: None,
            initial_subscribers: downstream,
            inbound_links: Vec::new(),
        })?;
        tracing::info!(
            stream = %stream_tag(stream_id),
            downstream = dispatcher.subscriber_count(),
            "AV relay room created (no epoch DEK — ciphertext-only forward)"
        );
        Ok(Self {
            stream_id,
            dispatcher,
        })
    }

    /// Number of downstream subscribers.
    #[must_use]
    pub fn subscriber_count(&self) -> usize {
        self.dispatcher.subscriber_count()
    }

    /// The stream this relay forwards.
    #[must_use]
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Spawn the forward pump. Consumes the relay: the dispatcher moves
    /// into the spawned task, which loops pulling wire frames from
    /// `inbound`, decoding each [`SealedAvChunk`], opening the inbound
    /// outer AEAD with `inbound_transit_key` + `inbound_link_id`, and
    /// re-sealing per downstream subscriber.
    ///
    /// The per-upstream-link `inbound_link_seq` starts at 0 and advances
    /// only on a successfully-forwarded chunk (mirroring the dispatcher's
    /// dense admitted-only counter), so a corrupt frame doesn't desync
    /// the keystream. Every skip is loud (CIRISEdge#425 — no silent
    /// drop). The task ends when the inbound link closes.
    #[must_use]
    pub fn spawn_pump(
        self,
        inbound: AvInboundLink,
        inbound_transit_key: [u8; 32],
        inbound_link_id: Vec<u8>,
    ) -> tokio::task::JoinHandle<()> {
        let stream_id = self.stream_id;
        let tag = stream_tag(stream_id);
        let mut dispatcher = self.dispatcher;
        tokio::spawn(async move {
            let mut inbound_link_seq: u64 = 0;
            tracing::info!(stream = %tag, "AV relay pump: started");
            loop {
                let bytes = match inbound.inbound_recv.recv().await {
                    Ok(b) => b,
                    Err(e) => {
                        // Permanently-closed / dead upstream link — the
                        // pump's only exit. Loud so a stopped relay is
                        // never mistaken for an idle one.
                        tracing::warn!(
                            stream = %tag,
                            error = %e,
                            "AV relay pump: upstream link closed — pump exiting"
                        );
                        break;
                    }
                };
                let sealed = match SealedAvChunk::from_bytes(&bytes) {
                    Ok(s) => s,
                    Err(e) => {
                        // Malformed wire — skip WITHOUT advancing the
                        // anti-replay counter (the next good frame keeps
                        // the keystream aligned). Loud per CIRISEdge#425.
                        tracing::warn!(
                            stream = %tag,
                            bytes = bytes.len(),
                            inbound_link_seq,
                            error = %e,
                            "AV relay pump: malformed inbound frame DROPPED (not forwarded)"
                        );
                        continue;
                    }
                };
                let chunk_seq = sealed.chunk_seq.0;
                match dispatcher
                    .relay_chunk(
                        sealed,
                        &inbound_transit_key,
                        &inbound_link_id,
                        inbound_link_seq,
                    )
                    .await
                {
                    Ok(()) => {
                        tracing::info!(
                            stream = %tag,
                            chunk_seq,
                            inbound_link_seq,
                            downstream = dispatcher.subscriber_count(),
                            "AV relay: forwarded chunk to downstream subscribers"
                        );
                        inbound_link_seq = inbound_link_seq.wrapping_add(1);
                    }
                    Err(e) => {
                        // Open / re-seal / send failure. Loud, and DO NOT
                        // advance the counter (an open failure means this
                        // link_seq wasn't consumed). CIRISEdge#425.
                        tracing::warn!(
                            stream = %tag,
                            chunk_seq,
                            inbound_link_seq,
                            error = %e,
                            "AV relay: chunk forward FAILED (not delivered downstream)"
                        );
                    }
                }
            }
        })
    }
}

// ─── Subscriber role ────────────────────────────────────────────────

/// The subscriber spine for one stream.
///
/// Two responsibilities:
///
/// 1. **Parent selection** ([`Self::plan_parent`]) — run
///    [`AlmJoinPlanner::plan`] over a pool of verified
///    [`ParentCandidate`]s to pick the primary parent (+ backups) for
///    this receiver's layer policy. The caller dials an RNS link to
///    `plan.primary_parent`.
/// 2. **Delivery** ([`Self::subscribe`]) — build a `Subscriber`-role
///    [`AvDispatcher`] over the inbound link from the chosen parent and
///    start its receive loop, surfacing [`ReconstructedChunk`]s.
///
/// Multi-parent dedup/heal ([`super::realtime_av_alm::MultiParentSubscription`])
/// is stretch — this MVP subscribes to the single primary.
pub struct AvSubscriber;

impl AvSubscriber {
    /// Pick the primary parent (+ up to `MAX_BACKUPS` backups) for a
    /// stream from a pool of verified capacity advertisements.
    ///
    /// `candidates` are already signature-verified upstream (ALM-B is
    /// signature-blind); `bitrate_mbps` is the stream's per-subscriber
    /// budget; `policy` is this receiver's layer cap; `wall_clock_unix_ms`
    /// drives the staleness filter deterministically.
    ///
    /// # Errors
    ///
    /// [`AlmJoinError`] with the most-specific empty-pool reason
    /// (all-stale / no-layer-support / no-feasible-parent).
    pub fn plan_parent(
        candidates: &[ParentCandidate],
        bitrate_mbps: f32,
        policy: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
    ) -> Result<JoinPlan, AlmJoinError> {
        let plan = AlmJoinPlanner::plan(candidates, bitrate_mbps, policy, wall_clock_unix_ms)?;
        tracing::info!(
            primary_parent = %plan.primary_parent,
            backups = plan.backup_parents.len(),
            bitrate_mbps = plan.stream_bitrate_mbps,
            candidates = candidates.len(),
            "AV subscriber: ALM parent plan selected"
        );
        Ok(plan)
    }

    /// CIRISEdge#430 — [`Self::plan_parent`] behind the `infra:transport`
    /// hop-eligibility gate: filter the pool through
    /// [`TransitGate::eligible_candidates`] (persist-resolved, cached,
    /// fail-closed), then plan over the survivors. **This is the live-path
    /// entry point** — the ungated [`Self::plan_parent`] is for pools a
    /// caller has already gated (tests, replans over a kept set).
    ///
    /// A relay hop is a POSITION of trust (traffic-analysis visibility + an
    /// availability lever over the subtree — never the DEK, that is
    /// structural), so an ineligible volunteer must not be selectable no
    /// matter how good its capacity ad looks. When the gate narrows the pool
    /// it says so loudly — a plan that fails AFTER filtering names the gate
    /// as the reason the pool emptied, not a capacity shortfall.
    ///
    /// # Errors
    ///
    /// [`AlmJoinError`] from the planner over the FILTERED pool (an
    /// all-ineligible pool surfaces as the planner's empty-pool reason,
    /// with the filter WARN above it naming why).
    pub async fn plan_parent_gated(
        gate: &TransitGate,
        candidates: Vec<ParentCandidate>,
        bitrate_mbps: f32,
        policy: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<JoinPlan, AlmJoinError> {
        // CIRISEdge#440 — the `feature.av_streams` mesh-config toggle, checked
        // BEFORE the per-hop eligibility walk: a paused plane is a policy fact
        // about the STREAM PLANE, not about any candidate, and must not be
        // reported as an empty pool. Named refusal + named log; the pause
        // lifts on the relief row's TTL or a superseding row.
        if gate.av_streams_paused().await {
            tracing::warn!(
                offered = candidates.len(),
                "AV subscriber: admission REFUSED — a trust root paused AV stream \
                 replication via mesh config (feature.av_streams=0, CIRISEdge#440); \
                 the pause expires on the relief row's TTL or a superseding row"
            );
            return Err(AlmJoinError::AvStreamsPaused);
        }
        let offered = candidates.len();
        let eligible = gate.eligible_candidates(candidates, now).await;
        if eligible.len() < offered {
            let filtered = offered - eligible.len();
            if eligible.is_empty() {
                tracing::warn!(
                    offered,
                    filtered,
                    "AV subscriber: transit gate refused EVERY offered hop — the pool is \
                     empty because of eligibility, not capacity (CIRISEdge#430). Peers \
                     must be directory-present nodes offering infra:transport under a \
                     shared trust root"
                );
            } else {
                tracing::info!(
                    offered,
                    kept = eligible.len(),
                    filtered,
                    "AV subscriber: transit gate filtered ineligible hops (CIRISEdge#430)"
                );
            }
        }
        Self::plan_parent(&eligible, bitrate_mbps, policy, wall_clock_unix_ms)
    }

    /// Stand up a subscriber over `inbound` (the dialed link from the
    /// chosen parent) and start its receive loop. Returns the channel of
    /// reconstructed plaintext chunks.
    ///
    /// `dek` is the MLS-derived epoch DEK the subscriber holds (obtained
    /// via [`AvSession::process_welcome`] on join, or a member's own
    /// exporter). The loop opens both AEAD layers and delivers plaintext.
    ///
    /// # Errors
    ///
    /// [`AvRuntimeError::Dispatcher`] if the subscriber dispatcher rejects
    /// its config (e.g. no DEK — a subscriber with no DEK would black-hole
    /// every frame, rejected at construction per v4.6.2).
    pub fn subscribe(
        stream_id: StreamId,
        dek: &EpochDek,
        parent: &PeerKeyId,
        inbound: AvInboundLink,
    ) -> Result<mpsc::Receiver<ReconstructedChunk>, AvRuntimeError> {
        let mut dispatcher = AvDispatcher::new(AvDispatcherConfig {
            stream_id,
            local_role: AvRole::Subscriber,
            epoch_dek: Some(*dek.as_bytes()),
            initial_subscribers: Vec::new(),
            inbound_links: vec![inbound],
        })?;
        let rx = dispatcher.spawn_subscriber_loop();
        tracing::info!(
            stream = %stream_tag(stream_id),
            parent = %parent,
            "AV subscriber: subscribed to parent, receive loop started"
        );
        // The dispatcher is dropped here; `spawn_subscriber_loop` already
        // moved the inbound link + a DEK copy into the spawned task, so
        // the loop outlives this handle. The returned `rx` is the only
        // thing the caller needs to drain chunks.
        drop(dispatcher);
        Ok(rx)
    }
}

// ─── Real-RNS transport seam (leviculum) ────────────────────────────

/// Real-RNS implementations of the dispatcher's [`AvLinkSender`] /
/// [`AvLinkReceiver`] seam over leviculum RNS links. Gated behind
/// `_reticulum-module` — the only part of the runtime that depends on
/// leviculum.
#[cfg(feature = "_reticulum-module")]
pub use leviculum_link::{LeviculumAvSender, LinkDataPump, PumpReceiver};

#[cfg(feature = "_reticulum-module")]
mod leviculum_link {
    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::sync::{mpsc, Mutex};

    use leviculum_core::link::LinkId;
    use leviculum_core::NodeEvent;
    use leviculum_std::driver::{EventReceiver, ReticulumNode};

    use crate::transport::realtime_av_dispatcher::{
        AvDispatcherError, AvLinkReceiver, AvLinkSender,
    };

    /// Bound on each per-link inbound queue. Realtime A/V is
    /// loss-tolerant: if the consumer falls behind by more than this many
    /// frames the pump drops the newest and says so loudly (CIRISEdge#425)
    /// rather than growing the queue unboundedly.
    const PUMP_QUEUE_DEPTH: usize = 256;

    /// A real-RNS [`AvLinkSender`] over one leviculum link.
    ///
    /// [`Self::send`] rides
    /// [`leviculum_std::driver::LinkHandle::send`] — the pacing- and
    /// busy-absorbing Channel packet path (the same `send_on_link` core
    /// the reverse-path reply uses in [`crate::transport::reticulum`]).
    /// One realtime chunk that fits the link MDU rides as a single link
    /// packet; oversized chunks need fragmentation (stretch — reuse
    /// [`crate::transport::frame_fragment`]).
    pub struct LeviculumAvSender {
        node: Arc<ReticulumNode>,
        link_id: LinkId,
    }

    impl LeviculumAvSender {
        /// Wrap `(node, link_id)` as an outbound A/V link. The link MUST
        /// already be established + identified (via the transport's
        /// `link_open` or a dialed connect) before any chunk is sent.
        #[must_use]
        pub fn new(node: Arc<ReticulumNode>, link_id: LinkId) -> Self {
            Self { node, link_id }
        }

        /// The link this sender drives.
        #[must_use]
        pub fn link_id(&self) -> &LinkId {
            &self.link_id
        }
    }

    #[async_trait::async_trait]
    impl AvLinkSender for LeviculumAvSender {
        async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError> {
            self.node
                .link_handle(&self.link_id)
                .send(bytes)
                .await
                .map_err(|e| {
                    AvDispatcherError::SendFailed(format!(
                        "leviculum link {:?} send failed: {e}",
                        self.link_id
                    ))
                })
        }
    }

    /// The inbound half of the real-RNS seam: an [`AvLinkReceiver`] fed
    /// by [`LinkDataPump`]. Wraps the per-link `mpsc` receiver the pump
    /// routes wire frames into.
    pub struct PumpReceiver {
        rx: Mutex<mpsc::Receiver<Vec<u8>>>,
        link_id: LinkId,
    }

    impl PumpReceiver {
        /// The link this receiver drains.
        #[must_use]
        pub fn link_id(&self) -> &LinkId {
            &self.link_id
        }
    }

    #[async_trait::async_trait]
    impl AvLinkReceiver for PumpReceiver {
        async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
            self.rx.lock().await.recv().await.ok_or_else(|| {
                AvDispatcherError::RecvFailed(format!(
                    "leviculum link {:?} pump queue closed",
                    self.link_id
                ))
            })
        }
    }

    /// Demultiplexes a leviculum node's single [`EventReceiver`] into
    /// per-link A/V inbound queues.
    ///
    /// A leviculum node funnels ALL link traffic (across every link) into
    /// one event stream. This pump owns that stream and routes each
    /// [`NodeEvent::LinkDataReceived`] / [`NodeEvent::MessageReceived`] to
    /// the per-`LinkId` queue a caller registered via [`Self::register`],
    /// surfaced as a [`PumpReceiver`] the dispatcher's subscriber /
    /// relay loop drains. A node dedicated to A/V hands its event
    /// receiver here; a node also carrying edge control-plane traffic
    /// cannot (the [`crate::transport::reticulum`] listener already owns
    /// that receiver) — bridging the two is a stretch follow-up.
    #[derive(Default)]
    pub struct LinkDataPump {
        registry: Arc<Mutex<HashMap<LinkId, mpsc::Sender<Vec<u8>>>>>,
    }

    impl LinkDataPump {
        /// A fresh pump with an empty link registry.
        #[must_use]
        pub fn new() -> Self {
            Self {
                registry: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        /// Register a per-link inbound queue and return its
        /// [`PumpReceiver`] half. Wire frames the pump routes for
        /// `link_id` after this call land on the returned receiver.
        pub async fn register(&self, link_id: LinkId) -> PumpReceiver {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(PUMP_QUEUE_DEPTH);
            self.registry.lock().await.insert(link_id, tx);
            tracing::info!(link = ?link_id, "AV link pump: registered inbound queue");
            PumpReceiver {
                rx: Mutex::new(rx),
                link_id,
            }
        }

        /// Drive the node's event stream, routing link data to the
        /// registered per-link queues. Runs until the event receiver
        /// closes (node shutdown). Consumes the pump handle; clone-free
        /// because the registry is `Arc`-shared with the [`PumpReceiver`]
        /// producers.
        ///
        /// No routing decision is silent (CIRISEdge#425): an unroutable
        /// frame (queue full, or an unregistered A/V link) is logged
        /// before it is dropped.
        pub async fn run(self, mut events: EventReceiver) {
            tracing::info!("AV link pump: event loop started");
            while let Some(event) = events.recv().await {
                // Every non-data event (link lifecycle, resources,
                // announces, …) is not A/V wire data — the A/V pump
                // ignores it by design. Link lifecycle for A/V links is
                // the caller's concern (it dialed them).
                let (NodeEvent::LinkDataReceived { link_id, data }
                | NodeEvent::MessageReceived { link_id, data, .. }) = event
                else {
                    continue;
                };
                let sender = self.registry.lock().await.get(&link_id).cloned();
                let Some(sender) = sender else {
                    // Data on a link no A/V consumer registered — not our
                    // traffic. Trace (not warn): a shared node legitimately
                    // carries non-A/V links.
                    tracing::trace!(
                        link = ?link_id,
                        bytes = data.len(),
                        "AV link pump: inbound data on an unregistered link — ignored"
                    );
                    continue;
                };
                if let Err(e) = sender.try_send(data) {
                    // Queue full or receiver dropped. Loud — a realtime
                    // drop under backpressure must be visible, never
                    // silent (CIRISEdge#425). The stream's own retransmit /
                    // heal owns recovery; the pump just refuses to hide it.
                    tracing::warn!(
                        link = ?link_id,
                        error = %e,
                        "AV link pump: inbound frame DROPPED (per-link queue full or closed)"
                    );
                }
            }
            tracing::info!("AV link pump: event loop ended (node event stream closed)");
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::federation_session::PeerKexPubkeys;

    fn stream(seed: u8) -> StreamId {
        StreamId([seed; 32])
    }

    fn hybrid_member(key_id: &str) -> Member {
        Member {
            key_id: key_id.to_string(),
            kex_pubkeys: PeerKexPubkeys {
                x25519_pub: [1u8; 32],
                mlkem768_pub: Some(vec![0xAB; 1184]),
            },
        }
    }

    /// The stream tag is a stable, whitespace-free 8-hex-char prefix.
    #[test]
    fn stream_tag_is_stable_hex_prefix() {
        let t = stream_tag(StreamId([
            0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ]));
        assert_eq!(t, "deadbeef");
        assert!(!t.contains(char::is_whitespace));
    }

    /// A publisher created via `AvSession` carries a non-zero MLS epoch
    /// DEK and reports its downstream subscriber count.
    #[test]
    fn publisher_create_wires_mls_epoch_dek() {
        let s = stream(0x11);
        let publisher = AvPublisher::create(s, "publisher", vec![hybrid_member("seed")], vec![])
            .expect("publisher create");
        assert_eq!(publisher.stream_id(), s);
        assert_eq!(publisher.subscriber_count(), 0);
        // A single seed member → one commit_add → openmls epoch 1.
        assert_eq!(publisher.epoch(), Epoch(1));
        // DEK is MLS-derived (non-zero): a subscriber built with it
        // constructs (a zero/absent DEK would be rejected).
        assert_ne!(publisher.dek.as_bytes(), &[0u8; 32]);
    }

    /// A relay is DEK-free by construction (AvRole::Relay drops any DEK).
    #[test]
    fn relay_holds_no_epoch_dek() {
        let s = stream(0x22);
        let relay = AvRelay::new(s, vec![]).expect("relay create");
        assert_eq!(relay.stream_id(), s);
        assert_eq!(relay.subscriber_count(), 0);
        assert_eq!(relay.dispatcher.role(), AvRole::Relay);
    }

    /// The subscriber refuses to construct without a DEK — proven via
    /// the dispatcher's construction guard surfaced through `subscribe`.
    /// (A subscriber with no DEK would black-hole every frame.)
    #[tokio::test]
    async fn subscribe_requires_dek_via_dispatcher_guard() {
        // We can't pass a None DEK through `subscribe` (its signature
        // takes an EpochDek), which is the point: the type makes the
        // black-hole state unrepresentable at this seam.
        let s = stream(0x33);
        let dek = EpochDek::from_bytes([0x44u8; 32]);
        let (_tx, rx) = mpsc::channel::<Vec<u8>>(4);
        let inbound = AvInboundLink {
            transit_key: [0x55u8; 32],
            link_id: b"sub".to_vec(),
            inbound_recv: Box::new(MpscReceiver {
                rx: tokio::sync::Mutex::new(rx),
            }),
        };
        let out = AvSubscriber::subscribe(s, &dek, &"parent".to_string(), inbound);
        assert!(out.is_ok(), "subscriber with a DEK must construct");
    }

    /// CIRISEdge#440 — `feature.av_streams=0` refuses ALM admission with its
    /// OWN named error, BEFORE the per-hop eligibility walk; an un-paused gate
    /// over the same (empty) directory falls through to the ordinary planner
    /// path — the absence contract.
    ///
    /// The reader here is `fixed_for_test` (consumer wiring); that a REAL
    /// admitted `feature.av_streams=0` row produces exactly this
    /// `av_streams_paused: true` snapshot is the field-provenance suite in
    /// `replication::mesh_config`.
    #[tokio::test]
    async fn av_streams_pause_refuses_admission_with_named_error() {
        use crate::replication::mesh_config::{MeshConfigReader, MeshConfigRelief};
        use ciris_persist::federation::FederationDirectory;
        use std::sync::Arc;
        let dir: Arc<dyn FederationDirectory> =
            Arc::new(ciris_persist::store::MemoryBackend::new());

        let paused_gate = TransitGate::new(Arc::clone(&dir), Some("us".to_string()))
            .with_mesh_config(Some(Arc::new(MeshConfigReader::fixed_for_test(
                Arc::clone(&dir),
                MeshConfigRelief {
                    av_streams_paused: true,
                    ..MeshConfigRelief::NONE
                },
            ))));
        let out = AvSubscriber::plan_parent_gated(
            &paused_gate,
            Vec::new(),
            2.0,
            ReceiverLayerPolicy::UNCAPPED,
            0,
            chrono::Utc::now(),
        )
        .await;
        assert!(
            matches!(out, Err(AlmJoinError::AvStreamsPaused)),
            "a paused plane must refuse with its OWN named error, never an \
             empty-pool NoFeasibleParent: {out:?}"
        );

        // Absence: no reader wired — the pause can never fire; the call falls
        // through to the ordinary planner (which reports the empty pool).
        let plain_gate = TransitGate::new(Arc::clone(&dir), Some("us".to_string()));
        let out = AvSubscriber::plan_parent_gated(
            &plain_gate,
            Vec::new(),
            2.0,
            ReceiverLayerPolicy::UNCAPPED,
            0,
            chrono::Utc::now(),
        )
        .await;
        assert!(
            !matches!(out, Err(AlmJoinError::AvStreamsPaused)),
            "without a reader the pause must be unreachable (absence = today): {out:?}"
        );
    }

    /// Minimal mpsc receiver so the unit test above can build an
    /// `AvInboundLink` without the reticulum feature. Mirrors the
    /// integration-test stub.
    struct MpscReceiver {
        rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl crate::transport::realtime_av_dispatcher::AvLinkReceiver for MpscReceiver {
        async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| AvDispatcherError::RecvFailed("closed".into()))
        }
    }
}
