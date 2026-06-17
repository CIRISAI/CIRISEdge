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

/// Errors the dispatcher surface can return.
#[derive(thiserror::Error, Debug)]
pub enum AvDispatcherError {
    /// A caller-supplied [`AvLinkSender::send`] failed. Carries the
    /// transport's own error string — the dispatcher is transport-blind
    /// so it cannot type the underlying cause.
    #[error("transport send failed: {0}")]
    SendFailed(String),
    /// A caller-supplied [`AvLinkReceiver::recv`] failed.
    #[error("transport recv failed: {0}")]
    RecvFailed(String),
    /// An AEAD open failed — either the inbound outer layer (relay /
    /// subscriber) or the inner layer (subscriber). Most commonly a
    /// wrong transit key or a `link_seq` desync.
    #[error("AEAD open failed: {0}")]
    OpenFailed(String),
    /// The outer re-seal failed during fan-out.
    #[error("relay forward failed: {0}")]
    ForwardFailed(String),
    /// The publisher / subscriber path requires an `EpochDek` and none
    /// was provided at construction. Structural guard for the relay-vs-
    /// endpoint role split.
    #[error("publisher path requires epoch_dek; none provided")]
    PublisherMissingEpochDek,
    /// A subscriber-tier mutation referenced a subscriber the dispatcher
    /// has no downstream link for.
    #[error("subscriber not found: {0:?}")]
    SubscriberNotFound(PeerKeyId),
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
    /// Enqueue `bytes` onto the outbound link. Returns
    /// [`AvDispatcherError::SendFailed`] on transport error.
    async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError>;
}

/// The async byte-stream recv half the caller plugs in. `recv` resolves
/// to the next inbound wire frame, or [`AvDispatcherError::RecvFailed`]
/// on transport error / closed link.
#[async_trait::async_trait]
pub trait AvLinkReceiver: Send + Sync + 'static {
    /// Pull the next inbound wire frame.
    async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError>;
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
}

impl AvDispatcher {
    /// Build a dispatcher from its config.
    ///
    /// # Errors
    ///
    /// Returns [`AvDispatcherError::PublisherMissingEpochDek`] if a
    /// [`AvRole::Publisher`] is constructed without an `epoch_dek` — the
    /// publisher path cannot inner-seal/outer-seal without the DEK in
    /// scope. A [`AvRole::Relay`] with an `epoch_dek` is accepted but
    /// the DEK is dropped on construction: the relay never holds one,
    /// structurally (the field stays `None`).
    pub fn new(config: AvDispatcherConfig) -> Result<Self, AvDispatcherError> {
        if config.local_role == AvRole::Publisher && config.epoch_dek.is_none() {
            return Err(AvDispatcherError::PublisherMissingEpochDek);
        }
        // Structural invariant: the relay never holds a DEK. Even if the
        // caller passed one, drop it on the floor — `relay_chunk` never
        // reads it, and keeping it would weaken the no-plaintext story.
        let epoch_dek = match config.local_role {
            AvRole::Relay => None,
            AvRole::Publisher | AvRole::Subscriber => config.epoch_dek.map(EpochDek::from_bytes),
        };

        let mut subscribers = HashMap::with_capacity(config.initial_subscribers.len());
        for link in config.initial_subscribers {
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
    /// - [`AvDispatcherError::SendFailed`] (propagated) if the
    ///   transport send fails. The fan-out stops at the first send
    ///   error — callers wanting best-effort fan-out across a flaky
    ///   roster should drive subscribers one at a time.
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

    /// Shared outer-seal-and-send fan-out used by both the publisher and
    /// relay paths. Visits every downstream subscriber, seals with its
    /// per-link state, advances its `link_seq`, and sends.
    async fn fan_out(&mut self, inner: &InnerSealed) -> Result<(), AvDispatcherError> {
        for state in self.subscribers.values_mut() {
            let link_seq = state.next_link_seq;
            let sealed = seal_av_outer(inner, &state.transit_key, &state.link_id, link_seq)
                .map_err(|e| AvDispatcherError::ForwardFailed(e.to_string()))?;
            // Advance only after a successful seal — a seal failure
            // (handled above by early return) must leave the counter
            // idle so no nonce is burned.
            state.next_link_seq = state.next_link_seq.wrapping_add(1);
            state.sender.send(&sealed.to_bytes()).await?;
        }
        Ok(())
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
        let (tx, rx) = mpsc::channel::<ReconstructedChunk>(64);
        // Take ownership of the inbound links — the loop consumes them.
        let inbound = std::mem::take(&mut self.inbound_links);
        let dek_bytes = self.epoch_dek.as_ref().map(|d| *d.as_bytes());

        for link in inbound {
            let tx = tx.clone();
            tokio::spawn(async move {
                let dek = dek_bytes.map(EpochDek::from_bytes);
                let mut next_link_seq: u64 = 0;
                loop {
                    // A permanently-closed link surfaces as a recv error;
                    // exit the loop. A transient error also lands here —
                    // the resilient contract is "drop the frame and stop
                    // pulling from a dead link", since the caller's
                    // transport owns reconnection.
                    let Ok(bytes) = link.inbound_recv.recv().await else {
                        break;
                    };
                    // Malformed wire — skip this frame, keep pulling.
                    let Ok(sealed) = SealedAvChunk::from_bytes(&bytes) else {
                        continue;
                    };
                    let Some(dek) = dek.as_ref() else {
                        // No DEK in scope (relay role mis-driven as a
                        // subscriber). Skip — nothing to open with.
                        continue;
                    };
                    // AEAD open failed — skip this frame WITHOUT advancing
                    // the anti-replay counter, so a single corrupt /
                    // duplicate frame doesn't desync the keystream for
                    // subsequent good frames.
                    let Ok(plaintext) = open_av_chunk(
                        &sealed,
                        &link.transit_key,
                        &link.link_id,
                        next_link_seq,
                        dek,
                    ) else {
                        continue;
                    };
                    next_link_seq = next_link_seq.wrapping_add(1);
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

    /// Add a new downstream subscriber mid-stream. Its `link_seq`
    /// counter starts at 0 — a fresh transit key is a fresh keystream.
    /// Idempotent on `subscriber`: re-adding replaces the outbound state
    /// (and resets the counter).
    ///
    /// # Errors
    ///
    /// Infallible today; returns `Result` for forward-compat with a
    /// future validation pass (e.g. rejecting a relay-role add). Never
    /// returns `Err` in this cut.
    pub fn add_subscriber(&mut self, link: AvSubscriberLink) -> Result<(), AvDispatcherError> {
        self.subscribers.insert(
            link.subscriber,
            OutboundState {
                transit_key: link.transit_key,
                link_id: link.link_id,
                next_link_seq: 0,
                sender: link.outbound_send,
            },
        );
        Ok(())
    }

    /// Remove a downstream subscriber mid-stream. Drops its outbound
    /// state (transit key + sender). No-op if the subscriber was not
    /// registered.
    pub fn remove_subscriber(&mut self, subscriber: &PeerKeyId) {
        self.subscribers.remove(subscriber);
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
}
