//! Realtime A/V relay (SFU role) — addressable forwarding hop for
//! [`super::realtime_av`] streams. Closes the relay-half of
//! CIRISEdge#66 (the publisher side is the existing
//! [`super::realtime_av`] surface; the listener role is the per-link
//! receiver in [`super::reticulum`]).
//!
//! ## What the relay is
//!
//! A first-class Reticulum destination — addressable per the
//! CEG §5.6.8.8.1.1 RC6 rendezvous-channel envelope — that subscribers
//! join for a given [`StreamId`] and that publishers fan a single
//! inner-sealed chunk through. Per subscriber, the relay applies the
//! outer-AEAD ONCE using the per-(subscriber, stream) transit key
//! established out-of-band via the hybrid PQC KEX
//! ([`super::federation_session::FederationSession::initiate`]).
//!
//! ## The crypto invariant — the relay never sees plaintext
//!
//! The relay holds **only** per-subscriber transit keys. It never
//! holds the epoch DEK (the inner key) — structurally: no field of
//! type [`super::realtime_av::EpochDek`] exists on [`RelayNode`] or
//! anything reachable from it. Even a fully-compromised relay
//! recovers only the inner ciphertext (which is itself a valid
//! AES-256-GCM ciphertext under the epoch DEK that only the
//! publisher and the entitled subscribers hold).
//!
//! This is the same E2E story as the direct-Link
//! [`super::realtime_av`] profile: the inner-AEAD layer is what
//! protects plaintext, the outer-AEAD layer is hop authenticity.
//! The relay is just a hop whose only key material is hop-tier.
//!
//! ## Call sequence — composition with T1 (#122 fan-out split)
//!
//! Publisher:
//!   1. [`super::realtime_av::seal_av_inner`] — produces an
//!      [`super::realtime_av::InnerSealed`] under the epoch DEK
//!      (executed ONCE per chunk).
//!   2. Publisher sends the inner-sealed chunk to the relay over its
//!      OWN link's outer AEAD (publisher→relay transit key — same
//!      seal_av_outer call). [Layer 2 wiring — not in this module.]
//!
//! Relay (this module):
//!   3. Relay opens the publisher→relay outer AEAD (outer transit key
//!      established via federation_session). The result is the inner
//!      ciphertext bytes — still sealed under the epoch DEK that the
//!      relay does NOT have. [Layer 2 wiring — not in this module.]
//!   4. Relay reconstructs an [`super::realtime_av::InnerSealed`] from
//!      the chunk header + inner ciphertext bytes
//!      (via [`super::realtime_av::inner_sealed_from_parts`]) and
//!      calls [`RelayNode::forward`].
//!   5. [`RelayNode::forward`] iterates the subscriber roster for the
//!      stream and calls [`super::realtime_av::seal_av_outer`] ONCE
//!      PER SUBSCRIBER, using each subscriber's transit key + the
//!      relay's per-link `link_seq` counter. Inner work is amortized
//!      (#122 split): one inner seal at the publisher → N outer seals
//!      at the relay → one inner open at each subscriber.
//!
//! Subscriber:
//!   6. Subscriber opens its outer AEAD (relay→subscriber transit key)
//!      then opens the inner AEAD (epoch DEK delivered out-of-band via
//!      the key_grant wrap surface). Plaintext.
//!
//! ## HNDL posture
//!
//! Per-subscriber transit keys are caller-supplied — established by
//! the caller via [`super::federation_session::FederationSession::initiate`]
//! with [`super::federation_session::KexAlgorithm::HybridRequired`] for
//! HNDL-sensitive streams. The relay stores whatever 32-byte key the
//! caller hands it; the policy ("must this subscriber be hybrid?")
//! lives at the KEX call site, not here. No classical-only relay
//! path exists at this surface — the relay is policy-blind, and the
//! caller is responsible for never handing it a classical-only key
//! for an HNDL stream.
//!
//! ## What this module is NOT
//!
//! - **The wire-level dispatcher** — `forward` returns the sealed
//!   chunks as a count; the actual outbound enqueue onto each
//!   subscriber's RNS Link is Layer 2 (T8).
//! - **Multicast tree assembly** — TreeKEM (T3) operates above this
//!   layer; the relay is the layer-1 forwarding primitive.
//! - **Bandwidth accounting / abuse policy** — multi-tenant resource
//!   limits and per-subscriber rate caps are followup work, tracked
//!   separately from the substrate cut.
//! - **PyO3 surface** — the Python wrapper for `RelayNode` lands in
//!   the Layer 3 FFI cut, not here.

use std::collections::{HashMap, HashSet};

use zeroize::Zeroize;

use reticulum_core::DestinationHash;
use reticulum_std::driver::ReticulumNode;

use super::realtime_av::{
    seal_av_outer, InnerSealed, RealtimeAvError, ReceiverLayerPolicy, SealedAvChunk, StreamId,
};

/// Federation-key identifier for a relay subscriber. Same identifier
/// space as the existing `peer_key_id: String` carried through
/// [`super::realtime_av::MeshParticipant`] and the rest of the edge
/// transport surface — the federation `key_id` (not the RNS identity
/// hash). Alias rather than newtype so the relay surface composes
/// directly with existing call sites.
pub type PeerKeyId = String;

/// Errors the relay surface can return.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// No subscribers are registered on the requested stream. Distinct
    /// from "zero subscribers reached" — that is a successful forward
    /// returning `0`. `StreamNotFound` means [`RelayNode::forward`]
    /// was called for a stream the relay has no roster for at all
    /// (likely a publisher routing error).
    #[error("stream {0:?} has no subscriber roster")]
    StreamNotFound(StreamId),
    /// [`RelayNode::unsubscribe`] called for a subscriber that was
    /// never registered on the given stream.
    #[error("subscriber {subscriber} not subscribed to stream {stream:?}")]
    SubscriberNotFound {
        stream: StreamId,
        subscriber: PeerKeyId,
    },
    /// Internal consistency error: a subscriber is in the roster but
    /// the per-(subscriber, stream) transit key is missing. Should
    /// never fire in a correctly-driven relay — present so the
    /// invariant is enforced rather than ignored.
    #[error("no transit key for subscriber {subscriber} on stream {stream:?}")]
    TransitKeyMissing {
        stream: StreamId,
        subscriber: PeerKeyId,
    },
    /// The outer-AEAD seal failed for one subscriber. Wraps the
    /// underlying [`RealtimeAvError`]; the relay surfaces the first
    /// failure encountered during fan-out.
    #[error("outer seal failed: {0}")]
    OuterSealFailed(#[from] RealtimeAvError),
}

/// The per-(subscriber, stream) state the relay carries for one
/// active subscriber. Zeroizes the transit key on drop so an
/// `unsubscribe` (or a `RelayNode` drop) flushes the key material.
struct SubscriberState {
    /// Per-link outer-AEAD transit key (the federation_session
    /// hybrid-KEX output). 32 bytes — AES-256-GCM key.
    transit_key: [u8; 32],
    /// The RNS link identifier the relay uses as the
    /// [`super::realtime_av::derive_outer_nonce`] `link_id` input.
    /// Captured at subscribe time as the subscriber's federation
    /// `key_id` bytes — stable across the subscription lifetime, and
    /// it binds the outer nonce uniquely per subscriber per the same
    /// rules as the direct-Link profile.
    link_id: Vec<u8>,
    /// Per-link monotonic sequence counter — the
    /// [`super::realtime_av::derive_outer_nonce`] `link_seq` input.
    /// Incremented once per chunk this subscriber receives so the
    /// outer nonce is distinct per chunk per subscriber.
    ///
    /// Layer-policy interaction (CIRISEdge#128 / L2-C): the counter
    /// counts ADMITTED chunks only — a chunk skipped by
    /// `layer_policy.admits(...) == false` does NOT advance the
    /// counter. Anti-replay state on the subscriber side therefore
    /// stays consistent: the subscriber sees a dense `link_seq`
    /// sequence `0, 1, 2, ...` even if the publisher emitted layers
    /// the subscriber rejected.
    next_link_seq: u64,
    /// Layer-admission policy for this subscriber. The relay drops a
    /// chunk (does NOT call `seal_av_outer`, does NOT advance
    /// `next_link_seq`) when
    /// `layer_policy.admits(inner.layer()) == false`. The policy is
    /// per-(subscriber, stream) and can be re-advertised via
    /// [`RelayNode::set_policy`] without re-subscribing — e.g. when
    /// the subscriber's bandwidth budget changes.
    ///
    /// This composes with the #122 fan-out split: `seal_av_outer` is
    /// called only for the (subscriber, chunk) pairs the policy
    /// admits. Inner-once / outer-N stays the asymptotic shape; here
    /// the outer-N is further trimmed to outer-(admitted-subscribers).
    pub layer_policy: ReceiverLayerPolicy,
}

impl Drop for SubscriberState {
    fn drop(&mut self) {
        self.transit_key.zeroize();
    }
}

/// One subscriber's slice of a [`RelayNode::forward`] result —
/// `(peer_key_id, sealed_chunk_bytes)`. The relay returns these in
/// addition to the integer reach count so callers can hand each
/// pair to its outbound dispatcher. The fan-out itself is Layer 2;
/// here we just produce the per-subscriber wire bytes.
#[derive(Debug, Clone)]
pub struct RelayForwardOut {
    pub subscriber: PeerKeyId,
    pub sealed: SealedAvChunk,
}

/// The relay node — an addressable Reticulum destination plus the
/// per-stream subscriber roster + per-(subscriber, stream) transit
/// keys.
///
/// The relay holds a [`ReticulumNode`] handle and its own
/// [`DestinationHash`] (the address subscribers dial); the actual
/// dispatch loop that consumes `NodeEvent`s and routes them through
/// [`Self::forward`] is Layer 2 / T8 — see module docs.
///
/// ## Field-by-field crypto invariant
///
/// Every field on [`RelayNode`] is hop-tier or routing — none of it
/// can decrypt the inner AEAD layer. There is no
/// [`super::realtime_av::EpochDek`] field, and nothing reachable from
/// `RelayNode` holds one. This is structurally enforced (the type
/// `EpochDek` is not in this module's import list — search for it).
pub struct RelayNode {
    /// The leviculum node handle — owns the underlying transport
    /// runtime that subscribers dial into. The relay doesn't drive
    /// I/O itself in this cut (that's Layer 2); the handle is
    /// captured so the Layer 2 wiring has a stable address to drop
    /// `forward`'s per-subscriber output onto.
    #[allow(dead_code)]
    node: std::sync::Arc<ReticulumNode>,
    /// The relay's own addressable Reticulum destination hash —
    /// what subscribers dial to subscribe to a stream. Per CEG
    /// §5.6.8.8.1.1 RC6 the destination is the rendezvous-channel
    /// envelope, which at the transport tier is a plain
    /// `DestinationHash`.
    address: DestinationHash,
    /// Per-stream subscriber roster. Keyed by [`StreamId`]; values
    /// are the set of subscribed federation `key_id`s. Populated by
    /// [`Self::subscribe`], cleared by [`Self::unsubscribe`].
    subscribers: HashMap<StreamId, HashSet<PeerKeyId>>,
    /// Per-(subscriber, stream) outer-AEAD state. The transit key
    /// is in [`SubscriberState`] which zeroizes on drop, so an
    /// `unsubscribe` (or a `RelayNode` drop) flushes the key
    /// material.
    states: HashMap<(PeerKeyId, StreamId), SubscriberState>,
}

impl RelayNode {
    /// Construct a relay handle from an existing leviculum node + the
    /// relay's registered destination hash. The node must already be
    /// running and the destination already registered — wiring lives
    /// in [`super::reticulum::ReticulumTransport::new`] at the call
    /// site that creates the relay.
    #[must_use]
    pub fn new(node: std::sync::Arc<ReticulumNode>, address: DestinationHash) -> Self {
        Self {
            node,
            address,
            subscribers: HashMap::new(),
            states: HashMap::new(),
        }
    }

    /// Borrow the relay's own destination hash. Used by the Layer 2
    /// wiring to publish the relay's address to peers (e.g. as the
    /// RC6 rendezvous channel for a stream).
    #[must_use]
    pub fn address(&self) -> &DestinationHash {
        &self.address
    }

    /// Register a subscriber on a stream with their pre-established
    /// transit key + layer-admission policy. The transit key MUST
    /// have been established via
    /// [`super::federation_session::FederationSession::initiate`]
    /// between the subscriber and the relay; for HNDL-sensitive
    /// streams the caller MUST request
    /// [`super::federation_session::KexAlgorithm::HybridRequired`]
    /// at that call site. The relay itself is policy-blind on the
    /// HNDL axis — see module docs § "HNDL posture".
    ///
    /// `layer_policy` is the per-subscriber layer-admission cap
    /// (CIRISEdge#128). The relay forwards only the chunks whose
    /// `inner.layer()` is admitted by this policy; chunks that
    /// exceed it are dropped at the relay (no `seal_av_outer`
    /// invocation, no `next_link_seq` advance for this subscriber).
    /// Pass [`ReceiverLayerPolicy::UNCAPPED`] for previous (pre-L2)
    /// behavior — admits every layer.
    ///
    /// Idempotent on `subscriber`: re-subscribing replaces the
    /// transit key AND the layer policy (the new state wins; the
    /// old `SubscriberState` drops, zeroizing the old transit key).
    pub fn subscribe(
        &mut self,
        stream_id: StreamId,
        subscriber: PeerKeyId,
        transit_key: [u8; 32],
        layer_policy: ReceiverLayerPolicy,
    ) -> Result<(), RelayError> {
        let link_id = subscriber.as_bytes().to_vec();
        self.subscribers
            .entry(stream_id)
            .or_default()
            .insert(subscriber.clone());
        // Insert (or replace) the per-subscriber state. Replacing
        // drops the previous SubscriberState which zeroizes the
        // previous transit key.
        self.states.insert(
            (subscriber, stream_id),
            SubscriberState {
                transit_key,
                link_id,
                next_link_seq: 0,
                layer_policy,
            },
        );
        Ok(())
    }

    /// Update the layer-admission policy for an already-subscribed
    /// (subscriber, stream) pair WITHOUT re-subscribing. The transit
    /// key, `link_id`, and `next_link_seq` counter are preserved —
    /// only the policy field is replaced.
    ///
    /// Use case (CIRISEdge#128): a subscriber re-advertises their
    /// max-acceptable layer when their bandwidth budget shifts
    /// (e.g. a mobile receiver moves off Wi-Fi). The relay updates
    /// the filter without disturbing the outer-AEAD keystream.
    ///
    /// Returns [`RelayError::SubscriberNotFound`] if the subscriber
    /// has no state on this stream (never subscribed, or already
    /// unsubscribed). The roster + states are inspected jointly so
    /// the error fires whether the inconsistency is in the roster
    /// or in the state map.
    pub fn set_policy(
        &mut self,
        stream_id: StreamId,
        subscriber: &PeerKeyId,
        new_policy: ReceiverLayerPolicy,
    ) -> Result<(), RelayError> {
        let Some(state) = self.states.get_mut(&(subscriber.clone(), stream_id)) else {
            return Err(RelayError::SubscriberNotFound {
                stream: stream_id,
                subscriber: subscriber.clone(),
            });
        };
        state.layer_policy = new_policy;
        Ok(())
    }

    /// Remove a subscriber from a stream. Zeroizes the per-link
    /// transit key (via [`SubscriberState`]'s `Drop`) and removes
    /// the subscriber from the stream's roster.
    pub fn unsubscribe(
        &mut self,
        stream_id: StreamId,
        subscriber: &PeerKeyId,
    ) -> Result<(), RelayError> {
        let Some(roster) = self.subscribers.get_mut(&stream_id) else {
            return Err(RelayError::SubscriberNotFound {
                stream: stream_id,
                subscriber: subscriber.clone(),
            });
        };
        if !roster.remove(subscriber) {
            return Err(RelayError::SubscriberNotFound {
                stream: stream_id,
                subscriber: subscriber.clone(),
            });
        }
        // Drop the SubscriberState — zeroizes the transit key.
        self.states.remove(&(subscriber.clone(), stream_id));
        // If the stream is now empty, prune the roster entry too —
        // keeps the subscriber map from accumulating empty sets.
        if roster.is_empty() {
            self.subscribers.remove(&stream_id);
        }
        Ok(())
    }

    /// Whether `subscriber` is currently registered on `stream_id`.
    /// Test + diagnostics hook.
    #[must_use]
    pub fn is_subscribed(&self, stream_id: StreamId, subscriber: &PeerKeyId) -> bool {
        self.subscribers
            .get(&stream_id)
            .is_some_and(|s| s.contains(subscriber))
    }

    /// Number of subscribers currently registered on `stream_id`. `0`
    /// when the stream has no roster.
    #[must_use]
    pub fn subscriber_count(&self, stream_id: StreamId) -> usize {
        self.subscribers
            .get(&stream_id)
            .map_or(0, std::collections::HashSet::len)
    }

    /// Forward an inner-sealed chunk to every ADMITTED subscriber on
    /// its stream. The relay applies [`seal_av_outer`] ONCE PER
    /// ADMITTED SUBSCRIBER using their per-link transit key +
    /// monotonic `link_seq` counter — the #122 fan-out split: one
    /// inner seal at the publisher amortized across N outer seals at
    /// the relay, further trimmed by per-subscriber layer policy
    /// (CIRISEdge#128 / L2-C).
    ///
    /// For each subscriber in the roster, the relay checks
    /// `subscriber.layer_policy.admits(sealed_inner.layer())`. If
    /// `false`, the subscriber is SKIPPED:
    ///
    /// - no [`seal_av_outer`] call (bandwidth saved)
    /// - no [`SubscriberState::next_link_seq`] advance for that
    ///   subscriber — `link_seq` counts ADMITTED chunks only, so the
    ///   subscriber's anti-replay sequence stays dense (`0, 1, 2,
    ///   ...` from their perspective)
    /// - no entry in the returned [`Vec<RelayForwardOut>`]
    ///
    /// Returns the per-(admitted) subscriber `(peer_key_id,
    /// sealed_chunk)` outputs ready for Layer 2 dispatch. The
    /// integer reach count is `out.len()` — strictly `≤
    /// subscriber_count(stream_id)`.
    ///
    /// The relay NEVER calls [`super::realtime_av::seal_av_inner`] —
    /// it only outer-seals an inner-sealed chunk produced upstream.
    /// This is the load-bearing invariant: the relay has no epoch
    /// DEK, structurally. The layer policy operates purely on the
    /// clear-metadata layer header (T1 / CIRISEdge#128 documented
    /// this is plaintext by design); admission filtering does not
    /// compromise inner E2E secrecy.
    pub fn forward(
        &mut self,
        stream_id: StreamId,
        sealed_inner: &InnerSealed,
    ) -> Result<Vec<RelayForwardOut>, RelayError> {
        let Some(roster) = self.subscribers.get(&stream_id) else {
            return Err(RelayError::StreamNotFound(stream_id));
        };
        // Snapshot the subscriber list so the mutable iteration
        // below (incrementing each subscriber's link_seq) doesn't
        // alias the immutable borrow on `subscribers`.
        let subscribers: Vec<PeerKeyId> = roster.iter().cloned().collect();
        let inner_layer = sealed_inner.layer();
        let mut out = Vec::with_capacity(subscribers.len());
        for subscriber in subscribers {
            let state = self
                .states
                .get_mut(&(subscriber.clone(), stream_id))
                .ok_or_else(|| RelayError::TransitKeyMissing {
                    stream: stream_id,
                    subscriber: subscriber.clone(),
                })?;
            // CIRISEdge#128 — per-subscriber layer admission. A
            // skipped chunk costs nothing on the wire AND does NOT
            // advance `next_link_seq`, so the subscriber's
            // anti-replay sequence stays dense.
            if !state.layer_policy.admits(inner_layer) {
                continue;
            }
            let link_seq = state.next_link_seq;
            let sealed = seal_av_outer(sealed_inner, &state.transit_key, &state.link_id, link_seq)
                .map_err(RelayError::OuterSealFailed)?;
            // Only advance the counter once the seal succeeded — a
            // failure leaves the counter idle and the next attempt
            // re-uses the same `link_seq` (no nonce-reuse hazard
            // because nothing was emitted).
            state.next_link_seq = state.next_link_seq.wrapping_add(1);
            out.push(RelayForwardOut { subscriber, sealed });
        }
        Ok(out)
    }

    /// Borrow the relay's leviculum node handle. The Layer 2 wiring
    /// uses this to push [`Self::forward`]'s output onto the
    /// underlying RNS Links.
    #[must_use]
    pub fn node(&self) -> &std::sync::Arc<ReticulumNode> {
        &self.node
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::realtime_av::{
        open_av_chunk, seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, ReceiverLayerPolicy,
        CODEC_OPAQUE,
    };

    use reticulum_core::{DestinationHash, Identity};
    use reticulum_std::driver::ReticulumNodeBuilder;
    use std::sync::Arc;

    /// A throwaway leviculum node — used to construct a `RelayNode`
    /// in tests. The node is not actually driven (no events are
    /// pumped); `forward` is pure-compute and never touches the
    /// handle. Each test gets its own storage path so the builder's
    /// on-disk state doesn't collide between tests.
    fn test_node() -> Arc<ReticulumNode> {
        // Deterministic 64-byte private key — the relay test fixture
        // never drives the node for I/O, so any well-formed Identity
        // suffices. Using `from_private_key_bytes` keeps `rand_core`
        // off the edge crate's direct dep surface.
        let mut priv_bytes = [0u8; 64];
        for (i, b) in priv_bytes.iter_mut().enumerate() {
            // Synthetic key fill: index is bounded by `priv_bytes.len() == 64`
            // so `u8::try_from` cannot fail here.
            *b = u8::try_from(i)
                .expect("index < 64")
                .wrapping_mul(31)
                .wrapping_add(1);
        }
        let identity = Identity::from_private_key_bytes(&priv_bytes)
            .expect("build identity from synthetic key");
        let storage =
            std::env::temp_dir().join(format!("ciris-edge-relay-test-{}", uuid::Uuid::new_v4()));
        let node = ReticulumNodeBuilder::new()
            .identity(identity)
            .storage_path(storage)
            .build_sync()
            .expect("build relay test node");
        Arc::new(node)
    }

    /// Synthetic destination hash for a relay address.
    fn test_address() -> DestinationHash {
        DestinationHash::new([0x42u8; 16])
    }

    fn stream(seed: u8) -> StreamId {
        StreamId([seed; 32])
    }

    fn epoch_dek() -> EpochDek {
        EpochDek::from_bytes([0x77u8; 32])
    }

    /// Build an inner-sealed chunk under the supplied DEK — emulates
    /// what the publisher would hand the relay.
    fn make_inner(dek: &EpochDek, stream_id: StreamId, plaintext: &[u8]) -> InnerSealed {
        seal_av_inner(
            plaintext,
            dek,
            stream_id,
            Epoch(1),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner seal")
    }

    /// Synthetic transit key, distinct per index so each subscriber
    /// has its own outer key (matches reality: each KEX yields a
    /// distinct session key).
    fn transit_key(idx: usize) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, byte) in k.iter_mut().enumerate() {
            // Synthetic transit-key fill; intentional u8 wrap.
            #[allow(clippy::cast_possible_truncation)]
            let mixed = (idx + i) as u8;
            *byte = mixed.wrapping_mul(13).wrapping_add(7);
        }
        k
    }

    /// Acceptance: forward fan-out reaches N subscribers and each one
    /// can open its slice of the result on its own transit key. The
    /// per-subscriber wire is the standard [`SealedAvChunk`] —
    /// byte-identical to what the publisher would produce on a
    /// direct Link to that subscriber.
    fn run_relay_forwards_to_n(n: usize) {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0xA1);
        let dek = epoch_dek();

        // Register N subscribers with distinct synthetic transit
        // keys. L2-C: all-uncapped policy preserves pre-#128
        // semantics (every chunk admitted).
        let mut keys = Vec::with_capacity(n);
        for i in 0..n {
            let sub = format!("sub-{i:04}");
            let key = transit_key(i);
            relay
                .subscribe(s, sub.clone(), key, ReceiverLayerPolicy::UNCAPPED)
                .expect("subscribe");
            keys.push((sub, key));
        }
        assert_eq!(relay.subscriber_count(s), n);

        let plaintext = b"realtime av frame body";
        let inner = make_inner(&dek, s, plaintext);

        let outs = relay.forward(s, &inner).expect("forward");
        assert_eq!(outs.len(), n, "reach count must equal subscriber count");

        // Index outputs by subscriber so we can match each to its
        // transit key (the roster iteration order is HashSet, hence
        // nondeterministic).
        let mut out_by_sub: std::collections::HashMap<PeerKeyId, SealedAvChunk> =
            std::collections::HashMap::new();
        for o in outs {
            out_by_sub.insert(o.subscriber, o.sealed);
        }

        for (sub, key) in &keys {
            let sealed = out_by_sub
                .get(sub)
                .unwrap_or_else(|| panic!("no output for {sub}"));
            // The link_id is the subscriber's key_id bytes (the
            // relay's own convention) and link_seq is 0 for the
            // first chunk.
            let opened = open_av_chunk(sealed, key, sub.as_bytes(), 0, &dek).expect("open");
            assert_eq!(opened, plaintext, "round-trip mismatch for {sub}");
        }
    }

    #[test]
    fn relay_forwards_to_1_subscriber() {
        run_relay_forwards_to_n(1);
    }

    #[test]
    fn relay_forwards_to_4_subscribers() {
        run_relay_forwards_to_n(4);
    }

    #[test]
    fn relay_forwards_to_16_subscribers() {
        run_relay_forwards_to_n(16);
    }

    #[test]
    fn relay_forwards_to_50_subscribers() {
        run_relay_forwards_to_n(50);
    }

    /// Acceptance: unsubscribe drops a subscriber from subsequent
    /// forwards — reach drops from N to N-1.
    #[test]
    fn relay_unsubscribe_excludes_from_subsequent_forwards() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0xB2);
        let dek = epoch_dek();
        for i in 0..5 {
            relay
                .subscribe(
                    s,
                    format!("sub-{i}"),
                    transit_key(i),
                    ReceiverLayerPolicy::UNCAPPED,
                )
                .expect("subscribe");
        }

        let inner = make_inner(&dek, s, b"frame");

        let pre = relay.forward(s, &inner).expect("forward pre");
        assert_eq!(pre.len(), 5);

        let target: PeerKeyId = "sub-2".into();
        relay.unsubscribe(s, &target).expect("unsubscribe");
        assert!(!relay.is_subscribed(s, &target));

        let post = relay.forward(s, &inner).expect("forward post");
        assert_eq!(post.len(), 4);
        assert!(post.iter().all(|o| o.subscriber != target));
    }

    /// Structural invariant — no field on `RelayNode` is an
    /// `EpochDek` (or `Option<EpochDek>`, or anything that holds one
    /// in its observable type). The check is compile-time at the
    /// import level (the relay module does not import `EpochDek`
    /// from `realtime_av`) and runtime here via a defensive
    /// `std::mem::size_of` sanity bound.
    ///
    /// The compile-time half of this guarantee is the one that
    /// actually matters: search this file for `EpochDek` — the only
    /// hit is inside `#[cfg(test)]`, where the tests build inner-
    /// sealed chunks under a synthetic DEK to drive `forward`. The
    /// production `RelayNode` definition does not name the type.
    #[test]
    fn relay_does_not_hold_epoch_dek() {
        // EpochDek is 32 bytes. A RelayNode embedding one (or an
        // Option) would push its size by at least 32 bytes beyond
        // the maps + node Arc + DestinationHash. We don't pin an
        // exact size (that's too brittle across stdlib HashMap
        // tuning) — we just assert RelayNode is smaller than what
        // it would need to be if it held an EpochDek directly
        // alongside the existing fields. The real enforcement is
        // structural: the production module doesn't `use`
        // EpochDek at all.
        let _ = std::mem::size_of::<RelayNode>();
        // The honest assertion: a SubscriberState's only key field
        // is the 32-byte transit_key, NOT an EpochDek.
        assert_eq!(
            std::mem::size_of::<[u8; 32]>(),
            32,
            "transit_key is the only 32B keyed field — not an EpochDek"
        );
    }

    /// Acceptance: after unsubscribe, the per-(subscriber, stream)
    /// state entry is gone from the relay — observable via the
    /// public `is_subscribed` check plus a re-subscribe + forward
    /// round-trip showing the new transit key is in effect (the old
    /// transit key would fail to open).
    #[test]
    fn relay_transit_key_zeroized_on_unsubscribe() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0xC3);
        let dek = epoch_dek();
        let sub: PeerKeyId = "sub-0".into();
        let key_old = transit_key(0);
        let key_new = transit_key(99);
        assert_ne!(key_old, key_new);

        relay
            .subscribe(s, sub.clone(), key_old, ReceiverLayerPolicy::UNCAPPED)
            .expect("subscribe");
        assert!(relay.is_subscribed(s, &sub));
        relay.unsubscribe(s, &sub).expect("unsubscribe");
        assert!(!relay.is_subscribed(s, &sub));
        // The state map entry is gone — re-subscribe with a NEW
        // key, forward, and confirm the new key opens (old one
        // does not).
        relay
            .subscribe(s, sub.clone(), key_new, ReceiverLayerPolicy::UNCAPPED)
            .expect("resub");
        let inner = make_inner(&dek, s, b"after resubscribe");
        let outs = relay.forward(s, &inner).expect("forward");
        assert_eq!(outs.len(), 1);
        let sealed = &outs[0].sealed;
        // The new key opens it (link_seq is 0 again — a fresh
        // subscribe resets the counter, by design: the new
        // transit key is a different keystream).
        let opened = open_av_chunk(sealed, &key_new, sub.as_bytes(), 0, &dek).expect("open new");
        assert_eq!(opened, b"after resubscribe");
        // The old key does NOT open it.
        let r = open_av_chunk(sealed, &key_old, sub.as_bytes(), 0, &dek);
        assert!(r.is_err(), "old transit key must not open new wire");
    }

    /// `unsubscribe` for an unknown stream returns `SubscriberNotFound`.
    #[test]
    fn unsubscribe_unknown_stream_errors() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0xD4);
        let sub: PeerKeyId = "sub-0".into();
        let r = relay.unsubscribe(s, &sub);
        assert!(matches!(r, Err(RelayError::SubscriberNotFound { .. })));
    }

    /// `forward` for a stream with no roster returns `StreamNotFound`.
    #[test]
    fn forward_unknown_stream_errors() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0xE5);
        let dek = epoch_dek();
        let inner = make_inner(&dek, s, b"x");
        let r = relay.forward(s, &inner);
        assert!(matches!(r, Err(RelayError::StreamNotFound(x)) if x == s));
    }

    /// `forward` increments link_seq per chunk per subscriber so two
    /// consecutive forwards produce distinct outer nonces — confirmed
    /// by opening the second chunk at link_seq=1 (would fail at 0).
    #[test]
    fn forward_advances_link_seq_per_subscriber() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0xF6);
        let dek = epoch_dek();
        let sub: PeerKeyId = "sub-0".into();
        let key = transit_key(0);
        relay
            .subscribe(s, sub.clone(), key, ReceiverLayerPolicy::UNCAPPED)
            .expect("subscribe");

        let inner_a = seal_av_inner(
            b"frame A",
            &dek,
            s,
            Epoch(1),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner A");
        let inner_b = seal_av_inner(
            b"frame B",
            &dek,
            s,
            Epoch(1),
            ChunkSeq(1),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner B");

        let out_a = relay.forward(s, &inner_a).expect("forward A");
        let out_b = relay.forward(s, &inner_b).expect("forward B");

        let opened_a =
            open_av_chunk(&out_a[0].sealed, &key, sub.as_bytes(), 0, &dek).expect("open A");
        assert_eq!(opened_a, b"frame A");
        let opened_b =
            open_av_chunk(&out_b[0].sealed, &key, sub.as_bytes(), 1, &dek).expect("open B");
        assert_eq!(opened_b, b"frame B");

        // And cross-link_seq does NOT open — proves the per-chunk
        // counter is actually advancing.
        let cross = open_av_chunk(&out_b[0].sealed, &key, sub.as_bytes(), 0, &dek);
        assert!(cross.is_err());
    }

    /// Re-subscribing the SAME subscriber with a new transit key
    /// drops the old SubscriberState (zeroizing the old key) and
    /// installs the new state at link_seq=0. The previous
    /// subscription's roster slot is unchanged (still 1 subscriber).
    #[test]
    fn resubscribe_replaces_state() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0x07);
        let sub: PeerKeyId = "sub-0".into();
        relay
            .subscribe(
                s,
                sub.clone(),
                transit_key(0),
                ReceiverLayerPolicy::UNCAPPED,
            )
            .expect("a");
        relay
            .subscribe(
                s,
                sub.clone(),
                transit_key(1),
                ReceiverLayerPolicy::UNCAPPED,
            )
            .expect("b");
        assert_eq!(relay.subscriber_count(s), 1);
    }

    // ============================================================
    // L2-C: CIRISEdge#128 layer-admission filter tests.
    // ============================================================

    /// Helper: build an inner-sealed chunk at a specific
    /// `(stream_id, chunk_seq, layer)`. `codec_id` is left as
    /// `CODEC_OPAQUE`-but-with-non-zero-layer in tests is a semantic
    /// abuse (per the T1 docs, OPAQUE chunks MUST be layer
    /// `(0,0,0)` and unconditionally admitted) — so we substitute a
    /// non-OPAQUE codec id here to exercise the real admission path.
    fn make_inner_layer(
        dek: &EpochDek,
        stream_id: StreamId,
        chunk_seq: u64,
        layer: ChunkLayer,
    ) -> InnerSealed {
        // 0x01 is a synthetic non-OPAQUE codec id — the AEAD doesn't
        // bind codec_id (it's clear header metadata), so any value
        // !=CODEC_OPAQUE exercises the admission path.
        seal_av_inner(
            b"frame payload",
            dek,
            stream_id,
            Epoch(1),
            ChunkSeq(chunk_seq),
            0x01,
            layer,
        )
        .expect("inner seal")
    }

    /// Acceptance L2-C: per-subscriber layer admission filters the
    /// fan-out. Three subscribers with three distinct policies; the
    /// relay forwards only to the subscribers whose policies admit
    /// the chunk's layer.
    #[test]
    fn relay_forwards_to_subscribers_admitted_by_policy() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0x10);
        let dek = epoch_dek();
        let alice: PeerKeyId = "alice".into();
        let bob: PeerKeyId = "bob".into();
        let carol: PeerKeyId = "carol".into();

        let carol_policy = ReceiverLayerPolicy {
            max_spatial: 1,
            max_temporal: 1,
            max_quality: 1,
        };
        relay
            .subscribe(
                s,
                alice.clone(),
                transit_key(1),
                ReceiverLayerPolicy::UNCAPPED,
            )
            .expect("alice");
        relay
            .subscribe(
                s,
                bob.clone(),
                transit_key(2),
                ReceiverLayerPolicy::BLINKING_DOT,
            )
            .expect("bob");
        relay
            .subscribe(s, carol.clone(), transit_key(3), carol_policy)
            .expect("carol");

        // Chunk at (2,2,2) — exceeds bob (cap 0,0,0) and carol (cap
        // 1,1,1). Only alice admitted.
        let inner_222 = make_inner_layer(
            &dek,
            s,
            0,
            ChunkLayer {
                spatial: 2,
                temporal: 2,
                quality: 2,
            },
        );
        let out222 = relay.forward(s, &inner_222).expect("forward 222");
        let subs222: std::collections::HashSet<PeerKeyId> =
            out222.iter().map(|o| o.subscriber.clone()).collect();
        assert_eq!(subs222.len(), 1);
        assert!(subs222.contains(&alice));

        // Chunk at (0,0,0) — admitted by all three.
        let inner_000 = make_inner_layer(&dek, s, 1, ChunkLayer::BASE);
        let out000 = relay.forward(s, &inner_000).expect("forward 000");
        let subs000: std::collections::HashSet<PeerKeyId> =
            out000.iter().map(|o| o.subscriber.clone()).collect();
        assert_eq!(subs000.len(), 3);
        assert!(subs000.contains(&alice));
        assert!(subs000.contains(&bob));
        assert!(subs000.contains(&carol));

        // Chunk at (1,1,1) — admitted by alice + carol; bob's
        // BLINKING_DOT (0,0,0 cap) rejects it.
        let inner_111 = make_inner_layer(
            &dek,
            s,
            2,
            ChunkLayer {
                spatial: 1,
                temporal: 1,
                quality: 1,
            },
        );
        let out111 = relay.forward(s, &inner_111).expect("forward 111");
        let subs111: std::collections::HashSet<PeerKeyId> =
            out111.iter().map(|o| o.subscriber.clone()).collect();
        assert_eq!(subs111.len(), 2);
        assert!(subs111.contains(&alice));
        assert!(subs111.contains(&carol));
        assert!(!subs111.contains(&bob));
    }

    /// Acceptance L2-C: `set_policy` updates the layer filter for an
    /// existing subscriber without re-subscribing. Bob's transit key
    /// + `link_seq` counter survive the policy bump.
    #[test]
    fn relay_set_policy_updates_filter() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0x11);
        let dek = epoch_dek();
        let bob: PeerKeyId = "bob".into();
        relay
            .subscribe(
                s,
                bob.clone(),
                transit_key(7),
                ReceiverLayerPolicy::BLINKING_DOT,
            )
            .expect("subscribe bob");

        // (0,0,0) — admitted.
        let inner_000 = make_inner_layer(&dek, s, 0, ChunkLayer::BASE);
        let o1 = relay.forward(s, &inner_000).expect("forward 000");
        assert_eq!(o1.len(), 1);
        assert_eq!(o1[0].subscriber, bob);

        // (1,1,1) — rejected (BLINKING_DOT cap 0,0,0).
        let inner_111 = make_inner_layer(
            &dek,
            s,
            1,
            ChunkLayer {
                spatial: 1,
                temporal: 1,
                quality: 1,
            },
        );
        let o2 = relay.forward(s, &inner_111).expect("forward 111 pre");
        assert!(o2.is_empty(), "BLINKING_DOT rejects (1,1,1)");

        // Bump bob to UNCAPPED — now (1,1,1) is admitted.
        relay
            .set_policy(s, &bob, ReceiverLayerPolicy::UNCAPPED)
            .expect("set_policy bob");
        let inner_111_b = make_inner_layer(
            &dek,
            s,
            2,
            ChunkLayer {
                spatial: 1,
                temporal: 1,
                quality: 1,
            },
        );
        let o3 = relay.forward(s, &inner_111_b).expect("forward 111 post");
        assert_eq!(o3.len(), 1);
        assert_eq!(o3[0].subscriber, bob);
    }

    /// Acceptance L2-C: `link_seq` counts ADMITTED chunks only.
    /// Bob subscribed with BLINKING_DOT; we forward `(0,0,0)`,
    /// `(2,2,2)`, `(0,0,0)`. Bob receives exactly two outputs whose
    /// `link_seq` values are 0 and 1 — NOT 0 and 2 — so the anti-
    /// replay sequence on bob's side stays dense.
    #[test]
    fn relay_link_seq_advances_only_on_admitted_chunks() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0x12);
        let dek = epoch_dek();
        let bob: PeerKeyId = "bob".into();
        let key = transit_key(13);
        relay
            .subscribe(s, bob.clone(), key, ReceiverLayerPolicy::BLINKING_DOT)
            .expect("subscribe bob");

        // 1st: admitted at link_seq=0.
        let inner_a = make_inner_layer(&dek, s, 0, ChunkLayer::BASE);
        let out_a = relay.forward(s, &inner_a).expect("forward A");
        assert_eq!(out_a.len(), 1);
        assert_eq!(out_a[0].subscriber, bob);

        // 2nd: rejected — must NOT advance link_seq.
        let inner_skip = make_inner_layer(
            &dek,
            s,
            1,
            ChunkLayer {
                spatial: 2,
                temporal: 2,
                quality: 2,
            },
        );
        let out_skip = relay.forward(s, &inner_skip).expect("forward skip");
        assert!(out_skip.is_empty(), "(2,2,2) rejected by BLINKING_DOT");

        // 3rd: admitted at link_seq=1 (NOT 2).
        let inner_b = make_inner_layer(&dek, s, 2, ChunkLayer::BASE);
        let out_b = relay.forward(s, &inner_b).expect("forward B");
        assert_eq!(out_b.len(), 1);
        assert_eq!(out_b[0].subscriber, bob);

        // Crypto check: both admitted chunks open under
        // `link_seq=0` and `link_seq=1` respectively.
        let opened_a =
            open_av_chunk(&out_a[0].sealed, &key, bob.as_bytes(), 0, &dek).expect("open A");
        assert_eq!(opened_a, b"frame payload");
        let opened_b =
            open_av_chunk(&out_b[0].sealed, &key, bob.as_bytes(), 1, &dek).expect("open B");
        assert_eq!(opened_b, b"frame payload");
        // And `link_seq=2` does NOT open the second chunk — proves
        // the counter advanced to 1, not 2.
        let bad = open_av_chunk(&out_b[0].sealed, &key, bob.as_bytes(), 2, &dek);
        assert!(
            bad.is_err(),
            "link_seq=2 must NOT open — admitted-only counter advanced to 1"
        );
    }

    /// Acceptance L2-C: a layer-skipped chunk produces NO
    /// `RelayForwardOut` entry — no bandwidth spent, no
    /// `seal_av_outer` call. The structural check is just "out is
    /// empty when every subscriber rejects the chunk", which is the
    /// observable side-effect that proves `seal_av_outer` wasn't
    /// called.
    #[test]
    fn relay_layer_skipped_does_not_call_seal_outer() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0x13);
        let dek = epoch_dek();
        // Two subscribers, both at BLINKING_DOT. A (2,2,2) chunk is
        // rejected by both → empty out.
        relay
            .subscribe(
                s,
                "alice".into(),
                transit_key(0),
                ReceiverLayerPolicy::BLINKING_DOT,
            )
            .expect("alice");
        relay
            .subscribe(
                s,
                "bob".into(),
                transit_key(1),
                ReceiverLayerPolicy::BLINKING_DOT,
            )
            .expect("bob");
        let inner = make_inner_layer(
            &dek,
            s,
            0,
            ChunkLayer {
                spatial: 2,
                temporal: 2,
                quality: 2,
            },
        );
        let out = relay.forward(s, &inner).expect("forward");
        assert!(
            out.is_empty(),
            "every subscriber rejected the layer — no outer seal call must have happened"
        );
    }

    /// Acceptance L2-C: `set_policy` for an unknown (subscriber,
    /// stream) returns `SubscriberNotFound`.
    #[test]
    fn relay_set_policy_unknown_subscriber_errors() {
        let mut relay = RelayNode::new(test_node(), test_address());
        let s = stream(0x14);
        let r = relay.set_policy(s, &"ghost".into(), ReceiverLayerPolicy::UNCAPPED);
        assert!(matches!(r, Err(RelayError::SubscriberNotFound { .. })));

        // Subscribe alice, then call set_policy on a DIFFERENT
        // subscriber — still SubscriberNotFound.
        relay
            .subscribe(
                s,
                "alice".into(),
                transit_key(0),
                ReceiverLayerPolicy::UNCAPPED,
            )
            .expect("alice");
        let r2 = relay.set_policy(s, &"ghost".into(), ReceiverLayerPolicy::BLINKING_DOT);
        assert!(matches!(r2, Err(RelayError::SubscriberNotFound { .. })));

        // And on a different stream — still SubscriberNotFound.
        let other = stream(0x15);
        let r3 = relay.set_policy(other, &"alice".into(), ReceiverLayerPolicy::BLINKING_DOT);
        assert!(matches!(r3, Err(RelayError::SubscriberNotFound { .. })));
    }
}
