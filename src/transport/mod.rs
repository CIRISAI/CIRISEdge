//! Transport abstraction.
//!
//! Mission: carry signed bytes between sovereign peers across the
//! network media that exist in the world. M-1 says "diverse sentient
//! beings may pursue their own flourishing" — diverse includes
//! off-grid, low-bandwidth, unreliable-uplink, adversary-controlled.
//!
//! Reticulum-native by default (canonical wire); HTTP/HTTPS fallback
//! for cloud deployments where Reticulum can't run. Same `Transport`
//! trait shape covers Beechat's reticulum-rs, Lew_Palm's Leviculum
//! (OQ-07 closure: optionality is mission-aligned per PoB §3.2),
//! plus Phase 3 LoRa / serial / I²P transports.
//!
//! See [`MISSION.md`](../../MISSION.md) §2 (`transport/`).

use chrono::{DateTime, Utc};

#[cfg(feature = "transport-http")]
pub mod http;

/// Hybrid X25519 + ML-KEM-768 KEX for federation session-key setup
/// (CIRISEdge#54 — Fed TM §3.3 Gap C closure). Stateless verbs that
/// operate on caller-supplied KEX pubkeys / privkeys; pubkey
/// advertisement + AEAD framing live in the medium-specific transports
/// that consume the derived session key.
pub mod federation_session;

/// N1 cryptographic addressing (`destination = sha256(pubkey)[..16]`)
/// + sliding-window replay protection per peer (CIRISEdge#53). Medium-
/// agnostic primitives consumed by every transport.
pub mod addressing;

/// Realtime A/V mesh profile — direct RNS Link low-latency push with
/// two-layer hybrid-PQC crypto (transit key under epoch DEK) and
/// reachability-driven fan-out (CIRISEdge#62 / CEG 0.13 §10.5.8).
pub mod realtime_av;

/// Realtime A/V session state — membership-change epoch rekey baseline
/// (CIRISEdge#129). Stateful group-key holder with `advance_epoch`
/// driving forward-secrecy rekey on join/leave; unicast O(N) baseline
/// using hybrid X25519+ML-KEM-768 wraps per remaining member.
pub mod realtime_av_session;

/// Realtime A/V — MLS (RFC 9420) group key agreement with the
/// X-Wing post-quantum hybrid ciphersuite 0x004D (CIRISEdge#66).
/// Thin CIRIS-shaped wrapper over openmls 0.8.1's `MlsGroup` +
/// Cryspen's formally-verified libcrux provider. Replaces the
/// discarded clean-room TreeKEM sketch — openmls inherits Draft-11
/// insider fixes, Quarantined-TreeKEM discipline, SUF-CMA Ed25519,
/// and the deployment-policy guidance the clean-room approach would
/// have re-exposed (Wallez/Protzenko/Bhargavan IEEE S&P 2025).
pub mod realtime_av_mls;

/// Realtime A/V relay (SFU role) — addressable forwarding hop for the
/// [`realtime_av`] profile (CIRISEdge#66). Holds per-subscriber transit
/// keys + a per-stream roster; the relay applies the outer AEAD ONCE
/// PER SUBSCRIBER over an inner-sealed chunk produced upstream. The
/// relay never holds the epoch DEK — structurally; see the module head.
/// Gated alongside the rest of the Reticulum surface via the internal
/// `_reticulum-module` grouping feature.
#[cfg(feature = "_reticulum-module")]
pub mod realtime_av_relay;

/// Realtime A/V Layer-2 wire dispatcher (CIRISEdge#155, Gap 1) — the
/// publisher / relay / subscriber wire-driver that takes the Layer-1
/// seal/open primitives ([`realtime_av`]) and drives them across
/// caller-supplied async byte-stream links. Closes the deferred
/// "outbound enqueue onto each subscriber's link" gap that
/// [`realtime_av_relay::RelayNode::forward`] left to Layer 2. Transport-
/// agnostic via the [`realtime_av_dispatcher::AvLinkSender`] /
/// [`realtime_av_dispatcher::AvLinkReceiver`] traits — no leviculum /
/// reticulum-core dependency, so it compiles for HTTP and Reticulum
/// alike and stays ungated.
pub mod realtime_av_dispatcher;

/// Application-Layer Multicast (ALM) — mesh-tree video built on the
/// per-peer [`realtime_av_relay::RelayNode`] primitive (CIRISEdge#131 +
/// CIRISEdge#128 MDC). Pure-Rust, signed [`realtime_av_alm::RelayCapacity`]
/// advertisements + stateless parent-finding planner + multi-parent
/// dedup/heal state machine. Variable-depth MDC sub-stream commitments
/// surface the "holographic" decomposition where any subset of
/// sub-streams decodes at proportional fidelity. No transport-feature
/// gate — the planner is signature-blind and the heal state machine is
/// pure Rust; both compile against the bare federation surface so they
/// stay reusable for HTTPS-only ALM trees.
pub mod realtime_av_alm;

/// Realtime A/V codec wiring — v3.9.0 Layer 1 (CIRISEdge#133). Wraps
/// the production-grade Rust codec stack (raptorq fountain + rav1e /
/// dav1d AV1 + libopus voice) into the substrate's per-symbol /
/// per-chunk shape. Each sub-module gates on its own `codec-*`
/// feature so substrate-only consumers pay zero binary-size cost.
/// The umbrella `codec-default` flips all three on for the realtime
/// A/V wheel build.
#[cfg(any(
    feature = "codec-fountain",
    feature = "codec-av1",
    feature = "codec-opus"
))]
pub mod realtime_av_codec;

/// Packet-radio transport — N2 multi-medium plug (CIRISEdge#53 Fed
/// TM §3.3 Gap D). LoRa / AX.25 / raw-serial mediums plug in via the
/// [`packet_radio::driver::PacketRadioDriver`] trait. Feature-gated
/// since it pulls a CRC dep + tokio's mpsc layer, neither of which the
/// pure-Reticulum / pure-HTTP build needs.
#[cfg(feature = "transport-packet-radio")]
pub mod packet_radio;

/// Announce attestation — the authenticated transport-identity ↔
/// federation-key binding carried in Reticulum announce app-data
/// (CIRISEdge#15 / AV-42). Feature-gated alongside the Reticulum
/// transport, its only consumer.
#[cfg(feature = "_reticulum-module")]
pub mod attestation;

/// Reticulum-native transport (OQ-07 first impl). Backed by Leviculum
/// (`reticulum-core` + `reticulum-std`). Canonical wire per
/// `MISSION.md` §2; HTTP is the documented fallback.
#[cfg(feature = "_reticulum-module")]
pub mod reticulum;

/// §24 NAT-traversal — store-and-forward queue for asleep mobile
/// edges (CIRISEdge#169). CEG-native (Leviculum exposes no LXMF
/// propagation surface); pairs with Reticulum Transport-node mode
/// (#168). Pure-Rust, always compiled.
pub mod store_and_forward;

// Remaining implementations land in subsequent commits; trait shape
// sealed Phase 1.
//
// pub mod lora;       // Phase 3
// pub mod serial;     // Phase 3
// pub mod i2p;        // Phase 3

/// Identifier for a transport instance. Used in metrics tags and
/// structured logs ("which transport carried this message").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TransportId(pub &'static str);

impl TransportId {
    pub const HTTP: Self = Self("http");
    pub const RETICULUM_RS: Self = Self("reticulum-rs");
    pub const LEVICULUM: Self = Self("leviculum");
    pub const LORA: Self = Self("lora");
    pub const SERIAL: Self = Self("serial");
    pub const I2P: Self = Self("i2p");
}

/// Outcome of a transport-level send. Sender-visible; the dispatch
/// loop maps this to outbound-queue state transitions
/// (FSD/EDGE_OUTBOUND_QUEUE.md §4).
#[derive(Debug)]
pub enum TransportSendOutcome {
    /// Transport accepted the bytes. For `Delivery::Durable` with
    /// `!requires_ack`, this is terminal. For `requires_ack=true`,
    /// the row transitions to `awaiting_ack`.
    Delivered,
    /// Receiver returned a typed wire reject. The dispatch loop
    /// inspects `class` to decide retry vs delivered (e.g.
    /// `replay_detected` → mark_replay_resolved → delivered, per
    /// OQ-09 closure).
    Reject { class: String, detail: String },
    /// §24 NAT-traversal (CIRISEdge#169) — the destination was
    /// unreachable and the envelope was accepted into a
    /// store-and-forward queue for later wake-up fetch instead of
    /// being delivered live. Only returned when the caller opted into
    /// [`PendingDelivery::PendingOrLive`] and a queue is wired.
    Queued,
}

/// §24 NAT-traversal (CIRISEdge#169) — per-send delivery discipline.
/// The default is live-only; callers explicitly opt into the
/// store-and-forward fallback.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PendingDelivery {
    /// Live-only: an unreachable destination yields
    /// [`TransportError::Unreachable`]. The pre-#169 behaviour.
    #[default]
    LiveOnly,
    /// Try live first; on an unreachable destination, fall back to the
    /// store-and-forward queue (if one is wired) and return
    /// [`TransportSendOutcome::Queued`].
    PendingOrLive,
}

/// Errors a transport may surface. Edge maps these to typed wire
/// reject codes for `Edge::send`; `Edge::send_durable` translates them
/// to `mark_transport_failed` calls.
#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("destination unreachable: {0}")]
    Unreachable(String),
    #[error("transport timeout after {0:?}")]
    Timeout(std::time::Duration),
    #[error("transport configuration error: {0}")]
    Config(String),
    #[error("transport-level i/o error: {0}")]
    Io(String),
    #[error("envelope too large: {actual} bytes > {limit}")]
    BodyTooLarge { actual: usize, limit: usize },
    /// v0.15.0 (CIRISEdge#33) — peer identity is on the operator-
    /// configured deny-list. The transport refused to dial. `until` is
    /// the optional ban expiry (RFC-3339 UTC); `reason` is the optional
    /// operator-supplied note. The `identity_hash` is the 16-byte
    /// Reticulum identity hash of the blocked peer.
    #[error("peer blackholed: identity_hash={identity_hash:?} reason={reason:?} until={until:?}")]
    PeerBlackholed {
        identity_hash: Vec<u8>,
        reason: Option<String>,
        until: Option<String>,
    },
    /// CIRISEdge#336 — the LINK_REQUEST target has **no route**: the link
    /// request was aimed at a destination the node has no path-table entry
    /// for, and it did not establish within the no-path window (a no-path
    /// dest is broadcast-only and answerable solely by a *directly-attached*
    /// neighbor in a single round-trip — a relay-reachable peer would have a
    /// path; see `NO_PATH_ESTABLISH_TIMEOUT`). This is the transport-routing
    /// sibling of the federation-vs-transport identity split: it fires when a
    /// peer is addressed on its **explicit-hash** dest (`sha256(fed_pubkey)`,
    /// which is un-announceable and therefore un-routable) while it is only
    /// reachable on its **named** dest. The message names every operand needed
    /// to see the mismatch at a glance — the target dest, the peer key_id, and
    /// the paths the node *does* hold — so this failure is never again a
    /// multi-day forensic. Unlike [`Self::Timeout`], this is an
    /// addressing/rooting fault, not a slow link.
    #[error(
        "no route to peer: key_id={key_id} target_dest={target_dest} \
         has_path={has_path} known_paths=[{paths}] (CIRISEdge#336)"
    )]
    NoRouteToPeer {
        /// The federation key_id the send was routed to.
        key_id: String,
        /// The 16-byte Reticulum destination hash the link request targeted,
        /// lowercase hex — the un-routable dest.
        target_dest: String,
        /// Whether the node held a path-table entry for `target_dest` at send
        /// time (always `false` when this error is raised — surfaced so the
        /// log line is self-contained).
        has_path: bool,
        /// A compact snapshot of the node's path table at failure — each
        /// `dest via next_hop hops=N`. The routable **named** dest for this
        /// very peer typically appears here, making the explicit-vs-named
        /// mismatch obvious.
        paths: String,
    },
}

/// One inbound frame from a transport — raw envelope bytes plus the
/// transport-level metadata that survives across the verify pipeline.
#[derive(Debug)]
pub struct InboundFrame {
    pub envelope_bytes: Vec<u8>,
    pub transport: TransportId,
    pub received_at: DateTime<Utc>,
    /// v3.5.1 (CIRISEdge#119) — transport-confirmed source identity
    /// for the inbound frame. `Some(key_id)` when the transport can
    /// vouch for the peer that sent these bytes (Reticulum: the link's
    /// rooted-peer key; HTTPS: mTLS-verified CN or bearer-decoded
    /// identity). `None` when the transport hasn't been wired for
    /// source attribution yet — preserves v3.5.0 behavior.
    ///
    /// Consumed by [`Edge::install_replication_routing`] (CIRISEdge#119)
    /// to gate inbound CRPL frame routing to
    /// `ReplicationRegistry::route_inbound_bytes`: replication
    /// routing fires ONLY when `source_key_id` is `Some` (no peer
    /// attribution → can't safely deliver to a peer-keyed
    /// coordinator). For envelope-tier dispatch the verify pipeline
    /// independently extracts the signer from the envelope bytes —
    /// `source_key_id` is the orthogonal transport-tier hint.
    ///
    /// Transports that don't yet populate this field set `None`;
    /// per-transport attribution lands as separate cuts (Reticulum
    /// link-rooted lookup, HTTPS mTLS surfacing).
    pub source_key_id: Option<String>,
}

/// The trait every transport implements. Edge holds a
/// `Vec<Box<dyn Transport>>`; multiple transports active simultaneously
/// is the multi-medium reach M-1 demands.
#[async_trait::async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Stable identifier for metrics + logs.
    fn id(&self) -> TransportId;

    /// Send the byte-exact signed envelope to the peer addressed by
    /// `destination_key_id`. The transport resolves the address from
    /// the key (Reticulum: `dest = sha256(pubkey)[..16]`; HTTP:
    /// configured per-peer base URL; LoRa: configured radio addr).
    async fn send(
        &self,
        destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError>;

    /// Listen for inbound frames; deliver them to `sink`. Returns when
    /// the listener task exits (graceful shutdown or fatal error).
    async fn listen(
        &self,
        sink: tokio::sync::mpsc::Sender<InboundFrame>,
    ) -> Result<(), TransportError>;
}
