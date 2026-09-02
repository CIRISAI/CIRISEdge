//! CEG-native federation replication transport.
//!
//! Closes the transport half of CIRISRegistry#58 ("Spock removal"
//! epic) and unblocks CIRISRegistry#62 (all-3-siblings CEG/RET-native).
//! Tracking issue: CIRISEdge#65.
//!
//! ## The shape of the problem
//!
//! CIRIS federation today moves point-to-point signed envelopes
//! synchronously: a write in region A reaches region B only when a
//! peer in A explicitly sends to a peer in B. Cross-region convergence
//! (every region eventually sees every other region's writes) was
//! Spock's job in the v1 architecture; CIRISRegistry#58 retires Spock
//! by making convergence **CEG-native** — every state change is a
//! signed CEG envelope that any pair of peers can replicate via
//! periodic anti-entropy gossip.
//!
//! The merge side lives in Persist (R1/Q1 quorum-merge with anti-
//! rollback — CIRISPersist V058 / `federation_revocation_quorum_state`).
//! Edge owns the **propagation** half: pairwise anti-entropy rounds
//! that exchange "what envelopes do you have?" summaries, compute the
//! diff, and stream the missing envelopes. Persist applies via the
//! existing `put_*` admit surfaces; R1/Q1 dedupes and rejects rollbacks.
//!
//! ## Layering
//!
//! ```text
//!   ┌──────────────────────────────────────────────────────────────┐
//!   │  Consumers (lens / agent / bridge / node-core)               │
//!   │  Subscribe to bounded-staleness telemetry via                │
//!   │  replication::StalenessSignal for τ_partial machinery        │
//!   │  (CIRISVerify#48/#49)                                        │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  replication::Session — pairwise anti-entropy state machine  │
//!   │  (this module)                                               │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  replication::protocol — Summary / Diff / Fetch / Deliver    │
//!   │  message types (wire-stable; serde)                          │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  crate::transport::Transport (any medium — HTTP, Reticulum,  │
//!   │  packet-radio) carries the protocol messages                 │
//!   ├──────────────────────────────────────────────────────────────┤
//!   │  ciris_persist::FederationDirectory — reads local state,     │
//!   │  applies received envelopes via existing put_* admits        │
//!   └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## What this PR ships
//!
//! - [`protocol`] — message types + wire codec + tests
//! - [`summary`] — local-state-to-summary computation (envelope-hash
//!   sets per envelope kind) + diff logic
//! - [`session`] — pairwise anti-entropy state machine, in-memory,
//!   deterministic, exhaustively tested against bidirectional sync
//!   scenarios (full diff, partial overlap, idempotent re-runs,
//!   bounded-staleness signal)
//!
//! ## What's NOT in this PR (well-scoped follow-ups)
//!
//! - **Transport binding** — gluing the state machine to a live
//!   [`crate::transport::Transport`] instance + scheduler. The protocol
//!   primitives in this PR are wire-bytes-in / wire-bytes-out so a
//!   follow-up can drop them onto HTTP / Reticulum / packet-radio
//!   with no protocol-side changes.
//! - **Persist adapter** — concrete [`StateProvider`] / [`StateApplier`]
//!   impls over `FederationDirectory` (this module defines the trait
//!   shape + provides an in-memory test impl).
//! - **Cross-region peer-set discovery** — which peers to anti-entropy
//!   with, on what cadence. Operator-config-driven; not a protocol
//!   concern.
//! - **Operational telemetry beyond `StalenessSignal`** — metrics
//!   counters for round counts, bytes transferred, diff sizes are
//!   surfaced via `tracing` spans the binding PR will wire to a
//!   metric backend.
//!
//! ## NAT traversal
//!
//! Edge does **not** implement STUN / TURN / ICE — and shouldn't.
//!
//! Reticulum (the canonical wire per MISSION §1.4) routes by
//! **cryptographic destination address** (`sha256(pubkey)[..16]`,
//! the same shape this crate's `transport::addressing` builds for
//! the packet-radio plug). Transit nodes carry packets by
//! destination-hash without decrypt capability — the relay can't
//! read what it's carrying, can't even tell which CEG namespace
//! it's in. As long as a NAT'd peer's announce graph reaches *any*
//! publicly-reachable transport node, mesh routing carries packets
//! both ways without endpoint-translation gymnastics.
//!
//! The federation topology itself supplies that public-side peer
//! set, by construction:
//!
//! - **Registry servers** — substrate of the federation; public by
//!   definition (CEG 0.15 §0.4, registry-anchored normative refs).
//! - **CIRISLens (LensCore → edge)** — public observability surface
//!   per the lens-opt-in model. The opt-in dimension is at the
//!   policy layer (does lens get to see this peer's CEG envelopes
//!   for telemetry?); the transit layer (Reticulum relay through
//!   lens's edge instance) is orthogonal — lens can relay packets
//!   it can't read.
//! - **Agent 2.9.6 (CEG/RET-native)** — community-server-opt-in
//!   instances on public IPs join the transport graph for free.
//!   Mobile agents behind NAT inherit the same benefit they give
//!   to other NAT'd peers.
//! - **Any other CEG 0.15 community peer with a public interface.**
//!
//! Practical implication: the only operator-doc bit is "your peer
//! set should include at least one publicly-reachable CIRIS peer"
//! — which is *automatically* satisfied if the operator points at
//! the registry / lens / public-agent set at all.
//!
//! **HTTP transport** stays the one exception: its accept-side
//! still needs port-forward / reverse-proxy to be reachable from
//! outside the NAT. That's operator config (Cloudflare Tunnel,
//! nginx reverse proxy, etc.), not edge code. Operators behind
//! hard NATs should use Reticulum, which is what MISSION §1.4
//! designates canonical anyway.

pub mod accord_relay_gate;
pub mod attestation_bind;
pub mod bridge;
pub mod convergence;
pub mod coordinator;
pub mod directory;
/// CIRISEdge#552 — hashes known to exist whose bodies this node does not
/// hold. NEVER holdings; see the module docs for why that distinction is the
/// whole safety of the design.
pub mod known_hashes;
pub mod mesh_config;
/// CIRISEdge#552 — which Key an unverifiable signature was missing, so it can
/// be pulled. `Key` is the root of every admission's dependency closure.
pub mod missing_signer;
pub mod protocol;
pub mod refusal_backoff;
pub mod registry;
pub mod resolved_state;
/// CIRISEdge#552/#553 — how much of a plane this node keeps, and the
/// revocation carve-out a configured retention cannot reach.
pub mod retention;
pub mod runtime;
pub mod scheduler;
pub mod serve_policy;
pub mod serve_tier;
pub mod session;
#[cfg(test)]
mod sim;
pub mod storage_contention;
pub mod summary;
pub mod wire_frame;

/// What [`InboundRouter::try_route`] did with a frame.
///
/// A typed answer rather than a `bool`, because the four cases are the field
/// diagnosis for "replication is not converging" and an operator that cannot
/// tell them apart is debugging blind — which is exactly how edge's own
/// harness spent six mesh runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDisposition {
    /// Consumed as a replication frame. Do not process it further.
    Routed,
    /// Not a replication frame at all — it is yours to handle.
    NotReplication,
    /// A replication frame on a link with NO usable peer identity, and not a
    /// self-authenticating bootstrap kind. Dropped.
    ///
    /// A steady stream of these means the link never got attributed. Check that
    /// `Key` and `IdentityOccurrence` are among the planes you replicate — an
    /// advisory link is promoted by anti-entropying exactly those two, and
    /// without them nothing else will ever flow.
    Unattributed,
    /// The registry refused the frame. Consumed; the reason is yours to log.
    Failed(String),
}

impl RouteDisposition {
    /// Did replication take ownership of this frame?
    #[must_use]
    pub fn consumed(&self) -> bool {
        !matches!(self, RouteDisposition::NotReplication)
    }
}

/// **Inbound replication routing, with every footgun already disarmed.**
///
/// `Transport::listen` runs in the application's own dispatch loop, so wiring
/// replication into it is the operator's job. That wiring has a non-obvious
/// half, and edge's own bench-mesh harness got it wrong in the obvious way:
/// route when `source_key_id` is `Some`, drop otherwise. The harness then sat
/// at ZERO replication for six mesh runs — ~75 frames per node arriving and
/// being discarded — with no error anywhere, because a dropped frame looks
/// exactly like a frame that never came.
///
/// So this type exists to be the whole wiring:
///
/// ```ignore
/// let router = InboundRouter::new(runtime.registry());
/// while let Some(frame) = rx.recv().await {
///     if router.try_route(&frame).await.consumed() {
///         continue;                 // replication owns it
///     }
///     // ... your own framing
/// }
/// ```
///
/// # What it disarms
///
/// **The bootstrap deadlock.** A peer first heard by announce is admitted
/// *advisory* (`owns_key = false`), and is promoted only by anti-entropying
/// that peer's `Key` (transport binding) and `IdentityOccurrence` (KEX
/// enc-keys) planes OVER THAT SAME LINK. Demanding attribution before routing
/// therefore deadlocks: the exchange that earns attribution is the exchange
/// attribution is required for. `try_route` applies the CIRISEdge#402 carve-out
/// — an un-attributed frame is routed under the link's advisory `link_key_id`,
/// but ONLY for a self-authenticating bootstrap kind, which persist verifies at
/// admission and which can never satisfy the trace-serve gate (that requires
/// `from_rooted_binding`). Every other kind on an un-attributed link is
/// dropped, exactly as a hand-written version would.
///
/// # What it cannot do for you
///
/// Two things still have to be right in YOUR configuration, and both were also
/// wrong in that harness:
///
/// 1. **Replicate `Key` and `IdentityOccurrence`.** Without them an advisory
///    link is never promoted, so no other plane ever flows. See
///    [`EnvelopeKind::BOOTSTRAP_PLANES`].
/// 2. **Author a directed `consent:replication:v1` grant per peer.** The
///    Attestation plane is consent-gated at the RECIPIENT: a peer that does not
///    resolve withholds the WHOLE plane, fail-closed, before any per-row
///    question. See
///    [`replication_consent_attestation`](crate::replication::attestation_bind::replication_consent_attestation).
#[derive(Clone)]
pub struct InboundRouter {
    registry: std::sync::Arc<ReplicationRegistry>,
}

impl InboundRouter {
    #[must_use]
    pub fn new(registry: std::sync::Arc<ReplicationRegistry>) -> Self {
        Self { registry }
    }

    /// Route `frame` if it is a replication frame. See the type docs.
    pub async fn try_route(&self, frame: &crate::transport::InboundFrame) -> RouteDisposition {
        // Cheap reject first: a frame that is not CRPL at all is the common
        // case in an application's dispatch loop, and must not cost an
        // attribution lookup.
        match wire_frame::try_unwrap(&frame.envelope_bytes) {
            Ok(Some(_)) => {}
            Ok(None) => return RouteDisposition::NotReplication,
            Err(e) => return RouteDisposition::Failed(format!("malformed CRPL frame: {e}")),
        }
        let Some(peer) = routing_source(frame) else {
            return RouteDisposition::Unattributed;
        };
        match self
            .registry
            .route_inbound_bytes(&peer, &frame.envelope_bytes)
            .await
        {
            Ok(RouteOutcome::NotAReplicationFrame) => RouteDisposition::NotReplication,
            Ok(_) => RouteDisposition::Routed,
            Err(e) => RouteDisposition::Failed(e.to_string()),
        }
    }
}

/// **The peer id to route an inbound frame under — the whole answer, one call.**
///
/// Edge's `Transport::listen` runs in the application's own dispatch loop, and
/// the module docs ask the operator for "a one-line addition" wiring
/// [`ReplicationRegistry::route_inbound_bytes`] into it. That line needs a
/// peer_key_id, and getting it right is the part the docs do not spell out:
///
/// * `source_key_id` is the E3-attributed identity (`Rooted ∧ owns_key`). When
///   present, use it.
/// * When it is ABSENT the frame is not necessarily junk. A peer first heard by
///   announce is admitted **advisory** (`owns_key = false`), and it can only be
///   promoted by anti-entropying that peer's `Key` (transport binding) and
///   `IdentityOccurrence` (KEX enc-keys) planes OVER THAT SAME LINK. Dropping
///   un-attributed frames therefore deadlocks the bootstrap: the exchange that
///   would earn attribution is the exchange attribution is demanded for.
///
/// So an un-attributed frame is routed under the link's advisory
/// `link_key_id` — but ONLY for a self-authenticating
/// [bootstrap kind](EnvelopeKind::is_bootstrap) (`Key` / `IdentityOccurrence`),
/// which persist verifies at admission and which can never satisfy the
/// trace-serve gate (that requires `from_rooted_binding`). Every other kind on
/// an un-attributed link returns `None` and is dropped, exactly as before.
///
/// # Why this is public
///
/// It was private to `Edge`'s dispatch loop, so an operator wiring their own
/// listener — as edge's own bench-mesh harness does — wrote the obvious version
/// instead: route when `source_key_id` is `Some`, drop otherwise. That harness
/// then sat at zero replication for six mesh runs, with ~75 frames per node
/// arriving and being discarded unattributed, and no error anywhere. The
/// non-obvious half of the contract should not have been behind a private fn.
///
/// ```ignore
/// // In your Transport::listen loop:
/// if let Some(peer) = replication::routing_source(&frame) {
///     registry.route_inbound_bytes(&peer, &frame.envelope_bytes).await?;
/// }
/// ```
#[must_use]
pub fn routing_source(frame: &crate::transport::InboundFrame) -> Option<String> {
    if let Some(attributed) = frame.source_key_id.as_ref() {
        return Some(attributed.as_str().to_owned());
    }
    // The bootstrap carve-out (CIRISEdge#402).
    let link_key_id = frame.link_key_id.as_deref()?;
    let msg = wire_frame::try_unwrap(&frame.envelope_bytes)
        .ok()
        .flatten()?;
    if !msg.kind().is_bootstrap() {
        return None;
    }
    Some(crate::transport::SourceKeyId::transport_authenticated(link_key_id).into_string())
}

#[doc(inline)]
pub use accord_relay_gate::{
    AccordRelayGate, RelayDecision, RelayRefusal, RELAY_VERDICT_TTL as ACCORD_RELAY_VERDICT_TTL,
};
#[doc(inline)]
pub use bridge::{
    ApplyRefusalClass, BridgeConfig, CohortProvider, FederationDirectoryReplicationBridge,
    KeyDirectoryProvider, OperationalProviders, RootStewardsProvider, StewardRosterProvider,
};
#[doc(inline)]
pub use coordinator::{CoordinatorError, DriveStep, ReplicationCoordinator, RoundReport};
#[doc(inline)]
pub use directory::{DirectoryStateAdapter, MutableDirectoryStateAdapter, ReplicationDirectory};
#[doc(inline)]
pub use mesh_config::{MeshConfigReader, MeshConfigRelief, DEFAULT_RELIEF_TTL};
#[doc(inline)]
pub use protocol::{
    DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, FetchMessage, ReplicationMessage,
    SummaryMessage,
};

#[doc(inline)]
pub use refusal_backoff::{RefusalBackoff, RetryDisposition};

pub use registry::{RegistryError, ReplicationRegistry, RouteOutcome};
#[doc(inline)]
pub use runtime::{ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig};
#[doc(inline)]
pub use scheduler::{ReplicationScheduler, RoundEvent, SchedulerConfig};
#[doc(inline)]
pub use session::{ReplicationOutcome, Session, SessionRole};
#[doc(inline)]
pub use summary::{ApplyOutcome, LocalState, StalenessSignal, StateApplier, StateProvider};
#[doc(inline)]
pub use wire_frame::{
    try_unwrap as try_unwrap_replication_frame, wrap as wrap_replication_frame,
    wrap_for_kind as wrap_replication_frame_for_kind, REPLICATION_FRAME_MAGIC,
    WIRE_PROTOCOL_VERSION, WIRE_PROTOCOL_VERSION_V2,
};
