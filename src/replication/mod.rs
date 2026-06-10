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

pub mod bridge;
pub mod coordinator;
pub mod directory;
pub mod protocol;
pub mod registry;
pub mod runtime;
pub mod scheduler;
pub mod session;
pub mod summary;
pub mod wire_frame;

#[doc(inline)]
pub use bridge::{BridgeConfig, CohortProvider, FederationDirectoryReplicationBridge};
#[doc(inline)]
pub use coordinator::{CoordinatorError, DriveStep, ReplicationCoordinator, RoundReport};
#[doc(inline)]
pub use directory::{DirectoryStateAdapter, MutableDirectoryStateAdapter, ReplicationDirectory};
#[doc(inline)]
pub use protocol::{
    DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, FetchMessage, ReplicationMessage,
    SummaryMessage,
};
#[doc(inline)]
pub use registry::{RegistryError, ReplicationRegistry, RouteOutcome};
#[doc(inline)]
pub use runtime::{ReplicationPeer, ReplicationRuntime, ReplicationRuntimeConfig};
#[doc(inline)]
pub use scheduler::{ReplicationScheduler, RoundEvent, SchedulerConfig};
#[doc(inline)]
pub use session::{ReplicationOutcome, Session, SessionRole};
#[doc(inline)]
pub use summary::{LocalState, StalenessSignal, StateApplier, StateProvider};
#[doc(inline)]
pub use wire_frame::{
    try_unwrap as try_unwrap_replication_frame, wrap as wrap_replication_frame,
    REPLICATION_FRAME_MAGIC,
};
