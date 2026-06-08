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

pub mod coordinator;
pub mod directory;
pub mod protocol;
pub mod session;
pub mod summary;

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
pub use session::{ReplicationOutcome, Session, SessionRole};
#[doc(inline)]
pub use summary::{LocalState, StalenessSignal, StateApplier, StateProvider};
