//! §3.1 Poisson emission discipline with substrate-maintenance cover
//! (CIRISEdge#175, v6.1.0).
//!
//! The CEWP `SCOPE_PRIVACY.md` §3.1 GPA-class cover layer: a Poisson
//! scheduler sitting between every `Edge::send_*` entry point and the
//! underlying `Transport::send`. The construction is the Loopix
//! discipline applied at the sender-side emission boundary; the
//! substrate's existing maintenance traffic (anti-entropy, RaptorQ
//! repair, witness chains) is the cover budget per FSD §2.6.
//!
//! # Properties (FSD §3.1)
//!
//! 1. **Fixed envelope size — `ENVELOPE_BYTES = 1400`** (one MTU,
//!    matching the §2.4 RaptorQ symbol). Larger payloads chunk via
//!    [`fragment`]'s fragmentation/reassembly primitive (sequence
//!    numbers + reassembly window + dedup-on-receive + drop-on-
//!    window-expiry).
//! 2. **Uniform XChaCha20-Poly1305 AEAD framing** for both real and
//!    synthetic cover envelopes via verify v6.3.0's `xchacha::{seal,
//!    open}`. Wire observers see indistinguishable bytes.
//! 3. **Per-scope `Exp(λ_scope)` timers per peer**, sampled from a
//!    peer-local CSPRNG seeded at process start (`ChaCha20Rng` —
//!    NEVER derived from public snapshot inputs, FSD §3.1 jitter
//!    rule).
//! 4. **On timer fire** the scheduler pops the next real envelope at
//!    that scope; if the queue is empty it emits a synthetic cover
//!    envelope marked `type=cover` in the AEAD-protected header.
//! 5. **Lifetime-average λ inequality** per scope across the
//!    measurement window — under-budget windows emit cover; over-
//!    budget windows back-pressure into the next interval (the
//!    [`BudgetMeter`]).
//!
//! # Module layout
//!
//! - [`envelope`] — the 1.4 KB fixed-size frame, the AEAD-protected
//!   header (`type`, scope, fragmentation indices), the seal/open
//!   round-trip.
//! - [`fragment`] — chunking + reassembly for payloads larger than
//!   one envelope.
//! - [`poisson`] — Poisson timer (`Exp(λ_scope)` sampling) per scope,
//!   CSPRNG-driven; the `next_interval()` primitive.
//! - [`budget`] — the §3.1 lifetime-average λ inequality book-keeper.
//! - [`scheduler`] — the runtime that wires queues + Poisson timers +
//!   budget meter + transport-side `send`.
//!
//! # Retrofit boundary
//!
//! v6.1.0 ships the primitive + scheduler. The enumerated emission
//! paths (FSD §6.1 — `ReplicationCoordinator`, `Edge::send_*`,
//! `outbound`, `realtime_av_dispatcher`, `realtime_av_alm`,
//! `blob_swarm`, MDC sub-streams) gain the scheduler at the boundary
//! incrementally; the scheduler exposes [`scheduler::Scheduler::submit`]
//! so each path threads through it without changing its internal
//! shape. Tests cover the boundary contract (KS-test on inter-emission
//! intervals; cover-envelope flow when queue empty); the retrofit
//! itself is mechanical wire-up tracked under CIRISEdge#175.

pub mod budget;
pub mod envelope;
pub mod fragment;
pub mod poisson;
pub mod scheduler;

pub use budget::{BudgetMeter, BudgetState};
pub use envelope::{
    seal_envelope, unseal_envelope, EmissionEnvelope, EmissionEnvelopeError, EmissionHeader,
    EnvelopeType, ENVELOPE_BYTES, HEADER_BYTES, MAX_PAYLOAD_BYTES,
};
pub use fragment::{
    fragment_payload, FragmentError, FragmentSet, Reassembler, ReassemblyOutcome,
    REASSEMBLY_WINDOW_MS,
};
pub use poisson::{PoissonScheduler, ScopeKey};
pub use scheduler::{Scheduler, SchedulerConfig, SchedulerHandle, SchedulerStats, SubmitError};
