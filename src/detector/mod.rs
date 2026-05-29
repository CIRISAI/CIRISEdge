//! Edge-side detectors that emit typed `edge_detection_event` rows for
//! downstream lens-core joint correlation (CIRISEdge#39).
//!
//! Per RATCHET's `Counter-RII detection / Per-layer signal spec / Edge
//! layer`:
//!
//! > Edge observes inbound probe-pattern signatures at the transport
//! > layer — message-shape clustering, rate anomalies, timing
//! > distributions. Emits typed `edge_detection_event` rows tagged
//! > with `signing_key_id` + observation window for downstream joint
//! > correlation.
//!
//! # Modules
//!
//! - [`probe_pattern_observer`] — per-signing-key-id rolling-window
//!   counters that detect probe-shaped traffic patterns.
//!
//! # Consent-role gating (load-bearing)
//!
//! Per RATCHET's `formal/RATCHET/Core/ConsentGate.lean` F-CR-3 invariant,
//! no edge detector ever emits for the following consent roles:
//!
//! - `SelfConscience` — the agent's own internal probes
//! - `AuthorizedReview` — review-mode traffic
//! - `AuthorizedResearch` — research-mode traffic
//! - `Peer` — peer-to-peer ordinary federation traffic
//!
//! Detection emission gates ONLY for `UnconsentedExternal`. Unknown /
//! unrecognized signing-keys default to `UnconsentedExternal`
//! (fail-closed for the federation, fail-open for the privacy
//! posture — the operator opt-in below covers the latter).
//!
//! # Configuration discipline
//!
//! The whole module is **opt-in per deployment** via
//! [`crate::EdgeConfig::probe_pattern_observer_enabled`]
//! (default `false`). When disabled, `Edge::detector` is `None` and the
//! `dispatch_inbound` hook is a single Option-is-None branch.
//!
//! # Persistence
//!
//! The verdict struct mirrors persist's `EdgeDetectionEvent` row shape
//! (CIRISPersist V020 / `cirislens.edge_detection_events`). v0.17.0
//! flips `emit_verdict` from a `tracing::warn!` STUB to a real
//! `put_edge_detection_event` admission call on the object-safe
//! [`EdgeDetectionAdmission`] wrapper, now that CIRISPersist v3.1.1
//! (#118) ships the write-side API on `DerivedSchema`. Deployments
//! that don't supply the admission handle (e.g. unit tests) fall back
//! to the v0.13.0 `tracing::warn!` log path.

pub mod probe_pattern_observer;

pub use probe_pattern_observer::{
    ConsentRole, DetectionVerdict, EdgeDetectionAdmission, ProbePatternConfig,
    ProbePatternObserver, ProbePatternState,
};
