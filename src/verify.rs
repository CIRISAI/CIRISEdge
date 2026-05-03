//! Verify pipeline.
//!
//! Mission: ensure no application code touches a byte that hasn't been
//! verified against persist's federation directory. Verify is a
//! precondition for handler dispatch, not an opt-in.
//! ([`MISSION.md`](../../MISSION.md) §2 `verify/`.)
//!
//! # The seven steps (FSD §3.3)
//!
//! 1. Transport delivers raw bytes + transport metadata.
//! 2. Edge parses the wire envelope (typed [`crate::EdgeEnvelope`] via serde).
//! 3. Edge extracts `(signing_key_id, signature, signature_pqc, canonical_bytes)`.
//! 4. Edge calls `persist::Engine.verify_hybrid_via_directory` — this
//!    folds `lookup_public_key` + Ed25519 + ML-DSA-65 verify + policy
//!    evaluation into one call (CIRISPersist v0.4.0 surface).
//!    Outcomes mapping to wire rejects:
//!    - `unknown_signing_key` → `unknown_key`
//!    - signature mismatch    → `signature_mismatch`
//!    - hybrid-pending under strict policy → `pqc_pending_strict_reject`
//! 5. Edge checks `destination_key_id == self.steward_key_id`
//!    (AV-8); mismatch → `misrouted`.
//! 6. Edge checks `(signing_key_id, nonce)` against the replay window
//!    (AV-3); hit → `replay_detected`.
//! 7. Edge dispatches to the registered handler with the parsed body.
//!
//! Step 4 is the AV-9 P0 invariant: handler dispatch is structurally
//! gated on this returning a success outcome.

use serde::{Deserialize, Serialize};

use crate::messages::EdgeEnvelope;
use crate::transport::TransportId;

/// Consumer-side acceptance policy for hybrid-pending federation_keys
/// rows (OQ-11 closure). Selected per peer at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridPolicy {
    /// Reject any envelope whose sender's `federation_keys` row is
    /// hybrid-pending. Highest assurance; slowest path.
    Strict,
    /// Accept hybrid-pending rows within a freshness window; reject
    /// older ones. The window value is the `soft_freshness_window`
    /// argument passed to `verify_hybrid_via_directory`.
    SoftFreshness { window_seconds: u64 },
    /// Accept Ed25519-only verification. Lowest-assurance default for
    /// environments where PQC reach is incomplete.
    Ed25519Fallback,
}

/// What `verify_hybrid_via_directory` reported. Mirror of persist's
/// `VerifyOutcome` enum (CIRISPersist v0.4.0 verify surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyOutcome {
    /// Both Ed25519 and ML-DSA-65 signatures verified; sender's row
    /// is hybrid-complete.
    HybridVerified,
    /// Ed25519 verified; sender's row is hybrid-pending (PQC kickoff
    /// still in flight). Accepted because policy was
    /// `SoftFreshness` and `row_age < window`.
    Ed25519VerifiedHybridPending { row_age_seconds: f64 },
    /// Ed25519 verified; consumer policy was `Ed25519Fallback`.
    Ed25519VerifiedFallback,
}

/// Verify-pipeline errors. Each maps to a typed wire reject code
/// returned to the sender — no silent drops (MISSION.md §3
/// anti-pattern 6).
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("unknown signing key: {0}")]
    UnknownKey(String),
    #[error("signature verification failed")]
    SignatureMismatch,
    #[error("hybrid-pending under strict policy")]
    PqcPendingStrictReject,
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),
    #[error("misrouted: destination_key_id mismatch")]
    Misrouted,
    #[error("replay detected within window")]
    ReplayDetected,
    #[error("unsupported schema version: {0:?}")]
    UnsupportedSchemaVersion(String),
    #[error("body too large: {actual} > {limit}")]
    BodyTooLarge { actual: usize, limit: usize },
    #[error("verify substrate unavailable: {0}")]
    VerifyUnavailable(String),
}

/// A successfully-verified envelope. The only way to construct one is
/// through [`VerifyPipeline::verify`] — handlers never see anything
/// else (AV-9 structural gate).
#[derive(Debug)]
pub struct VerifiedEnvelope {
    pub envelope: EdgeEnvelope,
    pub body_sha256: [u8; 32],
    pub verify_outcome: VerifyOutcome,
    pub transport: TransportId,
}

/// The verify pipeline itself. Holds the persist engine handle, the
/// configured hybrid policy, and the replay window state.
pub struct VerifyPipeline {
    // engine: ciris_persist::Engine,   // wired in next commit
    // policy: HybridPolicy,
    // replay_window: ReplayWindow,
    // self_steward_key_id: String,
    // max_body_bytes: usize,
}

impl VerifyPipeline {
    /// Run the seven-step verify pipeline against an inbound frame's
    /// envelope bytes. Returns `VerifiedEnvelope` on success — the
    /// only artifact handlers ever observe.
    pub async fn verify(
        &self,
        _envelope_bytes: &[u8],
        _transport: TransportId,
    ) -> Result<VerifiedEnvelope, VerifyError> {
        todo!(
            "FSD §3.3 seven steps; calls Engine.verify_hybrid_via_directory; \
             body-size cap (AV-13) at step 1; typed deserialize (AV-14) at step 2; \
             replay window (AV-3) at step 6"
        )
    }
}
