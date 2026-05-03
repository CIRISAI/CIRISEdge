//! Verify pipeline.
//!
//! Mission: ensure no application code touches a byte that hasn't been
//! verified against persist's federation directory. Verify is a
//! precondition for handler dispatch, not an opt-in.
//! ([`MISSION.md`](../../MISSION.md) §2 `verify/`.)
//!
//! # The seven steps (FSD §3.3, cost-asymmetric ordering)
//!
//! 1. Body size cap (AV-13).
//! 2. Typed envelope deserialize (AV-14; `MAX_DATA_DEPTH=32`).
//! 3. Schema-version allowlist (AV-7).
//! 4. Destination key check — `envelope.destination_key_id ==
//!    self.steward_key_id` (AV-8).
//! 5. Replay window — `(signing_key_id, nonce)` LRU (AV-3).
//! 6. Canonicalize-for-signing — calls
//!    `ciris_persist::prelude::canonicalize_envelope_for_signing`
//!    (CIRISPersist#7 single-source-of-truth; v0.4.1 surface).
//! 7. Hybrid verify via directory — calls
//!    `ciris_persist::prelude::verify_hybrid_via_directory`
//!    (AV-1 + AV-9 + AV-39 P0 invariant).
//!
//! Cheap rejects come first (AV-13/14/7/8/3 are constant-time / in-
//! memory) so adversaries pay verify-cost only on messages that
//! survive cheap checks. Step 7 is the only step that hits the network
//! (federation directory lookup).

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use ciris_persist::prelude::{
    body_sha256 as persist_body_sha256, canonicalize_envelope_for_signing,
    verify_hybrid_via_directory as persist_verify_hybrid_via_directory, FederationDirectory,
    HybridVerifyError,
};
pub use ciris_persist::prelude::{HybridPolicy, VerifyOutcome};

use crate::messages::{EdgeEnvelope, SchemaVersion};
use crate::transport::TransportId;

/// Adapter trait that erases `FederationDirectory`'s generics so edge
/// can hold an `Arc<dyn VerifyDirectory>` — `FederationDirectory`
/// itself uses `impl Future` returns (RPIT in trait) which makes it
/// non-dyn-compatible. Blanket-implemented for any
/// `FederationDirectory`, so hosts can pass `Arc::new(MemoryBackend)`
/// or `Arc::new(PostgresBackend)` without picking edge's generics.
#[async_trait]
pub trait VerifyDirectory: Send + Sync + 'static {
    async fn verify_hybrid_via_directory(
        &self,
        canonical_bytes: &[u8],
        signing_key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: Option<&str>,
        policy: HybridPolicy,
        row_age: Option<StdDuration>,
    ) -> Result<VerifyOutcome, HybridVerifyError>;
}

#[async_trait]
impl<F: FederationDirectory + Send + Sync + 'static> VerifyDirectory for F {
    async fn verify_hybrid_via_directory(
        &self,
        canonical_bytes: &[u8],
        signing_key_id: &str,
        ed25519_sig_b64: &str,
        ml_dsa_65_sig_b64: Option<&str>,
        policy: HybridPolicy,
        row_age: Option<StdDuration>,
    ) -> Result<VerifyOutcome, HybridVerifyError> {
        persist_verify_hybrid_via_directory(
            self,
            canonical_bytes,
            signing_key_id,
            ed25519_sig_b64,
            ml_dsa_65_sig_b64,
            policy,
            row_age,
        )
        .await
    }
}

/// Verify-pipeline errors. Each maps to a typed wire reject code
/// returned to the sender — no silent drops (MISSION.md §3 anti-
/// pattern 6).
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    /// Step 1 — body exceeded `max_body_bytes` (AV-13).
    #[error("body too large: {actual} > {limit}")]
    BodyTooLarge { actual: usize, limit: usize },
    /// Step 2 — envelope JSON parse / typed deserialize failure (AV-14).
    #[error("schema invalid: {0}")]
    SchemaInvalid(String),
    /// Step 3 — `edge_schema_version` not in the allowlist (AV-7).
    #[error("unsupported schema version: {0}")]
    UnsupportedSchemaVersion(String),
    /// Step 4 — envelope addressed to a different peer (AV-8).
    #[error("misrouted: destination_key_id mismatch")]
    Misrouted,
    /// Step 5 — `(signing_key_id, nonce)` already seen within the
    /// replay window (AV-3).
    #[error("replay detected within window")]
    ReplayDetected,
    /// Step 6/7 — sender's `signing_key_id` not registered in the
    /// federation directory (AV-1).
    #[error("unknown signing key: {0}")]
    UnknownKey(String),
    /// Step 7 — Ed25519 / hybrid signature did not verify.
    #[error("signature verification failed: {0}")]
    SignatureMismatch(String),
    /// Step 7 — sender's `federation_keys` row is hybrid-pending and
    /// our consumer policy is `Strict`.
    #[error("hybrid-pending under strict policy")]
    PqcPendingStrictReject,
    /// Step 6 — canonicalization round-trip failed (envelope shape
    /// rejected by persist's canonicalizer).
    #[error("canonicalization failed: {0}")]
    CanonicalizationFailed(String),
    /// Step 7 — federation directory unavailable (substrate fault).
    #[error("verify substrate unavailable: {0}")]
    VerifyUnavailable(String),
}

/// A successfully-verified envelope. The only way to construct one is
/// through [`VerifyPipeline::verify`] — handlers never see anything
/// else (AV-9 structural gate).
#[derive(Debug)]
pub struct VerifiedEnvelope {
    pub envelope: EdgeEnvelope,
    /// 32-byte forensic join key. Computed via
    /// `ciris_persist::prelude::body_sha256` so it matches persist's
    /// indexing convention exactly (single-source-of-truth).
    pub body_sha256: [u8; 32],
    pub verify_outcome: VerifyOutcome,
    pub transport: TransportId,
}

/// The verify pipeline. Holds the federation directory handle, the
/// configured hybrid policy, the self-steward key (for AV-8), and the
/// replay window state.
pub struct VerifyPipeline {
    directory: Arc<dyn VerifyDirectory>,
    policy: HybridPolicy,
    self_steward_key_id: String,
    max_body_bytes: usize,
    replay_window: Mutex<ReplayWindow>,
}

impl VerifyPipeline {
    /// Construct. `replay_window_seconds` defaults to 5min per OQ-08;
    /// `max_replay_entries` defaults to 100k per AV-12.
    pub fn new(
        directory: Arc<dyn VerifyDirectory>,
        policy: HybridPolicy,
        self_steward_key_id: String,
        max_body_bytes: usize,
        replay_window_seconds: u64,
        max_replay_entries: usize,
    ) -> Self {
        Self {
            directory,
            policy,
            self_steward_key_id,
            max_body_bytes,
            replay_window: Mutex::new(ReplayWindow::new(replay_window_seconds, max_replay_entries)),
        }
    }

    /// Run the seven-step verify pipeline against an inbound frame's
    /// envelope bytes. Returns `VerifiedEnvelope` on success — the
    /// only artifact handlers ever observe.
    pub async fn verify(
        &self,
        envelope_bytes: &[u8],
        transport: TransportId,
    ) -> Result<VerifiedEnvelope, VerifyError> {
        // Step 1 — body size cap (AV-13).
        if envelope_bytes.len() > self.max_body_bytes {
            return Err(VerifyError::BodyTooLarge {
                actual: envelope_bytes.len(),
                limit: self.max_body_bytes,
            });
        }

        // Step 2 — typed envelope deserialize (AV-14).
        let envelope: EdgeEnvelope = serde_json::from_slice(envelope_bytes)
            .map_err(|e| VerifyError::SchemaInvalid(format!("envelope parse: {e}")))?;

        // Step 3 — schema-version allowlist (AV-7). Exhaustive match
        // means a future variant rejects at compile time until we
        // explicitly handle it.
        match envelope.edge_schema_version {
            SchemaVersion::V1_0_0 => {}
        }

        // Step 4 — destination check (AV-8).
        if envelope.destination_key_id != self.self_steward_key_id {
            return Err(VerifyError::Misrouted);
        }

        // Step 5 — replay window (AV-3).
        {
            let mut window = self.replay_window.lock().await;
            if window.check_and_record(&envelope.signing_key_id, envelope.nonce) {
                return Err(VerifyError::ReplayDetected);
            }
        }

        // Step 6 — canonicalize-for-signing via persist
        // (CIRISPersist#7 single-source-of-truth).
        let envelope_value = serde_json::to_value(&envelope)
            .map_err(|e| VerifyError::SchemaInvalid(format!("envelope to_value: {e}")))?;
        let canonical_bytes = canonicalize_envelope_for_signing(&envelope_value)
            .map_err(|e| VerifyError::CanonicalizationFailed(format!("{e}")))?;

        // Step 7 — hybrid verify via directory (AV-1 + AV-9 + AV-39).
        // row_age = None in v0.1.0 — `SoftFreshness` policy collapses
        // to "always reject hybrid-pending" without per-row freshness
        // input. Real row_age computation lands when persist's
        // verify_hybrid_via_directory returns the looked-up row's
        // valid_from (potential follow-up ask).
        let outcome = self
            .directory
            .verify_hybrid_via_directory(
                &canonical_bytes,
                &envelope.signing_key_id,
                &envelope.signature,
                envelope.signature_pqc.as_deref(),
                self.policy,
                None,
            )
            .await
            .map_err(map_verify_error(&envelope.signing_key_id))?;

        // Forensic join key — single-source-of-truth via persist.
        let body_hash = persist_body_sha256(&envelope.body);

        Ok(VerifiedEnvelope {
            envelope,
            body_sha256: body_hash,
            verify_outcome: outcome,
            transport,
        })
    }
}

/// Map `HybridVerifyError` → typed `VerifyError`. The
/// `verify_unknown_key` token is persist's stable string for
/// directory-miss; everything else folds to `SignatureMismatch` or
/// `VerifyUnavailable` based on shape.
fn map_verify_error(signing_key_id: &str) -> impl FnOnce(HybridVerifyError) -> VerifyError + '_ {
    move |e| {
        let msg = format!("{e}");
        if msg.contains("verify_unknown_key") {
            VerifyError::UnknownKey(signing_key_id.to_string())
        } else if msg.contains("HybridPendingRejected")
            || msg.contains("hybrid-pending")
            || msg.contains("strict")
        {
            VerifyError::PqcPendingStrictReject
        } else if msg.contains("federation directory") || msg.contains("substrate") {
            VerifyError::VerifyUnavailable(msg)
        } else {
            VerifyError::SignatureMismatch(msg)
        }
    }
}

/// Bounded LRU replay-window. AV-3 closure for the on-wire portion;
/// persist's AV-9 dedup catches application-layer replay beyond the
/// window. Bounded by both time and capacity per AV-12 closure.
struct ReplayWindow {
    /// FIFO of (signing_key_id, nonce, seen_at) for time- and
    /// capacity-based eviction.
    queue: VecDeque<(String, [u8; 16], DateTime<Utc>)>,
    /// Set of `(signing_key_id, nonce)` for O(1) replay check.
    /// Stays in sync with `queue` via paired insertion + eviction.
    set: HashSet<(String, [u8; 16])>,
    window_seconds: u64,
    max_entries: usize,
}

impl ReplayWindow {
    fn new(window_seconds: u64, max_entries: usize) -> Self {
        Self {
            queue: VecDeque::new(),
            set: HashSet::new(),
            window_seconds,
            max_entries,
        }
    }

    /// Returns `true` if `(signing_key_id, nonce)` was already in the
    /// window (replay detected). Otherwise records it and returns
    /// `false`. Sweeps expired entries on every call so memory is
    /// bounded by `max(in-flight rate × window_seconds, max_entries)`.
    fn check_and_record(&mut self, signing_key_id: &str, nonce: [u8; 16]) -> bool {
        self.evict_expired();

        let key = (signing_key_id.to_string(), nonce);
        if self.set.contains(&key) {
            return true;
        }

        if self.queue.len() >= self.max_entries {
            if let Some((old_key_id, old_nonce, _)) = self.queue.pop_front() {
                self.set.remove(&(old_key_id, old_nonce));
            }
        }

        self.queue.push_back((key.0.clone(), key.1, Utc::now()));
        self.set.insert(key);
        false
    }

    fn evict_expired(&mut self) {
        let window_secs = i64::try_from(self.window_seconds).unwrap_or(i64::MAX);
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs);
        while let Some((_, _, seen_at)) = self.queue.front() {
            if *seen_at < cutoff {
                if let Some((key_id, nonce, _)) = self.queue.pop_front() {
                    self.set.remove(&(key_id, nonce));
                }
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window_detects_replay_within_window() {
        let mut w = ReplayWindow::new(300, 1000);
        let key = "agent-abc";
        let nonce = [1u8; 16];

        assert!(!w.check_and_record(key, nonce));
        assert!(w.check_and_record(key, nonce));
    }

    #[test]
    fn replay_window_distinct_nonces_pass() {
        let mut w = ReplayWindow::new(300, 1000);
        let key = "agent-abc";

        assert!(!w.check_and_record(key, [1u8; 16]));
        assert!(!w.check_and_record(key, [2u8; 16]));
        assert!(!w.check_and_record(key, [3u8; 16]));
    }

    #[test]
    fn replay_window_capacity_evicts_oldest() {
        let mut w = ReplayWindow::new(300, 3);
        assert!(!w.check_and_record("k", [1u8; 16]));
        assert!(!w.check_and_record("k", [2u8; 16]));
        assert!(!w.check_and_record("k", [3u8; 16]));
        // Capacity 3 reached; inserting [4] evicts [1] (oldest).
        assert!(!w.check_and_record("k", [4u8; 16]));
        // [1] was evicted — re-insertion is not a replay.
        assert!(!w.check_and_record("k", [1u8; 16]));
        // [3] is still within capacity window — replay rejects.
        assert!(w.check_and_record("k", [3u8; 16]));
    }
}
