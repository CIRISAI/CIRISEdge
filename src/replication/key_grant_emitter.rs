//! **The pending-`KeyGrant` loop** (CIRISEdge#768) — the one emitter a
//! sealing host's replication runtime runs per content engine.
//!
//! persist's receive doors re-wrap this node's own community-DEK epochs to a
//! member's device that arrives late (`rewrap_after_admission`,
//! CIRISPersist#916): the signed identity-occurrence door and the
//! owner-binding attestation door. They have no signer, so they write GRANT
//! ROWS ONLY and leave the epoch DIRTY in the V146 emission ledger; persist's
//! contract (`FederationDirectory::rewrap_own_epochs_for_device`) is that "the
//! pending-`KeyGrant` loop every host runs signs and emits" the updated set.
//! Edge never ran it. A re-wrap therefore never reached the wire: the minter
//! kept re-offering the epoch's ORIGINAL set and the late device read every
//! body of the room `NotGranted` for good — the mesh's pair-room failure
//! (runs 36798512838 / 36800354009).
//!
//! # Shape
//!
//! One task per engine, never one per apply, owned by the
//! [`ReplicationRuntime`](super::ReplicationRuntime) and stopped with it:
//!
//! - **Woken, not called.** The bridge's apply choke wakes it (a
//!   [`Notify`] permit) after admitting a row that can re-wrap
//!   ([`wakes_key_grant_emitter`]). The apply itself never signs: it runs
//!   under the round gate (#740), and signing there is blocking-pool pressure
//!   on the round path.
//! - **Debounced.** A wake waits [`KeyGrantEmitterConfig::debounce`] before
//!   emitting, so a burst of admissions (a peer's whole occurrence plane)
//!   coalesces into one emission: a [`Notify`] holds at most one permit.
//! - **Backstopped, cheaply.** Every [`KeyGrantEmitterConfig::backstop`] it
//!   emits the DIRTY sets only ([`EmitPass::DirtyOnly`]: one ledger read when
//!   nothing is dirty), so a write door whose own emission failed is retried.
//!   The full sweep ([`EmitPass::Sweep`]) runs at start and on a wake only: it
//!   walks every room this node minted in (measured: ~131 ms per no-op pass
//!   at 100 rooms once CIRISPersist#967 makes never-rotated rooms visible,
//!   debug build), which is the wrong price for a timer.
//!
//! What it calls is persist's own doors:
//! [`Engine::emit_pending_key_grants`](ciris_persist::Engine::emit_pending_key_grants)
//! for a sweep (the minter-side re-wrap under the engine's own key, then every
//! dirty epoch's and self/family blob's set), and the V146 ledger read plus
//! `Engine::emit_key_grant` for a dirty-only pass.
//!
//! # Every producer of dirty epochs, and what covers it
//!
//! | Producer (persist) | Signs? | Covered by |
//! |---|---|---|
//! | `put_identity_occurrence` → `rewrap_after_admission` (#916) | no — grant rows only | wake on an admitted `IdentityOccurrence` |
//! | owner-binding attestation insert → `rewrap_after_admission` (#916) | no — grant rows only | wake on an admitted owner-binding `Attestation` |
//! | `Engine` write doors (seal / `ensure_epoch_dek`, `rekey_*`, `rewrap_own_epochs_to_member_devices`) | yes, inline | their own emission; a FAILED emission leaves the epoch dirty → the backstop |
//! | an epoch dirty at start (crash between cascade and emission) | — | the start sweep |
//! | a device whose receive-door re-wrap did not run (occurrence before binding; backend not told its key) | — | the sweep on the next wake, and the start sweep |

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

use super::bridge::BridgeEngine;
use super::EnvelopeKind;

/// Timing for the emitter. The backstop is the scheduler cadence the runtime
/// was configured with (see [`super::ReplicationRuntime`]); the debounce is
/// short — long enough to coalesce one peer's burst, short enough that a late
/// device is wrapped within a round.
#[derive(Debug, Clone, Copy)]
pub struct KeyGrantEmitterConfig {
    /// Coalescing window after a wake.
    pub debounce: Duration,
    /// Emit at least this often, woken or not.
    pub backstop: Duration,
}

impl KeyGrantEmitterConfig {
    /// The default coalescing window.
    pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(250);
}

/// Does admitting this row give persist a reason to re-wrap an epoch to a
/// device (CIRISPersist#916)? Exactly the two receive doors that call
/// `rewrap_after_admission`: a signed identity occurrence, and an owner
/// binding (`delegates_to` carrying an owner-binding envelope). Pure, so the
/// rule is a test.
#[must_use]
pub fn wakes_key_grant_emitter(kind: EnvelopeKind, envelope_bytes: &[u8]) -> bool {
    match kind {
        EnvelopeKind::IdentityOccurrence => true,
        EnvelopeKind::Attestation => {
            // The wire is the bare `Attestation`; the pre-v14.1 wrap is
            // `{"attestation": …}` (the bridge's own decode order).
            let row =
                serde_json::from_slice::<ciris_persist::federation::Attestation>(envelope_bytes)
                    .ok()
                    .or_else(|| {
                        serde_json::from_slice::<ciris_persist::federation::SignedAttestation>(
                            envelope_bytes,
                        )
                        .ok()
                        .map(|s| s.attestation)
                    });
            row.is_some_and(|a| {
                a.attestation_type
                    == ciris_persist::federation::types::attestation_type::DELEGATES_TO
                    && ciris_persist::federation::admission::is_owner_binding_envelope(
                        &a.attestation_envelope,
                    )
            })
        }
        _ => false,
    }
}

/// The emitter's two passes, by what triggered it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitPass {
    /// A wake (a re-wrap door admitted a row) or the first pass at start:
    /// persist's whole door, [`Engine::emit_pending_key_grants`] — the
    /// minter-side re-wrap sweep under the engine's own key, then every dirty
    /// set. The sweep is what wraps a device whose receive-door re-wrap did not
    /// run (an occurrence that landed before its binding, a backend not told
    /// its key); it costs a walk of every room this node minted in, so it runs
    /// only when something happened.
    ///
    /// [`Engine::emit_pending_key_grants`]: ciris_persist::Engine::emit_pending_key_grants
    Sweep,
    /// The cadence backstop: the dirty sets only (persist's
    /// `key_grant::dirty_axes` ledger read, then `Engine::emit_key_grant` per
    /// axis) — no sweep. Retries a write door's failed emission at the price
    /// of an indexed read when nothing is dirty.
    DirtyOnly,
}

/// Run one pass. `Ok(n)` is the number of sets emitted.
///
/// # Errors
/// persist's error text, from the derivation, the ledger read or an emission.
pub async fn emit_pass(engine: &ciris_persist::Engine, pass: EmitPass) -> Result<usize, String> {
    match pass {
        EmitPass::Sweep => engine
            .emit_pending_key_grants()
            .await
            .map_err(|e| e.to_string()),
        EmitPass::DirtyOnly => {
            let me = engine
                .local_derived_key_id()
                .await
                .map_err(|e| format!("this engine's key: {e}"))?;
            let axes = dirty_axes_of(engine, &me).await?;
            let mut emitted = 0usize;
            for axis in &axes {
                if engine
                    .emit_key_grant(axis)
                    .await
                    .map_err(|e| e.to_string())?
                    .is_some()
                {
                    emitted += 1;
                }
            }
            Ok(emitted)
        }
    }
}

#[allow(unreachable_patterns)] // the wildcard is live only when persist builds without `postgres`
async fn dirty_axes_of(
    engine: &ciris_persist::Engine,
    me: &str,
) -> Result<Vec<ciris_persist::federation::key_grant::KeyGrantAxis>, String> {
    use ciris_persist::federation::key_grant::dirty_axes;
    match engine.backend() {
        ciris_persist::BackendDispatch::Sqlite(b) => dirty_axes(b.as_ref(), me).await,
        #[cfg(feature = "pyo3")]
        ciris_persist::BackendDispatch::Postgres(b) => dirty_axes(b.as_ref(), me).await,
        _ => Ok(Vec::new()),
    }
    .map_err(|e| format!("key_grant ledger: {e}"))
}

/// Spawn the emitter for `engine`. It runs until `cancel` reads `true` (the
/// runtime's shutdown signal) and returns the task's handle for the runtime to
/// await. First pass at start is a [`EmitPass::Sweep`].
pub fn spawn_key_grant_emitter(
    engine: BridgeEngine,
    wake: Arc<Notify>,
    mut cancel: watch::Receiver<bool>,
    config: KeyGrantEmitterConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut backstop = tokio::time::interval(config.backstop.max(Duration::from_millis(100)));
        backstop.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // `interval`'s first tick is immediate; it is the start pass below.
        backstop.tick().await;
        let mut pass = EmitPass::Sweep;
        loop {
            if *cancel.borrow() {
                break;
            }
            match emit_pass(&engine.0, pass).await {
                Ok(0) => {}
                Ok(sets) => tracing::info!(
                    sets,
                    ?pass,
                    "pending KeyGrant sets emitted — re-wraps and failed emissions are on the \
                     wire (CIRISPersist#916, CIRISEdge#768)"
                ),
                Err(e) => tracing::warn!(
                    error = %e,
                    ?pass,
                    "pending KeyGrant emission failed; the dirty epochs stay dirty and the \
                     next wake or backstop tick retries (CIRISEdge#768)"
                ),
            }
            pass = tokio::select! {
                () = wake.notified() => {
                    // Coalesce the burst this wake belongs to.
                    tokio::select! {
                        () = tokio::time::sleep(config.debounce) => {}
                        _ = cancel.changed() => {}
                    }
                    EmitPass::Sweep
                }
                _ = backstop.tick() => EmitPass::DirtyOnly,
                changed = cancel.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    continue;
                }
            };
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attestation_bytes(attestation_type: &str, envelope: &serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "attestation_id": "a-1",
            "attesting_key_id": "owner",
            "attested_key_id": "device",
            "attestation_type": attestation_type,
            "weight": null,
            "asserted_at": "2026-05-01T00:00:00Z",
            "expires_at": null,
            "attestation_envelope": envelope,
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_signature_pqc": null,
            "scrub_key_id": "owner",
            "scrub_timestamp": "2026-05-01T00:00:00Z",
            "pqc_completed_at": null,
            "persist_row_hash": "",
            "subject_key_ids": [],
            "withdraws_admission_rule": null,
            "cohort_scope": "federation",
            "tier": "federation",
            "promoted_at": null,
            "additional_scrubs": []
        }))
        .expect("encode")
    }

    /// A real owner binding — the row the #916 attestation door re-wraps on —
    /// wakes it, in both wire shapes the bridge decodes.
    #[tokio::test]
    async fn an_owner_binding_wakes_the_emitter() {
        let classical: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
            ciris_keyring::Ed25519SoftwareSigner::from_bytes(&[9u8; 32], "owner-768")
                .expect("ed25519"),
        );
        let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[10u8; 32], "owner-768-pqc")
                .expect("ml-dsa"),
        );
        let owner = crate::identity::LocalSigner::new("owner-768", classical, Some(pqc));
        let binding = crate::replication::attestation_bind::owner_binding_attestation(
            "owner-768",
            "device-768",
            chrono::Utc::now(),
            &owner,
        )
        .await
        .expect("owner binding");
        let bare = serde_json::to_vec(&binding).expect("bare");
        let wrapped = serde_json::to_vec(&ciris_persist::federation::SignedAttestation {
            attestation: binding,
        })
        .expect("wrapped");
        assert!(wakes_key_grant_emitter(EnvelopeKind::Attestation, &bare));
        assert!(wakes_key_grant_emitter(EnvelopeKind::Attestation, &wrapped));
    }

    /// The two #916 doors wake the emitter; nothing else does.
    #[test]
    fn only_the_rewrap_doors_wake_the_emitter() {
        assert!(wakes_key_grant_emitter(
            EnvelopeKind::IdentityOccurrence,
            b"{}"
        ));
        assert!(!wakes_key_grant_emitter(EnvelopeKind::Key, b"{}"));
        assert!(!wakes_key_grant_emitter(EnvelopeKind::Community, b"{}"));
        assert!(!wakes_key_grant_emitter(
            EnvelopeKind::Attestation,
            b"{not json"
        ));
        let scores = attestation_bytes("scores", &serde_json::json!({ "dimension": "x:v1" }));
        assert!(!wakes_key_grant_emitter(EnvelopeKind::Attestation, &scores));
    }
}
