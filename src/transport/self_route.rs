//! CIRISEdge#406 — the hybrid-signed `SignedTransportDestination` PRODUCER.
//!
//! Closes the "gate shipped ahead of its producer" gap (the #402 pattern,
//! third sighting): the CIRISEdge#393 item-2 attribution gate
//! ([`crate::verify::RootingDirectory::hybrid_transport_binding_exists`])
//! requires a stored `SignedTransportDestination` whose ML-DSA-65 half is
//! present, but nothing edge-side ever EMITTED one — the announce
//! write-through (#299) is Ed25519-only by MTU necessity, and the server's
//! self-publish wrote an unsigned row. So item 2 was unsatisfiable without
//! server-side hand-wiring, and every peer's frames dropped at the E3 gate.
//!
//! This module is the missing producer: when edge knows its OWN reticulum
//! destination + transport identity (the announce-compose path has both), it
//! emits a self-describing, hybrid-signed `SignedTransportDestination` row
//! through persist's REAL authenticated admission
//! (`put_signed_transport_destination` — hybrid 1-of-1 over
//! `JCS(signed_envelope)` against the PINNED federation pubkeys +
//! `signer_acts_for`; trivially satisfied for a self row). The row then
//! replicates on the `TransportDestination` plane and satisfies item 2 on
//! every peer that admits it — by each peer's own re-verification, not by
//! trust in us.
//!
//! # Why the ordering race is already closed (persist v21.3.1 "SIGNED WINS")
//!
//! A peer that roots our announce writes an UNSIGNED row for us (#299
//! write-through) with a wall-clock `asserted_at` that may postdate our
//! signed row's. Persist's route table resolves this by class, not clock:
//! a signed put always reclaims an unsigned row regardless of `(epoch,
//! asserted_at)`, and an unsigned writer can never demote a signed row
//! (it may only advance the advisory `last_seen_at` liveness clock). So
//! one emission per `(destination, epoch)` is sufficient — hence the
//! emit-only-on-change guard below, mirroring the #299 write-through's
//! "only on a genuinely-new / newer-epoch root" discipline.
//!
//! # Signing contract (verified against persist v30.2.0 source)
//!
//! `signed_envelope` is the serde serialization of the typed
//! [`TransportDestination`] row itself (`last_seen_at: None` is omitted —
//! advisory liveness is not signed material), so projection ≡ envelope by
//! construction and persist's field-by-field divergence checks pass
//! trivially. The detached signature is Ed25519 over
//! `JCS(signed_envelope)` and ML-DSA-65 over `JCS_bytes ‖ ed25519_sig`
//! (the bound-sig discipline; same as [`crate::identity::sign_envelope`]
//! and the touch-claim producer). Signing runs through the
//! ciris-keyring `HardwareSigner` / `PqcSigner` handles on
//! [`LocalSigner`] — never a raw key.

use std::sync::atomic::{AtomicBool, Ordering};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::Utc;
use ciris_persist::federation::self_at_login::{
    BindingProvenance, SignedTransportDestination, TransportDestination,
    TransportDestinationApplyOutcome,
};
use ciris_persist::prelude::ceg_produce_canonicalize;
use ciris_verify_core::transport_binding::TransportBindingSignature;

use crate::identity::LocalSigner;
use crate::verify::RootingDirectory;

/// The route-table `transport_kind` this producer emits — must match the
/// item-2 predicate's filter
/// ([`crate::verify::hybrid_reticulum_route_present`]).
pub const RETICULUM_TRANSPORT_KIND: &str = "reticulum";

/// What one [`SelfSignedRouteProducer::ensure`] pass decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfRouteOutcome {
    /// The durable store already holds a live hybrid-signed reticulum row
    /// for `(our key, our dest)` at `epoch` ≥ ours — nothing to emit.
    AlreadyCurrent,
    /// A fresh row went through persist's authenticated admission; the
    /// carried outcome is persist's verdict (`Inserted` / `Superseded` /
    /// `Unchanged` / `Refused`).
    Emitted(TransportDestinationApplyOutcome),
    /// The signer has no ML-DSA-65 (PQC) half — an Ed25519-only node
    /// cannot mint the hybrid signature item 2 requires, so nothing was
    /// emitted (warned LOUDLY once, not per tick).
    SkippedNoPqc,
    /// The store holds a signed RETIREMENT tombstone at `epoch` ≥ ours for
    /// this destination. Never auto-resurrected — retirement travels as a
    /// deliberate signed put; bump `local_epoch` to assert a new binding.
    SkippedRetired,
    /// The store's signed row carries a STRICTLY newer epoch than this
    /// process config — the config is stale (another emission superseded
    /// it); emitting would be refused, so nothing was written.
    SkippedStaleEpoch {
        /// The epoch the stored signed row carries.
        stored: u64,
    },
    /// A directory read/write or signer fault — nothing durable changed;
    /// safe to retry on the next announce tick.
    Deferred(String),
}

/// Idempotent self-signed-route producer. One per transport; holds only the
/// warn-once / memo state (the authoritative emit-or-not decision always
/// re-derives from the durable store).
#[derive(Debug, Default)]
pub struct SelfSignedRouteProducer {
    /// "Say so once": the Ed25519-only warn has fired.
    warned_no_pqc: AtomicBool,
    /// "Say so once": the stale-epoch / retired-tombstone warn has fired.
    warned_store_conflict: AtomicBool,
    /// Memo: the store was observed current (or we emitted) — later
    /// [`Self::ensure`] calls short-circuit without a directory read.
    current: AtomicBool,
}

impl SelfSignedRouteProducer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure the durable store carries OUR hybrid-signed reticulum route:
    /// emit if absent or stale (dest/epoch change), skip otherwise. Called
    /// at transport construction (bootstrap) and re-armed by the periodic
    /// announce tick, so a boot-time fault (directory not yet serving, own
    /// federation key not yet registered) heals without a restart.
    ///
    /// `dest_hash` is the NAMED destination hash — the hash the announce
    /// loop emits and therefore the dest peers record in their peers map,
    /// which is the exact operand their item-2 lookup uses.
    /// `transport_pubkey` is the 64-byte `x25519 ‖ ed25519` transport
    /// identity public material; `epoch` is the announce attestation's
    /// `local_epoch` (one supersession clock across both planes).
    pub async fn ensure(
        &self,
        signer: &LocalSigner,
        rooting: &dyn RootingDirectory,
        dest_hash: [u8; 16],
        transport_pubkey: [u8; 64],
        epoch: u64,
    ) -> SelfRouteOutcome {
        if self.current.load(Ordering::Relaxed) {
            return SelfRouteOutcome::AlreadyCurrent;
        }

        let want = hex::encode(dest_hash);

        // (1) Emit-only-on-change guard — the #299 write-through discipline
        // applied to our own row: consult the durable truth first.
        if let Some(early) = self.consult_store(signer, rooting, &want, epoch).await {
            return early;
        }

        // (2) The PQC precondition — item 2 exists to be quantum-adversary
        // safe, so an Ed25519-only emission would be admission-refused
        // (RequireHybrid) and useless even if admitted. Fail-open, LOUDLY,
        // once: the node keeps running, but its peers can never attribute
        // its frames until the ML-DSA-65 half is provisioned.
        let Some(pqc) = signer.pqc.as_ref() else {
            if !self.warned_no_pqc.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    key_id = %signer.key_id,
                    "CIRISEdge#406: cannot emit the hybrid-signed SignedTransportDestination \
                     — signer has NO ML-DSA-65 (PQC) half. This node is Ed25519-only, so \
                     CIRISEdge#393 item 2 (hybrid transport binding) is UNSATISFIABLE for it: \
                     peers will drop its frames unattributed at the E3 gate. Provision the \
                     PQC signer half to become attributable (warned once; not per tick)"
                );
            }
            return SelfRouteOutcome::SkippedNoPqc;
        };

        // (3)+(4) Build + hybrid-sign the row (extracted; see
        // [`build_and_sign_self_route`]).
        let signed_row =
            match build_and_sign_self_route(signer, pqc.as_ref(), want, &transport_pubkey, epoch)
                .await
            {
                Ok(s) => s,
                Err(deferred) => return deferred,
            };

        // (5) Emit through persist's REAL authenticated admission — the same
        // oracle every replicating peer re-runs on this exact record.
        match rooting.put_signed_transport_destination(&signed_row).await {
            Ok(outcome) => {
                if let TransportDestinationApplyOutcome::Refused { reason } = &outcome {
                    // Only reachable when a stored SIGNED row outranks us on
                    // `(epoch, asserted_at)` — a stale-config signal, not a
                    // crypto failure.
                    if !self.warned_store_conflict.swap(true, Ordering::Relaxed) {
                        tracing::warn!(
                            key_id = %signed_row.transport_destination.occurrence_key_id,
                            reason = %reason,
                            "CIRISEdge#406: own signed route emission REFUSED by the \
                             monotonic guard — the store holds a newer signed row \
                             (stale local_epoch?)"
                        );
                    }
                } else {
                    self.current.store(true, Ordering::Relaxed);
                    tracing::info!(
                        key_id = %signed_row.transport_destination.occurrence_key_id,
                        dest = %signed_row.transport_destination.destination,
                        epoch = signed_row.transport_destination.epoch,
                        outcome = ?outcome,
                        "CIRISEdge#406: emitted hybrid-signed SignedTransportDestination \
                         for own reticulum destination — #393 item 2 now self-satisfiable \
                         on every peer that admits this row"
                    );
                }
                SelfRouteOutcome::Emitted(outcome)
            }
            Err(e) => {
                // The expected boot-order fault: our own federation key may
                // not be registered yet (admission pins the attesting key in
                // the directory). The announce-tick re-arm heals this.
                tracing::warn!(
                    key_id = %signed_row.transport_destination.occurrence_key_id,
                    error = %e,
                    "CIRISEdge#406: own signed route emission failed at persist's \
                     authenticated admission — item 2 stays unsatisfiable for this node \
                     until it succeeds (will retry on the next announce tick)"
                );
                SelfRouteOutcome::Deferred(e)
            }
        }
    }

    /// Step (1) of [`Self::ensure`]: consult the durable store and decide
    /// whether anything needs emitting. `Some(outcome)` short-circuits
    /// (current / warned-skip / deferred); `None` means "emit".
    async fn consult_store(
        &self,
        signer: &LocalSigner,
        rooting: &dyn RootingDirectory,
        want: &str,
        epoch: u64,
    ) -> Option<SelfRouteOutcome> {
        let row = match rooting.signed_reticulum_route(&signer.key_id).await {
            Err(e) => {
                tracing::warn!(
                    key_id = %signer.key_id,
                    error = %e,
                    "CIRISEdge#406: cannot read own signed transport-destination state — \
                     bootstrap deferred (will retry on the next announce tick)"
                );
                return Some(SelfRouteOutcome::Deferred(e));
            }
            Ok(None) => return None, // No signed reticulum row — emit.
            Ok(Some(row)) => row,
        };
        let td = &row.transport_destination;
        if td.retired_at.is_some() {
            if td.epoch >= epoch {
                if !self.warned_store_conflict.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        key_id = %signer.key_id,
                        dest = %want,
                        stored_epoch = td.epoch,
                        config_epoch = epoch,
                        "CIRISEdge#406: own reticulum route is RETIRED (signed tombstone) \
                         at epoch >= this config — NOT auto-resurrecting; bump local_epoch \
                         to assert a new binding"
                    );
                }
                return Some(SelfRouteOutcome::SkippedRetired);
            }
            // Tombstone at an OLDER epoch: our newer-epoch binding
            // legitimately supersedes it — emit.
        } else if td.destination == want
            && td.epoch >= epoch
            && row.signature.mldsa65_signature_base64.is_some()
        {
            self.current.store(true, Ordering::Relaxed);
            return Some(SelfRouteOutcome::AlreadyCurrent);
        } else if td.epoch > epoch {
            if !self.warned_store_conflict.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    key_id = %signer.key_id,
                    stored_epoch = td.epoch,
                    config_epoch = epoch,
                    stored_dest = %td.destination,
                    dest = %want,
                    "CIRISEdge#406: stored signed route carries a NEWER epoch than this \
                     config (config stale — a later emission superseded it); not emitting"
                );
            }
            return Some(SelfRouteOutcome::SkippedStaleEpoch { stored: td.epoch });
        }
        // Absent-equivalent (dest changed at epoch >= stored, or a
        // signature-less anomaly) — emit.
        None
    }
}

/// Build the typed route row and hybrid-sign its envelope — steps (3)+(4)
/// of [`SelfSignedRouteProducer::ensure`], extracted for the 100-line gate.
///
/// The envelope IS the typed row serialized (`last_seen_at: None` omitted by
/// serde) — projection ≡ envelope by construction, the shape persist's
/// field-by-field divergence checks verify. The detached signature is
/// Ed25519 over `JCS(envelope)`, then ML-DSA-65 over `JCS_bytes ‖
/// ed25519_sig` (the bound-sig discipline persist's
/// `verify_threshold_signatures` re-checks). Signing runs through the
/// keyring signer handles only. `Err` carries the ready-to-return
/// [`SelfRouteOutcome::Deferred`].
async fn build_and_sign_self_route(
    signer: &LocalSigner,
    pqc: &dyn ciris_keyring::PqcSigner,
    destination: String,
    transport_pubkey: &[u8; 64],
    epoch: u64,
) -> Result<SignedTransportDestination, SelfRouteOutcome> {
    let row = TransportDestination {
        occurrence_key_id: signer.key_id.clone(),
        transport_kind: RETICULUM_TRANSPORT_KIND.to_string(),
        destination,
        asserted_at: Utc::now(),
        last_seen_at: None,
        // `[x25519 ‖ ed25519]` — same split as the #299 write-through.
        transport_ed25519_pubkey_base64: Some(B64.encode(&transport_pubkey[32..64])),
        transport_x25519_pubkey_base64: Some(B64.encode(&transport_pubkey[0..32])),
        // Self-asserted under our own federation key: the signature IS the
        // federation-key verification, re-checked at every peer's admission
        // — the Rooted claim is earned, not asserted on an unauthenticated
        // wire field (the #336 hijack shape).
        binding_provenance: BindingProvenance::Rooted,
        epoch,
        retired_at: None,
    };
    let envelope = serde_json::to_value(&row).map_err(|e| {
        // Structural — a typed row always serializes; keep the arm loud
        // rather than unwrap in prod code.
        tracing::warn!(error = %e, "CIRISEdge#406: route envelope serialize failed");
        SelfRouteOutcome::Deferred(format!("envelope serialize: {e}"))
    })?;
    let bytes = ceg_produce_canonicalize(&envelope).map_err(|e| {
        tracing::warn!(error = %e, "CIRISEdge#406: route envelope JCS canonicalize failed");
        SelfRouteOutcome::Deferred(format!("canonicalize: {e}"))
    })?;
    let ed = signer.classical.sign(&bytes).await.map_err(|e| {
        tracing::warn!(error = %e, "CIRISEdge#406: ed25519 sign failed");
        SelfRouteOutcome::Deferred(format!("ed25519 sign: {e}"))
    })?;
    let mut bound = bytes;
    bound.extend_from_slice(&ed);
    let mldsa = pqc.sign(&bound).await.map_err(|e| {
        tracing::warn!(error = %e, "CIRISEdge#406: ml-dsa-65 sign failed");
        SelfRouteOutcome::Deferred(format!("ml-dsa-65 sign: {e}"))
    })?;
    Ok(SignedTransportDestination {
        attesting_key_id: row.occurrence_key_id.clone(),
        transport_destination: row,
        signed_envelope: envelope,
        signature: TransportBindingSignature {
            ed25519_signature_base64: B64.encode(&ed),
            mldsa65_signature_base64: Some(B64.encode(&mldsa)),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
    use ciris_persist::federation::FederationDirectory;
    use ciris_persist::store::MemoryBackend;

    const DEST: [u8; 16] = [0xab; 16];
    const OTHER_DEST: [u8; 16] = [0xcd; 16];
    const TPK: [u8; 64] = [0x42; 64];

    /// Deterministic 32-byte seed for `label` (edge's fixture shape).
    fn seed32(label: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in label.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// A hybrid [`LocalSigner`] with deterministic Ed25519 + ML-DSA-65 keys
    /// (REAL signatures — persist's admission is the oracle, so no fakes).
    fn hybrid_signer(key_id: &str) -> Arc<LocalSigner> {
        let ed_seed = seed32(key_id);
        let mut pqc_seed = seed32(key_id);
        pqc_seed[0] ^= 0x55;
        let classical: Arc<dyn HardwareSigner> = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&ed_seed, key_id).expect("ed25519 from_bytes"),
        );
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&pqc_seed, format!("{key_id}-pqc"))
                .expect("ml_dsa_65 from_seed_bytes"),
        );
        Arc::new(LocalSigner::new(key_id, classical, Some(pqc)))
    }

    /// An Ed25519-ONLY signer — the hybrid-pending node that cannot satisfy
    /// item 2.
    fn classical_only_signer(key_id: &str) -> Arc<LocalSigner> {
        let classical: Arc<dyn HardwareSigner> =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&seed32(key_id), key_id).expect("ed25519"));
        Arc::new(LocalSigner::new(key_id, classical, None))
    }

    /// Register `signer`'s pubkeys as a federation key so its signatures
    /// verify against the PINNED directory entry at admission.
    async fn register(backend: &Arc<MemoryBackend>, signer: &LocalSigner) {
        let ed_pub = HardwareSigner::public_key(signer.classical.as_ref())
            .await
            .expect("ed25519 pubkey");
        let pqc_pub = match signer.pqc.as_ref() {
            Some(p) => Some(PqcSigner::public_key(p.as_ref()).await.expect("pqc pubkey")),
            None => None,
        };
        let now = Utc::now();
        let record = KeyRecord {
            key_id: signer.key_id.clone(),
            pubkey_ed25519_base64: B64.encode(&ed_pub),
            pubkey_ml_dsa_65_base64: pqc_pub.map(|p| B64.encode(&p)),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::NODE.into(),
            identity_ref: format!("node-ref-{}", signer.key_id),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": signer.key_id,
                "identity_type": identity_type::NODE,
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: signer.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("register federation key");
    }

    fn backend() -> Arc<MemoryBackend> {
        Arc::new(MemoryBackend::new())
    }

    /// The headline field-provenance test: the producer emits through
    /// persist's REAL `put_signed_transport_destination` admission (hybrid
    /// 1-of-1 over `JCS(envelope)` against the pinned key + acts-for — their
    /// verification is the oracle), and the EXACT gate the issue names as
    /// unsatisfiable (`hybrid_transport_binding_exists`) flips to `true` on
    /// our own row.
    #[tokio::test]
    async fn emits_through_real_admission_and_satisfies_item_2() {
        let backend = backend();
        let signer = hybrid_signer("self-route-emit");
        register(&backend, &signer).await;
        let dir: &dyn RootingDirectory = backend.as_ref();

        // Before: the #406 condition — item 2 unsatisfiable.
        assert!(
            !dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );

        let producer = SelfSignedRouteProducer::new();
        let out = producer.ensure(&signer, dir, DEST, TPK, 0).await;
        assert_eq!(
            out,
            SelfRouteOutcome::Emitted(TransportDestinationApplyOutcome::Inserted)
        );

        // After: the gate is satisfied by our own admitted row.
        assert!(
            dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );
        // And it is a REAL signed row (signature container stored), not a
        // trusted-local write: the replication read returns it, ML-DSA half
        // present — the exact shape peers re-verify.
        let row = dir
            .signed_reticulum_route(&signer.key_id)
            .await
            .expect("read")
            .expect("row present");
        assert_eq!(row.attesting_key_id, signer.key_id);
        assert!(row.signature.mldsa65_signature_base64.is_some());
        assert_eq!(row.transport_destination.destination, hex::encode(DEST));
        // A different dest still fails — the row binds THIS dest only.
        assert!(
            !dir.hybrid_transport_binding_exists(&signer.key_id, OTHER_DEST)
                .await
        );
    }

    /// Idempotence: same (dest, epoch) never re-emits — neither via the
    /// in-process memo nor via a fresh producer reading the store (a
    /// restart). A dest change or an epoch bump DOES re-emit (supersede).
    #[tokio::test]
    async fn reemits_only_on_dest_or_epoch_change() {
        let backend = backend();
        let signer = hybrid_signer("self-route-idem");
        register(&backend, &signer).await;
        let dir: &dyn RootingDirectory = backend.as_ref();

        let producer = SelfSignedRouteProducer::new();
        assert_eq!(
            producer.ensure(&signer, dir, DEST, TPK, 0).await,
            SelfRouteOutcome::Emitted(TransportDestinationApplyOutcome::Inserted)
        );
        let first = dir
            .signed_reticulum_route(&signer.key_id)
            .await
            .unwrap()
            .unwrap();

        // Same producer (memo) and a FRESH producer (store-read path — the
        // restart case) both decline to re-emit; the stored row is
        // byte-identical (asserted_at untouched).
        assert_eq!(
            producer.ensure(&signer, dir, DEST, TPK, 0).await,
            SelfRouteOutcome::AlreadyCurrent
        );
        assert_eq!(
            SelfSignedRouteProducer::new()
                .ensure(&signer, dir, DEST, TPK, 0)
                .await,
            SelfRouteOutcome::AlreadyCurrent
        );
        let unchanged = dir
            .signed_reticulum_route(&signer.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            first, unchanged,
            "no-change ensure must not rewrite the row"
        );

        // Epoch bump (transport-identity rotation) → supersede.
        assert_eq!(
            SelfSignedRouteProducer::new()
                .ensure(&signer, dir, DEST, TPK, 1)
                .await,
            SelfRouteOutcome::Emitted(TransportDestinationApplyOutcome::Superseded)
        );
        assert!(
            dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );

        // Dest change at the same epoch → supersede; item 2 tracks the NEW
        // dest and stops answering for the old one (route table: one live
        // reticulum row per key).
        assert_eq!(
            SelfSignedRouteProducer::new()
                .ensure(&signer, dir, OTHER_DEST, TPK, 1)
                .await,
            SelfRouteOutcome::Emitted(TransportDestinationApplyOutcome::Superseded)
        );
        assert!(
            dir.hybrid_transport_binding_exists(&signer.key_id, OTHER_DEST)
                .await
        );
        assert!(
            !dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );

        // Config now STALE (epoch 0 < stored 1) → warned skip, no write.
        assert_eq!(
            SelfSignedRouteProducer::new()
                .ensure(&signer, dir, DEST, TPK, 0)
                .await,
            SelfRouteOutcome::SkippedStaleEpoch { stored: 1 }
        );
    }

    /// The Ed25519-only path: warns LOUDLY once (the swap-guard), emits
    /// nothing, and item 2 stays honestly unsatisfied — no garbage row.
    #[tokio::test]
    async fn missing_pqc_warns_once_and_emits_nothing() {
        let backend = backend();
        let signer = classical_only_signer("self-route-nopqc");
        register(&backend, &signer).await;
        let dir: &dyn RootingDirectory = backend.as_ref();

        let producer = SelfSignedRouteProducer::new();
        assert_eq!(
            producer.ensure(&signer, dir, DEST, TPK, 0).await,
            SelfRouteOutcome::SkippedNoPqc
        );
        assert!(
            producer.warned_no_pqc.load(Ordering::Relaxed),
            "first skip warns"
        );
        // Second pass: same outcome, warn already spent (the announce-tick
        // re-arm must not spam).
        assert_eq!(
            producer.ensure(&signer, dir, DEST, TPK, 0).await,
            SelfRouteOutcome::SkippedNoPqc
        );

        // Nothing durable, no partial/classical-only row.
        assert!(dir
            .signed_reticulum_route(&signer.key_id)
            .await
            .expect("read")
            .is_none());
        assert!(
            !dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );
    }

    /// The field sequencing both ways round: the #299 Ed25519-only announce
    /// write-through neither blocks our signed emission (signed reclaims
    /// unsigned regardless of clocks) nor demotes it afterwards (unsigned
    /// never overwrites signed material) — persist v21.3.1 "SIGNED WINS",
    /// exercised through the real backend.
    #[tokio::test]
    async fn signed_row_reclaims_and_survives_the_unsigned_write_through() {
        let backend = backend();
        let signer = hybrid_signer("self-route-field");
        register(&backend, &signer).await;
        let dir: &dyn RootingDirectory = backend.as_ref();

        // Order B first: a peer's write-through-shaped UNSIGNED row already
        // present (rooted announce admitted before our row replicated over).
        dir.persist_transport_binding(&signer.key_id, DEST, TPK, BindingProvenance::Rooted, 0)
            .await;
        assert!(
            !dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await,
            "the unsigned write-through alone never satisfies item 2"
        );
        // Our signed emission reclaims the unsigned row even though its
        // asserted_at postdates ours' build instant.
        assert_eq!(
            SelfSignedRouteProducer::new()
                .ensure(&signer, dir, DEST, TPK, 0)
                .await,
            SelfRouteOutcome::Emitted(TransportDestinationApplyOutcome::Superseded)
        );
        assert!(
            dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );

        // Order A: a LATER unsigned write-through (same material, fresh
        // clock) may only touch advisory liveness — the signature survives.
        dir.persist_transport_binding(&signer.key_id, DEST, TPK, BindingProvenance::Rooted, 0)
            .await;
        assert!(
            dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await,
            "an unsigned writer must never demote the signed row"
        );
    }

    /// The boot-order reality: before the node's own federation key is
    /// registered, admission refuses the emission (Deferred, loud) — and the
    /// announce-tick re-arm succeeds once registration lands.
    #[tokio::test]
    async fn defers_until_own_federation_key_registered() {
        let backend = backend();
        let signer = hybrid_signer("self-route-boot");
        let dir: &dyn RootingDirectory = backend.as_ref();

        let producer = SelfSignedRouteProducer::new();
        assert!(matches!(
            producer.ensure(&signer, dir, DEST, TPK, 0).await,
            SelfRouteOutcome::Deferred(_)
        ));
        assert!(
            !dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );

        register(&backend, &signer).await;
        assert_eq!(
            producer.ensure(&signer, dir, DEST, TPK, 0).await,
            SelfRouteOutcome::Emitted(TransportDestinationApplyOutcome::Inserted)
        );
        assert!(
            dir.hybrid_transport_binding_exists(&signer.key_id, DEST)
                .await
        );
    }
}
