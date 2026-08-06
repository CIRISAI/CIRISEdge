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
use base64::Engine as _;
use chrono::{DateTime, Utc};
use tokio::sync::Mutex;

use ciris_persist::federation::rooting::{
    provenance_chain as persist_provenance_chain, root_binding as persist_root_binding,
};
pub use ciris_persist::federation::rooting::{
    ProvenanceChain, ProvenanceLink, RootingRejection, RootingVerdict,
};
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

    /// CIRISEdge#19 — enumerate accord-holder pubkeys for the 2-of-3
    /// multi-sig threshold check at the wire layer. Returns the rows
    /// from persist's `federation_keys` where `identity_type =
    /// 'accord_holder'` (persist v2.6.0+
    /// [`FederationDirectory::list_keys_by_identity_type`]), mapped to
    /// the lightweight [`AccordHolderKey`] shape edge needs.
    ///
    /// Returns an empty `Vec` when persist holds no accord-holder
    /// rows — edge's wire-layer hook distinguishes this case from
    /// "threshold not met" via [`RefusalReason::NoAccordHoldersConfigured`].
    async fn list_accord_holders(&self) -> Result<Vec<AccordHolderKey>, VerifyError>;

    /// CIRISEdge#23 — fetch a single `federation_keys` row by `key_id`.
    /// Returns the 32-byte raw Ed25519 pubkey if the row exists, `None`
    /// otherwise. Used by:
    ///   - The HTTPS transport's mTLS handshake verifier — the client
    ///     cert's CN is the federation `key_id`, and the cert's spki
    ///     public key MUST equal the directory's
    ///     `pubkey_ed25519_base64` for the handshake to proceed.
    ///   - The HTTPS transport's bearer-token path — the JWT's `kid`
    ///     header names a federation key, and verification uses this
    ///     row's pubkey as the JWT verification key.
    /// Backed by `FederationDirectory::lookup_public_key`.
    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<[u8; 32]>, VerifyError>;
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

    async fn list_accord_holders(&self) -> Result<Vec<AccordHolderKey>, VerifyError> {
        let rows = FederationDirectory::list_keys_by_identity_type(
            self,
            ciris_persist::federation::types::identity_type::ACCORD_HOLDER,
        )
        .await
        .map_err(|e| VerifyError::VerifyUnavailable(format!("list_keys_by_identity_type: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            // Decode the base64 pubkey at adapter boundary so the
            // verify hook gets ready-to-use [u8; 32] bytes — single
            // decode per row, not once per signature check.
            let raw = base64::engine::general_purpose::STANDARD
                .decode(row.pubkey_ed25519_base64.as_bytes())
                .map_err(|e| {
                    VerifyError::VerifyUnavailable(format!(
                        "accord-holder pubkey base64 decode for key_id={}: {e}",
                        row.key_id
                    ))
                })?;
            let pubkey: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                VerifyError::VerifyUnavailable(format!(
                    "accord-holder pubkey length != 32 for key_id={} (got {})",
                    row.key_id,
                    raw.len()
                ))
            })?;
            out.push(AccordHolderKey {
                key_id: row.key_id,
                pubkey_ed25519: pubkey,
                identity_ref: row.identity_ref,
            });
        }
        Ok(out)
    }

    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<[u8; 32]>, VerifyError> {
        let row = FederationDirectory::lookup_public_key(self, key_id)
            .await
            .map_err(|e| VerifyError::VerifyUnavailable(format!("lookup_public_key: {e}")))?;
        let Some(row) = row else { return Ok(None) };
        let raw = base64::engine::general_purpose::STANDARD
            .decode(row.pubkey_ed25519_base64.as_bytes())
            .map_err(|e| {
                VerifyError::VerifyUnavailable(format!(
                    "federation_keys.pubkey_ed25519_base64 decode for key_id={key_id}: {e}"
                ))
            })?;
        let pubkey: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
            VerifyError::VerifyUnavailable(format!(
                "federation_keys.pubkey_ed25519 length != 32 for key_id={key_id} (got {})",
                raw.len()
            ))
        })?;
        Ok(Some(pubkey))
    }
}

/// CIRISEdge#19 — one accord-holder key ready for wire-layer
/// signature verification. Returned by
/// [`VerifyDirectory::list_accord_holders`]. The `pubkey_ed25519`
/// field is the 32-byte raw key (already base64-decoded at adapter
/// boundary — see the blanket impl); `identity_ref` is preserved
/// from persist for forensic logging on refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccordHolderKey {
    pub key_id: String,
    pub pubkey_ed25519: [u8; 32],
    pub identity_ref: String,
}

/// Adapter trait that erases `FederationDirectory`'s generics for the
/// cold-start binding-rooting primitive (`root_binding`,
/// CIRISPersist#94 / v1.12.0).
///
/// `ciris_persist::federation::rooting::root_binding` is
/// `root_binding<F: FederationDirectory>` — generic over a concrete
/// directory. `FederationDirectory` itself uses `async fn in trait`
/// (RPIT), so it is not dyn-compatible and edge cannot hold a
/// `&dyn FederationDirectory`. This mirrors the [`VerifyDirectory`]
/// pattern exactly: blanket-implemented for any `FederationDirectory`,
/// `#[async_trait]`-erased so the Reticulum [`PeerResolver`] can hold
/// an `Arc<dyn RootingDirectory>` without picking edge's generics.
///
/// See `src/transport/reticulum.rs` for the resolver's cold-start
/// path; the `RootingVerdict` / `ProvenanceChain` types it returns
/// are CIRISPersist#94's ratified cross-repo contract surface.
#[async_trait]
pub trait RootingDirectory: Send + Sync + 'static {
    /// Root a claimed `(key_id, ed25519-pubkey)` binding against the
    /// `federation_keys` directory — confirm the row exists, the
    /// claimed pubkey matches it, and the recursive-provenance chain
    /// verifies up to a steward bootstrap. Replaces TOFU.
    async fn root_binding(
        &self,
        key_id: &str,
        claimed_pubkey_ed25519_base64: &str,
    ) -> RootingVerdict;

    /// Assemble the recursive-provenance chain for `key_id` without
    /// the verifying verdict — the verify-consumable read.
    async fn provenance_chain(&self, key_id: &str) -> Result<ProvenanceChain, RootingRejection>;

    /// CIRISEdge#299 — **write-through** a peer's rooted transport
    /// identity so it survives a restart (reloaded via
    /// `list_all_transport_destinations` on boot) and a KNOWN peer is
    /// reachable-and-sealable with zero announces. Called by the
    /// reticulum announce handler the moment an announce roots
    /// (`RootingVerdict::Rooted`), with the full 64-byte transport
    /// identity (`x25519 ‖ ed25519`) it holds. NOT TOFU — `root_binding`
    /// already verified the peer against the anchor; this only persists
    /// the already-verified binding. Idempotent upsert on `key_id`
    /// (last-writer-wins → a transport-identity rotation re-roots and
    /// overwrites). Default is a no-op so non-`FederationDirectory`
    /// impls (test doubles) don't break; the blanket impl over
    /// `FederationDirectory` does the real `put_transport_destination`.
    ///
    /// CIRISEdge#301 — `provenance` tags the durable row `Rooted`
    /// (authoritative, chained to a pinned steward) or `Advisory` (a
    /// self-consistent routing hint that did not root against the local
    /// directory, CC 3.3.6.2). Both are persisted (admit-not-drop); the
    /// consumer composes trust from the tag downstream.
    async fn persist_transport_binding(
        &self,
        _key_id: &str,
        _dest_hash: [u8; 16],
        _transport_pubkey: [u8; 64],
        _provenance: ciris_persist::federation::self_at_login::BindingProvenance,
        _epoch: u64,
    ) {
    }

    /// CIRISEdge#362 (CIRISPersist#469, persist v17.8.0) — the seeder bridge.
    /// Record a peer learned from a self-consistent announce as a
    /// **non-canonical, untrusted** directory BOOKMARK (persist's separate
    /// `announced_peers` table, V108), so a LAN-announced peer surfaces in the
    /// server's `GET /v1/federation/peers` (`canonical=false`, `trust="unknown"`,
    /// `last_seen`). Deliberately NOT an admission — the bookmark is invisible to
    /// every admission / quorum / rooting path by construction; it never
    /// satisfies an accord seat / WA / steward count. Idempotent + liveness-
    /// refreshing; a pubkey change for the same `key_id` is a real identity
    /// conflict (persist returns `Conflict`). Safe on BOTH Advisory and Rooted
    /// admits — once the key roots for real, `list_announced_peers` anti-joins
    /// the bookmark away. Default no-op so test doubles don't break; the blanket
    /// impl over `FederationDirectory` does the real `record_announced_peer`.
    async fn record_announced_peer(
        &self,
        _key_id: &str,
        _pubkey_ed25519_base64: &str,
        _pubkey_ml_dsa_65_base64: Option<&str>,
        _claimed_identity_type: Option<&str>,
        _last_seen: chrono::DateTime<chrono::Utc>,
    ) {
    }

    /// CIRISEdge#393 (E3, item 2) — does a HYBRID-verified (ML-DSA-65)
    /// `SignedTransportDestination` bind `key_id`'s reticulum transport identity
    /// to `dest_hash`?
    ///
    /// The post-quantum half of attribution. The announce binding is Ed25519-only
    /// and MTU-bounded (an ML-DSA-65 signature is ~3.3 KB vs the 300 B announce
    /// budget), so PQ assurance rides the replicated, hybrid-Strict
    /// `TransportDestination` plane instead — which edge already applies and
    /// persist already verifies the ML-DSA half of on `put`. A stored route
    /// carrying an `mldsa65_signature_base64` is therefore hybrid-verified; the
    /// Ed25519-only announce write-through ([`Self::persist_transport_binding`])
    /// carries `None` and does NOT satisfy this. A quantum adversary who forged
    /// the Ed25519 announce still cannot produce this ML-DSA-signed route, so
    /// attribution gated on it stays PQ-safe. Default `false` (test doubles /
    /// no-directory ⇒ fail-closed); the `FederationDirectory` blanket impl reads
    /// the stored routes.
    async fn hybrid_transport_binding_exists(&self, _key_id: &str, _dest_hash: [u8; 16]) -> bool {
        false
    }

    /// CIRISEdge#437 (CIRISVerify#181) — verify a peer's presented
    /// build-attestation bundle with every trust input pinned from THIS
    /// federation directory (never caller-supplied, never read from the
    /// bundle): the presenter member is `presenter_key_id`'s directory row,
    /// the pipeline member + accord-co-scrubbed record are the directory row
    /// the carried manifest NAMES (a name only — pubkeys and the
    /// `infra:attest` blessing come from the row), and the co-scrub anchors
    /// are the directory's `accord_holder` rows. See
    /// [`crate::bundle_gate`] for the full chain + what a verdict does and
    /// does not prove. Default is a typed
    /// [`BundleGateRefusal::NoDirectory`](crate::bundle_gate::BundleGateRefusal::NoDirectory)
    /// refusal (test doubles / no directory ⇒ fail-closed — under the gate a
    /// refusal can only downgrade a durable save, never widen one).
    async fn verify_peer_build_bundle(
        &self,
        _presenter_key_id: &str,
        _bundle_bytes: &[u8],
    ) -> crate::bundle_gate::BundleGateVerdict {
        crate::bundle_gate::BundleGateVerdict::Refused(
            crate::bundle_gate::BundleGateRefusal::NoDirectory,
        )
    }

    /// CIRISEdge#406 — the CURRENT signed reticulum route stored for
    /// `key_id`, signature container included (the read half of the
    /// self-signed-route producer's emit-only-on-change guard). One row per
    /// `(occurrence_key_id, transport_kind)` is structural in persist's
    /// route table, so this is at most one row; RETIRED rows are INCLUDED
    /// (a tombstone must be able to veto an auto-resurrecting re-emit).
    /// Default `Err` (test doubles / no directory ⇒ the producer defers,
    /// never emits blind).
    async fn signed_reticulum_route(
        &self,
        _key_id: &str,
    ) -> Result<Option<ciris_persist::federation::self_at_login::SignedTransportDestination>, String>
    {
        Err("no federation directory wired (RootingDirectory default)".to_string())
    }

    /// CIRISEdge#406 — submit a signed route through persist's authenticated
    /// admission (`put_signed_transport_destination`: hybrid 1-of-1 over
    /// `JCS(signed_envelope)` against the attesting key's PINNED federation
    /// pubkeys + `signer_acts_for` + the `(epoch, asserted_at)` monotonic
    /// guard). The write half of the self-signed-route producer — the same
    /// gate the replication bridge's apply path calls, so a self-emitted row
    /// is admitted under exactly the oracle every peer will re-run. Default
    /// `Err` (test doubles / no directory ⇒ the producer defers).
    async fn put_signed_transport_destination(
        &self,
        _signed: &ciris_persist::federation::self_at_login::SignedTransportDestination,
    ) -> Result<ciris_persist::federation::self_at_login::TransportDestinationApplyOutcome, String>
    {
        Err("no federation directory wired (RootingDirectory default)".to_string())
    }

    /// CIRISEdge#432 — point-read the durably stored reticulum binding for
    /// `key_id`: the read half of the live-map divergence heal.
    ///
    /// The live `peers` map and the durable `transport_destinations` store have
    /// INDEPENDENT writers (the announce path moves both in one motion, but a
    /// replication-side or server-side rooting writes only the store), so a
    /// long-lived node can hold a live entry at `Advisory` while the store says
    /// `rooted` — and the attribution gate reads the one that is wrong. This
    /// accessor lets the attribution-failure path consult the durable truth and
    /// heal the live entry in place — a one-peer, mid-session boot prime.
    /// Default `None` (test doubles / no directory ⇒ no heal, fail-closed —
    /// a missing store can only leave attribution as it was, never widen it).
    async fn stored_reticulum_binding(&self, _key_id: &str) -> Option<StoredTransportBinding> {
        None
    }
}

/// CIRISEdge#432 — the durable transport binding as the divergence heal
/// consumes it: provenance + the full 64-byte `(x25519 ‖ ed25519)` transport
/// identity (so the heal can require the STORED identity to equal the identity
/// the link actually proved — the store is authority for trust, never for
/// identity) + the stored supersession epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoredTransportBinding {
    /// The durably recorded provenance (`rooted` is what the heal acts on).
    pub provenance: ciris_persist::federation::self_at_login::BindingProvenance,
    /// The stored transport identity, `[x25519 ‖ ed25519]`.
    pub transport_pubkey64: [u8; 64],
    /// The stored monotonic supersession epoch (CIRISEdge#336).
    pub epoch: u64,
}

/// CIRISEdge#393 (E3, item 2) — pure predicate under
/// [`RootingDirectory::hybrid_transport_binding_exists`]: is any of `routes` a
/// reticulum route to `dest_hash` carrying a verified ML-DSA-65 half? Extracted
/// pure so the PQ gate is unit-testable against the exact stored shapes without
/// a live directory.
#[must_use]
pub fn hybrid_reticulum_route_present(
    routes: &[ciris_persist::federation::self_at_login::SignedTransportDestination],
    dest_hash: [u8; 16],
) -> bool {
    let want = hex::encode(dest_hash);
    routes.iter().any(|r| {
        r.transport_destination.transport_kind == "reticulum"
            && r.transport_destination.destination == want
            && r.signature.mldsa65_signature_base64.is_some()
    })
}

#[cfg(test)]
mod hybrid_transport_binding_tests {
    use super::hybrid_reticulum_route_present;
    use ciris_persist::federation::self_at_login::{
        BindingProvenance, SignedTransportDestination, TransportDestination,
    };
    use ciris_verify_core::transport_binding::TransportBindingSignature;

    fn route(dest_hash: [u8; 16], kind: &str, mldsa: Option<&str>) -> SignedTransportDestination {
        SignedTransportDestination {
            transport_destination: TransportDestination {
                occurrence_key_id: "peer".into(),
                transport_kind: kind.into(),
                destination: hex::encode(dest_hash),
                asserted_at: chrono::DateTime::UNIX_EPOCH,
                last_seen_at: None,
                transport_ed25519_pubkey_base64: None,
                transport_x25519_pubkey_base64: None,
                binding_provenance: BindingProvenance::Rooted,
                epoch: 0,
                retired_at: None,
            },
            attesting_key_id: "peer".into(),
            signed_envelope: serde_json::json!({}),
            signature: TransportBindingSignature {
                ed25519_signature_base64: "ed".into(),
                mldsa65_signature_base64: mldsa.map(str::to_string),
            },
        }
    }

    /// CIRISEdge#393 item 2 — the PQ attribution predicate against the EXACT
    /// stored shapes. Only a reticulum route to the peer's dest carrying an
    /// ML-DSA-65 half counts; the Ed25519-only announce write-through (`None`)
    /// and a wrong-dest / wrong-kind route do NOT — so a quantum-forged
    /// Ed25519 announce cannot make its peer attributable.
    #[test]
    fn only_a_hybrid_reticulum_route_to_the_dest_counts() {
        let dest = [0xab; 16];
        let other = [0xcd; 16];
        // Hybrid reticulum route to the dest → present.
        assert!(hybrid_reticulum_route_present(
            &[route(dest, "reticulum", Some("mldsa-sig"))],
            dest
        ));
        // Ed25519-only write-through (mldsa None) → NOT present (the PQ gap).
        assert!(!hybrid_reticulum_route_present(
            &[route(dest, "reticulum", None)],
            dest
        ));
        // Hybrid route to a DIFFERENT dest → not present for this dest.
        assert!(!hybrid_reticulum_route_present(
            &[route(other, "reticulum", Some("mldsa-sig"))],
            dest
        ));
        // Hybrid but non-reticulum kind → not present.
        assert!(!hybrid_reticulum_route_present(
            &[route(dest, "websocket", Some("mldsa-sig"))],
            dest
        ));
        // Empty → not present (fresh boot, no route yet).
        assert!(!hybrid_reticulum_route_present(&[], dest));
    }
}

#[async_trait]
impl<F: FederationDirectory + Send + Sync + 'static> RootingDirectory for F {
    async fn root_binding(
        &self,
        key_id: &str,
        claimed_pubkey_ed25519_base64: &str,
    ) -> RootingVerdict {
        persist_root_binding(self, key_id, claimed_pubkey_ed25519_base64).await
    }

    async fn provenance_chain(&self, key_id: &str) -> Result<ProvenanceChain, RootingRejection> {
        persist_provenance_chain(self, key_id).await
    }

    async fn hybrid_transport_binding_exists(&self, key_id: &str, dest_hash: [u8; 16]) -> bool {
        // Fail-closed on a backend read error: no VERIFIABLE hybrid route ⇒ not
        // PQ-attributable (a directory hiccup must never widen attribution).
        match self.list_signed_transport_destinations_for(key_id).await {
            Ok(routes) => hybrid_reticulum_route_present(&routes, dest_hash),
            Err(_) => false,
        }
    }

    async fn signed_reticulum_route(
        &self,
        key_id: &str,
    ) -> Result<Option<ciris_persist::federation::self_at_login::SignedTransportDestination>, String>
    {
        let rows = FederationDirectory::list_signed_transport_destinations_for(self, key_id)
            .await
            .map_err(|e| format!("list_signed_transport_destinations_for: {e}"))?;
        // One live row per `(occurrence_key_id, transport_kind)` is structural
        // (persist #443 route-table PK), so `find` is exhaustive.
        Ok(rows
            .into_iter()
            .find(|r| r.transport_destination.transport_kind == "reticulum"))
    }

    async fn put_signed_transport_destination(
        &self,
        signed: &ciris_persist::federation::self_at_login::SignedTransportDestination,
    ) -> Result<ciris_persist::federation::self_at_login::TransportDestinationApplyOutcome, String>
    {
        FederationDirectory::put_signed_transport_destination(self, signed)
            .await
            .map_err(|e| format!("put_signed_transport_destination: {e}"))
    }

    async fn verify_peer_build_bundle(
        &self,
        presenter_key_id: &str,
        bundle_bytes: &[u8],
    ) -> crate::bundle_gate::BundleGateVerdict {
        use crate::bundle_gate::{
            bundle_pipeline_key_id, verify_bundle_with_directory_rows, BundleGateRefusal as R,
            BundleGateVerdict as V, MAX_PEER_BUNDLE_BYTES,
        };
        // Cheap rejects first (the verify-pipeline cost-asymmetry discipline):
        // size cap before parse, parse before any directory round-trip.
        if bundle_bytes.len() > MAX_PEER_BUNDLE_BYTES {
            return V::Refused(R::OversizedBundle {
                actual: bundle_bytes.len(),
                limit: MAX_PEER_BUNDLE_BYTES,
            });
        }
        let Ok(bundle) =
            serde_json::from_slice::<ciris_verify_core::ceg_outbox::SignedCegObject>(bundle_bytes)
        else {
            return V::Refused(R::MalformedBundle("not a JSON SignedCegObject"));
        };
        // The ONLY thing read from the object: the pipeline row's NAME. All
        // pubkeys / roles / quorum inputs come from the directory rows below.
        let Some(pipeline_key_id) = bundle_pipeline_key_id(&bundle).map(str::to_string) else {
            return V::Refused(R::MalformedBundle(
                "carried manifest names no pipeline attesting_key_id",
            ));
        };
        // Pin the presenter — the peer being saved, named by the CALLER
        // (announce key_id), never by the bundle.
        let presenter_row =
            match FederationDirectory::lookup_public_key(self, presenter_key_id).await {
                Err(e) => return V::Refused(R::DirectoryUnavailable(e.to_string())),
                Ok(None) => {
                    return V::Refused(R::PresenterNotInDirectory {
                        key_id: presenter_key_id.to_string(),
                    })
                }
                Ok(Some(row)) => row,
            };
        // Pin the pipeline row the manifest named.
        let pipeline_row =
            match FederationDirectory::lookup_public_key(self, &pipeline_key_id).await {
                Err(e) => return V::Refused(R::DirectoryUnavailable(e.to_string())),
                Ok(None) => {
                    return V::Refused(R::PipelineNotInDirectory {
                        key_id: pipeline_key_id,
                    })
                }
                Ok(Some(row)) => row,
            };
        // Pin the accord anchors: the directory's accord_holder rows.
        let anchor_rows = match FederationDirectory::list_keys_by_identity_type(
            self,
            ciris_persist::federation::types::identity_type::ACCORD_HOLDER,
        )
        .await
        {
            Err(e) => return V::Refused(R::DirectoryUnavailable(e.to_string())),
            Ok(rows) => rows,
        };
        verify_bundle_with_directory_rows(&bundle, &presenter_row, &pipeline_row, &anchor_rows)
    }

    async fn stored_reticulum_binding(&self, key_id: &str) -> Option<StoredTransportBinding> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        // Fail-closed on a read error: no durable truth ⇒ no heal (the live
        // entry stays as it was; a directory hiccup must never widen anything).
        let rows = FederationDirectory::list_transport_destinations_for(self, key_id)
            .await
            .ok()?;
        // Best live reticulum row: max epoch, then latest asserted_at — the
        // same monotonic ordering the (epoch, asserted_at)-guarded put enforces.
        let row = rows
            .iter()
            .filter(|r| r.transport_kind == "reticulum" && r.retired_at.is_none())
            .max_by_key(|r| (r.epoch, r.asserted_at))?;
        // Both identity halves must be present + well-formed — a partial row
        // cannot bind an identity, so it cannot justify a trust upgrade.
        let x = b64
            .decode(row.transport_x25519_pubkey_base64.as_deref()?)
            .ok()?;
        let e = b64
            .decode(row.transport_ed25519_pubkey_base64.as_deref()?)
            .ok()?;
        let (x32, e32): ([u8; 32], [u8; 32]) =
            (x.as_slice().try_into().ok()?, e.as_slice().try_into().ok()?);
        let mut pk = [0u8; 64];
        pk[..32].copy_from_slice(&x32);
        pk[32..].copy_from_slice(&e32);
        Some(StoredTransportBinding {
            provenance: row.binding_provenance,
            transport_pubkey64: pk,
            epoch: row.epoch,
        })
    }

    async fn persist_transport_binding(
        &self,
        key_id: &str,
        dest_hash: [u8; 16],
        transport_pubkey: [u8; 64],
        provenance: ciris_persist::federation::self_at_login::BindingProvenance,
        epoch: u64,
    ) {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        // The 64-byte RNS transport identity is `[x25519 ‖ ed25519]`.
        let row = ciris_persist::federation::self_at_login::TransportDestination {
            occurrence_key_id: key_id.to_string(),
            transport_kind: "reticulum".to_string(),
            destination: hex::encode(dest_hash),
            asserted_at: chrono::Utc::now(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: Some(b64.encode(&transport_pubkey[32..64])),
            transport_x25519_pubkey_base64: Some(b64.encode(&transport_pubkey[0..32])),
            // CIRISEdge#301 — Rooted (Confirmed verdict) or Advisory (CC 3.3.6.2
            // admit-as-routing-hint); the caller decides from the verdict.
            binding_provenance: provenance,
            // CIRISEdge#336 / CIRISPersist#443 (v17.0.0) — the durable monotonic
            // supersession counter (the announce attestation's epoch, which is
            // `RootedPeer.epoch`). Persist's put is `(epoch, asserted_at)`-guarded,
            // so a replayed older frame can never clobber a newer binding — the
            // durable half of the verified-only supersession invariant. Route
            // retirement (`retired_at`) goes through the signed tombstone path,
            // never a plain local write-through, so it is `None` here.
            epoch,
            retired_at: None,
        };
        match FederationDirectory::put_transport_destination(self, &row).await {
            // CIRISEdge#337 §4 — DEBUG (was INFO): one per persist write, i.e. per
            // admit, so attacker-floodable. The failure branch stays WARN (a
            // durable-write failure is a real incident, and it is not
            // attacker-amplifiable beyond the admit rate the peers-map cap bounds).
            Ok(()) => tracing::debug!(
                key_id,
                dest_hash = %row.destination,
                provenance = ?provenance,
                epoch,
                "CIRISEdge#299/#301: persisted transport binding (write-through)"
            ),
            Err(e) => tracing::warn!(
                key_id,
                error = %e,
                provenance = ?provenance,
                epoch,
                "CIRISEdge#299/#301: write-through of transport binding failed (peer still \
                 admitted in-memory this session, but will not survive a restart)"
            ),
        }
    }

    async fn record_announced_peer(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        pubkey_ml_dsa_65_base64: Option<&str>,
        claimed_identity_type: Option<&str>,
        last_seen: chrono::DateTime<chrono::Utc>,
    ) {
        match FederationDirectory::record_announced_peer(
            self,
            key_id,
            pubkey_ed25519_base64,
            pubkey_ml_dsa_65_base64,
            claimed_identity_type,
            last_seen,
        )
        .await
        {
            // Attacker-floodable (one per advisory admit) → DEBUG. A `Conflict`
            // (a changed pubkey for a known key_id) is a genuine identity signal,
            // not a churn event, so it surfaces at WARN; any other write error is
            // a non-fatal bookmark miss (the peer is still admitted in-memory +
            // routing-bound this session).
            Ok(()) => tracing::debug!(
                key_id,
                claimed_identity_type,
                "CIRISEdge#362: recorded announced-peer bookmark (seeder bridge)"
            ),
            Err(ciris_persist::federation::Error::Conflict { .. }) => tracing::warn!(
                key_id,
                "CIRISEdge#362: announced-peer bookmark REJECTED — a different pubkey is \
                 already recorded for this key_id (identity conflict, not a refresh)"
            ),
            Err(e) => tracing::debug!(
                key_id,
                error = %e,
                "CIRISEdge#362: announced-peer bookmark write failed (peer still admitted \
                 in-memory this session; bookmark will not appear in /v1/federation/peers)"
            ),
        }
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
    /// CIRISEdge#42 (v0.12.0, CEG §10.1.1) — `ContentBody` integrity
    /// check failed: `sha256(body.bytes) != body.sha256`. The envelope
    /// signature verified (the responder really did send these bytes
    /// claiming this SHA), but the content-addressed contract was
    /// violated. CEG §10.1.1 normative — full SHA-256 of received
    /// bytes MUST be verified before any handler dispatch; short-
    /// circuiting to a prefix is REJECTED by the spec.
    #[error(
        "content integrity check failed: claimed_sha256={claimed_sha256} \
         but sha256(bytes)={actual_sha256}"
    )]
    ContentIntegrity {
        /// The SHA-256 the responder claimed (`body.sha256`).
        claimed_sha256: String,
        /// The SHA-256 actually computed over `body.bytes`.
        actual_sha256: String,
    },
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

/// Trace-flavored alias for [`VerifiedEnvelope`]. CIRISLensCore's
/// `LensCore::process(VerifiedTrace)` consumes this — the science-
/// layer's input is "an envelope edge has fully verified" and the
/// trace use-case is the dominant consumer at v0.1.0.
///
/// Identical type to [`VerifiedEnvelope`]; the alias exists so
/// `use ciris_edge::VerifiedTrace` reads naturally on the lens-core
/// side. Future Phase 2 work may promote this to a typed wrapper
/// that pre-parses the `AccordEventsBatch` body — for now,
/// consumers handle that themselves via `verified.envelope.body`.
pub type VerifiedTrace = VerifiedEnvelope;

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

    /// CIRISEdge#19 — expose a clone of the directory `Arc` so
    /// `dispatch_inbound`'s wire-layer accord-multi-sig hook can call
    /// [`VerifyDirectory::list_accord_holders`] without rebuilding the
    /// pipeline. The directory is already held inside the pipeline for
    /// the canonical verify path; the hook borrows it through this
    /// accessor for the same federation-key class lookup the
    /// `AccordCarrier` verification needs.
    #[must_use]
    pub fn directory(&self) -> Arc<dyn VerifyDirectory> {
        self.directory.clone()
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
            SchemaVersion::V2_0_0 => {}
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
