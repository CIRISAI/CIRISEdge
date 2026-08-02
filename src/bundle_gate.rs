//! CIRISEdge#437 — the build-attestation-bundle gate on the **durable**
//! transport-binding save (CIRISVerify#181, verify v10.7.0+, pinned v11.0.0).
//!
//! ## What this gates — and what it deliberately does NOT
//!
//! This is "manifest-gated KEX" territory (CIRISEdge#303): the gate applies to
//! the **durable Rooted save** (`RootingDirectory::persist_transport_binding`
//! with `BindingProvenance::Rooted`), never to in-memory routing. Routing ≠
//! trust: an unbundled peer still routes exactly as before (Advisory or Rooted
//! in the live map per the announce verdict); what it does not get, when the
//! gate is ON, is a **durably-Rooted** binding — the row a restart reloads as
//! authoritative and the CIRISEdge#432 divergence heal upgrades from. Advisory
//! saves are never gated (CC 3.3.6.2 admit-not-drop stands untouched).
//!
//! ## The verification seam (fail-closed chain)
//!
//! [`RootingDirectory::verify_peer_build_bundle`](crate::verify::RootingDirectory::verify_peer_build_bundle)
//! verifies a peer's presented bundle via
//! [`ciris_verify_core::build_attestation_bundle::verify_build_attestation_bundle`]
//! with every trust input pinned from the **federation directory** — never
//! caller-supplied, never read out of the bundle:
//!
//! - the **presenter** member is the directory row for the announce's
//!   `key_id` (the peer being saved), so a relayed third-party bundle can
//!   never satisfy this peer's gate
//!   (`BundleRejection::PresenterKeyMismatch`);
//! - the **pipeline** member + accord-co-scrubbed `KeyRecord` are the
//!   directory row named by the carried manifest's `attesting_key_id` (a
//!   *name* only — all pubkeys and the `infra:attest` blessing come from the
//!   directory row, and the co-scrub quorum from the anchors);
//! - the **accord anchors** are the directory's `identity_type =
//!   'accord_holder'` rows. No rows → refusal (fail-closed; no baked-anchor
//!   fallback is invented here).
//!
//! What a verified bundle proves — and does not — is verify's contract
//! (CIRISVerify#181): the holder of the peer's federation key signed an
//! assertion referencing an **independently-rooted** build manifest.
//! Attributable and falsifiable; NOT proof of remote execution. Per the same
//! contract the bundle is a **cacheable artifact, not a live handshake**:
//! verification is offline and cheap, nothing here ever triggers hardware ops
//! or a round-trip with the presenter, and [`TransparencyCheck::Absent`] is
//! not a failure on this SW-friendly path.
//!
//! ## Bundle arrival (CIRISEdge#436) is OUT of scope here
//!
//! Bundles enter through [`PeerBundleStore::register`] — a store/lookup seam
//! the #436 transport half (announce manifest-commitment + link-borne
//! package) will later feed. Until then the server hands bundles over via the
//! PyO3 surface (`Edge.register_peer_build_bundle`), or a deployment simply
//! leaves the gate OFF.
//!
//! [`TransparencyCheck::Absent`]: ciris_verify_core::build_attestation_bundle::TransparencyCheck::Absent

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use ciris_persist::federation::self_at_login::BindingProvenance;
use ciris_persist::federation::KeyRecord as PersistKeyRecord;
use ciris_verify_core::build_attestation_bundle::{
    verify_build_attestation_bundle, BundleRejection, BundleVerdict, BUILD_ATTESTATION_BUNDLE_KIND,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::federation_self_record::KeyRecord as VerifyKeyRecord;
use ciris_verify_core::threshold::ThresholdMember;

/// Hard byte cap on a registered peer bundle. A real bundle is a presenter
/// hybrid signature + the carried pipeline-signed manifest (+ an optional
/// Merkle inclusion proof) — ~10–15 KiB; 64 KiB is a wide margin. The cap is
/// checked BEFORE parse (cheap reject first) so an oversized blob costs
/// nothing but a length compare.
pub const MAX_PEER_BUNDLE_BYTES: usize = 64 * 1024;

/// Cap on distinct peers with a stored bundle. Bundles matter only for peers
/// that can reach a Rooted save (accord-bounded, finite — the same argument
/// as the peers-map `MAX_PEERS` eviction rationale in CIRISEdge#318); the cap
/// bounds memory against a registration flood. At cap a NEW key_id is
/// refused loudly (typed error) rather than silently evicting a possibly-good
/// bundle; an already-stored peer may always re-register (rotation).
pub const MAX_STORED_PEER_BUNDLES: usize = 256;

/// CIRISEdge#437 — enforcement posture for the bundle gate on the durable
/// Rooted transport-binding save.
///
/// **`Off` MUST be the default.** The flip to
/// [`RequireBundleForRootedSave`](Self::RequireBundleForRootedSave) is a
/// **dated fleet-floor coordination event** — the same staged-rollout
/// discipline as `TransportBindingEnforcement` (CIRISEdge#205 /
/// CIRISVerify#28 Phase 4) and
/// [`CohortScopeEnforcement`](crate::cohort_scope::CohortScopeEnforcement),
/// NOT a routine default change. Before any deployment flips it, the fleet
/// floor must hold: every peer that should persist as Rooted must be
/// producing + distributing build-attestation bundles (the CIRISEdge#436
/// arrival transport, or server-side registration via
/// `Edge.register_peer_build_bundle`), or those peers silently degrade to
/// Advisory-only durable bindings — they keep routing, but lose the
/// restart-survivable Rooted classification and the #432 heal's upgrade
/// path. Operators opt in once the floor is met; the flip date is a fleet
/// announcement, not a code change.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BundleSaveGateMode {
    /// Gate OFF — the durable save behaves exactly as before this cut
    /// (byte-identical; the gate code path is a single `match` and returns
    /// the incoming provenance untouched). **The default.**
    #[default]
    Off,
    /// A `Rooted` durable write-through requires a verified
    /// build-attestation bundle for that peer; otherwise the SAVE (never the
    /// live map) downgrades to `Advisory` with a loud named warn. Advisory
    /// saves are never gated. The flip is a dated fleet-floor event — see
    /// the enum docs.
    RequireBundleForRootedSave,
}

impl BundleSaveGateMode {
    /// Stable string-token for telemetry / config parsing.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::RequireBundleForRootedSave => "require_bundle_for_rooted_save",
        }
    }
}

/// Why [`PeerBundleStore::register`] refused a bundle. Every variant is loud
/// and typed — a refused registration must never look like a stored one.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BundleRegisterError {
    /// The blob exceeds [`MAX_PEER_BUNDLE_BYTES`].
    #[error("bundle too large: {actual} > {limit} bytes")]
    TooLarge { actual: usize, limit: usize },
    /// The blob is not a JSON `SignedCegObject`.
    #[error("bundle is not a JSON SignedCegObject: {0}")]
    NotJson(String),
    /// The object parses but is not a `build_attestation_bundle`.
    #[error("not a build_attestation_bundle (kind = {kind})")]
    WrongKind { kind: String },
    /// The store is at [`MAX_STORED_PEER_BUNDLES`] and this is a NEW peer.
    #[error("bundle store full ({cap} peers) — new peer refused, not evicted")]
    StoreFull { cap: usize },
    /// No Reticulum transport is wired on this Edge (the store lives on the
    /// transport). Surfaced by `Edge::register_peer_build_bundle`.
    #[error("no reticulum transport on this Edge — nowhere to store the bundle")]
    NoTransport,
}

/// One stored bundle: the raw bytes plus (when set) the SHA-256 of the exact
/// bytes that last verified — the verdict cache. Only VERIFIED outcomes are
/// cached; a refusal is never cached, so a late-arriving directory row (the
/// pipeline record replicating in after registration) flips the gate on the
/// next Rooted save rather than pinning the downgrade (the transit-gate
/// don't-cache-refusals honesty rule, CIRISEdge#430).
#[derive(Debug, Clone)]
struct StoredPeerBundle {
    bytes: Vec<u8>,
    verified_sha256: Option<[u8; 32]>,
}

/// CIRISEdge#437 — per-peer store of presented build-attestation bundles.
///
/// The arrival transport (CIRISEdge#436) is out of scope for this cut;
/// bundles enter via [`Self::register`] (PyO3: `Edge.register_peer_build_bundle`)
/// and are consumed by [`gated_save_provenance`] at Rooted-save time.
/// Bounded by [`MAX_PEER_BUNDLE_BYTES`] × [`MAX_STORED_PEER_BUNDLES`].
#[derive(Debug, Default)]
pub struct PeerBundleStore {
    inner: Mutex<HashMap<String, StoredPeerBundle>>,
}

impl PeerBundleStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) `key_id`'s presented bundle. Shape-gated
    /// fail-closed: size cap, JSON parse, `kind` check — garbage never
    /// occupies a store slot. Replacing an existing bundle clears its
    /// verified-cache entry (new bytes ⇒ re-verify).
    ///
    /// # Errors
    ///
    /// A typed [`BundleRegisterError`] naming the first failing check.
    pub fn register(&self, key_id: &str, bytes: &[u8]) -> Result<(), BundleRegisterError> {
        if bytes.len() > MAX_PEER_BUNDLE_BYTES {
            return Err(BundleRegisterError::TooLarge {
                actual: bytes.len(),
                limit: MAX_PEER_BUNDLE_BYTES,
            });
        }
        let parsed: SignedCegObject = serde_json::from_slice(bytes)
            .map_err(|e| BundleRegisterError::NotJson(e.to_string()))?;
        if parsed.kind != BUILD_ATTESTATION_BUNDLE_KIND {
            return Err(BundleRegisterError::WrongKind { kind: parsed.kind });
        }
        let mut map = self.inner.lock().expect("peer bundle store poisoned");
        if !map.contains_key(key_id) && map.len() >= MAX_STORED_PEER_BUNDLES {
            return Err(BundleRegisterError::StoreFull {
                cap: MAX_STORED_PEER_BUNDLES,
            });
        }
        map.insert(
            key_id.to_string(),
            StoredPeerBundle {
                bytes: bytes.to_vec(),
                verified_sha256: None,
            },
        );
        Ok(())
    }

    /// The stored bundle bytes for `key_id`, if any.
    #[must_use]
    pub fn bytes_for(&self, key_id: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .expect("peer bundle store poisoned")
            .get(key_id)
            .map(|b| b.bytes.clone())
    }

    /// Record that the bytes hashing to `sha256` verified for `key_id`.
    /// No-op if the stored bytes have changed since (a racing re-register
    /// must not inherit the old bytes' verdict).
    pub fn note_verified(&self, key_id: &str, sha256: [u8; 32]) {
        let mut map = self.inner.lock().expect("peer bundle store poisoned");
        if let Some(entry) = map.get_mut(key_id) {
            if sha256_of(&entry.bytes) == sha256 {
                entry.verified_sha256 = Some(sha256);
            }
        }
    }

    /// Is `key_id`'s stored bundle already verified at exactly these bytes?
    #[must_use]
    pub fn is_verified(&self, key_id: &str, sha256: [u8; 32]) -> bool {
        self.inner
            .lock()
            .expect("peer bundle store poisoned")
            .get(key_id)
            .is_some_and(|b| b.verified_sha256 == Some(sha256))
    }

    /// Number of peers with a stored bundle.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().expect("peer bundle store poisoned").len()
    }

    /// Is the store empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// SHA-256 of `bytes` — the store's verdict-cache key.
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(bytes).into()
}

/// Why the seam refused to produce a [`BundleVerdict`]. Distinct from
/// [`BundleRejection`] (verify's typed rejection of a well-pinned bundle):
/// these are the EDGE-side pin/plumbing failures that precede the crypto
/// chain. Every variant is a hard refusal — under the gate they all read as
/// "no verified bundle" (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleGateRefusal {
    /// No federation directory is wired (the `RootingDirectory` default
    /// impl) — nothing can be pinned, so nothing can verify.
    NoDirectory,
    /// The blob exceeds [`MAX_PEER_BUNDLE_BYTES`] (checked before parse).
    OversizedBundle { actual: usize, limit: usize },
    /// The blob is not a JSON `SignedCegObject`, or the carried manifest
    /// names no pipeline `attesting_key_id` to pin.
    MalformedBundle(&'static str),
    /// The presenter (the peer being saved) has no `federation_keys` row —
    /// there is no directory-pinned member to bind the bundle to.
    PresenterNotInDirectory { key_id: String },
    /// The pipeline key named by the carried manifest has no
    /// `federation_keys` row.
    PipelineNotInDirectory { key_id: String },
    /// The pipeline's directory row would not convert to verify's
    /// `KeyRecord` wire shape (should be unreachable — same wire shape).
    MalformedPipelineRecord { key_id: String },
    /// The directory holds no `accord_holder` rows to pin the co-scrub
    /// quorum against. Fail-closed: no anchors ⇒ no Rooted-save evidence.
    NoAccordAnchors,
    /// A directory read failed (transient) — refuse now, retry at the next
    /// Rooted save (refusals are never cached).
    DirectoryUnavailable(String),
    /// The pins held; verify's fail-closed chain rejected the bundle.
    Rejected(BundleRejection),
}

impl std::fmt::Display for BundleGateRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDirectory => write!(f, "no rooting directory wired"),
            Self::OversizedBundle { actual, limit } => {
                write!(f, "bundle too large: {actual} > {limit} bytes")
            }
            Self::MalformedBundle(what) => write!(f, "malformed bundle: {what}"),
            Self::PresenterNotInDirectory { key_id } => {
                write!(f, "presenter {key_id} not in federation directory")
            }
            Self::PipelineNotInDirectory { key_id } => {
                write!(f, "pipeline key {key_id} not in federation directory")
            }
            Self::MalformedPipelineRecord { key_id } => {
                write!(f, "pipeline directory row for {key_id} malformed")
            }
            Self::NoAccordAnchors => write!(f, "no accord_holder rows in directory"),
            Self::DirectoryUnavailable(e) => write!(f, "directory unavailable: {e}"),
            Self::Rejected(r) => write!(f, "bundle rejected: {r}"),
        }
    }
}

/// Typed outcome of the peer-bundle verification seam.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum BundleGateVerdict {
    /// The full CIRISVerify#181 chain held; the boxed [`BundleVerdict`]
    /// carries the measurements (presenter, independently-rooted build
    /// facts, transparency-leg result).
    Verified(Box<BundleVerdict>),
    /// No verdict — a typed edge-side refusal or verify-side rejection.
    Refused(BundleGateRefusal),
}

/// Pin the pipeline `key_id` NAME out of a bundle's carried manifest — the
/// only thing ever read from the object itself (all pubkeys, roles, and the
/// co-scrub quorum come from the directory rows this name selects).
#[must_use]
pub fn bundle_pipeline_key_id(bundle: &SignedCegObject) -> Option<&str> {
    bundle
        .body
        .get("manifest_contribution")?
        .get("body")?
        .get("signed_envelope")?
        .get("attesting_key_id")?
        .as_str()
}

/// A directory row as a pinned [`ThresholdMember`] (both pubkey halves;
/// classical-only rows stay hybrid-pending exactly as the directory says).
#[must_use]
pub fn threshold_member_from_row(row: &PersistKeyRecord) -> ThresholdMember {
    ThresholdMember {
        member_id: row.key_id.clone(),
        ed25519_public_key_base64: row.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: row.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    }
}

/// A persist directory row as verify's `KeyRecord`. The two are the same
/// wire shape by contract (verify's producer docs: "Serializes to
/// CIRISPersist's `KeyRecord` wire shape"), so this is a serde round-trip —
/// `registration_envelope`, scrub signatures, and `additional_scrubs` ride
/// verbatim, which is exactly what the co-scrub verification signs over.
#[must_use]
pub fn verify_key_record_from_row(row: &PersistKeyRecord) -> Option<VerifyKeyRecord> {
    let value = serde_json::to_value(row).ok()?;
    serde_json::from_value(value).ok()
}

/// The pure verification core: verify `bundle` against directory rows the
/// caller already pinned. Split from the directory-reading seam
/// ([`crate::verify::RootingDirectory::verify_peer_build_bundle`]) so the
/// crypto chain is unit-testable against the EXACT stored row shapes.
pub fn verify_bundle_with_directory_rows(
    bundle: &SignedCegObject,
    presenter_row: &PersistKeyRecord,
    pipeline_row: &PersistKeyRecord,
    anchor_rows: &[PersistKeyRecord],
) -> BundleGateVerdict {
    if anchor_rows.is_empty() {
        return BundleGateVerdict::Refused(BundleGateRefusal::NoAccordAnchors);
    }
    let presenter = threshold_member_from_row(presenter_row);
    let pipeline_member = threshold_member_from_row(pipeline_row);
    let Some(pipeline_record) = verify_key_record_from_row(pipeline_row) else {
        return BundleGateVerdict::Refused(BundleGateRefusal::MalformedPipelineRecord {
            key_id: pipeline_row.key_id.clone(),
        });
    };
    let anchors: Vec<ThresholdMember> = anchor_rows.iter().map(threshold_member_from_row).collect();
    match verify_build_attestation_bundle(
        bundle,
        &presenter,
        &pipeline_member,
        &pipeline_record,
        &anchors,
    ) {
        Ok(verdict) => BundleGateVerdict::Verified(Box::new(verdict)),
        Err(rejection) => BundleGateVerdict::Refused(BundleGateRefusal::Rejected(rejection)),
    }
}

/// CIRISEdge#437 — the single choke the durable write-through runs its
/// provenance through. Returns the provenance to PERSIST (the live map is
/// never touched here — routing ≠ trust).
///
/// - Gate [`Off`](BundleSaveGateMode::Off), or an `Advisory` save → the
///   incoming provenance, untouched (today's behavior byte-identical;
///   Advisory saves are never gated).
/// - Gate ON + `Rooted` → requires a stored bundle for `key_id` that
///   verifies via the directory-pinned seam. Verified → `Rooted` proceeds
///   (and the verdict is cached against the exact bytes). No bundle, or a
///   refused/rejected one → the SAVE downgrades to `Advisory` with a loud
///   named warn. Refusals are never cached, so a directory row that
///   replicates in later un-sticks the gate at the next Rooted save.
pub async fn gated_save_provenance(
    mode: BundleSaveGateMode,
    provenance: BindingProvenance,
    key_id: &str,
    bundles: &PeerBundleStore,
    rooting: &dyn crate::verify::RootingDirectory,
) -> BindingProvenance {
    // Advisory saves are never gated; gate Off touches nothing.
    if mode == BundleSaveGateMode::Off || provenance != BindingProvenance::Rooted {
        return provenance;
    }
    let Some(bytes) = bundles.bytes_for(key_id) else {
        tracing::warn!(
            key_id,
            gate = mode.as_str(),
            refusal = "no_bundle_registered",
            "CIRISEdge#437 bundle_gate: Rooted DURABLE save DOWNGRADED to Advisory — no \
             build-attestation bundle registered for this peer (in-memory routing untouched; \
             register the peer's bundle or hold the gate flip until the fleet floor is met)"
        );
        return BindingProvenance::Advisory;
    };
    let digest = sha256_of(&bytes);
    if bundles.is_verified(key_id, digest) {
        tracing::debug!(
            key_id,
            "CIRISEdge#437 bundle_gate: cached verified bundle — Rooted durable save proceeds"
        );
        return BindingProvenance::Rooted;
    }
    match rooting.verify_peer_build_bundle(key_id, &bytes).await {
        BundleGateVerdict::Verified(verdict) => {
            bundles.note_verified(key_id, digest);
            tracing::info!(
                key_id,
                target = %verdict.build.target,
                build_id = %verdict.build.build_id,
                binary_version = %verdict.build.binary_version,
                transparency = ?verdict.transparency,
                "CIRISEdge#437 bundle_gate: peer bundle VERIFIED against directory pins — \
                 Rooted durable save proceeds"
            );
            BindingProvenance::Rooted
        }
        BundleGateVerdict::Refused(refusal) => {
            tracing::warn!(
                key_id,
                gate = mode.as_str(),
                refusal = %refusal,
                "CIRISEdge#437 bundle_gate: Rooted DURABLE save DOWNGRADED to Advisory — the \
                 registered bundle did not verify (in-memory routing untouched; refusals are \
                 not cached, the next Rooted save re-checks)"
            );
            BindingProvenance::Advisory
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::types::identity_type;
    use ciris_persist::federation::FederationDirectory;
    use ciris_persist::store::MemoryBackend;
    use ciris_verify_core::build_attestation_bundle::{
        produce_build_attestation_bundle, BundleInputs,
    };
    use ciris_verify_core::federation_self_record::{produce_multiscrub_key_record, ScrubTarget};
    use ciris_verify_core::manifest_contribution::{
        sign_build_manifest_contribution, BuildAttestation,
    };
    use ciris_verify_core::self_at_login::HybridSigningIdentity;

    use crate::verify::{ProvenanceChain, RootingDirectory, RootingRejection, RootingVerdict};

    const TS: &str = "2026-08-02T00:00:00Z";
    const PRESENTER: &str = "presenter-437";
    const PIPELINE: &str = "ci-pipeline-437";
    const TARGET: &str = "x86_64-unknown-linux-gnu";

    /// A rooting backend with NO directory — every seam call must take the
    /// default-impl `NoDirectory` refusal. The two required methods are
    /// unreachable in these tests by construction.
    struct NoDirectoryRooting;

    #[async_trait::async_trait]
    impl RootingDirectory for NoDirectoryRooting {
        async fn root_binding(&self, _key_id: &str, _claimed: &str) -> RootingVerdict {
            unreachable!("bundle-gate tests never root announces")
        }
        async fn provenance_chain(
            &self,
            _key_id: &str,
        ) -> Result<ProvenanceChain, RootingRejection> {
            unreachable!("bundle-gate tests never walk chains")
        }
    }

    /// A minimal well-shaped (but crypto-empty) bundle blob — enough to pass
    /// the registration shape gate, never enough to verify.
    fn shaped_bundle_bytes(key_id: &str) -> Vec<u8> {
        let obj = SignedCegObject::new(
            BUILD_ATTESTATION_BUNDLE_KIND,
            key_id,
            TS,
            serde_json::json!({}),
        );
        serde_json::to_vec(&obj).expect("serialize shaped bundle")
    }

    /// The exact fresh Android/Strongbox evidence blob persist's
    /// `test_support::fresh_accord_holder_evidence` emits — inlined (the
    /// `replication::bridge` precedent) so these tests do not gate on the
    /// `test-anchor` feature.
    fn accord_holder_evidence() -> serde_json::Value {
        serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        [0x30, 0x82, 0x01, 0x00],
                        [0x30, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        })
    }

    /// A `federation_keys` row for a minted hybrid identity — real pubkeys
    /// (both halves), fixture scrub fields (persist's memory backend does
    /// not verify self-scrub signatures at admission; the co-scrub gates
    /// only fire for privileged roles).
    fn row_for_identity(
        id: &HybridSigningIdentity,
        it: &str,
        evidence: Option<serde_json::Value>,
    ) -> ciris_persist::federation::KeyRecord {
        let member = id.directory_member().expect("directory member");
        ciris_persist::federation::KeyRecord {
            key_id: id.key_id().to_string(),
            pubkey_ed25519_base64: member.ed25519_public_key_base64,
            pubkey_ml_dsa_65_base64: member.mldsa65_public_key_base64,
            algorithm: "hybrid".to_string(),
            identity_type: it.to_string(),
            identity_ref: format!("ref-{}", id.key_id()),
            valid_from: chrono::Utc::now(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "key_id": id.key_id() }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: id.key_id().to_string(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: evidence,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// The full field fixture: a `MemoryBackend` federation directory holding
    /// - two accord-anchor rows REGISTERED UNDER the effective genesis
    ///   roster `key_id`s (the ids persist's `infra:attest` admission gate
    ///   resolves) with OUR minted pubkeys + hardware evidence,
    /// - the pipeline's accord-co-scrubbed `infra:attest` record, admitted
    ///   through persist's REAL role-admission gate (the co-scrub verifies
    ///   against the anchor rows above),
    /// - the presenter's plain node row,
    ///
    /// plus a VALID bundle minted with verify's own producers — the exact
    /// artifact chain the field presents.
    async fn field_fixture() -> (MemoryBackend, Vec<u8>) {
        let backend = MemoryBackend::new();

        // The roster ids the admission quorum resolves — derived, not
        // invented, so the fixture tracks whichever genesis is effective.
        let roster: Vec<String> =
            ciris_persist::federation::genesis::effective_accord_holder_records()
                .iter()
                .map(|r| r.record.key_id.clone())
                .collect();
        assert!(roster.len() >= 2, "genesis roster must seat >= 2 holders");
        let a1 = HybridSigningIdentity::generate(roster[0].clone()).expect("anchor 1");
        let a2 = HybridSigningIdentity::generate(roster[1].clone()).expect("anchor 2");
        for anchor in [&a1, &a2] {
            FederationDirectory::put_public_key(
                &backend,
                ciris_persist::federation::SignedKeyRecord {
                    record: row_for_identity(
                        anchor,
                        identity_type::ACCORD_HOLDER,
                        Some(accord_holder_evidence()),
                    ),
                },
            )
            .await
            .expect("seed accord anchor row");
        }

        // The pipeline key, blessed for `infra:attest` by a REAL 2-anchor
        // co-scrub (verify's own producer), admitted through persist's REAL
        // role gate — no fixture backdoor.
        let pipeline = HybridSigningIdentity::generate(PIPELINE).expect("pipeline identity");
        let pm = pipeline.directory_member().expect("pipeline member");
        let pipeline_record = produce_multiscrub_key_record(
            &[&a1, &a2],
            ScrubTarget {
                key_id: PIPELINE.to_string(),
                pubkey_ed25519_base64: pm.ed25519_public_key_base64.clone(),
                pubkey_ml_dsa_65_base64: pm
                    .mldsa65_public_key_base64
                    .clone()
                    .expect("hybrid pipeline key"),
                identity_type: "node".to_string(),
                roles: vec!["infra:attest".to_string()],
            },
            TS,
            &[],
        )
        .await
        .expect("co-scrubbed pipeline record")
        .record;
        // verify's KeyRecord IS persist's wire shape — serde round-trip.
        let persist_pipeline_record: ciris_persist::federation::KeyRecord = serde_json::from_value(
            serde_json::to_value(&pipeline_record).expect("serialize pipeline record"),
        )
        .expect("pipeline record converts to persist wire shape");
        FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord {
                record: persist_pipeline_record,
            },
        )
        .await
        .expect("pipeline record admits through persist's infra:attest co-scrub gate");

        // The presenter — a plain node row with its real pubkeys.
        let presenter = HybridSigningIdentity::generate(PRESENTER).expect("presenter identity");
        FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord {
                record: row_for_identity(&presenter, identity_type::NODE, None),
            },
        )
        .await
        .expect("seed presenter row");

        // The pipeline-signed manifest + the presenter-signed bundle —
        // verify's own producers, the exact field artifacts.
        let bh = "aa".repeat(32);
        let mh = "bb".repeat(32);
        let manifest = sign_build_manifest_contribution(
            &pipeline,
            &BuildAttestation {
                target: TARGET,
                binary_hash: &bh,
                build_id: "build-437",
                binary_version: "15.11.0",
                manifest_hash: &mh,
            },
            "human-1",
            "grant-1",
            TS,
        )
        .await
        .expect("pipeline-signed manifest");
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                manifest_contribution: &manifest,
                inclusion: None,
            },
            TS,
        )
        .await
        .expect("presenter-signed bundle");
        let bytes = serde_json::to_vec(&bundle).expect("serialize bundle");
        (backend, bytes)
    }

    /// Flip the carried manifest's binary_hash AFTER signing — the
    /// evidence-swap the commitment must catch.
    fn tampered(bytes: &[u8]) -> Vec<u8> {
        let mut bundle: SignedCegObject = serde_json::from_slice(bytes).expect("parse bundle");
        bundle.body["manifest_contribution"]["body"]["signed_envelope"]["build"]["binary_hash"] =
            serde_json::json!("00".repeat(32));
        serde_json::to_vec(&bundle).expect("serialize tampered bundle")
    }

    // ── Store: registration shape gate + bounds + verdict cache ────────

    #[test]
    fn store_shape_gates_and_caps_at_registration() {
        let store = PeerBundleStore::new();

        // Oversized → typed refusal BEFORE parse.
        let big = vec![b'x'; MAX_PEER_BUNDLE_BYTES + 1];
        assert_eq!(
            store.register("p", &big),
            Err(BundleRegisterError::TooLarge {
                actual: MAX_PEER_BUNDLE_BYTES + 1,
                limit: MAX_PEER_BUNDLE_BYTES,
            })
        );
        // Not JSON → typed refusal.
        assert!(matches!(
            store.register("p", b"not json"),
            Err(BundleRegisterError::NotJson(_))
        ));
        // Wrong kind → typed refusal (garbage never occupies a slot).
        let wrong = SignedCegObject::new("self_login", "p", TS, serde_json::json!({}));
        assert_eq!(
            store.register("p", &serde_json::to_vec(&wrong).unwrap()),
            Err(BundleRegisterError::WrongKind {
                kind: "self_login".to_string(),
            })
        );
        assert!(store.is_empty(), "refused registrations store nothing");

        // A well-shaped bundle registers; replacement is allowed.
        let ok = shaped_bundle_bytes("p");
        assert_eq!(store.register("p", &ok), Ok(()));
        assert_eq!(store.len(), 1);

        // At cap, a NEW peer is refused loudly; an EXISTING peer may
        // re-register (rotation) — never a silent eviction.
        for i in 1..MAX_STORED_PEER_BUNDLES {
            store
                .register(&format!("peer-{i}"), &ok)
                .expect("under cap registers");
        }
        assert_eq!(store.len(), MAX_STORED_PEER_BUNDLES);
        assert_eq!(
            store.register("one-too-many", &ok),
            Err(BundleRegisterError::StoreFull {
                cap: MAX_STORED_PEER_BUNDLES,
            })
        );
        assert_eq!(
            store.register("p", &ok),
            Ok(()),
            "existing peer re-registers at cap"
        );
    }

    #[test]
    fn verdict_cache_is_per_exact_bytes_and_resets_on_replace() {
        let store = PeerBundleStore::new();
        let bytes = shaped_bundle_bytes("p");
        store.register("p", &bytes).expect("register");
        let digest = sha256_of(&bytes);

        assert!(!store.is_verified("p", digest), "nothing verified yet");
        // A stale digest (bytes that are not the stored ones) never caches.
        store.note_verified("p", [0u8; 32]);
        assert!(!store.is_verified("p", [0u8; 32]));
        // The exact stored bytes' digest caches.
        store.note_verified("p", digest);
        assert!(store.is_verified("p", digest));
        // Re-registration (even of the same bytes) resets the cache — new
        // registration, fresh verification.
        store.register("p", &bytes).expect("re-register");
        assert!(
            !store.is_verified("p", digest),
            "replace clears the verdict cache"
        );
    }

    // ── The seam + the gate, end to end against the field artifacts ────

    /// CIRISEdge#437 acceptance — with the EXACT artifacts the field
    /// presents (verify-minted bundle, persist-admitted directory rows):
    /// gate ON + verified bundle → the Rooted durable save proceeds (and
    /// the verdict caches against the exact bytes).
    #[tokio::test]
    async fn verified_bundle_with_gate_on_lets_the_rooted_save_proceed() {
        let (backend, bytes) = field_fixture().await;

        // The seam, driven exactly as the gate drives it.
        let verdict = RootingDirectory::verify_peer_build_bundle(&backend, PRESENTER, &bytes).await;
        let BundleGateVerdict::Verified(v) = verdict else {
            panic!("expected Verified, got {verdict:?}");
        };
        assert_eq!(v.presenter_key_id, PRESENTER);
        assert_eq!(v.build.target, TARGET);
        assert_eq!(v.build.build_id, "build-437");

        // The gate: Rooted stays Rooted, and the verdict caches.
        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register bundle");
        let saved = gated_save_provenance(
            BundleSaveGateMode::RequireBundleForRootedSave,
            BindingProvenance::Rooted,
            PRESENTER,
            &store,
            &backend,
        )
        .await;
        assert_eq!(saved, BindingProvenance::Rooted);
        assert!(
            store.is_verified(PRESENTER, sha256_of(&bytes)),
            "verified outcome is cached against the exact bytes"
        );
        // Cache hit path returns the same answer.
        let saved_again = gated_save_provenance(
            BundleSaveGateMode::RequireBundleForRootedSave,
            BindingProvenance::Rooted,
            PRESENTER,
            &store,
            &backend,
        )
        .await;
        assert_eq!(saved_again, BindingProvenance::Rooted);
    }

    /// CIRISEdge#437 acceptance — gate ON + no bundle, or a tampered one:
    /// the Rooted SAVE downgrades to Advisory; refusals are never cached.
    /// Advisory saves are never gated.
    #[tokio::test]
    async fn missing_or_tampered_bundle_with_gate_on_downgrades_the_save() {
        let (backend, bytes) = field_fixture().await;
        let store = PeerBundleStore::new();

        // No bundle registered → downgrade.
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Advisory
        );

        // A tampered bundle: the seam rejects it (evidence-commitment
        // mismatch) and the save downgrades.
        let bad = tampered(&bytes);
        let verdict = RootingDirectory::verify_peer_build_bundle(&backend, PRESENTER, &bad).await;
        assert_eq!(
            verdict,
            BundleGateVerdict::Refused(BundleGateRefusal::Rejected(
                BundleRejection::EvidenceCommitmentMismatch
            ))
        );
        store
            .register(PRESENTER, &bad)
            .expect("tampered blob is still shaped");
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Advisory
        );
        assert!(
            !store.is_verified(PRESENTER, sha256_of(&bad)),
            "a refusal is NEVER cached — the next Rooted save re-checks"
        );

        // Advisory saves are never gated — even with no/invalid bundle.
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Advisory,
                "peer-without-bundle",
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Advisory
        );
    }

    /// CIRISEdge#437 acceptance — gate OFF is byte-identical to today: the
    /// provenance passes through untouched for BOTH values, with an empty
    /// store and no directory work (a `NoDirectoryRooting` whose required
    /// methods are unreachable proves the gate touches nothing when Off).
    #[tokio::test]
    async fn gate_off_passes_both_provenances_through_untouched() {
        let store = PeerBundleStore::new();
        for provenance in [BindingProvenance::Rooted, BindingProvenance::Advisory] {
            assert_eq!(
                gated_save_provenance(
                    BundleSaveGateMode::Off,
                    provenance,
                    PRESENTER,
                    &store,
                    &NoDirectoryRooting,
                )
                .await,
                provenance
            );
        }
        assert_eq!(BundleSaveGateMode::default(), BundleSaveGateMode::Off);
        assert_eq!(BundleSaveGateMode::Off.as_str(), "off");
        assert_eq!(
            BundleSaveGateMode::RequireBundleForRootedSave.as_str(),
            "require_bundle_for_rooted_save"
        );
    }

    /// The presenter binding is load-bearing at THIS seam too: the SAME
    /// valid bundle checked for a DIFFERENT directory peer (a relay trying
    /// to wear someone else's bundle) refuses with the typed mismatch.
    #[tokio::test]
    async fn a_relayed_bundle_cannot_satisfy_another_peers_gate() {
        let (backend, bytes) = field_fixture().await;
        let verdict = RootingDirectory::verify_peer_build_bundle(&backend, PIPELINE, &bytes).await;
        assert!(
            matches!(
                verdict,
                BundleGateVerdict::Refused(BundleGateRefusal::Rejected(
                    BundleRejection::PresenterKeyMismatch { .. }
                ))
            ),
            "expected PresenterKeyMismatch, got {verdict:?}"
        );
    }

    /// Pin failures are typed and fail-closed: an unknown presenter, then an
    /// unknown pipeline row, each refuse by name; malformed / oversized
    /// blobs refuse before any directory read.
    #[tokio::test]
    async fn missing_directory_pins_refuse_by_name() {
        let (_seeded, bytes) = field_fixture().await;
        let empty = MemoryBackend::new();

        // No presenter row.
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&empty, PRESENTER, &bytes).await,
            BundleGateVerdict::Refused(BundleGateRefusal::PresenterNotInDirectory {
                key_id: PRESENTER.to_string(),
            })
        );

        // Presenter present, pipeline row absent. (The pubkeys need not
        // match the bundle for THIS arm — the pin failure fires before any
        // signature check.)
        let presenter_only = MemoryBackend::new();
        let presenter = HybridSigningIdentity::generate(PRESENTER).expect("presenter");
        FederationDirectory::put_public_key(
            &presenter_only,
            ciris_persist::federation::SignedKeyRecord {
                record: row_for_identity(&presenter, identity_type::NODE, None),
            },
        )
        .await
        .expect("seed presenter row");
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&presenter_only, PRESENTER, &bytes).await,
            BundleGateVerdict::Refused(BundleGateRefusal::PipelineNotInDirectory {
                key_id: PIPELINE.to_string(),
            })
        );

        // Malformed / oversized blobs refuse before any directory read.
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&empty, PRESENTER, b"not json").await,
            BundleGateVerdict::Refused(BundleGateRefusal::MalformedBundle(
                "not a JSON SignedCegObject"
            ))
        );
        let big = vec![b'x'; MAX_PEER_BUNDLE_BYTES + 1];
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&empty, PRESENTER, &big).await,
            BundleGateVerdict::Refused(BundleGateRefusal::OversizedBundle {
                actual: MAX_PEER_BUNDLE_BYTES + 1,
                limit: MAX_PEER_BUNDLE_BYTES,
            })
        );
    }

    /// The anchor pin is fail-closed at the PURE core: zero accord rows →
    /// `NoAccordAnchors` (never an empty-quorum pass). And the default
    /// trait impl (no directory at all) refuses as `NoDirectory` — which
    /// under the gate downgrades the save.
    #[tokio::test]
    async fn no_anchors_and_no_directory_both_fail_closed() {
        let (backend, bytes) = field_fixture().await;
        let bundle: SignedCegObject = serde_json::from_slice(&bytes).expect("parse");
        let presenter_row = FederationDirectory::lookup_public_key(&backend, PRESENTER)
            .await
            .expect("lookup")
            .expect("presenter row");
        let pipeline_row = FederationDirectory::lookup_public_key(&backend, PIPELINE)
            .await
            .expect("lookup")
            .expect("pipeline row");
        assert_eq!(
            verify_bundle_with_directory_rows(&bundle, &presenter_row, &pipeline_row, &[]),
            BundleGateVerdict::Refused(BundleGateRefusal::NoAccordAnchors)
        );

        // Default trait impl: typed NoDirectory refusal…
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&NoDirectoryRooting, PRESENTER, &bytes)
                .await,
            BundleGateVerdict::Refused(BundleGateRefusal::NoDirectory)
        );
        // …and under the gate that downgrades the save (fail-closed).
        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                &store,
                &NoDirectoryRooting,
            )
            .await,
            BindingProvenance::Advisory
        );
    }
}
