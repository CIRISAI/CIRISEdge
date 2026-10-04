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
//! saves are never gated (admit-not-drop stands untouched — CC 3.3, authorization
//! is consumer-policy, not wire; CC 3.3.6.2 is the authenticated binding itself).
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
//! - the **pipeline** member is the directory row named by the carried
//!   manifest's signed `row.attesting_key_id` (a *name* only — the pubkeys
//!   come from the directory row);
//! - the pipeline's **standing** to attest builds (`infra:attest`) is a
//!   [`PipelineBlessing`] from persist, asked from THIS node's trust root
//!   ([`pipeline_blessing`]). CC 3.1.2.1 (rc6 22ea349) names two planes and a
//!   reader MUST ask both before it finds no standing: the capability walk
//!   (`capability_roots_to_trusted_root(dir, reader, pipeline,
//!   "infra:attest")`, a `trust:confers:v1` grant from a root this node
//!   accepts), then, only if the walk finds none, the ceremony plane
//!   (`admission::is_infra_attest_effective`, the accord co-scrub of
//!   `infra:attest` onto the pipeline's own record, minus any quorum
//!   withdrawal). Both say no → refusal. Production pipelines stand on the
//!   second plane (the CIRISServer `/v1/accord/ci-key` ceremony), so a
//!   walk-only gate would refuse every production build.
//!
//! Until verify 19 the gate handed verify the pipeline's key record and the
//! directory's `accord_holder` rows and let verify re-check the co-scrub. That
//! copy could not see a quorum role-withdrawal, so a withdrawn pipeline still
//! verified (CIRISEdge#786); the substrate, which sees withdrawals, now
//! answers.
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
//! ## Bundle arrival (CIRISEdge#436)
//!
//! Bundles enter through [`PeerBundleStore::register`] — a store/lookup seam
//! fed by the #436 arrival transport (the announce carries a 32-byte
//! [`manifest commitment`](manifest_commitment_of_bundle); the package rides
//! the established link as a `CBND` frame — see
//! `transport::reticulum::process_peer_bundle_frame` for the one-motion
//! Advisory→Rooted upgrade it drives) and/or by the server via the PyO3
//! surface (`Edge.register_peer_build_bundle`).
//!
//! [`TransparencyCheck::Absent`]: ciris_verify_core::build_attestation_bundle::TransparencyCheck::Absent

use std::collections::HashMap;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use ciris_persist::federation::self_at_login::BindingProvenance;
use ciris_persist::federation::trust_root::{capability_roots_to_trusted_root, ConferralPlane};
use ciris_persist::federation::{FederationDirectory, KeyRecord as PersistKeyRecord};
use ciris_verify_core::build_attestation_bundle::{
    verify_build_attestation_bundle, BundleRejection, BundleVerdict, BUILD_ATTESTATION_BUNDLE_KIND,
};
use ciris_verify_core::ceg_outbox::SignedCegObject;
use ciris_verify_core::manifest_contribution::{
    PipelineBlessing, WalkPlane, MANIFEST_PUBLISH_SCOPE,
};
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

/// One stored bundle: the raw bytes plus (when set) what the last
/// verification of exactly these bytes established — the verdict cache. Only
/// VERIFIED outcomes are cached; a refusal is never cached, so a late-arriving
/// directory row (the pipeline record replicating in after registration)
/// flips the gate on the next Rooted save rather than pinning the downgrade
/// (the transit-gate don't-cache-refusals honesty rule, CIRISEdge#430).
#[derive(Debug, Clone)]
struct StoredPeerBundle {
    bytes: Vec<u8>,
    verified: Option<VerifiedBundle>,
}

/// CIRISEdge#793 — what a verification of one bundle's bytes established.
/// The bytes-dependent work (decode, the signature chain against the pinned
/// rows) is cached against `sha256`. The pipeline's STANDING is not a
/// property of the bytes (CC 3.1.2.1: the reader evaluates it at use, and a
/// withdrawal, a dropped root or a de-rooted root changes it with the bundle
/// unchanged), so the blessing the verification ran under is kept only to be
/// compared with a fresh [`pipeline_blessing`] at every use, and it is
/// reader-relative: a cached verdict serves only the reader it was asked for.
#[derive(Debug, Clone)]
struct VerifiedBundle {
    sha256: [u8; 32],
    reader_key_id: String,
    blessing: PipelineBlessing,
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
                verified: None,
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

    /// Record that the bytes hashing to `sha256` verified for `key_id`, read
    /// by `reader_key_id`, under the standing `verdict` names (CIRISEdge#793:
    /// kept to be re-checked at each use, never trusted from the cache).
    /// No-op if the stored bytes have changed since (a racing re-register
    /// must not inherit the old bytes' verdict).
    pub fn note_verified(
        &self,
        key_id: &str,
        sha256: [u8; 32],
        reader_key_id: &str,
        verdict: &BundleVerdict,
    ) {
        let mut map = self.inner.lock().expect("peer bundle store poisoned");
        if let Some(entry) = map.get_mut(key_id) {
            if sha256_of(&entry.bytes) == sha256 {
                entry.verified = Some(VerifiedBundle {
                    sha256,
                    reader_key_id: reader_key_id.to_owned(),
                    blessing: PipelineBlessing {
                        pipeline_key_id: verdict.build.attested_by.clone(),
                        standing: verdict.build.standing.clone(),
                    },
                });
            }
        }
    }

    /// Is `key_id`'s stored bundle already verified at exactly these bytes?
    /// The bytes' answer only — whether the pipeline still has standing is
    /// asked at use ([`gated_save_provenance`], CIRISEdge#793).
    #[must_use]
    pub fn is_verified(&self, key_id: &str, sha256: [u8; 32]) -> bool {
        self.inner
            .lock()
            .expect("peer bundle store poisoned")
            .get(key_id)
            .is_some_and(|b| b.verified.as_ref().is_some_and(|v| v.sha256 == sha256))
    }

    /// CIRISEdge#793 — the blessing `key_id`'s bundle verified under, if
    /// these exact bytes verified for `reader_key_id`. The caller re-resolves
    /// the standing and compares; this never answers "still has standing".
    fn verified_blessing(
        &self,
        key_id: &str,
        sha256: [u8; 32],
        reader_key_id: &str,
    ) -> Option<PipelineBlessing> {
        self.inner
            .lock()
            .expect("peer bundle store poisoned")
            .get(key_id)
            .and_then(|b| b.verified.as_ref())
            .filter(|v| v.sha256 == sha256 && v.reader_key_id == reader_key_id)
            .map(|v| v.blessing.clone())
    }

    /// CIRISEdge#793 — drop `key_id`'s cached verdict (its pipeline lost
    /// standing): the next use verifies from scratch.
    fn forget_verified(&self, key_id: &str) {
        if let Some(entry) = self
            .inner
            .lock()
            .expect("peer bundle store poisoned")
            .get_mut(key_id)
        {
            entry.verified = None;
        }
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
#[non_exhaustive]
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
    /// Neither standing plane blesses the pipeline for `infra:attest`: the
    /// capability walk from this node found no grant from a root it accepts,
    /// and the ceremony plane finds no effective accord co-scrub (absent, or
    /// withdrawn by quorum). See [`pipeline_blessing`].
    PipelineWithoutStanding { key_id: String },
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
            Self::PipelineWithoutStanding { key_id } => write!(
                f,
                "pipeline key {key_id} holds infra:attest on neither standing plane"
            ),
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

/// CIRISEdge#436 — the 32-byte **manifest commitment** an announce carries:
/// `sha256(JCS(manifest_contribution))` over the manifest the bundle carries.
///
/// This is deliberately the SAME canonical preimage verify's bundle producer
/// signs as `manifest_contribution_sha256` (CIRISVerify#181,
/// `build_attestation_bundle::commitment_hex`) and uses as the transparency
/// leaf — so the announce commitment, the bundle-internal commitment, and the
/// log leaf can never drift. Sender and receiver both derive it from their
/// copy of the bundle bytes with this one function; equality means the
/// link-borne package IS the package the announce committed to.
///
/// `None` for anything that is not a well-shaped `build_attestation_bundle`
/// carrying a canonicalizable `manifest_contribution` (fail-closed: no
/// commitment ⇒ nothing to announce / nothing to match).
#[must_use]
pub fn manifest_commitment_of_bundle(bundle_bytes: &[u8]) -> Option<[u8; 32]> {
    let bundle: SignedCegObject = serde_json::from_slice(bundle_bytes).ok()?;
    if bundle.kind != BUILD_ATTESTATION_BUNDLE_KIND {
        return None;
    }
    let manifest = bundle.body.get("manifest_contribution")?;
    let canonical = ciris_verify_core::jcs::canonicalize(manifest).ok()?;
    Some(sha2::Sha256::digest(canonical).into())
}

/// Pin the pipeline `key_id` NAME out of a bundle's carried manifest — the
/// only thing ever read from the object itself (all pubkeys come from the
/// directory row this name selects, and the standing from
/// [`pipeline_blessing`]). Verify 19 signs the attester into the envelope's
/// `row` mirror (CIRISPersist#643) and checks it against the pinned member.
#[must_use]
pub fn bundle_pipeline_key_id(bundle: &SignedCegObject) -> Option<&str> {
    bundle
        .body
        .get("manifest_contribution")?
        .get("body")?
        .get("signed_envelope")?
        .get("row")?
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

/// CC 3.1.2.1 (rc6 22ea349) — does `pipeline_key_id` hold `infra:attest`,
/// asked from `reader_key_id`'s trust root? Both standing planes, in order,
/// and `None` only when both say no:
///
/// 1. persist's capability walk, `capability_roots_to_trusted_root(dir,
///    reader, pipeline, "infra:attest")` — reader-relative: a grant from a
///    root this node accepts. Its `AccordCoScrub` arm answers the ceremony
///    question (the co-scrubbed role, not withdrawn) for a subject that is
///    also a valid root, so it maps to [`PipelineBlessing::accord_role`], as
///    CIRISRegistry's door does.
/// 2. Only if the walk finds nothing: `admission::is_infra_attest_effective`
///    — the accord co-scrub of `infra:attest` onto the pipeline's own key
///    record, minus any quorum withdrawal. Not reader-relative.
///
/// # Errors
///
/// A directory read failure from either plane (transient; the caller refuses
/// now and asks again at the next save).
pub async fn pipeline_blessing(
    directory: &dyn FederationDirectory,
    reader_key_id: &str,
    pipeline_key_id: &str,
) -> Result<Option<PipelineBlessing>, ciris_persist::federation::Error> {
    if let Some(grant) = capability_roots_to_trusted_root(
        directory,
        reader_key_id,
        pipeline_key_id,
        MANIFEST_PUBLISH_SCOPE,
    )
    .await?
    {
        let conferred = |plane| {
            PipelineBlessing::conferred(
                pipeline_key_id,
                grant.root_key_id.clone(),
                grant.grant_attestation_id.clone(),
                plane,
            )
        };
        return Ok(Some(match grant.conferral_plane {
            ConferralPlane::Delegation => conferred(WalkPlane::Delegation),
            ConferralPlane::FamilyQuorum => conferred(WalkPlane::FamilyQuorum),
            ConferralPlane::AccordCoScrub => PipelineBlessing::accord_role(pipeline_key_id),
        }));
    }
    let by_role =
        ciris_persist::federation::admission::is_infra_attest_effective(directory, pipeline_key_id)
            .await?;
    Ok(by_role.then(|| PipelineBlessing::accord_role(pipeline_key_id)))
}

/// The pure verification core: verify `bundle` against directory rows and a
/// [`PipelineBlessing`] the caller already pinned. Split from the
/// directory-reading seam
/// ([`crate::verify::RootingDirectory::verify_peer_build_bundle`]) so the
/// crypto chain is unit-testable against the EXACT stored row shapes.
pub fn verify_bundle_with_directory_rows(
    bundle: &SignedCegObject,
    presenter_row: &PersistKeyRecord,
    pipeline_row: &PersistKeyRecord,
    blessing: &PipelineBlessing,
) -> BundleGateVerdict {
    let presenter = threshold_member_from_row(presenter_row);
    let pipeline_member = threshold_member_from_row(pipeline_row);
    match verify_build_attestation_bundle(bundle, &presenter, &pipeline_member, blessing) {
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
/// - CIRISEdge#793 — a cached verdict skips only the bytes-dependent work.
///   The pipeline's standing is re-resolved at EVERY use
///   ([`RootingDirectory::pipeline_standing`](crate::verify::RootingDirectory::pipeline_standing),
///   [`pipeline_blessing`]) for the reader now asking: the same blessing →
///   `Rooted`; none (the grant or co-scrub withdrawn, the root no longer
///   accepted or rooted) → `Advisory` and the cache entry is dropped; a
///   different blessing → a full re-verification under it.
pub async fn gated_save_provenance(
    mode: BundleSaveGateMode,
    provenance: BindingProvenance,
    key_id: &str,
    reader_key_id: &str,
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
    if let Some(cached) = bundles.verified_blessing(key_id, digest, reader_key_id) {
        match rooting
            .pipeline_standing(reader_key_id, &cached.pipeline_key_id)
            .await
        {
            Ok(Some(now)) if now == cached => {
                tracing::debug!(
                    key_id,
                    "CIRISEdge#437 bundle_gate: cached verified bundle, standing re-checked \
                     (CIRISEdge#793) — Rooted durable save proceeds"
                );
                return BindingProvenance::Rooted;
            }
            // The standing moved planes or roots: verify again under it.
            Ok(Some(_)) => {}
            Ok(None) => {
                bundles.forget_verified(key_id);
                tracing::warn!(
                    key_id,
                    gate = mode.as_str(),
                    pipeline = %cached.pipeline_key_id,
                    refusal = "pipeline_without_standing",
                    "CIRISEdge#793 bundle_gate: Rooted DURABLE save DOWNGRADED to Advisory — the \
                     cached bundle's pipeline no longer holds infra:attest on either standing \
                     plane from this node (withdrawn, or its root is no longer accepted)"
                );
                return BindingProvenance::Advisory;
            }
            Err(refusal) => {
                tracing::warn!(
                    key_id,
                    gate = mode.as_str(),
                    refusal = %refusal,
                    "CIRISEdge#793 bundle_gate: Rooted DURABLE save DOWNGRADED to Advisory — the \
                     cached bundle's standing could not be re-checked (refusals are not cached; \
                     the next Rooted save asks again)"
                );
                return BindingProvenance::Advisory;
            }
        }
    }
    match rooting
        .verify_peer_build_bundle(reader_key_id, key_id, &bytes)
        .await
    {
        BundleGateVerdict::Verified(verdict) => {
            bundles.note_verified(key_id, digest, reader_key_id, &verdict);
            tracing::info!(
                key_id,
                target = %verdict.build.target,
                build_id = %verdict.build.build_id,
                binary_version = %verdict.build.binary_version,
                standing = verdict.build.standing.plane_str(),
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

/// CIRISEdge#436/#437 shared test fixture — the FIELD-provenance artifact
/// chain: a `MemoryBackend` federation directory seeded through persist's REAL
/// admission gates, plus a valid bundle minted with verify's own producers.
/// `pub(crate)` so the #436 arrival-transport tests (`transport::reticulum`)
/// drive the exact same artifacts the #437 gate tests pinned — one fixture,
/// never two that drift.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{SignedCegObject, BUILD_ATTESTATION_BUNDLE_KIND};
    use ciris_persist::federation::types::identity_type;
    use ciris_persist::federation::FederationDirectory;
    use ciris_persist::store::MemoryBackend;
    use ciris_verify_core::build_attestation_bundle::{
        produce_build_attestation_bundle, BundleInputs, PresentedBuild,
    };
    use ciris_verify_core::federation_self_record::{produce_multiscrub_key_record, ScrubTarget};
    use ciris_verify_core::manifest_contribution::{
        sign_build_manifest_contribution, BuildAttestation,
    };
    use ciris_verify_core::self_at_login::HybridSigningIdentity;

    pub(crate) const TS: &str = "2026-08-02T00:00:00Z";
    pub(crate) const PRESENTER: &str = "presenter-437";
    pub(crate) const PIPELINE: &str = "ci-pipeline-437";
    pub(crate) const TARGET: &str = "x86_64-unknown-linux-gnu";
    /// The node READING the bundle — whose trust root the capability walk
    /// asks from (CIRISEdge#786). Under the ceremony plane it does not matter.
    pub(crate) const READER: &str = "reader-786";

    /// [`TS`] as the instant verify 19's producers sign.
    pub(crate) fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(TS)
            .expect("fixture instant")
            .with_timezone(&chrono::Utc)
    }

    /// A minimal well-shaped (but crypto-empty) bundle blob — enough to pass
    /// the registration shape gate, never enough to verify.
    pub(crate) fn shaped_bundle_bytes(key_id: &str) -> Vec<u8> {
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
    pub(crate) fn accord_holder_evidence() -> serde_json::Value {
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
    pub(crate) fn row_for_identity(
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
    pub(crate) async fn field_fixture() -> (MemoryBackend, Vec<u8>) {
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
            // CIRISVerify v14.0.0 — `valid_until` is a new parameter between
            // `valid_from` and the transport hints. `None` is this fixture's
            // pre-v14 behaviour: no producer-stated expiry.
            None,
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

        let bytes = seed_presenter_and_mint_bundle(&backend, &pipeline).await;
        (backend, bytes)
    }

    /// CIRISEdge#786 — the same artifact chain with NO standing on either
    /// plane: the pipeline is a plain `node` row (no `infra:attest`, no
    /// co-scrub), and nothing grants it the scope. A test adds the grant (the
    /// walk plane) or leaves it standing-less.
    pub(crate) async fn plain_pipeline_fixture() -> (MemoryBackend, Vec<u8>) {
        let backend = MemoryBackend::new();
        let pipeline = HybridSigningIdentity::generate(PIPELINE).expect("pipeline identity");
        FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord {
                record: row_for_identity(&pipeline, identity_type::NODE, None),
            },
        )
        .await
        .expect("seed plain pipeline row");
        let bytes = seed_presenter_and_mint_bundle(&backend, &pipeline).await;
        (backend, bytes)
    }

    /// Seed the presenter's plain node row and mint the pipeline-signed
    /// manifest + presenter-signed bundle with verify's own producers — the
    /// exact field artifacts.
    async fn seed_presenter_and_mint_bundle(
        backend: &MemoryBackend,
        pipeline: &HybridSigningIdentity,
    ) -> Vec<u8> {
        let presenter = HybridSigningIdentity::generate(PRESENTER).expect("presenter identity");
        FederationDirectory::put_public_key(
            backend,
            ciris_persist::federation::SignedKeyRecord {
                record: row_for_identity(&presenter, identity_type::NODE, None),
            },
        )
        .await
        .expect("seed presenter row");

        let bh = "aa".repeat(32);
        let mh = "bb".repeat(32);
        let manifest = sign_build_manifest_contribution(
            pipeline,
            &BuildAttestation {
                target: TARGET,
                binary_hash: &bh,
                build_id: "build-437",
                binary_version: "15.11.0",
                manifest_hash: &mh,
                manifest_size: 4096,
            },
            ts(),
        )
        .await
        .expect("pipeline-signed manifest");
        let bundle = produce_build_attestation_bundle(
            &presenter,
            &BundleInputs {
                presents: PresentedBuild::SelfVerify,
                manifest_contribution: &manifest,
                inclusion: None,
            },
            ts(),
        )
        .await
        .expect("presenter-signed bundle");
        serde_json::to_vec(&bundle).expect("serialize bundle")
    }

    /// Flip the carried manifest's binary_hash AFTER signing — the
    /// evidence-swap the commitment must catch.
    pub(crate) fn tampered(bytes: &[u8]) -> Vec<u8> {
        let mut bundle: SignedCegObject = serde_json::from_slice(bytes).expect("parse bundle");
        bundle.body["manifest_contribution"]["body"]["signed_envelope"]["build"]["binary_hash"] =
            serde_json::json!("00".repeat(32));
        serde_json::to_vec(&bundle).expect("serialize tampered bundle")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{
        field_fixture, plain_pipeline_fixture, row_for_identity, shaped_bundle_bytes, tampered,
        PIPELINE, PRESENTER, READER, TARGET, TS,
    };
    use super::*;
    use ciris_persist::federation::types::identity_type;
    use ciris_persist::federation::FederationDirectory;
    use ciris_persist::store::MemoryBackend;
    use ciris_verify_core::self_at_login::HybridSigningIdentity;

    use crate::verify::{ProvenanceChain, RootingDirectory, RootingRejection, RootingVerdict};

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

    /// CIRISEdge#436 — the announce commitment helper derives EXACTLY the
    /// commitment verify's producer signed into the bundle
    /// (`manifest_contribution_sha256`, the `sha256(JCS(manifest))` preimage),
    /// is stable across a serialize/parse round-trip, moves when the carried
    /// manifest is tampered, and refuses non-bundle blobs.
    #[tokio::test]
    async fn manifest_commitment_matches_the_bundles_own_signed_commitment() {
        let (_backend, bytes) = field_fixture().await;
        let commitment =
            manifest_commitment_of_bundle(&bytes).expect("valid bundle has a commitment");

        // Equal to the producer-signed internal commitment — one preimage,
        // three uses (announce, bundle envelope, transparency leaf).
        let bundle: SignedCegObject = serde_json::from_slice(&bytes).expect("parse");
        let signed_hex = bundle.body["signed_envelope"]["manifest_contribution_sha256"]
            .as_str()
            .expect("producer signs the commitment");
        assert_eq!(hex::encode(commitment), signed_hex);

        // Stable across a JSON round-trip (re-serialized bytes, same JCS).
        let reserialized = serde_json::to_vec(&bundle).expect("serialize");
        assert_eq!(
            manifest_commitment_of_bundle(&reserialized),
            Some(commitment)
        );

        // A tampered manifest moves the commitment — the announce→package
        // binding catches the evidence swap.
        let bad = tampered(&bytes);
        let moved = manifest_commitment_of_bundle(&bad).expect("still shaped");
        assert_ne!(moved, commitment);

        // Non-bundles refuse: junk, wrong kind, missing manifest.
        assert_eq!(manifest_commitment_of_bundle(b"not json"), None);
        let wrong = SignedCegObject::new("self_login", PRESENTER, TS, serde_json::json!({}));
        assert_eq!(
            manifest_commitment_of_bundle(&serde_json::to_vec(&wrong).unwrap()),
            None
        );
        assert_eq!(
            manifest_commitment_of_bundle(&shaped_bundle_bytes(PRESENTER)),
            None,
            "a bundle without a manifest_contribution has no commitment"
        );
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

    /// A verdict as verify returns one, for the cache's unit tests.
    fn a_verdict() -> BundleVerdict {
        use ciris_verify_core::build_attestation_bundle::{PresentedBuild, TransparencyCheck};
        use ciris_verify_core::manifest_contribution::{PipelineStanding, VerifiedManifest};
        BundleVerdict {
            presenter_key_id: PRESENTER.to_owned(),
            presents: PresentedBuild::SelfVerify,
            build: VerifiedManifest {
                attested_by: PIPELINE.to_owned(),
                standing: PipelineStanding::AccordRole,
                attestation_id: "m-1".to_owned(),
                asserted_at: TS.to_owned(),
                target: TARGET.to_owned(),
                build_id: "build-793".to_owned(),
                binary_hash: "ab".repeat(32),
                binary_version: "0.0.0".to_owned(),
                manifest_hash: "cd".repeat(32),
                manifest_size: 0,
                evidence_refs: Vec::new(),
            },
            transparency: TransparencyCheck::Absent,
        }
    }

    #[test]
    fn verdict_cache_is_per_exact_bytes_and_resets_on_replace() {
        let store = PeerBundleStore::new();
        let bytes = shaped_bundle_bytes("p");
        store.register("p", &bytes).expect("register");
        let digest = sha256_of(&bytes);

        assert!(!store.is_verified("p", digest), "nothing verified yet");
        // A stale digest (bytes that are not the stored ones) never caches.
        let verdict = a_verdict();
        store.note_verified("p", [0u8; 32], READER, &verdict);
        assert!(!store.is_verified("p", [0u8; 32]));
        // The exact stored bytes' digest caches, for the reader that asked.
        store.note_verified("p", digest, READER, &verdict);
        assert!(store.is_verified("p", digest));
        assert_eq!(
            store.verified_blessing("p", digest, READER),
            Some(PipelineBlessing::accord_role(PIPELINE))
        );
        assert_eq!(store.verified_blessing("p", digest, "another-reader"), None);
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
        let verdict =
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PRESENTER, &bytes).await;
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
            READER,
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
            READER,
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
                READER,
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Advisory
        );

        // A tampered bundle: the seam rejects it (evidence-commitment
        // mismatch) and the save downgrades.
        let bad = tampered(&bytes);
        let verdict =
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PRESENTER, &bad).await;
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
                READER,
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
                READER,
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
                    READER,
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
        let verdict =
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PIPELINE, &bytes).await;
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
            RootingDirectory::verify_peer_build_bundle(&empty, READER, PRESENTER, &bytes).await,
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
            RootingDirectory::verify_peer_build_bundle(&presenter_only, READER, PRESENTER, &bytes)
                .await,
            BundleGateVerdict::Refused(BundleGateRefusal::PipelineNotInDirectory {
                key_id: PIPELINE.to_string(),
            })
        );

        // Malformed / oversized blobs refuse before any directory read.
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&empty, READER, PRESENTER, b"not json")
                .await,
            BundleGateVerdict::Refused(BundleGateRefusal::MalformedBundle(
                "not a JSON SignedCegObject"
            ))
        );
        let big = vec![b'x'; MAX_PEER_BUNDLE_BYTES + 1];
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&empty, READER, PRESENTER, &big).await,
            BundleGateVerdict::Refused(BundleGateRefusal::OversizedBundle {
                actual: MAX_PEER_BUNDLE_BYTES + 1,
                limit: MAX_PEER_BUNDLE_BYTES,
            })
        );
    }

    /// The default trait impl (no directory at all) refuses as
    /// `NoDirectory` — which under the gate downgrades the save.
    #[tokio::test]
    async fn no_directory_fails_closed() {
        let (_backend, bytes) = field_fixture().await;
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(
                &NoDirectoryRooting,
                READER,
                PRESENTER,
                &bytes
            )
            .await,
            BundleGateVerdict::Refused(BundleGateRefusal::NoDirectory)
        );
        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                READER,
                &store,
                &NoDirectoryRooting,
            )
            .await,
            BindingProvenance::Advisory
        );
    }

    // ── CIRISEdge#786: the two standing planes (CC 3.1.2.1, rc6 22ea349) ──

    use ciris_verify_core::build_attestation_bundle::PresentedBuild;
    use ciris_verify_core::manifest_contribution::{PipelineStanding, WalkPlane};

    /// Register `reader` (a node the bridge fixture signer can sign for) and
    /// give it the bridge fixtures' common root `root-r`: a charter with a
    /// recovery pre-commitment and `reader`'s acceptance of it.
    async fn reader_accepts_common_root(backend: &MemoryBackend, reader: &str) {
        FederationDirectory::put_public_key(
            backend,
            ciris_persist::federation::SignedKeyRecord {
                record: crate::replication::bridge::tests::fixture_key_record(
                    reader,
                    identity_type::NODE,
                ),
            },
        )
        .await
        .expect("seed reader row");
        crate::replication::bridge::tests::seed_common_root(backend, &[reader]).await;
    }

    /// Witness (a) — plane 1: the pipeline holds no co-scrub and no role,
    /// but `root-r` grants it `infra:attest` and the reader accepts
    /// `root-r`. The walk confers → the bundle verifies with
    /// `Conferred { Delegation }` standing and the Rooted save proceeds.
    /// The SAME grant read by a node that does not accept `root-r` confers
    /// nothing (the walk is reader-relative) → refused.
    #[tokio::test]
    async fn walk_conferred_pipeline_is_admitted_from_a_reader_that_accepts_the_root() {
        let (backend, bytes) = plain_pipeline_fixture().await;
        reader_accepts_common_root(&backend, READER).await;
        let grant = crate::replication::bridge::tests::seed_delegates_to(
            &backend,
            "root-r",
            PIPELINE,
            &serde_json::json!([ciris_verify_core::manifest_contribution::MANIFEST_PUBLISH_SCOPE]),
        )
        .await;

        let verdict =
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PRESENTER, &bytes).await;
        let BundleGateVerdict::Verified(v) = verdict else {
            panic!("expected Verified via the capability walk, got {verdict:?}");
        };
        assert_eq!(
            v.build.standing,
            PipelineStanding::Conferred {
                root_key_id: "root-r".to_string(),
                grant_attestation_id: grant,
                plane: WalkPlane::Delegation,
            }
        );
        assert_eq!(v.presents, PresentedBuild::SelfVerify);

        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                READER,
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Rooted
        );

        // A reader that never accepted `root-r`: same rows, no standing.
        let stranger = "reader-stranger-786";
        FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord {
                record: crate::replication::bridge::tests::fixture_key_record(
                    stranger,
                    identity_type::NODE,
                ),
            },
        )
        .await
        .expect("seed stranger row");
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&backend, stranger, PRESENTER, &bytes).await,
            BundleGateVerdict::Refused(BundleGateRefusal::PipelineWithoutStanding {
                key_id: PIPELINE.to_string(),
            })
        );
    }

    /// Witness (b) — plane 2 only: the pipeline's record carries the
    /// accord co-scrub of `infra:attest` (the `/v1/accord/ci-key` ceremony)
    /// and NOTHING grants it the scope, so the walk finds nothing. The
    /// ceremony plane blesses it → `AccordRole` standing, admitted. A
    /// walk-only gate would refuse this, i.e. every production pipeline.
    #[tokio::test]
    async fn ceremony_plane_pipeline_is_admitted_when_the_walk_finds_nothing() {
        let (backend, bytes) = field_fixture().await;
        assert_eq!(
            capability_roots_to_trusted_root(
                &backend,
                READER,
                PIPELINE,
                ciris_verify_core::manifest_contribution::MANIFEST_PUBLISH_SCOPE,
            )
            .await
            .expect("walk"),
            None,
            "precondition: no grant — plane 1 says no"
        );
        let verdict =
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PRESENTER, &bytes).await;
        let BundleGateVerdict::Verified(v) = verdict else {
            panic!("expected Verified via the ceremony plane, got {verdict:?}");
        };
        assert_eq!(v.build.standing, PipelineStanding::AccordRole);
    }

    /// Witness (c) — neither plane: a plain pipeline row, no grant, no
    /// co-scrub → refused by name, and the Rooted save downgrades.
    #[tokio::test]
    async fn pipeline_with_standing_on_neither_plane_is_refused() {
        let (backend, bytes) = plain_pipeline_fixture().await;
        reader_accepts_common_root(&backend, READER).await;
        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PRESENTER, &bytes).await,
            BundleGateVerdict::Refused(BundleGateRefusal::PipelineWithoutStanding {
                key_id: PIPELINE.to_string(),
            })
        );
        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                READER,
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Advisory
        );
    }

    /// **The pre-19 standing check, reconstructed** (CIRISEdge#786 witness
    /// (d)). Verify 18's `verify_build_manifest_via_coscrub` step 4, which the
    /// old seam ran over `(pipeline_record, accord_anchors)` read from the
    /// directory: the record's declared identity binds its signed envelope,
    /// names the pipeline, carries `infra:attest` in its envelope roles, and
    /// at least `MIN_ACCORD_COSCRUBS` (2) distinct accord anchors' scrubs
    /// hybrid-verify (RequireHybrid) over `JCS(registration_envelope)`. Built
    /// from verify 19's own public primitives (`KeyRecord::scrubs`,
    /// `roles_in_envelope`, `check_subject_binding`,
    /// `verify_threshold_signatures`), which are unchanged from 18; only the
    /// composition is restated. It reads nothing a withdrawal writes, which
    /// is the point.
    fn pre_19_co_scrub_roots(
        pipeline_row: &PersistKeyRecord,
        anchors: &[PersistKeyRecord],
    ) -> bool {
        use ciris_verify_core::federation_self_record::KeyRecord as VerifyKeyRecord;
        use ciris_verify_core::threshold::{verify_threshold_signatures, ThresholdSignature};
        const MIN_ACCORD_COSCRUBS: usize = 2;
        let Ok(record) =
            serde_json::to_value(pipeline_row).and_then(serde_json::from_value::<VerifyKeyRecord>)
        else {
            return false;
        };
        if record.check_subject_binding().is_err() || record.key_id != pipeline_row.key_id {
            return false;
        }
        if !record
            .roles_in_envelope()
            .iter()
            .any(|r| r == MANIFEST_PUBLISH_SCOPE)
        {
            return false;
        }
        let Ok(canonical) = ciris_verify_core::jcs::canonicalize(&record.registration_envelope)
        else {
            return false;
        };
        let members: Vec<ThresholdMember> = anchors.iter().map(threshold_member_from_row).collect();
        let mut verified = std::collections::BTreeSet::new();
        for scrub in record.scrubs() {
            let Some(member) = members.iter().find(|m| m.member_id == scrub.scrub_key_id) else {
                continue;
            };
            let sig = ThresholdSignature {
                member_id: member.member_id.clone(),
                ed25519_signature_base64: scrub.scrub_signature_classical.clone(),
                mldsa65_signature_base64: scrub.scrub_signature_pqc.clone(),
            };
            if verify_threshold_signatures(&canonical, std::slice::from_ref(member), &[sig], 1)
                == Ok(1)
            {
                verified.insert(scrub.scrub_key_id);
            }
        }
        verified.len() >= MIN_ACCORD_COSCRUBS
    }

    /// Witness (d) — the bundle the pre-19 path rooted and neither plane
    /// admits: the accord quorum WITHDREW the pipeline's `infra:attest`.
    /// The withdrawal is a tombstone and never mutates the row, so the
    /// stored record still carries the role under its valid 2-anchor
    /// co-scrub and the directory still holds the `accord_holder` rows —
    /// exactly the `(pipeline_record, accord_anchors)` the pre-19 seam handed
    /// verify, whose co-scrub re-check could not see a withdrawal and
    /// returned Verified (this fixture, un-withdrawn, is the one
    /// `verified_bundle_with_gate_on_lets_the_rooted_save_proceed` admits).
    /// Persist sees the tombstone: the ceremony plane says no, the walk has
    /// no grant → refused.
    #[tokio::test]
    async fn a_withdrawn_pipeline_the_co_scrub_path_rooted_is_refused() {
        use ciris_persist::federation::admission::{is_infra_attest, is_infra_attest_effective};
        use ciris_persist::federation::types::roles::INFRA_ATTEST;

        let (backend, bytes) = field_fixture().await;
        FederationDirectory::record_role_withdrawal(
            &backend,
            INFRA_ATTEST,
            PIPELINE,
            None,
            &"cd".repeat(32),
        )
        .await
        .expect("record the quorum withdrawal tombstone");

        // What the pre-19 path read is untouched: the co-scrubbed role on the
        // stored row, and the anchors it verified against.
        assert!(is_infra_attest(&backend, PIPELINE).await.expect("read"));
        assert!(
            !FederationDirectory::list_keys_by_identity_type(
                &backend,
                identity_type::ACCORD_HOLDER
            )
            .await
            .expect("anchors")
            .is_empty(),
            "the accord anchors the co-scrub path pinned are still there"
        );
        // What the substrate answers: withdrawn.
        assert!(!is_infra_attest_effective(&backend, PIPELINE)
            .await
            .expect("read"));

        // The pre-19 path, run: over the same directory rows it read, its
        // standing check ROOTS this pipeline. And it discriminates: a plain
        // pipeline row (no co-scrub) does not root under it.
        let pipeline_row = FederationDirectory::lookup_public_key(&backend, PIPELINE)
            .await
            .expect("read")
            .expect("pipeline row");
        let anchors =
            FederationDirectory::list_keys_by_identity_type(&backend, identity_type::ACCORD_HOLDER)
                .await
                .expect("anchors");
        assert!(
            pre_19_co_scrub_roots(&pipeline_row, &anchors),
            "the pre-19 co-scrub path roots the withdrawn pipeline"
        );
        let (plain, _) = plain_pipeline_fixture().await;
        let plain_row = FederationDirectory::lookup_public_key(&plain, PIPELINE)
            .await
            .expect("read")
            .expect("plain pipeline row");
        assert!(
            !pre_19_co_scrub_roots(&plain_row, &anchors),
            "control: the reconstruction refuses a pipeline with no co-scrub"
        );
        // Neither CC 3.1.2.1 plane admits it.
        assert_eq!(
            pipeline_blessing(&backend, READER, PIPELINE)
                .await
                .expect("standing"),
            None
        );

        assert_eq!(
            RootingDirectory::verify_peer_build_bundle(&backend, READER, PRESENTER, &bytes).await,
            BundleGateVerdict::Refused(BundleGateRefusal::PipelineWithoutStanding {
                key_id: PIPELINE.to_string(),
            })
        );
        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        assert_eq!(
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                READER,
                &store,
                &backend,
            )
            .await,
            BindingProvenance::Advisory
        );
    }

    /// **CIRISEdge#793 — a cached verdict does not outlive the pipeline's
    /// standing.** The bundle verifies (ceremony plane) and the Rooted save
    /// proceeds, caching the verdict against its bytes. Then the accord quorum
    /// withdraws the pipeline's `infra:attest`. The next Rooted save, same
    /// bytes, no re-register, is Advisory, and the cache entry is dropped.
    /// Fails with the cache answering `Rooted` by bytes alone (the pre-#793
    /// `is_verified` short-circuit).
    #[tokio::test]
    async fn a_cached_verdict_does_not_outlive_the_pipelines_standing_793() {
        use ciris_persist::federation::types::roles::INFRA_ATTEST;

        let (backend, bytes) = field_fixture().await;
        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        let save = || {
            gated_save_provenance(
                BundleSaveGateMode::RequireBundleForRootedSave,
                BindingProvenance::Rooted,
                PRESENTER,
                READER,
                &store,
                &backend,
            )
        };
        assert_eq!(save().await, BindingProvenance::Rooted);
        assert!(store.is_verified(PRESENTER, sha256_of(&bytes)), "cached");
        assert_eq!(save().await, BindingProvenance::Rooted, "the cache hit");

        FederationDirectory::record_role_withdrawal(
            &backend,
            INFRA_ATTEST,
            PIPELINE,
            None,
            &"cd".repeat(32),
        )
        .await
        .expect("the quorum withdraws the pipeline's infra:attest");
        assert_eq!(
            save().await,
            BindingProvenance::Advisory,
            "same bytes, no re-register: the withdrawal reaches the cached peer"
        );
        assert!(
            !store.is_verified(PRESENTER, sha256_of(&bytes)),
            "the stale verdict is dropped"
        );
        assert_eq!(save().await, BindingProvenance::Advisory);
    }

    /// **CIRISEdge#793 — a cached verdict is the reader's, not the bundle's.**
    /// The walk confers the pipeline from a root `READER` accepts, and the
    /// Rooted save for `READER` caches. A node that never accepted that root,
    /// asking of the same store and bytes, gets Advisory: standing is
    /// reader-relative (CC 3.1.2.1), so the cache never answers for another
    /// reader. Fails with the cache keyed by bytes alone.
    #[tokio::test]
    async fn a_cached_verdict_answers_only_the_reader_it_was_asked_for_793() {
        let (backend, bytes) = plain_pipeline_fixture().await;
        reader_accepts_common_root(&backend, READER).await;
        crate::replication::bridge::tests::seed_delegates_to(
            &backend,
            "root-r",
            PIPELINE,
            &serde_json::json!([ciris_verify_core::manifest_contribution::MANIFEST_PUBLISH_SCOPE]),
        )
        .await;
        let stranger = "reader-stranger-793";
        FederationDirectory::put_public_key(
            &backend,
            ciris_persist::federation::SignedKeyRecord {
                record: crate::replication::bridge::tests::fixture_key_record(
                    stranger,
                    identity_type::NODE,
                ),
            },
        )
        .await
        .expect("seed stranger row");

        let store = PeerBundleStore::new();
        store.register(PRESENTER, &bytes).expect("register");
        let save = |reader: &'static str| {
            let store = &store;
            let backend = &backend;
            async move {
                gated_save_provenance(
                    BundleSaveGateMode::RequireBundleForRootedSave,
                    BindingProvenance::Rooted,
                    PRESENTER,
                    reader,
                    store,
                    backend,
                )
                .await
            }
        };
        assert_eq!(save(READER).await, BindingProvenance::Rooted);
        assert!(store.is_verified(PRESENTER, sha256_of(&bytes)));
        assert_eq!(
            save(stranger).await,
            BindingProvenance::Advisory,
            "a reader that does not accept the root gets no standing from another's cache"
        );
        assert_eq!(save(READER).await, BindingProvenance::Rooted);
    }
}
