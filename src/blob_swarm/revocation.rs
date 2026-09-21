//! **CC 2.3 at the bytes plane — edge's half** (CIRISEdge#606 / CIRISPersist#853).
//!
//! CC 2.3 says a person who appears in someone else's data can still pull
//! it. Until this module, that held at the ROW plane only: a subject's
//! `withdraws` tombstoned the referencing attestation and every reader of the
//! row saw it retracted, while the bytes it referenced stayed readable on the
//! author's node and on every holder that adopted them, indefinitely. The
//! serve side answered `NotHeld` at worst — "ask another holder" — and walked
//! the fetcher around the mesh to nodes that all still had the bytes.
//!
//! Two things close it here, both fed by one [`RevocationRegister`]:
//!
//! 1. **The serve side says `Withdrawn`.** A holder consults the register
//!    before serving a chunk; a blob whose every known reference has been
//!    withdrawn is refused with [`ChunkSourceRefusal::Withdrawn`], which
//!    `blob_swarm` already maps to `MissReason::Withdrawn` and on which the
//!    fetcher ABORTS the whole blob rather than trying the next holder.
//! 2. **An admitted, RE-VERIFIED `withdraws` evicts.** When a `withdraws`
//!    lands against a row this node holds that references bytes this node
//!    holds, the admission rule is recomputed against the local target at
//!    the moment of acting; only an authorized withdrawal marks the bytes
//!    `Revoked`, deletes the blob row, and hands the converger a
//!    `ConsentState::Revoked` it can route to `EjectHardDelete`.
//!
//! # The constraint that shapes everything below
//!
//! persist admits a `withdraws` whose target is not local with
//! `withdraws_admission_rule = None` — "authority is a read-side concern",
//! because at admission it may not hold the target row. **Anything that
//! deletes bytes on the strength of a stored `withdraws` must re-derive the
//! rule against the target it now holds, at the moment it acts.** A hook that
//! trusts the stored rule, or reads `None` as permission, turns replication
//! into a remote-delete primitive: anyone who can get a `withdraws` admitted
//! erases content they had no authority over — and with CIRISEdge#582 still
//! open that lands as mass deletion. So [`apply_observation`] calls persist's
//! own [`check_withdraws_admission`] every time, never reads the column, and
//! treats `None`/`Err` as **inert**.
//!
//! # Fail-closed toward RETENTION
//!
//! Consent and holder-count fail secure in opposite directions (the
//! converger's own note). On this axis every doubt resolves to keeping the
//! bytes: a reference set that cannot be resolved does not refuse a serve, a
//! rule that cannot be recomputed does not evict, and a register at its cap
//! stops indexing rather than guessing. Each of those is logged at WARN
//! naming the sha, so silence is never the reason bytes stayed.
//!
//! # What "every known reference" means, and its one bound
//!
//! A blob is revoked when every row known to reference it is withdrawn. The
//! known set is: the withdrawn row itself, plus every referencing row this
//! node admitted through the replication apply path since the register
//! existed (indexed as it landed), plus every row persist's own binding
//! predicate finds through `evidence_refs`
//! (`attestations_binding_content`). What it is NOT: a `BlobPointer` row
//! this node authored locally or admitted before the register existed. For
//! encrypted tiers this cannot matter — a seal is a fresh DEK and nonce, so
//! the ciphertext sha is unique to its one referencing row. For plaintext
//! commons content shared by several rows it can: the residual is stated in
//! CIRISEdge#606, and the CC-native closure is for producers to carry the
//! sha in `evidence_refs` so persist's predicate is complete
//! (CIRISVerify#281 did this for manifests).
//!
//! **CIRISEdge#646 (v29.0.0) closes edge's half of that**: every chat row
//! now carries its blob's sha in `evidence_refs` beside the typed pointer
//! (`chat::chat_row`), so persist's predicate finds it and the known set is
//! complete for edge-authored content. The residual that remains is a row
//! authored by some OTHER producer that still cites only a pointer.
//!
//! # Out-of-order arrival
//!
//! A `withdraws` that lands before its target is held as PENDING (bounded);
//! when the target row is admitted later, every pending withdrawal against
//! it is replayed through the same recompute. That is how a withdrawal
//! persist admitted with `rule = None` gets its authority decided — by this
//! node, against the row, and never by the column.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use ciris_persist::federation::blobs::BlobStorage;
use ciris_persist::federation::types::attestation_type;
use ciris_persist::federation::{Attestation, FederationDirectory};

use super::meaning::{is_holds_bytes_row, referenced_shas};
use crate::holonomic::swarm_rarity::ConsentState;

/// The default cap on distinct blobs the register tracks. Chosen as a
/// generous multiple of what one node holds in `federation_blobs` today; a
/// node past it stops INDEXING (never deleting) and says so at WARN.
pub const DEFAULT_CAP: usize = 65_536;

/// The default cap on `withdraws` rows held pending a target that has not
/// arrived. Past it, a new pending withdrawal is dropped at WARN — it can be
/// re-applied when the target lands only if it was kept, so this is the
/// retention direction.
pub const DEFAULT_PENDING_CAP: usize = 4_096;

/// What the register knows about a blob's bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytesVerdict {
    /// No referencing row is indexed. The bytes are served as before; the
    /// register cannot say they were revoked because it cannot say what
    /// references them.
    Unknown,
    /// At least one known referencing row is live.
    Live,
    /// Every known referencing row has been withdrawn by an AUTHORIZED
    /// withdrawal (rule recomputed against the local target). Serve refuses
    /// `Withdrawn`; the converger sees `ConsentState::Revoked`.
    Revoked,
}

/// Deletes a blob's bytes on this node. Object-safe so the register can hold
/// it behind `dyn`; persist's [`BlobStorage`] is not (RPITIT), which is the
/// same reason the fountain-evict adapters exist.
#[async_trait]
pub trait BlobEvictor: Send + Sync {
    /// Delete the blob row **and its satellites** (epoch binding, at-rest
    /// grants) for `sha256`. `Ok(false)` when no row existed.
    async fn delete_blob_bytes(&self, sha256: &[u8; 32]) -> Result<bool, String>;
}

#[async_trait]
impl<B> BlobEvictor for B
where
    B: BlobStorage + Send + Sync + 'static,
{
    async fn delete_blob_bytes(&self, sha256: &[u8; 32]) -> Result<bool, String> {
        self.delete_blob(sha256).await.map_err(|e| e.to_string())
    }
}

#[derive(Default)]
struct Inner {
    /// sha → referencing attestation ids (the known reference set).
    refs: HashMap<[u8; 32], HashSet<String>>,
    /// Attestation ids with an AUTHORIZED withdrawal against them.
    withdrawn: HashSet<String>,
    /// shas whose every known reference is withdrawn.
    revoked: HashSet<[u8; 32]>,
    /// `withdraws` rows whose target was absent when they landed, keyed by
    /// the target id, awaiting the target.
    pending: HashMap<String, Vec<Attestation>>,
    pending_len: usize,
    /// References not indexed because the register was at its cap.
    dropped_refs: u64,
    /// Pending withdrawals dropped because the pending cap was hit.
    dropped_pending: u64,
}

/// The one register the serve side, the converger and the apply path share.
pub struct RevocationRegister {
    inner: Mutex<Inner>,
    cap: usize,
    pending_cap: usize,
}

impl std::fmt::Debug for RevocationRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (refs, withdrawn, revoked, pending) = self.inner.lock().map_or((0, 0, 0, 0), |g| {
            (
                g.refs.len(),
                g.withdrawn.len(),
                g.revoked.len(),
                g.pending_len,
            )
        });
        f.debug_struct("RevocationRegister")
            .field("blobs_indexed", &refs)
            .field("rows_withdrawn", &withdrawn)
            .field("blobs_revoked", &revoked)
            .field("withdraws_pending", &pending)
            .field("cap", &self.cap)
            .field("pending_cap", &self.pending_cap)
            .finish()
    }
}

impl Default for RevocationRegister {
    fn default() -> Self {
        Self::new(DEFAULT_CAP, DEFAULT_PENDING_CAP)
    }
}

impl RevocationRegister {
    /// A register that indexes at most `cap` distinct blobs and holds at
    /// most `pending_cap` out-of-order withdrawals.
    #[must_use]
    pub fn new(cap: usize, pending_cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            cap,
            pending_cap,
        }
    }

    /// `row_id` references `sha`. Returns `false` (and counts) when the
    /// register is at its cap and `sha` is not already tracked — the blob is
    /// then `Unknown` forever, which is the retention direction.
    pub fn note_reference(&self, sha: [u8; 32], row_id: &str) -> bool {
        let Ok(mut g) = self.inner.lock() else {
            return false;
        };
        if !g.refs.contains_key(&sha) && g.refs.len() >= self.cap {
            g.dropped_refs += 1;
            return false;
        }
        g.refs.entry(sha).or_default().insert(row_id.to_owned());
        true
    }

    /// `row_id` has an AUTHORIZED withdrawal against it (the caller
    /// recomputed the rule). `shas` are the blobs the row references; each is
    /// added to the known set if not yet tracked. Returns the shas that are
    /// NEWLY revoked — every known reference withdrawn — so the caller can
    /// evict exactly those, once.
    pub fn note_withdrawn(&self, row_id: &str, shas: &[[u8; 32]]) -> Vec<[u8; 32]> {
        let Ok(mut g) = self.inner.lock() else {
            return Vec::new();
        };
        g.withdrawn.insert(row_id.to_owned());
        let mut newly = Vec::new();
        for sha in shas {
            if !g.refs.contains_key(sha) && g.refs.len() >= self.cap {
                g.dropped_refs += 1;
                continue;
            }
            g.refs.entry(*sha).or_default().insert(row_id.to_owned());
            let all_withdrawn = g.refs[sha].iter().all(|id| g.withdrawn.contains(id));
            if all_withdrawn && g.revoked.insert(*sha) {
                newly.push(*sha);
            }
        }
        newly
    }

    /// The register's answer for `sha`.
    #[must_use]
    pub fn verdict(&self, sha: &[u8; 32]) -> BytesVerdict {
        let Ok(g) = self.inner.lock() else {
            return BytesVerdict::Unknown;
        };
        if g.revoked.contains(sha) {
            BytesVerdict::Revoked
        } else if g.refs.contains_key(sha) {
            BytesVerdict::Live
        } else {
            BytesVerdict::Unknown
        }
    }

    /// The converger's consent input for a fountain `content_id` — which on
    /// the blob plane is the sha256 hex (`FountainHoldingClaim::content_id`,
    /// "typically the manifest sha256 hex"). `Revoked` only for a blob this
    /// register revoked; everything else keeps the retention-favouring
    /// `Active` the converger has used since v5.2.0, so wiring the register
    /// cannot make a single byte evict-eligible that was not withdrawn.
    #[must_use]
    pub fn consent_for(&self, content_id: &str) -> ConsentState {
        let Ok(bytes) = hex::decode(content_id) else {
            return ConsentState::Active;
        };
        let Ok(sha) = <[u8; 32]>::try_from(bytes.as_slice()) else {
            return ConsentState::Active;
        };
        match self.verdict(&sha) {
            BytesVerdict::Revoked => ConsentState::Revoked,
            BytesVerdict::Live | BytesVerdict::Unknown => ConsentState::Active,
        }
    }

    /// Hold `row` (a `withdraws`) until its target arrives. Dropped at WARN
    /// past the pending cap.
    fn hold_pending(&self, target_id: &str, row: Attestation) {
        let Ok(mut g) = self.inner.lock() else {
            return;
        };
        if g.pending_len >= self.pending_cap {
            g.dropped_pending += 1;
            tracing::warn!(
                target = target_id,
                withdraws = %row.attestation_id,
                cap = self.pending_cap,
                "revocation register: pending-withdraws cap reached — this withdrawal is \
                 DROPPED and will not be replayed when its target lands (retention direction, \
                 CIRISEdge#606)"
            );
            return;
        }
        g.pending.entry(target_id.to_owned()).or_default().push(row);
        g.pending_len += 1;
    }

    /// Every pending withdrawal against `target_id`, removed.
    fn take_pending(&self, target_id: &str) -> Vec<Attestation> {
        let Ok(mut g) = self.inner.lock() else {
            return Vec::new();
        };
        let rows = g.pending.remove(target_id).unwrap_or_default();
        g.pending_len = g.pending_len.saturating_sub(rows.len());
        rows
    }

    /// Counters for telemetry: `(blobs_indexed, blobs_revoked,
    /// withdraws_pending, refs_dropped_at_cap, pending_dropped_at_cap)`.
    #[must_use]
    pub fn stats(&self) -> (usize, usize, usize, u64, u64) {
        self.inner.lock().map_or((0, 0, 0, 0, 0), |g| {
            (
                g.refs.len(),
                g.revoked.len(),
                g.pending_len,
                g.dropped_refs,
                g.dropped_pending,
            )
        })
    }
}

/// What the apply path saw in an ADMITTED row, captured before the row moves
/// into persist. Cheap for every row that is neither: a `holds_bytes` claim,
/// a row with no reference and no target, contributes nothing.
#[derive(Debug, Clone)]
pub enum Observation {
    /// A row that references blobs — index it, and replay any withdrawal
    /// that was waiting for it.
    References { row_id: String, shas: Vec<[u8; 32]> },
    /// A `withdraws` row — resolve its target and decide. Boxed: the
    /// `References` arm is what every content row produces, and it should not
    /// pay an `Attestation`'s size for the rare plane.
    Withdraws(Box<Attestation>),
}

/// Look at an about-to-be-admitted row. Call BEFORE the row moves into the
/// put door; clones the row only when it is a `withdraws` (a rare plane).
#[must_use]
pub fn observe(row: &Attestation) -> Option<Observation> {
    if row.attestation_type == attestation_type::WITHDRAWS {
        return Some(Observation::Withdraws(Box::new(row.clone())));
    }
    // Possession is not a reference (memory trap 4 / `BlobMeaning` step 2).
    if is_holds_bytes_row(row) {
        return None;
    }
    let shas = referenced_shas(&row.attestation_envelope);
    if shas.is_empty() {
        return None;
    }
    Some(Observation::References {
        row_id: row.attestation_id.clone(),
        shas,
    })
}

/// Act on an observation AFTER the row was admitted. Returns the shas whose
/// bytes were evicted by this call (empty for the common case).
///
/// The only place bytes are deleted on the strength of a `withdraws`, and it
/// recomputes the admission rule against the local target every time.
pub async fn apply_observation(
    register: &RevocationRegister,
    directory: &dyn FederationDirectory,
    evictor: Option<&dyn BlobEvictor>,
    observation: Observation,
) -> Vec<[u8; 32]> {
    match observation {
        Observation::References { row_id, shas } => {
            for sha in &shas {
                if !register.note_reference(*sha, &row_id) {
                    tracing::warn!(
                        sha = %hex::encode(sha),
                        row = %row_id,
                        cap = register.cap,
                        "revocation register: cap reached — this blob is NOT indexed and will \
                         read Unknown (served, never evicted here) (CIRISEdge#606)"
                    );
                }
            }
            // The target of a withdrawal that arrived first has landed.
            let mut evicted = Vec::new();
            for pending in register.take_pending(&row_id) {
                evicted.extend(
                    act_on_withdraws(register, directory, evictor, Box::new(pending)).await,
                );
            }
            evicted
        }
        Observation::Withdraws(row) => act_on_withdraws(register, directory, evictor, row).await,
    }
}

async fn act_on_withdraws(
    register: &RevocationRegister,
    directory: &dyn FederationDirectory,
    evictor: Option<&dyn BlobEvictor>,
    row: Box<Attestation>,
) -> Vec<[u8; 32]> {
    let Some((target_id, shas)) = resolve_withdraws_target(register, directory, &row).await else {
        return Vec::new();
    };
    let Some(rule) = authorized_rule(directory, &row, &target_id).await else {
        return Vec::new();
    };
    let eligible = complete_known_references(register, directory, shas).await;
    let newly = register.note_withdrawn(&target_id, &eligible);
    if newly.is_empty() {
        tracing::info!(
            withdraws = %row.attestation_id,
            target = %target_id,
            rule,
            "revocation register: authorized withdrawal recorded; the blob(s) it references \
             still have a live reference, bytes retained"
        );
        return Vec::new();
    }
    evict_revoked(evictor, &row, &target_id, rule, newly).await
}

/// The target row and the blobs it references — or `None` when there is
/// nothing to act on: a malformed reference, a target that is not content,
/// or a target that has not landed (held pending, replayed on arrival).
async fn resolve_withdraws_target(
    register: &RevocationRegister,
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Option<(String, Vec<[u8; 32]>)> {
    use ciris_persist::federation::precedence::references_attestation_id_from_envelope;

    // Malformed by CEG §3.2 — persist's read side treats it as un-grouped.
    let target_id =
        references_attestation_id_from_envelope(&row.attestation_envelope).map(str::to_owned)?;
    let target = match directory.get_attestation(&target_id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            // Out of order: the target has not landed. Hold the withdrawal;
            // it is replayed — through this same recompute — when it does.
            tracing::debug!(
                withdraws = %row.attestation_id,
                target = %target_id,
                "revocation register: withdraws target not held yet — pending"
            );
            register.hold_pending(&target_id, row.clone());
            return None;
        }
        Err(e) => {
            tracing::warn!(
                withdraws = %row.attestation_id,
                target = %target_id,
                error = %e,
                "revocation register: could not resolve the withdraws target — INERT \
                 (retention direction)"
            );
            return None;
        }
    };
    // A holder retracting its own `holds_bytes` claim is the FSD's own
    // content-location plane (ContentMiss / eviction announcements), not a
    // revocation of content. persist's gate skips the consent rules for it
    // (`Ok(None)`); so do we, by the same predicate `BlobMeaning` uses.
    if is_holds_bytes_row(&target) {
        return None;
    }
    let shas = referenced_shas(&target.attestation_envelope);
    if shas.is_empty() {
        // Not a content row; the row plane handles it and no bytes are involved.
        return None;
    }
    Some((target_id, shas))
}

/// **THE RECOMPUTE.** persist's own admission rule, against the target this
/// node holds, now. Never the stored `withdraws_admission_rule`, never
/// `None`-as-permission. `Some(rule)` is the only value that lets bytes go.
async fn authorized_rule(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    target_id: &str,
) -> Option<u8> {
    use ciris_persist::federation::admission::check_withdraws_admission;

    match check_withdraws_admission(directory, row).await {
        Ok(Some(rule)) => Some(rule),
        Ok(None) => {
            tracing::warn!(
                withdraws = %row.attestation_id,
                target = target_id,
                issuer = %row.attesting_key_id,
                "revocation register: withdraws authority is UNRESOLVED against the local \
                 target — INERT, no bytes touched (CIRISEdge#606 / CIRISPersist#853)"
            );
            None
        }
        Err(e) => {
            tracing::warn!(
                withdraws = %row.attestation_id,
                target = target_id,
                issuer = %row.attesting_key_id,
                error = %e,
                "revocation register: withdraws REFUSED on recompute — INERT, no bytes touched. \
                 A replicated withdrawal that persist stored with rule=None is not an \
                 authority; this node just declined to treat it as one (CIRISEdge#606)"
            );
            None
        }
    }
}

/// Complete the known reference set with persist's own binding predicate
/// (`evidence_refs`). A read that fails could hide a live reference, so it is
/// the retention direction: that sha is left out of the eligible set.
async fn complete_known_references(
    register: &RevocationRegister,
    directory: &dyn FederationDirectory,
    shas: Vec<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut eligible: Vec<[u8; 32]> = Vec::with_capacity(shas.len());
    for sha in shas {
        let hex_sha = hex::encode(sha);
        match directory.attestations_binding_content(&hex_sha).await {
            Ok(rows) => {
                for r in rows {
                    if !is_holds_bytes_row(&r) {
                        register.note_reference(sha, &r.attestation_id);
                    }
                }
                eligible.push(sha);
            }
            Err(e) => {
                tracing::warn!(
                    sha = %hex_sha,
                    error = %e,
                    "revocation register: could not enumerate referencing rows — this blob \
                     is NOT revoked by this withdrawal (retention direction)"
                );
            }
        }
    }
    eligible
}

/// Delete the bytes of every NEWLY revoked blob. The register already says
/// `Revoked` for each, so the serve door refuses and the converger sees
/// `Revoked` whether or not this delete succeeds; a failure is logged, not
/// hidden, and the converger's `EjectHardDelete` is the retry.
async fn evict_revoked(
    evictor: Option<&dyn BlobEvictor>,
    row: &Attestation,
    target_id: &str,
    rule: u8,
    newly: Vec<[u8; 32]>,
) -> Vec<[u8; 32]> {
    let mut evicted = Vec::with_capacity(newly.len());
    for sha in newly {
        let hex_sha = hex::encode(sha);
        let Some(ev) = evictor else {
            tracing::warn!(
                sha = %hex_sha,
                "revocation: blob revoked with NO evictor installed — serve refuses Withdrawn; \
                 bytes stay until an evictor or the converger acts"
            );
            continue;
        };
        match ev.delete_blob_bytes(&sha).await {
            Ok(existed) => {
                tracing::info!(
                    sha = %hex_sha,
                    withdraws = %row.attestation_id,
                    target = target_id,
                    rule,
                    existed,
                    "revocation: every reference withdrawn by an AUTHORIZED withdrawal — \
                     blob bytes deleted; serve now answers Withdrawn; the converger sees \
                     Revoked (CC 2.3 at the bytes plane, CIRISEdge#606)"
                );
                evicted.push(sha);
            }
            Err(e) => tracing::warn!(
                sha = %hex_sha,
                error = %e,
                "revocation: blob revoked but the delete FAILED — serve refuses Withdrawn \
                 and the converger will retry through EjectHardDelete"
            ),
        }
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn a_blob_is_revoked_only_when_every_known_reference_is_withdrawn() {
        let r = RevocationRegister::default();
        assert_eq!(r.verdict(&sha(1)), BytesVerdict::Unknown);
        assert!(r.note_reference(sha(1), "row-a"));
        assert!(r.note_reference(sha(1), "row-b"));
        assert_eq!(r.verdict(&sha(1)), BytesVerdict::Live);

        // One of two references withdrawn: still live, nothing to evict.
        assert!(r.note_withdrawn("row-a", &[sha(1)]).is_empty());
        assert_eq!(r.verdict(&sha(1)), BytesVerdict::Live);
        assert_eq!(r.consent_for(&hex::encode(sha(1))), ConsentState::Active);

        // The last one: revoked, and reported exactly once.
        assert_eq!(r.note_withdrawn("row-b", &[sha(1)]), vec![sha(1)]);
        assert_eq!(r.verdict(&sha(1)), BytesVerdict::Revoked);
        assert_eq!(r.consent_for(&hex::encode(sha(1))), ConsentState::Revoked);
        assert!(
            r.note_withdrawn("row-b", &[sha(1)]).is_empty(),
            "a second withdrawal of an already-revoked blob reports nothing new"
        );
    }

    #[test]
    fn a_withdrawn_row_is_its_own_first_reference() {
        // The target arrives only through the withdrawal (never indexed as a
        // reference): it IS a reference, and its withdrawal alone revokes.
        let r = RevocationRegister::default();
        assert_eq!(r.note_withdrawn("row-solo", &[sha(2)]), vec![sha(2)]);
        assert_eq!(r.verdict(&sha(2)), BytesVerdict::Revoked);
    }

    #[test]
    fn the_cap_stops_indexing_and_never_revokes_past_it() {
        let r = RevocationRegister::new(1, 1);
        assert!(r.note_reference(sha(1), "a"));
        assert!(!r.note_reference(sha(2), "b"), "past the cap: not indexed");
        assert_eq!(r.verdict(&sha(2)), BytesVerdict::Unknown);
        // A withdrawal against an untracked blob past the cap does NOT revoke
        // it: retention is the failure direction.
        assert!(r.note_withdrawn("b", &[sha(2)]).is_empty());
        assert_eq!(r.verdict(&sha(2)), BytesVerdict::Unknown);
        let (_, _, _, dropped_refs, _) = r.stats();
        assert_eq!(dropped_refs, 2);
    }

    #[test]
    fn consent_for_is_active_for_anything_that_is_not_a_revoked_sha() {
        let r = RevocationRegister::default();
        assert_eq!(r.consent_for("not-a-sha"), ConsentState::Active);
        assert_eq!(r.consent_for(&hex::encode(sha(9))), ConsentState::Active);
        r.note_reference(sha(9), "live");
        assert_eq!(r.consent_for(&hex::encode(sha(9))), ConsentState::Active);
    }

    #[test]
    fn observe_skips_possession_and_rows_with_no_reference() {
        let mut row = ciris_persist::federation::Attestation {
            attestation_id: "x".into(),
            attesting_key_id: "k".into(),
            attested_key_id: "k".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({ "dimension": "d" }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "k".into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        assert!(observe(&row).is_none(), "no reference, nothing to observe");

        row.attestation_envelope = serde_json::json!({
            "evidence_refs": [hex::encode(sha(3))],
        });
        assert!(matches!(
            observe(&row),
            Some(Observation::References { shas, .. }) if shas == vec![sha(3)]
        ));

        // A holds_bytes claim naming the same sha is possession, not a reference.
        row.attestation_type = "holds_bytes:sha256:03030303".into();
        assert!(observe(&row).is_none());

        row.attestation_type = "withdraws".into();
        assert!(matches!(observe(&row), Some(Observation::Withdraws(_))));
    }
}
