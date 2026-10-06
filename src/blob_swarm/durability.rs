//! CIRISEdge#763 (CC 6.1.5.3, persist v53 S2/S3) — **durability at every
//! tier**, for the `self` and `family` files edge pulls.
//!
//! The target-replication model used to stop at `community`: a `self` or
//! `family` file was delivered once to the devices that happened to pull it,
//! and a device that later lost its copy stayed without one. CC 6.1.5.3 makes
//! the machinery standard at every tier, bounded to the content's own
//! audience. This module is the edge half; every rule it applies is persist's:
//!
//! - **the audience** is persist's
//!   [`content_audience`](ciris_persist::federation::durability::content_audience)
//!   over the row's own provenance (the author, the family it names): for
//!   `self` the owner's personal-class nodes, for `family` its members'
//!   allowed nodes (S1). A server-class node of the owner is in neither.
//! - **the deficit** is persist's
//!   [`deficit_over`](ciris_persist::federation::durability::deficit_over):
//!   the audience nodes with a live `here` custody report (72 h) and the rest
//!   (`received`, `none`, `unknown` and lapsed reports are all missing). It is
//!   read from the directory alone, so a device that has lost the bytes (and
//!   the blob row with them) still computes it from the file row it holds.
//! - **the target** is persist's
//!   [`durability_mode`](ciris_persist::federation::durability::durability_mode):
//!   every audience node a full holder below `N + K` = 26 nodes, the fountain
//!   tuple at or above.
//!
//! What edge adds is the motion: [`rarest_first`] orders a node's repairs by
//! how few live holders each file has, the puller pulls each from the live
//! holders ([`BlobPuller::durability_sweep`](super::pull::BlobPuller::durability_sweep)),
//! and every completed pull files this node's `here` (persist's
//! `Engine::put_custody_ack`), which for a chunk DAG means the WHOLE DAG — so a
//! chunk repair re-files it. The `custody:ack:v1` rows replicate only within
//! their cohort through the existing audience gate (persist's `may_receive`:
//! a `self` row reaches the owner's personal nodes, a `family` row the
//! family's audience). Nothing here is a `holds_bytes` claim, at any audience
//! (CC 5.2, CIRISEdge#499: self/family bytes are delivered, never discovered).

use std::collections::{BTreeMap, HashMap};

use ciris_persist::federation::custody_ack::{
    fold_device_custody, parse_custody_ack, CustodyAck, DeviceCustody,
};
use ciris_persist::federation::durability::{
    content_audience, deficit_over, durability_mode, ContentAudience, DurabilityDeficit,
    DurabilityMode, DEFAULT_FEASIBILITY_FLOOR,
};
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::federation::{Attestation, FederationDirectory};

/// `N + K` at the shipped fountain tuple: the audience size at which the
/// target switches from full holding to the tuple. Persist's constant, which
/// restates edge's own [`DEFAULT_N_SOURCE`](crate::holonomic::fountain_defaults::DEFAULT_N_SOURCE)
/// \+ [`DEFAULT_K_REPAIR`](crate::holonomic::fountain_defaults::DEFAULT_K_REPAIR)
/// (pinned equal by a test, so the two cannot drift).
pub const FEASIBILITY_FLOOR: usize = DEFAULT_FEASIBILITY_FLOOR;

/// **The target for an audience of `audience_size` nodes** (CC 6.1.5.3):
/// [`DurabilityMode::Full`] below [`FEASIBILITY_FLOOR`], [`DurabilityMode::Tuple`]
/// at or above it. Persist's rule at the shipped tuple.
#[must_use]
pub fn target_mode(audience_size: usize) -> DurabilityMode {
    durability_mode(audience_size, FEASIBILITY_FLOOR)
}

/// Is `row` placed at a tier whose files this module keeps durable? `self`
/// and `family`: the tiers whose bytes are delivered to the cohort and never
/// claimed (`community` and the commons keep their `holds_bytes` plane).
#[must_use]
pub fn is_cohort_delivered(row: &Attestation) -> bool {
    matches!(
        row.cohort_scope.as_str(),
        cohort_scope::SELF | cohort_scope::FAMILY
    )
}

/// The group a `self`/`family` row is bound to: the family it names (its
/// signed cohort target). `None` for `self`, whose audience follows its
/// author.
fn group_of(row: &Attestation) -> Option<&str> {
    ciris_persist::federation::admission::envelope_cohort_target(&row.attestation_envelope)
        .ok()
        .flatten()
}

/// **The durability deficit of the blob `sha` that `row` names**, from the
/// directory alone: persist's audience over the row's provenance, and each
/// audience node's custody fold at `now`.
///
/// # Errors
/// The directory read failed.
pub async fn row_deficit(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    sha: &[u8; 32],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DurabilityDeficit, ciris_persist::federation::Error> {
    let audience = content_audience(
        directory,
        &row.cohort_scope,
        Some(&row.attesting_key_id),
        group_of(row),
    )
    .await?;
    deficit_over(
        directory,
        &hex::encode(sha),
        audience,
        &BTreeMap::new(),
        FEASIBILITY_FLOOR,
        now,
    )
    .await
}

/// **CIRISEdge#817 — one durability pass's custody reads.**
///
/// [`row_deficit`] hands persist's `deficit_over` an EMPTY `known` map, so
/// every audience node is folded afresh for every file: one
/// `list_attestations_by(device)` (≈ 7 KB of heap per row the device signed)
/// per audience node per file, plus one more for this node's own verdict.
/// A pass over F files and D audience devices paid F × D + F full-history
/// reads, which is what made the pass's churn quadratic in the field.
///
/// This holds each device's admitted custody reports, indexed by blob, read
/// ONCE per device per pass, and folds every `(device, file)` verdict from
/// that index with persist's own [`fold_device_custody`]. The reports are
/// re-derived exactly as persist's `custody_acks_of` derives them: the rows
/// the device signed, its retired rows (persist's `retired_ids`) folded out, a
/// row that does not parse skipped, and only the device's own reports kept.
/// Every `known` entry handed to `deficit_over` is therefore the verdict its
/// own fold would have reached, and no audience node is folded there.
///
/// One value per pass, never kept across passes: a report filed or
/// replicated after a device's index was read is seen by the NEXT pass. Within
/// a pass that is exact for this node's own filings too, because a pass
/// visits each blob once and a filing only moves that blob's verdict, which
/// the pass has already read. A read that fails is not cached: the file it
/// was for is skipped, as before, and the next file asks again.
#[derive(Debug, Default)]
pub struct PassCustody {
    by_device: HashMap<String, HashMap<String, Vec<CustodyAck>>>,
    folds: usize,
}

impl PassCustody {
    /// A pass with nothing read yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many device histories this pass has read from the directory: one
    /// per device it met, plus any audience node handed to persist without a
    /// verdict (none, since every audience node is filled). The pass's
    /// witness, booked on the pass log line.
    #[must_use]
    pub fn folds(&self) -> usize {
        self.folds
    }

    /// `device`'s custody reports, by blob, read once per pass.
    async fn reports_of(
        &mut self,
        directory: &dyn FederationDirectory,
        device: &str,
    ) -> Result<&HashMap<String, Vec<CustodyAck>>, ciris_persist::federation::Error> {
        if !self.by_device.contains_key(device) {
            let rows = directory.list_attestations_by(device).await?;
            self.folds += 1;
            let refs: Vec<&Attestation> = rows.iter().collect();
            let retired = ciris_persist::federation::precedence::retired_ids(&refs);
            let mut by_blob: HashMap<String, Vec<CustodyAck>> = HashMap::new();
            for row in rows.iter().filter(|r| !retired.contains(&r.attestation_id)) {
                let ack = match parse_custody_ack(row) {
                    Ok(Some(a)) => a,
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::warn!(
                            attestation_id = %row.attestation_id,
                            error = %e,
                            "custody fold skips a malformed report"
                        );
                        continue;
                    }
                };
                if ack.device_key_id == device {
                    by_blob
                        .entry(ack.blob_sha256_hex.clone())
                        .or_default()
                        .push(ack);
                }
            }
            self.by_device.insert(device.to_owned(), by_blob);
        }
        Ok(&self.by_device[device])
    }

    /// **`device`'s custody of the blob `sha256_hex`** at `now`, with no
    /// receipt: persist's `device_custody_of`, over this pass's index.
    ///
    /// # Errors
    /// The device's history could not be read.
    pub async fn custody_of(
        &mut self,
        directory: &dyn FederationDirectory,
        device: &str,
        sha256_hex: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<DeviceCustody, ciris_persist::federation::Error> {
        let reports = self.reports_of(directory, device).await?;
        let acks = reports.get(sha256_hex).map_or(&[][..], Vec::as_slice);
        Ok(fold_device_custody(device, acks, None, now))
    }

    /// **[`row_deficit`], inside a pass**: the same audience and the same
    /// deficit, with every audience node's verdict taken from this pass's
    /// index instead of re-folded per file.
    ///
    /// # Errors
    /// The directory read failed.
    pub async fn row_deficit(
        &mut self,
        directory: &dyn FederationDirectory,
        row: &Attestation,
        sha: &[u8; 32],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<DurabilityDeficit, ciris_persist::federation::Error> {
        let audience = content_audience(
            directory,
            &row.cohort_scope,
            Some(&row.attesting_key_id),
            group_of(row),
        )
        .await?;
        let sha_hex = hex::encode(sha);
        let mut known = BTreeMap::new();
        if let ContentAudience::Nodes(nodes) = &audience {
            for node in nodes {
                let state = self.custody_of(directory, node, &sha_hex, now).await?.state;
                known.insert(node.clone(), state);
            }
            // Every node persist would still fold itself: zero, by the loop
            // above. Counted rather than assumed, so the witness measures it.
            self.folds += nodes.iter().filter(|n| !known.contains_key(*n)).count();
        }
        deficit_over(
            directory,
            &sha_hex,
            audience,
            &known,
            FEASIBILITY_FLOOR,
            now,
        )
        .await
    }
}

/// The audience nodes a deficit names, or `None` when it is not enumerable
/// (the commons, or an unresolvable row).
#[must_use]
pub fn audience_of(deficit: &DurabilityDeficit) -> Option<&[String]> {
    match &deficit.audience {
        ciris_persist::federation::durability::DeficitAudience::Nodes(n) => Some(n),
        _ => None,
    }
}

/// One file this node is missing: the row that names it, its address, and
/// how many audience nodes hold it live.
#[derive(Debug, Clone)]
pub struct Repair {
    /// The file row (the pull's access grant).
    pub row: Attestation,
    /// The blob's at-rest address.
    pub sha: [u8; 32],
    /// The audience nodes with a live `here` — the holders to pull from.
    pub live_here: Vec<String>,
}

/// **Rarest first** (CC 6.1.5.3): the file with the fewest live holders is
/// repaired first, since it is the one closest to being lost. Ties by
/// address, so the order is stable.
pub fn rarest_first(repairs: &mut [Repair]) {
    repairs.sort_by(|a, b| {
        a.live_here
            .len()
            .cmp(&b.live_here.len())
            .then_with(|| a.sha.cmp(&b.sha))
    });
}

/// What one durability pass found on this node.
#[derive(Debug, Clone, Default)]
pub struct DurabilitySweep {
    /// Files this node is in the audience of and does not hold whole,
    /// rarest first.
    pub repairs: Vec<Repair>,
    /// Files this node holds whole and (re-)filed its `here` for.
    pub reported_here: Vec<[u8; 32]>,
    /// Files this node read but is not in the audience of.
    pub not_in_audience: usize,
}

/// A report older than this is re-filed on the next sweep, well inside its
/// 72 h liveness (persist: "re-acknowledge about daily").
pub const CUSTODY_REFRESH: chrono::Duration = chrono::Duration::hours(24);

/// Does this node hold the file `pointer` names WHOLE — every byte it would
/// read? A whole blob is its row; a chunk DAG is its manifest AND every chunk
/// the manifest names (persist's readiness door, opened as `me` under the
/// row's own AAD). `Ok(false)` for an adopted manifest not yet promoted.
///
/// # Errors
/// A store read failed.
pub async fn holds_whole<B>(
    engine: &ciris_persist::Engine,
    backend: &B,
    me: &str,
    row: &Attestation,
    sha: &[u8; 32],
    pointer: &crate::group_content::BlobPointer,
) -> Result<bool, String>
where
    B: ciris_persist::federation::blobs::BlobStorage + Sync,
{
    let Some(head) = backend
        .blob_head(sha)
        .await
        .map_err(|e| format!("blob_head: {e}"))?
    else {
        return Ok(false);
    };
    if pointer.stream_id.is_none() && head.storage_kind != "chunk_dag" {
        return Ok(true);
    }
    if head.storage_kind != "chunk_dag" {
        // A manifest adopted by a pull that has not promoted it yet.
        return Ok(false);
    }
    let aad = crate::group_content::content_aad(
        &row.attesting_key_id,
        row.asserted_at,
        pointer.content_field,
    );
    engine
        .sealed_dag_readiness(sha, me, Some(&aad))
        .await
        .map(|r| r.held)
        .map_err(|e| format!("sealed_dag_readiness: {e}"))
}

/// **File this node's custody report** for the file `row` names
/// (`custody:ack:v1`, CC 3.1.3.3), placed at the row's own cohort, through
/// persist's door (`Engine::put_custody_ack`). `here` is filed only when
/// every byte is held — for a chunk DAG the manifest AND every chunk, so a
/// report filed after a chunk repair covers the whole DAG — and names the
/// stored length; `none` is "this device is in the audience and holds no
/// copy".
///
/// The door opens the manifest under the row's own AAD (`content_aad`, the
/// data every file edge seals is bound to): a DAG not held whole is refused
/// `custody_ack_here_dag_incomplete`, a manifest that does not open under the
/// row's data `custody_ack_here_seal_did_not_open`.
///
/// A file whose row is withdrawn or recanted (CC 2.3) is never reported
/// `here`: the report is a holding of content its author retracted, and a
/// device must not advertise, to its cohort or to persist's tombstone fold,
/// that it keeps it. Asked by the same composer read the drive's lifecycle
/// uses ([`crate::files::FileLifecycle`]); a superseded file (a rename) still
/// has a live row over the same bytes and is reported as before.
///
/// # Errors
/// Persist refused the report (a `here` for a file not held whole, a seal that
/// did not open) or the emit failed; `here` for a retracted file; the
/// file's composers could not be read.
pub async fn file_custody(
    engine: &ciris_persist::Engine,
    row: &Attestation,
    sha: &[u8; 32],
    pointer: &crate::group_content::BlobPointer,
    state: ciris_persist::federation::custody_ack::CustodyState,
) -> Result<String, String> {
    use crate::files::FileLifecycle;
    if state == ciris_persist::federation::custody_ack::CustodyState::Here {
        match crate::files::row_lifecycle(engine, row).await? {
            FileLifecycle::Withdrawn | FileLifecycle::Recanted => {
                return Err(format!(
                    "custody: `here` not filed — {} is retracted (CC 2.3)",
                    row.attestation_id
                ));
            }
            FileLifecycle::Live | FileLifecycle::Superseded => {}
        }
    }
    let aad = crate::group_content::content_aad(
        &row.attesting_key_id,
        row.asserted_at,
        pointer.content_field,
    );
    engine
        .put_custody_ack(
            sha,
            state,
            Some(&row.cohort_scope),
            group_of(row),
            Some(&aad),
        )
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Tuple mode kicks in at `N + K` = 26 audience nodes; below it every
    /// audience node is a full holder** (CC 6.1.5.3). Written as literals,
    /// and pinned to edge's own fountain defaults so persist's restated
    /// constant and edge's tuple cannot drift apart.
    #[test]
    fn the_target_is_full_holding_below_26_and_the_tuple_at_26_763() {
        use crate::holonomic::fountain_defaults::{DEFAULT_K_REPAIR, DEFAULT_N_SOURCE};
        assert_eq!(FEASIBILITY_FLOOR, 26);
        assert_eq!(
            FEASIBILITY_FLOOR,
            (DEFAULT_N_SOURCE + DEFAULT_K_REPAIR) as usize,
            "persist's floor is edge's N + K"
        );
        assert_eq!(target_mode(1), DurabilityMode::Full);
        assert_eq!(target_mode(2), DurabilityMode::Full);
        assert_eq!(target_mode(25), DurabilityMode::Full);
        assert_eq!(target_mode(26), DurabilityMode::Tuple);
        assert_eq!(target_mode(40), DurabilityMode::Tuple);
    }
}
