//! persist v59.0.0 (sealed-transport floor, operator ruling 2026-10-19) — **the
//! key plane on the wire is its attestation rows.**
//!
//! A key record, a key revocation and an identity occurrence each live as one
//! `scores` row on the attestation plane (`key:record:v1`, `key:revocation:v1`,
//! `identity:occurrence:v1`; persist v58.0.0, CIRISPersist#991), and since
//! v59.0.0 their FRAMED objects (`SignedKeyRecord`, `SignedRevocation`,
//! `SignedIdentityOccurrence`, the framed occurrence revocation) are refused at
//! every persist door with the terminal `federation_envelope_kind_retired`.
//! A peer's framed object is never taken in to be re-minted locally as a row.
//!
//! This module holds the reads edge's three key-plane SESSION planes
//! ([`EnvelopeKind::key_plane_family`]) and first contact share. Every fold is
//! persist's: the family of a row is [`KeyPlaneFamily::of_row`], the object it
//! carries is `key_plane::{key_record_of_row, occurrence_of_row,
//! revocation_row}`, and the rows are read through persist's bounded
//! [`AttestationQuery`]. Nothing here re-derives a row.

use ciris_persist::federation::attestation_query::{AttestationQuery, FOLD_PAGE};
use ciris_persist::federation::key_plane::{self, KeyPlaneFamily};
use ciris_persist::federation::replication_policy;
use ciris_persist::federation::types::{Attestation, SignedAttestation};
use ciris_persist::federation::{Error, FederationDirectory};

use super::protocol::EnvelopeKind;

/// The attestation row a wire body carries: the bare [`Attestation`] (the wire
/// since CIRISEdge#397), or the pre-v14.1 `{"attestation": …}` wrap — the
/// bridge's own decode order.
#[must_use]
pub(crate) fn row_of_bytes(bytes: &[u8]) -> Option<Attestation> {
    serde_json::from_slice::<Attestation>(bytes)
        .ok()
        .or_else(|| {
            serde_json::from_slice::<SignedAttestation>(bytes)
                .ok()
                .map(|s| s.attestation)
        })
}

/// The key-plane family of the row a wire body carries, with the row; `None`
/// for any body that is not a key-plane row.
#[must_use]
pub(crate) fn key_plane_row_of_bytes(bytes: &[u8]) -> Option<(KeyPlaneFamily, Attestation)> {
    let row = row_of_bytes(bytes)?;
    KeyPlaneFamily::of_row(&row).map(|family| (family, row))
}

/// persist's typed refusal for a framed object of `kind` —
/// [`Error::EnvelopeKindRetired`] from persist's own
/// [`replication_policy::refuse_retired_framed`] — or `None` when the kind's
/// framed carriage is not retired. The refusal's `kind()` is the stable token
/// `federation_envelope_kind_retired`; its kind label is persist's
/// [`replication_policy::retired_detail`].
#[must_use]
pub(crate) fn retired_framed_refusal(kind: EnvelopeKind) -> Option<Error> {
    replication_policy::refuse_retired_framed(kind.persist_kind().as_str()).err()
}

/// Every `key:record:v1` row this node holds for `key_id`, newest first. A key
/// held without a row (it verifies under neither of persist's rules) has none
/// and does not travel.
///
/// # Errors
/// A page persist did not serve.
pub(crate) async fn key_record_rows<D>(dir: &D, key_id: &str) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    let mut pages = AttestationQuery::to(key_id, FOLD_PAGE)
        .dimension(key_plane::KEY_RECORD_DIMENSION)
        .pages();
    while let Some(page) = pages.next(dir).await? {
        out.extend(
            page.into_iter().filter(|row| {
                key_plane::key_record_of_row(row).is_some_and(|r| r.key_id == key_id)
            }),
        );
    }
    Ok(out)
}

/// Every `identity:occurrence:v1` row this node holds about `identity_key_id`
/// (the row is attested about the identity), newest first.
///
/// # Errors
/// A page persist did not serve.
pub(crate) async fn occurrence_rows_about<D>(
    dir: &D,
    identity_key_id: &str,
) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    let mut pages = AttestationQuery::to(identity_key_id, FOLD_PAGE)
        .dimension(key_plane::IDENTITY_OCCURRENCE_DIMENSION)
        .pages();
    while let Some(page) = pages.next(dir).await? {
        out.extend(
            page.into_iter()
                .filter(|row| key_plane::occurrence_of_row(row).is_some()),
        );
    }
    Ok(out)
}

/// Every `identity:occurrence:v1` row this node holds that binds
/// `occurrence_key_id`, under any identity. The identities are persist's
/// `list_identity_occurrences_by_occurrence_key` (every identity the key is
/// bound under, a stale binding included); the rows are each identity's.
///
/// # Errors
/// A read persist did not serve.
pub(crate) async fn occurrence_rows_binding<D>(
    dir: &D,
    occurrence_key_id: &str,
) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut identities: Vec<String> = dir
        .list_identity_occurrences_by_occurrence_key(occurrence_key_id)
        .await?
        .into_iter()
        .map(|o| o.identity_key_id)
        .collect();
    identities.sort();
    identities.dedup();
    let mut out = Vec::new();
    for identity in identities {
        out.extend(
            occurrence_rows_about(dir, &identity)
                .await?
                .into_iter()
                .filter(|row| {
                    key_plane::occurrence_of_row(row).is_some_and(|o| {
                        o.identity_occurrence.occurrence_key_id == occurrence_key_id
                    })
                }),
        );
    }
    Ok(out)
}

/// The `key:revocation:v1` row of every revocation this node holds OF
/// `key_id`, when it holds the row (persist's own `wire_refs_for_subject`
/// read: `revocations_for`, then the row persist minted for each).
///
/// # Errors
/// A read persist did not serve.
pub(crate) async fn revocation_rows_of<D>(dir: &D, key_id: &str) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for revocation in dir.revocations_for(key_id).await? {
        let id = key_plane::revocation_row(&revocation)?.attestation_id;
        if let Some(row) = dir.get_attestation(&id).await? {
            out.push(row);
        }
    }
    Ok(out)
}

/// What a row on the IdentityOccurrenceRevocation plane is, as this node
/// holds it — THE family check of that plane, in one place.
///
/// persist v59.0.0 — an occurrence revocation travels as a `withdraws` whose
/// target is a held `identity:occurrence:v1` row, or as an
/// `identity:occurrence_revocation:v1` carrier (a legacy framed revocation's
/// row); persist's [`key_plane::occurrence_revoked_by`] names both. The one
/// reading edge adds is the ordering gap: a `withdraws` whose target this node
/// does not hold yet ([`OccurrenceRevocation::UnheldTarget`]), which may still
/// turn out to be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OccurrenceRevocation {
    /// It revokes an occurrence (persist's predicate).
    Revokes,
    /// A `withdraws` naming a row this node does not hold (yet).
    UnheldTarget,
    /// Anything else.
    Not,
}

/// Classify `row` as an [`OccurrenceRevocation`] against what `dir` holds.
///
/// # Errors
/// A read persist did not serve.
pub(crate) async fn occurrence_revocation<D>(
    dir: &D,
    row: &Attestation,
) -> Result<OccurrenceRevocation, Error>
where
    D: FederationDirectory + ?Sized,
{
    use ciris_persist::federation::types::attestation_type::WITHDRAWS;
    if key_plane::occurrence_revoked_by(dir, row).await?.is_some() {
        return Ok(OccurrenceRevocation::Revokes);
    }
    if row.attestation_type == WITHDRAWS {
        if let Some(target) =
            ciris_persist::federation::precedence::references_attestation_id_from_envelope(
                &row.attestation_envelope,
            )
        {
            if dir.get_attestation(target).await?.is_none() {
                return Ok(OccurrenceRevocation::UnheldTarget);
            }
        }
    }
    Ok(OccurrenceRevocation::Not)
}

/// Every `identity:occurrence_revocation:v1` carrier this node holds about
/// `identity_key_id` (the carrier is attested about the identity).
async fn carriers_about<D>(dir: &D, identity_key_id: &str) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    use ciris_persist::federation::occurrence_revocation_carrier::{
        carrier_of_row, CARRIER_DIMENSION,
    };
    let mut out = Vec::new();
    let mut pages = AttestationQuery::to(identity_key_id, FOLD_PAGE)
        .dimension(CARRIER_DIMENSION)
        .pages();
    while let Some(page) = pages.next(dir).await? {
        out.extend(page.into_iter().filter(|row| carrier_of_row(row).is_some()));
    }
    Ok(out)
}

/// Every `withdraws` this node holds whose target is one of `rows` (the
/// occurrence rows), through persist's indexed composer read.
async fn withdrawals_of<D>(dir: &D, rows: Vec<Attestation>) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    use ciris_persist::federation::types::attestation_type::WITHDRAWS;
    let ids: Vec<String> = rows.into_iter().map(|r| r.attestation_id).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    Ok(dir
        .list_composers_referencing_any(&ids, None, None)
        .await?
        .into_iter()
        .filter(|r| r.attestation_type == WITHDRAWS)
        .collect())
}

/// persist v59.0.0 — the occurrence revocations of `occurrence_key_id`: every
/// held `withdraws` of an `identity:occurrence:v1` row binding it, and every
/// `identity:occurrence_revocation:v1` carrier naming it.
///
/// # Errors
/// A read persist did not serve.
pub(crate) async fn occurrence_withdrawals_binding<D>(
    dir: &D,
    occurrence_key_id: &str,
) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let rows = occurrence_rows_binding(dir, occurrence_key_id).await?;
    let mut identities: Vec<String> = rows
        .iter()
        .filter_map(key_plane::occurrence_of_row)
        .map(|o| o.identity_occurrence.identity_key_id)
        .collect();
    identities.sort();
    identities.dedup();
    let mut out = withdrawals_of(dir, rows).await?;
    // The key as an IDENTITY too: a carrier revoking one of its own
    // occurrences is attested about it, whether or not this node holds that
    // occurrence's row.
    out.extend(carriers_about(dir, occurrence_key_id).await?);
    for identity in identities {
        for carrier in carriers_about(dir, &identity).await? {
            if key_plane::occurrence_revoked_by(dir, &carrier)
                .await?
                .is_some_and(|(_, occ)| occ == occurrence_key_id)
            {
                out.push(carrier);
            }
        }
    }
    Ok(out)
}

/// persist v59.0.0 — the occurrence revocations about `identity_key_id`: every
/// held `withdraws` of an `identity:occurrence:v1` row about it, and every
/// carrier about it.
///
/// # Errors
/// A read persist did not serve.
pub(crate) async fn occurrence_withdrawals_about<D>(
    dir: &D,
    identity_key_id: &str,
) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let rows = occurrence_rows_about(dir, identity_key_id).await?;
    let mut out = withdrawals_of(dir, rows).await?;
    out.extend(carriers_about(dir, identity_key_id).await?);
    Ok(out)
}

/// The occurrence key an `identity:occurrence:v1` row binds.
#[must_use]
pub(crate) fn occurrence_key_of(row: &Attestation) -> Option<String> {
    key_plane::occurrence_of_row(row).map(|o| o.identity_occurrence.occurrence_key_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// persist v59.0.0 — the four retired kinds answer persist's typed refusal
    /// under its stable token, labelled per kind; no other kind does.
    #[test]
    fn retired_framed_refusal_is_persists_typed_token_per_kind_v59() {
        for kind in EnvelopeKind::ALL {
            match retired_framed_refusal(kind) {
                Some(e) => {
                    assert!(kind.is_framed_retired(), "{kind:?}");
                    // persist v59.0.0 — the token is persist's const, never a
                    // literal (the witness the retired token matches it).
                    assert_eq!(e.kind(), replication_policy::ENVELOPE_KIND_RETIRED);
                    assert!(
                        e.to_string().starts_with(&format!(
                            "{}: {}",
                            replication_policy::ENVELOPE_KIND_RETIRED,
                            kind.as_wire_str()
                        )),
                        "{kind:?}: {e}"
                    );
                }
                None => assert!(!kind.is_framed_retired(), "{kind:?}"),
            }
        }
    }

    #[test]
    fn a_body_that_is_not_a_row_has_no_family_v59() {
        assert!(key_plane_row_of_bytes(b"{\"record\":{}}").is_none());
        assert!(key_plane_row_of_bytes(b"not json").is_none());
    }
}
