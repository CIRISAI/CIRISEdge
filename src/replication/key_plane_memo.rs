//! CIRISEdge#930 — **the key-plane listings, computed once and served many.**
//!
//! persist v59.0.0 left edge four key-plane listings it reads per SUBJECT:
//! each subject in the plane's publish set costs one to several indexed reads
//! ([`super::key_plane_rows`]), and two of the four (Revocation and the
//! occurrence-revocation plane) enumerate `Projection::Global` — own ∪
//! cohort, which on the production canonical is every key in the federation
//! (7,226). Every peer's round re-ran the whole fan-out, so the node spent
//! ~800 indexed reads/s answering "nothing" (143,824 `attestation_query` and
//! 10,484 empty `list_composers_referencing_any` calls in its first three
//! minutes), and before 0.5.243 one thread sat at 99% for hours.
//!
//! These listings are PEER-INVARIANT: a subject's rows on a key plane do not
//! depend on who asks (the per-peer narrowing of the identity planes, #682,
//! narrows the SUBJECT SET, never one subject's rows). So one subject's
//! answer is memoized per plane ([`PlaneMemo`]), and a listing over any
//! subject set reads the store only for the subjects it has no answer for.
//!
//! ## When an answer goes stale — the store's own cursor
//!
//! A stale answer would silently stop replicating a new revocation, which is
//! worse than the CPU. So invalidation is driven by THE STORE, not by edge's
//! apply path: every listing first drains persist's admission cursor
//! (`list_attestations_since`, the `(admitted_at, attestation_id)` serve
//! position, monotonic per CIRISPersist#668) from where the memo last
//! stopped, and every key-plane-relevant row in that delta drops the answers
//! it can change ([`dirt_of`]). The cursor sees every write that lands a
//! federation-tier row, whichever door it came through: a replicated apply,
//! the local authoring doors (`put_revocation`, `put_identity_occurrence`,
//! the claim path's `put_public_key`), a promotion (which re-stamps the
//! position). That is the CIRISEdge#858 lesson: a mechanism keyed on edge's
//! apply choke misses every local registration.
//!
//! ## What the cursor cannot see, and the bound on it
//!
//! A write that changes a listing WITHOUT landing a federation-tier row —
//! a key admitted with no `key:record:v1` row (it then resolves a revocation
//! held before it), a projection-table write with no row, a purge tombstone,
//! or two postgres writers tying on one position — is caught by the
//! [`MEMO_TTL`] rebuild: every answer is re-read at least that often. The old
//! behaviour was a TTL of zero; the bound is now explicit instead of being an
//! accident of how often peers asked.
//!
//! What the per-round sweep was ALSO doing (the "symptom doing work" check):
//! retrying a subject whose read failed. A failed read is never memoized, so
//! it is retried on the next listing exactly as before.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use ciris_persist::federation::key_plane::{self, KeyPlaneFamily};
use ciris_persist::federation::occurrence_revocation_carrier::is_carrier_row;
use ciris_persist::federation::types::{attestation_type::WITHDRAWS, Attestation};
use ciris_persist::federation::{Error, FederationDirectory};

use super::key_plane_rows;
use super::protocol::{EnvelopeKind, EnvelopeRef};

/// Every memoized answer is re-read at least this often, whatever the
/// cursor says (see the module docs for what the cursor cannot see).
pub(crate) const MEMO_TTL: Duration = Duration::from_secs(600);

/// How far before "now" a rebuilt memo's cursor starts. The rebuild drains
/// the cursor to the end of the log before it reads any subject, so the lag
/// only bounds that first drain (a wall clock that stepped is absorbed by
/// persist's monotonic position allocator, CIRISPersist#668). On sqlite every
/// write allocates its position and commits under the one connection, so a
/// row committed after the drain is always past the cursor; a postgres tie
/// between concurrent writers is the [`MEMO_TTL`] residual.
pub(crate) const CURSOR_LAG: Duration = Duration::from_secs(60);

/// The change probe's page: rows of the delta read per statement.
pub(crate) const PROBE_PAGE: u32 = 500;

/// The persist `(serve_position, resume_id)` cursor.
pub(crate) type ResumeCursor = (chrono::DateTime<chrono::Utc>, String);

/// The four per-subject key-plane reads, one memo each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KeyPlaneRead {
    /// [`key_plane_rows::key_record_rows`] — the Key plane.
    KeyRecord,
    /// [`key_plane_rows::occurrence_rows_binding`] — the IdentityOccurrence plane.
    OccurrenceBinding,
    /// [`key_plane_rows::revocation_rows_of`] — the Revocation plane.
    Revocation,
    /// [`key_plane_rows::occurrence_withdrawals_binding`] — the
    /// IdentityOccurrenceRevocation plane.
    OccurrenceWithdrawal,
}

impl KeyPlaneRead {
    #[cfg(test)]
    pub(crate) const ALL: [Self; 4] = [
        Self::KeyRecord,
        Self::OccurrenceBinding,
        Self::Revocation,
        Self::OccurrenceWithdrawal,
    ];

    /// The memo slot.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::KeyRecord => 0,
            Self::OccurrenceBinding => 1,
            Self::Revocation => 2,
            Self::OccurrenceWithdrawal => 3,
        }
    }

    /// The session plane this read serves.
    pub(crate) const fn kind(self) -> EnvelopeKind {
        match self {
            Self::KeyRecord => EnvelopeKind::Key,
            Self::OccurrenceBinding => EnvelopeKind::IdentityOccurrence,
            Self::Revocation => EnvelopeKind::Revocation,
            Self::OccurrenceWithdrawal => EnvelopeKind::IdentityOccurrenceRevocation,
        }
    }

    /// The withhold-detail site name (stable: the pre-#930 function names).
    pub(crate) const fn site(self) -> &'static str {
        match self {
            Self::KeyRecord => "list_key_record_rows",
            Self::OccurrenceBinding => "list_occurrence_rows",
            Self::Revocation => "list_revocation_rows",
            Self::OccurrenceWithdrawal => "list_occurrence_withdrawal_rows",
        }
    }

    /// The per-subject read itself — exactly the pre-#930 call.
    ///
    /// # Errors
    /// A read persist did not serve.
    pub(crate) async fn read<D>(self, dir: &D, subject: &str) -> Result<Vec<Attestation>, Error>
    where
        D: FederationDirectory + ?Sized,
    {
        match self {
            Self::KeyRecord => key_plane_rows::key_record_rows(dir, subject).await,
            Self::OccurrenceBinding => key_plane_rows::occurrence_rows_binding(dir, subject).await,
            Self::Revocation => key_plane_rows::revocation_rows_of(dir, subject).await,
            Self::OccurrenceWithdrawal => {
                key_plane_rows::occurrence_withdrawals_binding(dir, subject).await
            }
        }
    }
}

/// What one delta row means for one plane's memo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Dirt {
    /// Nothing this plane answers can change.
    Clean,
    /// These subjects' answers may change.
    Subjects(Vec<String>),
    /// The row may change an answer this plane cannot pin to a subject
    /// (a revocation names its subject by digest; a carrier's reach runs
    /// through identities): every answer goes.
    Plane,
}

/// The occurrence key of the `identity:occurrence:v1` row a `withdraws`
/// targets, when this node holds that target (`Ok(None)` for any other
/// target, or one not held yet — its arrival is itself a delta row).
async fn withdrawn_occurrence<D>(dir: &D, row: &Attestation) -> Result<Option<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(target) =
        ciris_persist::federation::precedence::references_attestation_id_from_envelope(
            &row.attestation_envelope,
        )
    else {
        return Ok(None);
    };
    Ok(dir
        .get_attestation(target)
        .await?
        .as_ref()
        .and_then(key_plane_rows::occurrence_key_of))
}

/// What `row` — a row the store admitted (or re-stamped) since the memo's
/// cursor — can change in `read`'s answers. Conservative by construction:
/// every arm names AT LEAST the subjects whose per-subject read can see the
/// row, and an arm that cannot pin a subject drops the plane.
///
/// - `key:record:v1` of K: the Key plane's K, and the Revocation plane's K (a
///   revocation held before K's key resolves once the key lands, persist
///   #784's digest rule);
/// - `key:revocation:v1`: the Revocation plane, whole (the row is attested
///   by its REVOKER; the subject is a digest);
/// - `identity:occurrence:v1` binding O: the IdentityOccurrence and
///   occurrence-revocation planes' O (a `withdraws` held before its target
///   is found once the target lands);
/// - a `withdraws` of a held occurrence row binding O: both planes' O;
/// - an `identity:occurrence_revocation:v1` carrier: the occurrence-revocation
///   plane, whole.
///
/// # Errors
/// The `withdraws` target read failed; the caller drops the plane.
pub(crate) async fn dirt_of<D>(
    read: KeyPlaneRead,
    dir: &D,
    row: &Attestation,
) -> Result<Dirt, Error>
where
    D: FederationDirectory + ?Sized,
{
    use KeyPlaneRead as R;
    let family = KeyPlaneFamily::of_row(row);
    let key_record_subjects = || {
        let mut s = vec![row.attested_key_id.clone()];
        if let Some(record) = key_plane::key_record_of_row(row) {
            s.push(record.key_id);
        }
        s
    };
    Ok(match (read, family) {
        (R::KeyRecord | R::Revocation, Some(KeyPlaneFamily::KeyRecord)) => {
            Dirt::Subjects(key_record_subjects())
        }
        (R::Revocation, Some(KeyPlaneFamily::KeyRevocation)) => Dirt::Plane,
        (
            R::OccurrenceBinding | R::OccurrenceWithdrawal,
            Some(KeyPlaneFamily::IdentityOccurrence),
        ) => key_plane_rows::occurrence_key_of(row)
            .map_or(Dirt::Clean, |occurrence| Dirt::Subjects(vec![occurrence])),
        (R::OccurrenceWithdrawal, None) if is_carrier_row(row) => Dirt::Plane,
        (R::OccurrenceBinding | R::OccurrenceWithdrawal, None)
            if row.attestation_type == WITHDRAWS =>
        {
            withdrawn_occurrence(dir, row)
                .await?
                .map_or(Dirt::Clean, |occurrence| Dirt::Subjects(vec![occurrence]))
        }
        _ => Dirt::Clean,
    })
}

/// One plane's memo: each subject's refs, the store cursor the answers are
/// current to, and when the memo was last rebuilt.
#[derive(Debug, Default)]
pub(crate) struct PlaneMemo {
    entries: HashMap<String, Vec<EnvelopeRef>>,
    cursor: Option<ResumeCursor>,
    built_at: Option<Instant>,
}

impl PlaneMemo {
    /// Is the memo due a rebuild (never built, or past [`MEMO_TTL`])?
    pub(crate) fn needs_rebuild(&self, now: Instant) -> bool {
        self.built_at.map_or(true, |built| {
            now.saturating_duration_since(built) >= MEMO_TTL
        })
    }

    /// Drop every answer and restart the cursor [`CURSOR_LAG`] before `wall`.
    pub(crate) fn rebuild(&mut self, now: Instant, wall: chrono::DateTime<chrono::Utc>) {
        self.entries.clear();
        let lag =
            chrono::Duration::from_std(CURSOR_LAG).unwrap_or_else(|_| chrono::Duration::zero());
        self.cursor = Some((wall - lag, String::new()));
        self.built_at = Some(now);
    }

    /// Forget everything, so the next listing rebuilds (a probe that could
    /// not read the store cannot vouch for any answer).
    pub(crate) fn forget(&mut self) {
        self.entries.clear();
        self.cursor = None;
        self.built_at = None;
    }

    /// The cursor the next probe resumes from.
    pub(crate) fn cursor(&self) -> Option<ResumeCursor> {
        self.cursor.clone()
    }

    /// The probe consumed through `cursor`.
    pub(crate) fn advance(&mut self, cursor: ResumeCursor) {
        self.cursor = Some(cursor);
    }

    /// Apply one row's [`Dirt`]; returns how many answers were dropped.
    pub(crate) fn apply(&mut self, dirt: &Dirt) -> usize {
        match dirt {
            Dirt::Clean => 0,
            Dirt::Subjects(subjects) => subjects
                .iter()
                .filter(|s| self.entries.remove(s.as_str()).is_some())
                .count(),
            Dirt::Plane => {
                let n = self.entries.len();
                self.entries.clear();
                n
            }
        }
    }

    /// The memoized answer for `subject`.
    pub(crate) fn get(&self, subject: &str) -> Option<&Vec<EnvelopeRef>> {
        self.entries.get(subject)
    }

    /// Memoize `subject`'s answer.
    pub(crate) fn insert(&mut self, subject: String, refs: Vec<EnvelopeRef>) {
        self.entries.insert(subject, refs);
    }

    /// Answers held.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The four plane memos. Each has its own lock so a long fill on one plane
/// (the Global Revocation sweep after a rebuild) never parks another plane's
/// listing; within a plane the lock IS the single flight — N peers' rounds
/// arriving together wait for one fill and then answer from it.
#[derive(Debug, Default)]
pub(crate) struct KeyPlaneMemos {
    planes: [tokio::sync::Mutex<PlaneMemo>; 4],
}

impl KeyPlaneMemos {
    /// `read`'s memo.
    pub(crate) fn plane(&self, read: KeyPlaneRead) -> &tokio::sync::Mutex<PlaneMemo> {
        &self.planes[read.index()]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_reads_have_four_slots() {
        let mut slots: Vec<usize> = KeyPlaneRead::ALL.iter().map(|r| r.index()).collect();
        slots.sort_unstable();
        assert_eq!(slots, vec![0, 1, 2, 3]);
    }

    #[test]
    fn a_fresh_memo_rebuilds_and_a_rebuilt_one_holds_until_the_ttl() {
        let mut m = PlaneMemo::default();
        let t0 = Instant::now();
        assert!(m.needs_rebuild(t0));
        m.rebuild(t0, chrono::Utc::now());
        let just_before = (t0 + MEMO_TTL)
            .checked_sub(Duration::from_secs(1))
            .expect("after t0");
        assert!(!m.needs_rebuild(just_before));
        assert!(m.needs_rebuild(t0 + MEMO_TTL));
    }

    #[test]
    fn dirt_drops_only_what_it_names() {
        let mut m = PlaneMemo::default();
        m.insert("a".into(), Vec::new());
        m.insert("b".into(), Vec::new());
        assert_eq!(m.apply(&Dirt::Clean), 0);
        assert_eq!(m.apply(&Dirt::Subjects(vec!["a".into(), "z".into()])), 1);
        assert!(m.get("a").is_none() && m.get("b").is_some());
        assert_eq!(m.apply(&Dirt::Plane), 1);
        assert_eq!(m.len(), 0);
    }
}
