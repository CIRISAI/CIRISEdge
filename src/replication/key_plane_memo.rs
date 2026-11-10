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
//! position, monotonic per CIRISPersist#668) from where it last stopped,
//! and every key-plane-relevant row in that delta drops the answers it can
//! change ([`dirt_of`]). v45 (CIRISEdge#971): that position is ONE, shared by
//! the four memos and the holdings index ([`super::store_feed`]); a memo
//! receives the rows drained while it was not listing through the feed's
//! inbox, so the guarantee per listing is unchanged. The cursor sees every write that lands a
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
//! [`MEMO_TTL`] revalidation: every answer is re-read at least that often. The
//! old behaviour was a TTL of zero; the bound is now explicit instead of being
//! an accident of how often peers asked.
//!
//! **The stated bound is two [`MEMO_TTL`]s** (it was one before v45, when the
//! TTL cleared the memo). With stale-while-revalidate an answer read late in
//! one epoch can be served through the next, so a write the cursor cannot
//! see — a purge tombstone above all — may leave a hash offered for up to
//! 2 × [`MEMO_TTL`] after the write. The cost is bounded and honest: the
//! peer's Fetch of that hash misses (the row is gone, and admission refuses
//! it by its tombstone), so the residual is a wasted offer, never a wrong
//! row. Anything the cursor DOES see (a revocation, a new key row) drops the
//! answer at once, fresh or stale. Accepted for the v45 LTS (team lead,
//! 2026-11-09).
//!
//! ## v45 (CIRISEdge#971): stale-while-revalidate, a read budget, a listing cache
//!
//! Before v45 the TTL cleared the memo and the next listing re-read every
//! subject under the plane's lock: one burst of 8,211 Key reads (DERIVED
//! ~16 s) with every peer's round waiting. Now:
//!
//! - the TTL opens a new EPOCH instead of clearing ([`PlaneMemo::revalidate`]):
//!   an answer of the last epoch is served while it waits for its re-read,
//!   and one not re-read in a whole epoch is dropped, so nothing is served
//!   more than two TTLs after it was read. The feed's dirt is applied BEFORE
//!   the epoch turns, and a stale answer is dropped by dirt exactly as a fresh
//!   one is: a stale answer is only ever wrong by what the cursor cannot see,
//!   the residual the TTL always bounded;
//! - one listing reads at most [`KEY_PLANE_READ_BUDGET`] subjects, for every
//!   cause together; the host's own keys are outside it. A subject not read
//!   is ABSENT from the listing (a missed offer, never a wrong one), and the
//!   number left is a gauge;
//! - a listing every subject of which was answered fresh is kept whole
//!   ([`PlaneMemo::store_listing`]) and served again for an equal subject set
//!   while the memo's generation has not moved, so an idle round costs no
//!   walk of the memo either.
//!
//! What the per-round sweep was ALSO doing (the "symptom doing work" check):
//! retrying a subject whose read failed. A failed read is never memoized, so
//! it is retried on the next listing exactly as before.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use ciris_persist::federation::key_plane::{self, KeyPlaneFamily};
use ciris_persist::federation::occurrence_revocation_carrier::is_carrier_row;
use ciris_persist::federation::types::{attestation_type::WITHDRAWS, Attestation};
use ciris_persist::federation::{Error, FederationDirectory};

use super::key_plane_rows;
use super::protocol::{EnvelopeKind, EnvelopeRef};

/// Every memoized answer is re-read at least this often, whatever the
/// cursor says (see the module docs for what the cursor cannot see).
pub(crate) const MEMO_TTL: Duration = Duration::from_mins(10);

/// How far before "now" the shared feed's first cursor starts
/// ([`super::store_feed::Position::cursor`]). The first listing drains the
/// cursor to the end of the log before it reads any subject, so the lag only
/// bounds that first drain (a wall clock that stepped is absorbed by
/// persist's monotonic position allocator, CIRISPersist#668). On sqlite every
/// write allocates its position and commits under the one connection, so a
/// row committed after the drain is always past the cursor; a postgres tie
/// between concurrent writers is the [`MEMO_TTL`] residual.
pub(crate) const CURSOR_LAG: Duration = Duration::from_mins(1);

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

/// How many key-plane subjects one listing reads from the store, for every
/// cause together (never built, the [`MEMO_TTL`] revalidation, a forgotten
/// memo, a subject a delta row dirtied). CIRISEdge#971: before v45 a TTL
/// refill read every subject of the plane under the plane's lock in one
/// listing (DERIVED at ~2 ms a read: ~16 s for the Key plane's 8,211
/// subjects on canonical-1, ~11 to 22 s for the IdentityOccurrence plane's
/// 5,652), and every peer round on that plane waited behind it. With the
/// budget a listing reads at most this many; the rest wait for the next
/// listings, each of which reads the next `KEY_PLANE_READ_BUDGET`, so a full
/// refill is spread over `subjects / KEY_PLANE_READ_BUDGET` listings
/// (33 for the Key plane at that size).
///
/// The host's OWN keys (`self_provider`) are outside the budget: a node's
/// own rows are never late. A subject left unread by the budget is ABSENT
/// from the listing (a missed offer, as a failed read always was), never
/// offered from an answer a delta row has dropped; the count left is the
/// `key_plane.<plane>.unread` gauge, so a stall is a number.
pub(crate) const KEY_PLANE_READ_BUDGET: usize = 256;

/// How many whole listings a plane's memo keeps (CIRISEdge#971 listing
/// cache). A listing is keyed on its subject set: the Global planes ask one
/// set, the Key plane one per host selector answer, the IdentityOccurrence
/// plane one per #682 per-peer narrowing. A few slots cover the sets that
/// recur between two changes; a set past them is walked from the memo, as
/// before v45, which costs hash lookups and no store read.
pub(crate) const LISTING_CACHE_SLOTS: usize = 4;

/// One subject's memoized answer and the TTL epoch it was read in.
#[derive(Debug, Clone)]
struct Answer {
    refs: Vec<EnvelopeRef>,
    epoch: u64,
}

/// What the memo holds for one subject (see [`PlaneMemo::lookup`]).
#[derive(Debug, Clone, Copy)]
pub(crate) enum Lookup<'a> {
    /// Read in the current epoch: served as is.
    Fresh(&'a [EnvelopeRef]),
    /// Read in the epoch before the current one, and no delta row has dropped
    /// it since: served while it waits for its revalidation read
    /// (stale-while-revalidate). Only what the cursor cannot see can make it
    /// wrong, which is exactly what the TTL bound was always for.
    Stale(&'a [EnvelopeRef]),
    /// Never read, dropped by a delta row, or forgotten: absent until read.
    Missing,
}

/// One whole listing kept for reuse: the subject set it answered, the memo
/// generation it was computed at, and its refs.
#[derive(Debug)]
struct CachedListing {
    subjects: HashSet<String>,
    generation: u64,
    refs: Vec<EnvelopeRef>,
}

/// One plane's memo: each subject's refs, the TTL epoch, and when the memo
/// was last built or revalidated.
///
/// # Bound (CIRISEdge#971)
///
/// No cap and no eviction, on purpose: an entry is made only for a subject a
/// listing asked, and a listing asks only the host's sets (the plane's publish
/// set for `Key` / `IdentityOccurrence`, own ∪ the runtime's peers for the two
/// Global planes). So `entries` is at most the distinct subjects those sets
/// held over the last two [`MEMO_TTL`] epochs (a revalidation drops every
/// answer not read since the one before): bounded by the keys the host
/// publishes (8,211 `key:record` and 5,652 occurrence subjects on
/// canonical-1, 2026-11-09), not by traffic. An empty answer costs the key-id
/// `String` (24 bytes plus the id's heap bytes), an empty `Vec` (24 bytes, no
/// heap) and its epoch (8 bytes), plus the map's slot overhead: about 140
/// bytes, so about 1 MB per plane at that size; a non-empty answer adds 40
/// bytes per ref. The size is exported per plane as the
/// `holdings_index_gauge.key_plane.<plane>.memo_entries` gauge. The listing
/// cache adds at most [`LISTING_CACHE_SLOTS`] copies of a subject set and its
/// refs per plane.
///
/// # The generation (the listing cache's key)
///
/// `generation` moves on EVERY change to what the memo would answer: an
/// insert, a removal by a delta row ([`Self::apply`]) or a failed
/// revalidation ([`Self::remove`]), a rebuild, a revalidation, and a forget.
/// A cached listing is served only at the generation it was computed at and
/// for an equal subject set, so it is always the listing a walk over the
/// memo would produce at that instant. The witnesses are in this module's
/// tests: removing the bump from any one of those mutators serves a stale
/// listing.
///
/// v45 (CIRISEdge#971) — the store cursor the answers are current to is no
/// longer per memo: it is the one [`super::store_feed`] position, shared with
/// the holdings index, and a memo receives its delta through the feed's inbox.
#[derive(Debug, Default)]
pub(crate) struct PlaneMemo {
    entries: HashMap<String, Answer>,
    built_at: Option<Instant>,
    /// Set by [`Self::forget`], so the next rebuild is counted under its cause.
    forgotten: bool,
    /// The TTL epoch: an answer read in it is fresh, one read in the epoch
    /// before is stale (served while it waits), older is gone.
    epoch: u64,
    /// Moves on every change to the answers (see the type docs).
    generation: u64,
    /// The listing cache, most recently used first.
    listings: Vec<CachedListing>,
    /// Test-only: how much older than `built_at` the memo reads ([`Self::age`]).
    #[cfg(test)]
    aged: Duration,
}

/// Why a memo is rebuilt (CIRISEdge#971: the seat's rebuild counter by cause).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RebuildCause {
    /// Never built.
    First,
    /// Past [`MEMO_TTL`]: revalidated, not cleared (stale-while-revalidate).
    Ttl,
    /// Forgotten after a failed probe.
    Forgotten,
}

impl PlaneMemo {
    /// Is the memo due a rebuild (never built, or past [`MEMO_TTL`])?
    #[cfg(test)]
    pub(crate) fn needs_rebuild(&self, now: Instant) -> bool {
        self.rebuild_cause(now).is_some()
    }

    /// Why the memo is due a rebuild, if it is.
    pub(crate) fn rebuild_cause(&self, now: Instant) -> Option<RebuildCause> {
        match self.built_at {
            None if self.forgotten => Some(RebuildCause::Forgotten),
            None => Some(RebuildCause::First),
            Some(built) if now.saturating_duration_since(built) + self.aged() >= MEMO_TTL => {
                Some(RebuildCause::Ttl)
            }
            Some(_) => None,
        }
    }

    fn bump(&mut self) {
        self.generation = self.generation.wrapping_add(1);
    }

    #[cfg(test)]
    fn aged(&self) -> Duration {
        self.aged
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)] // the offset exists under cfg(test) only
    const fn aged(&self) -> Duration {
        Duration::ZERO
    }

    #[cfg(test)]
    fn reset_age(&mut self) {
        self.aged = Duration::ZERO;
    }

    #[cfg(not(test))]
    #[allow(clippy::unused_self)] // the offset exists under cfg(test) only
    const fn reset_age(&mut self) {}

    /// Drop every answer (never built, or forgotten). The shared feed
    /// position is already current (the listing drains it before reading any
    /// subject), so a rebuild no longer restarts a cursor of its own.
    pub(crate) fn rebuild(&mut self, now: Instant) {
        self.entries.clear();
        self.listings.clear();
        self.built_at = Some(now);
        self.forgotten = false;
        self.reset_age();
        self.bump();
    }

    /// The [`MEMO_TTL`] path: open a new epoch. Every answer read in the
    /// epoch that just ended becomes [`Lookup::Stale`] (served until its
    /// revalidation read, within the read budget); every answer that was
    /// already stale, so was not re-read in a whole epoch, is dropped. A
    /// stale answer is at most two epochs old. An answer a delta row dropped
    /// is not here to be served: the caller drains the feed and applies its
    /// dirt BEFORE this runs.
    pub(crate) fn revalidate(&mut self, now: Instant) {
        let prior = self.epoch;
        self.entries.retain(|_, a| a.epoch == prior);
        self.epoch = self.epoch.wrapping_add(1);
        self.built_at = Some(now);
        self.reset_age();
        self.bump();
    }

    /// Forget everything, so the next listing rebuilds (a probe that could
    /// not read the store cannot vouch for any answer).
    pub(crate) fn forget(&mut self) {
        self.entries.clear();
        self.listings.clear();
        self.built_at = None;
        self.forgotten = true;
        self.reset_age();
        self.bump();
    }

    /// Apply one row's [`Dirt`]; returns how many answers were dropped. A
    /// stale answer is dropped exactly as a fresh one is.
    pub(crate) fn apply(&mut self, dirt: &Dirt) -> usize {
        let dropped = match dirt {
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
        };
        if dropped > 0 {
            self.bump();
        }
        dropped
    }

    /// Drop one subject's answer (its revalidation read failed: a read that
    /// failed vouches for nothing, so it is not served stale either).
    pub(crate) fn remove(&mut self, subject: &str) {
        if self.entries.remove(subject).is_some() {
            self.bump();
        }
    }

    /// What the memo holds for `subject`.
    pub(crate) fn lookup(&self, subject: &str) -> Lookup<'_> {
        match self.entries.get(subject) {
            Some(a) if a.epoch == self.epoch => Lookup::Fresh(&a.refs),
            Some(a) if a.epoch.wrapping_add(1) == self.epoch => Lookup::Stale(&a.refs),
            _ => Lookup::Missing,
        }
    }

    /// The memoized answer for `subject`, fresh or stale.
    #[cfg(test)]
    pub(crate) fn get(&self, subject: &str) -> Option<&[EnvelopeRef]> {
        match self.lookup(subject) {
            Lookup::Fresh(r) | Lookup::Stale(r) => Some(r),
            Lookup::Missing => None,
        }
    }

    /// Memoize `subject`'s answer, read now (in the current epoch).
    pub(crate) fn insert(&mut self, subject: String, refs: Vec<EnvelopeRef>) {
        let epoch = self.epoch;
        self.entries.insert(subject, Answer { refs, epoch });
        self.bump();
    }

    /// Answers held, fresh and stale (the `key_plane.<plane>.memo_entries`
    /// gauge).
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// The memo's generation (moves on every change to its answers).
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// The cached listing over exactly `subjects`, if one was computed at the
    /// current generation. A hit moves the slot to the front.
    pub(crate) fn cached_listing(
        &mut self,
        subjects: &HashSet<String>,
    ) -> Option<Vec<EnvelopeRef>> {
        let generation = self.generation;
        let at = self
            .listings
            .iter()
            .position(|l| l.generation == generation && l.subjects == *subjects)?;
        let hit = self.listings.remove(at);
        let refs = hit.refs.clone();
        self.listings.insert(0, hit);
        Some(refs)
    }

    /// Keep a COMPLETE listing (every subject answered fresh, none left
    /// unread, none failed) for reuse at the current generation. Slots
    /// computed at an older generation can never be served again and go
    /// first; past [`LISTING_CACHE_SLOTS`] the least recently used goes.
    pub(crate) fn store_listing(&mut self, subjects: HashSet<String>, refs: Vec<EnvelopeRef>) {
        let generation = self.generation;
        self.listings
            .retain(|l| l.generation == generation && l.subjects != subjects);
        self.listings.insert(
            0,
            CachedListing {
                subjects,
                generation,
                refs,
            },
        );
        self.listings.truncate(LISTING_CACHE_SLOTS);
    }

    /// Listings cached (any generation).
    #[cfg(test)]
    pub(crate) fn cached_listings(&self) -> usize {
        self.listings.len()
    }

    /// Test-only: the memo was built or revalidated `by` earlier than it
    /// was, so the TTL path can be reached at an explicit instant.
    #[cfg(test)]
    pub(crate) fn age(&mut self, by: Duration) {
        self.aged += by;
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
        m.rebuild(t0);
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

    fn r(n: u8) -> EnvelopeRef {
        EnvelopeRef {
            envelope_hash: [n; 32],
            seq: u64::from(n),
        }
    }

    fn set(subjects: &[&str]) -> HashSet<String> {
        subjects.iter().map(|s| (*s).to_owned()).collect()
    }

    fn sorted(refs: &[EnvelopeRef]) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<_> = refs.iter().map(|r| (r.envelope_hash, r.seq)).collect();
        v.sort_unstable();
        v
    }

    /// THE ORACLE for the listing cache: the listing a walk over the memo
    /// would produce for `subjects` right now, when it is complete (every
    /// subject fresh), deduped by hash as the bridge's walk dedups; `None`
    /// when a walk would have to read the store (a subject missing or stale),
    /// which is exactly when no cached listing may stand in for it.
    fn walk(m: &PlaneMemo, subjects: &HashSet<String>) -> Option<Vec<([u8; 32], u64)>> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for s in subjects {
            match m.lookup(s) {
                Lookup::Fresh(refs) => {
                    out.extend(
                        refs.iter()
                            .filter(|r| seen.insert(r.envelope_hash))
                            .cloned(),
                    );
                }
                Lookup::Stale(_) | Lookup::Missing => return None,
            }
        }
        Some(sorted(&out))
    }

    /// The cache's contract after any op: what it serves for `q` is what a
    /// walk would produce, or nothing.
    fn assert_cache_sound(m: &mut PlaneMemo, q: &HashSet<String>, ctx: &str) {
        if let Some(cached) = m.cached_listing(q) {
            assert_eq!(
                Some(sorted(&cached)),
                walk(m, q),
                "{ctx}: the cache served a listing a walk would not produce"
            );
        }
    }

    /// **v45 (CIRISEdge#971) — stale-while-revalidate is bounded and dirt
    /// comes first.** After the TTL path an answer of the last epoch is
    /// stale (still served); a delta row naming it drops it at once, stale
    /// or fresh, so the TTL path never has it to serve; one more epoch
    /// without a re-read drops it; a re-read makes it fresh again.
    #[test]
    fn a_stale_answer_is_served_until_dirt_or_a_second_epoch_drops_it_971() {
        let t0 = Instant::now();
        let mut m = PlaneMemo::default();
        m.rebuild(t0);
        m.insert("a".into(), vec![r(1)]);
        m.insert("b".into(), vec![r(2)]);
        m.insert("c".into(), vec![r(3)]);
        assert!(matches!(m.lookup("a"), Lookup::Fresh(_)));
        m.revalidate(t0 + MEMO_TTL);
        assert!(matches!(m.lookup("a"), Lookup::Stale(x) if x == [r(1)]));
        assert!(matches!(m.lookup("b"), Lookup::Stale(_)));
        // Dirt on a stale answer drops it: never served stale after a row
        // the cursor saw.
        assert_eq!(m.apply(&Dirt::Subjects(vec!["a".into()])), 1);
        assert!(matches!(m.lookup("a"), Lookup::Missing));
        // A re-read is fresh in the new epoch.
        m.insert("b".into(), vec![r(4)]);
        assert!(matches!(m.lookup("b"), Lookup::Fresh(x) if x == [r(4)]));
        // A second epoch drops what was not re-read in the first (c), keeps
        // what was (b, now stale).
        m.revalidate(t0 + MEMO_TTL + MEMO_TTL);
        assert!(matches!(m.lookup("c"), Lookup::Missing));
        assert!(matches!(m.lookup("b"), Lookup::Stale(_)));
        // Plane dirt drops stale answers too.
        assert_eq!(m.apply(&Dirt::Plane), 1);
        assert_eq!(m.len(), 0);
    }

    /// One named mutation of a plane memo, at a time.
    type Mutator = (&'static str, fn(&mut PlaneMemo, Instant));

    /// **v45 (CIRISEdge#971) — every mutator moves the generation, so no
    /// cached listing outlives a change to its answers.** One case per
    /// mutator; removing the generation bump from any ONE of insert, apply,
    /// remove, rebuild, revalidate or forget makes its case serve the stale
    /// listing and fail here.
    #[test]
    fn no_cached_listing_survives_any_mutator_971() {
        let t0 = Instant::now();
        let q = set(&["a", "b"]);
        let ops: [Mutator; 7] = [
            ("insert overwrites an answer", |m, _| {
                m.insert("a".into(), vec![r(9)]);
            }),
            ("apply drops a subject", |m, _| {
                m.apply(&Dirt::Subjects(vec!["a".into()]));
            }),
            ("apply drops the plane", |m, _| {
                m.apply(&Dirt::Plane);
            }),
            ("a failed revalidation removes", |m, _| m.remove("a")),
            ("rebuild", |m, t| m.rebuild(t)),
            ("revalidate (the TTL path)", |m, t| m.revalidate(t)),
            ("forget", |m, _| m.forget()),
        ];
        for (name, op) in ops {
            let mut m = PlaneMemo::default();
            m.rebuild(t0);
            m.insert("a".into(), vec![r(1)]);
            m.insert("b".into(), vec![r(2)]);
            let listing = vec![r(1), r(2)];
            assert_eq!(walk(&m, &q), Some(sorted(&listing)));
            m.store_listing(q.clone(), listing);
            assert!(
                m.cached_listing(&q).is_some(),
                "{name}: precondition, a hit"
            );
            let before = m.generation();
            op(&mut m, t0 + MEMO_TTL);
            assert_ne!(m.generation(), before, "{name}: the generation moved");
            assert!(
                m.cached_listing(&q).is_none(),
                "{name}: the listing computed before the change is not served"
            );
            assert_cache_sound(&mut m, &q, name);
        }
    }

    /// A no-op mutator leaves the cache serving: dirt naming nothing held,
    /// and a remove of an absent subject, move no generation.
    #[test]
    fn a_no_op_keeps_the_cached_listing_971() {
        let mut m = PlaneMemo::default();
        m.rebuild(Instant::now());
        m.insert("a".into(), vec![r(1)]);
        let q = set(&["a"]);
        m.store_listing(q.clone(), vec![r(1)]);
        assert_eq!(m.apply(&Dirt::Clean), 0);
        assert_eq!(m.apply(&Dirt::Subjects(vec!["z".into()])), 0);
        m.remove("z");
        assert!(m.cached_listing(&q).is_some());
        // A different subject set is a different listing.
        assert!(m.cached_listing(&set(&["a", "z"])).is_none());
        assert!(m.cached_listing(&set(&[])).is_none());
    }

    /// The cache holds at most [`LISTING_CACHE_SLOTS`] listings per plane,
    /// least recently used out first, and storing at a new generation drops
    /// every slot that can no longer be served.
    #[test]
    fn the_listing_cache_is_bounded_971() {
        let mut m = PlaneMemo::default();
        m.rebuild(Instant::now());
        m.insert("a".into(), vec![r(1)]);
        let sets: Vec<HashSet<String>> = (0..=LISTING_CACHE_SLOTS)
            .map(|i| {
                let mut s = set(&["a"]);
                s.insert(format!("x{i}"));
                s
            })
            .collect();
        for s in &sets {
            m.store_listing(s.clone(), vec![r(1)]);
        }
        assert_eq!(m.cached_listings(), LISTING_CACHE_SLOTS);
        assert!(m.cached_listing(&sets[0]).is_none(), "the oldest went");
        assert!(m.cached_listing(&sets[LISTING_CACHE_SLOTS]).is_some());
        m.insert("b".into(), Vec::new());
        m.store_listing(set(&["b"]), Vec::new());
        assert_eq!(m.cached_listings(), 1, "dead generations are dropped");
    }

    fn splitmix(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// **The cache's differential (CIRISEdge#971).** 32 seeds × 300 random
    /// ops over six subjects (inserts with fresh refs, subject and plane
    /// dirt, removes, rebuilds, revalidations, forgets, and storing the
    /// listing of a random subject set whenever a walk of it is complete);
    /// after EVERY op, for every one of the query sets, the cache serves what
    /// the cache-off walk produces or nothing. Any missing generation bump
    /// fails some seed.
    #[test]
    fn the_cache_equals_the_walk_after_every_op_971() {
        const SUBJECTS: [&str; 6] = ["a", "b", "c", "d", "e", "f"];
        let queries: Vec<HashSet<String>> = vec![
            set(&["a"]),
            set(&["a", "b"]),
            set(&["b", "c", "d"]),
            set(&SUBJECTS),
            set(&["e", "f"]),
        ];
        let mut served = 0usize;
        for seed in 0..32u64 {
            let mut rng = seed.wrapping_mul(0x2545_F491_4F6C_DD1D) ^ 0x971;
            let t0 = Instant::now();
            let mut m = PlaneMemo::default();
            m.rebuild(t0);
            let mut tag = 0u8;
            for step in 0..300u32 {
                let pick = |rng: &mut u64| {
                    SUBJECTS[usize::try_from(splitmix(rng) % 6).expect("small")].to_owned()
                };
                let ctx = format!("seed {seed} step {step}");
                match splitmix(&mut rng) % 16 {
                    0..=5 => {
                        tag = tag.wrapping_add(1);
                        let n = splitmix(&mut rng) % 3;
                        let refs = (0..n)
                            .map(|i| r(tag.wrapping_add(u8::try_from(i).expect("small"))))
                            .collect();
                        let s = pick(&mut rng);
                        m.insert(s, refs);
                    }
                    6 | 7 => {
                        let s = pick(&mut rng);
                        m.apply(&Dirt::Subjects(vec![s]));
                    }
                    8 => {
                        m.apply(&Dirt::Plane);
                    }
                    9 => {
                        let s = pick(&mut rng);
                        m.remove(&s);
                    }
                    10 => m.revalidate(t0),
                    11 => m.rebuild(t0),
                    12 => m.forget(),
                    _ => {
                        let q = &queries[usize::try_from(splitmix(&mut rng) % 5).expect("small")];
                        if let Some(listing) = walk(&m, q) {
                            let refs = listing
                                .into_iter()
                                .map(|(envelope_hash, seq)| EnvelopeRef { envelope_hash, seq })
                                .collect();
                            m.store_listing(q.clone(), refs);
                        }
                    }
                }
                for q in &queries {
                    if m.cached_listing(q).is_some() {
                        served += 1;
                    }
                    assert_cache_sound(&mut m, q, &ctx);
                }
            }
        }
        assert!(served > 100, "the differential exercised hits ({served})");
    }
}
