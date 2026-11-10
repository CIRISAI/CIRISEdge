//! CIRISEdge#971 (v45) — **the holdings index: the receive diff answered from
//! memory, kept equal to persist's `signed_wire_index`.**
//!
//! `Session::on_summary` asks "which of the peer's hashes do I lack?" once per
//! Summary. Before this, every ask drained persist's content-hash index from
//! the top ([`super::bridge`]'s `holdings_from_wire_index`): one 1024-hash page
//! per sweep permit, 42 pages for the Attestation index on the production
//! canonical (42,520 rows) and 18 for TransportDestination, and the answer was
//! dropped as soon as the diff was taken. Six session planes share the
//! Attestation index (`EnvelopeKind::persist_index_kind`), so one device's
//! five bootstrap planes cost the seat ~190 index pages per 30 s round. This
//! module keeps the set instead.
//!
//! # What the set is
//!
//! For each covered index (`Attestation`, `TransportDestination`) the set is
//! the content hashes persist's `signed_wire_index` holds for that kind, and
//! nothing else: the receive diff is `remote ∖ set`, so a hash the index lacks
//! would make a row a peer offers never fetched (the wrong answer), and a hash
//! the set lacks makes a held row fetched again (a `Duplicate`, the old cost).
//! Every rule below leans toward the second when it cannot be exact.
//!
//! # Three feeds and an audit
//!
//! 1. **Warm-up and boot drain.** At runtime start a background task
//!    (`FederationDirectoryReplicationBridge::warm_holdings_index`, spawned by
//!    `ReplicationRuntime::start`) walks each plane's served log from its
//!    head, keying every record, then drains the index once and seeds the
//!    set from it. Until then every ask is the old drain, at the old cost, and
//!    no ask waits on the walk. A bridge with no warm-up (or whose warm-up
//!    failed) boots on its first holdings ask instead: that drain is the
//!    ask's answer, as before. `holdings_index_gauge.<plane>.ready_after_ms`
//!    says when a plane came up.
//! 2. **Write-through.** Every `Admitted` apply inserts the applied envelope's
//!    hash at once, so a row this node just admitted is in the set before the
//!    next peer's Summary arrives, not one probe later. Duplicates and
//!    refusals insert nothing (a `Duplicate` of a hash the set lacks is
//!    counted instead: it is the free "missing" signal).
//! 3. **Cursor deltas.** Every other door (an authoring door, a promotion,
//!    the claim path, a mutating door that re-stamps the serve position) is
//!    seen on persist's serve cursor: `list_attestations_since` for the
//!    Attestation index, drained ONCE for this set and the CIRISEdge#930
//!    key-plane memos together ([`super::store_feed`]), and
//!    `list_signed_transport_destinations_since` for the route index. Every
//!    ask brings the feed current first, coalesced (an ask is satisfied by
//!    any drain that STARTED after the ask did, so N concurrent Summaries
//!    cost one probe) and spaced (a clean feed probed less than
//!    [`super::store_feed::FEED_PROBE_SPACING`] ago is not probed again
//!    unless a door edge sees marked it dirty), so an idle round costs no
//!    store read at all.
//! 4. **Audit.** Every [`DEFAULT_AUDIT_EVERY`] (env [`AUDIT_EVERY_ENV`]) the
//!    next ask drains the index again, reconciles the set to it, and counts
//!    the drift both ways. Deletions (a purge, an erase, a projection purge)
//!    land on no cursor, so the audit is what removes them.
//!
//! # The set's truth is the index, not the rows
//!
//! The set equals `signed_wire_index`, which is what the drain it replaces
//! read. That is not the same as "the rows the store holds": outside tests
//! persist deletes index entries at exactly three sites
//! (`purge_attestation_projections`, `*_erase_cited_rows`,
//! `store_purge_execution`) plus the upsert's own replaced-hash delete, and
//! every other row delete (`delete_attestation`, `set_aside_form_refused`,
//! `sqlite_drop_key_record_rows`, `link_group_plane_row`, trace erasure)
//! leaves the entry. A hash whose row is gone but whose entry remains is
//! "held" by the pre-v45 drain too, and a peer's Fetch of it answers
//! `EnvelopeUnfetchable` (the point read's reload finds nothing). That is
//! existing behaviour this module preserves, not one it introduces.
//!
//! # Which rows a delta adds
//!
//! persist indexes a row by reloading it through the read path
//! (`wire_index::entry_as_stored` → `reload_record_bytes`): an `Attestation`
//! entry exists iff, when it was written, the row was federation tier and not
//! withheld by a purge tombstone; a `TransportDestination` entry iff the row
//! is a signed put. The serve cursor applies `read_plan::serve_rule_parts`:
//! federation tier, the purge-tombstone rule, and the row-type filter
//! (CIRISPersist#975). At the pin the row-type mode is `Report`, whose filter
//! leaves out exactly the retired carrier families (`holds_bytes:*` and the
//! rc6 `key_grant:content:*` set, persist `registry::RETIRED_CARRIER_STEMS`)
//! and nothing else. So the one class the cursor and the index disagree on is
//! **held rows of a retired carrier type**, written before v55. persist
//! refuses those types at every door that WRITES a row (`registry.rs`,
//! "refuses at EVERY door"), so after boot no door can add one; the boot drain
//! seeds the ones the index already holds, and the cursor never names them.
//! Two doors can REWRITE one, because neither checks the row type: a PQC
//! completion (`attach_attestation_pqc_signature` → `store_pqc_completion`)
//! and a re-seal (`store_planned_reseal`). Each re-stamps the row and
//! re-indexes it under a new hash the cursor filters out, so the set keeps the
//! old hash and lacks the new one until the next audit (at most
//! [`DEFAULT_AUDIT_EVERY`]): a `Duplicate` once if a peer offers the new hash
//! (counted `duplicate_unheld`), then two hashes of drift the audit repairs.
//! Witness: `a_retired_carrier_row_rewritten_is_repaired_by_the_audit_971`.
//! For every other row the predicate is equal. `holdings_index_971_tests` witnesses the
//! equality by a differential run (index vs drain, at every step of a random
//! sequence over every door edge can drive).
//!
//! The hash is `sha256(serde_json::to_vec(row))` over the row the cursor
//! returns, the same bytes `reload_record_bytes` hashes (persist's lockstep
//! fact, `wire_index` module docs), proved by test per envelope kind.
//!
//! # The door table
//!
//! Every persist v61.2.0 site that writes `signed_wire_index`
//! (`store/sqlite.rs`; the postgres backend has a twin of each), the feed that
//! carries it into the set, and its witness. A persist bump that adds a door
//! is checked against this list: grep persist for `index_stored_record(`,
//! `sqlite_upsert_wire_index(` and `DELETE FROM signed_wire_index`.
//!
//! | persist door (sqlite.rs line of the index write) | edge reaches it as | feed | witness |
//! |---|---|---|---|
//! | `store_planned_attestation` (15856) | `put_attestation`, the replicated apply, every emitted row incl. KeyGrant | write-through, cursor | `the_set_equals_a_full_drain_through_every_door_971`, the differential |
//! | `store_planned_key_record` → `index_stored_key_row` (2777) | the key door | cursor | `the_set_equals_a_full_drain_through_every_door_971` |
//! | `index_occurrence_row` → `index_plane_row` (2790) | the occurrence door | cursor | `the_set_equals_a_full_drain_through_every_door_971` |
//! | `store_planned_revocation` → `index_plane_row` (2790) | `put_revocation` | cursor | `the_set_equals_a_full_drain_through_every_door_971` |
//! | `store_planned_signed_destination` (25339) | the route door, a supersession | route cursor | `the_set_equals_a_full_drain_through_every_door_971` |
//! | `enter_mesh` (7590) | a promotion | cursor (re-stamped) | `door_promotion_971` |
//! | `index_holder_claim` (2834) from `store_planned_blob`, `store_holding_claim` | `put_blob_signing`, `put_holding_claim` | cursor | `door_holder_claim_971` |
//! | `index_holder_claim` (2834) from `store_planned_announcement` | none: reachable only from persist's own tests | cursor | none possible from edge |
//! | `store_pqc_completion` (15008) | `attach_attestation_pqc_signature` | cursor (re-stamped) | `door_pqc_completion_971`; retired class above |
//! | `store_planned_reseal` (15562) | `reseal_attestation_v31` | cursor (re-stamped) | `door_reseal_971` |
//! | `link_group_plane_row` → `index_plane_row` (23199) | `put_family`, `put_community`, `supersede_group_row` | cursor | `door_group_plane_link_971` |
//! | `store_planned_consent_role` → `index_stored_key_row` (26501) | `set_consent_role` | none needed: the key row's bytes omit the role, the hash is unchanged | `door_consent_role_971` |
//! | `rebuild_signed_wire_index` (7418) | runtime start (`rebuild_signed_wire_index_fail_soft`), host FFI | none: the warm-up's boot drain runs after it; a runtime rebuild by a host is repaired by the audit (CIRISServer does none) | audit witnesses |
//! | `store_planned_location_proof(_withdrawal)` (26271, 26329) | not a covered index (`LocationProof`) | n/a | n/a |
//! | REMOVE `sqlite_upsert_wire_index`'s replaced-hash delete (14789) | every upsert of a known record | mirrored by replacement by record | the differential, `door_pqc_completion_971` |
//! | REMOVE `purge_attestation_projections` (4829) | `purge_attestation_projections`, `reap_expired_attestations` | none: audit | `removes_converge_at_the_audit_971` |
//! | REMOVE `store_purge_execution` (24255) | `purge_put_execution` | none: audit | `removes_converge_at_the_audit_971` |
//! | REMOVE `sqlite_erase_cited_rows` (18210) | trace erasure (`delete_traces_for_agent*`) | none: audit | none yet: the rows it erases are local tier (no entry) unless crossed first, and persist has no crossed-then-erased fixture |
//!
//! `rehome_legacy_key_plane` (22995) writes key-plane rows with no index
//! call; the startup rebuild above indexes them before the warm-up drains.
//!
//! **What this table cannot prove on its own.** It was written by reading
//! persist's source at one pin; a writer persist adds later fails no edge
//! test. CIRISPersist#1249 asks persist to export its federation-tier writer
//! list (or run a source-scan test) so this table can be checked against it
//! at every pin. The `sqlite_erase_cited_rows` row above has no witness until
//! persist has a crossed-then-erased fixture; #1249 also asks whether erasure
//! has a path other than `purge_put_execution`.
//!
//! **Removes are skipped on purpose.** Between audits the set keeps a removed
//! hash, so a peer offering it is not asked for it. That is the right want, not
//! a lag to fix: a purged row is refused at admission by its tombstone, and an
//! erasure requires that this node NOT re-acquire the row. Do not "fix" the
//! audit to re-want them.
//!
//! # Replacement by record
//!
//! The index holds ONE current hash per record (`sqlite_upsert_wire_index`
//! drops a record's earlier hashes), and so does the set: a new hash for a
//! known record removes the old one. The warm-up walks the served log from
//! its head before the boot drain, so every record the store serves is known
//! by its key when the set first answers:
//! `attestation_id` on the Attestation plane, `(occurrence_key_id,
//! transport_kind)` on the route plane. A PQC completion or a re-seal (both
//! re-stamp the serve position, persist `store_pqc_completion`,
//! `store_planned_reseal`) or a superseding route therefore replaces its
//! hash on the next probe, including for a record held before boot. Only
//! drain-seeded entries the cursor never serves (the retired class above) are
//! known by hash alone; a rewrite of one is the audit's (see the predicate
//! section above). The route entry also keeps
//! the route's subject: the stranger view (CC 5.4.6, CIRISEdge#972) can later
//! filter by owner binding without a second read. Serving is not changed here.
//!
//! # Drift between audits, and what each direction costs
//!
//! - **Missing** (the index holds a hash the set lacks): the row is in the
//!   want of the next Summary that offers it, the peer re-delivers it, and the
//!   apply answers `Duplicate` (the CIRISEdge#416 shape, counted as
//!   `duplicate_unheld`). Waste, bounded by the audit.
//! - **Extra** (the set holds a hash the index no longer does): the row is
//!   not wanted when a peer offers it. Every way an entry leaves the index
//!   is a purge or an erasure (the three delete sites above) or a
//!   replacement the set mirrors; re-fetching a purged or erased row is
//!   refused at admission by its tombstone, and erasure requires that this
//!   node NOT re-acquire the row, so the extra direction never withholds a
//!   row this node should hold. Nothing in edge depends on re-fetching a
//!   deleted record. The holdings set is the WANT side only: the Summary this
//!   node offers is the advertise, which never reads it, so an extra hash is
//!   never offered to a peer.
//!
//! # The audit's tolerance
//!
//! An audit that finds more drift than [`drift_tolerance`] marks the plane
//! suspect. Between audits a working set drifts only by the index deletes no
//! cursor carries (purge executions, erasures) and by a feed row the index
//! write failed for (persist logs that at ERROR). [`DRIFT_FLOOR`] (16) absorbs
//! one purge or erasure batch in a minute on a small store; one in a thousand
//! of the set absorbs the same on a seat (42 on 42,520). Drift past that is
//! not a purge: it is a door the feeds do not see, and the set stops answering
//! until a clean audit, rather than keep answering from a set with a known
//! hole.
//!
//! # Failing to the old behaviour
//!
//! The set answers only when it is [`Status::Ready`]. Before the boot drain
//! completes, after a probe or audit read fails, and after an audit finds more
//! drift than [`drift_tolerance`], the plane is not Ready and every ask is the
//! old drain (which then doubles as the next audit, so a suspect set recovers
//! on the first clean one). Never a set known to be suspect.
//!
//! # Concurrency
//!
//! The set sits behind one `std` `RwLock`, held only for synchronous work (a
//! diff, an insert, the reconcile swap), never across an await. A boot drain
//! or an audit runs OUTSIDE the lock with a journal open: every insert and
//! every replacement that happens while it runs is journalled, and the
//! reconcile applies `drain ∪ added ∖ replaced` in one write-locked step. A
//! diff therefore sees either the whole set before the reconcile or the whole
//! set after it, never a partial one.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use super::protocol::{EnvelopeKind, EnvelopeRef};

/// Audit cadence default for v45: about one index page a second at the
/// production size, a hundredth of the pre-index rate, until persist's
/// per-kind generation counter lands and an audit can be skipped when the
/// generation has not moved.
pub(crate) const DEFAULT_AUDIT_EVERY: Duration = Duration::from_mins(1);

/// Env override for [`DEFAULT_AUDIT_EVERY`], whole seconds. Read once at
/// runtime assembly; an unparseable or zero value is ignored with a WARN.
pub(crate) const AUDIT_EVERY_ENV: &str = "CIRIS_EDGE_HOLDINGS_AUDIT_SECS";

/// The lever. `0`, `off` or `false` turns the index off: every holdings ask is
/// the pre-index drain. Read once at runtime assembly.
pub(crate) const ENABLED_ENV: &str = "CIRIS_EDGE_HOLDINGS_INDEX";

/// Absolute floor of the drift an audit tolerates before it marks the plane
/// suspect.
const DRIFT_FLOOR: usize = 16;

/// The drift an audit tolerates for a set of `size` hashes: [`DRIFT_FLOOR`],
/// or one in a thousand, whichever is larger. Small on purpose: a feed that
/// is working leaves only deletions and drain-seeded supersessions behind,
/// and both are rare. Anything more means a feed is broken.
#[must_use]
pub(crate) fn drift_tolerance(size: usize) -> usize {
    DRIFT_FLOOR.max(size / 1000)
}

/// The two persist indexes the set covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum IndexPlane {
    /// `signed_wire_index` kind `Attestation`: six session planes.
    Attestation,
    /// `signed_wire_index` kind `TransportDestination`.
    TransportDestination,
}

impl IndexPlane {
    /// The plane serving `kind`'s holdings, or `None` for a kind the index
    /// does not cover (it keeps the old path).
    #[must_use]
    pub(crate) fn of_kind(kind: EnvelopeKind) -> Option<Self> {
        match kind.persist_index_kind()? {
            "Attestation" => Some(Self::Attestation),
            "TransportDestination" => Some(Self::TransportDestination),
            _ => None,
        }
    }

    /// persist's `signed_wire_index.kind` token.
    #[must_use]
    pub(crate) const fn index_kind(self) -> &'static str {
        match self {
            Self::Attestation => "Attestation",
            Self::TransportDestination => "TransportDestination",
        }
    }

    /// The plane's index into per-plane tables (the `HOLDINGS_*` metric
    /// label pairs).
    #[must_use]
    pub(crate) const fn slot(self) -> usize {
        match self {
            Self::Attestation => 0,
            Self::TransportDestination => 1,
        }
    }

    /// The metric label prefix.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::TransportDestination => "transport_destination",
        }
    }
}

/// Whether a plane's set may answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// No boot drain has completed.
    Unbooted,
    /// A boot drain is running; asks take the old drain.
    Booting,
    /// The set equals the index as of the last reconcile plus every feed since.
    Ready,
    /// A probe or an audit read failed, or an audit found more drift than
    /// [`drift_tolerance`]. Asks take the old drain; the next clean drain
    /// restores Ready.
    Suspect,
}

impl Status {
    /// The gauge value: 0 unbooted, 1 booting, 2 ready, 3 suspect.
    #[must_use]
    pub(crate) const fn gauge(self) -> u64 {
        match self {
            Self::Unbooted => 0,
            Self::Booting => 1,
            Self::Ready => 2,
            Self::Suspect => 3,
        }
    }
}

/// One record's current hash, as a delta or a write-through named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Record {
    /// The record's identity in persist's index (`attestation_id`, or the
    /// route's `occurrence_key_id` and `transport_kind`).
    pub(crate) key: String,
    /// The route's subject (its `occurrence_key_id`); `None` on the
    /// Attestation plane. Kept so the stranger view can filter by owner later.
    pub(crate) subject: Option<String>,
}

impl Record {
    /// An Attestation-index record.
    #[must_use]
    pub(crate) fn attestation(attestation_id: &str) -> Self {
        Self {
            key: attestation_id.to_owned(),
            subject: None,
        }
    }

    /// A route-index record.
    #[must_use]
    pub(crate) fn route(occurrence_key_id: &str, transport_kind: &str) -> Self {
        Self {
            key: format!("{occurrence_key_id}\u{1f}{transport_kind}"),
            subject: Some(occurrence_key_id.to_owned()),
        }
    }
}

/// What one reconcile found.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Drift {
    /// Hashes the index held and the set did not.
    pub(crate) missing: usize,
    /// Hashes the set held and the index did not.
    pub(crate) extra: usize,
}

impl Drift {
    #[must_use]
    pub(crate) const fn total(self) -> usize {
        self.missing + self.extra
    }
}

/// Inserts and replacements made while a drain runs outside the lock.
#[derive(Debug, Default)]
struct Journal {
    added: HashSet<[u8; 32]>,
    replaced: HashSet<[u8; 32]>,
}

/// One plane's set.
#[derive(Debug)]
struct PlaneSet {
    status: Status,
    hashes: HashSet<[u8; 32]>,
    /// Record key → (current hash, subject), for records a feed named.
    records: HashMap<String, ([u8; 32], Option<String>)>,
    journal: Option<Journal>,
    last_reconcile: Option<Instant>,
}

impl Default for PlaneSet {
    fn default() -> Self {
        Self {
            status: Status::Unbooted,
            hashes: HashSet::new(),
            records: HashMap::new(),
            journal: None,
            last_reconcile: None,
        }
    }
}

impl PlaneSet {
    /// Insert `hash`, replacing `record`'s previous hash when it had one.
    /// Applied in every status: a feed that runs before the boot drain
    /// completes is journalled so the reconcile keeps it.
    fn upsert(&mut self, record: Option<Record>, hash: [u8; 32]) -> bool {
        let mut replaced = None;
        if let Some(Record { key, subject }) = record {
            if let Some((old, _)) = self.records.insert(key, (hash, subject)) {
                if old != hash {
                    replaced = Some(old);
                }
            }
        }
        if let Some(old) = replaced {
            self.hashes.remove(&old);
        }
        let inserted = self.hashes.insert(hash);
        if let Some(j) = self.journal.as_mut() {
            j.added.insert(hash);
            if let Some(old) = replaced {
                j.replaced.insert(old);
                j.added.remove(&old);
            }
        }
        inserted
    }

    /// Replace the set with `drained` plus every journalled change, and say
    /// how far the set had drifted from that.
    fn reconcile(&mut self, drained: HashSet<[u8; 32]>) -> Drift {
        let journal = self.journal.take().unwrap_or_default();
        let mut expected = drained;
        for h in &journal.replaced {
            if !journal.added.contains(h) {
                expected.remove(h);
            }
        }
        expected.extend(journal.added.iter().copied());
        let drift = Drift {
            missing: expected.difference(&self.hashes).count(),
            extra: self.hashes.difference(&expected).count(),
        };
        self.hashes = expected;
        let hashes = &self.hashes;
        self.records.retain(|_, (h, _)| hashes.contains(h));
        drift
    }
}

/// Why an ask was not answered from the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotReady {
    /// The lever is off.
    Disabled,
    /// No boot drain has completed (or one is running).
    Unbooted,
    /// The plane is suspect.
    Suspect,
}

/// The holdings index: one [`PlaneSet`] per covered persist index, plus the
/// single-flight that keeps one boot or audit drain running per plane.
#[derive(Debug)]
pub(crate) struct HoldingsIndex {
    enabled: bool,
    audit_every: Duration,
    planes: [std::sync::RwLock<PlaneSet>; 2],
    maintenance: [tokio::sync::Mutex<()>; 2],
}

impl HoldingsIndex {
    #[must_use]
    pub(crate) fn new(enabled: bool, audit_every: Duration) -> Self {
        Self {
            enabled,
            audit_every,
            planes: Default::default(),
            maintenance: Default::default(),
        }
    }

    #[must_use]
    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }

    fn plane(&self, plane: IndexPlane) -> &std::sync::RwLock<PlaneSet> {
        &self.planes[plane.slot()]
    }

    /// The single-flight of `plane`'s boot and audit drains.
    pub(crate) fn maintenance(&self, plane: IndexPlane) -> &tokio::sync::Mutex<()> {
        &self.maintenance[plane.slot()]
    }

    #[must_use]
    pub(crate) fn status(&self, plane: IndexPlane) -> Status {
        self.plane(plane)
            .read()
            .map_or(Status::Suspect, |s| s.status)
    }

    #[must_use]
    pub(crate) fn size(&self, plane: IndexPlane) -> usize {
        self.plane(plane).read().map_or(0, |s| s.hashes.len())
    }

    /// Does a holdings ask on `plane` owe the index a drain (boot, audit, or
    /// recovery from suspect)?
    #[must_use]
    pub(crate) fn drain_due(&self, plane: IndexPlane, now: Instant) -> bool {
        if !self.enabled {
            return false;
        }
        self.plane(plane).read().map_or(true, |s| match s.status {
            Status::Unbooted | Status::Suspect => true,
            Status::Booting => false,
            Status::Ready => s
                .last_reconcile
                .is_none_or(|at| now.saturating_duration_since(at) >= self.audit_every),
        })
    }

    /// The runtime's warm-up has begun for `plane`: an Unbooted plane is
    /// Booting from now on, so an ask meanwhile takes the old drain and does
    /// not boot the set itself (the warm-up's boot drain will). A plane that
    /// has booted already is left as it is.
    pub(crate) fn begin_warm(&self, plane: IndexPlane) {
        if let Ok(mut s) = self.plane(plane).write() {
            if s.status == Status::Unbooted {
                s.status = Status::Booting;
            }
        }
    }

    /// The warm-up could not finish `plane`: a plane it left Booting with no
    /// drain running is Unbooted again, so the next ask boots it inline.
    pub(crate) fn abort_warm(&self, plane: IndexPlane) {
        if let Ok(mut s) = self.plane(plane).write() {
            if s.status == Status::Booting && s.journal.is_none() {
                s.status = Status::Unbooted;
            }
        }
    }

    /// Test-only: the next ask on `plane` runs its audit (as if
    /// `audit_every` had passed since the last reconcile).
    #[cfg(test)]
    pub(crate) fn audit_due_now(&self, plane: IndexPlane) {
        if let Ok(mut s) = self.plane(plane).write() {
            s.last_reconcile = None;
        }
    }

    /// Open a drain's journal. A plane that has never booted is Booting until
    /// the drain reconciles; a Ready plane stays Ready (the set it answers from
    /// is complete, and the journal keeps every change made meanwhile).
    pub(crate) fn begin_drain(&self, plane: IndexPlane) {
        if let Ok(mut s) = self.plane(plane).write() {
            if s.status == Status::Unbooted {
                s.status = Status::Booting;
            }
            s.journal = Some(Journal::default());
        }
    }

    /// The drain failed: drop its journal and leave the plane unable to answer.
    pub(crate) fn abort_drain(&self, plane: IndexPlane) {
        if let Ok(mut s) = self.plane(plane).write() {
            s.journal = None;
            s.status = match s.status {
                Status::Booting | Status::Unbooted => Status::Unbooted,
                Status::Ready | Status::Suspect => Status::Suspect,
            };
        }
    }

    /// Reconcile `plane` to a completed drain. Returns the drift and whether
    /// the plane is now Ready. A first boot reports no drift (there was no set
    /// to drift); a boot drain never marks the plane suspect.
    pub(crate) fn finish_drain(
        &self,
        plane: IndexPlane,
        drained: HashSet<[u8; 32]>,
        now: Instant,
    ) -> (Drift, bool) {
        let Ok(mut s) = self.plane(plane).write() else {
            return (Drift::default(), false);
        };
        let booting = s.status == Status::Booting;
        let size = drained.len();
        let drift = s.reconcile(drained);
        s.last_reconcile = Some(now);
        if booting {
            s.status = Status::Ready;
            return (Drift::default(), true);
        }
        s.status = if drift.total() > drift_tolerance(size) {
            Status::Suspect
        } else {
            Status::Ready
        };
        (drift, s.status == Status::Ready)
    }

    /// A probe of `plane`'s serve cursor could not read the store: its set is
    /// no longer vouched for (a row may have landed that no feed saw).
    pub(crate) fn mark_suspect(&self, plane: IndexPlane) {
        if let Ok(mut s) = self.plane(plane).write() {
            if s.status == Status::Ready {
                s.status = Status::Suspect;
            }
        }
    }

    /// One feed row (a cursor delta or a write-through). Returns whether the
    /// hash was new to the set.
    pub(crate) fn upsert(&self, plane: IndexPlane, record: Option<Record>, hash: [u8; 32]) -> bool {
        if !self.enabled {
            return false;
        }
        self.plane(plane)
            .write()
            .is_ok_and(|mut s| s.upsert(record, hash))
    }

    /// Does the set hold `hash`? `None` when the set may not answer.
    #[must_use]
    pub(crate) fn holds(&self, plane: IndexPlane, hash: &[u8; 32]) -> Option<bool> {
        let s = self.plane(plane).read().ok()?;
        (s.status == Status::Ready).then(|| s.hashes.contains(hash))
    }

    /// The receive diff, `remote ∖ set`, taken under one read lock so it sees
    /// one whole set. `Err` names why the set may not answer.
    pub(crate) fn want(
        &self,
        plane: IndexPlane,
        remote: &[EnvelopeRef],
    ) -> Result<Vec<[u8; 32]>, NotReady> {
        if !self.enabled {
            return Err(NotReady::Disabled);
        }
        let s = self.plane(plane).read().map_err(|_| NotReady::Suspect)?;
        match s.status {
            Status::Ready => Ok(super::summary::diff_refs_against(&s.hashes, remote)),
            Status::Unbooted | Status::Booting => Err(NotReady::Unbooted),
            Status::Suspect => Err(NotReady::Suspect),
        }
    }

    /// The set as refs (the `list_holdings` contract), or why it may not
    /// answer. `seq` is zero, exactly as the wire-index drain returns it.
    pub(crate) fn refs(&self, plane: IndexPlane) -> Result<Vec<EnvelopeRef>, NotReady> {
        if !self.enabled {
            return Err(NotReady::Disabled);
        }
        let s = self.plane(plane).read().map_err(|_| NotReady::Suspect)?;
        match s.status {
            Status::Ready => Ok(s
                .hashes
                .iter()
                .map(|h| EnvelopeRef {
                    envelope_hash: *h,
                    seq: 0,
                })
                .collect()),
            Status::Unbooted | Status::Booting => Err(NotReady::Unbooted),
            Status::Suspect => Err(NotReady::Suspect),
        }
    }

    /// The route subjects the set holds a current hash for (the future
    /// stranger view's input; see the module docs).
    #[cfg(test)]
    pub(crate) fn route_subject(&self, hash: &[u8; 32]) -> Option<String> {
        let s = self.plane(IndexPlane::TransportDestination).read().ok()?;
        s.records
            .values()
            .find(|(h, _)| h == hash)
            .and_then(|(_, subject)| subject.clone())
    }
}

/// The record a write-through names, read from the applied envelope's bytes.
/// `None` when the bytes do not name one (the hash is still inserted).
#[must_use]
pub(crate) fn record_of_envelope(plane: IndexPlane, envelope_bytes: &[u8]) -> Option<Record> {
    let value: serde_json::Value = serde_json::from_slice(envelope_bytes).ok()?;
    match plane {
        IndexPlane::Attestation => {
            let inner = value.get("attestation").unwrap_or(&value);
            inner
                .get("attestation_id")
                .and_then(serde_json::Value::as_str)
                .map(Record::attestation)
        }
        IndexPlane::TransportDestination => {
            let td = value.get("transport_destination")?;
            let occurrence = td.get("occurrence_key_id")?.as_str()?;
            let kind = td.get("transport_kind")?.as_str()?;
            Some(Record::route(occurrence, kind))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = seed;
        a
    }

    fn r(seed: u8) -> EnvelopeRef {
        EnvelopeRef {
            envelope_hash: h(seed),
            seq: 0,
        }
    }

    fn ready(index: &HoldingsIndex, plane: IndexPlane, seeds: &[u8]) {
        index.begin_drain(plane);
        let (_, ok) =
            index.finish_drain(plane, seeds.iter().map(|s| h(*s)).collect(), Instant::now());
        assert!(ok);
    }

    #[test]
    fn the_covered_kinds_map_to_their_index() {
        for kind in [
            EnvelopeKind::Attestation,
            EnvelopeKind::KeyGrant,
            EnvelopeKind::Key,
            EnvelopeKind::Revocation,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::IdentityOccurrenceRevocation,
        ] {
            assert_eq!(IndexPlane::of_kind(kind), Some(IndexPlane::Attestation));
        }
        assert_eq!(
            IndexPlane::of_kind(EnvelopeKind::TransportDestination),
            Some(IndexPlane::TransportDestination)
        );
        assert_eq!(IndexPlane::of_kind(EnvelopeKind::LocationProof), None);
        assert_eq!(
            IndexPlane::of_kind(EnvelopeKind::AccordQuorumEvidence),
            None
        );
    }

    #[test]
    fn nothing_answers_before_the_boot_drain_completes() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::Attestation;
        assert_eq!(index.want(p, &[r(1)]), Err(NotReady::Unbooted));
        assert!(index.drain_due(p, Instant::now()));
        index.begin_drain(p);
        assert_eq!(index.status(p), Status::Booting);
        assert_eq!(index.want(p, &[r(1)]), Err(NotReady::Unbooted));
        assert!(!index.drain_due(p, Instant::now()), "one boot at a time");
        let (_, ok) = index.finish_drain(p, [h(1)].into_iter().collect(), Instant::now());
        assert!(ok);
        assert_eq!(index.want(p, &[r(1), r(2)]), Ok(vec![h(2)]));
    }

    #[test]
    fn the_lever_off_never_answers_and_never_drains() {
        let index = HoldingsIndex::new(false, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::Attestation;
        assert!(!index.drain_due(p, Instant::now()));
        assert!(!index.upsert(p, None, h(1)));
        assert_eq!(index.want(p, &[r(1)]), Err(NotReady::Disabled));
    }

    #[test]
    fn a_feed_during_the_boot_drain_survives_the_reconcile() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::Attestation;
        index.begin_drain(p);
        // Admitted after the drain read past it: the drain does not see it.
        index.upsert(p, Some(Record::attestation("late")), h(9));
        index.finish_drain(p, [h(1)].into_iter().collect(), Instant::now());
        assert_eq!(index.want(p, &[r(1), r(9)]), Ok(vec![]));
    }

    #[test]
    fn a_replacement_during_a_drain_removes_the_hash_the_drain_read() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::TransportDestination;
        ready(&index, p, &[]);
        index.upsert(p, Some(Record::route("occ", "rns")), h(1));
        index.begin_drain(p);
        // The drain read h(1); then the route was superseded.
        index.upsert(p, Some(Record::route("occ", "rns")), h(2));
        let (drift, ok) = index.finish_drain(p, [h(1)].into_iter().collect(), Instant::now());
        assert!(ok);
        assert_eq!(
            drift,
            Drift::default(),
            "a concurrent supersession is not drift"
        );
        assert_eq!(index.want(p, &[r(1), r(2)]), Ok(vec![h(1)]));
    }

    #[test]
    fn a_route_supersession_replaces_its_record() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::TransportDestination;
        ready(&index, p, &[]);
        assert!(index.upsert(p, Some(Record::route("occ", "rns")), h(1)));
        assert!(index.upsert(p, Some(Record::route("occ", "rns")), h(2)));
        assert!(index.upsert(p, Some(Record::route("occ", "lxmf")), h(3)));
        assert_eq!(index.size(p), 2);
        assert_eq!(index.holds(p, &h(1)), Some(false));
        assert_eq!(index.route_subject(&h(2)).as_deref(), Some("occ"));
    }

    #[test]
    fn an_audit_repairs_and_counts_drift_both_ways() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::Attestation;
        ready(&index, p, &[1, 2, 3]);
        index.begin_drain(p);
        // The index lost 3 (a purge) and gained 4 by a door no feed saw.
        let (drift, ok) =
            index.finish_drain(p, [h(1), h(2), h(4)].into_iter().collect(), Instant::now());
        assert!(ok);
        assert_eq!(
            drift,
            Drift {
                missing: 1,
                extra: 1
            }
        );
        assert_eq!(index.want(p, &[r(3), r(4)]), Ok(vec![h(3)]));
    }

    #[test]
    fn drift_over_the_tolerance_marks_the_plane_suspect_until_a_clean_drain() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::Attestation;
        ready(&index, p, &[]);
        let drained: HashSet<[u8; 32]> = (0..=u8::try_from(DRIFT_FLOOR).expect("small"))
            .map(h)
            .collect();
        index.begin_drain(p);
        let (drift, ok) = index.finish_drain(p, drained.clone(), Instant::now());
        assert!(!ok);
        assert_eq!(drift.missing, DRIFT_FLOOR + 1);
        assert_eq!(index.status(p), Status::Suspect);
        assert_eq!(index.want(p, &[r(1)]), Err(NotReady::Suspect));
        assert!(
            index.drain_due(p, Instant::now()),
            "a suspect plane drains every ask"
        );
        index.begin_drain(p);
        let (drift, ok) = index.finish_drain(p, drained, Instant::now());
        assert!(ok, "the repaired set matched: {drift:?}");
        assert_eq!(index.status(p), Status::Ready);
    }

    #[test]
    fn a_failed_probe_suspects_its_plane_only() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        ready(&index, IndexPlane::Attestation, &[1]);
        ready(&index, IndexPlane::TransportDestination, &[2]);
        index.mark_suspect(IndexPlane::Attestation);
        assert_eq!(index.status(IndexPlane::Attestation), Status::Suspect);
        assert_eq!(
            index.status(IndexPlane::TransportDestination),
            Status::Ready
        );
    }

    #[test]
    fn a_failed_boot_drain_leaves_the_plane_unbooted() {
        let index = HoldingsIndex::new(true, DEFAULT_AUDIT_EVERY);
        let p = IndexPlane::Attestation;
        index.begin_drain(p);
        index.abort_drain(p);
        assert_eq!(index.status(p), Status::Unbooted);
        ready(&index, p, &[1]);
        index.begin_drain(p);
        index.abort_drain(p);
        assert_eq!(index.status(p), Status::Suspect);
    }

    #[test]
    fn an_audit_is_due_after_the_interval() {
        let every = Duration::from_mins(1);
        let index = HoldingsIndex::new(true, every);
        let p = IndexPlane::Attestation;
        let t0 = Instant::now();
        index.begin_drain(p);
        index.finish_drain(p, HashSet::new(), t0);
        assert!(!index.drain_due(p, t0 + Duration::from_secs(59)));
        assert!(index.drain_due(p, t0 + every));
    }

    #[test]
    fn a_write_through_names_its_record() {
        let att = br#"{"attestation_id":"a-1","attestation_type":"scores"}"#;
        assert_eq!(
            record_of_envelope(IndexPlane::Attestation, att),
            Some(Record::attestation("a-1"))
        );
        let td = br#"{"transport_destination":{"occurrence_key_id":"o","transport_kind":"rns"}}"#;
        assert_eq!(
            record_of_envelope(IndexPlane::TransportDestination, td),
            Some(Record::route("o", "rns"))
        );
        assert_eq!(
            record_of_envelope(IndexPlane::Attestation, b"not json"),
            None
        );
    }
}
