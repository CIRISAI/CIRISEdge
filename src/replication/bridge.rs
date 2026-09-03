//! `FederationDirectoryReplicationBridge` — production layer (c-2)
//! wiring of `ReplicationDirectory` over persist's `FederationDirectory`.
//!
//! Closes the substantive remaining rung of CIRISEdge#65. The trait
//! shape ([`super::ReplicationDirectory`]) shipped in layer (c-1)
//! (#71); this module wires it to persist's actual federation surface
//! per `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.6.
//!
//! ## Design
//!
//! The bridge holds two persist surfaces + a cohort callback + a cache:
//!
//! - **`Arc<dyn FederationDirectory>`** — persist's write/read trait
//!   (dyn-compatible via `async-trait` macro). Used to dispatch
//!   [`Self::apply_envelope_bytes`] to the matching `put_*` admit
//!   (10 arms, 1:1 with [`EnvelopeKind`]); also used to page through
//!   keyed `list_*_for` methods to enumerate envelopes per kind.
//! - **Cohort callback** — operator-configured callback yielding the
//!   federation key_ids we want to anti-entropy with. Each round
//!   re-invokes it, so peer-set evolution is observable without
//!   restart.
//! - **Hash→bytes cache** — bounded FIFO (4096 entries). Since
//!   CIRISEdge#397 it is populated + consulted ONLY for the `Revocation`
//!   plane (the one kind persist does not index); every other plane's
//!   fetch is the content-hash point-read below.
//!
//! ## How much of a plane one sweep reads (CIRISEdge#531)
//!
//! A production node runs one bulk sweep per `(peer, plane)` per round, times
//! TWO — the advertise view and the holdings view — and the scheduler starts
//! them phase-aligned, so ~72 sweeps enter a bulk read in the same millisecond
//! at 6 peers × 6 planes. Two bounds shape that, and they are different
//! resources:
//!
//! * **WIDTH** ([`SweepGate`], v18.6.0) — how many sweeps MATERIALISE at once.
//!   A FIFO-fair semaphore, default 2 permits.
//! * **DEPTH** ([`PlaneWatermark`] / [`SweepCursors`] / [`SweepWindow`]) — how
//!   much of a plane ONE sweep reads. Width alone bounds
//!   `permits × corpus × 2`, which still grows with the table; a page bounds it
//!   at `permits × page × 2`, which does not.
//!
//! Depth has two windows, and which one a sweep gets is a CORRECTNESS choice,
//! not a tuning one:
//!
//! * the **advertise** (send) axis is [`SweepWindow::Watermark`]: one page
//!   budget per round against a per-`(peer, plane)` position — new rows first,
//!   then a page of a rolling re-sweep that wraps. Reach is unbounded;
//!   convergence is spread across rounds. The re-sweep is load-bearing, not
//!   decorative: it is what lets a row refused TRANSIENTLY (AV-45), deferred by
//!   a Deliver byte budget, or lost with a frame be offered again;
//! * the **holdings** (receive) axis is [`SweepWindow::Full`]: paged for memory,
//!   but COMPLETE in result. `want = remote ∖ holdings`, so a partial holdings
//!   view leaves held rows in `want` forever and re-fetches them every round —
//!   CIRISEdge#416's non-convergence, recreated by the fix for the memory.
//!
//! The cursor edge resumes from is persist's `(serve_position, resume_id)` PAIR
//! ([`ResumeCursor`], CIRISPersist#668), never the instant alone: a page
//! boundary inside a group of rows sharing one instant would otherwise skip the
//! group's remainder, silently and permanently.
//!
//! ## envelope_hash semantics — content-hash (CIRISEdge#397)
//!
//! The envelope identity is each row's **content-hash**:
//! `sha256(serde_json::to_vec(row))` ([`content_hash_of`]), byte-exact
//! with persist's `wire_index::content_hash_of`. The `row` is whatever
//! element type the corresponding `list_signed_*_since` /
//! `list_attestations_since` bulk read returns (the `Signed*` wrapper for
//! most planes; the BARE `Attestation` / `Organization` / `OrgMembership`
//! for the three persist indexes bare). Because persist's
//! `signed_wire_index` keys `(kind, content_hash)` on the SAME bytes and
//! its `lookup_signed_record_by_content_hash` point-read reloads +
//! re-serializes that same row, the advertised hash equals `sha256` of the
//! served bytes equals the point-read key — end to end, by construction.
//!
//! This retires the pre-#397 `persist_row_hash` / JCS `v2_envelope_hash`
//! bases and the per-subject `list_*_for` fan-out: each plane now reads ONE
//! bulk since-cursor page per round.
//!
//! ## Federation-tier-only invariant (FSD §7.1)
//!
//! The bridge reads ONLY persist's federation directory (the
//! `federation_*` table family). CEG §10.1.4 structurally-invisible
//! private records live in a separate local-only store that this
//! bridge never touches — by construction, since
//! `FederationDirectory::list_*_for` reads only the federation tables.
//!
//! Three tests at the bottom of this module fence that invariant per
//! FSD §7.1 acceptance criteria.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;

use super::refusal_backoff::{RefusalBackoff, RetryDisposition};
use super::resolved_state::{ResolvedPeerSet, ResolvedRecipient};
use ciris_persist::federation::admission::has_accord_conferred_role;
use ciris_persist::federation::consent_grammar::{self, ConsentTransferPolicy};
use ciris_persist::federation::namespace::{self, Projection};
use ciris_persist::federation::operational::{
    OrgMembership, Organization, SignedOrgMembership, SignedOrganization, SignedPartnerRecord,
};
use ciris_persist::federation::register::{KeyRefusalReason, ReplicatedKeyOutcome};
use ciris_persist::federation::trust_root::capability_roots_to_trusted_root;
use ciris_persist::federation::types::delegation_scope;
use ciris_persist::federation::types::{
    Attestation, KeyRecord, SignedAttestation, SignedCommunity,
    SignedCommunityMembershipRevocation, SignedFamily, SignedFamilyMembershipRevocation,
    SignedIdentityOccurrence, SignedIdentityOccurrenceRevocation, SignedKeyRecord,
    SignedLocationProof, SignedRevocation,
};
use ciris_persist::federation::{AttestationOutcome, FederationDirectory};
use ciris_verify_core::threshold::ThresholdMember;

use super::directory::ReplicationDirectory;
use super::protocol::{EnvelopeKind, EnvelopeRef};
use super::summary::ApplyOutcome;

// ─── CIRISEdge#423 → #425 — apply-refusal diagnostics, now by construction ──
//
// The `apply_*` family once collapsed BOTH failure arms of "deserialize the
// delivered bytes, then admit the record" to a silent `false`: a malformed
// envelope was dropped with `Err(_) => false` (reason discarded), and an admission
// REFUSAL — with its typed reason (`FederationTierUnverified`, …) — collapsed to
// `false` too. #423 made each arm log LOUDLY at the bridge; but that fix MISSED
// three sites in this very file (the `if self.operational.is_none() { return
// false }` early returns sit ABOVE the helpers), which is the argument for a
// STRUCTURAL cure. #425: every `apply_*` now returns an [`ApplyOutcome`] carrying
// its reason, and the SINGLE choke point `session::on_deliver` logs it. A future
// `apply_*` branch cannot add a silent `return false` — `ApplyOutcome` is
// `#[must_use]` and there is no `false` to return. These helpers just BUILD the
// reason string (the logging lives at the choke point, so no double-log).

/// The `Deserialize` reason for a delivered envelope that failed to parse: the
/// wire-bytes hash (correlates with the delivered frame) + the serde error.
fn apply_deser_reason(plane: &str, bytes: &[u8], err: &serde_json::Error) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{plane}: deserialize failed (bytes={}, wire_hash={}): {err}",
        bytes.len(),
        hex::encode(Sha256::digest(bytes)),
    )
}

/// The `Refused` reason for a well-formed envelope a gate declined: the record's
/// content hash (the value persist's `signed_wire_index` keys on — correlates with
/// the offered `EnvelopeRef` + a direct `put_*`) + the typed refusal token
/// ([`ciris_persist::federation::Error::kind`]).
/// CIRISEdge#441 — the removal-class planes: every kind whose rows REMOVE
/// standing (revocations + membership revocations). Attestation-plane
/// `withdraws`/`recants` rows are the named follow-up (they need content
/// inspection at the ref tier; kind-level covers the four typed planes).
#[must_use]
pub fn is_removal_kind(kind: EnvelopeKind) -> bool {
    matches!(
        kind,
        EnvelopeKind::Revocation
            | EnvelopeKind::IdentityOccurrenceRevocation
            | EnvelopeKind::FamilyMembershipRevocation
            | EnvelopeKind::CommunityMembershipRevocation
    )
}

fn apply_refusal_reason(
    plane: &str,
    content_hash: &str,
    err: &ciris_persist::federation::Error,
) -> String {
    format!(
        "{plane}: admission refused (content_hash={content_hash}, refusal={}): {err}",
        err.kind(),
    )
}

/// persist v38.2.0 (CIRISEdge#522) — **the closed set of apply-door refusals
/// edge has something to SAY about**, beyond persist's own stable `kind()`.
///
/// # Why a second axis exists next to `kind()`
///
/// [`ciris_persist::federation::Error::kind`] answers *which persist error*.
/// It cannot answer the question the apply loop actually has to act on, which
/// is *what does a relay DO about this row*: a `federation_write_scope_refused`
/// is a permanent policy verdict when the writer is genuinely not a member and
/// a self-healing ordering artefact when the roster simply has not landed on
/// this node yet — the SAME token, opposite operational meaning. Persist is
/// right not to distinguish them (it cannot: only the receiving node knows
/// whether it is mid-sync), and #522 asks the receiver to.
///
/// The three v38.2.0 doors map onto three answers:
///
/// - [`CommunityRosterFork`](Self::CommunityRosterFork) — **surface, do not
///   retry.** A differing roster under an occupied `community_key_id`
///   (persist#758's typed `Error::Conflict`). Retrying spins; logging and
///   dropping hides a fork.
/// - [`RetryAfterCommunityRoster`](Self::RetryAfterCommunityRoster) /
///   [`RetryAfterFamilyRoster`](Self::RetryAfterFamilyRoster) — **transient,
///   converges on its own.** AV-45 at the put door (persist#757) refuses a
///   member's cohort-scoped row that arrives before this node applied the
///   cohort's roster. Correct and temporary. The REMOVED-member half of the
///   revocation pairing lands in the same class and is indistinguishable from
///   here on purpose: both are "this node's roster does not show the writer as
///   an active member", both are decided by state that is still moving, and
///   both converge — one when the roster arrives, the other when the sender's
///   roster catches up and it stops offering the row. Neither is terminal
///   *at this door*, which is exactly what the apply loop needs to know.
/// - [`ThirdPartyRow`](Self::ThirdPartyRow) — **a verdict about the ROW.**
///   AV-84 at the put door: a family/community-targeted row naming anyone but
///   its producer. Never a delivery problem, so it must never be counted or
///   reported as one.
///
/// Closed and small ON PURPOSE — this is a metric key, so its cardinality is
/// bounded by this enum rather than by traffic, exactly like persist's
/// [`KeyRefusalReason`] on the Key plane. [`Self::ALL`] is the drift anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApplyRefusalClass {
    /// persist#758 — a DIFFERING community roster under an occupied
    /// `community_key_id`. The fork signal.
    CommunityRosterFork,
    /// persist#757 (AV-45) — a `community`-scoped row whose writer this node
    /// cannot yet see as a member, because it has not applied that
    /// community's roster.
    RetryAfterCommunityRoster,
    /// persist#757 (AV-45) — the family mirror of
    /// [`Self::RetryAfterCommunityRoster`].
    RetryAfterFamilyRoster,
    /// persist#757 (AV-84) — a targeted-cohort row naming a party other than
    /// its own producer.
    ThirdPartyRow,
}

impl ApplyRefusalClass {
    /// Every class, for the drift test + any consumer enumerating the ledger's
    /// key space without traffic.
    pub const ALL: &'static [Self] = &[
        Self::CommunityRosterFork,
        Self::RetryAfterCommunityRoster,
        Self::RetryAfterFamilyRoster,
        Self::ThirdPartyRow,
    ];

    /// The stable, low-cardinality metric token. Consumers key on THIS, never
    /// on message prose — edge deleted a `reason.contains("conflict")`
    /// discriminator in v18.2.0 and must not grow another.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CommunityRosterFork => "community_roster_fork",
            Self::RetryAfterCommunityRoster => "retry_after_community_roster",
            Self::RetryAfterFamilyRoster => "retry_after_family_roster",
            Self::ThirdPartyRow => "third_party_row",
        }
    }

    /// Is this refusal expected to resolve itself once more state lands, with
    /// no operator action?
    ///
    /// TRUE for the two roster-ordering classes and **only** those: a refused
    /// row is not stored, so this node still lacks its hash and the next
    /// Summary/Diff re-offers it — convergence is by construction, not by a
    /// retry queue. FALSE for a fork and for a third-party row: neither
    /// changes on its own, and both are decisions someone has to see.
    #[must_use]
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::RetryAfterCommunityRoster | Self::RetryAfterFamilyRoster
        )
    }

    /// CIRISEdge#544 — the same disposition, in the vocabulary the RETRY loop
    /// consumes. Derived from [`Self::is_transient`] rather than re-decided, so
    /// there is exactly one place the four #522 door classes say whether they
    /// converge; the log line the receiver already prints
    /// ([`classified_refusal_reason`]) and the window the receiver now backs off
    /// for cannot disagree.
    #[must_use]
    pub fn retry(self) -> RetryDisposition {
        if self.is_transient() {
            RetryDisposition::Transient
        } else {
            RetryDisposition::Terminal
        }
    }

    /// Classify a persist apply-door `Err` on the **attestation** doors —
    /// AV-45 and AV-84, both of which persist types (`WriteScopeRefused`
    /// carries a [`ScopeRefusalReason`](ciris_persist::scope::ScopeRefusalReason);
    /// `CohortStandingRefused` is its own variant). `None` = an error outside
    /// the #522 door set, which stays a plain `Refused` carrying persist's own
    /// `kind()`.
    ///
    /// Matched on the TYPED variants, never on the message text. The
    /// `Conflict` fork class is deliberately absent here: `Error::Conflict` is
    /// generic across planes and only means "roster fork" at the Community
    /// door, so [`FederationDirectoryReplicationBridge::apply_community`]
    /// names it at the site that knows the plane.
    #[must_use]
    pub fn classify(err: &ciris_persist::federation::Error) -> Option<Self> {
        use ciris_persist::federation::Error as E;
        use ciris_persist::scope::ScopeRefusalReason as R;
        match err {
            E::WriteScopeRefused(R::NoCommunityMembership) => Some(Self::RetryAfterCommunityRoster),
            E::WriteScopeRefused(R::NoFamilyMembership) => Some(Self::RetryAfterFamilyRoster),
            E::CohortStandingRefused { .. } => Some(Self::ThirdPartyRow),
            _ => None,
        }
    }
}

/// The `Refused` reason for a classified apply-door refusal: persist's own
/// message + token, then edge's class and what a relay does about it.
///
/// The persist half is byte-identical to [`apply_refusal_reason`] so existing
/// correlation (content hash, `kind()` token) is unchanged; the class is
/// APPENDED. That ordering matters — the class is edge's reading, and it must
/// not displace the substrate's own verdict in the log line.
fn classified_refusal_reason(
    plane: &str,
    content_hash: &str,
    err: &ciris_persist::federation::Error,
    class: ApplyRefusalClass,
) -> String {
    let disposition = if class.is_transient() {
        "TRANSIENT — THIS NODE'S view of the cohort roster decided it, and the row is \
         not stored, so the node still lacks it and the next round re-offers it. It \
         lands once the roster shows the writer as an ACTIVE member, and keeps \
         refusing while the roster shows the member removed — the same discipline \
         covers both halves of the revocation pairing (CIRISEdge#522)"
    } else {
        "TERMINAL — this does not resolve by retrying (CIRISEdge#522)"
    };
    format!(
        "{}; class={} [{disposition}]",
        apply_refusal_reason(plane, content_hash, err),
        class.as_str(),
    )
}

/// CIRISEdge#544 — does re-offering the IDENTICAL bytes that earned this
/// Key-plane refusal have any chance of a different answer?
///
/// The issue's measured row is here: `conflicting_version`, one `Key` record,
/// 55 re-offers in 30 minutes, same content hash every time. The disposition is
/// read off persist's own doc-comments on
/// [`KeyRefusalReason`](ciris_persist::federation::register::KeyRefusalReason) —
/// they are the authority on what each branch is a function of, and edge keys on
/// the typed variant, never on the message prose (#565's whole point).
///
/// # TERMINAL — the verdict is a function of state replication cannot move
///
/// - `PubkeySwap` — "replication may never swap an identity's keys". The verdict
///   compares the stored pubkey with the offered one; replication is structurally
///   barred from changing the first, and the second is fixed by the bytes.
/// - `Downgrade` — "Monotonic — never demote an anchored row". The stored row can
///   only become MORE anchored, so a self-signed record's answer can only stay no.
/// - `ConflictingVersion` — "First-seen wins", and these bytes did not. Terminal
///   in every reachable successor state too: if the stored self-signed row is
///   later anchor-scrubbed, the same offer becomes a `Downgrade` — still refused.
///
/// # TRANSIENT — decided by state that is still moving, or by a token that
/// collapses a recoverable arm with an unrecoverable one
///
/// - `StoreConflict` — persist says it outright: "the record is safe to re-offer".
///   A lost plan/act race on a planning backend.
/// - `UnverifiableSignature` — the token covers a malformed record (terminal) AND
///   an **unregistered signer** (recoverable: the scrub key is itself a Key-plane
///   row that replicates, so this is ordinary bootstrap ordering). Indistinguishable
///   from here, and dropping a record whose signer key is merely still in flight
///   would silently strand a key registration — so: transient, bounded by backoff.
/// - `ReScrub` — likewise mixed: "not canonical-scoped" / "valid_from not newer"
///   cannot move, but "the m-of-n quorum re-verify … failed" can — quorum evidence
///   replicates on its own cursor plane (#474). A canonical KEY SUPERSEDE is the
///   single worst row to drop for being early, so it stays re-askable.
/// - `OwnerAbsent` / `OwnerAmbiguous` — `owner_of` is resolved from replicated
///   ownership rows; both readings change when those rows (or a revocation of a
///   duplicate claim) land. Fail-closed, per persist — not permanent.
/// - `AlreadyAnchoredIdentical` — unreachable here: [`key_outcome_to_apply`] maps
///   it to [`ApplyOutcome::Duplicate`] (the receiver already holds what was
///   offered), so it never reaches a refusal memory. Listed transient because a
///   duplicate is the opposite of a thing to stop asking for, and because the
///   compiler must see every variant answered.
///
/// The asymmetry is deliberate and is the rule for any future variant: a
/// permanent refusal called transient costs a decaying trickle of re-asks; a
/// recoverable one called terminal withholds state. When a token is ambiguous,
/// it is transient.
#[must_use]
fn key_refusal_retry(reason: KeyRefusalReason) -> RetryDisposition {
    match reason {
        KeyRefusalReason::PubkeySwap
        | KeyRefusalReason::Downgrade
        | KeyRefusalReason::ConflictingVersion => RetryDisposition::Terminal,
        KeyRefusalReason::ReScrub
        | KeyRefusalReason::AlreadyAnchoredIdentical
        | KeyRefusalReason::UnverifiableSignature
        | KeyRefusalReason::OwnerAbsent
        | KeyRefusalReason::OwnerAmbiguous
        | KeyRefusalReason::StoreConflict => RetryDisposition::Transient,
    }
}

/// persist v24.2.0 (CIRISPersist#565) — map the typed Key-plane apply outcome to
/// edge's [`ApplyOutcome`], returning alongside it the stable refusal TOKEN to
/// count on the receive-plane mirror ledger (`None` when nothing was refused).
///
/// Pure so the whole mapping is unit-testable over [`KeyRefusalReason::ALL`]
/// without a backend. Two load-bearing decisions:
///
/// - **Both duplicate halves map to `Duplicate`** (persist's #565 finding, not
///   just the ask): a byte-identical re-offer already resolved `Unchanged` at
///   the `persist_row_hash` comparison, and `AlreadyAnchoredIdentical` is its
///   sibling — a same-envelope-DIFFERENT-BYTES legitimate re-encoding of a
///   record this node already anchors (every baked-seed node re-offered the
///   canonical's own record hits it). Before v24.2.0 that read as a
///   security-shaped refusal on the COMMON path. Neither half counts on the
///   refusal ledger: the receiver already holds what was offered.
/// - **The reason is the branch**: the refusal message carries persist's stable
///   token (`pubkey_swap`, `downgrade`, …) — the #565 twin of the #433 rule.
///   Consumers key on the token constant, never on message prose.
fn key_outcome_to_apply(
    result: Result<ReplicatedKeyOutcome, ciris_persist::federation::Error>,
    content_hash: &str,
) -> (ApplyOutcome, Option<&'static str>) {
    match result {
        Ok(
            ReplicatedKeyOutcome::Inserted
            | ReplicatedKeyOutcome::Upgraded
            | ReplicatedKeyOutcome::Superseded,
        ) => (ApplyOutcome::Admitted, None),
        Ok(
            ReplicatedKeyOutcome::Unchanged
            | ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AlreadyAnchoredIdentical,
            },
        ) => (ApplyOutcome::Duplicate, None),
        // CIRISEdge#544 — the disposition rides the SAME typed value the token
        // does. `key_refusal_retry` carries the per-variant reasoning; the
        // message states the verdict so an operator reading one WARN line knows
        // whether to wait or to supersede.
        Ok(ReplicatedKeyOutcome::Refused { reason }) => {
            let retry = key_refusal_retry(reason);
            (
                ApplyOutcome::Refused {
                    reason: format!(
                        "Key: admission refused ({}; content_hash={content_hash}) [retry={}]",
                        reason.as_str(),
                        retry.as_str(),
                    ),
                    retry,
                },
                Some(reason.as_str()),
            )
        }
        // A persist `Err` on this door is NOT one of the typed policy branches —
        // it is a backend/plumbing failure, which is the definition of moving
        // state. Transient (bounded by the short backoff), never terminal.
        Err(e) => (
            ApplyOutcome::refused(apply_refusal_reason("Key", content_hash, &e)),
            None,
        ),
    }
}

static SERVE_GATE_WITHHELD_LOG: std::sync::OnceLock<crate::log_throttle::LogThrottle> =
    std::sync::OnceLock::new();

/// CIRISEdge#425 Exhibit A — a serve-gate refusal WITHHOLDS an entire plane (every
/// `trace:*` attestation) from a peer. That is a `warn!`, never `debug!`: a node at
/// default log levels was silently withholding every trace FOREVER, indistinguishable
/// from "there was nothing to send" (the round reported `completed`, `envelopes_sent=0`
/// — perfect health, zero carriage). Throttled to a FLOOR — a few per five minutes
/// per (peer, reason), a PERIODIC repeat that resets each window, NEVER to silence:
/// a persistently-dark plane is exactly the failure you must not go quiet about.
fn serve_gate_withheld_log() -> &'static crate::log_throttle::LogThrottle {
    SERVE_GATE_WITHHELD_LOG
        .get_or_init(|| crate::log_throttle::LogThrottle::new(3, Duration::from_secs(300), 256))
}

/// CIRISEdge#425 — a single-shape plane: deserialize `$ty`, admit via `$put`, and
/// yield an [`ApplyOutcome`] (never a silent `false`). `Ok(())` from persist means
/// admitted-or-idempotent-dedupe (matching the old `is_ok()`); a gate `Err`
/// becomes `Refused(reason)`; a parse failure becomes `Deserialize(reason)`.
macro_rules! apply_signed_plane {
    ($self:expr, $plane:literal, $bytes:expr, $ty:ty, $put:ident) => {
        match serde_json::from_slice::<$ty>($bytes) {
            Ok(record) => {
                let content_hash =
                    content_hash_of(&record).map_or_else(String::new, |(h, _)| hex::encode(h));
                match $self.directory.$put(record).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    // CIRISEdge#522 — through `refuse`, so a v38.2.0 door class
                    // (AV-45 roster ordering, AV-84 third-party) is named and
                    // counted whichever plane surfaces it.
                    Err(e) => $self.refuse($plane, &content_hash, &e),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason($plane, $bytes, &e)),
        }
    };
}

// ─── Configuration ───────────────────────────────────────────────────

/// Tuning knobs for the production bridge.
#[derive(Debug, Clone, Copy)]
pub struct BridgeConfig {
    /// Page size for the v2 operational kinds' bulk-list sweep
    /// (`list_organizations_since` / `list_org_memberships_since` /
    /// `list_partner_records_since`). v2.0.0 ships unlimited single-page
    /// (`u32::MAX`) by default — federations of operational records are
    /// O(orgs × partners), far below the wire MTU concern that motivated
    /// pagination. Operators with very large operational rosters tune
    /// this downward and accept multiple round trips per round.
    ///
    /// CIRISEdge#531 — that last sentence was UNSAFE until the watermark
    /// landed. The reads are `ORDER BY (pos, id) ASC`, so a cap with a `None`
    /// cursor served the OLDEST N rows every round, forever: new rows —
    /// including every new chat message — would stop being advertised the
    /// moment the corpus exceeded the cap. Lowering this is safe now because
    /// [`SweepWindow::Watermark`] carries the position between rounds; it is
    /// still the REACH bound (what a node is willing to offer and serve), while
    /// [`Self::sweep_page_rows`] is the MEMORY bound. The effective page is the
    /// `min`.
    pub operational_page_limit: u32,

    /// CIRISEdge#531 — how many bulk advertise/holdings sweeps may be
    /// MATERIALISED at the same time across the whole node. See
    /// [`Self::DEFAULT_ADVERTISE_SWEEP_PERMITS`] for the arithmetic; `0`
    /// disables the bound entirely (the pre-#531 behaviour) and is an escape
    /// hatch, not a supported production setting.
    pub advertise_sweep_permits: usize,

    /// CIRISEdge#531 **DEPTH** — rows per SWEEP PAGE: how much of a plane one
    /// bulk read materialises at a time. See
    /// [`Self::DEFAULT_SWEEP_PAGE_ROWS`]. `0` disables paging (one whole-table
    /// read per sweep — the pre-DEPTH behaviour), and is an escape hatch, not
    /// a supported production setting.
    ///
    /// This is the knob that makes the memory FLAT. [`Self::advertise_sweep_permits`]
    /// bounds `permits × corpus × 2`, which still grows with the table; with a
    /// finite page the same product becomes `permits × page × 2`, which does
    /// not. It is a separate field from [`Self::operational_page_limit`]
    /// because that one is the operator's *reach* bound (and the accord
    /// cursor's truncation sentinel keys on it); this one is a *materialisation*
    /// bound that costs nothing but rounds. The effective page is the `min` of
    /// the two.
    pub sweep_page_rows: u32,
}

impl BridgeConfig {
    /// Default for [`Self::operational_page_limit`].
    pub const DEFAULT_OPERATIONAL_PAGE_LIMIT: u32 = u32::MAX;

    /// CIRISEdge#531 DEPTH — default for [`Self::sweep_page_rows`]: **1024**.
    ///
    /// ## Why a page at all
    ///
    /// [`Self::DEFAULT_ADVERTISE_SWEEP_PERMITS`] bounds how many whole-table
    /// `Vec`s are alive at once; it does not bound the table. On the measured
    /// box (CIRISServer#476) the corpus was 14,616 attestations = 194.8 MiB,
    /// and a second node on the same host carried 52,125 rows. `permits ×
    /// corpus × 2` grows with the corpus, so the width bound buys time, not
    /// safety. A page turns the same product into a constant:
    ///
    /// ```text
    ///   1024 rows × ~24.5 KiB/row (the trace family, the heaviest)  ≈ 25 MiB
    ///   peak ≈ permits × page_payload × 2  =  2 × 25 MiB × 2  ≈  100 MiB
    /// ```
    ///
    /// — flat in the corpus, against 780 MiB at 14.6k rows and ~2.8 GB
    /// unbounded.
    ///
    /// ## Why 1024 and not smaller
    ///
    /// The page also sets the ROLLING RE-SWEEP period: after a peer's
    /// watermark catches up, every row is re-offered once per
    /// `ceil(corpus / page)` rounds (see [`SweepCursors`]). At 52k rows and
    /// the 30 s default cadence that is ~51 rounds ≈ 25 min — the outer bound
    /// on how long a TRANSIENTLY-refused row (AV-45 `retry_after_community_roster`)
    /// can wait for its next offer. Halving the page halves the memory and
    /// doubles that wait. 1024 keeps both defensible without tuning; an
    /// operator on a big corpus who cares more about re-offer latency than
    /// about 25 MiB raises it.
    ///
    /// ## Why paging is not an I/O regression
    ///
    /// Every `list_*_since` cursor is index-backed as of persist v36
    /// (migration `V130__serve_cursor_local_admission_instants` creates
    /// `<table>_admitted ON (COALESCE(admitted_at, …), <id>)` for all 13
    /// planes), so a page is an index RANGE SCAN — `O(page)`, not a re-sort
    /// of the table. Without that index, paging would have turned one full
    /// scan per round into many, and this change would be wrong; it is the
    /// load-bearing fact under the whole DEPTH design.
    pub const DEFAULT_SWEEP_PAGE_ROWS: u32 = 1024;

    /// CIRISEdge#531 DEPTH — process-level override for
    /// [`Self::sweep_page_rows`], read ONCE at runtime assembly, for the same
    /// reason [`Self::ADVERTISE_SWEEP_PERMITS_ENV`] exists: the deployment
    /// that OOMed never constructs a [`BridgeConfig`]. `0` disables paging;
    /// an unparseable value is IGNORED with a WARN.
    pub const SWEEP_PAGE_ROWS_ENV: &'static str = "CIRIS_EDGE_SWEEP_PAGE_ROWS";

    /// CIRISEdge#531 — default for [`Self::advertise_sweep_permits`]: **2**.
    ///
    /// ## What this bounds
    ///
    /// This is the WIDTH axis of #531, not the DEPTH one. Every bulk sweep
    /// still reads its whole table (`list_*_since(None, page_limit)`); what
    /// this caps is how many of those `Vec`s are alive AT ONCE. The OOM is a
    /// PRODUCT — planes × peers × (advertise + holdings) — and the scheduler
    /// spawns one independent task per `(peer, kind)` on a shared cadence
    /// (`scheduler::spawn_coord`), so today every one of them materialises in
    /// the same tick. Bounding the product is the cheap half; the cursor that
    /// bounds one sweep's depth is CIRISEdge#531's other, larger half.
    ///
    /// ## The arithmetic (measured, CIRISServer#476)
    ///
    /// The production node that OOMed carried 14,616 federation attestations
    /// = **194.8 MiB of payload**, and reached **2.8 GB RSS** on a 3.9 GB box
    /// with ~6 peers' Attestation coordinators sweeping in the same tick:
    ///
    /// ```text
    ///   2.8 GB RSS − ~0.4 GB baseline ≈ 2.4 GB over ~6 in-flight sweeps
    ///   ⇒ ~400 MiB resident per in-flight sweep
    ///   ⇒ ~2× the 194.8 MiB payload (parsed rows + the per-row Value + refs)
    ///
    ///   peak ≈ permits × corpus_payload × 2
    ///        = 2 × 194.8 MiB × 2  ≈  780 MiB
    /// ```
    ///
    /// ~780 MiB of sweep + ~400 MiB of baseline ≈ **1.2 GB on a 3.9 GB box**,
    /// against 2.8 GB unbounded — headroom for the same corpus to roughly
    /// double before the box is at risk again.
    ///
    /// ## Why not 1
    ///
    /// 1 would halve the peak again, but it serialises every plane behind the
    /// slowest one and makes the node's whole replication throughput one
    /// sweep deep. 2 keeps a cheap plane (Key, TransportDestination — sweeps
    /// measured in milliseconds) moving while an Attestation sweep runs.
    ///
    /// ## Why this does not serialise a healthy mesh
    ///
    /// At the default 30 s cadence with ~6 peers × 6 planes = ~36 coordinators
    /// (plus responders), the queue drains at 2 sweeps at a time. The
    /// expensive plane is Attestation (~1.5 s/sweep on the measured corpus,
    /// ~12 sweeps/tick counting responders); every other plane's sweep is
    /// sub-10 ms and drains behind it. Worst case ≈ 12/2 × 1.5 s ≈ 9 s of
    /// queueing inside a 30 s cadence, and a round whose tick is missed is
    /// SKIPPED rather than burst-replayed
    /// (`MissedTickBehavior::Skip`) — so queueing costs latency, never a
    /// compounding backlog.
    pub const DEFAULT_ADVERTISE_SWEEP_PERMITS: usize = 2;

    /// CIRISEdge#531 — process-level override for
    /// [`Self::advertise_sweep_permits`], read ONCE at runtime assembly
    /// (`replication::runtime::build_bridge`).
    ///
    /// The reason this exists at all: the deployment that OOMed —
    /// CIRISServer — rides `ReplicationRuntime` and never constructs a
    /// [`BridgeConfig`], so the field alone is not reachable by an operator
    /// on a wedged box without a downstream release. The env var is the
    /// out-of-band lever; the DEFAULT is still what production runs, and is
    /// chosen to need no tuning.
    ///
    /// Parsed as a `usize`; `0` disables the bound (pre-#531 behaviour). An
    /// unparseable value is IGNORED with a WARN rather than fail-closing to
    /// zero permits — a typo must not deadlock replication.
    pub const ADVERTISE_SWEEP_PERMITS_ENV: &'static str = "CIRIS_EDGE_ADVERTISE_SWEEP_PERMITS";
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            operational_page_limit: Self::DEFAULT_OPERATIONAL_PAGE_LIMIT,
            advertise_sweep_permits: Self::DEFAULT_ADVERTISE_SWEEP_PERMITS,
            sweep_page_rows: Self::DEFAULT_SWEEP_PAGE_ROWS,
        }
    }
}

// ─── CIRISEdge#531 — the advertise-sweep width bound ─────────────────

/// CIRISEdge#531 — the node-wide bound on how many bulk sweeps are
/// MATERIALISED simultaneously, plus its own high-water witness.
///
/// ## Why a semaphore and not a lock
///
/// The failure is a memory PRODUCT, not a data race: N sweeps each holding a
/// whole-table `Vec` live at the same instant. A mutex would serialise to one
/// (throughput cliff) and, worse, would not be fair. [`tokio::sync::Semaphore`]
/// is documented FIFO-fair on the `acquire` family — *"this method uses a queue
/// to fairly distribute permits in the order they were requested"* — which is
/// what turns "bound the memory" into something that cannot become a liveness
/// bug: a plane that queues is at a FIXED position behind a bounded number of
/// bounded holds, so no plane can be indefinitely overtaken by a busier one.
/// (`try_acquire` is deliberately NOT used anywhere here — it is the one path
/// that can jump the queue, and a fast plane repeatedly barging a slow one is
/// exactly the starvation this must not have.)
///
/// ## Release is structural
///
/// [`SweepGate::enter`] hands back a [`SweepPermit`] whose `Drop` releases both
/// the permit and the in-flight count. Every exit path out of a sweep —
/// `return`, `?`, an early `Vec::new()` refusal, a panic unwinding through the
/// `block_in_place` bridge — runs it. There is no manual release to forget.
///
/// ## Re-entrancy
///
/// The gate is entered at EXACTLY ONE layer, and CIRISEdge#531 DEPTH moved
/// which layer that is: v18.6.0 took the permit at the [`ReplicationDirectory`]
/// trait boundary, once per sweep; it is now taken around exactly ONE PAGE's
/// read plus that page's projection — [`FederationDirectoryReplicationBridge::sweep_paged`],
/// `attestation_page`, `accord_evidence_page`, and `fan_out_for_member`'s
/// per-member read. Nothing above those takes one.
///
/// The move is what keeps the bound from becoming a liveness bug once a sweep
/// is many reads: a `Full` holdings drain of a large plane would otherwise hold
/// one of two permits for its whole duration, and a FIFO-fair queue behind a
/// long hold is a long queue for every other plane. The invariant is also
/// stronger to state than the boundary version — *a permit covers one page,
/// never a caller of one* — and a second acquire while holding one still
/// self-deadlocks at `permits == 1`, which is what
/// `sweep_gate_is_not_re_entrant` pins for every kind and every entry point.
#[derive(Debug)]
struct SweepGate {
    /// `None` = unbounded (`advertise_sweep_permits == 0`), so the disabled
    /// path costs nothing — not even an uncontended atomic on the semaphore.
    sem: Option<Arc<tokio::sync::Semaphore>>,
    /// Sweeps currently inside the gate. `SeqCst` so `max` is a real
    /// high-water mark rather than a plausible one — this counter exists to be
    /// ASSERTED on, and a relaxed read could observe a stale peak.
    in_flight: std::sync::atomic::AtomicUsize,
    /// The high-water mark of [`Self::in_flight`] over the process's life. The
    /// bound's own witness: "at most N sweeps materialise at once" is a claim
    /// that has to be checkable rather than asserted (the same discipline as
    /// `owner_reads` above).
    max_in_flight: std::sync::atomic::AtomicUsize,
    /// CIRISEdge#531 DEPTH — CUMULATIVE entries. The depth fix moved the
    /// acquire from "once per sweep" to "once per PAGE", and that is a claim
    /// with a number attached: a `Full` drain of `ceil(rows / page)` pages must
    /// show that many entries, not one. Without this the difference between
    /// "released between pages" and "held across the whole drain" is invisible
    /// to a test, and holding it across the drain is the exact starvation shape
    /// the width bound was built to avoid.
    entries: std::sync::atomic::AtomicUsize,
}

impl SweepGate {
    /// CIRISEdge#531 (review finding, v18.6.0 follow-up) — the permit count is
    /// CLAMPED to [`tokio::sync::Semaphore::MAX_PERMITS`] (`usize::MAX >> 3`)
    /// before construction.
    ///
    /// `Semaphore::new` PANICS above that ceiling. The documented contract for
    /// [`BridgeConfig::ADVERTISE_SWEEP_PERMITS_ENV`] is that a bad value is
    /// ignored and the default retained — and a value that parses as a `usize`
    /// but exceeds the ceiling (`18446744073709551615`) sailed past the parse
    /// check and took the node down AT BOOT, on an operator typo, in the one
    /// code path whose entire purpose is keeping a wedged box alive. The env
    /// resolver now rejects such a value with a WARN
    /// (`replication::runtime::resolve_sweep_permits`); this clamp is the belt
    /// under that brace, because `advertise_sweep_permits` is also a plain
    /// public field any downstream may set directly.
    ///
    /// Clamping rather than refusing: a caller asking for `usize::MAX` permits
    /// is asking for "effectively unbounded", and `MAX_PERMITS` IS effectively
    /// unbounded — honouring the intent beats panicking on the arithmetic.
    fn new(permits: usize) -> Self {
        let permits = permits.min(tokio::sync::Semaphore::MAX_PERMITS);
        Self {
            sem: (permits > 0).then(|| Arc::new(tokio::sync::Semaphore::new(permits))),
            in_flight: std::sync::atomic::AtomicUsize::new(0),
            max_in_flight: std::sync::atomic::AtomicUsize::new(0),
            entries: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Acquire one sweep permit, FIFO-fair. Held only for the caller's
    /// materialising section; released by [`SweepPermit`]'s `Drop`.
    ///
    /// A CLOSED semaphore (nothing closes it today; the gate lives as long as
    /// the bridge) degrades to unbounded rather than refusing the sweep —
    /// replication going dark is a strictly worse failure than replication
    /// using more memory, and a closed gate is a shutdown state, not a policy.
    async fn enter(&self) -> SweepPermit<'_> {
        let permit = match self.sem.as_ref() {
            None => None,
            Some(sem) => Arc::clone(sem).acquire_owned().await.ok(),
        };
        let now = self
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        self.max_in_flight
            .fetch_max(now, std::sync::atomic::Ordering::SeqCst);
        self.entries
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        SweepPermit {
            gate: self,
            _permit: permit,
        }
    }
}

/// RAII half of [`SweepGate`]. Dropping it releases the semaphore permit (via
/// the owned permit's own `Drop`) and decrements the in-flight count, in that
/// order-independent way — neither is load-bearing for the other.
///
/// `#[must_use]` because the ONE way to silently un-bound the sweep is
/// `self.sweep_gate.enter().await;` as a bare statement: the permit would be
/// taken and dropped before the materialisation it is supposed to cover, and
/// nothing else about the code would look wrong.
#[must_use = "the sweep permit must be BOUND for the whole materialising \
              section — dropping it immediately silently un-bounds the sweep \
              (CIRISEdge#531)"]
struct SweepPermit<'a> {
    gate: &'a SweepGate,
    _permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Drop for SweepPermit<'_> {
    fn drop(&mut self) {
        self.gate
            .in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

// ─── CIRISEdge#531 DEPTH — the advertise WATERMARK ───────────────────

/// persist v36 (CIRISPersist#668) keyset-pagination cursor: the
/// `(serve_position, resume_id)` PAIR every `Served*` wrapper yields from its
/// `resume_pair()`, and the value every `list_*_since` takes back.
///
/// The pair, never the instant alone — that is the whole of #531's
/// "timestamp-collision skip" hazard, and persist already solved it: the page
/// is ordered by `(pos, id)` and filtered `pos > ?1 OR (pos = ?1 AND id > ?2)`,
/// so a tie LARGER than one page resumes into the middle of the tie instead of
/// skipping its remainder. Edge's job is only to stop throwing the pair away.
type ResumeCursor = (chrono::DateTime<chrono::Utc>, String);

/// CIRISEdge#531 DEPTH — one peer's advertise position on one plane.
///
/// ## Why there are TWO cursors and not one
///
/// A single monotonic cursor bounds memory and breaks convergence. Three
/// things a peer must still be offered live BEHIND a cursor that has passed
/// them:
///
///   1. a row the peer refused TRANSIENTLY (v18.4.0's AV-45
///      `retry_after_community_roster`: correctly refused now, admissible once
///      the roster lands). The refusal happens on the RECEIVER and is never
///      reported back, so the sender cannot keep a "recently refused" replay
///      set — it does not know. `ApplyRefusalClass::is_transient`'s documented
///      guarantee is literally *"the next Summary/Diff re-offers it"*, which is
///      a claim about the SENDER's advertise set;
///   2. a row the peer wanted but whose `Deliver` did not fit the round's byte
///      budget (`session::pack_bounded_deliver` defers the remainder to "the
///      peer's `want` next round" — which only works if we still advertise it);
///   3. a row lost with a dropped frame.
///
/// So the watermark must be an OPTIMISATION, never a one-way door. The second
/// cursor is that door-stop: a rolling re-sweep that walks the whole plane from
/// the beginning, one page per round, and wraps.
///
/// ## The round
///
/// * **[`Self::high_water`]** — the NEW-ROWS cursor. Read first, with the whole
///   page budget. In steady state this is empty or a handful of rows, and a row
///   admitted between rounds (every new chat message) is offered in the NEXT
///   round, not one re-sweep cycle later. This is why new rows do not pay the
///   backfill's latency.
/// * **[`Self::backfill`]** — the rolling re-sweep cursor. Gets whatever page
///   budget the new-rows read did not spend, so a busy plane cannot starve it
///   to zero and an idle one gives it the whole page. Wraps to `None` at the
///   end of the plane.
/// * **[`Self::caught_up`]** — until the new-rows walk has reached the end of
///   the plane once, that walk IS the first re-sweep pass, so the backfill
///   tracks it and no second read happens. This is what keeps a COLD peer's
///   catch-up at one page per round instead of two.
///
/// ## Lifecycle
///
/// In memory, per process. A restart re-sweeps every peer from the beginning —
/// which costs WORK and converges, rather than costing correctness. That is a
/// deliberate v1 choice: persisting the watermark would make a mis-persisted
/// cursor able to strand rows across restarts, which is the failure this whole
/// design refuses to have. Evicted by [`SweepCursors`]'s cap, which is likewise
/// only a re-sweep.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PlaneWatermark {
    /// Highest `(pos, id)` this peer has been offered on this plane.
    high_water: Option<ResumeCursor>,
    /// The rolling re-sweep position. `None` = start over from the beginning.
    backfill: Option<ResumeCursor>,
    /// Has [`Self::high_water`] reached the end of the plane at least once?
    caught_up: bool,
    /// Monotonic touch tick, for the cap's least-recently-used eviction.
    touched: u64,
}

/// CIRISEdge#531 DEPTH — the second page of a round, when the new-rows read
/// left budget for one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BackfillPage {
    since: Option<ResumeCursor>,
    budget: u32,
}

/// CIRISEdge#531 DEPTH — the per-`(peer, plane)` advertise watermarks.
///
/// PURE: no directory, no clock, no I/O. The convergence properties of the
/// whole DEPTH change are properties of this state machine, so it is separated
/// from everything that would need a federation fixture to exercise (the same
/// discipline as [`OwnerCache`]).
#[derive(Debug, Default)]
struct SweepCursors {
    by_peer_plane: HashMap<(String, EnvelopeKind), PlaneWatermark>,
    /// Monotonic tick, incremented on every touch, so eviction can be LRU
    /// without a clock.
    tick: u64,
}

/// CIRISEdge#531 DEPTH — how many `(peer, plane)` watermarks are retained.
///
/// Peers churn (CIRISEdge#532's link churn is on the same node), and an
/// unreapable per-peer map is exactly the shape CIRISEdge#530 is open about on
/// the announce plane. 512 entries ≈ 40 peers × 13 planes; a `PlaneWatermark`
/// is two small cursors, so the whole map is kilobytes. Evicting the
/// least-recently-touched entry costs that peer one re-sweep from the
/// beginning — the same "costs work, not correctness" trade the restart makes.
const MAX_TRACKED_SWEEP_CURSORS: usize = 512;

impl SweepCursors {
    /// The `since` for this round's NEW-ROWS page.
    fn head(&mut self, key: &(String, EnvelopeKind)) -> Option<ResumeCursor> {
        self.touch(key).high_water.clone()
    }

    /// Record the new-rows page and decide whether a backfill page follows.
    ///
    /// `served` is how many rows the read RETURNED (not how many survived the
    /// projection gates — the gates shape the offer, the cursor tracks the
    /// READ), `budget` is what was asked for, and `last` is the final row's
    /// [`ResumeCursor`].
    fn after_head(
        &mut self,
        key: &(String, EnvelopeKind),
        served: usize,
        budget: u32,
        last: Option<ResumeCursor>,
    ) -> Option<BackfillPage> {
        let wm = self.touch(key);
        let short = served < budget as usize;
        if let Some(c) = last {
            wm.high_water = Some(c);
        }
        if !wm.caught_up {
            if short {
                // First time the forward walk has reached the end of the
                // plane: that walk WAS the first full pass, so the rolling
                // re-sweep starts over from the beginning NEXT round rather
                // than re-reading the tail we have just read.
                wm.caught_up = true;
                wm.backfill = None;
            } else {
                // Still catching up. The forward walk is the sweep; a second
                // read would double a cold peer's per-round cost for nothing.
                wm.backfill.clone_from(&wm.high_water);
            }
            return None;
        }
        let remaining = budget.saturating_sub(u32::try_from(served).unwrap_or(u32::MAX));
        (remaining > 0).then(|| BackfillPage {
            since: wm.backfill.clone(),
            budget: remaining,
        })
    }

    /// Record the backfill page: advance, or WRAP to the beginning when the
    /// page came back short (the end of the plane).
    fn after_backfill(
        &mut self,
        key: &(String, EnvelopeKind),
        served: usize,
        budget: u32,
        last: Option<ResumeCursor>,
    ) {
        let wm = self.touch(key);
        if served < budget as usize {
            wm.backfill = None;
        } else if let Some(c) = last {
            wm.backfill = Some(c);
        }
    }

    /// Fetch-or-create, stamping the LRU tick and enforcing the cap.
    fn touch(&mut self, key: &(String, EnvelopeKind)) -> &mut PlaneWatermark {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        if !self.by_peer_plane.contains_key(key)
            && self.by_peer_plane.len() >= MAX_TRACKED_SWEEP_CURSORS
        {
            self.evict_oldest();
        }
        let wm = self.by_peer_plane.entry(key.clone()).or_default();
        wm.touched = tick;
        wm
    }

    /// Drop the least-recently-touched entry. Costs that peer a re-sweep from
    /// the beginning, never a skipped row.
    fn evict_oldest(&mut self) {
        let Some(victim) = self
            .by_peer_plane
            .iter()
            .min_by_key(|(_, wm)| wm.touched)
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        tracing::debug!(
            peer = %victim.0,
            kind = ?victim.1,
            cap = MAX_TRACKED_SWEEP_CURSORS,
            "advertise watermark EVICTED at the cap — this peer/plane re-sweeps \
             from the beginning (costs a cycle of work, never a skipped row; \
             CIRISEdge#531)"
        );
        self.by_peer_plane.remove(&victim);
    }
}

/// CIRISEdge#531 DEPTH — how much of a plane ONE sweep is allowed to see.
///
/// The distinction is not cosmetic: [`Self::Watermark`] is the SEND axis (what
/// this node OFFERS a peer this round — a page, converging over rounds), and
/// [`Self::Full`] is the RECEIVE axis (`want = remote ∖ holdings`), which MUST
/// be complete. Watermarking the holdings view would leave a held-but-unlisted
/// row in `want` forever and re-fetch it every round — CIRISEdge#416's
/// non-convergence, re-created by the fix for the memory. `Full` is still
/// PAGED — it just keeps every page's refs instead of only the last one's, so
/// its memory is `O(page rows + corpus × 40 bytes)` rather than
/// `O(corpus rows)`. On the measured corpus that is ~25 MiB + 2 MiB against
/// 195 MiB.
#[derive(Debug, Clone, Copy)]
enum SweepWindow<'a> {
    /// Drain every page; the RESULT is the complete set.
    Full,
    /// One page budget against this peer's watermark for this plane.
    Watermark(&'a str),
}

/// CIRISEdge#531 DEPTH — the Attestation sweep's per-ROUND state, threaded
/// across the round's pages.
///
/// Every field was already a once-per-sweep fact when a sweep was one read.
/// Paging turned "per sweep" into "per page" unless they are hoisted, and the
/// two caches here are directory reads: `serve_allowed` is one KeyRecord
/// capability lookup, `grant_cache` one consent-grant parse per owner, and
/// `quarantine_memo` one standing read per distinct author. Re-resolving them
/// per page is the CIRISEdge#400 shape (a per-record re-resolution that blew
/// the round budget), so they live here rather than inside
/// [`FederationDirectoryReplicationBridge::attestation_page`].
struct AttestationSweepCtx {
    /// The consent-membership proof for this peer (`None` = peer-blind view).
    resolved_recipient: Option<ResolvedRecipient>,
    /// The `SelfOwn` publish set for the projection filter.
    self_set: HashSet<String>,
    /// CIRISEdge#379 — the peer's `infra:serve` capability, resolved lazily on
    /// the first gated row and then for the whole round.
    serve_allowed: Option<bool>,
    /// CIRISEdge#396 item 6 — per-owner parsed consent grants.
    grant_cache: HashMap<String, Vec<ConsentTransferPolicy>>,
    /// CIRISEdge#440 — is the `trace:*` plane paused by a live relief?
    trace_paused: bool,
    /// Book the pause ONCE per round, not once per page and not once per row.
    trace_pause_booked: bool,
    /// CIRISEdge#440 ask 3 — per-author quarantine standing.
    quarantine_memo: HashMap<String, QuarantineConsult>,
}

/// CIRISEdge#531 DEPTH — the hard stop on a [`SweepWindow::Full`] drain.
///
/// A `Full` drain loops until a page comes back short. Every exit depends on
/// persist returning fewer rows than asked for eventually; a backend that
/// ignored `limit`, or a cursor that could not advance, would spin forever
/// inside a permit. 4096 pages × the default 1024 rows = 4.2M rows per plane,
/// far above any real corpus and far below "forever". Hitting it is LOUD and
/// truncates the holdings view for that round — which re-wants rows we hold
/// (wasteful, self-correcting) rather than hanging the node.
const MAX_FULL_DRAIN_PAGES: usize = 4096;

/// CIRISEdge#531 — the byte budget on ONE accord-quorum-evidence cursor page.
///
/// Every other `Deliver` on the wire is byte-bounded
/// ([`crate::replication::session::MAX_DELIVER_ENVELOPE_BYTES`] for the
/// Diff-driven path, [`crate::replication::session::PROACTIVE_PUSH_BUDGET_BYTES`]
/// for the proactive push); the cursor plane's Deliver was the ONE that was not
/// — it served a whole page of serialized bundles, and that page then stayed
/// resident through the send. This is the same 512 KiB the Diff path uses, for
/// the same reason: it bounds the frame so its fragment count stays
/// reassemblable under loss, and here it also bounds RETENTION, which the sweep
/// permit cannot (the permit is gone before the bytes reach the session).
const CURSOR_PAGE_BUDGET_BYTES: usize = 512 * 1024;

/// Type alias for the cohort provider — an operator-configured
/// callback yielding the federation key_ids we want to anti-entropy
/// with. Re-invoked at the start of every `list_envelope_refs` call,
/// so the bridge observes peer-set evolution without restart.
pub type CohortProvider = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Type alias for the v2 key-directory provider — an operator-configured
/// callback yielding the current federation key_directory
/// (`Vec<ThresholdMember>`). Re-invoked on each operational admit so
/// admission sees the live directory. Used by persist's
/// `put_organization` / `put_org_membership` admit surfaces for the
/// single-signer role-chain authority check (Verify v5.1.0's
/// `resolve_role_authority`). When `None`, the bridge refuses to admit
/// operational-kind envelopes (returns `false` from `apply_*`) —
/// fail-closed.
pub type KeyDirectoryProvider = Arc<dyn Fn() -> Vec<ThresholdMember> + Send + Sync>;

/// Type alias for the v2 root-stewards provider — an operator-configured
/// callback yielding the federation's bootstrap steward `member_id`s.
/// Used by persist's `put_organization` / `put_org_membership` admit
/// surfaces to anchor the role-chain at trust root (the founder set
/// per CEG §9.1). When `None`, the bridge refuses to admit operational-
/// kind envelopes — fail-closed.
pub type RootStewardsProvider = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

/// Type alias for the v2 steward-roster provider — an operator-configured
/// callback yielding the current federation steward roster
/// (`Vec<ThresholdMember>`). Used by persist's `put_partner_record`
/// admit surface for the M-of-N steward quorum verification. When
/// `None`, the bridge refuses to admit `partner_record` envelopes —
/// fail-closed.
pub type StewardRosterProvider = Arc<dyn Fn() -> Vec<ThresholdMember> + Send + Sync>;

/// v2 (CEG 1.0-RC2 §5.6.8.13 / FSD §5.2) — operational-data admission
/// providers bundle. Operators set this at bridge construction time to
/// enable v2 operational-kind admission; leaving it `None` keeps the
/// bridge v1-only (operational `apply_*` returns `false`, gracefully
/// declining to admit).
#[derive(Clone)]
pub struct OperationalProviders {
    /// The federation key_directory — `Vec<ThresholdMember>`. See
    /// [`KeyDirectoryProvider`].
    pub key_directory: KeyDirectoryProvider,
    /// The federation bootstrap stewards' `member_id`s. See
    /// [`RootStewardsProvider`].
    pub root_stewards: RootStewardsProvider,
    /// The federation steward roster — `Vec<ThresholdMember>`. See
    /// [`StewardRosterProvider`].
    pub steward_roster: StewardRosterProvider,
}

/// CIRISEdge#440 ask 3 — one author's memoized quarantine consult within a
/// single sweep/fetch. A tri-state on purpose: `Withheld` and `ReadError` both
/// withhold, but they are DIFFERENT facts booking DIFFERENT
/// [`crate::observability::WithholdReason`]s (#433 — a reason is a branch,
/// never a disjunction), and collapsing them to a `bool` at the memo would
/// re-create exactly the fold this ledger exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuarantineConsult {
    /// No live withhold marker governs the author.
    Clear,
    /// A live `quarantine:withheld:v1` marker governs the author.
    Withheld,
    /// The consult failed; fail-closed for this sweep, reported as a read
    /// error.
    ReadError,
}

// ─── The bridge ──────────────────────────────────────────────────────

/// Throttle for the rate-limit denial WARN. A denied peer keeps sending, so
/// the log line about limiting it needs limiting too.
fn lookup_limit_log() -> &'static crate::log_throttle::LogThrottle {
    static T: std::sync::OnceLock<crate::log_throttle::LogThrottle> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        crate::log_throttle::LogThrottle::new(3, std::time::Duration::from_secs(60), 1024)
    })
}

/// Wall-clock seconds, for the limiter's caller-supplied clock (FSD D1).
///
/// A backwards clock is safe by construction: `RateLimiter` uses saturating
/// arithmetic throughout, so a jump reads as "no time passed" — it neither
/// refills a quota early nor locks a peer out.
fn unix_now_secs() -> crate::rate_limit::Ts {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Cap on the missing-signer set (CIRISEdge#552 B). Sized for a federation's
/// SIGNER count, not its record count: a name repeats across every row that
/// signer signed, so the set dedupes hard. Past the cap names are dropped and
/// the rows they gate stay transient-refused — bounded and visible, and it
/// drains as pulls land.
const MISSING_SIGNER_CAP: usize = 1024;

/// Production-grade [`ReplicationDirectory`] implementation over
/// persist's `FederationDirectory`.
pub struct FederationDirectoryReplicationBridge {
    directory: Arc<dyn FederationDirectory>,
    cohort: CohortProvider,
    /// CIRISEdge#311 — the SELF-plane publish set. Collapses the #257
    /// `key_selector` + #305 `occurrence_selector` into ONE provider: both were
    /// the same `Projection::SelfOwn` re-implemented per plane. When `Some`, the
    /// unified engine advertises the node's OWN records for the key_ids THIS
    /// callback yields across every `SelfOwn` kind — `KeyRecord` (#257),
    /// `IdentityOccurrence` (#305, carries the content-tier `encryption_pubkeys`
    /// for KEX), and `TransportDestination` (reachability). `None` preserves the
    /// pre-#257/#305 cohort projection (back-compat). The server supplies the
    /// set (own + anchored); edge only provides the hook — all replication
    /// policy is resolved by persist's `namespace::projection_for`.
    self_provider: Option<CohortProvider>,
    config: BridgeConfig,
    /// v2 operational-data admission providers. `None` = v2 admission
    /// fail-closed; operational kinds' `apply_*` returns `false` without
    /// touching persist. Set via [`Self::with_operational`] or
    /// [`Self::with_config_and_operational`].
    operational: Option<OperationalProviders>,
    /// CIRISEdge#386 — this node's OWN federation key_id: the `user` half of
    /// the trust-root walk ("does the recipient's capability root to a root
    /// *I* trust?"). `None` fail-closes the trace serve gate — without a local
    /// identity there is no "I" whose trust could be evaluated. Supplied by
    /// `ReplicationRuntimeConfig::local_key_id`.
    local_key_id: Option<String>,
    /// CIRISEdge#400 — memoized consent send-set (`list_consent_peers(local)`),
    /// with the [`Instant`] it was resolved. The item-1 fan-out bound must
    /// re-resolve *per round* but NOT *per envelope*: v14.2.0 called
    /// `resolve_attestation_recipient` inside `fetch_envelope_bytes_for_peer`,
    /// so an N-envelope Deliver did N `list_consent_peers` reads inside the
    /// unbounded reply assembly and blew the 10 s round budget (100% round
    /// timeouts). This memo collapses a round's advertise + N fetches to ONE
    /// read; the [`CONSENT_SEND_SET_MEMO_TTL`] window sits under the anti-entropy
    /// cadence so a between-round withdraw still takes effect next round.
    consent_memo: Mutex<Option<(ResolvedPeerSet, Instant)>>,
    /// CIRISEdge#433 — the live metrics handle backing the WITHHOLD LEDGER + the
    /// replication-plane served counter. `None` makes every increment a no-op, so
    /// the (extensive) test constructions below stay untouched; every PRODUCTION
    /// construction site threads `Edge`'s handle in via [`Self::with_metrics`].
    metrics: Option<crate::observability::EdgeMetrics>,
    /// Bumped once per ADMITTED envelope so waiters wake on convergence
    /// instead of on a poll boundary. `None` makes every bump a no-op.
    convergence: Option<std::sync::Arc<super::convergence::ConvergenceSignal>>,
    /// CIRISEdge#430 — observer called with the revoked `key_id` after an
    /// ADMITTED Revocation apply. The transit gate's event-driven cache
    /// invalidation rides this (an in-band un-trust must drop cached hop
    /// verdicts before any TTL would); the bridge knows nothing about who
    /// listens. `None` ⇒ no listener (tests, non-A/V deployments).
    revocation_observer: Option<RevocationObserver>,
    /// CIRISEdge#440 — the resolved mesh-config read seam. `Some` lets a root's
    /// TTL'd relief shrink the since-page limit
    /// ([`Self::effective_page_limit`]) and pause the `trace:*` plane
    /// (`feature.trace_replication=0` ⇒ the advertise sweep + direct-fetch twin
    /// withhold, booking [`crate::observability::WithholdReason::ConfigPaused`]).
    /// `None` — every test construction and any host without a `local_key_id` —
    /// is byte-identical pre-#440 behavior (relief, not a gate).
    mesh_config: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    /// Workstream F — the `accord:*` RELAY predicate
    /// ([`AccordRelayGate`](crate::replication::accord_relay_gate::AccordRelayGate),
    /// persist v36.2.0 `may_relay_accord_object`). `accord:*` projects `Global`
    /// — correct for CARRIAGE, since a partial quorum object must be holdable
    /// across a cohort span nobody knows at emit time — but Global is wrong as
    /// REACH: CC 4.2.1 says a node that never trusted the accord *"is simply not
    /// reached"*. This gate is what narrows carriage back to that set.
    ///
    /// `Some` ENFORCES, fail-closed, on the advertise sweep and its direct-fetch
    /// twin. `None` leaves `accord:*` carriage exactly as it was before this
    /// workstream (the projection row alone), so installing it stays a
    /// deliberate fleet-floor wiring event (the AV-42 `RequireTransportBinding`
    /// shape) rather than something a bridge defaults itself into. That absence
    /// is a WIRING state, visible at construction; every per-object decision the
    /// installed gate makes is fail-closed.
    ///
    /// CIRISPersist#731 — the gate no longer carries a nominated root. Which
    /// accord an object belongs to is read from that object's signature-covered
    /// bytes, so this is an ON/OFF choice, never a choice of which accord to
    /// believe in.
    accord_relay_gate: Option<Arc<crate::replication::accord_relay_gate::AccordRelayGate>>,
    /// CIRISEdge#523 — the resolved owner-binding memo backing the Cohort-scoped
    /// advertise widening (`node_key_id → owner`). See [`OwnerCache`].
    owner_cache: Mutex<OwnerCache>,
    /// CIRISEdge#523 — how many times the bridge actually asked persist's
    /// `owner_of` (i.e. the memo MISSED). The cache's own witness: the advertise
    /// path runs per round per plane, so "three planes in one round cost ONE
    /// directory walk per cohort member" is a claim that has to be checkable
    /// rather than asserted. `Relaxed` — a counter nobody orders against.
    owner_reads: std::sync::atomic::AtomicUsize,
    /// CIRISEdge#524 — how many times the bridge asked persist's
    /// `nodes_owned_by` for a consent grant subject (i.e. the send-set memo
    /// MISSED and the owner-binding walk ran). The same "the claim has to be
    /// checkable" discipline as [`Self::owner_reads`]: this walk is the more
    /// expensive of the two, and "one round's advertise + N fetches pay for it
    /// ONCE" is exactly the CIRISEdge#400 property that must not silently
    /// regress. `Relaxed`.
    owner_route_walks: std::sync::atomic::AtomicUsize,
    /// CIRISEdge#524 — how many peers were minted as recipients by the
    /// OWNER-BINDING axis rather than by a grant naming them: the routing half
    /// of #524 actually firing. Stays zero on a fleet whose grants all name
    /// nodes. `Relaxed`.
    owner_routed_recipients: std::sync::atomic::AtomicUsize,
    /// CIRISEdge#531 — the node-wide bound on SIMULTANEOUS bulk sweeps. Built
    /// from [`BridgeConfig::advertise_sweep_permits`]. Lives on the bridge
    /// rather than on `BridgeConfig` so the config stays `Copy`, and because
    /// the ONE production bridge is shared by every coordinator (initiators,
    /// the #312 responder factory, hot-adds) — so one gate here IS the
    /// node-wide bound, with no separate registry to keep in sync.
    sweep_gate: SweepGate,
    /// CIRISEdge#531 DEPTH — the per-`(peer, plane)` advertise watermarks. See
    /// [`SweepCursors`] / [`PlaneWatermark`]. On the bridge for the same reason
    /// [`Self::sweep_gate`] is: the ONE production bridge is shared by every
    /// coordinator, so a peer's position is the same fact whichever task
    /// observes it — an initiator sweep and the #312 responder sweep for the
    /// same `(peer, kind)` share one cursor and therefore cannot re-offer the
    /// same page twice per round.
    ///
    /// `std::sync::Mutex`, never held across an `.await`: the lock is taken to
    /// read a cursor, dropped, the page is read, then taken again to record it.
    sweep_cursors: Mutex<SweepCursors>,
    /// CIRISEdge#552 — hashes learned without their bodies, and who advertised
    /// them. In-memory: CIRISPersist#785 is where this becomes durable, and the
    /// advertise re-sweep re-learns anything lost to a restart.
    known_hashes: Mutex<crate::replication::known_hashes::KnownHashes>,
    /// Per-requesting-peer budget on IDENTIFIER lookups (FSD_RATE_LIMIT §5.4).
    ///
    /// Option 1 concentrates bodies at conferred servers, so a conferred
    /// responder answering by name is the one place bulk harvesting is
    /// possible — one named subject at a time. That bound is nominal until
    /// something enforces it: without this, an attributed peer can walk a list
    /// of fedIDs as fast as it can send.
    ///
    /// Friction on a public plane, not confidentiality (CC 1.13.3.1).
    lookup_limiter: Mutex<crate::rate_limit::RateLimiter>,
    /// ROLE_MATRIX Axis 3 — this node's own serving tier, cached (sync reads
    /// on the apply loop, async refresh once per TTL). Fail-closed: reads
    /// `None` until first resolution.
    serve_tier: crate::replication::serve_tier::CachedServeTier,
    /// The resolver behind the cache; `None` in fixtures that pin the tier.
    serve_tier_resolver:
        Option<std::sync::Arc<dyn crate::replication::serve_tier::ServeTierResolver>>,
    /// CIRISEdge#541 — the subject whose tier is resolved: the identity peers
    /// REGISTERED and conferred against. Distinct from `local_key_id`, which is
    /// the E3 truster and the own-record Pull subject. `None` falls back to
    /// `local_key_id`, correct wherever the two coincide.
    serve_tier_subject: Option<String>,
    /// CIRISEdge#552 (B) — signers a transient refusal named that this node may
    /// not hold. Bounded: a peer that offers unadmittable rows must not be able
    /// to grow this without limit, so past the cap new names are DROPPED rather
    /// than evicting older ones — the older names are the ones with rows already
    /// waiting on them.
    missing_signers: Mutex<std::collections::BTreeMap<String, Option<String>>>,
    /// Source accounting for `missing_signers`, maintained incrementally.
    ///
    /// FOURTH appearance of the O(cap)-per-rejection class: this map rebuilt a
    /// source-count HashMap on every note once full, so a peer sending
    /// unverifiable rows bought a full scan and allocation per rejected signer.
    /// The shared [`crate::rate_limit::SourceLedger`] exists so the fix is
    /// imported rather than re-derived a fifth time.
    missing_signer_sources: Mutex<crate::rate_limit::SourceLedger>,
    /// CIRISEdge#531 DEPTH — the largest row count ANY single page read has
    /// returned on this bridge. The flat bound's own witness, in the same
    /// discipline as [`Self::sweep_gate`]'s `max_in_flight` and
    /// [`Self::owner_reads`]: "one sweep materialises at most one page" is a
    /// claim, and a claim about memory that no test can observe is the kind
    /// that silently stops being true. A value above the configured budget
    /// means a bulk read was wired past the page driver. `SeqCst` because it
    /// exists to be asserted on.
    sweep_max_page_rows: std::sync::atomic::AtomicUsize,
    /// CIRISEdge#544 — the node-wide refusal memory: which `(plane, content
    /// hash)` this node has already refused, and until when it should stop
    /// ASKING for it. Populated at the apply choke
    /// ([`Self::apply_envelope_bytes`]), read by the round's want-diff through
    /// [`ReplicationDirectory::retry_suppressed`].
    ///
    /// On the bridge for the same reason [`Self::sweep_cursors`] is: the ONE
    /// production bridge backs every per-peer provider AND the single shared
    /// applier, so a refusal learned from one peer's Deliver removes the row
    /// from every peer's next `want`. A per-session memory would re-learn the
    /// same verdict once per peer and keep paying for it once per peer, which is
    /// the amplification the issue measured.
    refusal_backoff: RefusalBackoff,
    /// CIRISEdge#544 — how many wanted hashes the backoff has actually removed
    /// from a round's `want`. The memory's own witness, in the discipline of
    /// [`Self::owner_reads`] and [`Self::sweep_max_page_rows`]: "the retry storm
    /// stopped" is a claim, and a claim about traffic that did NOT happen is
    /// exactly the kind nothing else can observe. `Relaxed` — a counter nobody
    /// orders against.
    retry_suppressions: std::sync::atomic::AtomicUsize,
}

/// CIRISEdge#523 — one memoized owner-binding resolution for one node.
#[derive(Debug, Clone)]
struct CachedOwner {
    /// `Some(owner)` = persist resolved a single live owner-binding; `None` =
    /// the node is provably unowned (persist's `Ok(None)`). A FAILED resolution
    /// (read error / [`ciris_persist::federation::Error::AmbiguousNodeOwner`])
    /// is NEVER stored: caching a failure would pin a plane dark across the
    /// event that fixes it, and the fallback is already the safe direction.
    owner: Option<String>,
    resolved_at: Instant,
}

/// CIRISEdge#523 — the pure, directory-free owner memo. Split out from the
/// bridge (the [`crate::transport::realtime_av_alm::transit_gate`] `VerdictCache`
/// shape) so the freshness + invalidation rules are unit-testable without a
/// federation fixture; the resolution correctness itself is persist's.
#[derive(Debug, Default)]
struct OwnerCache {
    by_node: HashMap<String, CachedOwner>,
}

impl OwnerCache {
    /// The memoized answer for `node` iff the entry is still fresh. `None` is
    /// "no usable entry — go resolve"; it is deliberately a DIFFERENT value from
    /// `Some(OwnerLookup::Unowned)`, because collapsing "unowned" into "unknown"
    /// is the #425 absent-vs-empty class of bug. The storage stays two-valued
    /// ([`CachedOwner::owner`]), so [`OwnerLookup::Unresolved`] is unrepresentable
    /// here by construction — a failed resolution is never cached.
    fn get_fresh(&self, node: &str, now: Instant) -> Option<OwnerLookup> {
        let entry = self.by_node.get(node)?;
        (now.duration_since(entry.resolved_at) < OWNER_BINDING_MEMO_TTL).then(|| {
            entry
                .owner
                .clone()
                .map_or(OwnerLookup::Unowned, OwnerLookup::Owner)
        })
    }

    fn put(&mut self, node: &str, owner: Option<String>, now: Instant) {
        self.by_node.insert(
            node.to_string(),
            CachedOwner {
                owner,
                resolved_at: now,
            },
        );
    }

    /// Drop every entry a change naming `key_id` could falsify: the node whose
    /// binding it is, and any node whose memoized OWNER is `key_id` (a revoked
    /// owner key stops conferring membership on the nodes it owns). Event-driven
    /// from the apply path; [`OWNER_BINDING_MEMO_TTL`] is the backstop.
    fn invalidate(&mut self, key_id: &str) {
        self.by_node
            .retain(|node, e| node != key_id && e.owner.as_deref() != Some(key_id));
    }
}

/// CIRISEdge#523 — the outcome of one owner resolution, kept as three values
/// rather than `Option<String>` so "unowned" can never be read as "we could not
/// tell". Only [`Self::Unresolved`] changes the gate's behaviour (it narrows to
/// the pre-#523 direct-key test); the other two are answers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OwnerLookup {
    /// A single live owner-binding names this user as the node's owner.
    Owner(String),
    /// The node carries no live owner-binding (persist's `Ok(None)`).
    Unowned,
    /// The resolution FAILED — a directory read error, or
    /// `AmbiguousNodeOwner` (a node with two live owners is not a resolvable
    /// membership claim, CIRISConstitution#23 consumer-fail-closed). Never
    /// cached, never widens.
    Unresolved,
}

/// CIRISEdge#430 — the revoked-key listener installed via
/// [`FederationDirectoryReplicationBridge::with_revocation_observer`]: called
/// with the revoked `key_id` after each ADMITTED Revocation apply.
pub type RevocationObserver = Arc<dyn Fn(&str) + Send + Sync>;

/// CIRISEdge#400 — how long a memoized consent send-set stays fresh. Chosen to
/// span one anti-entropy round's assembly steps (advertise → Diff → Deliver,
/// bounded by the scheduler's 10 s round budget) while staying well under the
/// default 30 s cadence, so the item-1 bound still re-resolves every round.
const CONSENT_SEND_SET_MEMO_TTL: Duration = Duration::from_secs(10);

/// CIRISEdge#523 — how long a resolved owner-binding stays fresh.
///
/// Sized at the default anti-entropy cadence, so the widened cohort is resolved
/// about ONCE PER ROUND per cohort member and shared by all three Cohort-scoped
/// planes in that round (the #430 "resolve once, cache, invalidate" discipline;
/// this walk is persist's, and edge must not pay for it three times a round).
///
/// The TTL is a BACKSTOP, not the mechanism: `apply` invalidates on an admitted
/// owner-binding, on an admitted `withdraws`/`recants` naming the node, and on
/// an admitted `Revocation` naming either side. It is nonetheless LOAD-BEARING
/// for the two liveness clauses no apply event announces — a `delegates_to`
/// whose `expires_at` passes, and a CC 3.4.12 `valid_until` that lapses — both
/// of which are time-driven, so a TTL is the only thing that can observe them.
const OWNER_BINDING_MEMO_TTL: Duration = Duration::from_secs(30);

impl FederationDirectoryReplicationBridge {
    /// Construct with default [`BridgeConfig`], **v1-only** (no v2
    /// operational-kind admission). For v2 operational admission, use
    /// [`Self::with_operational`].
    pub fn new(directory: Arc<dyn FederationDirectory>, cohort: CohortProvider) -> Self {
        Self::with_config(directory, cohort, BridgeConfig::default())
    }

    /// Construct with explicit configuration, **v1-only**.
    pub fn with_config(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        config: BridgeConfig,
    ) -> Self {
        Self {
            directory,
            cohort,
            self_provider: None,
            local_key_id: None,
            config,
            operational: None,
            consent_memo: Mutex::new(None),
            metrics: None,
            convergence: None,
            revocation_observer: None,
            mesh_config: None,
            accord_relay_gate: None,
            owner_cache: Mutex::new(OwnerCache::default()),
            owner_reads: std::sync::atomic::AtomicUsize::new(0),
            owner_route_walks: std::sync::atomic::AtomicUsize::new(0),
            owner_routed_recipients: std::sync::atomic::AtomicUsize::new(0),
            sweep_gate: SweepGate::new(config.advertise_sweep_permits),
            known_hashes: Mutex::new(crate::replication::known_hashes::KnownHashes::new()),
            lookup_limiter: Mutex::new(crate::rate_limit::RateLimiter::new(
                crate::rate_limit::Policy::quota(
                    Self::IDENTIFIER_LOOKUPS_PER_WINDOW,
                    Self::IDENTIFIER_LOOKUP_WINDOW_SECS,
                    Self::IDENTIFIER_LOOKUP_MAX_PEERS,
                )
                .with_long_windows([
                    Some(crate::rate_limit::Quota::new(
                        Self::IDENTIFIER_LOOKUPS_PER_HOUR,
                        3_600,
                    )),
                    Some(crate::rate_limit::Quota::new(
                        Self::IDENTIFIER_LOOKUPS_PER_DAY,
                        86_400,
                    )),
                ]),
            )),
            serve_tier: crate::replication::serve_tier::CachedServeTier::new(),
            serve_tier_resolver: None,
            serve_tier_subject: None,
            missing_signers: Mutex::new(std::collections::BTreeMap::new()),
            missing_signer_sources: Mutex::new(crate::rate_limit::SourceLedger::new()),
            sweep_cursors: Mutex::new(SweepCursors::default()),
            sweep_max_page_rows: std::sync::atomic::AtomicUsize::new(0),
            // CIRISEdge#544 — always on. It is a rate limiter on asking for what
            // this node just refused, not a policy, so there is no configuration
            // in which asking flat-out is the right answer.
            refusal_backoff: RefusalBackoff::new(),
            retry_suppressions: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Construct with default [`BridgeConfig`] **+ v2 operational
    /// admission enabled**. The operational providers (key_directory /
    /// root_stewards / steward_roster) are required for the bridge to
    /// admit `organization` / `org_membership` / `partner_record`
    /// envelopes; without them, the operational-kind `apply_*` returns
    /// `false` (fail-closed; v1 kinds remain unaffected).
    pub fn with_operational(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        operational: OperationalProviders,
    ) -> Self {
        Self::with_config_and_operational(directory, cohort, BridgeConfig::default(), operational)
    }

    /// Construct with explicit configuration **+ v2 operational
    /// admission enabled**.
    pub fn with_config_and_operational(
        directory: Arc<dyn FederationDirectory>,
        cohort: CohortProvider,
        config: BridgeConfig,
        operational: OperationalProviders,
    ) -> Self {
        Self {
            directory,
            cohort,
            self_provider: None,
            local_key_id: None,
            config,
            operational: Some(operational),
            consent_memo: Mutex::new(None),
            metrics: None,
            convergence: None,
            revocation_observer: None,
            mesh_config: None,
            accord_relay_gate: None,
            owner_cache: Mutex::new(OwnerCache::default()),
            owner_reads: std::sync::atomic::AtomicUsize::new(0),
            owner_route_walks: std::sync::atomic::AtomicUsize::new(0),
            owner_routed_recipients: std::sync::atomic::AtomicUsize::new(0),
            sweep_gate: SweepGate::new(config.advertise_sweep_permits),
            known_hashes: Mutex::new(crate::replication::known_hashes::KnownHashes::new()),
            lookup_limiter: Mutex::new(crate::rate_limit::RateLimiter::new(
                crate::rate_limit::Policy::quota(
                    Self::IDENTIFIER_LOOKUPS_PER_WINDOW,
                    Self::IDENTIFIER_LOOKUP_WINDOW_SECS,
                    Self::IDENTIFIER_LOOKUP_MAX_PEERS,
                )
                .with_long_windows([
                    Some(crate::rate_limit::Quota::new(
                        Self::IDENTIFIER_LOOKUPS_PER_HOUR,
                        3_600,
                    )),
                    Some(crate::rate_limit::Quota::new(
                        Self::IDENTIFIER_LOOKUPS_PER_DAY,
                        86_400,
                    )),
                ]),
            )),
            serve_tier: crate::replication::serve_tier::CachedServeTier::new(),
            serve_tier_resolver: None,
            serve_tier_subject: None,
            missing_signers: Mutex::new(std::collections::BTreeMap::new()),
            missing_signer_sources: Mutex::new(crate::rate_limit::SourceLedger::new()),
            sweep_cursors: Mutex::new(SweepCursors::default()),
            sweep_max_page_rows: std::sync::atomic::AtomicUsize::new(0),
            // CIRISEdge#544 — always on. It is a rate limiter on asking for what
            // this node just refused, not a policy, so there is no configuration
            // in which asking flat-out is the right answer.
            refusal_backoff: RefusalBackoff::new(),
            retry_suppressions: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// CIRISEdge#311 — install the SELF-plane publish set (collapses the #257
    /// `with_key_selector` + #305 `with_occurrence_selector` into one). When
    /// set, the unified engine advertises the key_ids THIS callback yields
    /// across every `Projection::SelfOwn` kind (`KeyRecord`,
    /// `IdentityOccurrence`, `TransportDestination`) — the KERI publish-own
    /// model: the controller publishes its own establishment record + KEX
    /// occurrence + reachability; verifiers pull-and-verify. `None` restores
    /// the pre-#257/#305 cohort projection. The server computes the
    /// own+anchored set (it holds the anchor knowledge); edge only provides the
    /// hook — projection itself is resolved by persist's `projection_for`.
    #[must_use]
    pub fn with_self_provider(mut self, selector: Option<CohortProvider>) -> Self {
        self.self_provider = selector;
        self
    }

    /// CIRISEdge#386 — bind this node's own federation key_id (builder). The
    /// `user` half of the trust-root walk that gates `trace:*` serving; without
    /// it the gate fail-closes and logs a WARN, since a missing local identity
    /// is a wiring fault rather than a policy decision.
    #[must_use]
    pub fn with_local_key_id(mut self, local_key_id: Option<String>) -> Self {
        self.local_key_id = local_key_id;
        self
    }

    /// How many signer recoveries are queued (diagnostics + tests).
    #[must_use]
    pub fn tracked_missing_signers(&self) -> usize {
        self.missing_signers.lock().map_or(0, |m| m.len())
    }

    /// ROLE_MATRIX Axis 3 — install the serve-tier resolver (builder).
    /// Production wiring passes [`DirectoryServeTierResolver`]; fixtures pin
    /// the tier with [`Self::with_serve_tier_for_test`] instead.
    ///
    /// [`DirectoryServeTierResolver`]:
    ///     crate::replication::serve_tier::DirectoryServeTierResolver
    #[must_use]
    pub fn with_serve_tier_resolver(
        mut self,
        resolver: Option<std::sync::Arc<dyn crate::replication::serve_tier::ServeTierResolver>>,
    ) -> Self {
        self.serve_tier_resolver = resolver;
        self
    }

    /// CIRISEdge#541 — the subject whose serving tier is resolved (builder).
    ///
    /// The ADVERTISED identity: a conferral is granted against the identity
    /// peers registered, which under `use_node_identity` is the node rather
    /// than the actor. `None` falls back to `local_key_id`.
    #[must_use]
    pub fn with_serve_tier_subject(mut self, subject: Option<String>) -> Self {
        self.serve_tier_subject = subject;
        self
    }

    /// Pin the serving tier (builder, TEST ONLY). With no resolver installed
    /// the pinned value is never overwritten, so a fixture can exercise every
    /// tier without a directory that can resolve one.
    #[cfg(test)]
    #[must_use]
    pub fn with_serve_tier_for_test(self, tier: crate::replication::serve_tier::ServeTier) -> Self {
        self.serve_tier.store(tier);
        self
    }

    /// How many known hashes are recorded (tests + diagnostics).
    #[cfg(test)]
    #[must_use]
    pub fn known_hash_count_for_test(&self) -> usize {
        self.known_hashes.lock().map_or(0, |k| k.len())
    }

    /// The trace-plane serve gate, exposed for the ROLE_MATRIX gauntlet (R9).
    #[cfg(test)]
    pub async fn peer_has_serve_capability_for_test(&self, peer_key_id: &str) -> bool {
        self.peer_has_serve_capability(peer_key_id).await
    }

    /// This node's serving tier, as last resolved (sync — the apply loop reads
    /// this; async paths call [`Self::refresh_serve_tier`] first).
    #[must_use]
    pub fn serve_tier(&self) -> crate::replication::serve_tier::ServeTier {
        self.serve_tier.read()
    }

    /// Re-resolve the tier if stale. Called from the async read paths that run
    /// once per round, so the sync readers are at most [`CachedServeTier::TTL`]
    /// behind the directory.
    ///
    /// [`CachedServeTier::TTL`]: crate::replication::serve_tier::CachedServeTier::TTL
    async fn refresh_serve_tier(&self) {
        // The ADVERTISED identity, not the actor. Building the resolver with the
        // right subject and then refreshing against the wrong one leaves the fix
        // half-applied: a blessed node still resolves as its actor.
        if let (Some(resolver), Some(subject)) = (
            self.serve_tier_resolver.as_deref(),
            self.serve_tier_subject
                .as_deref()
                .or(self.local_key_id.as_deref()),
        ) {
            self.serve_tier.refresh_if_stale(resolver, subject).await;
        }
    }

    /// CIRISEdge#433 — install the live metrics handle (builder), enabling the
    /// withhold ledger + the replication-plane served counter.
    /// [`crate::observability::EdgeMetrics`] is `Clone` and `Arc`-backed, so the
    /// bridge shares the SAME counters the rest of the edge writes.
    ///
    /// Takes an `Option` to match its two sibling builders
    /// ([`Self::with_self_provider`] / [`Self::with_local_key_id`]), which both
    /// carry an operator-supplied `Option` straight through from
    /// `ReplicationRuntimeConfig`. `None` makes every increment a no-op.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<crate::observability::EdgeMetrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Install the node's convergence signal. Every ADMITTED envelope bumps it,
    /// which is what lets a caller await a row's arrival instead of polling for
    /// it (see [`super::convergence`]).
    #[must_use]
    pub fn with_convergence(
        mut self,
        convergence: Option<std::sync::Arc<super::convergence::ConvergenceSignal>>,
    ) -> Self {
        self.convergence = convergence;
        self
    }

    /// CIRISEdge#430 — install the revoked-key observer (called with the revoked
    /// `key_id` after an ADMITTED Revocation apply). The transit gate's
    /// `TransitGate::invalidate`
    /// is the intended listener; the TTL remains the backstop when no observer
    /// is wired.
    #[must_use]
    pub fn with_revocation_observer(mut self, observer: Option<RevocationObserver>) -> Self {
        self.revocation_observer = observer;
        self
    }

    /// CIRISEdge#440 — install the resolved mesh-config reader (builder). An
    /// `Option` like its siblings: the runtime threads `Some` only when it has
    /// a `local_key_id` to fold for; `None` keeps every consumer on its exact
    /// pre-#440 path.
    #[must_use]
    pub fn with_mesh_config(
        mut self,
        reader: Option<Arc<crate::replication::mesh_config::MeshConfigReader>>,
    ) -> Self {
        self.mesh_config = reader;
        self
    }

    /// Workstream F — install the `accord:*` relay gate (builder). See the
    /// [`Self::accord_relay_gate`] field doc for why it is an `Option` and why
    /// installing it is a deliberate wiring event. Post-CIRISPersist#731 the
    /// gate takes no root: CC 4.2.3 still makes the accord an instance
    /// parameter (*"another instantiation of this form names its own three"*),
    /// but it is the OBJECT that names its instance, not the host.
    #[must_use]
    pub fn with_accord_relay_gate(
        mut self,
        gate: Option<Arc<crate::replication::accord_relay_gate::AccordRelayGate>>,
    ) -> Self {
        self.accord_relay_gate = gate;
        self
    }

    /// Workstream F / CIRISEdge#505 / CIRISPersist#743 — is this row on the
    /// `accord:*` family, in EITHER namespace, i.e. is its carriage the relay
    /// gate's to decide?
    ///
    /// **The two-namespace rule.** The family rides BOTH namespaces a row can
    /// carry it on, and persist's admission comment
    /// (`check_reserved_prefix_admission`, the CIRISPersist#733 placement note)
    /// is explicit: *"The `accord:*` family rides BOTH namespaces —
    /// `accord:invoke:*` as a TYPE, `accord:human_dignity:v1` as a `scores`
    /// DIMENSION"*. So this pre-filter reads the exact two fields persist's own
    /// admission reads — the `attestation_type` column
    /// (`/attestation_type`, persist's `row.attestation_type`) and the signed
    /// envelope dimension (`/attestation_envelope/dimension`, persist's
    /// `admission::envelope_dimension`) — and hands both to persist's own
    /// classifier, [`ciris_persist::federation::trust_root::is_accord_family`].
    /// `objection:*` is deliberately NOT in this family (CIRISPersist#713 —
    /// the co-scrub argument covers `accord:` only).
    ///
    /// This read only the `dimension` until v37.1.0, and that was a live
    /// under-gating hole: every `accord:invoke:*` row carried in the
    /// `attestation_type` namespace skipped the CC 4.2.1 relay gate entirely —
    /// advertised, fetched and subject-pulled with no carriage check. A false
    /// NEGATIVE: the gate never carried something it should have refused once
    /// it looked, it failed to look.
    ///
    /// Persist now owns the question (`is_accord_family`), so edge stops
    /// spelling it. Edge widening the pre-filter itself would have put a
    /// second reading of *"is this the accord family"* in this repo — the
    /// exact drift CIRISPersist#731 and #733 spent two releases removing, and
    /// it would re-break the moment a third namespace arm appears.
    fn attestation_is_accord(canonical_json: &serde_json::Value) -> bool {
        ciris_persist::federation::trust_root::is_accord_family(
            canonical_json
                .pointer("/attestation_type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(""),
            canonical_json
                .pointer("/attestation_envelope/dimension")
                .and_then(serde_json::Value::as_str),
        )
    }

    /// Workstream F — does the relay gate WITHHOLD this row? `false` when no
    /// gate is installed, when the row is not `accord:*`, or when the gate
    /// allows.
    ///
    /// Shape (the CIRISEdge#430 pattern): resolve ASYNC, cache-first
    /// (`prime` — a hit is one lock and no directory read, so a round's N
    /// per-envelope gates share ONE trust walk, which is what keeps the
    /// CIRISEdge#400 per-envelope-read regression from coming back), then gate
    /// on the PURE SYNC predicate (`decide`). No lock is held across the await
    /// and no `tokio::time` is touched — CIRISEdge#217, on a path that can run
    /// on persist's runtime thread.
    ///
    /// Every refusal is LOUD (CIRISEdge#425): its own
    /// [`crate::observability::WithholdReason`] booked at the DECIDING branch
    /// — cannot-judge, not-seated, no-edge and unresolved are four different
    /// operator findings and are never folded — plus the throttled serve-gate
    /// WARN, on the same throttle every other withheld plane uses. Never a
    /// silent `continue`.
    async fn accord_relay_withholds(
        &self,
        canonical_json: &serde_json::Value,
        peer_label: &str,
        site: &str,
    ) -> bool {
        use crate::observability::WithholdReason;
        use crate::replication::accord_relay_gate::RelayRefusal;
        let Some(gate) = self.accord_relay_gate.as_ref() else {
            return false;
        };
        if !Self::attestation_is_accord(canonical_json) {
            return false;
        }
        let now = std::time::Instant::now();
        // CIRISPersist#733 — the gate hands the ROW to persist's taking verb
        // (`may_relay_accord_attestation`), which reads the accord and the signer
        // out of it. Nothing on this path nominates a root, and edge parses none
        // of it, so an object belonging to another accord can no longer be waved
        // through on a roster that happens to seat its signer.
        //
        // The `&serde_json::Value` plumbing is deliberate. Two of the three call
        // sites (advertise, subject-Pull) hold a typed `Attestation` and could
        // pass it, but the DIRECT-FETCH site serves arbitrary stored bytes — a
        // KeyRecord, a Family, an attestation — and can only ever hold a `Value`.
        // Keeping one signature puts the deserialize-failure handling in exactly
        // ONE place, so all three sites withhold identically by construction;
        // plumbing the typed row would need a second, site-local failure branch
        // that only the fetch path could reach, which is two behaviours. The
        // `attestation_is_accord` early-out above bounds the cost: the
        // deserialize runs only for rows persist's own classifier calls
        // `accord:*`, and never for the non-attestations the fetch path carries.
        let Some(refusal) = gate
            .may_relay_attestation(canonical_json, now)
            .await
            .refusal()
        else {
            return false;
        };
        let reason = match refusal {
            RelayRefusal::RosterUnresolvable => WithholdReason::AccordRelayRosterUnresolvable,
            RelayRefusal::SignerNotSeated => WithholdReason::AccordRelaySignerNotSeated,
            RelayRefusal::NoTrustEdge => WithholdReason::AccordRelayNoTrustEdge,
            // A wiring fault shares the ONE condition + ONE remedy the
            // established `LocalIdentityMissing` variant names (wire
            // `ReplicationRuntimeConfig::local_key_id`); the `detail` names
            // this site.
            RelayRefusal::NoLocalIdentity => WithholdReason::LocalIdentityMissing,
            RelayRefusal::Unresolved => WithholdReason::AccordRelayUnresolved,
            // #733 — the FIVE object-shaped refusals, each its own ledger line.
            // persist's relay verb collapses every one of them into
            // `roster_resolvable: false`; edge does not, because they are five
            // different things to go fix (fix the producer's serializer; re-mint
            // a pre-#643 row or investigate a rewriting relay; a classifier
            // disagreement; add the `accord_root` key; remove one of two). The
            // gate derives them from persist's OWN `check_row_column_binding` +
            // `accord_root_claim`, so naming them costs no second rule.
            RelayRefusal::ObjectUnreadable => WithholdReason::AccordRelayObjectUnreadable,
            RelayRefusal::MirrorUnbound => WithholdReason::AccordRelayMirrorUnbound,
            RelayRefusal::ObjectNotAccord => WithholdReason::AccordRelayObjectNotAccord,
            RelayRefusal::ObjectRootUnnamed => WithholdReason::AccordRelayObjectRootUnnamed,
            RelayRefusal::ObjectRootDisagrees => WithholdReason::AccordRelayObjectRootDisagrees,
        };
        self.withhold(reason, peer_label, refusal.as_str());
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            serve_gate_withheld_log().check(&format!("accord-relay:{peer_label}:{refusal}:{site}"))
        {
            let subject =
                crate::replication::accord_relay_gate::AccordRelaySubject::of_attestation(
                    canonical_json,
                )
                .ok();
            tracing::warn!(
                peer = peer_label,
                signer = subject.as_ref().map(|s| s.signer_key_id.as_str()),
                root = subject.as_ref().map(|s| s.root_ref.as_str()),
                refusal = %refusal,
                site,
                suppressed_prev,
                "accord:* row WITHHELD by the relay gate — this node may not carry it \
                 (CC 4.2.1 reach is consent-scoped; `roster_unresolvable` means I CANNOT \
                 JUDGE, which is not `signer_not_seated`; `unresolved` means the verdict \
                 was never resolved rather than refused on its merits; and \
                 `object_root_unnamed` means the row's SIGNED bytes name no accord, so \
                 there is nothing to judge it against — CIRISPersist#731)"
            );
        }
        true
    }

    /// Workstream F — drop cached relay verdicts an ADMITTED apply could have
    /// falsified. The event-driven half of the gate's freshness contract
    /// (CIRISEdge#430's shape): an in-band roster change, seat revocation, or
    /// trust-edge tombstone must take effect before [`RELAY_VERDICT_TTL`](crate::replication::accord_relay_gate::RELAY_VERDICT_TTL)
    /// would expire; the TTL is the backstop if an event is ever missed.
    ///
    /// Deliberately over-broad on the key: any id the applied record NAMES drops
    /// every cached verdict whose ROOT or whose SIGNER is that id (both of
    /// persist's legs are root-relative, so a root drops all its signers).
    /// Choosing invalidation keys is a cache concern, never a trust rule —
    /// over-eager costs a re-resolve, too-narrow caches a verdict past the event
    /// that falsified it.
    fn invalidate_accord_relay(&self, key_ids: &[&str]) {
        let Some(gate) = self.accord_relay_gate.as_ref() else {
            return;
        };
        for k in key_ids {
            gate.invalidate(k);
        }
    }

    /// CIRISEdge#440 — the since-page limit this sweep runs under:
    /// the configured [`BridgeConfig::operational_page_limit`], shrunk to a
    /// live `antientropy.page_limit` relief when one is resolved. `min`, never
    /// replacement — relief can only shrink a page (relieve-never-expand,
    /// enforced again here against the configured value in case the operator's
    /// limit is already tighter than the relieved one). One cached read per
    /// round-ish window (the reader's TTL), not per row.
    async fn effective_page_limit(&self) -> u32 {
        match &self.mesh_config {
            None => self.config.operational_page_limit,
            Some(reader) => reader
                .relief()
                .await
                .page_limit
                .map_or(self.config.operational_page_limit, |relieved| {
                    relieved.min(self.config.operational_page_limit)
                }),
        }
    }

    /// CIRISEdge#531 DEPTH — the row budget ONE sweep page may materialise.
    ///
    /// `min` of the operator's reach bound ([`Self::effective_page_limit`],
    /// which a mesh-config relief can shrink further) and the materialisation
    /// bound ([`BridgeConfig::sweep_page_rows`]). Never zero: a zero budget
    /// would make a [`SweepWindow::Full`] drain read empty pages forever, so
    /// the floor is one row — a pathological config costs rounds, never a spin.
    async fn sweep_page_budget(&self) -> u32 {
        let limit = self.effective_page_limit().await;
        match self.config.sweep_page_rows {
            // 0 = paging disabled (the documented escape hatch): one page IS
            // the operator's whole reach bound, i.e. the pre-DEPTH read.
            0 => limit,
            rows => rows.min(limit),
        }
        .max(1)
    }

    /// CIRISEdge#531 DEPTH — the watermark key for this sweep, or `None` for a
    /// [`SweepWindow::Full`] drain (which has no peer and keeps no position).
    fn watermark_key(
        window: SweepWindow<'_>,
        kind: EnvelopeKind,
    ) -> Option<(String, EnvelopeKind)> {
        match window {
            SweepWindow::Full => None,
            SweepWindow::Watermark(peer) => Some((peer.to_owned(), kind)),
        }
    }

    /// CIRISEdge#531 DEPTH — this round's NEW-ROWS `since` for `key`.
    fn sweep_head(&self, key: &(String, EnvelopeKind)) -> Option<ResumeCursor> {
        self.sweep_cursors.lock().ok().and_then(|mut c| c.head(key))
    }

    /// CIRISEdge#531 DEPTH — record the new-rows page; get the backfill plan.
    fn sweep_after_head(
        &self,
        key: &(String, EnvelopeKind),
        served: usize,
        budget: u32,
        last: Option<ResumeCursor>,
    ) -> Option<BackfillPage> {
        self.sweep_cursors
            .lock()
            .ok()
            .and_then(|mut c| c.after_head(key, served, budget, last))
    }

    /// CIRISEdge#531 DEPTH — the LATER of two cursor positions, treating
    /// `None` as "from the beginning" (i.e. the earliest possible position).
    ///
    /// Used to combine a peer's watermark with the floor its `CursorPull`
    /// declared: neither may pull the serve position BACKWARD, so the answer is
    /// whichever is further along.
    fn later_cursor(a: Option<ResumeCursor>, b: Option<ResumeCursor>) -> Option<ResumeCursor> {
        match (a, b) {
            (None, x) | (x, None) => x,
            (Some(x), Some(y)) => Some(if x >= y { x } else { y }),
        }
    }

    /// CIRISEdge#531 DEPTH — read ONE accord-evidence page and serialize it
    /// under the byte budget.
    ///
    /// Returns `(bytes, page_len_for_the_cursor, last_SERVED_resume_pair)`.
    ///
    /// The two subtleties, both load-bearing:
    ///
    ///  * the cursor advances to the last bundle actually **served**, never the
    ///    last one read. Everywhere else in this file the watermark tracks the
    ///    READ (policy gates shape the offer, not the position); here the
    ///    truncation is a BUDGET, so advancing past an unserved bundle would
    ///    skip it for a whole re-sweep cycle;
    ///  * the length reported to the cursor machine is the READ length. A page
    ///    cut short by bytes was still a FULL read, and reporting the served
    ///    count would look like "end of plane" and wrap the re-sweep early.
    async fn accord_evidence_page(
        &self,
        since: Option<ResumeCursor>,
        budget: u32,
    ) -> (Vec<Vec<u8>>, usize, Option<ResumeCursor>) {
        let bundles = match self
            .directory
            .list_signed_accord_quorum_evidence_since(since, budget)
            .await
        {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "accord-quorum-evidence cursor serve read failed (CIRISEdge#474)"
                );
                return (Vec::new(), 0, None);
            }
        };
        let read = bundles.len();
        self.record_page(read);
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut bytes_used = 0usize;
        let mut last: Option<ResumeCursor> = None;
        for b in &bundles {
            let encoded = match serde_json::to_vec(b) {
                Ok(bytes) => bytes,
                Err(e) => {
                    // v18 — was a silent `filter_map(.. .ok())` two lines from
                    // the loud read-error arm above: a bundle that will not
                    // serialize is OMITTED from every cursor page and never
                    // replicates from this node. Loud + booked (#433).
                    //
                    // The cursor still advances past it (`last` is stamped
                    // below): a bundle that cannot serialize will not serialize
                    // next round either, and wedging the whole peer's position
                    // behind one poison row would strand every bundle after it.
                    tracing::warn!(
                        error = %e,
                        "accord-quorum-evidence bundle could not be serialized for \
                         the wire — OMITTED from this cursor page; it will not \
                         replicate from this node (CIRISEdge#474/#433)"
                    );
                    self.withhold(
                        crate::observability::WithholdReason::RowNotSerializable,
                        "<unattributed>",
                        "accord_evidence_since: to_vec failed",
                    );
                    last = Some((b.evidence_at, b.proposal.digest()));
                    continue;
                }
            };
            // A single bundle larger than the whole budget still ships, ALONE —
            // a budget must bound the batch, never strand an envelope (the
            // `session::pack_bounded_deliver` rule, applied to the one Deliver
            // path that never had it).
            if !out.is_empty() && bytes_used + encoded.len() > CURSOR_PAGE_BUDGET_BYTES {
                break;
            }
            bytes_used += encoded.len();
            out.push(encoded);
            last = Some((b.evidence_at, b.proposal.digest()));
        }
        if out.len() < read {
            tracing::debug!(
                read,
                served = out.len(),
                bytes_used,
                budget_bytes = CURSOR_PAGE_BUDGET_BYTES,
                "accord-quorum-evidence page cut at the BYTE budget — the remainder \
                 rides the next round from this peer's watermark (CIRISEdge#531)"
            );
        }
        (out, read, last)
    }

    /// CIRISEdge#531 DEPTH — record the backfill page (advance, or wrap).
    fn sweep_after_backfill(
        &self,
        key: &(String, EnvelopeKind),
        served: usize,
        budget: u32,
        last: Option<ResumeCursor>,
    ) {
        if let Ok(mut c) = self.sweep_cursors.lock() {
            c.after_backfill(key, served, budget, last);
        }
    }

    /// CIRISEdge#531 DEPTH — drive one plane's round under `window`, turning
    /// each page into refs and dropping that page's ROWS before the next read.
    ///
    /// This is the whole flat-memory mechanism for the 12 planes whose per-row
    /// projection is pure. The Attestation plane runs the identical page plan
    /// with its own loop, because its per-row gates are `async` and carry
    /// per-sweep memos ([`Self::list_attestations`]).
    ///
    /// ## The permit is per PAGE
    ///
    /// v18.6.0 held one [`SweepGate`] permit across a whole sweep, which was
    /// right when a sweep was one read. Now a `Full` drain is many reads, and
    /// holding one permit across all of them would turn the FIFO-fair gate
    /// into a long queue for every other plane — the starvation the width fix
    /// was careful not to create. So the permit is acquired around exactly one
    /// page's read + projection and released between pages: the bound becomes
    /// `permits × page`, which is both flat AND short-held.
    // Eight parameters, and each is a distinct axis of ONE plane's sweep:
    // which plane, how much of it, how to read a page, how to resume, which
    // rows are in scope, what their `seq` is, and what gets hashed. Bundling
    // them into a struct would just move the same eight behind a name and cost
    // every call site a builder. The alternative — 13 hand-written page loops —
    // is what this exists to prevent.
    #[allow(clippy::too_many_arguments)]
    async fn sweep_paged<S, Read, Fut, T, IN, RS, TS, C>(
        &self,
        kind: EnvelopeKind,
        window: SweepWindow<'_>,
        read: Read,
        resume: RS,
        in_scope: IN,
        seq_of: TS,
        content_of: C,
    ) -> Vec<EnvelopeRef>
    where
        T: serde::Serialize,
        Read: Fn(Option<ResumeCursor>, u32) -> Fut,
        Fut: std::future::Future<Output = Vec<S>>,
        RS: Fn(&S) -> ResumeCursor,
        IN: Fn(&S) -> bool,
        TS: Fn(&S) -> u64,
        C: Fn(&S) -> &T,
    {
        let budget = self.sweep_page_budget().await;
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let Some(key) = Self::watermark_key(window, kind) else {
            // ── FULL drain: page for MEMORY, keep every page's refs. ──
            let mut since: Option<ResumeCursor> = None;
            for page in 0..MAX_FULL_DRAIN_PAGES {
                let (served, last) = {
                    let _permit = self.sweep_gate.enter().await;
                    let rows = read(since.clone(), budget).await;
                    self.record_page(rows.len());
                    self.advertise_page_into(
                        &rows,
                        &in_scope,
                        &seq_of,
                        &content_of,
                        &mut refs,
                        &mut seen,
                    );
                    (rows.len(), rows.last().map(&resume))
                };
                if served < budget as usize {
                    return refs;
                }
                if last.is_none() || last == since {
                    // Cannot advance: a backend returned a FULL page and either
                    // no cursor or the same cursor twice. Stopping is the only
                    // safe move — looping would spin inside a permit — but it
                    // truncates the holdings view, so it never does it quietly.
                    tracing::warn!(
                        kind = ?kind,
                        budget,
                        "holdings drain CANNOT ADVANCE — a full page came back with \
                         no new resume cursor, so this round's holdings view is \
                         truncated and rows past it are re-wanted from peers even \
                         though they are held (CIRISEdge#531)"
                    );
                    break;
                }
                since = last;
                if page + 1 == MAX_FULL_DRAIN_PAGES {
                    tracing::warn!(
                        kind = ?kind,
                        pages = MAX_FULL_DRAIN_PAGES,
                        budget,
                        "holdings drain hit the page CAP — this round's holdings view is \
                         TRUNCATED, so rows past the cap are re-wanted from peers even \
                         though they are held (wasteful, self-correcting). Raise \
                         `sweep_page_rows` or investigate a plane this large \
                         (CIRISEdge#531)"
                    );
                }
            }
            return refs;
        };

        // ── WATERMARK: new rows first, then the rolling re-sweep. ──
        let head = self.sweep_head(&key);
        let (served, last) = {
            let _permit = self.sweep_gate.enter().await;
            let rows = read(head, budget).await;
            self.record_page(rows.len());
            self.advertise_page_into(&rows, &in_scope, &seq_of, &content_of, &mut refs, &mut seen);
            (rows.len(), rows.last().map(&resume))
        };
        if let Some(plan) = self.sweep_after_head(&key, served, budget, last) {
            let (b_served, b_last) = {
                let _permit = self.sweep_gate.enter().await;
                let rows = read(plan.since, plan.budget).await;
                self.record_page(rows.len());
                self.advertise_page_into(
                    &rows,
                    &in_scope,
                    &seq_of,
                    &content_of,
                    &mut refs,
                    &mut seen,
                );
                (rows.len(), rows.last().map(&resume))
            };
            self.sweep_after_backfill(&key, b_served, plan.budget, b_last);
        }
        refs
    }

    /// CIRISEdge#440 — is the `trace:*` plane paused by a live
    /// `feature.trace_replication=0` relief? `false` on every absence path.
    async fn trace_plane_paused(&self) -> bool {
        match &self.mesh_config {
            None => false,
            Some(reader) => reader.relief().await.trace_replication_paused,
        }
    }

    /// CIRISEdge#440 — book ONE `ConfigPaused` withhold + its named, throttled
    /// WARN. Shared by the advertise sweep (booked once per sweep) and the
    /// direct-fetch twin (booked per refused fetch); `site` keeps the two
    /// throttle keys distinct so neither exit can silence the other's log.
    fn withhold_config_paused(&self, peer_label: &str, site: &str) {
        self.withhold(
            crate::observability::WithholdReason::ConfigPaused,
            peer_label,
            "feature.trace_replication=0",
        );
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            serve_gate_withheld_log().check(&format!("{peer_label}:{site}"))
        {
            tracing::warn!(
                peer = peer_label,
                suppressed_prev,
                site,
                "trace plane PAUSED by mesh config — a trust root relieved \
                 `feature.trace_replication` to 0, so `trace:*` rows are withheld \
                 until the relief expires or is superseded (CIRISEdge#440)"
            );
        }
    }

    /// CIRISEdge#433 — record ONE withhold against the ledger. A no-op when no
    /// metrics handle is installed, so every gate below can call it
    /// unconditionally and no test construction has to care.
    ///
    /// Called at the BRANCH, never at a join point: the ledger's contract is that
    /// the reason is the branch, not a disjunction over the reasons that might
    /// have applied.
    fn withhold(&self, reason: crate::observability::WithholdReason, peer: &str, detail: &str) {
        if let Some(m) = self.metrics.as_ref() {
            m.inc_withhold(reason, peer, detail);
        }
    }

    /// CIRISEdge#433 — the short, low-cardinality `detail` for a hash-addressed
    /// withhold: the kind plus an 8-byte hash prefix (the same prefix the #379
    /// withheld-trace log already carries, so a ledger entry and a log line join).
    fn withhold_detail(kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> String {
        format!(
            "{}:{}",
            kind.as_wire_str(),
            hex::encode(&envelope_hash[..8])
        )
    }

    /// Decode persist's hex-encoded `persist_row_hash` (64 chars,
    /// lowercase) into the 32-byte `envelope_hash` shape the
    /// replication protocol uses. Returns `None` if decode fails —
    /// defensive against a future persist row whose hash isn't the
    /// expected hex shape.
    fn decode_hash(hex: &str) -> Option<[u8; 32]> {
        let bytes = hex::decode(hex).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(out)
    }

    /// CIRISEdge#531 — the advertise build plus the removal-receipt bookkeeping.
    ///
    /// v18.6.0 (WIDTH) had the [`ReplicationDirectory`] entry points take a
    /// sweep permit at the trait boundary and call this permit-FREE builder
    /// below it, so an acquire could never nest. CIRISEdge#531 DEPTH moves the
    /// acquire DOWN, to exactly one page's read + projection
    /// ([`Self::sweep_paged`], [`Self::attestation_page`],
    /// [`Self::fan_out_for_member`]) — a `Full` drain is now many reads, and one
    /// permit held across all of them would make the FIFO-fair gate a long queue
    /// for every other plane. The re-entrancy discipline is unchanged in
    /// substance and stronger in statement: a permit is held around ONE PAGE and
    /// never around a caller of one. `sweep_gate_is_not_re_entrant` pins it.
    async fn list_envelope_refs_unbounded(
        &self,
        kind: EnvelopeKind,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        let refs = self.list_envelope_refs_inner(kind, window).await;
        // CIRISEdge#441 — removal-class rows enter the receipt ledger the
        // moment they are advertisable; the serve exit records offers and
        // the coordinator's Summary observer records protocol-native acks.
        if is_removal_kind(kind) {
            if let Some(m) = self.metrics.as_ref() {
                for r in &refs {
                    m.removal_track(kind, r.envelope_hash);
                }
            }
        }
        refs
    }

    /// CIRISEdge#531 — the high-water mark of simultaneously-materialised bulk
    /// sweeps this bridge has ever reached. The width bound's own witness: a
    /// value above [`BridgeConfig::advertise_sweep_permits`] means a sweep
    /// escaped the gate (a new bulk read wired past the trait layer).
    #[must_use]
    pub fn max_sweeps_in_flight(&self) -> usize {
        self.sweep_gate
            .max_in_flight
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// CIRISEdge#531 DEPTH — the largest single page read this bridge has
    /// materialised. See [`Self::sweep_max_page_rows`]: this is what makes
    /// "memory is flat in the corpus" checkable rather than asserted.
    #[must_use]
    pub fn max_sweep_page_rows(&self) -> usize {
        self.sweep_max_page_rows
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// CIRISEdge#531 DEPTH — how many sweep permits have been taken over this
    /// bridge's life. One per PAGE, so a multi-page drain shows multiple.
    #[must_use]
    pub fn sweep_permits_taken(&self) -> usize {
        self.sweep_gate
            .entries
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    /// CIRISEdge#531 DEPTH — record one page's materialised row count. Called
    /// at EVERY page read site; a site that forgets is exactly the regression
    /// [`Self::max_sweep_page_rows`] exists to catch, so keep them together.
    fn record_page(&self, rows: usize) {
        self.sweep_max_page_rows
            .fetch_max(rows, std::sync::atomic::Ordering::SeqCst);
    }
}

// ─── ReplicationDirectory impl ──────────────────────────────────────

#[async_trait]
impl ReplicationDirectory for FederationDirectoryReplicationBridge {
    /// CIRISEdge#552 — the operator's switch, filtered through the correctness
    /// rule. `retention_for` pins every plane that must hold bodies, so a node
    /// configured hash-first still holds revocations, rosters, and anything else
    /// whose body it needs — the switch cannot turn those off.
    ///
    /// # Freshness, and the one window that remains
    ///
    /// Synchronous by design: this sits on the apply loop. It reads the tier
    /// cache, refreshed by the async calls that precede it —
    /// `list_envelope_refs_for_peer` on the initiator round path and
    /// `list_holdings` on the responder's, both once per round.
    ///
    /// **Residual:** an UNSOLICITED `Deliver` (the #927 proactive-publish
    /// shape) reaches `Session::on_deliver` with no async provider call ahead
    /// of it, so if one is the very first inbound after startup or after a
    /// [`CachedServeTier::TTL`] expiry, it is processed against the
    /// fail-closed `None` — that message's bodies are applied rather than
    /// learned, and a signer it would have queued is not. Bounded to one
    /// message per window and self-healing on the next round. Closing it needs
    /// either an async hook on the deliver path or a background refresh from
    /// the sync one; neither is worth a runtime hop on the apply loop today.
    ///
    /// [`CachedServeTier::TTL`]:
    ///     crate::replication::serve_tier::CachedServeTier::TTL
    fn retention(&self, kind: EnvelopeKind) -> crate::replication::retention::Retention {
        // ROLE_MATRIX Axis 3 — the MESH SERVER carries hashes; a CANONICAL
        // carries bodies. Not a ladder: answering an identifier lookup requires
        // the body, so the tier that answers cannot be hash-first, and the tier
        // that is hash-first cannot answer. Bodies therefore concentrate at
        // canonicals — few, accountable, rate-limited — which is where the
        // anti-harvest property actually lives.
        //
        // Keyed on the tier, NOT on `AgentMode`: mode is the local-resources
        // posture (listener, queue), and shipping this keyed on it was the
        // one-variable-two-jobs bug.
        let configured = if self.serve_tier().holds_hash_directory() {
            crate::replication::retention::Retention::HashFirst
        } else {
            crate::replication::retention::Retention::Bodies
        };
        crate::replication::retention::retention_for(kind, configured)
    }

    /// CIRISEdge#552 — record hashes learned without their bodies, with the peer
    /// that advertised them (the holder map). In-memory and local only: this is
    /// an OBSERVATION, not a claim, and CIRISPersist#785 is where it becomes
    /// durable.
    fn note_missing_signer(
        &self,
        _kind: EnvelopeKind,
        signer_key_id: &str,
        source_peer: Option<&str>,
    ) {
        // Gated on the KEY plane's retention: the row that stalled can be any
        // kind, but the row it waits on is always a Key. Under `Bodies` that
        // body replicates on its own and #544 admits the row later.
        if !crate::replication::retention::should_note_missing_signer(
            self.retention(EnvelopeKind::Key),
        ) {
            return;
        }
        // Third-party signers ARE queueable again: a conferred server answers
        // an identifier Pull for any subject on a public plane (ROLE_MATRIX
        // axis 3), so a name this node cannot resolve locally is reachable by
        // asking one. `source_peer` is kept as a ROUTING HINT — the peer that
        // delivered the row is the best first guess — but is no longer a
        // requirement, because an unrouted name is simply offered to successive
        // peers until a conferred one answers.
        //
        // The flood vector that a bare cap leaves open (a peer manufacturing
        // unique nonexistent signers) is bounded below by charging eviction to
        // the LARGEST source rather than to whoever arrived last.
        if let Ok(mut pending) = self.missing_signers.lock() {
            let Ok(mut sources) = self.missing_signer_sources.lock() else {
                return;
            };
            if pending.len() >= MISSING_SIGNER_CAP && !pending.contains_key(signer_key_id) {
                // O(1) rejection — a lookup and a comparison. Rebuilding the
                // counts here handed a peer sending unverifiable rows a full
                // scan per rejected signer.
                if !sources.eviction_worth_considering(source_peer) {
                    tracing::warn!(
                        signer = %signer_key_id,
                        cap = MISSING_SIGNER_CAP,
                        "missing-signer set at cap with no source hoarding — \
                         DROPPING this name (CIRISEdge#552)"
                    );
                    return;
                }
                let victim = sources.dominant_excluding(source_peer).and_then(|(d, _)| {
                    pending
                        .iter()
                        .find(|(_, src)| src.as_deref() == d.as_deref())
                        .map(|(name, _)| name.clone())
                });
                if let Some(name) = victim {
                    if let Some(src) = pending.remove(&name) {
                        sources.forget(src.as_deref());
                    }
                } else {
                    return;
                }
            }
            // Never downgrade a routed name to unrouted: a known holder
            // candidate beats ask-anyone.
            let is_new = !pending.contains_key(signer_key_id);
            let slot = pending
                .entry(signer_key_id.to_string())
                .or_insert_with(|| source_peer.map(str::to_owned));
            if slot.is_none() && source_peer.is_some() {
                // UPGRADED from unrouted to routed — the ledger must follow, or
                // the entry stays counted against `None` forever and fair
                // eviction charges the wrong source.
                if !is_new {
                    sources.forget(None);
                    sources.note(source_peer);
                }
                *slot = source_peer.map(str::to_owned);
            }
            if is_new {
                sources.note(slot.as_deref());
            }
        }
    }

    fn take_missing_signer_for(&self, peer_key_id: &str) -> Option<String> {
        let mut pending = self.missing_signers.lock().ok()?;
        // Prefer a name this peer actually delivered (best holder guess), then
        // fall back to an unrouted one so successive rounds try successive
        // peers until a CONFERRED one answers.
        let pick = pending
            .iter()
            .find(|(_, src)| src.as_deref() == Some(peer_key_id))
            .or_else(|| pending.iter().find(|(_, src)| src.is_none()))
            .map(|(name, _)| name.clone())?;
        if let Some(src) = pending.remove(&pick) {
            if let Ok(mut sources) = self.missing_signer_sources.lock() {
                sources.forget(src.as_deref());
            }
        }
        Some(pick)
    }

    fn note_known_hashes(
        &self,
        kind: EnvelopeKind,
        hashes: &[[u8; 32]],
        advertised_by: Option<&str>,
    ) {
        let Some(peer) = advertised_by else {
            // A hash with no holder is not actionable: knowing a record exists
            // without knowing who has it cannot be resolved into anything.
            return;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // ROLE_MATRIX Axis 3 — only a CONFERRED server accumulates the
        // directory. An unconferred node that recorded every hash a peer
        // advertised would end up holding the whole federation as hashes —
        // the enumeration surface again, just cheaper to carry. What it needs
        // is the subset that concerns it, reached through the on-demand path.
        if !self.serve_tier().holds_hash_directory() {
            return;
        }
        if let Ok(mut known) = self.known_hashes.lock() {
            for h in hashes {
                known.note(kind, *h, peer, now);
            }
        }
    }

    async fn list_envelope_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        // CIRISEdge#531 DEPTH — the PEER-BLIND projection view (diagnostics and
        // tests; every production provider is peer-bound via
        // `DirectoryStateAdapter::with_peer`). No peer means no watermark to
        // keep, and callers of this surface expect the WHOLE projection — so it
        // is a `Full` drain: paged for memory, complete in result.
        //
        // The width permit is no longer taken here; it is taken per page
        // inside the sweep. See [`Self::list_envelope_refs_unbounded`].
        self.list_envelope_refs_unbounded(kind, SweepWindow::Full)
            .await
    }

    async fn fetch_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        // CIRISEdge#397 §3 — the content-hash point-read. Every indexed kind
        // (all 13 except `Revocation`) resolves its bytes from persist's
        // `signed_wire_index` keyed on `(kind, content_hash)`. Because edge
        // advertised `sha256(serde_json::to_vec(row))` and persist reloads +
        // re-serializes that SAME row, the returned bytes hash back to
        // `envelope_hash` by construction.
        if let Some(k) = kind.persist_index_kind() {
            return self
                .directory
                .lookup_signed_record_by_content_hash(k, &hex::encode(envelope_hash))
                .await
                .ok()
                .flatten();
        }
        // CIRISEdge#396 item 3 — `Revocation` is the ONE kind persist does not
        // content-hash-index; it rides the `persist_row_hash` wire. Resolve it
        // with NO cache: this retires the last in-memory fetch cache, so every
        // plane's fetch is now a direct persist read.
        if kind.is_row_hash_served() {
            return self.fetch_revocation_bytes(envelope_hash).await;
        }
        None
    }

    /// CIRISEdge#379 — recipient-aware listing: the Attestation plane routes
    /// through the `infra:serve`-gated sweep; every other kind is peer-invariant.
    async fn list_envelope_refs_for_peer(
        &self,
        kind: EnvelopeKind,
        peer_key_id: Option<&str>,
    ) -> Vec<EnvelopeRef> {
        // ROLE_MATRIX Axis 3 — THE once-per-round production path.
        // `DirectoryStateAdapter::local_refs` calls THIS, not the peer-blind
        // `list_envelope_refs` (that one is diagnostics and tests). Refreshing
        // only there left the cache at `ServeTier::None` forever in production:
        // even a canonical would use `Bodies` and discard every advertised
        // hash — the feature inert exactly where it matters.
        self.refresh_serve_tier().await;
        // CIRISEdge#531 DEPTH — this is THE advertise axis, and the only one
        // that carries a watermark: a bound peer gets one page budget per
        // round (new rows first, then a page of the rolling re-sweep), so the
        // node's advertise memory is flat in the corpus instead of merely
        // bounded by the width permit. An UNBOUND peer (`None`) has no
        // watermark to key on and falls through to the complete `Full` view.
        let window = peer_key_id.map_or(SweepWindow::Full, SweepWindow::Watermark);
        match (kind, peer_key_id) {
            (EnvelopeKind::Attestation, Some(peer)) => {
                self.list_attestations(Some(peer), window).await
            }
            _ => self.list_envelope_refs_unbounded(kind, window).await,
        }
    }

    /// CIRISEdge#416 — RAW holdings for the RECEIVE-diff axis: "what I hold",
    /// NOT "what I advertise". The `want = remote ∖ holdings` diff must see
    /// every row local state holds, or a held-but-not-advertised row sits in
    /// `want` forever — re-fetched and re-applied as `Duplicate` every round
    /// (the CIRISAgent#932 non-convergence).
    ///
    /// v18 sweep: FOUR planes filter their advertise below their holdings, not
    /// one. Attestation (`attestation_is_advertised`, per-record) was fixed by
    /// #416 itself; the three `SelfOwn` publish-own planes — Key /
    /// IdentityOccurrence / TransportDestination — filter their advertise to
    /// `subjects_for_projection(SelfOwn)`, so a FOREIGN-subject row this node
    /// admitted (exactly what those planes replicate IN) was invisible to its
    /// own holdings view and never converged. Each now has an unfiltered
    /// holdings twin (the filter belongs to advertise only). The remaining
    /// planes keep the advertise default: the membership/tombstone planes
    /// project `Global` (own ∪ cohort — the widest set this node can
    /// enumerate), `Revocation` likewise, and the three Cohort-scoped planes
    /// (Family / Community / LocationProof) assume advertise == holdings for
    /// rows the node would ever be re-offered — a cohort-filter residual of the
    /// same class is conceivable there and is deliberately left to its own
    /// audit rather than silently widened here.
    ///
    /// CIRISEdge#523 is that audit, and the residual was real: those three
    /// planes' cohort filter is NODE-keyed while their rosters name PERSONS, so
    /// the advertise — and therefore this holdings view — was empty by
    /// construction. [`Self::cohort_set_with_owners`] widens the FILTER, which
    /// repairs both axes at once and keeps advertise == holdings, exactly as
    /// this arm's `_ =>` fall-through assumes.
    async fn list_holdings(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        // ROLE_MATRIX Axis 3 — the RESPONDER receive path's refresh point.
        //
        // `Session::on_summary` calls `local_holdings` and only THEN reads
        // `provider.retention(kind)`, which is a synchronous cache read. Without
        // a refresh here, the very first Summary after startup (and the first
        // after any `CachedServeTier::TTL` expiry) is processed against the
        // fail-closed `ServeTier::None`: a conferred server takes the `Bodies`
        // branch and that round's advertised hashes are pulled as bodies
        // instead of learned. Bounded and self-healing — the next round has a
        // fresh cache — but a whole round of hash learning lost per window, on
        // exactly the nodes the feature is for.
        //
        // Refreshing HERE rather than inside `retention()` keeps the sync
        // readers sync: this is the async call that already precedes them.
        self.refresh_serve_tier().await;
        // CIRISEdge#547 / CIRISPersist#780 — READ THE INDEX, NOT THE ROWS.
        //
        // Everything below is correct and was killing production. `holdings`
        // must be COMPLETE (a partial view leaves held rows in `want` forever,
        // CIRISEdge#416), so #531 made these arms paged — which bounded MEMORY
        // and deliberately not I/O. The result: every round, every plane,
        // re-reading the whole corpus from disk in 1024-row chunks to recompute
        // hashes. On the canonical (1.3 GB corpus, 808 MB page cache for the
        // whole box) that is 35–118 MB/s continuous, every fault taken while
        // holding persist's single connection mutex, so every other DB task
        // parked behind it. The node went unreachable after ~22 h, `restarts=0`,
        // no panic, with the health endpoint inside the same convoy.
        //
        // persist already had these hashes: `signed_wire_index`, PRIMARY KEY
        // `(kind, content_hash)`, maintained by the same hooks that admit rows.
        // v38.7.0 exposes it. This is index-only — ~50k hashes ≈ 1.6 MB against
        // 1.3 GB of rows — and still COMPLETE across pages, so the convergence
        // invariant is untouched. Bounded I/O, not bounded reach.
        if let Some(index_kind) = kind.persist_index_kind() {
            if let Some(refs) = self.holdings_from_wire_index(index_kind).await {
                return refs;
            }
        }
        self.list_holdings_from_rows(kind).await
    }

    /// CIRISEdge#474 — serve an accord-quorum-evidence cursor pull. The plane has
    /// no content-hash `signed_wire_index`, so this is its ONLY serve path: read
    /// persist's `list_signed_accord_quorum_evidence_since` (ordered `(evidence_at,
    /// proposal_digest)`, bounded by the page limit) and JSON-serialize each bundle
    /// exactly as the apply side (`apply_accord_quorum_evidence`) deserializes it —
    /// the byte-for-byte round trip persist's re-tally admit expects. A read error
    /// is a loud empty (the round re-pulls next pass), never a panic. Non-cursor
    /// kinds return empty: they converge over Summary/Diff/Fetch, not here.
    async fn accord_evidence_since(
        &self,
        kind: EnvelopeKind,
        since: Option<chrono::DateTime<chrono::Utc>>,
        peer_key_id: Option<&str>,
    ) -> Vec<Vec<u8>> {
        // v18 — gated on the PREDICATE, not a kind literal, so this site and
        // `is_cursor_served` cannot drift. NOTE: the body below is
        // accord-specific; a future second cursor kind passes this gate and
        // MUST add its own dispatch here (the protocol.rs over-ALL pin makes
        // widening the predicate a deliberate act, and
        // `cursor_arm_set_equals_the_predicate_over_all` binds this site).
        if !kind.is_cursor_served() {
            return Vec::new();
        }
        // ── CIRISEdge#531 — RETENTION, not just materialisation ─────────
        //
        // The v18.6.0 width permit bounds how many pages are BUILT at once. It
        // does not bound how many are HELD: this method returns owned bytes,
        // the permit drops at `return`, and the `Vec<Vec<u8>>` then lives on
        // through `Session::on_cursor_pull` → `DeliverMessage` → the send —
        // potentially a whole round. So peak RETAINED memory scaled with PEER
        // COUNT while peak materialised memory scaled with permits, and for
        // this plane (the only one that hands back bytes rather than 40-byte
        // refs) those diverge badly.
        //
        // The fix is a BYTE budget on the page, not a longer permit. Extending
        // the permit through consumption would make a slow peer's send hold a
        // sweep permit for its whole duration — the FIFO starvation the width
        // bound was careful not to create — and retention and materialisation
        // are genuinely different resources. With the budget, retention per
        // response is bounded by a constant an operator can multiply by their
        // peer count (6 peers × 512 KiB ≈ 3 MiB) instead of by the corpus.
        //
        // The budget is only SAFE because of the watermark below. Before it,
        // the initiator opened every round from `since: None`
        // (`Session::start_round`), so truncating a page meant the bundles past
        // it were never served — the plane would silently stop converging,
        // which is strictly worse than the memory. The responder-side watermark
        // is what turns "truncated" into "continued next round".
        let _permit = self.sweep_gate.enter().await;
        let budget = self.sweep_page_budget().await;
        // The wire `since` is a FLOOR the requester declared ("I hold
        // everything up to here"), never a position we may fall behind: pair it
        // with the EMPTY id, which sorts before every real digest, so a tie at
        // the floor is re-delivered rather than skipped (persist documents
        // duplicates-on-resume; edge's apply re-tallies, so at-least-once is
        // correct here and a skip would be silent evidence loss).
        let floor = since.map(|ts| (ts, String::new()));
        let Some(key) = peer_key_id.map(|p| (p.to_owned(), kind)) else {
            // An UNATTRIBUTED pull keeps no position — there is no peer to keep
            // it for. It gets one budgeted page from the declared floor, which
            // is the pre-#531 behaviour bounded.
            return self.accord_evidence_page(floor, budget).await.0;
        };
        let head = Self::later_cursor(self.sweep_head(&key), floor.clone());
        let (mut out, served, last) = self.accord_evidence_page(head, budget).await;
        if let Some(plan) = self.sweep_after_head(&key, served, budget, last) {
            let (mut more, b_served, b_last) = self
                .accord_evidence_page(Self::later_cursor(plan.since, floor), plan.budget)
                .await;
            out.append(&mut more);
            self.sweep_after_backfill(&key, b_served, plan.budget, b_last);
        }
        out
    }

    /// CIRISEdge#462 — serve a subject-scoped RECEIVE-axis Pull. Entitlement is
    /// FAIL-CLOSED, with one narrow widening bounded by the ADVERTISE
    /// projection (CIRISEdge#552).
    ///
    /// A Pull for subject `S` is answered to a requester authenticated AS `S`
    /// (the data-subject access path), **or** — on a plane whose serve cell is
    /// unconditionally `public` — when `S` is THIS NODE'S OWN key_id. An
    /// unattributed requester still gets nothing, and it still says so.
    ///
    /// # Why a CONFERRED server answers for any subject, and others do not
    ///
    /// The identity plane is **public**: announced, rooted, attributable, with
    /// no anonymity claim (README, "the two-plane hybrid"). The property this
    /// system actually protects is on the GROUP plane — family/community
    /// existence is structurally invisible because destinations are *derived*
    /// from state members already hold and never announced. Derivation replaces
    /// discovery. So a third-party lookup of a `Key` or a `TransportDestination`
    /// discloses nothing the design withholds; treating it as a confidentiality
    /// breach imports a property onto the one plane that disclaims it.
    ///
    /// What differs between nodes is not entitlement but HOLDINGS.
    /// `AgentMode::Server` is the node that opted into carrying the directory —
    /// storage, uptime, the whole corpus as hashes with bodies on demand.
    /// Answering "which records do you hold for this subject" is what being one
    /// means. A `Proxy` or `Client` holds essentially its own records, so it can
    /// answer for itself and has nothing else to offer; that is also why the
    /// enumeration surface does not follow the corpus around the fabric.
    ///
    /// A fedID is therefore sufficient to reach someone: ask a server, get the
    /// refs, fetch the bodies by content hash — the hash-addressed path that was
    /// always safe. Canonicals hold the contents, so the answer always exists
    /// somewhere.
    ///
    /// # Why the own-record arm still exists separately
    ///
    /// `serve: public` and `advertise: self_own` answer DIFFERENT questions, and
    /// conflating them is how the first attempt at this went wrong. `public`
    /// says a record needs no capability gate *once it reaches you*.
    /// `self_own` is what decides **which** records reach you at all: on these
    /// planes a node advertises only its own. But `subject_holdings_inner`
    /// performs an ARBITRARY subject lookup against the node's whole local
    /// directory. Serving that to any attributed requester would let a peer
    /// probe identifiers for third-party keys and routes that never appeared in
    /// any Summary it received — turning a body-holding server into an
    /// address-book oracle and destroying the opaque-directory property
    /// hash-first exists to create. "Already public" is not "already disclosed
    /// to you".
    ///
    /// Restricting `S` to this node's own record keeps the answer inside what
    /// `self_own` already hands every peer, so it is disclosure-neutral in fact
    /// and not merely in claim. It recovers the case that matters most: *"you
    /// signed a row I cannot verify — send me your key."*
    ///
    /// A THIRD-PARTY signer remains unfetchable by identifier. That is a real
    /// gap, and closing it needs a separately authorized, rate-limited resolver
    /// rather than a widening here.
    ///
    /// `Attestation` keeps the subject-only rule outright: its serve cell is
    /// conditional (`trace:*` → `capability:infra:serve`, plus the per-row G2
    /// scores carve), so its entitlement is decided per RECORD.
    ///
    /// (Owner-delegation, a node key pulling for its owner fedID, needs
    /// `owner_of` and is still a deliberate follow-up, not silently permitted.) The refs themselves come from
    /// [`Self::subject_holdings_inner`], which hashes the SAME struct the wire
    /// index keys on and applies the G2 capacity carve.
    async fn subject_holdings(
        &self,
        kind: EnvelopeKind,
        subject_key_id: &str,
        peer_key_id: Option<&str>,
    ) -> Vec<EnvelopeRef> {
        // Authorize BEFORE resolving. The subject and own-record arms need no
        // tier at all, and an unattributed requester needs nothing but a
        // refusal — so neither may reach the trust-graph walk. `CachedServeTier`
        // has no single-flight lock, so a burst of probes crossing a
        // stale-cache boundary would otherwise buy one graph walk per request
        // from a peer that is not even entitled to an answer.
        let entitled_without_tier = match peer_key_id {
            Some(p) => {
                p == subject_key_id
                    || (kind.is_public_subject_pull()
                        && self.local_key_id.as_deref() == Some(subject_key_id))
            }
            None => false,
        };
        // Only the third-party public-plane arm depends on the tier — and it
        // is also the only arm that is rate limited (FSD_RATE_LIMIT §5.4).
        //
        // The subject and own-record arms are exempt on purpose: a data subject
        // asking about itself is exercising an access right, and a node's own
        // record is what `self_own` already advertises to everyone. Charging
        // those against a harvesting budget would throttle the two flows that
        // cannot harvest anything.
        // Third-party identifier lookups: entitled by a MUTUAL TRUST ROOT, not
        // by a serving tier.
        //
        // node/fed/agent IDs are FEDERATION COHORT — servable by any peer
        // holding them, to any requester under a shared root. An earlier
        // revision gated this on the canonical rung, which was too narrow: it
        // made the fleet's storage helpers unable to answer for records they
        // legitimately hold, and any node that received an ID may hold it
        // (unless revoked or superseded) precisely because any ID may be
        // load-bearing.
        //
        // What bounds abuse is not WHO answers but HOW MUCH any one peer may
        // extract, across layered windows — see the drain ceilings above.
        let mut cohort_entitled = false;
        if !entitled_without_tier && peer_key_id.is_some() && kind.is_public_subject_pull() {
            if let Some(requester) = peer_key_id {
                cohort_entitled = self.shares_a_trust_root_with(requester).await;
                if !cohort_entitled {
                    tracing::debug!(
                        requester,
                        subject = %subject_key_id,
                        "identifier lookup refused: no mutual trust root — two \
                         nodes with no shared root compose nothing (CC 4)"
                    );
                    return Vec::new();
                }
                let verdict = self.lookup_limiter.lock().map_or(
                    crate::rate_limit::Decision::Allow {
                        suppressed_since_last_allow: 0,
                    },
                    |mut rl| rl.check_from(&requester.to_owned(), Some(requester), unix_now_secs()),
                );
                if let crate::rate_limit::Decision::Deny { reason } = verdict {
                    // THROTTLED. "Not asked again this window" was wrong — the
                    // limiter suppresses the directory work, not the peer's
                    // sending, so a rate-limited peer that keeps asking would
                    // buy one WARN per request. Being loud about a flood is how
                    // you become its amplifier.
                    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        lookup_limit_log().check(requester)
                    {
                        tracing::warn!(
                            requester,
                            subject = %subject_key_id,
                            kind = ?kind,
                            reason = reason.as_str(),
                            suppressed_prev,
                            "identifier lookup RATE LIMITED — a conferred server \
                             answering by name is where bulk harvesting is \
                             possible, one named subject at a time \
                             (FSD_RATE_LIMIT §5.4)"
                        );
                    }
                    return Vec::new();
                }
            }
            self.refresh_serve_tier().await;
        }
        match peer_key_id {
            // Three entitled cases, in the order they were established:
            //   1. the subject itself — the data-subject access path (#462);
            //   2. this node's OWN record on a public plane — exactly what the
            //      `self_own` advertise projection already hands every peer;
            //   3. ANY subject on a public plane, when this node is a SERVER —
            //      because that is what a server IS.
            Some(p)
                if p == subject_key_id
                    || (kind.is_public_subject_pull()
                        && (self.local_key_id.as_deref() == Some(subject_key_id)
                            || cohort_entitled)) =>
            {
                // CIRISEdge#531 — WIDTH bound on the subject-Pull sweep too:
                // it is per-subject rather than whole-table, but the
                // Attestation arm sweeps BOTH testimonial axes and a
                // high-degree subject is not small. Taken INSIDE the entitled
                // arm so the fail-closed refusal below never queues behind a
                // sweep — refusing costs nothing and must stay instant.
                let _permit = self.sweep_gate.enter().await;
                self.subject_holdings_inner(kind, subject_key_id).await
            }
            other => {
                tracing::warn!(
                    subject = %subject_key_id,
                    requester = ?other,
                    kind = ?kind,
                    "subject Pull refused: requester is not the subject and this kind \
                     is not publicly pullable — serving nothing (#462 fail-closed; \
                     #552 widened only the unconditionally-public planes)"
                );
                Vec::new()
            }
        }
    }

    /// CIRISEdge#379 — recipient-aware fetch: the serve-side twin of the
    /// listing gate, so a peer excluded from the listing cannot obtain a
    /// `trace:*` envelope anyway by Diff/Fetch-ing a hash it learned
    /// out-of-band.
    #[allow(clippy::too_many_lines)] // the serve-side twin set: five gates + the v18 projection twin
    async fn fetch_envelope_bytes_for_peer(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
        peer_key_id: Option<&str>,
    ) -> Option<Vec<u8>> {
        // CIRISEdge#433 / #429 — the requester asked for a hash we just claimed to
        // hold and we cannot resolve it to bytes. This is the bridge-level ORIGIN
        // of the advertised-then-unfetchable event `session::pack_bounded_deliver`
        // reports in its `dropped` set (every entry there is this `None`); counting
        // it HERE keeps it disjoint from the policy gates below — "we could not
        // find it" never hides inside "we chose not to serve it". The `detail`
        // string is built INSIDE the branch: this is the per-envelope serve path,
        // and the happy path must not pay for an attribution nobody reads.
        let Some(bytes) = self.fetch_envelope_bytes(kind, envelope_hash).await else {
            self.withhold(
                crate::observability::WithholdReason::EnvelopeUnfetchable,
                peer_key_id.unwrap_or("<unattributed>"),
                &Self::withhold_detail(kind, envelope_hash),
            );
            return None;
        };
        if kind == EnvelopeKind::Attestation {
            // CIRISEdge#440 — the direct-fetch twins of the advertise-sweep
            // pause + quarantine gates, so a peer cannot obtain a paused
            // `trace:*` row or a quarantined author's row by Diff/Fetch-ing a
            // hash it learned out-of-band (the same twin discipline #379/#396
            // established). Parse tolerance matches the sweep: an unparseable
            // wire row is not gated here (the existing gates below keep their
            // own parse-and-tolerate shape untouched).
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let inner = value.get("attestation").unwrap_or(&value);
                let peer_label = peer_key_id.unwrap_or("<unattributed>");
                if Self::attestation_requires_serve(inner) && self.trace_plane_paused().await {
                    self.withhold_config_paused(peer_label, "config-paused-fetch");
                    return None;
                }
                if self
                    .author_quarantine_withholds(inner, &mut HashMap::new(), peer_label)
                    .await
                {
                    return None;
                }
                // Workstream F — the direct-fetch twin of the advertise sweep's
                // relay gate, so a peer cannot obtain an `accord:*` row this
                // node may not CARRY by Diff/Fetch-ing a hash it learned
                // out-of-band (the twin discipline #379/#396/#440 established).
                if self
                    .accord_relay_withholds(inner, peer_label, "fetch")
                    .await
                {
                    return None;
                }
                // v18 — the PROJECTION twin (the last un-twinned advertise gate).
                // `attestation_is_advertised` structurally hides a `SelfOwn`-
                // projecting row this node did not produce (a `self`/`family`
                // attestation is published by its own producer, never relayed —
                // the structural-invisibility discipline), but until now ONLY on
                // the listing: a peer that learned the hash out-of-band was
                // served the bytes anyway. The twin matches the advertise gate's
                // semantics INCLUDING the v16 first-party override: a peer that
                // is this row's author or data-subject fetches its OWN testimony
                // (the same carve `pull_ref_is_serveable` grants the subject-Pull
                // LIST — the #462 recovery right), and that carve deliberately
                // bypasses the whole advertise predicate, malformed-scope decline
                // included, so LIST and FETCH agree on the subject-Pull axis.
                // An unattributed fetch has no first party and fails closed.
                //
                // The booked reason BORROWS `RecipientNotInSendSet` — the
                // closest documented audience-membership variant (the enum is a
                // closed operator vocabulary; no variant names the projection
                // gate, and widening the enum is not this change's to make). The
                // `detail` string names the true branch so a ledger reader is
                // not misled toward the consent plane.
                let first_party =
                    peer_key_id.is_some_and(|p| Self::attestation_is_first_party_to(inner, p));
                if !first_party {
                    let self_set: HashSet<String> = self
                        .self_provider
                        .as_ref()
                        .map(|p| p())
                        .unwrap_or_default()
                        .into_iter()
                        .collect();
                    if !Self::attestation_is_advertised(inner, &self_set) {
                        self.withhold(
                            crate::observability::WithholdReason::RecipientNotInSendSet,
                            peer_label,
                            "projection: row not advertised by this node (SelfOwn fetch twin)",
                        );
                        tracing::debug!(
                            peer = peer_label,
                            envelope_hash = %hex::encode(&envelope_hash[..8]),
                            "attestation withheld from direct fetch — the projection \
                             structurally hides this row from third parties (SelfOwn \
                             publish-own; only a first party may fetch it) (v18 \
                             projection twin)"
                        );
                        return None;
                    }
                }
            }
            if let Some(peer) = peer_key_id {
                // v16 review: FIRST-PARTY right overrides #396 producer-advertise-
                // consent. If `peer` is this attestation's AUTHOR or DATA-SUBJECT it is
                // fetching its OWN testimony — the same first-party carve the subject-
                // Pull LIST gate (`pull_ref_is_serveable`) applies — so list and fetch
                // AGREE (no advertised-then-unfetchable, no ref disclosed-then-withheld).
                // For a first-party fetch the recipient IS the peer; #396 item-1
                // consent-membership and item-6 recipient_capability do not apply. The
                // E3 trace serve-cap gate below STILL does (a subject pulling its own
                // `trace:*` row needs `infra:serve`, exactly as the list requires).
                let first_party = serde_json::from_slice::<serde_json::Value>(&bytes)
                    .ok()
                    .is_some_and(|v| {
                        Self::attestation_is_first_party_to(
                            v.get("attestation").unwrap_or(&v),
                            peer,
                        )
                    });
                // #396 item 1 — the same consent-membership bound the listing applies,
                // so a THIRD-party peer excluded from the advertise cannot obtain an
                // attestation by fetching a hash it learned out-of-band. Fail-closed:
                // no `ResolvedRecipient`, no bytes. (#433: `resolve_attestation_recipient`
                // books its OWN branch's reason — no re-count here.)
                let recipient: String = if first_party {
                    peer.to_owned()
                } else {
                    self.resolve_attestation_recipient(peer)
                        .await?
                        .as_str()
                        .to_owned()
                };
                // #379 `infra:serve` + #396 item 6 `recipient_capability`, over the WIRE
                // bytes — the direct-fetch twins of the listing gates. The wire is the
                // BARE `Attestation` (§3); tolerate the legacy `{"attestation": …}` wrap.
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let inner = value.get("attestation").unwrap_or(&value);
                    if Self::attestation_requires_serve(inner)
                        && !self.peer_has_serve_capability(&recipient).await
                    {
                        // #433: `peer_has_serve_capability` books the specific leg
                        // (no-role / read-error / not-rooted / walk-error) — its
                        // `bool` return is exactly the disjunction the ledger must
                        // not report, so this site logs and does not count.
                        tracing::debug!(
                            peer,
                            envelope_hash = %hex::encode(&envelope_hash[..8]),
                            "trace attestation withheld — recipient lacks an effective \
                             `infra:serve` capability (CIRISEdge#379)"
                        );
                        return None;
                    }
                    // #396 item 6 — recipient_capability gates a THIRD-party recipient
                    // (an author-chosen audience). A first-party subject/author is not
                    // such a recipient, so it does not apply (matches the list gate).
                    if !first_party
                        && self
                            .recipient_capability_withholds(inner, &recipient, &mut HashMap::new())
                            .await
                    {
                        // #433 — item 6 was the purest silent withhold on this path.
                        // Countable now, booked inside `recipient_capability_withholds`
                        // at the deciding branch, so this site does not re-count.
                        return None;
                    }
                }
            }
        }
        // CIRISEdge#433 — the replication plane's metric-visible moment. This is
        // where the bridge hands the wire bytes back to `pack_bounded_deliver`;
        // every gate has cleared and local state resolved the row, so THIS layer's
        // part of the transaction is definitely complete. Mirrors the CIRISEdge#28
        // precedent (`edge.rs`: "durable enqueue is the metric-visible moment"):
        // count where success is definite for the layer doing the counting, not at
        // a peer acknowledgement this layer never observes. Two known, deliberate
        // imprecisions, both bounded and both in the honest direction: the caller
        // may drop the LAST fetched envelope when it would exceed
        // `MAX_DELIVER_ENVELOPE_BYTES` (at most one per Deliver, re-served next
        // round), and a Deliver frame lost in flight still counts as served — the
        // same semantics `envelopes_sent_total` has carried since v0.19.0.
        if let Some(m) = self.metrics.as_ref() {
            m.inc_replication_served(kind);
            // CIRISEdge#441 — a removal-class serve is an OFFER in the receipt
            // ledger: this peer was handed the row; the ack arrives when its
            // own next Summary advertises the hash.
            if is_removal_kind(kind) {
                if let Some(p) = peer_key_id {
                    m.removal_offer(
                        kind,
                        *envelope_hash,
                        p,
                        u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0),
                    );
                }
            }
        }
        Some(bytes)
    }

    async fn apply_envelope_bytes(
        &self,
        kind: EnvelopeKind,
        envelope_bytes: &[u8],
        source_peer: Option<&str>,
    ) -> ApplyOutcome {
        // CIRISEdge#426 — the authenticated sender now REACHES the apply layer (it
        // was dropped upstream, which made the consent plane send-only). The actual
        // per-peer write enforcement lives in persist v22's put-gates + AV-76
        // per-peer quota (a Sybil's forged/self-emitted rows are refused there and
        // surface as a loud `Refused` via the #425 choke point); this trace records
        // that the receive is attributed, so a per-peer edge policy is now
        // expressible on top of a peer that is present rather than discarded.
        tracing::trace!(
            kind = ?kind,
            source_peer = source_peer.unwrap_or("<unattributed>"),
            "apply_envelope_bytes: receiving from attributed peer (CIRISEdge#426)"
        );
        // persist v24.2.0 / #565 — the receive-plane mirror's kind axis: every
        // `Refused` leaving this choke is counted per envelope kind (the #425
        // choke already logs it; now it is also a metrics-scrape fact). The
        // typed Key-plane token axis books inside `apply_key`.
        let outcome = self.dispatch_apply(kind, envelope_bytes).await;
        // CIRISEdge#457 — the receive plane now books EVERY outcome at this
        // choke, not just refusals: an accepted apply (Admitted = new state)
        // and a duplicate (already held) are counted distinctly, so "applied
        // all N" and "offered nothing" no longer both read `{}` (the #433
        // distinct-states rule, on the receive side; the mirror of #434).
        if let Some(m) = &self.metrics {
            match &outcome {
                ApplyOutcome::Admitted => m.inc_applied(kind),
                ApplyOutcome::Duplicate => m.inc_duplicate(kind),
                ApplyOutcome::Refused { .. } => m.inc_apply_refusal_kind(kind),
                // Deserialize is a malformed-bytes drop, not an apply outcome
                // on a well-formed row — it stays uncounted here (the choke's
                // `on_deliver` logs it loud; a metrics kind-count of undecodable
                // bytes would conflate wire corruption with a policy decision).
                ApplyOutcome::Deserialize(_) => {}
            }
        }
        // The convergence signal, at the same choke and on the same rule as the
        // `applied` counter: ADMITTED only. A duplicate or a refusal changed
        // nothing a waiter can observe, and waking every waiter on the node for
        // a row it already held would make the signal a busy-loop with extra
        // steps.
        if outcome.is_admitted() {
            if let Some(signal) = &self.convergence {
                signal.note_admitted();
            }
        }
        self.remember_outcome(kind, envelope_bytes, &outcome);
        outcome
    }

    /// CIRISEdge#544 — the round's want-diff asks this before putting a hash on
    /// the wire. Pure in-memory probe of the refusal memory; counts the drops so
    /// the traffic that did NOT happen is observable.
    fn retry_suppressed(&self, kind: EnvelopeKind, envelope_hash: &[u8; 32]) -> bool {
        let hit = self
            .refusal_backoff
            .suppressed_at(kind, envelope_hash, Instant::now());
        if hit {
            self.retry_suppressions
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        hit
    }
}

impl FederationDirectoryReplicationBridge {
    async fn list_envelope_refs_inner(
        &self,
        kind: EnvelopeKind,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        match kind {
            // CIRISEdge#397 §1+§2 — the five primary signed planes advertise
            // via persist v21.2.0's bulk since-cursor reads, hashing each row by
            // its content-hash (`sha256(serde_json::to_vec(row))`) so the wire
            // hash == the point-read key. Key + IdentityOccurrence +
            // TransportDestination project SelfOwn (publish-own); Attestation is
            // per-record (`attestation_is_advertised`); IdentityOccurrenceRevocation
            // is a tombstone → Global (anti-rollback).
            EnvelopeKind::Key => self.list_keys(window).await,
            EnvelopeKind::IdentityOccurrence => self.list_identity_occurrences(window).await,
            EnvelopeKind::TransportDestination => self.list_transport_destinations(window).await,
            EnvelopeKind::IdentityOccurrenceRevocation => {
                self.list_identity_occurrence_revocations(window).await
            }
            EnvelopeKind::Attestation => self.list_attestations(None, window).await,
            // CIRISEdge#531 DEPTH — `Revocation` is the one plane persist does
            // not expose a `_since` cursor for: it fans out per cohort member
            // (`revocations_for`). There is no page to keep a watermark on, so
            // the window is not consulted; the width bound moved INSIDE the
            // fan-out (one permit per member read) so its materialisation stays
            // one member's rows rather than the whole cohort's.
            EnvelopeKind::Revocation => self.list_revocations().await,
            EnvelopeKind::Family => self.list_families(window).await,
            EnvelopeKind::Community => self.list_communities(window).await,
            EnvelopeKind::Organization => self.list_organizations(window).await,
            EnvelopeKind::OrgMembership => self.list_org_memberships(window).await,
            EnvelopeKind::PartnerRecord => self.list_partner_records(window).await,
            EnvelopeKind::FamilyMembershipRevocation => {
                self.list_family_membership_revocations(window).await
            }
            EnvelopeKind::CommunityMembershipRevocation => {
                self.list_community_membership_revocations(window).await
            }
            EnvelopeKind::LocationProof => self.list_location_proofs(window).await,
            // CIRISEdge#474 — the accord-quorum-evidence plane is NEVER advertised
            // by content-hash: it has no `signed_wire_index` entry
            // (`persist_index_kind` → None), so a ref here would be listed-then-
            // unfetchable (the LIST-vs-FETCH divergence class). It converges over
            // the dedicated cursor path (`CursorPull` → `Deliver`) instead.
            //
            // v18 — this arm IS `EnvelopeKind::is_cursor_served` in match form:
            // the match must stay exhaustive (a new kind must decide its
            // advertise read here), so the predicate cannot replace the arm.
            // `cursor_arm_set_equals_the_predicate_over_all` asserts the arm-set
            // equals the predicate over `ALL` — widening one without the other
            // reds there, not on the wire.
            EnvelopeKind::AccordQuorumEvidence => Vec::new(),
        }
    }

    /// CIRISEdge#462 — the subject-scoped RECEIVE-axis ref builder (entitlement
    /// already checked by [`Self::subject_holdings`]). For each replicated kind
    /// it calls the SAME per-subject persist read `list_signed_records` composes,
    /// but hashes the returned STRUCT with [`content_hash_of`] — the wire index
    /// keys on `sha256(to_vec(row))`, whereas `list_signed_records`' `to_value`
    /// canonical JSON re-orders keys (no serde_json `preserve_order`) and would
    /// not resolve through the content-hash fetch path. So the refs here are the
    /// index's own hashes by construction, and the unchanged Diff/Deliver flow
    /// (re-gated per record by `fetch_envelope_bytes_for_peer`) serves them.
    /// (CIRISPersist#634 asks for a subject-scoped wire-index read that would
    /// return these index hashes directly and retire this compose-and-rehash.)
    ///
    /// The Attestation plane sweeps BOTH testimonial axes: `list_attestations_for`
    /// (records ABOUT the subject — the revocation-reachability set, with the G2
    /// [`Self::is_non_retainable_score`] carve) and `list_attestations_by`
    /// (records BY the subject — authorship recovery, no carve: mine to recover).
    /// Non-replicated / cohort kinds are not subject-pullable and return empty.
    #[allow(clippy::too_many_lines)] // five per-plane arms + the v18 loud-read/booking mirrors
    async fn subject_holdings_inner(
        &self,
        kind: EnvelopeKind,
        subject_key_id: &str,
    ) -> Vec<EnvelopeRef> {
        let mut refs: Vec<EnvelopeRef> = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut push = |hash: [u8; 32], seq: u64| {
            if seen.insert(hash) {
                refs.push(EnvelopeRef {
                    envelope_hash: hash,
                    seq,
                });
            }
        };
        // v18 (the #429 class) — a persist read error on this path used to be an
        // `unwrap_or_default()`: the subject was told "no testimony" with no warn
        // and no counter, indistinguishable from a genuinely empty axis. Every
        // read below now warns like the cursor plane's serve read does
        // (`accord_evidence_since`); the served result stays empty-for-this-round
        // (the requester re-pulls next round), never a panic.
        macro_rules! subject_read {
            ($fut:expr, $what:literal) => {
                match $fut.await {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            subject = %subject_key_id,
                            concat!(
                                "subject-Pull ", $what, " read FAILED — serving an \
                                 EMPTY axis this round (a transient read error, NOT \
                                 a statement the subject has no testimony; the \
                                 requester re-pulls next round) (CIRISEdge#462/#429)"
                            )
                        );
                        Vec::new()
                    }
                }
            };
        }
        // v18 — a row that cleared every gate but would not content-hash was a
        // bare `if let Some(..)`: absent from the Pull with no trace. The
        // advertise twins book the identical failure (`advertise_since`,
        // `list_attestations`); these sites now mirror them.
        let book_unhashable = |detail: &str| {
            self.withhold(
                crate::observability::WithholdReason::RowNotSerializable,
                subject_key_id,
                detail,
            );
        };
        match kind {
            EnvelopeKind::Key => {
                match self.directory.lookup_public_key(subject_key_id).await {
                    Ok(Some(record)) => {
                        let seq = Self::ms_seq(record.valid_from);
                        match content_hash_of(&SignedKeyRecord { record }) {
                            Some((hash, _)) => push(hash, seq),
                            None => book_unhashable("subject_holdings/key: content_hash_of failed"),
                        }
                    }
                    Ok(None) => {} // no key row for the subject — a normal absence
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            subject = %subject_key_id,
                            "subject-Pull key lookup FAILED — serving an EMPTY axis \
                             this round (transient, NOT 'no testimony') \
                             (CIRISEdge#462/#429)"
                        );
                    }
                }
            }
            EnvelopeKind::IdentityOccurrence => {
                for row in subject_read!(
                    self.directory
                        .list_signed_identity_occurrences_for(subject_key_id),
                    "identity-occurrence"
                ) {
                    let seq = Self::ms_seq(row.identity_occurrence.asserted_at);
                    match content_hash_of(&row) {
                        Some((hash, _)) => push(hash, seq),
                        None => book_unhashable("subject_holdings/idocc: content_hash_of failed"),
                    }
                }
            }
            EnvelopeKind::TransportDestination => {
                for row in subject_read!(
                    self.directory
                        .list_signed_transport_destinations_for(subject_key_id),
                    "transport-destination"
                ) {
                    let td = &row.transport_destination;
                    let seq = if td.epoch > 0 {
                        td.epoch
                    } else {
                        Self::ms_seq(td.asserted_at)
                    };
                    match content_hash_of(&row) {
                        Some((hash, _)) => push(hash, seq),
                        None => {
                            book_unhashable("subject_holdings/transport: content_hash_of failed");
                        }
                    }
                }
            }
            EnvelopeKind::IdentityOccurrenceRevocation => {
                for row in subject_read!(
                    self.directory
                        .list_signed_identity_occurrence_revocations_for(subject_key_id),
                    "identity-occurrence-revocation"
                ) {
                    let seq = Self::ms_seq(row.identity_occurrence_revocation.revoked_at);
                    match content_hash_of(&row) {
                        Some((hash, _)) => push(hash, seq),
                        None => {
                            book_unhashable("subject_holdings/idocc-rev: content_hash_of failed");
                        }
                    }
                }
            }
            EnvelopeKind::Attestation => {
                // DATA-SUBJECT axis — records ABOUT the subject (the 84-family
                // revocation-reachability set), MINUS the G2 self-non-retainable
                // scores.
                for att in subject_read!(
                    self.directory.list_attestations_for(subject_key_id),
                    "attestation (data-subject axis)"
                ) {
                    if Self::is_non_retainable_score(&att) {
                        continue;
                    }
                    let seq = Self::ms_seq(att.asserted_at);
                    match content_hash_of(&att) {
                        Some((hash, _)) => {
                            if self.pull_ref_is_serveable(&att, subject_key_id).await {
                                push(hash, seq);
                            }
                        }
                        None => book_unhashable("subject_holdings/att-for: content_hash_of failed"),
                    }
                }
                // SENDER axis — records BY the subject (authorship recovery). No
                // G2 carve (an attestation I authored is mine to recover, even a
                // `capacity:*` score I asserted about someone else) — but the SAME
                // serve gate, so a ref and its bytes always agree.
                for att in subject_read!(
                    self.directory.list_attestations_by(subject_key_id),
                    "attestation (sender axis)"
                ) {
                    let seq = Self::ms_seq(att.asserted_at);
                    match content_hash_of(&att) {
                        Some((hash, _)) => {
                            if self.pull_ref_is_serveable(&att, subject_key_id).await {
                                push(hash, seq);
                            }
                        }
                        None => book_unhashable("subject_holdings/att-by: content_hash_of failed"),
                    }
                }
            }
            // Revocation (key-level), the cohort planes (Family/Community/
            // LocationProof), the membership-revocation planes, and the
            // operational trio are not subject-scoped-pullable via this axis.
            _ => {}
        }
        refs
    }

    /// CIRISEdge#462 — may this Attestation ref be disclosed to the requester
    /// (== the subject)? A Pull answers with refs, and a ref discloses the row's
    /// existence (hash + seq), so a row the requester could not be SERVED must not
    /// be LISTED — else the Summary is an info-leak and an advertised-then-
    /// unfetchable #429.
    ///
    /// The gate is deliberately NARROWER than the advertise/`fetch_envelope_bytes_for_peer`
    /// path: it applies the E3 CONFIDENTIALITY gates (the `trace:*` plane pause,
    /// author quarantine, and the `trace:* → infra:serve` capability check) but
    /// NOT the #396 producer-advertise-consent bound (`resolve_attestation_recipient`).
    /// A peer receiving another producer's advertised attestation is #396-gated;
    /// a SUBJECT pulling its OWN testimony is not — its first-party right to obtain
    /// the rows it must act on (a conferred duty, a revocation target) overrides a
    /// producer's choice of advertise-recipients. So `delegates_to`/`trust:confers`
    /// about the subject serve unconditionally, while a `trace:*` row still
    /// requires the subject to hold `infra:serve`. `peer == subject` here (enforced
    /// by [`Self::subject_holdings`]).
    /// (Projection sweep, v18: every row this gate sees is FIRST-PARTY to the
    /// requester by construction — `subject_holdings_inner` lists only rows
    /// ABOUT or BY the subject, and `subject_holdings` pins requester == subject
    /// — so the fetch twin's first-party carve keeps `fetch_envelope_bytes_for_peer`
    /// in agreement with this LIST on every ref it discloses. No projection gate
    /// is needed here.)
    async fn pull_ref_is_serveable(&self, att: &Attestation, requester: &str) -> bool {
        let Ok(value) = serde_json::to_value(att) else {
            // An unserializable row is not disclosed — and it is BOOKED, exactly
            // as the advertise twins book the identical failure (#433: eligible
            // and not served is the ledger's definition; was a bare `false`).
            self.withhold(
                crate::observability::WithholdReason::RowNotSerializable,
                requester,
                "pull_ref_is_serveable: to_value failed",
            );
            return false;
        };
        if Self::attestation_requires_serve(&value) {
            // `trace:*` — E3 confidentiality. Withheld while the plane is paused,
            // and served only to a subject that itself holds `infra:serve`.
            if self.trace_plane_paused().await {
                // Booked via the shared #440 helper — the subject-Pull twin of
                // the advertise (:config-paused-advertise) and direct-fetch
                // (:config-paused-fetch) sites; its own throttle key so neither
                // exit can silence this one's log. Was a bare `false`.
                self.withhold_config_paused(requester, "config-paused-subject-pull");
                return false;
            }
            // `peer_has_serve_capability` books its OWN per-leg reason at the
            // deciding branch (#433) — no re-count here, same as the twins.
            if !self.peer_has_serve_capability(requester).await {
                return false;
            }
        }
        // A quarantined author's row is withheld on every path.
        if self
            .author_quarantine_withholds(&value, &mut HashMap::new(), requester)
            .await
        {
            return false;
        }
        // Workstream F — CARRIAGE is peer-independent, so the relay gate applies
        // to the subject-Pull LIST too. Without it, a Pull would DISCLOSE an
        // `accord:*` ref that `fetch_envelope_bytes_for_peer` then refuses —
        // the advertised-then-unfetchable (#429) shape this whole function
        // exists to prevent. (Unlike the #396 consent bound, there is no
        // first-party carve here: a first-party fetch still moves the accord's
        // bytes off this node, which is exactly what CC 4.2.1 scopes.)
        !self
            .accord_relay_withholds(&value, requester, "subject-pull")
            .await
    }

    /// CIRISEdge#462 — the G2 self-revocation-hole carve, resolved by CONSUMING
    /// persist's authoritative retainability ALLOWLIST (CIRISPersist#635,
    /// [`is_subject_retainable`](ciris_persist::federation::namespace::is_subject_retainable)):
    /// a data-subject-axis attestation whose DIMENSION is a score is withheld
    /// UNLESS persist affirms the subject is necessarily its author (`emit_authority`
    /// — trace:*, transport:{kind}, the substrate self-reports, …). Landing a score
    /// ABOUT me onto the node where I am the sole writer is safe only when I am its
    /// author; otherwise it conflates read-copy with write-authority (the G2 hole).
    ///
    /// This REPLACES the earlier `consent_gated_claim` (capacity-only) carve, which
    /// UNDER-carved: it withheld only the consent-gated family and let every other
    /// peer-authored score through. `is_subject_retainable` is an allowlist, so it
    /// is FAIL-CLOSED — an unknown / new / renamed scored family reads
    /// non-retainable and is carved, not silently pulled. (Consequence per #635: a
    /// family edge legitimately needs to pull that is missing from the allowlist
    /// shrinks the pull SILENTLY; that is a persist ask — tell them to add it, do
    /// not assume persist knows.)
    ///
    /// CONFERRALS ARE RETAINED BY TYPE, not by dimension: a `delegates_to` (the
    /// moderation-duty shape #462 exists to recover) is signed by the conferring
    /// authority — the subject cannot forge it, so a retained copy grants no write
    /// authority. This holds EVEN when the conferral is dimension-bearing: the
    /// `self_at_login` shape carries `dimension:
    /// "self:delegates_to:agent_occurrence:v1"` (src/edge.rs), which is NOT in
    /// persist's retainable allowlist. The subject's OWN authored scores (the sender
    /// axis) are likewise untouched — a score I authored is mine to recover.
    ///
    /// INVARIANT (corrected — Codex on #470): key the carve on the SCORES PLANE, not
    /// on has-a-dimension. The earlier "scores are dimension-bearing, conferrals are
    /// dimensionless" reading was FALSE — `self_at_login` is a dimension-bearing
    /// conferral — and the has-dimension gate would carve that delegation out of the
    /// very pull the receive axis exists to serve. The reliable discriminator is
    /// `attestation_type`: every peer-authored claim (reputation / capacity /
    /// moderation) rides `attestation_type == "scores"` with a distinguishing
    /// dimension; conferrals ride `delegates_to` / `trust:confers`. So the carve is
    /// `type == scores AND !is_subject_retainable(dimension)`. The one thing to keep
    /// true across both repos: persist keeps peer-authored claims on the scores
    /// plane and conferrals off it.
    fn is_non_retainable_score(att: &Attestation) -> bool {
        // Only the SCORES plane is carveable. A conferral (delegates_to /
        // trust:confers) is authority-signed — unforgeable by the subject — so it is
        // retained by TYPE regardless of dimension, INCLUDING the dimension-bearing
        // self_at_login shape (`self:delegates_to:agent_occurrence:v1`, src/edge.rs),
        // which is NOT in persist's retainable allowlist. Gating on the dimension
        // alone would carve that delegation OUT of the pull the receive axis exists
        // to recover (Codex on #470).
        //
        // FAIL-CLOSED on the scores axis: a scores row is carved UNLESS it carries a
        // dimension that is EXPLICITLY retainable. A scores row with an absent or
        // non-string `/dimension` (legacy / malformed) is therefore carved, not
        // served — the earlier `!is_subject_retainable(dim)` form fell OPEN on a
        // missing dimension, reopening G2 for that input (Codex on #470, round 2).
        att.attestation_type == ciris_persist::federation::types::attestation_type::SCORES
            && !att
                .attestation_envelope
                .pointer("/dimension")
                .and_then(serde_json::Value::as_str)
                .is_some_and(ciris_persist::federation::namespace::is_subject_retainable)
    }

    /// CIRISEdge#522 — **the ONE place a persist apply-door `Err` becomes an
    /// [`ApplyOutcome::Refused`]**, so a v38.2.0 door class cannot be booked at
    /// one call site and dropped at the next.
    ///
    /// Classifies via the TYPED variant ([`ApplyRefusalClass::classify`]),
    /// books the class on the reason-axis ledger when there is one, and folds
    /// the class into the message the #425 choke logs. An unclassified error
    /// takes the unchanged pre-#522 path: persist's message + its `kind()`
    /// token, counted on the kind axis at the choke like every other refusal.
    fn refuse(
        &self,
        plane: &str,
        content_hash: &str,
        err: &ciris_persist::federation::Error,
    ) -> ApplyOutcome {
        match ApplyRefusalClass::classify(err) {
            Some(class) => self.refuse_as(plane, content_hash, err, class),
            // CIRISEdge#544 — an UNCLASSIFIED persist error keeps the pre-#522
            // message AND takes the conservative retry disposition. We do not
            // know what moved it, so we may not assert that nothing will: the
            // short transient backoff bounds the cost of being wrong here, while
            // guessing terminal on an unread error would silently strand rows on
            // every plane at once.
            None => ApplyOutcome::refused(apply_refusal_reason(plane, content_hash, err)),
        }
    }

    /// [`Self::refuse`] with the class supplied by the CALLER — for the one
    /// door whose class is not derivable from the error alone
    /// ([`Self::apply_community`]: `Error::Conflict` means "roster fork" only
    /// on the Community plane).
    fn refuse_as(
        &self,
        plane: &str,
        content_hash: &str,
        err: &ciris_persist::federation::Error,
        class: ApplyRefusalClass,
    ) -> ApplyOutcome {
        if let Some(m) = self.metrics.as_ref() {
            m.inc_apply_refusal_class(class.as_str());
        }
        // CIRISEdge#544 — the class already decided this; `retry()` just says it
        // in the retry loop's vocabulary, so the "[TERMINAL — …]" prose in the
        // message and the backoff window the receiver installs are the same
        // verdict rather than two that can drift.
        ApplyOutcome::Refused {
            reason: classified_refusal_reason(plane, content_hash, err, class),
            retry: class.retry(),
        }
    }

    /// CIRISEdge#544 — fold one apply outcome into the node-wide refusal memory.
    /// Called once, at the [`StateApplier::apply_envelope_bytes`] choke, for the
    /// same reason #425 put the logging there: a per-plane call site is a
    /// per-plane opportunity to forget.
    ///
    /// # Why the key is `sha256(envelope_bytes)`
    ///
    /// The wire identity of a row IS its content hash — `sha256(serde_json::
    /// to_vec(row))` ([`content_hash_of`]) — and the serve path is persist's
    /// `signed_wire_index` point-read, which reloads and re-serializes that same
    /// row. So the bytes delivered here hash to the value the peer advertised in
    /// its Summary and the value this node put in `want` (see the module's
    /// `envelope_hash semantics` note). Hashing the DELIVERED BYTES rather than
    /// re-deriving the hash per plane keeps this one line instead of thirteen,
    /// and fails in the safe direction: if a peer ever serves bytes that do not
    /// hash to what it advertised, the key simply never matches a future want
    /// and the row stays fully re-askable.
    ///
    /// `Admitted` / `Duplicate` CLEAR rather than skip: the row is now held, so
    /// the diff drops it on its own, and any refusal history for those bytes is
    /// obsolete — leaving it would let a stale attempt count lengthen the
    /// backoff of an unrelated later refusal of the same record.
    fn remember_outcome(&self, kind: EnvelopeKind, envelope_bytes: &[u8], outcome: &ApplyOutcome) {
        use sha2::{Digest as _, Sha256};
        let hash: [u8; 32] = Sha256::digest(envelope_bytes).into();
        match outcome.retry_disposition() {
            None => self.refusal_backoff.clear(kind, &hash),
            Some(disposition) => {
                let window =
                    self.refusal_backoff
                        .record_at(kind, hash, disposition, Instant::now());
                // DEBUG: the refusal itself already WARNs at the #425 choke with
                // its reason and disposition. This line answers only "and for how
                // long will the node stop asking", which is the operator's next
                // question when a row goes quiet.
                tracing::debug!(
                    kind = ?kind,
                    envelope_hash = %hex::encode(&hash[..8]),
                    retry = disposition.as_str(),
                    backoff_secs = window.as_secs(),
                    remembered = self.refusal_backoff.len(),
                    "apply refused — the round's want will skip these bytes until the \
                     backoff window elapses (CIRISEdge#544)"
                );
            }
        }
    }

    /// CIRISEdge#544 — how many wanted hashes the refusal memory has removed
    /// from a round's `want` since construction. The witness for "the re-offer
    /// storm stopped": traffic that did not happen has no other observable.
    #[must_use]
    pub fn retry_suppressions(&self) -> usize {
        self.retry_suppressions
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#544 — how many `(plane, content hash)` rows are currently
    /// remembered as refused. Bounded by
    /// [`refusal_backoff::DEFAULT_MAX_KEYS`](super::refusal_backoff::DEFAULT_MAX_KEYS);
    /// a bound nobody can read is a bound that silently stops holding.
    #[must_use]
    pub fn refusal_memory_len(&self) -> usize {
        self.refusal_backoff.len()
    }

    /// The per-kind apply dispatch behind the #425 choke —
    /// [`StateApplier::apply_envelope_bytes`] wraps this with the #426
    /// source-peer trace and the #565 refusal counter.
    async fn dispatch_apply(&self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> ApplyOutcome {
        match kind {
            EnvelopeKind::Key => self.apply_key(envelope_bytes).await,
            EnvelopeKind::Attestation => self.apply_attestation(envelope_bytes).await,
            EnvelopeKind::Revocation => {
                let outcome = self.apply_revocation(envelope_bytes).await;
                // CIRISEdge#430 — an ADMITTED revocation is the event-driven
                // invalidation signal for cached trust verdicts (the transit
                // gate's hop cache). Fired only on admit (a refused/duplicate
                // revocation changed no trust state); the re-deserialize is
                // once per admitted revocation, a rare event. TTLs remain the
                // backstop when no observer is installed.
                if outcome.is_admitted() {
                    if let Ok(r) = serde_json::from_slice::<SignedRevocation>(envelope_bytes) {
                        if let Some(observer) = &self.revocation_observer {
                            observer(&r.revocation.revoked_key_id);
                        }
                        // Workstream F — a revoked key can be a seated accord
                        // holder or the root itself; either way its cached
                        // relay verdict is now false.
                        self.invalidate_accord_relay(&[&r.revocation.revoked_key_id]);
                        // CIRISEdge#523 — and it can be either SIDE of an
                        // owner-binding: the node whose owner is memoized, or
                        // the owner key itself (which stops conferring
                        // membership on every node it owns). `invalidate`
                        // drops both directions.
                        self.invalidate_owner_memo(&r.revocation.revoked_key_id);
                    }
                }
                outcome
            }
            EnvelopeKind::IdentityOccurrence => {
                self.apply_identity_occurrence(envelope_bytes).await
            }
            EnvelopeKind::Family => {
                let outcome = self.apply_family(envelope_bytes).await;
                // Workstream F — a family record IS the accord roster
                // (`active_roster_of` reads exactly this row's members), so an
                // admitted one moves the `signer_seated` leg for every signer
                // under that root. Re-parsed only when a gate is installed.
                if outcome.is_admitted() && self.accord_relay_gate.is_some() {
                    if let Ok(f) = serde_json::from_slice::<SignedFamily>(envelope_bytes) {
                        self.invalidate_accord_relay(&[&f.family.family_key_id]);
                    }
                }
                outcome
            }
            EnvelopeKind::Community => self.apply_community(envelope_bytes).await,
            EnvelopeKind::Organization => self.apply_organization(envelope_bytes).await,
            EnvelopeKind::OrgMembership => self.apply_org_membership(envelope_bytes).await,
            EnvelopeKind::PartnerRecord => self.apply_partner_record(envelope_bytes).await,
            EnvelopeKind::IdentityOccurrenceRevocation => {
                self.apply_identity_occurrence_revocation(envelope_bytes)
                    .await
            }
            EnvelopeKind::FamilyMembershipRevocation => {
                let outcome = self
                    .apply_family_membership_revocation(envelope_bytes)
                    .await;
                // Workstream F — a seat removal is the revocation fold
                // `active_roster_of` applies; a cached `signer_seated: true`
                // for the removed holder must not outlive it.
                if outcome.is_admitted() && self.accord_relay_gate.is_some() {
                    if let Ok(r) =
                        serde_json::from_slice::<SignedFamilyMembershipRevocation>(envelope_bytes)
                    {
                        self.invalidate_accord_relay(&[
                            &r.family_membership_revocation.family_key_id,
                            &r.family_membership_revocation.removed_identity_key_id,
                        ]);
                    }
                }
                outcome
            }
            EnvelopeKind::CommunityMembershipRevocation => {
                self.apply_community_membership_revocation(envelope_bytes)
                    .await
            }
            EnvelopeKind::LocationProof => self.apply_location_proof(envelope_bytes).await,
            EnvelopeKind::TransportDestination => {
                self.apply_transport_destination(envelope_bytes).await
            }
            EnvelopeKind::AccordQuorumEvidence => {
                self.apply_accord_quorum_evidence(envelope_bytes).await
            }
        }
    }
}

// ─── list_envelope_refs — per-kind dispatch ─────────────────────────

impl FederationDirectoryReplicationBridge {
    fn ms_seq(timestamp: chrono::DateTime<chrono::Utc>) -> u64 {
        u64::try_from(timestamp.timestamp_millis()).unwrap_or(0)
    }

    // ─── CIRISEdge#397 §1+§2 — the primary-plane since-cursor engine ───────
    //
    // Each of the 5 primary signed planes (Key / IdentityOccurrence /
    // TransportDestination / IdentityOccurrenceRevocation / Attestation) reads
    // ONE bulk `list_signed_<kind>_since(None, limit)` page per round (retiring
    // the per-subject `list_signed_records` fan-out), filters in-memory to its
    // projection subject set — the EXACT scoping the pre-#397 fan-out applied
    // (Key/IdOcc/TransportDest = SelfOwn; IdOccRevocation = Global; Attestation
    // per-record via `attestation_is_advertised`) — and advertises each row by
    // its content-hash (`sha256(serde_json::to_vec(row))`, [`content_hash_of`]),
    // which persist's `signed_wire_index` keys on, so the wire hash IS the
    // point-read key. These planes no longer cache (the point-read is the fetch).

    /// The subject set to sweep for a resolved [`Projection`]. `SelfOwn` uses
    /// the node's OWN publish set ([`Self::self_provider`] — collapsing the #257
    /// and #305 selectors, falling back to the cohort for pre-selector
    /// back-compat); `Cohort` uses the anti-entropy cohort; `Global` uses
    /// own-union-cohort, the widest set the node can enumerate, so a tombstone
    /// is never dropped when its subject exits the cohort (anti-rollback).
    fn subjects_for_projection(&self, projection: Projection) -> Vec<String> {
        match projection {
            Projection::SelfOwn => {
                let set = self.self_provider.as_ref().unwrap_or(&self.cohort);
                set()
            }
            // v36 (CIRISPersist#713 decomposition) — role-keyed (`Capability`)
            // and subject-keyed (`Subject`) audiences are NOT enumerable from a
            // roster: the narrowing happens PER RECIPIENT at send/fetch time
            // (the capability-token holder check and the data-subject's grant).
            // They therefore enumerate the same CANDIDATE set as `Cohort` and the
            // per-recipient gates cut it down — never wider than today, and those
            // gates are fail-closed.
            Projection::Cohort | Projection::Capability(_) | Projection::Subject => (self.cohort)(),
            Projection::Global => {
                let mut subjects: Vec<String> =
                    self.self_provider.as_ref().map(|p| p()).unwrap_or_default();
                subjects.extend((self.cohort)());
                subjects
            }
        }
    }

    /// CIRISEdge#397 §1+§2 — advertise a bulk since-cursor page: keep the rows
    /// `in_scope` (the plane's projection subject filter), advertise each by its
    /// content-hash ([`content_hash_of`] — `sha256(serde_json::to_vec(row))`,
    /// the exact value persist's `signed_wire_index` keys on), and dedupe by
    /// hash. No caching — [`Self::fetch_envelope_bytes`]'s point-read is the
    /// serve path for every plane but `Revocation`.
    /// v17.7.0 (persist v36 `Served*` reshape) — `content_of` names WHAT IS
    /// HASHED, separately from the row that carries the resume cursor.
    ///
    /// v36 wraps every plane as `Served<X> { <inner>, admitted_at }`. Hashing the
    /// WRAPPER folds node-local `admitted_at` into the content hash, so the
    /// advertise hash stops matching the point-read (which keys on persist's
    /// `signed_wire_index` over the SIGNED container) — an advertised-then-
    /// unfetchable split, silent on the wire and compiler-green. This is the
    /// v31 `ServedKeyRecord` lesson (`KeyAdvertiseRow`) generalized to the other
    /// 12 planes instead of re-solved 12 times: callers pass `|r| &r.<inner>`.
    ///
    /// The withhold DETAIL token still reads `advertise_since:` after the
    /// CIRISEdge#531 rename: it is a stable operator-facing key that dashboards
    /// and the ledger's key space are indexed on, and renaming a metric to match
    /// a Rust symbol is a breaking change for the people reading it.
    ///
    /// CIRISEdge#531 DEPTH — this is now ONE PAGE's projection, appending into
    /// accumulators [`Self::sweep_paged`] owns across the round's pages. The
    /// `seen` dedupe is therefore round-wide, not page-wide: the new-rows page
    /// and the rolling backfill page can legitimately overlap (a row admitted
    /// just as the backfill reaches the tail), and offering the same hash twice
    /// in one Summary would make `diff_refs` do redundant work for nothing.
    fn advertise_page_into<S, T, IN, TS, C>(
        &self,
        rows: &[S],
        in_scope: IN,
        seq_of: TS,
        content_of: C,
        refs: &mut Vec<EnvelopeRef>,
        seen: &mut HashSet<[u8; 32]>,
    ) where
        T: serde::Serialize,
        IN: Fn(&S) -> bool,
        TS: Fn(&S) -> u64,
        C: Fn(&S) -> &T,
    {
        for row in rows.iter().filter(|r| in_scope(r)) {
            let Some((hash, _bytes)) = content_hash_of(content_of(row)) else {
                // CIRISEdge#425 — a row that will not serialize is silently absent
                // from the advertise set (peers never learn it exists, so it never
                // replicates). Near-impossible for these types, but a real
                // silent-withhold if it ever fires — so it speaks.
                tracing::warn!(
                    "advertise_since: a row could not be serialized to its content \
                     hash and is OMITTED from the advertise set — it will not replicate \
                     (CIRISEdge#425)"
                );
                // CIRISEdge#433 — and it COUNTS. This is what took `&self`: a plane
                // going dark for a non-policy reason is the one withhold an
                // operator has no other way to see, since there is no peer and no
                // gate to correlate against.
                self.withhold(
                    crate::observability::WithholdReason::RowNotSerializable,
                    "<unattributed>",
                    "advertise_since: content_hash_of failed",
                );
                continue;
            };
            if !seen.insert(hash) {
                continue;
            }
            refs.push(EnvelopeRef {
                envelope_hash: hash,
                seq: seq_of(row),
            });
        }
    }

    /// Key plane — `SelfOwn` (publish-own): the node's OWN establishment records.
    /// Scope filter is the `SelfOwn` publish set.
    ///
    /// persist v32 (CIRISPersist#682) wraps each served key in
    /// `ServedKeyRecord { record, admitted_at }` — `admitted_at` is the node-local
    /// admission instant (monotonic, out of the content hash) that fixes the
    /// late-replication cursor bug (a record signed in January, admitted here in
    /// February, must not sort under January and become permanently invisible).
    /// Two consequences edge MUST honor, both invisible to the compiler:
    ///   1. the wire content hash is over the SIGNED record ONLY — the v31
    ///      `SignedKeyRecord{record}` shape — so `admitted_at` must stay OUT of it.
    ///      [`KeyAdvertiseRow`]'s `#[serde(skip)]` reproduces that exact byte shape
    ///      (pinned by `key_advertise_row_hashes_identically_to_signed_key_record`),
    ///      so the advertised hash still resolves through the content-hash fetch —
    ///      hashing the bare `ServedKeyRecord` would fold `admitted_at` in and make
    ///      every ref listed-then-unfetchable (the LIST-vs-FETCH class);
    ///   2. the resume `seq` moves from the producer's `valid_from` to the
    ///      node-local `admitted_at` — the #682 fix, so a late-admitted key sorts
    ///      by when THIS node saw it, not by a stale producer clock.
    async fn list_keys(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::SelfOwn)
            .into_iter()
            .collect();
        self.list_keys_page(Some(&subjects), window).await
    }

    /// The Key plane's since-cursor page, with the `SelfOwn` publish filter as
    /// a PARAMETER: `Some(subjects)` is the advertise view ([`Self::list_keys`]),
    /// `None` is the raw holdings view ([`Self::list_key_holdings`], #416 — the
    /// filter belongs to advertise only).
    async fn list_keys_page(
        &self,
        subjects: Option<&HashSet<String>>,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        // CIRISEdge#531 DEPTH — the row carries persist's `(pos, id)` resume
        // pair BESIDE the advertise row, because the advertise row is a
        // reshaped `KeyAdvertiseRow` (the `#[serde(skip)]` that keeps
        // `admitted_at` out of the wire hash) and so no longer HAS the served
        // wrapper's `resume_pair()`.
        self.sweep_paged(
            EnvelopeKind::Key,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_key_records_since(since, limit)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .map(|served| {
                        (
                            served.resume_pair(),
                            KeyAdvertiseRow {
                                record: served.record,
                                admitted_at: served.admitted_at,
                            },
                        )
                    })
                    .collect::<Vec<_>>()
            },
            |row: &(ResumeCursor, KeyAdvertiseRow)| row.0.clone(),
            // (`map_or(true, ..)`, not `is_none_or` — MSRV 1.75.)
            |row| subjects.map_or(true, |s| s.contains(&row.1.record.key_id)),
            |row| Self::ms_seq(row.1.admitted_at),
            // Already hash-correct: `KeyAdvertiseRow` #[serde(skip)]s admitted_at.
            |row| &row.1,
        )
        .await
    }

    /// CIRISEdge#416 (v18 sweep) — the RAW Key holdings: every key row in local
    /// state, UNFILTERED. See [`Self::list_holdings`] for why the SelfOwn
    /// publish filter must not shape the receive-diff view, and
    /// [`Self::list_attestation_holdings`] for why the page limit is the RAW
    /// configured one (relief bounds offers, never self-knowledge).
    async fn list_key_holdings(&self) -> Vec<EnvelopeRef> {
        self.list_keys_page(None, SweepWindow::Full).await
    }

    /// IdentityOccurrence plane — `SelfOwn` (publish-own): the node's OWN KEX
    /// occurrences. Scope filter is the `SelfOwn` publish set (keyed by the
    /// occurrence key_id); seq is `asserted_at`.
    async fn list_identity_occurrences(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::SelfOwn)
            .into_iter()
            .collect();
        self.list_identity_occurrences_page(Some(&subjects), window)
            .await
    }

    /// The IdentityOccurrence plane's since-cursor page — the `SelfOwn` filter
    /// as a parameter, mirroring [`Self::list_keys_page`] (#416 sweep).
    async fn list_identity_occurrences_page(
        &self,
        subjects: Option<&HashSet<String>>,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        self.sweep_paged(
            EnvelopeKind::IdentityOccurrence,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_identity_occurrences_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedIdentityOccurrence::resume_pair,
            |row| {
                subjects.map_or(true, |s| {
                    s.contains(&row.occurrence.identity_occurrence.occurrence_key_id)
                })
            },
            |row| Self::ms_seq(row.occurrence.identity_occurrence.asserted_at),
            |row| &row.occurrence,
        )
        .await
    }

    /// CIRISEdge#416 (v18 sweep) — the RAW IdentityOccurrence holdings,
    /// unfiltered. See [`Self::list_holdings`].
    async fn list_identity_occurrence_holdings(&self) -> Vec<EnvelopeRef> {
        self.list_identity_occurrences_page(None, SweepWindow::Full)
            .await
    }

    /// TransportDestination plane — `SelfOwn` (publish-own): the node's OWN
    /// reachability routes. Scope filter is the `SelfOwn` publish set (keyed by
    /// the occurrence key_id); seq is the durable supersession `epoch`
    /// (CIRISPersist#443), falling back to `asserted_at` for a pre-#443
    /// producer whose projection reads epoch 0.
    async fn list_transport_destinations(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::SelfOwn)
            .into_iter()
            .collect();
        self.list_transport_destinations_page(Some(&subjects), window)
            .await
    }

    /// The TransportDestination plane's since-cursor page — the `SelfOwn`
    /// filter as a parameter, mirroring [`Self::list_keys_page`] (#416 sweep).
    async fn list_transport_destinations_page(
        &self,
        subjects: Option<&HashSet<String>>,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        self.sweep_paged(
            EnvelopeKind::TransportDestination,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_transport_destinations_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedTransportDestination::resume_pair,
            |row| {
                subjects.map_or(true, |s| {
                    s.contains(&row.destination.transport_destination.occurrence_key_id)
                })
            },
            |row| {
                if row.destination.transport_destination.epoch > 0 {
                    row.destination.transport_destination.epoch
                } else {
                    Self::ms_seq(row.destination.transport_destination.asserted_at)
                }
            },
            |row| &row.destination,
        )
        .await
    }

    /// CIRISEdge#416 (v18 sweep) — the RAW TransportDestination holdings,
    /// unfiltered. See [`Self::list_holdings`].
    async fn list_transport_destination_holdings(&self) -> Vec<EnvelopeRef> {
        self.list_transport_destinations_page(None, SweepWindow::Full)
            .await
    }

    /// IdentityOccurrenceRevocation plane — tombstone → `Global` (anti-rollback,
    /// never out-run by the stale occurrence it retracts). Scope filter is the
    /// widest own∪cohort set (keyed by the occurrence key_id); seq is
    /// `revoked_at`.
    async fn list_identity_occurrence_revocations(
        &self,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        let subjects: HashSet<String> = self
            .subjects_for_projection(Projection::Global)
            .into_iter()
            .collect();
        self.sweep_paged(
            EnvelopeKind::IdentityOccurrenceRevocation,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_identity_occurrence_revocations_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedIdentityOccurrenceRevocation::resume_pair,
            |row| {
                subjects.contains(
                    &row.revocation
                        .identity_occurrence_revocation
                        .occurrence_key_id,
                )
            },
            |row| Self::ms_seq(row.revocation.identity_occurrence_revocation.revoked_at),
            |row| &row.revocation,
        )
        .await
    }

    // ─── v6.2.0 (#179, CIRISPersist#249 Cut D) — generic cohort fan-out ──
    //
    // The 9 per-kind blocks below collapsed into a single
    // [`Self::fan_out_for_member`] combinator + 9 call sites. The
    // structural pattern is uniform across kinds (cohort iterate → per-key
    // `list_*_for` → `persist_row_hash` decode → HashSet dedupe → wrap in
    // `Signed*` → cache + emit `EnvelopeRef`); only the per-row
    // projections (timestamp accessor, hash accessor) and the wrapper
    // differ. Persist v9.3.0 keeps the `list_*_for_member` surface
    // uniform across kinds, so one parameterized combinator replaces the
    // hand-unrolled cases without changing wire-format behavior.
    //
    // `Row`-generic by inference: the closures fix the row type per call
    // site without requiring dyn-compatibility on the directory trait.
    // Async via boxed future on the per-key fetch (the directory trait is
    // already `async_trait`-boxed).
    async fn fan_out_for_member<Row, FetchFut, F, H>(
        &self,
        subjects: Vec<String>,
        mut fetch: F,
        timestamp: impl Fn(&Row) -> chrono::DateTime<chrono::Utc>,
        hash: H,
    ) -> Vec<EnvelopeRef>
    where
        F: FnMut(String) -> FetchFut,
        FetchFut: std::future::Future<Output = Vec<Row>>,
        H: Fn(&Row) -> &str,
    {
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        for key_id in subjects {
            // #433 — keep the subject for the withhold attribution below; `fetch`
            // consumes the owned `String`.
            let subject = key_id.clone();
            // CIRISEdge#531 — the width permit, taken PER MEMBER READ. This is
            // the one plane with no `_since` cursor (persist exposes only
            // `revocations_for`), so there is no page to bound and no watermark
            // to keep; what bounds it instead is that the acquire is here, so
            // the gate holds one member's rows rather than the whole cohort's,
            // and a long cohort releases between members instead of parking the
            // FIFO queue for its whole fan-out.
            let _permit = self.sweep_gate.enter().await;
            let rows = fetch(key_id).await;
            for row in rows {
                let Some(envelope_hash) = Self::decode_hash(hash(&row)) else {
                    // CIRISEdge#433 — the row exists but its `persist_row_hash` is
                    // not 32 hex bytes, so it is absent from the advertise set and
                    // will never replicate. Was a bare `continue`; now countable.
                    // Distinct from `RowNotSerializable`: the row serializes fine,
                    // its persist-side hash is the wrong shape.
                    self.withhold(
                        crate::observability::WithholdReason::RowHashUndecodable,
                        &subject,
                        "fan_out_for_member: persist_row_hash not 32 hex bytes",
                    );
                    continue;
                };
                if !seen.insert(envelope_hash) {
                    continue;
                }
                refs.push(EnvelopeRef {
                    envelope_hash,
                    seq: Self::ms_seq(timestamp(&row)),
                });
            }
        }
        refs
    }

    /// CIRISEdge#396 item 3 — resolve a `Revocation` tombstone's wire bytes
    /// without a cache: scan the same `Global` subject set the advertise
    /// ([`Self::list_revocations`]) walks, match on `persist_row_hash`, and
    /// re-serialize the `SignedRevocation` exactly as [`Self::fan_out_for_member`]
    /// did on the advertise. A revocation is an immutable tombstone, so the
    /// re-read can never drift from what was advertised — the byte-exactness the
    /// point-read gives the indexed planes, achieved here by re-derivation.
    async fn fetch_revocation_bytes(&self, envelope_hash: &[u8; 32]) -> Option<Vec<u8>> {
        for subject in self.subjects_for_projection(Projection::Global) {
            let rows = self
                .directory
                .revocations_for(&subject)
                .await
                .unwrap_or_default();
            for row in rows {
                if Self::decode_hash(row.persist_row_hash.as_str()) == Some(*envelope_hash) {
                    return serde_json::to_vec(&SignedRevocation { revocation: row }).ok();
                }
            }
        }
        None
    }

    /// v10 — resolve ONE attestation's replication policy dynamically from its
    /// actual CEG fields (persist#425), then decide whether THIS node advertises
    /// it. The `scores`/Attestation plane is the one plane whose policy varies
    /// per record: a `dimension` (CC 2.1 — carried inside `attestation_envelope`)
    /// selects the [`namespace::authority_for`] class across all 95 families, the
    /// top-level `cohort_scope` selects the audience, and `attestation_type`
    /// selects tombstone status. `namespace::projection_for` then resolves the
    /// projection, which the list side applies exhaustively:
    ///
    /// - [`Global`](Projection::Global) — always advertise. Trust-root commons
    ///   (`provenance:build_manifest:*` and any future `AccordCoScrub` family at
    ///   a commons scope) reach the whole federation, as do every
    ///   withdraws/recants tombstone (anti-rollback).
    /// - [`Cohort`](Projection::Cohort) — advertise (hold-and-forward relay).
    /// - [`SelfOwn`](Projection::SelfOwn) — advertise **iff THIS node produced
    ///   it** (`attesting_key_id ∈ self_set`). A `self`/`family`-scoped
    ///   attestation is published by its own subject (KERI publish-own), never
    ///   relayed by a third party — the structural-invisibility discipline.
    ///
    /// Unknown/absent dimensions fall to `authority_for`'s `ProducerSteward`
    /// default and unknown scopes to `projection_for`'s `Cohort` negative
    /// default, so every record resolves (no panic, never silently GLOBAL).
    ///
    /// ── CIRISEdge#352 (pushdown verdict, persist v24.2.0) ──────────────
    ///
    /// This per-record projection deliberately stays EDGE-SIDE. #352 asked to
    /// push it into persist v17.4.0's `list_scores`, but persist itself moved
    /// first: v17.5.0 (CIRISPersist#455) split the read surfaces and made the
    /// split contractual —
    ///
    /// - `list_scores` is the CALLER-GATED consumer view (§4.3 visibility
    ///   gate on `cohort_scope`/`attested_key_id` resolved from the caller,
    ///   plus `Live`-lifecycle folding and the V106 subject join). Persist's
    ///   own `list_attestation_log` doc names wiring the sweep through it as
    ///   the CIRISEdge#336 failure shape ("silently narrows"): a relay must
    ///   see rows attested *between other parties*, which a caller-relative
    ///   gate hides.
    /// - `list_attestation_log` — the read persist DESIGNATES for
    ///   replication — carries NO projection axes by contract: "gossip policy
    ///   (what to actually advertise) lives at the consumer tier (edge
    ///   `projection_for`), never here."
    /// - `AttestationFilter` cannot express the decision anyway: it has no
    ///   `cohort_scope` axis (that axis exists only on `FederationKeyFilter`)
    ///   and composes AND-only, while this predicate is a negated conjunction
    ///   — advertise UNLESS (scope ∈ {self, family} ∧ ¬tombstone ∧ producer ∉
    ///   self_set). And the one axis it does offer, `dimension_prefixes`, is
    ///   a no-op here: `authority_for(dimension)` only picks Global-vs-Cohort,
    ///   BOTH of which advertise.
    ///
    /// The equivalence pin any future pushdown must keep green:
    /// `advertise_projection_boundary_and_ledger_are_pinned`.
    async fn list_holdings_from_rows(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        // CIRISEdge#531 DEPTH — the holdings view is the OTHER whole-table
        // read per plane per round (`want = remote ∖ holdings`), and
        // #523/v18.2.0 deliberately routed four planes' holdings to UNFILTERED
        // twins at the raw page limit — so a cursored advertise against an
        // uncursored holdings would still materialise the corpus and the fix
        // would be half. Every arm here is now PAGED.
        //
        // But NEVER watermarked: `want` is computed against this set, so a
        // partial holdings view leaves held rows in `want` forever and
        // re-fetches them every round — CIRISEdge#416's non-convergence,
        // recreated by the memory fix. `SweepWindow::Full` is the type-level
        // statement of that: pages for memory, complete in result.
        match kind {
            EnvelopeKind::Attestation => self.list_attestation_holdings().await,
            EnvelopeKind::Key => self.list_key_holdings().await,
            EnvelopeKind::IdentityOccurrence => self.list_identity_occurrence_holdings().await,
            EnvelopeKind::TransportDestination => self.list_transport_destination_holdings().await,
            _ => {
                self.list_envelope_refs_unbounded(kind, SweepWindow::Full)
                    .await
            }
        }
    }

    /// CIRISEdge#547 / CIRISPersist#780 — the holdings set read from persist's
    /// content-hash index instead of re-derived from every row.
    ///
    /// `None` means "could not read it" and the caller MUST fall back to the row
    /// path. That distinction is the whole safety of this function: `want` is
    /// `remote ∖ holdings`, so an error mistaken for an empty holdings set makes
    /// `want` mean EVERYTHING — a full re-fetch storm against every peer, from a
    /// read that merely failed. persist made the same call on its side: its
    /// default refuses rather than returning an empty vec, precisely so a
    /// set-difference consumer cannot confuse the two. `Ok(vec![])` is a real
    /// answer (the plane is genuinely empty); an `Err` never is.
    ///
    /// Pages on the CONTENT HASH, not a timestamp: the index has no time column,
    /// and its PRIMARY KEY `(kind, content_hash)` makes the hash the keyset —
    /// ordered, unique within a kind, and covered. Completeness comes from
    /// draining to a short page, exactly as the row path does.
    async fn holdings_from_wire_index(&self, index_kind: &str) -> Option<Vec<EnvelopeRef>> {
        let budget = self.sweep_page_budget().await;
        let mut refs: Vec<EnvelopeRef> = Vec::new();
        let mut after: Option<String> = None;
        for _page in 0..MAX_FULL_DRAIN_PAGES {
            // CIRISEdge#531 WIDTH — one permit per PAGE, released between pages,
            // exactly as the row drain takes it. The index read is far cheaper
            // per page but it is still a database read, and the gate bounds
            // CONCURRENT pressure, not bytes: without it every coordinator's
            // holdings read hits the store unbounded, which is the convoy
            // #547 is about arriving by a cheaper route. Caught by
            // `a_multi_page_drain_takes_one_permit_per_page`, which saw this
            // path return correct data while taking ZERO permits.
            let read = {
                let _permit = self.sweep_gate.enter().await;
                self.directory
                    .list_wire_hashes_since(index_kind, after.as_deref(), budget)
                    .await
            };
            let page = match read {
                Ok(p) => p,
                Err(e) => {
                    // Throttled, and at WARN: falling back is CORRECT but it is
                    // also the expensive path this exists to retire, so a
                    // deployment silently paying it should be able to see that.
                    tracing::warn!(
                        kind = index_kind,
                        error = %e,
                        "wire-hash holdings read failed — falling back to the ROW \
                         scan (correct, but this is the O(corpus) read CIRISEdge#547 \
                         is about). A backend predating CIRISPersist#780 reports \
                         Unsupported here."
                    );
                    return None;
                }
            };
            let served = page.len();
            for hex_hash in &page {
                let Some(h) = Self::decode_hash(hex_hash) else {
                    // A hash the index holds but edge cannot decode would silently
                    // shrink `holdings` and put a held row back in `want` forever
                    // — the #416 shape. Refuse the whole read instead.
                    tracing::warn!(
                        kind = index_kind,
                        hash = %hex_hash,
                        "wire-hash index returned an undecodable content hash — \
                         refusing the index read rather than returning a SHORT \
                         holdings set (CIRISEdge#547)"
                    );
                    return None;
                };
                // `seq` is unread on the holdings side: `diff_refs` builds its
                // local set from `envelope_hash` alone. Zero is not a lie here,
                // it is the absence of a field this axis never consults.
                refs.push(EnvelopeRef {
                    envelope_hash: h,
                    seq: 0,
                });
            }
            if served < budget as usize {
                return Some(refs);
            }
            after = page.last().cloned();
        }
        // Drained to the page cap without a short page. The row path has the same
        // guard for the same reason; a truncated holdings set is worse than a slow
        // one, so this refuses rather than returning what it has.
        tracing::warn!(
            kind = index_kind,
            pages = MAX_FULL_DRAIN_PAGES,
            "wire-hash holdings drain hit the page cap — refusing rather than \
             returning a truncated holdings set (CIRISEdge#547)"
        );
        None
    }

    /// CIRISEdge#531 (second half) — the projection of a row that the advertise
    /// gates actually consume.
    ///
    /// The gates read four strings: `cohort_scope`, `attestation_type`,
    /// `attesting_key_id`, and `attestation_envelope.dimension`. Building those
    /// directly is O(4 short strings); `serde_json::to_value` over the row was
    /// O(whole signed envelope), and the envelope is the large part.
    ///
    /// Deliberately returns a `Value` rather than changing the gates to take a
    /// typed row: the same gates are reached from the direct-fetch twin and the
    /// pull-serve path, which hold a `Value` and not an `Attestation`. Keeping
    /// one gate signature keeps the advertise and fetch answers IDENTICAL by
    /// construction — the `#429` advertised-then-unfetchable shape is exactly
    /// what a second, subtly different gate path reintroduces.
    fn advertise_gate_view(att: &ciris_persist::federation::Attestation) -> serde_json::Value {
        serde_json::json!({
            "attesting_key_id": att.attesting_key_id,
            "attestation_type": att.attestation_type,
            "cohort_scope": att.cohort_scope,
            "attestation_envelope": {
                "dimension": att.attestation_envelope.get("dimension"),
            },
        })
    }

    fn attestation_is_advertised(
        canonical_json: &serde_json::Value,
        self_set: &HashSet<String>,
    ) -> bool {
        // v17.7.0 — the field reads live in `attestation_projection` /
        // `attestation_cohort_scope` (ONE reader each). A vestigial
        // `.get("cohort_scope").unwrap_or("")` block sat here after the v36
        // refactor with its value discarded: harmless, but it is the exact
        // CIRISPersist#727 shape, and dead code is where a live bug gets
        // recruited from. Removed rather than left to be reused.
        // DECLINE a present-but-empty scope rather than projecting it. An empty
        // string is malformed data (the column is a closed set), and asking the
        // registry about it would silently pick a policy — the exact
        // "one signal covering two worlds" shape this arc has been removing.
        // Fail-closed AND loud: not advertised, and it says so.
        if Self::attestation_cohort_scope(canonical_json).is_empty() {
            tracing::warn!(
                dimension = %canonical_json
                    .pointer("/attestation_envelope/dimension")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                "attestation DECLINED from the advertise set — `cohort_scope` is \
                 present but EMPTY (malformed: the column is a closed set). A \
                 missing key means `federation` by persist's serde contract; an \
                 empty one means the row is bad (CIRISEdge v17.7.0 / CIRISPersist#713)"
            );
            return false;
        }
        // v36 (CIRISPersist#713) — one resolver for the whole family decision:
        // `Plane::Attestation { dimension }` is value-keyed, so `trace:*` resolves
        // Capability and `scores:*` resolves Subject from the TABLE rather than
        // from edge-side prose.
        match Self::attestation_projection(canonical_json) {
            // Capability/Subject rows ARE advertisable at the list level; the
            // audience narrowing is per-recipient at send/fetch (the token-holder
            // check and the subject grant), exactly as the pre-v36 overlays did.
            Projection::Global
            | Projection::Cohort
            | Projection::Capability(_)
            | Projection::Subject => true,
            Projection::SelfOwn => canonical_json
                .get("attesting_key_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|producer| self_set.contains(producer)),
        }
    }

    /// CIRISEdge#386 — the capability a peer must hold to receive `trace:*`
    /// scores-attestations (CIRISPersist#473/v18). The contextual-integrity
    /// Recipient parameter: the crossing (`enter_mesh` / `widen_audience`) consents to
    /// sharing with infrastructure blessed to SERVE, not with every cohort peer.
    ///
    /// v13.11.0 corrects the v13.10.0 token. #379 shipped a bare `"observer"`
    /// string, which is **not a federation capability token anywhere in the
    /// stack** (persist's only `observer` is the unrelated `wa_cert` WA role).
    /// The token the fleet actually confers — named by CIRISPersist#480, the
    /// CIRISServer Trust Root card, and CC 4.4.3.4.3 — is
    /// [`delegation_scope::INFRA_SERVE`]. Sourced from persist's const so the
    /// two sides cannot drift again.
    pub const SERVE_CAPABILITY: &'static str = delegation_scope::INFRA_SERVE;

    /// Do this node and `peer` share a trust root?
    ///
    /// The entitlement for a federation-cohort identifier lookup. CC 4: two
    /// nodes under one shared root cross-attest and vouch; two nodes with no
    /// shared root compose nothing. So the question is not what tier either
    /// node holds — it is whether they are in the same trust domain at all.
    ///
    /// Fail-closed on a read error; the caller logs the refusal with the
    /// requester, and an unreadable directory is already loud elsewhere.
    async fn shares_a_trust_root_with(&self, peer_key_id: &str) -> bool {
        use ciris_persist::federation::trust_root::trusted_roots_of;
        let Some(local) = self.local_key_id.as_deref() else {
            return false;
        };
        let now = chrono::Utc::now();
        let (Ok(mine), Ok(theirs)) = (
            trusted_roots_of(&*self.directory, local, now).await,
            trusted_roots_of(&*self.directory, peer_key_id, now).await,
        ) else {
            return false;
        };
        mine.iter().any(|r| theirs.contains(r))
    }

    /// Identifier lookups one peer may make per window (FSD_RATE_LIMIT §5.4).
    ///
    /// Generous for a human walking a contact list, restrictive for a script
    /// walking a fedID dictionary — which is the only distinction that matters,
    /// since the lookup cannot enumerate on its own (the requester must already
    /// know the name it asks for).
    pub const IDENTIFIER_LOOKUPS_PER_WINDOW: u32 = 60;
    /// The window those lookups refill over.
    pub const IDENTIFIER_LOOKUP_WINDOW_SECS: u64 = 60;
    /// The HOURLY ceiling, and the DAILY one. The burst quota above bounds a
    /// spike; these bound the total, which is what a directory-copying attack
    /// is actually made of.
    ///
    /// A peer that never exceeds 60/minute still walks off with 86 400 rows a
    /// day, one compliant request at a time. A slow drain is defined by its
    /// aggregate, so only an aggregate ceiling can see it.
    pub const IDENTIFIER_LOOKUPS_PER_HOUR: u32 = 600;
    /// Ditto, per day.
    pub const IDENTIFIER_LOOKUPS_PER_DAY: u32 = 2_000;
    /// How many requesting peers are tracked — a bounded key space like every
    /// other here. Peer ids are attributed, so this is a backstop rather than
    /// the control.
    pub const IDENTIFIER_LOOKUP_MAX_PEERS: usize = 16_384;

    /// CIRISEdge#379 — does this attestation row require the recipient to hold
    /// [`Self::SERVE_CAPABILITY`]? True iff its `dimension` (CC 2.1 — inside
    /// `attestation_envelope`) is in the `trace:*` namespace.
    ///
    /// ## v17.7.0 — folded onto the registry's FAMILY classifier (v36.1.0)
    ///
    /// This was edge's `dimension.starts_with("trace:")` prefix rule — a policy
    /// duplicated from persist's table, i.e. two owners for one fact. It is now
    /// persist's own `attestation_family` classifier, exported in v36.1.0 for
    /// exactly this fold (CIRISPersist#713).
    ///
    /// **It is NOT folded onto `Projection::Capability(_)`**, which the v36.0.0
    /// adopt note recommended and which edge verified is unsafe: `Capability` is
    /// the `trace:*` cell only at the COMMONS tiers; at `self` / `family` /
    /// `community` / `affiliations` the same family resolves `SelfOwn`, so a
    /// projection-keyed gate stops firing there — on the direct-fetch path,
    /// where E3 requires `infra:serve` even for a subject pulling its OWN row.
    /// The gate is a FAMILY question (is this trace content?), scope-free; the
    /// projection is a family-AND-scope answer. `AttestationFamily` is
    /// `#[non_exhaustive]`, so a future decided family is additive policy rather
    /// than a build break.
    /// Pinned both directions by
    /// `capability_and_subject_folds_match_the_replaced_overlays`.
    fn attestation_requires_serve(canonical_json: &serde_json::Value) -> bool {
        let dimension = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        // Reads `family_gates::gates_for`, not a local `matches!`. An inline
        // `matches!(.., Trace)` returns `false` for a family this build
        // predates, which SKIPS the E3 `infra:serve` gate and SERVES the row.
        // `gates_for`'s wildcard is maximally gated, so an unknown family is
        // withheld rather than served.
        crate::family_gates::gates_for(dimension).requires_serve_capability
    }

    /// v17.7.0 — the ONE reader of an attestation's `cohort_scope`.
    ///
    /// persist's `Attestation::cohort_scope` carries `default = "federation"` +
    /// `skip_serializing_if = (s == "federation")` — exact inverses, so a MISSING
    /// key means `federation`, NOT "unknown". Edge's old `unwrap_or("")`
    /// manufactured a scope the wire never carried: invisible pre-v36 (every
    /// family mapped unknown → `Cohort`) and a silent `trace:*` replication halt
    /// in v36 (the Trace family maps unknown → `SelfOwn`). Measured with persist
    /// on #713 — the backends round-trip the column; the defect was this read.
    ///
    /// A key that is PRESENT but empty is malformed data, not a policy state, and
    /// is declined by [`Self::attestation_is_advertised`] rather than projected —
    /// "absent" and "empty" must never collapse to one value again.
    fn attestation_cohort_scope(canonical_json: &serde_json::Value) -> &str {
        canonical_json.get("cohort_scope").map_or(
            ciris_persist::federation::types::cohort_scope::FEDERATION,
            |v| v.as_str().unwrap_or_default(),
        )
    }

    /// v17.7.0 (CIRISPersist#713 decomposition) — resolve an attestation's
    /// PROJECTION from the registry: `Plane::Attestation { dimension }` +
    /// cohort_scope + authority + tombstone. This replaced edge's two bespoke
    /// overlays — the `dimension.starts_with("trace:")` prefix heuristic and the
    /// hand-classified recipient-capability rule — with the one tested table.
    /// The heuristic was the "one signal covering two worlds" shape: edge
    /// asserted an audience the registry didn't know about, so the claim and the
    /// enforcement could drift. Now the registry decides WHICH audience kind
    /// applies; edge still owns the per-recipient MECHANISM (does this peer hold
    /// the token / the subject's grant), which persist does not model.
    fn attestation_projection(canonical_json: &serde_json::Value) -> Projection {
        let dimension = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        // v17.7.0 — READ THE SERDE CONTRACT, don't invent a value. persist's
        // `Attestation::cohort_scope` carries
        // `default = "federation"` + `skip_serializing_if = (s == "federation")`
        // — exact inverses, so a MISSING key means `federation`, not "unknown".
        // Edge's old `unwrap_or("")` manufactured a scope the wire never carried;
        // pre-v36 that was invisible (every family mapped unknown → Cohort), and
        // in v36 it silently halted `trace:*` replication (the Trace family maps
        // unknown → SelfOwn). Measured and confirmed with persist on #713: the
        // backends round-trip the column faithfully; the defect was this read.
        let cohort_scope = Self::attestation_cohort_scope(canonical_json);
        let attestation_type = canonical_json
            .get("attestation_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        namespace::projection_for(
            namespace::Plane::Attestation { dimension },
            cohort_scope,
            namespace::registry::authority_for(dimension).class,
            namespace::is_withdraw_or_revocation(attestation_type),
        )
    }

    /// CIRISEdge#379 — `[`Self::attestation_requires_serve`]` over WIRE bytes
    /// (BARE `Attestation`, tolerating the legacy `{"attestation": …}` wrap;
    /// parse failure → `false`). Since CIRISEdge#396 v14.2 the production
    /// fetch twin ([`Self::fetch_envelope_bytes_for_peer`]) parses the wire once
    /// and reuses the value for BOTH the #379 and item-6 gates, so this thin
    /// re-parse survives only as a test utility (`locate_trace_hash`).
    #[cfg(test)]
    fn envelope_requires_serve(bytes: &[u8]) -> bool {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return false;
        };
        let inner = v.get("attestation").unwrap_or(&v);
        Self::attestation_requires_serve(inner)
    }

    /// CIRISEdge#386 — may `peer_key_id` receive `trace:*` rows?
    ///
    /// **The gate is the trust root, not the bare capability.** We serve iff the
    /// peer's [`Self::SERVE_CAPABILITY`] is granted by a root THIS node itself
    /// trusts — persist's [`capability_roots_to_trusted_root`] (CIRISPersist#483)
    /// walks live `delegates_to(root → peer)` edges carrying the scope and, for
    /// each candidate root, evaluates `trust_root_valid` **from our own records**
    /// (live `delegates_to(us → root)`, root self-declaration, fresh
    /// `accord:lifecycle`, no halt latched).
    ///
    /// Two properties follow, both of which a bare-role check cannot give:
    /// - two nodes serve each other only under a **common** trusted root, so the
    ///   Recipient parameter is evaluated relative to the sender's own trust
    ///   rather than a global namespace; and
    /// - **un-trust is immediate and nuclear** — withdrawing our
    ///   `delegates_to(us → root)` edge stops serving every peer that rooted
    ///   through it on the very next call, with no cached flag to go stale.
    ///
    /// Any error, unknown peer, or absent local identity → `false` (fail-closed:
    /// an unresolvable recipient gets no gated rows). Because a dead gate is
    /// exactly how v13.10.0 failed, each refusal reason is logged distinctly at
    /// DEBUG (and a missing `local_key_id` at WARN, since that one is a wiring
    /// fault that would silently dark the whole plane).
    ///
    /// **Both planes are required (AND, never OR).** Alongside the trust-root
    /// walk, the peer's record must ALSO carry an accord-conferred
    /// `infra:serve` resolved through persist's self-authenticating read
    /// ([`has_accord_conferred_role`], CIRISPersist#440) — the record's scrub set must
    /// still verify to the accord family m-of-n against the live roster, with no
    /// un-superseded V104 tombstone. The two planes are deliberately not
    /// conflated (persist's `trust_root` module doc: a delegation SCOPE token
    /// inside a `delegates_to` envelope is NOT the accord-conferred ROLE on a
    /// `federation_keys` row), so requiring both means a recipient must be
    /// blessed by the accord AND rooted in a root we personally trust. An OR
    /// would have restored an accord-role bypass around the un-trust property.
    ///
    /// Consequence, accepted deliberately: the baked canonical seed still ships
    /// `roles: []` (CIRISPersist#480), so the trace plane stays dark until the
    /// fleet re-genesises with an `infra:serve`-blessed canonical. That is the
    /// intended sequencing — a plane that cannot yet flow is preferable to one
    /// that flows under a weaker gate, and unlike v13.10.0 this darkness is
    /// deliberate, logged per-leg, and covered by an ALLOW-path test.
    async fn peer_has_serve_capability(&self, peer_key_id: &str) -> bool {
        // CIRISEdge#425 Exhibit A/C — every arm below WITHHOLDS the whole trace
        // plane; each is a throttled `warn!` (a floor, not silence), and — Exhibit
        // C — a directory READ ERROR is reported as such, NOT folded into "no role"
        // (a transient failure reported as a confident statement about the peer's
        // blessing is worse than silence: it sends you looking in the wrong place).
        //
        // CIRISEdge#433 carries that same split into the LEDGER. This fn returns a
        // `bool`, which is precisely the disjunction the ledger must not report —
        // so each leg books its own reason HERE, at the branch, and the callers
        // (`fetch_envelope_bytes_for_peer`, `list_attestations`) do not re-count.
        // The counter is unthrottled even though the log is: a floor is right for
        // log volume, but a metric that under-counts is a metric that lies.
        use crate::observability::WithholdReason;
        let withhold = |reason: WithholdReason, reason_tag: &str, msg: String| {
            self.withhold(reason, peer_key_id, reason_tag);
            if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                serve_gate_withheld_log().check(&format!("{peer_key_id}:{reason_tag}"))
            {
                tracing::warn!(peer_key_id, suppressed_prev, "{msg}");
            }
        };

        // Leg A — accord plane. Re-derived from the record's own cryptography on
        // every call, so a withdrawn blessing takes effect immediately. Exhibit C:
        // split `Err` (transient read failure) from `Ok(false)` (genuinely no role).
        match has_accord_conferred_role(&*self.directory, peer_key_id, Self::SERVE_CAPABILITY).await
        {
            Ok(true) => {}
            Ok(false) => {
                withhold(
                    WithholdReason::ServeCapabilityMissing,
                    "legA-no-role",
                    "trace attestation WITHHELD (leg A) — recipient has no accord-conferred, \
                     still-verifying `infra:serve`. The fleet must re-genesis with an \
                     infra:serve-blessed canonical (CIRISPersist#480)."
                        .to_string(),
                );
                return false;
            }
            Err(e) => {
                withhold(
                    WithholdReason::ServeCapabilityReadError,
                    "legA-read-error",
                    format!(
                        "trace attestation WITHHELD (leg A) — the `infra:serve` DIRECTORY READ \
                         FAILED (fail-closed). This is a transient read error, NOT a statement \
                         that the peer lacks the role: {e}"
                    ),
                );
                return false;
            }
        }

        // Leg B — pluggable-trust-root plane.
        let Some(local) = self.local_key_id.as_deref() else {
            withhold(
                WithholdReason::LocalIdentityMissing,
                "legB-no-local-key",
                "trace attestation WITHHELD (leg B) — replication runtime has no `local_key_id`, \
                 so the CIRISEdge#386 trust-root gate cannot be evaluated. This darks the trace \
                 plane; wire ReplicationRuntimeConfig::local_key_id (CIRISServer#300)."
                    .to_string(),
            );
            return false;
        };
        match capability_roots_to_trusted_root(
            &*self.directory,
            local,
            peer_key_id,
            Self::SERVE_CAPABILITY,
        )
        .await
        {
            Ok(Some(grant)) => {
                // The SUCCESS path — routine, quiet.
                tracing::debug!(
                    peer_key_id,
                    root_key_id = %grant.root_key_id,
                    grant_attestation_id = %grant.grant_attestation_id,
                    "trace attestation permitted — recipient's `infra:serve` roots to a trusted root"
                );
                true
            }
            Ok(None) => {
                // The walk needs THREE inputs; `Ok(None)` doesn't say which is
                // absent, so enumerate them as an actionable checklist (CIRISEdge#425).
                withhold(
                    WithholdReason::ServeCapabilityNotRooted,
                    "legB-no-trusted-root",
                    format!(
                        "trace attestation WITHHELD (leg B) — recipient's `infra:serve` roots to \
                         no root this node (local_key_id={local}) trusts. One of THREE inputs is \
                         missing: (1) a scoped `delegates_to(root → {peer_key_id})` grant, (2) \
                         this node's own `delegates_to({local} → root)` trust edge, or (3) a live \
                         root charter with a pre-rotation commitment (CIRISEdge#386)."
                    ),
                );
                false
            }
            Err(e) => {
                withhold(
                    WithholdReason::TrustRootWalkError,
                    "legB-walk-error",
                    format!(
                        "trace attestation WITHHELD (leg B) — the trust-root walk FAILED \
                         (fail-closed). Transient read/verify error, not a trust verdict: {e}"
                    ),
                );
                false
            }
        }
    }

    /// CIRISEdge#396 item 6 — the `recipient_capability` serve control (the
    /// #393 gate-first pattern). True iff serving `canonical_json` to `peer`
    /// would violate a `recipient_capability` restriction the DATA PRODUCER
    /// attached to its own `consent:replication:v1` grant.
    ///
    /// **Not gated on the server.** persist's closed consent grammar
    /// ([`consent_grammar::RestrictionOp::RecipientCapability`]) is parsed +
    /// admitted today; the grammar itself documents this op as *"enforced at
    /// the SERVE layer (P3), not at promotion time"* — promotion applies no
    /// transform for it, so THIS gate is its enforcer. The server merely starts
    /// PRODUCING such restrictions later; until it does, every grant carries an
    /// empty `restrictions` set and this returns `false` (fail-open-when-absent)
    /// — the row serves exactly as before, with no window where a restriction
    /// exists but isn't enforced.
    ///
    /// The owner whose grant governs a row is its `attesting_key_id`; we read
    /// that owner's LIVE grants via [`FederationDirectory::list_live_consent_grants_by`]
    /// (persist folds `withdraws`/`recants` at write time — a revoked grant is
    /// already gone, never re-derived here). For every grant whose
    /// `attestation_prefixes` [`consent_grammar::covers`] this row's dimension,
    /// the recipient must hold each named `capability` via the SAME
    /// accord-conferred, self-re-verifying [`has_accord_conferred_role`] read the #379
    /// serve gate's leg A uses — a self-asserted `roles:[…]` entry does not
    /// satisfy it. Missing capability → withhold (fail-closed). A malformed
    /// grant parses to nothing and covers nothing (persist's whole-grant
    /// fail-closed doctrine), so it can never widen the served set.
    ///
    /// `grant_cache` memoizes each owner's parsed policies for the lifetime of
    /// one listing sweep, so a plane of same-owner rows costs one grant read.
    async fn recipient_capability_withholds(
        &self,
        canonical_json: &serde_json::Value,
        peer: &str,
        grant_cache: &mut HashMap<String, Vec<ConsentTransferPolicy>>,
    ) -> bool {
        // The row's dimension (CC 2.1 — inside `attestation_envelope`) and its
        // owner. A row with neither cannot be covered by any grant → unrestricted.
        let Some(dimension) = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(|v| v.as_str())
        else {
            return false;
        };
        let Some(owner) = canonical_json
            .get("attesting_key_id")
            .and_then(|v| v.as_str())
        else {
            return false;
        };
        if !grant_cache.contains_key(owner) {
            let policies = self
                .directory
                .list_live_consent_grants_by(owner)
                .await
                .unwrap_or_default()
                .iter()
                .filter_map(|grant| {
                    consent_grammar::parse_grant_payload(&grant.attestation_envelope).ok()
                })
                .collect();
            grant_cache.insert(owner.to_string(), policies);
        }
        // Collect required capabilities WITHOUT holding the cache borrow across
        // the `has_accord_conferred_role` awaits below.
        let required: Vec<String> = grant_cache[owner]
            .iter()
            .filter(|policy| consent_grammar::covers(&policy.attestation_prefixes, dimension))
            .flat_map(|policy| {
                policy.restrictions.iter().filter_map(|op| match op {
                    consent_grammar::RestrictionOp::RecipientCapability { capability } => {
                        Some(capability.clone())
                    }
                    // `StripField` is applied at PROMOTION (persist strips the
                    // field before the row is promoted), so it is a no-op at the
                    // serve layer. A future restriction variant lands here as a
                    // compile error — the deliberate prompt to decide whether it
                    // needs serve-side enforcement too.
                    consent_grammar::RestrictionOp::StripField { .. } => None,
                })
            })
            .collect();
        for capability in required {
            if !has_accord_conferred_role(&*self.directory, peer, &capability)
                .await
                .unwrap_or(false)
            {
                tracing::debug!(
                    peer_key_id = peer,
                    capability = %capability,
                    dimension,
                    "trace attestation withheld — recipient lacks a producer-required \
                     `recipient_capability` (CIRISEdge#396 item 6)"
                );
                // CIRISEdge#433 — booked at the branch, on the ADVERTISE side. The
                // direct-fetch twin books at its own call site (this fn is shared,
                // and each path withholds one row per call, so the two never
                // double-count a single decision).
                self.withhold(
                    crate::observability::WithholdReason::RecipientCapabilityRestriction,
                    peer,
                    dimension,
                );
                return true;
            }
        }
        false
    }

    /// CIRISEdge#440 ask 3 — is this row's AUTHOR under a live tier-2
    /// quarantine (`quarantine:withheld:v1`, persist's marker fold)?
    ///
    /// The offer-side twin of persist's own `filter_withheld_rows` serve
    /// consult (which persist applies on `list_attestation_log`, the #455
    /// relay read — but NOT on `list_attestations_since`, the read this
    /// bridge's advertise sweep uses; without this gate a quarantined author's
    /// rows would still be OFFERED). Same two properties, kept deliberately:
    ///
    /// - **The marker plane is never withheld** — a row on a quarantine marker
    ///   dimension passes unconditionally, even about a withheld author. A
    ///   marker that stops replicating cannot be folded by the rest of the
    ///   mesh, and a release that stops replicating makes a quarantine
    ///   permanent by accident.
    /// - **Rows are retained locally** — this gates the advertise/serve exits
    ///   only; [`Self::list_attestation_holdings`] (the receive-diff axis) is
    ///   untouched, which is what "withhold-from-serving, rows retained,
    ///   reversible" means.
    ///
    /// One directory read per DISTINCT author per sweep (`memo`), mirroring
    /// persist's own memo shape. Each branch books its OWN reason (#433):
    /// a withheld author books `QuarantinedAuthor`; a FAILED consult books
    /// `QuarantineReadError` and fails closed (a transient error must not
    /// leak a row the markers may withhold) — never both for one row.
    async fn author_quarantine_withholds(
        &self,
        canonical_json: &serde_json::Value,
        memo: &mut HashMap<String, QuarantineConsult>,
        peer_label: &str,
    ) -> bool {
        use crate::observability::WithholdReason;
        // The convergence carve-out: marker rows always pass.
        let dimension = canonical_json
            .pointer("/attestation_envelope/dimension")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if ciris_persist::federation::quarantine::is_marker_dimension(dimension) {
            return false;
        }
        let Some(author) = canonical_json
            .get("attesting_key_id")
            .and_then(|v| v.as_str())
        else {
            // No author to consult about — nothing to withhold on this axis.
            return false;
        };
        let consult = if let Some(c) = memo.get(author) {
            *c
        } else {
            let c = match ciris_persist::federation::quarantine::is_withheld(
                &*self.directory,
                author,
                chrono::Utc::now(),
            )
            .await
            {
                Ok(true) => QuarantineConsult::Withheld,
                Ok(false) => QuarantineConsult::Clear,
                Err(e) => {
                    if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                        serve_gate_withheld_log().check(&format!("quarantine-read:{author}"))
                    {
                        tracing::warn!(
                            author,
                            suppressed_prev,
                            error = %e,
                            "quarantine consult FAILED for a row's author — withholding \
                             the author's rows from the offer (fail-closed; a transient \
                             read error, NOT a quarantine verdict; CIRISEdge#440)"
                        );
                    }
                    QuarantineConsult::ReadError
                }
            };
            memo.insert(author.to_string(), c);
            c
        };
        match consult {
            QuarantineConsult::Clear => false,
            QuarantineConsult::Withheld => {
                self.withhold(WithholdReason::QuarantinedAuthor, peer_label, author);
                tracing::debug!(
                    author,
                    peer = peer_label,
                    "row withheld from the offer — its author is under a live \
                     quarantine:withheld marker; the row is retained locally and the \
                     withhold lifts on a release marker (CIRISEdge#440 ask 3)"
                );
                true
            }
            QuarantineConsult::ReadError => {
                self.withhold(WithholdReason::QuarantineReadError, peer_label, author);
                true
            }
        }
    }

    /// CIRISEdge#396 item 1 — resolve `peer` against this node's live consent
    /// send-set (persist's `list_consent_peers` E7 projection, revocation-folded).
    /// `Some(ResolvedRecipient)` iff consent includes it; `None` (fail-closed)
    /// when there is no `local_key_id` to resolve against, the consent view
    /// won't resolve, or the peer is not consent-included. The Attestation plane
    /// — the only consentable plane — serves a peer ONLY with a
    /// `ResolvedRecipient` in hand, so both the advertise ([`Self::list_attestations`])
    /// and the direct-fetch ([`Self::fetch_envelope_bytes_for_peer`]) paths funnel
    /// through here; a peer excluded from the listing cannot obtain an
    /// attestation by Diff/Fetch-ing its hash out-of-band.
    /// CIRISEdge#433 — each of the three `None` branches books its OWN
    /// [`crate::observability::WithholdReason`]. They are NOT interchangeable: a
    /// wiring fault (no local identity), a transient read failure, and a peer the
    /// operator genuinely did not consent to are three different things to go
    /// look at. Booked here rather than at the two call sites
    /// ([`Self::fetch_envelope_bytes_for_peer`] and [`Self::list_attestations`])
    /// because only here is the branch visible — and so a withhold is counted
    /// exactly once.
    /// Whether the authenticated `peer` is FIRST-PARTY to this attestation `inner`
    /// (the BARE wire value): its author (`attesting_key_id`), its primary subject
    /// (`attested_key_id`), or in its data-subject set (`subject_key_ids`). All three
    /// are bound into the SIGNED envelope (#643), and the link authenticates `peer`,
    /// so a match means the peer genuinely authored-or-is-the-subject-of the row.
    ///
    /// v16 review: first-party right overrides #396 producer-advertise-consent. The
    /// subject-Pull LIST gate (`pull_ref_is_serveable`) already drops #396 (a subject
    /// pulls its own testimony from a node no peer would ever advertise it to); the
    /// FETCH must AGREE, else the ref is listed-then-withheld (advertised-then-
    /// unfetchable + a disclosed ref the subject can't obtain).
    fn attestation_is_first_party_to(inner: &serde_json::Value, peer: &str) -> bool {
        let is = |field: &str| inner.get(field).and_then(serde_json::Value::as_str) == Some(peer);
        is("attesting_key_id")
            || is("attested_key_id")
            || inner
                .get("subject_key_ids")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|arr| arr.iter().any(|s| s.as_str() == Some(peer)))
    }

    async fn resolve_attestation_recipient(&self, peer: &str) -> Option<ResolvedRecipient> {
        use crate::observability::WithholdReason;
        // CIRISEdge#524 — every withhold on this path names the peer it
        // evaluated, including the one the field measured as `peer=` empty.
        let peer_label = Self::peer_label(peer);
        let Some(local) = self.local_key_id.as_deref() else {
            tracing::warn!(
                peer = peer_label,
                "attestation plane withheld — no `local_key_id` to resolve the CIRISEdge#396 \
                 consent send-set; wire ReplicationRuntimeConfig::local_key_id"
            );
            self.withhold(
                WithholdReason::LocalIdentityMissing,
                peer_label,
                "consent-send-set: no local_key_id",
            );
            return None;
        };
        let Some(set) = self.resolved_peer_set(local).await else {
            tracing::debug!(
                peer = peer_label,
                "attestation plane withheld — consent send-set unresolved (fail-closed)"
            );
            self.withhold(
                WithholdReason::SendSetUnresolved,
                peer_label,
                "list_consent_peers read failed",
            );
            return None;
        };
        let resolved = set.recipient(peer);
        match &resolved {
            // CIRISEdge#524 — the ROUTING half. The mint came through the same
            // one door either way; this only says WHICH axis put the peer in
            // the set, because "a grant naming a person reached that person's
            // node" is the thing the field could not previously see happen.
            Some(_) if set.routes_by_owner_binding(peer) && !set.names(peer) => {
                self.owner_routed_recipients
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::debug!(
                    peer = peer_label,
                    send_set_size = set.len(),
                    owner_routed = set.owner_routed_len(),
                    "attestation plane served by OWNER-BINDING: no grant names this peer, \
                     but a grant names the person it is the bound instrument of \
                     (persist `nodes_owned_by`, CIRISEdge#524)"
                );
            }
            Some(_) => {}
            None => {
                // CIRISEdge#524 — the line that must NAME the peer. See
                // [`Self::log_send_set_withhold`].
                self.log_send_set_withhold(peer, &set).await;
                self.withhold(
                    WithholdReason::RecipientNotInSendSet,
                    Self::peer_label(peer),
                    "attestation: not consent-included",
                );
            }
        }
        resolved
    }

    /// **CIRISEdge#524 — a withhold that can name its peer.**
    ///
    /// The field-measured line was
    /// `attestation plane withheld — recipient is not in this node's live
    /// consent:replication send-set (CIRISEdge#396 item 1) peer=` — with the
    /// peer EMPTY. A withhold that cannot say who it withheld from turns a
    /// five-minute diagnosis into a harness build; CIRISServer's team paid the
    /// latter. Three things changed here:
    ///
    /// 1. **The label is never empty.** An empty `peer` reaches this gate as
    ///    `<empty-peer-id>`, not as blank space — and it says so LOUDLY, because
    ///    an inbound round attributed to nobody is a WIRING fault (the link
    ///    authenticated no one) rather than a consent decision. Note the empty
    ///    id is deliberately NOT normalized to "unattributed" anywhere upstream:
    ///    `list_envelope_refs_for_peer(kind, None)` is the peer-BLIND projection
    ///    view, so mapping `""` to `None` would WIDEN what gets served.
    /// 2. **The send-set's size is stated.** `0` is a fleet-wide consent problem;
    ///    `n > 0` with no match is a per-peer addressing problem.
    /// 3. **The person/node axis is named when it is what happened.** If the
    ///    live grant projection does not name this peer but DOES name the peer's
    ///    OWNER, the operator is looking at CIRISEdge#524's routing class: a
    ///    grant naming a person — the natural thing for a consent OBJECT to
    ///    name, since consent is between people.
    ///
    /// # v18.5.0 — what an owner match MEANS now
    ///
    /// Persist v38.3.0 shipped the reverse walk (`nodes_owned_by`,
    /// CIRISPersist#764), so edge ROUTES that case: the send-set carries the
    /// grant subjects' bound nodes and [`ResolvedPeerSet::recipient`] mints for
    /// them. Reaching this branch therefore no longer means "edge cannot route
    /// a person-named grant" — it means the FORWARD walk (`owner_of`, the #523
    /// memo) and the REVERSE walk disagreed about this peer, and there are
    /// exactly two ways that happens:
    ///
    /// - the binding is not live from the reverse walk's side — an
    ///   `AmbiguousNodeOwner` candidate is SKIPPED by `nodes_owned_by` (one
    ///   poisoned node must not unroute its owner's every grant) while the
    ///   forward walk fails closed on it; or
    /// - the two memos are momentarily out of step — the owner memo re-resolved
    ///   after a binding landed while the send-set memo still serves the
    ///   pre-binding expansion (bounded by [`CONSENT_SEND_SET_MEMO_TTL`]) — or
    ///   that subject's walk ERRORED, which
    ///   [`ResolvedPeerSet::owner_walk_complete`] reports and the line states.
    ///
    /// Both are named, because they are different things to go look at. The
    /// branch stays DIAGNOSIS ONLY: it reads [`ResolvedPeerSet::names`], which
    /// cannot mint a `ResolvedRecipient`.
    ///
    /// The owner probe rides the CIRISEdge#523 memo, so a withheld round costs
    /// no extra directory walk; the WARN is throttled to a floor (never to
    /// silence) because a peer can trigger it every round.
    async fn log_send_set_withhold(&self, peer: &str, set: &ResolvedPeerSet) {
        let peer_label = Self::peer_label(peer);
        let send_set_size = set.len();
        if peer.is_empty() {
            tracing::warn!(
                peer = peer_label,
                send_set_size,
                "attestation plane withheld — the inbound round is attributed to an EMPTY \
                 peer key_id, so no consent:replication grant can ever match it. This is a \
                 WIRING fault in the host's listen loop (the peer id handed to \
                 `route_inbound_bytes`), not a consent decision (CIRISEdge#524)"
            );
            return;
        }
        // The #523 memo answers this without a fresh walk in the common case.
        // `Unowned` / `Unresolved` simply mean there is no owner story to tell.
        let owner_named = match self.owner_of_cached(peer).await {
            OwnerLookup::Owner(owner) if set.names(&owner) => Some(owner),
            _ => None,
        };
        let Some(owner) = owner_named else {
            tracing::debug!(
                peer = peer_label,
                send_set_size,
                owner_routed = set.owner_routed_len(),
                owner_walk_complete = set.owner_walk_complete(),
                "attestation plane withheld — recipient is not in this node's live \
                 consent:replication send-set (CIRISEdge#396 item 1)"
            );
            return;
        };
        if let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
            serve_gate_withheld_log().check(&format!("consent-send-set:{peer_label}"))
        {
            tracing::warn!(
                peer = peer_label,
                grant_subject = %owner,
                send_set_size,
                owner_routed = set.owner_routed_len(),
                owner_walk_complete = set.owner_walk_complete(),
                suppressed_prev,
                "attestation plane withheld — the live consent:replication send-set does NOT \
                 name this peer, but DOES name its OWNER, and the reverse owner-binding walk \
                 (persist `nodes_owned_by`, CIRISPersist#764) did NOT return this peer. Since \
                 v18.5.0 a person-named grant IS routed to that person's bound nodes, so the \
                 two walks disagreeing means one of: the node carries more than one live \
                 owner (`AmbiguousNodeOwner` — the reverse walk skips it, and an ambiguous \
                 owner is not a resolvable recipient), or the owner-binding landed inside the \
                 send-set memo window and routes next round, or `owner_walk_complete=false` \
                 (this subject's walk errored and its nodes are fail-closed OUT this round). \
                 A grant naming the peer NODE (CIRISServer#472) sidesteps all three \
                 (CIRISEdge#524, CIRISEdge#396 item 1)"
            );
        }
    }

    /// CIRISEdge#524 — a peer id that is always safe to print. An EMPTY id is
    /// the measured failure (`peer=` with nothing after it), and it is a
    /// distinct thing from an ABSENT one — hence a distinct label, never the
    /// `<unattributed>` the `None` paths use.
    fn peer_label(peer: &str) -> &str {
        if peer.is_empty() {
            "<empty-peer-id>"
        } else {
            peer
        }
    }

    /// CIRISEdge#400 — the memoized consent send-set. Returns the live
    /// `list_consent_peers(local)` projection, re-reading persist only when the
    /// memo is empty or older than [`CONSENT_SEND_SET_MEMO_TTL`]. A round's
    /// advertise + N `fetch_envelope_bytes_for_peer` calls therefore share ONE
    /// read instead of N (the v14.2.0 regression that blew the round budget),
    /// while a between-round withdraw still re-resolves next round. `None` (the
    /// caller fails closed) only on a directory error. The `Arc`-backed
    /// [`ResolvedPeerSet`] makes the memo-hit clone O(1); the `std` mutex is
    /// never held across the `await`.
    ///
    /// # CIRISEdge#524 — the memo now covers the owner-binding walk too
    ///
    /// The set is the consent subjects PLUS their bound nodes
    /// ([`Self::nodes_owned_by_grant_subjects`]), so the memo saves the more
    /// expensive read as well. Two honest consequences:
    ///
    /// - **Freshness is TTL + event, not exact.** An owner-binding ADMITTED on
    ///   the apply path drops this memo ([`Self::invalidate_owner_memo`]), so
    ///   the common case is exact. What the TTL still backstops is what no
    ///   apply event announces: a binding whose `expires_at` passes, a CC
    ///   3.4.12 `valid_until` that lapses, and a binding admitted by some path
    ///   that does not run through the bridge's apply loop. Bounded by
    ///   [`CONSENT_SEND_SET_MEMO_TTL`], i.e. under one round.
    /// - **A PARTIAL walk is memoized.** If a subject's walk errors, the
    ///   narrower set is still stored (with `owner_walk_complete = false`)
    ///   rather than re-read per envelope. Not caching it would re-create
    ///   CIRISEdge#400's per-envelope re-resolution inside the reply assembly —
    ///   the harder-won lesson — and the stale value here is NARROWER than the
    ///   truth, which is the fail-closed direction and self-heals at the next
    ///   refresh. This is the one place this file's rule differs from #523's
    ///   "never cache a failure", and the difference is deliberate: #523 caches
    ///   ONE node's verdict (a cached failure pins that node dark), while this
    ///   caches a SET whose failure only omits members.
    async fn resolved_peer_set(&self, local: &str) -> Option<ResolvedPeerSet> {
        if let Ok(memo) = self.consent_memo.lock() {
            if let Some((set, resolved_at)) = memo.as_ref() {
                if resolved_at.elapsed() < CONSENT_SEND_SET_MEMO_TTL {
                    return Some(set.clone());
                }
            }
        }
        let peers = match self.directory.list_consent_peers(local).await {
            Ok(peers) => peers,
            Err(e) => {
                tracing::debug!(error = %e, "consent send-set read failed (fail-closed)");
                return None;
            }
        };
        // CIRISEdge#524 — resolve the grant subjects' bound nodes BEFORE the
        // set is minted, so `recipient` stays the one door and stays pure.
        let (owned_nodes, complete) = self.nodes_owned_by_grant_subjects(&peers).await;
        let set = ResolvedPeerSet::from_consent_peers(peers)
            .widened_by_owner_binding(owned_nodes, complete);
        if let Ok(mut memo) = self.consent_memo.lock() {
            *memo = Some((set.clone(), Instant::now()));
        }
        Some(set)
    }

    /// **CIRISEdge#524 — the send-set's owner-binding walk** (persist v38.3.0
    /// `nodes_owned_by`, CIRISPersist#764): every node the grant subjects are
    /// the single responsible owner of, so a grant naming a PERSON routes to
    /// that person's bound nodes.
    ///
    /// Returns `(owned_nodes, complete)`. `complete = false` means at least one
    /// subject's walk errored, so the widening is NARROWER than consent
    /// authorizes — the fail-closed direction, booked (never silent) and
    /// self-healing at the next memo refresh.
    ///
    /// # Cost, and where it is paid
    ///
    /// One `nodes_owned_by` per grant subject, per memo refresh — i.e. about
    /// ONCE PER ROUND for the whole round's advertise + N fetches, because it
    /// runs inside [`Self::resolved_peer_set`] behind
    /// [`CONSENT_SEND_SET_MEMO_TTL`]. Doing it per-peer at the serve site would
    /// have re-created CIRISEdge#400 (the per-envelope re-resolution that blew
    /// the round budget) on a walk that is strictly more expensive than the one
    /// #400 was about.
    ///
    /// EVERY subject is walked, including one that is itself a node: which
    /// subjects can own a node is persist's question, and pre-filtering by
    /// identity type here would be edge re-deriving a rule it does not own —
    /// and would silently narrow routing if the rule ever widened. A node
    /// subject's walk is simply empty.
    async fn nodes_owned_by_grant_subjects(&self, subjects: &[String]) -> (Vec<String>, bool) {
        let mut owned = Vec::new();
        let mut complete = true;
        for subject in subjects {
            self.owner_route_walks
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match ciris_persist::federation::admission::nodes_owned_by(
                &*self.directory as &dyn ciris_persist::federation::FederationDirectory,
                subject,
            )
            .await
            {
                Ok(nodes) => owned.extend(nodes),
                Err(e) => {
                    complete = false;
                    tracing::debug!(
                        grant_subject = %subject,
                        error = %e,
                        "the consent send-set's owner-binding walk failed for this grant \
                         subject — its bound nodes are NOT routed this round (fail-closed, \
                         CIRISEdge#524)"
                    );
                    // The #523 borrow discipline: `WithholdReason` is a closed
                    // operator vocabulary, no variant names the owner walk, and
                    // widening it is not this change's to make. This is the
                    // closest variant in KIND — "the audience projection could
                    // not be READ" — and the detail names the true branch. The
                    // subject is booked as the entity that failed to resolve,
                    // because no single PEER is responsible for this narrowing.
                    self.withhold(
                        crate::observability::WithholdReason::SendSetUnresolved,
                        Self::peer_label(subject),
                        "nodes_owned_by unresolved — this grant subject's bound nodes are \
                         not in the send-set (CIRISEdge#524)",
                    );
                }
            }
        }
        (owned, complete)
    }

    /// CIRISEdge#416 — the RAW Attestation holdings: the content-hash of EVERY
    /// federation-tier attestation in local state, with NO `attestation_is_advertised`
    /// projection filter, NO `self_set`, NO recipient gates. This is the RECEIVE
    /// axis's "what do I hold" — distinct from [`Self::list_attestations`]'s "what
    /// would I advertise". Using the advertise view for the round's
    /// `want = remote ∖ holdings` diff meant a held-but-not-advertised row (a
    /// `self`/`family` attestation from ANOTHER producer, which projects `SelfOwn`
    /// and is advertised only by its own producer) was permanently absent from the
    /// node's own holdings view — so it stayed in `want` every round and the round
    /// never converged (CIRISAgent#932 responder-driver stall). The convergence
    /// invariant this restores: after admitting an attestation, its hash is here.
    /// Cheaper than the advertise sweep — it drops the per-row projection resolution.
    ///
    /// CIRISEdge#531 DEPTH — PAGED but never watermarked. The result set is
    /// still COMPLETE (every held hash, every round); what changed is that the
    /// rows are read a page at a time and each page's rows are dropped before
    /// the next, so peak memory is one page of rows plus the (40-byte-per-row)
    /// ref set instead of the whole corpus. Watermarking THIS view would put
    /// held-but-unlisted rows back in `want` forever — #416 by a new door — so
    /// the window here is hard-coded [`SweepWindow::Full`], not a parameter a
    /// caller could get wrong.
    async fn list_attestation_holdings(&self) -> Vec<EnvelopeRef> {
        let budget = self.sweep_page_budget().await;
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut since: Option<ResumeCursor> = None;
        for page in 0..MAX_FULL_DRAIN_PAGES {
            let (served, last) = {
                // CIRISEdge#531 — one permit per PAGE, released between pages,
                // so a many-page drain does not hold the FIFO-fair gate for the
                // whole plane and queue every other coordinator behind it.
                let _permit = self.sweep_gate.enter().await;
                let attestations = self
                    .directory
                    .list_attestations_since(since.clone(), budget)
                    .await
                    .unwrap_or_default();
                self.record_page(attestations.len());
                self.attestation_holdings_page_into(&attestations, &mut refs, &mut seen);
                (
                    attestations.len(),
                    attestations
                        .last()
                        .map(ciris_persist::federation::ServedAttestation::resume_pair),
                )
            };
            if served < budget as usize {
                break;
            }
            if last.is_none() || last == since {
                tracing::warn!(
                    budget,
                    "Attestation holdings drain CANNOT ADVANCE — a full page came \
                     back with no new resume cursor; this round's holdings view is \
                     truncated (CIRISEdge#531)"
                );
                break;
            }
            since = last;
            if page + 1 == MAX_FULL_DRAIN_PAGES {
                tracing::warn!(
                    pages = MAX_FULL_DRAIN_PAGES,
                    budget,
                    "Attestation holdings drain hit the page CAP — this round's holdings \
                     view is TRUNCATED, so held rows past the cap are re-wanted from peers \
                     (wasteful, self-correcting). Raise `sweep_page_rows` (CIRISEdge#531)"
                );
            }
        }
        refs
    }

    /// CIRISEdge#531 DEPTH — one holdings page's rows → refs. Split out of
    /// [`Self::list_attestation_holdings`] so the page loop reads as a loop.
    fn attestation_holdings_page_into(
        &self,
        attestations: &[ciris_persist::federation::ServedAttestation],
        refs: &mut Vec<EnvelopeRef>,
        seen: &mut HashSet<[u8; 32]>,
    ) {
        for att in attestations {
            // Skip only an unparseable/unhashable row (never a projection filter).
            let Some((hash, _bytes)) = content_hash_of(&att.attestation) else {
                // v18 (#433) — the sibling advertise sweep (`list_attestations`)
                // books this identical failure; a bare `continue` here made the
                // HOLDINGS view silently blind to a held row, which re-enters it
                // into `want` every round (the #416 non-convergence shape, by a
                // different door).
                self.withhold(
                    crate::observability::WithholdReason::RowNotSerializable,
                    "<unattributed>",
                    "list_attestation_holdings: content_hash_of failed",
                );
                continue;
            };
            if !seen.insert(hash) {
                continue;
            }
            refs.push(EnvelopeRef {
                envelope_hash: hash,
                seq: Self::ms_seq(att.admitted_at),
            });
        }
    }

    async fn list_attestations(
        &self,
        recipient: Option<&str>,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        // CIRISEdge#397 §1+§2 — the scores/Attestation plane reads ONE bulk
        // `list_attestations_since(None, limit)` page per round. That surface is
        // already **federation-tier only** (the E5 invariant) and cursored on the
        // VISIBILITY timestamp `COALESCE(promoted_at, asserted_at)` — so a
        // consent-promoted trace (§2) is included the moment it becomes
        // federation-visible, retiring the per-subject about/by sweep.
        //
        // The per-record policy is UNCHANGED: each attestation's projection is
        // resolved from its ACTUAL dimension (all 95 families), cohort_scope, and
        // attestation_type via [`Self::attestation_is_advertised`] — a trust-root
        // build-manifest reaches the whole federation, a self/family attestation
        // is published-own, a withdraws tombstone gossips GLOBAL. The #379 trace
        // RECIPIENT serve gate is likewise preserved verbatim.
        //
        // The wire hash is the BARE `Attestation`'s content-hash
        // ([`content_hash_of`]) — the exact bytes persist's `signed_wire_index`
        // keys on and its point-read serves; the plane no longer caches.
        // CIRISEdge#396 item 1 — the consent-membership fan-out bound (the
        // by-construction funnel; the Attestation plane is the ONLY consentable
        // plane). Edge advertises attestations to a peer ONLY if persist's live
        // consent projection includes it. Resolved once per sweep and
        // re-resolved every sweep, so a between-round `withdraws`/`recants`
        // takes effect at the next send (nuclear un-trust). `None` recipient =
        // projection-only/local view (ungated; tests). A `Some(peer)` that does
        // not resolve withholds the WHOLE plane (fail-closed). The resulting
        // `ResolvedRecipient` (consent-membership proof) is what the per-record
        // #379 + item-6 gates operate on — serving an unresolved peer is
        // unrepresentable.
        let resolved_recipient = match recipient {
            None => None,
            Some(peer) => match self.resolve_attestation_recipient(peer).await {
                Some(resolved) => Some(resolved),
                None => return Vec::new(),
            },
        };
        let peer_label = recipient.unwrap_or("<unattributed>");
        // CIRISEdge#531 DEPTH — the per-sweep memos now outlive a single PAGE
        // and are threaded through the round's pages in one context. They were
        // always per-sweep facts ("this peer's serve capability", "the trace
        // pause", "this author's quarantine standing"); re-resolving them per
        // page would turn a bounded read into an unbounded number of directory
        // lookups — the CIRISEdge#400 shape the memos exist to prevent.
        let mut ctx = AttestationSweepCtx {
            resolved_recipient,
            self_set: self
                .self_provider
                .as_ref()
                .map(|p| p())
                .unwrap_or_default()
                .into_iter()
                .collect(),
            serve_allowed: None,
            grant_cache: HashMap::new(),
            trace_paused: self.trace_plane_paused().await,
            trace_pause_booked: false,
            quarantine_memo: HashMap::new(),
        };
        let budget = self.sweep_page_budget().await;
        let mut refs = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();

        let Some(key) = Self::watermark_key(window, EnvelopeKind::Attestation) else {
            // ── The peer-blind projection view (tests / diagnostics): COMPLETE,
            //    drained a page at a time. No peer ⇒ no watermark to keep.
            let mut since: Option<ResumeCursor> = None;
            for _ in 0..MAX_FULL_DRAIN_PAGES {
                let (served, last) = self
                    .attestation_page(
                        since.clone(),
                        budget,
                        &mut ctx,
                        peer_label,
                        &mut refs,
                        &mut seen,
                    )
                    .await;
                if served < budget as usize || last.is_none() || last == since {
                    break;
                }
                since = last;
            }
            return refs;
        };

        // ── The WATERMARKED advertise: this peer's new rows first, then a
        //    page of the rolling re-sweep with whatever budget is left.
        let head = self.sweep_head(&key);
        let (served, last) = self
            .attestation_page(head, budget, &mut ctx, peer_label, &mut refs, &mut seen)
            .await;
        if let Some(plan) = self.sweep_after_head(&key, served, budget, last) {
            let (b_served, b_last) = self
                .attestation_page(
                    plan.since,
                    plan.budget,
                    &mut ctx,
                    peer_label,
                    &mut refs,
                    &mut seen,
                )
                .await;
            self.sweep_after_backfill(&key, b_served, plan.budget, b_last);
        }
        refs
    }

    /// CIRISEdge#531 DEPTH — read ONE Attestation page and run the full
    /// per-record gate stack over it, appending into the round's accumulators.
    ///
    /// Returns `(rows_read, last_resume_cursor)` — the CURSOR facts, deliberately
    /// counted on the READ and not on the offer: the gates shape what a peer is
    /// offered, the watermark tracks what this node has LOOKED AT. Conflating
    /// them would stall the cursor on a plane whose page happens to be entirely
    /// withheld (a peer without `infra:serve` against a page of `trace:*`, which
    /// is 80% of the measured corpus), and that plane would then never advance
    /// past its first page.
    ///
    /// The sweep permit covers the read AND the gate loop, and is released
    /// before returning: the loop is where the `serde_json::Value` per row is
    /// built, so it is part of the materialisation the width bound is about.
    async fn attestation_page(
        &self,
        since: Option<ResumeCursor>,
        budget: u32,
        ctx: &mut AttestationSweepCtx,
        peer_label: &str,
        refs: &mut Vec<EnvelopeRef>,
        seen: &mut HashSet<[u8; 32]>,
    ) -> (usize, Option<ResumeCursor>) {
        let _permit = self.sweep_gate.enter().await;
        let attestations = self
            .directory
            .list_attestations_since(since, budget)
            .await
            .unwrap_or_default();
        self.record_page(attestations.len());
        let served = attestations.len();
        let last = attestations
            .last()
            .map(ciris_persist::federation::ServedAttestation::resume_pair);
        for att in &attestations {
            // CIRISEdge#531, SECOND HALF — the gates below read exactly FOUR
            // strings, and this used to hand them a full `serde_json::to_value`
            // of the whole row: ~19 fields serialised AND a deep clone of the
            // entire signed `attestation_envelope`, per row, per plane, per
            // peer, per round. On the measured corpora (14,564 and 52,125 rows)
            // across six coordinators that is the constant factor the issue
            // names — and with the cursor already bounding MEMORY (v18.7.0),
            // it is what remained on the CPU side.
            //
            // Every field is a direct read off the typed row; the envelope is
            // ALREADY a `Value`, so the one nested field is a borrow, not a
            // re-serialisation. `Attestation` carries no `rename_all`, so these
            // keys are byte-identical to what `to_value` produced and the gates
            // are untouched.
            //
            // The #433 `RowNotSerializable` withhold is gone from here because
            // it is now unreachable here — this construction cannot fail. That
            // failure CLASS is still covered: `content_hash_of` below serialises
            // the same row and withholds on failure, so a row that will not
            // serialise is still refused loudly rather than silently advertised.
            let canonical_json = Self::advertise_gate_view(&att.attestation);
            // NOTE (#433, deliberate): the projection filter below is NOT a
            // withhold. `attestation_is_advertised` defines which rows this node
            // is the publisher OF (a `self`/`family` row is published by its own
            // subject, never relayed) — a row it excludes was never eligible, so
            // counting it would flood the ledger with by-design non-events every
            // sweep and bury the gates that ARE decisions. The audit trail for
            // projection lives in `namespace::projection_for`, not here.
            if !Self::attestation_is_advertised(&canonical_json, &ctx.self_set) {
                continue;
            }
            // CIRISEdge#440 — the mesh-config pause: `feature.trace_replication`
            // relieved to 0 withholds every `trace:*` row from the advertise.
            // Booked ONCE per sweep (the decision is one per-sweep fact, not one
            // per row — the same shape the #379 serve-allowed memo takes), with
            // a named, throttled WARN; the pause lifts on the relief row's TTL
            // or a superseding row, with no operator action on this node.
            if ctx.trace_paused && Self::attestation_requires_serve(&canonical_json) {
                if !ctx.trace_pause_booked {
                    ctx.trace_pause_booked = true;
                    self.withhold_config_paused(peer_label, "config-paused-advertise");
                }
                continue;
            }
            // CIRISEdge#440 ask 3 — quarantined-author rows are withheld from
            // the offer (retained locally; markers themselves always pass).
            if self
                .author_quarantine_withholds(&canonical_json, &mut ctx.quarantine_memo, peer_label)
                .await
            {
                continue;
            }
            // Workstream F — the `accord:*` RELAY gate. `accord:*` projects
            // `Global`, which is right for carriage (a partial quorum object
            // must be holdable across a cohort span unknown at emit time) and
            // wrong as reach: CC 4.2.1 — a node that never trusted the accord
            // "is simply not reached". Withholding here keeps the advertise and
            // the direct-fetch twin in AGREEMENT, so a row this node may not
            // carry is never offered and then refused (the #429
            // advertised-then-unfetchable shape).
            // CIRISEdge#531 — THE ONE GATE THAT NEEDS THE WHOLE ROW. The relay
            // gate hands the row to persist's taking verb, which DESERIALISES it
            // to read the accord and the signer out (CIRISPersist#733) — four
            // fields cannot satisfy that, and passing the view here silently
            // withheld every accord row (caught by
            // `accord_row_is_relayed_when_the_gate_allows_and_withheld_when_it_refuses`).
            //
            // So the full materialisation is not removed, it is made LAZY: paid
            // only for rows persist's own classifier calls `accord:*`, which the
            // cheap view can decide on its own. Every other row — the vast
            // majority — never pays it.
            if Self::attestation_is_accord(&canonical_json) {
                let Ok(full_row) = serde_json::to_value(&att.attestation) else {
                    // CIRISEdge#433 — this is where `RowNotSerializable` is now
                    // reachable: an accord row that will not serialise cannot be
                    // put to the gate, so it is withheld loudly rather than
                    // relayed ungated.
                    self.withhold(
                        crate::observability::WithholdReason::RowNotSerializable,
                        peer_label,
                        "list_attestations: accord row to_value failed",
                    );
                    continue;
                };
                if self
                    .accord_relay_withholds(&full_row, peer_label, "advertise")
                    .await
                {
                    continue;
                }
            }
            // CIRISEdge#379 — RECIPIENT gate (the contextual-integrity
            // Recipient parameter): a `trace:*` scores-attestation is
            // listed for a peer ONLY if that peer's KeyRecord advertises
            // an effective `infra:serve` capability. Non-trace rows are
            // untouched; a `None` recipient (projection-only view / tests)
            // is ungated — every production provider is peer-bound
            // (`DirectoryStateAdapter::with_peer`).
            if let Some(peer) = ctx.resolved_recipient.as_ref() {
                // The peer already cleared the item-1 consent-membership bound
                // (it holds a `ResolvedRecipient`); these gates further narrow
                // WHAT this consent-included peer receives.
                if Self::attestation_requires_serve(&canonical_json) {
                    if ctx.serve_allowed.is_none() {
                        ctx.serve_allowed =
                            Some(self.peer_has_serve_capability(peer.as_str()).await);
                    }
                    if ctx.serve_allowed != Some(true) {
                        continue;
                    }
                }
                // CIRISEdge#396 item 6 — producer-declared `recipient_capability`
                // restrictions (any dimension a live grant covers, not just
                // `trace:*`). Fail-open when the producer declared none.
                if self
                    .recipient_capability_withholds(
                        &canonical_json,
                        peer.as_str(),
                        &mut ctx.grant_cache,
                    )
                    .await
                {
                    continue;
                }
            }
            let Some((hash, _bytes)) = content_hash_of(&att.attestation) else {
                // CIRISEdge#433 — cleared every gate, then could not be hashed:
                // eligible and not served, which is the ledger's exact definition.
                self.withhold(
                    crate::observability::WithholdReason::RowNotSerializable,
                    peer_label,
                    "list_attestations: content_hash_of failed",
                );
                continue;
            };
            if !seen.insert(hash) {
                continue;
            }
            refs.push(EnvelopeRef {
                envelope_hash: hash,
                seq: Self::ms_seq(att.admitted_at),
            });
        }
        (served, last)
    }

    async fn list_revocations(&self) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — key revocations project `Global` (own ∪ cohort),
        // not cohort-only RELAY, so a revocation is never out-run by the stale
        // record it retracts even after the subject exits the cohort.
        self.fan_out_for_member(
            self.subjects_for_projection(Projection::Global),
            |key_id| async move {
                self.directory
                    .revocations_for(&key_id)
                    .await
                    .unwrap_or_default()
            },
            |row| row.revoked_at,
            |row| row.persist_row_hash.as_str(),
        )
        .await
    }

    // ── CIRISEdge#504 — the 5 E4 keyless-declaration planes advertise via
    //    persist v21.1.0's SIGNED, since-cursor bulk reads ──────────────────
    //
    // v21 #502 E4 gave these planes an authority signature (`authority_key_id`
    // + hybrid scrub sigs on the `Signed*` wrapper), which edge — NOT the
    // authority — cannot produce. persist self-signs on write and now exposes
    // `list_signed_<kind>_since(since, limit) -> Vec<Signed*>` (mirroring the
    // org/orgmembership/partner reads), so edge serves those wrappers BYTE-EXACT.
    // CIRISEdge#397: the wire hash is now each wrapper's content-hash
    // ([`content_hash_of`] — `sha256(serde_json::to_vec(Signed*))`), the exact
    // value persist's `signed_wire_index` keys on for these kinds, so the
    // advertised hash IS the point-read key (fetch is the point-read, no cache).
    // This also retires the per-member `fan_out_for_member` for these 5: ONE
    // paginated read per plane per round instead of O(cohort) round-trips
    // (CIRISPersist#504 hot-path floor).
    //
    // ADVERTISE SCOPE is preserved from the pre-v21 fan_out per the §4.3
    // 14-kind table: Family / Community / LocationProof are **Cohort**-scoped
    // (filtered in-memory to rows touching a cohort member — the bulk read is
    // over edge's OWN directory, so reading-then-filtering leaks nothing), and
    // the two membership-revocation planes are **Global** (advertised whole,
    // matching the pre-v21 `subjects_for_projection(Global)` subject set).

    /// The operator-configured cohort as a set, for the Cohort-scoped advertise
    /// filters. This is the DIRECT key test — a roster entry naming a peer NODE
    /// outright — and CIRISEdge#523 leaves it exactly as it was; the owner
    /// widening in [`Self::cohort_set_with_owners`] is added BESIDE it, never
    /// in place of it.
    fn cohort_set(&self) -> HashSet<String> {
        (self.cohort)().into_iter().collect()
    }

    /// **CIRISEdge#523 — the person/node identity axis on the SERVE side.**
    ///
    /// The three Cohort-scoped planes (Family / Community / LocationProof) test
    /// roster membership against the anti-entropy cohort, and that cohort is
    /// NODE-keyed (`ReplicationPeer::peer_key_id`). A Community's or Family's
    /// members are PERSONS — owner fed-IDs — so the intersection is empty *by
    /// construction*, and the plane is unservable to exactly the entities that
    /// transport it. Measured on CIRISServer's two-node chat ladder: 0
    /// `federation_communities` rows served for a room the peer's owner is a
    /// member of, while 7 attestation rows landed on the same link in the same
    /// rounds.
    ///
    /// The fix runs in the FAVORABLE direction, so it needs no new persist
    /// surface: the requesting peer IS a node, and persist already exposes
    /// [`owner_of`](ciris_persist::federation::admission::owner_of) — the
    /// dimension-precise single owner, revocation-folded, which edge already
    /// consumes at `edge.rs`'s `key_is_own_node`. So each cohort node
    /// contributes BOTH itself and its owner to the membership test. The walk
    /// itself stays persist's (the #430 discipline: zero trust logic in edge —
    /// resolve once, cache, invalidate).
    ///
    /// Fail-closed means **do not widen**: an unresolved owner ([`OwnerLookup::Unresolved`]
    /// — read error or `AmbiguousNodeOwner`) contributes nothing, leaving the
    /// gate at its exact pre-#523 behaviour, and books a withhold so the
    /// narrowing is never silent.
    ///
    /// # The serve-side twin
    ///
    /// v18.2.0's lesson (the `SelfOwn` fetch path with no projection twin) is
    /// that an advertise gate and its direct-fetch gate must agree. These three
    /// planes have **no fetch-side gate at all**:
    /// [`Self::fetch_envelope_bytes_for_peer`] applies policy only to
    /// `EnvelopeKind::Attestation`, and every other kind resolves straight
    /// through the content-hash point-read. So the advertise filter was, and
    /// remains, the only gate — strictly NARROWER than the fetch. Widening it
    /// moves LIST toward FETCH and closes an asymmetry rather than opening one;
    /// there is no twin to widen, and this is the note that says so, so the next
    /// reader does not go looking for one.
    ///
    /// The subject-scoped Pull (`subject_holdings`) is a different axis — it
    /// pins requester == subject and is an ENTITLEMENT question, not an
    /// advertise scope — and is deliberately untouched here (its own
    /// owner-delegation follow-up is noted at that site).
    async fn cohort_set_with_owners(&self) -> HashSet<String> {
        let direct = self.cohort_set();
        // Resolve over a snapshot: the owners are inserted into the SAME set the
        // membership test reads, so iterating it while inserting is not an option.
        let mut lookups: Vec<(String, OwnerLookup)> = Vec::with_capacity(direct.len());
        for node in direct.iter().cloned().collect::<Vec<_>>() {
            let lookup = self.owner_of_cached(&node).await;
            lookups.push((node, lookup));
        }
        let (widened, unresolved) = Self::widen_cohort_by_owners(direct, lookups);
        for node in unresolved {
            // CIRISEdge#433 — booked, because a Cohort plane silently narrowing
            // back to the pre-#523 gate is precisely the invisible-withhold
            // class the ledger exists for.
            //
            // The reason BORROWS [`crate::observability::WithholdReason::SendSetUnresolved`]:
            // the enum is a closed operator vocabulary, no variant names the
            // owner walk, and widening it is not this change's to make (the same
            // borrow discipline the v18 `SelfOwn` fetch twin used for
            // `RecipientNotInSendSet`). It is the closest documented variant in
            // KIND — "the audience projection could not be READ, and a transient
            // failure is not a verdict about the peer" — and the `detail` names
            // the true branch so a ledger reader is not sent to the consent plane.
            self.withhold(
                crate::observability::WithholdReason::SendSetUnresolved,
                &node,
                "owner_of unresolved — cohort advertise falls back to the \
                 direct-key test (CIRISEdge#523)",
            );
        }
        widened
    }

    /// CIRISEdge#523 — the pure half of [`Self::cohort_set_with_owners`]: fold
    /// resolved owner lookups into the membership set, and name the nodes whose
    /// lookup failed so the caller can book them.
    ///
    /// Split out because the fail-closed rule — **`Unresolved` contributes
    /// NOTHING** — is the whole security content of this change, and it is not
    /// reachable through a `MemoryBackend` fixture (persist's single-owner
    /// admission gate refuses a second owner-binding, so `AmbiguousNodeOwner`
    /// cannot be seeded, and an in-memory directory read does not fail). Pinning
    /// it here tests the branch that decides, with the exact three inputs the
    /// field produces, instead of testing nothing and calling it covered.
    fn widen_cohort_by_owners(
        direct: HashSet<String>,
        lookups: Vec<(String, OwnerLookup)>,
    ) -> (HashSet<String>, Vec<String>) {
        let mut widened = direct;
        let mut unresolved = Vec::new();
        for (node, lookup) in lookups {
            match lookup {
                OwnerLookup::Owner(owner) => {
                    widened.insert(owner);
                }
                // A node with no owner adds nothing — and that is an ANSWER, not
                // a failure: it is the unowned self-anchor case.
                OwnerLookup::Unowned => {}
                OwnerLookup::Unresolved => unresolved.push(node),
            }
        }
        (widened, unresolved)
    }

    /// CIRISEdge#523 — `owner_of(node)` behind the round-scoped memo.
    ///
    /// The advertise sweep runs per round PER PLANE, and `owner_of` is a
    /// directory walk (persist's `live_delegation_granters` over the node's
    /// incoming `delegates_to` rows, revocation- and expiry-folded). Without a
    /// memo the three Cohort planes would pay for it three times a round, per
    /// cohort member — the exact per-envelope re-resolution CIRISEdge#400 had to
    /// undo on the consent plane. `OWNER_BINDING_MEMO_TTL` bounds staleness; the
    /// apply path invalidates on the events that move the answer.
    ///
    /// A failed resolution is NOT cached (see [`CachedOwner::owner`]).
    async fn owner_of_cached(&self, node_key_id: &str) -> OwnerLookup {
        if let Ok(cache) = self.owner_cache.lock() {
            if let Some(hit) = cache.get_fresh(node_key_id, Instant::now()) {
                return hit;
            }
        }
        // The `std` mutex is never held across the await (the #400 shape).
        self.owner_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let resolved = ciris_persist::federation::admission::owner_of(
            &*self.directory as &dyn ciris_persist::federation::FederationDirectory,
            node_key_id,
        )
        .await;
        match resolved {
            Ok(owner) => {
                if let Ok(mut cache) = self.owner_cache.lock() {
                    cache.put(node_key_id, owner.clone(), Instant::now());
                }
                owner.map_or(OwnerLookup::Unowned, OwnerLookup::Owner)
            }
            // Mirrors `edge.rs`'s `key_is_own_node` error handling exactly:
            // `AmbiguousNodeOwner` and a read error are the SAME fail-closed
            // outcome — a `self`/ownership boundary is never resolved from an
            // ambiguous owner (CIRISConstitution#23).
            Err(e) => {
                tracing::debug!(
                    node = node_key_id,
                    error = %e,
                    "owner_of unresolved — the Cohort-scoped advertise keeps the \
                     direct-key test only (CIRISEdge#523 fail-closed)"
                );
                OwnerLookup::Unresolved
            }
        }
    }

    /// CIRISEdge#523 — drop the memoized owner-binding for `key_id` and for any
    /// node it owns. Called from the apply path on the three events that move
    /// `owner_of`; see [`OWNER_BINDING_MEMO_TTL`] for what the TTL still covers.
    ///
    /// # CIRISEdge#524 — the SECOND owner-derived memo
    ///
    /// The consent send-set is now owner-derived too (its widening is
    /// `nodes_owned_by` over the grant subjects), so the same events move it
    /// and it is dropped here as well. The two directions do NOT share an
    /// invalidation KEY, which is why this is a whole-memo drop rather than a
    /// keyed one:
    ///
    /// - node → owner (#523) moves when a binding naming THAT NODE lands or
    ///   dies, and [`OwnerCache::invalidate`] can key on either endpoint;
    /// - person → nodes (#524) also moves when a binding names a node the memo
    ///   has never heard of — a NEW instrument appearing under an existing
    ///   grant subject. There is no key to evict, because the answer that
    ///   changed is the SET.
    ///
    /// Dropping the whole send-set memo costs one `list_consent_peers` plus one
    /// walk per subject on the next resolve, and only on an ownership event
    /// (rare); keeping it would leave a newly bound node dark for up to
    /// [`CONSENT_SEND_SET_MEMO_TTL`]. Same trade the #523 memo took, made in
    /// the same direction.
    fn invalidate_owner_memo(&self, key_id: &str) {
        if let Ok(mut cache) = self.owner_cache.lock() {
            cache.invalidate(key_id);
        }
        if let Ok(mut memo) = self.consent_memo.lock() {
            *memo = None;
        }
    }

    /// CIRISEdge#523 — the node whose `owner_of` an ADMITTED attestation could
    /// have moved, if any. Three shapes, and the split is deliberate:
    ///
    /// - a `delegates_to` is an owner-binding only when persist's OWN predicate
    ///   ([`is_owner_binding_envelope`](ciris_persist::federation::admission::is_owner_binding_envelope))
    ///   says so — never a locally re-derived dimension string (the capability-token
    ///   provenance rule: import the authority's predicate, don't reinvent it);
    /// - a `withdraws` / `recants` carries NO owner-binding dimension of its own
    ///   — it names the edge it retracts by `references_attestation_id` — so it
    ///   is impossible to tell from the row alone whether it retracts one. We
    ///   drop the entry for its subject regardless: a memo eviction costs one
    ///   directory walk, and the other direction is a node keeping a withdrawn
    ///   owner for a whole TTL;
    /// - everything else (`scores`, `supersedes`, …) moves nothing, so the
    ///   highest-volume plane pays only a string compare.
    fn owner_binding_touched(attestation: &Attestation) -> Option<&str> {
        use ciris_persist::federation::types::attestation_type;
        match attestation.attestation_type.as_str() {
            attestation_type::DELEGATES_TO => {
                ciris_persist::federation::admission::is_owner_binding_envelope(
                    &attestation.attestation_envelope,
                )
                .then_some(attestation.attested_key_id.as_str())
            }
            attestation_type::WITHDRAWS | attestation_type::RECANTS => {
                Some(attestation.attested_key_id.as_str())
            }
            _ => None,
        }
    }

    async fn list_families(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        // CIRISEdge#523 — plane 1 of 3. A Family's members are PERSONS; the
        // cohort is NODE-keyed. See [`Self::cohort_set_with_owners`].
        let cohort = self.cohort_set_with_owners().await;
        self.sweep_paged(
            EnvelopeKind::Family,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_families_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedFamily::resume_pair,
            |s| {
                s.family
                    .family
                    .members
                    .iter()
                    .any(|m| cohort.contains(&m.key_id))
            },
            |s| Self::ms_seq(s.family.family.founded_at),
            |s| &s.family,
        )
        .await
    }

    async fn list_communities(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        // CIRISEdge#523 — plane 2 of 3, and the one the ladder MEASURED: the
        // recipient held 0 `federation_communities` rows for a room its owner
        // is a member of. See [`Self::cohort_set_with_owners`].
        let cohort = self.cohort_set_with_owners().await;
        self.sweep_paged(
            EnvelopeKind::Community,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_communities_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedCommunity::resume_pair,
            |s| {
                s.community
                    .community
                    .members
                    .iter()
                    .any(|m| cohort.contains(&m.key_id))
            },
            |s| Self::ms_seq(s.community.community.founded_at),
            |s| &s.community,
        )
        .await
    }

    async fn list_family_membership_revocations(
        &self,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — membership revocation projects `Global`
        // (advertised whole, no cohort filter).
        self.sweep_paged(
            EnvelopeKind::FamilyMembershipRevocation,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_family_membership_revocations_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedFamilyMembershipRevocation::resume_pair,
            |_| true,
            |s| Self::ms_seq(s.revocation.family_membership_revocation.removed_at),
            |s| &s.revocation,
        )
        .await
    }

    async fn list_community_membership_revocations(
        &self,
        window: SweepWindow<'_>,
    ) -> Vec<EnvelopeRef> {
        // #311 tombstone fix — membership revocation projects `Global`
        // (advertised whole, no cohort filter).
        self.sweep_paged(
            EnvelopeKind::CommunityMembershipRevocation,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_community_membership_revocations_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedCommunityMembershipRevocation::resume_pair,
            |_| true,
            |s| Self::ms_seq(s.revocation.community_membership_revocation.removed_at),
            |s| &s.revocation,
        )
        .await
    }

    async fn list_location_proofs(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        // CIRISEdge#523 — plane 3 of 3. A LocationProof's `subject_key_id` is
        // whoever the proof is ABOUT, which for a person's presence claim is a
        // person fed-ID: the same empty intersection with a node-keyed cohort.
        // See [`Self::cohort_set_with_owners`].
        let cohort = self.cohort_set_with_owners().await;
        self.sweep_paged(
            EnvelopeKind::LocationProof,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_location_proofs_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedLocationProof::resume_pair,
            |s| cohort.contains(&s.proof.location_proof.subject_key_id),
            |s| Self::ms_seq(s.proof.location_proof.asserted_at),
            |s| &s.proof,
        )
        .await
    }

    // ── v2 operational-data list_* ─────────────────────────────────
    //
    // v2 operational kinds enumerate via persist's
    // `list_organizations_since` / `list_org_memberships_since` /
    // `list_signed_partner_records_since` (cursor + limit; CIRISPersist
    // v5.1.0 shipped the first two and v5.2.0 / #194 shipped the third
    // explicitly "for CIRISEdge#65 v2 bidirectional partner_record"
    // — closes the v2.0.0 admit-only carve-out). Each row's wire
    // `envelope_hash` is `sha256(JCS(Signed*Record))` per FSD §3.2.2 —
    // JCS-conformant, edge-defined, reproducible by any non-persist
    // CEG implementer (the §3.2.1 deferred-interop fix).
    //
    // The page limit is operator-tunable via [`BridgeConfig::operational_page_limit`];
    // default `u32::MAX` covers federations whose operational rosters
    // (orgs × memberships × licenses) fit in a single page.
    //
    // Skipping with `continue` on a row whose JCS hash can't be computed
    // is safe: the row exists in persist but won't be advertised on the
    // wire this round; the next round retries. Logging that skip is a
    // v2.0.x follow-up (matches the v1 trust-kinds' silent-skip on
    // decode_hash failure).

    async fn list_organizations(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        // CIRISEdge#397 — advertise the BARE `Organization` row's content-hash.
        // Persist's `signed_wire_index` keys `Organization` on
        // `content_hash_of(&Organization)` (the bare row `list_organizations_since`
        // returns — the row carries its own inline single-signer signature, so
        // there is NO separate signed-since surface), and its point-read reloads +
        // re-serializes that SAME bare row. Hashing the wrapper here would
        // advertise a hash the point-read can never resolve. The receiver's
        // `apply_organization` re-wraps the bare row for `put_organization`.
        self.sweep_paged(
            EnvelopeKind::Organization,
            window,
            |since, limit| async move {
                self.directory
                    .list_organizations_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedOrganization::resume_pair,
            |_| true,
            |row| Self::ms_seq(row.admitted_at),
            |row| &row.organization,
        )
        .await
    }

    async fn list_org_memberships(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        // CIRISEdge#397 — advertise the BARE `OrgMembership` row's content-hash;
        // same bare-row basis as `list_organizations` (persist indexes + reloads
        // the bare row). `apply_org_membership` re-wraps on the receive side.
        self.sweep_paged(
            EnvelopeKind::OrgMembership,
            window,
            |since, limit| async move {
                self.directory
                    .list_org_memberships_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedOrgMembership::resume_pair,
            |_| true,
            |row| Self::ms_seq(row.admitted_at),
            |row| &row.org_membership,
        )
        .await
    }

    async fn list_partner_records(&self, window: SweepWindow<'_>) -> Vec<EnvelopeRef> {
        // v2.0.1 — `partner_record` is **bidirectional**. CIRISPersist#194's
        // `list_signed_partner_records_since` returns the full
        // `SignedPartnerRecord` wrapper (row + steward_signatures + threshold).
        // CIRISEdge#397 — advertise that wrapper's content-hash
        // ([`content_hash_of`]); persist's `signed_wire_index` keys `PartnerRecord`
        // on `content_hash_of(&SignedPartnerRecord)` and its point-read reloads +
        // re-serializes the SAME wrapper, so advertise-hash == point-read here.
        self.sweep_paged(
            EnvelopeKind::PartnerRecord,
            window,
            |since, limit| async move {
                self.directory
                    .list_signed_partner_records_since(since, limit)
                    .await
                    .unwrap_or_default()
            },
            ciris_persist::federation::ServedSignedPartnerRecord::resume_pair,
            |_| true,
            |s| Self::ms_seq(s.record.partner_record.asserted_at),
            |s| &s.record,
        )
        .await
    }
}

// ─── apply_envelope_bytes — per-kind dispatch ───────────────────────

impl FederationDirectoryReplicationBridge {
    async fn apply_key(&self, bytes: &[u8]) -> ApplyOutcome {
        // #277 — route the replicated Key plane through persist's
        // upgrade-aware `apply_replicated_key_record` (CIRISPersist#375,
        // dyn-reachable on `FederationDirectory` since v13.0.1) instead of
        // the `ON CONFLICT DO NOTHING` `put_public_key`. An anchor-scrubbed
        // record now *upgrades* a stale self-signed row over anti-entropy
        // (owner_of-gated, monotonic, fail-closed) rather than being
        // silently dropped — so the KERI publish-own Key plane rides
        // replication end-to-end (retires CIRISServer#150's adopt-scrubbed
        // endpoint once the owner-cohort Key plane lands).
        //
        // CIRISEdge#425 — the typed `ReplicatedKeyOutcome` maps cleanly to
        // `ApplyOutcome`: `Inserted`/`Upgraded`/`Superseded` changed local state
        // (progress); `Unchanged` is a byte-identical duplicate (routine, quiet).
        //
        // persist v24.2.0 (CIRISPersist#565) — `Refused { reason }` now NAMES the
        // branch that fired (a closed, append-only 9-token enum), so the message
        // carries the verdict's evidence instead of the whole five-cause
        // disjunction we used to print. We key on the enum constant, never the
        // message string (the two-lists-that-disagree rule). A persist `Err` /
        // deserialize failure carry their reason. The choke point (`on_deliver`)
        // logs every non-`Admitted`; the receive-plane mirror of the #433 withhold
        // ledger counts every refusal by its token.
        match serde_json::from_slice::<SignedKeyRecord>(bytes) {
            Ok(record) => {
                let content_hash =
                    content_hash_of(&record).map_or_else(String::new, |(h, _)| hex::encode(h));
                let (outcome, refusal_token) = key_outcome_to_apply(
                    self.directory.apply_replicated_key_record(record).await,
                    &content_hash,
                );
                if let Some(token) = refusal_token {
                    if let Some(m) = &self.metrics {
                        m.inc_key_apply_refusal(token);
                    }
                }
                outcome
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("Key", bytes, &e)),
        }
    }

    async fn apply_attestation(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#397 — the wire is now the BARE `Attestation` (the shape
        // persist's content-hash index/point-read serves), so deserialize that
        // first and re-wrap; fall back to the pre-v14.1 `SignedAttestation`
        // `{"attestation": …}` wrap for a peer still on the old wire.
        let signed = serde_json::from_slice::<Attestation>(bytes)
            .map(|attestation| SignedAttestation { attestation })
            .or_else(|_| serde_json::from_slice::<SignedAttestation>(bytes));
        match signed {
            Ok(record) => {
                // Hash the BARE attestation — the value persist's content-hash
                // index (and edge's `advertise_since`) keys on (#397), so the reason
                // correlates with the offered `EnvelopeRef` AND a direct
                // `put_attestation` of the same row.
                let content_hash = content_hash_of(&record.attestation)
                    .map_or_else(String::new, |(h, _)| hex::encode(h));
                // Workstream F — the ids an ADMITTED attestation could have
                // moved a relay verdict for: its author (a seat's own row) and
                // its subject (a `delegates_to` naming the root, or a tombstone
                // over one). Cloned only when a gate is installed, so the apply
                // hot path pays nothing otherwise.
                let relay_invalidation: Option<(String, String)> =
                    self.accord_relay_gate.as_ref().map(|_| {
                        (
                            record.attestation.attesting_key_id.clone(),
                            record.attestation.attested_key_id.clone(),
                        )
                    });
                // CIRISEdge#523 — the node (if any) whose memoized `owner_of`
                // this row could move once ADMITTED. Resolved before the move
                // into `put_attestation`; `None` for every non-ownership row,
                // so the high-volume `scores` plane pays one string compare.
                let owner_invalidation: Option<String> =
                    Self::owner_binding_touched(&record.attestation).map(ToOwned::to_owned);
                // persist v38.5.0 (CIRISPersist#771) — the Attestation plane's
                // typed outcome, the twin of the Key plane's #565
                // `ReplicatedKeyOutcome` that `key_outcome_to_apply` above has
                // folded since v24.2.0. Before it, an already-held row came
                // back as `Error::Backend("UNIQUE constraint failed …")` and
                // fell through to `refuse` — so edge WARN-logged and counted a
                // refusal for a row it already had, which is the receive-side
                // half of the storm #771 measured on the canonical (7,536
                // refusals in six hours, 58% of that node's total, every one a
                // row it held). The variants are named EXPLICITLY, never
                // collapsed: upstream's own note is that folding `AlreadyHeld`
                // back into `()` at a boundary would reproduce #771 one layer
                // down, and edge's boundary is a boundary.
                match self.directory.put_attestation(record).await {
                    Ok(AttestationOutcome::Inserted) => {
                        // A NEW row — the only outcome that can have moved a
                        // cached verdict, so the only one that invalidates.
                        if let Some((author, subject)) = relay_invalidation {
                            self.invalidate_accord_relay(&[&author, &subject]);
                        }
                        if let Some(node) = owner_invalidation {
                            self.invalidate_owner_memo(&node);
                        }
                        ApplyOutcome::Admitted
                    }
                    // Byte-identical row already held: routine non-progress,
                    // exactly like `ReplicatedKeyOutcome::Unchanged`. COUNTED
                    // (`inc_duplicate(Attestation)` at the #425 choke, so it is
                    // never a silent drop) and QUIET (`on_deliver` logs
                    // Duplicate at DEBUG). No invalidation: nothing changed, so
                    // no memoized verdict can have moved.
                    Ok(AttestationOutcome::AlreadyHeld) => ApplyOutcome::Duplicate,
                    // `AttestationOutcome` is `#[non_exhaustive]`, so this arm
                    // is compulsory — and it is the MAXIMAL_UNKNOWN trap in a
                    // second location (`family_gates.rs` is the first). A
                    // future persist minor adding an outcome must NOT land here
                    // as a quiet `Admitted` (a false convergence-progress
                    // signal) or a quiet `Duplicate` (a false already-held).
                    // It is LOUD instead: a refusal naming the variant, which
                    // is the correct reading of "this node's persist told it
                    // something it was not built to understand".
                    // CIRISEdge#544 — TERMINAL: the verdict is a property of THIS
                    // BUILD's vocabulary, and the identical bytes will produce the
                    // identical unknown variant every round. The event that fixes
                    // it (adopting the persist cut) restarts the process and empties
                    // the refusal memory, so "terminal" here means exactly
                    // "until this node runs a build that understands it".
                    Ok(other) => ApplyOutcome::refused_terminal(format!(
                        "Attestation: persist returned an AttestationOutcome this edge \
                         build does not know ({other:?}); adopt the persist cut that \
                         added it — CIRISPersist#771 (content_hash={content_hash})"
                    )),
                    // persist v38.2.0 (CIRISEdge#522) — THIS is the door the
                    // cut moved. AV-45 membership now gates community/family
                    // -scoped rows here (target resolved from the producer's
                    // SIGNED envelope, no replicated-row bypass) and AV-84
                    // refuses a targeted row naming a third party. Both arrive
                    // as typed persist variants and `refuse` names + counts
                    // them; everything else keeps the pre-#522 shape.
                    Err(e) => self.refuse("Attestation", &content_hash, &e),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("Attestation", bytes, &e)),
        }
    }

    async fn apply_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(self, "Revocation", bytes, SignedRevocation, put_revocation)
    }

    async fn apply_identity_occurrence(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "IdentityOccurrence",
            bytes,
            SignedIdentityOccurrence,
            put_identity_occurrence
        )
    }

    // ── CIRISEdge#394 (E4 lockstep verdict) — edge is PASS-THROUGH on the
    // five authority-signed declaration planes ──────────────────────────
    //
    // Family / Community / FamilyMembershipRevocation /
    // CommunityMembershipRevocation / LocationProof carry an authority
    // signature persist v21.0.0+ (CIRISPersist#502 E4) verifies FAIL-CLOSED
    // at admission (hybrid Ed25519 + bound-form ML-DSA-65,
    // `HybridPolicy::Strict`, over
    // `ceg_produce_canonicalize(record.signing_envelope())`, against the
    // authority's REGISTERED pubkeys — `verify_family_admission` et al.).
    // Edge PRODUCES none of these records: no constructor of the five
    // `Signed*` wrappers exists anywhere in edge, and the pyo3
    // `apply_envelope` surface hands over PRE-SIGNED bytes from the rider.
    // So edge's lockstep duty is byte-transparency, not signing:
    //
    //   * RECEIVE (the `apply_*` below): typed deserialize → persist
    //     `put_*`. The three wrapper fields (`authority_key_id`,
    //     `scrub_signature_classical`, `scrub_signature_pqc`) flow through
    //     the typed struct unmodified; persist's gate is the admission
    //     oracle.
    //   * SERVE (`list_*` + `fetch_envelope_bytes`): served bytes come from
    //     persist's `signed_wire_index` — persist's OWN serialization of the
    //     stored row, never re-signed or re-shaped by edge.
    //
    // Pinned by `e4_*_forward_path_preserves_authority_signature` (the five
    // positive round trips, re-admission on a second node as the oracle) and
    // `e4_unsigned_declarations_refuse_at_admission` (the fail-closed half)
    // in the tests module below.
    async fn apply_family(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(self, "Family", bytes, SignedFamily, put_family)
    }

    /// persist v38.2.0 / CIRISPersist#758 (CIRISEdge#522) — the Community door
    /// stopped being an insert and became a **verdict**, so this plane leaves
    /// [`apply_signed_plane!`] behind.
    ///
    /// Three outcomes now, where the macro could only express two:
    ///
    /// - **fresh row → `Admitted`.** Unchanged.
    /// - **identical re-put → `Duplicate`.** Convergent derivation (a pair
    ///   chat mints one deterministic community per pair) means two nodes
    ///   author BYTE-IDENTICAL content and each signs as itself, so a
    ///   re-offered copy is the COMMON case, not an anomaly. persist answers
    ///   `Ok` and leaves the stored row and its first-accepted authority
    ///   signature untouched. The macro would have called that `Admitted` —
    ///   claiming anti-entropy progress on every round that re-offers a
    ///   community this node already holds, which is the "applied all N" /
    ///   "nothing moved" collapse #457 exists to prevent.
    /// - **differing roster under an occupied id → `Refused`, named.**
    ///   persist returns the TYPED
    ///   [`Error::Conflict`](ciris_persist::federation::Error::Conflict); edge
    ///   books it as [`ApplyRefusalClass::CommunityRosterFork`]. It is not
    ///   retryable (retrying spins) and must not be dropped (dropping hides a
    ///   fork). Roster CHANGES travel as supersedes, never as a differing
    ///   re-put, so this can only mean two authorities disagree about one id.
    ///
    /// # Why the pre-read, and why it is honest
    ///
    /// `put_community` returns `Result<(), Error>`: `Ok` alone cannot say
    /// whether a row was inserted or absorbed. Persist decides by comparing
    /// the stored `persist_row_hash` to the offered one; edge asks the
    /// equivalent question with the read it already has — *was this
    /// `community_key_id` occupied before we knocked?* Occupied + `Ok` is
    /// exactly persist's identical-re-put branch, because the differing branch
    /// is the `Conflict` above. Recomputing the hash here instead would
    /// re-implement `compute_persist_row_hash`'s stamping rules downstream of
    /// the authority that owns them — a second spelling that can drift.
    ///
    /// A concurrent insert between the read and the put mislabels one row
    /// `Admitted` that was really a duplicate. That is a counter's rounding,
    /// not a safety property: the stored state is whatever persist's verdict
    /// made it either way, and the honest direction (over-reporting progress
    /// once) is the one that cannot hide a fork. Communities are rare and this
    /// costs one point-read per applied community row.
    async fn apply_community(&self, bytes: &[u8]) -> ApplyOutcome {
        let record: SignedCommunity = match serde_json::from_slice(bytes) {
            Ok(r) => r,
            Err(e) => return ApplyOutcome::Deserialize(apply_deser_reason("Community", bytes, &e)),
        };
        let content_hash =
            content_hash_of(&record).map_or_else(String::new, |(h, _)| hex::encode(h));
        // Read BEFORE the put — see the doc comment. A read ERROR is not an
        // occupancy answer: fall back to `false`, which can only mislabel a
        // duplicate as admitted, never invent a refusal.
        let was_occupied = self
            .directory
            .lookup_community(&record.community.community_key_id)
            .await
            .ok()
            .flatten()
            .is_some();
        match self.directory.put_community(record).await {
            Ok(()) if was_occupied => ApplyOutcome::Duplicate,
            Ok(()) => ApplyOutcome::Admitted,
            // The FORK signal. Matched on the typed variant — edge deleted a
            // `reason.contains("conflict")` discriminator in v18.2.0 and this
            // is not the place to grow another.
            Err(e @ ciris_persist::federation::Error::Conflict(_)) => self.refuse_as(
                "Community",
                &content_hash,
                &e,
                ApplyRefusalClass::CommunityRosterFork,
            ),
            Err(e) => self.refuse("Community", &content_hash, &e),
        }
    }

    async fn apply_identity_occurrence_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "IdentityOccurrenceRevocation",
            bytes,
            SignedIdentityOccurrenceRevocation,
            put_identity_occurrence_revocation
        )
    }

    async fn apply_family_membership_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "FamilyMembershipRevocation",
            bytes,
            SignedFamilyMembershipRevocation,
            put_family_membership_revocation
        )
    }

    async fn apply_community_membership_revocation(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "CommunityMembershipRevocation",
            bytes,
            SignedCommunityMembershipRevocation,
            put_community_membership_revocation
        )
    }

    async fn apply_location_proof(&self, bytes: &[u8]) -> ApplyOutcome {
        apply_signed_plane!(
            self,
            "LocationProof",
            bytes,
            SignedLocationProof,
            put_location_proof
        )
    }

    /// CIRISEdge#474 — RECEIVE half of the accord-quorum-evidence cursor plane.
    /// This does NOT go through [`apply_signed_plane!`]: there is no `Signed*`
    /// wrapper and no `put_*`. The delivered bytes are a persist
    /// [`AccordQuorumEvidence`](ciris_persist::federation::accord_carriage::AccordQuorumEvidence)
    /// bundle; `apply_replicated_accord_evidence` **re-tallies** it against THIS
    /// node's own accord roster (never the sender's verdict), fail-closed with
    /// [`Error::AccordEvidenceUnverified`](ciris_persist::federation::Error), and
    /// is idempotent on replay. Progress (`Admitted`) iff a new participation
    /// landed OR a withdrawal tombstone was re-derived locally; a byte-identical
    /// replay (`participations_admitted == 0`, no new tombstone) is `Duplicate`,
    /// exactly as the anti-entropy loop counts one — never a silent no-op.
    async fn apply_accord_quorum_evidence(&self, bytes: &[u8]) -> ApplyOutcome {
        use ciris_persist::federation::accord_carriage::{
            AccordAdmissionEffect, AccordQuorumEvidence,
        };
        let evidence: AccordQuorumEvidence = match serde_json::from_slice(bytes) {
            Ok(e) => e,
            Err(e) => {
                return ApplyOutcome::Deserialize(apply_deser_reason(
                    "AccordQuorumEvidence",
                    bytes,
                    &e,
                ))
            }
        };
        match self
            .directory
            .apply_replicated_accord_evidence(&evidence)
            .await
        {
            Ok(admission) => {
                // v36 — the count became a typed effect. Exhaustive match (not
                // `matches!`) so a NEW variant breaks the build instead of
                // silently falling through to "duplicate".
                let novel = match admission.effect {
                    AccordAdmissionEffect::Supplied { .. } => true,
                    AccordAdmissionEffect::Duplicate => false,
                };
                if novel || !admission.withdrawals_projected.is_empty() {
                    ApplyOutcome::Admitted
                } else {
                    ApplyOutcome::Duplicate
                }
            }
            // CIRISEdge#544 — transient: this plane's refusals turn on trust
            // state (a root's standing, a seat's conferral) that is itself
            // replicating, and the cursor plane re-pulls from a watermark
            // rather than from a want-diff, so the backoff is the only rate
            // limit it has.
            Err(e) => ApplyOutcome::refused(format!(
                "AccordQuorumEvidence: admission refused (refusal={}): {e}",
                e.kind(),
            )),
        }
    }

    /// CIRISEdge#338 / CIRISPersist#443 (v17.0.0) — admit a replicated route.
    ///
    /// The wire bytes are now the SIGNED CONTAINER `SignedTransportDestination`
    /// (`{transport_destination, attesting_key_id, signed_envelope, signature}`),
    /// NOT a bare row. This closes the CIRISEdge#337 CRITICAL-2 confused-deputy:
    /// the old path deserialized a bare `TransportDestination` and wrote it with
    /// an attacker-chosen `binding_provenance = Rooted` for ANY `occurrence_key_id`,
    /// with no signature and no authority check. `put_signed_transport_destination`
    /// authenticates the whole thing in persist — the hybrid signature over
    /// `JCS(signed_envelope)` against the attesting key's PINNED federation
    /// pubkeys, then `signer_acts_for(attesting_key_id, occurrence_key_id)` (a peer
    /// cannot sign a victim's route with its own unrelated key), and
    /// `binding_provenance` is read ONLY from inside the verified envelope, never
    /// a wire field. Supersession is `(epoch, asserted_at)`-monotonic, so a
    /// replayed older frame is `Refused`, not applied.
    ///
    /// ## The `Refused { reason }` mapping (v18 — the refusal-laundering fix)
    ///
    /// Until v18 this arm returned `Admitted` for EVERY persist `Refused` — the
    /// deliberate old-`bool`-world anti-retry-storm shape — which made this the
    /// ONE plane whose refusals evaded the #425 choke: `apply_refusals_by_kind`
    /// under-counted, and a same-clock CONTENT CONFLICT read as an admit in
    /// metrics. Worse, its `reason.contains("conflict")` discriminator was DEAD:
    /// all three persist backends emit the SAME "does not supersede" reason
    /// string for a stale epoch and for a same-clock fork (the word "conflict"
    /// never appears), so every fork debug-logged as a routine stale epoch.
    ///
    /// The mapping now mirrors the Key plane's [`key_outcome_to_apply`]
    /// precedent, and NOTHING retries on any outcome (the #425 choke counts and
    /// logs; re-offering is driven by the want-diff, not by this value), so the
    /// no-retry property is kept by construction:
    ///
    /// - `Inserted` / `Superseded` → `Admitted` (state changed);
    /// - `Unchanged` → `Duplicate` (idempotent replay — was mis-counted as an
    ///   admit);
    /// - `Refused`, STALE (we hold a strictly newer `(epoch, asserted_at)`) →
    ///   `Duplicate`, DELIBERATELY: it is routine non-progress the choke logs at
    ///   DEBUG. Mapping it to `Refused` would WARN per redelivery every round —
    ///   the log-noise analogue of the retry storm — while `Duplicate` still
    ///   counts truthfully as non-admitted (`inc_duplicate`, never
    ///   `inc_applied`). This is the documented compromise;
    /// - `Refused`, SAME-CLOCK FORK (equal `(epoch, asserted_at)`, different
    ///   content — the split-truth signal) → `ApplyOutcome::Refused`, loud at
    ///   the choke AND counted on `apply_refusals_by_kind`. Because persist's
    ///   reason string cannot distinguish the two, the classification re-reads
    ///   the stored row's clock; an unreadable/absent stored row classifies to
    ///   the LOUD arm (never launder what we cannot classify).
    ///   CIRISEdge#544 — the two loud sub-arms take DIFFERENT retry
    ///   dispositions: a classified same-clock fork is terminal (the stored
    ///   clock can only move forward, after which these bytes are merely stale),
    ///   an unclassifiable one is transient (a failed re-read is not a verdict).
    ///
    /// A genuine gate failure (bad signature / unknown attesting key /
    /// not-acts-for) surfaces as `Err` from persist → `Refused`. A parse failure
    /// (a pre-v17 bare row from an un-upgraded peer) is `Deserialize` — such a
    /// peer's routes simply do not replicate until it adopts v17, which is the
    /// intended breaking behavior, not a silent bare-row admit.
    async fn apply_transport_destination(&self, bytes: &[u8]) -> ApplyOutcome {
        use ciris_persist::federation::self_at_login::{
            SignedTransportDestination, TransportDestinationApplyOutcome,
        };
        match serde_json::from_slice::<SignedTransportDestination>(bytes) {
            Ok(signed) => match self
                .directory
                .put_signed_transport_destination(&signed)
                .await
            {
                Ok(TransportDestinationApplyOutcome::Refused { reason }) => {
                    let td = &signed.transport_destination;
                    // Classify stale-vs-fork from the STORED row's clock (persist's
                    // reason string is identical for both). `None` = the stored row
                    // could not be read or was not found — unclassifiable, and an
                    // unclassifiable refusal goes to the loud arm.
                    let stored_clock = self
                        .directory
                        .list_signed_transport_destinations_for(&td.occurrence_key_id)
                        .await
                        .ok()
                        .and_then(|rows| {
                            rows.into_iter()
                                .find(|r| {
                                    r.transport_destination.transport_kind == td.transport_kind
                                })
                                .map(|r| {
                                    (
                                        r.transport_destination.epoch,
                                        r.transport_destination.asserted_at,
                                    )
                                })
                        });
                    match stored_clock {
                        Some(stored) if stored > (td.epoch, td.asserted_at) => {
                            // STALE — routine; keyed on the low-cardinality reason,
                            // never the attacker-influenced key_id/dest (#337 §4).
                            tracing::debug!(
                                occurrence_key_id = %td.occurrence_key_id,
                                reason = %reason,
                                "replicated route refused (fail-closed, re-offerable): stale \
                                 (epoch, asserted_at) — not applied; counted as Duplicate, \
                                 see the mapping doc (CIRISEdge#338)"
                            );
                            ApplyOutcome::Duplicate
                        }
                        _ => {
                            // SAME-CLOCK FORK (or unclassifiable) — split truth.
                            tracing::warn!(
                                occurrence_key_id = %td.occurrence_key_id,
                                reason = %reason,
                                classified = stored_clock.is_some(),
                                "replicated route CONTENT CONFLICT at same (epoch, \
                                 asserted_at) — split-truth signal, not applied \
                                 (CIRISEdge#338/#425; `classified=false` = the stored row \
                                 could not be re-read, refusing loud rather than laundering)"
                            );
                            // CIRISEdge#544 — the two sub-arms this branch fuses
                            // have OPPOSITE dispositions, and `stored_clock`
                            // already separates them, so name them separately
                            // rather than take the worse of the two:
                            //  - a CLASSIFIED same-clock fork is terminal. The
                            //    stored row's `(epoch, asserted_at)` equals the
                            //    offer's; if the stored row later moves it can
                            //    only move FORWARD, at which point these bytes
                            //    become the stale arm (Duplicate) — never
                            //    admitted. The fix is a new epoch, i.e. new
                            //    bytes, i.e. a hash this memory does not hold.
                            //  - an UNCLASSIFIABLE refusal (the stored row could
                            //    not be re-read) is a failed READ, not a verdict
                            //    about the row. Transient: the read may succeed
                            //    next round and classify it properly.
                            if stored_clock.is_some() {
                                ApplyOutcome::refused_terminal(format!(
                                    "TransportDestination: supersession refused \
                                     (same-clock content conflict): {reason}"
                                ))
                            } else {
                                ApplyOutcome::refused(format!(
                                    "TransportDestination: supersession refused \
                                     (unclassifiable — the stored row could not be \
                                     re-read): {reason}"
                                ))
                            }
                        }
                    }
                }
                // v18 — `Unchanged` is persist's byte-identical idempotent no-op:
                // the exact `Duplicate` semantics (was mis-counted as an admit).
                Ok(TransportDestinationApplyOutcome::Unchanged) => ApplyOutcome::Duplicate,
                Ok(
                    TransportDestinationApplyOutcome::Inserted
                    | TransportDestinationApplyOutcome::Superseded,
                ) => ApplyOutcome::Admitted,
                // CIRISEdge#544 — transient: the gate fuses "bad signature"
                // (terminal) with "attesting key not registered here yet" and
                // "acts-for not yet visible" (both ordinary bootstrap ordering
                // over rows that replicate). Dropping a route because its
                // attesting key is still in flight would strand reachability, so
                // the ambiguous token stays re-askable under backoff.
                Err(e) => ApplyOutcome::refused(format!(
                    "TransportDestination: authenticated apply gate rejected (signature / \
                     attesting-key / acts-for, CIRISEdge#337 CRITICAL-2): {e}"
                )),
            },
            // A pre-v17 bare row from an un-upgraded peer (intended breaking
            // behavior) — no longer silent (CIRISEdge#425).
            Err(e) => {
                ApplyOutcome::Deserialize(apply_deser_reason("TransportDestination", bytes, &e))
            }
        }
    }

    // ── v2 operational-data apply_* ────────────────────────────────
    //
    // The 3 v2 operational kinds (CEG 1.0-RC2 §5.6.8.13) gate on the
    // [`OperationalProviders`] callbacks being set at bridge
    // construction. Without them, admission fail-closes (returns
    // `false`); persist is not touched. With them, the bridge resolves
    // the live `key_directory` / `root_stewards` / `steward_roster` via
    // the operator-supplied closures and passes them to persist's
    // `put_*` admit surface. Persist + verify perform the 4-check
    // admission pipeline (skew-bound, no-payment-processor identifiers,
    // authority, set-semantics) — edge stays agnostic per the FSD §5.2
    // commitment "merge policy stays persist-side per §10.1.6 declared
    // intents."

    // CIRISEdge#504 / persist v21 #502 E9 — persist now resolves the steward
    // roster from its OWN registered directory (never a caller-passed roster:
    // that was itself a classical FK-existence edge). So `put_organization` /
    // `put_org_membership` / `put_partner_record` no longer take
    // key_directory/root_stewards/steward_roster args. The `operational` gate
    // stays the opt-in for whether THIS edge participates in operational-kind
    // admission at all — admission SCOPE is unchanged, only the (now
    // persist-internal) roster plumbing is dropped. The `OperationalProviders`
    // roster fields are vestigial post-E9; the server drops computing them when
    // it adopts v14.
    async fn apply_organization(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#425 Exhibit B — this early return was one of the THREE sites
        // #423 missed because it sits ABOVE the loud helpers. An edge built without
        // `OperationalProviders` silently declined every delivered Organization,
        // while the round reported healthy. Now it yields a reason the choke logs.
        if self.operational.is_none() {
            // CIRISEdge#544 — TERMINAL. `operational` is fixed at bridge
            // construction (`with_operational`), so within this process no
            // amount of re-asking makes an opted-out node admit the plane. Left
            // transient, an edge without operational providers re-pulls every
            // Organization/OrgMembership/PartnerRecord row its peers hold, every
            // round, forever — the #544 pattern with a whole plane in it rather
            // than one row. Wiring the providers is a restart, which empties the
            // memory.
            return ApplyOutcome::refused_terminal(
                "Organization: operational providers not configured on this edge — \
                 operational-kind admission is opted out",
            );
        }
        // CIRISEdge#397 — the content-hash point-read serves the BARE
        // `Organization` row (the shape `list_organizations_since` returns + the
        // `signed_wire_index` keys on); deserialize that and re-wrap for
        // `put_organization`, falling back to the pre-v14.1 `SignedOrganization`
        // `{"organization": …}` wrap for a peer still on the old wire.
        let signed = serde_json::from_slice::<Organization>(bytes)
            .map(|organization| SignedOrganization { organization })
            .or_else(|_| serde_json::from_slice::<SignedOrganization>(bytes));
        match signed {
            Ok(s) => {
                let content_hash = content_hash_of(&s.organization)
                    .map_or_else(String::new, |(h, _)| hex::encode(h));
                match self.directory.put_organization(s).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    Err(e) => self.refuse("Organization", &content_hash, &e),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("Organization", bytes, &e)),
        }
    }

    async fn apply_org_membership(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#425 Exhibit B — the second escaped early return.
        if self.operational.is_none() {
            // CIRISEdge#544 — TERMINAL. `operational` is fixed at bridge
            // construction (`with_operational`), so within this process no
            // amount of re-asking makes an opted-out node admit the plane. Left
            // transient, an edge without operational providers re-pulls every
            // Organization/OrgMembership/PartnerRecord row its peers hold, every
            // round, forever — the #544 pattern with a whole plane in it rather
            // than one row. Wiring the providers is a restart, which empties the
            // memory.
            return ApplyOutcome::refused_terminal(
                "OrgMembership: operational providers not configured on this edge — \
                 operational-kind admission is opted out",
            );
        }
        // CIRISEdge#397 — same bare-row wire as `apply_organization`: deserialize
        // the BARE `OrgMembership` and re-wrap, falling back to the pre-v14.1
        // `SignedOrgMembership` wrap.
        let signed = serde_json::from_slice::<OrgMembership>(bytes)
            .map(|org_membership| SignedOrgMembership { org_membership })
            .or_else(|_| serde_json::from_slice::<SignedOrgMembership>(bytes));
        match signed {
            Ok(s) => {
                let content_hash = content_hash_of(&s.org_membership)
                    .map_or_else(String::new, |(h, _)| hex::encode(h));
                match self.directory.put_org_membership(s).await {
                    Ok(()) => ApplyOutcome::Admitted,
                    Err(e) => self.refuse("OrgMembership", &content_hash, &e),
                }
            }
            Err(e) => ApplyOutcome::Deserialize(apply_deser_reason("OrgMembership", bytes, &e)),
        }
    }

    async fn apply_partner_record(&self, bytes: &[u8]) -> ApplyOutcome {
        // CIRISEdge#425 Exhibit B — the third escaped early return.
        if self.operational.is_none() {
            // CIRISEdge#544 — TERMINAL. `operational` is fixed at bridge
            // construction (`with_operational`), so within this process no
            // amount of re-asking makes an opted-out node admit the plane. Left
            // transient, an edge without operational providers re-pulls every
            // Organization/OrgMembership/PartnerRecord row its peers hold, every
            // round, forever — the #544 pattern with a whole plane in it rather
            // than one row. Wiring the providers is a restart, which empties the
            // memory.
            return ApplyOutcome::refused_terminal(
                "PartnerRecord: operational providers not configured on this edge — \
                 operational-kind admission is opted out",
            );
        }
        apply_signed_plane!(
            self,
            "PartnerRecord",
            bytes,
            SignedPartnerRecord,
            put_partner_record
        )
    }
}

/// CIRISEdge#397 / persist v21.2.0 (#507) — the content-hash contract: return
/// the wire bytes edge serves for `value` AND their sha256, computed EXACTLY as
/// persist's `wire_index::content_hash_of`: `sha256(serde_json::to_vec(value))`
/// (NO JCS — the raw `to_vec` bytes of the signed wrapper element the
/// `list_signed_*_since` reads return). Serving these same bytes makes
/// advertise-hash = served-bytes = the point-read's `content_hash`, so a Diff'd
/// peer fetches byte-identical what was advertised
/// ([`ciris_persist::federation::FederationDirectory::lookup_signed_record_by_content_hash`]).
fn content_hash_of<T: serde::Serialize>(value: &T) -> Option<([u8; 32], Vec<u8>)> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(value).ok()?;
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    Some((hash, bytes))
}

/// CIRISEdge#474-adjacent (persist v32/#682) — the Key plane's advertise row.
///
/// persist v32's `list_signed_key_records_since` returns
/// `ServedKeyRecord { record, admitted_at }`; edge advertises the content hash of
/// the SIGNED record only (the v31 `SignedKeyRecord { record }` shape). This
/// carries `admitted_at` for the resume seq but `#[serde(skip)]`s it, so
/// [`content_hash_of`] of this row is byte-identical to
/// `content_hash_of(&SignedKeyRecord { record })` — the exact hash persist's
/// `signed_wire_index` keys on. The identity is pinned by a test
/// (`key_advertise_row_hashes_identically_to_signed_key_record`); if serde field
/// order or naming ever drifted, that test reds before the wire does.
#[derive(serde::Serialize)]
struct KeyAdvertiseRow {
    record: KeyRecord,
    #[serde(skip)]
    admitted_at: chrono::DateTime<chrono::Utc>,
}

/// CIRISEdge#531 DEPTH — the test-side spelling of the production advertise
/// call. `list_envelope_refs_for_peer` picks the window from whether a peer is
/// bound; tests that reach the Attestation builder directly must make the SAME
/// choice, or they would exercise a window production never uses.
#[cfg(test)]
impl FederationDirectoryReplicationBridge {
    async fn list_attestations_for_peer(&self, recipient: Option<&str>) -> Vec<EnvelopeRef> {
        let window = recipient.map_or(SweepWindow::Full, SweepWindow::Watermark);
        self.list_attestations(recipient, window).await
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod test_fixtures {
    //! Shared fixtures for the in-crate bridge tests AND the ROLE_MATRIX
    //! gauntlet — one construction path so the gauntlet exercises the same
    //! bridge the unit tests do.
    use super::{CohortProvider, FederationDirectoryReplicationBridge};
    use ciris_persist::federation::{identity_type, FederationDirectory};
    use ciris_persist::store::MemoryBackend;
    use std::sync::Arc;

    pub(crate) fn make_bridge(
        cohort: &[String],
    ) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
        let backend = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let cohort_clone = cohort.to_vec();
        let cohort_cb: CohortProvider = Arc::new(move || cohort_clone.clone());
        let bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb);
        (backend, bridge)
    }

    /// A bridge whose backend already holds AGENT key rows for `key_ids`.
    pub(crate) async fn make_bridge_with_keys(
        key_ids: &[&str],
    ) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
        let (backend, bridge) = make_bridge(&[]);
        for kid in key_ids {
            backend
                .put_public_key(ciris_persist::federation::SignedKeyRecord {
                    record: super::tests::fixture_key_record(kid, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        (backend, bridge)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::SubsecRound as _;
    use chrono::Utc;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_persist::federation::types::{
        algorithm, identity_type, Attestation, Community, CommunityMember,
        CommunityMembershipRevocation, Family, FamilyMember, FamilyMembershipRevocation, KeyRecord,
        LocationProof, Revocation, SignedAttestation, SignedKeyRecord,
    };
    use ciris_persist::store::MemoryBackend;
    use sha2::{Digest as _, Sha256};

    // ── Test fixture helpers ────────────────────────────────────────

    /// Construct a bridge over a fresh `MemoryBackend` with the
    /// supplied cohort. Returns the backend (so the test can seed
    /// data via persist's put_*) plus the bridge.
    fn make_bridge(
        cohort: &[String],
    ) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
        let backend = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let cohort_clone = cohort.to_vec();
        let cohort_cb: CohortProvider = Arc::new(move || cohort_clone.clone());
        let bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb);
        (backend, bridge)
    }

    // ── v6.3.2 (CIRISEdge#166) — real hybrid PQC fixture sigs ───────
    //
    // Mirrors persist's `federation::tier_ingest::test_support` shape
    // (pub(crate) over there). Deterministic per-key_id keypair plus
    // the same V2Jcs (RFC 8785) canonicalizer persist's
    // `ceg_produce_canonicalize` wraps — edge depends on
    // ciris-verify-core directly so the canonical bytes match without
    // persist exposing the helper.

    /// Deterministic 32-byte seed for `key_id`.
    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// `key_id`'s registered hybrid pubkeys, base64.
    fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed");
        let mldsa = Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"));
        let ed_pk = B64.encode(ed.public_key().expect("ed pk"));
        let mldsa_pk = B64.encode(mldsa.public_key().expect("mldsa pk"));
        (ed_pk, Some(mldsa_pk))
    }

    /// Hybrid-sign `envelope` with `signing_key_id`'s deterministic
    /// keys; returns `(original_content_hash, ed_sig_b64,
    /// Some(mldsa_sig_b64))`. PQC half signs the bound payload
    /// (canonical || ed_sig).
    fn sign_attestation_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(signing_key_id)).expect("ed seed");
        let mldsa =
            Box::new(MlDsa65Signer::from_seed(&seed_for(signing_key_id)).expect("mldsa seed"));
        let canonical = ciris_verify_core::jcs::canonicalize(envelope).expect("jcs canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (
            original_content_hash,
            B64.encode(&ed_sig),
            Some(B64.encode(&pqc_sig)),
        )
    }

    /// Synthesize a `KeyRecord` for testing. The `persist_row_hash`
    /// is server-computed by persist's `put_public_key`, so we
    /// pass an empty string here — persist fills it on admit.
    ///
    /// v6.3.2: pubkeys now derived from `hybrid_pubkeys(key_id)` so
    /// federation-tier attestations signed by this key verify under
    /// persist v9.0.0's `verify_federation_tier_ingest`. Scrub
    /// fields stay placeholders — `put_public_key` does NOT
    /// hybrid-verify the registration row.
    pub(crate) fn fixture_key_record(key_id: &str, identity_type_: &str) -> KeyRecord {
        let now = Utc::now();
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.to_string(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: algorithm::HYBRID.to_string(),
            identity_type: identity_type_.to_string(),
            identity_ref: format!("{identity_type_}-ref-{key_id}"),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": key_id,
                "identity_type": identity_type_,
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// persist v32/#682 belt: the Key-plane advertise row must hash byte-identically
    /// to the v31 `SignedKeyRecord { record }` shape (persist's `signed_wire_index`
    /// basis), and the node-local `admitted_at` must NOT enter that hash. If serde
    /// field order/naming ever drifted, this reds BEFORE the wire does — the silent
    /// LIST-vs-FETCH break `cargo check` cannot see.
    #[test]
    fn key_advertise_row_hashes_identically_to_signed_key_record() {
        let record = fixture_key_record("agent-alice", identity_type::AGENT);
        // The exact wire hash edge must reproduce.
        let (want, _) = content_hash_of(&SignedKeyRecord {
            record: record.clone(),
        })
        .expect("signed key hashes");
        // Two DIFFERENT admission instants → the advertise hash is unchanged.
        let t1 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_700_000_000, 0).unwrap();
        let t2 = chrono::DateTime::<chrono::Utc>::from_timestamp(1_800_000_123, 456).unwrap();
        let (h1, _) = content_hash_of(&KeyAdvertiseRow {
            record: record.clone(),
            admitted_at: t1,
        })
        .expect("advertise row hashes");
        let (h2, _) = content_hash_of(&KeyAdvertiseRow {
            record,
            admitted_at: t2,
        })
        .expect("advertise row hashes");
        assert_eq!(
            h1, want,
            "KeyAdvertiseRow must hash as SignedKeyRecord{{record}} — the content-hash \
             fetch keys on it; folding admitted_at in makes every ref unfetchable"
        );
        assert_eq!(
            h1, h2,
            "the wire hash is INVARIANT to admitted_at (node-local, never serialized)"
        );
    }

    // ── Construction smoke ───────────────────────────────────────────

    #[test]
    fn config_defaults_match_constants() {
        let c = BridgeConfig::default();
        assert_eq!(
            c.operational_page_limit,
            BridgeConfig::DEFAULT_OPERATIONAL_PAGE_LIMIT
        );
    }

    /// Bridge can be constructed with default config + an empty
    /// cohort, and listing every kind returns empty refs (no panics).
    #[tokio::test]
    async fn empty_cohort_yields_empty_refs_for_every_kind() {
        let (_backend, bridge) = make_bridge(&[]);
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::Attestation,
            EnvelopeKind::Revocation,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::Family,
            EnvelopeKind::Community,
            EnvelopeKind::IdentityOccurrenceRevocation,
            EnvelopeKind::FamilyMembershipRevocation,
            EnvelopeKind::CommunityMembershipRevocation,
            EnvelopeKind::LocationProof,
            EnvelopeKind::TransportDestination,
        ] {
            let refs = bridge.list_envelope_refs(kind).await;
            assert!(refs.is_empty(), "expected empty refs for {kind:?}");
        }
    }

    // ── Key round-trip ──────────────────────────────────────────────

    /// Seed a key via put_public_key → list_envelope_refs(Key)
    /// returns one ref → fetch_envelope_bytes returns the bytes →
    /// apply_envelope_bytes round-trips through put_public_key
    /// (idempotent on matching content per persist's contract).
    #[tokio::test]
    async fn key_round_trips_through_bridge() {
        let key_id = "agent-alice";
        let (backend, bridge) = make_bridge(&[key_id.to_string()]);
        let record = fixture_key_record(key_id, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord {
                record: record.clone(),
            })
            .await
            .expect("seed key");

        // list_envelope_refs surfaces the seeded key.
        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(refs.len(), 1, "exactly one key in cohort");
        let hash = refs[0].envelope_hash;

        // fetch_envelope_bytes returns the cached canonical bytes.
        let bytes = bridge
            .fetch_envelope_bytes(EnvelopeKind::Key, &hash)
            .await
            .expect("bytes cached during list");

        // The bytes round-trip through serde back to SignedKeyRecord.
        let decoded: SignedKeyRecord =
            serde_json::from_slice(&bytes).expect("canonical bytes decode");
        assert_eq!(decoded.record.key_id, key_id);

        // apply_envelope_bytes routes the Key plane through
        // apply_replicated_key_record (#277). On MemoryBackend (the trait
        // default) a matching-content apply is a first-seen Ok ⇒ Inserted
        // ⇒ admitted; the Unchanged/Refused ⇒ false distinction only
        // surfaces on the scrub-upgrade-aware SqliteBackend (persist owns
        // that classification test).
        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, None)
            .await;
        assert!(
            admitted.is_admitted(),
            "matching-content apply admits on MemoryBackend, got {admitted:?}"
        );
    }

    /// CIRISEdge#257 — the Key-plane selector publishes the node's OWN
    /// record + a third-party anchored record even though neither is in the
    /// node's consent cohort (KERI publish-own). Without the selector,
    /// `list_keys` projects the cohort and would never carry them — the
    /// mesh-seed blocker (a verifier can't root a key it never received).
    #[tokio::test]
    async fn self_provider_publishes_own_and_anchored_not_cohort() {
        let cohort_member = "peer-in-cohort";
        let own_key = "this-node-own";
        let anchored = "third-party-anchored";

        // Cohort contains ONLY the peer — never own / anchored (a node is
        // not in its own consent cohort).
        let (backend, bridge) = make_bridge(&[cohort_member.to_string()]);
        for k in [cohort_member, own_key, anchored] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }

        // Pre-#257 projection: the cohort → only the cohort member's own.
        let cohort_refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(
            cohort_refs.len(),
            1,
            "cohort projection advertises only cohort members' own"
        );

        // Install the SELF publish set {own, anchored}: publish-own. #311 — one
        // `self_provider` drives every SelfOwn kind (here: Key) via the engine.
        let publish_set = vec![own_key.to_string(), anchored.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));
        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(
            refs.len(),
            2,
            "self_provider advertises the node's own + the anchored record, not the cohort"
        );
    }

    /// CIRISEdge#416 — the RECEIVE-diff convergence invariant: an attestation the
    /// node HOLDS must appear in `list_attestation_holdings()` (holdings) EVEN
    /// WHEN it is not in `list_attestations(None)` (the advertise view). The
    /// load-bearing case is a `self`-scoped row from ANOTHER producer: it projects
    /// `SelfOwn` and is advertised only by its own producer, so on this node it is
    /// held-but-not-advertised. Before #416 the receive diff used the advertise
    /// view, so this row stayed in `want` forever and the round never converged.
    #[tokio::test]
    async fn holdings_include_held_but_not_advertised_rows() {
        let this_node = "this-node";
        let other_producer = "other-producer";
        let (backend, bridge) = make_bridge(&[this_node.to_string(), other_producer.to_string()]);
        for k in [this_node, other_producer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // A federation-tier, SELF-scoped attestation authored by `other_producer`
        // — held here, advertisable only by its own producer. The dimension is
        // incidental to this test (it asserts SCOPE projection, not dimension), so
        // it uses a self-descriptive `identity:*` dimension: CIRISPersist v22's
        // AV-62 anti-Goodhart gate forbids a SELF-attested `capacity:*` row (you
        // can't rate your own reputation), which the old `capacity:example:v1`
        // fixture tripped — but self-attesting one's own identity is legitimate.
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "attesting_key_id": other_producer,
            "attested_key_id": other_producer,
            "attestation_type": "scores",
            "dimension": "identity:example:v1",
            "cohort_scope": "self",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            other_producer,
            "scores",
            other_producer,
            &[other_producer],
            "self",
        );
        let (hash_hex, ed_sig, pqc_sig) = sign_attestation_envelope(other_producer, &envelope);
        let att = Attestation {
            attestation_id,
            attesting_key_id: other_producer.to_string(),
            attested_key_id: other_producer.to_string(),
            attestation_type: "scores".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash_hex,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: other_producer.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![other_producer.to_string()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "self".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed self-scoped attestation");
        // This node publishes only its OWN — NOT other_producer's. (The single
        // seeded row is the only attestation in local state.)
        let publish_set = vec![this_node.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));

        // The ADVERTISE view (projection-filtered) EXCLUDES the row — a self-scoped
        // row from another producer is held-but-not-own, so it is not advertised.
        let advertised = bridge.list_attestations_for_peer(None).await;
        assert!(
            advertised.is_empty(),
            "a self-scoped row from another producer must NOT be advertised here, got {advertised:?}"
        );
        // The HOLDINGS view (raw, #416) INCLUDES it — the convergence invariant:
        // the round's `want = remote ∖ holdings` can now shrink for this row after
        // admission, where the pre-#416 advertise-filtered view left it stuck.
        let holdings = bridge.list_attestation_holdings().await;
        assert_eq!(
            holdings.len(),
            1,
            "list_attestation_holdings MUST contain the held row (#416 convergence \
             invariant) even though the advertise view excludes it"
        );
    }

    /// v18 SECURITY — the SelfOwn fetch-path projection twin. A FOREIGN-produced
    /// `cohort_scope:"self"` attestation is structurally hidden by
    /// `attestation_is_advertised`, and until v18 the direct fetch never
    /// consulted that gate: any consent-included peer that learned the hash
    /// out-of-band was served the bytes byte-for-byte. Field-exact scenario:
    /// - a third-party peer IN the consent set, fetching by hash → refused AND
    ///   booked (isolating the projection twin — consent cannot be the refuser);
    /// - the row's own producer/subject → served (the v16 first-party override,
    ///   matching the subject-Pull LIST gate);
    /// - an advertised (federation-scope) row → unaffected for the same peer.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // e2e security scenario: full fixture + both peers + both verdicts
    async fn foreign_self_scope_attestation_is_not_served_by_direct_fetch() {
        let local = "this-node";
        let producer = "other-producer";
        let third = "third-peer";
        let (backend, bridge) =
            make_bridge(&[local.to_string(), producer.to_string(), third.to_string()]);
        let metrics = crate::observability::EdgeMetrics::new();
        let publish_set = vec![local.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            .with_self_provider(Some(selector))
            .with_metrics(Some(metrics.clone()));
        for kid in [local, producer, third] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // BOTH fetching peers are consent-included by this node, so a refusal
        // below can only be the projection twin, never the #396 item-1 bound.
        seed_consent_membership(&backend, local, third).await;
        seed_consent_membership(&backend, local, producer).await;
        // The hidden row: self-scoped, produced by ANOTHER node (held here via
        // replication; advertised only by its own producer).
        let hidden_id = uuid::Uuid::new_v4().to_string();
        seed_scoped_attestation(
            &backend,
            &hidden_id,
            producer,
            producer,
            "scores",
            "self",
            serde_json::json!({ "dimension": "identity:example:v1" }),
        )
        .await;
        // An ADVERTISED control row `third` is NOT first-party to (attester =
        // local, subject = producer): federation scope → projected → served.
        seed_delegates_to(
            &backend,
            local,
            producer,
            &serde_json::json!(["infra:attest"]),
        )
        .await;

        // Locate both rows by CONTENT via the raw holdings view.
        let mut hidden_hash = None;
        let mut advertised_hash = None;
        for r in bridge.list_attestation_holdings().await {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                .await
                .expect("holdings resolve to bytes");
            let v: serde_json::Value = serde_json::from_slice(&bytes).expect("wire json");
            // Read the scope through the bridge's ONE reader (#727 discipline —
            // a raw `.get("cohort_scope")` here trips the skip_serializing_if
            // source guard, and rightly so).
            if FederationDirectoryReplicationBridge::attestation_cohort_scope(&v) == "self" {
                hidden_hash = Some(r.envelope_hash);
            } else if v
                .get("attestation_type")
                .and_then(serde_json::Value::as_str)
                == Some("delegates_to")
            {
                advertised_hash = Some(r.envelope_hash);
            }
        }
        let hidden_hash = hidden_hash.expect("the self-scoped row is held");
        let advertised_hash = advertised_hash.expect("the delegates_to row is held");

        // The advertise view excludes the hidden row for the third party…
        assert!(
            !bridge
                .list_attestations_for_peer(Some(third))
                .await
                .iter()
                .any(|r| r.envelope_hash == hidden_hash),
            "a foreign self-scoped row must not be advertised to a third party"
        );
        // …and (v18) the direct fetch now AGREES: refused + booked.
        let before = metrics.withholds(crate::observability::WithholdReason::RecipientNotInSendSet);
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hidden_hash, Some(third))
                .await
                .is_none(),
            "SECURITY: a consent-included third party must NOT obtain a \
             structurally-hidden self-scope row by fetching its hash out-of-band \
             (the v18 projection twin)"
        );
        assert!(
            metrics.withholds(crate::observability::WithholdReason::RecipientNotInSendSet) > before,
            "the projection-twin refusal must be BOOKED on the withhold ledger \
             (borrowing the closest documented audience-membership reason)"
        );
        // An UNATTRIBUTED fetch has no first party — fail-closed.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hidden_hash, None)
                .await
                .is_none(),
            "an unattributed fetch of a hidden row fails closed"
        );
        // The first party (author AND subject) still recovers its own testimony
        // — the v16 override the twin must preserve.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &hidden_hash,
                    Some(producer)
                )
                .await
                .is_some(),
            "the first party fetches its own self-scope row (v16 override intact)"
        );
        // Advertised rows are unaffected: the same third party still fetches a
        // projected row it is NOT first-party to.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &advertised_hash,
                    Some(third)
                )
                .await
                .is_some(),
            "an advertised (federation-scope) row still serves the same peer — \
             the twin narrows nothing the advertise gate would have served"
        );
    }

    /// v18 (#416 sweep) — the SelfOwn-plane HOLDINGS views are UNFILTERED. A
    /// held-but-unpublished KEY (a foreign subject's row this node admitted via
    /// replication) must appear in `list_holdings(Key)` even though the
    /// advertise view excludes it — else the round's `want = remote ∖ holdings`
    /// re-wants it forever (round 2 re-fetches, re-applies `Duplicate`, never
    /// converges). Drives the two-round shape: remote advertises, local
    /// computes `want` from holdings → empty on the second round.
    #[tokio::test]
    async fn held_but_unpublished_key_leaves_want_on_the_second_round() {
        use crate::replication::summary::diff_refs;
        let this_node = "this-node";
        let foreign = "foreign-subject";
        let (backend, bridge) = make_bridge(&[foreign.to_string()]);
        for k in [this_node, foreign] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // This node publishes only its OWN key.
        let publish_set = vec![this_node.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));

        // The REMOTE view: the foreign subject's own node advertises its key.
        // Same backend = the same stored row bytes, exactly as after round 1
        // replicated it here.
        let remote_dir: Arc<dyn FederationDirectory> = backend.clone();
        let remote_cohort: CohortProvider = Arc::new(Vec::new);
        let foreign_set = vec![foreign.to_string()];
        let remote_selector: CohortProvider = Arc::new(move || foreign_set.clone());
        let remote = FederationDirectoryReplicationBridge::new(remote_dir, remote_cohort)
            .with_self_provider(Some(remote_selector));
        let remote_refs = remote.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(
            remote_refs.len(),
            1,
            "the remote advertises the foreign key"
        );

        // The ADVERTISE view here excludes the foreign key (SelfOwn publish-own)…
        let advertise = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert!(
            !diff_refs(&advertise, &remote_refs).is_empty(),
            "precondition: the advertise view does NOT cover the remote ref — \
             using it as the diff basis is exactly the pre-v18 non-convergence"
        );
        // …and the HOLDINGS view covers it: round 2's want is EMPTY.
        let holdings = bridge.list_holdings(EnvelopeKind::Key).await;
        assert!(
            diff_refs(&holdings, &remote_refs).is_empty(),
            "v18: `want = remote ∖ holdings` must be empty for a held \
             foreign-subject key — the round converges instead of re-fetching \
             it forever (#416 on the Key plane)"
        );
    }

    /// v18 — a deterministic, REALLY-signed `SignedTransportDestination` (the
    /// same JCS + Ed25519 + bound ML-DSA-65 construction persist verifies;
    /// `sign_attestation_envelope` is the generic hybrid envelope signer).
    /// `attesting == occurrence` (self-asserted, the `signer_acts_for` self
    /// path — the same shape `self_route.rs` emits in production).
    fn sign_transport_destination_fixture(
        key_id: &str,
        dest: &str,
        epoch: u64,
        asserted_at: chrono::DateTime<Utc>,
    ) -> ciris_persist::federation::self_at_login::SignedTransportDestination {
        use ciris_persist::federation::self_at_login::{
            BindingProvenance, SignedTransportDestination, TransportDestination,
        };
        use ciris_verify_core::transport_binding::TransportBindingSignature;
        let row = TransportDestination {
            occurrence_key_id: key_id.to_string(),
            transport_kind: "reticulum".to_string(),
            destination: dest.to_string(),
            asserted_at,
            last_seen_at: None,
            transport_ed25519_pubkey_base64: Some(B64.encode([0xbb; 32])),
            transport_x25519_pubkey_base64: Some(B64.encode([0xcc; 32])),
            binding_provenance: BindingProvenance::Rooted,
            epoch,
            retired_at: None,
        };
        let envelope = serde_json::to_value(&row).expect("route row serializes");
        let (_hash, ed_sig, pqc_sig) = sign_attestation_envelope(key_id, &envelope);
        SignedTransportDestination {
            attesting_key_id: key_id.to_string(),
            transport_destination: row,
            signed_envelope: envelope,
            signature: TransportBindingSignature {
                ed25519_signature_base64: ed_sig,
                mldsa65_signature_base64: pqc_sig,
            },
        }
    }

    /// v18 (#416 sweep, TransportDestination arm) — same convergence shape as
    /// the Key-plane test, driven through the REAL signed-route admission.
    #[tokio::test]
    async fn held_but_unpublished_route_is_in_holdings() {
        let this_node = "this-node";
        let foreign = "foreign-subject";
        let (backend, bridge) = make_bridge(&[foreign.to_string()]);
        for k in [this_node, foreign] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let publish_set = vec![this_node.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));
        // Admit the FOREIGN node's signed route exactly as replication would.
        let now = Utc::now().trunc_subsecs(6);
        let signed = sign_transport_destination_fixture(foreign, "aa00", 3, now);
        let outcome = bridge
            .apply_envelope_bytes(
                EnvelopeKind::TransportDestination,
                &serde_json::to_vec(&signed).expect("wire"),
                None,
            )
            .await;
        assert!(
            outcome.is_admitted(),
            "signed route admits, got {outcome:?}"
        );

        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::TransportDestination)
                .await
                .is_empty(),
            "the advertise view excludes the foreign route (SelfOwn publish-own)"
        );
        assert_eq!(
            bridge
                .list_holdings(EnvelopeKind::TransportDestination)
                .await
                .len(),
            1,
            "v18: the holdings view contains the held foreign route (#416 on the \
             TransportDestination plane)"
        );
    }

    /// v18 — the TransportDestination refusal-laundering fix: persist outcomes
    /// map HONESTLY (`Unchanged` → Duplicate; stale → Duplicate, quiet;
    /// same-clock content FORK → Refused, loud) instead of everything reading
    /// `Admitted` in metrics. Nothing here retries on any outcome — the #425
    /// choke counts and logs, and re-offers are want-diff-driven.
    #[tokio::test]
    async fn apply_transport_destination_counts_refusals_honestly() {
        let key = "route-owner";
        let (backend, bridge) = make_bridge(&[]);
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(key, identity_type::AGENT),
            })
            .await
            .expect("seed key");
        let t5 = Utc::now().trunc_subsecs(6);
        let current = sign_transport_destination_fixture(key, "aa00", 5, t5);
        let wire = |s: &ciris_persist::federation::self_at_login::SignedTransportDestination| {
            serde_json::to_vec(s).expect("wire")
        };

        // Fresh insert → Admitted.
        let r = bridge
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &wire(&current), None)
            .await;
        assert_eq!(r, ApplyOutcome::Admitted, "fresh signed route admits");

        // Byte-identical replay → persist `Unchanged` → Duplicate (was
        // mis-counted as an admit).
        let r = bridge
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &wire(&current), None)
            .await;
        assert_eq!(
            r,
            ApplyOutcome::Duplicate,
            "an idempotent replay is a Duplicate, not an admit"
        );

        // STALE: strictly older (epoch, asserted_at) → Duplicate (routine
        // non-progress; deliberately NOT the loud Refused arm — see the
        // mapping doc), and NEVER Admitted.
        let stale =
            sign_transport_destination_fixture(key, "bb11", 3, t5 - chrono::Duration::seconds(10));
        let r = bridge
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &wire(&stale), None)
            .await;
        assert_eq!(
            r,
            ApplyOutcome::Duplicate,
            "a stale-epoch re-offer counts as Duplicate — quiet, and no longer \
             laundered into the admit metrics"
        );

        // SAME-CLOCK FORK: equal (epoch, asserted_at), DIFFERENT content →
        // the split-truth signal must surface as a LOUD Refused at the #425
        // choke and count on `apply_refusals_by_kind`.
        let fork = sign_transport_destination_fixture(key, "cc22", 5, t5);
        let r = bridge
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &wire(&fork), None)
            .await;
        assert!(
            matches!(r, ApplyOutcome::Refused { .. }),
            "a same-clock content fork is a REFUSAL (split truth), got {r:?}"
        );
    }

    /// v18 — the cursor-plane arm-set is BOUND to the predicate: the kinds
    /// `list_envelope_refs_inner` declines to advertise by construction (and
    /// `accord_evidence_since` answers) are EXACTLY `is_cursor_served` over
    /// `ALL`. Widening the predicate without visiting the bridge's dispatch
    /// (or vice versa) reds here, not on the wire.
    #[tokio::test]
    async fn cursor_arm_set_equals_the_predicate_over_all() {
        let cursor_kinds: Vec<EnvelopeKind> = EnvelopeKind::ALL
            .into_iter()
            .filter(|k| k.is_cursor_served())
            .collect();
        assert_eq!(
            cursor_kinds,
            vec![EnvelopeKind::AccordQuorumEvidence],
            "the `EnvelopeKind::AccordQuorumEvidence => Vec::new()` advertise arm \
             and `accord_evidence_since`'s accord-specific body are written for \
             EXACTLY this set — a new cursor kind must visit BOTH dispatch sites \
             in bridge.rs (see the comments naming this test)"
        );
        let (_backend, bridge) = make_bridge(&[]);
        for kind in EnvelopeKind::ALL {
            if kind.is_cursor_served() {
                assert!(
                    bridge.list_envelope_refs(kind).await.is_empty(),
                    "a cursor-served kind must never advertise content-hash refs \
                     (listed-then-unfetchable otherwise): {kind:?}"
                );
            } else {
                assert!(
                    bridge
                        .accord_evidence_since(kind, None, None)
                        .await
                        .is_empty(),
                    "a non-cursor kind must never be answered by the cursor serve \
                     path: {kind:?}"
                );
            }
        }
    }

    /// Bridge dedupes the same key when listed across multiple cohort
    /// entries that all resolve to the same record (cohort-callback
    /// can yield the same key_id multiple times; the bridge must
    /// dedupe by hash so the wire round only carries each envelope
    /// once).
    #[tokio::test]
    async fn key_dedupes_across_cohort() {
        let key_id = "agent-bob";
        let (backend, bridge) =
            make_bridge(&[key_id.to_string(), key_id.to_string(), key_id.to_string()]);
        let record = fixture_key_record(key_id, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed key");

        let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
        assert_eq!(refs.len(), 1, "cohort dedupe — three lookups, one ref");
    }

    // ── apply_envelope_bytes refuses garbage ────────────────────────

    /// persist v24.2.0 / CIRISPersist#565 — the pure outcome mapping, exhaustive
    /// over `KeyRefusalReason::ALL`: both duplicate halves (`Unchanged` AND
    /// `already_anchored_identical`) map to `Duplicate` with NO ledger token
    /// (mapping only the new variant would leave the common baked-seed re-offer
    /// path misreported); every other reason maps to `Refused` whose message
    /// carries the stable token, which is also returned for the receive-plane
    /// mirror to count.
    #[test]
    fn key_outcome_mapping_is_exhaustive_and_names_the_branch() {
        // The three progress outcomes admit, no token.
        for o in [
            ReplicatedKeyOutcome::Inserted,
            ReplicatedKeyOutcome::Upgraded,
            ReplicatedKeyOutcome::Superseded,
        ] {
            let (a, t) = key_outcome_to_apply(Ok(o), "h");
            assert!(matches!(a, ApplyOutcome::Admitted), "{a:?}");
            assert!(t.is_none());
        }
        // Both duplicate halves: Duplicate, never counted as a refusal.
        let (a, t) = key_outcome_to_apply(Ok(ReplicatedKeyOutcome::Unchanged), "h");
        assert!(matches!(a, ApplyOutcome::Duplicate), "{a:?}");
        assert!(t.is_none());
        let (a, t) = key_outcome_to_apply(
            Ok(ReplicatedKeyOutcome::Refused {
                reason: KeyRefusalReason::AlreadyAnchoredIdentical,
            }),
            "h",
        );
        assert!(
            matches!(a, ApplyOutcome::Duplicate),
            "already_anchored_identical is the receiver ALREADY HOLDING what was \
             offered (a re-encoding of an anchored record) — Duplicate, not a \
             security-shaped refusal; got {a:?}"
        );
        assert!(t.is_none());
        // Every OTHER reason: Refused carrying the stable token, token returned.
        for &reason in KeyRefusalReason::ALL {
            if matches!(reason, KeyRefusalReason::AlreadyAnchoredIdentical) {
                continue;
            }
            let (a, t) = key_outcome_to_apply(Ok(ReplicatedKeyOutcome::Refused { reason }), "h");
            let ApplyOutcome::Refused { reason: msg, .. } = &a else {
                panic!("{} must map to Refused, got {a:?}", reason.as_str());
            };
            assert!(
                msg.contains(reason.as_str()),
                "the refusal message must carry the branch token {}: {msg}",
                reason.as_str()
            );
            assert_eq!(t, Some(reason.as_str()), "the mirror counts the token");
        }
    }

    /// CIRISEdge#544 — the classification the issue turns on, asserted through
    /// the EXACT value persist hands the field: `ReplicatedKeyOutcome::Refused
    /// { reason }`, one per closed-set variant, not a hand-written message.
    ///
    /// `conflicting_version` is the measured row (55 re-offers in 30 minutes of
    /// byte-identical bytes); it and the two other first-seen/monotonic verdicts
    /// are TERMINAL. Every reason whose token fuses a recoverable arm with an
    /// unrecoverable one stays TRANSIENT — mislabelling a permanent refusal
    /// transient costs a decaying trickle, mislabelling a recoverable one
    /// terminal withholds state.
    #[test]
    fn conflicting_version_is_terminal_and_the_ambiguous_key_reasons_stay_transient() {
        let terminal = [
            KeyRefusalReason::PubkeySwap,
            KeyRefusalReason::Downgrade,
            KeyRefusalReason::ConflictingVersion,
        ];
        for &reason in KeyRefusalReason::ALL {
            // Drive the mapping the field drives, not the private fn alone.
            let (outcome, _) =
                key_outcome_to_apply(Ok(ReplicatedKeyOutcome::Refused { reason }), "h");
            let want = if terminal.contains(&reason) {
                RetryDisposition::Terminal
            } else {
                RetryDisposition::Transient
            };
            // `already_anchored_identical` never reaches a refusal at all — it is
            // the receiver already holding what was offered.
            if matches!(reason, KeyRefusalReason::AlreadyAnchoredIdentical) {
                assert_eq!(outcome.retry_disposition(), None, "{}", reason.as_str());
                continue;
            }
            assert_eq!(
                outcome.retry_disposition(),
                Some(want),
                "{} must be {} — see key_refusal_retry for the per-variant reasoning",
                reason.as_str(),
                want.as_str()
            );
            let ApplyOutcome::Refused { reason: msg, .. } = &outcome else {
                panic!("{} must map to Refused, got {outcome:?}", reason.as_str());
            };
            assert!(
                msg.contains(want.as_str()),
                "an operator reading ONE line must be able to tell wait-for-state \
                 from supersede-it: {msg}"
            );
        }
    }

    /// CIRISEdge#544 — the whole loop, end to end, on the real apply choke: a
    /// terminally-refused row is remembered, and the round's want-diff stops
    /// asking for it.
    ///
    /// Driven on the operational plane because its terminal verdict is
    /// structural rather than backend-dependent (an edge built without
    /// `OperationalProviders` cannot admit the plane in this process, whatever
    /// the store does), so the assertion is about edge's decision and not about
    /// which branch `MemoryBackend` happens to take. The suppression key is
    /// `sha256(delivered bytes)` — the same value the peer advertised and the
    /// same value `diff_refs` puts in `want`.
    #[tokio::test]
    async fn a_terminally_refused_row_is_dropped_from_the_next_rounds_want() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        let bytes = br#"{"organization": {
            "attestation_id": "att-1",
            "org_id": "org-acme",
            "name": "ACME",
            "org_type": "internal",
            "status": "active",
            "asserted_at": "2026-06-10T20:00:00Z",
            "attesting_key_id": "k1",
            "signed_envelope": {},
            "ed25519_signature_base64": ""
        }}"#;
        let hash: [u8; 32] = Sha256::digest(bytes).into();

        // Before the refusal the node asks for it like any other missing row.
        assert!(
            !bridge.retry_suppressed(EnvelopeKind::Organization, &hash),
            "a row this node has never refused must stay wanted"
        );

        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Organization, bytes, Some("peer-x"))
            .await;
        assert!(
            matches!(&outcome, ApplyOutcome::Refused { retry, .. } if retry.is_terminal()),
            "got {outcome:?}"
        );

        // …and now it does not. This is the 55-per-30-minutes becoming one.
        assert!(
            bridge.retry_suppressed(EnvelopeKind::Organization, &hash),
            "the round's want must skip bytes this node just terminally refused"
        );
        assert_eq!(bridge.refusal_memory_len(), 1);
        assert_eq!(
            bridge.retry_suppressions(),
            1,
            "the suppression is counted — traffic that did not happen has no \
             other observable"
        );
        // The suppression is on THESE bytes only: a corrected, superseding
        // record hashes differently and is asked for immediately, which is the
        // way forward the issue says a stuck sender needs.
        let superseding: [u8; 32] = Sha256::digest(b"a corrected version of the row").into();
        assert!(!bridge.retry_suppressed(EnvelopeKind::Organization, &superseding));
        // …and it is scoped to the plane the verdict was reached on.
        assert!(!bridge.retry_suppressed(EnvelopeKind::Key, &hash));
    }

    /// CIRISEdge#544 — suppression gates the ASK, never the ADMIT. A row this
    /// node stopped asking for is still applied on its merits if a peer pushes
    /// it (the #927 proactive-publish shape), so an over-eager memory can delay
    /// a row but can never withhold one.
    #[tokio::test]
    async fn a_suppressed_row_is_still_applied_when_a_peer_pushes_it_anyway() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        let record = fixture_key_record("k1", identity_type::NODE);
        let bytes = serde_json::to_vec(&SignedKeyRecord { record }).expect("serialize offer");
        let hash: [u8; 32] = Sha256::digest(&bytes).into();
        // Pre-load the memory as if a previous round had refused these bytes.
        bridge.refusal_backoff.record_at(
            EnvelopeKind::Key,
            hash,
            crate::replication::refusal_backoff::RetryDisposition::Terminal,
            Instant::now(),
        );
        assert!(bridge.retry_suppressed(EnvelopeKind::Key, &hash));

        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some("peer-x"))
            .await;
        assert!(
            outcome.is_admitted(),
            "the apply path must not consult the retry memory — it gates asking, \
             not admitting; got {outcome:?}"
        );
        // …and admitting CLEARS the history, so a later refusal of the same
        // bytes starts its backoff from the base rather than inheriting a stale
        // attempt count.
        assert!(
            !bridge.retry_suppressed(EnvelopeKind::Key, &hash),
            "an admitted row's refusal history is obsolete"
        );
    }

    /// persist v24.2.0 / #565 — the wire drive: a pubkey swap offered through
    /// the real apply choke books on BOTH receive-plane mirror axes (kind +
    /// stable token) and surfaces the branch in the refusal message.
    #[tokio::test]
    async fn a_pubkey_swap_books_on_both_receive_mirror_axes() {
        let (backend, bridge, metrics) = make_metered_bridge(&[]);
        // The node already holds k1 at its canonical pubkeys...
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record("k1", identity_type::NODE),
            })
            .await
            .expect("seed k1");
        // ...and a peer offers k1 under DIFFERENT pubkeys (the hijack shape).
        let mut swapped = fixture_key_record("k1", identity_type::NODE);
        let (other_ed, other_mldsa) = hybrid_pubkeys("attacker-keys");
        swapped.pubkey_ed25519_base64 = other_ed;
        swapped.pubkey_ml_dsa_65_base64 = other_mldsa;
        let bytes =
            serde_json::to_vec(&SignedKeyRecord { record: swapped }).expect("serialize offer");

        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some("peer-x"))
            .await;
        let ApplyOutcome::Refused { reason: msg, .. } = &outcome else {
            panic!("a pubkey swap must be Refused, got {outcome:?}");
        };
        // WHICH branch classifies is persist's unit (certified upstream; on the
        // MemoryBackend this shape currently books `store_conflict` — its
        // plan-free write site — where the planned sqlite/postgres paths name
        // `pubkey_swap`). EDGE's unit is coherence: the message carries exactly
        // one stable token from the closed set, and BOTH mirror axes book it.
        let snap = metrics.snapshot();
        let booked: Vec<&str> = snap
            .key_apply_refusals_by_reason
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(booked.len(), 1, "exactly one token booked: {booked:?}");
        let token = booked[0];
        assert!(
            KeyRefusalReason::ALL.iter().any(|r| r.as_str() == token),
            "the booked token is from the closed contract set: {token}"
        );
        assert!(
            msg.contains(token),
            "the message names the SAME branch the ledger booked ({token}): {msg}"
        );
        assert_eq!(
            snap.apply_refusals_by_kind.get(&EnvelopeKind::Key).copied(),
            Some(1),
            "the kind axis books at the #425 choke"
        );
        assert_eq!(
            snap.key_apply_refusals_by_reason.get(token).copied(),
            Some(1),
            "the token axis books the typed branch once"
        );
    }

    /// CIRISEdge#430 — an ADMITTED revocation fires the revocation observer
    /// with the REVOKED key_id (the transit gate's event-driven cache
    /// invalidation signal); a non-admitted apply (garbage) never fires it.
    ///
    ///
    /// `test-anchor`-gated: persist v30.8.0 (CIRISPersist#628 / CIRISConstitution#87)
    /// requires a THIRD-PARTY revocation's revoker to hold `slash` conferred by a
    /// root THIS NODE trusts, and standing up a valid trust root needs the accord
    /// roster helpers persist exports only behind `test-anchor` (the same fence
    /// #386's ALLOW-path twin uses; its CI lane runs the whole lib, so this is
    /// real coverage). The test MUST stay third-party (revoked ≠ revoking) — its
    /// whole value is proving the observer fires with the REVOKED key, not the
    /// revoker's, so a self-revocation or empty-revoker shortcut would hide a
    /// fire-with-the-wrong-field bug. We model the FULL production-shaped
    /// authorized graph on purpose: the `slash`-wielding revoker is a `user`
    /// (CC 4.4.3.4.3 — infrastructure has no agency), a trusted external root
    /// confers `slash` on it, and only then does edge's apply path admit the
    /// revocation and fire the observer. That is exactly what a real node will
    /// see, so a green here is confidence the prod path behaves as intended.
    #[cfg(feature = "test-anchor")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // roster + trust graph + authorized revocation: one scenario
    async fn admitted_revocation_fires_the_observer_with_the_revoked_key() {
        use ciris_persist::federation::accord_test_support::{register_accord_holder, Identity};
        use ciris_persist::federation::genesis::effective_accord_holder_records;

        let (backend, bridge) = make_bridge(&[]);
        let local = "self-node";
        let root = "trust-root";
        let lifecycle_attester = "accord-holder-live";
        // The revoker is a USER: only agency-bearing identities may hold `slash`.
        let revoker = "revoker-user";
        let target = "bad-peer";

        // The live accord family, registered at their pinned pubkeys so the
        // root's accord:lifecycle row verifies against the real roster.
        let holders: Vec<Identity> = effective_accord_holder_records()
            .iter()
            .map(|r| Identity::new(&r.record.key_id))
            .collect();
        for h in &holders {
            register_accord_holder(&*backend, h)
                .await
                .expect("register accord holder");
        }

        // Register the identities. The revoker is a USER (agency); local/root are
        // infrastructure; the lifecycle attester is an ACCORD_HOLDER and must
        // carry attestation_evidence (CIRISPersist v22 #543/#513).
        for (k, it) in [
            (local, identity_type::NODE),
            (root, identity_type::NODE),
            (revoker, identity_type::USER),
            (target, identity_type::NODE),
            (lifecycle_attester, identity_type::ACCORD_HOLDER),
        ] {
            let mut record = fixture_key_record(k, it);
            if it == identity_type::ACCORD_HOLDER {
                record.attestation_evidence = Some(serde_json::json!({
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
                    "nonce_captured_at": Utc::now().to_rfc3339(),
                }));
            }
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("seed key");
        }

        // The authorized trust graph, exactly the production shape
        // `check_revocation_authority` walks: root self-declares (charter), THIS
        // NODE trusts it, it is live, and it confers `slash` on the revoker.
        backend.set_node_key_id(local);
        seed_root_charter(&backend, root, &[format!("{root}-successor")]).await;
        seed_delegates_to(
            &backend,
            local,
            root,
            &serde_json::json!(["infra:attest", "infra:serve"]),
        )
        .await;
        seed_accord_lifecycle(&backend, lifecycle_attester, root).await;
        seed_delegates_to(
            &backend,
            root,
            revoker,
            &serde_json::json!([ciris_persist::federation::admission::DELEGATION_SCOPE_SLASH]),
        )
        .await;

        let fired: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&fired);
        let bridge = bridge.with_revocation_observer(Some(Arc::new(move |k: &str| {
            sink.lock().expect("observer sink").push(k.to_string());
        })));

        let now = Utc::now().trunc_subsecs(6);
        let mut rev = ciris_persist::federation::types::Revocation {
            revocation_id: "rev-1".to_string(),
            revoked_key_id: target.to_string(),
            revoking_key_id: revoker.to_string(),
            reason: None,
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: revoker.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            observed_region: "us".to_string(),
            revoked_after: None,
        };
        ciris_persist::federation::admission::bind_revocation_into_envelope(&mut rev)
            .expect("bind revocation envelope");
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(revoker, &rev.revocation_envelope);
        rev.original_content_hash = hash;
        rev.scrub_signature_classical = ed_sig;
        rev.scrub_signature_pqc = pqc_sig;
        let bytes =
            serde_json::to_vec(&SignedRevocation { revocation: rev }).expect("serialize rev");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Revocation, &bytes, None)
            .await;
        assert!(
            outcome.is_admitted(),
            "the fixture revocation must admit (else the observer half is untested): {outcome:?}"
        );
        assert_eq!(
            *fired.lock().expect("read sink"),
            vec!["bad-peer".to_string()],
            "the observer fires ONCE with the REVOKED key_id"
        );

        // A non-admitted apply (garbage) never fires the observer.
        let _ = bridge
            .apply_envelope_bytes(EnvelopeKind::Revocation, b"{not a revocation}", None)
            .await;
        assert_eq!(
            fired.lock().expect("read sink").len(),
            1,
            "a refused/undeserializable revocation fires nothing"
        );
    }

    /// CIRISEdge#457 — the receive plane's distinct-states discriminator:
    /// an accepted apply books `replication_applied_total`, a duplicate books
    /// `replication_duplicate_total`, and BOTH are empty on a node that was
    /// offered nothing — so "applied all N" and "received nothing" no longer
    /// render identically (the last uncounted limb of the #433 arc, receive
    /// side; the mirror of #434).
    #[tokio::test]
    async fn accepted_apply_and_duplicate_are_counted_distinctly_from_idle() {
        let (_backend, bridge, metrics) = make_metered_bridge(&[]);
        // (a) IDLE — nothing offered: both accepted-apply counters empty.
        let idle = metrics.snapshot();
        assert!(
            idle.replication_applied_total.is_empty()
                && idle.replication_duplicate_total.is_empty(),
            "an idle node books no accepted applies"
        );
        // (b) Apply a FRESH (never-seeded) Key row → Admitted → applied_total.
        let rec = fixture_key_record("fresh-457", identity_type::NODE);
        let bytes = serde_json::to_vec(&SignedKeyRecord {
            record: rec.clone(),
        })
        .expect("serialize key");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some("peer-457"))
            .await;
        assert!(outcome.is_admitted(), "fresh row admits: {outcome:?}");
        let snap = metrics.snapshot();
        assert_eq!(
            snap.replication_applied_total
                .get(&EnvelopeKind::Key)
                .copied(),
            Some(1),
            "an accepted apply is now counted — the state that used to read {{}} \
             is now distinguishable from idle (CIRISEdge#457)"
        );
        // The applied axis is distinct from the duplicate axis — an admit
        // books ONLY applied, never both (the #433 distinct-states rule).
        assert!(
            snap.replication_duplicate_total.is_empty(),
            "an Admitted apply books applied_total, not duplicate_total"
        );
    }

    /// apply_envelope_bytes returns false on undeserializable bytes
    /// for every kind. Defence against a peer that ships bytes the
    /// bridge can't parse (the protocol's UnexpectedMessage handling
    /// + scheduler's RoundEvent::Error reporting is the production
    /// observability surface).
    #[tokio::test]
    async fn apply_envelope_bytes_refuses_garbage() {
        let (_backend, bridge) = make_bridge(&[]);
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::Attestation,
            EnvelopeKind::Revocation,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::Family,
            EnvelopeKind::Community,
            EnvelopeKind::IdentityOccurrenceRevocation,
            EnvelopeKind::FamilyMembershipRevocation,
            EnvelopeKind::CommunityMembershipRevocation,
            EnvelopeKind::LocationProof,
            EnvelopeKind::TransportDestination,
        ] {
            let r = bridge
                .apply_envelope_bytes(kind, b"{not a signed record}", None)
                .await;
            assert!(
                !r.is_admitted(),
                "expected garbage refused for {kind:?}, got {r:?}"
            );
            // CIRISEdge#425 — garbage must classify as a NAMED non-admit (a reason
            // the choke point logs), never a bare drop.
            assert!(
                matches!(
                    r,
                    ApplyOutcome::Refused { .. } | ApplyOutcome::Deserialize(_)
                ),
                "garbage must be a named Refused/Deserialize for {kind:?}, got {r:?}"
            );
        }
    }

    /// CIRISEdge#337 CRITICAL-2 — the confused-deputy closure. A WELL-FORMED
    /// BARE `TransportDestination` (valid JSON of the bare route row — the exact
    /// shape the pre-v17 apply path deserialized and wrote with an attacker-set
    /// `binding_provenance = Rooted` for ANY key_id, with no signature and no
    /// authority check) must now be REFUSED. Only a `SignedTransportDestination`
    /// container that clears persist's hybrid-sig + `signer_acts_for` gate is
    /// admitted. This is the route-table half of the AV-42 saga: a peer can no
    /// longer inject a route for a victim's key_id over replication.
    #[tokio::test]
    async fn apply_transport_destination_refuses_a_bare_unsigned_route() {
        use ciris_persist::federation::self_at_login::{BindingProvenance, TransportDestination};

        let (backend, bridge) = make_bridge(&[]);

        // A perfectly well-formed bare route claiming a Rooted binding for a
        // victim key_id — no signature, no authority. The confused-deputy input.
        let bare = TransportDestination {
            occurrence_key_id: "victim-key".to_string(),
            transport_kind: "reticulum".to_string(),
            destination: hex::encode([0xaa; 16]),
            asserted_at: chrono::Utc::now(),
            last_seen_at: None,
            transport_ed25519_pubkey_base64: Some(
                base64::engine::general_purpose::STANDARD.encode([0xbb; 32]),
            ),
            transport_x25519_pubkey_base64: Some(
                base64::engine::general_purpose::STANDARD.encode([0xcc; 32]),
            ),
            binding_provenance: BindingProvenance::Rooted, // attacker-chosen
            epoch: u64::MAX,                               // attacker-chosen ceiling
            retired_at: None,
        };
        let bytes = serde_json::to_vec(&bare).expect("serialize bare route");

        let admitted = bridge
            .apply_envelope_bytes(EnvelopeKind::TransportDestination, &bytes, None)
            .await;

        assert!(
            !admitted.is_admitted(),
            "a bare unsigned TransportDestination must be REFUSED — admitting it is the \
             CIRISEdge#337 CRITICAL-2 confused-deputy route-hijack",
        );

        // And nothing was written for the victim.
        let rows = backend
            .list_transport_destinations_for("victim-key")
            .await
            .expect("list");
        assert!(
            rows.is_empty(),
            "a refused bare route must not touch persist; found {} row(s)",
            rows.len(),
        );
    }

    // ── CIRISEdge#394 (E4 lockstep) — the pass-through verdict pins ──
    //
    // Edge produces NONE of the five authority-signed declaration planes
    // (Family / Community / FamilyMembershipRevocation /
    // CommunityMembershipRevocation / LocationProof) — see the verdict
    // comment on `apply_family`. These tests pin the property that verdict
    // rests on: a record signed EXACTLY per persist's E4 contract
    // (hybrid-sign `record.signing_envelope()` as the registered authority)
    // survives edge's full forward path — apply (persist ADMITS, the
    // fail-closed oracle) → advertise → fetch → RE-ADMISSION on a second
    // node — with the three wrapper fields byte-identical throughout.
    //
    // Fixture signing mirrors persist's pub(crate)
    // `federation::tier_ingest::test_support::sign_*`: the generic hybrid
    // envelope signer (`sign_attestation_envelope`, despite its name) is the
    // SAME construction persist verifies — JCS canonical bytes, Ed25519 over
    // canonical, ML-DSA-65 over `canonical ‖ ed25519_sig`.

    /// Register a deterministic hybrid fixture key for each `(id,
    /// identity_type)`, so the authority resolves at `verify_*_admission` and
    /// the FK'd ids exist. The identity_type matters on the Community plane:
    /// an `agent`-role member must be steward-bound (CC 3.2 / CC 3.4.7.1),
    /// while a `user`-role member self-anchors — the fixtures register
    /// community members as `user`.
    async fn register_fixture_keys(backend: &MemoryBackend, keys: &[(&str, &str)]) {
        for (k, ty) in keys {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, ty),
                })
                .await
                .expect("register fixture key");
        }
    }

    /// Hybrid-sign a [`Family`] for submission as `authority_key_id` —
    /// persist's `tier_ingest::test_support::sign_family` shape.
    fn sign_family_fixture(authority_key_id: &str, family: Family) -> SignedFamily {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &family.signing_envelope());
        SignedFamily {
            family,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`Community`] — mirrors [`sign_family_fixture`].
    fn sign_community_fixture(authority_key_id: &str, community: Community) -> SignedCommunity {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &community.signing_envelope());
        SignedCommunity {
            community,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`FamilyMembershipRevocation`] — mirrors
    /// [`sign_family_fixture`].
    fn sign_family_membership_revocation_fixture(
        authority_key_id: &str,
        revocation: FamilyMembershipRevocation,
    ) -> SignedFamilyMembershipRevocation {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &revocation.signing_envelope());
        SignedFamilyMembershipRevocation {
            family_membership_revocation: revocation,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`CommunityMembershipRevocation`] — mirrors
    /// [`sign_family_fixture`].
    fn sign_community_membership_revocation_fixture(
        authority_key_id: &str,
        revocation: CommunityMembershipRevocation,
    ) -> SignedCommunityMembershipRevocation {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &revocation.signing_envelope());
        SignedCommunityMembershipRevocation {
            community_membership_revocation: revocation,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// Hybrid-sign a [`LocationProof`] — mirrors [`sign_family_fixture`].
    fn sign_location_proof_fixture(
        authority_key_id: &str,
        proof: LocationProof,
    ) -> SignedLocationProof {
        let (_h, classical, pqc) =
            sign_attestation_envelope(authority_key_id, &proof.signing_envelope());
        SignedLocationProof {
            location_proof: proof,
            authority_key_id: authority_key_id.to_string(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// A minimal admissible [`Family`]: `founder_only` is a canonical
    /// `consensus_protocol` form and every member key_id must be registered
    /// (persist `validate_family_members`); `family_key_id` itself is
    /// keyless (persist v24.0.0 dropped that FK).
    fn fixture_family(family_key_id: &str, member_key_id: &str) -> Family {
        Family {
            family_key_id: family_key_id.to_string(),
            family_name: "E4 Pin Household".to_string(),
            members: vec![FamilyMember {
                key_id: member_key_id.to_string(),
                joined_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                role: None,
            }],
            founded_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
            consensus_protocol: "founder_only".to_string(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        }
    }

    /// A minimal admissible [`Community`] — structural mirror of
    /// [`fixture_family`].
    fn fixture_community(community_key_id: &str, member_key_id: &str) -> Community {
        Community {
            community_key_id: community_key_id.to_string(),
            community_name: "E4 Pin Co-op".to_string(),
            members: vec![CommunityMember {
                key_id: member_key_id.to_string(),
                joined_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                role: None,
            }],
            founded_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
            consensus_protocol: "founder_only".to_string(),
            policy_blob: None,
            persist_row_hash: String::new(),
        }
    }

    /// Drive ONE E4 plane through edge's complete forward path and assert
    /// the pass-through verdict:
    ///
    /// 1. node A applies the pre-signed wire bytes → persist ADMITS (the
    ///    v21.0.0 fail-closed verify is the oracle that the bytes edge
    ///    forwarded still carry a valid authority signature);
    /// 2. A advertises exactly one ref and serves bytes that hash back to
    ///    the advertised hash (byte-integrity of the serve half);
    /// 3. the three E4 wrapper fields and the signed canonical envelope
    ///    survive the apply→store→serve round trip unmodified (persist
    ///    stamps only the server-computed `persist_row_hash`, which is
    ///    excluded from the signed envelope by construction);
    /// 4. node B re-admits the bytes A SERVED — the lockstep property
    ///    itself: what edge passes on remains admissible at the next hop.
    ///
    /// `delegations` seeds `delegates_to(granter → delegate)` edges into BOTH
    /// nodes' backends before the apply. v37.0.0 (CIRISPersist#734) made one
    /// plane need them: a `LocationProof`'s `authority_key_id` must be the
    /// subject itself or a LIVE delegate of it, because location is
    /// self-knowledge and a third party's signature proves only that they
    /// signed it. Every other E4 kind admits a distinct authority by design
    /// (an authority legitimately speaks about parties who are not itself) and
    /// passes `&[]`.
    async fn pin_e4_forward_path<T>(
        kind: EnvelopeKind,
        cohort: &[&str],
        registered_keys: &[(&str, &str)],
        delegations: &[(&str, &str)],
        signed: &T,
        wrapper_fields_of: impl Fn(&T) -> (String, String, Option<String>),
        signing_envelope_of: impl Fn(&T) -> serde_json::Value,
    ) where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let cohort: Vec<String> = cohort.iter().map(|s| (*s).to_string()).collect();

        // Node A — the forwarding edge.
        let (backend_a, bridge_a) = make_bridge(&cohort);
        register_fixture_keys(&backend_a, registered_keys).await;
        for (granter, delegate) in delegations {
            seed_delegates_to(
                &backend_a,
                granter,
                delegate,
                &serde_json::json!(["infra:attest"]),
            )
            .await;
        }
        let wire = serde_json::to_vec(signed).expect("signed wrapper serializes");
        let outcome = bridge_a.apply_envelope_bytes(kind, &wire, None).await;
        assert!(
            outcome.is_admitted(),
            "persist must ADMIT the pre-signed {kind:?} edge forwarded \
             (E4 fail-closed oracle); got {outcome:?}"
        );

        // Serve half: advertise + fetch, hash-integral.
        let refs = bridge_a.list_envelope_refs(kind).await;
        assert_eq!(refs.len(), 1, "exactly one advertised {kind:?} envelope");
        let served = bridge_a
            .fetch_envelope_bytes(kind, &refs[0].envelope_hash)
            .await
            .expect("advertised envelope must be fetchable");
        let served_hash: [u8; 32] = Sha256::digest(&served).into();
        assert_eq!(
            served_hash, refs[0].envelope_hash,
            "served bytes must hash back to the advertised hash"
        );

        // Signature preservation through the round trip.
        let decoded: T = serde_json::from_slice(&served).expect("served bytes decode");
        assert_eq!(
            wrapper_fields_of(&decoded),
            wrapper_fields_of(signed),
            "authority_key_id + scrub signatures must survive byte-identical"
        );
        assert_eq!(
            signing_envelope_of(&decoded),
            signing_envelope_of(signed),
            "the signed canonical envelope must survive the forward path"
        );

        // Node B — re-admission of what A served IS the lockstep property.
        let (backend_b, bridge_b) = make_bridge(&cohort);
        register_fixture_keys(&backend_b, registered_keys).await;
        for (granter, delegate) in delegations {
            seed_delegates_to(
                &backend_b,
                granter,
                delegate,
                &serde_json::json!(["infra:attest"]),
            )
            .await;
        }
        let outcome_b = bridge_b.apply_envelope_bytes(kind, &served, None).await;
        assert!(
            outcome_b.is_admitted(),
            "node B must re-admit the {kind:?} bytes node A served; got {outcome_b:?}"
        );
    }

    #[tokio::test]
    async fn e4_family_forward_path_preserves_authority_signature() {
        let signed = sign_family_fixture("e4-authority", fixture_family("e4-family", "e4-member"));
        pin_e4_forward_path(
            EnvelopeKind::Family,
            &["e4-member"], // cohort-scoped advertise: a member must be in cohort
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-member", identity_type::AGENT),
            ],
            &[], // an authority speaks about others BY DESIGN on this plane
            &signed,
            |s: &SignedFamily| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.family.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_community_forward_path_preserves_authority_signature() {
        let signed = sign_community_fixture(
            "e4-authority",
            fixture_community("e4-community", "e4-member"),
        );
        pin_e4_forward_path(
            EnvelopeKind::Community,
            &["e4-member"],
            // CC 3.2 steward-binding gate: a non-infra community member must
            // root in an accountable human — a `user`-role member self-anchors.
            // And unlike the KEYLESS family (persist v24.0.0 dropped that FK),
            // `community_key_id` must itself exist in federation_keys.
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-community", identity_type::AGENT),
                ("e4-member", identity_type::USER),
            ],
            &[],
            &signed,
            |s: &SignedCommunity| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.community.signing_envelope(),
        )
        .await;
    }

    // ── persist v38.2.0 / CIRISEdge#522 — the three apply-door adoptions ──

    /// The classifier, over the TYPED persist variants — the unit the three
    /// door adoptions all funnel through.
    ///
    /// This is a pure test on purpose. Two of the three doors
    /// (`retry_after_*_roster`, `third_party_row`) are persist gates whose
    /// preconditions persist itself certifies per backend; what is EDGE's to
    /// get right is the reading — that the typed variant maps to the right
    /// class, that the class carries the right disposition, and that the match
    /// is on the variant and not on the message. A `Display`-shaped
    /// discriminator would pass a prose test and fail the day persist rewords
    /// a message, which is why v18.2.0 deleted the last one.
    #[test]
    fn the_typed_door_verdicts_classify_and_carry_their_disposition() {
        use ciris_persist::federation::admission::CohortStandingRefusal;
        use ciris_persist::federation::Error as E;
        use ciris_persist::scope::ScopeRefusalReason as R;

        // AV-45 (persist#757) — the two roster-ordering classes. TRANSIENT:
        // the roster simply has not landed on this node yet.
        assert_eq!(
            ApplyRefusalClass::classify(&E::WriteScopeRefused(R::NoCommunityMembership)),
            Some(ApplyRefusalClass::RetryAfterCommunityRoster),
        );
        assert_eq!(
            ApplyRefusalClass::classify(&E::WriteScopeRefused(R::NoFamilyMembership)),
            Some(ApplyRefusalClass::RetryAfterFamilyRoster),
        );
        assert!(ApplyRefusalClass::RetryAfterCommunityRoster.is_transient());
        assert!(ApplyRefusalClass::RetryAfterFamilyRoster.is_transient());

        // AV-84 (persist#757) — a policy verdict about the ROW's content, and
        // NOT a delivery problem. Terminal: nothing about it changes by
        // waiting or by retrying.
        for reason in [
            CohortStandingRefusal::AttestedParty,
            CohortStandingRefusal::NamedSubject,
        ] {
            let err = E::CohortStandingRefused {
                cohort_scope: "community".to_owned(),
                producer_key_id: "producer".to_owned(),
                foreign_key_id: "somebody-else".to_owned(),
                reason,
            };
            assert_eq!(
                ApplyRefusalClass::classify(&err),
                Some(ApplyRefusalClass::ThirdPartyRow),
            );
        }
        assert!(!ApplyRefusalClass::ThirdPartyRow.is_transient());
        assert!(!ApplyRefusalClass::CommunityRosterFork.is_transient());

        // The OTHER `WriteScopeRefused` reasons are NOT roster-ordering. A
        // wildcard-first classifier would have swept `WrongIdentity` into
        // "retry after the roster lands", which is a permanent refusal wearing
        // a transient label — the exact inversion of the silent-narrowing bug
        // this ledger exists to prevent.
        for reason in [
            R::WrongIdentity,
            R::BoundaryAuthFailed,
            R::UnauthenticatedSuppressedCohort,
            R::InvalidCohortScope("nonsense".to_owned()),
        ] {
            assert_eq!(
                ApplyRefusalClass::classify(&E::WriteScopeRefused(reason)),
                None,
                "only the two MEMBERSHIP reasons are roster-ordering",
            );
        }
        // And an error outside the #522 door set keeps the pre-adopt shape.
        assert_eq!(
            ApplyRefusalClass::classify(&E::InvalidArgument("whatever".to_owned())),
            None,
        );
        // `Conflict` is generic across planes — it means "roster fork" only at
        // the Community door, which names it at the site that knows the plane.
        assert_eq!(
            ApplyRefusalClass::classify(&E::Conflict("whatever".to_owned())),
            None,
        );
    }

    /// The ledger's key space is CLOSED and its tokens are distinct — the
    /// bounded-cardinality contract `apply_refusals_by_class` rests on.
    #[test]
    fn the_apply_refusal_classes_have_distinct_stable_tokens() {
        let tokens: std::collections::BTreeSet<&str> =
            ApplyRefusalClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            tokens.len(),
            ApplyRefusalClass::ALL.len(),
            "two classes collapsed onto one metric key: {tokens:?}",
        );
        // Snake-case, no whitespace — these are metric keys, not prose.
        for token in &tokens {
            assert!(
                token
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()),
                "{token} is not a metric-safe token",
            );
        }
    }

    /// The refusal MESSAGE keeps persist's own verdict first and appends
    /// edge's reading — so the existing `kind()` correlation still works and
    /// the class never displaces the substrate's answer.
    #[test]
    fn a_classified_refusal_names_persists_verdict_and_then_edges_class() {
        use ciris_persist::federation::Error as E;
        use ciris_persist::scope::ScopeRefusalReason as R;
        let err = E::WriteScopeRefused(R::NoCommunityMembership);
        let msg = classified_refusal_reason(
            "Attestation",
            "deadbeef",
            &err,
            ApplyRefusalClass::RetryAfterCommunityRoster,
        );
        assert!(
            msg.starts_with(&apply_refusal_reason("Attestation", "deadbeef", &err)),
            "persist's message + kind() token lead: {msg}",
        );
        assert!(msg.contains("federation_write_scope_refused"), "{msg}");
        assert!(msg.contains("class=retry_after_community_roster"), "{msg}");
        assert!(msg.contains("TRANSIENT"), "{msg}");
        let terminal = classified_refusal_reason(
            "Community",
            "deadbeef",
            &E::Conflict("forked".to_owned()),
            ApplyRefusalClass::CommunityRosterFork,
        );
        assert!(
            terminal.contains("class=community_roster_fork"),
            "{terminal}"
        );
        assert!(terminal.contains("TERMINAL"), "{terminal}");
    }

    /// persist#758 (CIRISEdge#522 item 1) — the Community door's THREE
    /// verdicts, driven through edge's real apply path on all three arms.
    ///
    /// The convergent re-put is the one that would have been silently wrong:
    /// before v38.2.0 the memory backend OVERWROTE the stored row (and its
    /// first-accepted authority signature) on a re-put, and edge's macro
    /// reported `Admitted` either way — anti-entropy progress claimed on every
    /// round that re-offers a community this node already holds.
    #[tokio::test]
    async fn the_community_door_verdicts_are_duplicate_and_named_fork() {
        let cohort = vec!["fork-member".to_string()];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        register_fixture_keys(
            &backend,
            &[
                ("fork-authority", identity_type::AGENT),
                ("fork-community", identity_type::AGENT),
                // CC 3.2 steward-binding: a non-infra community member must
                // root in an accountable human — a `user` self-anchors.
                ("fork-member", identity_type::USER),
            ],
        )
        .await;

        let signed = sign_community_fixture(
            "fork-authority",
            fixture_community("fork-community", "fork-member"),
        );
        let wire = serde_json::to_vec(&signed).expect("signed community serializes");

        // 1. Fresh row — real progress.
        assert_eq!(
            bridge
                .apply_envelope_bytes(EnvelopeKind::Community, &wire, None)
                .await,
            ApplyOutcome::Admitted,
        );

        // 2. The SAME bytes again — persist#758's idempotent `Ok` no-op. Not
        //    progress, and not a refusal either: a duplicate.
        assert_eq!(
            bridge
                .apply_envelope_bytes(EnvelopeKind::Community, &wire, None)
                .await,
            ApplyOutcome::Duplicate,
            "a convergent re-put is an idempotent no-op, not fresh state",
        );

        // 3. DIFFERING content under the occupied id — the fork.
        let mut forked = fixture_community("fork-community", "fork-member");
        forked.community_name = "A DIFFERENT CO-OP".to_string();
        let forked_wire = serde_json::to_vec(&sign_community_fixture("fork-authority", forked))
            .expect("forked community serializes");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Community, &forked_wire, None)
            .await;
        let ApplyOutcome::Refused { reason: msg, .. } = &outcome else {
            panic!("a differing roster under an occupied id must be REFUSED, got {outcome:?}");
        };
        assert!(
            msg.contains(ApplyRefusalClass::CommunityRosterFork.as_str()),
            "the fork must be NAMED, not just refused: {msg}",
        );
        assert!(
            msg.contains("TERMINAL"),
            "an apply loop must not read a fork as retryable: {msg}",
        );

        // ...and it is COUNTED. A fork nobody can see from a scrape is the
        // log-and-drop failure #522 names.
        let snap = metrics.snapshot();
        assert_eq!(
            snap.apply_refusals_by_class
                .get(ApplyRefusalClass::CommunityRosterFork.as_str())
                .copied(),
            Some(1),
            "the class axis books the fork once: {:?}",
            snap.apply_refusals_by_class,
        );
        assert_eq!(
            snap.apply_refusals_by_kind
                .get(&EnvelopeKind::Community)
                .copied(),
            Some(1),
            "and the kind axis still books it at the #425 choke",
        );
        // The DUPLICATE is not a refusal on either axis (#457's distinct
        // states): it books as a duplicate and nothing else.
        assert_eq!(
            snap.replication_duplicate_total
                .get(&EnvelopeKind::Community)
                .copied(),
            Some(1),
        );
        assert_eq!(
            snap.replication_applied_total
                .get(&EnvelopeKind::Community)
                .copied(),
            Some(1),
            "exactly ONE apply changed state across three offers",
        );

        // The stored row is the FIRST one — the fork did not overwrite it.
        let stored = backend
            .lookup_community("fork-community")
            .await
            .expect("lookup")
            .expect("the community is stored");
        assert_eq!(stored.community_name, "E4 Pin Co-op");
    }

    /// persist#757 (CIRISEdge#522 item 2) — AV-45 at the PUT door, including
    /// replicated rows, and edge's closure over it.
    ///
    /// A member's community-scoped row that reaches a node before that node
    /// applied the community's roster refuses — correctly. The whole ask is
    /// that the apply loop must not read that as terminal and must not read it
    /// as a transport failure. Edge's closure is classification, not
    /// re-ordering, and the two properties that make it a closure are asserted
    /// here: the refusal is NAMED transient on the class axis, and the row is
    /// NOT in local state afterwards — so this node still lacks its hash and
    /// the next Summary/Diff re-offers it. Convergence is by construction; the
    /// thing that was missing was the ability to TELL this apart from a real
    /// policy refusal.
    #[tokio::test]
    async fn a_community_scoped_row_ahead_of_its_roster_refuses_as_named_transient() {
        let cohort = vec!["chat-member".to_string()];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        register_fixture_keys(&backend, &[("chat-member", identity_type::USER)]).await;

        // A `chat:*` row the member signs about ITSELF (AV-84-clean), naming
        // its community in the SIGNED envelope — the target persist v38.2.0
        // resolves at the put door where it used to pass a hardcoded `None`.
        // Deliberately applied to a node that has NEVER seen `chat-community`.
        let wire = community_scoped_chat_row("chat-member", "chat-community");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("some-peer"))
            .await;
        let ApplyOutcome::Refused { reason: msg, .. } = &outcome else {
            panic!("AV-45 must refuse a row ahead of its roster, got {outcome:?}");
        };
        assert!(
            msg.contains(ApplyRefusalClass::RetryAfterCommunityRoster.as_str()),
            "the refusal must NAME itself retry-after-roster: {msg}",
        );
        assert!(
            msg.contains("TRANSIENT"),
            "an apply loop must not read this as terminal: {msg}",
        );
        assert!(
            msg.contains("federation_write_scope_refused"),
            "persist's own typed token is still the leading evidence: {msg}",
        );

        let snap = metrics.snapshot();
        assert_eq!(
            snap.apply_refusals_by_class
                .get(ApplyRefusalClass::RetryAfterCommunityRoster.as_str())
                .copied(),
            Some(1),
            "a transient refusal no counter sees is the silent-narrowing class: {:?}",
            snap.apply_refusals_by_class,
        );

        // NOT stored ⇒ still wanted ⇒ re-offered. This is the retry: there is
        // no queue to drain and nothing to re-drive by hand.
        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Attestation)
                .await
                .is_empty(),
            "the refused row must NOT be in local state — that absence is what \
             makes the next round ask for it again",
        );
    }

    /// A community-scoped `chat:*` attestation, signed by `member` about
    /// itself, naming `community_id` in the SIGNED envelope. Third-party-clean
    /// by construction (`attested_key_id` is the producer, `subject_key_ids`
    /// empty), so AV-84 has nothing to refuse and the AV-45 membership
    /// question is the one under test.
    fn community_scoped_chat_row(member: &str, community: &str) -> Vec<u8> {
        let now = Utc::now().trunc_subsecs(6);
        let mut envelope = serde_json::json!({
            "dimension": "chat:message:v1",
            "community_id": community,
            "body_hash": "0000000000000000000000000000000000000000000000000000000000000000",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            "chat-row-1",
            member,
            ciris_persist::federation::types::attestation_type::SCORES,
            member,
            &[],
            "community",
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(member, &envelope);
        let attestation = Attestation {
            attestation_id: "chat-row-1".to_string(),
            attesting_key_id: member.to_string(),
            attested_key_id: member.to_string(),
            attestation_type: ciris_persist::federation::types::attestation_type::SCORES
                .to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: member.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "community".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        serde_json::to_vec(&attestation).expect("attestation serializes")
    }

    #[tokio::test]
    async fn e4_family_membership_revocation_forward_path_preserves_authority_signature() {
        // FK: family_key_id AND removed_identity_key_id must exist in
        // federation_keys (persist checks both at put).
        let signed = sign_family_membership_revocation_fixture(
            "e4-authority",
            FamilyMembershipRevocation {
                family_key_id: "e4-family".to_string(),
                removed_identity_key_id: "e4-member".to_string(),
                removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        pin_e4_forward_path(
            EnvelopeKind::FamilyMembershipRevocation,
            &[], // tombstone plane advertises Global — no cohort needed
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-family", identity_type::AGENT),
                ("e4-member", identity_type::AGENT),
            ],
            &[],
            &signed,
            |s: &SignedFamilyMembershipRevocation| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.family_membership_revocation.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_community_membership_revocation_forward_path_preserves_authority_signature() {
        // effective_at must NOT be future-dated (SecReview F4: community
        // removal is immediate for forward secrecy).
        let signed = sign_community_membership_revocation_fixture(
            "e4-authority",
            CommunityMembershipRevocation {
                community_key_id: "e4-community".to_string(),
                removed_identity_key_id: "e4-member".to_string(),
                removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        );
        pin_e4_forward_path(
            EnvelopeKind::CommunityMembershipRevocation,
            &[],
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-community", identity_type::AGENT),
                ("e4-member", identity_type::AGENT),
            ],
            &[],
            &signed,
            |s: &SignedCommunityMembershipRevocation| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.community_membership_revocation.signing_envelope(),
        )
        .await;
    }

    #[tokio::test]
    async fn e4_location_proof_forward_path_preserves_authority_signature() {
        // "87283472bffffff" is a canonical resolution-7 H3 cell (verified
        // against h3o 0.7.1, the version in this build's dependency graph) —
        // within the §0.8.1 rough-only bound persist enforces at admission.
        let signed = sign_location_proof_fixture(
            "e4-authority",
            LocationProof {
                subject_key_id: "e4-subject".to_string(),
                cell_id: "87283472bffffff".to_string(),
                cell_resolution: 7,
                asserted_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                valid_until: None,
                attestation_evidence: None,
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        );
        pin_e4_forward_path(
            EnvelopeKind::LocationProof,
            &["e4-subject"], // cohort-scoped advertise keys on the subject
            &[
                ("e4-authority", identity_type::AGENT),
                ("e4-subject", identity_type::AGENT),
            ],
            // CIRISPersist#734 — location is SELF-KNOWLEDGE, so a distinct
            // `authority_key_id` is admissible only as a LIVE delegate of the
            // subject. The edge is seeded on BOTH nodes, through the real
            // `put_attestation` door, rather than collapsing the fixture to a
            // self-authored proof: `authority_key_id` surviving byte-identical
            // is what this test is about, and it proves nothing if the
            // authority is the subject.
            &[("e4-subject", "e4-authority")],
            &signed,
            |s: &SignedLocationProof| {
                (
                    s.authority_key_id.clone(),
                    s.scrub_signature_classical.clone(),
                    s.scrub_signature_pqc.clone(),
                )
            },
            |s| s.location_proof.signing_envelope(),
        )
        .await;
    }

    /// CIRISEdge#394 — the fail-closed half of the pass-through verdict. An
    /// UNSIGNED declaration (empty wrapper fields — the exact legacy shape a
    /// pre-v21 producer emitted) DECODES fine (the wrapper fields are
    /// additive `#[serde(default)]`) and is REFUSED at admission: a named
    /// `Refused`, never `Admitted` and never a wire-shape `Deserialize`
    /// error. Edge adds no signing of its own, so nothing on the edge side
    /// can heal — or mask — a stripped authority signature.
    #[tokio::test]
    async fn e4_unsigned_declarations_refuse_at_admission() {
        let (backend, bridge) = make_bridge(&[]);
        // Every FK'd id exists, so the ONLY failing gate is the E4 verify
        // (which runs FIRST on every put_* — verify-before-mutation).
        register_fixture_keys(
            &backend,
            &[
                ("e4-family", identity_type::AGENT),
                ("e4-community", identity_type::AGENT),
                ("e4-member", identity_type::USER),
                ("e4-subject", identity_type::AGENT),
            ],
        )
        .await;

        let unsigned: Vec<(EnvelopeKind, Vec<u8>)> = vec![
            (
                EnvelopeKind::Family,
                serde_json::to_vec(&SignedFamily {
                    family: fixture_family("e4-family", "e4-member"),
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::Community,
                serde_json::to_vec(&SignedCommunity {
                    community: fixture_community("e4-community", "e4-member"),
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::FamilyMembershipRevocation,
                serde_json::to_vec(&SignedFamilyMembershipRevocation {
                    family_membership_revocation: FamilyMembershipRevocation {
                        family_key_id: "e4-family".to_string(),
                        removed_identity_key_id: "e4-member".to_string(),
                        removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        reason: None,
                        witness_set: Vec::new(),
                        persist_row_hash: String::new(),
                    },
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::CommunityMembershipRevocation,
                serde_json::to_vec(&SignedCommunityMembershipRevocation {
                    community_membership_revocation: CommunityMembershipRevocation {
                        community_key_id: "e4-community".to_string(),
                        removed_identity_key_id: "e4-member".to_string(),
                        removed_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        effective_at: "2026-07-02T00:00:00Z".parse().expect("rfc3339"),
                        reason: None,
                        witness_set: Vec::new(),
                        persist_row_hash: String::new(),
                    },
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
            (
                EnvelopeKind::LocationProof,
                serde_json::to_vec(&SignedLocationProof {
                    location_proof: LocationProof {
                        subject_key_id: "e4-subject".to_string(),
                        cell_id: "87283472bffffff".to_string(),
                        cell_resolution: 7,
                        asserted_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                        valid_until: None,
                        attestation_evidence: None,
                        withdrawn_at: None,
                        persist_row_hash: String::new(),
                    },
                    authority_key_id: String::new(),
                    scrub_signature_classical: String::new(),
                    scrub_signature_pqc: None,
                })
                .expect("serialize"),
            ),
        ];
        for (kind, bytes) in unsigned {
            let outcome = bridge.apply_envelope_bytes(kind, &bytes, None).await;
            assert!(
                matches!(outcome, ApplyOutcome::Refused { .. }),
                "an unsigned {kind:?} must be REFUSED at persist's E4 gate \
                 (not admitted, not a wire-shape error); got {outcome:?}"
            );
        }
    }

    // ── FSD §7.1 federation-tier-only invariant fence ───────────────

    /// Local-tier (pre-promotion) attestations have no `SignedAttestation`
    /// form — persist's local-tier attestation API
    /// (`attestation_upsert_local` / `attestation_query`) stores
    /// deferred-signature rows that the federation `list_attestations_for`
    /// surface never returns.
    ///
    /// We exercise the FSD §7.1 invariant operationally: build a
    /// cohort + put NO federation attestations → expect empty refs.
    /// This is the weaker structural assertion (we can't construct a
    /// "local-tier attestation that leaks into federation" because
    /// it's structurally ineligible per CEG §10.1.5). The full
    /// substrate-side assertion (persist's bulk-list only ever
    /// returns promoted rows) is a persist-side regression test —
    /// flagged as a one-line confirmation on the FSD §7.1 ask.
    #[tokio::test]
    async fn local_tier_attestation_absent_from_list_envelope_refs() {
        let key_id = "agent-carol";
        let (backend, bridge) = make_bridge(&[key_id.to_string()]);

        // Seed a key for the attestation to attach to — but seed NO
        // federation-tier attestations. The cohort lookup runs but
        // finds nothing.
        let record = fixture_key_record(key_id, identity_type::AGENT);
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed key");

        let refs = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            refs.is_empty(),
            "no federation-tier attestations seeded → empty refs (FSD §7.1)"
        );
    }

    /// A federation-PRESENT record IS surfaced. Counter-example
    /// confirming the gate isn't over-restrictive: seed a federation-
    /// tier attestation via put_attestation → it appears.
    #[tokio::test]
    async fn federation_present_attestation_appears_in_list_envelope_refs() {
        let attesting_id = "agent-dave";
        let attested_id = "agent-eve";
        let (backend, bridge) = make_bridge(&[attesting_id.to_string(), attested_id.to_string()]);

        // Seed both keys so attestation's FK constraints satisfy.
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(attesting_id, identity_type::AGENT),
            })
            .await
            .expect("seed attesting key");
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(attested_id, identity_type::AGENT),
            })
            .await
            .expect("seed attested key");

        // Build a federation-tier attestation with real hybrid sigs
        // (v6.3.2 / CIRISEdge#166 — passes persist v9.0.0's
        // verify_federation_tier_ingest).
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "attesting_key_id": attesting_id,
            "attested_key_id": attested_id,
            "attestation_type": "delegates_to",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            attesting_id,
            "delegates_to",
            attested_id,
            &[],
            "federation",
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attesting_id, &envelope);
        let att = Attestation {
            attestation_id,
            attesting_key_id: attesting_id.to_string(),
            attested_key_id: attested_id.to_string(),
            attestation_type: "delegates_to".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: attesting_id.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "federation".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed attestation");

        let refs = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            !refs.is_empty(),
            "federation-PRESENT attestation MUST appear (FSD §7.1)"
        );
    }

    // ── CIRISEdge#397 — the load-bearing round-trip invariant ────────

    /// **The wire-critical proof.** For the Key and Attestation planes, the
    /// `envelope_hash` `list_envelope_refs` advertises MUST equal `sha256` of the
    /// exact bytes `fetch_envelope_bytes` returns for it — end-to-end, over the
    /// same `MemoryBackend` the other bridge tests use (which self-indexes the
    /// `signed_wire_index` on put, so no rebuild is needed). This closes the
    /// advertise-hash == served-bytes == point-read loop CIRISEdge#397 establishes.
    #[tokio::test]
    async fn advertise_hash_equals_sha256_of_fetched_bytes() {
        let key_id = "agent-roundtrip";
        let attester = "agent-attester";
        let (backend, bridge) = make_bridge(&[key_id.to_string(), attester.to_string()]);

        // A signed KeyRecord via the signed put path (indexes under "Key").
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(key_id, identity_type::AGENT),
            })
            .await
            .expect("seed key");
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(attester, identity_type::AGENT),
            })
            .await
            .expect("seed attester key");

        // A federation-tier (tier="federation") Attestation via put_attestation
        // (indexes under "Attestation"; cohort_scope="federation" → advertised).
        let now = Utc::now().trunc_subsecs(6);
        let attestation_id = uuid::Uuid::new_v4().to_string();
        let mut envelope = serde_json::json!({
            "attesting_key_id": attester,
            "attested_key_id": key_id,
            "attestation_type": "delegates_to",
        });
        bind_attestation_envelope(
            &mut envelope,
            now,
            &attestation_id,
            attester,
            "delegates_to",
            key_id,
            &[],
            "federation",
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attester, &envelope);
        backend
            .put_attestation(SignedAttestation {
                attestation: Attestation {
                    attestation_id,
                    attesting_key_id: attester.to_string(),
                    attested_key_id: key_id.to_string(),
                    attestation_type: "delegates_to".to_string(),
                    weight: None,
                    asserted_at: now,
                    expires_at: None,
                    attestation_envelope: envelope,
                    original_content_hash: hash,
                    scrub_signature_classical: ed_sig,
                    scrub_signature_pqc: pqc_sig,
                    scrub_key_id: attester.to_string(),
                    scrub_timestamp: now,
                    pqc_completed_at: None,
                    persist_row_hash: String::new(),
                    subject_key_ids: Vec::new(),
                    withdraws_admission_rule: None,
                    additional_scrubs: Vec::new(),
                    cohort_scope: "federation".to_string(),
                    tier: "federation".to_string(),
                    promoted_at: None,
                },
            })
            .await
            .expect("seed federation-tier attestation");

        for kind in [EnvelopeKind::Key, EnvelopeKind::Attestation] {
            let refs = bridge.list_envelope_refs(kind).await;
            assert!(!refs.is_empty(), "{kind:?} advertises at least one ref");
            for r in &refs {
                let bytes = bridge
                    .fetch_envelope_bytes(kind, &r.envelope_hash)
                    .await
                    .unwrap_or_else(|| {
                        panic!("{kind:?} point-read must serve the advertised hash")
                    });
                let served: [u8; 32] = Sha256::digest(&bytes).into();
                assert_eq!(
                    served, r.envelope_hash,
                    "{kind:?}: advertised envelope_hash MUST equal sha256(fetched bytes)"
                );
            }
        }
    }

    // ── CIRISEdge#386 — infra:serve recipient gate (trace plane) ──

    /// Seed one `delegates_to(attester → subject)` carrying `scope`, and
    /// return its `attestation_id` (so a test can tombstone that exact edge).
    async fn seed_delegates_to(
        backend: &MemoryBackend,
        attester: &str,
        subject: &str,
        scope: &serde_json::Value,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": subject,
            "attestation_type": "delegates_to",
            "scope": scope,
        });
        seed_raw_attestation(backend, &id, attester, subject, "delegates_to", envelope).await;
        id
    }

    /// Seed a root's SELF-CHARTER — `delegates_to(root → root)`. persist v19
    /// (CIRISPersist#488) tightened this shape twice, and both are enforced at
    /// admission, so the fixture carries what the field must carry:
    /// `scope` must contain BOTH `infra:serve` AND `infra:attest` (the finalized
    /// charter minimum; v18's OR is gone), and the envelope must carry a
    /// well-formed `pre_rotation_commitment` — sha256 over the canonicalized,
    /// sorted pre-committed successor key set — without which root-key
    /// compromise is unrecoverable by construction (the KERI prior-art lesson).
    /// Built with persist's own `pre_rotation_commitment` helper rather than a
    /// hand-rolled digest, so the fixture cannot drift from the verifier.
    async fn seed_root_charter(
        backend: &MemoryBackend,
        root: &str,
        successor_keys: &[String],
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let commitment =
            ciris_persist::federation::trust_root::pre_rotation_commitment(successor_keys)
                .expect("pre-rotation commitment");
        let envelope = serde_json::json!({
            "id": id,
            "references_attestation_id": id,
            "attesting_key_id": root,
            "attested_key_id": root,
            "attestation_type": "delegates_to",
            "scope": ["infra:serve", "infra:attest"],
            "pre_rotation_commitment": commitment,
        });
        seed_raw_attestation(backend, &id, root, root, "delegates_to", envelope).await;
        id
    }

    /// Seed a fresh `accord:lifecycle:v1` scores row ABOUT `root` — the
    /// liveness leg of `trust_root_valid`.
    /// A DRILL row. `accord:lifecycle:v1` is the one dimension whose root rule
    /// persist defines for itself (`trust_root_valid` resolves drills as
    /// `list_attestations_for(root)` filtered to it), so `attested_key_id` IS the
    /// accord and no signed `accord_root` key is required — persist v37.0.0's
    /// write door accepts this shape unchanged
    /// (`AccordRootClaim::Named { source: HeartbeatDimensionRule }`).
    async fn seed_accord_lifecycle(backend: &MemoryBackend, attester: &str, root: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": root,
            "attestation_type": "scores",
            "dimension": "accord:lifecycle:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        seed_raw_attestation(backend, &id, attester, root, "scores", envelope).await;
    }

    /// v37.0.0 (CIRISPersist#733) — an `accord:*` row on a NON-drill dimension,
    /// naming its own accord with the SIGNED `accord_root` envelope key.
    ///
    /// `accord:human_dignity:v1` is the field shape that motivated the key:
    /// `attested_key_id` there is the AGENT BEING SCORED, never a root, so before
    /// #733 nothing on the row said which accord it acted under and edge's gate
    /// refused every such row outright. The key is now REQUIRED at the write door
    /// (`check_accord_root_binding`), which is why this fixture carries it — a
    /// producer that omits it is refused at admission, and edge's fixtures are
    /// producers in exactly that sense.
    async fn seed_accord_scored(
        backend: &MemoryBackend,
        attester: &str,
        scored: &str,
        accord_root: &str,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": scored,
            "attestation_type": "scores",
            "dimension": "accord:human_dignity:v1",
            "accord_root": accord_root,
            "score": 1.0,
            "confidence": 0.9,
        });
        seed_raw_attestation(backend, &id, attester, scored, "scores", envelope).await;
    }

    /// CIRISEdge#505 / CIRISPersist#743 — an `accord:*` row in the **TYPE
    /// namespace**: `attestation_type = "accord:invoke:…"`, NO `dimension` key
    /// at all, naming its accord with the signed `accord_root` envelope key.
    ///
    /// This is the OTHER half of persist's two-namespace admission rule
    /// (*"`accord:invoke:*` as a TYPE, `accord:human_dignity:v1` as a `scores`
    /// DIMENSION"*), and the wire shape the pre-#505 pre-filter never showed
    /// the relay gate. The invoke shape is self-attesting
    /// (`attested_key_id` = the holder — persist #733: "the SELF-ATTESTING
    /// HOLDER"), and admission requires the attesting key's `identity_type` to
    /// be `accord_holder` (CC 3.4.1) plus the signed root
    /// (`check_accord_root_binding`) — the fixture goes through the REAL write
    /// door, so it carries what the field must carry.
    async fn seed_accord_invoke(backend: &MemoryBackend, holder: &str, accord_root: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": holder,
            "attested_key_id": holder,
            "attestation_type": "accord:invoke:notify:halt",
            "accord_root": accord_root,
        });
        seed_raw_attestation(
            backend,
            &id,
            holder,
            holder,
            "accord:invoke:notify:halt",
            envelope,
        )
        .await;
    }

    /// Seed a `withdraws` composer tombstoning `target_id` — the CEG un-trust
    /// primitive. Shape mirrors persist's own `fix_withdraws` witness: the
    /// composer references its target through `references_attestation_id`
    /// (CEG §3.2, read by `precedence::references_attestation_id_from_envelope`)
    /// and is attested BY the issuer ABOUT itself, since same-attester authority
    /// is what admits a withdrawal of one's own edge.
    #[cfg(feature = "test-anchor")]
    async fn seed_withdraws(backend: &MemoryBackend, attester: &str, target_id: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": attester,
            "attested_key_id": attester,
            "attestation_type": "withdraws",
            "references_attestation_id": target_id,
            "withdrawal_reason": "test: operator un-trusts the root",
        });
        seed_raw_attestation(backend, &id, attester, attester, "withdraws", envelope).await;
    }

    /// Seed ONE `trace:complete:v1` scores row in the shape persist v18.1.0's
    /// Information-Type validator admits (trace_id + agent_id_hash + trace).
    /// (Un-`cfg`d for CIRISEdge#433: the withhold-ledger tests below seed the same
    /// gated row on the default feature set, so this is no longer test-anchor-only.)
    async fn seed_trace_attestation(backend: &MemoryBackend, producer: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": producer,
            "attested_key_id": producer,
            "attestation_type": "scores",
            "dimension": "trace:complete:v1",
            "trace_id": "t-fixture-1",
            "agent_id_hash": "ah-fixture-1",
            "trace": { "steps": [] },
        });
        seed_raw_attestation(backend, &id, producer, producer, "scores", envelope).await;
    }

    /// Find the seeded trace row by CONTENT in the bridge's own projection —
    /// robust to however many trust-graph rows share the plane.
    async fn locate_trace_hash(bridge: &FederationDirectoryReplicationBridge) -> [u8; 32] {
        let all = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        let mut found = None;
        for r in &all {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                .await
                .expect("projection-only fetch");
            if FederationDirectoryReplicationBridge::envelope_requires_serve(&bytes) {
                assert!(found.is_none(), "exactly one trace row was seeded");
                found = Some(r.envelope_hash);
            }
        }
        found.expect("the seeded trace row appears in the local view")
    }

    async fn seed_raw_attestation(
        backend: &MemoryBackend,
        id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
    ) {
        seed_scoped_attestation(
            backend,
            id,
            attester,
            subject,
            attestation_type,
            "federation",
            envelope,
        )
        .await;
    }

    /// CIRISEdge#352 — [`seed_raw_attestation`] with an explicit
    /// `cohort_scope`, for tests exercising the advertise projection across
    /// the audience axis. `self` / `affiliations` / `federation` are the
    /// membership-free scopes MemoryBackend's write gate admits without
    /// family/community rows (`family`/`community` require seeded
    /// membership).
    /// CIRISPersist#598 + #643 (v31.0.0) — stamp the SIGNED bindings an attestation
    /// envelope must now carry before signing, so the scrub signature covers them:
    /// the `asserted_at` instant (the fold orders on it) and the `row` mirror of the
    /// typed columns (else a relay rewrites attestation_id/attester/type/subject/
    /// cohort while the signature still verifies — the subject-blindness class).
    /// `subject_key_ids` omitted ⇔ the column is empty; `weight` omitted ⇔ NULL.
    /// The single sink every attestation fixture routes through.
    #[allow(clippy::too_many_arguments)] // mirrors the attestation's typed-column set
    fn bind_attestation_envelope(
        envelope: &mut serde_json::Value,
        asserted_at: chrono::DateTime<chrono::Utc>,
        attestation_id: &str,
        attesting_key_id: &str,
        attestation_type: &str,
        attested_key_id: &str,
        subject_key_ids: &[&str],
        cohort_scope: &str,
    ) {
        let Some(obj) = envelope.as_object_mut() else {
            return;
        };
        obj.entry("asserted_at")
            .or_insert_with(|| serde_json::json!(asserted_at.to_rfc3339()));
        let mut row = serde_json::json!({
            "attestation_id": attestation_id,
            "attesting_key_id": attesting_key_id,
            "attestation_type": attestation_type,
            "attested_key_id": attested_key_id,
            "cohort_scope": cohort_scope,
        });
        if !subject_key_ids.is_empty() {
            row["subject_key_ids"] = serde_json::json!(subject_key_ids);
        }
        obj.entry("row").or_insert(row);
    }

    async fn seed_scoped_attestation(
        backend: &MemoryBackend,
        id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        cohort_scope: &str,
        mut envelope: serde_json::Value,
    ) {
        // CIRISPersist#598 (v31.0.0): truncate to MICROSECONDS — postgres TIMESTAMPTZ
        // can't store sub-µs, so a producer that mints ns precision makes an op
        // sequence a strict order on sqlite/memory but a TIE on postgres. The fold
        // refuses ns rows outright.
        let now = Utc::now().trunc_subsecs(6);
        // #598: the fold orders on the `asserted_at` COLUMN, so that instant must be
        // SIGNED — stamp it into the envelope (matching the column) before signing,
        // or the row is REFUSED as an unbound replay. RFC3339, the shape persist's
        // own fixtures bind.
        bind_attestation_envelope(
            &mut envelope,
            now,
            id,
            attester,
            attestation_type,
            subject,
            &[subject],
            cohort_scope,
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attester, &envelope);
        let att = Attestation {
            attestation_id: id.to_string(),
            attesting_key_id: attester.to_string(),
            attested_key_id: subject.to_string(),
            attestation_type: attestation_type.to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: attester.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_string()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: cohort_scope.to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        };
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("seed trust-graph attestation");
    }

    /// CIRISEdge#523 — [`seed_scoped_attestation`]'s row WITHOUT the put: the
    /// signed, bound `Attestation` a peer would hand edge on the wire. Needed
    /// wherever a test must drive a row through `apply_envelope_bytes` (the real
    /// receive path, which is where the memo invalidation hangs) rather than
    /// side-loading it into the backend — seeding first and applying second
    /// collides on `attestation_id`.
    fn build_federation_attestation(
        id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        envelope: serde_json::Value,
    ) -> Attestation {
        build_scoped_federation_attestation(
            id,
            attester,
            subject,
            attestation_type,
            envelope,
            "federation",
        )
    }

    /// v18.5.0 (persist v38.3.0 / CIRISPersist#765) —
    /// [`build_federation_attestation`] with an explicit `cohort_scope`, so a
    /// test can drive a `community`-scoped row through the REAL receive path.
    /// Federation TIER is not a parameter: persist's
    /// `check_targeted_cohort_requires_federation_tier` refuses a targeted
    /// cohort at any other tier (a lower tier is signature-exempt, so the
    /// membership claim would be mintable by anyone), and a fixture that could
    /// express the refused shape would be testing a door that is already shut.
    fn build_scoped_federation_attestation(
        id: &str,
        attester: &str,
        subject: &str,
        attestation_type: &str,
        mut envelope: serde_json::Value,
        cohort_scope: &str,
    ) -> Attestation {
        let now = Utc::now().trunc_subsecs(6); // #598 microsecond floor
        bind_attestation_envelope(
            &mut envelope,
            now,
            id,
            attester,
            attestation_type,
            subject,
            &[subject],
            cohort_scope,
        );
        let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(attester, &envelope);
        Attestation {
            attestation_id: id.to_string(),
            attesting_key_id: attester.to_string(),
            attested_key_id: subject.to_string(),
            attestation_type: attestation_type.to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: hash,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: attester.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_string()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: cohort_scope.to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        }
    }

    /// CIRISEdge#462 — build a minimal `Attestation` carrying `dimension` inside
    /// its envelope (CC 2.1), for the pure G2-carve predicate test. All other
    /// fields are placeholders — only `attestation_envelope/dimension` is read.
    fn att_with_dimension(dimension: Option<&str>) -> Attestation {
        let now = Utc::now();
        Attestation {
            attestation_id: "t".into(),
            attesting_key_id: "a".into(),
            attested_key_id: "s".into(),
            attestation_type: "scores".into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: match dimension {
                Some(d) => serde_json::json!({ "dimension": d }),
                None => serde_json::json!({}),
            },
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: "a".into(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec!["s".into()],
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "federation".into(),
            tier: "federation".into(),
            promoted_at: None,
        }
    }

    /// CIRISEdge#462 — the G2 carve is persist's authoritative retainability
    /// ALLOWLIST (`is_subject_retainable`, CIRISPersist#635), keyed on authorship.
    /// A scored dimension is carved UNLESS persist affirms the subject is its
    /// author. This is FAIL-CLOSED: unlike the earlier capacity-only carve, ANY
    /// peer-authored score — capacity, capacity_assurance, moderation, or an
    /// unknown/new family — is withheld. Self-authored scores (trace:*) and
    /// dimensionless conferrals (delegates_to) are kept.
    #[test]
    fn g2_carve_is_persist_retainability_allowlist() {
        use FederationDirectoryReplicationBridge as B;
        // Peer-authored scores about the subject — ALL carved (fail-closed
        // allowlist), including families the old capacity-only carve missed.
        for carved in [
            "capacity:core_identity:v1",       // the canonical G2 reputation score
            "capacity_assurance:composite:v1", // the old carve LET THIS THROUGH
            "moderation:removal:v1",           // ditto — now correctly carved
            "some_future:score:v9",            // unknown family → fail-closed → carved
        ] {
            assert!(
                B::is_non_retainable_score(&att_with_dimension(Some(carved))),
                "{carved} is not in persist's retainable allowlist — carved (G2, fail-closed)"
            );
        }
        // Self-authored (allowlisted) scores are kept here (trace:* is separately
        // E3-gated at fetch).
        assert!(
            !B::is_non_retainable_score(&att_with_dimension(Some("trace:coherence:v1"))),
            "trace:* is self-emission-mandatory (retainable); kept here, E3-gated at fetch"
        );
        // FAIL-CLOSED: a SCORES row with NO dimension is carved, not served — a
        // missing/malformed dimension must never fall open on the data-subject axis
        // (Codex on #470 round 2). `att_with_dimension` builds attestation_type=scores.
        assert!(
            B::is_non_retainable_score(&att_with_dimension(None)),
            "a scores row with no dimension is carved (fail-closed); it is NOT a conferral"
        );
    }

    /// Codex on #470 — the carve keys on the SCORES PLANE, not on has-a-dimension.
    /// `self_at_login` proves conferrals CAN be dimension-bearing
    /// (`self:delegates_to:agent_occurrence:v1`, src/edge.rs), and that dimension is
    /// NOT in persist's retainable allowlist — so a has-dimension gate would carve
    /// the delegation OUT of the very pull the receive axis exists to recover. The
    /// control proves the discriminator is `attestation_type`, not the dimension.
    #[test]
    fn g2_carve_keeps_dimension_bearing_conferrals() {
        use FederationDirectoryReplicationBridge as B;
        let dim = "self:delegates_to:agent_occurrence:v1";
        let mut conferral = att_with_dimension(Some(dim));
        conferral.attestation_type = "delegates_to".into();
        assert!(
            !B::is_non_retainable_score(&conferral),
            "a dimension-bearing delegates_to conferral is retained by TYPE, never carved"
        );
        // Control: the SAME non-retainable dimension on a SCORES-type row IS carved.
        assert!(
            B::is_non_retainable_score(&att_with_dimension(Some(dim))),
            "the same non-retainable dimension on a scores-type row is still carved (fail-closed)"
        );
        // A DIMENSIONLESS conferral is kept by TYPE — NOT because it lacks a
        // dimension (a dimensionless SCORES row is carved, fail-closed).
        let mut dimensionless_conferral = att_with_dimension(None);
        dimensionless_conferral.attestation_type = "delegates_to".into();
        assert!(
            !B::is_non_retainable_score(&dimensionless_conferral),
            "a dimensionless conferral is kept by TYPE (the moderation-duty shape)"
        );
    }

    /// v16 review (#3): the FETCH first-party classifier. Author (sender axis),
    /// primary subject, and any co-subject are first-party; an unrelated peer is not.
    #[test]
    fn attestation_is_first_party_to_matches_author_and_subject() {
        use FederationDirectoryReplicationBridge as B;
        let att = serde_json::json!({
            "attesting_key_id": "author-A",
            "attested_key_id": "subject-S",
            "subject_key_ids": ["subject-S", "co-subject-C"],
            "dimension": "x",
        });
        assert!(B::attestation_is_first_party_to(&att, "author-A")); // sender axis
        assert!(B::attestation_is_first_party_to(&att, "subject-S")); // primary subject
        assert!(B::attestation_is_first_party_to(&att, "co-subject-C")); // data-subject set
        assert!(!B::attestation_is_first_party_to(&att, "stranger-X")); // still #396-gated
                                                                        // Missing fields must not false-positive into a first-party bypass.
        assert!(!B::attestation_is_first_party_to(
            &serde_json::json!({}),
            "anyone"
        ));
    }

    /// v16 review (#3): the FETCH honors first-party right, matching the Pull LIST
    /// gate. A subject fetching a `delegates_to` ABOUT itself gets the bytes even
    /// though the node granted it NO #396 consent-membership — while a third party
    /// with no consent is still withheld. Closes the list-wider-than-fetch gap (a
    /// ref listed then unfetchable).
    #[tokio::test]
    async fn first_party_fetch_overrides_producer_advertise_consent() {
        let local = "this-node";
        let producer = "author-A";
        let subject = "subject-S";
        let stranger = "stranger-X";
        let (backend, bridge) = make_bridge(&[
            local.to_string(),
            producer.to_string(),
            subject.to_string(),
            stranger.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for kid in [local, producer, subject, stranger] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // A delegates_to ABOUT the subject, authored by the producer, with NO consent
        // grant/membership for anyone → #396 withholds every THIRD party.
        seed_delegates_to(
            &backend,
            producer,
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        // The subject's own Pull LISTS the ref (entitlement fail-closed to the subject).
        let refs = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await;
        assert!(!refs.is_empty(), "the subject lists its own delegates_to");
        let hash = refs[0].envelope_hash;

        // FIRST-PARTY: the subject fetches its own testimony despite no #396 consent.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hash, Some(subject))
                .await
                .is_some(),
            "the data-subject fetches its own row — first-party overrides #396"
        );
        // THIRD-PARTY: a stranger with no consent-membership is still withheld.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &hash, Some(stranger))
                .await
                .is_none(),
            "a third party without #396 consent still cannot fetch it (the gate holds)"
        );
    }

    /// CIRISEdge#462 — the subject-scoped serve reader answers the SUBJECT with
    /// its testimony across BOTH axes (ABOUT-me via the data-subject axis +
    /// authored-BY-me via the sender axis), never leaks another subject's rows,
    /// and serves NOTHING to a requester that is not the subject (fail-closed).
    #[tokio::test]
    async fn subject_pull_serves_both_axes_and_fails_closed() {
        let subject = "eric-moore-v2-portable";
        let other = "some-other-subject";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);

        // Every attester AND attested key must exist in federation_keys to seed
        // a delegates_to attestation.
        for kid in [subject, other, "peer-attester"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register attester key");
        }

        // ABOUT the subject — the data-subject axis.
        seed_delegates_to(
            &backend,
            "peer-attester",
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;
        // BY the subject about someone else — the sender axis (authorship recovery).
        seed_delegates_to(
            &backend,
            subject,
            other,
            &serde_json::json!(["infra:serve"]),
        )
        .await;
        // About a DIFFERENT subject, by a peer — neither of S's axes; must not leak.
        seed_delegates_to(
            &backend,
            "peer-attester",
            other,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        let refs = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await;
        assert_eq!(
            refs.len(),
            2,
            "subject pull = {{about-me (data-subject), by-me (sender)}}; the other \
             subject's peer-authored row never leaks"
        );

        // Fail-closed entitlement: a requester ≠ subject, or an unattributed one,
        // gets nothing.
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, Some("intruder"))
                .await
                .is_empty(),
            "a Pull for S by a requester ≠ S serves nothing (#462 fail-closed)"
        );
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, None)
                .await
                .is_empty(),
            "an unattributed Pull serves nothing"
        );
    }

    /// CIRISEdge#552 — a third-party signer IS queued (a conferred server will
    /// answer for it), and one peer cannot crowd out another's recovery.
    ///
    /// The axis-3 widening is what makes third-party recovery possible: a
    /// responder holding `infra:serve` answers an identifier Pull for any
    /// subject on a public plane. So the queue accepts names this node cannot
    /// resolve locally, `source_peer` is a routing HINT rather than a
    /// requirement, and an unrouted name is offered to successive peers until a
    /// conferred one answers.
    ///
    /// That reopens the flood vector a bare cap leaves — a peer manufacturing
    /// unique nonexistent signers — so eviction is charged to the LARGEST
    /// source, never to whoever arrived last. An honest peer's one revocation
    /// signer survives a flood of thousands.
    #[tokio::test]
    async fn a_flooding_peer_cannot_crowd_out_another_peers_signer_recovery() {
        let (_backend, bridge) = test_fixtures::make_bridge(&[]);
        let bridge =
            bridge.with_serve_tier_for_test(crate::replication::serve_tier::ServeTier::MeshServer);

        // A hostile peer manufactures far more than the cap.
        for i in 0..(MISSING_SIGNER_CAP + 500) {
            bridge.note_missing_signer(
                EnvelopeKind::Attestation,
                &format!("nonexistent-{i}"),
                Some("peer-flood"),
            );
        }
        assert!(
            bridge.tracked_missing_signers() <= MISSING_SIGNER_CAP,
            "the queue stays bounded: {} entries",
            bridge.tracked_missing_signers()
        );

        // The honest peer's revocation signer — a THIRD PARTY, which is exactly
        // what the widening made fetchable.
        bridge.note_missing_signer(EnvelopeKind::Revocation, "revoker-key", Some("peer-honest"));
        assert_eq!(
            bridge.take_missing_signer_for("peer-honest").as_deref(),
            Some("revoker-key"),
            "a third-party signer must be queued and routed to the peer that \
             delivered the row — one peer's noise may not suppress another's \
             revocation"
        );
    }

    /// An UNROUTED name (a contact lookup has no delivering peer) is offered to
    /// any coordinator, so successive rounds try successive peers until a
    /// conferred server answers — and a routed name is never downgraded by it.
    #[tokio::test]
    async fn an_unrouted_name_is_offered_to_any_peer() {
        let (_backend, bridge) = test_fixtures::make_bridge(&[]);
        let bridge =
            bridge.with_serve_tier_for_test(crate::replication::serve_tier::ServeTier::MeshServer);

        bridge.note_missing_signer(EnvelopeKind::Key, "wanted-C", None);
        assert_eq!(
            bridge.take_missing_signer_for("any-peer").as_deref(),
            Some("wanted-C"),
            "an unrouted name is available to whichever coordinator asks — that \
             is how a contact lookup reaches a conferred server"
        );

        bridge.note_missing_signer(EnvelopeKind::Key, "wanted-D", Some("peer-9"));
        bridge.note_missing_signer(EnvelopeKind::Key, "wanted-D", None);
        assert_eq!(
            bridge.take_missing_signer_for("someone-else"),
            None,
            "a known holder beats ask-anyone; a later unrouted note must not \
             erase the routing hint"
        );
        assert_eq!(
            bridge.take_missing_signer_for("peer-9").as_deref(),
            Some("wanted-D")
        );
    }

    /// FSD_RATE_LIMIT §5.4 — identifier lookups are rate limited per
    /// requesting peer; the subject and own-record arms are NOT.
    ///
    /// A conferred server answering by name is the one place bulk harvesting is
    /// possible, one named subject at a time. That bound is nominal until
    /// something enforces it. The exemptions are deliberate: a data subject
    /// asking about itself is exercising an access right, and a node's own
    /// record is what `self_own` already advertises to everyone — charging
    /// either against a harvesting budget would throttle the two flows that
    /// cannot harvest anything.
    #[tokio::test]
    async fn identifier_lookups_are_rate_limited_but_subject_access_is_not() {
        let local = "local-A";
        let third_party = "subject-S";
        let stranger = "stranger-X";
        let (_backend, bridge) =
            test_fixtures::make_bridge_with_keys(&[local, third_party, stranger]).await;
        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            // Canonical: the tier that HOLDS BODIES and therefore answers
            // identifier lookups. With MeshServer this test would pass for the
            // wrong reason — every lookup returns empty because it has no
            // bodies, not because the budget bound it.
            .with_serve_tier_for_test(crate::replication::serve_tier::ServeTier::Canonical);

        // Spend the whole third-party budget.
        let budget = FederationDirectoryReplicationBridge::IDENTIFIER_LOOKUPS_PER_WINDOW;
        for _ in 0..budget {
            let _ = bridge
                .subject_holdings(EnvelopeKind::Key, third_party, Some(stranger))
                .await;
        }
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Key, third_party, Some(stranger))
                .await
                .is_empty(),
            "past its budget a peer gets nothing — walking a fedID dictionary \
             is the shape this bounds"
        );

        // The SUBJECT asking about itself is unaffected by that flood.
        assert!(
            !bridge
                .subject_holdings(EnvelopeKind::Key, stranger, Some(stranger))
                .await
                .is_empty(),
            "a data subject's access right is not a harvesting budget"
        );
        // And so is a request for this node's OWN record.
        assert!(
            !bridge
                .subject_holdings(EnvelopeKind::Key, local, Some(stranger))
                .await
                .is_empty(),
            "the own record is what self_own already advertises to everyone"
        );
    }

    /// Federation-cohort identifier lookups are entitled by a MUTUAL TRUST
    /// ROOT — not by a serving tier.
    ///
    /// node/fed/agent IDs are federation cohort: servable by any peer holding
    /// them, to any requester under a shared root, and any node that received
    /// an ID may hold it (unless revoked or superseded) because any ID may be
    /// load-bearing. An earlier revision gated this on the canonical rung,
    /// which was too narrow — it stopped the fleet's storage helpers answering
    /// for records they legitimately hold.
    ///
    /// CC 4 is the rule: two nodes under one shared root cross-attest and
    /// vouch; two nodes with no shared root compose nothing. So the question is
    /// whether the requester is in the same trust domain, and abuse is bounded
    /// by HOW MUCH one peer may extract, not by who may answer.
    #[tokio::test]
    async fn identifier_lookups_are_entitled_by_a_mutual_trust_root() {
        let local = "local-A";
        let third_party = "subject-S";
        let stranger = "stranger-X";
        let root = "root-R";
        let scope = serde_json::json!(["infra:serve"]);

        // ── No shared root: refused, whatever tier this node holds.
        for tier in [
            crate::replication::serve_tier::ServeTier::MeshServer,
            crate::replication::serve_tier::ServeTier::Canonical,
        ] {
            let (_b, bridge) =
                test_fixtures::make_bridge_with_keys(&[local, third_party, stranger, root]).await;
            let bridge = bridge
                .with_local_key_id(Some(local.to_string()))
                .with_serve_tier_for_test(tier);
            assert!(
                bridge
                    .subject_holdings(EnvelopeKind::Key, third_party, Some(stranger))
                    .await
                    .is_empty(),
                "{tier:?}: no mutual root ⇒ nothing composes, whatever the tier"
            );
        }

        // ── Shared root: answered, and the tier is not what decides it.
        for tier in [
            crate::replication::serve_tier::ServeTier::MeshServer,
            crate::replication::serve_tier::ServeTier::Canonical,
        ] {
            let (backend, bridge) =
                test_fixtures::make_bridge_with_keys(&[local, third_party, stranger, root]).await;
            // Both hang their trust off the same root (CC 4's shape).
            seed_delegates_to(&backend, local, root, &scope).await;
            seed_delegates_to(&backend, stranger, root, &scope).await;
            let bridge = bridge
                .with_local_key_id(Some(local.to_string()))
                .with_serve_tier_for_test(tier);

            assert!(
                !bridge
                    .subject_holdings(EnvelopeKind::Key, third_party, Some(stranger))
                    .await
                    .is_empty(),
                "{tier:?}: a shared root entitles the lookup — a storage helper \
                 must be able to answer for records it legitimately holds"
            );
            // The two arms that never depended on any of this.
            assert!(
                !bridge
                    .subject_holdings(EnvelopeKind::Key, stranger, Some(stranger))
                    .await
                    .is_empty(),
                "{tier:?}: a data subject's own access is unconditional"
            );
            assert!(
                bridge
                    .subject_holdings(EnvelopeKind::Key, third_party, None)
                    .await
                    .is_empty(),
                "{tier:?}: unattributed still serves nothing"
            );
            assert!(
                bridge
                    .subject_holdings(EnvelopeKind::Attestation, third_party, Some(stranger))
                    .await
                    .is_empty(),
                "{tier:?}: Attestation entitlement stays per ROW"
            );
        }
    }

    /// CIRISEdge#462 — seed `subject`'s `consent:state:granted` for `covers` on
    /// the `analyze` scope, so a peer-authored `capacity:*` row about `subject`
    /// clears persist's `check_capacity_consent_admission` gate
    /// (`resolve_scoped_consent(attester, subject, "analyze") == Granted`). Lets
    /// the G2 test admit REAL capacity data rather than assert on a synthetic
    /// struct.
    async fn seed_analyze_consent(backend: &MemoryBackend, subject: &str, covers: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        seed_scoped_attestation(
            backend,
            &id,
            subject,
            covers,
            "scores",
            "federation",
            serde_json::json!({ "dimension": "consent:state:granted:v1", "scope": ["analyze"] }),
        )
        .await;
    }

    /// CIRISEdge#462 — the G2 carve holds on REAL admitted capacity data and is
    /// AXIS-SPECIFIC. Modeled as store mutations so the security assumption is
    /// proven on the real serve path, not just the predicate:
    ///   MUTATION 1 — a peer-authored `capacity:*` score ABOUT me is carved from
    ///     the pull (it must NEVER land on the node where I am the sole writer:
    ///     the G2 self-revocation-hole shape).
    ///   MUTATION 2 — a `capacity:*` score I AUTHORED about someone else IS
    ///     recoverable (the carve must not be over-broad and eat my own
    ///     authorship).
    #[tokio::test]
    async fn g2_carve_holds_on_real_capacity_data_and_is_axis_specific() {
        let subject = "subject-s";
        let peer = "peer-p";
        let other = "other-t";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);
        for kid in [subject, peer, other] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        // Consents that let the capacity rows admit: S grants P (so P may score
        // S); T grants S (so S may score T). Both are `scores` attestations that
        // also ride S's pull axes — so we snapshot the BASELINE after seeding them
        // and assert only the DELTAS the two capacity mutations produce.
        seed_analyze_consent(&backend, subject, peer).await;
        seed_analyze_consent(&backend, other, subject).await;
        // A benign attestation ABOUT S (data-subject axis).
        seed_delegates_to(&backend, peer, subject, &serde_json::json!(["infra:serve"])).await;

        let baseline = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await
            .len();

        // MUTATION 1 — a peer-authored capacity score ABOUT S. It admits (S
        // granted P), but the pull must be UNCHANGED: the score is carved.
        seed_scoped_attestation(
            &backend,
            "cap-p-about-s",
            peer,
            subject,
            "scores",
            "federation",
            serde_json::json!({ "dimension": "capacity:core_identity:v1" }),
        )
        .await;
        assert_eq!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
                .await
                .len(),
            baseline,
            "G2: a peer-authored capacity score ABOUT me is carved — it must not be pullable \
             onto my own node (the self-revocation-hole shape)"
        );

        // MUTATION 2 — a capacity score S AUTHORED about T (sender axis). It
        // admits (T granted S), and the pull MUST gain it: authorship recovery,
        // the carve is not over-broad.
        seed_scoped_attestation(
            &backend,
            "cap-s-about-t",
            subject,
            other,
            "scores",
            "federation",
            serde_json::json!({ "dimension": "capacity:integrity:v1" }),
        )
        .await;
        assert_eq!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
                .await
                .len(),
            baseline + 1,
            "axis-specific: a capacity score I AUTHORED (sender axis) is recoverable — the carve \
             must not eat my own authorship"
        );
    }

    /// CIRISEdge#462 — entitlement DISCRIMINATES, it is not deny-all. Two legit
    /// registered subjects each hold testimony: each pulls its OWN and gets it;
    /// neither can pull the OTHER's (the impersonation mutation). This is the
    /// fail-closed gate proving it still serves the rightful subject.
    #[tokio::test]
    async fn subject_pull_entitlement_discriminates() {
        let s = "subject-s";
        let t = "subject-t";
        let (backend, bridge) = make_bridge(&[s.to_string(), t.to_string()]);
        for kid in [s, t, "peer-p"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        // Each subject has one attestation ABOUT it.
        seed_delegates_to(&backend, "peer-p", s, &serde_json::json!(["infra:serve"])).await;
        seed_delegates_to(&backend, "peer-p", t, &serde_json::json!(["infra:serve"])).await;

        let s_pulls_s = bridge
            .subject_holdings(EnvelopeKind::Attestation, s, Some(s))
            .await;
        let t_pulls_t = bridge
            .subject_holdings(EnvelopeKind::Attestation, t, Some(t))
            .await;
        assert!(!s_pulls_s.is_empty(), "S pulling S gets S's testimony");
        assert!(
            !t_pulls_t.is_empty(),
            "T pulling T gets T's testimony (not deny-all)"
        );

        // The impersonation mutation: S authenticated, pulling T's subject — and
        // vice versa — gets NOTHING. The gate discriminates on the subject.
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, t, Some(s))
                .await
                .is_empty(),
            "S must not pull T's testimony (impersonation blocked)"
        );
        assert!(
            bridge
                .subject_holdings(EnvelopeKind::Attestation, s, Some(t))
                .await
                .is_empty(),
            "T must not pull S's testimony (impersonation blocked)"
        );
    }

    /// CIRISEdge#462 (Codex #463 Finding 2) — a Pull ref must not DISCLOSE a row
    /// the requester could not be served. A `trace:*` row is E3-confidential
    /// (`infra:serve` only); a subject WITHOUT that capability must not even learn
    /// the row exists (its hash + seq) — so it is gated OUT of the Summary, not
    /// merely withheld at Deliver. A non-trace attestation about the subject (its
    /// first-party testimony) is served regardless — the pull gate is E3
    /// confidentiality, NOT the #396 producer-advertise-consent bound.
    #[tokio::test]
    async fn subject_pull_gates_trace_refs_it_cannot_serve() {
        let subject = "subject-s";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);
        for kid in [subject, "peer-p"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        // Non-trace testimony ABOUT the subject — served (first-party right; not
        // #396-gated).
        seed_delegates_to(
            &backend,
            "peer-p",
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;
        let before = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await
            .len();
        assert_eq!(
            before, 1,
            "the subject's non-trace testimony is served (not gated by the producer's #396 consent)"
        );

        // A trace:* row about the subject (self-emitted). The subject holds no
        // infra:serve capability, so the row must NOT appear in the pull refs —
        // no hash/seq disclosure of a row that Deliver would withhold.
        seed_trace_attestation(&backend, subject).await;
        let after = bridge
            .subject_holdings(EnvelopeKind::Attestation, subject, Some(subject))
            .await
            .len();
        assert_eq!(
            after, before,
            "a trace:* row the requester cannot be served is gated OUT of the Pull refs \
             (E3 confidentiality — no ref info-leak)"
        );
    }

    /// CIRISPersist#659 (v31.0.0) — SPOOFING PROOF (the Revocation plane).
    ///
    /// A signed revocation now binds `revoked_key_id` (and its sibling typed
    /// columns) INTO the signed envelope. Pre-v31 that column was UNSIGNED, so a
    /// single genuine revocation could be re-pointed at ANY key: a relay repaints
    /// the column, the scrub signature still verifies over the (now-mismatched)
    /// envelope, and the row de-admits whatever the column names — one signature,
    /// unbounded reach (the subject-blindness class: possession of a signed blob
    /// conferred authority over a key the signer never named). This exercises the
    /// binding gate directly — `check_revocation_envelope_binding`, which EVERY
    /// store's admit path (memory / sqlite / postgres / tier_ingest) runs — proving
    /// the honestly bound row passes while the paste is refused, and isolating the
    /// subject-binding fix from the ORTHOGONAL slash-authority gate (a third-party
    /// `put_revocation` also requires the revoker hold `slash` from a trusted root:
    /// defense in depth, but not what #659 closes). Authority is bound to the
    /// SIGNATURE, never to custody of the row.
    #[test]
    fn v31_revocation_paste_cannot_deadmit_an_unintended_key() {
        // Build a well-formed, signed revocation of `revoked`, tagged `id`.
        let build = |id: &str, revoked: &str| {
            let now = Utc::now().trunc_subsecs(6);
            let mut rev = Revocation {
                revocation_id: id.to_string(),
                revoked_key_id: revoked.to_string(),
                revoking_key_id: "revoker".to_string(),
                reason: None,
                revoked_at: now,
                effective_at: now,
                revocation_envelope: serde_json::json!({}),
                original_content_hash: String::new(),
                scrub_signature_classical: String::new(),
                scrub_signature_pqc: None,
                scrub_key_id: "revoker".to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                observed_region: "us".to_string(),
                persist_row_hash: String::new(),
                revoked_after: None,
            };
            // persist's OWN binder stamps the typed columns into the envelope, so
            // the member set can never drift from the verifier.
            ciris_persist::federation::admission::bind_revocation_into_envelope(&mut rev)
                .expect("bind revocation envelope");
            let (hash, ed_sig, pqc_sig) =
                sign_attestation_envelope("revoker", &rev.revocation_envelope);
            rev.original_content_hash = hash;
            rev.scrub_signature_classical = ed_sig;
            rev.scrub_signature_pqc = pqc_sig;
            rev
        };

        // CONTROL: the honestly-bound revocation PASSES the binding gate. Every
        // store's admit path (memory / sqlite / postgres / tier_ingest) runs
        // exactly this check, so it is the real gate, not a stand-in.
        let honest = build("rev-honest", "victim-A");
        ciris_persist::federation::admission::check_revocation_envelope_binding(&honest)
            .expect("an honestly-bound revocation satisfies the column-to-envelope binding");

        // ATTACK: sign a revocation of victim-A, then repaint the target column to
        // victim-B. The signed envelope still pins victim-A.
        let mut pasted = build("rev-spoof", "victim-A");
        pasted.revoked_key_id = "victim-B".to_string();

        let err = ciris_persist::federation::admission::check_revocation_envelope_binding(&pasted)
            .expect_err(
                "a revocation signed to de-admit victim-A must NOT de-admit victim-B once its \
                 column is repainted — pre-v31 the unsigned column pasted onto ANY key (#659)",
            );
        let msg = format!("{err:?}");
        assert!(
            msg.contains("RevocationEnvelopeUnbound") || msg.contains("revoked_key_id"),
            "refused for the RIGHT reason (revoked_key_id column ≠ signed envelope), got: {msg}"
        );
    }

    /// CIRISPersist#643 (v31.0.0) — SPOOFING PROOF (the Attestation/conferral plane).
    ///
    /// A `delegates_to` conferral now binds `attested_key_id` + `subject_key_ids`
    /// into the signed `row` mirror. Pre-v31 those columns were UNSIGNED, so a
    /// single genuine conferral (say `infra:serve` granted to grantee-A) could be
    /// lifted onto ANY key — repaint the target column and the authority the signer
    /// never granted rides the same signature. persist's own doc flags
    /// `subject_key_ids` as the column that "grants revocation authority", so
    /// lifting it is the highest-value forgery; this proves v31 refuses the lift
    /// while the honest conferral admits.
    #[tokio::test]
    async fn v31_conferral_paste_cannot_lift_authority_onto_another_key() {
        let (backend, _bridge) = make_bridge(&[]);
        for kid in ["root", "grantee-A", "grantee-B"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }

        // Build a signed delegates_to(root → attested, scope infra:serve).
        let build = |id: &str, attested: &str| {
            let now = Utc::now().trunc_subsecs(6);
            let mut envelope = serde_json::json!({
                "id": id,
                "attesting_key_id": "root",
                "attested_key_id": attested,
                "attestation_type": "delegates_to",
                "scope": ["infra:serve"],
            });
            bind_attestation_envelope(
                &mut envelope,
                now,
                id,
                "root",
                "delegates_to",
                attested,
                &[attested],
                "federation",
            );
            let (hash, ed_sig, pqc_sig) = sign_attestation_envelope("root", &envelope);
            Attestation {
                attestation_id: id.to_string(),
                attesting_key_id: "root".to_string(),
                attested_key_id: attested.to_string(),
                attestation_type: "delegates_to".to_string(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: hash,
                scrub_signature_classical: ed_sig,
                scrub_signature_pqc: pqc_sig,
                scrub_key_id: "root".to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![attested.to_string()],
                withdraws_admission_rule: None,
                additional_scrubs: Vec::new(),
                cohort_scope: "federation".to_string(),
                tier: "federation".to_string(),
                promoted_at: None,
            }
        };

        // CONTROL: the honest conferral onto grantee-A ADMITS.
        backend
            .put_attestation(SignedAttestation {
                attestation: build("att-honest", "grantee-A"),
            })
            .await
            .expect("an honestly-bound conferral admits");

        // ATTACK: sign a conferral onto grantee-A, then repaint BOTH target columns
        // to grantee-B. The signed `row` mirror still pins grantee-A.
        let mut pasted = build("att-spoof", "grantee-A");
        pasted.attested_key_id = "grantee-B".to_string();
        pasted.subject_key_ids = vec!["grantee-B".to_string()];

        let err = backend
            .put_attestation(SignedAttestation {
                attestation: pasted,
            })
            .await
            .expect_err(
                "a delegates_to signed to grant grantee-A must NOT grant grantee-B once its \
                 target columns are repainted — pre-v31 the unsigned columns lifted authority \
                 onto ANY key (#643)",
            );
        let msg = format!("{err:?}");
        // v16 review: assert the #643 row-column binding gate refused it SPECIFICALLY
        // — check_row_column_binding names the divergent member. A bare
        // "InvalidArgument" is NOT enough: many other put_attestation gates
        // (cohort-scope, #510 consent-grammar, canonicalize) Debug-format the same,
        // so accepting it would let this test stay green even if the paste were
        // refused by an unrelated gate (false confidence).
        assert!(
            msg.contains("subject_key_ids") || msg.contains("attested_key_id"),
            "must be refused by the #643 row-column binding (naming the divergent \
             attested_key_id/subject_key_ids), not an incidental InvalidArgument, got: {msg}"
        );
    }

    /// CIRISEdge#462 — the load-bearing hash-match invariant: every ref
    /// `subject_holdings` emits resolves through the SAME content-hash fetch path
    /// a `Deliver` uses (`fetch_envelope_bytes` → persist's `signed_wire_index`).
    /// If the pull's struct-hashing (`content_hash_of` on the `_for`-read struct)
    /// ever diverged from what the index keys on, this would surface as
    /// advertised-then-unfetchable and a Pull would deliver nothing. Proven across
    /// the Key plane (lookup + `SignedKeyRecord` wrap) and the Attestation plane.
    #[tokio::test]
    async fn subject_pull_refs_resolve_through_fetch() {
        let subject = "eric-moore-v2-portable";
        let (backend, bridge) = make_bridge(&[subject.to_string()]);
        // Register the subject's key (also the Key-plane row) + a peer attester,
        // then seed an attestation ABOUT the subject.
        for kid in [subject, "peer-attester"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(kid, "user"),
                })
                .await
                .expect("register key");
        }
        seed_delegates_to(
            &backend,
            "peer-attester",
            subject,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        for kind in [EnvelopeKind::Key, EnvelopeKind::Attestation] {
            let refs = bridge.subject_holdings(kind, subject, Some(subject)).await;
            assert!(
                !refs.is_empty(),
                "{kind:?}: a subject Pull must surface at least one ref"
            );
            for r in &refs {
                assert!(
                    bridge
                        .fetch_envelope_bytes(kind, &r.envelope_hash)
                        .await
                        .is_some(),
                    "{kind:?}: pull ref {} must resolve through the content-hash fetch path \
                     (hash-match with the wire index; else advertised-then-unfetchable)",
                    hex::encode(r.envelope_hash),
                );
            }
        }
    }

    /// Seed a producer's `consent:replication:v1` grant carrying a single
    /// `recipient_capability` restriction over `prefix`, naming `recipient` as
    /// the consented peer — so persist's E7 projection sources a live row from
    /// it and [`FederationDirectory::list_live_consent_grants_by`] returns it.
    async fn seed_consent_grant(
        backend: &MemoryBackend,
        producer: &str,
        recipient: &str,
        prefix: &str,
        capability: &str,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": producer,
            "attested_key_id": recipient,
            "attestation_type": "scores",
            "dimension": "consent:replication:v1",
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": [prefix],
                "restrictions": [{ "op": "recipient_capability", "capability": capability }],
            },
        });
        seed_raw_attestation(backend, &id, producer, recipient, "scores", envelope).await;
    }

    /// Seed a bare `consent:replication:v1` grant (NO restrictions) by `granter`
    /// naming `peer` — the minimum that puts `peer` in
    /// `list_consent_peers(granter)` so it clears the CIRISEdge#396 item-1
    /// membership bound WITHOUT a `recipient_capability` that would separately
    /// trip item 6. Use when a test needs a peer to be consent-included but is
    /// exercising a DIFFERENT gate.
    async fn seed_consent_membership(backend: &MemoryBackend, granter: &str, peer: &str) {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": granter,
            "attested_key_id": peer,
            "attestation_type": "scores",
            "dimension": "consent:replication:v1",
            "payload": {
                "grants": "transfer",
                "attestation_prefixes": ["trace:"],
            },
        });
        seed_raw_attestation(backend, &id, granter, peer, "scores", envelope).await;
    }

    /// Seed a hybrid-signed `Revocation` of `revoked` by `revoking` (both must
    /// be registered keys). persist computes `persist_row_hash` on put — the
    /// value the Revocation plane advertises + the cache-free fetch scan matches.
    async fn seed_revocation(backend: &MemoryBackend, revoking: &str, revoked: &str) {
        let now = Utc::now().trunc_subsecs(6); // #598 microsecond floor
        let id = uuid::Uuid::new_v4().to_string();
        let mut revocation = Revocation {
            revocation_id: id,
            revoked_key_id: revoked.to_string(),
            revoking_key_id: revoking.to_string(),
            reason: None,
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: revoking.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: "us".to_string(), // #598-era: must be {us,eu,apac}, not empty
            persist_row_hash: String::new(),
            revoked_after: None,
        };
        // CIRISPersist#659 (v31.0.0): bind the typed columns (revoked_key_id, reason,
        // revoked_at, …) into the signed envelope — else a relay could paste one
        // signed revocation onto ANY key. Use persist's OWN binder so the member set
        // never drifts, then sign the now-bound envelope.
        ciris_persist::federation::admission::bind_revocation_into_envelope(&mut revocation)
            .expect("bind revocation envelope");
        let (hash, ed_sig, pqc_sig) =
            sign_attestation_envelope(revoking, &revocation.revocation_envelope);
        revocation.original_content_hash = hash;
        revocation.scrub_signature_classical = ed_sig;
        revocation.scrub_signature_pqc = pqc_sig;
        backend
            .put_revocation(SignedRevocation { revocation })
            .await
            .expect("seed revocation");
    }

    /// CIRISEdge#396 item 3 — the Revocation plane (the one kind persist does
    /// not content-hash-index) fetches with NO cache: `fetch_envelope_bytes`
    /// re-derives the tombstone's bytes by scanning the same `Global` subject
    /// set the advertise walked. A revocation advertised by `list_revocations`
    /// must therefore fetch back byte-for-byte through the point-read surface.
    #[tokio::test]
    async fn revocation_fetch_is_cache_free_round_trip() {
        let revoking = "revoker-node";
        let revoked = "revoked-key";
        // `revoked` must be in the cohort so the Global-projection scan reaches it.
        let (backend, bridge) = make_bridge(&[revoking.to_string(), revoked.to_string()]);
        for key_id in [revoking, revoked] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        // persist v30.8.0 (CIRISPersist#628) — a third-party revocation now needs
        // the revoker authorized with `slash` from a trusted root. This test is
        // about the cache-free FETCH round trip (#396 item 3), where the
        // revocation's authority is irrelevant — so seed a SELF-revocation
        // (`revoking == revoked`, the path v30.8.0 leaves untouched) rather than
        // drag a conferral fixture into a fetch-mechanics test. `revoking` still
        // seeds a distinct key above (harmless); the fetched row's revoked_key_id
        // is what this asserts.
        seed_revocation(&backend, revoked, revoked).await;

        let refs = bridge.list_revocations().await;
        assert!(!refs.is_empty(), "the seeded revocation is advertised");
        for r in &refs {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Revocation, &r.envelope_hash)
                .await
                .expect("cache-free revocation fetch resolves the advertised hash");
            let parsed: SignedRevocation =
                serde_json::from_slice(&bytes).expect("fetched bytes are a SignedRevocation");
            assert_eq!(
                parsed.revocation.revoked_key_id, revoked,
                "the re-derived bytes are the advertised revocation"
            );
        }
    }

    /// CIRISEdge#547 — an index read that FAILS must never look like empty
    /// holdings.
    ///
    /// This is the one way the fix could be worse than the bug. `want` is
    /// `remote ∖ holdings`; an empty holdings set means "I hold nothing", so a
    /// failed read mistaken for an empty answer turns one bad query into a full
    /// re-fetch of every plane from every peer — an outage caused by the code
    /// meant to prevent one. `holdings_from_wire_index` returns `Option`
    /// precisely so the two cannot be spelled the same way, and persist's own
    /// default refuses rather than returning an empty vec for the same reason.
    ///
    /// Pinned as the type-level property, since the failure is unreachable in a
    /// test that can only exercise the happy path against a real backend.
    #[test]
    fn a_failed_index_read_is_not_an_empty_holdings_set() {
        // The contract: None ⇒ fall back to rows. Some(vec![]) ⇒ genuinely empty.
        let failed: Option<Vec<EnvelopeRef>> = None;
        let genuinely_empty: Option<Vec<EnvelopeRef>> = Some(Vec::new());
        assert!(
            failed.is_none(),
            "a read failure must be distinguishable from an empty plane"
        );
        assert_ne!(
            failed.as_ref().map(Vec::len),
            genuinely_empty.as_ref().map(Vec::len),
            "an error and an empty plane must not collapse to the same reading — \
             `want = remote ∖ holdings` turns the confusion into a re-fetch storm"
        );
    }

    /// The holdings axis reads only `envelope_hash`, so `seq: 0` on an
    /// index-sourced ref is the absence of a field this axis never consults —
    /// not a wrong value. If `diff_refs` ever starts reading local `seq`, this
    /// fails and the index path needs the row path's seq back.
    #[test]
    fn the_holdings_diff_reads_only_the_hash() {
        let h = [7u8; 32];
        let from_index = EnvelopeRef {
            envelope_hash: h,
            seq: 0,
        };
        let from_rows = EnvelopeRef {
            envelope_hash: h,
            seq: 99,
        };
        let remote = vec![EnvelopeRef {
            envelope_hash: h,
            seq: 42,
        }];
        assert_eq!(
            crate::replication::summary::diff_refs(&[from_index], &remote),
            crate::replication::summary::diff_refs(&[from_rows], &remote),
            "an index-sourced holdings set must produce the SAME want as a \
             row-sourced one; if it does not, `seq` became load-bearing here"
        );
    }

    /// CIRISEdge#531 (second half) — the gate view must be INDISTINGUISHABLE
    /// from `serde_json::to_value` as far as the gates can tell.
    ///
    /// This is the whole safety argument for dropping the full materialisation:
    /// not "the fields look right" but "every gate returns the same verdict on
    /// both values, for the same row". Compared on ONE typed fixture so the two
    /// values cannot drift apart the way two hand-written shapes would
    /// ([[feedback_test_field_provenance]]).
    #[test]
    fn the_gate_view_answers_every_gate_exactly_as_full_serialization_did() {
        let producer = "fed_producer_1";
        let att = trace_row_att(producer);
        let full = serde_json::to_value(&att).expect("serialize trace row");
        let view = FederationDirectoryReplicationBridge::advertise_gate_view(&att);

        // Fields the gates read verbatim.
        assert_eq!(full.get("attesting_key_id"), view.get("attesting_key_id"));
        assert_eq!(full.get("attestation_type"), view.get("attestation_type"));
        assert_eq!(
            full.pointer("/attestation_envelope/dimension"),
            view.pointer("/attestation_envelope/dimension"),
            "the one nested read the gates make"
        );

        // `cohort_scope` is deliberately NOT compared by key presence, and the
        // reason is load-bearing: persist declares it
        // `skip_serializing_if = "is_default_cohort_scope"`, so `to_value`
        // OMITS the key when the scope is `federation`, while the view always
        // carries it. Edge does not replicate that predicate — duplicating an
        // upstream serde rule is the drift this codebase keeps paying for.
        //
        // It is safe because the gate's own contract already collapses the two:
        // a MISSING key means `federation` (persist's serde default), a present
        // one is used as-is, and an EMPTY one is malformed and declines. So the
        // verdicts agree for every scope, which is what the loop actually asks.
        // Checked across all three cases rather than asserted.
        let self_set: HashSet<String> = std::iter::once(producer.to_string()).collect();
        for scope in ["federation", "self", "cohort", ""] {
            let mut row = trace_row_att(producer);
            row.cohort_scope = scope.to_string();
            let full = serde_json::to_value(&row).expect("serialize trace row");
            let view = FederationDirectoryReplicationBridge::advertise_gate_view(&row);
            assert_eq!(
                FederationDirectoryReplicationBridge::attestation_is_advertised(&full, &self_set),
                FederationDirectoryReplicationBridge::attestation_is_advertised(&view, &self_set),
                "advertise verdict must not change for cohort_scope={scope:?}"
            );
            assert_eq!(
                FederationDirectoryReplicationBridge::attestation_requires_serve(&full),
                FederationDirectoryReplicationBridge::attestation_requires_serve(&view),
                "serve-gate verdict must not change for cohort_scope={scope:?}"
            );
        }
    }

    /// A `trace:complete:v1` row's canonical JSON in EXACTLY the shape
    /// `list_attestations` feeds the item-6 gate — `serde_json::to_value` over an
    /// `Attestation` ([[feedback_test_field_provenance]]: the gate reads
    /// `/attestation_envelope/dimension` and `attesting_key_id` off THIS value).
    /// Built directly rather than round-tripped through `put_attestation` because
    /// admitting a real `trace:*` row needs persist's `test-anchor` relaxation
    /// (a `#[cfg]`-gated lib test never runs in CI's lanes); the gate reads the
    /// projected value, not the store, so this isolates item 6 faithfully.
    fn trace_row_json(producer: &str) -> serde_json::Value {
        serde_json::to_value(trace_row_att(producer)).expect("serialize trace row")
    }

    /// The same fixture as a TYPED row, so the #531 gate-view equivalence can be
    /// checked against `to_value` on identical input rather than on two
    /// separately hand-written shapes (which would prove nothing).
    fn trace_row_att(producer: &str) -> Attestation {
        let now = Utc::now();
        let envelope = serde_json::json!({
            "id": "trace-fixture-1",
            "attesting_key_id": producer,
            "attested_key_id": producer,
            "attestation_type": "scores",
            "dimension": "trace:complete:v1",
            "trace_id": "t-fixture-1",
            "agent_id_hash": "ah-fixture-1",
            "trace": { "steps": [] },
        });
        Attestation {
            attestation_id: "trace-fixture-1".to_string(),
            attesting_key_id: producer.to_string(),
            attested_key_id: producer.to_string(),
            attestation_type: "scores".to_string(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: producer.to_string(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            additional_scrubs: Vec::new(),
            cohort_scope: "federation".to_string(),
            tier: "federation".to_string(),
            promoted_at: None,
        }
    }

    /// CIRISEdge#396 item 6 — the `recipient_capability` serve control (the #393
    /// gate-first pattern), asserted against the inputs the serve gate actually
    /// reads. Like the #379 gate, the ALLOW path (recipient HOLDS the capability)
    /// needs a live accord co-scrub whose minting helper is private to persist
    /// (CIRISPersist#484), so the load-bearing WITHHOLD path + the two SERVE
    /// paths are locked here; the ALLOW path lands with the same fleet
    /// re-genesis that lights the #379 ALLOW path.
    #[tokio::test]
    async fn recipient_capability_serve_control() {
        let producer = "agent-producer";
        // A recipient whose record EXISTS but carries no accord-conferred role —
        // `has_accord_conferred_role(_, "trace:read")` is false for it. (Seeding the key
        // means the WITHHOLD below is because the record lacks the capability, not
        // because the key is absent — the same provenance discipline the #379
        // test uses to refuse a self-asserted `roles:[…]` peer.)
        let recipient = "peer-no-capability";
        let (backend, bridge) = make_bridge(&[producer.to_string(), recipient.to_string()]);
        // Both keys registered: the producer's so `put_attestation` can verify
        // its grant's hybrid signature, the recipient's so `has_accord_conferred_role`
        // reads a real (role-less) record — not a missing one.
        for key_id in [producer, recipient] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let trace_json = trace_row_json(producer);

        // (a) No grant → no restriction → SERVE (fail-open-when-absent: the
        //     fleet's servers emit no `recipient_capability` yet, and the plane
        //     must flow exactly as it did before this control shipped).
        assert!(
            !bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await,
            "no consent grant declares a restriction → the row must serve"
        );

        // (b) A grant COVERING `trace:` with a `recipient_capability` the
        //     recipient lacks → WITHHOLD. This is the load-bearing case: the
        //     instant the producer's restriction materializes, enforcement lights
        //     up with no window where the restriction exists but isn't enforced.
        seed_consent_grant(&backend, producer, recipient, "trace:", "trace:read").await;
        assert!(
            bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await,
            "covering grant + recipient lacks the required capability → withhold"
        );

        // (c) A restriction on a grant that does NOT cover the row's dimension →
        //     SERVE (the `covers()` gate; a `capacity:` grant never gates a
        //     `trace:` row). Fresh backend so no `trace:`-covering grant lingers.
        let (backend2, bridge2) = make_bridge(&[producer.to_string(), recipient.to_string()]);
        for key_id in [producer, recipient] {
            backend2
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let trace_json2 = trace_row_json(producer);
        seed_consent_grant(&backend2, producer, recipient, "capacity:", "trace:read").await;
        assert!(
            !bridge2
                .recipient_capability_withholds(&trace_json2, recipient, &mut HashMap::new())
                .await,
            "grant prefix `capacity:` does not cover a `trace:` row → serve"
        );
    }

    /// Seed a federation-tier `delegates_to` attestation the plane advertises —
    /// no `trace:` dimension (so the #379 gate is inert) and no envelope
    /// `dimension` at all (so no consent grant's `covers` can trip item 6),
    /// leaving item 1 (consent membership) as the ONLY differentiator. Returns
    /// the attestation id.
    async fn seed_advertised_attestation(backend: &MemoryBackend, producer: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": producer,
            "attested_key_id": producer,
            "attestation_type": "delegates_to",
            "scope": { "grant": ["infra:attest"] },
        });
        seed_raw_attestation(backend, &id, producer, producer, "delegates_to", envelope).await;
        id
    }

    /// CIRISEdge#396 item 1 — the consent-membership fan-out bound. The
    /// Attestation plane is served to a peer ONLY if persist's live consent
    /// projection (`list_consent_peers`, E7) includes it. Asserted against the
    /// actual advertise path: a consent-included peer receives the plane; a peer
    /// absent from the send-set receives NOTHING (the whole plane withheld,
    /// fail-closed) — the by-construction bound `resolved_state.rs` enforces.
    #[tokio::test]
    async fn consent_membership_fan_out_bound() {
        let local = "this-node";
        let producer = "agent-producer";
        let peer_in = "peer-consented";
        let peer_out = "peer-unconsented";
        let (backend, bridge) = make_bridge(&[
            local.to_string(),
            producer.to_string(),
            peer_in.to_string(),
            peer_out.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for key_id in [local, producer, peer_in, peer_out] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_advertised_attestation(&backend, producer).await;
        // `local` consents to replicate to `peer_in` only (the grant names it →
        // list_consent_peers(local) ∋ peer_in). Prefix "trace:" so the grant's
        // own recipient_capability can never cover the dimensionless row above.
        seed_consent_grant(&backend, local, peer_in, "trace:", "trace:read").await;

        // Projection-only baseline (ungated) proves the row IS advertised.
        let baseline = bridge.list_attestations_for_peer(None).await;
        assert!(
            !baseline.is_empty(),
            "the seeded federation attestation is advertised in the local view"
        );

        // (a) consent-INCLUDED peer → receives the advertised plane (item 1 passes).
        let included = bridge.list_attestations_for_peer(Some(peer_in)).await;
        assert_eq!(
            included.len(),
            baseline.len(),
            "a consent-included peer receives the advertised attestations"
        );

        // (b) consent-EXCLUDED peer → the WHOLE plane is withheld (item 1).
        let excluded = bridge.list_attestations_for_peer(Some(peer_out)).await;
        assert!(
            excluded.is_empty(),
            "a peer absent from the consent send-set receives no attestations (CIRISEdge#396 item 1)"
        );
    }

    /// CIRISEdge#396 item 1 — fail-closed when the send-set is unresolvable: a
    /// bridge with no `local_key_id` cannot compute `list_consent_peers(local)`,
    /// so it withholds the attestation plane from every peer rather than
    /// serving unbounded (the #386 leg-B posture).
    #[tokio::test]
    async fn fan_out_fail_closed_without_local_key_id() {
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge) =
            make_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        // NOTE: deliberately NO `with_local_key_id`.
        for key_id in [local, producer, peer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_advertised_attestation(&backend, producer).await;
        seed_consent_grant(&backend, local, peer, "trace:", "trace:read").await;

        // The row is advertised in the ungated view...
        assert!(
            !bridge.list_attestations_for_peer(None).await.is_empty(),
            "the row is advertised projection-only"
        );
        // ...but WITHOUT a local_key_id the peer-bound serve fails closed.
        assert!(
            bridge
                .list_attestations_for_peer(Some(peer))
                .await
                .is_empty(),
            "no local_key_id → consent send-set unresolvable → whole plane withheld (fail-closed)"
        );
    }

    /// CIRISEdge#400 — the consent send-set is memoized across a round window,
    /// so a round's advertise + N fetches share ONE `list_consent_peers` read
    /// instead of N. This is the regression witness: v14.2.0 re-read persist
    /// per envelope inside the unbounded reply assembly, blowing the 10 s round
    /// budget (100% round timeouts). Two resolves within the TTL must return the
    /// SAME `Arc`-backed set — a re-read would allocate a distinct one.
    #[tokio::test]
    async fn consent_send_set_is_memoized_within_the_round_window() {
        let local = "this-node";
        let peer = "peer-consented";
        let (backend, bridge) = make_bridge(&[local.to_string(), peer.to_string()]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for key_id in [local, peer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_consent_membership(&backend, local, peer).await;

        let set1 = bridge.resolved_peer_set(local).await.expect("resolve 1");
        let set2 = bridge.resolved_peer_set(local).await.expect("resolve 2");
        assert!(
            set1.ptr_eq(&set2),
            "second resolve within the TTL is a memo HIT, not a per-envelope re-read (CIRISEdge#400)"
        );
        // ...and the memoized set is the real consent membership.
        assert!(
            set1.recipient(peer).is_some(),
            "the memoized set resolves the consent-included peer"
        );
    }

    /// The v13.10.0 gate this replaces was wrong TWICE, and this test is
    /// written against the inputs the FIELD produces so it cannot be wrong the
    /// same way again ([[feedback_test_field_provenance]] in anger):
    ///
    /// 1. **Wrong token** — it keyed on a bare `"observer"` string that is not
    ///    a federation capability anywhere in the stack, so the plane was
    ///    fail-closed DEAD for every peer. Now [`Self::SERVE_CAPABILITY`] is
    ///    persist's own `delegation_scope::INFRA_SERVE` const — the two sides
    ///    cannot drift apart again without a compile error.
    /// 2. **Unsound derivation** — it read claim-presence off the `roles`
    ///    vector, which persist documents as self-assertable on pre-v17.0.0
    ///    rows. The `self_asserted_*` assertions below are the regression
    ///    lock: a peer that simply WRITES `roles:["infra:serve"]` into its own
    ///    record, with no accord co-scrub behind it, is refused. The old gate
    ///    would have served it every trace on the node.
    ///
    /// **Known coverage gap (deliberate, not an oversight).** The ALLOW path is
    /// not asserted here: a record that satisfies `has_accord_conferred_role` must
    /// carry a live 2-of-3 accord-family co-scrub over its canonical
    /// registration bytes, and persist's minting helpers for that
    /// (`register_founder` / `signed_canonical_record`) are private to its own
    /// test module. Faking it with a hand-built record would re-create exactly
    /// the false confidence being fixed, so it is left to the layer that can
    /// prove it: CIRISPersist#484 (export the helper) and the field acceptance
    /// check on CIRISPersist#480 — `has_accord_conferred_role(dir, canonical,
    /// "infra:serve") == true` read on a MOBILE edge's own directory after the
    /// re-blessing ceremony, not on the server that minted it.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // seed + both peers + both paths, one coherent scenario
    async fn trace_attestation_gated_on_serve_capability() {
        let producer = "agent-mobile";
        // A peer that SELF-ASSERTS the capability: its record literally carries
        // `roles:["infra:serve"]`, with no accord co-scrub behind it — the
        // shape v13.10.0's claim-presence check would have admitted.
        let self_asserted_peer = "peer-self-asserted-serve";
        let plain_peer = "peer-no-capability";
        // The trust graph: `root` grants `infra:serve`, and WE trust `root`.
        let local = "this-node";
        let root = "trust-root-1";
        let lifecycle_attester = "accord-holder-1";
        let trusted_peer = "canonical-under-our-root";
        let (backend, bridge) = make_bridge(&[
            producer.to_string(),
            trusted_peer.to_string(),
            self_asserted_peer.to_string(),
            plain_peer.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));

        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(producer, identity_type::AGENT),
            })
            .await
            .expect("seed producer key");
        let mut self_asserted_rec = fixture_key_record(self_asserted_peer, identity_type::AGENT);
        self_asserted_rec.capability_roles =
            vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()];
        backend
            .put_public_key(SignedKeyRecord {
                record: self_asserted_rec,
            })
            .await
            .expect("seed self-asserting key");
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(plain_peer, identity_type::AGENT),
            })
            .await
            .expect("seed plain key");
        for (k, it) in [
            (local, identity_type::NODE),
            (root, identity_type::NODE),
            (trusted_peer, identity_type::NODE),
            (lifecycle_attester, identity_type::ACCORD_HOLDER),
        ] {
            let mut record = fixture_key_record(k, it);
            // CIRISPersist v22 (#543 / the FIPS anti-Sybil floor #513) — an
            // `accord:*` attestation now requires its attester to be a hardware-
            // attested ACCORD_HOLDER: the key must carry `attestation_evidence` at
            // registration AND the attester's identity_type must be ACCORD_HOLDER
            // (so the lifecycle attester cannot be downgraded to a plain NODE). Seed
            // the exact fresh Android/Strongbox blob persist's
            // `test_support::fresh_accord_holder_evidence` emits — inlined so this
            // test does not have to gate on the `test-anchor` feature.
            if it == identity_type::ACCORD_HOLDER {
                record.attestation_evidence = Some(serde_json::json!({
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
                    "nonce_captured_at": Utc::now().to_rfc3339(),
                }));
            }
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("seed trust-graph key");
        }

        // The CIRISEdge#386 trust graph, in the shape persist's own #483
        // witness uses (field provenance — these are the exact rows
        // `capability_roots_to_trusted_root` walks):
        //   1. delegates_to(root → root, scope infra:*)   — root self-declares
        //   2. delegates_to(local → root)                 — WE trust the root
        //   3. accord:lifecycle scores about root, fresh  — root is live
        //   4. delegates_to(root → trusted_peer, infra:serve) — the grant
        let trust_edge_id = seed_root_charter(&backend, root, &[format!("{root}-successor")]).await;
        let our_trust_edge = seed_delegates_to(
            &backend,
            local,
            root,
            &serde_json::json!(["infra:attest", "infra:serve"]),
        )
        .await;
        let _ = trust_edge_id;
        seed_accord_lifecycle(&backend, lifecycle_attester, root).await;
        seed_delegates_to(
            &backend,
            root,
            trusted_peer,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        // CIRISEdge#396 item 1 — this test isolates the #386 per-ROW infra:serve
        // gate, so every peer it probes must first clear the per-PEER consent
        // membership bound: `local` consents to replicate to each (a bare grant,
        // no `recipient_capability`, so item 6 stays inert here). Without this,
        // item 1 would blanket-withhold the whole plane and mask the per-row gate.
        for peer in [self_asserted_peer, trusted_peer, plain_peer] {
            seed_consent_membership(&backend, local, peer).await;
        }

        // A trace scores-attestation (self-subject, federation tier =
        // promoted) + a NON-trace attestation for the control.
        let now = Utc::now().trunc_subsecs(6);
        for (attestation_type, dimension) in [
            ("scores", Some("trace:complete:v1")),
            ("delegates_to", None),
        ] {
            let mut envelope = serde_json::json!({
                "attesting_key_id": producer,
                "attested_key_id": producer,
                "attestation_type": attestation_type,
            });
            if let Some(d) = dimension {
                // The persist v18.1.0 trace:* Information-Type validator
                // (CIRISPersist#479) enforces the inline shape at admission:
                // trace_id + agent_id_hash strings + a `trace` object.
                envelope["dimension"] = serde_json::json!(d);
                envelope["trace_id"] = serde_json::json!("t-fixture-1");
                envelope["agent_id_hash"] = serde_json::json!("ah-fixture-1");
                envelope["trace"] = serde_json::json!({ "steps": [] });
            }
            let attestation_id = uuid::Uuid::new_v4().to_string();
            bind_attestation_envelope(
                &mut envelope,
                now,
                &attestation_id,
                producer,
                attestation_type,
                producer,
                &[producer],
                "federation",
            );
            let (hash, ed_sig, pqc_sig) = sign_attestation_envelope(producer, &envelope);
            let att = Attestation {
                attestation_id,
                attesting_key_id: producer.to_string(),
                attested_key_id: producer.to_string(),
                attestation_type: attestation_type.to_string(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: hash,
                scrub_signature_classical: ed_sig,
                scrub_signature_pqc: pqc_sig,
                scrub_key_id: producer.to_string(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![producer.to_string()],
                withdraws_admission_rule: None,
                additional_scrubs: Vec::new(),
                cohort_scope: "federation".to_string(),
                tier: "federation".to_string(),
                promoted_at: None,
            };
            backend
                .put_attestation(SignedAttestation { attestation: att })
                .await
                .expect("seed attestation");
        }

        // Identify the trace row by CONTENT, not by counting — the trust-graph
        // rows seeded above live in this same plane, so any count is brittle.
        let trace_hash = locate_trace_hash(&bridge).await;

        // Every peer WITHOUT both legs is refused the trace row, on BOTH paths,
        // while non-trace rows keep flowing to them (the gate is per-row):
        //   - self_asserted_peer: writes `roles:["infra:serve"]` into its own
        //     record with no accord co-scrub — the shape v13.10.0 served.
        //   - trust_rooted_peer:  genuinely rooted under a root we trust, but
        //     NOT accord-conferred — proves leg A is a required conjunct.
        //   - plain_peer:         neither.
        for peer in [self_asserted_peer, trusted_peer, plain_peer] {
            let refs = bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
                .await;
            assert!(
                !refs.iter().any(|r| r.envelope_hash == trace_hash),
                "{peer} must NOT be offered the trace attestation — it lacks the \
                 accord-conferred `infra:serve` (CIRISEdge#386 leg A)"
            );
            assert!(
                !refs.is_empty(),
                "{peer} still receives the non-trace rows — the gate is per-row, \
                 not a blanket refusal"
            );
            assert!(
                bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &trace_hash,
                        Some(peer)
                    )
                    .await
                    .is_none(),
                "{peer} must not obtain the trace envelope by hash either \
                 (out-of-band Diff/Fetch bypass, CIRISEdge#379)"
            );
        }
        let _ = our_trust_edge;
    }

    /// CIRISEdge#386 — the ALLOW path, and the proof that BOTH legs are
    /// required. Gated on `test-anchor` because minting a record that satisfies
    /// `has_accord_conferred_role` needs a genuine 2-of-3 accord-family co-scrub, which
    /// persist exports only behind that fence (CIRISPersist#484). Edge CI runs a
    /// dedicated `test-anchor` lane (#435), so this is real coverage — not a
    /// test that quietly never runs. (#435 is the proof that clause must be a
    /// CI job, not a doc claim: while no lane ran it, this test silently missed
    /// TWO fixture waves — the v22 ACCORD_HOLDER evidence blob and the #396
    /// item-1 consent-membership bound — and sat broken at HEAD.)
    ///
    /// This is the assertion whose ABSENCE let v13.10.0 ship a permanently-dark
    /// gate with a green suite.
    ///
    /// Also asserts the #433 ledger's leg-B arm: the blessed-but-not-rooted
    /// DENY books `ServeCapabilityNotRooted` — the one WithholdReason only
    /// reachable through this lane (leg A must PASS first).
    #[cfg(feature = "test-anchor")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // roster + trust graph + allow/deny/un-trust: one scenario
    async fn trace_serve_requires_accord_blessing_and_trusted_root() {
        use ciris_persist::federation::accord_test_support::{
            register_accord_holder, signed_canonical_record_with_roles, Identity,
        };
        // CIRISPersist v31.0.0 (#467): the helper now stamps the SUBJECT BINDING
        // (pubkeys) into the envelope before signing, so a signature can no longer
        // be lifted onto a different key_id. This fixture doesn't spoof, so the
        // placeholder subject + no-PQC is the byte-preserving update.
        use ciris_persist::federation::operational::test_support::PLACEHOLDER_SUBJECT_ED25519_BASE64;
        // The roster key_ids `has_accord_conferred_role` resolves against. Persist's
        // own `accord_holder_roster_key_ids` is private, but it is derived from
        // this public genesis accessor — so we mint identities under exactly
        // those key_ids and the co-scrub verifies against the real roster.
        use ciris_persist::federation::genesis::effective_accord_holder_records;

        let producer = "agent-mobile";
        let local = "this-node";
        let root = "trust-root-1";
        let lifecycle_attester = "accord-holder-live";
        // Blessed by the accord AND rooted under a root we trust → served.
        let full_peer = "canonical-blessed-and-rooted";
        // Blessed by the accord but rooted nowhere we trust → refused (leg B).
        let blessed_only = "canonical-blessed-not-rooted";
        let (backend, bridge, metrics) = make_metered_bridge(&[
            producer.to_string(),
            full_peer.to_string(),
            blessed_only.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));

        // The live accord family, registered at their PINNED pubkeys so the
        // co-scrub verifies against the real roster.
        let holders: Vec<Identity> = effective_accord_holder_records()
            .iter()
            .map(|r| Identity::new(&r.record.key_id))
            .collect();
        assert!(
            holders.len() >= 2,
            "the accord family must resolve to at least a 2-of-n roster"
        );
        for h in &holders {
            register_accord_holder(&*backend, h)
                .await
                .expect("register accord holder");
        }
        let scrubbers = [&holders[0], &holders[1]];

        for (k, it) in [
            (producer, identity_type::AGENT),
            (local, identity_type::NODE),
            (root, identity_type::NODE),
            (lifecycle_attester, identity_type::ACCORD_HOLDER),
        ] {
            let mut record = fixture_key_record(k, it);
            // CIRISPersist v22 (#543/#513) — an ACCORD_HOLDER key must carry
            // `attestation_evidence` at registration. Same inlined Android/
            // Strongbox blob as the sibling non-anchored test above (#435: the
            // v22 adopt fixed the sibling and missed this anchored twin).
            if it == identity_type::ACCORD_HOLDER {
                record.attestation_evidence = Some(serde_json::json!({
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
                    "nonce_captured_at": Utc::now().to_rfc3339(),
                }));
            }
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("seed key");
        }
        // Both candidate recipients carry a GENUINE 2-of-3 accord co-scrub
        // conferring `infra:serve` — leg A holds for both.
        for peer in [full_peer, blessed_only] {
            let rec = signed_canonical_record_with_roles(
                peer,
                identity_type::NODE,
                PLACEHOLDER_SUBJECT_ED25519_BASE64,
                None,
                vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()],
                serde_json::json!({ "key_id": peer }),
                &scrubbers,
            );
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .expect("seed co-scrubbed recipient");
        }

        // Trust graph: root self-declares, WE trust it, it is live, and it
        // grants `infra:serve` to full_peer ONLY.
        seed_root_charter(&backend, root, &[format!("{root}-successor")]).await;
        let our_trust_edge = seed_delegates_to(
            &backend,
            local,
            root,
            &serde_json::json!(["infra:attest", "infra:serve"]),
        )
        .await;
        seed_accord_lifecycle(&backend, lifecycle_attester, root).await;
        seed_delegates_to(
            &backend,
            root,
            full_peer,
            &serde_json::json!(["infra:serve"]),
        )
        .await;

        // CIRISEdge#396 item 1 — this test isolates the #386 per-ROW infra:serve
        // gate, so both probed peers must first clear the per-PEER consent
        // membership bound (a bare grant, no `recipient_capability`, so item 6
        // stays inert here). The sibling deny-path test gained this block when
        // #396 landed; this anchored twin missed it while no CI lane ran it —
        // half of #435's failure 2.
        for peer in [full_peer, blessed_only] {
            seed_consent_membership(&backend, local, peer).await;
        }

        seed_trace_attestation(&backend, producer).await;
        let trace_hash = locate_trace_hash(&bridge).await;

        // ALLOW — accord-blessed AND rooted under a root we trust.
        assert!(
            bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(full_peer))
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "a recipient with an accord-conferred `infra:serve` that ALSO roots to \
             a root this node trusts receives the trace row"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &trace_hash,
                    Some(full_peer)
                )
                .await
                .is_some(),
            "...and can fetch its bytes"
        );

        // DENY — accord-blessed but rooted nowhere we trust (leg B required).
        assert!(
            !bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(blessed_only))
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "an accord blessing alone is NOT sufficient — the capability must root \
             to a root this node trusts (CIRISEdge#386 leg B)"
        );
        // #433 — that leg-B DENY is a WITHHOLD, booked at its branch. This is
        // the only test that can reach `ServeCapabilityNotRooted` (leg A must
        // pass first, which needs the co-scrub this lane mints), so the ledger
        // arm is proven here or nowhere.
        assert!(
            metrics.withholds(crate::observability::WithholdReason::ServeCapabilityNotRooted) >= 1,
            "the blessed-but-not-rooted deny must book ServeCapabilityNotRooted \
             in the withhold ledger (CIRISEdge#433)"
        );

        // NUCLEAR UN-TRUST — withdrawing OUR `delegates_to(local → root)` edge
        // stops serving every peer that rooted through it, immediately, with
        // nothing else in the graph changed and no cache to go stale. This is
        // the property an OR-composition would have destroyed.
        seed_withdraws(&backend, local, &our_trust_edge).await;
        assert!(
            !bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(full_peer))
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "un-trusting the root stops serving traces to peers that rooted through it"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &trace_hash,
                    Some(full_peer)
                )
                .await
                .is_none(),
            "un-trust closes the fetch path too, not just the listing"
        );
    }

    // ── v2 operational-data (FSD §5.2 / CEG 1.0-RC2 §5.6.8.13) ──────

    /// CIRISEdge#397 — `content_hash_of` is `sha256(serde_json::to_vec(value))`:
    /// deterministic (a federation invariant — two peers hash the same on-wire
    /// bytes identically), returns those exact bytes alongside the hash, and
    /// discriminates distinct values. Byte-exact with persist's
    /// `wire_index::content_hash_of`, the lockstep fact the point-read depends on.
    #[test]
    fn content_hash_of_hashes_the_to_vec_bytes() {
        let value = serde_json::json!({
            "organization": { "attestation_id": "att-1", "org_id": "org-acme" }
        });
        let (h1, bytes1) = content_hash_of(&value).expect("hash 1");
        let (h2, _bytes2) = content_hash_of(&value).expect("hash 2");
        assert_eq!(h1, h2, "deterministic");
        // The returned bytes ARE serde_json::to_vec, and the hash is their sha256.
        assert_eq!(bytes1, serde_json::to_vec(&value).unwrap());
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes1)), h1);
        // Distinct values → distinct hashes.
        let (hb, _) = content_hash_of(&serde_json::json!({"org_id": "bob"})).expect("hash b");
        let (hc, _) = content_hash_of(&serde_json::json!({"org_id": "alice"})).expect("hash c");
        assert_ne!(hb, hc);
    }

    /// Without `OperationalProviders` configured, `apply_organization`
    /// fail-closes (returns `false`) — v2 admission requires the
    /// operator to wire up `key_directory` + `root_stewards`. Verifies
    /// the v1-bridge constructors don't accidentally admit v2 envelopes.
    #[tokio::test]
    async fn apply_organization_fail_closes_without_operational_providers() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        // Bridge constructed via `new` (no operational providers).
        // Even if the bytes happen to deserialize cleanly, admission
        // must refuse.
        let bytes = br#"{"organization": {
            "attestation_id": "att-1",
            "org_id": "org-acme",
            "name": "ACME",
            "org_type": "internal",
            "status": "active",
            "asserted_at": "2026-06-10T20:00:00Z",
            "attesting_key_id": "k1",
            "signed_envelope": {},
            "ed25519_signature_base64": ""
        }}"#;
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Organization, bytes, None)
            .await;
        // CIRISEdge#425 — fail-closed AND named: the escaped early return now yields
        // a `Refused` reason the choke point logs, not a silent `false`.
        assert!(
            matches!(&outcome, ApplyOutcome::Refused { reason: r, retry } if r.contains("operational providers") && retry.is_terminal()),
            "v2 operational admission MUST fail-close with a NAMED refusal without \
             OperationalProviders — and TERMINAL (CIRISEdge#544): the providers are \
             fixed at construction, so re-asking every round for a plane this node \
             opted out of admitting can never succeed. Got {outcome:?}"
        );
    }

    /// Same fail-closed invariant for `org_membership`.
    #[tokio::test]
    async fn apply_org_membership_fail_closes_without_operational_providers() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        let bytes = br#"{"org_membership": {
            "attestation_id": "att-1",
            "user_id": "u1",
            "org_id": "org-acme",
            "role": "viewer",
            "status": "active",
            "asserted_at": "2026-06-10T20:00:00Z",
            "attesting_key_id": "k1",
            "signed_envelope": {},
            "ed25519_signature_base64": ""
        }}"#;
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::OrgMembership, bytes, None)
            .await;
        assert!(
            matches!(&outcome, ApplyOutcome::Refused { reason: r, retry } if r.contains("operational providers") && retry.is_terminal()),
            "org_membership must fail-close with a named TERMINAL refusal \
             (CIRISEdge#544), got {outcome:?}"
        );
    }

    /// Same fail-closed invariant for `partner_record`.
    #[tokio::test]
    async fn apply_partner_record_fail_closes_without_operational_providers() {
        let (_backend, bridge) = make_bridge(&["k1".into()]);
        let bytes = br#"{
            "partner_record": {
                "attestation_id":"att-1","license_id":"lic-1","partner_id":"p-1","org_id":"org-1",
                "license_type":"community","max_autonomy_tier":"A0","requires_supervisor":false,
                "deployment_limit":1,"offline_grace_hours":24,"status":"active","revision":1,
                "issued_at":"2026-06-10T20:00:00Z","expires_at":"2027-06-10T20:00:00Z",
                "asserted_at":"2026-06-10T20:00:00Z","signed_envelope":{}
            },
            "steward_signatures": [],
            "threshold": 0
        }"#;
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::PartnerRecord, bytes, None)
            .await;
        assert!(
            matches!(&outcome, ApplyOutcome::Refused { reason: r, retry } if r.contains("operational providers") && retry.is_terminal()),
            "partner_record must fail-close with a named TERMINAL refusal \
             (CIRISEdge#544), got {outcome:?}"
        );
    }

    /// v2.0.1 — bidirectional `partner_record` replication lights up.
    /// Persist v5.2.0's `list_signed_partner_records_since` returns the
    /// full `SignedPartnerRecord` wrapper with `steward_signatures`
    /// inline (CIRISPersist#194 / V072), so a peer-cached envelope
    /// re-emits as the same bytes the original sender hashed. Tests
    /// against an empty backend (no rows) confirms the no-rows path
    /// returns an empty ref set without panic. The deeper convergence
    /// (sender's hash = receiver's hash from peer's
    /// `list_signed_partner_records_since` output) is fenced by the
    /// JCS-determinism + key-order-invariance tests above + persist's
    /// own V072 cohabitation convergence_roundtrip test.
    #[tokio::test]
    async fn v2_list_partner_records_handles_empty_backend() {
        let (_backend, bridge) = make_bridge(&[]);
        let refs = bridge.list_envelope_refs(EnvelopeKind::PartnerRecord).await;
        assert!(
            refs.is_empty(),
            "empty backend yields empty ref set (no panics, no errors)"
        );
    }

    // ── v10 — per-record dynamic policy for the scores/Attestation plane ──

    type Bridge = FederationDirectoryReplicationBridge;

    /// Build an attestation `canonical_json` with the fields the resolver reads:
    /// `dimension` inside `attestation_envelope` (CC 2.1), the rest top-level.
    fn att_json(
        dimension: &str,
        cohort_scope: &str,
        attestation_type: &str,
        attesting_key_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "attesting_key_id": attesting_key_id,
            "attestation_type": attestation_type,
            "cohort_scope": cohort_scope,
            "attestation_envelope": { "dimension": dimension },
        })
    }

    fn set_of(keys: &[&str]) -> HashSet<String> {
        keys.iter().map(|s| (*s).to_string()).collect()
    }

    /// CIRISPersist#713 macro-acceptance instrument — times the FULL advertise
    /// decision (JSON field extraction + authority resolution + the per-plane
    /// `projection_for`) that runs per envelope-ref on the publish loop.
    /// `#[ignore]` by default: run on demand for the before/after A-B a persist
    /// re-pin commits edge to reporting:
    /// `cargo test --release -p ciris-edge --lib advertise_decision_micro_timing --features transport-http -- --ignored --nocapture`
    #[test]
    #[ignore = "on-demand hot-path measurement (CIRISPersist#713 acceptance), not a correctness test"]
    #[allow(clippy::cast_precision_loss)] // ns/call diagnostic print; f64 precision is ample
    fn advertise_decision_micro_timing() {
        const N: u32 = 1_000_000;
        let fixtures = [
            att_json("trust:reliability:v1", "self", "scores", "node-own"),
            att_json("trust:reliability:v1", "community", "scores", "peer-a"),
            att_json(
                "provenance:build_manifest:linux-x86_64",
                "federation",
                "scores",
                "some-builder",
            ),
            att_json("trust:reliability:v1", "family", "withdraw", "node-own"),
        ];
        let self_set = set_of(&["node-own"]);
        // Warm-up pass so allocator/caches settle before the timed window.
        let mut acc = 0u32;
        for f in &fixtures {
            acc += u32::from(Bridge::attestation_is_advertised(f, &self_set));
        }
        let start = std::time::Instant::now();
        for _ in 0..N {
            for f in &fixtures {
                acc += u32::from(Bridge::attestation_is_advertised(f, &self_set));
            }
        }
        let elapsed = start.elapsed();
        let calls = u64::from(N) * fixtures.len() as u64;
        println!(
            "advertise_decision_micro_timing: {calls} calls in {elapsed:?} => {:.1} ns/call (acc={acc})",
            elapsed.as_nanos() as f64 / calls as f64
        );
    }

    /// **CIRISPersist#727 structural gate** — a `skip_serializing_if` field must
    /// never be read by JSON KEY with an empty/default fallback.
    ///
    /// This is the class that produced the v36 trace-replication halt: persist's
    /// `Attestation::cohort_scope` carries `default = "federation"` +
    /// `skip_serializing_if = (s == "federation")`, so the key is ABSENT exactly
    /// when the value is the default. Edge read the key with `unwrap_or("")` and
    /// turned "omitted because default" into "unknown" — invisible for as long as
    /// every family mapped unknown to the same projection, then a silent
    /// replication halt the moment one family didn't.
    ///
    /// A fix is not the close; a GATE is. This scans edge's own source for the
    /// shape and fails on a NEW one, the same way the #425 inbound-exit pin does.
    /// The allowlist is the audited set: each entry either resolves the persist
    /// DEFAULT on absence, or is a field whose skipped value is genuinely empty
    /// (`Option`/`Vec`), where `unwrap_or_default()` is already correct.
    ///
    /// To add a read: resolve the persist default explicitly (see
    /// [`Bridge::attestation_cohort_scope`]) and record it here with why.
    #[test]
    fn skip_serializing_if_fields_are_never_read_by_json_key_with_an_empty_default() {
        // persist fields whose SKIPPED value is a non-empty default — reading the
        // key and falling back to ""/default silently substitutes a different
        // value. (`dimension`/`subject_key_ids` are Option/Vec: absent genuinely
        // means none/empty, so `unwrap_or_default` is correct for them.)
        const NON_EMPTY_DEFAULTED: [&str; 1] = ["cohort_scope"];
        // Audited sites that resolve the persist default explicitly.
        const ALLOWED: [&str; 1] = [
            // `attestation_cohort_scope` — map_or(cohort_scope::FEDERATION, …)
            "ciris_persist::federation::types::cohort_scope::FEDERATION",
        ];
        let src = include_str!("bridge.rs");
        let mut violations = Vec::new();
        for (idx, line) in src.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            for field in NON_EMPTY_DEFAULTED {
                if !line.contains(&format!("\"{field}\"")) {
                    continue;
                }
                if !(line.contains(".get(") || line.contains(".pointer(")) {
                    continue;
                }
                // The read must resolve persist's default within the next 4 lines.
                let window: String = src.lines().skip(idx).take(5).collect::<Vec<_>>().join("\n");
                if ALLOWED.iter().any(|a| window.contains(a)) {
                    continue;
                }
                violations.push(format!("bridge.rs:{}: {}", idx + 1, trimmed));
            }
        }
        assert!(
            violations.is_empty(),
            "CIRISPersist#727 — a `skip_serializing_if` field is read by JSON key \
             without resolving persist's default. The key is ABSENT exactly when the \
             value IS the default, so a `unwrap_or(\"\")`/`unwrap_or_default()` here \
             substitutes a DIFFERENT value and the failure presents as silence \
             (v36: a silent trace-replication halt). Resolve the persist default \
             explicitly and add the site to ALLOWED:\n{}",
            violations.join("\n")
        );
    }

    /// v17.7.0 (CIRISPersist#713) — VALUE pin, not a boolean pin. The advertise
    /// gate maps `Global | Cohort | Capability | Subject => true`, so a narrowing
    /// of the trust-root provenance audience is INVISIBLE to
    /// `attestation_trust_root_commons_is_global_advertised` below: that test
    /// stays green while the audience halves. This test asserts the projection
    /// ITSELF so the change is loud on edge.
    ///
    /// **This pin has already done its job once.** v36.0.0 capped
    /// `provenance:*` at `Cohort` via the conservative default; edge argued on
    /// #713 that `provenance:build_manifest:*` is the cross-cohort
    /// binary-verification surface (capped at Cohort, the #436/#437 bundle gate
    /// degrades to Advisory at first contact BETWEEN cohorts) and persist shipped
    /// the decided row in v36.1.0 — `provenance:build_manifest:` at the
    /// trust-root arm across all three commons tiers. The pin failed on the
    /// v36.1.0 re-pin, which is exactly how edge learned the row had landed.
    ///
    /// If this fails again, the audience of build manifests moved: re-verify
    /// cross-cohort bundle-gate admission before changing the expectation.
    #[test]
    fn trust_root_provenance_projection_value_is_pinned() {
        let a = att_json(
            "provenance:build_manifest:linux-x86_64",
            "federation",
            "scores",
            "some-builder",
        );
        let got = Bridge::attestation_projection(&a);
        assert!(
            matches!(got, Projection::Global),
            "trust-root provenance projects {got:?}; expected Global (the v36.1.0 \
             decided row). A narrowing here silently degrades cross-cohort \
             bundle-gate admission to Advisory (CIRISPersist#713)."
        );
        // The stem is `provenance:build_manifest:`, NOT `provenance:` — a
        // sibling provenance family is deliberately NOT widened by that row.
        let sibling = att_json(
            "provenance:other:v1",
            "federation",
            "scores",
            "some-builder",
        );
        assert!(
            !matches!(Bridge::attestation_projection(&sibling), Projection::Global),
            "only the build_manifest stem is widened; `provenance:*` at large stays \
             at the conservative default"
        );
    }

    /// v17.7.0 — the #713 overlay fold is 1:1 with the heuristic it replaced.
    /// Edge deleted `dimension.starts_with("trace:")` in favour of the registry
    /// resolving `Capability`; this pins that the swap did not move the gate.
    #[test]
    fn capability_and_subject_folds_match_the_replaced_overlays() {
        // The serve gate is scope-INDEPENDENT: trace content requires
        // `infra:serve` at EVERY scope. This is the invariant that made the
        // naive fold onto `Capability(_)` unsafe.
        for scope in ["self", "family", "community", "affiliations", "federation"] {
            let trace = att_json("trace:complete:v1", scope, "scores", "peer-a");
            assert!(
                Bridge::attestation_requires_serve(&trace),
                "the infra:serve gate must fire for trace:* at scope {scope:?}"
            );
        }
        // …while the PROJECTION is family-AND-scope: Capability only at the
        // commons tiers, SelfOwn below. Pinning the trap so a future fold onto
        // `Capability(_)` cannot be made without seeing it.
        assert!(
            matches!(
                Bridge::attestation_projection(&att_json(
                    "trace:complete:v1",
                    "federation",
                    "scores",
                    "peer-a"
                )),
                Projection::Capability(_)
            ),
            "trace:* at a commons tier resolves Capability"
        );
        assert!(
            matches!(
                Bridge::attestation_projection(&att_json(
                    "trace:complete:v1",
                    "community",
                    "scores",
                    "peer-a"
                )),
                Projection::SelfOwn
            ),
            "trace:* at community resolves SelfOwn — NOT Capability. A serve gate \
             folded onto `Capability(_)` would silently stop firing here."
        );
        // scores:* → Subject → the item-6 recipient gate's family.
        let scores = att_json("scores:reliability:v1", "community", "scores", "peer-a");
        assert!(
            matches!(Bridge::attestation_projection(&scores), Projection::Subject),
            "scores:* must resolve Subject (folds recipient_capability_withholds)"
        );
        // A non-gated family must NOT acquire the serve gate.
        let other = att_json("trust:reliability:v1", "community", "scores", "peer-a");
        assert!(
            !Bridge::attestation_requires_serve(&other),
            "the serve gate must not widen to families the heuristic never gated"
        );
    }

    /// A trust-root (`provenance:build_manifest:*` → `AccordCoScrub`) attestation
    /// at a commons scope reaches the WHOLE federation — advertised even though
    /// this node didn't produce it. This is the v10 fix: infra / canonical /
    /// build-manifest attestations were stuck at coarse `Cohort` before.
    #[test]
    fn attestation_trust_root_commons_is_global_advertised() {
        let a = att_json(
            "provenance:build_manifest:linux-x86_64",
            "federation",
            "scores",
            "some-builder",
        );
        assert!(
            Bridge::attestation_is_advertised(&a, &HashSet::new()),
            "trust-root build-manifest attestation reaches the whole federation regardless of producer"
        );
    }

    /// A `self`-scoped attestation is publish-own: advertised iff THIS node
    /// produced it, never relayed by a third party.
    #[test]
    fn attestation_self_scoped_advertised_only_when_produced_here() {
        let a = att_json("trust:reliability:v1", "self", "scores", "node-own");
        assert!(
            Bridge::attestation_is_advertised(&a, &set_of(&["node-own"])),
            "self-scoped: advertised when THIS node produced it (publish-own)"
        );
        assert!(
            !Bridge::attestation_is_advertised(&a, &set_of(&["someone-else"])),
            "self-scoped: NOT relayed by a third party"
        );
    }

    /// A `community`-scoped attestation relays over the cohort — advertised
    /// regardless of the self set.
    #[test]
    fn attestation_community_scoped_relays_over_cohort() {
        let a = att_json("trust:reliability:v1", "community", "scores", "peer");
        assert!(Bridge::attestation_is_advertised(&a, &HashSet::new()));
    }

    /// A `withdraws` tombstone gossips GLOBAL (anti-rollback) even at `self`
    /// scope and even if this node didn't produce it — a revocation can never be
    /// out-run by the stale record it retracts.
    #[test]
    fn attestation_withdraws_is_tombstone_global() {
        let a = att_json("trust:reliability:v1", "self", "withdraws", "peer");
        assert!(
            Bridge::attestation_is_advertised(&a, &HashSet::new()),
            "withdraws tombstone → Global regardless of scope/producer"
        );
    }

    /// Every one of the 95 families resolves — an unknown or absent dimension
    /// falls to `authority_for`'s `ProducerSteward` default and an unknown scope
    /// to `projection_for`'s `Cohort` negative default (never a panic, never
    /// silently Global/SelfOwn).
    #[test]
    fn attestation_unknown_or_absent_dimension_defaults_to_cohort() {
        let unknown = att_json("totally:unknown:prefix", "community", "scores", "peer");
        assert!(Bridge::attestation_is_advertised(&unknown, &HashSet::new()));
        // Dimension absent entirely (e.g. a `delegates_to` relation).
        let absent = serde_json::json!({
            "attesting_key_id": "peer",
            "attestation_type": "delegates_to",
            "cohort_scope": "community",
        });
        assert!(
            Bridge::attestation_is_advertised(&absent, &HashSet::new()),
            "absent dimension still resolves (no panic)"
        );
    }

    /// The resolver DISCRIMINATES — a non-trust-root producer's commons-scoped
    /// attestation relays over the cohort (advertised), but the same producer's
    /// `self`-scoped attestation is filtered when this node didn't make it. Only
    /// a trust-root authority promotes a commons scope to Global.
    #[test]
    fn attestation_resolver_discriminates_by_authority_and_scope() {
        let commons = att_json("trust:reliability:v1", "federation", "scores", "peer");
        assert!(
            Bridge::attestation_is_advertised(&commons, &HashSet::new()),
            "non-trust-root federation scope relays over cohort"
        );
        let self_scoped = att_json("trust:reliability:v1", "self", "scores", "peer");
        assert!(
            !Bridge::attestation_is_advertised(&self_scoped, &HashSet::new()),
            "self-scoped from a non-producer is filtered — resolver is not blanket-advertising"
        );
    }

    /// **Exhaustiveness proof** — EVERY family in persist's vendored namespace
    /// registry (all `VENDORED_N_FAMILIES`) resolves a projection through the
    /// resolver at every `cohort_scope`, with no panic. This is what "all the
    /// namespaces replicate" means concretely: replication policy is defined for
    /// the ENTIRE namespace, not a hand-picked subset.
    #[test]
    fn every_registry_family_resolves_a_projection() {
        let scopes = [
            "self",
            "family",
            "community",
            "affiliations",
            "species",
            "biosphere",
            "federation",
            // v17.7.0 — "" is NOT "absent". persist's serde contract makes an
            // ABSENT key mean `federation` (default + skip_serializing_if are
            // inverses); a PRESENT-but-empty value is malformed and is DECLINED
            // by the advertise gate. Asserted separately below.
        ];
        // The empty-scope decline, pinned once rather than per family: malformed
        // input is refused, never silently projected.
        assert!(
            !Bridge::attestation_is_advertised(
                &att_json("trust:reliability:v1", "", "scores", "peer"),
                &HashSet::new()
            ),
            "a present-but-EMPTY cohort_scope must be declined, not projected"
        );
        let families = namespace::registry::entries();
        assert_eq!(
            families.len(),
            namespace::registry::VENDORED_N_FAMILIES,
            "resolver covers the full vendored family set"
        );
        for entry in families {
            for scope in scopes {
                // Must resolve (no panic) for both a live score and a tombstone.
                let scored = att_json(&entry.prefix, scope, "scores", "peer");
                let tombstone = att_json(&entry.prefix, scope, "withdraws", "peer");
                let _ = Bridge::attestation_is_advertised(&scored, &HashSet::new());
                // v17.7.0 (#713) — a tombstone no longer gossips unconditionally
                // Global; it projects at `tombstone_ceiling(plane, authority)`.
                // Every family's ceiling is an ADVERTISED projection (Global /
                // Cohort / Capability / Subject — never SelfOwn), so the
                // advertise invariant holds while the audience is per-plane.
                assert!(
                    Bridge::attestation_is_advertised(&tombstone, &HashSet::new()),
                    "every family's withdraws tombstone advertises at its ceiling ({})",
                    entry.prefix
                );
            }
        }
    }

    // ── CIRISEdge#433 — the withhold ledger ─────────────────────────
    //
    // Field-provenance discipline ([[feedback_test_field_provenance]]): each test
    // below drives the REAL gate through the bridge with a directory state that
    // makes that branch fire, then asserts the LEDGER counted that branch. None
    // of them call `inc_withhold` directly — a green test on a hand-fed reason
    // would prove only that the counter increments, not that the gate reaches it.
    // (The single exception is the ring-buffer bound smoke test in
    // `observability.rs`, where the bound itself is the unit under test.)

    /// A bridge over a fresh `MemoryBackend` with a LIVE metrics handle attached
    /// — the production shape (`ReplicationRuntime::start` threads `Edge`'s
    /// handle in). Returns the handle so a test can read the ledger back.
    fn make_metered_bridge(
        cohort: &[String],
    ) -> (
        Arc<MemoryBackend>,
        FederationDirectoryReplicationBridge,
        crate::observability::EdgeMetrics,
    ) {
        let (backend, bridge) = make_bridge(cohort);
        let metrics = crate::observability::EdgeMetrics::new();
        (backend, bridge.with_metrics(Some(metrics.clone())), metrics)
    }

    /// The scaffold BOTH halves of the discriminator share: registered keys for
    /// every party, and `local`'s bare consent grant naming `peer` so the #396
    /// item-1 membership bound passes. Identical configuration on both sides
    /// means the ONLY difference between "idle" and "withholding" is whether a
    /// gated row exists — which is exactly the distinction #433 exists to make
    /// visible.
    async fn seed_serve_scaffold(backend: &MemoryBackend, local: &str, producer: &str, peer: &str) {
        for key_id in [local, producer, peer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_consent_membership(backend, local, peer).await;
    }

    /// CIRISEdge#455 — the FULL field signature, reproduced and NAMED: on a
    /// canonical whose `infra:serve` is claimed but not accord-conferred (the
    /// un-re-genesised fleet state), a `trace:*` row is
    ///   (1) present in the GLOBAL advertise (the harness's "but it IS among
    ///       the refs the agent advertises" observation — true and misleading:
    ///       that read is peer-blind),
    ///   (2) ABSENT from the PER-PEER offer the wire Summary is actually built
    ///       from (`DirectoryStateAdapter::local_refs` →
    ///       `list_envelope_refs_for_peer`), so the receiver never wants it,
    ///       never fetches it, and reports NOTHING — the "neither admitted nor
    ///       refused" silence at the canonical,
    ///   (3) while consent rows still cross the same offer (the "admitted: 5"),
    ///   (4) and the AGENT's withhold ledger names the branch:
    ///       `serve_capability_missing` — the reason the ledger's own docs
    ///       predicted for a dark trace plane (CIRISPersist#480).
    /// Not a want/Diff/Deliver defect: the row never enters the offer.
    #[tokio::test]
    async fn trace_offered_globally_but_withheld_per_peer_is_the_455_signature() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let canonical = "canonical-claimed-not-conferred";
        let cohort = [
            local.to_string(),
            producer.to_string(),
            canonical.to_string(),
        ];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for (k, it) in [
            (local, identity_type::NODE),
            (producer, identity_type::AGENT),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        // The canonical CLAIMS infra:serve in its own record — no accord
        // co-scrub (persist admits the claim; conferral is read-time).
        let mut rec = fixture_key_record(canonical, identity_type::NODE);
        rec.capability_roles =
            vec![FederationDirectoryReplicationBridge::SERVE_CAPABILITY.to_string()];
        backend
            .put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("seed canonical");
        seed_consent_membership(&backend, local, canonical).await;
        seed_trace_attestation(&backend, producer).await;
        let trace_hash = locate_trace_hash(&bridge).await;

        // (1) The peer-BLIND advertise contains the trace — the harness's
        // observation, reproduced.
        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Attestation)
                .await
                .iter()
                .any(|r| r.envelope_hash == trace_hash),
            "(1) globally advertised"
        );
        // (2)+(3) The per-peer offer — what the wire Summary is built from —
        // omits the trace but still carries the consent row.
        let offer = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(canonical))
            .await;
        assert!(
            !offer.iter().any(|r| r.envelope_hash == trace_hash),
            "(2) absent from the per-peer offer — the receiver never wants it"
        );
        assert!(
            !offer.is_empty(),
            "(3) consent rows still cross — the round completes and admits"
        );
        // (4) The ledger names the branch on the AGENT side.
        assert!(
            metrics
                .snapshot()
                .withholds_by_reason
                .get(&WithholdReason::ServeCapabilityMissing)
                .copied()
                .unwrap_or(0)
                >= 1,
            "(4) the withhold ledger books serve_capability_missing — the \
             silence has a name, on the sender"
        );
    }

    /// CIRISEdge#433, the discriminator property from the issue — **two states,
    /// now distinguishable**.
    ///
    /// Before this cut, a node withholding every `trace:*` row from every peer
    /// reported exactly what a node with nothing to send reported: zero sent,
    /// round `completed`, perfect health, zero carriage. Both bridges here are
    /// configured IDENTICALLY (same keys, same consent grant, same peer lacking
    /// `infra:serve`); the only difference is that one holds a trace row. That
    /// used to be invisible. It is now the difference between an empty ledger
    /// and `serve_capability_missing >= 1`.
    #[tokio::test]
    async fn idle_and_withholding_bridges_are_distinguishable() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-no-capability";
        let cohort = [local.to_string(), producer.to_string(), peer.to_string()];

        // (a) IDLE — fully wired, consent-included peer, and NOTHING held back:
        //     every row it advertises, it serves.
        let (idle_backend, idle_bridge, idle_metrics) = make_metered_bridge(&cohort);
        let idle_bridge = idle_bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&idle_backend, local, producer, peer).await;
        let idle_refs = idle_bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
        for r in &idle_refs {
            assert!(
                idle_bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &r.envelope_hash,
                        Some(peer)
                    )
                    .await
                    .is_some(),
                "the idle bridge holds nothing back"
            );
        }
        let idle = idle_metrics.snapshot();
        assert!(
            idle.withholds_by_reason.is_empty(),
            "an IDLE node withholds nothing — its ledger is empty, got {:?}",
            idle.withholds_by_reason
        );
        assert_eq!(
            idle.replication_envelopes_served_total
                .get(&EnvelopeKind::Attestation)
                .copied()
                .unwrap_or(0),
            idle_refs.len() as u64,
            "an IDLE node's carriage equals what it advertised"
        );

        // (b) WITHHOLDING — same wiring, plus one `trace:*` row the peer may not
        //     have (it holds no accord-conferred `infra:serve`).
        let (hold_backend, hold_bridge, hold_metrics) = make_metered_bridge(&cohort);
        let hold_bridge = hold_bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&hold_backend, local, producer, peer).await;
        seed_trace_attestation(&hold_backend, producer).await;
        let trace_hash = locate_trace_hash(&hold_bridge).await;

        // Drive the REAL advertise gate, then the REAL serve gate.
        let held_refs = hold_bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
        assert!(
            !held_refs.iter().any(|r| r.envelope_hash == trace_hash),
            "the trace row is withheld from a peer with no `infra:serve`"
        );
        assert!(
            hold_bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &trace_hash, Some(peer))
                .await
                .is_none(),
            "...on the direct-fetch path too"
        );

        let held = hold_metrics.snapshot();
        assert!(
            held.withholds_by_reason
                .get(&WithholdReason::ServeCapabilityMissing)
                .copied()
                .unwrap_or(0)
                >= 1,
            "the WITHHOLDING node books the branch that decided, got {:?}",
            held.withholds_by_reason
        );
        assert_eq!(
            held.replication_envelopes_served_total
                .get(&EnvelopeKind::Attestation)
                .copied()
                .unwrap_or(0),
            0,
            "and it served NOTHING — the state that used to look identical to idle"
        );

        // The property, stated directly: the two nodes' reports now differ.
        assert_ne!(
            idle.withholds_by_reason, held.withholds_by_reason,
            "an idle node and a withholding node must not report the same thing"
        );
    }

    /// CIRISEdge#433 — a serve that MOVES a row bumps
    /// `replication_envelopes_served_total`, keyed by the same `EnvelopeKind` the
    /// wire uses. This is the mirror-image defect: `inc_sent` is called only from
    /// `src/edge.rs`, so before this counter a node that moved N rows through
    /// anti-entropy rounds reported `envelopes_sent_total: 0` — reporting broken
    /// while working.
    #[tokio::test]
    async fn a_serve_that_moves_rows_bumps_the_replication_served_counter() {
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&backend, local, producer, peer).await;
        // A NON-trace row: no `trace:` dimension, so the #379/#386 gate is inert
        // and this exercises the SERVE path, not a withhold.
        seed_advertised_attestation(&backend, producer).await;

        let refs = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;
        assert!(
            !refs.is_empty(),
            "the row is advertised to the consented peer"
        );
        for r in &refs {
            assert!(
                bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &r.envelope_hash,
                        Some(peer)
                    )
                    .await
                    .is_some(),
                "every advertised row serves"
            );
        }

        let snap = metrics.snapshot();
        assert_eq!(
            snap.replication_envelopes_served_total
                .get(&EnvelopeKind::Attestation)
                .copied()
                .unwrap_or(0),
            refs.len() as u64,
            "one bump per envelope the bridge handed to the wire path"
        );
        assert!(
            snap.withholds_by_reason.is_empty(),
            "a clean serve withholds nothing, got {:?}",
            snap.withholds_by_reason
        );
    }

    // ── Workstream F — the `accord:*` relay gate, wired ─────────────────

    /// Seed one ACCORD_HOLDER key: `accord:*` rows require a hardware-attested
    /// holder as attester (persist v22 / #543 / the FIPS anti-Sybil floor
    /// #513), so the fixture carries the exact fresh Android/Strongbox blob
    /// persist's `fresh_accord_holder_evidence` emits (inlined so this does not
    /// gate on `test-anchor` — same inline the #386 trust-graph test uses).
    async fn seed_accord_holder_key(backend: &MemoryBackend, key_id: &str) {
        let mut record = fixture_key_record(key_id, identity_type::ACCORD_HOLDER);
        record.attestation_evidence = Some(serde_json::json!({
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
            "nonce_captured_at": Utc::now().to_rfc3339(),
        }));
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .expect("seed accord-holder key");
    }

    /// Locate the advertised hash of the `accord:*` row whose SIGNED subject is
    /// `(root, signer)`, through the PEER-BLIND view (which the relay gate does
    /// not touch), so a test can then drive the per-peer advertise + fetch gates
    /// at that exact hash.
    ///
    /// CIRISPersist#731 — matched on the same
    /// [`AccordRelaySubject`](crate::replication::accord_relay_gate::AccordRelaySubject)
    /// the gate itself derives, so a test always aims at the row the gate will
    /// actually judge. (It previously matched the UNSIGNED top-level
    /// `attesting_key_id` column, which is not what the gate reads.)
    /// `ty` discriminates the NAMESPACE the row rides (CIRISEdge#505): one
    /// holder can hold both a dimension-namespace row (`ty = "scores"`) and a
    /// type-namespace row (`ty = "accord:invoke:…"`) under the same root, and
    /// `(root, signer)` alone no longer picks one.
    async fn locate_accord_hash(
        bridge: &FederationDirectoryReplicationBridge,
        root: &str,
        signer: &str,
        ty: &str,
    ) -> [u8; 32] {
        use crate::replication::accord_relay_gate::AccordRelaySubject;
        for r in bridge.list_envelope_refs(EnvelopeKind::Attestation).await {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                .await
                .expect("projection-only fetch");
            let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
                continue;
            };
            let inner = v.get("attestation").unwrap_or(&v);
            if FederationDirectoryReplicationBridge::attestation_is_accord(inner)
                && inner.get("attestation_type").and_then(|t| t.as_str()) == Some(ty)
                && AccordRelaySubject::of_attestation(inner)
                    .is_ok_and(|s| s.root_ref == root && s.signer_key_id == signer)
            {
                return r.envelope_hash;
            }
        }
        panic!("the seeded {ty} accord row by {signer} under {root} appears in the local view");
    }

    /// Workstream F, the whole property in one scenario — and deliberately BOTH
    /// halves, because a gate only ever seen refusing is indistinguishable from
    /// a gate that is dead (the #435 / v13.10.0 lesson), while a gate only ever
    /// seen allowing proves nothing about carriage at all.
    ///
    /// One node, one accord root, one peer, and five rows — the family's BOTH
    /// namespaces (CIRISEdge#505: `accord:invoke:*` as a TYPE,
    /// `accord:human_dignity:v1`-style rows as a `scores` DIMENSION), each with
    /// an allow and a refuse so neither namespace can pass by being skipped:
    ///
    /// | row | expectation |
    /// |---|---|
    /// | dimension-namespace `accord:*` by a SEATED holder | advertised AND served — persist's `may_relay` holds |
    /// | dimension-namespace `accord:*` by an UNSEATED holder | withheld from BOTH paths, booked `accord_relay_signer_not_seated` |
    /// | TYPE-namespace `accord:invoke:*` by a SEATED holder | advertised AND served — the pre-filter admits it AND the gate allows it |
    /// | TYPE-namespace `accord:invoke:*` by an UNSEATED holder | withheld from BOTH paths — pre-#505 this row skipped the gate and was CARRIED |
    /// | a non-`accord:` row | untouched — this gate narrows exactly one family |
    ///
    /// The trust state is seeded the way persist's own
    /// `exercise_accord_relay_eligibility` seeds it: a KEYLESS family whose
    /// `family_key_id` IS the accord root (a family cannot sign its own
    /// declaration, hence `put_family_local`), plus a live
    /// `delegates_to(local → root)` — the CC 4.2.1 consent edge whose absence
    /// is the whole reason a bare `Global` projection over-delivers.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // one coherent scenario: seed + allow + refuse + untouched
    async fn accord_row_is_relayed_when_the_gate_allows_and_withheld_when_it_refuses() {
        use crate::observability::WithholdReason;
        use crate::replication::accord_relay_gate::AccordRelayGate;
        use ciris_persist::federation::types::{Family, FamilyMember};

        let local = "this-node";
        let peer = "peer-consented";
        let producer = "agent-producer";
        let root = "humanity-accord-under-test";
        let seated = "accord-holder-seated";
        let unseated = "accord-holder-unseated";
        let cohort = [
            local.to_string(),
            peer.to_string(),
            producer.to_string(),
            root.to_string(),
        ];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);

        for (k, it) in [
            (local, identity_type::NODE),
            (peer, identity_type::AGENT),
            (producer, identity_type::AGENT),
            (root, identity_type::NODE),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        seed_accord_holder_key(&backend, seated).await;
        seed_accord_holder_key(&backend, unseated).await;
        seed_consent_membership(&backend, local, peer).await;

        // The accord roster: a keyless family whose id IS the root, seating
        // exactly one of the two holders.
        let founded: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned founding instant");
        backend
            .put_family_local(Family {
                family_key_id: root.to_owned(),
                family_name: root.to_owned(),
                members: vec![FamilyMember {
                    key_id: seated.to_owned(),
                    joined_at: founded,
                    role: Some("founder".to_owned()),
                }],
                founded_at: founded,
                consensus_protocol: "quorum:2/3".to_owned(),
                consensus_protocol_entrenched: true,
                persist_row_hash: String::new(),
            })
            .await
            .expect("seed the accord family");
        // CC 4.2.1 — OUR consent edge to the root. Without this leg the gate
        // refuses even the seated holder, which is exactly the point of it.
        seed_delegates_to(
            &backend,
            local,
            root,
            &serde_json::json!(["infra:attest", "infra:serve"]),
        )
        .await;

        // The rows: per holder, one accord row in EACH namespace (dimension +
        // type — CIRISEdge#505), plus a non-accord row.
        seed_accord_lifecycle(&backend, seated, root).await;
        seed_accord_lifecycle(&backend, unseated, root).await;
        seed_accord_invoke(&backend, seated, root).await;
        seed_accord_invoke(&backend, unseated, root).await;
        seed_advertised_attestation(&backend, producer).await;

        let seated_hash = locate_accord_hash(&bridge, root, seated, "scores").await;
        let unseated_hash = locate_accord_hash(&bridge, root, unseated, "scores").await;
        let seated_invoke_hash =
            locate_accord_hash(&bridge, root, seated, "accord:invoke:notify:halt").await;
        let unseated_invoke_hash =
            locate_accord_hash(&bridge, root, unseated, "accord:invoke:notify:halt").await;
        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            .with_accord_relay_gate(Some(Arc::new(AccordRelayGate::new(
                backend.clone(),
                Some(local.to_string()),
            ))));

        let offer = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;

        // (A) THE ALLOW — seated signer + our live edge ⇒ the row is carried,
        // on the advertise AND the direct-fetch path.
        assert!(
            offer.iter().any(|r| r.envelope_hash == seated_hash),
            "a seated holder's accord row is ADVERTISED (the gate is not dead)"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &seated_hash, Some(peer))
                .await
                .is_some(),
            "…and SERVED on the direct-fetch twin"
        );

        // (C) THE REFUSAL — an unseated signer's row is carried by neither.
        assert!(
            !offer.iter().any(|r| r.envelope_hash == unseated_hash),
            "an UNSEATED holder's accord row is withheld from the offer"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &unseated_hash,
                    Some(peer)
                )
                .await
                .is_none(),
            "…and cannot be obtained by fetching a hash learned out-of-band"
        );

        // (B/D) THE TYPE NAMESPACE (CIRISEdge#505) — the same allow/refuse
        // pair for `accord:invoke:*` rows, whose family membership rides the
        // `attestation_type` and NOT the dimension. Before the pre-filter fix
        // these rows never reached the gate at all, so the UNSEATED holder's
        // row below was advertised and served — the under-gating hole.
        assert!(
            offer.iter().any(|r| r.envelope_hash == seated_invoke_hash),
            "a seated holder's TYPE-namespace accord row is ADVERTISED — the \
             pre-filter admits it to the gate and the gate allows it"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &seated_invoke_hash,
                    Some(peer)
                )
                .await
                .is_some(),
            "…and SERVED on the direct-fetch twin"
        );
        assert!(
            !offer
                .iter()
                .any(|r| r.envelope_hash == unseated_invoke_hash),
            "an UNSEATED holder's TYPE-namespace accord row is withheld from the \
             offer — pre-#505 the pre-filter skipped the gate and CARRIED it"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &unseated_invoke_hash,
                    Some(peer)
                )
                .await
                .is_none(),
            "…and cannot be obtained by fetching its hash out-of-band either"
        );

        // The refusal is LOUD and NAMES ITS BRANCH (CIRISEdge#425/#433) — and
        // it is the *seated* branch, not `cannot judge`: the roster resolved
        // fine here, so reporting `roster_unresolvable` would send an operator
        // to sync a family record that is already present.
        let snap = metrics.snapshot();
        assert!(
            snap.withholds_by_reason
                .get(&WithholdReason::AccordRelaySignerNotSeated)
                .copied()
                .unwrap_or(0)
                >= 1,
            "the ledger books `accord_relay_signer_not_seated`, got {:?}",
            snap.withholds_by_reason
        );
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::AccordRelayRosterUnresolvable)
                .copied()
                .unwrap_or(0),
            0,
            "…and NOT `roster_unresolvable` — the two never collapse"
        );

        // (4) A non-`accord:` row is untouched: this gate narrows exactly one
        // dimension family and nothing else.
        assert!(
            offer.len() >= 2,
            "the non-accord rows still cross (offer: {})",
            offer.len()
        );
        for r in &offer {
            assert!(
                bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &r.envelope_hash,
                        Some(peer)
                    )
                    .await
                    .is_some(),
                "every row the gate let into the offer still fetches — advertise \
                 and serve AGREE (no #429 advertised-then-unfetchable)"
            );
        }
    }

    /// CIRISEdge#505 — the pre-filter must see BOTH namespaces.
    ///
    /// Until v37.1.0 this read only the dimension, so an `accord:invoke:*` row
    /// carried in the `attestation_type` namespace never reached the relay
    /// gate at all — advertised, fetched and subject-pulled with no CC 4.2.1
    /// carriage check. A false NEGATIVE: the gate failed to look.
    #[test]
    fn the_accord_pre_filter_sees_the_type_namespace_not_only_the_dimension() {
        let by_dimension = serde_json::json!({
            "attestation_type": "scores",
            "attestation_envelope": { "dimension": "accord:human_dignity:v1" },
        });
        let by_type = serde_json::json!({
            "attestation_type": "accord:invoke:notify:halt",
            "attestation_envelope": { "dimension": "trust:example:v1" },
        });
        // The shape a TYPE-namespace row actually produces on the wire: the
        // namespace travels as the type and there is NO `dimension` key at all
        // (persist's `is_accord_family` takes `Option<&str>` for exactly this
        // row — `None` is not a dimension-arm match, never an error).
        let by_type_no_dimension = serde_json::json!({
            "attestation_type": "accord:invoke:notify:halt",
            "attestation_envelope": { "accord_root": "humanity-accord" },
        });
        // BOTH fields accord-shaped — one row, one family membership, and the
        // caller consults ONE gate for it (the gate resolves ONE subject; see
        // accord_relay_gate's
        // `the_type_namespace_row_is_judged_not_skipped_and_both_namespaces_gate_once`).
        let by_both = serde_json::json!({
            "attestation_type": "accord:invoke:notify:halt",
            "attestation_envelope": { "dimension": "accord:human_dignity:v1" },
        });
        let neither = serde_json::json!({
            "attestation_type": "scores",
            "attestation_envelope": { "dimension": "trust:example:v1" },
        });
        // Non-accord in the TYPE namespace with no dimension — the
        // `delegates_to` / `withdraws` wire shape must keep bypassing the gate.
        let neither_no_dimension = serde_json::json!({
            "attestation_type": "delegates_to",
            "attestation_envelope": { "scope": ["infra:attest"] },
        });

        assert!(FederationDirectoryReplicationBridge::attestation_is_accord(
            &by_dimension
        ));
        assert!(
            FederationDirectoryReplicationBridge::attestation_is_accord(&by_type),
            "an accord:* row in the TYPE namespace must reach the relay gate — \
             skipping it is the CIRISEdge#505 under-gating hole",
        );
        assert!(
            FederationDirectoryReplicationBridge::attestation_is_accord(&by_type_no_dimension),
            "…including with NO dimension key at all, which is the exact wire \
             shape an `accord:invoke:*` row carries",
        );
        assert!(
            FederationDirectoryReplicationBridge::attestation_is_accord(&by_both),
            "a row accord-shaped on BOTH namespaces is on the family",
        );
        assert!(
            !FederationDirectoryReplicationBridge::attestation_is_accord(&neither),
            "and a non-accord row must still bypass the gate, so this cannot \
             pass by gating everything",
        );
        assert!(
            !FederationDirectoryReplicationBridge::attestation_is_accord(&neither_no_dimension),
            "a non-accord TYPE with no dimension bypasses too — widening to \
             `None`-dimension rows must not have gated the structural verbs",
        );
    }

    /// **THE CIRISEdge#505 RE-OPEN FENCE** — a source assertion, in the style
    /// of `skip_serializing_if_fields_are_never_read_by_json_key_with_an_empty_default`.
    ///
    /// The behavioural test above proves the pre-filter's ANSWERS; this pins
    /// its READS, because on every constructible fixture today the answers
    /// cannot distinguish persist's `is_accord_family` from a re-inlined
    /// prefix check or from the dimension-half helper the pre-filter consulted
    /// before v37.1.0 (`AccordRelayGate::dimension_half_is_gated`, the fenced
    /// remnant) — the three diverge exactly when a third namespace arm or a
    /// registry change lands, which is when the second spelling bites.
    #[test]
    fn the_carriage_pre_filter_reads_is_accord_family_not_the_dimension_half() {
        let src = include_str!("bridge.rs");
        let start = src
            .find("fn attestation_is_accord")
            .expect("the pre-filter exists");
        let end = src[start..].find("\n    }").expect("the fn body closes");
        let body = &src[start..start + end];
        assert!(
            body.contains("is_accord_family"),
            "attestation_is_accord must delegate to persist's `is_accord_family` — \
             the ONE owner of the two-namespace accord family test (CIRISPersist#743)"
        );
        for (path, mirror_of) in [
            ("\"/attestation_type\"", "`row.attestation_type`"),
            (
                "\"/attestation_envelope/dimension\"",
                "`admission::envelope_dimension`",
            ),
        ] {
            assert!(
                body.contains(path),
                "attestation_is_accord must read {path} — the exact field persist's \
                 admission reads via {mirror_of}; dropping either re-opens CIRISEdge#505"
            );
        }
        assert!(
            !body.contains("dimension_half_is_gated") && !body.contains("dimension_is_gated"),
            "the dimension-half helper is NOT a carriage classifier — routing the \
             pre-filter through it is the CIRISEdge#505 under-gating hole verbatim"
        );
        assert!(
            !body.contains("starts_with"),
            "no edge-side prefix spelling — persist owns the family test \
             (the CIRISPersist#731/#733 two-owners drift)"
        );
    }

    /// **THE CIRISPersist#731 REGRESSION TEST.** One signer, two accords, a node
    /// that validly trusts BOTH — and the object decides which roster it is
    /// judged against.
    ///
    /// | | row | old gate (`root_ref = accord-a`) | new gate |
    /// |---|---|---|---|
    /// | allow half | drill about `accord-a` by a holder seated on A | relayed | **relayed** |
    /// | the defect | drill about `accord-b` by that same holder | **RELAYED** | **withheld** `accord_relay_signer_not_seated` |
    ///
    /// The old gate never looked at the object. It asked *"is this signer seated
    /// on the root the HOST named, and do we have an edge to it?"* — both true —
    /// and carried a `accord-b` object on `accord-a`'s roster. persist's finding
    /// exactly: *"a confidently wrong answer […] in the permissive direction"*.
    ///
    /// Both halves are asserted on purpose. A gate that refused everything would
    /// satisfy the refusal half alone, so the allow half is what proves the
    /// refusal is about the ROOT rather than the gate being dead (#435).
    ///
    /// `accord-b` gets a REAL family (seating someone else), so the refusal is
    /// `signer_not_seated` — the roster resolved fine — and not the weaker
    /// `roster_unresolvable`, which a node simply missing B's family record
    /// would produce and which would leave the cross-accord property untested.
    #[tokio::test]
    // One coherent scenario: two accords seeded + the allow half + the defect
    // half. Splitting it would put the ALLOW in a different test from the
    // REFUSAL, and it is the pair that carries the property.
    #[allow(clippy::too_many_lines)]
    async fn an_object_belonging_to_another_accord_is_not_relayed_on_this_ones_roster() {
        use crate::observability::WithholdReason;
        use crate::replication::accord_relay_gate::AccordRelayGate;
        use ciris_persist::federation::types::{Family, FamilyMember};

        let local = "this-node";
        let peer = "peer-consented";
        let accord_a = "accord-alpha";
        let accord_b = "accord-beta";
        let holder = "holder-seated-on-a-only";
        let b_holder = "holder-seated-on-b";
        let cohort = [
            local.to_string(),
            peer.to_string(),
            accord_a.to_string(),
            accord_b.to_string(),
        ];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);

        for (k, it) in [
            (local, identity_type::NODE),
            (peer, identity_type::AGENT),
            (accord_a, identity_type::NODE),
            (accord_b, identity_type::NODE),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        seed_accord_holder_key(&backend, holder).await;
        seed_accord_holder_key(&backend, b_holder).await;
        seed_consent_membership(&backend, local, peer).await;

        let founded: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned founding instant");
        let member = |k: &str| FamilyMember {
            key_id: k.to_owned(),
            joined_at: founded,
            role: Some("founder".to_owned()),
        };
        // TWO real accords. `holder` sits on A only; B seats someone else, so
        // B's roster RESOLVES — "cannot judge" is not what does the work here.
        for (root, seat) in [(accord_a, holder), (accord_b, b_holder)] {
            backend
                .put_family_local(Family {
                    family_key_id: root.to_owned(),
                    family_name: root.to_owned(),
                    members: vec![member(seat)],
                    founded_at: founded,
                    consensus_protocol: "quorum:2/3".to_owned(),
                    consensus_protocol_entrenched: true,
                    persist_row_hash: String::new(),
                })
                .await
                .expect("seed the accord family");
            // CC 4.2.1 — this node validly trusts BOTH roots, so leg 2 holds
            // either way and cannot be what separates the two rows.
            seed_delegates_to(
                &backend,
                local,
                root,
                &serde_json::json!(["infra:attest", "infra:serve"]),
            )
            .await;
        }

        // The same holder emits a drill about EACH accord. Only the root inside
        // the signed bytes differs.
        seed_accord_lifecycle(&backend, holder, accord_a).await;
        seed_accord_lifecycle(&backend, holder, accord_b).await;

        let own_accord_hash = locate_accord_hash(&bridge, accord_a, holder, "scores").await;
        let other_accord_hash = locate_accord_hash(&bridge, accord_b, holder, "scores").await;
        assert_ne!(
            own_accord_hash, other_accord_hash,
            "two distinct rows, differing only in the accord they name"
        );

        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            .with_accord_relay_gate(Some(Arc::new(AccordRelayGate::new(
                backend.clone(),
                Some(local.to_string()),
            ))));

        let offer = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;

        // ── THE ALLOW HALF — without it a refuse-everything gate would pass ──
        assert!(
            offer.iter().any(|r| r.envelope_hash == own_accord_hash),
            "the drill about the accord this holder IS seated on is ADVERTISED — the gate \
             is not simply refusing everything"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &own_accord_hash,
                    Some(peer)
                )
                .await
                .is_some(),
            "…and SERVED on the direct-fetch twin"
        );

        // ── THE DEFECT — the old gate carried this row ──────────────────────
        assert!(
            !offer.iter().any(|r| r.envelope_hash == other_accord_hash),
            "a drill belonging to accord B is NOT advertised: the object names B, this \
             holder holds no seat on B, and the fact that we trust B and that the holder \
             is seated on A is not a licence to carry it (CIRISPersist#731)"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(
                    EnvelopeKind::Attestation,
                    &other_accord_hash,
                    Some(peer)
                )
                .await
                .is_none(),
            "…and cannot be obtained by fetching a hash learned out-of-band either"
        );

        // The refusal NAMES the right leg: the roster resolved (B is a real
        // family here), so this is `signer_not_seated`, never `cannot judge`.
        let snap = metrics.snapshot();
        assert!(
            snap.withholds_by_reason
                .get(&WithholdReason::AccordRelaySignerNotSeated)
                .copied()
                .unwrap_or(0)
                >= 1,
            "booked `accord_relay_signer_not_seated`, got {:?}",
            snap.withholds_by_reason
        );
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::AccordRelayRosterUnresolvable)
                .copied()
                .unwrap_or(0),
            0,
            "…and NOT `roster_unresolvable` — B's roster resolved; the signer is simply \
             not on it"
        );
    }

    /// **THE REQUIRED CIRISPersist#733 PAIR, end to end.** A row's SIGNED
    /// `accord_root` key decides which roster judges it — and the answer is a
    /// row genuinely SERVED or genuinely WITHHELD, not merely a refusal reason.
    ///
    /// REWRITTEN from `an_accord_row_that_names_no_root_is_withheld_loudly`,
    /// whose premise persist deleted. That test seeded an
    /// `accord:human_dignity:v1` row carrying NO root and asserted the gate
    /// withheld it as `accord_relay_object_root_unnamed`. As of v37.0.0 such a
    /// row cannot exist in this node's store at all: `check_accord_root_binding`
    /// runs inside `check_reserved_prefix_admission`, which every backend's
    /// `put_attestation` and the promote door call, so an `accord:*` row that
    /// names no accord is REFUSED at admission. The fixture stopped seeding, and
    /// stamping a root into it would have turned it into the opposite assertion.
    ///
    /// The `Unnamed` leg is not lost — it moved to where it is still reachable.
    /// A relaying node handles rows it never admitted, and persist's own note is
    /// that the stored PRE-#733 corpus is what edge's enforcement flag covers, so
    /// the leg lives in `accord_relay_gate::tests` on rows constructed rather
    /// than seeded. What CAN be driven through the real store is the thing #733
    /// actually added, which is this:
    ///
    /// | row | expectation |
    /// |---|---|
    /// | `accord:human_dignity:v1`, `accord_root: A`, signer seated on A | **SERVED** |
    /// | the same, `accord_root: B`, same signer (seated only on A) | **WITHHELD** `accord_relay_signer_not_seated` |
    ///
    /// The node holds a real family for BOTH accords and a live
    /// `delegates_to(local → root)` to BOTH, so neither `roster_unresolvable` nor
    /// `no_trust_edge` can be doing the work: the ONLY difference between the two
    /// rows is the accord their signed bytes name. And `attested_key_id` is the
    /// SCORED AGENT in both, so nothing but the `accord_root` key could have
    /// answered — which is precisely the dimension shape the drill fallback
    /// cannot serve.
    #[tokio::test]
    // One coherent scenario: two accords seeded with edges and rosters, plus
    // both halves of the pair. Splitting it would put the ALLOW in a different
    // test from the REFUSAL, and it is the pair that carries the property.
    #[allow(clippy::too_many_lines)]
    async fn a_signed_accord_root_decides_which_roster_judges_the_row() {
        use crate::observability::WithholdReason;
        use crate::replication::accord_relay_gate::AccordRelayGate;
        use ciris_persist::federation::types::{Family, FamilyMember};

        let local = "this-node";
        let peer = "peer-consented";
        let accord_a = "accord-a-under-test";
        let accord_b = "accord-b-under-test";
        let holder = "accord-holder-on-a";
        let b_holder = "accord-holder-on-b";
        let scored = "some-scored-agent";
        let (backend, bridge, metrics) = make_metered_bridge(&[
            local.to_string(),
            peer.to_string(),
            accord_a.to_string(),
            accord_b.to_string(),
            scored.to_string(),
        ]);
        for (k, it) in [
            (local, identity_type::NODE),
            (peer, identity_type::AGENT),
            (accord_a, identity_type::NODE),
            (accord_b, identity_type::NODE),
            (scored, identity_type::AGENT),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        seed_accord_holder_key(&backend, holder).await;
        seed_accord_holder_key(&backend, b_holder).await;
        seed_consent_membership(&backend, local, peer).await;

        // Two REAL rosters: the signer is seated on A and only on A.
        let founded: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned founding instant");
        for (root, member) in [(accord_a, holder), (accord_b, b_holder)] {
            backend
                .put_family_local(Family {
                    family_key_id: root.to_owned(),
                    family_name: root.to_owned(),
                    members: vec![FamilyMember {
                        key_id: member.to_owned(),
                        joined_at: founded,
                        role: Some("founder".to_owned()),
                    }],
                    founded_at: founded,
                    consensus_protocol: "quorum:2/3".to_owned(),
                    consensus_protocol_entrenched: true,
                    persist_row_hash: String::new(),
                })
                .await
                .expect("seed the accord family");
        }
        // CC 4.2.1 — OUR consent edge to BOTH roots, so leg 2 holds either way
        // and cannot be what separates the two rows.
        for root in [accord_a, accord_b] {
            seed_delegates_to(
                &backend,
                local,
                root,
                &serde_json::json!(["infra:attest", "infra:serve"]),
            )
            .await;
        }

        // The pair. Same signer, same dimension, same scored subject — only the
        // SIGNED `accord_root` differs.
        seed_accord_scored(&backend, holder, scored, accord_a).await;
        seed_accord_scored(&backend, holder, scored, accord_b).await;

        let on_a = locate_accord_hash(&bridge, accord_a, holder, "scores").await;
        let on_b = locate_accord_hash(&bridge, accord_b, holder, "scores").await;
        assert_ne!(
            on_a, on_b,
            "the two rows are distinct on the wire — the `accord_root` key is inside the \
             signed envelope, so it changes the content hash"
        );
        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            .with_accord_relay_gate(Some(Arc::new(AccordRelayGate::new(
                backend.clone(),
                Some(local.to_string()),
            ))));

        let offer = bridge
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
            .await;

        // THE POSITIVE TWIN — the row names the accord its signer is seated on,
        // and this node granted that accord. persist's `may_relay` holds, so the
        // row is advertised AND served. Without this half the refusal below
        // could be satisfied by a gate that is simply dead (#435).
        assert!(
            offer.iter().any(|r| r.envelope_hash == on_a),
            "a row naming the accord its signer IS seated on is ADVERTISED"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &on_a, Some(peer))
                .await
                .is_some(),
            "…and SERVED on the direct-fetch twin"
        );

        // THE REFUSAL — the same signer, on a row naming accord B.
        assert!(
            !offer.iter().any(|r| r.envelope_hash == on_b),
            "a row naming accord B is judged on B's roster, where this signer holds no \
             seat — withheld from the offer"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &on_b, Some(peer))
                .await
                .is_none(),
            "…and cannot be obtained by fetching a hash learned out-of-band"
        );

        // And the LEDGER names the right leg. Both rosters resolved and both
        // edges are live, so `roster_unresolvable` and `no_trust_edge` would
        // each be a confident lie pointing an operator at state that is fine.
        let snap = metrics.snapshot();
        assert!(
            snap.withholds_by_reason
                .get(&WithholdReason::AccordRelaySignerNotSeated)
                .copied()
                .unwrap_or(0)
                >= 1,
            "booked `accord_relay_signer_not_seated`, got {:?}",
            snap.withholds_by_reason
        );
        for quiet in [
            WithholdReason::AccordRelayRosterUnresolvable,
            WithholdReason::AccordRelayNoTrustEdge,
            WithholdReason::AccordRelayObjectRootUnnamed,
            WithholdReason::AccordRelayObjectRootDisagrees,
            WithholdReason::AccordRelayMirrorUnbound,
            WithholdReason::AccordRelayObjectUnreadable,
            WithholdReason::AccordRelayObjectNotAccord,
        ] {
            assert_eq!(
                snap.withholds_by_reason.get(&quiet).copied().unwrap_or(0),
                0,
                "{} must stay silent — the row named its accord, the roster resolved, and \
                 our edge is live; the ONLY thing wrong is the seat",
                quiet.as_str()
            );
        }

        // Advertise and serve AGREE — nothing was offered then refused (#429).
        for r in &offer {
            assert!(
                bridge
                    .fetch_envelope_bytes_for_peer(
                        EnvelopeKind::Attestation,
                        &r.envelope_hash,
                        Some(peer)
                    )
                    .await
                    .is_some(),
                "advertise and serve AGREE"
            );
        }
    }

    /// Workstream F — with NO gate installed, `accord:*` carriage is byte-for-
    /// byte what it was before this workstream (the `Global` projection row
    /// alone). Installing the gate is a deliberate fleet-floor wiring event
    /// (the accord ROOT is an instance parameter a bridge cannot default
    /// itself into), and this pins that the absence is a wiring state rather
    /// than a silent policy change to every existing deployment.
    #[tokio::test]
    async fn without_a_gate_accord_carriage_is_unchanged() {
        let local = "this-node";
        let peer = "peer-consented";
        let root = "humanity-accord-under-test";
        let holder = "accord-holder-seated";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), peer.to_string(), root.to_string()]);
        for (k, it) in [
            (local, identity_type::NODE),
            (peer, identity_type::AGENT),
            (root, identity_type::NODE),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        seed_accord_holder_key(&backend, holder).await;
        seed_consent_membership(&backend, local, peer).await;
        // NO family, NO trust edge: an installed gate would refuse this row
        // outright ("cannot judge"). Without one, nothing consults the
        // predicate.
        seed_accord_lifecycle(&backend, holder, root).await;
        let hash = locate_accord_hash(&bridge, root, holder, "scores").await;
        let bridge = bridge.with_local_key_id(Some(local.to_string()));

        assert!(
            bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some(peer))
                .await
                .iter()
                .any(|r| r.envelope_hash == hash),
            "no gate installed ⇒ the projection row alone decides, as before"
        );
        assert!(
            metrics
                .snapshot()
                .withholds_by_reason
                .keys()
                .all(|r| !r.as_str().starts_with("accord_relay")),
            "…and the relay ledger stays silent — nothing was decided"
        );
    }

    /// Workstream F — the APPLY-PATH invalidation, driven through the bridge's
    /// real apply dispatch: an admitted `Family` row (the accord roster itself)
    /// drops the cached verdict for every signer under that root, so the very
    /// next serve decision re-resolves against the new roster instead of
    /// serving a grant the roster no longer supports. The TTL is the backstop;
    /// this is the event that must not wait for it.
    #[tokio::test]
    // One invalidation lifecycle: seed + prime + the REFUSED apply that must
    // not invalidate + the real roster change that must. Splitting it would
    // separate "a refused apply changes nothing" from the admitted apply it is
    // the control for, and the pair is what carries the property.
    #[allow(clippy::too_many_lines)]
    async fn an_admitted_family_apply_invalidates_the_cached_relay_verdict() {
        use crate::replication::accord_relay_gate::{
            AccordRelayGate, AccordRelaySubject, RelayDecision, RelayRefusal,
        };
        use ciris_persist::federation::types::{Family, FamilyMember};

        let local = "this-node";
        let root = "humanity-accord-under-test";
        let holder = "accord-holder-seated";
        let (backend, bridge) = make_bridge(&[local.to_string(), root.to_string()]);
        for (k, it) in [(local, identity_type::NODE), (root, identity_type::NODE)] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        // A family member must be a registered federation_keys row.
        seed_accord_holder_key(&backend, holder).await;
        let gate = Arc::new(AccordRelayGate::new(
            backend.clone(),
            Some(local.to_string()),
        ));
        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            .with_accord_relay_gate(Some(Arc::clone(&gate)));

        // CIRISPersist#733 — prime with a REAL ROW, seeded through persist's own
        // write door and read back out of the store. The gate keys the verdict
        // on the (root, signer) pair persist reads off that row, so the subject
        // below is an EXPECTATION rather than an input: nothing here nominates
        // a root, and a fixture the door would refuse could not stand in for a
        // row the field produces.
        seed_accord_lifecycle(&backend, holder, root).await;
        let row = backend
            .list_attestations_since(None, 100)
            .await
            .expect("list the seeded rows")
            .into_iter()
            .map(|s| s.attestation)
            .find(|a| a.attesting_key_id == holder)
            .expect("the seeded accord drill row");
        let subject = AccordRelaySubject {
            root_ref: root.to_owned(),
            signer_key_id: holder.to_owned(),
        };
        // Prime a verdict: with no family seeded this is `cannot judge`, which
        // is a RESOLVED verdict — distinct from "we never ran".
        let t0 = std::time::Instant::now();
        assert_eq!(
            gate.prime(&row, t0).await,
            Ok(subject.clone()),
            "the verdict is filed under the pair persist read off the seeded row"
        );
        assert_eq!(
            gate.decide(&subject, t0),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "the sync predicate serves the cached verdict"
        );

        // An unsigned Family apply is REFUSED by persist's E4 gate, so it must
        // NOT invalidate: a refused apply changed no state.
        let founded: chrono::DateTime<chrono::Utc> = "2020-01-01T00:00:00Z"
            .parse()
            .expect("pinned founding instant");
        let family = Family {
            family_key_id: root.to_owned(),
            family_name: root.to_owned(),
            members: vec![FamilyMember {
                key_id: holder.to_owned(),
                joined_at: founded,
                role: Some("founder".to_owned()),
            }],
            founded_at: founded,
            consensus_protocol: "quorum:2/3".to_owned(),
            consensus_protocol_entrenched: true,
            persist_row_hash: String::new(),
        };
        let unsigned = serde_json::to_vec(&SignedFamily {
            family: family.clone(),
            authority_key_id: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
        })
        .expect("serialize unsigned family");
        let refused = bridge
            .apply_envelope_bytes(EnvelopeKind::Family, &unsigned, Some("peer"))
            .await;
        assert!(
            !refused.is_admitted(),
            "an unsigned family declaration is refused at admission (persist E4)"
        );
        assert_eq!(
            gate.decide(&subject, t0),
            RelayDecision::Refused(RelayRefusal::RosterUnresolvable),
            "a REFUSED apply changed no state, so it must not drop the verdict"
        );

        // The real roster change (through persist's local door, then the
        // invalidation the apply path fires) is what must be visible at once.
        backend
            .put_family_local(family)
            .await
            .expect("seed the accord family");
        bridge.invalidate_accord_relay(&[root]);
        assert_eq!(
            gate.decide(&subject, t0),
            RelayDecision::Refused(RelayRefusal::Unresolved),
            "post-invalidation the gate reports `unresolved` — it no longer knows, and \
             says so rather than serving the dropped verdict"
        );
        // …and re-resolving now sees the roster: the signer IS seated (only our
        // consent edge is still missing), which proves the drop was real and
        // not merely a stale repeat.
        gate.prime(&row, t0).await.expect("judgeable");
        assert_eq!(
            gate.decide(&subject, t0),
            RelayDecision::Refused(RelayRefusal::NoTrustEdge),
            "the re-resolve reads the NEW roster — `cannot judge` became `seated, \
             but this node never granted the root`"
        );
    }

    /// CIRISEdge#433 / #396 item 1 — a peer absent from the live consent send-set
    /// books `RecipientNotInSendSet`, driven through the REAL advertise path (the
    /// `consent_membership_fan_out_bound` scenario, now with a ledger on it).
    #[tokio::test]
    async fn recipient_not_in_send_set_is_booked_at_the_branch() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer_in = "peer-consented";
        let peer_out = "peer-unconsented";
        let (backend, bridge, metrics) = make_metered_bridge(&[
            local.to_string(),
            producer.to_string(),
            peer_in.to_string(),
            peer_out.to_string(),
        ]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        for key_id in [local, producer, peer_in, peer_out] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_advertised_attestation(&backend, producer).await;
        seed_consent_membership(&backend, local, peer_in).await;

        // The consent-INCLUDED peer serves cleanly — no withhold.
        assert!(!bridge
            .list_attestations_for_peer(Some(peer_in))
            .await
            .is_empty());
        assert!(
            metrics.snapshot().withholds_by_reason.is_empty(),
            "the consented peer's plane is not a withhold"
        );

        // The consent-EXCLUDED peer loses the WHOLE plane — and it is counted.
        assert!(bridge
            .list_attestations_for_peer(Some(peer_out))
            .await
            .is_empty());
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::RecipientNotInSendSet)
                .copied()
                .unwrap_or(0),
            1,
            "the item-1 bound books ONE plane-wide withhold, got {:?}",
            snap.withholds_by_reason
        );
        // The reason is the BRANCH: no other reason fired.
        assert_eq!(
            snap.withholds_by_reason.len(),
            1,
            "exactly one reason, not a disjunction: {:?}",
            snap.withholds_by_reason
        );
        let recent = &snap.recent_withholds;
        assert_eq!(recent.last().expect("a recent entry").peer_key_id, peer_out);
    }

    /// CIRISEdge#433 — a bridge with no `local_key_id` cannot resolve the consent
    /// send-set, so it fail-closes; that is a WIRING fault, and the ledger says so
    /// (`LocalIdentityMissing`) rather than blaming the peer's consent. Driven
    /// through the real advertise path (`fan_out_fail_closed_without_local_key_id`).
    #[tokio::test]
    async fn missing_local_identity_is_booked_as_a_wiring_fault_not_a_consent_verdict() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        // NOTE: deliberately NO `with_local_key_id` — the field condition.
        seed_serve_scaffold(&backend, local, producer, peer).await;
        seed_advertised_attestation(&backend, producer).await;

        assert!(
            bridge
                .list_attestations_for_peer(Some(peer))
                .await
                .is_empty(),
            "no local_key_id → the whole plane is withheld (fail-closed)"
        );
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::LocalIdentityMissing)
                .copied()
                .unwrap_or(0),
            1
        );
        assert!(
            !snap
                .withholds_by_reason
                .contains_key(&WithholdReason::RecipientNotInSendSet),
            "a wiring fault must NOT be reported as 'the peer is unconsented' — \
             that sends the operator looking in the wrong place"
        );
    }

    /// CIRISEdge#433 / #396 item 6 — a producer-declared `recipient_capability`
    /// the recipient lacks books `RecipientCapabilityRestriction`, and the ring
    /// records the offending DIMENSION. Driven through the real gate with the
    /// canonical value the advertise sweep feeds it.
    #[tokio::test]
    async fn recipient_capability_restriction_is_booked_with_its_dimension() {
        use crate::observability::WithholdReason;
        let producer = "agent-producer";
        let recipient = "peer-no-capability";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[producer.to_string(), recipient.to_string()]);
        for key_id in [producer, recipient] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let trace_json = trace_row_json(producer);

        // No grant → no restriction → SERVE, and nothing is booked.
        assert!(
            !bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await
        );
        assert!(metrics.snapshot().withholds_by_reason.is_empty());

        // A covering grant naming a capability the recipient lacks → WITHHOLD.
        seed_consent_grant(&backend, producer, recipient, "trace:", "trace:read").await;
        assert!(
            bridge
                .recipient_capability_withholds(&trace_json, recipient, &mut HashMap::new())
                .await
        );
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::RecipientCapabilityRestriction)
                .copied()
                .unwrap_or(0),
            1
        );
        let last = snap.recent_withholds.last().expect("a recent entry");
        assert_eq!(last.peer_key_id, recipient);
        assert_eq!(
            last.detail, "trace:complete:v1",
            "the ring attributes the offending dimension, not the whole envelope"
        );
    }

    /// CIRISEdge#433 / #429 — a hash the requester asks for that local state
    /// cannot resolve books `EnvelopeUnfetchable`, kept DISJOINT from every
    /// policy gate. This is the bridge-level origin of the
    /// advertised-then-unfetchable event `session::pack_bounded_deliver` reports
    /// in its `dropped` set: "we could not find it" must never hide inside "we
    /// chose not to serve it".
    #[tokio::test]
    async fn an_unfetchable_hash_is_booked_separately_from_every_policy_gate() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let peer = "peer-consented";
        let (backend, bridge, metrics) =
            make_metered_bridge(&[local.to_string(), producer.to_string(), peer.to_string()]);
        let bridge = bridge.with_local_key_id(Some(local.to_string()));
        seed_serve_scaffold(&backend, local, producer, peer).await;

        // A hash that was never seeded — the #429 field condition (stale
        // wire-index / pruned row / hash skew).
        let missing = [0x5au8; 32];
        assert!(bridge
            .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &missing, Some(peer))
            .await
            .is_none());
        let snap = metrics.snapshot();
        assert_eq!(
            snap.withholds_by_reason
                .get(&WithholdReason::EnvelopeUnfetchable)
                .copied()
                .unwrap_or(0),
            1
        );
        assert_eq!(
            snap.withholds_by_reason.len(),
            1,
            "an unfetchable row is NOT a consent / capability verdict: {:?}",
            snap.withholds_by_reason
        );
        assert_eq!(
            snap.recent_withholds.last().expect("a recent entry").detail,
            format!("attestation:{}", hex::encode(&missing[..8])),
            "the ring carries kind + hash prefix, joinable with the #379 log line"
        );
    }

    /// CIRISEdge#352 — seed the five-row projection matrix for the pin test
    /// below and return the ids in seeding order:
    ///
    /// 1. federation-scoped scores by OTHER → Cohort/Global      → IN
    /// 2. affiliations-scoped scores by OTHER → Cohort           → IN
    /// 3. self-scoped scores by NODE (publish-own)               → IN
    /// 4. self-scoped scores by OTHER (foreign producer — the
    ///    structural-invisibility case)                          → OUT
    /// 5. self-scoped withdraws by OTHER tombstoning row 4:
    ///    anti-rollback overrides the scope → Global             → IN
    ///
    /// Dimension is `identity:example:v1` throughout (self-attesting one's
    /// own identity passes admission; the dimension is deliberately
    /// projection-irrelevant — `authority_for` only picks Global-vs-Cohort,
    /// both advertised).
    async fn seed_projection_matrix(
        backend: &MemoryBackend,
        node: &str,
        other: &str,
    ) -> [&'static str; 5] {
        let identity_scores = |id: &str, attester: &str| {
            serde_json::json!({
                "id": id,
                "attesting_key_id": attester,
                "attested_key_id": attester,
                "attestation_type": "scores",
                "dimension": "identity:example:v1",
            })
        };
        let in_fed = "att-352-in-federation";
        seed_scoped_attestation(
            backend,
            in_fed,
            other,
            other,
            "scores",
            "federation",
            identity_scores(in_fed, other),
        )
        .await;
        let in_affil = "att-352-in-affiliations";
        seed_scoped_attestation(
            backend,
            in_affil,
            other,
            other,
            "scores",
            "affiliations",
            identity_scores(in_affil, other),
        )
        .await;
        let in_self_own = "att-352-in-self-own";
        seed_scoped_attestation(
            backend,
            in_self_own,
            node,
            node,
            "scores",
            "self",
            identity_scores(in_self_own, node),
        )
        .await;
        let out_self_foreign = "att-352-out-self-foreign";
        seed_scoped_attestation(
            backend,
            out_self_foreign,
            other,
            other,
            "scores",
            "self",
            identity_scores(out_self_foreign, other),
        )
        .await;
        let in_tombstone = "att-352-in-tombstone";
        seed_scoped_attestation(
            backend,
            in_tombstone,
            other,
            other,
            "withdraws",
            "self",
            serde_json::json!({
                "id": in_tombstone,
                "attesting_key_id": other,
                "attested_key_id": other,
                "attestation_type": "withdraws",
                "references_attestation_id": out_self_foreign,
                "withdrawal_reason": "test: producer withdraws its own self-scoped edge",
            }),
        )
        .await;
        [
            in_fed,
            in_affil,
            in_self_own,
            out_self_foreign,
            in_tombstone,
        ]
    }

    /// CIRISEdge#352 — the advertise-projection pushdown verdict, pinned as
    /// an equivalence test over a seeded directory.
    ///
    /// The projection stays edge-side on the pinned persist (v24.2.0) — see
    /// the verdict block on
    /// [`FederationDirectoryReplicationBridge::attestation_is_advertised`] —
    /// so this test is the byte-identity pin any future pushdown must keep
    /// green: over a directory holding rows on BOTH sides of the projection,
    /// the advertised `(hash, seq)` set must equal the exact expected set
    /// derived from the seeded state. The IN/OUT verdict per row is
    /// HARD-CODED from the CC replication contract (persist
    /// `namespace::projection_for`), never computed by re-running the filter
    /// under test; the hashes come from the rows persist actually holds
    /// (the store stamps server-side fields — `persist_row_hash`,
    /// `withdraws_admission_rule` — that the content-hash covers).
    ///
    /// The #433 ledger boundary rides the same state: the projection DEFINES
    /// eligibility, so a row it excludes was never eligible and the sweep
    /// books NOTHING for it — while the row still appears in the RAW
    /// holdings view, proving its absence from the advertise set is the
    /// projection, not admission or serialization.
    #[tokio::test]
    async fn advertise_projection_boundary_and_ledger_are_pinned() {
        let node = "this-node";
        let other = "other-producer";
        let cohort = [node.to_string(), other.to_string()];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        // The node's OWN publish set — the SelfOwn axis of the projection.
        let publish_set = vec![node.to_string()];
        let selector: CohortProvider = Arc::new(move || publish_set.clone());
        let bridge = bridge.with_self_provider(Some(selector));
        for key_id in [node, other] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(key_id, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        let [in_fed, in_affil, in_self_own, out_self_foreign, in_tombstone] =
            seed_projection_matrix(&backend, node, other).await;

        // Derive the EXPECTED set from the state persist actually holds,
        // keyed by the hard-coded verdicts above.
        let held = backend
            .list_attestations_since(None, 100)
            .await
            .expect("read back seeded rows");
        assert_eq!(
            held.len(),
            5,
            "all five rows were ADMITTED — the OUT verdict below is the projection, not admission"
        );
        let expected_in = [in_fed, in_affil, in_self_own, in_tombstone];
        let expected: std::collections::BTreeSet<([u8; 32], u64)> = held
            .iter()
            .filter(|row| expected_in.contains(&row.attestation.attestation_id.as_str()))
            .map(|row| {
                let (hash, _bytes) = content_hash_of(&row.attestation).expect("held row hashes");
                (
                    hash,
                    FederationDirectoryReplicationBridge::ms_seq(row.admitted_at),
                )
            })
            .collect();
        assert_eq!(expected.len(), 4);
        let out_hash = held
            .iter()
            .find(|row| row.attestation.attestation_id == out_self_foreign)
            .map(|row| {
                content_hash_of(&row.attestation)
                    .expect("held row hashes")
                    .0
            })
            .expect("the OUT row is held");

        // Equivalence: the advertise view (the exact entry the round's
        // `list_envelope_refs` dispatches; `None` recipient = projection-only)
        // equals the expected (hash, seq) set — nothing more, nothing less.
        let advertised = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        let advertised_set: std::collections::BTreeSet<([u8; 32], u64)> = advertised
            .iter()
            .map(|r| (r.envelope_hash, r.seq))
            .collect();
        assert_eq!(advertised.len(), advertised_set.len(), "no duplicate refs");
        assert_eq!(
            advertised_set, expected,
            "the advertised (hash, seq) set is exactly the projection's expected set"
        );

        // The RAW holdings view (receive axis, #416) still carries the OUT
        // row: its absence above is the PROJECTION at work.
        let holdings = bridge.list_holdings(EnvelopeKind::Attestation).await;
        assert!(
            holdings.iter().any(|r| r.envelope_hash == out_hash),
            "the out-of-projection row IS held (receive axis)"
        );
        assert_eq!(holdings.len(), 5, "holdings carry every admitted row");

        // #433 boundary: the projection DEFINES eligibility. A row it
        // excludes was never eligible, so the sweep books NOTHING — not
        // `RowNotSerializable`, not `RowHashUndecodable`, not anything.
        let snap = metrics.snapshot();
        assert!(
            snap.withholds_by_reason.is_empty(),
            "a by-design projection non-event books no withhold, got {:?}",
            snap.withholds_by_reason
        );
    }

    // ── CIRISEdge#440 — mesh-config consumption + quarantine-aware offers ──

    /// Seed the mesh-config plane's trust scaffolding for `node`: the root's
    /// key record + the node's `delegates_to(node → root)` subscription edge
    /// ("the trust edge is the subscription", persist's `trusted_roots_of`).
    async fn seed_mesh_config_root(backend: &MemoryBackend, node: &str, root: &str) {
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(root, identity_type::NODE),
            })
            .await
            .expect("seed mesh-config root key");
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "attesting_key_id": node,
            "attested_key_id": root,
            "attestation_type": "delegates_to",
            // Infra duty scopes only — the reject-agency-on-node-key gate
            // (persist #236) refuses agency conferrals on node-typed keys.
            "scope": ["infra:attest", "infra:serve"],
        });
        seed_raw_attestation(backend, &id, node, root, "delegates_to", envelope).await;
    }

    /// Seed one root-authored mesh-config relief row through the REAL
    /// replication-plane admission (`put_attestation` — the door edge's own
    /// `apply_attestation` uses; persist: "the read-time clamp in
    /// `fold_mesh_config` is what holds for rows that arrive on the
    /// replication plane"). Built with persist's own `mesh_config_envelope`
    /// so the shape cannot drift from the fold's `parse_row`.
    async fn seed_mesh_config_relief(
        backend: &MemoryBackend,
        root: &str,
        key: ciris_persist::federation::MeshConfigKey,
        value: i64,
    ) {
        let envelope = ciris_persist::federation::mesh_config::mesh_config_envelope(
            key,
            value,
            root,
            ciris_persist::federation::MeshConfigForm::Emergency,
            Some(Utc::now() + chrono::Duration::hours(1)),
            "delegation-test-1",
            None,
            "test congestion relief",
        );
        let id = uuid::Uuid::new_v4().to_string();
        seed_raw_attestation(backend, &id, root, root, "scores", envelope).await;
    }

    /// A `MeshConfigReader` over the SAME backend the bridge reads, resolving
    /// for `node` with the production default baseline shape and TTL zero
    /// (every consult re-folds, so a just-seeded row is visible immediately).
    fn mesh_reader_over(
        backend: &Arc<MemoryBackend>,
        node: &str,
    ) -> Arc<crate::replication::mesh_config::MeshConfigReader> {
        let dir: Arc<dyn FederationDirectory> = Arc::clone(backend) as _;
        Arc::new(
            crate::replication::mesh_config::MeshConfigReader::new(
                dir,
                node.to_string(),
                crate::replication::mesh_config::MeshConfigReader::baseline_for(
                    std::time::Duration::from_secs(30),
                    BridgeConfig::DEFAULT_OPERATIONAL_PAGE_LIMIT,
                ),
            )
            .with_ttl(std::time::Duration::ZERO),
        )
    }

    /// ABSENCE — a bridge with a reader over an EMPTY mesh-config plane
    /// advertises and serves byte-identically to a bridge with no reader at
    /// all: same refs, same bytes, per plane. This is the "config is RELIEF,
    /// not a gate" contract as an executable statement.
    #[tokio::test]
    async fn empty_mesh_config_plane_is_byte_identical_to_no_reader() {
        let local = "this-node";
        let producer = "agent-producer";
        let cohort = [local.to_string(), producer.to_string()];
        let (backend, plain_bridge) = make_bridge(&cohort);
        seed_serve_scaffold(&backend, local, producer, "peer-consented").await;
        seed_trace_attestation(&backend, producer).await;
        // The mesh-config trust scaffolding EXISTS (root subscribed) but the
        // plane carries no relief rows — the fold resolves everything to
        // baseline.
        seed_mesh_config_root(&backend, local, "mc-root").await;

        let dir: Arc<dyn FederationDirectory> = Arc::clone(&backend) as _;
        let cohort_vec = cohort.to_vec();
        let cohort_cb: CohortProvider = Arc::new(move || cohort_vec.clone());
        let read_bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb)
            .with_mesh_config(Some(mesh_reader_over(&backend, local)));

        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::Attestation,
            EnvelopeKind::Revocation,
        ] {
            let mut plain = plain_bridge.list_envelope_refs(kind).await;
            let mut read = read_bridge.list_envelope_refs(kind).await;
            plain.sort_by_key(|r| r.envelope_hash);
            read.sort_by_key(|r| r.envelope_hash);
            assert_eq!(
                plain, read,
                "{kind:?}: an empty plane must not change the advertise set"
            );
            for r in &plain {
                let a = plain_bridge
                    .fetch_envelope_bytes(kind, &r.envelope_hash)
                    .await;
                let b = read_bridge
                    .fetch_envelope_bytes(kind, &r.envelope_hash)
                    .await;
                assert_eq!(a, b, "{kind:?}: byte-identical serve under an empty plane");
            }
        }
    }

    /// FIELD PROVENANCE, end to end — a root-authored
    /// `feature.trace_replication=0` relief row admitted through the real
    /// replication-plane door pauses the trace plane: the advertise sweep
    /// withholds the `trace:*` row (non-trace rows untouched), the
    /// direct-fetch twin refuses the hash, and BOTH book
    /// `WithholdReason::ConfigPaused` — the #433 rule: a named branch, never
    /// silence.
    #[tokio::test]
    async fn trace_replication_pause_withholds_trace_rows_and_books_config_paused() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let producer = "agent-producer";
        let cohort = [local.to_string(), producer.to_string()];
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        seed_serve_scaffold(&backend, local, producer, "peer-consented").await;
        seed_trace_attestation(&backend, producer).await;
        seed_mesh_config_root(&backend, local, "mc-root").await;

        // Locate the trace hash while the plane is un-paused (reader wired,
        // no relief row yet — also proves the reader alone changes nothing).
        let bridge = bridge.with_mesh_config(Some(mesh_reader_over(&backend, local)));
        let trace_hash = locate_trace_hash(&bridge).await;
        let before = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            before.iter().any(|r| r.envelope_hash == trace_hash),
            "un-paused: the trace row advertises"
        );

        // The relief row, through the real door.
        seed_mesh_config_relief(
            &backend,
            "mc-root",
            ciris_persist::federation::MeshConfigKey::FeatureTraceReplication,
            0,
        )
        .await;

        let after = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            !after.iter().any(|r| r.envelope_hash == trace_hash),
            "paused: the trace row is withheld from the advertise"
        );
        assert!(
            !after.is_empty(),
            "paused: NON-trace rows (consent grant, trust edges, the relief \
             row itself) still advertise — the pause is trace-scoped"
        );
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &trace_hash, None)
                .await
                .is_none(),
            "paused: the direct-fetch twin refuses the trace hash"
        );
        assert!(
            metrics.withholds(WithholdReason::ConfigPaused) >= 2,
            "the pause books config_paused on BOTH exits (sweep + fetch twin)"
        );
    }

    /// FIELD PROVENANCE, end to end — a root-authored
    /// `antientropy.page_limit` relief bounds the bridge's since-page: the Key
    /// plane's ADVERTISE shrinks to the relieved limit.
    ///
    /// CIRISEdge#531 DEPTH sharpened both halves of this, and the second half
    /// was a latent bug:
    ///
    ///  1. the relief is asserted on the PEER-BOUND advertise — the actual
    ///     offer, and the only path production takes
    ///     (`DirectoryStateAdapter::with_peer`). It is one page per ROUND now,
    ///     not one page forever: the peer's watermark carries the rest;
    ///  2. the RECEIVE-axis holdings view is asserted NOT to shrink. #440's own
    ///     note says relief "bounds what we OFFER and SERVE, never what we admit
    ///     knowing about ourselves", and gave four planes an unfiltered holdings
    ///     twin at the raw limit — but the other nine fell through to the
    ///     advertise builder, so a congestion relief WAS shrinking their
    ///     holdings, making the node re-want rows it already holds: more wire
    ///     traffic under a relief, the exact inversion of the knob. Routing
    ///     holdings through `SweepWindow::Full` fixes it for every plane at once.
    #[tokio::test]
    async fn page_limit_relief_bounds_the_since_page() {
        let local = "this-node";
        let producers = ["key-a", "key-b", "key-c"];
        let cohort: Vec<String> = std::iter::once(local.to_string())
            .chain(producers.iter().map(|s| (*s).to_string()))
            .collect();
        let (backend, bridge) = make_bridge(&cohort);
        backend
            .put_public_key(SignedKeyRecord {
                record: fixture_key_record(local, identity_type::NODE),
            })
            .await
            .expect("seed local key");
        for p in producers {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(p, identity_type::AGENT),
                })
                .await
                .expect("seed key");
        }
        seed_mesh_config_root(&backend, local, "mc-root").await;
        let bridge = bridge.with_mesh_config(Some(mesh_reader_over(&backend, local)));

        assert_eq!(
            bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-x"))
                .await
                .len(),
            4,
            "no relief: the full page (local + the three producers; mc-root is \
             outside the cohort projection)"
        );
        let holdings_unrelieved = bridge.list_holdings(EnvelopeKind::Key).await.len();

        seed_mesh_config_relief(
            &backend,
            "mc-root",
            ciris_persist::federation::MeshConfigKey::AntientropyPageLimit,
            2,
        )
        .await;
        assert_eq!(
            bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-y"))
                .await
                .len(),
            2,
            "relieved: the OFFER is bounded to the relieved limit (a fresh peer, \
             so this is its first page; its watermark carries the rest)"
        );
        assert_eq!(
            bridge.list_holdings(EnvelopeKind::Key).await.len(),
            holdings_unrelieved,
            "relieved: the RECEIVE-axis holdings view is UNCHANGED — relief bounds \
             what we offer, never what we know we hold, or the node re-wants rows \
             it already has under a congestion relief (CIRISEdge#440/#531)"
        );
    }

    /// CIRISEdge#440 ask 3 — quarantine-aware offers, end to end against
    /// persist's REAL marker fold:
    ///   (1) a `quarantine:withheld:v1` marker about author A withholds A's
    ///       rows from the ADVERTISE while B's still flow,
    ///   (2) the ledger books `quarantined_author` (named, never silent),
    ///   (3) A's rows are KEPT LOCALLY — the raw holdings view still carries
    ///       them (tier 2: withhold-from-serving, rows retained),
    ///   (4) the direct-fetch twin refuses A's hash,
    ///   (5) the MARKER ROW ITSELF still advertises (the convergence
    ///       carve-out: a quarantine that stopped replicating could not be
    ///       folded, and a release that stopped replicating would make a
    ///       reversible control irreversible),
    ///   (6) a `quarantine:released:v1` marker LIFTS the withhold — reversible,
    ///       exactly the fediverse-silence / Tor-flag precedent the issue
    ///       names.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // the six-property scenario is one coherent story
    async fn quarantined_author_rows_withheld_from_offer_kept_locally_and_reversible() {
        use crate::observability::WithholdReason;
        let local = "this-node";
        let author_a = "author-quarantined";
        let author_b = "author-clear";
        let moderator = "quarantine-authority";
        let cohort = [
            local.to_string(),
            author_a.to_string(),
            author_b.to_string(),
        ];
        let commons = "mod-commons";
        let (backend, bridge, metrics) = make_metered_bridge(&cohort);
        // The moderator is USER-typed (steward-bound clause 1) — the slash
        // gate persist runs on EVERY quarantine marker put (`put_attestation`
        // → `check_delegated_duty_scores_admission`) resolves duty-holders
        // from the marker's community's steward-bound authority set, so the
        // marker below is admitted under the REAL authority walk, not waved in.
        for (k, it) in [
            (local, identity_type::NODE),
            (author_a, identity_type::AGENT),
            (author_b, identity_type::AGENT),
            (moderator, identity_type::USER),
            (commons, identity_type::USER),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fixture_key_record(k, it),
                })
                .await
                .expect("seed key");
        }
        // The community whose authority set holds the `slash` duty: the
        // moderator is its founder.
        backend
            .put_community(sign_community_fixture(
                moderator,
                Community {
                    community_key_id: commons.to_string(),
                    community_name: "quarantine test commons".to_string(),
                    members: vec![CommunityMember {
                        key_id: moderator.to_string(),
                        joined_at: Utc::now(),
                        role: Some("founder".to_string()),
                    }],
                    founded_at: Utc::now(),
                    consensus_protocol: "majority".to_string(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("seed moderation commons");
        // One ordinary scores row per author (an open-vocabulary dimension —
        // Cohort projection, so both advertise peer-blind).
        for author in [author_a, author_b] {
            let id = uuid::Uuid::new_v4().to_string();
            let envelope = serde_json::json!({
                "id": id,
                "attesting_key_id": author,
                "attested_key_id": author,
                "attestation_type": "scores",
                "dimension": "credits:test:v1",
                "score": 1.0,
            });
            seed_raw_attestation(&backend, &id, author, author, "scores", envelope).await;
        }
        // Map advertised hash → author while nothing is withheld.
        let mut hash_of: HashMap<String, [u8; 32]> = HashMap::new();
        for r in bridge.list_envelope_refs(EnvelopeKind::Attestation).await {
            let bytes = bridge
                .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                .await
                .expect("fetch advertised row");
            let v: serde_json::Value = serde_json::from_slice(&bytes).expect("wire json");
            if v.pointer("/attestation_envelope/dimension")
                .and_then(|d| d.as_str())
                == Some("credits:test:v1")
            {
                let author = v["attesting_key_id"].as_str().expect("author").to_string();
                hash_of.insert(author, r.envelope_hash);
            }
        }
        let a_hash = hash_of[author_a];
        let b_hash = hash_of[author_b];

        // The withhold marker, via persist's own envelope builder + the real
        // replication-plane door.
        let marker_id = uuid::Uuid::new_v4().to_string();
        let marker_env = ciris_persist::federation::quarantine::withhold_envelope(
            author_a,
            commons,
            "delegation-test-1",
            "test: withhold-from-serving",
        );
        seed_raw_attestation(
            &backend, &marker_id, moderator, author_a, "scores", marker_env,
        )
        .await;

        // (1) + (5): A withheld, B flows, the marker itself advertises.
        let offer = bridge.list_envelope_refs(EnvelopeKind::Attestation).await;
        assert!(
            !offer.iter().any(|r| r.envelope_hash == a_hash),
            "(1) the quarantined author's row is withheld from the offer"
        );
        assert!(
            offer.iter().any(|r| r.envelope_hash == b_hash),
            "(1) the clear author's row still flows"
        );
        let marker_advertised = {
            let mut found = false;
            for r in &offer {
                if let Some(bytes) = bridge
                    .fetch_envelope_bytes(EnvelopeKind::Attestation, &r.envelope_hash)
                    .await
                {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        if v.pointer("/attestation_envelope/dimension")
                            .and_then(|d| d.as_str())
                            == Some("quarantine:withheld:v1")
                        {
                            found = true;
                        }
                    }
                }
            }
            found
        };
        assert!(marker_advertised, "(5) the marker plane is never withheld");
        // (2) named, never silent.
        assert!(
            metrics.withholds(WithholdReason::QuarantinedAuthor) >= 1,
            "(2) the ledger books quarantined_author"
        );
        // (3) rows retained: the raw holdings (receive axis) still carry A.
        assert!(
            bridge
                .list_holdings(EnvelopeKind::Attestation)
                .await
                .iter()
                .any(|r| r.envelope_hash == a_hash),
            "(3) tier 2 retains the row locally"
        );
        // (4) the direct-fetch twin refuses A's hash.
        assert!(
            bridge
                .fetch_envelope_bytes_for_peer(EnvelopeKind::Attestation, &a_hash, None)
                .await
                .is_none(),
            "(4) the fetch twin withholds too — no out-of-band bypass"
        );

        // (6) REVERSIBLE: a release marker lifts the withhold.
        let release_id = uuid::Uuid::new_v4().to_string();
        let release_env = ciris_persist::federation::quarantine::release_envelope(
            author_a,
            commons,
            &marker_id,
            "delegation-test-1",
            "test: released",
        );
        seed_raw_attestation(
            &backend,
            &release_id,
            moderator,
            author_a,
            "scores",
            release_env,
        )
        .await;
        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Attestation)
                .await
                .iter()
                .any(|r| r.envelope_hash == a_hash),
            "(6) a release marker lifts the withhold — the control is reversible"
        );
    }

    // ─── CIRISEdge#523 — the person/node identity axis on the SERVE side ───
    //
    // The measurement (CIRISServer's two-node chat ladder, release-read run):
    // the recipient held 0 `federation_communities` rows for a room the sender
    // created, while 7 sender-authored attestation rows landed on the SAME link
    // in the SAME rounds. Mechanism: the three Cohort-scoped planes test roster
    // membership against a NODE-keyed cohort, and Community/Family rosters name
    // PERSONS — an empty intersection by construction.
    //
    // Every fixture below is field-provenance-exact: the roster names a `user`
    // key, the cohort holds a `node` key, and the two are joined by a live
    // CC 1.13.3.3 owner-binding built from persist's OWN dimension constant.

    /// Seed a live owner-binding `delegates_to(owner → node)` — the exact edge
    /// `owner_of` resolves. The dimension + purpose come from persist's own
    /// `owner_binding` module, never a local string literal: an invented
    /// dimension would make every test below green against a predicate the
    /// field does not run.
    fn owner_binding_envelope(id: &str, owner: &str, node: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "attesting_key_id": owner,
            "attested_key_id": node,
            "attestation_type": "delegates_to",
            // CC 4.4.3.4.3 — a `node`-role delegate may carry ONLY `infra:*`.
            "scope": ["infra:network_presence"],
            "dimension": ciris_persist::federation::types::owner_binding::DIMENSION,
            "delegation_purpose": ciris_persist::federation::types::owner_binding::PURPOSE,
        })
    }

    async fn seed_owner_binding(backend: &MemoryBackend, owner: &str, node: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = owner_binding_envelope(&id, owner, node);
        seed_raw_attestation(backend, &id, owner, node, "delegates_to", envelope).await;
        id
    }

    /// The #523 fixture in one place: a PERSON (`user`), a NODE (`node`) owned
    /// by that person, and an unrelated node owned by nobody. Returns a backend
    /// whose keys are registered and (when `bind`) whose owner-binding is live.
    async fn owner_axis_backend(bind: bool) -> Arc<MemoryBackend> {
        let backend = Arc::new(MemoryBackend::new());
        register_fixture_keys(
            &backend,
            &[
                ("person-alice", identity_type::USER),
                ("person-bob", identity_type::USER),
                ("node-bob", identity_type::NODE),
                ("node-stranger", identity_type::NODE),
                ("room-authority", identity_type::AGENT),
                ("chat-room", identity_type::AGENT),
                ("household", identity_type::AGENT),
            ],
        )
        .await;
        if bind {
            seed_owner_binding(&backend, "person-bob", "node-bob").await;
        }
        backend
    }

    /// v18.5.0 — [`fixture_community`] with a **seated moderator**.
    ///
    /// `check_no_moderator_federate_apply` (CC 4.5.4 / §11.11) re-checks live
    /// `moderate`-holder existence on every federation apply step keyed on a
    /// community this node KNOWS, and refuses when none resolves. A roster
    /// whose member holds persist's own [`MEMBER_ROLE_FOUNDER`] is a zero-hop
    /// named moderator provided that member is steward-bound — and a `user`
    /// key self-anchors (clause 1 of `steward_bindings_of`), which is why
    /// `owner_axis_backend` registers the people as `user`.
    ///
    /// [`fixture_community`] deliberately keeps `role: None`: it pins the E4
    /// pass-through plane, where the moderator question never comes up because
    /// nothing federation-applies keyed on it. THIS is the roster a chat row
    /// can actually land into, and building it was the blocker v18.4.0 named
    /// when it deferred the positive convergence arm.
    ///
    /// The role string is imported from persist, never spelled locally — an
    /// invented `"founder"` literal would make this fixture green against a
    /// predicate the field does not run.
    fn fixture_moderated_community(community_key_id: &str, member_key_id: &str) -> Community {
        let mut community = fixture_community(community_key_id, member_key_id);
        community.members[0].role =
            Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER.to_string());
        community
    }

    /// Build a bridge over an existing backend with `cohort`.
    fn bridge_over(
        backend: &Arc<MemoryBackend>,
        cohort: &[&str],
    ) -> FederationDirectoryReplicationBridge {
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let cohort: Vec<String> = cohort.iter().map(|s| (*s).to_string()).collect();
        let cohort_cb: CohortProvider = Arc::new(move || cohort.clone());
        FederationDirectoryReplicationBridge::new(dir, cohort_cb)
    }

    /// Seed a Community whose SOLE member is `member` (a person, in the field).
    async fn seed_community_with_member(backend: &MemoryBackend, member: &str) {
        backend
            .put_community(sign_community_fixture(
                "room-authority",
                fixture_community("chat-room", member),
            ))
            .await
            .expect("seed community");
    }

    /// **The CIRISEdge#523 regression pin.** A Community whose member list names
    /// a PERSON, requested by a NODE that person owns → the row IS advertised.
    /// Pre-fix this returned 0 refs — the measured field state.
    #[tokio::test]
    async fn community_advertises_to_a_node_whose_owner_is_a_member() {
        let backend = owner_axis_backend(true).await;
        seed_community_with_member(&backend, "person-bob").await;
        let bridge = bridge_over(&backend, &["node-bob"]);

        let refs = bridge.list_envelope_refs(EnvelopeKind::Community).await;
        assert_eq!(
            refs.len(),
            1,
            "a room whose member is the requesting node's OWNER must be advertised \
             — the person/node axis (CIRISEdge#523); got {refs:?}"
        );
    }

    /// The pre-fix shape as the NEGATIVE CONTROL: an unrelated node — no owner
    /// match, not directly named — is still served nothing. The widening must
    /// not become "advertise to everyone".
    #[tokio::test]
    async fn community_stays_withheld_from_an_unrelated_node() {
        let backend = owner_axis_backend(true).await;
        seed_community_with_member(&backend, "person-bob").await;
        // `node-stranger` has no owner-binding at all, and is not a member.
        let bridge = bridge_over(&backend, &["node-stranger"]);

        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Community)
                .await
                .is_empty(),
            "an unrelated node is neither a member nor a member's node — nothing advertised"
        );
    }

    /// A node whose owner is a member of a DIFFERENT roster gets nothing: the
    /// widening joins on the owner-binding, not on "has an owner".
    #[tokio::test]
    async fn community_stays_withheld_when_the_owner_is_not_a_member() {
        let backend = owner_axis_backend(true).await;
        // The room's member is alice; the cohort node is owned by BOB.
        seed_community_with_member(&backend, "person-alice").await;
        let bridge = bridge_over(&backend, &["node-bob"]);

        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Community)
                .await
                .is_empty(),
            "an owner who is not on the roster confers nothing"
        );
    }

    /// The DIRECT path is widened, never replaced: a roster entry naming the
    /// node itself still advertises. The node carries an owner-binding because
    /// CC 3.2 requires one — persist refuses an `UnstewardedCommunityMember`, so
    /// "a node-named roster entry with no owner" is not a field-realizable
    /// shape. Its owner is deliberately NOT a member, so only the direct test
    /// can be what admits this row.
    #[tokio::test]
    async fn community_still_advertises_to_a_directly_named_node() {
        let backend = owner_axis_backend(true).await;
        seed_community_with_member(&backend, "node-bob").await;
        let bridge = bridge_over(&backend, &["node-bob"]);

        assert_eq!(
            bridge
                .list_envelope_refs(EnvelopeKind::Community)
                .await
                .len(),
            1,
            "a member entry naming the NODE directly keeps working (no regression \
             on the pre-#523 path)"
        );
    }

    /// Plane 2 of 3 — Family carries the identical gate shape.
    #[tokio::test]
    async fn family_advertises_to_a_node_whose_owner_is_a_member() {
        let backend = owner_axis_backend(true).await;
        backend
            .put_family(sign_family_fixture(
                "room-authority",
                fixture_family("household", "person-bob"),
            ))
            .await
            .expect("seed family");

        assert_eq!(
            bridge_over(&backend, &["node-bob"])
                .list_envelope_refs(EnvelopeKind::Family)
                .await
                .len(),
            1,
            "Family shares the Community gate shape (CIRISEdge#523 plane 2)"
        );
        assert!(
            bridge_over(&backend, &["node-stranger"])
                .list_envelope_refs(EnvelopeKind::Family)
                .await
                .is_empty(),
            "…and the same negative control holds"
        );
    }

    /// Plane 3 of 3 — LocationProof keys on `subject_key_id`, which for a
    /// person's presence claim is a person fed-ID.
    #[tokio::test]
    async fn location_proof_advertises_to_a_node_whose_owner_is_the_subject() {
        let backend = owner_axis_backend(true).await;
        // CIRISPersist#734 — location is SELF-KNOWLEDGE: a distinct authority is
        // admissible only as a LIVE delegate of the subject.
        seed_delegates_to(
            &backend,
            "person-bob",
            "room-authority",
            &serde_json::json!(["infra:attest"]),
        )
        .await;
        backend
            .put_location_proof(sign_location_proof_fixture(
                "room-authority",
                LocationProof {
                    subject_key_id: "person-bob".to_string(),
                    cell_id: "87283472bffffff".to_string(),
                    cell_resolution: 7,
                    asserted_at: "2026-07-01T00:00:00Z".parse().expect("rfc3339"),
                    valid_until: None,
                    attestation_evidence: None,
                    withdrawn_at: None,
                    persist_row_hash: String::new(),
                },
            ))
            .await
            .expect("seed location proof");

        assert_eq!(
            bridge_over(&backend, &["node-bob"])
                .list_envelope_refs(EnvelopeKind::LocationProof)
                .await
                .len(),
            1,
            "LocationProof shares the gate shape (CIRISEdge#523 plane 3)"
        );
        assert!(
            bridge_over(&backend, &["node-stranger"])
                .list_envelope_refs(EnvelopeKind::LocationProof)
                .await
                .is_empty(),
            "…and the same negative control holds"
        );
    }

    /// **The fail-closed rule.** An UNRESOLVED owner (`owner_of` errored, or
    /// persist reported `AmbiguousNodeOwner`) contributes NOTHING: the gate
    /// falls back to the direct-key test — exactly the pre-#523 behaviour — and
    /// the node is handed back for booking.
    ///
    /// Pinned at `widen_cohort_by_owners` rather than end-to-end because the
    /// error is not reachable through a `MemoryBackend` fixture: persist's
    /// single-owner ADMISSION gate refuses a second owner-binding (so
    /// `AmbiguousNodeOwner` cannot be seeded), and an in-memory directory read
    /// does not fail. Testing the branch that decides, with the three inputs the
    /// field produces, beats testing nothing.
    #[test]
    fn an_unresolved_owner_does_not_widen_the_cohort() {
        let direct: HashSet<String> = ["node-a", "node-b", "node-c"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let (widened, unresolved) = FederationDirectoryReplicationBridge::widen_cohort_by_owners(
            direct.clone(),
            vec![
                ("node-a".to_string(), OwnerLookup::Owner("person-a".into())),
                ("node-b".to_string(), OwnerLookup::Unowned),
                ("node-c".to_string(), OwnerLookup::Unresolved),
            ],
        );
        assert!(
            widened.contains("person-a"),
            "a RESOLVED owner joins the membership test"
        );
        assert!(
            !widened.contains("person-c"),
            "an UNRESOLVED owner adds nothing — the gate narrows to the direct test"
        );
        assert_eq!(
            widened.len(),
            direct.len() + 1,
            "exactly one owner was added; Unowned and Unresolved widen nothing"
        );
        assert!(
            direct.iter().all(|n| widened.contains(n)),
            "the DIRECT key test survives untouched — widened BESIDE it, not instead"
        );
        assert_eq!(
            unresolved,
            vec!["node-c".to_string()],
            "the unresolved node is named so the caller can book the withhold"
        );
    }

    /// **The memo.** All three Cohort planes in one round cost ONE `owner_of`
    /// walk per cohort member — the #430 "resolve once, cache" discipline. The
    /// witness is the bridge's own `owner_reads` counter (incremented only on a
    /// memo MISS, i.e. an actual directory walk).
    #[tokio::test]
    async fn owner_lookups_are_memoized_across_planes_in_one_round() {
        use std::sync::atomic::Ordering;
        let backend = owner_axis_backend(true).await;
        seed_community_with_member(&backend, "person-bob").await;
        let bridge = bridge_over(&backend, &["node-bob", "node-stranger"]);

        let _ = bridge.list_envelope_refs(EnvelopeKind::Community).await;
        let after_first = bridge.owner_reads.load(Ordering::Relaxed);
        assert_eq!(
            after_first, 2,
            "the first plane resolves each of the 2 cohort members exactly once"
        );

        let _ = bridge.list_envelope_refs(EnvelopeKind::Family).await;
        let _ = bridge.list_envelope_refs(EnvelopeKind::LocationProof).await;
        assert_eq!(
            bridge.owner_reads.load(Ordering::Relaxed),
            after_first,
            "the other two planes in the same round re-read the directory ZERO times \
             (CIRISEdge#523 memo; the #400 per-envelope-re-resolution regression)"
        );
    }

    /// The memo's freshness + invalidation rules, pure (the `VerdictCache`
    /// shape). `Unowned` is a cached ANSWER and must not read back as "unknown".
    #[test]
    fn owner_cache_freshness_and_invalidation() {
        let t0 = Instant::now();
        let mut cache = OwnerCache::default();
        cache.put("node-bob", Some("person-bob".to_string()), t0);
        cache.put("node-orphan", None, t0);

        assert_eq!(
            cache.get_fresh("node-bob", t0),
            Some(OwnerLookup::Owner("person-bob".to_string())),
            "a fresh entry is a HIT"
        );
        assert_eq!(
            cache.get_fresh("node-orphan", t0),
            Some(OwnerLookup::Unowned),
            "`unowned` is a cached ANSWER, never a miss — and never `Unresolved`, \
             which the two-valued storage makes unrepresentable"
        );
        assert_eq!(
            cache.get_fresh("node-unknown", t0),
            None,
            "an absent entry is a MISS"
        );
        assert_eq!(
            cache.get_fresh("node-bob", t0 + OWNER_BINDING_MEMO_TTL),
            None,
            "the TTL expires the entry (the backstop for the time-driven \
             `expires_at` / `valid_until` clauses no apply event announces)"
        );

        // Invalidation drops BOTH directions of the binding.
        cache.put("node-bob", Some("person-bob".to_string()), t0);
        cache.invalidate("node-bob");
        assert_eq!(
            cache.get_fresh("node-bob", t0),
            None,
            "the node's own entry is dropped"
        );
        cache.put("node-bob", Some("person-bob".to_string()), t0);
        cache.invalidate("person-bob");
        assert_eq!(
            cache.get_fresh("node-bob", t0),
            None,
            "a revoked OWNER key drops every node it owned (the value side)"
        );
    }

    /// The apply-path invalidation predicate, over the exact row shapes the
    /// field produces. `delegates_to` is owner-binding-only per persist's OWN
    /// predicate; retractions are conservative (they carry no dimension of their
    /// own); everything else moves nothing.
    #[test]
    fn owner_binding_touched_recognizes_only_ownership_rows() {
        let mut owner_binding = att_with_dimension(Some(
            ciris_persist::federation::types::owner_binding::DIMENSION,
        ));
        owner_binding.attestation_type = "delegates_to".to_string();
        owner_binding.attested_key_id = "node-bob".to_string();
        assert_eq!(
            FederationDirectoryReplicationBridge::owner_binding_touched(&owner_binding),
            Some("node-bob"),
            "an owner-binding delegates_to moves owner_of(subject)"
        );

        let mut plain_delegation = att_with_dimension(Some("some:other:dimension:v1"));
        plain_delegation.attestation_type = "delegates_to".to_string();
        assert_eq!(
            FederationDirectoryReplicationBridge::owner_binding_touched(&plain_delegation),
            None,
            "an act-on-behalf / hierarchy delegates_to is NOT an owner-binding \
             (persist's `is_owner_binding_envelope` decides, not a local literal)"
        );

        let mut withdrawal = att_with_dimension(None);
        withdrawal.attestation_type = "withdraws".to_string();
        withdrawal.attested_key_id = "node-bob".to_string();
        assert_eq!(
            FederationDirectoryReplicationBridge::owner_binding_touched(&withdrawal),
            Some("node-bob"),
            "a retraction carries no dimension, so it is treated conservatively"
        );

        let mut scores = att_with_dimension(Some("trace:complete:v1"));
        scores.attestation_type = "scores".to_string();
        assert_eq!(
            FederationDirectoryReplicationBridge::owner_binding_touched(&scores),
            None,
            "the high-volume plane pays one string compare and moves nothing"
        );
    }

    /// End-to-end invalidation: an ADMITTED owner-binding drops the memoized
    /// `Unowned` verdict for that node, so the next round's advertise sees the
    /// new owner instead of waiting out the TTL.
    #[tokio::test]
    async fn an_admitted_owner_binding_invalidates_the_memo() {
        use std::sync::atomic::Ordering;
        let backend = owner_axis_backend(false).await; // NOT bound yet
        seed_community_with_member(&backend, "person-bob").await;
        let bridge = bridge_over(&backend, &["node-bob"]);

        assert!(
            bridge
                .list_envelope_refs(EnvelopeKind::Community)
                .await
                .is_empty(),
            "unowned node → the room is not advertised (and `Unowned` is memoized)"
        );
        let reads_before = bridge.owner_reads.load(Ordering::Relaxed);

        // The owner-binding arrives ON THE WIRE and is ADMITTED — the real
        // receive path, which is where the invalidation hangs.
        let id = uuid::Uuid::new_v4().to_string();
        let row = build_federation_attestation(
            &id,
            "person-bob",
            "node-bob",
            "delegates_to",
            owner_binding_envelope(&id, "person-bob", "node-bob"),
        );
        let wire = serde_json::to_vec(&row).expect("serialize owner-binding");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-bob"))
            .await;
        assert!(
            outcome.is_admitted(),
            "the owner-binding must be admitted (idempotent re-put); got {outcome:?}"
        );

        assert_eq!(
            bridge
                .list_envelope_refs(EnvelopeKind::Community)
                .await
                .len(),
            1,
            "the admitted owner-binding invalidated the memo — the room is advertised \
             in the SAME round, not one TTL later"
        );
        assert!(
            bridge.owner_reads.load(Ordering::Relaxed) > reads_before,
            "…and it did so by re-walking the directory, not by serving a stale hit"
        );
    }

    /// persist v38.5.0 (CIRISPersist#771) — **a re-delivered attestation is a
    /// DUPLICATE, not a refusal**, measured at the door the field actually
    /// uses.
    ///
    /// This is the receive-side end of the storm #771 filed: on the production
    /// canonical, 7,536 refusals in six hours — 428 distinct rows re-sent up to
    /// 82 times each, 58% of that node's refusals and ~44% of its total WARN —
    /// were rows the node ALREADY HELD. persist raised a UNIQUE violation, its
    /// error mapping defaulted it to `Error::Backend`, and edge's `refuse` arm
    /// dutifully WARN-logged and counted a policy refusal for the anti-entropy
    /// protocol working correctly.
    ///
    /// Asserted through `apply_envelope_bytes` — the real receive path, on the
    /// SAME bytes a peer re-offers — rather than over a hand-made
    /// `AttestationOutcome`, because the value of this test is that the field's
    /// input reaches the field's classifier. Three distinct properties, because
    /// collapsing any one of them is a way to get this wrong:
    ///   1. the second apply is `Duplicate`, NOT `Refused` (quiet: `on_deliver`
    ///      logs Duplicate at DEBUG);
    ///   2. it is COUNTED as a duplicate — quiet must not become invisible;
    ///   3. it books NOTHING on either refusal axis (kind or class) — which is
    ///      the 58% of refusals this cut removes.
    #[tokio::test]
    async fn a_re_delivered_attestation_is_a_quiet_counted_duplicate() {
        let backend = owner_axis_backend(false).await;
        let metrics = crate::observability::EdgeMetrics::new();
        let bridge = bridge_over(&backend, &["node-bob"]).with_metrics(Some(metrics.clone()));

        // One row, serialized ONCE — the second apply offers byte-identical
        // wire, exactly as a peer's re-offer does.
        let id = uuid::Uuid::new_v4().to_string();
        let row = build_federation_attestation(
            &id,
            "person-bob",
            "node-bob",
            "delegates_to",
            owner_binding_envelope(&id, "person-bob", "node-bob"),
        );
        let wire = serde_json::to_vec(&row).expect("serialize owner-binding");

        let first = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-bob"))
            .await;
        assert_eq!(
            first,
            ApplyOutcome::Admitted,
            "the first delivery changed local state — `AttestationOutcome::Inserted`"
        );

        let second = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-bob"))
            .await;
        assert_eq!(
            second,
            ApplyOutcome::Duplicate,
            "a byte-identical re-delivery is idempotent success — `AlreadyHeld` — \
             not a refusal; under persist <= v38.4.0 this was \
             `Error::Backend(\"UNIQUE constraint failed\")` and edge WARNed it \
             (CIRISPersist#771)",
        );

        let snap = metrics.snapshot();
        assert_eq!(
            snap.replication_applied_total
                .get(&EnvelopeKind::Attestation)
                .copied(),
            Some(1),
            "exactly ONE apply changed state",
        );
        assert_eq!(
            snap.replication_duplicate_total
                .get(&EnvelopeKind::Attestation)
                .copied(),
            Some(1),
            "…and the duplicate is COUNTED — quiet is not the same as invisible",
        );
        assert_eq!(
            snap.apply_refusals_by_kind
                .get(&EnvelopeKind::Attestation)
                .copied(),
            None,
            "nothing was refused: {:?}",
            snap.apply_refusals_by_kind,
        );
        assert!(
            snap.apply_refusals_by_class.is_empty(),
            "and no refusal CLASS was booked either — the 58%-of-refusals axis \
             #771 measured: {:?}",
            snap.apply_refusals_by_class,
        );
    }

    // ─── CIRISEdge#524 — the withhold that could not name its peer ─────────

    /// The measured line was
    /// `attestation plane withheld — … send-set (CIRISEdge#396 item 1) peer=`
    /// with the peer EMPTY. The ledger record — same label the log field and the
    /// throttle key carry — must now name what was evaluated.
    #[test]
    fn a_peer_label_is_never_empty() {
        assert_eq!(
            FederationDirectoryReplicationBridge::peer_label(""),
            "<empty-peer-id>",
            "an empty peer id is NAMED, and named distinctly from an absent one"
        );
        assert_eq!(
            FederationDirectoryReplicationBridge::peer_label("node-bob"),
            "node-bob",
            "a real peer id passes through verbatim"
        );
    }

    /// The #524 fix on the real withhold path: the ledger entry names the peer
    /// the gate actually evaluated, including the empty-id wiring fault.
    #[tokio::test]
    async fn the_send_set_withhold_names_the_peer_it_evaluated() {
        let local = "this-node";
        let (backend, bridge) = make_bridge(&[local.to_string()]);
        let metrics = crate::observability::EdgeMetrics::default();
        let bridge = bridge
            .with_local_key_id(Some(local.to_string()))
            .with_metrics(Some(metrics.clone()));
        register_fixture_keys(&backend, &[(local, identity_type::AGENT)]).await;

        // No consent grant at all → every peer is withheld (item 1, fail-closed).
        assert!(bridge.list_attestations_for_peer(Some("")).await.is_empty());
        assert!(bridge
            .list_attestations_for_peer(Some("node-bob"))
            .await
            .is_empty());

        let peers: Vec<String> = metrics
            .recent_withholds
            .read()
            .iter()
            .map(|w| w.peer_key_id.clone())
            .collect();
        assert!(
            peers.contains(&"<empty-peer-id>".to_string()),
            "an EMPTY peer id is booked under a name, not as blank space \
             (CIRISEdge#524); got {peers:?}"
        );
        assert!(
            peers.contains(&"node-bob".to_string()),
            "a real peer is booked under its own id; got {peers:?}"
        );
    }

    // ─── CIRISEdge#524 — the ROUTING half (persist v38.3.0 `nodes_owned_by`) ──
    //
    // **A DELIBERATELY CHANGED PINNED BEHAVIOUR.** v18.4.0 pinned the opposite
    // assertion — `a_person_named_grant_is_diagnosed_but_never_routed`, "an
    // owner match must NOT serve" — because the send-side reverse index did not
    // exist and diagnosing without routing was the honest half to ship. persist
    // v38.3.0 (CIRISPersist#764) shipped `nodes_owned_by`, so that pin is now
    // the wrong behaviour to hold, and it is replaced below by its inverse plus
    // the negative controls that keep the widening from becoming
    // "serve everyone". The by-construction funnel is UNCHANGED:
    // `ResolvedPeerSet::recipient` is still the only constructor of a
    // `ResolvedRecipient`, and `names` still returns a `bool`.

    /// **The #524 routing pin.** The live grant names a PERSON — the natural
    /// thing for a consent object to name, and exactly what CIRISServer emitted
    /// — and the peer is the NODE that person owns. The peer is now a
    /// recipient, minted through the same one door every other recipient comes
    /// through.
    #[tokio::test]
    async fn a_person_named_grant_routes_to_that_persons_bound_node() {
        let local = "this-node";
        let backend = owner_axis_backend(true).await;
        register_fixture_keys(&backend, &[(local, identity_type::AGENT)]).await;
        let bridge =
            bridge_over(&backend, &["node-bob"]).with_local_key_id(Some(local.to_string()));
        seed_consent_membership(&backend, local, "person-bob").await;

        let set = bridge
            .resolved_peer_set(local)
            .await
            .expect("the send-set resolves");
        assert!(
            set.names("person-bob"),
            "the grant names the person (the field's shape)"
        );
        assert!(
            !set.names("node-bob"),
            "…and NOT the node: `names` stays the DIRECT projection, which is what \
             makes the person/node diagnostic readable"
        );
        assert!(
            set.routes_by_owner_binding("node-bob"),
            "…but the reverse owner-binding walk (persist `nodes_owned_by`) puts the \
             person's bound node in the send-set (CIRISEdge#524)"
        );
        assert!(
            set.recipient("node-bob").is_some(),
            "…so the ONE minting door authorizes it — no side door was added"
        );
        assert!(
            set.owner_walk_complete(),
            "the walk answered for every grant subject"
        );
        assert_eq!(
            set.owner_routed_len(),
            1,
            "exactly the one bound node, not a widening to everything"
        );
    }

    /// The negative controls, on the SAME backend as the pin above: the
    /// widening reaches the grant subject's bound node and NOTHING else. An
    /// unowned node, and a node owned by a person NO grant names, are both
    /// still withheld — the fail-closed shape #396 item 1 rests on.
    #[tokio::test]
    async fn the_owner_binding_widening_reaches_only_the_grant_subjects_nodes() {
        let local = "this-node";
        let backend = owner_axis_backend(true).await;
        register_fixture_keys(&backend, &[(local, identity_type::AGENT)]).await;
        let bridge = bridge_over(&backend, &["node-bob", "node-stranger"])
            .with_local_key_id(Some(local.to_string()));
        // The grant names person-ALICE, who owns nothing.
        seed_consent_membership(&backend, local, "person-alice").await;

        let set = bridge
            .resolved_peer_set(local)
            .await
            .expect("the send-set resolves");
        assert_eq!(
            set.owner_routed_len(),
            0,
            "a grant subject who owns no live-bound node widens the set by nothing"
        );
        assert!(
            set.recipient("node-bob").is_none(),
            "node-bob's owner (person-bob) is named by NO grant — the widening is per \
             grant subject, never 'every node with an owner'"
        );
        assert!(
            set.recipient("node-stranger").is_none(),
            "an unowned node is reached by neither axis"
        );
    }

    /// The routing half on the REAL serve path, end to end: the plane the field
    /// measured dark is served, and only to the owner-bound node. This is the
    /// assertion CIRISServer's ladder was missing — 7 rows on the link under a
    /// node-named grant, 0 under a person-named one.
    #[tokio::test]
    async fn the_attestation_plane_is_served_to_the_grant_subjects_bound_node() {
        let local = "this-node";
        let producer = "agent-producer";
        let backend = owner_axis_backend(true).await;
        register_fixture_keys(
            &backend,
            &[
                (local, identity_type::AGENT),
                (producer, identity_type::AGENT),
            ],
        )
        .await;
        seed_advertised_attestation(&backend, producer).await;
        seed_consent_membership(&backend, local, "person-bob").await;
        let bridge =
            bridge_over(&backend, &["node-bob"]).with_local_key_id(Some(local.to_string()));

        let baseline = bridge.list_attestations_for_peer(None).await;
        assert!(
            !baseline.is_empty(),
            "the seeded attestation is advertised in the ungated local view"
        );
        let served = bridge.list_attestations_for_peer(Some("node-bob")).await;
        assert_eq!(
            served.len(),
            baseline.len(),
            "the person-named grant now reaches that person's bound NODE — the plane \
             the field measured dark (CIRISEdge#524); got {served:?}"
        );
        assert!(
            bridge
                .owner_routed_recipients
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0,
            "…and it was booked as an owner-BINDING route, so an operator can tell this \
             from a grant that simply named the node"
        );
        // The negative control on the same serve path.
        assert!(
            bridge
                .list_attestations_for_peer(Some("node-stranger"))
                .await
                .is_empty(),
            "an unrelated node is still served nothing"
        );
    }

    /// The owner-binding walk rides the CIRISEdge#400 memo: a round's advertise
    /// + N fetches pay for it ONCE, not per envelope. This walk is strictly
    /// more expensive than the `list_consent_peers` read #400 was about, so the
    /// regression it guards against is the same one, worse.
    #[tokio::test]
    async fn the_owner_binding_walk_is_memoized_across_the_round() {
        use std::sync::atomic::Ordering;
        let local = "this-node";
        let backend = owner_axis_backend(true).await;
        register_fixture_keys(&backend, &[(local, identity_type::AGENT)]).await;
        let bridge =
            bridge_over(&backend, &["node-bob"]).with_local_key_id(Some(local.to_string()));
        seed_consent_membership(&backend, local, "person-bob").await;

        let set1 = bridge.resolved_peer_set(local).await.expect("resolve 1");
        let after_first = bridge.owner_route_walks.load(Ordering::Relaxed);
        assert_eq!(
            after_first, 1,
            "one grant subject → exactly one `nodes_owned_by` walk"
        );
        let set2 = bridge.resolved_peer_set(local).await.expect("resolve 2");
        assert_eq!(
            bridge.owner_route_walks.load(Ordering::Relaxed),
            after_first,
            "the second resolve inside the TTL walks the directory ZERO more times"
        );
        assert!(
            set1.ptr_eq(&set2),
            "…and it is the same memoized set, BOTH halves (the O(1) `Arc` clone)"
        );
    }

    /// End-to-end invalidation for the direction the #523 memo cannot key on:
    /// an owner-binding for a node the send-set memo has never heard of. There
    /// is no entry to evict — the answer that changed is the SET — so the memo
    /// is dropped whole, and the newly bound node routes in the SAME round
    /// rather than one TTL later.
    #[tokio::test]
    async fn an_admitted_owner_binding_reroutes_the_send_set_in_the_same_round() {
        let local = "this-node";
        let backend = owner_axis_backend(false).await; // NOT bound yet
        register_fixture_keys(&backend, &[(local, identity_type::AGENT)]).await;
        let bridge =
            bridge_over(&backend, &["node-bob"]).with_local_key_id(Some(local.to_string()));
        seed_consent_membership(&backend, local, "person-bob").await;

        assert!(
            bridge
                .resolved_peer_set(local)
                .await
                .expect("resolve")
                .recipient("node-bob")
                .is_none(),
            "unbound node → not a recipient (and the narrow set is memoized)"
        );

        // The binding arrives ON THE WIRE and is ADMITTED — the real receive
        // path, which is where the invalidation hangs.
        let id = uuid::Uuid::new_v4().to_string();
        let row = build_federation_attestation(
            &id,
            "person-bob",
            "node-bob",
            "delegates_to",
            owner_binding_envelope(&id, "person-bob", "node-bob"),
        );
        let wire = serde_json::to_vec(&row).expect("serialize owner-binding");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-bob"))
            .await;
        assert!(
            outcome.is_admitted(),
            "the owner-binding must be admitted; got {outcome:?}"
        );

        assert!(
            bridge
                .resolved_peer_set(local)
                .await
                .expect("resolve")
                .recipient("node-bob")
                .is_some(),
            "the admitted owner-binding dropped the send-set memo — the person's new \
             instrument routes in the SAME round, not one TTL later (CIRISEdge#524)"
        );
    }

    // ─── persist v38.3.0 / CIRISPersist#765 — the transient that can now ───
    // ─── actually TRANSITION (the positive arm v18.4.0 deferred)         ───

    /// **The convergence arm: roster applies → the row lands.**
    ///
    /// v18.4.0 classified `WriteScopeRefused(NoCommunityMembership)` as
    /// `retry_after_community_roster` — TRANSIENT, re-offered next round — and
    /// pinned that reading with a pure classifier test, but could not pin the
    /// second half ("…and then it converges") for two reasons, both now gone:
    ///
    /// 1. persist v38.2.0 resolved a NODE writer to ITSELF (its
    ///    identity-occurrence row is self-referential), so it asked AV-45's
    ///    membership question about the instrument. The roster's members are
    ///    PERSONS, so no roster arrival could ever satisfy it — the "transient"
    ///    could not transition, which is the ladder CIRISServer measured.
    ///    persist v38.3.0's principal fold (#765) walks the live owner-binding
    ///    when the occurrence axis is self-referential.
    /// 2. The fixture could not seat a moderator, so §11.11's federate-apply
    ///    re-check refused a row keyed on a KNOWN community regardless. See
    ///    [`fixture_moderated_community`].
    ///
    /// So this asserts the disposition end to end, on the REAL receive path:
    /// the same bytes refuse TRANSIENTLY before the roster and are ADMITTED
    /// after it, with no operator action and no retry queue — convergence by
    /// construction (a refused row is not stored, so the node still lacks its
    /// hash and the next Summary/Diff re-offers it).
    #[tokio::test]
    async fn a_bound_nodes_community_row_lands_once_the_roster_applies() {
        let backend = owner_axis_backend(true).await;
        let metrics = crate::observability::EdgeMetrics::default();
        let bridge = bridge_over(&backend, &["node-bob"]).with_metrics(Some(metrics.clone()));

        // The on-behalf chat row: signed by the NODE, about its OWNER, into the
        // owner's room. Exactly the shape CIRISServer's ladder emits.
        let id = uuid::Uuid::new_v4().to_string();
        let row = build_scoped_federation_attestation(
            &id,
            "node-bob",
            "person-bob",
            "scores",
            serde_json::json!({
                "id": id,
                "dimension": "chat:message:v1",
                "community_id": "chat-room",
                "on_behalf_of_key_id": "person-bob",
            }),
            "community",
        );
        let wire = serde_json::to_vec(&row).expect("serialize chat row");

        // (1) BEFORE the roster lands — refused, and refused TRANSIENTLY.
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-bob"))
            .await;
        match &outcome {
            ApplyOutcome::Refused { reason, .. } => {
                assert!(
                    reason.contains("class=retry_after_community_roster"),
                    "the roster has not landed — this is the transient class: {reason}"
                );
                assert!(reason.contains("TRANSIENT"), "{reason}");
            }
            other => panic!("expected a roster-ordering refusal, got {other:?}"),
        }
        assert_eq!(
            metrics
                .snapshot()
                .apply_refusals_by_class
                .get("retry_after_community_roster"),
            Some(&1),
            "…and it is COUNTED on the closed-set axis, not mixed into `by_kind`"
        );

        // (2) The roster applies (in the field: the Community plane's own
        // envelope, one round earlier or later — the ordering nobody controls).
        backend
            .put_community(sign_community_fixture(
                "room-authority",
                fixture_moderated_community("chat-room", "person-bob"),
            ))
            .await
            .expect("seed the roster");

        // (3) The SAME bytes, re-offered — and now they LAND. The membership
        // question is asked about the PRINCIPAL (persist#765): the node resolves
        // through its live owner-binding to person-bob, who is on the roster.
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-bob"))
            .await;
        assert!(
            outcome.is_admitted(),
            "the roster landed, so the transient must TRANSITION — this is the arm that \
             was impossible at persist v38.2.0, where the membership question was asked \
             about the instrument instead of the principal (CIRISPersist#765); got \
             {outcome:?}"
        );
    }

    /// The other half of #765's equivalence, held from edge's side: it widens
    /// to the single live OWNER and never past it. An UNBOUND node inherits
    /// nothing, so its identical row keeps refusing after the roster lands —
    /// and keeps refusing as the SAME transient class, because "this writer is
    /// nobody's principal" is indistinguishable from "the roster has not
    /// landed" at the membership door, and edge must not invent a distinction
    /// persist does not draw.
    #[tokio::test]
    async fn an_unbound_node_inherits_no_membership_from_the_roster() {
        let backend = owner_axis_backend(true).await;
        backend
            .put_community(sign_community_fixture(
                "room-authority",
                fixture_moderated_community("chat-room", "person-bob"),
            ))
            .await
            .expect("seed the roster");
        let bridge = bridge_over(&backend, &["node-stranger"]);

        let id = uuid::Uuid::new_v4().to_string();
        let row = build_scoped_federation_attestation(
            &id,
            "node-stranger", // owned by nobody
            "person-bob",
            "scores",
            serde_json::json!({
                "id": id,
                "dimension": "chat:message:v1",
                "community_id": "chat-room",
                "on_behalf_of_key_id": "person-bob",
            }),
            "community",
        );
        let wire = serde_json::to_vec(&row).expect("serialize chat row");
        let outcome = bridge
            .apply_envelope_bytes(EnvelopeKind::Attestation, &wire, Some("node-stranger"))
            .await;
        match &outcome {
            ApplyOutcome::Refused { reason, .. } => assert!(
                reason.contains("class=retry_after_community_roster"),
                "an unbound node must not inherit anyone's membership — the principal \
                 fold widens to the single live owner and NEVER past it, and the door it \
                 refuses at is still the MEMBERSHIP door: {reason}"
            ),
            other => panic!("an unbound node must not inherit anyone's membership; got {other:?}"),
        }
    }

    /// The fail-closed rule, on the set itself: a walk that could not answer
    /// NARROWS and says so. Pure, because the branch is not reachable through a
    /// `MemoryBackend` fixture (an in-memory directory read does not fail) —
    /// the same reason `widen_cohort_by_owners` is pinned pure, and the same
    /// discipline: pin the value that decides, with the shape the field
    /// produces.
    #[test]
    fn an_incomplete_owner_walk_narrows_and_is_never_silent() {
        let complete = ResolvedPeerSet::from_consent_peers(vec!["person-bob".to_string()])
            .widened_by_owner_binding(vec!["node-bob".to_string()], true);
        assert!(complete.recipient("node-bob").is_some());
        assert!(complete.owner_walk_complete());

        // The same grant, with the walk unable to answer for its subject.
        let narrowed = ResolvedPeerSet::from_consent_peers(vec!["person-bob".to_string()])
            .widened_by_owner_binding(Vec::new(), false);
        assert!(
            narrowed.recipient("node-bob").is_none(),
            "an unresolvable owner walk must NARROW — never widen, never guess"
        );
        assert!(
            narrowed.recipient("person-bob").is_some(),
            "…and it must not disturb the DIRECT half: the grant still names its subject"
        );
        assert!(
            !narrowed.owner_walk_complete(),
            "…and the narrowing is observable, not silent (it is stated in the withhold \
             line and booked as a withhold)"
        );
    }
    // ─── CIRISEdge#531 DEPTH — the advertise WATERMARK ──────────────────
    //
    // The width bound (v18.6.0) capped how many sweeps materialise at once;
    // this is the half that makes the memory FLAT — a page-bounded advertise
    // with a per-(peer, plane) watermark, so `permits × corpus × 2` becomes
    // `permits × page × 2`.
    //
    // CONVERGENCE is the property, so it is what is pinned. A watermark that
    // bounds memory by never re-offering a row would trade an OOM for silent
    // non-convergence, which this repo has closed as a bug class three times
    // (#416, #429, #425) and which is strictly worse than the OOM. Every test
    // below asserts a SET, not a count.
    mod depth {
        use super::*;
        use std::collections::BTreeSet;

        fn paged_bridge(
            cohort: &[String],
            page: u32,
        ) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
            let backend = Arc::new(MemoryBackend::new());
            let dir: Arc<dyn FederationDirectory> = backend.clone();
            let cohort_clone = cohort.to_vec();
            let cohort_cb: CohortProvider = Arc::new(move || cohort_clone.clone());
            let bridge = FederationDirectoryReplicationBridge::with_config(
                dir,
                cohort_cb,
                BridgeConfig {
                    sweep_page_rows: page,
                    ..BridgeConfig::default()
                },
            );
            (backend, bridge)
        }

        /// Seed `n` key records and return the cohort naming them.
        async fn seed_keys(backend: &Arc<MemoryBackend>, ids: &[String]) {
            for id in ids {
                backend
                    .put_public_key(SignedKeyRecord {
                        record: fixture_key_record(id, identity_type::AGENT),
                    })
                    .await
                    .expect("seed key");
            }
        }

        fn hashes(refs: &[EnvelopeRef]) -> BTreeSet<[u8; 32]> {
            refs.iter().map(|r| r.envelope_hash).collect()
        }

        // ── the pure cursor state machine ───────────────────────────────

        /// A DETERMINISTIC cursor: the state machine is pure, so its tests
        /// must be too — a `Utc::now()` here makes two calls for "the same"
        /// position compare unequal by nanoseconds.
        fn cur(n: u8) -> ResumeCursor {
            (
                chrono::DateTime::from_timestamp(1_700_000_000 + i64::from(n), 0)
                    .expect("fixed cursor instant"),
                format!("id-{n}"),
            )
        }

        fn key() -> (String, EnvelopeKind) {
            ("peer".to_string(), EnvelopeKind::Key)
        }

        /// A COLD peer walks forward one page per round and pays for exactly
        /// ONE read while doing it — the catch-up walk IS the first re-sweep
        /// pass, so a second (backfill) read would double a new peer's cost for
        /// no coverage it does not already get.
        #[test]
        fn catch_up_costs_one_page_per_round_and_no_backfill_read() {
            let mut c = SweepCursors::default();
            let k = key();
            assert_eq!(c.head(&k), None, "a cold peer starts at the beginning");
            // A FULL page ⇒ still catching up.
            assert_eq!(c.after_head(&k, 4, 4, Some(cur(1))), None);
            assert_eq!(
                c.head(&k),
                Some(cur(1)),
                "the next round resumes from the last row of the last page"
            );
            assert_eq!(c.after_head(&k, 4, 4, Some(cur(2))), None);
            assert_eq!(c.head(&k), Some(cur(2)));
        }

        /// The moment the forward walk reaches the end of the plane, the
        /// rolling re-sweep starts over from the BEGINNING — the door-stop that
        /// keeps the watermark an optimisation rather than a one-way door.
        #[test]
        fn reaching_the_end_starts_the_rolling_resweep_from_the_beginning() {
            let mut c = SweepCursors::default();
            let k = key();
            // A SHORT page ⇒ end of plane.
            assert_eq!(
                c.after_head(&k, 2, 4, Some(cur(9))),
                None,
                "the transition round does not also pay for a backfill read — \
                 the tail it would read is the tail just read"
            );
            // Next round: nothing new, so the whole budget goes to the re-sweep,
            // starting from the beginning.
            let plan = c
                .after_head(&k, 0, 4, None)
                .expect("caught up ⇒ the spare budget rolls the re-sweep");
            assert_eq!(plan.since, None, "the re-sweep restarts at the beginning");
            assert_eq!(
                plan.budget, 4,
                "an idle plane gives the re-sweep the WHOLE page"
            );
        }

        /// NEW ROWS come first and take the budget they need; the re-sweep gets
        /// the remainder. A new chat message is therefore offered in the NEXT
        /// round, not one re-sweep cycle later — which is the whole reason for
        /// two cursors instead of one wrapping one.
        #[test]
        fn new_rows_are_served_before_the_rolling_resweep() {
            let mut c = SweepCursors::default();
            let k = key();
            c.after_head(&k, 1, 4, Some(cur(1))); // short ⇒ caught up
            let plan = c
                .after_head(&k, 3, 4, Some(cur(4)))
                .expect("some budget left");
            assert_eq!(
                plan.budget, 1,
                "three new rows leave one row of re-sweep budget"
            );
            assert_eq!(
                c.after_head(&k, 4, 4, Some(cur(8))),
                None,
                "a FULL page of new rows leaves the re-sweep nothing this round — \
                 it resumes next round, from where it was"
            );
        }

        /// The re-sweep WRAPS: a short backfill page means the end of the plane,
        /// so the next pass starts over. This is what bounds the re-offer
        /// interval at `ceil(corpus / page)` rounds instead of leaving it open.
        #[test]
        fn the_rolling_resweep_wraps_at_the_end_of_the_plane() {
            let mut c = SweepCursors::default();
            let k = key();
            c.after_head(&k, 0, 4, None); // caught up (short page, nothing there)
            let plan = c.after_head(&k, 0, 4, None).expect("plan");
            assert_eq!(plan.since, None);
            // A FULL backfill page advances it…
            c.after_backfill(&k, 4, 4, Some(cur(3)));
            let plan = c.after_head(&k, 0, 4, None).expect("plan");
            assert_eq!(
                plan.since,
                Some(cur(3)),
                "the re-sweep resumes where it was"
            );
            // …and a SHORT one wraps it.
            c.after_backfill(&k, 1, 4, Some(cur(5)));
            let plan = c.after_head(&k, 0, 4, None).expect("plan");
            assert_eq!(plan.since, None, "the end of the plane WRAPS the re-sweep");
        }

        /// The map is CAPPED and evicts least-recently-touched. Peers churn,
        /// and an unreapable per-peer map is the shape CIRISEdge#530 is open
        /// about one plane over. Eviction costs a re-sweep, never a skipped row.
        #[test]
        fn the_watermark_map_is_capped_and_evicts_the_oldest() {
            let mut c = SweepCursors::default();
            for i in 0..MAX_TRACKED_SWEEP_CURSORS + 8 {
                let k = (format!("peer-{i}"), EnvelopeKind::Key);
                c.after_head(&k, 1, 4, Some(cur(1)));
            }
            assert!(
                c.by_peer_plane.len() <= MAX_TRACKED_SWEEP_CURSORS,
                "the watermark map grew past its cap ({} entries) — an unreapable \
                 per-peer map is a leak (CIRISEdge#531/#530)",
                c.by_peer_plane.len()
            );
            assert_eq!(
                c.head(&("peer-0".to_string(), EnvelopeKind::Key)),
                None,
                "the least-recently-touched peer was evicted, so it re-sweeps from \
                 the beginning — work, not a skipped row"
            );
        }

        /// A declared floor never pulls the serve position BACKWARD, and
        /// `None` is the earliest position rather than the latest.
        #[test]
        fn later_cursor_treats_none_as_the_beginning() {
            type B = FederationDirectoryReplicationBridge;
            assert_eq!(B::later_cursor(None, None), None);
            assert_eq!(B::later_cursor(Some(cur(1)), None), Some(cur(1)));
            assert_eq!(B::later_cursor(None, Some(cur(1))), Some(cur(1)));
            assert_eq!(B::later_cursor(Some(cur(1)), Some(cur(2))), Some(cur(2)));
            assert_eq!(B::later_cursor(Some(cur(2)), Some(cur(1))), Some(cur(2)));
        }

        // ── the real bridge, over a real backend ────────────────────────

        /// **The headline property.** A corpus LARGER than the page converges:
        /// every row is eventually offered, the union over rounds equals the
        /// whole advertise set, and no single read ever materialises more than
        /// one page.
        ///
        /// The set, not a count — a watermark that offered the right NUMBER of
        /// rows while permanently skipping one would pass a count assertion and
        /// be exactly the bug this is guarding.
        #[tokio::test]
        async fn a_corpus_larger_than_the_page_fully_converges_across_rounds() {
            let ids: Vec<String> = (0..7).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids).await;

            let whole = hashes(&bridge.list_envelope_refs(EnvelopeKind::Key).await);
            assert_eq!(whole.len(), 7, "the complete advertise set");

            let mut offered: BTreeSet<[u8; 32]> = BTreeSet::new();
            for round in 0..6 {
                let refs = bridge
                    .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-a"))
                    .await;
                assert!(
                    refs.len() <= 4,
                    "round {round}: one round offers at most the page budget \
                     (new-rows page + re-sweep page), got {}",
                    refs.len()
                );
                offered.extend(refs.iter().map(|r| r.envelope_hash));
            }
            assert_eq!(
                offered, whole,
                "the peer was never offered part of the plane — a watermark that \
                 bounds memory by skipping rows is worse than the OOM it fixes"
            );
            assert!(
                bridge.max_sweep_page_rows() <= 2,
                "a single page materialised {} rows against a budget of 2 — a bulk \
                 read was wired past the page driver (CIRISEdge#531)",
                bridge.max_sweep_page_rows()
            );
        }

        /// **The timestamp-collision hazard, which persist already closed and
        /// edge must not re-open.**
        ///
        /// #531 was filed believing the serve cursor was `WHERE ts > since`
        /// with an `ORDER BY (ts, id)` — strict on the timestamp ALONE — so a
        /// page boundary landing inside a group of rows sharing one instant
        /// (batch admissions do; persist truncates to microsecond resolution)
        /// would advance past the instant and skip the group's remainder,
        /// permanently and silently. That was true before persist v36.
        ///
        /// CIRISPersist#668 made every `list_*_since` a PAIR cursor —
        /// `WHERE pos > ?1 OR (pos = ?1 AND id > ?2)`, resumed from the served
        /// row's `resume_pair()` — so the hazard is closed at the source and
        /// edge's only job is to hand the pair back instead of the instant.
        /// No local dedup, and no persist ask.
        ///
        /// This drives the page loop over a corpus whose rows ALL share one
        /// instant, through a reader that reproduces persist's exact predicate.
        /// An edge that resumed on the timestamp alone would re-read the same
        /// first page every round and converge on two rows out of five.
        #[tokio::test]
        async fn a_page_boundary_inside_a_timestamp_tie_skips_nothing() {
            let (_backend, bridge) = paged_bridge(&[], 2);
            let tie = chrono::DateTime::from_timestamp(1_700_000_000, 0).expect("instant");
            let corpus: Vec<(ResumeCursor, String)> = (0..5)
                .map(|i| ((tie, format!("id-{i}")), format!("row-{i}")))
                .collect();

            let mut offered: BTreeSet<[u8; 32]> = BTreeSet::new();
            // ceil(5 / 2) = 3 rounds is the whole plane, and not one more:
            // asserting the exact round count is what separates "resumes into
            // the tie" from "re-reads page one forever".
            for _ in 0..3 {
                let corpus = corpus.clone();
                let refs = bridge
                    .sweep_paged(
                        EnvelopeKind::Key,
                        SweepWindow::Watermark("peer-tie"),
                        move |since: Option<ResumeCursor>, limit: u32| {
                            let corpus = corpus.clone();
                            async move {
                                // persist's predicate, verbatim in Rust:
                                // ORDER BY (pos, id), strictly greater than the PAIR.
                                corpus
                                    .into_iter()
                                    .filter(|(c, _)| since.as_ref().map_or(true, |sc| c > sc))
                                    .take(limit as usize)
                                    .collect::<Vec<_>>()
                            }
                        },
                        |row: &(ResumeCursor, String)| row.0.clone(),
                        |_| true,
                        |_| 0u64,
                        |row| &row.1,
                    )
                    .await;
                offered.extend(refs.iter().map(|r| r.envelope_hash));
            }
            assert_eq!(
                offered.len(),
                5,
                "a page boundary inside a one-instant tie skipped part of the group \
                 — the watermark is resuming on the timestamp instead of the \
                 `(pos, id)` pair persist serves (CIRISPersist#668/CIRISEdge#531)"
            );
        }

        /// **The transient-refusal door-stop.** v18.4.0's AV-45
        /// `retry_after_community_roster` is refused on the RECEIVER and never
        /// reported back, so the sender cannot keep a replay set — its
        /// documented guarantee is literally *"the next Summary/Diff re-offers
        /// it"*. A purely monotonic watermark can never re-offer a row it has
        /// passed, which would strand exactly those rows forever.
        ///
        /// So: take a row the watermark has demonstrably PASSED, and keep
        /// sweeping. It must come back.
        #[tokio::test]
        async fn a_row_the_watermark_has_passed_is_re_offered_by_the_resweep() {
            let ids: Vec<String> = (0..6).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids).await;

            // Round 1 offers the first page. Pick a row from it — the watermark
            // is now past it by construction.
            let first = bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-b"))
                .await;
            assert!(!first.is_empty(), "round one offers a page");
            let passed = first[0].envelope_hash;

            // …the peer refuses it transiently (a roster that has not landed),
            // so it is NOT in the peer's holdings and only a RE-OFFER can carry
            // it. Count how many times the re-sweep brings it back.
            //
            // TWICE, not once: one re-offer is satisfied by the re-sweep's FIRST
            // pass, which a design with no wrap-around would also produce before
            // going silent forever. Requiring a second re-offer is what actually
            // pins the CYCLE — the property that makes the watermark an
            // optimisation rather than a one-way door, at every future round and
            // not just the next one.
            let mut re_offers = 0usize;
            for _ in 0..16 {
                let refs = bridge
                    .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-b"))
                    .await;
                if refs.iter().any(|r| r.envelope_hash == passed) {
                    re_offers += 1;
                }
            }
            assert!(
                re_offers >= 2,
                "a row the watermark passed came back {re_offers} time(s) in 16 \
                 rounds — the rolling re-sweep is not CYCLING, so the AV-45 \
                 transient class is stranded and `is_transient`'s \"the next \
                 Summary/Diff re-offers it\" stops being true (CIRISEdge#531)"
            );
        }

        /// A row admitted AFTER the peer caught up is offered in the very next
        /// round — not one re-sweep cycle later. This is the property that
        /// makes the design usable for chat (every new message is a new row on
        /// the Attestation plane), and the reason the new-rows cursor is read
        /// FIRST and with the whole page budget rather than the design being
        /// one wrapping cursor.
        #[tokio::test]
        async fn a_newly_admitted_row_is_offered_in_the_next_round() {
            // The cohort names the late row from the start; only its KEY RECORD
            // arrives late, which is exactly what a new row looks like.
            let mut ids: Vec<String> = (0..3).map(|i| format!("key-{i}")).collect();
            let late = "key-late".to_string();
            ids.push(late.clone());
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids[..3]).await;

            // Sweep until this peer has caught up with the plane as it stands.
            for _ in 0..5 {
                let _ = bridge
                    .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-c"))
                    .await;
            }
            // The late row's hash, taken from the plane itself rather than
            // recomputed: `fixture_key_record` stamps `Utc::now()`, so a
            // rebuilt record would hash to something the plane never held —
            // a test that then passes or fails for the wrong reason.
            let before = hashes(&bridge.list_envelope_refs(EnvelopeKind::Key).await);
            seed_keys(&backend, std::slice::from_ref(&late)).await;
            let after = hashes(&bridge.list_envelope_refs(EnvelopeKind::Key).await);
            let late_hash = *after
                .difference(&before)
                .next()
                .expect("the late row entered the advertise set");

            let refs = bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-c"))
                .await;
            assert!(
                refs.iter().any(|r| r.envelope_hash == late_hash),
                "the round right after a row was admitted must OFFER it — the \
                 new-rows cursor is read first and with the whole page budget, so \
                 a new chat message does not wait a re-sweep cycle (CIRISEdge#531)"
            );
        }

        /// A FRESH peer converges from empty against a corpus that is already
        /// there — the cold-start path, which is also what a restart looks like
        /// from the other side.
        #[tokio::test]
        async fn a_fresh_peer_converges_from_empty() {
            let ids: Vec<String> = (0..5).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids).await;
            // An established peer has already swept the plane.
            for _ in 0..6 {
                let _ = bridge
                    .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-old"))
                    .await;
            }
            let whole = hashes(&bridge.list_envelope_refs(EnvelopeKind::Key).await);
            let mut offered: BTreeSet<[u8; 32]> = BTreeSet::new();
            for _ in 0..6 {
                let refs = bridge
                    .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-new"))
                    .await;
                offered.extend(refs.iter().map(|r| r.envelope_hash));
            }
            assert_eq!(
                offered, whole,
                "a peer that joined late must still be offered the WHOLE plane — \
                 watermarks are per-peer, never node-global"
            );
        }

        /// A RESTART drops the watermarks (they are in memory, by design), and
        /// the node re-sweeps from the beginning: it costs work and converges,
        /// rather than costing correctness. And the re-offer is not a duplicate
        /// APPLICATION — the refs are the same content hashes, so a peer that
        /// already holds them computes an empty `want`.
        #[tokio::test]
        async fn a_restart_re_converges_without_duplicate_application() {
            let ids: Vec<String> = (0..5).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids).await;
            let mut before: BTreeSet<[u8; 32]> = BTreeSet::new();
            for _ in 0..6 {
                before.extend(
                    bridge
                        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-r"))
                        .await
                        .iter()
                        .map(|r| r.envelope_hash),
                );
            }

            // "Restart": a NEW bridge over the SAME state, with no watermarks.
            let dir: Arc<dyn FederationDirectory> = backend.clone();
            let cohort_clone = ids.clone();
            let restarted = FederationDirectoryReplicationBridge::with_config(
                dir,
                Arc::new(move || cohort_clone.clone()),
                BridgeConfig {
                    sweep_page_rows: 2,
                    ..BridgeConfig::default()
                },
            );
            let mut after: BTreeSet<[u8; 32]> = BTreeSet::new();
            for _ in 0..6 {
                after.extend(
                    restarted
                        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-r"))
                        .await
                        .iter()
                        .map(|r| r.envelope_hash),
                );
            }
            assert_eq!(
                after, before,
                "a restart must re-converge to the SAME advertise set"
            );
            // The peer's holdings after the first pass ARE `before`; a
            // re-offer of the same hashes leaves `want` empty, so nothing is
            // applied twice.
            assert!(
                after.difference(&before).next().is_none(),
                "the re-sweep offered a hash the peer does not already hold — \
                 that would be a duplicate application, not a re-offer"
            );
        }

        /// The HOLDINGS axis is paged for MEMORY but never watermarked: it is
        /// COMPLETE every round. A partial holdings view leaves held rows in
        /// `want` forever and re-fetches them every round — CIRISEdge#416's
        /// non-convergence, recreated by the fix for the memory.
        #[tokio::test]
        async fn holdings_stay_complete_under_paging() {
            let ids: Vec<String> = (0..7).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids).await;

            let first = hashes(&bridge.list_holdings(EnvelopeKind::Key).await);
            assert_eq!(first.len(), 7, "every held row, in ONE call");
            for _ in 0..4 {
                assert_eq!(
                    hashes(&bridge.list_holdings(EnvelopeKind::Key).await),
                    first,
                    "the holdings view is the same COMPLETE set every round — it \
                     carries no position and must never converge over rounds"
                );
            }
            assert!(
                bridge.max_sweep_page_rows() <= 2,
                "the holdings drain materialised {} rows in one page — complete in \
                 RESULT must not mean whole-corpus in MEMORY (CIRISEdge#531)",
                bridge.max_sweep_page_rows()
            );
        }

        /// The permit is taken PER PAGE, not per sweep. A multi-page holdings
        /// drain must show one entry per page — holding one permit across the
        /// whole drain would put every other plane behind it in a FIFO queue,
        /// which is the starvation the width bound was built to avoid.
        #[tokio::test]
        async fn a_multi_page_drain_takes_one_permit_per_page() {
            let ids: Vec<String> = (0..7).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 2);
            seed_keys(&backend, &ids).await;

            let before = bridge.sweep_permits_taken();
            let refs = bridge.list_holdings(EnvelopeKind::Key).await;
            let taken = bridge.sweep_permits_taken() - before;
            assert_eq!(refs.len(), 7);
            assert_eq!(
                taken, 4,
                "7 rows at a page of 2 is 4 reads (2+2+2+1), so 4 permit \
                 acquisitions — {taken} means the permit was held across pages \
                 (CIRISEdge#531)"
            );
            assert!(
                bridge.max_sweeps_in_flight() <= 2,
                "the width bound still holds across the paged drain"
            );
        }

        /// Paging DISABLED (`sweep_page_rows = 0`) is the documented escape
        /// hatch back to one whole-table read, and it must still be correct —
        /// an operator reaching for it on a wedged box must not also lose
        /// convergence.
        #[tokio::test]
        async fn paging_disabled_is_one_read_and_the_whole_plane() {
            let ids: Vec<String> = (0..5).map(|i| format!("key-{i}")).collect();
            let (backend, bridge) = paged_bridge(&ids, 0);
            seed_keys(&backend, &ids).await;
            let refs = bridge
                .list_envelope_refs_for_peer(EnvelopeKind::Key, Some("peer-z"))
                .await;
            assert_eq!(hashes(&refs).len(), 5, "the whole plane in one page");
            assert_eq!(
                bridge.sweep_permits_taken(),
                1,
                "one read, so one permit — the pre-DEPTH shape exactly"
            );
        }

        /// The production DEFAULTS are what CIRISServer runs — it never
        /// constructs a `BridgeConfig` — so they are pinned here. Changing
        /// either is then a deliberate act with the arithmetic on
        /// `DEFAULT_SWEEP_PAGE_ROWS` to answer to.
        #[test]
        fn the_default_page_is_finite() {
            // A `u32::MAX` page IS the pre-#531 whole-table read: the DEPTH fix
            // is inert without a finite default, so the ceiling is pinned at
            // COMPILE time — the strongest form available, and the one clippy
            // asks for over a runtime assertion on a constant.
            const _: () = assert!(BridgeConfig::DEFAULT_SWEEP_PAGE_ROWS < u32::MAX);
            assert_eq!(BridgeConfig::default().sweep_page_rows, 1024);
            assert_eq!(
                BridgeConfig::DEFAULT_SWEEP_PAGE_ROWS,
                BridgeConfig::default().sweep_page_rows,
            );
        }

        /// CIRISEdge#531 (review finding) — a permit count that PARSES as a
        /// `usize` but exceeds `Semaphore::MAX_PERMITS` must not panic the
        /// node at boot. The documented contract is "a bad value is ignored";
        /// a panic in the knob whose purpose is keeping a wedged box alive is
        /// the worst possible way to break it.
        #[tokio::test]
        async fn an_absurd_permit_count_clamps_instead_of_panicking() {
            let backend = Arc::new(MemoryBackend::new());
            let dir: Arc<dyn FederationDirectory> = backend.clone();
            let bridge = FederationDirectoryReplicationBridge::with_config(
                dir,
                Arc::new(Vec::new),
                BridgeConfig {
                    advertise_sweep_permits: usize::MAX,
                    ..BridgeConfig::default()
                },
            );
            // …and the bridge still sweeps.
            let _ = bridge.list_holdings(EnvelopeKind::Key).await;
            assert!(bridge.sweep_permits_taken() >= 1);
        }

        /// The cursor plane's Deliver is byte-bounded like every OTHER Deliver
        /// on the wire. It was the one that was not: it served a whole page of
        /// serialized bundles, and that page stayed resident through the send,
        /// so RETAINED memory scaled with peer count while MATERIALISED memory
        /// scaled with permits. Pinned against the Diff path's budget so the
        /// two cannot drift apart silently.
        #[test]
        fn the_cursor_page_carries_the_same_byte_budget_as_every_other_deliver() {
            assert_eq!(
                CURSOR_PAGE_BUDGET_BYTES,
                crate::replication::session::MAX_DELIVER_ENVELOPE_BYTES,
                "the cursor Deliver must be bounded like the Diff-driven one — \
                 a page that is not byte-bounded is retained memory that scales \
                 with PEERS, which the sweep permit cannot bound (CIRISEdge#531)"
            );
        }
    }
}

// ─── CIRISEdge#531 — the advertise-sweep WIDTH bound ─────────────────
//
// Two layers, deliberately:
//
//   * [`SweepGate`] on its own — deterministic saturation, RAII release
//     (including off the error and panic paths), and the anti-starvation
//     property. These hold the permit across a `sleep`, so the bound is
//     actually exercised rather than trivially satisfied by a fast sweep.
//   * the REAL bridge over a real `MemoryBackend` — that the gate is entered
//     at exactly ONE layer, so the `list_holdings` /
//     `list_envelope_refs_for_peer` fall-through into the shared advertise
//     builder cannot self-deadlock at `permits == 1`. That is the failure mode
//     a width bound most easily introduces, and a HANG is what it looks like,
//     so every call there is under a `timeout`.
#[cfg(test)]
mod sweep_width_tests {
    use super::*;
    use ciris_persist::store::MemoryBackend;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration as StdDuration;

    fn make_bridge_with_permits(
        permits: usize,
    ) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
        let backend = Arc::new(MemoryBackend::new());
        let dir: Arc<dyn FederationDirectory> = backend.clone();
        let cohort: CohortProvider = Arc::new(Vec::new);
        let bridge = FederationDirectoryReplicationBridge::with_config(
            dir,
            cohort,
            BridgeConfig {
                advertise_sweep_permits: permits,
                ..BridgeConfig::default()
            },
        );
        (backend, bridge)
    }

    /// The DEFAULT is what production runs — CIRISServer never constructs a
    /// [`BridgeConfig`] — so it is pinned here rather than left to whatever a
    /// later edit finds convenient. Changing it is then a deliberate act, with
    /// the arithmetic on `DEFAULT_ADVERTISE_SWEEP_PERMITS` to answer to.
    #[test]
    fn default_config_bounds_the_sweep_width() {
        assert_eq!(
            BridgeConfig::default().advertise_sweep_permits,
            2,
            "the production default must BOUND the width (CIRISEdge#531); \
             0 would restore the unbounded pre-#531 fan-out"
        );
        assert_eq!(
            BridgeConfig::DEFAULT_ADVERTISE_SWEEP_PERMITS,
            BridgeConfig::default().advertise_sweep_permits
        );
    }

    /// THE concurrency pin: with `permits = N`, at most N sweeps are inside the
    /// materialising section at the same instant — and, because the holds here
    /// overlap by construction, exactly N are, so this also catches a bound that
    /// had silently become a full serialization.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn at_most_n_sweeps_materialise_simultaneously() {
        for permits in [1usize, 2, 3] {
            let gate = Arc::new(SweepGate::new(permits));
            let mut handles = Vec::new();
            for _ in 0..8 {
                let gate = Arc::clone(&gate);
                handles.push(tokio::spawn(async move {
                    let _permit = gate.enter().await;
                    // Hold across a real await so the windows genuinely overlap;
                    // a zero-length hold would satisfy any bound vacuously.
                    tokio::time::sleep(StdDuration::from_millis(40)).await;
                }));
            }
            for h in handles {
                h.await.expect("sweep task joined");
            }
            assert_eq!(
                gate.max_in_flight.load(Ordering::SeqCst),
                permits,
                "8 overlapping sweeps under {permits} permits must saturate the \
                 bound and never exceed it (CIRISEdge#531)"
            );
            assert_eq!(
                gate.in_flight.load(Ordering::SeqCst),
                0,
                "every permit released"
            );
        }
    }

    /// `advertise_sweep_permits = 0` is the documented escape hatch back to the
    /// pre-#531 unbounded fan-out. Pinned so "disabled" cannot silently become
    /// "zero permits", which would deadlock replication rather than unbound it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn zero_permits_means_unbounded_not_deadlocked() {
        let gate = Arc::new(SweepGate::new(0));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let gate = Arc::clone(&gate);
            handles.push(tokio::spawn(async move {
                let _permit = gate.enter().await;
                tokio::time::sleep(StdDuration::from_millis(40)).await;
            }));
        }
        tokio::time::timeout(StdDuration::from_secs(10), async {
            for h in handles {
                h.await.expect("sweep task joined");
            }
        })
        .await
        .expect("0 permits must not block — it disables the bound");
        assert_eq!(
            gate.max_in_flight.load(Ordering::SeqCst),
            8,
            "with the bound disabled all 8 sweeps materialise at once — the shape \
             CIRISEdge#531 exists to stop, kept reachable only as an explicit \
             operator opt-out"
        );
    }

    /// Release is STRUCTURAL, not a manual call an early return can skip. Both
    /// non-happy exits are covered: an error return out of the middle of a
    /// sweep, and a panic unwinding through it (the `block_in_place` bridge the
    /// production provider uses can carry one).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn permit_is_released_on_every_exit_path() {
        /// A sweep that takes the gate and then bails out mid-way, the shape
        /// every `unwrap_or_default()` / early-`return Vec::new()` exit in the
        /// bridge's bulk readers has.
        async fn sweep_that_fails(gate: &SweepGate) -> Result<(), &'static str> {
            let _permit = gate.enter().await;
            Err("persist read failed mid-sweep")
        }

        let gate = Arc::new(SweepGate::new(1));

        // (a) early return with an error.
        assert!(sweep_that_fails(&gate).await.is_err());
        assert_eq!(
            gate.in_flight.load(Ordering::SeqCst),
            0,
            "the error path released the permit"
        );

        // (b) panic unwinding out of the held section.
        let panicking = {
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                let _permit = gate.enter().await;
                panic!("sweep panicked while holding a permit");
            })
        };
        assert!(
            panicking.await.is_err(),
            "the spawned sweep panicked as intended"
        );
        assert_eq!(
            gate.in_flight.load(Ordering::SeqCst),
            0,
            "the panic path released the permit too — Drop, not a manual release"
        );

        // The single permit is still obtainable, i.e. neither exit leaked it.
        let regained = tokio::time::timeout(StdDuration::from_secs(10), gate.enter())
            .await
            .expect("the one permit is still available after both failure exits");
        assert_eq!(gate.in_flight.load(Ordering::SeqCst), 1);
        drop(regained);
        assert_eq!(gate.in_flight.load(Ordering::SeqCst), 0);
    }

    /// A width bound a busy plane can monopolise turns a memory bug into a
    /// liveness bug. Two properties together rule that out:
    ///
    ///   * tokio's `acquire_owned` is FIFO-fair (*"uses a queue to fairly
    ///     distribute permits in the order they were requested"*), so a waiter
    ///     holds a FIXED queue position — it cannot be overtaken. `try_acquire`,
    ///     the one path that CAN jump the queue, is used nowhere in the gate.
    ///   * every hold is bounded (one sweep), so a fixed position is a bounded
    ///     wait.
    ///
    /// Asserted at `permits = 1` — maximum contention — with one "plane"
    /// deliberately far slower than the rest: every plane still completes, and
    /// the fast planes' repeated re-acquires never push the slow one out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn no_plane_is_starved_under_contention() {
        let gate = Arc::new(SweepGate::new(1));
        let completed: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
        let slow_rounds = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        // Five fast planes, each taking the gate repeatedly — the "busy mesh"
        // an unfair bound would let starve the sixth.
        for _ in 0..5 {
            let gate = Arc::clone(&gate);
            let completed = Arc::clone(&completed);
            handles.push(tokio::spawn(async move {
                for _ in 0..20 {
                    let _permit = gate.enter().await;
                    tokio::task::yield_now().await;
                }
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }
        // One slow plane (the Attestation sweep's shape).
        {
            let gate = Arc::clone(&gate);
            let completed = Arc::clone(&completed);
            let slow_rounds = Arc::clone(&slow_rounds);
            handles.push(tokio::spawn(async move {
                for _ in 0..5 {
                    let _permit = gate.enter().await;
                    tokio::time::sleep(StdDuration::from_millis(10)).await;
                    slow_rounds.fetch_add(1, Ordering::SeqCst);
                }
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }

        tokio::time::timeout(StdDuration::from_secs(60), async {
            for h in handles {
                h.await.expect("plane task joined");
            }
        })
        .await
        .expect("every plane completed — no starvation, no deadlock");

        assert_eq!(
            completed.load(Ordering::SeqCst),
            6,
            "all six planes finished their rounds under a single permit"
        );
        assert_eq!(
            slow_rounds.load(Ordering::SeqCst),
            5,
            "the SLOW plane got every one of its rounds — the fast planes' 100 \
             re-acquires could not overtake it (tokio Semaphore is FIFO-fair)"
        );
        assert_eq!(gate.max_in_flight.load(Ordering::SeqCst), 1);
    }

    /// The re-entrancy pin, and the one that would fail as a HANG rather than an
    /// assertion: `list_envelope_refs_for_peer` and `list_holdings` both fall
    /// through to the shared advertise builder, so if either called the trait
    /// method (which takes a permit) instead of `list_envelope_refs_unbounded`,
    /// a single-permit node would self-deadlock on its first round for that kind.
    ///
    /// Driven over the REAL bridge at `permits = 1`, across every
    /// [`EnvelopeKind`] and every gated entry point, each under a timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sweep_gate_is_not_re_entrant() {
        let (_backend, bridge) = make_bridge_with_permits(1);
        for kind in EnvelopeKind::ALL {
            tokio::time::timeout(StdDuration::from_secs(30), async {
                let _ = bridge.list_envelope_refs(kind).await;
                let _ = bridge.list_envelope_refs_for_peer(kind, None).await;
                let _ = bridge
                    .list_envelope_refs_for_peer(kind, Some("some-peer"))
                    .await;
                let _ = bridge.list_holdings(kind).await;
                let _ = bridge.subject_holdings(kind, "subj", Some("subj")).await;
                let _ = bridge.subject_holdings(kind, "subj", Some("other")).await;
                let _ = bridge.accord_evidence_since(kind, None, None).await;
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{kind:?}: a gated entry point re-acquired the sweep permit while \
                     already holding it — self-deadlock at permits == 1 (CIRISEdge#531)"
                )
            });
        }
        assert!(
            bridge.max_sweeps_in_flight() <= 1,
            "never more than the configured permit count materialised at once"
        );
    }

    /// The bound holds on the real bridge under real concurrency, not only on
    /// the gate in isolation: many peers' entry points hammered at once, and the
    /// bridge's own high-water witness stays at or under the configured permits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn real_bridge_never_exceeds_its_permits() {
        for permits in [1usize, 2] {
            let (_backend, bridge) = make_bridge_with_permits(permits);
            let bridge = Arc::new(bridge);
            let mut handles = Vec::new();
            for i in 0..24 {
                let bridge = Arc::clone(&bridge);
                let kind = EnvelopeKind::ALL[i % EnvelopeKind::ALL.len()];
                let peer = format!("peer-{i}");
                handles.push(tokio::spawn(async move {
                    let _ = bridge.list_envelope_refs_for_peer(kind, Some(&peer)).await;
                    let _ = bridge.list_holdings(kind).await;
                    let _ = bridge.list_envelope_refs(kind).await;
                }));
            }
            tokio::time::timeout(StdDuration::from_secs(60), async {
                for h in handles {
                    h.await.expect("sweep task joined");
                }
            })
            .await
            .expect("every concurrent sweep completed under the width bound");
            assert!(
                bridge.max_sweeps_in_flight() <= permits,
                "high-water {} exceeded the {permits}-permit bound — a bulk read \
                 was wired past the trait layer (CIRISEdge#531)",
                bridge.max_sweeps_in_flight()
            );
        }
    }
}
