//! Wire-stable message types for the anti-entropy protocol.
//!
//! Five messages, exchanged pairwise between region peers:
//!
//! ```text
//!  A → B   Summary  { kind, refs: [(envelope_hash, seq)] }
//!  A ← B   Diff     { kind, want: [envelope_hash] }     // B asks for what A has that B doesn't
//!  A → B   Deliver  { kind, envelopes: [signed_bytes] }
//!
//!  (and vice versa — both sides initiate Summary in the same round
//!   so the diff is bidirectional)
//! ```
//!
//! A [`FetchMessage`] is the explicit "I want these envelopes by hash"
//! shape, used when a peer learns of envelope hashes via a third
//! channel (e.g. a downstream consumer that needs to chase an unknown
//! reference). The [`SummaryMessage`] / [`DiffMessage`] flow is the
//! steady-state anti-entropy path; [`FetchMessage`] is the on-demand
//! path.
//!
//! A [`PullMessage`] (CIRISEdge#462) is the RECEIVE axis's discovery verb —
//! "which `kind` records do you hold where I am the data-subject or the sender?"
//! It is the SUBJECT-scoped "third channel" `FetchMessage` documents: the
//! responder answers with a [`SummaryMessage`] of the subject's refs and the
//! ordinary Diff/Deliver flow carries the bytes. Unlike anti-entropy (which can
//! only ever converge what a peer *advertises*), a Pull reaches the `SelfOwn`
//! plane no peer advertises — a fedID pulling its own testimony onto a fresh
//! node. See [`PullMessage`] for the entitlement + G2 carve.
//!
//! ## Wire codec
//!
//! Messages serialize via `serde_json` for the v1 protocol. Future
//! versions may upgrade to CBOR or persist's canonical-bytes shape,
//! but JSON keeps the v1 implementation simple and debuggable; the
//! anti-entropy traffic is low-frequency (sync rounds every N seconds
//! per peer-pair, not per-envelope) so the codec efficiency is not
//! a hot path.
//!
//! ## Wire stability
//!
//! Every variant is `#[serde(tag = "type")]` so adding a new
//! `ReplicationMessage` variant doesn't break v1 receivers — they
//! see an unknown tag and refuse the message at the deserializer.
//! Adding a NEW field to an existing message is a non-break (serde
//! defaults the absent field on the receiver side) provided the
//! field is annotated `#[serde(default)]`. Removing or renaming a
//! field IS a break and requires bumping the protocol version (a
//! follow-up adds `protocol_version` to the [`SummaryMessage`]
//! envelope; v1 is implicit version `1`).

use serde::{Deserialize, Serialize};

/// The kinds of envelope the anti-entropy protocol replicates. Each
/// kind corresponds to a separate sync stream so partitions on one
/// kind don't gate convergence on others.
///
/// ## v1 wire-stable taxonomy — aligned 1:1 with persist's
/// `FederationDirectory` `put_*` surface
///
/// Per `FSD/REPLICATION_WIRE_FORMAT_V1.md` §3.3, the ten variants
/// here match persist's ten put_* admit methods exactly (as of
/// persist v4.10.0). `apply_envelope_bytes` dispatches via a simple
/// match on `EnvelopeKind` — no JSON shape sniffing, no schema
/// inference. Each branch deserializes the matching `Signed*Record`
/// and calls the matching put_*.
///
/// | Variant                          | Persist put_*                                       | Substrate ship |
/// |----------------------------------|------------------------------------------------------|----------------|
/// | `Key`                            | `put_public_key(SignedKeyRecord)`                   | v1.0+          |
/// | `Attestation`                    | `put_attestation(SignedAttestation)`                | v1.0+          |
/// | `Revocation`                     | `put_revocation(SignedRevocation)`                  | v1.0+          |
/// | `IdentityOccurrence`             | `put_identity_occurrence(SignedIdentityOccurrence)` | CEG 0.7        |
/// | `Family`                         | `put_family(SignedFamily)`                          | CEG 0.7        |
/// | `Community`                      | `put_community(SignedCommunity)`                    | CEG 0.8        |
/// | `IdentityOccurrenceRevocation`   | `put_identity_occurrence_revocation(...)`           | v4.8.0 (#161)  |
/// | `FamilyMembershipRevocation`     | `put_family_membership_revocation(...)`             | v4.8.0 (#161)  |
/// | `CommunityMembershipRevocation`  | `put_community_membership_revocation(...)`          | v4.8.0 (#161)  |
/// | `LocationProof`                  | `put_location_proof(SignedLocationProof)`           | v4.10.0 (#154) |
///
/// Adding a variant going forward bumps `WIRE_PROTOCOL_VERSION` (see
/// `wire_frame.rs`). Anticipated v2 additions (operational-data CEG
/// envelopes for CIRISRegistry#58 Phase 2 / CIRIS 2.0): `Org`,
/// `User`, `License`, `Partner` or whatever Registry settles on.
///
/// New variants MUST be appended (not inserted) to preserve `Ord` /
/// `Hash` stability on the `BTreeMap<EnvelopeKind, …>` keys
/// `LocalState` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// `federation_keys` — newly-published key registrations.
    /// `put_public_key(SignedKeyRecord)`.
    Key,
    /// `federation_attestations` — trust grants / scores / withdraws /
    /// delegates_to / etc. `put_attestation(SignedAttestation)`.
    Attestation,
    /// `federation_revocations` — key-level revocations with R1/Q1
    /// quorum-merge per CIRISPersist V058.
    /// `put_revocation(SignedRevocation)`.
    Revocation,
    /// `federation_identity_occurrences` — agent / human / partner
    /// occurrence records per CEG 0.7.
    /// `put_identity_occurrence(SignedIdentityOccurrence)`.
    IdentityOccurrence,
    /// `federation_families` — family roster declarations per CEG 0.7.
    /// `put_family(SignedFamily)`.
    Family,
    /// `federation_communities` — community roster declarations per
    /// CEG 0.8. `put_community(SignedCommunity)`.
    Community,
    /// `federation_identity_occurrence_revocations` — Option-A forward-
    /// secrecy primitive per CIRISPersist v4.8.0 (#161).
    /// `put_identity_occurrence_revocation(...)`.
    IdentityOccurrenceRevocation,
    /// `federation_family_membership_revocations` — Option-A forward-
    /// secrecy primitive per CIRISPersist v4.8.0 (#161).
    /// `put_family_membership_revocation(...)`.
    FamilyMembershipRevocation,
    /// `federation_community_membership_revocations` — Option-A
    /// forward-secrecy primitive per CIRISPersist v4.8.0 (#161).
    /// `put_community_membership_revocation(...)`.
    CommunityMembershipRevocation,
    /// `federation_location_proofs` — CEG 0.8 §0.8.1 normative privacy
    /// primitive (H3 rough-only geographic claim, resolution ≤ 7).
    /// CIRISPersist v4.10.0 (#154) ships V068 + `LocationProof` /
    /// `SignedLocationProof` types + `put_location_proof` on all 3
    /// backends + the pure-Rust `h3o` validation helpers
    /// (`validate_location_cell` / `h3_cell_contained`). The substrate's
    /// resolution-≤-7 rejection IS the privacy enforcement — a producer
    /// can't over-share precise location even if client UI gating fails.
    /// `put_location_proof(SignedLocationProof)`.
    LocationProof,
    /// v2 wire (CEG 1.0-RC2 §5.6.8.13 / FSD §5.2) — operational-data
    /// envelope: an `organization` row (public org identity, LWW +
    /// withdrawal-forward-only). PII (`tax_id`, contacts, `metadata`)
    /// stays region-local; never federates. CIRISPersist v5.1.0 ships
    /// `put_organization(SignedOrganization, key_directory, root_stewards)`.
    /// REQUIRES `WIRE_PROTOCOL_VERSION = 0x02`.
    Organization,
    /// v2 wire (CEG 1.0-RC2 §5.6.8.13 / FSD §5.2) — operational-data
    /// envelope: an `org_membership` row (the authz binding —
    /// `user_id`/`org_id`/`role`/`status`; LWW + withdrawal-forward-only).
    /// User PII NEVER federates: only the role binding crosses. CIRISPersist
    /// v5.1.0 ships `put_org_membership(SignedOrgMembership, key_directory,
    /// root_stewards)`. REQUIRES `WIRE_PROTOCOL_VERSION = 0x02`.
    OrgMembership,
    /// v2 wire (CEG 1.0-RC2 §5.6.8.13 / FSD §5.2) — operational-data
    /// envelope: a `partner_record` row (combines old License+Partner;
    /// M-of-N steward quorum + monotonic-fail-secure merge — `revoked` >
    /// `suspended` > `active`). CIRISPersist v5.1.0 ships
    /// `put_partner_record(SignedPartnerRecord, steward_roster)`.
    /// REQUIRES `WIRE_PROTOCOL_VERSION = 0x02`.
    PartnerRecord,
    /// CIRISEdge#311 — `transport_destinations` reachability row
    /// (`TransportDestination`; V078). A member of persist v15.1.0's
    /// `ReplicatedKind::all()`, swept by the unified replication engine as
    /// the `SelfOwn` transport plane: a node publishes its OWN reachable
    /// address(es) so peers can dial it (the occurrence-KEX arc). Unlike the
    /// signed identity kinds this row carries **no signature /
    /// `persist_row_hash`** — it is mutable + disposable reachability, so its
    /// `envelope_hash` uses the JCS basis (`sha256(JCS(record))`) like the v2
    /// operational kinds. A NEW post-v1 tag: `put_transport_destination`.
    /// REQUIRES `WIRE_PROTOCOL_VERSION_V2` (v1-only peers refuse the unknown
    /// tag at serde-decode — the additive-and-safe transition per FSD §3.7).
    TransportDestination,
    /// CIRISEdge#474 / CIRISPersist v31.1.0 (#662) — the accord-quorum-evidence
    /// plane: a `put_accord_proposal` bundle (`proposal` + `participations` +
    /// `evidence_at`) that carries a steward-quorum decision projecting
    /// `RoleWithdrawals` across the federation (`WireTier::FederationOnly`).
    /// UNLIKE every other kind it is **cursor-served, NOT content-hash-indexed**:
    /// a bundle is an aggregate whose hash moves as each participation lands, so
    /// persist deliberately keeps it out of the `signed_wire_index`
    /// ([`Self::persist_index_kind`] returns `None`). It therefore rides the
    /// dedicated cursor path (`CursorPull` → `Deliver`, resume on `evidence_at`),
    /// never Summary/Diff/Fetch, and its RECEIVE gate **re-tallies** against the
    /// receiver's own roster (`apply_replicated_accord_evidence`) rather than
    /// trusting the sender's verdict. A NEW post-v1 tag: v1-only peers serde-reject
    /// it (`min_wire_version` → V2). `list_signed_accord_quorum_evidence_since`.
    AccordQuorumEvidence,
}

impl EnvelopeKind {
    /// All 15 replicated wire kinds, in declaration order. Mirrors persist's
    /// `replication_policy::EnvelopeKind::ALL` (same 15 names/order, pinned by
    /// `REPLICATION_POLICY_HASH`). Basis for the serve/advertise manifest
    /// (CIRISEdge#393 item 3). `AccordQuorumEvidence` (CIRISEdge#474) is appended
    /// last — order is hashed, so it MUST stay at the end.
    pub const ALL: [EnvelopeKind; 15] = [
        Self::Key,
        Self::Attestation,
        Self::Revocation,
        Self::IdentityOccurrence,
        Self::Family,
        Self::Community,
        Self::IdentityOccurrenceRevocation,
        Self::FamilyMembershipRevocation,
        Self::CommunityMembershipRevocation,
        Self::LocationProof,
        Self::Organization,
        Self::OrgMembership,
        Self::PartnerRecord,
        Self::TransportDestination,
        Self::AccordQuorumEvidence,
    ];

    /// CIRISEdge#402/#406 — the finite, self-authenticating **bootstrap** kinds a
    /// fresh peer must deliver to introduce itself into the trust graph AND make
    /// itself attributable:
    /// - `Key` — its own `KeyRecord` (the `owns_key` half of #393 item 1);
    /// - `IdentityOccurrence` — its identity binding;
    /// - `TransportDestination` — its hybrid-signed transport binding, the ONLY
    ///   thing that satisfies #393 **item 2** (`hybrid_transport_binding_exists`).
    ///
    /// These are the ONLY kinds the attribution gate exempts from
    /// `Rooted ∧ owns_key` (CIRISEdge#393/E3). The deadlock the exemption breaks:
    /// a fresh peer is `UnknownKeyId` until its `Key` is admitted, but the `Key`
    /// frame is exactly what admits it; and (CIRISEdge#406) its signed
    /// `TransportDestination` is exactly what item 2 requires, but item 2 would
    /// drop that frame too — the deadlock, once more. Safe because ALL THREE are
    /// hybrid-verified at persist admission (`put_public_key` E2/#502,
    /// `put_identity_occurrence` + `put_signed_transport_destination`,
    /// `signer_acts_for`), so an un-attributed delivery is *verified* at the apply
    /// layer where verification belongs; each grants no trust and is served no
    /// `trace:*` (that plane stays strictly `Rooted ∧ owns_key`-attributed).
    /// Consentable/other-structural planes are NOT bootstrap kinds — the
    /// exemption is exactly these three, a deliberate compile-fenced edit to widen.
    #[must_use]
    pub fn is_bootstrap(self) -> bool {
        matches!(
            self,
            Self::Key | Self::IdentityOccurrence | Self::TransportDestination
        )
    }

    /// CIRISEdge#462 — is this kind answerable by a subject-scoped `Pull` (the
    /// RECEIVE axis)? EXACTLY the five replicated kinds — the persist
    /// `ReplicatedKind` set the bridge's `subject_holdings` sweeps. This is the
    /// single source of truth the initiation loop iterates; it MUST agree with
    /// the `receive` column of
    /// [`crate::replication::serve_policy::serve_advertise_manifest`] (asserted in
    /// that module's `only_the_five_replicated_kinds_answer_a_subject_pull`).
    #[must_use]
    pub fn is_subject_pullable(self) -> bool {
        matches!(
            self,
            Self::Key
                | Self::IdentityOccurrence
                | Self::TransportDestination
                | Self::IdentityOccurrenceRevocation
                | Self::Attestation
        )
    }

    /// CIRISEdge#474 — is this kind served over the dedicated CURSOR path
    /// (`CursorPull` → `Deliver`, resume on `evidence_at`) rather than the
    /// content-hash Summary/Diff/Fetch flow? EXACTLY the kinds with no
    /// `signed_wire_index` entry ([`Self::persist_index_kind`] → None AND not
    /// [`Self::Revocation`], which is index-less but rides `persist_row_hash`).
    /// Currently only [`Self::AccordQuorumEvidence`]; checked over `ALL` in a test
    /// so a future cursor kind is a deliberate widening, never an accident. An
    /// Initiator round for such a kind opens with a `CursorPull`, not a Summary.
    #[must_use]
    pub fn is_cursor_served(self) -> bool {
        matches!(self, Self::AccordQuorumEvidence)
    }

    /// The kinds a subject sweep issues a `Pull` for — the
    /// [`Self::is_subject_pullable`] set, in `ALL` order.
    #[must_use]
    pub fn subject_pullable() -> Vec<EnvelopeKind> {
        Self::ALL
            .into_iter()
            .filter(|k| k.is_subject_pullable())
            .collect()
    }

    /// Stable snake_case wire name for this kind — the manifest/witness key
    /// (CIRISEdge#393 item 3). Stable across releases; a rename is a wire-policy
    /// change that must flip `SERVE_ADVERTISE_POLICY_HASH`.
    #[must_use]
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Attestation => "attestation",
            Self::Revocation => "revocation",
            Self::IdentityOccurrence => "identity_occurrence",
            Self::Family => "family",
            Self::Community => "community",
            Self::IdentityOccurrenceRevocation => "identity_occurrence_revocation",
            Self::FamilyMembershipRevocation => "family_membership_revocation",
            Self::CommunityMembershipRevocation => "community_membership_revocation",
            Self::LocationProof => "location_proof",
            Self::Organization => "organization",
            Self::OrgMembership => "org_membership",
            Self::PartnerRecord => "partner_record",
            Self::TransportDestination => "transport_destination",
            Self::AccordQuorumEvidence => "accord_quorum_evidence",
        }
    }

    /// CIRISEdge#397 / persist v21.2.0 (#507) — the `kind` token persist's
    /// `signed_wire_index` keys on for this kind's content-hash point-read
    /// ([`ciris_persist::federation::FederationDirectory::lookup_signed_record_by_content_hash`]).
    /// This is persist's `replication_policy::EnvelopeKind::as_str` PascalCase
    /// token (`"Key"`, `"Attestation"`, …) — NOT [`Self::as_wire_str`]'s
    /// snake_case. `None` for the two kinds persist deliberately does not index:
    /// [`Self::Revocation`] (its fetch stays on the local cache) and
    /// [`Self::AccordQuorumEvidence`] (a vote-aggregating bundle whose hash moves
    /// as participations land — served by cursor, never by content-hash point-read;
    /// CIRISEdge#474).
    #[must_use]
    pub fn persist_index_kind(self) -> Option<&'static str> {
        Some(match self {
            Self::Key => "Key",
            Self::Attestation => "Attestation",
            // Both are absent from persist's content-hash `signed_wire_index`:
            // Revocation rides `persist_row_hash`; AccordQuorumEvidence rides the
            // cursor path (#474). Neither has a content-hash point-read.
            Self::Revocation | Self::AccordQuorumEvidence => return None,
            Self::IdentityOccurrence => "IdentityOccurrence",
            Self::Family => "Family",
            Self::Community => "Community",
            Self::IdentityOccurrenceRevocation => "IdentityOccurrenceRevocation",
            Self::FamilyMembershipRevocation => "FamilyMembershipRevocation",
            Self::CommunityMembershipRevocation => "CommunityMembershipRevocation",
            Self::LocationProof => "LocationProof",
            Self::Organization => "Organization",
            Self::OrgMembership => "OrgMembership",
            Self::PartnerRecord => "PartnerRecord",
            Self::TransportDestination => "TransportDestination",
        })
    }

    /// The minimum [`crate::replication::wire_frame::WIRE_PROTOCOL_VERSION`]
    /// at which this kind can be exchanged on the wire.
    ///
    /// The 10 v1 kinds (Key through LocationProof) ride at `0x01`. The
    /// 3 v2 operational kinds (Organization / OrgMembership /
    /// PartnerRecord — CEG 1.0-RC2 §5.6.8.13) require `0x02` framing
    /// because v1-only peers don't recognize the new tags and would
    /// reject the body at serde-decode time. Used by
    /// [`crate::replication::wire_frame::wrap_for_kind`] to pick the
    /// outbound version automatically per the FSD §3.7 peer-by-peer
    /// transition path.
    #[must_use]
    pub fn min_wire_version(self) -> u8 {
        match self {
            Self::Key
            | Self::Attestation
            | Self::Revocation
            | Self::IdentityOccurrence
            | Self::Family
            | Self::Community
            | Self::IdentityOccurrenceRevocation
            | Self::FamilyMembershipRevocation
            | Self::CommunityMembershipRevocation
            | Self::LocationProof => crate::replication::wire_frame::WIRE_PROTOCOL_VERSION,
            Self::Organization
            | Self::OrgMembership
            | Self::PartnerRecord
            // #311 — a new post-v1 tag; v1-only peers don't know it and
            // would serde-reject the body, so it rides at V2 framing.
            | Self::TransportDestination
            // #474 — the accord-quorum-evidence plane is likewise a new post-v1
            // tag; v1-only peers serde-reject it, so it rides at V2 framing.
            | Self::AccordQuorumEvidence => {
                crate::replication::wire_frame::WIRE_PROTOCOL_VERSION_V2
            }
        }
    }
}

/// A reference to a single envelope in a peer's local state. The
/// `envelope_hash` is `sha256(canonical_bytes(envelope))` — same shape
/// persist uses for `original_content_hash`. The `seq` is monotonic
/// per (kind, signer) and lets the receiver detect anti-rollback
/// attempts locally before round-tripping to persist's R1/Q1 merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeRef {
    /// 32-byte sha256 of the canonical-bytes form of the envelope.
    pub envelope_hash: [u8; 32],
    /// Per-(kind, signer) monotonic counter. v1 is best-effort —
    /// persist's R1/Q1 merge is the canonical anti-rollback oracle;
    /// this field is a hint for receivers to short-circuit obvious
    /// stale data without paying the merge round-trip.
    pub seq: u64,
}

/// "Here are the envelope hashes I have for `kind`." First message
/// of an anti-entropy round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryMessage {
    pub kind: EnvelopeKind,
    pub refs: Vec<EnvelopeRef>,
}

/// "I want these envelopes." Receiver's response to a `SummaryMessage`
/// — the list of `envelope_hash`es present in the sender's summary
/// but absent from the receiver's local state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffMessage {
    pub kind: EnvelopeKind,
    pub want: Vec<[u8; 32]>,
}

/// "I want these envelopes by hash." Used for on-demand fetch (a
/// consumer learns of a hash via a third channel and asks edge to
/// chase it). The receiver of a `Fetch` MUST NOT speculatively
/// deliver envelopes the requester didn't ask for — anti-entropy
/// uses the Summary/Diff flow for unsolicited convergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessage {
    pub kind: EnvelopeKind,
    pub want: Vec<[u8; 32]>,
}

/// CIRISEdge#462 — the RECEIVE axis's discovery request: a subject-scoped
/// pull. This is the "third channel" [`FetchMessage`] documents but the wire
/// never had — a node asks a peer "which `kind` records do you hold where I am
/// the data-subject or the sender?"
///
/// It is NOT anti-entropy. The want-set it seeds is scoped to a SUBJECT (my own
/// testimony / testimony about me), not to a kind's advertised convergence set —
/// so it reaches the `SelfOwn` plane that `namespace::projection_for` never
/// advertises. A fedID that just claimed a fresh node can pull its own testimony
/// (and a moderation duty conferred on it) that no peer would ever *advertise*.
///
/// The responder answers with an ordinary [`SummaryMessage`] of the refs it
/// holds for the subject — projection-gated exactly as its advertise path would
/// be, with peer-authored `capacity:*` scores about the subject WITHHELD (the G2
/// self-revocation-hole carve). The existing Summary → Diff → Deliver flow then
/// carries the bytes unchanged; the responder's per-record serve gate
/// (`fetch_envelope`) still backs every byte, so a Pull can only surface rows
/// the requester was already entitled to receive — it widens nothing.
///
/// The requester MUST be admitted as `subject_key_id` (or its owner). Like every
/// other message, a Pull is scoped to ONE `kind` (one Session/round per kind); a
/// subject sweep issues one Pull per replicated kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullMessage {
    /// The kind this pull is scoped to.
    pub kind: EnvelopeKind,
    /// The fedID whose testimony is requested — `ci_axes.data_subject` (records
    /// about it) and `ci_axes.sender` (records by it) both resolve to this id.
    pub subject_key_id: String,
}

/// CIRISEdge#474 — the accord-quorum-evidence CURSOR request. The plane has no
/// content-hash `signed_wire_index` (its bundle hash moves as participations
/// land), so it CANNOT ride the Summary/Diff/Fetch convergence flow like every
/// other kind, nor the #462 subject `Pull` (which resolves to a content-hash
/// `Summary`). Instead the requester names a resume watermark and the responder
/// answers DIRECTLY with a [`DeliverMessage`] of the bundles past it — ordered
/// `(evidence_at, proposal_digest)`, served by
/// [`ciris_persist::federation::FederationDirectory::list_signed_accord_quorum_evidence_since`].
///
/// `since` is the requester's high-water `evidence_at`: the responder returns
/// bundles with `evidence_at > since` (`None` = from the beginning). The receiver
/// RE-TALLIES each bundle against its own roster on apply, so pulling from `None`
/// every round is always safe (idempotent) — the cursor is an optimization, not a
/// trust input. A post-v1 verb, exactly like `Pull`: v1 peers serde-refuse the
/// unknown `type` tag, coordinated by the `SERVE_ADVERTISE_POLICY_HASH` re-pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorPullMessage {
    /// The kind this cursor pull is scoped to — currently only
    /// [`EnvelopeKind::AccordQuorumEvidence`].
    pub kind: EnvelopeKind,
    /// Resume watermark: the responder returns records with `evidence_at`
    /// strictly greater than this. `None` pulls from the beginning.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<chrono::DateTime<chrono::Utc>>,
}

/// "Here are the bytes." Wraps the requested envelopes' raw signed-
/// bytes form (the same shape `put_*` admits expect on the receiver's
/// persist side). Order is unspecified; the receiver MUST validate
/// each envelope's signature + canonical-bytes hash before applying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverMessage {
    pub kind: EnvelopeKind,
    /// Each entry is the byte-exact signed envelope as it would have
    /// been admitted by the original signer's local `put_*` call.
    pub envelopes: Vec<Vec<u8>>,
}

/// The protocol's top-level message type — what flows on the wire
/// between region peers. `#[serde(tag = "type")]` so a future variant
/// is transparent to v1 receivers (they refuse on unknown tag, NOT
/// silent ignore).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplicationMessage {
    Summary(SummaryMessage),
    Diff(DiffMessage),
    Fetch(FetchMessage),
    Deliver(DeliverMessage),
    /// CIRISEdge#462 — subject-scoped RECEIVE-axis discovery. A post-v1 verb: v1
    /// peers serde-refuse the unknown `type` tag (they do NOT silently ignore
    /// it), so it is a genuine wire-compat event, coordinated by the
    /// [`crate::replication::serve_policy::SERVE_ADVERTISE_POLICY_HASH`] re-pin.
    Pull(PullMessage),
    /// CIRISEdge#474 — the accord-quorum-evidence CURSOR request (resume on
    /// `evidence_at`). Like `Pull`, a post-v1 verb v1 peers serde-refuse; the
    /// responder answers with a `Deliver` of the bundles past the watermark.
    CursorPull(CursorPullMessage),
}

impl ReplicationMessage {
    /// The `EnvelopeKind` this message is about. All four message
    /// variants (Summary / Diff / Fetch / Deliver) carry an inner
    /// `kind` field — used by
    /// [`crate::replication::wire_frame::wrap_for_kind`] to pick the
    /// outbound wire-protocol version (v1 for the 10 trust kinds, v2
    /// for the 3 v2 operational kinds per FSD §3.7 / §5.2).
    #[must_use]
    pub fn kind(&self) -> EnvelopeKind {
        match self {
            Self::Summary(m) => m.kind,
            Self::Diff(m) => m.kind,
            Self::Fetch(m) => m.kind,
            Self::Deliver(m) => m.kind,
            Self::Pull(m) => m.kind,
            Self::CursorPull(m) => m.kind,
        }
    }

    /// Serialize to JSON bytes for transport. Returns the bytes ready
    /// to hand to `Transport::send`.
    pub fn to_bytes(&self) -> Vec<u8> {
        // serde_json::to_vec on an enum it knows the shape of cannot
        // fail; unwrap is safe.
        serde_json::to_vec(self).expect("ReplicationMessage serialization cannot fail")
    }

    /// Parse from on-wire JSON bytes. Returns `Err` on JSON parse
    /// failure or unknown tag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|e| ProtocolError::Decode(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("replication message decode failed: {0}")]
    Decode(String),
    /// The wire frame carried a version byte the local code can't
    /// speak. The frame's MAG prefix asserted it was a replication
    /// frame, but the version byte was outside the locally-supported
    /// set (currently only `WIRE_PROTOCOL_VERSION = 0x01`). Surfaced
    /// by `wire_frame::try_unwrap`; the caller logs + drops.
    #[error("unknown replication wire-protocol version: {0:#x}")]
    UnknownVersion(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xFF).unwrap().wrapping_mul(seed.max(1));
        }
        h
    }

    /// Round-trip — JSON-encoded then parsed yields the same value.
    #[test]
    fn summary_round_trips_via_json() {
        let m = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Attestation,
            refs: vec![
                EnvelopeRef {
                    envelope_hash: fake_hash(1),
                    seq: 100,
                },
                EnvelopeRef {
                    envelope_hash: fake_hash(2),
                    seq: 101,
                },
            ],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn diff_round_trips() {
        let m = ReplicationMessage::Diff(DiffMessage {
            kind: EnvelopeKind::Revocation,
            want: vec![fake_hash(3)],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn fetch_round_trips() {
        let m = ReplicationMessage::Fetch(FetchMessage {
            kind: EnvelopeKind::Key,
            want: vec![fake_hash(4), fake_hash(5)],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn deliver_round_trips() {
        let m = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    /// CIRISEdge#462 — the subject-scoped Pull verb round-trips, and its wire
    /// tag is the snake_case `pull`.
    #[test]
    fn pull_round_trips() {
        let m = ReplicationMessage::Pull(PullMessage {
            kind: EnvelopeKind::Attestation,
            subject_key_id: "eric-moore-v2-portable-f34de31d8c21".to_string(),
        });
        let bytes = m.to_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""type":"pull""#), "pull wire tag: {s}");
        assert!(
            s.contains("eric-moore-v2-portable-f34de31d8c21"),
            "subject: {s}"
        );
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
        // The verb carries its kind so wire-framing picks the version like any
        // other message.
        assert_eq!(parsed.kind(), EnvelopeKind::Attestation);
    }

    /// CIRISEdge#474 — the `CursorPull` verb round-trips on the wire (snake_case
    /// `cursor_pull` tag), carries its kind for framing, and omits `since` when
    /// `None` (the stateless pull-all case) so the wire stays compact.
    #[test]
    fn cursor_pull_round_trips() {
        let m = ReplicationMessage::CursorPull(CursorPullMessage {
            kind: EnvelopeKind::AccordQuorumEvidence,
            since: None,
        });
        let bytes = m.to_bytes();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(
            s.contains(r#""type":"cursor_pull""#),
            "cursor_pull wire tag: {s}"
        );
        assert!(
            !s.contains("since"),
            "None `since` is skipped on the wire: {s}"
        );
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
        assert_eq!(parsed.kind(), EnvelopeKind::AccordQuorumEvidence);
        // A v2-framed kind — v1-only peers serde-refuse the tag.
        assert_eq!(
            parsed.kind().min_wire_version(),
            crate::replication::wire_frame::WIRE_PROTOCOL_VERSION_V2
        );
    }

    /// CIRISEdge#474 — `is_cursor_served` is EXACTLY `AccordQuorumEvidence`,
    /// checked over ALL so a future cursor kind is a deliberate widening. It agrees
    /// with `persist_index_kind() == None` (no content-hash index) — but NOT with
    /// `Revocation`, which is also index-less yet rides `persist_row_hash`, not the
    /// cursor path.
    #[test]
    fn is_cursor_served_is_exactly_accord_quorum_evidence() {
        for kind in EnvelopeKind::ALL {
            assert_eq!(
                kind.is_cursor_served(),
                matches!(kind, EnvelopeKind::AccordQuorumEvidence),
                "{kind:?}: cursor-served iff it is AccordQuorumEvidence"
            );
        }
        // The one cursor kind is unindexed, v2-framed, and NOT subject-pullable.
        assert!(EnvelopeKind::AccordQuorumEvidence
            .persist_index_kind()
            .is_none());
        assert!(!EnvelopeKind::AccordQuorumEvidence.is_subject_pullable());
        assert_eq!(
            EnvelopeKind::AccordQuorumEvidence.as_wire_str(),
            "accord_quorum_evidence"
        );
        // Revocation is index-less but is NOT cursor-served (different wire).
        assert!(EnvelopeKind::Revocation.persist_index_kind().is_none());
        assert!(!EnvelopeKind::Revocation.is_cursor_served());
    }

    /// CIRISEdge#462 — `is_subject_pullable` is EXACTLY the five replicated kinds
    /// (the persist `ReplicatedKind` set), checked over ALL 14 so a new pullable
    /// kind must be a deliberate edit here. MUST agree with the serve-policy
    /// `receive` witness.
    #[test]
    fn is_subject_pullable_is_exactly_the_five_replicated_kinds() {
        for kind in EnvelopeKind::ALL {
            let expected = matches!(
                kind,
                EnvelopeKind::Key
                    | EnvelopeKind::IdentityOccurrence
                    | EnvelopeKind::TransportDestination
                    | EnvelopeKind::IdentityOccurrenceRevocation
                    | EnvelopeKind::Attestation
            );
            assert_eq!(
                kind.is_subject_pullable(),
                expected,
                "{kind:?}: pullable iff it is one of the five replicated kinds"
            );
        }
        assert_eq!(EnvelopeKind::subject_pullable().len(), 5);
        // The key-level Revocation plane is NOT subject-pullable (not a
        // ReplicatedKind — it rides the persist_row_hash wire, no subject index).
        assert!(!EnvelopeKind::Revocation.is_subject_pullable());
    }

    /// Unknown tag refused — wire-stability guarantee.
    #[test]
    fn unknown_tag_refused() {
        let raw = br#"{"type":"hostile_takeover","payload":42}"#;
        let r = ReplicationMessage::from_bytes(raw);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// Malformed JSON refused.
    #[test]
    fn malformed_json_refused() {
        let r = ReplicationMessage::from_bytes(b"{not json");
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// All ten `EnvelopeKind` variants round-trip via JSON — kind
    /// values are wire-load-bearing per FSD §3.3.
    #[test]
    fn envelope_kind_wire_values_are_stable() {
        let cases = [
            (EnvelopeKind::Key, "key"),
            (EnvelopeKind::Attestation, "attestation"),
            (EnvelopeKind::Revocation, "revocation"),
            (EnvelopeKind::IdentityOccurrence, "identity_occurrence"),
            (EnvelopeKind::Family, "family"),
            (EnvelopeKind::Community, "community"),
            (
                EnvelopeKind::IdentityOccurrenceRevocation,
                "identity_occurrence_revocation",
            ),
            (
                EnvelopeKind::FamilyMembershipRevocation,
                "family_membership_revocation",
            ),
            (
                EnvelopeKind::CommunityMembershipRevocation,
                "community_membership_revocation",
            ),
            (EnvelopeKind::LocationProof, "location_proof"),
        ];
        for (kind, wire) in cases {
            let m = ReplicationMessage::Summary(SummaryMessage { kind, refs: vec![] });
            let bytes = m.to_bytes();
            let s = std::str::from_utf8(&bytes).unwrap();
            assert!(s.contains(wire), "expected `{wire}` in {s}");
            assert_eq!(ReplicationMessage::from_bytes(&bytes).unwrap(), m);
        }
    }

    /// CIRISEdge#402/#406 — `is_bootstrap` is EXACTLY
    /// `{Key, IdentityOccurrence, TransportDestination}`. Checked over ALL 14
    /// kinds so widening the attribution carve-out can't slip in unnoticed: a new
    /// bootstrap kind must be a deliberate edit here.
    #[test]
    fn is_bootstrap_is_exactly_the_three_bootstrap_kinds() {
        for kind in EnvelopeKind::ALL {
            let expected = matches!(
                kind,
                EnvelopeKind::Key
                    | EnvelopeKind::IdentityOccurrence
                    | EnvelopeKind::TransportDestination
            );
            assert_eq!(
                kind.is_bootstrap(),
                expected,
                "{kind:?}: is_bootstrap must be true iff Key/IdentityOccurrence/TransportDestination",
            );
        }
        // The load-bearing E3 negative: the trace-bearing plane is never bootstrap.
        assert!(!EnvelopeKind::Attestation.is_bootstrap());
    }

    /// Wire-stability sanity: confirm no two kinds collide on their
    /// serde rename. Catches accidental duplicates if a future
    /// variant is added with a typo.
    #[test]
    fn envelope_kind_wire_values_are_unique() {
        use std::collections::HashSet;
        let kinds = [
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
        ];
        let wires: HashSet<String> = kinds
            .iter()
            .map(|k| serde_json::to_string(k).unwrap())
            .collect();
        assert_eq!(wires.len(), kinds.len(), "wire-name collision detected");
    }
}
