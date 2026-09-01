//! CIRISEdge#393 (E3, item 3) — the SERVE/ADVERTISE policy manifest: edge's
//! responder half of the Registry-of-Record contract.
//!
//! persist owns the APPLY policy for all 15 replicated kinds and exports it as
//! `ciris_persist::federation::replication_policy::REPLICATION_POLICY_HASH`
//! (pinned by edge in `lib.rs`). Edge owns the **serve/advertise** half — for
//! each kind, WHICH peers it advertises to (the projection scope) and WHETHER
//! serving is capability-gated. This module exports that half as a canonical
//! manifest + a sha256 const, exactly like [`crate::WIRE_VOCABULARY_HASH`], so
//! CIRISServer pins BOTH hashes (`tests/release_gates/`) and any drift in edge's
//! responder policy — e.g. silently un-gating the `trace:*` serve path — is a
//! build failure across the triple, not a quiet confidentiality regression.
//!
//! The one load-bearing fact this witnesses is E3's closure: `trace:*`
//! attestations serve ONLY to `capability:infra:serve` recipients; every other
//! kind serves public (public signed envelopes). A change to that column flips
//! the hash.

use super::protocol::EnvelopeKind;

/// The per-kind serve/advertise policy edge (the responder) enforces.
fn policy_for(kind: EnvelopeKind) -> serde_json::Value {
    // `advertise`: the projection scope the bridge fans a kind out over.
    //   - `per_record_projection` — the bridge decides PER ROW (the Attestation
    //     plane's `attestation_projection`: SelfOwn / Cohort / Capability /
    //     Subject / Global from the record's own dimension/cohort_scope).
    //   - `self_own` / `cohort` / `global` — ONE constant projection for the
    //     whole plane (the node's own publish set / the operator cohort set /
    //     the widest own∪cohort set).
    //   - `bulk_since` — the paginated since-cursor operational reads.
    //   - `cursor:evidence_at` — the dedicated cursor plane (never
    //     content-hash-advertised).
    // `serve`: `public` (public signed envelope) or a `capability:*` gate.
    let (advertise, serve) = match kind {
        // These five planes do NOT consult a per-record projection: the bridge
        // hardcodes ONE `Projection` constant per plane (`list_keys` /
        // `list_identity_occurrences` / `list_transport_destinations` →
        // `Projection::SelfOwn`; `list_identity_occurrence_revocations` /
        // `list_revocations` → `Projection::Global`, the #311 tombstone rule).
        // The manifest states that truth — the earlier `per_record_projection`
        // claim here described a mechanism these planes never had.
        EnvelopeKind::Key
        | EnvelopeKind::IdentityOccurrence
        | EnvelopeKind::TransportDestination => ("self_own", "public"),
        // E3: the trace plane is the sole capability-gated serve path — and the
        // ONE plane whose projection is genuinely decided per row.
        EnvelopeKind::Attestation => (
            "per_record_projection",
            "trace:* → capability:infra:serve; else public",
        ),
        EnvelopeKind::Family | EnvelopeKind::Community | EnvelopeKind::LocationProof => {
            ("cohort", "public")
        }
        // The four `global` planes: the two tombstone planes above join the two
        // membership-revocation planes here — all four fan out over the
        // hardcoded widest own∪cohort set (`Projection::Global`).
        EnvelopeKind::IdentityOccurrenceRevocation
        | EnvelopeKind::Revocation
        | EnvelopeKind::FamilyMembershipRevocation
        | EnvelopeKind::CommunityMembershipRevocation => ("global", "public"),
        EnvelopeKind::Organization | EnvelopeKind::OrgMembership | EnvelopeKind::PartnerRecord => {
            ("bulk_since", "public")
        }
        // CIRISEdge#474 — the accord-quorum-evidence plane rides the dedicated
        // CURSOR path (`CursorPull` → `Deliver`, resume on `evidence_at`), NOT the
        // content-hash Summary/Diff/Fetch flow (`persist_index_kind` → None). The
        // bundle is a public `FederationOnly`-tier record — no capability gate.
        EnvelopeKind::AccordQuorumEvidence => ("cursor:evidence_at", "public"),
    };
    // CIRISEdge#462 — `receive`: whether this kind answers a subject-scoped Pull
    // (the RECEIVE axis), and under what rule. The FIVE replicated kinds are
    // subject-pullable; entitlement is FAIL-CLOSED to the subject itself, plus
    // CIRISEdge#552's own-record arm on the four unconditionally-`public`
    // planes (bounded by the `self_own` advertise projection — see
    // `EnvelopeKind::is_public_subject_pull`); the
    // Attestation plane sweeps BOTH testimonial axes with the G2 score carve;
    // every other kind is NOT subject-pullable (`none`). This column is the
    // coordinated-cut witness CIRISServer pins alongside `serve`.
    let receive = match kind {
        // CIRISEdge#552 — on these four planes a Pull is also answered when the
        // SUBJECT IS THE RESPONDING NODE ITSELF, which is exactly what the
        // `self_own` advertise projection already hands every peer. Not "any
        // attributed requester for any subject": `subject_holdings_inner` does
        // an arbitrary directory lookup, so that would make a body-holding
        // server an address-book oracle for subjects it never advertised.
        // Derived from `is_public_subject_pull` (test-locked below).
        EnvelopeKind::Key
        | EnvelopeKind::IdentityOccurrence
        | EnvelopeKind::TransportDestination
        | EnvelopeKind::IdentityOccurrenceRevocation => {
            "subject_pull:data_subject+own_record; within self_own projection"
        }
        EnvelopeKind::Attestation => {
            "subject_pull:data_subject+sender; subject-only; \
             non-retainable scores-plane rows carved on data_subject axis \
             (G2: attestation_type==scores AND !persist::is_subject_retainable(dimension))"
        }
        EnvelopeKind::Revocation
        | EnvelopeKind::Family
        | EnvelopeKind::Community
        | EnvelopeKind::LocationProof
        | EnvelopeKind::FamilyMembershipRevocation
        | EnvelopeKind::CommunityMembershipRevocation
        | EnvelopeKind::Organization
        | EnvelopeKind::OrgMembership
        | EnvelopeKind::PartnerRecord => "none",
        // CIRISEdge#474 — NOT a subject-scoped Pull. It is received over the
        // dedicated cursor path and its RECEIVE gate re-tallies against the
        // receiver's own roster rather than trusting the sender's verdict; the
        // value stays out of the `subject_pull:*` namespace by construction.
        EnvelopeKind::AccordQuorumEvidence => {
            "cursor_pull:evidence_at; re-tally admit (apply_replicated_accord_evidence)"
        }
    };
    serde_json::json!({
        "kind": kind.as_wire_str(),
        "advertise": advertise,
        "serve": serve,
        "receive": receive,
    })
}

/// The canonical serve/advertise policy manifest (mirrors persist's
/// `replication_policy_manifest` shape). JCS-canonicalized + hashed for the
/// cross-repo drift witness.
#[must_use]
pub fn serve_advertise_manifest() -> serde_json::Value {
    serde_json::json!({
        // CIRISEdge#462 — v2 adds the per-kind `receive` (subject-Pull) axis.
        "contract": "replication_serve_advertise_policy",
        "version": 2,
        "policies": EnvelopeKind::ALL
            .iter()
            .map(|k| policy_for(*k))
            .collect::<Vec<_>>(),
    })
}

/// sha256(JCS(manifest)), hex — the responder half of the drift witness.
#[must_use]
pub fn serve_advertise_policy_sha256() -> String {
    use sha2::Digest as _;
    let canonical = ciris_verify_core::jcs::canonicalize(&serve_advertise_manifest())
        .expect("serve/advertise manifest canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The pinned serve/advertise policy hash. A change to edge's responder policy
/// (advertise scope or serve gate for ANY of the 15 kinds) flips this — a
/// deliberate, reviewed re-pin, visible to CIRISServer which pins it alongside
/// persist's `REPLICATION_POLICY_HASH`. See CIRISEdge#393 §4.2/§4.3.
// v16.0.0 — re-pinned: the Attestation `receive` carve text now describes the
// retainability-allowlist rule (scores-plane, `!is_subject_retainable(dimension)`),
// replacing the stale `consent_gated_claim` prose the #635 carve had left behind
// (Codex on #470). CIRISServer re-pins from 049e71ef… to this value.
// v16.3.0 (CIRISEdge#474) — re-pinned: the 15th kind `accord_quorum_evidence` is
// appended (advertise `cursor:evidence_at`, serve `public`, receive
// `cursor_pull:evidence_at` — the cursor plane, NOT a subject Pull). CIRISServer
// re-pins from 6f683311… to this value alongside persist's v31 REPLICATION_POLICY_HASH.
// (was 328d73b0…)
//
// serve-policy audit — re-pinned: the `advertise` column now states the TRUTH
// for the five planes the bridge fans out over ONE hardcoded `Projection`
// constant (they never consulted a per-record projection): Key /
// IdentityOccurrence / TransportDestination → `self_own`,
// IdentityOccurrenceRevocation / Revocation → `global` (the #311 tombstone
// rule). `per_record_projection` now names only the Attestation plane, the one
// whose projection is genuinely decided per row. NO serve-path behavior
// changed — this is the manifest catching up to the code it witnesses.
// **CIRISServer must mirror**: re-pin from 328d73b0… to 20499cab….
//
// CIRISEdge#552 — RE-PINNED, 20499cab… → e54c5677…. On the four
// unconditionally-`public` planes (Key, IdentityOccurrence,
// TransportDestination, IdentityOccurrenceRevocation) a subject Pull is now
// ALSO answered when the subject is the RESPONDING NODE ITSELF.
//
// Bounded deliberately at the node's own record, because `serve: public` and
// `advertise: self_own` answer different questions. `public` means no
// capability gate once a record reaches you; `self_own` decides which records
// reach you at all. `subject_holdings_inner` does an arbitrary directory
// lookup, so answering any attributed requester about any subject would let a
// peer probe identifiers for third-party keys and routes that never appeared in
// its Summaries — a body-holding server as address-book oracle, and the end of
// the opaque-directory property. The own-record arm stays inside what
// `self_own` already advertises, so it is disclosure-neutral in fact.
//
// It recovers "you signed a row I cannot verify — send me your key". A
// THIRD-PARTY signer stays unfetchable by identifier; that needs a separately
// authorized, rate-limited resolver. `Attestation` is untouched.
// **CIRISServer must mirror this pin.**
pub const SERVE_ADVERTISE_POLICY_HASH: &str =
    "e54c56775e8d56442f9fdbaa0346397cdc169e7cc6237f5a6fe71681710dbf25";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serve_advertise_policy_hash_pinned() {
        assert_eq!(
            serve_advertise_policy_sha256(),
            SERVE_ADVERTISE_POLICY_HASH,
            "edge's serve/advertise responder policy changed — re-review it (esp. the \
             trace:* serve gate), then re-pin deliberately (CIRISEdge#393 §4.2). \
             CIRISServer pins this alongside persist's REPLICATION_POLICY_HASH.",
        );
    }

    /// CIRISEdge#462 — the RECEIVE axis witness, DERIVED from the protocol
    /// predicate: the manifest's `subject_pull:*` kinds are exactly
    /// `EnvelopeKind::is_subject_pullable` over `ALL` (wire names via
    /// `as_wire_str`, in `ALL` order). This is what makes the doc claim on
    /// `is_subject_pullable` true: widening the predicate reds this test until
    /// the manifest column moves (and the pinned hash flips deliberately) —
    /// the earlier hardcoded 5-string vec asserted nothing about the predicate.
    #[test]
    fn only_the_five_replicated_kinds_answer_a_subject_pull() {
        let manifest = serve_advertise_manifest();
        let policies = manifest["policies"].as_array().unwrap();
        let pullable: Vec<&str> = policies
            .iter()
            .filter(|p| p["receive"].as_str().unwrap().starts_with("subject_pull"))
            .map(|p| p["kind"].as_str().unwrap())
            .collect();
        let expected: Vec<&str> = EnvelopeKind::ALL
            .into_iter()
            .filter(|k| k.is_subject_pullable())
            .map(EnvelopeKind::as_wire_str)
            .collect();
        assert_eq!(
            pullable, expected,
            "the manifest's subject_pull kinds must be EXACTLY \
             EnvelopeKind::is_subject_pullable over ALL (RECEIVE axis)"
        );
        assert_eq!(expected.len(), 5, "the five replicated kinds");
        // The Attestation plane is the one that sweeps both axes + carves scores.
        let att = policies
            .iter()
            .find(|p| p["kind"] == "attestation")
            .unwrap();
        let recv = att["receive"].as_str().unwrap();
        assert!(recv.contains("data_subject+sender"), "both axes: {recv}");
        assert!(recv.contains("G2"), "the score carve is witnessed: {recv}");
    }

    /// CIRISEdge#474 — the cursor-plane witness, DERIVED from the protocol
    /// predicate: for EVERY kind in `ALL`, its manifest row is a cursor plane
    /// (advertise `cursor:evidence_at`, receive `cursor_pull:*`, serve
    /// `public`) iff `is_cursor_served` says so. Adding a cursor kind
    /// therefore reds this module until the manifest moves — the earlier
    /// version looked up one hardcoded row and never consulted the predicate.
    #[test]
    fn accord_quorum_evidence_is_a_public_cursor_plane() {
        let manifest = serve_advertise_manifest();
        let policies = manifest["policies"].as_array().unwrap();
        for kind in EnvelopeKind::ALL {
            let row = policies
                .iter()
                .find(|p| p["kind"] == kind.as_wire_str())
                .unwrap_or_else(|| panic!("{kind:?} missing from the manifest"));
            let advertise = row["advertise"].as_str().unwrap();
            let recv = row["receive"].as_str().unwrap();
            assert_eq!(
                advertise == "cursor:evidence_at",
                kind.is_cursor_served(),
                "{kind:?}: cursor advertise cell iff is_cursor_served"
            );
            assert_eq!(
                recv.starts_with("cursor_pull:"),
                kind.is_cursor_served(),
                "{kind:?}: cursor_pull receive cell iff is_cursor_served"
            );
            if kind.is_cursor_served() {
                assert_eq!(row["serve"], "public");
                assert!(
                    !recv.starts_with("subject_pull"),
                    "{kind:?}: NOT a subject pull — stays out of the five: {recv}"
                );
                assert!(
                    !row["serve"].as_str().unwrap().contains("capability:"),
                    "the cursor plane is public, never capability-gated"
                );
            }
        }
        // The predicate currently names exactly one cursor plane.
        assert!(EnvelopeKind::AccordQuorumEvidence.is_cursor_served());
    }

    /// CIRISEdge#552 — the RECEIVE cell's entitlement is DERIVED from
    /// `is_public_subject_pull`, not written twice.
    ///
    /// The manifest is the artifact CIRISServer pins, and the gate in
    /// `subject_holdings` reads the predicate. If those two could drift, the
    /// pinned witness would attest to an entitlement the code does not enforce
    /// — the manifest describing a mechanism the planes never had, which is the
    /// error the `per_record_projection` cell had to be corrected for.
    #[test]
    fn the_public_pull_cell_is_derived_from_the_predicate() {
        let manifest = serve_advertise_manifest();
        for policy in manifest["policies"].as_array().unwrap() {
            let wire = policy["kind"].as_str().unwrap();
            let kind = EnvelopeKind::ALL
                .into_iter()
                .find(|k| k.as_wire_str() == wire)
                .expect("every manifest row names a real kind");
            let recv = policy["receive"].as_str().unwrap();
            assert_eq!(
                recv.contains("own_record"),
                kind.is_public_subject_pull(),
                "{kind:?}: the manifest's receive cell and \
                 is_public_subject_pull disagree — the pinned witness would \
                 attest to an entitlement the gate does not enforce"
            );
        }
    }

    /// CIRISEdge#393 item 3 — the manifest's columns are TEST-LOCKED to the
    /// `protocol.rs` predicates over `EnvelopeKind::ALL`: the manifest covers
    /// exactly `ALL` (in order), and each row's `receive` cell agrees with
    /// `is_subject_pullable` / `is_cursor_served` — `none` exactly when
    /// neither holds. So a predicate edit in protocol.rs reds THIS module
    /// until the manifest (and `SERVE_ADVERTISE_POLICY_HASH`) move
    /// deliberately, and a manifest edit that contradicts the predicates
    /// cannot land at all: the columns can no longer drift from the code that
    /// enforces them.
    #[test]
    fn manifest_columns_are_derived_from_the_protocol_predicates() {
        let manifest = serve_advertise_manifest();
        let policies = manifest["policies"].as_array().unwrap();
        assert_eq!(
            policies.len(),
            EnvelopeKind::ALL.len(),
            "one manifest row per kind in ALL"
        );
        for (row, kind) in policies.iter().zip(EnvelopeKind::ALL) {
            assert_eq!(
                row["kind"],
                kind.as_wire_str(),
                "manifest rows ride in ALL order (the order is hashed)"
            );
            let recv = row["receive"].as_str().unwrap();
            assert_eq!(
                recv.starts_with("subject_pull:"),
                kind.is_subject_pullable(),
                "{kind:?}: receive is subject_pull:* iff is_subject_pullable"
            );
            assert_eq!(
                recv.starts_with("cursor_pull:"),
                kind.is_cursor_served(),
                "{kind:?}: receive is cursor_pull:* iff is_cursor_served"
            );
            if !kind.is_subject_pullable() && !kind.is_cursor_served() {
                assert_eq!(
                    recv, "none",
                    "{kind:?}: neither predicate holds → the receive cell is `none`"
                );
            }
        }
    }

    /// The load-bearing E3 fact must hold in the manifest: exactly ONE kind is
    /// capability-gated (Attestation's trace:* path), the rest public.
    #[test]
    fn only_the_trace_attestation_plane_is_capability_gated() {
        let manifest = serve_advertise_manifest();
        let policies = manifest["policies"].as_array().unwrap();
        let gated: Vec<&str> = policies
            .iter()
            .filter(|p| p["serve"].as_str().unwrap().contains("capability:"))
            .map(|p| p["kind"].as_str().unwrap())
            .collect();
        assert_eq!(
            gated,
            vec!["attestation"],
            "E3: only the attestation plane's trace:* serve path is capability-gated",
        );
    }
}
