//! CIRISEdge#393 (E3, item 3) — the SERVE/ADVERTISE policy manifest: edge's
//! responder half of the Registry-of-Record contract.
//!
//! persist owns the APPLY policy for all 14 replicated kinds and exports it as
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
    //   - `per_record_projection` — persist `projection_for` decides per row
    //     (SelfOwn / Cohort / Global from the record's own dimension/cohort_scope).
    //   - `cohort` / `global` — the operator cohort set / the whole plane.
    //   - `bulk_since` — the paginated since-cursor operational reads.
    // `serve`: `public` (public signed envelope) or a `capability:*` gate.
    let (advertise, serve) = match kind {
        EnvelopeKind::Key
        | EnvelopeKind::IdentityOccurrence
        | EnvelopeKind::TransportDestination
        | EnvelopeKind::IdentityOccurrenceRevocation
        | EnvelopeKind::Revocation => ("per_record_projection", "public"),
        // E3: the trace plane is the sole capability-gated serve path.
        EnvelopeKind::Attestation => (
            "per_record_projection",
            "trace:* → capability:infra:serve; else public",
        ),
        EnvelopeKind::Family | EnvelopeKind::Community | EnvelopeKind::LocationProof => {
            ("cohort", "public")
        }
        EnvelopeKind::FamilyMembershipRevocation | EnvelopeKind::CommunityMembershipRevocation => {
            ("global", "public")
        }
        EnvelopeKind::Organization | EnvelopeKind::OrgMembership | EnvelopeKind::PartnerRecord => {
            ("bulk_since", "public")
        }
    };
    serde_json::json!({ "kind": kind.as_wire_str(), "advertise": advertise, "serve": serve })
}

/// The canonical serve/advertise policy manifest (mirrors persist's
/// `replication_policy_manifest` shape). JCS-canonicalized + hashed for the
/// cross-repo drift witness.
#[must_use]
pub fn serve_advertise_manifest() -> serde_json::Value {
    serde_json::json!({
        "contract": "replication_serve_advertise_policy",
        "version": 1,
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
/// (advertise scope or serve gate for ANY of the 14 kinds) flips this — a
/// deliberate, reviewed re-pin, visible to CIRISServer which pins it alongside
/// persist's `REPLICATION_POLICY_HASH`. See CIRISEdge#393 §4.2/§4.3.
pub const SERVE_ADVERTISE_POLICY_HASH: &str =
    "79f5c63a4e4945995f9beba6f3746c380e0bee3fe805866ebfaff34ac6d7c9ff";

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
