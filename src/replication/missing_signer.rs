//! CIRISEdge#552 (B) — resolving the one dependency hash-first cannot hold.
//!
//! # Why this exists
//!
//! The dependency-closure analysis for #552 found that `Key` is the root of
//! every admission's closure: persist's shared ingest gate resolves the signer's
//! registered pubkeys via `lookup_public_key` before verifying anything —
//! `attesting_key_id` for a row, `revoking_key_id` for a revocation. So NO plane
//! admits while its signer's Key body is absent.
//!
//! Today that resolves itself: the bridge classifies `UnverifiableSignature` as
//! TRANSIENT precisely because *"the scrub key is itself a Key-plane row that
//! replicates, so this is ordinary bootstrap ordering"* — the key arrives on its
//! own and the backoff retry admits the row.
//!
//! Under hash-first for `Key` it never arrives, and the retry spins forever. A
//! revocation whose revoker is unknown is then permanently unadmittable — which
//! is a kill order that does not land, defeating #553 through the plane it
//! depends on rather than through itself.
//!
//! # The resolution, and what it deliberately does NOT do
//!
//! It does **not** put a network fetch on the admission path. Admission stays
//! local and still fails transient; this only records WHICH key was missing, so
//! something out of band can pull it. The existing #544 backoff then re-offers
//! the row and it admits normally.
//!
//! That ordering matters: the revocation admission path is the one path that
//! must never depend on a peer answering.
//!
//! No new wire verb and nothing from persist — `PullMessage { kind: Key,
//! subject_key_id }` is already "give me the Key record for this subject"
//! (CIRISEdge#462), and Pull replies are already exempt from hash-first
//! suppression.

use super::protocol::EnvelopeKind;

/// The fields a record can name its signer in, in the order persist's gate
/// prefers them.
///
/// NOT a per-kind mapping. I wrote one twice and got it wrong twice: the
/// membership-revocation planes have no `revoking_key_id` at all — they are
/// authority-signed, carrying `authority_key_id` on the wrapper and
/// `family_key_id` / `community_key_id` inside — so a kind-keyed guess looked
/// for a field that does not exist, found nothing, and silently fetched no key.
///
/// A record names its signer in exactly one of these, so trying them in the
/// gate's own order of specificity removes the guess. Order matters where a
/// record carries several: a `Revocation` has BOTH `revoking_key_id` and
/// `scrub_key_id`, and `verify_revocation_admission` reads the revoker.
const SIGNER_FIELDS: [&str; 4] = [
    // The revoker — read by `verify_revocation_admission`.
    "revoking_key_id",
    // The authority — read by the E4 keyless-declaration and roster planes
    // (Family, Community, both membership revocations, LocationProof,
    // Organization, OrgMembership, PartnerRecord).
    "authority_key_id",
    // The attester — the shared row gate's field, and the common case.
    "attesting_key_id",
    // A key registration's scrubber. Last because a self-attested registration
    // names ITSELF here, and a key that is its own signer is never the missing
    // dependency.
    "scrub_key_id",
];

/// The key whose absence would explain an unverifiable signature on these bytes.
///
/// `None` when the envelope names no signer — a malformed record, which
/// `UnverifiableSignature` also covers and which no fetch can repair. Returning
/// `None` there is the point: the token fuses a recoverable arm with an
/// unrecoverable one, and only the recoverable arm names a key to go and get.
#[must_use]
pub fn missing_signer_of(_kind: EnvelopeKind, envelope_bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(envelope_bytes).ok()?;
    SIGNER_FIELDS.iter().find_map(|field| {
        // Top level first, then one level into the `Signed*` wrapper: the wrapper
        // carries the row under a single key, and some signers sit on the wrapper
        // while others sit on the row.
        value
            .get(*field)
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                value
                    .as_object()?
                    .values()
                    .find_map(|v| v.get(*field).and_then(serde_json::Value::as_str))
            })
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_owned)
    })
}

#[cfg(test)]
mod tests {
    use super::missing_signer_of;
    use crate::replication::protocol::EnvelopeKind;

    /// A revocation is verified against its REVOKER, not its subject. Reading
    /// the wrong field would send the node to fetch the key being revoked —
    /// which it may well already hold, so the pull would "succeed" and the
    /// revocation would still never admit.
    #[test]
    fn a_revocation_names_its_revoker_not_its_subject() {
        let bytes = br#"{"revoked_key_id":"victim-aaa","revoking_key_id":"revoker-bbb"}"#;
        assert_eq!(
            missing_signer_of(EnvelopeKind::Revocation, bytes).as_deref(),
            Some("revoker-bbb")
        );
    }

    /// An authority-signed plane names `authority_key_id`, and the membership
    /// revocations have NO `revoking_key_id` — a kind-keyed mapping looked for
    /// one, found nothing, and fetched no key at all.
    #[test]
    fn an_authority_signed_revocation_names_its_authority() {
        let bytes = br#"{"community_key_id":"c-1","removed_identity_key_id":"v","authority_key_id":"authority-eee"}"#;
        assert_eq!(
            missing_signer_of(EnvelopeKind::CommunityMembershipRevocation, bytes).as_deref(),
            Some("authority-eee")
        );
    }

    /// A revocation carries BOTH `revoking_key_id` and `scrub_key_id`, and the
    /// gate reads the revoker. Order of preference is the whole correctness of
    /// a candidate list.
    #[test]
    fn the_revoker_wins_over_the_scrubber() {
        let bytes = br#"{"revoking_key_id":"revoker-bbb","scrub_key_id":"scrubber-fff"}"#;
        assert_eq!(
            missing_signer_of(EnvelopeKind::Revocation, bytes).as_deref(),
            Some("revoker-bbb")
        );
    }

    /// Every non-revocation plane is verified against `attesting_key_id` — the
    /// field persist's shared row gate reads.
    #[test]
    fn a_row_names_its_attester() {
        let bytes = br#"{"attestation_id":"a-1","attesting_key_id":"producer-ccc"}"#;
        assert_eq!(
            missing_signer_of(EnvelopeKind::Attestation, bytes).as_deref(),
            Some("producer-ccc")
        );
    }

    /// The signer commonly sits one level in, under the `Signed*` wrapper.
    #[test]
    fn the_signer_is_found_inside_a_signed_wrapper() {
        let bytes = br#"{"revocation":{"revoked_key_id":"v","revoking_key_id":"revoker-ddd"}}"#;
        assert_eq!(
            missing_signer_of(EnvelopeKind::Revocation, bytes).as_deref(),
            Some("revoker-ddd")
        );
    }

    /// `UnverifiableSignature` also covers a MALFORMED record, which no fetch
    /// repairs. Naming no key is the correct answer there — inventing one would
    /// send the node chasing a dependency that was never the problem, and the
    /// row would keep failing for the reason it actually failed.
    #[test]
    fn a_malformed_record_names_no_one_to_fetch() {
        assert_eq!(
            missing_signer_of(EnvelopeKind::Attestation, b"not json"),
            None
        );
        assert_eq!(
            missing_signer_of(EnvelopeKind::Attestation, br#"{"no_signer_here":1}"#),
            None
        );
    }

    /// An empty signer is absence, not a key id. Fetching "" would be a
    /// guaranteed-miss pull on every retry.
    #[test]
    fn an_empty_signer_is_not_a_key_to_fetch() {
        let bytes = br#"{"attesting_key_id":""}"#;
        assert_eq!(missing_signer_of(EnvelopeKind::Attestation, bytes), None);
    }
}
