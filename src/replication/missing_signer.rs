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

/// The signer field a plane's admission resolves, if this kind has one.
///
/// Not a guess: these are the fields persist's gate reads. A row is verified
/// against `attesting_key_id`, a revocation against `revoking_key_id`, and a key
/// registration against `scrub_key_id` (which for a self-attested registration
/// is the subject itself, and therefore never missing).
#[must_use]
pub const fn signer_field(kind: EnvelopeKind) -> &'static str {
    match kind {
        EnvelopeKind::Revocation
        | EnvelopeKind::IdentityOccurrenceRevocation
        | EnvelopeKind::FamilyMembershipRevocation
        | EnvelopeKind::CommunityMembershipRevocation => "revoking_key_id",
        EnvelopeKind::Key => "scrub_key_id",
        _ => "attesting_key_id",
    }
}

/// The key whose absence would explain an unverifiable signature on these bytes.
///
/// `None` when the envelope does not name one — a malformed record, which
/// `UnverifiableSignature` also covers and which no fetch can repair. Returning
/// `None` there is the point: the token fuses a recoverable arm with an
/// unrecoverable one, and only the recoverable arm names a key to go and get.
#[must_use]
pub fn missing_signer_of(kind: EnvelopeKind, envelope_bytes: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(envelope_bytes).ok()?;
    let field = signer_field(kind);
    // Top level first, then one level into the record wrapper: the Signed*
    // wrappers carry the row under a single key, and the signer lives on the row.
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            value
                .as_object()?
                .values()
                .find_map(|v| v.get(field).and_then(serde_json::Value::as_str))
        })
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::{missing_signer_of, signer_field};
    use crate::replication::protocol::EnvelopeKind;

    /// A revocation is verified against its REVOKER, not its subject. Reading
    /// the wrong field would send the node to fetch the key being revoked —
    /// which it may well already hold, so the pull would "succeed" and the
    /// revocation would still never admit.
    #[test]
    fn a_revocation_names_its_revoker_not_its_subject() {
        assert_eq!(signer_field(EnvelopeKind::Revocation), "revoking_key_id");
        let bytes = br#"{"revoked_key_id":"victim-aaa","revoking_key_id":"revoker-bbb"}"#;
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
