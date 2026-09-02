//! Bind an attestation's unsigned columns INTO its signed envelope.
//!
//! # Why this is not optional
//!
//! The signature covers `attestation_envelope` and **nothing else**. So every
//! typed column beside it — `attestation_id` (the row's identity),
//! `attesting_key_id` (who made the claim), `attestation_type` (the verb),
//! `subject_key_ids` (which grants revocation authority), `attested_key_id`,
//! `cohort_scope`, `weight` — is a value a relay could rewrite while the
//! signature still verified. And `asserted_at` is the column folds ORDER on, so
//! an unbound one lets an attacker re-submit bytes the producer genuinely
//! signed under a newer timestamp and win the fold.
//!
//! persist refuses an unbound row outright, with no legacy regime
//! (CIRISPersist#598 for the instant, #643 for the row mirror). That refusal is
//! correct and this helper is how a producer satisfies it.
//!
//! # Why it lives here
//!
//! It was written twice — once in `bridge.rs`'s test module and once copied
//! **verbatim** into `mesh_config.rs`, with a comment saying as much because
//! `cfg(test)` items cannot cross module boundaries. `edge_node` needed it a
//! third time, for a real producer rather than a fixture. Three copies of a
//! rule whose whole purpose is "get this exactly right or the row is a replay"
//! is the wrong number; a producer should import the binding, not re-derive it.

/// The complete set of typed columns the `row` mirror covers.
///
/// persist states it as closed: all seven, REQUIRED except `subject_key_ids`
/// (defaults to empty) and `weight` (absent ⇔ the column is NULL), and **no
/// others**. Kept here so a reader can check the mirror against the rule
/// without going to persist for it.
pub const ROW_MIRROR_MEMBERS: [&str; 7] = [
    "attestation_id",
    "attesting_key_id",
    "attestation_type",
    "attested_key_id",
    "subject_key_ids",
    "cohort_scope",
    "weight",
];

/// The typed columns of the attestation being bound.
#[derive(Debug, Clone)]
pub struct AttestationColumns<'a> {
    pub attestation_id: &'a str,
    pub attesting_key_id: &'a str,
    pub attestation_type: &'a str,
    pub attested_key_id: &'a str,
    pub subject_key_ids: &'a [String],
    pub cohort_scope: &'a str,
    /// `None` ⇔ the column is NULL. Absent from the mirror in that case, which
    /// is the encoding persist specifies — not merely an omission.
    pub weight: Option<f64>,
}

/// Bind `asserted_at` and the `row` mirror into `envelope`, **before signing**.
///
/// Existing members are left alone: a producer that already bound them keeps
/// its own values, so this is safe to call on a partially-built envelope.
///
/// `asserted_at` is written RFC3339 — and must not carry NANOSECOND precision,
/// which persist refuses. `chrono`'s `to_rfc3339` on a microsecond-or-coarser
/// instant satisfies that; a producer that built its timestamp from
/// `Utc::now()` should truncate before calling.
pub fn bind_attestation_envelope(
    envelope: &mut serde_json::Value,
    asserted_at: chrono::DateTime<chrono::Utc>,
    cols: &AttestationColumns<'_>,
) {
    let Some(obj) = envelope.as_object_mut() else {
        return;
    };
    obj.entry("asserted_at")
        .or_insert_with(|| serde_json::json!(asserted_at.to_rfc3339()));

    let mut row = serde_json::json!({
        "attestation_id": cols.attestation_id,
        "attesting_key_id": cols.attesting_key_id,
        "attestation_type": cols.attestation_type,
        "attested_key_id": cols.attested_key_id,
        "cohort_scope": cols.cohort_scope,
    });
    if !cols.subject_key_ids.is_empty() {
        row["subject_key_ids"] = serde_json::json!(cols.subject_key_ids);
    }
    if let Some(w) = cols.weight {
        row["weight"] = serde_json::json!(w);
    }
    obj.entry("row").or_insert(row);
}

/// Build the OWNER-BINDING attestation: `owner_key_id` is responsible for
/// `node_id`.
///
/// This is the row that makes federation directory discovery answerable.
/// `owner_of` resolves through `live_owner_binding_granters` and the reverse
/// walk enumerates a person's nodes — so without one, a fedID lookup finds a
/// person with no nodes and every discovery stops there.
///
/// # Why it lives in the library
///
/// It is a real PRODUCER, and edge has production producers (the A/V ALM
/// score rows are the other). A producer that builds its own envelope by hand
/// re-derives the binding rule, and this one got it wrong twice in a row —
/// once missing `asserted_at`, once missing the `row` mirror — each time
/// costing a full mesh round-trip to discover. Here it is covered by an admit
/// test against a real persist backend, which fails in seconds instead.
///
/// Signed **bound-hybrid** via [`crate::identity::sign_bound_hybrid`]: the
/// federation tier is PQC-mandatory (CC 5.3.2.4.3.1), and persist verifies
/// under `HybridPolicy::Strict`, so a classical-only signer produces a row
/// that canonicalizes, hashes and verifies its Ed25519 half correctly and is
/// then refused anyway. `signer` must therefore carry a PQC half, and the
/// attester's directory record must carry the matching ML-DSA-65 pubkey —
/// `verify_hybrid` requires the signature and the pubkey both-or-neither.
///
/// The substrate recognises a binding by `delegation_purpose: "owner_binding"`
/// (CC 2.4.1.2's canonical marker) or by the internal dimension; the raw
/// `delegates_to` emit path carries only the former, so that is what is
/// written here.
pub async fn owner_binding_attestation(
    owner_key_id: &str,
    node_id: &str,
    asserted_at: chrono::DateTime<chrono::Utc>,
    signer: &crate::identity::LocalSigner,
) -> Result<ciris_persist::federation::Attestation, String> {
    use sha2::Digest as _;

    let attestation_id = format!("owner-binding-{node_id}");
    let subjects = vec![node_id.to_owned()];
    let mut envelope = serde_json::json!({
        "attesting_key_id": owner_key_id,
        "attested_key_id": node_id,
        "delegation_purpose": "owner_binding",
        "scope": ["infra:network_presence"],
    });
    // Bind the unsigned columns into the signed bytes BEFORE signing. The
    // signature covers the envelope and nothing else.
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: owner_key_id,
            attestation_type: "delegates_to",
            attested_key_id: node_id,
            subject_key_ids: &subjects,
            cohort_scope: "federation",
            weight: None,
        },
    );
    // Canonicalize through the CEG produce gate (RFC 8785 JCS) — the same
    // canonical form persist's admission recomputes. `serde_json::to_vec` is
    // NOT it, and the difference is invisible until the verifier disagrees.
    //
    // And the signature is over those canonical BYTES, not over their digest.
    // The digest is only the `original_content_hash` column. Signing the
    // digest verifies against nothing and reads exactly like a wrong key:
    // persist reports "ed25519 signature mismatch", which sends you hunting
    // for a key problem that is not there.
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(signer, &canonical, "owner binding").await?;

    Ok(ciris_persist::federation::Attestation {
        attestation_id,
        attesting_key_id: owner_key_id.to_owned(),
        attested_key_id: node_id.to_owned(),
        attestation_type: "delegates_to".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: owner_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        // Born federation-tier: an owner binding is exactly the kind of claim
        // that must be carriable, and a promoted row is byte-identical on the
        // wire to a natively-federation one anyway.
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cols(subjects: &[String]) -> AttestationColumns<'_> {
        AttestationColumns {
            attestation_id: "att-1",
            attesting_key_id: "owner-a",
            attestation_type: "delegates_to",
            attested_key_id: "node-b",
            subject_key_ids: subjects,
            cohort_scope: "federation",
            weight: None,
        }
    }

    /// The mirror carries every member persist requires, and none it forbids.
    ///
    /// The member set is CLOSED, so an extra key is as wrong as a missing one —
    /// this asserts both directions rather than only presence.
    #[test]
    fn the_row_mirror_matches_the_closed_member_set() {
        let subjects = vec!["node-b".to_string()];
        let mut env = serde_json::json!({ "delegation_purpose": "owner_binding" });
        bind_attestation_envelope(&mut env, chrono::Utc::now(), &cols(&subjects));

        let row = env["row"].as_object().expect("a row mirror is bound");
        for member in [
            "attestation_id",
            "attesting_key_id",
            "attestation_type",
            "attested_key_id",
            "cohort_scope",
            "subject_key_ids",
        ] {
            assert!(row.contains_key(member), "{member} is required");
        }
        assert!(
            !row.contains_key("weight"),
            "weight ABSENT is how NULL is encoded — writing it as null would be \
             a different claim"
        );
        for key in row.keys() {
            assert!(
                ROW_MIRROR_MEMBERS.contains(&key.as_str()),
                "{key} is not a member of the closed set"
            );
        }
        assert!(
            env.get("asserted_at").is_some(),
            "the fold's ordering instant"
        );
    }

    /// An empty subject list is ABSENT rather than `[]`.
    #[test]
    fn empty_subjects_are_omitted_not_written_empty() {
        let none: Vec<String> = Vec::new();
        let mut env = serde_json::json!({});
        bind_attestation_envelope(&mut env, chrono::Utc::now(), &cols(&none));
        assert!(
            !env["row"]
                .as_object()
                .unwrap()
                .contains_key("subject_key_ids"),
            "absent ⇔ empty, per the rule; an explicit [] is a different \
             encoding of the same fact and the set is closed"
        );
    }

    /// A producer that already bound a member keeps its own value — this is
    /// safe on a partially-built envelope.
    #[test]
    fn existing_members_are_not_overwritten() {
        let none: Vec<String> = Vec::new();
        let mut env = serde_json::json!({ "asserted_at": "2020-01-01T00:00:00+00:00" });
        bind_attestation_envelope(&mut env, chrono::Utc::now(), &cols(&none));
        assert_eq!(env["asserted_at"], "2020-01-01T00:00:00+00:00");
    }

    /// No NANOSECOND precision — persist refuses it.
    #[test]
    fn the_bound_instant_is_not_nanosecond_precision() {
        let none: Vec<String> = Vec::new();
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut env = serde_json::json!({});
        bind_attestation_envelope(&mut env, ts, &cols(&none));
        let s = env["asserted_at"].as_str().unwrap();
        let frac = s.split('.').nth(1).unwrap_or("");
        let digits = frac.chars().take_while(char::is_ascii_digit).count();
        assert!(
            digits <= 6,
            "asserted_at must not carry nanosecond precision: {s}"
        );
    }
}

/// The ADMIT tests — the producer is driven through a real persist backend.
///
/// The tests above check the binding's SHAPE against the rule as written down.
/// That was not enough twice running: the shape rule was incomplete both
/// times, and the only thing that knew it was persist. These tests ask persist
/// directly, in-memory, in about a second — the signal that previously cost a
/// full mesh round-trip to obtain.
#[cfg(test)]
mod admit_tests {
    use super::*;
    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
    use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
    use ciris_persist::store::sqlite::SqliteBackend;
    use ciris_persist::store::Backend as _;
    use sha2::Digest as _;
    use std::sync::Arc;

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .unwrap()
            .into()
    }

    fn b64(bytes: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// A HYBRID signer with deterministic halves — real signatures, because
    /// persist's admission is the oracle and a fake would only prove the fake.
    fn signer(key_id: &str, seed_byte: u8) -> crate::identity::LocalSigner {
        let classical: Arc<dyn HardwareSigner> =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed_byte; 32], key_id).expect("ed25519"));
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(
                &[seed_byte ^ 0x55; 32],
                format!("{key_id}-pqc"),
            )
            .expect("ml-dsa-65"),
        );
        crate::identity::LocalSigner::new(key_id, classical, Some(pqc))
    }

    async fn pubkeys(s: &crate::identity::LocalSigner) -> (String, Option<String>) {
        let ed = b64(&s.classical.public_key().await.expect("ed pubkey"));
        let pqc = match s.pqc.as_ref() {
            Some(p) => Some(b64(&p.public_key().await.expect("pqc pubkey"))),
            None => None,
        };
        (ed, pqc)
    }

    /// Same shape as the runner's `signed_record` and `tests/common`.
    async fn signed_record(
        subject_key_id: &str,
        subject_pubkeys: (String, Option<String>),
        s: &crate::identity::LocalSigner,
        signer_key_id: &str,
        identity_type: &str,
    ) -> KeyRecord {
        let envelope = serde_json::json!({ "key_id": subject_key_id });
        let canonical = serde_json::to_vec(&envelope).unwrap();
        let digest = sha2::Sha256::digest(&canonical);
        let (sig, sig_pqc) = crate::identity::sign_bound_hybrid(s, digest.as_slice(), "key record")
            .await
            .expect("sign");
        KeyRecord {
            key_id: subject_key_id.to_owned(),
            pubkey_ed25519_base64: subject_pubkeys.0,
            pubkey_ml_dsa_65_base64: subject_pubkeys.1,
            algorithm: "hybrid".to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: subject_key_id.to_owned(),
            valid_from: ts(),
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig,
            scrub_signature_pqc: sig_pqc,
            scrub_key_id: signer_key_id.to_owned(),
            scrub_timestamp: ts(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// Owner (`user`) and node (`node`) seeded, exactly as the mesh runner's
    /// standup does.
    async fn directory_with_owner_and_node() -> (Arc<SqliteBackend>, crate::identity::LocalSigner) {
        let owner = signer("owner-a", 1);
        let node = signer("node-b", 2);
        let dir = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open");
        dir.run_migrations().await.expect("migrate");
        for rec in [
            signed_record("owner-a", pubkeys(&owner).await, &owner, "owner-a", "user").await,
            signed_record("node-b", pubkeys(&node).await, &owner, "owner-a", "node").await,
        ] {
            dir.put_public_key(SignedKeyRecord { record: rec })
                .await
                .expect("put_public_key");
        }
        (dir, owner)
    }

    async fn bind(owner: &crate::identity::LocalSigner) -> Attestation {
        owner_binding_attestation("owner-a", "node-b", ts(), owner)
            .await
            .expect("build")
    }

    /// **The row persist actually admits.**
    ///
    /// This is the test that would have turned two failed mesh runs into two
    /// seconds. Both refusals — the missing signed `asserted_at`
    /// (CIRISPersist#598) and the missing `row` mirror (#643) — reach the
    /// producer through exactly this call.
    #[tokio::test]
    async fn the_owner_binding_is_admitted_by_persist() {
        let (dir, owner) = directory_with_owner_and_node().await;
        dir.put_attestation(SignedAttestation {
            attestation: bind(&owner).await,
        })
        .await
        .expect("persist must ADMIT the owner binding this producer builds");
    }

    /// **And discovery resolves through it** — the leg the mesh exists to
    /// prove.
    ///
    /// Admission alone is not the property: a row can be admitted and still be
    /// invisible to the resolver if its purpose marker or subject list is
    /// wrong. `owner_of` is what a fedID lookup calls, so this asserts the
    /// binding is not merely well-formed but LOAD-BEARING.
    #[tokio::test]
    async fn owner_of_resolves_the_bound_node() {
        let (dir, owner) = directory_with_owner_and_node().await;
        dir.put_attestation(SignedAttestation {
            attestation: bind(&owner).await,
        })
        .await
        .expect("admit");

        let resolved = ciris_persist::federation::admission::owner_of(&*dir, "node-b")
            .await
            .expect("owner_of must not error");
        assert_eq!(
            resolved.as_deref(),
            Some("owner-a"),
            "the binding must be visible to the resolver a fedID lookup uses — \
             an admitted-but-unresolvable row is the silent version of this bug"
        );

        // And the FORWARD direction, which is the one discovery actually walks:
        // a fedID resolves to the person, the person to their nodes. Asserting
        // only `owner_of` would leave the leg's own direction unproven.
        let owned = ciris_persist::federation::admission::nodes_owned_by(&*dir, "owner-a")
            .await
            .expect("nodes_owned_by must not error");
        assert!(
            owned.contains(&"node-b".to_string()),
            "fedID -> owned nodes is the direction `discover` walks; got {owned:?}"
        );
    }

    /// An UNBOUND envelope is refused — the guard proves persist's rule is
    /// still live, so this file's binder cannot quietly become unnecessary
    /// and then quietly become wrong again.
    #[tokio::test]
    async fn an_unbound_envelope_is_refused() {
        let (dir, owner) = directory_with_owner_and_node().await;
        let mut att = bind(&owner).await;
        // Strip the mirror and re-sign, so the ONLY difference from the
        // admitted row is the binding itself — not a broken signature.
        if let Some(obj) = att.attestation_envelope.as_object_mut() {
            obj.remove("row");
            obj.remove("asserted_at");
        }
        let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&att.attestation_envelope)
            .expect("canonicalize");
        att.original_content_hash = hex::encode(sha2::Sha256::digest(&canonical));
        let (c, q) = crate::identity::sign_bound_hybrid(&owner, &canonical, "unbound probe")
            .await
            .expect("sign");
        att.scrub_signature_classical = c;
        att.scrub_signature_pqc = q;

        let refused = dir
            .put_attestation(SignedAttestation { attestation: att })
            .await;
        assert!(
            refused.is_err(),
            "persist must still refuse an unbound envelope; if this ever passes, \
             the binding rule relaxed and this module's reason for existing changed"
        );
    }
}
