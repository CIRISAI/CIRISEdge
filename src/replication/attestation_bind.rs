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

/// **The one rendering of a signed instant** (CC 2.6.2): `YYYY-MM-DDTHH:MM:SS.sssZ`
/// — literal `Z`, exactly three fractional digits. Persist's, re-exported:
/// `chrono::to_rfc3339()` emits `+00:00` at whatever precision the value
/// carries, which the constitution says a consumer MUST reject when verifying
/// a signature.
pub use ciris_persist::federation::admission::render_signed_instant;
/// The substrate's instant floor — **milliseconds** since persist v39.0.0
/// (CC 2.6.2). Re-exported so every edge producer truncates through the ONE
/// helper the substrate itself mints with; the signed envelope and the typed
/// `asserted_at` COLUMN must agree exactly, so both go through this.
pub use ciris_persist::federation::admission::truncate_to_substrate_resolution;

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
/// `asserted_at` is TRUNCATED to the substrate floor here (milliseconds since
/// persist v39.0.0, CC 2.6.2) and rendered in the ONE canonical form
/// (`.sssZ`), because persist binds the envelope instant to the typed column
/// and refuses a row whose two disagree (CIRISPersist#598).
///
/// This used to be documented as the caller's job. It should not have been —
/// `Utc::now()` is the obvious thing to pass and carries nanoseconds, so every
/// producer got one chance to be refused at admission for a reason that reads
/// like a clock problem. Truncating at the one place that builds the envelope
/// makes the requirement unmissable instead of merely written down.
pub fn bind_attestation_envelope(
    envelope: &mut serde_json::Value,
    asserted_at: chrono::DateTime<chrono::Utc>,
    cols: &AttestationColumns<'_>,
) {
    let Some(obj) = envelope.as_object_mut() else {
        return;
    };
    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    obj.entry("asserted_at")
        .or_insert_with(|| serde_json::json!(render_signed_instant(asserted_at)));

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

    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let attestation_id = format!("owner-binding-{node_id}");
    let subjects = vec![node_id.to_owned()];

    // persist's OWN builder, not a hand-rolled envelope.
    //
    // It stamps the ownership `dimension` and the `responsible_for` purpose
    // marker together — the pair CIRISServer's `auth::ownership` writes, byte
    // for byte, because the wire is the contract. Hand-building this was how
    // the row ended up with NO dimension at all: admission recognises an owner
    // binding by the CC `delegation_purpose` OR the dimension, so it admitted
    // and `owner_of` resolved, while the ADVERTISE projection — which reads the
    // dimension — saw an unknown family and never offered the row to a peer.
    let mut envelope =
        ciris_persist::federation::self_at_login::owner_binding_delegates_to_envelope(
            node_id,
            &["infra:network_presence".to_string()],
        );

    // Bind the unsigned columns into the signed bytes BEFORE signing. The
    // signature covers the envelope and NOTHING else.
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

/// The default namespace prefixes a node consents to replicate.
///
/// **Byte-identical to CIRISServer's `DEFAULT_GRANT_ATTESTATION_PREFIXES`**,
/// plus `ownership:` — the wire is the contract, and a restated list forks.
/// The server's own comment records what the omission cost there: with the
/// authority plane missing from the grant, *"no node ever serves anyone's
/// bindings — measured on the chat ladder, every node held only its OWN
/// owner-binding, so every person→node resolution walk starved one hop out."*
/// That is precisely the symptom edge's mesh reported (`identity_type: "user"`
/// with `owned_nodes: []`), from the same cause.
///
/// `ownership:` is edge's addition, because
/// [`owner_binding_delegates_to_envelope`] stamps the ownership dimension
/// (`ownership:responsible_party:node:v1`) rather than the general
/// `self:delegates_to:v1` axis — both are carried so a binding written either
/// way is covered.
///
/// [`owner_binding_delegates_to_envelope`]: ciris_persist::federation::self_at_login::owner_binding_delegates_to_envelope
pub const DEFAULT_CONSENT_PREFIXES: [&str; 5] = [
    "capacity:",
    // Chat rides `chat:message:v1`. Omit this and messages are authored,
    // admitted locally, and NEVER offered to the contact — the plane is
    // consent-gated at the recipient, so a missing prefix is silent.
    crate::chat::CHAT_ATTESTATION_PREFIX,
    "ownership:",
    "self:delegates_to:",
    "trace:",
];

/// Build this node's directed **`consent:replication:v1`** grant at `peer`.
///
/// # Why a node needs one at all
///
/// The Attestation plane is consent-gated at the RECIPIENT, not per row: a peer
/// that does not resolve to a consent-membership proof withholds the WHOLE
/// plane, fail-closed. So without this grant a node advertises no attestations
/// to that peer — not its owner binding, not anything — and every lookup that
/// depends on someone else's records starves one hop out with no error
/// anywhere. It reads exactly like slow convergence.
///
/// # The shape is the server's
///
/// A directed `scores` row: `attesting_key_id` = this node (**self-attested**,
/// per CEG 1.0-RC29 §5.6.8.15 — a consent object is authored by the granting
/// party, which forecloses third-party forgery of consent),
/// `subject_key_ids = [peer]` (the single recipient), `cohort_scope`
/// `federation`, hybrid-signed. Consent is DIRECTED: A granting B says nothing
/// about B granting A, so a bilateral pair needs both halves.
///
/// The payload is authored in FULL rather than leaning on persist's defaults —
/// the server's rule, learned the hard way: *"a default that lives only in
/// persist is a policy nobody stated,"* and `attestation_prefixes` silently
/// defaulting for eight releases is how zero traces reached production with
/// every gate green.
///
/// # Errors
///
/// Refuses a vacuous prefix set, and validates the payload through persist's
/// own `parse_grant_payload` BEFORE signing — so a member spelled wrong is
/// caught here, named, instead of surfacing as a refused row on a peer.
pub async fn replication_consent_attestation(
    node_key_id: &str,
    peer_key_id: &str,
    prefixes: &[&str],
    asserted_at: chrono::DateTime<chrono::Utc>,
    signer: &crate::identity::LocalSigner,
) -> Result<ciris_persist::federation::Attestation, String> {
    use sha2::Digest as _;

    let asserted_at = truncate_to_substrate_resolution(asserted_at);
    let mut prefixes: Vec<String> = prefixes
        .iter()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    prefixes.sort();
    prefixes.dedup();
    if prefixes.is_empty() {
        return Err(
            "refusing to author a consent:replication grant with a vacuous prefix set —              persist admits an empty array, but the grant would cover nothing and still              look authoritative"
                .to_owned(),
        );
    }

    let attestation_id = format!("consent-replication-{node_key_id}-{peer_key_id}");
    let subjects = vec![peer_key_id.to_owned()];
    let payload = serde_json::json!({
        // "replication" is the legacy spelling persist accepts alongside
        // "transfer"; kept so edge and server grants stay the same shape.
        "grants": "replication",
        "direction": "egress",
        "kinds": ["Attestation"],
        "attestation_prefixes": prefixes,
        "principle": "share",
        "audience": ciris_persist::federation::types::cohort_scope::FEDERATION,
        "restrictions": serde_json::Value::Array(Vec::new()),
    });

    // Parse our OWN payload through persist's strict parser before signing it.
    // `deny_unknown_fields` means a misspelled member is caught here, with the
    // field named, rather than as a refusal on somebody else's node.
    ciris_persist::federation::consent_grammar::parse_grant_payload(
        &serde_json::json!({ "payload": payload }),
    )
    .map_err(|e| format!("refusing to author a grant persist would reject: {e}"))?;

    let mut envelope = serde_json::json!({
        "dimension": ciris_persist::federation::consent_peer_set::DIMENSION,
        "payload": payload,
    });
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: node_key_id,
            attestation_type: "scores",
            attested_key_id: peer_key_id,
            subject_key_ids: &subjects,
            cohort_scope: "federation",
            weight: None,
        },
    );

    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
        .map_err(|e| format!("canonicalize: {e}"))?;
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) =
        crate::identity::sign_bound_hybrid(signer, &canonical, "replication consent").await?;

    Ok(ciris_persist::federation::Attestation {
        attestation_id,
        attesting_key_id: node_key_id.to_owned(),
        attested_key_id: peer_key_id.to_owned(),
        attestation_type: "scores".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: node_key_id.to_owned(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: "federation".to_owned(),
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

// ═══════════════════════════════════════════════════════════════════
// The share surface — docs/FSD_REPLICATION_DX.md §3, over persist v39's
// two crossing verbs.
//
// A crossing is TWO operations, never one (CIRISPersist
// FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE):
//
//   * `enter_mesh`     — `tier: local → federation` over the SAME bytes
//                        (CC 5.3.2.4.2). The actor's signature, when present,
//                        stays the base scrub; the node may only APPEND a
//                        co-scrub. `cohort_scope` is one of the signed bytes,
//                        so it does not move.
//   * `widen_audience` — a NEW `supersedes` row the ACTOR signs at a strictly
//                        wider `cohort_scope` (CC 4.4.3.3.1 / 8.1.5). The prior
//                        row is untouched. A share that widens therefore yields
//                        TWO rows.
//
// `share` composes them. What it never does is decide whose key is on the
// row: that is persist's, and the fabric key never stands in for the actor.
// ═══════════════════════════════════════════════════════════════════

pub use ciris_persist::federation::crossing::describe as describe_crossing;
pub use ciris_persist::federation::{
    Audience, ContentRef, ContextualIntegrity, CrossingBasis, Custody, DataSubject, DeliveryMode,
    Lifecycle, MeshCrossing, MeshCrossingOutcome, Replicates, RevocationAuthority,
    TierPromotionCustody,
};

/// **Who a row is shared with.** The `recipient_see` axis of contextual
/// integrity as a type — every non-public audience, in widening order.
///
/// This is an OPTION over the substrate, not a gate in front of it: a row
/// authored directly at `tier: federation` with the intended `cohort_scope`
/// replicates exactly as well. `With` exists because the two-axis model
/// (`tier` = on the wire at all; `cohort_scope` = who) is easy to get wrong,
/// so it names the audience and answers the two questions callers get wrong
/// FROM THE VALUE — delegating to persist's own classifiers rather than
/// restating them, so a drift is a test failure, not a doc bug.
///
/// `family` and `community` NAME their cohort. A cohort placement is a
/// membership claim about ONE cohort, proven at the put door against the id
/// the row carries (AV-45), so a targeted audience without its id is not an
/// audience — persist's [`Audience`] says the same, and `With` maps onto it.
///
/// `federation` is deliberately absent. Publishing is [`publish`], its own
/// verb: `federation` reads like "the mesh" and means "anyone at all, in the
/// clear", and it should be something you typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum With {
    /// `self` — the owner's OWN device set. A node has exactly one owner
    /// (CC 3.2), so `self` widens to that owner's nodes and nowhere else.
    /// Replicated to them by consent fan-out; never advertised (CC 5.2).
    MyDevices,
    /// `family` — the named partnered family. Replicated to the family's
    /// nodes; never advertised (CC 5.2).
    MyFamily {
        /// The family the row is placed in.
        family_key_id: String,
    },
    /// `community` — a named group. Encrypted under the room DEK; discoverable.
    Community {
        /// The community the row is placed in — for a two-person chat,
        /// [`crate::chat::pair_community_key_id`].
        community_key_id: String,
    },
    /// `affiliations` — organisations the subject is attached to. Same tier
    /// as `community` (CC 4.4.3.2.1).
    Affiliations,
    /// `species` — narrower AUDIENCE than the federation, but **plaintext**
    /// (Commons). Check [`Self::is_encrypted_at_rest`] before assuming
    /// otherwise.
    Species,
    /// `biosphere` — likewise plaintext Commons.
    Biosphere,
}

impl With {
    /// The audience as persist's own type.
    #[must_use]
    pub fn audience(&self) -> Audience {
        match self {
            With::MyDevices => Audience::SelfOnly,
            With::MyFamily { family_key_id } => Audience::Family {
                family_key_id: family_key_id.clone(),
            },
            With::Community { community_key_id } => Audience::Community {
                community_key_id: community_key_id.clone(),
            },
            With::Affiliations => Audience::Affiliations,
            With::Species => Audience::Species,
            With::Biosphere => Audience::Biosphere,
        }
    }

    /// The wire `cohort_scope` value.
    #[must_use]
    pub fn cohort_scope(&self) -> &'static str {
        self.audience().cohort_scope()
    }

    /// Are the bytes encrypted at rest? persist's `crypto_tier` is the
    /// authority and it is negative-default (#188): only self/family and
    /// community/affiliations encrypt; everything else is plaintext.
    ///
    /// Passes `cohort_subkind = None`. A `community` whose subkind is
    /// `infrastructure` is plaintext by carve-out — a caller placing into one
    /// of those should consult `crypto_tier` with the subkind directly.
    #[must_use]
    pub fn is_encrypted_at_rest(&self) -> bool {
        use ciris_persist::federation::types::cohort_scope::{crypto_tier, CryptoTier};
        !matches!(
            crypto_tier(self.cohort_scope(), None),
            CryptoTier::Plaintext
        )
    }

    /// Can a non-member tell the content EXISTS? `false` means the
    /// `holds_bytes` discovery row is withheld — true only of `self` and
    /// `family` (CC 5.2). Undiscoverable is NOT un-replicated: those rows
    /// still reach the owner's / the family's nodes by consent fan-out.
    #[must_use]
    pub fn is_structurally_invisible(&self) -> bool {
        !self.audience().discoverable()
    }
}

/// **A cohort whose content is ENCRYPTED at rest.**
///
/// Sharing has two orthogonal privacy properties, and this type carries the
/// first (the second is [`EncryptedCohort::is_structurally_invisible`]):
///
/// | cohort | at rest | invisible to non-members? |
/// |---|---|---|
/// | [`MyOwnDevices`](EncryptedCohort::MyOwnDevices) | per-write DEK | **no** |
/// | [`MyFamily`](EncryptedCohort::MyFamily) | per-write DEK, wrapped per member | **no** |
/// | [`Community`](EncryptedCohort::Community) | shared per-community DEK (mandatory) | yes |
/// | [`Affiliations`](EncryptedCohort::Affiliations) | shared DEK | yes |
///
/// ("invisible" here means the `holds_bytes` discovery row is withheld; the
/// bytes still replicate to the cohort's nodes.) Community content is
/// deliberately NOT suppressed (CEG 0.8 §8.1.13.3) — communities can be large
/// and per-member byte-level invisibility is infeasible, so the community
/// property is **cohort-filtered visibility**. "Only members can read it" is
/// true of a community; "nobody can tell it exists" is true only of self and
/// family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptedCohort {
    /// **`self` — the owner's own device set, and the most important tier.**
    ///
    /// Not "unshared": a node has exactly one owner (CIRISConstitution#23), and
    /// `self` widens to that owner's whole node set — so this replicates across
    /// YOUR devices and nowhere else. Edge enforces it structurally rather than
    /// by label: it refuses federation-class and mandatory-class fan-out, and
    /// refuses any point-to-point emission whose recipient is not self.
    ///
    /// It is also the locality dividend (FEDERATION_SCALING_MODEL §9.5): self
    /// bytes never cost the federation a directory entry. Most content should
    /// live here and go no further.
    MyOwnDevices,
    /// `family` — the named partnered family. Structurally invisible, like
    /// `self`.
    MyFamily {
        /// The family the row is placed in.
        family_key_id: String,
    },
    /// `community` — a named group; where a two-party chat lives.
    Community {
        /// The community the row is placed in.
        community_key_id: String,
    },
    /// `affiliations` — organisations the subject is attached to.
    Affiliations,
}

/// **A cohort whose content is PLAINTEXT at rest**, despite naming an audience
/// narrower than the whole federation.
///
/// This type exists to stop a caller reading `species` as "more private than
/// federation". It is not: persist's negative-default dispatch encrypts only
/// self/family and community/affiliations, so these tiers are stored in the
/// clear and emit `holds_bytes` normally. They narrow the intended AUDIENCE;
/// they do not protect the bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearCohort {
    /// `species` — a broader-than-community human audience. Plaintext.
    Species,
    /// `biosphere` — including non-human stakeholders. Plaintext.
    Biosphere,
}

impl EncryptedCohort {
    /// The same audience as a [`With`].
    #[must_use]
    pub fn with(&self) -> With {
        match self {
            EncryptedCohort::MyOwnDevices => With::MyDevices,
            EncryptedCohort::MyFamily { family_key_id } => With::MyFamily {
                family_key_id: family_key_id.clone(),
            },
            EncryptedCohort::Community { community_key_id } => With::Community {
                community_key_id: community_key_id.clone(),
            },
            EncryptedCohort::Affiliations => With::Affiliations,
        }
    }

    /// The wire `cohort_scope` value.
    #[must_use]
    pub fn cohort_scope(&self) -> &'static str {
        self.with().cohort_scope()
    }

    /// Does this tier withhold the `holds_bytes` discovery row entirely, so a
    /// non-member cannot learn the content exists? `self` and `family` only.
    #[must_use]
    pub fn is_structurally_invisible(&self) -> bool {
        self.with().is_structurally_invisible()
    }
}

impl ClearCohort {
    /// The same audience as a [`With`].
    #[must_use]
    pub fn with(self) -> With {
        match self {
            ClearCohort::Species => With::Species,
            ClearCohort::Biosphere => With::Biosphere,
        }
    }

    /// The wire `cohort_scope` value.
    #[must_use]
    pub fn cohort_scope(self) -> &'static str {
        self.with().cohort_scope()
    }
}

/// **The keys a crossing may sign with.** Two, because a crossing has two
/// parties: the ACTOR who made the claim, and the NODE that holds it.
///
/// Who signs is decided by the row, not by the caller ([`custody_for`]):
///
/// | row | signer in hand | custody |
/// |---|---|---|
/// | signed at write by another key | — | the node **co-scrubs** (`additional_scrubs`, `cosigned_at`) |
/// | signed at write by this node | — | the existing base scrub is re-offered |
/// | unsigned, attested by this node | — | this node signs as the actor |
/// | unsigned, attested by another key | that key's signer | the actor signs now |
/// | unsigned, attested by another key | none | **waits** — `AwaitingActor` |
///
/// A widening always needs the ACTOR's signer (or this node's, when this node
/// authored the claim): a `supersedes` is a new claim, and there is no
/// delegated widening — a node-only key cannot carry agency (CC 4.4,
/// `check_node_agency_admission`).
#[derive(Clone, Copy)]
pub struct Signers<'a> {
    /// THIS NODE's hybrid signer — custody.
    pub node: &'a crate::identity::LocalSigner,
    /// The ATTESTER's signer, when the caller holds it: the human's FedID
    /// signer as they hit send, or an AgentID signer in-process. `None` is a
    /// statement ("the actor is not here"), and an unsigned row then waits.
    pub actor: Option<&'a crate::identity::LocalSigner>,
}

/// **Who signs a tier crossing — the one decision, made from the row.**
///
/// Edge's copy of persist's `Engine::custody_for` (v39.0.0), over the
/// directory primitive rather than the engine, so a consumer that holds a
/// `FederationDirectory` and its own keys can cross without an `Engine`. The
/// table is in [`Signers`]. `Ok(None)` is "the actor is not in hand" — the row
/// waits. A signer that is in hand but is NOT the attester is refused rather
/// than ignored: a caller handing over the wrong key is a bug worth surfacing,
/// not a reason to wait.
///
/// # Errors
/// Canonicalization or signing failure; a signer that is not the attester.
pub async fn custody_for(
    row: &ciris_persist::federation::Attestation,
    signers: Signers<'_>,
) -> Result<Option<TierPromotionCustody>, String> {
    use ciris_persist::federation::admission::{
        render_signed_instant, truncate_to_substrate_resolution,
    };
    use ciris_persist::federation::types::ScrubSig;
    use ciris_persist::federation::{crossing, AttestationReseal};

    let node = &signers.node.key_id;
    let mut envelope = row.attestation_envelope.clone();
    let (bytes, hash) = crossing::canonical_bytes(&mut envelope)
        .map_err(|e| format!("canonicalize {}: {e}", row.attestation_id))?;
    let node_is_actor = row.attesting_key_id == *node;

    if !row.scrub_signature_classical.is_empty() {
        if node_is_actor {
            // Signed at write by this node: the base scrub already IS the
            // actor's. Re-offer it; the directory re-verifies it.
            return Ok(Some(TierPromotionCustody::ActorSigned(AttestationReseal {
                attestation_envelope: envelope,
                original_content_hash: row.original_content_hash.clone(),
                scrub_signature_classical: row.scrub_signature_classical.clone(),
                scrub_signature_pqc: row.scrub_signature_pqc.clone(),
                scrub_key_id: row.scrub_key_id.clone(),
                scrub_timestamp: row.scrub_timestamp,
            })));
        }
        // Signed at write by the actor: preserve it, add custody alongside.
        let (classical, pqc) =
            crate::identity::sign_bound_hybrid(signers.node, &bytes, "node co-scrub").await?;
        return Ok(Some(TierPromotionCustody::NodeCoScrub(ScrubSig {
            scrub_key_id: node.clone(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            // The co-signer stamps the moment it signed (CC 2.6.7), here,
            // where the signature is produced — outside the signed preimage.
            cosigned_at: Some(render_signed_instant(chrono::Utc::now())),
        })));
    }

    // Unsigned (CC 5.3.2.2 deferral): the actor signs now, or the row waits.
    let signer = if node_is_actor {
        signers.node
    } else {
        match signers.actor {
            Some(a) if a.key_id == row.attesting_key_id => a,
            Some(a) => {
                return Err(format!(
                    "custody is not the actor: row {} is attested by {} but the signer in hand \
                     is {} — the fabric never replaces the actor's key \
                     (FSD/PROMOTION_PRESERVES_THE_ACTOR_SIGNATURE §5.1 W5)",
                    row.attestation_id, row.attesting_key_id, a.key_id
                ))
            }
            None => return Ok(None),
        }
    };
    let (classical, pqc) =
        crate::identity::sign_bound_hybrid(signer, &bytes, "actor signature at the crossing")
            .await?;
    Ok(Some(TierPromotionCustody::ActorSigned(AttestationReseal {
        attestation_envelope: envelope,
        original_content_hash: hash,
        scrub_signature_classical: classical,
        scrub_signature_pqc: pqc,
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: truncate_to_substrate_resolution(chrono::Utc::now()),
    })))
}

/// **Where edge routes the bytes** — the half of the consequence persist
/// cannot state. Persist says what the row IS (`Replicates { kinds,
/// discoverable }`); only the replicating substrate says where it GOES.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "to", rename_all = "snake_case")]
pub enum RoutesTo {
    /// `self` — the owner's own node set, by consent fan-out; no `holds_bytes`.
    OwnerNodes,
    /// `family` — the family's nodes, by consent fan-out; no `holds_bytes`.
    FamilyNodes { family_key_id: String },
    /// `community` — members, served on discovery.
    CommunityMembers { community_key_id: String },
    /// `affiliations` — served on discovery.
    Affiliations,
    /// `species` — served on discovery, plaintext.
    Species,
    /// `biosphere` — served on discovery, plaintext.
    Biosphere,
    /// `federation` — anyone at all, plaintext (lightnet).
    Everyone,
}

impl RoutesTo {
    /// Edge's routing consequence of an audience.
    #[must_use]
    pub fn of(audience: &Audience) -> Self {
        match audience {
            Audience::SelfOnly => RoutesTo::OwnerNodes,
            Audience::Family { family_key_id } => RoutesTo::FamilyNodes {
                family_key_id: family_key_id.clone(),
            },
            Audience::Community { community_key_id } => RoutesTo::CommunityMembers {
                community_key_id: community_key_id.clone(),
            },
            Audience::Affiliations => RoutesTo::Affiliations,
            Audience::Species => RoutesTo::Species,
            Audience::Biosphere => RoutesTo::Biosphere,
            Audience::Federation => RoutesTo::Everyone,
        }
    }
}

/// What [`share`] / [`publish`] did, in one word — plus the id a peer will
/// see, because "it is on the wire" is only checkable by that id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "shared", rename_all = "snake_case")]
pub enum Shared {
    /// The row is now on the wire at the audience asked for. After a
    /// widening this is the NEW `supersedes` row's id, not the one passed in.
    Placed { attestation_id: String },
    /// Already there: in the mesh at that audience, or already widened to it
    /// by its attester. Idempotent by constitution (CC 5.3.2.4.2 / CEG §6.1),
    /// so this is a fact, not a fault.
    AlreadyThere { attestation_id: String },
    /// The row WAITS for its actor: it is unsigned and no actor signer was in
    /// hand (nothing to co-scrub), or it needs widening and only the actor can
    /// author a `supersedes`. Typed, never a silent stay-local.
    AwaitingActor { attestation_id: String, age_ms: i64 },
}

/// **What a crossing did, and what crossed.**
///
/// Two verb outcomes, verbatim, because a share that widens is two rows:
/// `entered` is the row you passed (tier crossing), `widened` is the new
/// `supersedes` row at the wider audience. `ci` is the nine-axis description
/// persist verified against the row before anything moved (CC 4.5.1.1).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Crossing {
    /// The one-word summary, with the id on the wire.
    pub shared: Shared,
    /// All nine contextual-integrity axes, as applied at the audience asked
    /// for — cross-checked by persist and refused by axis name on a mismatch.
    pub ci: ContextualIntegrity,
    /// Where edge routes it.
    pub routes_to: RoutesTo,
    /// CC 5.2 — whether a `holds_bytes` row advertises it. `false` for
    /// `self`/`family`: replicated, not discoverable.
    pub discoverable: bool,
    /// `enter_mesh`'s outcome for the row passed in.
    pub entered: MeshCrossingOutcome,
    /// `widen_audience`'s outcome, when the audience asked for is wider than
    /// the row's own. `Some(Crossed(..))` means a SECOND row now exists.
    pub widened: Option<MeshCrossingOutcome>,
}

/// The pure plan both verbs share — decided from the row and the audience,
/// before any directory is touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharePlan {
    /// In the mesh at exactly this audience already.
    AlreadyThere,
    /// A local row whose own audience is the one asked for: tier crossing only.
    Enter,
    /// A local row asked for a wider audience: tier crossing, then a widening.
    EnterThenWiden(Audience),
    /// A row already in the mesh, asked for a wider audience: widening only.
    Widen(Audience),
}

/// Decide what a share must do. Public so the verdict is testable without a
/// directory, which is also the proof that it runs before one is touched.
///
/// Refuses, by name: a row with no `dimension` (information type is the strict
/// admission test — without a namespace no consent grant can cover it); a
/// `family`/`community` row naming no cohort; an audience NARROWER than the
/// row's own (a `supersedes` widens; to narrow, withdraw — CC 4.4.3.3.1).
///
/// # Errors
/// Any of the refusals above.
pub fn share_plan(
    row: &ciris_persist::federation::Attestation,
    target: &Audience,
) -> Result<SharePlan, String> {
    use ciris_persist::federation::types::attestation_tier;
    if ciris_persist::federation::admission::envelope_dimension(&row.attestation_envelope).is_none()
    {
        return Err(format!(
            "row {} has no `dimension` — the information-type axis is the strict admission \
             test, and without a namespace no consent grant can cover it, so it must not \
             cross the wire",
            row.attestation_id
        ));
    }
    let current = Audience::of_row(row).map_err(|e| format!("row {}: {e}", row.attestation_id))?;
    let local = row.tier == attestation_tier::LOCAL;
    if *target == current {
        return Ok(if local {
            SharePlan::Enter
        } else {
            SharePlan::AlreadyThere
        });
    }
    ciris_persist::federation::crossing::check_strictly_wider(row, target.cohort_scope())
        .map_err(|e| e.to_string())?;
    Ok(if local {
        SharePlan::EnterThenWiden(target.clone())
    } else {
        SharePlan::Widen(target.clone())
    })
}

/// **Share a row with an audience — the one verb.**
///
/// Enters the mesh over the row's own bytes and, when `with` is wider than
/// the row's own audience, widens it by a `supersedes` the actor signs. The
/// actor's signature is preserved end to end; the node only ever co-scrubs.
/// Idempotent on a row already there. Refuses — by name — a narrowing, a row
/// with no information type, and a signer that is not the attester.
///
/// `basis` is the `transmission_principle` axis: what the crossing rides on.
/// [`CrossingBasis::ProducerAuthority`] for a producer's own claim (a chat
/// message, a score); [`CrossingBasis::ConsentGrant`] naming the live
/// egress grant that covers this dimension at this audience otherwise. It
/// rides the CALL, never the reseal — a member on the reseal would change the
/// bytes the actor signed.
///
/// Sharing is not the whole flow: the recipient must ALSO be covered by a
/// directed `consent:replication:v1` grant whose prefixes include the row's
/// namespace, or the plane withholds it. See [`replication_consent_attestation`].
///
/// # Errors
/// A refusal from [`share_plan`]; canonicalization or signing failure; the
/// substrate's own typed refusals (`CustodyIsNotTheActor`,
/// `NoActorSignature`, `PromotionMovedThePreimage`,
/// `ContextualIntegrityMismatch`, `AudienceNotWider`, ...), by name.
pub async fn share(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    row: &ciris_persist::federation::Attestation,
    with: With,
    basis: CrossingBasis,
    signers: Signers<'_>,
) -> Result<Crossing, String> {
    share_to(directory, row, with.audience(), basis, signers).await
}

/// **Publish a row — world-readable, plaintext, federation-wide.**
///
/// The one act that cannot be walked back for anyone who already read it,
/// which is why it is a separate verb and not a `With` variant. Same
/// composition, idempotency and refusals as [`share`].
///
/// # Errors
/// As [`share`].
pub async fn publish(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    row: &ciris_persist::federation::Attestation,
    basis: CrossingBasis,
    signers: Signers<'_>,
) -> Result<Crossing, String> {
    tracing::info!(
        attestation_id = %row.attestation_id,
        dimension = ?ciris_persist::federation::admission::envelope_dimension(&row.attestation_envelope),
        "PUBLISHING to the federation (lightnet): world-readable and plaintext \
         at rest. This cannot be walked back for anyone who already read it"
    );
    share_to(directory, row, Audience::Federation, basis, signers).await
}

/// **Share a row with a cohort that encrypts it at rest.** The ordinary case.
///
/// ```ignore
/// // A chat message: authored `self`, then shared with the room.
/// share_encrypted_privately(
///     &*dir, &row,
///     EncryptedCohort::Community { community_key_id: room },
///     CrossingBasis::ProducerAuthority,
///     Signers { node: &node, actor: Some(&alice) },
/// ).await?;
/// ```
///
/// **Retention is not a parameter here, deliberately.** A retention limit is a
/// property of the row at AUTHORSHIP (`expires_at`, inside the signed bytes),
/// so it is set by the producer; accepting it here would be a parameter that
/// silently did nothing.
///
/// # Errors
/// As [`share`].
pub async fn share_encrypted_privately(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    row: &ciris_persist::federation::Attestation,
    cohort: EncryptedCohort,
    basis: CrossingBasis,
    signers: Signers<'_>,
) -> Result<Crossing, String> {
    share(directory, row, cohort.with(), basis, signers).await
}

/// **Share a row with a narrower AUDIENCE, but in the clear.**
///
/// `species` and `biosphere` name an audience smaller than the federation and
/// are nonetheless stored plaintext with a normal `holds_bytes` row. Separate
/// from [`share_encrypted_privately`] so the difference cannot be missed by
/// picking a neighbouring enum variant.
///
/// # Errors
/// As [`share`].
pub async fn share_clear_privately(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    row: &ciris_persist::federation::Attestation,
    cohort: ClearCohort,
    basis: CrossingBasis,
    signers: Signers<'_>,
) -> Result<Crossing, String> {
    tracing::info!(
        attestation_id = %row.attestation_id,
        cohort_scope = cohort.cohort_scope(),
        "sharing to a narrower audience but IN THE CLEAR — plaintext at rest, \
         and a discoverable holds_bytes row"
    );
    share(directory, row, cohort.with(), basis, signers).await
}

/// **Publish a row to the whole federation — world-readable, in the clear.**
///
/// The same act as [`publish`], under the name the `share_*` family uses.
///
/// # Errors
/// As [`share`].
pub async fn share_publicly(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    row: &ciris_persist::federation::Attestation,
    basis: CrossingBasis,
    signers: Signers<'_>,
) -> Result<Crossing, String> {
    publish(directory, row, basis, signers).await
}

/// **State, at the call site, that a row is NOT being shared.**
///
/// A `local` row never crosses a wire and is readable by the producing
/// occurrence only (CC 5.3.2.4.3) — that is already true without this call.
/// `keep_local` exists so "I did not share it" is something you write and an
/// audit can find, rather than something achieved by not calling anything.
///
/// It refuses two rows:
///
/// * one already at federation tier — it is not local, so the statement is
///   false;
/// * a **subject-side revocation** (`withdraws` / `recants` naming a subject
///   other than the producer). Local-tier eligibility is decided by
///   revocation authority (CC 5.3.2.4.1 / 5.3.2.2): a row another subject can
///   revoke is federation-tier BY CLASSIFICATION, may transit local in flight,
///   and MUST NOT rest there — the substrate drives it to promotion within a
///   24 h SLA. Keeping it local is not a choice on offer.
///
/// # Errors
/// Either refusal above, naming which.
pub fn keep_local(row: &ciris_persist::federation::Attestation) -> Result<(), String> {
    use ciris_persist::federation::types::attestation_tier;
    if row.tier != attestation_tier::LOCAL {
        return Err(format!(
            "row {} is at tier `{}`, not `local` — it is already on the wire, so \
             keep_local would be a false statement",
            row.attestation_id, row.tier
        ));
    }
    // CC 5.3.2.2: a revocation whose authority belongs to a subject other than
    // the producer must not rest local. The structural revocation primitives
    // are `withdraws` and `recants`.
    let is_revocation = matches!(row.attestation_type.as_str(), "withdraws" | "recants");
    let names_another_subject = row
        .subject_key_ids
        .iter()
        .any(|s| s != &row.attesting_key_id);
    if is_revocation && names_another_subject {
        return Err(format!(
            "row {} is a `{}` naming a subject other than its producer — a subject-side \
             revocation is federation-tier by classification (CC 5.3.2.2) and must not \
             rest local; it must promote within the 24h SLA",
            row.attestation_id, row.attestation_type
        ));
    }
    Ok(())
}

/// The composition both verbs are: plan → enter → widen, each refusal named.
async fn share_to(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    row: &ciris_persist::federation::Attestation,
    target: Audience,
    basis: CrossingBasis,
    signers: Signers<'_>,
) -> Result<Crossing, String> {
    // Everything decidable from the row alone is decided here, before any
    // directory is touched: no dimension, no cohort id, a narrowing.
    let plan = share_plan(row, &target)?;
    let current = Audience::of_row(row).map_err(|e| e.to_string())?;

    // ── enter_mesh: the row's own audience, the row's own bytes ──────
    let (entered, entered_ci) = match &plan {
        SharePlan::Enter | SharePlan::EnterThenWiden(_) => {
            let ci = describe_crossing(row, current.clone(), basis.clone())
                .map_err(|e| format!("describe {}: {e}", row.attestation_id))?;
            let outcome = match custody_for(row, signers).await? {
                None => MeshCrossingOutcome::AwaitingActor {
                    attestation_id: row.attestation_id.clone(),
                    age_ms: (chrono::Utc::now() - row.asserted_at).num_milliseconds(),
                },
                Some(custody) => directory
                    .enter_mesh(&row.attestation_id, &ci, &custody)
                    .await
                    .map_err(|e| format!("enter_mesh({}): {e}", row.attestation_id))?,
            };
            (outcome, ci)
        }
        SharePlan::AlreadyThere | SharePlan::Widen(_) => (
            MeshCrossingOutcome::AlreadyInMesh {
                attestation_id: row.attestation_id.clone(),
            },
            describe_crossing(row, current.clone(), basis.clone())
                .map_err(|e| format!("describe {}: {e}", row.attestation_id))?,
        ),
    };

    // ── widen_audience: a NEW row, by the actor ──────────────────────
    let (widened, ci) = match (&plan, &entered) {
        (
            SharePlan::EnterThenWiden(_) | SharePlan::Widen(_),
            MeshCrossingOutcome::AwaitingActor { .. },
        ) => {
            // A local row cannot be widened; it waits as a whole.
            (None, entered_ci)
        }
        (SharePlan::EnterThenWiden(wider) | SharePlan::Widen(wider), _) => {
            // The prior AS STORED — its tier moved a moment ago, and the
            // widening's shape rule reads it.
            let prior = directory
                .get_attestation(&row.attestation_id)
                .await
                .map_err(|e| format!("get_attestation({}): {e}", row.attestation_id))?
                .ok_or_else(|| format!("row {} vanished between verbs", row.attestation_id))?;
            let ci = describe_crossing(&prior, wider.clone(), basis)
                .map_err(|e| format!("describe widening of {}: {e}", row.attestation_id))?;
            let outcome = widen(directory, &prior, wider, &ci, signers).await?;
            (Some(outcome), ci)
        }
        (SharePlan::AlreadyThere | SharePlan::Enter, _) => (None, entered_ci),
    };

    let shared = summarize(&entered, widened.as_ref());
    let discoverable = match (&widened, &entered) {
        (Some(MeshCrossingOutcome::Crossed(mc)), _) | (None, MeshCrossingOutcome::Crossed(mc)) => {
            mc.replicates.discoverable
        }
        _ => target.discoverable(),
    };
    let crossing = Crossing {
        shared,
        ci,
        routes_to: RoutesTo::of(&target),
        discoverable,
        entered,
        widened,
    };
    tracing::info!(
        attestation_id = %row.attestation_id,
        cohort_scope = target.cohort_scope(),
        shared = ?crossing.shared,
        discoverable,
        "CROSSING THE WIRE — sender={} subject={:?} type={:?} basis={:?} custody={}",
        crossing.ci.sender,
        crossing.ci.data_subject,
        crossing.ci.information_type,
        crossing.ci.transmission_principle,
        match &crossing.entered {
            MeshCrossingOutcome::Crossed(mc) => format!("{:?}", mc.custody),
            other => format!("{other:?}"),
        }
    );
    Ok(crossing)
}

/// One `supersedes` at a wider audience, built the way every other emit is
/// (`build_widening` → `stamp_and_canonicalize` → sign → `assemble`), signed
/// by the prior's attester, written through the ordinary put door.
async fn widen(
    directory: &dyn ciris_persist::federation::FederationDirectory,
    prior: &ciris_persist::federation::Attestation,
    wider: &Audience,
    ci: &ContextualIntegrity,
    signers: Signers<'_>,
) -> Result<MeshCrossingOutcome, String> {
    use ciris_persist::federation::{attestation_emit, crossing, SignedAttestation};

    let signer = if prior.attesting_key_id == signers.node.key_id {
        signers.node
    } else {
        match signers.actor {
            Some(a) if a.key_id == prior.attesting_key_id => a,
            Some(a) => {
                return Err(format!(
                    "custody is not the actor: widening {} is a new claim by {} and cannot be \
                     signed by {} — there is no delegated widening (CC 4.4; subsidiarity)",
                    prior.attestation_id, prior.attesting_key_id, a.key_id
                ))
            }
            None => {
                return Ok(MeshCrossingOutcome::AwaitingActor {
                    attestation_id: prior.attestation_id.clone(),
                    age_ms: (chrono::Utc::now() - prior.asserted_at).num_milliseconds(),
                })
            }
        }
    };
    // ONE instant for both the act (`widened_at`, signed — persist v40.0.0 /
    // CIRISPersist#801) and whatever `stamp_and_canonicalize` still fills, so
    // the placement time is recorded once while the CLAIM's `asserted_at` is
    // carried verbatim off the prior rather than re-minted.
    let now = chrono::Utc::now();
    let mut input = crossing::build_widening(prior, wider, &[], now)
        .map_err(|e| format!("build_widening({}): {e}", prior.attestation_id))?;
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, &prior.attesting_key_id, now)
            .map_err(|e| format!("stamp widening of {}: {e}", prior.attestation_id))?;
    let sig = crate::identity::sign_hybrid_raw(signer, &canonical, "audience widening").await?;
    let (row, _emitted) =
        attestation_emit::assemble(prior.attesting_key_id.clone(), &canonical, sig, input)
            .map_err(|e| format!("assemble widening of {}: {e}", prior.attestation_id))?;
    directory
        .widen_audience(
            &prior.attestation_id,
            ci,
            SignedAttestation { attestation: row },
        )
        .await
        .map_err(|e| {
            format!(
                "widen_audience({} → {}): {e}",
                prior.attestation_id,
                wider.cohort_scope()
            )
        })
}

fn summarize(entered: &MeshCrossingOutcome, widened: Option<&MeshCrossingOutcome>) -> Shared {
    use MeshCrossingOutcome as O;
    // The widening's outcome is the one that names the audience asked for;
    // the tier crossing's stands only when no widening was needed.
    match widened.unwrap_or(entered) {
        O::Crossed(mc) => Shared::Placed {
            attestation_id: mc.attestation_id.clone(),
        },
        O::AlreadyInMesh { attestation_id } => Shared::AlreadyThere {
            attestation_id: attestation_id.clone(),
        },
        O::AlreadyWidened {
            prior_attestation_id,
        } => Shared::AlreadyThere {
            attestation_id: prior_attestation_id.clone(),
        },
        O::AwaitingActor {
            attestation_id,
            age_ms,
        } => Shared::AwaitingActor {
            attestation_id: attestation_id.clone(),
            age_ms: *age_ms,
        },
    }
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
        let owned_nodes = ciris_persist::federation::admission::nodes_owned_by(&*dir, "owner-a")
            .await
            .expect("nodes_owned_by must not error");
        assert!(
            owned_nodes.contains(&"node-b".to_string()),
            "fedID -> owned nodes is the direction `discover` walks; got {owned_nodes:?}"
        );
    }

    /// **The three-key shape**: a human owns BOTH a node and an agent, and
    /// `owner_of` resolves each to the same person.
    ///
    /// Three keys are the minimum for a viable agent — human, node, agent — and
    /// the agent needs its own owner binding or `resolve(agentID)` finds no
    /// owner and stops before it can reach a dialable node. That walk is the
    /// point of keeping the agent and node identities separate: conflated, it
    /// would be a tautology.
    #[tokio::test]
    async fn one_human_owns_both_a_node_and_an_agent() {
        let (dir, owner) = directory_with_owner_and_node().await;
        // Seed the agent's own key record, then bind it to the same human.
        let agent = signer("agent-c", 3);
        dir.put_public_key(SignedKeyRecord {
            record: signed_record("agent-c", pubkeys(&agent).await, &owner, "owner-a", "agent")
                .await,
        })
        .await
        .expect("seed agent record");

        for subject in ["node-b", "agent-c"] {
            let att = owner_binding_attestation("owner-a", subject, ts(), &owner)
                .await
                .expect("build");
            dir.put_attestation(SignedAttestation { attestation: att })
                .await
                .unwrap_or_else(|e| panic!("persist must admit the {subject} binding: {e}"));
        }

        for subject in ["node-b", "agent-c"] {
            let resolved = ciris_persist::federation::admission::owner_of(&*dir, subject)
                .await
                .expect("owner_of must not error");
            assert_eq!(
                resolved.as_deref(),
                Some("owner-a"),
                "{subject} must resolve to the same human — an agent that resolves \
                 to nobody cannot be dialled, because the dial target is a NODE \
                 reached through its owner"
            );
        }

        let dial_targets = ciris_persist::federation::admission::nodes_owned_by(&*dir, "owner-a")
            .await
            .expect("nodes_owned_by");
        assert!(
            dial_targets.contains(&"node-b".to_string()),
            "the human's NODE is the dial target reached from either identity: {dial_targets:?}"
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

/// Is an owner binding ADVERTISED by anti-entropy — and to whom?
///
/// The mesh's `ladder.discover_by_fedid` reported `identity_type: "user"` with
/// `owned_nodes: []`: the peer's directory row had arrived and its owner-binding
/// attestation had not. These tests ask the bridge's own advertise path why,
/// locally, instead of spending a mesh run per hypothesis.
#[cfg(test)]
mod advertise_tests {
    use super::*;
    use crate::replication::bridge::test_fixtures::make_bridge;
    use crate::replication::directory::ReplicationDirectory as _;
    use crate::replication::protocol::EnvelopeKind;
    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    use ciris_persist::federation::{FederationDirectory, SignedAttestation};
    use std::sync::Arc;

    /// A signer whose keys MATCH `fixture_key_record(key_id)` — the bridge
    /// fixtures derive both halves from the same `0x11`-padded key_id seed, so
    /// a signer built any other way produces a row the directory refuses.
    fn hybrid(key_id: &str) -> crate::identity::LocalSigner {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        let classical: Arc<dyn HardwareSigner> =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&seed, key_id).expect("ed"));
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&seed, format!("{key_id}-pqc")).expect("pqc"),
        );
        crate::identity::LocalSigner::new(key_id, classical, Some(pqc))
    }

    async fn bridge_world(
        self_set: &[&str],
        with_binding: bool,
    ) -> crate::replication::bridge::FederationDirectoryReplicationBridge {
        let (backend, bridge) = make_bridge(&["peer-1".to_string()]);
        let owner = hybrid("owner-a");
        // The attester must exist in `federation_keys` — an attestation whose
        // granter is unknown is a rumor with a column.
        for (kid, ity) in [
            ("owner-a", ciris_persist::federation::identity_type::USER),
            ("node-b", ciris_persist::federation::identity_type::NODE),
            // The RECIPIENT too: the sweep resolves the peer, and an
            // unresolvable recipient is withheld from before any projection
            // question is reached.
            ("peer-1", ciris_persist::federation::identity_type::NODE),
        ] {
            backend
                .put_public_key(ciris_persist::federation::SignedKeyRecord {
                    record: crate::replication::bridge::tests::fixture_key_record(kid, ity),
                })
                .await
                .expect("seed key record");
        }
        if with_binding {
            let att = owner_binding_attestation("owner-a", "node-b", chrono::Utc::now(), &owner)
                .await
                .expect("build");
            // Straight into the store: this asks what the ADVERTISE path does
            // with a held row, not what admission does with a new one.
            backend
                .put_attestation(SignedAttestation { attestation: att })
                .await
                .expect("store the binding");
        }

        // THIS node's directed consent grant at the peer. Without it the
        // recipient does not resolve and the WHOLE plane is withheld,
        // fail-closed — before any projection question is even asked.
        let local = hybrid("local-node");
        backend
            .put_public_key(ciris_persist::federation::SignedKeyRecord {
                record: crate::replication::bridge::tests::fixture_key_record(
                    "local-node",
                    ciris_persist::federation::identity_type::NODE,
                ),
            })
            .await
            .expect("seed local key record");
        let grant = replication_consent_attestation(
            "local-node",
            "peer-1",
            &DEFAULT_CONSENT_PREFIXES,
            chrono::Utc::now(),
            &local,
        )
        .await
        .expect("build consent grant");
        backend
            .put_attestation(SignedAttestation { attestation: grant })
            .await
            .expect("the consent grant must admit");

        let publish_set: Vec<String> = self_set.iter().map(|s| (*s).to_string()).collect();
        let provider: crate::replication::bridge::CohortProvider =
            Arc::new(move || publish_set.clone());
        bridge
            .with_local_key_id(Some("local-node".to_string()))
            .with_self_provider(Some(provider))
    }

    /// How many attestations this peer is offered, with and without the
    /// binding in the store. The DELTA is the binding's own contribution — the
    /// consent grant is itself an attestation and is advertised too, so a bare
    /// count answers the wrong question.
    async fn offered(self_set: &[&str], with_binding: bool) -> usize {
        bridge_world(self_set, with_binding)
            .await
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some("peer-1"))
            .await
            .len()
    }

    /// **The dimension is what makes the binding advertisable** — and it is
    /// independent of the self-publish set.
    ///
    /// Built through persist's `owner_binding_delegates_to_envelope`, the row
    /// resolves to an advertisable projection and the self-set does not enter
    /// it. Worth pinning because TWO plausible explanations for the mesh's
    /// `owned_nodes: []` were tried here first and both were wrong: a missing
    /// `self_provider` (the projection is not `SelfOwn`), and a missing
    /// `dimension` (a dimension-less binding is advertised just the same).
    /// Neither is the gate — see
    /// [`without_a_consent_grant_the_entire_plane_is_withheld`], which is.
    #[tokio::test]
    async fn the_canonical_dimension_makes_the_binding_advertisable() {
        for self_set in [&[][..], &["owner-a"][..], &["node-b"][..]] {
            assert_eq!(
                offered(self_set, true).await,
                offered(self_set, false).await + 1,
                "the binding must be offered regardless of the self-publish set \
                 (self_set={self_set:?})"
            );
        }
    }

    /// **The consent gate, stated as a test.** Strip the grant and the peer
    /// does not resolve, so the WHOLE plane is withheld — not just the binding.
    ///
    /// This is the fault the mesh actually hit: fail-closed, silent, and
    /// indistinguishable from slow convergence unless you know to look.
    #[tokio::test]
    async fn without_a_consent_grant_the_entire_plane_is_withheld() {
        let (backend, bridge) = make_bridge(&["peer-1".to_string()]);
        for (kid, ity) in [
            ("owner-a", ciris_persist::federation::identity_type::USER),
            ("node-b", ciris_persist::federation::identity_type::NODE),
            ("peer-1", ciris_persist::federation::identity_type::NODE),
            ("local-node", ciris_persist::federation::identity_type::NODE),
        ] {
            backend
                .put_public_key(ciris_persist::federation::SignedKeyRecord {
                    record: crate::replication::bridge::tests::fixture_key_record(kid, ity),
                })
                .await
                .expect("seed");
        }
        let owner = hybrid("owner-a");
        let att = owner_binding_attestation("owner-a", "node-b", chrono::Utc::now(), &owner)
            .await
            .expect("build");
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect("store");

        let publish_set = vec!["owner-a".to_string()];
        let provider: crate::replication::bridge::CohortProvider =
            Arc::new(move || publish_set.clone());
        let refs = bridge
            .with_local_key_id(Some("local-node".to_string()))
            .with_self_provider(Some(provider))
            .list_envelope_refs_for_peer(EnvelopeKind::Attestation, Some("peer-1"))
            .await;
        assert!(
            refs.is_empty(),
            "with no consent grant the recipient does not resolve and the whole \
             plane is withheld, fail-closed: {refs:?}"
        );
    }
}
