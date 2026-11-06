//! **Who is in a room, as signed records** — the two producers a roster
//! change needs, built the way [`owner_binding_attestation`] is: persist's
//! own signing envelope, hybrid-signed over exactly the bytes the door
//! verifies, admit-tested against a real backend (CIRISEdge#608).
//!
//! # The two doors, now symmetric (persist v48.0.0, CIRISPersist#860)
//!
//! persist keeps a community roster as ONE record (`Community.members`) plus
//! TWO append-only planes — widenings and revocations — folded at read time
//! by `effective_at` (`active_community_members`; a removal wins a tie). The
//! record is never rewritten to grow. Both changes are the same shape on the
//! wire: a hybrid-signed row under an authority.
//!
//! - **Widening** is [`add_community_member`]: the caller's authority signs
//!   the **widening row** `{community_key_id, member_key_id, joined_at,
//!   effective_at = joined_at, role}` ([`AdmitSpec`]) and persist appends it
//!   as a `CommunityMembershipWidening` — the 17th replicated kind. A re-add
//!   of a member already active at `effective_at` is `Ok(false)` and writes
//!   nothing; only a genuine change writes. (Before v48 the spec was a scrub
//!   over the GROWN record, which rewrote the roster in place — a fork at
//!   every peer.)
//! - **Revocation** is [`put_community_membership_revocation`]: a signed
//!   append-only row, keyed `(community, member, effective_at)` so a re-added
//!   member can be removed again. It is also the **DEK-rotation trigger** —
//!   the door verifies the signature, then bumps the community DEK epoch in
//!   the same transaction (CC 4.4.3.2.2), so the next seal wraps only to the
//!   remaining members. Blobs already sealed keep their grants: forward
//!   secrecy on this axis is rotation, not recall (CC 4.5.12.1 Option A). A
//!   widening does NOT rotate: the minter wraps the member at its next seal.
//!
//! A room is a keyless identifier (V151): neither door needs the room to be a
//! registered key — every pair room and allocated room edge produces can now
//! be revoked from.
//!
//! # What the substrate adjudicates (persist v49.0.0, CIRISPersist#908)
//!
//! Both doors verify the signature AND the signers' **standing**: a widening
//! or revocation counts only if its signers satisfy the group's
//! `consensus_protocol` evaluated over the active roster at the row's
//! `effective_at` (`founder_only`, `unanimous`, `majority`, `quorum:M/N`,
//! `reverse_quorum`, `weighted:*`/`custom:*` from the `policy_blob`; only
//! founders count in `infrastructure` rooms), or is a member removing
//! themself, or, for a widening, a moderator whose appointment was live at
//! that instant. A moderator removes nobody (persist v61.0.3, CIRISPersist#1200):
//! a removal meets the protocol. The fold keeps the ones already admitted.
//! Rows may carry `cosignatures` (each hybrid-verified over the same
//! envelope) to reach a threshold. A change that leaves the group with no
//! founder is never admitted; no ending is retroactive. The refusal is
//! `RosterAuthorityUnauthorized { rule }` — edge classifies it terminal except
//! `roster_authority_not_established` (retry after the roster) and
//! `roster_consensus_insufficient` (a moderator's widening may have outrun its
//! `delegates_to`). `witness_set` is stored, not counted. Whether `authority`
//! SHOULD change this roster is therefore no longer only the caller's policy:
//! the door enforces the room's own protocol.
//!
//! # A removal under `unanimous` (persist v61.0.2, CIRISPersist#1192)
//!
//! Every OTHER active member signs, and those voices are a strict majority of
//! the roster. At two members nobody is removable and resignation is the exit:
//! a removal the removed member signs is their own resignation, whoever else
//! signs it. An admission still needs every member.
//!
//! # v61: every voice cosigns the row; edge counts nothing
//!
//! Since persist v61 (CIRISPersist#1123) one voice never widens or removes
//! above the family, and a widening or removal is a `membership:*` row whose
//! cosignatures ride as `additional_scrubs`. This module is edge's share of
//! that (CIRISConstitution#198 §5, `FSD/QUORUM_AND_PENDING_DECISIONS.md`):
//! [`RosterEvent`] is the exact bytes every voice signs, [`cosign`] is one
//! voice made with one pen, and [`assemble`] hands the voices to persist's
//! door in the order given. **Whether they suffice is the door's answer**;
//! edge holds no threshold, no window and no tally.
//!
//! A room is a keyless identifier (V151): neither door needs the room to be a
//! registered key — every pair room and allocated room edge produces can now
//! be revoked from.
//!
//! # A widening needs the member's own acceptance (persist v52.0.0)
//!
//! CIRISConstitution#133 / CIRISPersist#955: nobody joins without their own
//! consent. The widening door admits a growth only on a matching live
//! `membership:acceptance:v1` by the member, so the producer here is step 3
//! of [`crate::membership`]'s propose → accept → widen; without the
//! acceptance persist refuses it by rule. A room is founded by its opener
//! alone ([`crate::chat::community`] with one member, or
//! [`crate::chat::open_pair_room`]).
//!
//! # Both changes replicate
//!
//! `CommunityMembershipWidening` and `CommunityMembershipRevocation` are each
//! their own envelope kind; the bridge sweeps and applies them like every
//! structural plane, and every node folds the same events into the same
//! roster. There is no longer a "local truth" widening.
//!
//! [`owner_binding_attestation`]: crate::replication::attestation_bind::owner_binding_attestation
//! [`add_community_member`]: FederationDirectory::add_community_member
//! [`put_community_membership_revocation`]: FederationDirectory::put_community_membership_revocation

use ciris_persist::federation::cohort::AdmitSpec;
use ciris_persist::federation::types::{
    CommunityMember, CommunityMembershipRevocation, CommunityMembershipWidening, RosterCosignature,
    SignedCommunityMembershipRevocation,
};
use ciris_persist::federation::FederationDirectory;

/// **One roster event, as the bytes persist's door verifies** (v61; CC 2.4
/// cosigned rows, CC 3.1.3.2). Every voice on the change, whether authority
/// or cosigner, signs exactly [`Self::signing_bytes`]. Edge builds the event, a
/// pen signs it ([`cosign`]), and persist's door counts the voices
/// ([`assemble`]); **edge counts nothing** (CIRISConstitution#198 §5,
/// `FSD/QUORUM_AND_PENDING_DECISIONS.md`).
#[derive(Debug, Clone, PartialEq)]
pub enum RosterEvent {
    /// A seat: `membership:widening:v1`.
    Widening(CommunityMembershipWidening),
    /// A removal (`membership:removal:v1`), or a resignation when the removed
    /// member signs it alone.
    Revocation(CommunityMembershipRevocation),
}

impl RosterEvent {
    /// The widening that seats `member_key_id` in `community_key_id` at
    /// `role`, effective `at`. Persist stores the instant at millisecond
    /// precision, so it is truncated here: a signature over sub-millisecond
    /// digits would cover bytes the row never carries.
    #[must_use]
    pub fn widening(
        community_key_id: &str,
        member_key_id: &str,
        role: Option<&str>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let at = crate::replication::attestation_bind::truncate_to_substrate_resolution(at);
        Self::Widening(CommunityMembershipWidening {
            community_key_id: community_key_id.to_owned(),
            member_key_id: member_key_id.to_owned(),
            joined_at: at,
            effective_at: at,
            role: role.map(str::to_owned),
            persist_row_hash: String::new(),
        })
    }

    /// The removal of `removed_identity_key_id`, effective (and removed) `at`.
    /// Persist refuses a future-dated community removal (SecReview F4), so `at`
    /// is now or the past. `witness_set` is stored, not counted.
    #[must_use]
    pub fn revocation(
        community_key_id: &str,
        removed_identity_key_id: &str,
        at: chrono::DateTime<chrono::Utc>,
        reason: Option<&str>,
        witness_set: &[&str],
    ) -> Self {
        let at = crate::replication::attestation_bind::truncate_to_substrate_resolution(at);
        Self::Revocation(CommunityMembershipRevocation {
            community_key_id: community_key_id.to_owned(),
            removed_identity_key_id: removed_identity_key_id.to_owned(),
            removed_at: at,
            effective_at: at,
            reason: reason.map(str::to_owned),
            witness_set: witness_set.iter().map(|w| (*w).to_owned()).collect(),
            persist_row_hash: String::new(),
        })
    }

    /// The room the event changes.
    #[must_use]
    pub fn community_key_id(&self) -> &str {
        match self {
            Self::Widening(w) => &w.community_key_id,
            Self::Revocation(r) => &r.community_key_id,
        }
    }

    /// The member the event seats or removes.
    #[must_use]
    pub fn member_key_id(&self) -> &str {
        match self {
            Self::Widening(w) => &w.member_key_id,
            Self::Revocation(r) => &r.removed_identity_key_id,
        }
    }

    /// `JCS(signing_envelope())`: the one byte string every voice signs.
    ///
    /// # Errors
    /// Canonicalization failure.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let envelope = match self {
            Self::Widening(w) => w.signing_envelope(),
            Self::Revocation(r) => r.signing_envelope(),
        };
        ciris_persist::prelude::ceg_produce_canonicalize(&envelope)
            .map_err(|e| format!("canonicalize the roster event: {e}"))
    }
}

/// **One voice on a roster event**: `pen`'s hybrid signature (Ed25519, then
/// ML-DSA-65 over `bytes ‖ ed25519_sig`) over [`RosterEvent::signing_bytes`].
/// Made on the signer's own node with their own pen. It travels to whoever
/// assembles unaltered; edge never re-signs or edits it.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn cosign(
    event: &RosterEvent,
    pen: &crate::identity::LocalSigner,
) -> Result<RosterCosignature, String> {
    let bytes = event.signing_bytes()?;
    let (scrub_signature_classical, scrub_signature_pqc) =
        crate::identity::sign_bound_hybrid(pen, &bytes, "roster event").await?;
    Ok(RosterCosignature {
        authority_key_id: pen.key_id.clone(),
        scrub_signature_classical,
        scrub_signature_pqc,
    })
}

/// The first voice is the row's authority; the rest ride as its
/// cosignatures, **in the order given**. Nothing is counted, de-duplicated or
/// dropped: a duplicate or an ineligible voice is the door's to ignore.
fn split_voices(
    signatures: Vec<RosterCosignature>,
) -> Result<(RosterCosignature, Vec<RosterCosignature>), String> {
    let mut it = signatures.into_iter();
    let primary = it
        .next()
        .ok_or_else(|| "a roster event needs at least one signature".to_owned())?;
    Ok((primary, it.collect()))
}

/// **Hand a signed roster event to persist's door**: the widening through
/// `add_community_member`, the removal through
/// `put_community_membership_revocation` (which rotates the room's DEK in
/// the same transaction when admitted). The door verifies every signature
/// and judges the voices under the room's `consensus_protocol` (and, for a
/// growth, the member's own acceptance); its refusal comes back verbatim.
///
/// `Ok(true)` = the row was written; `Ok(false)` = the door's idempotent
/// no-op (a widening of a member already active at that instant). Whichever
/// node assembles first writes; every later assembly of the same event is the
/// no-op, and the row reaches every node through replication.
///
/// # Errors
/// No signature; the community is unknown here (a widening); the door's
/// refusal, e.g. `roster_consensus_insufficient` for a short set.
pub async fn assemble(
    directory: &dyn FederationDirectory,
    event: &RosterEvent,
    signatures: Vec<RosterCosignature>,
) -> Result<bool, String> {
    let (primary, cosignatures) = split_voices(signatures)?;
    match event {
        RosterEvent::Widening(w) => {
            if directory
                .lookup_community(&w.community_key_id)
                .await
                .map_err(|e| format!("lookup room {}: {e}", w.community_key_id))?
                .is_none()
            {
                return Err(format!(
                    "room {} is not on this directory: a widening names a roster that must \
                     exist to be folded",
                    w.community_key_id
                ));
            }
            let member = CommunityMember {
                key_id: w.member_key_id.clone(),
                joined_at: w.joined_at,
                role: w.role.clone(),
            };
            let spec = AdmitSpec {
                authority_key_id: primary.authority_key_id,
                scrub_signature_classical: primary.scrub_signature_classical,
                scrub_signature_pqc: primary.scrub_signature_pqc,
                cosignatures,
            };
            directory
                .add_community_member(&w.community_key_id, member, &spec)
                .await
                .map_err(|e| {
                    format!(
                        "widen room {} with {}: {e}",
                        w.community_key_id, w.member_key_id
                    )
                })
        }
        RosterEvent::Revocation(r) => directory
            .put_community_membership_revocation(SignedCommunityMembershipRevocation {
                community_membership_revocation: r.clone(),
                authority_key_id: primary.authority_key_id,
                scrub_signature_classical: primary.scrub_signature_classical,
                scrub_signature_pqc: primary.scrub_signature_pqc,
                cosignatures,
            })
            .await
            .map(|()| true)
            .map_err(|e| {
                format!(
                    "remove {} from room {}: {e}",
                    r.removed_identity_key_id, r.community_key_id
                )
            }),
    }
}

/// [`cosign`] by each pen in `pens`, in order: the signature set a host
/// holding several pens (or a test) hands to [`assemble`].
///
/// # Errors
/// [`cosign`]'s.
pub async fn cosign_all(
    event: &RosterEvent,
    pens: &[&crate::identity::LocalSigner],
) -> Result<Vec<RosterCosignature>, String> {
    let mut out = Vec::with_capacity(pens.len());
    for pen in pens {
        out.push(cosign(event, pen).await?);
    }
    Ok(out)
}

/// **The widening signed by ONE authority**, as an [`AdmitSpec`] with no
/// cosignatures, plus the member row: the shape CIRISServer's `put_widening`
/// builds on. One voice is admitted only where the room's protocol says one
/// voice is enough (a room of one, a `founder_only` family). Collect the
/// others with [`cosign`] and use [`assemble`].
///
/// # Errors
/// The community is unknown to this directory; canonicalization or signing
/// failed.
pub async fn community_membership_widening(
    directory: &dyn FederationDirectory,
    community_key_id: &str,
    member_key_id: &str,
    role: Option<&str>,
    joined_at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<(CommunityMember, AdmitSpec), String> {
    if directory
        .lookup_community(community_key_id)
        .await
        .map_err(|e| format!("lookup room {community_key_id}: {e}"))?
        .is_none()
    {
        return Err(format!(
            "room {community_key_id} is not on this directory: a widening names a roster \
             that must exist to be folded"
        ));
    }
    let event = RosterEvent::widening(community_key_id, member_key_id, role, joined_at);
    let RosterEvent::Widening(w) = &event else {
        unreachable!("RosterEvent::widening builds a widening")
    };
    let member = CommunityMember {
        key_id: w.member_key_id.clone(),
        joined_at: w.joined_at,
        role: w.role.clone(),
    };
    let voice = cosign(&event, authority).await?;
    Ok((
        member,
        AdmitSpec {
            authority_key_id: voice.authority_key_id,
            scrub_signature_classical: voice.scrub_signature_classical,
            scrub_signature_pqc: voice.scrub_signature_pqc,
            cosignatures: Vec::new(),
        },
    ))
}

/// **Widen with every pen in `pens`**: [`cosign_all`] then [`assemble`].
/// `Ok(true)` is a genuine add, `Ok(false)` the idempotent no-op.
///
/// # Errors
/// [`assemble`]'s; the door refuses a set its protocol does not admit.
pub async fn widen_community(
    directory: &dyn FederationDirectory,
    community_key_id: &str,
    member_key_id: &str,
    role: Option<&str>,
    joined_at: chrono::DateTime<chrono::Utc>,
    pens: &[&crate::identity::LocalSigner],
) -> Result<bool, String> {
    let event = RosterEvent::widening(community_key_id, member_key_id, role, joined_at);
    let voices = cosign_all(&event, pens).await?;
    assemble(directory, &event, voices).await
}

/// **The removal signed by ONE authority**: a member removing themself (a
/// resignation), or the authority voice of a removal whose cosignatures are
/// added by the caller. The CIRISServer `put_revocation` shape.
///
/// # Errors
/// Canonicalization or signing failure.
pub async fn community_membership_revocation(
    community_key_id: &str,
    removed_identity_key_id: &str,
    effective_at: chrono::DateTime<chrono::Utc>,
    reason: Option<&str>,
    witness_set: &[&str],
    authority: &crate::identity::LocalSigner,
) -> Result<SignedCommunityMembershipRevocation, String> {
    let event = RosterEvent::revocation(
        community_key_id,
        removed_identity_key_id,
        effective_at,
        reason,
        witness_set,
    );
    let RosterEvent::Revocation(revocation) = &event else {
        unreachable!("RosterEvent::revocation builds a revocation")
    };
    let voice = cosign(&event, authority).await?;
    Ok(SignedCommunityMembershipRevocation {
        community_membership_revocation: revocation.clone(),
        authority_key_id: voice.authority_key_id,
        scrub_signature_classical: voice.scrub_signature_classical,
        scrub_signature_pqc: voice.scrub_signature_pqc,
        cosignatures: Vec::new(),
    })
}

/// **Remove with every pen in `pens`**: [`cosign_all`] then [`assemble`].
/// When this returns `Ok`, the member is off the room's ACTIVE roster on this
/// directory and the DEK epoch has moved. A member already off the active
/// roster is `Ok` with nothing written (what the caller asked for already
/// holds).
///
/// # Errors
/// [`assemble`]'s; the door refuses a set the protocol does not admit, a
/// future-dated instant, or a signature that does not verify.
pub async fn revoke_community_member(
    directory: &dyn FederationDirectory,
    community_key_id: &str,
    removed_identity_key_id: &str,
    effective_at: chrono::DateTime<chrono::Utc>,
    reason: Option<&str>,
    witness_set: &[&str],
    pens: &[&crate::identity::LocalSigner],
) -> Result<(), String> {
    if !ciris_persist::federation::is_active_community_member(
        directory,
        community_key_id,
        removed_identity_key_id,
    )
    .await
    .map_err(|e| format!("active roster of room {community_key_id}: {e}"))?
    {
        return Ok(());
    }
    let event = RosterEvent::revocation(
        community_key_id,
        removed_identity_key_id,
        effective_at,
        reason,
        witness_set,
    );
    let voices = cosign_all(&event, pens).await?;
    assemble(directory, &event, voices).await.map(|_| ())
}

#[cfg(test)]
mod admit_tests {
    use super::*;
    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    use ciris_persist::federation::SignedKeyRecord;
    use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord};
    use ciris_persist::store::sqlite::SqliteBackend;
    use ciris_persist::store::Backend as _;
    use sha2::Digest as _;
    use std::sync::Arc;

    fn ts() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .unwrap()
            .into()
    }

    /// A person's signer, registered under the id derived from its own key
    /// (CIRISPersist#1103); the seed is the person's ([`fed`]).
    fn signer(label: &str, seed: u8) -> crate::identity::LocalSigner {
        signer_as(
            &crate::identity::derived_fixture_key_id(label, &[seed; 32]),
            seed,
        )
    }

    /// A signer under `key_id` verbatim — for the room id, which persist's
    /// fixture convention registers as a key (a group id: not derived).
    fn signer_as(key_id: &str, seed: u8) -> crate::identity::LocalSigner {
        let classical: Arc<dyn HardwareSigner> =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).unwrap());
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
                .unwrap(),
        );
        crate::identity::LocalSigner::new(key_id, classical, Some(pqc))
    }

    /// The registered id of the fixture person `label` (CIRISPersist#1103).
    fn fed(label: &str) -> String {
        let seed = match label {
            "alice-fed" => 1,
            "bob-fed" => 2,
            "carol-fed" => 3,
            "dave-fed" => 4,
            other => panic!("no fixture person {other}"),
        };
        crate::identity::derived_fixture_key_id(label, &[seed; 32])
    }

    async fn user_record(s: &crate::identity::LocalSigner) -> KeyRecord {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let ed = b64.encode(s.classical.public_key().await.unwrap());
        let pqc = b64.encode(s.pqc.as_ref().unwrap().public_key().await.unwrap());
        let envelope = serde_json::json!({
            "key_id": s.key_id,
            "identity_type": "user",
            "pubkey_ed25519_base64": ed,
            "pubkey_ml_dsa_65_base64": pqc,
        });
        let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).unwrap();
        let digest = sha2::Sha256::digest(&canonical);
        let (sig, sig_pqc) = crate::identity::sign_bound_hybrid(s, &canonical, "key record")
            .await
            .unwrap();
        KeyRecord {
            key_id: s.key_id.clone(),
            pubkey_ed25519_base64: ed,
            pubkey_ml_dsa_65_base64: Some(pqc),
            algorithm: "hybrid".to_owned(),
            identity_type: "user".to_owned(),
            identity_ref: s.key_id.clone(),
            valid_from: ts(),
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig,
            scrub_signature_pqc: sig_pqc,
            scrub_key_id: s.key_id.clone(),
            scrub_timestamp: ts(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// persist v52.0.0 (CIRISPersist#955) — `member` consents to join `room`
    /// (at `role`): a proposal by `founder`, accepted by `member` — the real
    /// flow, through [`crate::membership`], not a fixture shortcut.
    async fn consent(
        dir: &SqliteBackend,
        room: &str,
        founder: &crate::identity::LocalSigner,
        member: &crate::identity::LocalSigner,
        role: Option<&str>,
    ) {
        let proposal = crate::membership::propose(
            dir,
            crate::membership::GroupScope::Community,
            room,
            &member.key_id,
            role,
            chrono::Utc::now() + chrono::Duration::days(7),
            founder,
        )
        .await
        .expect("the founder's proposal is admitted");
        crate::membership::reply(dir, &proposal.attestation_id, true, member)
            .await
            .expect("the member's acceptance is admitted");
    }

    /// A directory with three registered humans and a room founded by the
    /// first ALONE (persist v52.0.0: a founding record admits only its
    /// signers), the second joined by proposal → acceptance → widening.
    /// Returns `(dir, founder, room id, carol)` — carol has NOT consented.
    ///
    /// `register_room_key` decides whether the room's id is ALSO registered
    /// as a federation key. persist's revocation table FKs
    /// `community_key_id` onto `federation_keys`, and persist's own
    /// invariant fixtures satisfy it by registering the community id as a
    /// key (`seed_community_everywhere`: "the community key", role `user`).
    /// That is a FIXTURE convention, not a production shape — edge does not
    /// register a room as a person — so it is a parameter here: the
    /// revocation tests need it to exercise the door at all, and
    /// `a_room_that_is_not_a_registered_key_cannot_revoke_yet` pins the
    /// refusal a production room gets without it.
    async fn room_of_two(
        register_room_key: bool,
    ) -> (
        Arc<SqliteBackend>,
        crate::identity::LocalSigner,
        String,
        crate::identity::LocalSigner,
    ) {
        room_of_two_under(
            ciris_persist::federation::types::consensus_protocol::UNANIMOUS,
            register_room_key,
        )
        .await
    }

    /// [`room_of_two`] under `protocol`.
    async fn room_of_two_under(
        protocol: &str,
        register_room_key: bool,
    ) -> (
        Arc<SqliteBackend>,
        crate::identity::LocalSigner,
        String,
        crate::identity::LocalSigner,
    ) {
        let alice = signer("alice-fed", 1);
        let bob = signer("bob-fed", 2);
        let carol = signer("carol-fed", 3);
        let dir = FederationDirectorySqlite::open(":memory:").await.unwrap();
        dir.run_migrations().await.unwrap();
        for s in [&alice, &bob, &carol] {
            dir.put_public_key(SignedKeyRecord {
                record: user_record(s).await,
            })
            .await
            .expect("register");
        }
        let room = crate::chat::new_room_community_key_id();
        if register_room_key {
            // persist's I63 shape: the community id is a registered key. The
            // key material is throwaway — nothing signs AS the room here; the
            // founder signs everything — the row exists to satisfy the FK.
            dir.put_public_key(SignedKeyRecord {
                record: user_record(&signer_as(&room, 9)).await,
            })
            .await
            .expect("register the room id as a key (persist fixture convention)");
        }
        let record = crate::chat::community(
            &room,
            "the room",
            &[(
                &fed("alice-fed"),
                Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER),
            )],
            protocol,
            ts(),
        )
        .expect("a founder is on it");
        dir.put_community(
            crate::chat::signed_community(record, &alice)
                .await
                .expect("sign"),
        )
        .await
        .expect("persist admits the room");
        consent(&dir, &room, &alice, &bob, None).await;
        assert!(
            widen_community(&*dir, &room, &fed("bob-fed"), None, ts(), &[&alice])
                .await
                .expect("bob joins on his acceptance")
        );
        (dir, alice, room, carol)
    }

    async fn active(dir: &SqliteBackend, room: &str) -> Vec<String> {
        let mut m: Vec<String> = dir
            .active_community_members(room)
            .await
            .expect("active roster")
            .into_iter()
            .map(|m| m.key_id)
            .collect();
        m.sort();
        m
    }

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        ts() + chrono::Duration::seconds(secs)
    }

    fn insufficient(err: &str) -> bool {
        err.contains(ciris_persist::federation::ROSTER_CONSENSUS_INSUFFICIENT)
    }

    /// A `majority` room of THREE (alice, bob, carol): carol consented and
    /// was seated by alice and bob together. (Majority, not unanimous: persist
    /// v61 counts the removed member among a unanimous removal's eligible
    /// signers, where CC 3.1.3.2 says "every other member and a strict
    /// majority"; CIRISPersist#1192. A removal witness under unanimous would
    /// need the target's own voice.)
    async fn room_of_three(
        register_room_key: bool,
    ) -> (
        Arc<SqliteBackend>,
        crate::identity::LocalSigner,
        crate::identity::LocalSigner,
        crate::identity::LocalSigner,
        String,
    ) {
        let (dir, alice, room, carol) = room_of_two_under(
            ciris_persist::federation::types::consensus_protocol::MAJORITY,
            register_room_key,
        )
        .await;
        let bob = signer("bob-fed", 2);
        consent(&dir, &room, &alice, &carol, None).await;
        assert!(widen_community(
            &*dir,
            &room,
            &fed("carol-fed"),
            None,
            at(1),
            &[&alice, &bob]
        )
        .await
        .expect("alice and bob together seat carol"));
        (dir, alice, bob, carol, room)
    }

    /// **The cosigned widening persist admits, and the roster reads back
    /// grown** (v61: under `unanimous`, every member signs). One voice is
    /// refused BY THE DOOR (`roster_consensus_insufficient`) and writes
    /// nothing; edge counted nothing in either case.
    #[tokio::test]
    async fn a_widening_is_admitted_and_the_active_roster_grows() {
        let (dir, alice, room, carol) = room_of_two(false).await;
        let bob = signer("bob-fed", 2);
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")]
        );
        consent(&dir, &room, &alice, &carol, None).await;

        let err = widen_community(&*dir, &room, &fed("carol-fed"), None, at(1), &[&alice])
            .await
            .expect_err("one voice of two never seats under unanimous");
        assert!(insufficient(&err), "the door's rule, verbatim: {err}");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")]
        );

        let added = widen_community(
            &*dir,
            &room,
            &fed("carol-fed"),
            None,
            at(1),
            &[&alice, &bob],
        )
        .await
        .expect("persist must ADMIT the cosigned widening");
        assert!(added, "a genuine add reports true");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed"), fed("carol-fed")],
            "the ACTIVE roster (what the DEK cascade wraps to) includes the new member",
        );

        // Idempotent: whichever node assembles the same event later writes
        // nothing (the door's no-op), with either signature order.
        let again = widen_community(
            &*dir,
            &room,
            &fed("carol-fed"),
            None,
            at(1),
            &[&bob, &alice],
        )
        .await
        .expect("a second assembly of the same event is not an error");
        assert!(!again, "a member already on the roster is a no-op");
    }

    /// **The voices travel as signed: `assemble` hands the door every
    /// cosignature it was given.** The same two voices carried by hand
    /// through [`cosign`] on each signer's side, then [`assemble`]d by a
    /// third party who signs nothing, are admitted.
    #[tokio::test]
    async fn cosignatures_made_apart_assemble_anywhere() {
        let (dir, alice, room, carol) = room_of_two(false).await;
        let bob = signer("bob-fed", 2);
        consent(&dir, &room, &alice, &carol, None).await;
        let event = RosterEvent::widening(&room, &fed("carol-fed"), None, at(1));
        let from_alice = cosign(&event, &alice)
            .await
            .expect("alice signs on her node");
        let from_bob = cosign(&event, &bob).await.expect("bob signs on his node");
        assert!(assemble(&*dir, &event, vec![from_bob, from_alice])
            .await
            .expect("admitted"));
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed"), fed("carol-fed")]
        );
    }

    /// **A widening is signed over the ROW, so a roster that moved does not
    /// invalidate it** (v48, #860). Under v61 the door judges the row's voices
    /// against the roster AT ITS OWN INSTANT: alice and bob seat carol at t1,
    /// then (a roster of three) all three seat dave at t2; the voices alice
    /// and bob signed for carol before dave arrived still count.
    #[tokio::test]
    async fn a_widening_signed_over_the_row_survives_a_moved_roster() {
        let (dir, alice, room, carol) = room_of_two(false).await;
        let bob = signer("bob-fed", 2);
        let dave = signer("dave-fed", 4);
        dir.put_public_key(SignedKeyRecord {
            record: user_record(&dave).await,
        })
        .await
        .expect("register dave");
        consent(&dir, &room, &alice, &carol, None).await;
        consent(&dir, &room, &alice, &dave, None).await;
        let carol_event = RosterEvent::widening(&room, &fed("carol-fed"), None, at(1));
        let carol_voices = cosign_all(&carol_event, &[&alice, &bob])
            .await
            .expect("signed before anything moved");
        // Put carol first (her instant is earlier), then dave by all three.
        assert!(assemble(&*dir, &carol_event, carol_voices)
            .await
            .expect("carol's row is the row alice and bob signed"));
        assert!(widen_community(
            &*dir,
            &room,
            &fed("dave-fed"),
            None,
            at(2),
            &[&alice, &bob, &carol]
        )
        .await
        .expect("dave, by the room of three"));
        assert_eq!(
            active(&dir, &room).await,
            [
                fed("alice-fed"),
                fed("bob-fed"),
                fed("carol-fed"),
                fed("dave-fed")
            ],
        );
        assert!(
            !widen_community(
                &*dir,
                &room,
                &fed("carol-fed"),
                None,
                at(1),
                &[&alice, &bob]
            )
            .await
            .expect("re-add is not an error"),
            "a member already active at effective_at is Ok(false)"
        );
    }

    /// **The removal persist admits, the active roster shrinks, and the DEK
    /// epoch moved.** In a `majority` room of three, alice and carol remove
    /// bob (two of three); bob's own voice is not needed, and one voice is
    /// refused.
    #[tokio::test]
    async fn a_removal_is_admitted_shrinks_the_roster_and_rotates_the_epoch() {
        let (dir, alice, _bob, carol, room) = room_of_three(true).await;
        assert!(dir
            .list_community_membership_revocations_for(&room)
            .await
            .expect("list")
            .is_empty());

        let err = revoke_community_member(
            &*dir,
            &room,
            &fed("bob-fed"),
            at(2),
            Some("left the room"),
            &[],
            &[&alice],
        )
        .await
        .expect_err("one voice of three never removes under majority");
        assert!(insufficient(&err), "{err}");

        revoke_community_member(
            &*dir,
            &room,
            &fed("bob-fed"),
            at(2),
            Some("left the room"),
            &[],
            &[&alice, &carol],
        )
        .await
        .expect("persist must ADMIT the cosigned removal");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("carol-fed")],
            "the ACTIVE roster excludes the removed member (append-only revocation)",
        );
        let revs = dir
            .list_community_membership_revocations_for(&room)
            .await
            .expect("list");
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].removed_identity_key_id, fed("bob-fed"));
        assert_eq!(revs[0].reason.as_deref(), Some("left the room"));

        // A member already off the active roster: nothing to write.
        revoke_community_member(&*dir, &room, &fed("bob-fed"), at(3), None, &[], &[&alice])
            .await
            .expect("a repeated removal is not an error");
    }

    /// **A widening signed by a key that is not what it claims is refused**:
    /// roster growth is not an unauthenticated write door.
    #[tokio::test]
    async fn a_widening_under_a_forged_authority_is_refused() {
        let (dir, alice, room, carol) = room_of_two(false).await;
        consent(&dir, &room, &alice, &carol, None).await;
        let (member, mut spec) =
            community_membership_widening(&*dir, &room, &fed("carol-fed"), None, ts(), &carol)
                .await
                .expect("build");
        spec.authority_key_id = fed("alice-fed");
        let err = dir
            .add_community_member(&room, member, &spec)
            .await
            .expect_err(
                "a signature that does not verify against the claimed authority is refused",
            );
        let msg = err.to_string();
        assert!(
            msg.contains("signature") || msg.contains("verify") || msg.contains("Signature"),
            "the refusal names the signature, not a later step: {msg}",
        );
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")],
            "and nothing was written",
        );
    }

    /// **A forged cosignature is refused, not skipped**: a voice claiming bob
    /// but made by carol fails the door's verify, so a set that would have
    /// met the protocol with bob's real voice does not land.
    #[tokio::test]
    async fn a_forged_cosignature_is_refused() {
        let (dir, alice, room, carol) = room_of_two(false).await;
        consent(&dir, &room, &alice, &carol, None).await;
        let event = RosterEvent::widening(&room, &fed("carol-fed"), None, at(1));
        let mut forged = cosign(&event, &carol).await.expect("sign");
        forged.authority_key_id = fed("bob-fed");
        let voices = vec![cosign(&event, &alice).await.expect("sign"), forged];
        assemble(&*dir, &event, voices)
            .await
            .expect_err("a cosignature that does not verify is refused");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")]
        );
    }

    /// **A removal signed by a key that is not what it claims is refused**
    /// before any rotation (the E4 hole: an unverified removal would rotate
    /// the room's DEK).
    #[tokio::test]
    async fn a_removal_under_a_forged_authority_is_refused_before_any_rotation() {
        let (dir, _alice, room, carol) = room_of_two(true).await;
        let mut signed =
            community_membership_revocation(&room, &fed("bob-fed"), ts(), None, &[], &carol)
                .await
                .expect("build");
        signed.authority_key_id = fed("alice-fed");
        let msg = dir
            .put_community_membership_revocation(signed)
            .await
            .expect_err("a forged removal is refused at the signature, before the epoch bump")
            .to_string();
        // Alice alone is refused at two members anyway (CIRISPersist#1192), so
        // the refusal has to name the signature or this witnesses nothing.
        assert!(
            msg.contains("signature") || msg.contains("verify") || msg.contains("Signature"),
            "the refusal names the signature, not the tally: {msg}",
        );
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")],
            "nothing was written",
        );
    }

    /// **A future-dated removal is refused** (persist SecReview F4: community
    /// removal is immediate, for forward secrecy), even with every voice.
    #[tokio::test]
    async fn a_future_dated_removal_is_refused() {
        let (dir, alice, _bob, carol, room) = room_of_three(true).await;
        let future = chrono::Utc::now() + chrono::Duration::days(1);
        let err = revoke_community_member(
            &*dir,
            &room,
            &fed("bob-fed"),
            future,
            None,
            &[],
            &[&alice, &carol],
        )
        .await
        .expect_err("persist refuses a future-dated community removal");
        assert!(
            err.contains("effective_at") || err.contains("future"),
            "the refusal names the instant: {err}",
        );
    }

    /// **A keyless room can revoke (V151), and a re-added member can be
    /// removed again** (the PK carries `effective_at`). bob's re-seat needs a
    /// FRESH acceptance: the first one was spent by the widening that seated
    /// him (CC 3.1.3.2 (5)).
    #[tokio::test]
    async fn a_keyless_room_can_revoke_and_a_re_added_member_can_be_removed_again() {
        let (dir, alice, bob, carol, room) = room_of_three(false).await;
        revoke_community_member(
            &*dir,
            &room,
            &fed("bob-fed"),
            at(2),
            None,
            &[],
            &[&alice, &carol],
        )
        .await
        .expect("a room that is not a registered key can revoke");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("carol-fed")]
        );
        consent(&dir, &room, &alice, &bob, None).await;
        assert!(widen_community(
            &*dir,
            &room,
            &fed("bob-fed"),
            None,
            at(3),
            &[&alice, &carol]
        )
        .await
        .expect("re-add, on bob's fresh acceptance"));
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed"), fed("carol-fed")]
        );
        revoke_community_member(
            &*dir,
            &room,
            &fed("bob-fed"),
            at(4),
            None,
            &[],
            &[&alice, &carol],
        )
        .await
        .expect("a re-added member can be removed again");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("carol-fed")]
        );
        assert_eq!(
            dir.list_community_membership_revocations_for(&room)
                .await
                .expect("list")
                .len(),
            2,
            "two revocations, two instants"
        );
    }

    /// persist v52.0.0 (CIRISPersist#955) — **a widening without the member's
    /// own acceptance is refused BY RULE**, retryable, even with every voice.
    #[tokio::test]
    async fn a_widening_without_the_members_acceptance_is_refused_by_rule() {
        let (dir, alice, room, _carol) = room_of_two(false).await;
        let bob = signer("bob-fed", 2);
        let err = crate::membership::widen_cosigned(
            &*dir,
            crate::membership::GroupScope::Community,
            &room,
            &fed("carol-fed"),
            None,
            at(1),
            &[&alice, &bob],
        )
        .await
        .expect_err("no acceptance, no growth");
        assert_eq!(
            err.rule(),
            Some(crate::membership::RULE_ACCEPTANCE_UNRESOLVED),
            "{err}"
        );
        assert!(err.is_retryable(), "the acceptance may still arrive");
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")]
        );
    }

    /// persist v52.0.0 (CIRISPersist#955) — **a decline is final**: a later
    /// widening under that proposal is refused `membership_declined`, TERMINAL,
    /// whatever voices it carries.
    #[tokio::test]
    async fn a_declined_proposal_refuses_the_widening_terminally() {
        let (dir, alice, room, carol) = room_of_two(false).await;
        let bob = signer("bob-fed", 2);
        let proposal = crate::membership::propose(
            &*dir,
            crate::membership::GroupScope::Community,
            &room,
            &fed("carol-fed"),
            None,
            chrono::Utc::now() + chrono::Duration::days(7),
            &alice,
        )
        .await
        .expect("propose");
        crate::membership::reply(&*dir, &proposal.attestation_id, false, &carol)
            .await
            .expect("carol declines");
        let err = crate::membership::widen_cosigned(
            &*dir,
            crate::membership::GroupScope::Community,
            &room,
            &fed("carol-fed"),
            None,
            at(1),
            &[&alice, &bob],
        )
        .await
        .expect_err("declined");
        assert_eq!(err.rule(), Some(crate::membership::RULE_DECLINED), "{err}");
        assert!(!err.is_retryable());
        assert_eq!(
            active(&dir, &room).await,
            [fed("alice-fed"), fed("bob-fed")]
        );
        let persist_err = ciris_persist::federation::Error::MembershipAcceptanceRefused {
            group_key_id: room.clone(),
            member_key_id: fed("carol-fed"),
            rule: crate::membership::RULE_DECLINED,
        };
        let class = crate::replication::bridge::ApplyRefusalClass::classify(&persist_err)
            .expect("classified");
        assert!(!class.is_transient(), "{class:?}");
    }
}
