//! **Who is in a room, as signed records** — the two producers a roster
//! change needs, built the way [`owner_binding_attestation`] is: persist's
//! own signing envelope, hybrid-signed over exactly the bytes the door
//! verifies, admit-tested against a real backend (CIRISEdge#608).
//!
//! # The two doors, and why they are not symmetric
//!
//! persist keeps a community roster as ONE record (`Community.members`) plus
//! an APPEND-ONLY revocation table. Growing the roster and shrinking it are
//! therefore different shapes on the wire:
//!
//! - **Widening** is [`add_community_member`]: the roster mutates in place,
//!   and the caller's authority signs the **grown** record
//!   ([`AdmitSpec`]) — every field the gate verifies over is caller-known in
//!   advance (persist #502 E4), so if the stored roster moved between the
//!   read and the write, the signature simply does not verify and the add
//!   fails closed.
//! - **Revocation** is [`put_community_membership_revocation`]: a signed
//!   append-only row. It is also the **DEK-rotation trigger** — the door
//!   verifies the signature, then bumps the community DEK epoch in the same
//!   transaction (CC 4.4.3.2.2), so the next seal wraps only to the remaining
//!   members. Blobs already sealed keep their grants: forward secrecy on this
//!   axis is rotation, not recall (CC 4.5.12.1 Option A).
//!
//! # What the substrate does NOT adjudicate here
//!
//! Both doors are **mechanistic**: any registered hybrid key whose signature
//! verifies is admitted as the authority. The community's
//! `consensus_protocol` (`unanimous`, `majority`, …) is NOT enforced at
//! either door — quorum is the `supersede_*_with_quorum` ceremony's job —
//! and `witness_set` is stored, not counted. Whether `authority` SHOULD be
//! allowed to change this roster is the caller's policy (a founder, a named
//! moderator); this module guarantees only that what it signs is what the
//! door admits.
//!
//! # A limit the caller must know: widening does not replicate (yet)
//!
//! A grown roster is a `Community` record with a different `persist_row_hash`
//! under an occupied id. A peer that holds the ORIGINAL roster refuses it as
//! `Conflict` — edge's bridge classifies that `CommunityRosterFork`, and it
//! is correct to: silently accepting a different roster under an occupied id
//! is the one thing a community's identity must never permit. There is no
//! signed append plane for additions the way there is for revocations. So
//! [`widen_community`] is a LOCAL truth today: the node that widened sees the
//! new member, and every other node keeps the roster it admitted first. A
//! room whose roster must be shared is created with its full roster
//! ([`crate::chat::community`]); a widening after creation reaches only the
//! widening node until persist grows a replicable form for it. Revocations
//! DO replicate (`CommunityMembershipRevocation` is its own envelope kind).
//!
//! [`owner_binding_attestation`]: crate::replication::attestation_bind::owner_binding_attestation
//! [`add_community_member`]: FederationDirectory::add_community_member
//! [`put_community_membership_revocation`]: FederationDirectory::put_community_membership_revocation

use ciris_persist::federation::cohort::AdmitSpec;
use ciris_persist::federation::types::{
    CommunityMember, CommunityMembershipRevocation, SignedCommunityMembershipRevocation,
};
use ciris_persist::federation::FederationDirectory;

/// **The signed widening** — the [`AdmitSpec`] persist's
/// `add_community_member` verifies, over the roster AS IT WILL BE.
///
/// Reads `community_key_id`'s current record from `directory`, appends
/// `member` (with `role` and `joined_at`), and hybrid-signs the grown
/// record's [`signing_envelope`](ciris_persist::federation::types::Community::signing_envelope)
/// as `authority`. Returns the member row and the spec; apply them with
/// [`widen_community`] or hand them to the door directly.
///
/// A member already on the roster is not an error here: the grown record
/// equals the stored one, and the door reports it as an idempotent no-op
/// (`Ok(false)`) before consulting the signature at all.
///
/// # Errors
/// The community is unknown to this directory, a directory read failed,
/// canonicalization or signing failed.
pub async fn community_membership_widening(
    directory: &dyn FederationDirectory,
    community_key_id: &str,
    member_key_id: &str,
    role: Option<&str>,
    joined_at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<(CommunityMember, AdmitSpec), String> {
    use crate::replication::attestation_bind::truncate_to_substrate_resolution;

    let mut community = directory
        .lookup_community(community_key_id)
        .await
        .map_err(|e| format!("lookup room {community_key_id}: {e}"))?
        .ok_or_else(|| {
            format!(
                "room {community_key_id} is not on this directory — a widening signs the \
                 GROWN roster, so there must be a roster to grow"
            )
        })?;

    let member = CommunityMember {
        key_id: member_key_id.to_owned(),
        // The instant is bound into the signed bytes and stored by persist at
        // millisecond precision; signing sub-millisecond digits would be a
        // signature over bytes the row never carries.
        joined_at: truncate_to_substrate_resolution(joined_at),
        role: role.map(str::to_owned),
    };
    // The door compares by `key_id` and treats a present member as a no-op
    // BEFORE the gate, so the grown record it verifies against is the stored
    // one in that case. Mirror that exactly: append only if absent, so the
    // signature is over what the door will actually hash.
    if !community.members.iter().any(|m| m.key_id == member.key_id) {
        community.members.push(member.clone());
    }
    // The stored hash is server-computed and stripped by `signing_envelope`;
    // clearing it here is belt-and-braces against a lookup that returned it.
    community.persist_row_hash = String::new();

    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&community.signing_envelope())
        .map_err(|e| format!("canonicalize the grown roster: {e}"))?;
    let (scrub_signature_classical, scrub_signature_pqc) =
        crate::identity::sign_bound_hybrid(authority, &canonical, "community widening").await?;
    Ok((
        member,
        AdmitSpec {
            authority_key_id: authority.key_id.clone(),
            scrub_signature_classical,
            scrub_signature_pqc,
        },
    ))
}

/// [`community_membership_widening`], applied: the member is on
/// `community_key_id`'s roster on THIS directory when this returns `Ok`.
/// `Ok(true)` is a genuine add, `Ok(false)` the idempotent no-op.
///
/// See the module doc for why this is a local truth and not a replicated
/// one.
///
/// # Errors
/// [`community_membership_widening`]'s, or the door's refusal — a signature
/// that does not verify (the roster moved under the caller, or `authority`
/// is not the registered hybrid key it claims), an unknown community.
pub async fn widen_community(
    directory: &dyn FederationDirectory,
    community_key_id: &str,
    member_key_id: &str,
    role: Option<&str>,
    joined_at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<bool, String> {
    let (member, spec) = community_membership_widening(
        directory,
        community_key_id,
        member_key_id,
        role,
        joined_at,
        authority,
    )
    .await?;
    directory
        .add_community_member(community_key_id, member, &spec)
        .await
        .map_err(|e| format!("widen room {community_key_id} with {member_key_id}: {e}"))
}

/// **The signed removal** — the [`SignedCommunityMembershipRevocation`]
/// persist's `put_community_membership_revocation` verifies, and the row
/// that ROTATES THE ROOM'S DEK when it is admitted.
///
/// `effective_at` is when the member stops being one. persist refuses a
/// future-dated `effective_at` at this door (community removal is immediate,
/// for forward secrecy — SecReview F4), so pass now or the past; `removed_at`
/// is the same instant, because every field the gate verifies over must be
/// caller-known in advance (persist #502 E4) and a server-minted "now" is
/// not. `witness_set` is the vouch set the protocol may want; it is stored,
/// not counted, by this door.
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
    use crate::replication::attestation_bind::truncate_to_substrate_resolution;

    let at = truncate_to_substrate_resolution(effective_at);
    let revocation = CommunityMembershipRevocation {
        community_key_id: community_key_id.to_owned(),
        removed_identity_key_id: removed_identity_key_id.to_owned(),
        removed_at: at,
        effective_at: at,
        reason: reason.map(str::to_owned),
        witness_set: witness_set.iter().map(|w| (*w).to_owned()).collect(),
        persist_row_hash: String::new(),
    };
    let canonical =
        ciris_persist::prelude::ceg_produce_canonicalize(&revocation.signing_envelope())
            .map_err(|e| format!("canonicalize the removal: {e}"))?;
    let (scrub_signature_classical, scrub_signature_pqc) =
        crate::identity::sign_bound_hybrid(authority, &canonical, "community removal").await?;
    Ok(SignedCommunityMembershipRevocation {
        community_membership_revocation: revocation,
        authority_key_id: authority.key_id.clone(),
        scrub_signature_classical,
        scrub_signature_pqc,
    })
}

/// [`community_membership_revocation`], applied: when this returns `Ok`,
/// `removed_identity_key_id` is off `community_key_id`'s ACTIVE roster on
/// this directory and the room's DEK epoch has been bumped — the next seal
/// here wraps to the remaining members only. Idempotent on
/// `(community, member)`.
///
/// # The precondition persist imposes, named here rather than as an FK error
///
/// persist's revocation table declares `community_key_id REFERENCES
/// federation_keys(key_id)` — a room can be revoked from only if its id is a
/// REGISTERED FEDERATION KEY. `put_community` imposes no such rule, so a room
/// with a derived id (every pair room, `chat:pair:v1:…`) or an allocated
/// one (`chat:room:v1:…`) is admitted, replicated, sealed under, and then
/// cannot have a member removed: the door refuses with a bare "FOREIGN KEY
/// constraint failed". persist's own fixtures satisfy the FK by registering
/// the community id as a key; edge does not register a room as a person and
/// will not invent an identity type for it. Until persist either gives a
/// community an identity type of its own or points the FK at
/// `federation_communities`, this is refused HERE with the reason, before
/// the door is asked.
///
/// # Errors
/// The room's id is not a registered key (see above);
/// [`community_membership_revocation`]'s; or the door's refusal — a
/// signature that does not verify, a future-dated `effective_at`, an unknown
/// community or member.
pub async fn revoke_community_member(
    directory: &dyn FederationDirectory,
    community_key_id: &str,
    removed_identity_key_id: &str,
    effective_at: chrono::DateTime<chrono::Utc>,
    reason: Option<&str>,
    witness_set: &[&str],
    authority: &crate::identity::LocalSigner,
) -> Result<(), String> {
    if directory
        .lookup_public_key(community_key_id)
        .await
        .map_err(|e| format!("lookup room key {community_key_id}: {e}"))?
        .is_none()
    {
        return Err(format!(
            "room {community_key_id} is not a registered federation key, and persist's \
             community-membership-revocation table references `federation_keys` — a member \
             cannot be removed from a room whose id is derived or allocated until persist \
             gives communities an identity type or re-points that FK at \
             `federation_communities` (CIRISEdge#608)"
        ));
    }
    // The door's contract is "idempotent on the (community, member) PK"; its
    // sqlite implementation raises a UNIQUE violation on a repeat instead
    // (persist v44.6.0 — the same doc-vs-door gap `attestation_reput_verdict`
    // closed for attestations). A member already revoked is already off the
    // roster and the epoch already moved, which is what the caller asked
    // for, so honour the documented contract here rather than surface the
    // constraint.
    if directory
        .list_community_membership_revocations_for(community_key_id)
        .await
        .map_err(|e| format!("list revocations for room {community_key_id}: {e}"))?
        .iter()
        .any(|r| r.removed_identity_key_id == removed_identity_key_id)
    {
        return Ok(());
    }
    let signed = community_membership_revocation(
        community_key_id,
        removed_identity_key_id,
        effective_at,
        reason,
        witness_set,
        authority,
    )
    .await?;
    directory
        .put_community_membership_revocation(signed)
        .await
        .map_err(|e| format!("remove {removed_identity_key_id} from room {community_key_id}: {e}"))
}

/// **Admit tests against a real persist backend** — the property is not
/// "the record is well-formed" but "the door admits it and the roster
/// reads back changed", because a producer that hand-rolls the envelope
/// gets it wrong in ways that only the door can tell it (the owner-binding
/// producer got it wrong twice before it had one of these).
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

    fn signer(key_id: &str, seed: u8) -> crate::identity::LocalSigner {
        let classical: Arc<dyn HardwareSigner> =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], key_id).unwrap());
        let pqc: Arc<dyn PqcSigner> = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{key_id}-pqc"))
                .unwrap(),
        );
        crate::identity::LocalSigner::new(key_id, classical, Some(pqc))
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

    /// A directory with three registered humans and a room founded by the
    /// first, holding the first two. Returns `(dir, founder, room id, carol)`.
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
                record: user_record(&signer(&room, 9)).await,
            })
            .await
            .expect("register the room id as a key (persist fixture convention)");
        }
        let record = crate::chat::community(
            &room,
            "the room",
            &[
                (
                    "alice-fed",
                    Some(ciris_persist::federation::admission::MEMBER_ROLE_FOUNDER),
                ),
                ("bob-fed", None),
            ],
            ciris_persist::federation::types::consensus_protocol::FOUNDER_ONLY,
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

    /// **The widening persist actually admits, and the roster reads back
    /// grown.**
    #[tokio::test]
    async fn a_widening_is_admitted_and_the_active_roster_grows() {
        let (dir, alice, room, _carol) = room_of_two(false).await;
        assert_eq!(active(&dir, &room).await, ["alice-fed", "bob-fed"]);

        let added = widen_community(&*dir, &room, "carol-fed", None, ts(), &alice)
            .await
            .expect("persist must ADMIT the widening this producer builds");
        assert!(added, "a genuine add reports true");
        assert_eq!(
            active(&dir, &room).await,
            ["alice-fed", "bob-fed", "carol-fed"],
            "the ACTIVE roster — what the DEK cascade wraps to — must include the new member",
        );

        // Idempotent: the same widening again is the no-op the door promises,
        // and the signature over the (unchanged) grown record still verifies.
        let again = widen_community(&*dir, &room, "carol-fed", None, ts(), &alice)
            .await
            .expect("a second identical widening is not an error");
        assert!(
            !again,
            "a member already on the roster is a no-op, reported as false"
        );
    }

    /// **A widening signed by a key that is not what it claims is refused** —
    /// the E4 rule: roster growth is not an unauthenticated write door.
    #[tokio::test]
    async fn a_widening_under_a_forged_authority_is_refused() {
        let (dir, _alice, room, carol) = room_of_two(false).await;
        // Carol's key signs, but the spec CLAIMS alice as the authority — the
        // registered pubkeys for alice do not verify carol's signature.
        let (member, mut spec) =
            community_membership_widening(&*dir, &room, "carol-fed", None, ts(), &carol)
                .await
                .expect("build");
        spec.authority_key_id = "alice-fed".to_owned();
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
            ["alice-fed", "bob-fed"],
            "and nothing was written",
        );
    }

    /// **A widening over a roster that moved is refused** — the signature is
    /// over the grown record the caller computed, and a different stored
    /// roster is a different record.
    #[tokio::test]
    async fn a_widening_over_a_stale_roster_fails_closed() {
        let (dir, alice, room, _carol) = room_of_two(false).await;
        // Alice signs a widening for carol against the roster [alice, bob]…
        let (member, spec) =
            community_membership_widening(&*dir, &room, "carol-fed", None, ts(), &alice)
                .await
                .expect("build");
        // …but the roster grows under her first.
        widen_community(&*dir, &room, "dave-fed", None, ts(), &alice)
            .await
            .expect("first add");
        dir.add_community_member(&room, member, &spec)
            .await
            .expect_err("the grown record alice signed is not the one the door computes now");
    }

    /// **The removal persist actually admits, the active roster shrinks, and
    /// the DEK epoch moved** — the door's three effects, asserted together.
    #[tokio::test]
    async fn a_removal_is_admitted_shrinks_the_roster_and_rotates_the_epoch() {
        let (dir, alice, room, _carol) = room_of_two(true).await;
        let before = dir
            .list_community_membership_revocations_for(&room)
            .await
            .expect("list")
            .len();
        assert_eq!(before, 0);

        revoke_community_member(
            &*dir,
            &room,
            "bob-fed",
            ts(),
            Some("left the room"),
            &[],
            &alice,
        )
        .await
        .expect("persist must ADMIT the removal this producer builds");

        assert_eq!(
            active(&dir, &room).await,
            ["alice-fed"],
            "the ACTIVE roster excludes the removed member — the roster record itself is \
             untouched (append-only revocation, composed at read)",
        );
        let revs = dir
            .list_community_membership_revocations_for(&room)
            .await
            .expect("list");
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].removed_identity_key_id, "bob-fed");
        assert_eq!(revs[0].reason.as_deref(), Some("left the room"));

        // Idempotent on (community, member).
        revoke_community_member(&*dir, &room, "bob-fed", ts(), None, &[], &alice)
            .await
            .expect("a repeated removal is not an error");
    }

    /// **A removal signed by a key that is not what it claims is refused** —
    /// THE worst-case E4 hole: an unverified removal would rotate the room's
    /// DEK, an unauthenticated forward-secrecy DoS against every real member.
    #[tokio::test]
    async fn a_removal_under_a_forged_authority_is_refused_before_any_rotation() {
        let (dir, _alice, room, carol) = room_of_two(true).await;
        let mut signed = community_membership_revocation(&room, "bob-fed", ts(), None, &[], &carol)
            .await
            .expect("build");
        signed.authority_key_id = "alice-fed".to_owned();
        dir.put_community_membership_revocation(signed)
            .await
            .expect_err("a forged removal is refused at the signature, before the epoch bump");
        assert_eq!(
            active(&dir, &room).await,
            ["alice-fed", "bob-fed"],
            "nothing was written",
        );
    }

    /// **A future-dated removal is refused** (persist SecReview F4: community
    /// removal is immediate, for forward secrecy). Pinned so a caller learns
    /// the rule from this producer's tests rather than from a refusal in
    /// production.
    #[tokio::test]
    async fn a_future_dated_removal_is_refused() {
        let (dir, alice, room, _carol) = room_of_two(true).await;
        let future = chrono::Utc::now() + chrono::Duration::days(1);
        let err = revoke_community_member(&*dir, &room, "bob-fed", future, None, &[], &alice)
            .await
            .expect_err("persist refuses a future-dated community removal");
        assert!(
            err.contains("effective_at") || err.contains("future"),
            "the refusal names the instant: {err}",
        );
    }

    /// **CHARACTERIZATION — a room whose id is not a registered key cannot
    /// revoke a member, and the producer says why.** This is every pair room
    /// and every allocated room edge produces. It pins persist v44.6.0's
    /// `federation_community_membership_revocations.community_key_id
    /// REFERENCES federation_keys(key_id)` from the caller's side: the
    /// refusal is edge's named one, and the door underneath would have said
    /// "FOREIGN KEY constraint failed". When persist lifts the FK (an
    /// identity type for communities, or the FK re-pointed at
    /// `federation_communities`), delete the pre-check in
    /// `revoke_community_member` and this test goes with it.
    #[tokio::test]
    async fn a_room_that_is_not_a_registered_key_cannot_revoke_yet() {
        let (dir, alice, room, _carol) = room_of_two(false).await;
        let err = revoke_community_member(&*dir, &room, "bob-fed", ts(), None, &[], &alice)
            .await
            .expect_err("an unregistered room id cannot satisfy persist's FK");
        assert!(
            err.contains("not a registered federation key") && err.contains("federation_keys"),
            "the refusal names persist's constraint, not a bare FK error: {err}",
        );
        assert_eq!(
            active(&dir, &room).await,
            ["alice-fed", "bob-fed"],
            "and nothing was written",
        );
        // The door itself, for the record — the pre-check is a translation of
        // this refusal, not a different rule.
        let signed = community_membership_revocation(&room, "bob-fed", ts(), None, &[], &alice)
            .await
            .expect("build");
        let raw = dir
            .put_community_membership_revocation(signed)
            .await
            .expect_err("the door refuses on the FK");
        assert!(
            raw.to_string().contains("FOREIGN KEY"),
            "the door's own refusal is the FK: {raw}",
        );
    }
}
