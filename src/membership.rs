//! **Nobody joins a group without their own consent** — the membership
//! proposal → acceptance → widening flow (CIRISConstitution#133, persist
//! v52.0.0 / CIRISPersist#955), as edge producers and host calls.
//!
//! # The rule edge follows
//!
//! A family or community is **founded by its opener alone**: the founding
//! record lists only the members who signed it (persist refuses any other
//! with `membership_founding_member_unsigned`). Everyone else joins in three
//! steps, each a signed row:
//!
//! 1. **Proposal** ([`propose`]) — a member of the group (a founder under
//!    `founder_only`) emits `membership:proposal:v1`, placed at the group,
//!    naming the invitee in `subject_key_ids` and the offered `role`, live for
//!    at most 30 days. Edge serves it to the invitee's nodes whatever rooms
//!    they are in (the #955 arm of the audience gate).
//! 2. **Reply** ([`reply`]) — the invitee's PERSON (or a device acting for
//!    them) accepts or declines. A decline is final for that proposal.
//! 3. **Widening** ([`widen_on_acceptance`]) — once the acceptance is held,
//!    the proposer's side signs the ordinary roster widening with the offered
//!    role. persist admits a growth only on a matching live acceptance
//!    (`check_growth_accepted`); a widening without one is refused BY NAME
//!    ([`MembershipError::Refused`]) and never retried as if it were
//!    transient unless the rule says the missing row may still arrive.
//!
//! The replication bridge performs step 3 by itself when a host installs a
//! [`MembershipWidener`]: an admitted acceptance of a proposal one of the
//! widener's identities issued is widened on arrival, so the opener's person
//! takes no second action. Idempotent — a re-applied acceptance finds the
//! member already active.
//!
//! Every row is built through persist's own builders
//! ([`membership_acceptance::proposal_input`] / [`reply_input`]) and emit
//! recipe (`stamp_and_canonicalize` → hybrid sign → `assemble`), so the wire
//! shape is persist's and cannot drift.
//!
//! [`membership_acceptance::proposal_input`]: ciris_persist::federation::membership_acceptance::proposal_input
//! [`reply_input`]: ciris_persist::federation::membership_acceptance::reply_input

use std::sync::Arc;

use ciris_persist::federation::membership_acceptance as ma;
use ciris_persist::federation::types::cohort_scope;
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};

pub use ma::{
    ACCEPTANCE_DIMENSION, DECLINE_DIMENSION, MEMBERSHIP_PROPOSAL_MAX_TTL_SECS, PROPOSAL_DIMENSION,
    RULE_ACCEPTANCE_MISMATCH, RULE_ACCEPTANCE_UNRESOLVED, RULE_DECLINED,
    RULE_FOUNDING_MEMBER_UNSIGNED, RULE_PROPOSAL_EXPIRED, RULE_PROPOSAL_UNRESOLVED,
    RULE_REPLY_CONFLICT, RULE_SUPERSEDE_CANNOT_ADD,
};

/// Which kind of group a membership row is placed at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupScope {
    /// A family (`cohort_scope: family`, `family_key_id`).
    Family,
    /// A community / room (`cohort_scope: community`, `community_key_id`).
    Community,
}

impl GroupScope {
    /// The row's `cohort_scope`.
    #[must_use]
    pub fn cohort_scope(self) -> &'static str {
        match self {
            Self::Family => cohort_scope::FAMILY,
            Self::Community => cohort_scope::COMMUNITY,
        }
    }

    /// The envelope member naming the group.
    #[must_use]
    pub fn target_member(self) -> &'static str {
        match self {
            Self::Family => "family_key_id",
            Self::Community => "community_key_id",
        }
    }

    /// The scope of a stored membership row, if it is placed at a group.
    #[must_use]
    pub fn of_row(row: &Attestation) -> Option<Self> {
        match row.cohort_scope.as_str() {
            cohort_scope::FAMILY => Some(Self::Family),
            cohort_scope::COMMUNITY => Some(Self::Community),
            _ => None,
        }
    }
}

/// Why a membership step did not happen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipError {
    /// persist refused on the consent rule `rule` (one of the `RULE_*`
    /// tokens). [`Self::is_retryable`] says whether waiting can change it.
    Refused {
        /// The family or community.
        group_key_id: String,
        /// The member whose consent is missing or does not hold.
        member_key_id: String,
        /// persist's rule token.
        rule: &'static str,
    },
    /// The row named is not a membership proposal (or not held here).
    NotAProposal(String),
    /// Any other refusal, read failure, or build/sign failure.
    Other(String),
}

impl MembershipError {
    /// `true` only for the two rules persist names retryable
    /// (`membership_acceptance_unresolved`, `membership_proposal_unresolved`):
    /// the missing row may still arrive. A decline, an expiry, a mismatch or
    /// a conflict is TERMINAL for that proposal.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Refused { rule, .. } if ma::is_retryable_rule(rule))
    }

    /// The stable rule token, when the refusal is a consent rule.
    #[must_use]
    pub fn rule(&self) -> Option<&'static str> {
        match self {
            Self::Refused { rule, .. } => Some(rule),
            _ => None,
        }
    }

    fn from_persist(what: &str, e: &ciris_persist::federation::Error) -> Self {
        match e {
            ciris_persist::federation::Error::MembershipAcceptanceRefused {
                group_key_id,
                member_key_id,
                rule,
            } => Self::Refused {
                group_key_id: group_key_id.clone(),
                member_key_id: member_key_id.clone(),
                rule,
            },
            other => Self::Other(format!("{what}: {other}")),
        }
    }
}

impl std::fmt::Display for MembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused {
                group_key_id,
                member_key_id,
                rule,
            } => write!(
                f,
                "membership of {member_key_id} in {group_key_id} refused ({rule}){}",
                if ma::is_retryable_rule(rule) {
                    " — the missing row may still arrive"
                } else {
                    " — terminal for this proposal"
                }
            ),
            Self::NotAProposal(s) | Self::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for MembershipError {}

/// One persist emit input, stamped, hybrid-signed by `signer` and assembled —
/// the recipe every edge emit shares (`attestation_bind::widen`'s shape).
async fn sign_input(
    mut input: ciris_persist::federation::EmitAttestationInput,
    signer: &crate::identity::LocalSigner,
    what: &str,
) -> Result<Attestation, MembershipError> {
    use ciris_persist::federation::attestation_emit;
    let canonical =
        attestation_emit::stamp_and_canonicalize(&mut input, &signer.key_id, chrono::Utc::now())
            .map_err(|e| MembershipError::Other(format!("{what}: stamp: {e}")))?;
    let sig = crate::identity::sign_hybrid_raw(signer, &canonical, what)
        .await
        .map_err(MembershipError::Other)?;
    attestation_emit::assemble(signer.key_id.clone(), &canonical, sig, input)
        .map(|(row, _)| row)
        .map_err(|e| MembershipError::Other(format!("{what}: assemble: {e}")))
}

/// **Build** (do not store) a `membership:proposal:v1` row signed by
/// `signer`: `invitee` into `group` at `role`, live until `expires_at` (at
/// most [`MEMBERSHIP_PROPOSAL_MAX_TTL_SECS`] after now).
///
/// # Errors
/// Stamping, signing or assembly failure.
pub async fn proposal_attestation(
    scope: GroupScope,
    group_key_id: &str,
    invitee_key_id: &str,
    role: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, MembershipError> {
    sign_input(
        ma::proposal_input(
            scope.cohort_scope(),
            group_key_id,
            invitee_key_id,
            role,
            expires_at,
        ),
        signer,
        "membership proposal",
    )
    .await
}

/// **Build** (do not store) the invitee's reply to `proposal`: an acceptance
/// (`accept`) binding its id, content hash and role, or a decline.
///
/// # Errors
/// `proposal` is not a proposal; stamping, signing or assembly failure.
pub async fn reply_attestation(
    proposal: &Attestation,
    accept: bool,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, MembershipError> {
    if dimension_of(proposal) != Some(PROPOSAL_DIMENSION) {
        return Err(MembershipError::NotAProposal(format!(
            "{} is not a {PROPOSAL_DIMENSION} row",
            proposal.attestation_id
        )));
    }
    sign_input(
        ma::reply_input(proposal, accept),
        signer,
        if accept {
            "membership acceptance"
        } else {
            "membership decline"
        },
    )
    .await
}

/// **Host call: invite `invitee_key_id` into `group_key_id` at `role`.** The
/// proposal is stored through the authored put door and replicates to the
/// invitee's nodes. Returns the stored row (its `attestation_id` is what the
/// reply references).
///
/// `signer` must act for a member of the group (a founder under
/// `founder_only`) — persist judges it where the roster is held.
///
/// # Errors
/// persist's refusal (by rule where it is a consent rule) or a build failure.
pub async fn propose(
    directory: &dyn FederationDirectory,
    scope: GroupScope,
    group_key_id: &str,
    invitee_key_id: &str,
    role: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, MembershipError> {
    let row = proposal_attestation(
        scope,
        group_key_id,
        invitee_key_id,
        role,
        expires_at,
        signer,
    )
    .await?;
    directory
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .map_err(|e| MembershipError::from_persist("put membership proposal", &e))?;
    Ok(row)
}

/// **Host call: accept (`accept = true`) or decline a held proposal** — what
/// the server's invite inbox calls. `signer` must act for the proposal's
/// invitee (their person key, or a device bound to them). Returns the stored
/// reply, which replicates back to the group.
///
/// # Errors
/// [`MembershipError::Refused`] with `membership_proposal_unresolved` when the
/// proposal is not held here yet (retryable); `NotAProposal`; persist's
/// refusal (a mismatch, or a reply that conflicts with an earlier one).
pub async fn reply(
    directory: &dyn FederationDirectory,
    proposal_attestation_id: &str,
    accept: bool,
    signer: &crate::identity::LocalSigner,
) -> Result<Attestation, MembershipError> {
    let proposal = directory
        .get_attestation(proposal_attestation_id)
        .await
        .map_err(|e| MembershipError::from_persist("read proposal", &e))?
        .ok_or_else(|| MembershipError::Refused {
            group_key_id: String::new(),
            member_key_id: String::new(),
            rule: RULE_PROPOSAL_UNRESOLVED,
        })?;
    let row = reply_attestation(&proposal, accept, signer).await?;
    directory
        .put_attestation_authored(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .map_err(|e| MembershipError::from_persist("put membership reply", &e))?;
    Ok(row)
}

/// A proposal waiting on its invitee — one entry of the invite inbox.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingProposal {
    /// The proposal row (reply to it by `attestation_id`).
    pub proposal: Attestation,
    /// Family or community.
    pub scope: GroupScope,
    /// The group named.
    pub group_key_id: String,
    /// The role offered.
    pub role: Option<String>,
    /// When the offer lapses.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// **Host call: the invite inbox** — every live, federation-tier proposal
/// held here naming `invitee_key_id`, that `invitee_key_id` has not replied
/// to. Oldest first.
///
/// # Errors
/// A directory read failure.
pub async fn pending_proposals_for(
    directory: &dyn FederationDirectory,
    invitee_key_id: &str,
) -> Result<Vec<PendingProposal>, MembershipError> {
    const PAGE: u32 = 512;
    let now = chrono::Utc::now();
    let replied: std::collections::HashSet<String> = directory
        .list_attestations_for(invitee_key_id)
        .await
        .map_err(|e| MembershipError::from_persist("list replies", &e))?
        .into_iter()
        .filter(|r| {
            matches!(
                dimension_of(r),
                Some(ACCEPTANCE_DIMENSION | DECLINE_DIMENSION)
            )
        })
        .filter_map(|r| {
            r.attestation_envelope
                .get("references_attestation_id")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    let mut out = Vec::new();
    let mut since = None;
    loop {
        let page = directory
            .list_attestations_since(since.clone(), PAGE)
            .await
            .map_err(|e| MembershipError::from_persist("list proposals", &e))?;
        let full = page.len() == PAGE as usize;
        since = page
            .last()
            .map(ciris_persist::federation::types::ServedAttestation::resume_pair);
        for served in page {
            let p = served.attestation;
            if dimension_of(&p) != Some(PROPOSAL_DIMENSION)
                || p.tier != ciris_persist::federation::types::attestation_tier::FEDERATION
                || p.subject_key_ids.first().map(String::as_str) != Some(invitee_key_id)
                || replied.contains(&p.attestation_id)
            {
                continue;
            }
            let (Some(scope), Some(expires_at)) = (GroupScope::of_row(&p), p.expires_at) else {
                continue;
            };
            if expires_at <= now {
                continue;
            }
            let Some(group_key_id) = group_of(&p, scope) else {
                continue;
            };
            out.push(PendingProposal {
                role: role_of(&p),
                scope,
                group_key_id,
                expires_at,
                proposal: p,
            });
        }
        if !full {
            break;
        }
    }
    out.sort_by_key(|p| p.proposal.asserted_at);
    Ok(out)
}

/// The identities whose proposals a node widens on acceptance, and the
/// signers that sign those widenings. Install on the replication bridge
/// ([`crate::replication::bridge::FederationDirectoryReplicationBridge::with_membership_widener`])
/// or pass to [`widen_on_acceptance`] directly.
///
/// Each signer is a PERSON (or other roster) key: the roster's consensus
/// counts raw seat keys, so a widening must be signed by the founder's own
/// key, not by a device acting for it.
#[derive(Clone, Default)]
pub struct MembershipWidener {
    authorities: Vec<Arc<crate::identity::LocalSigner>>,
}

impl std::fmt::Debug for MembershipWidener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipWidener")
            .field(
                "authorities",
                &self
                    .authorities
                    .iter()
                    .map(|a| a.key_id.as_str())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl MembershipWidener {
    /// A widener signing as `authorities`.
    #[must_use]
    pub fn new(authorities: Vec<Arc<crate::identity::LocalSigner>>) -> Self {
        Self { authorities }
    }

    /// The signers.
    #[must_use]
    pub fn authorities(&self) -> &[Arc<crate::identity::LocalSigner>] {
        &self.authorities
    }
}

/// What [`widen_on_acceptance`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WidenOutcome {
    /// The member was added to the roster, at the offered role.
    Widened {
        /// Family or community.
        scope: GroupScope,
        /// The group.
        group_key_id: String,
        /// The new member.
        member_key_id: String,
        /// Their role.
        role: Option<String>,
    },
    /// The member was already active (a re-applied acceptance): nothing written.
    AlreadyMember,
    /// The row is not an acceptance (a decline ends the proposal; nothing to do).
    NotAnAcceptance,
    /// The proposal was issued by someone none of the authorities acts for.
    NotOurs,
}

/// **Step 3: widen on a held acceptance.** When `reply` is an acceptance of a
/// proposal held here that one of `widener`'s identities issued (compared as
/// identities, so a proposal a device signed for its person counts), sign the
/// roster widening naming the invitee at the offered role, now, and put it.
///
/// # Errors
/// The proposal is not held here (`membership_proposal_unresolved`,
/// retryable); persist's refusal of the widening — by rule when it is a
/// consent rule (a decline or an expiry since, TERMINAL) — or of its standing.
pub async fn widen_on_acceptance(
    directory: &dyn FederationDirectory,
    reply: &Attestation,
    widener: &MembershipWidener,
) -> Result<WidenOutcome, MembershipError> {
    if dimension_of(reply) != Some(ACCEPTANCE_DIMENSION) {
        return Ok(WidenOutcome::NotAnAcceptance);
    }
    let proposal_id = reply
        .attestation_envelope
        .get("references_attestation_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let Some(proposal) = directory
        .get_attestation(proposal_id)
        .await
        .map_err(|e| MembershipError::from_persist("read proposal", &e))?
    else {
        return Err(MembershipError::Refused {
            group_key_id: String::new(),
            member_key_id: reply.attested_key_id.clone(),
            rule: RULE_PROPOSAL_UNRESOLVED,
        });
    };
    if dimension_of(&proposal) != Some(PROPOSAL_DIMENSION) {
        return Err(MembershipError::NotAProposal(proposal_id.to_owned()));
    }
    let proposer = ciris_persist::federation::admission::admission_identity_for_writer(
        directory,
        &proposal.attesting_key_id,
    )
    .await
    .map_err(|e| MembershipError::from_persist("resolve proposer", &e))?;
    let Some(authority) = widener
        .authorities
        .iter()
        .find(|a| a.key_id == proposer || a.key_id == proposal.attesting_key_id)
    else {
        return Ok(WidenOutcome::NotOurs);
    };
    let scope = GroupScope::of_row(&proposal)
        .ok_or_else(|| MembershipError::NotAProposal(proposal_id.to_owned()))?;
    let group = group_of(&proposal, scope)
        .ok_or_else(|| MembershipError::NotAProposal(proposal_id.to_owned()))?;
    let member = proposal
        .subject_key_ids
        .first()
        .cloned()
        .ok_or_else(|| MembershipError::NotAProposal(proposal_id.to_owned()))?;
    let role = role_of(&proposal);
    let added = widen(
        directory,
        scope,
        &group,
        &member,
        role.as_deref(),
        chrono::Utc::now(),
        authority,
    )
    .await?;
    Ok(if added {
        WidenOutcome::Widened {
            scope,
            group_key_id: group,
            member_key_id: member,
            role,
        }
    } else {
        WidenOutcome::AlreadyMember
    })
}

/// **The roster widening, signed by `authority`, put through the group's
/// door.** Community: [`crate::community_roster::community_membership_widening`]
/// → `add_community_member`. Family: a signed `FamilyMembershipWidening` →
/// `put_family_membership_widening`. persist admits it only on a matching
/// live acceptance by `member_key_id`; without one the refusal comes back by
/// persist's rule, verbatim (a member who only ever DECLINED is refused
/// `membership_declined`, terminal, by persist itself since v52 — CIRISPersist
/// #955 follow-up; edge keeps no second copy of that rule). `Ok(false)` = the
/// member was already active (no row written).
///
/// # Errors
/// Build/sign failure, or persist's refusal.
pub async fn widen(
    directory: &dyn FederationDirectory,
    scope: GroupScope,
    group_key_id: &str,
    member_key_id: &str,
    role: Option<&str>,
    at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<bool, MembershipError> {
    widen_at_door(
        directory,
        scope,
        group_key_id,
        member_key_id,
        role,
        at,
        authority,
    )
    .await
}

async fn widen_at_door(
    directory: &dyn FederationDirectory,
    scope: GroupScope,
    group_key_id: &str,
    member_key_id: &str,
    role: Option<&str>,
    at: chrono::DateTime<chrono::Utc>,
    authority: &crate::identity::LocalSigner,
) -> Result<bool, MembershipError> {
    use crate::replication::attestation_bind::truncate_to_substrate_resolution;
    match scope {
        GroupScope::Community => {
            let (member, spec) = crate::community_roster::community_membership_widening(
                directory,
                group_key_id,
                member_key_id,
                role,
                at,
                authority,
            )
            .await
            .map_err(MembershipError::Other)?;
            directory
                .add_community_member(group_key_id, member, &spec)
                .await
                .map_err(|e| MembershipError::from_persist("widen community", &e))
        }
        GroupScope::Family => {
            let already = directory
                .active_family_members(group_key_id)
                .await
                .map_err(|e| MembershipError::from_persist("read family roster", &e))?
                .iter()
                .any(|m| m.key_id == member_key_id && m.role.as_deref() == role);
            if already {
                return Ok(false);
            }
            let at = truncate_to_substrate_resolution(at);
            let widening = ciris_persist::federation::types::FamilyMembershipWidening {
                family_key_id: group_key_id.to_owned(),
                member_key_id: member_key_id.to_owned(),
                joined_at: at,
                effective_at: at,
                role: role.map(str::to_owned),
                persist_row_hash: String::new(),
            };
            let canonical =
                ciris_persist::prelude::ceg_produce_canonicalize(&widening.signing_envelope())
                    .map_err(|e| MembershipError::Other(format!("canonicalize widening: {e}")))?;
            let (scrub_signature_classical, scrub_signature_pqc) =
                crate::identity::sign_bound_hybrid(authority, &canonical, "family widening")
                    .await
                    .map_err(MembershipError::Other)?;
            directory
                .put_family_membership_widening(
                    ciris_persist::federation::types::SignedFamilyMembershipWidening {
                        family_membership_widening: widening,
                        authority_key_id: authority.key_id.clone(),
                        scrub_signature_classical,
                        scrub_signature_pqc,
                        cosignatures: Vec::new(),
                    },
                )
                .await
                .map(|()| true)
                .map_err(|e| MembershipError::from_persist("widen family", &e))
        }
    }
}

/// The row's `dimension`, if any.
#[must_use]
pub fn dimension_of(row: &Attestation) -> Option<&str> {
    row.attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
}

/// `true` for a proposal / acceptance / decline row.
#[must_use]
pub fn is_membership_row(row: &Attestation) -> bool {
    matches!(
        dimension_of(row),
        Some(PROPOSAL_DIMENSION | ACCEPTANCE_DIMENSION | DECLINE_DIMENSION)
    )
}

pub(crate) fn group_of(row: &Attestation, scope: GroupScope) -> Option<String> {
    row.attestation_envelope
        .get(scope.target_member())
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

fn role_of(row: &Attestation) -> Option<String> {
    row.attestation_envelope
        .get("role")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}
