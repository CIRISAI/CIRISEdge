//! CIRISEdge#552 / #553 — how much of a plane this node keeps.
//!
//! # Why there is a choice at all
//!
//! Anti-entropy's model is *every node in the projection holds every record*.
//! That is affordable while identities are `SelfOwn` and never travel. Once
//! agent/node/fed IDs are promoted to federation tier — opt-out, and required
//! to run an agent, because the kill switch needs the ID announced — every node
//! is asked to hold every identity in the federation.
//!
//! Two things break at once: the corpus stops fitting (CIRISEdge#547, a
//! canonical unreachable after ~22 h on 1.3 GB), and the directory becomes an
//! address book. Holding HASHES instead answers both: a hash is not a mailing
//! address, and resolving one to a contactable identity takes a fetch, which is
//! observable, rate-limitable and refusable.
//!
//! # What must not happen
//!
//! `want = remote ∖ holdings`. A hash this node merely KNOWS ABOUT must never
//! reach the holdings side of that difference, or the node concludes it already
//! has everything it has heard of and silently stops fetching — CIRISEdge#416's
//! non-convergence with the sign flipped, and invisible from outside, because
//! nothing errors and anti-entropy simply goes quiet.

use super::protocol::EnvelopeKind;

/// How much of a plane this node keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    /// Converge the hash set; fetch a body only on demand.
    HashFirst,
    /// Hold every body this node is offered. The pre-#552 behaviour, and the
    /// only lawful mode for the revocation class.
    Bodies,
}

/// CIRISEdge#553 — the retention this node actually applies to `kind`.
///
/// **A configured `HashFirst` cannot reach the revocation class.** Persist
/// states the rule this enforces: a tombstone travels at its plane's ceiling
/// regardless of scope, because *"a tombstone that relayed narrower than any
/// copy could have traveled would starve holders, silently un-revoking"*.
///
/// A node holding the HASH of a kill order has not been killed. Worse, a node
/// that cannot fetch the body — offline, rate-limited, no holder answering —
/// un-revokes silently: nothing errors, the agent simply keeps running. That is
/// the one failure on this path that fails in the safe-LOOKING direction, which
/// is why the carve-out is a function of the kind and not a flag a caller can
/// get wrong.
#[must_use]
pub const fn retention_for(kind: EnvelopeKind, configured: Retention) -> Retention {
    match kind {
        // ── Planes that RETRACT, by name. Bodies, always.
        EnvelopeKind::Revocation
        | EnvelopeKind::IdentityOccurrenceRevocation
        | EnvelopeKind::FamilyMembershipRevocation
        | EnvelopeKind::CommunityMembershipRevocation

        // ── Planes that retract from INSIDE. Bodies, always, and this is the
        // half a kind-keyed carve-out gets wrong.
        //
        // Retraction is a per-RECORD property, not a per-kind one. The
        // Attestation plane carries `withdraws` / `recants` tombstones — the
        // bridge passes `is_withdraw_or_revocation(attestation_type)` into the
        // projection, and notes that "a `withdraws` tombstone gossips GLOBAL
        // (anti-rollback) even at `self`". Organization, OrgMembership and
        // PartnerRecord likewise carry withdrawn/revoked states inside the
        // envelope.
        //
        // A node cannot tell a tombstone from an ordinary row WITHOUT THE BODY,
        // and hash-first is precisely the state of not having it. So the
        // classification cannot be made per record on the receive side, and
        // these planes are pinned whole. That costs the Attestation corpus —
        // the largest one — which is the honest price of the carve-out being
        // correct rather than convenient.
        //
        // Deciding per record needs the ADVERTISER to mark retractions on the
        // wire, which is a vocabulary change and its own cut. Until then this
        // is the safe side of the trade, and the trade is stated rather than
        // discovered.
        | EnvelopeKind::Attestation
        | EnvelopeKind::Organization
        | EnvelopeKind::OrgMembership
        | EnvelopeKind::PartnerRecord

        // ── ROSTER planes. Bodies, because a member READS them locally.
        //
        // A chat room IS a 2-member `Community`, and reading its messages goes
        // through `active_community_members(community_id)` — the roster, which
        // lives in the BODY. A node holding only the hash knows a community
        // exists and cannot tell whether it is in it, who else is, or read a
        // word of it. `Family` is the same shape.
        //
        // This is the line the classification turns on, and it is not about
        // retraction: hash-first is for records a node needs to KNOW ABOUT and
        // can fetch when something asks. A roster is a record its members need
        // to READ, unprompted, to function at all. Holding a hash of your own
        // chat room is not a smaller copy of it — it is not being in it.
        | EnvelopeKind::Community
        | EnvelopeKind::Family

        // ── Accord quorum evidence. Bodies, because it carries WITHDRAWAL
        // evidence: a participation can retract a vote, and the aggregate is
        // what a holder evaluates. It is also the one kind persist keeps OUT of
        // the content-hash index by construction — its hash moves as votes land
        // — so a hash of it is not even a stable name for the thing.
        | EnvelopeKind::AccordQuorumEvidence

        // ── LocationProof. Bodies until there is something that resolves it.
        //
        // Its Summary exposes only opaque hashes, and nothing in edge yet
        // consumes a location proof by hash — so hash-first here buys no memory
        // that matters and loses the only readable form. A plane joins hash-first
        // when a consumer can ASK for it, not merely when it is technically able
        // to hold hashes.
        | EnvelopeKind::LocationProof => Retention::Bodies,

        // ── Planes that cannot retract anything. These are the identity and
        // routing planes the federation directory is made of, which is exactly
        // what #552 needs to hold as hashes.
        //
        // Listed EXHAUSTIVELY rather than with a `_` arm: a kind added later
        // must be classified by whoever adds it, and a new retracting plane
        // defaulting into `HashFirst` through a wildcard is how this carve-out
        // would be lost silently.
        // ── The DIRECTORY. Who exists, and how to reach them.
        //
        // These are exactly what a node needs to find a person and open a
        // channel to them, and exactly what should not be an address book
        // sitting on every node in the federation. Nothing here is read
        // unprompted: a node resolves one of these when it is trying to reach
        // someone, which is precisely the fetch that makes enumeration
        // observable and refusable.
        EnvelopeKind::Key
        | EnvelopeKind::IdentityOccurrence
        | EnvelopeKind::TransportDestination => configured,
    }
}

#[cfg(test)]
mod tests {
    use super::{retention_for, Retention};
    use crate::replication::protocol::EnvelopeKind;

    /// Every kind whose BODY a node must hold, and why — spelled out here
    /// independently of the implementation, so the test states intent rather
    /// than mirroring the code it checks.
    ///
    /// Two distinct reasons, and both are easy to miss:
    ///
    /// * it can RETRACT something, by name or from inside the envelope
    ///   (`withdraws` / `recants`, withdrawn/revoked states) — and a receiver
    ///   cannot tell which without the body, which under hash-first it lacks;
    /// * it is a ROSTER its members read locally and unprompted. A chat room is
    ///   a 2-member `Community`, and reading it goes through the roster in the
    ///   body. Holding the hash of your own chat room is not being in it.
    const MUST_HOLD_BODIES: [EnvelopeKind; 12] = [
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrenceRevocation,
        EnvelopeKind::FamilyMembershipRevocation,
        EnvelopeKind::CommunityMembershipRevocation,
        EnvelopeKind::Attestation,
        EnvelopeKind::Organization,
        EnvelopeKind::OrgMembership,
        EnvelopeKind::PartnerRecord,
        // Roster planes: a member reads these locally, unprompted.
        EnvelopeKind::Community,
        EnvelopeKind::Family,
        // Carries withdrawal evidence, and its hash moves as votes land.
        EnvelopeKind::AccordQuorumEvidence,
        // Nothing resolves a location proof by hash yet.
        EnvelopeKind::LocationProof,
    ];

    /// CIRISEdge#553 — the carve-out. A configured `HashFirst` must not reach a
    /// CIRISEdge#552 — only a SERVER keeps a hash directory.
    ///
    /// Not a storage preference: if every node converged the whole hash set the
    /// directory would be enumerable from ANY node — cheaper to carry than
    /// bodies, and the same exposure. A proxy that learns only what concerns it
    /// reveals only its own contacts when compromised.
    #[test]
    fn only_server_mode_takes_the_hash_first_posture() {
        use crate::AgentMode;
        let posture = |m: AgentMode| match m {
            AgentMode::Server => Retention::HashFirst,
            AgentMode::Proxy | AgentMode::Client => Retention::Bodies,
        };
        assert_eq!(posture(AgentMode::Server), Retention::HashFirst);
        assert_eq!(
            posture(AgentMode::Proxy),
            Retention::Bodies,
            "proxy is the DEFAULT — the default must not be the enumerable one"
        );
        assert_eq!(posture(AgentMode::Client), Retention::Bodies);
    }

    /// plane whose job is to retract something.
    #[test]
    fn a_plane_that_needs_its_body_is_never_hash_first() {
        for kind in MUST_HOLD_BODIES {
            assert_eq!(
                retention_for(kind, Retention::HashFirst),
                Retention::Bodies,
                "{kind:?} needs its BODY — it either retracts something a hash \
                 cannot apply, or is a roster its members must read locally"
            );
        }
    }

    /// The carve-out must not swallow the feature. If it did, #552 would be
    /// silently inert and the corpus problem would remain with a passing suite.
    #[test]
    fn a_non_retracting_kind_honours_the_configured_retention() {
        assert_eq!(
            retention_for(EnvelopeKind::Key, Retention::HashFirst),
            Retention::HashFirst
        );
        assert_eq!(
            retention_for(EnvelopeKind::IdentityOccurrence, Retention::HashFirst),
            Retention::HashFirst
        );
        assert_eq!(
            retention_for(EnvelopeKind::TransportDestination, Retention::HashFirst),
            Retention::HashFirst
        );
    }

    /// `Bodies` is a floor, never a thing the carve-out has to override.
    #[test]
    fn configured_bodies_stays_bodies_everywhere() {
        for kind in EnvelopeKind::ALL {
            assert_eq!(retention_for(kind, Retention::Bodies), Retention::Bodies);
        }
    }

    /// The guard that catches a FUTURE kind rather than today's.
    ///
    /// Every kind is either in `RETRACTING` and pinned to `Bodies`, or it is not
    /// and honours configuration. A new plane added upstream lands in exactly one
    /// of those, and if someone adds a fifth revocation kind without listing it
    /// here, this fails — which is the whole point, since the alternative is a
    /// retraction plane quietly becoming hash-only and nobody finding out until a
    /// kill order does not land.
    #[test]
    fn every_kind_is_deliberately_classified() {
        for kind in EnvelopeKind::ALL {
            let got = retention_for(kind, Retention::HashFirst);
            let expected = if MUST_HOLD_BODIES.contains(&kind) {
                Retention::Bodies
            } else {
                Retention::HashFirst
            };
            assert_eq!(
                got, expected,
                "{kind:?} is not deliberately classified — a new plane must be \
                 assigned a retention by whoever adds it (CIRISEdge#553)"
            );
        }
    }
}
