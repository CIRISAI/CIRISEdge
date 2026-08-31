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
        // The revocation class. Bodies, always, whatever is configured.
        EnvelopeKind::Revocation
        | EnvelopeKind::IdentityOccurrenceRevocation
        | EnvelopeKind::FamilyMembershipRevocation
        | EnvelopeKind::CommunityMembershipRevocation => Retention::Bodies,

        // Everything else honours the configuration. Listed EXHAUSTIVELY rather
        // than with a `_` arm: a kind added later must be classified by whoever
        // adds it, and a new revocation plane defaulting into `HashFirst`
        // through a wildcard is exactly how this carve-out would be lost.
        EnvelopeKind::Key
        | EnvelopeKind::Attestation
        | EnvelopeKind::IdentityOccurrence
        | EnvelopeKind::Family
        | EnvelopeKind::Community
        | EnvelopeKind::LocationProof
        | EnvelopeKind::Organization
        | EnvelopeKind::OrgMembership
        | EnvelopeKind::PartnerRecord
        | EnvelopeKind::TransportDestination
        | EnvelopeKind::AccordQuorumEvidence => configured,
    }
}

#[cfg(test)]
mod tests {
    use super::{retention_for, Retention};
    use crate::replication::protocol::EnvelopeKind;

    /// The kinds that retract something. Spelled out here, independently of the
    /// implementation, so the test is a statement of intent rather than a mirror
    /// of the code it checks.
    const RETRACTING: [EnvelopeKind; 4] = [
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrenceRevocation,
        EnvelopeKind::FamilyMembershipRevocation,
        EnvelopeKind::CommunityMembershipRevocation,
    ];

    /// CIRISEdge#553 — the carve-out. A configured `HashFirst` must not reach a
    /// plane whose job is to retract something.
    #[test]
    fn the_revocation_class_is_never_hash_first() {
        for kind in RETRACTING {
            assert_eq!(
                retention_for(kind, Retention::HashFirst),
                Retention::Bodies,
                "{kind:?} retracts something — a node holding the HASH of a \
                 retraction has not applied it"
            );
        }
    }

    /// The carve-out must not swallow the feature. If it did, #552 would be
    /// silently inert and the corpus problem would remain with a passing suite.
    #[test]
    fn a_non_retracting_kind_honours_the_configured_retention() {
        assert_eq!(
            retention_for(EnvelopeKind::Attestation, Retention::HashFirst),
            Retention::HashFirst
        );
        assert_eq!(
            retention_for(EnvelopeKind::Key, Retention::HashFirst),
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
            let expected = if RETRACTING.contains(&kind) {
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
