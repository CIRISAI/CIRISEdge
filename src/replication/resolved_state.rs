//! CIRISEdge#396 — the by-construction routing-input funnel.
//!
//! Contextual integrity's strongest form (per <https://ciris.ai/contextual-integrity/>)
//! is *"the strongest flow rule is one the network cannot express breaking."*
//! This module is where edge makes the inappropriate replication flow
//! **unrepresentable**: every routing decision that SENDS a consentable claim
//! to a peer must be constructed from persist's resolved consent projection —
//! not from an operator-supplied peer list, a cohort closure, or a raw string.
//!
//! The move is the one #393's [`SourceKeyId`](crate::transport::SourceKeyId)
//! made for verify-against-sender: a private newtype with vetted constructors,
//! so the only way to obtain the capability the downstream code REQUIRES is to
//! have passed the check.
//!
//! ## The fan-out bound (#396 item 1)
//!
//! Nissenbaum's *recipient* parameter (who receives a flow) must never exceed
//! its *transmission principle* (the consent grant). Edge's replication fan-out
//! is therefore `operator-addressed peers ∩ list_consent_peers(local)`:
//! consent can only **narrow** the operator's addressing, never widen it. The
//! intersection is realized at serve time — only an operator-connected peer
//! ever reaches the serve path, and there it must clear consent membership —
//! so the two constraints compose to the same set without materializing it.
//!
//! Persist's [`list_consent_peers`](ciris_persist::federation::FederationDirectory::list_consent_peers)
//! is the E7 `consent_peer_set` projection, **revocation-folded at write time**:
//! a `withdraws`/`recants` admitted between rounds has already dropped the peer,
//! so re-resolving each round makes un-trust nuclear — *"the authority to say
//! stop stays in human hands"* (<https://ciris.ai/vision/>) enforced at the wire.
//!
//! **Fail-closed corollary** (deliberate, documented — the #379/#386 gate's
//! posture): a node with no `consent:replication` grants has an empty send set
//! and advertises NO consentable claims until consent explicitly grants them.
//! A plane that cannot yet flow is preferable to one that flows past consent.
//!
//! ## Scope: the consentable plane only
//!
//! Per persist's `consent_transferability`, ONLY
//! [`EnvelopeKind::Attestation`](ciris_persist::federation::replication_policy::EnvelopeKind::Attestation)
//! is `Consentable`; keys, roster, and every other structural plane replicate
//! by `KindPolicy` membership (they bootstrap the trust graph and are not
//! consent-gated). This funnel therefore bounds the attestation serve path and
//! leaves structural replication untouched.

use std::collections::HashSet;

use ciris_persist::federation::{Error, FederationDirectory};

/// The consent-resolved set of peers this node may SEND consentable claims to
/// this round — persist's live `consent:replication` peer projection for
/// `local_key_id` (E7, revocation-folded). Re-resolve every round; never cache
/// across rounds (a between-round withdraw must take effect at the next send).
pub(crate) struct ResolvedPeerSet {
    send_set: HashSet<String>,
}

impl ResolvedPeerSet {
    /// Resolve `local_key_id`'s live consent send-set from persist's E7
    /// projection. The operator-addressing half of the intersection is applied
    /// by the caller's serve path (only a connected peer is ever tested), so
    /// this reads the consent side alone. Propagates the directory error so the
    /// caller can fail **closed** (an unresolved consent view withholds).
    pub(crate) async fn resolve(
        directory: &dyn FederationDirectory,
        local_key_id: &str,
    ) -> Result<Self, Error> {
        let send_set = directory
            .list_consent_peers(local_key_id)
            .await?
            .into_iter()
            .collect();
        Ok(Self { send_set })
    }

    /// A send-authorization for `peer_key_id`, IFF consent includes it. `None`
    /// means edge must advertise nothing consentable to `peer_key_id` this
    /// round — the peer is not in the transmission principle's recipient set.
    /// This is the ONLY constructor of [`ResolvedRecipient`], so no code path
    /// can serve a consentable claim to a peer persist's consent projection did
    /// not authorize.
    pub(crate) fn recipient(&self, peer_key_id: &str) -> Option<ResolvedRecipient> {
        self.send_set
            .contains(peer_key_id)
            .then(|| ResolvedRecipient(peer_key_id.to_owned()))
    }
}

/// Proof that a peer is consent-included as a recipient of consentable claims —
/// the key the attestation serve path REQUIRES. Constructible ONLY via
/// [`ResolvedPeerSet::recipient`], so possessing one is proof the consent
/// membership check passed. Holding a raw `&str` peer id grants no such right:
/// serving to it is unrepresentable without first resolving.
pub(crate) struct ResolvedRecipient(String);

impl ResolvedRecipient {
    /// The peer key id this authorization is for — feed the per-record serve
    /// gates (#379 `infra:serve`, #396 item 6 `recipient_capability`), which
    /// further narrow WHAT this already-consent-included peer receives.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}
