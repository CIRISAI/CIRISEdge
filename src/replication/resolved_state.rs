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
use std::sync::Arc;

/// The consent-resolved set of peers this node may SEND consentable claims to
/// this round — persist's live `consent:replication` peer projection for
/// `local_key_id` (E7, revocation-folded). `Arc`-backed so the bridge can
/// memoize ONE read across a round's advertise + N fetches (CIRISEdge#400: a
/// per-envelope re-read blew the round budget); the memo TTL stays under the
/// anti-entropy cadence, so a between-round withdraw still takes effect at the
/// next round (nuclear un-trust preserved at round granularity).
#[derive(Clone)]
pub(crate) struct ResolvedPeerSet {
    send_set: Arc<HashSet<String>>,
}

impl ResolvedPeerSet {
    /// Build from persist's `list_consent_peers(local)` result. The
    /// operator-addressing half of the intersection is applied by the caller's
    /// serve path (only a connected peer is ever tested), so this holds the
    /// consent side alone. The `Arc` makes [`Clone`] O(1) for the memo.
    pub(crate) fn from_consent_peers(peers: Vec<String>) -> Self {
        Self {
            send_set: Arc::new(peers.into_iter().collect()),
        }
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

    /// **CIRISEdge#524 — DIAGNOSTIC ONLY.** Does the send-set NAME `key_id`?
    ///
    /// Answers *"who did the grant name?"* for the withhold log, and returns a
    /// `bool` — never a [`ResolvedRecipient`]. Minting the send authorization
    /// stays the sole privilege of [`Self::recipient`], so this cannot be used
    /// to serve anything: the by-construction funnel is intact. It exists
    /// because a `consent:replication:v1` grant naming a PERSON is silently
    /// unroutable (a person's key has no transport binding, and edge resolves
    /// recipients by EXACT key match), and a withhold that cannot say *that*
    /// costs the operator a harness build.
    pub(crate) fn names(&self, key_id: &str) -> bool {
        self.send_set.contains(key_id)
    }

    /// CIRISEdge#524 — how many subjects the live grant projection named. Part
    /// of the same diagnostic: `0` is a fleet-wide consent problem while `n > 0`
    /// with no match is a per-peer addressing problem, and the withhold line
    /// should not make an operator guess which.
    pub(crate) fn len(&self) -> usize {
        self.send_set.len()
    }

    /// Test-only: do two handles share the SAME memoized set (the O(1)
    /// `Arc` clone)? The regression witness for CIRISEdge#400 — a memo HIT
    /// returns a clone of the same `Arc`; a re-read would allocate a new one.
    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.send_set, &other.send_set)
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
