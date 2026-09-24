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
//! is therefore `operator-addressed peers ∩ consent_peers_by_principals(local)`:
//! consent can only **narrow** the operator's addressing, never widen it. The
//! intersection is realized at serve time — only an operator-connected peer
//! ever reaches the serve path, and there it must clear consent membership —
//! so the two constraints compose to the same set without materializing it.
//!
//! Persist's [`consent_peers_by_principals`](ciris_persist::federation::consent_by_humans::consent_peers_by_principals)
//! (v44.6.0, CIRISPersist#857 / CIRISEdge#609 — `local`'s own machine-authored
//! grants ∪ every steward's grants whose `for_key_id == local`; before v25.x the
//! read was `list_consent_peers(local)`, the machine-authored half alone) is the
//! E7 `consent_peer_set` projection, **revocation-folded at write time**:
//! a `withdraws`/`recants` admitted between rounds has already dropped the peer,
//! so re-resolving each round makes un-trust nuclear — *"the authority to say
//! stop stays in human hands"* (<https://ciris.ai/vision/>) enforced at the wire.
//!
//! **The recipient set is resolved, not literal** (CIRISEdge#524, v18.5.0).
//! The consent read returns the SUBJECTS the live grants name, and a
//! consent object naturally names a PERSON. A person's key carries no
//! transport binding, so the literal set is not a routable set: the measured
//! field state was a whole attestation plane dark under a valid grant. The
//! send set is therefore the consent subjects PLUS the nodes each subject is
//! the single responsible owner of (persist v38.3.0 `nodes_owned_by`,
//! CIRISPersist#764) — the person's own instrument, not a third party. The
//! walk, its liveness fold and its ambiguity rule are all persist's; edge
//! resolves once per round, caches, and invalidates (the #430 discipline).
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

use ciris_persist::federation::Audience;

/// **How a peer came to be in the send set** — and therefore which rows it
/// may be handed (CIRISPersist#884 / CIRISEdge#646, v29.3.0).
///
/// Persist's `send_set_for(k, cohort_scope)` is per scope: the consent set
/// reaches every scope; the owner's own nodes are added for `self` and
/// `family` rows; the family members' nodes for `family` rows only. Edge
/// resolves one set per node and carries the basis with each recipient, so
/// the per-row audience gate can refuse a row the basis does not cover.
/// Without this a family member's node — in the set for family rows — would
/// receive every `Global`-projected row this node advertises, which is not
/// the set persist ruled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reach {
    /// A consent grant names the peer (or the person it is the bound
    /// instrument of, CIRISEdge#524): every scope, as before.
    Consent,
    /// The peer is one of the owner's OWN nodes (persist `send_set_for(self)`,
    /// the CC 3.3.6 self-collective, resolved to nodes): `self` and `family`
    /// rows only.
    SelfCollective,
    /// The peer is a family member's node (persist `send_set_for(family)`):
    /// `family` rows only.
    Family,
    /// CIRISEdge#671 (`FSD/FIRST_CONTACT.md` §2, rung R2) — no grant names the
    /// peer, no axis widened to it: it is an Attributed stranger. The recipient
    /// exists so that this node's OWN allegiance facts (owner-binding,
    /// acceptances, charter) can reach a peer that has not been consented to —
    /// the rows a reader needs before Policy A (CC 4.4.3.8) can be evaluated
    /// about us at all. It carries nothing else: `admits` allows only
    /// `federation`, and the audience gate narrows it to the allegiance shape.
    FirstContact,
}

impl Reach {
    /// May a peer reached this way be handed a row that names `audience`?
    /// The row's own audience gate (principal equality, membership) still
    /// runs after this — this is the send-set half, that is the row half.
    #[must_use]
    pub(crate) fn admits(self, audience: &Audience) -> bool {
        match self {
            Self::Consent => true,
            Self::SelfCollective => {
                matches!(audience, Audience::SelfOnly | Audience::Family { .. })
            }
            Self::Family => matches!(audience, Audience::Family { .. }),
            Self::FirstContact => matches!(audience, Audience::Federation),
        }
    }

    /// Stable tag for logs and withhold text.
    #[must_use]
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Consent => "consent",
            Self::SelfCollective => "self_collective",
            Self::Family => "family",
            Self::FirstContact => "first_contact",
        }
    }
}

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
    /// CIRISEdge#524 (v18.5.0, persist v38.3.0 `nodes_owned_by` / #764) — the
    /// NODES reachable because a grant SUBJECT is their single responsible
    /// owner. See [`Self::widened_by_owner_binding`] for why this widening is
    /// the same transmission principle rather than a loosening of it.
    owned_nodes: Arc<HashSet<String>>,
    /// CIRISEdge#524 — did the owner-binding walk answer for EVERY grant
    /// subject? `false` means at least one subject's `nodes_owned_by` read
    /// errored, so this set is NARROWER than the live consent projection.
    /// Recorded rather than hidden: a fail-closed narrowing is still a
    /// narrowing, and the withhold line must be able to say which one this is.
    owner_walk_complete: bool,
    /// CIRISPersist#884 (v46.3.0) — the owner's OWN nodes beyond the consent
    /// set (`send_set_for(local, self)`): [`Reach::SelfCollective`].
    collective: Arc<HashSet<String>>,
    /// CIRISPersist#884 — family members' nodes beyond the self set
    /// (`send_set_for(local, family)`): [`Reach::Family`].
    family_nodes: Arc<HashSet<String>>,
}

impl ResolvedPeerSet {
    /// Build from persist's `consent_peers_by_principals(local)` result. The
    /// operator-addressing half of the intersection is applied by the caller's
    /// serve path (only a connected peer is ever tested), so this holds the
    /// consent side alone. The `Arc` makes [`Clone`] O(1) for the memo.
    ///
    /// The result is DIRECT-NAMED only. Production goes on to
    /// [`Self::widened_by_owner_binding`]; a set that never does simply routes
    /// nothing by owner-binding, which is the pre-v18.5.0 behaviour.
    pub(crate) fn from_consent_peers(peers: Vec<String>) -> Self {
        Self {
            send_set: Arc::new(peers.into_iter().collect()),
            owned_nodes: Arc::new(HashSet::new()),
            owner_walk_complete: true,
            collective: Arc::new(HashSet::new()),
            family_nodes: Arc::new(HashSet::new()),
        }
    }

    /// CIRISPersist#884 (v46.3.0) — widen by the self-collective: persist's
    /// `send_set_for(local, self)` and `send_set_for(local, family)`, each a
    /// superset of the consent set. What the consent set already names keeps
    /// its [`Reach::Consent`]; the owner's own nodes beyond it become
    /// [`Reach::SelfCollective`]; family members' nodes beyond THAT become
    /// [`Reach::Family`]. No grant is read for either — CC 3.2 makes an
    /// owner's consent to their own node a category error, and CC 3.3.6
    /// makes the collective a cryptographic fact. The sets are NODES: persist
    /// resolves each occurrence to the node that hosts it (CC 4.4.3.2.4.1(b)).
    pub(crate) fn widened_by_self_collective(
        mut self,
        self_set: Vec<String>,
        family_set: Vec<String>,
    ) -> Self {
        let collective: HashSet<String> = self_set
            .into_iter()
            .filter(|k| !self.send_set.contains(k))
            .collect();
        let family_nodes: HashSet<String> = family_set
            .into_iter()
            .filter(|k| !self.send_set.contains(k) && !collective.contains(k))
            .collect();
        self.collective = Arc::new(collective);
        self.family_nodes = Arc::new(family_nodes);
        self
    }

    /// **CIRISEdge#524 — the routing half, closed against persist v38.3.0's
    /// `nodes_owned_by` (CIRISPersist#764).**
    ///
    /// `owned_nodes` is the union of `nodes_owned_by(subject)` over the grant
    /// subjects this set was built from: the nodes each subject is the SINGLE
    /// RESPONSIBLE OWNER of (CC 1.13.3.3 / CIRISConstitution#23), resolved by
    /// persist, live-folded (expiry + admitted `withdraws`), never derived here.
    ///
    /// # Why this is the same transmission principle, not a wider one
    ///
    /// A `consent:replication:v1` grant naming a PERSON is the natural shape —
    /// consent is between people — and was silently unroutable, because a
    /// person's key carries no transport binding and edge resolves recipients
    /// by exact key match. Nissenbaum's *recipient* parameter is the person;
    /// their own bound node is the INSTRUMENT through which that person is
    /// reached, not a third party. Delivering to it is delivering to them. The
    /// equivalence is persist's and is exact: `nodes_owned_by` takes candidates
    /// from the granter-side index and gives each one to `owner_of` for its
    /// verdict, so `n ∈ nodes_owned_by(U) ⟺ owner_of(n) == U` holds by
    /// construction, and a node with two live owners (`AmbiguousNodeOwner`) is
    /// SKIPPED — an ambiguous owner is never a resolvable recipient.
    ///
    /// # Why it enters HERE and not at the call site
    ///
    /// [`Self::recipient`] stays the ONE door that mints a
    /// [`ResolvedRecipient`], and stays a pure set-membership test. Resolving
    /// the owner axis per-peer at the serve site would have needed either a
    /// second minting constructor or a directory read inside the funnel — a
    /// side door, which is exactly what #396's by-construction argument spends
    /// its safety on. Widening the SET keeps one door.
    ///
    /// `complete = false` records that at least one subject's walk errored, so
    /// the set is narrower than consent authorizes (fail-closed) and the
    /// withhold line can say so.
    pub(crate) fn widened_by_owner_binding(
        mut self,
        owned_nodes: Vec<String>,
        complete: bool,
    ) -> Self {
        self.owned_nodes = Arc::new(owned_nodes.into_iter().collect());
        self.owner_walk_complete = complete;
        self
    }

    /// A send-authorization for `peer_key_id`, IFF consent includes it —
    /// either because a grant NAMES it, or because a grant names the person
    /// this node is the bound instrument of ([`Self::widened_by_owner_binding`]).
    /// `None` means edge must advertise nothing consentable to `peer_key_id`
    /// this round — the peer is not in the transmission principle's recipient
    /// set. This is the ONLY constructor of [`ResolvedRecipient`], so no code
    /// path can serve a consentable claim to a peer persist's consent
    /// projection did not authorize.
    pub(crate) fn recipient(&self, peer_key_id: &str) -> Option<ResolvedRecipient> {
        let reach = if self.send_set.contains(peer_key_id) || self.owned_nodes.contains(peer_key_id)
        {
            Reach::Consent
        } else if self.collective.contains(peer_key_id) {
            Reach::SelfCollective
        } else if self.family_nodes.contains(peer_key_id) {
            Reach::Family
        } else {
            return None;
        };
        Some(ResolvedRecipient {
            key_id: peer_key_id.to_owned(),
            reach,
        })
    }

    /// CIRISEdge#671 — the recipient for a peer in NONE of the sets: reach
    /// `FirstContact`, which the audience gate confines to this node's own
    /// allegiance facts. Minted by the bridge's one door
    /// (`resolve_attestation_recipient`) only after `recipient` answered
    /// `None`, and never for the node itself. It is a `ResolvedRecipient` so the
    /// serve and fetch paths need no second key type: the narrowing lives in
    /// the reach, not in a bypass.
    pub(crate) fn first_contact_recipient(peer_key_id: &str) -> ResolvedRecipient {
        ResolvedRecipient {
            key_id: peer_key_id.to_owned(),
            reach: Reach::FirstContact,
        }
    }

    /// Is `key_id` in the set ONLY because it is one of the owner's own
    /// nodes, or a family member's (CIRISPersist#884)? Diagnostic, not a
    /// capability — the capability is [`Self::recipient`].
    pub(crate) fn routes_by_self_collective(&self, key_id: &str) -> Option<Reach> {
        if self.collective.contains(key_id) {
            Some(Reach::SelfCollective)
        } else if self.family_nodes.contains(key_id) {
            Some(Reach::Family)
        } else {
            None
        }
    }

    /// How many peers the self-collective widening added beyond consent
    /// (own nodes + family nodes).
    pub(crate) fn collective_routed_len(&self) -> usize {
        self.collective.len() + self.family_nodes.len()
    }

    /// **CIRISEdge#524 — DIAGNOSTIC ONLY.** Does the send-set NAME `key_id`?
    ///
    /// Answers *"who did the grant name?"* for the withhold log, and returns a
    /// `bool` — never a [`ResolvedRecipient`]. Deliberately the DIRECT-named
    /// projection only: it is what separates "the grant named this peer" from
    /// "the grant named this peer's owner", which is the whole content of the
    /// person/node diagnostic and of [`Self::routes_by_owner_binding`].
    pub(crate) fn names(&self, key_id: &str) -> bool {
        self.send_set.contains(key_id)
    }

    /// CIRISEdge#524 — was `key_id` reached by the OWNER-BINDING walk rather
    /// than by a grant naming it? Observability only (the serve line + the
    /// counter); it mints nothing.
    pub(crate) fn routes_by_owner_binding(&self, key_id: &str) -> bool {
        self.owned_nodes.contains(key_id)
    }

    /// CIRISEdge#524 — how many owner-bound nodes the walk contributed. Pairs
    /// with [`Self::len`] in the withhold line: `0` here with a non-empty
    /// send-set says the grant subjects own no live-bound nodes.
    pub(crate) fn owner_routed_len(&self) -> usize {
        self.owned_nodes.len()
    }

    /// CIRISEdge#524 — did the owner-binding walk answer for every subject?
    /// `false` = this set is fail-closed NARROW and self-heals at the next
    /// memo refresh.
    pub(crate) fn owner_walk_complete(&self) -> bool {
        self.owner_walk_complete
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
    /// BOTH halves are checked: the owner-binding walk (#524) is the more
    /// expensive of the two reads, so a memo that shared only the consent half
    /// would still pay the regression this witnesses.
    #[cfg(test)]
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.send_set, &other.send_set)
            && Arc::ptr_eq(&self.owned_nodes, &other.owned_nodes)
    }
}

/// Proof that a peer is consent-included as a recipient of consentable claims —
/// the key the attestation serve path REQUIRES. Constructible ONLY via
/// [`ResolvedPeerSet::recipient`], so possessing one is proof the consent
/// membership check passed. Holding a raw `&str` peer id grants no such right:
/// serving to it is unrepresentable without first resolving.
///
/// Carries the [`Reach`] that minted it: the per-row audience gate refuses a
/// row the reach does not cover (a family member's node is not handed this
/// node's `Global` rows), so the basis travels with the proof instead of
/// being re-derived at the row.
pub(crate) struct ResolvedRecipient {
    key_id: String,
    reach: Reach,
}

impl ResolvedRecipient {
    /// The peer key id this authorization is for — feed the per-record serve
    /// gates (#379 `infra:serve`, #396 item 6 `recipient_capability`), which
    /// further narrow WHAT this already-consent-included peer receives.
    pub(crate) fn as_str(&self) -> &str {
        &self.key_id
    }

    /// How the peer came to be a recipient (CIRISPersist#884).
    pub(crate) fn reach(&self) -> Reach {
        self.reach
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// CIRISPersist#884 — the reach is the send-set half of the audience
    /// question: consent reaches every scope, the owner's own nodes reach
    /// `self` and `family`, a family member's node reaches `family` only.
    #[test]
    fn a_reach_admits_exactly_the_scopes_persist_puts_the_peer_in_the_set_for() {
        let fam = Audience::Family {
            family_key_id: "fam-1".to_owned(),
        };
        let com = Audience::Community {
            community_key_id: "c-1".to_owned(),
        };
        for a in [&Audience::SelfOnly, &fam, &com, &Audience::Federation] {
            assert!(
                Reach::Consent.admits(a),
                "consent reaches {}",
                a.cohort_scope()
            );
        }
        assert!(Reach::SelfCollective.admits(&Audience::SelfOnly));
        assert!(Reach::SelfCollective.admits(&fam));
        assert!(
            !Reach::SelfCollective.admits(&com),
            "own nodes get community rows from the community"
        );
        assert!(!Reach::SelfCollective.admits(&Audience::Federation));
        assert!(Reach::Family.admits(&fam));
        assert!(
            !Reach::Family.admits(&Audience::SelfOnly),
            "a family node never sees a self row"
        );
        assert!(!Reach::Family.admits(&Audience::Federation));
    }

    /// The widening classifies each peer by the NARROWEST axis that admits
    /// it, and the consent set is never re-labelled: a consented peer that is
    /// also the owner's node keeps its full reach.
    #[test]
    fn the_collective_widening_labels_each_node_by_its_axis_and_adds_nothing_else() {
        let set = ResolvedPeerSet::from_consent_peers(v(&["peer-consented"]))
            .widened_by_self_collective(
                v(&["peer-consented", "my-laptop"]),
                v(&["peer-consented", "my-laptop", "sister-phone"]),
            );
        assert_eq!(
            set.recipient("peer-consented").unwrap().reach(),
            Reach::Consent
        );
        assert_eq!(
            set.recipient("my-laptop").unwrap().reach(),
            Reach::SelfCollective
        );
        assert_eq!(
            set.recipient("sister-phone").unwrap().reach(),
            Reach::Family
        );
        assert!(set.recipient("stranger").is_none(), "no side door");
        assert_eq!(set.collective_routed_len(), 2);
        assert!(
            !set.names("my-laptop"),
            "`names` stays the DIRECT consent projection"
        );
        assert_eq!(
            set.routes_by_self_collective("my-laptop"),
            Some(Reach::SelfCollective)
        );
        assert_eq!(set.routes_by_self_collective("peer-consented"), None);
        assert_eq!(
            set.len(),
            1,
            "the consent count is untouched by the widening"
        );
    }
}
