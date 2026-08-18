//! Scope-aware fountain **holdings publication** (CIRISEdge#499).
//!
//! # The defect this closes
//!
//! Before this module the swarm publisher
//! ([`run_publisher`](super::runtime::FountainSwarmRuntime)) walked every
//! held `content_id` returned by
//! [`FountainHoldingsSource::list_held_fountain_content`] and broadcast a
//! signed [`FountainHoldingClaim`] — the `content_id` **and its
//! `symbol_ids`** — to every peer a caller-supplied
//! `Fn() -> Vec<String>` returned. There was no entitlement filter of any
//! kind. A family-scoped or community-scoped holding was announced,
//! unprompted, to peers with no business knowing it exists.
//!
//! That is a wider disclosure than the fetch path
//! [`crate::blob_swarm::scope`] closes one plane over: a fetch discloses
//! to one asker who at least had to ask, a holdings broadcast discloses to
//! everyone on a timer. Per <https://ciris.ai/contextual-integrity/>,
//! *"I hold this content"* is itself a flow — publishing it to the wrong
//! cohort is a violation even though **no content bytes move**. The
//! `symbol_ids` make it worse, not better: they are a per-content
//! fingerprint that lets an observer correlate holdings across ticks.
//!
//! # Whose rule is whose
//!
//! This module invents **no** projection policy. It is a two-input join:
//!
//! - **persist owns the projection.** `Plane::FountainContent` is one of
//!   persist's five planes and
//!   [`projection_for`]`(Plane::FountainContent, cohort_scope, authority,
//!   is_tombstone)` answers exactly the question "who may learn this?"
//!   Edge's replication bridge already calls it on the advertise sweep
//!   (`FederationDirectoryReplicationBridge::attestation_projection`); the
//!   swarm publisher is performing an advertise by another name and was
//!   the one advertise path skipping it.
//! - **the host owns the content's scope.** Edge never infers what scope a
//!   fountain content lives in — that is the persist-backed consumer's
//!   classification, surfaced through
//!   [`FountainHoldingsSource::content_scope`], exactly as
//!   [`BlobChunkSource::chunk_scope`](crate::blob_swarm::BlobChunkSource::chunk_scope)
//!   surfaces a blob's. `None` means **UNKNOWN**, never *public*.
//! - **edge owns the per-recipient MECHANISM.** persist's [`Projection`]
//!   names an audience *kind* (`Global` commons gossip / `Cohort`
//!   hold-and-forward over the record's roster / `SelfOwn`
//!   structurally-invisible publish-own); resolving "is THIS peer in that
//!   audience" is the consumer tier's, and edge's existing resolver for a
//!   scope roster is [`ScopeAddressTable::send_address`] — a peer holds a
//!   derived address in a group iff it is a member at a live epoch. That
//!   is the same membership fact
//!   [`ScopeRouteRefusal::HolderNotInGroup`](crate::blob_swarm::ScopeRouteRefusal::HolderNotInGroup)
//!   already rides, reused rather than re-derived.
//!
//! # Fail-closed, and the exact shape of "closed"
//!
//! [`HoldingAnnounce`] is `#[must_use]` and its refusal arm carries a
//! named [`HoldingRefusal`] which maps to a
//! [`WithholdReason`] — the #433 ledger, the #425 choke-point pattern.
//! There is no arm that refuses silently and no arm a caller can drop on
//! the floor: [`HoldingsPublishGate::admit_and_book`] books the withhold
//! **before** it returns the refusal, so a caller that ignores the value
//! still leaves a counted, attributed event behind.
//!
//! **But fail-closed is armed, not unconditional.** The whole gate is
//! gated on whether a [`ScopeAddressTable`] is installed
//! ([`HoldingsScopeGate::is_scope_native`]) — the identical arming
//! condition [`BlobScopeRouter::is_scope_native`] uses, and for the
//! identical reason. A deployment with no table has no scope roster to
//! resolve anyone against, so a gate over it could only refuse
//! everything; it therefore behaves **byte-identically to pre-#499**:
//! every held content announced to every cohort peer. Refusing every
//! holding on a node that cannot resolve a roster would not be
//! fail-closed, it would be fail-broken.
//!
//! [`FountainHoldingsSource::list_held_fountain_content`]: super::FountainHoldingsSource::list_held_fountain_content
//! [`FountainHoldingsSource::content_scope`]: super::FountainHoldingsSource::content_scope
//! [`FountainHoldingClaim`]: crate::holonomic::swarm_rarity::FountainHoldingClaim
//! [`BlobScopeRouter::is_scope_native`]: crate::blob_swarm::BlobScopeRouter::is_scope_native

use std::sync::Arc;

use ciris_persist::federation::namespace::{projection_for, AuthorityClass, Plane, Projection};
use ciris_persist::federation::types::cohort_scope;

use crate::blob_swarm::ContentScope;
use crate::cohort_scope::CohortScope;
use crate::observability::{EdgeMetrics, WithholdReason};
use crate::scope_addressing::ScopeAddressTable;

/// The [`AuthorityClass`] the holdings gate feeds `projection_for`.
///
/// **The negative default, deliberately.** `projection_for`'s authority
/// axis is a property of the CONTENT's provenance (an accord-co-scrubbed
/// canonical corpus vs. a plain producer's), and nothing on the holdings
/// seam carries it: [`HeldFountainContent`](super::HeldFountainContent)
/// has `content_id` / `corpus_kind` / `symbol_ids`, and mapping
/// `corpus_kind` onto a trust-root class would be edge inventing an
/// authority rule persist owns. So the gate asserts the class it can
/// honestly assert — a plain producer/steward — which on
/// [`Plane::FountainContent`] resolves `Cohort` where a trust root would
/// resolve `Global`. Both admit the broadcast today, so the conservative
/// choice costs nothing and stays correct if persist ever narrows
/// `Cohort`.
///
/// Reported upstream as the one input this plane needs and no edge seam
/// supplies.
pub const HOLDING_AUTHORITY: AuthorityClass = AuthorityClass::ProducerSteward;

/// Edge's [`CohortScope`] → persist's `cohort_scope` string token.
///
/// **Not a new mapping.** It is the exact mapping
/// [`CohortScope::crypto_tier`] already performs against persist's
/// 7-value lattice (`Public` → `federation`, `SelfOnly` → `self`,
/// `Family` → `family`, `Cohort{..}` → `community`), lifted so the
/// projection axis and the crypto-tier axis cannot drift to two answers
/// for one scope. The tokens come from persist's own consts, never a
/// string literal.
fn persist_scope_token(scope: &CohortScope) -> &'static str {
    match scope {
        CohortScope::Public => cohort_scope::FEDERATION,
        CohortScope::SelfOnly => cohort_scope::SELF,
        CohortScope::Family => cohort_scope::FAMILY,
        CohortScope::Cohort { .. } => cohort_scope::COMMUNITY,
    }
}

/// Stable low-cardinality tag for a [`Projection`] — for logs and the
/// bounded withhold record. Never carries a capability token's value.
fn projection_tag(projection: Projection) -> &'static str {
    match projection {
        Projection::Global => "global",
        Projection::Cohort => "cohort",
        Projection::SelfOwn => "self_own",
        Projection::Capability(_) => "capability",
        Projection::Subject => "subject",
    }
}

/// Why a holdings claim was NOT announced to a peer.
///
/// Each variant is ONE code branch, per the CIRISEdge#433 rule that a
/// refusal reason is the BRANCH and never a disjunction — folding "I
/// cannot tell what this content is" into "you are not on its roster"
/// would send an operator to fix a membership list when the actual remedy
/// is to wire [`FountainHoldingsSource::content_scope`](super::FountainHoldingsSource::content_scope).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingRefusal {
    /// The host could not determine the content's scope on a node that IS
    /// scope-native. Refused rather than defaulted: "unclassified means
    /// public" is the single most expensive default this stack could
    /// adopt, and it is not edge's to choose — `content_scope`'s `None`
    /// means *unknown*, not *public*.
    ScopeUndeterminable,
    /// The host declared [`ContentScope::Group`] at a `Public` cohort
    /// scope. Refused for the same reason
    /// [`ScopeRouteRefusal::PublicIsNotScoped`](crate::blob_swarm::ScopeRouteRefusal::PublicIsNotScoped)
    /// is: a private roster paired with "public" is a contradiction, not
    /// a configuration. Public content is [`ContentScope::Federation`].
    PublicIsNotScoped,
    /// The projection bounds this record to its OWN roster
    /// ([`Projection::Cohort`] over a named group, or the
    /// structurally-invisible [`Projection::SelfOwn`]) and this peer holds
    /// no derived address in that group — not a member at any live epoch,
    /// or excluded at a rotation seal. **This is the leak closing.**
    PeerNotInRoster {
        /// [`CohortScope::kind_token`] of the content's scope.
        content_kind: &'static str,
        /// Stable low-cardinality tag of the projection that bound the
        /// audience (`cohort` / `self_own`).
        projection: &'static str,
    },
    /// `projection_for` named an audience kind this gate has no mechanism
    /// to resolve to a peer set on this plane — today
    /// [`Projection::Capability`] / [`Projection::Subject`] (role-keyed
    /// and subject-keyed audiences that `Plane::FountainContent` has no
    /// cell for), or a `SelfOwn` record that names no roster to be
    /// invisible within.
    ///
    /// Structurally unreachable against persist v37's table; booked
    /// fail-closed anyway so a future persist widening surfaces as a NAMED
    /// withhold instead of as an allow.
    ProjectionUnsupported {
        /// Stable low-cardinality tag of the projection edge cannot
        /// resolve (`capability` / `subject`).
        projection: &'static str,
    },
}

impl HoldingRefusal {
    /// Stable, low-cardinality tag for log throttling and metric detail.
    /// Never contains a peer id, a content id or a group id — those ride
    /// the bounded record, not the label (unbounded label cardinality
    /// explodes downstream metric storage).
    #[must_use]
    pub const fn reason_tag(&self) -> &'static str {
        match self {
            Self::ScopeUndeterminable => "holding_scope_undeterminable",
            Self::PublicIsNotScoped => "holding_scope_public_group",
            Self::PeerNotInRoster { .. } => "holding_scope_peer_not_in_roster",
            Self::ProjectionUnsupported { .. } => "holding_scope_projection_unsupported",
        }
    }

    /// The withhold-ledger reason for this branch (CIRISEdge#433).
    #[must_use]
    pub const fn withhold_reason(&self) -> WithholdReason {
        match self {
            Self::ScopeUndeterminable => WithholdReason::HoldingScopeUndeterminable,
            Self::PublicIsNotScoped => WithholdReason::HoldingScopePublicGroup,
            Self::PeerNotInRoster { .. } => WithholdReason::HoldingScopePeerNotInRoster,
            Self::ProjectionUnsupported { .. } => WithholdReason::HoldingScopeProjectionUnsupported,
        }
    }
}

impl std::fmt::Display for HoldingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScopeUndeterminable => f.write_str(
                "fountain holding scope is UNDETERMINABLE and this node is scope-native \
                 — refusing to announce the holding (and its symbol_ids) to anyone. Wire \
                 FountainHoldingsSource::content_scope; a None answer is never read as \
                 Public (CIRISEdge#499)",
            ),
            Self::PublicIsNotScoped => f.write_str(
                "fountain holding declared a scope GROUP at Public scope — a private \
                 roster is not a public audience; public content must be declared \
                 ContentScope::Federation (CIRISEdge#499)",
            ),
            Self::PeerNotInRoster {
                content_kind,
                projection,
            } => write!(
                f,
                "fountain holding is scoped '{content_kind}' and projects '{projection}' \
                 (audience = the record's own roster); this peer holds no derived address \
                 in that group at any live epoch, so it is not told the holding exists \
                 (CIRISEdge#499)"
            ),
            Self::ProjectionUnsupported { projection } => write!(
                f,
                "fountain holding projects '{projection}', an audience kind this gate has \
                 no peer-set mechanism for on Plane::FountainContent — refusing \
                 fail-closed rather than guessing the audience (CIRISEdge#499)"
            ),
        }
    }
}

/// Whether a holdings claim may be announced to one peer.
///
/// `#[must_use]` with a payload-carrying refusal arm, mirroring
/// [`ServeAdmission`](crate::blob_swarm::ServeAdmission) and
/// [`ApplyOutcome`](crate::replication::summary::ApplyOutcome)
/// (CIRISEdge#425): the publisher cannot drop this on the floor, and a
/// refusal always arrives with a named reason to book and log. A bare
/// `bool` would have made "withheld" and "withheld for a reason nobody
/// can see" the same value — the exact silent-refusal class #423–#429
/// spent four cuts removing.
#[must_use = "a holding admission carries a refusal reason the publisher must book and log — do not drop it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldingAnnounce {
    /// Announce the holding to this peer.
    Announce,
    /// Do not announce; book and log this reason.
    Withhold(HoldingRefusal),
}

impl HoldingAnnounce {
    /// `true` iff the holding may be announced to this peer.
    #[must_use]
    pub fn is_announced(&self) -> bool {
        matches!(self, Self::Announce)
    }
}

/// Resolves whether a held content's scope admits announcing it to a
/// given peer.
///
/// Holds only the address table (a pure lookup structure) — it cannot
/// send, so it cannot be the place a publish decision leaks into the
/// transport. Every method is synchronous and takes no lock across
/// anything: the table's own methods are synchronous by design
/// (CIRISEdge#217 — a guard held across an `.await` on a publish path is
/// what produced the real hangs), and this type adds no state of its own.
#[derive(Clone, Default)]
pub struct HoldingsScopeGate {
    table: Option<Arc<ScopeAddressTable>>,
}

impl HoldingsScopeGate {
    /// A gate over an installed table. `None` — the production state
    /// until the MLS exporter label is specified upstream — yields a gate
    /// that announces everything, i.e. exactly pre-#499 behaviour.
    #[must_use]
    pub fn new(table: Option<Arc<ScopeAddressTable>>) -> Self {
        Self { table }
    }

    /// `true` iff a [`ScopeAddressTable`] is installed, i.e. iff this node
    /// can resolve a scope roster at all.
    ///
    /// THE arming condition. A deployment fact, not a policy knob: a node
    /// with no table has no roster to resolve any peer against, so a gate
    /// over it could only ever refuse everything.
    #[must_use]
    pub fn is_scope_native(&self) -> bool {
        self.table.is_some()
    }

    /// The projection persist resolves for `scope` on
    /// [`Plane::FountainContent`]. Exposed so the pin test reads the real
    /// table rather than a copy of it — the #636 lesson that a gate must
    /// see the table itself.
    #[must_use]
    pub fn projection_of(scope: &CohortScope) -> Projection {
        projection_for(
            Plane::FountainContent,
            persist_scope_token(scope),
            HOLDING_AUTHORITY,
            // A holdings claim is a live claim about what this node
            // currently retains. It is never a tombstone: there is no
            // "un-holding" record on this plane — a dropped holding is
            // expressed by the claim ceasing to be republished, which the
            // runtime's TTL prune reads. Passing `true` here would raise
            // every scoped holding to the anti-rollback ceiling.
            false,
        )
    }

    /// May a holdings claim for content scoped `content` be announced to
    /// `peer_key_id`?
    ///
    /// `content` is the host's declaration
    /// ([`FountainHoldingsSource::content_scope`](super::FountainHoldingsSource::content_scope)),
    /// or `None` when it could not be determined.
    ///
    /// # Arming
    ///
    /// `is_scope_native() == false` ⇒ [`HoldingAnnounce::Announce`]
    /// unconditionally, with no table probe and no log. See the module
    /// docs: additive, not disruptive.
    pub fn admits(&self, content: Option<&ContentScope>, peer_key_id: &str) -> HoldingAnnounce {
        let Some(table) = self.table.as_ref() else {
            return HoldingAnnounce::Announce;
        };

        let Some(content) = content else {
            return HoldingAnnounce::Withhold(HoldingRefusal::ScopeUndeterminable);
        };

        // Resolve the projection PER RECORD from the record's real scope
        // — never from a cached assumption, the discipline `bridge.rs`
        // holds on the attestation plane.
        let content_scope = content.cohort_scope();
        let projection = Self::projection_of(content_scope);

        match content {
            // Federation/public content: the record names no roster, so
            // its audience is the node's own cohort — which is precisely
            // the peer set the publisher was handed. Byte-identical to
            // pre-#499 for `Global` (trust-root commons gossip) and
            // `Cohort` (hold-and-forward for non-root commons content)
            // alike.
            ContentScope::Federation => match projection {
                Projection::Global | Projection::Cohort => HoldingAnnounce::Announce,
                other => HoldingAnnounce::Withhold(HoldingRefusal::ProjectionUnsupported {
                    projection: projection_tag(other),
                }),
            },
            ContentScope::Group { scope, group_id } => {
                // A private roster at Public scope is a contradiction, not
                // a configuration — refused before any lookup, exactly as
                // the blob router refuses it on the send side.
                if matches!(scope, CohortScope::Public) {
                    return HoldingAnnounce::Withhold(HoldingRefusal::PublicIsNotScoped);
                }
                match projection {
                    // Commons gossip — the record reaches the whole
                    // federation regardless of roster. Unreachable under
                    // `HOLDING_AUTHORITY`; kept exhaustive so a future
                    // authority input is a one-line change, not a rewrite.
                    Projection::Global => HoldingAnnounce::Announce,
                    // `Cohort` — persist: "the record relays to the members
                    // of ITS community/affiliations roster". `SelfOwn` —
                    // persist: publish-own, "the structurally-invisible
                    // identity plane". Both bound the audience to the
                    // record's OWN roster; edge's resolver for that roster
                    // is the address table's membership, one hash-map probe
                    // and no derivation.
                    Projection::Cohort | Projection::SelfOwn => {
                        if table.send_address(scope, group_id, peer_key_id).is_some() {
                            HoldingAnnounce::Announce
                        } else {
                            HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                                content_kind: scope.kind_token(),
                                projection: projection_tag(projection),
                            })
                        }
                    }
                    other => HoldingAnnounce::Withhold(HoldingRefusal::ProjectionUnsupported {
                        projection: projection_tag(other),
                    }),
                }
            }
        }
    }
}

/// The publisher-side choke point: decide **and book**.
///
/// Pairs the pure [`HoldingsScopeGate`] with the CIRISEdge#433 withhold
/// ledger so the publisher has exactly one call to make and no way to
/// refuse silently — [`Self::admit_and_book`] increments the counter and
/// pushes the attribution record BEFORE it returns the refusal. A caller
/// that ignores the returned value still leaves a counted, attributed,
/// logged event behind, which is the property #433 exists to guarantee
/// (a withholding node must not report what an idle node reports).
#[derive(Clone, Default)]
pub struct HoldingsPublishGate {
    gate: HoldingsScopeGate,
    metrics: Option<EdgeMetrics>,
}

impl HoldingsPublishGate {
    /// Construct from the runtime's optional address table and optional
    /// metrics handle. Both `None` is the pre-#499 deployment: the gate
    /// admits everything and books nothing.
    #[must_use]
    pub fn new(table: Option<Arc<ScopeAddressTable>>, metrics: Option<EdgeMetrics>) -> Self {
        Self {
            gate: HoldingsScopeGate::new(table),
            metrics,
        }
    }

    /// `true` iff the gate is armed (a [`ScopeAddressTable`] is installed).
    #[must_use]
    pub fn is_scope_native(&self) -> bool {
        self.gate.is_scope_native()
    }

    /// Decide whether `content_id` (scoped `content`) may be announced to
    /// `peer_key_id`, booking + logging any withhold before returning it.
    ///
    /// Synchronous and lock-free across suspension points: the only guard
    /// taken is inside [`ScopeAddressTable::send_address`], released
    /// before this returns, so no guard can be held across the publisher's
    /// subsequent `.await` on the transport (CIRISEdge#217).
    pub fn admit_and_book(
        &self,
        content_id: &str,
        content: Option<&ContentScope>,
        peer_key_id: &str,
    ) -> HoldingAnnounce {
        let verdict = self.gate.admits(content, peer_key_id);
        if let HoldingAnnounce::Withhold(refusal) = &verdict {
            if let Some(m) = self.metrics.as_ref() {
                m.inc_withhold(
                    refusal.withhold_reason(),
                    peer_key_id,
                    &withhold_detail(content_id),
                );
            }
            tracing::warn!(
                peer = %peer_key_id,
                content_id = %content_id,
                reason = refusal.reason_tag(),
                "swarm_runtime.publisher: holding WITHHELD — {refusal}",
            );
        }
        verdict
    }
}

/// The short, low-cardinality `detail` for a holdings withhold: the plane
/// tag plus a bounded content-id prefix. Mirrors the bridge's
/// `withhold_detail` (kind + 8-byte hash prefix) — the ring is an
/// attribution window, not a log sink, so its entries stay bounded in size
/// as well as in count.
fn withhold_detail(content_id: &str) -> String {
    let prefix: String = content_id.chars().take(16).collect();
    format!("fountain:{prefix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_addressing::StubDeriver;

    const ALICE: &str = "ed25519:alice";
    const BOB: &str = "ed25519:bob";
    const OUTSIDER: &str = "ed25519:mallory";

    fn cohort(id: &str) -> CohortScope {
        CohortScope::Cohort {
            cohort_id: id.to_owned(),
        }
    }

    /// One family group `fam-1` and one community group `com-1`, each
    /// holding alice + bob. `mallory` is in NEITHER.
    fn table() -> Arc<ScopeAddressTable> {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[ALICE, BOB])
            .expect("family install");
        t.install_group(
            &cohort("neighbourhood"),
            "com-1",
            1,
            &[0xB2; 32],
            &[ALICE, BOB],
        )
        .expect("community install");
        Arc::new(t)
    }

    fn armed() -> HoldingsScopeGate {
        HoldingsScopeGate::new(Some(table()))
    }

    fn family_content() -> ContentScope {
        ContentScope::Group {
            scope: CohortScope::Family,
            group_id: "fam-1".to_owned(),
        }
    }

    fn community_content() -> ContentScope {
        ContentScope::Group {
            scope: cohort("neighbourhood"),
            group_id: "com-1".to_owned(),
        }
    }

    // ─── The projection is persist's, and this reads the real table ───

    /// The load-bearing pin: what `Plane::FountainContent` projects for
    /// each scope token edge can produce. If persist re-decides a cell,
    /// this reds HERE rather than silently changing who learns what.
    #[test]
    fn persist_owns_the_fountain_content_projection() {
        assert_eq!(
            HoldingsScopeGate::projection_of(&CohortScope::SelfOnly),
            Projection::SelfOwn,
            "self scope must be structurally invisible",
        );
        assert_eq!(
            HoldingsScopeGate::projection_of(&CohortScope::Family),
            Projection::SelfOwn,
            "family scope must be structurally invisible",
        );
        assert_eq!(
            HoldingsScopeGate::projection_of(&cohort("neighbourhood")),
            Projection::Cohort,
            "community scope relays over ITS OWN roster, not the federation cohort",
        );
        assert_eq!(
            HoldingsScopeGate::projection_of(&CohortScope::Public),
            Projection::Cohort,
            "federation scope under a non-root authority is the cohort relay — \
             the pre-#499 broadcast, unchanged",
        );
    }

    /// The scope-token map is persist's lattice, not a literal table of
    /// edge's own — pinned against persist's consts.
    #[test]
    fn scope_tokens_come_from_persists_lattice() {
        assert_eq!(
            persist_scope_token(&CohortScope::Public),
            cohort_scope::FEDERATION
        );
        assert_eq!(
            persist_scope_token(&CohortScope::SelfOnly),
            cohort_scope::SELF
        );
        assert_eq!(
            persist_scope_token(&CohortScope::Family),
            cohort_scope::FAMILY
        );
        assert_eq!(persist_scope_token(&cohort("x")), cohort_scope::COMMUNITY);
    }

    // ─── Arming: the no-regression case ───────────────────────────────

    /// A node with NO address table announces everything, including
    /// content whose scope is unknown AND content that is family-scoped.
    /// This is the pre-#499 deployment and it must not change.
    #[test]
    fn unarmed_gate_announces_everything() {
        let g = HoldingsScopeGate::new(None);
        assert!(!g.is_scope_native());
        assert!(g.admits(None, OUTSIDER).is_announced());
        assert!(g
            .admits(Some(&ContentScope::Federation), OUTSIDER)
            .is_announced());
        assert!(g.admits(Some(&family_content()), OUTSIDER).is_announced());
        assert!(g
            .admits(Some(&community_content()), OUTSIDER)
            .is_announced());
    }

    // ─── Armed: the leak closes, and only where it should ─────────────

    /// THE test: a family-scoped holding is withheld from a peer outside
    /// the family, AND a federation-scoped one to the SAME peer still
    /// goes — so this cannot pass by announcing nothing.
    #[test]
    fn family_holding_withheld_from_outsider_while_federation_still_flows() {
        let g = armed();
        assert_eq!(
            g.admits(Some(&family_content()), OUTSIDER),
            HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                content_kind: "family",
                projection: "self_own",
            }),
        );
        assert!(
            g.admits(Some(&ContentScope::Federation), OUTSIDER)
                .is_announced(),
            "a federation-scoped holding must still reach the same peer — \
             otherwise this suite passes by broadcasting nothing",
        );
        // …and the family member still learns of it.
        assert!(
            g.admits(Some(&family_content()), BOB).is_announced(),
            "a family MEMBER must still be told; withholding from everyone \
             is not the fix",
        );
    }

    /// The community half of the same leak: persist projects `Cohort`,
    /// which persist defines as "the members of ITS roster" — not every
    /// peer the publisher happens to hold.
    #[test]
    fn community_holding_withheld_from_non_member() {
        let g = armed();
        assert_eq!(
            g.admits(Some(&community_content()), OUTSIDER),
            HoldingAnnounce::Withhold(HoldingRefusal::PeerNotInRoster {
                content_kind: "cohort",
                projection: "cohort",
            }),
        );
        assert!(g.admits(Some(&community_content()), ALICE).is_announced());
    }

    /// Possession of the FAMILY roster says nothing about the COMMUNITY
    /// one and vice versa: membership is resolved per (scope, group), so a
    /// member of one group is not admitted to another group's holdings.
    #[test]
    fn membership_does_not_cross_groups() {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[ALICE])
            .expect("family install");
        t.install_group(&cohort("neighbourhood"), "com-1", 1, &[0xB2; 32], &[BOB])
            .expect("community install");
        let g = HoldingsScopeGate::new(Some(Arc::new(t)));
        // alice is family-only, bob is community-only.
        assert!(g.admits(Some(&family_content()), ALICE).is_announced());
        assert!(!g.admits(Some(&family_content()), BOB).is_announced());
        assert!(g.admits(Some(&community_content()), BOB).is_announced());
        assert!(!g.admits(Some(&community_content()), ALICE).is_announced());
    }

    /// Unknown scope on a scope-native node is refused, with the branch's
    /// own named reason — never read as public.
    #[test]
    fn unknown_scope_is_refused_not_defaulted_public() {
        let g = armed();
        assert_eq!(
            g.admits(None, BOB),
            HoldingAnnounce::Withhold(HoldingRefusal::ScopeUndeterminable),
        );
        assert_eq!(
            HoldingRefusal::ScopeUndeterminable.withhold_reason(),
            WithholdReason::HoldingScopeUndeterminable,
        );
    }

    /// A group declared at Public scope is a contradiction, refused before
    /// any roster lookup — and NOT folded into `PeerNotInRoster`.
    #[test]
    fn group_at_public_scope_is_its_own_refusal() {
        let g = armed();
        let bogus = ContentScope::Group {
            scope: CohortScope::Public,
            group_id: "fam-1".to_owned(),
        };
        assert_eq!(
            g.admits(Some(&bogus), ALICE),
            HoldingAnnounce::Withhold(HoldingRefusal::PublicIsNotScoped),
        );
    }

    /// A member excluded at a rotation seal loses the holding announcement
    /// — the roster is read live, not cached.
    #[test]
    fn removed_member_stops_being_announced_to() {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &[ALICE, BOB])
            .expect("family install");
        let t = Arc::new(t);
        let g = HoldingsScopeGate::new(Some(Arc::clone(&t)));
        assert!(g.admits(Some(&family_content()), BOB).is_announced());
        t.remove_member(&CohortScope::Family, "fam-1", BOB);
        assert!(
            !g.admits(Some(&family_content()), BOB).is_announced(),
            "the roster must be read per-decision, never cached",
        );
    }

    /// Content naming a group the table has never heard of is withheld —
    /// fail-closed, not "no group means everyone".
    #[test]
    fn unknown_group_is_withheld() {
        let g = armed();
        let ghost = ContentScope::Group {
            scope: CohortScope::Family,
            group_id: "fam-does-not-exist".to_owned(),
        };
        assert!(!g.admits(Some(&ghost), ALICE).is_announced());
    }

    // ─── The refusal taxonomy is a taxonomy ───────────────────────────

    /// #433: one reason per branch. Four branches, four distinct
    /// `WithholdReason`s, four distinct labels.
    #[test]
    fn every_refusal_branch_has_its_own_named_reason() {
        let all = [
            HoldingRefusal::ScopeUndeterminable,
            HoldingRefusal::PublicIsNotScoped,
            HoldingRefusal::PeerNotInRoster {
                content_kind: "family",
                projection: "self_own",
            },
            HoldingRefusal::ProjectionUnsupported {
                projection: "subject",
            },
        ];
        let tags: std::collections::BTreeSet<&str> =
            all.iter().map(HoldingRefusal::reason_tag).collect();
        assert_eq!(tags.len(), all.len(), "reason tags must not collide");
        let reasons: std::collections::BTreeSet<WithholdReason> =
            all.iter().map(HoldingRefusal::withhold_reason).collect();
        assert_eq!(
            reasons.len(),
            all.len(),
            "withhold reasons must not collide"
        );
        for r in &all {
            assert!(!r.to_string().is_empty(), "every refusal must say why");
        }
    }

    // ─── Booking: a withhold is an event, not a non-event ─────────────

    /// `admit_and_book` books BEFORE returning, so an ignored return value
    /// still leaves a counted, attributed event.
    #[test]
    fn withholds_are_booked_on_the_ledger() {
        let metrics = EdgeMetrics::default();
        let pg = HoldingsPublishGate::new(Some(table()), Some(metrics.clone()));
        let _ = pg.admit_and_book("c-secret", Some(&family_content()), OUTSIDER);
        let _ = pg.admit_and_book("c-unknown", None, OUTSIDER);
        assert_eq!(
            metrics.withholds(WithholdReason::HoldingScopePeerNotInRoster),
            1
        );
        assert_eq!(
            metrics.withholds(WithholdReason::HoldingScopeUndeterminable),
            1
        );
        let snap = metrics.snapshot();
        assert!(
            snap.recent_withholds
                .iter()
                .any(|w| w.peer_key_id == OUTSIDER && w.detail.starts_with("fountain:")),
            "the attribution ring must name the peer and the content",
        );
    }

    /// An ANNOUNCE books nothing — the ledger must distinguish a
    /// withholding node from a working one.
    #[test]
    fn announces_book_nothing() {
        let metrics = EdgeMetrics::default();
        let pg = HoldingsPublishGate::new(Some(table()), Some(metrics.clone()));
        let _ = pg.admit_and_book("c-pub", Some(&ContentScope::Federation), OUTSIDER);
        let _ = pg.admit_and_book("c-fam", Some(&family_content()), BOB);
        assert!(metrics.snapshot().withholds_by_reason.is_empty());
    }

    /// The detail string stays bounded regardless of content-id length.
    #[test]
    fn withhold_detail_is_bounded() {
        let long = "c".repeat(4096);
        let d = withhold_detail(&long);
        assert_eq!(d, format!("fountain:{}", "c".repeat(16)));
    }
}
