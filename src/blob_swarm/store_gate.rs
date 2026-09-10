//! CIRISEdge#581 — the store gate. What may ENTER this node's store.
//!
//! # The asymmetry this closes
//!
//! [`admit_blob_serve`](super::scope::admit_blob_serve) decides who may read
//! what we hold, and decides it well: on the address a frame physically
//! arrived on, never on anything the requester claimed, refusing
//! `ScopeUndeterminable` rather than defaulting to public.
//!
//! Nothing decided what may enter. So:
//!
//! > *"No one ever stores anything they did not consent to store, or that is
//! > not from a community they joined, or is not from someone they trust."*
//!
//! was a property of nothing — not weakly enforced, **unenforced**, because
//! the decision point did not exist.
//!
//! # Why it could not be bolted on later
//!
//! - **Storing IS announcing.** persist's `put_blob` auto-emits a
//!   `holds_bytes:sha256:*` holder attestation, and `list_holders` is how the
//!   swarm finds you. You cannot quietly hold federation-tier content. That
//!   is why this gate returns a *trichotomy* rather than a boolean — persist's
//!   two write doors make "store and announce" and "store silently" genuinely
//!   different consents.
//! - **The fountain swarm pushes.** On a pull, consent is implicit in the
//!   request: you asked. The converger rebalances symbols *toward* you, and
//!   nobody asked. So the decision must be explicit and must precede the
//!   bytes.
//! - **Eviction is a retention bound, not an admission bound.** Evicting
//!   above `target_holders + grace` means a node accepted everything and
//!   announced it, however briefly. The copy ceiling does not double as a
//!   consent gate.
//!
//! # The three axes, in the order the operator stated them
//!
//! > *"trust first, then whether we MAY accept the blob, then whether we
//! > SHOULD accept the blob"*
//!
//! 1. **Provenance** — is this sender approved *for this tier*? (trust)
//! 2. **Scope** — are we in the audience the content declares? (may)
//! 3. **Local consent** — did this operator agree to hold this class at all?
//!    (should)
//!
//! They are independent and **all must hold**. Each refuses on its own and
//! none implies another: a blessed CI runner's manifest satisfies 1 and 2 and
//! is still refused if the operator has not agreed to host public blobs.
//!
//! The order is not cosmetic. It refuses on the cheapest and most
//! fundamental ground first, and it means a refusal reason names the *first*
//! rule that failed — which is the one the peer or operator can act on.
//!
//! # A valid signature is not authorization
//!
//! The load-bearing point of axis 1, and edge has already paid for this
//! confusion once: CIRISEdge#564, where an envelope's `on_behalf_of_key_id`
//! proved authorship of a *string* and was read as authorship of the
//! *message*. Same class. Verification proves who authored the bytes; it says
//! nothing about whether they may consume our disk. Federation tier is an
//! **allowlist**, not "anyone whose signature verifies" — which is why
//! [`SenderStanding::VerifiedOnly`] is a distinct input and is never
//! sufficient on its own.

use super::scope::ContentScope;
use crate::CohortScope;

/// What may be done with the bytes. A trichotomy because persist has two
/// write doors and they publish different things.
#[must_use = "a store admission carries a refusal reason the caller must book and log — do not drop it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreAdmission {
    /// Accept the bytes and emit the holder attestation — persist's
    /// `put_blob`. The swarm will find us through `list_holders`.
    StoreAndAnnounce,
    /// Accept the bytes and announce NOTHING — persist's
    /// `store_blob_local`. The bytes are ours to read and the substrate
    /// publishes no claim that we hold them.
    ///
    /// Two independent reasons to land here: the scope suppresses
    /// `holds_bytes` structurally (`self` / `family` — announcing would
    /// defeat the invisibility the scope exists for), or the operator
    /// consented to hold this class but not to advertise holding it.
    StoreLocalOnly,
    /// Do not accept the bytes. The reason names WHICH axis refused,
    /// because the three have different remedies: join the community, get
    /// blessed, or grant consent.
    Refuse(StoreRefusal),
}

impl StoreAdmission {
    /// `true` iff the bytes may be accepted at all.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::StoreAndAnnounce | Self::StoreLocalOnly)
    }

    /// `true` iff a `holds_bytes` attestation may be emitted.
    #[must_use]
    pub fn may_announce(&self) -> bool {
        matches!(self, Self::StoreAndAnnounce)
    }

    /// Which axis refused, if this is a refusal. See [`StoreRefusal::axis`].
    #[must_use]
    pub fn axis_of_refusal(&self) -> Option<u8> {
        match self {
            Self::Refuse(r) => Some(r.axis()),
            _ => None,
        }
    }
}

/// Which rule refused, and enough to act on it.
///
/// Deliberately NOT collapsed into one `PolicyDenied`: that would make the
/// three axes indistinguishable in the field, and an operator staring at a
/// refusal needs to know whether to join a community, get a key blessed, or
/// change local policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreRefusal {
    /// The content's scope could not be determined, so no axis can be
    /// evaluated. Fail-closed — the same posture the serve gate takes, and
    /// for the same reason: "undeterminable" is never read as "public".
    ScopeUndeterminable,
    /// **Axis 1.** The sender is not approved to place content of this tier
    /// on this node. Includes the merely-signature-verified case, which is
    /// the whole point of the axis.
    SenderNotApprovedForTier {
        /// The content tier the sender tried to place.
        content_kind: &'static str,
        /// What the sender actually established.
        sender: SenderStanding,
    },
    /// **Axis 1, fail-closed.** The sender's standing could not be resolved.
    SenderUndeterminable {
        /// The content tier the sender tried to place.
        content_kind: &'static str,
    },
    /// **Axis 2.** The content names an audience this node is not in.
    NotInAudience {
        /// The content tier whose audience excluded us.
        content_kind: &'static str,
    },
    /// **Axis 2, fail-closed.** Membership could not be resolved, so we
    /// cannot know we are in the audience.
    AudienceUndeterminable {
        /// The content tier whose audience could not be resolved.
        content_kind: &'static str,
    },
    /// **Axis 3.** The operator has not agreed to hold this class of content
    /// on this node, whatever its provenance or audience.
    OperatorDeclined {
        /// The content tier the operator declined.
        content_kind: &'static str,
    },
}

impl StoreRefusal {
    /// Which axis refused — `1` provenance, `2` scope, `3` consent, `0` for
    /// the pre-axis undeterminable case. For metrics that want to see which
    /// rule carries the traffic without parsing a message.
    #[must_use]
    pub fn axis(&self) -> u8 {
        match self {
            Self::ScopeUndeterminable => 0,
            Self::SenderNotApprovedForTier { .. } | Self::SenderUndeterminable { .. } => 1,
            Self::NotInAudience { .. } | Self::AudienceUndeterminable { .. } => 2,
            Self::OperatorDeclined { .. } => 3,
        }
    }
}

/// **Axis 1 input** — what the sender has established, resolved by the
/// caller against the directory. Not a claim the sender makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderStanding {
    /// On the blessed allowlist for commons/federation-tier content.
    Allowlisted,
    /// A current member of a community or family **this node has joined**.
    /// "Current" matters: membership is read now, not remembered.
    MemberOfJoinedGroup,
    /// One of the owner's own nodes.
    OwnNode,
    /// The signature verified and nothing further was established.
    /// **Never sufficient on its own** — see the module docs.
    VerifiedOnly,
    /// Standing could not be resolved. Fail-closed.
    Undeterminable,
}

/// **Axis 2 input** — whether this node is in the audience the content
/// declares, answered through the ROW-PLANE predicate rather than a second
/// implementation.
///
/// CIRISEdge#581 is explicit that a second "may I hold this" would drift
/// from the first, and that a cross-plane risk wants the duplication
/// *removed* rather than guarded by a test. The caller resolves this by
/// asking `audience_withholds` whether it would withhold the content from
/// THIS node — inverting the serve question rather than re-deriving it, and
/// inheriting its property that membership is checked against persist's own
/// rosters and so cannot be forged by the sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudienceStanding {
    /// This node is in the declared audience.
    In,
    /// It is not.
    Out,
    /// Membership could not be resolved. Fail-closed.
    Undeterminable,
}

/// **Axis 3 input** — what this operator has agreed to hold, per content
/// class. Purely local: no peer can influence it and the substrate is not
/// entitled to infer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentDisposition {
    /// Hold it, and let the substrate announce that we hold it.
    Announce,
    /// Hold it, announce nothing.
    LocalOnly,
    /// Do not hold it.
    Decline,
}

/// The operator's store policy, one disposition per cohort class.
///
/// The default is the **conservative** one and deliberately not today's
/// behaviour: commons content is `Decline`, because "anyone whose signature
/// verifies may consume this node's disk" is exactly the posture #581 exists
/// to end. A deployment that wants to host public blobs says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorStoreConsent {
    /// `species` / `biosphere` / `federation` — the commons.
    pub commons: ConsentDisposition,
    /// Content scoped to a community this node has joined.
    pub community: ConsentDisposition,
    /// Content scoped to the operator's family cohort.
    pub family: ConsentDisposition,
    /// The owner's own content.
    pub own: ConsentDisposition,
}

impl Default for OperatorStoreConsent {
    fn default() -> Self {
        Self {
            // Not a default anyone should ride into production silently;
            // it refuses, and a refusal is legible. The opposite default
            // would be the unenforced state #581 describes, wearing a
            // struct.
            commons: ConsentDisposition::Decline,
            // Joining a community IS the consent to carry its content —
            // that is what joining means, and a node that joined and then
            // refuses every row is a member in name only.
            community: ConsentDisposition::Announce,
            // Family and own content are structurally invisible; holding
            // them announces nothing regardless (see `announce_is_possible`).
            family: ConsentDisposition::LocalOnly,
            own: ConsentDisposition::LocalOnly,
        }
    }
}

impl OperatorStoreConsent {
    /// The disposition for a given content scope.
    #[must_use]
    pub fn for_scope(&self, scope: &CohortScope) -> ConsentDisposition {
        match scope {
            CohortScope::Public => self.commons,
            CohortScope::Cohort { .. } => self.community,
            CohortScope::Family => self.family,
            CohortScope::SelfOnly => self.own,
        }
    }
}

/// Whether the substrate would announce a hold at this scope AT ALL.
///
/// `self` and `family` suppress `holds_bytes` structurally — that is what
/// makes them invisible, and it is persist's rule, not a preference. So a
/// `ConsentDisposition::Announce` at those scopes cannot be honoured and
/// resolves to local-only rather than being treated as a conflict: the
/// operator asked for something the tier does not offer, and the tier wins.
fn announce_is_possible(scope: &CohortScope) -> bool {
    match scope {
        CohortScope::Public | CohortScope::Cohort { .. } => true,
        CohortScope::SelfOnly | CohortScope::Family => false,
    }
}

/// Whether a sender's standing authorises placing content of this scope.
///
/// The table from CIRISEdge#581, and the one place it is written down.
fn sender_authorised(scope: &CohortScope, sender: SenderStanding) -> bool {
    match scope {
        // Commons: an allowlist. NOT "anyone who verifies".
        CohortScope::Public => matches!(sender, SenderStanding::Allowlisted),
        // A community's content may be placed by its current members —
        // of a community we joined. The caller resolves "joined".
        CohortScope::Cohort { .. } | CohortScope::Family => {
            matches!(sender, SenderStanding::MemberOfJoinedGroup)
        }
        // Only the owner's own nodes may place the owner's own content.
        CohortScope::SelfOnly => matches!(sender, SenderStanding::OwnNode),
    }
}

/// **The store gate.** Evaluated BEFORE bytes are accepted.
///
/// Pure and input-resolved, exactly like
/// [`admit_blob_serve`](super::scope::admit_blob_serve): the async walks
/// (directory membership, allowlist) belong to the caller, so the rule
/// itself is testable at the exact points the field produces.
///
/// Returns the disposition, never a bare bool — see [`StoreAdmission`].
pub fn admit_blob_store(
    content: Option<&ContentScope>,
    sender: SenderStanding,
    audience: AudienceStanding,
    operator: &OperatorStoreConsent,
) -> StoreAdmission {
    // Fail-closed before any axis: we cannot judge what we cannot classify.
    let Some(content) = content else {
        return StoreAdmission::Refuse(StoreRefusal::ScopeUndeterminable);
    };
    let scope = content.cohort_scope();
    let content_kind = scope.kind_token();

    // ── Axis 1 — TRUST. Cheapest and most fundamental; a sender with no
    //    standing gets no further, whatever the content says about itself.
    if sender == SenderStanding::Undeterminable {
        return StoreAdmission::Refuse(StoreRefusal::SenderUndeterminable { content_kind });
    }
    if !sender_authorised(scope, sender) {
        return StoreAdmission::Refuse(StoreRefusal::SenderNotApprovedForTier {
            content_kind,
            sender,
        });
    }

    // ── Axis 2 — MAY. Are we in the audience this content declares?
    match audience {
        AudienceStanding::Undeterminable => {
            return StoreAdmission::Refuse(StoreRefusal::AudienceUndeterminable { content_kind });
        }
        AudienceStanding::Out => {
            return StoreAdmission::Refuse(StoreRefusal::NotInAudience { content_kind });
        }
        AudienceStanding::In => {}
    }

    // ── Axis 3 — SHOULD. The operator's own answer, which no peer and no
    //    roster can override in either direction.
    match operator.for_scope(scope) {
        ConsentDisposition::Decline => {
            StoreAdmission::Refuse(StoreRefusal::OperatorDeclined { content_kind })
        }
        ConsentDisposition::LocalOnly => StoreAdmission::StoreLocalOnly,
        ConsentDisposition::Announce => {
            if announce_is_possible(scope) {
                StoreAdmission::StoreAndAnnounce
            } else {
                // The tier does not offer announcement. Honour the hold,
                // drop the advertisement.
                StoreAdmission::StoreLocalOnly
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> ContentScope {
        ContentScope::Federation
    }

    fn community() -> ContentScope {
        ContentScope::Group {
            scope: CohortScope::Cohort {
                cohort_id: "c-1".into(),
            },
            group_id: "g-1".into(),
        }
    }

    fn permissive() -> OperatorStoreConsent {
        OperatorStoreConsent {
            commons: ConsentDisposition::Announce,
            community: ConsentDisposition::Announce,
            family: ConsentDisposition::LocalOnly,
            own: ConsentDisposition::LocalOnly,
        }
    }

    #[test]
    fn undeterminable_scope_refuses_before_any_axis_runs() {
        // Even with every other input maximally permissive.
        let a = admit_blob_store(
            None,
            SenderStanding::Allowlisted,
            AudienceStanding::In,
            &permissive(),
        );
        assert_eq!(
            a,
            StoreAdmission::Refuse(StoreRefusal::ScopeUndeterminable),
            "we cannot judge what we cannot classify",
        );
        assert!(!a.is_admitted());
    }

    /// The load-bearing case of axis 1, and the whole reason the axis exists.
    #[test]
    fn a_verified_signature_is_not_authorization() {
        let a = admit_blob_store(
            Some(&public()),
            SenderStanding::VerifiedOnly,
            AudienceStanding::In,
            &permissive(),
        );
        assert_eq!(
            a,
            StoreAdmission::Refuse(StoreRefusal::SenderNotApprovedForTier {
                content_kind: CohortScope::Public.kind_token(),
                sender: SenderStanding::VerifiedOnly,
            }),
            "verification proves who authored the bytes, never that they may \
             consume our disk (CIRISEdge#564's class)",
        );
    }

    #[test]
    fn commons_content_needs_the_allowlist_and_nothing_else_substitutes() {
        for s in [
            SenderStanding::MemberOfJoinedGroup,
            SenderStanding::OwnNode,
            SenderStanding::VerifiedOnly,
        ] {
            let a = admit_blob_store(Some(&public()), s, AudienceStanding::In, &permissive());
            assert!(!a.is_admitted(), "{s:?} must not place commons content");
        }
        assert!(admit_blob_store(
            Some(&public()),
            SenderStanding::Allowlisted,
            AudienceStanding::In,
            &permissive(),
        )
        .is_admitted());
    }

    #[test]
    fn a_community_member_cannot_place_commons_and_vice_versa() {
        // Being blessed for the commons says nothing about a community.
        let a = admit_blob_store(
            Some(&community()),
            SenderStanding::Allowlisted,
            AudienceStanding::In,
            &permissive(),
        );
        assert!(
            !a.is_admitted(),
            "the axes do not substitute for each other"
        );
    }

    #[test]
    fn every_axis_refuses_on_its_own() {
        let ok = (
            SenderStanding::MemberOfJoinedGroup,
            AudienceStanding::In,
            permissive(),
        );

        // Axis 1 alone.
        let mut c = ok.2;
        assert!(
            !admit_blob_store(Some(&community()), SenderStanding::VerifiedOnly, ok.1, &c)
                .is_admitted()
        );

        // Axis 2 alone.
        assert!(
            !admit_blob_store(Some(&community()), ok.0, AudienceStanding::Out, &c).is_admitted()
        );

        // Axis 3 alone.
        c.community = ConsentDisposition::Decline;
        assert!(!admit_blob_store(Some(&community()), ok.0, ok.1, &c).is_admitted());

        // All three together.
        assert!(admit_blob_store(Some(&community()), ok.0, ok.1, &ok.2).is_admitted());
    }

    /// #581's own example: a blessed runner's manifest satisfies axes 1 and
    /// 2 and must STILL be refused if the operator has not consented.
    #[test]
    fn a_blessed_runner_is_still_refused_by_local_consent() {
        let mut c = permissive();
        c.commons = ConsentDisposition::Decline;
        assert_eq!(
            admit_blob_store(
                Some(&public()),
                SenderStanding::Allowlisted,
                AudienceStanding::In,
                &c,
            ),
            StoreAdmission::Refuse(StoreRefusal::OperatorDeclined {
                content_kind: CohortScope::Public.kind_token(),
            }),
            "consent is the operator's, and the substrate is not entitled to \
             infer it",
        );
    }

    #[test]
    fn both_fail_closed_arms_refuse_rather_than_default_open() {
        let a = admit_blob_store(
            Some(&community()),
            SenderStanding::Undeterminable,
            AudienceStanding::In,
            &permissive(),
        );
        assert_eq!(a.axis_of_refusal(), Some(1));

        let b = admit_blob_store(
            Some(&community()),
            SenderStanding::MemberOfJoinedGroup,
            AudienceStanding::Undeterminable,
            &permissive(),
        );
        assert_eq!(b.axis_of_refusal(), Some(2));
    }

    /// The trichotomy is the point: `store` and `store-and-announce` are
    /// different consents because persist's two write doors publish
    /// different things.
    #[test]
    fn local_only_holds_the_bytes_without_advertising_them() {
        let mut c = permissive();
        c.community = ConsentDisposition::LocalOnly;
        let a = admit_blob_store(
            Some(&community()),
            SenderStanding::MemberOfJoinedGroup,
            AudienceStanding::In,
            &c,
        );
        assert_eq!(a, StoreAdmission::StoreLocalOnly);
        assert!(a.is_admitted(), "the bytes are accepted");
        assert!(!a.may_announce(), "and no holds_bytes is emitted");
    }

    /// An operator asking to announce `self`/`family` content asked for
    /// something the tier does not offer. The tier wins, and the hold is
    /// still honoured.
    #[test]
    fn an_invisible_scope_cannot_be_announced_however_the_operator_asks() {
        let c = OperatorStoreConsent {
            family: ConsentDisposition::Announce,
            own: ConsentDisposition::Announce,
            ..permissive()
        };
        for scope in [CohortScope::Family, CohortScope::SelfOnly] {
            let content = ContentScope::Group {
                scope: scope.clone(),
                group_id: "g".into(),
            };
            let sender = if scope == CohortScope::SelfOnly {
                SenderStanding::OwnNode
            } else {
                SenderStanding::MemberOfJoinedGroup
            };
            let a = admit_blob_store(Some(&content), sender, AudienceStanding::In, &c);
            assert_eq!(
                a,
                StoreAdmission::StoreLocalOnly,
                "{scope:?} suppresses holds_bytes structurally",
            );
        }
    }

    /// The default must not be the unenforced state wearing a struct.
    #[test]
    fn the_default_consent_declines_the_commons() {
        let d = OperatorStoreConsent::default();
        assert_eq!(d.commons, ConsentDisposition::Decline);
        assert_eq!(
            admit_blob_store(
                Some(&public()),
                SenderStanding::Allowlisted,
                AudienceStanding::In,
                &d,
            ),
            StoreAdmission::Refuse(StoreRefusal::OperatorDeclined {
                content_kind: CohortScope::Public.kind_token(),
            }),
            "a deployment that wants to host public blobs says so",
        );
    }

    #[test]
    fn a_refusal_names_which_rule_refused() {
        // The three have different remedies — join, get blessed, consent —
        // and a single PolicyDenied would make them indistinguishable.
        let axes: Vec<u8> = [
            admit_blob_store(
                Some(&community()),
                SenderStanding::VerifiedOnly,
                AudienceStanding::In,
                &permissive(),
            ),
            admit_blob_store(
                Some(&community()),
                SenderStanding::MemberOfJoinedGroup,
                AudienceStanding::Out,
                &permissive(),
            ),
            admit_blob_store(
                Some(&community()),
                SenderStanding::MemberOfJoinedGroup,
                AudienceStanding::In,
                &OperatorStoreConsent {
                    community: ConsentDisposition::Decline,
                    ..permissive()
                },
            ),
        ]
        .iter()
        .filter_map(StoreAdmission::axis_of_refusal)
        .collect();
        assert_eq!(axes, vec![1, 2, 3], "one axis each, in order");
    }
}

/// The consumer seam that resolves the two async axes.
///
/// Edge owns the RULE ([`admit_blob_store`]); the persist-backed consumer
/// owns the FACTS, exactly as it owns content classification for the serve
/// gate. Edge never infers membership or blessing — those are directory
/// walks against persist's own rosters, which is the property that makes
/// them unforgeable by the sender.
#[async_trait::async_trait]
pub trait BlobStorePolicy: Send + Sync + 'static {
    /// **Axis 1.** What has `holder_key_id` actually established with
    /// respect to content at this scope?
    ///
    /// Implementations MUST NOT return [`SenderStanding::Allowlisted`] on
    /// the strength of a valid signature. The allowlist is a roster, and
    /// which authority blesses a CI key is a Registry/Server question —
    /// edge consumes the roster, it does not decide it.
    async fn sender_standing(&self, holder_key_id: &str, content: &ContentScope) -> SenderStanding;

    /// **Axis 2.** Is THIS node in the audience the content declares?
    ///
    /// Implementations should answer through the row-plane predicate
    /// (`audience_withholds` asked about this node) rather than a second
    /// implementation of the same question — see [`AudienceStanding`].
    async fn audience_standing(&self, content: &ContentScope) -> AudienceStanding;

    /// **Axis 3.** The operator's local policy. Synchronous because it is
    /// local configuration, not a walk.
    fn consent(&self) -> OperatorStoreConsent {
        OperatorStoreConsent::default()
    }
}

#[cfg(test)]
mod seam_tests {
    use super::*;

    /// A policy that answers whatever it was built with — the shape a
    /// persist-backed consumer implements, minus the directory walks.
    struct FixedPolicy {
        sender: SenderStanding,
        audience: AudienceStanding,
        consent: OperatorStoreConsent,
    }

    #[async_trait::async_trait]
    impl BlobStorePolicy for FixedPolicy {
        async fn sender_standing(&self, _: &str, _: &ContentScope) -> SenderStanding {
            self.sender
        }
        async fn audience_standing(&self, _: &ContentScope) -> AudienceStanding {
            self.audience
        }
        fn consent(&self) -> OperatorStoreConsent {
            self.consent
        }
    }

    fn commons() -> ContentScope {
        ContentScope::Federation
    }

    /// The default trait method must be the conservative one, so an
    /// implementation that forgets axis 3 fails closed on the commons
    /// rather than open.
    #[tokio::test]
    async fn the_default_consent_method_declines_the_commons() {
        struct MinimalPolicy;
        #[async_trait::async_trait]
        impl BlobStorePolicy for MinimalPolicy {
            async fn sender_standing(&self, _: &str, _: &ContentScope) -> SenderStanding {
                SenderStanding::Allowlisted
            }
            async fn audience_standing(&self, _: &ContentScope) -> AudienceStanding {
                AudienceStanding::In
            }
            // consent() not overridden
        }
        let p = MinimalPolicy;
        let verdict = admit_blob_store(
            Some(&commons()),
            p.sender_standing("k", &commons()).await,
            p.audience_standing(&commons()).await,
            &p.consent(),
        );
        assert_eq!(
            verdict.axis_of_refusal(),
            Some(3),
            "an implementation that forgets axis 3 must fail closed",
        );
    }

    /// Each axis, driven through the seam the way the scheduler drives it.
    #[tokio::test]
    async fn the_seam_carries_each_axis_through_to_a_refusal() {
        let cases = [
            (
                SenderStanding::VerifiedOnly,
                AudienceStanding::In,
                ConsentDisposition::Announce,
                Some(1u8),
            ),
            (
                SenderStanding::Allowlisted,
                AudienceStanding::Out,
                ConsentDisposition::Announce,
                Some(2),
            ),
            (
                SenderStanding::Allowlisted,
                AudienceStanding::In,
                ConsentDisposition::Decline,
                Some(3),
            ),
            (
                SenderStanding::Allowlisted,
                AudienceStanding::In,
                ConsentDisposition::Announce,
                None,
            ),
        ];
        for (sender, audience, commons_consent, want_axis) in cases {
            let p = FixedPolicy {
                sender,
                audience,
                consent: OperatorStoreConsent {
                    commons: commons_consent,
                    ..OperatorStoreConsent::default()
                },
            };
            let verdict = admit_blob_store(
                Some(&commons()),
                p.sender_standing("holder-1", &commons()).await,
                p.audience_standing(&commons()).await,
                &p.consent(),
            );
            assert_eq!(
                verdict.axis_of_refusal(),
                want_axis,
                "sender={sender:?} audience={audience:?} consent={commons_consent:?}",
            );
        }
    }
}
