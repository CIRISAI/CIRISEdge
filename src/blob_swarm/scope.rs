//! Scope-native addressing for the blob / content plane (CIRISEdge#499).
//!
//! # The defect this closes
//!
//! Before this module, [`SwarmScheduler::fetch_blob`] and the inbound
//! `BlobChunkFetch` responder had **zero** scope awareness: a community's
//! blob was requested from, and served at, the node's single federation
//! address regardless of the content's scope. The record layer was
//! scope-private; the address the bytes moved over was not. An observer
//! sitting on the fabric therefore correlated a family flow, a community
//! flow and a public flow to one endpoint — the same context collapse
//! #499 removed from the message and A/V planes, one plane over.
//!
//! Per <https://ciris.ai/contextual-integrity/>, privacy is appropriate
//! *flow*, and a scoped blob moving over an unscoped address is an
//! inappropriate one **even when the bytes are sealed**: the ciphertext
//! is not the leak, the endpoint correlation is.
//!
//! # Two halves, one rule
//!
//! Both halves reduce to the SAME already-owned predicate,
//! [`CohortScope::allows_recipient_scope`] (CIRISEdge#48-A). This module
//! invents no scope rule of its own — it only changes what the
//! *recipient scope* input is made of:
//!
//! - **Send** ([`BlobScopeRouter::route`]) — resolve the holder's
//!   scope-derived address ABOVE the transport and hand the send path a
//!   [`BlobRecipient`], which cannot name a wrong address because the
//!   only way to build one is to have resolved it. This is the
//!   `ResolvedRecipient` pattern (CIRISEdge#396/#402) applied to the blob
//!   plane. `Transport::send` grows NO scope parameter (it has 10
//!   implementors, including HTTP and packet radio) and the transport
//!   parses no scope: the caller already knows the content's scope, so it
//!   hands down an address rather than a question.
//!
//! - **Serve** ([`admit_blob_serve`]) — the recipient scope is no longer
//!   a directory-recorded *claim* but a **cryptographic fact**. A frame
//!   that arrived on a scope-derived address carries an
//!   [`InboundAddress`], and holding one proves the sender possessed the
//!   group's MLS `exporter_secret`, which binds `(group_id, epoch)` per
//!   RFC 9420 §8.5. That is why the gate is cheap and why it can sit
//!   ahead of the body parse: the admission fact is a hash-map probe the
//!   transport already performed, not something the responder derives
//!   from anything the requester said.
//!
//! # Fail-closed, and the exact shape of "closed"
//!
//! A blob whose scope cannot be determined is NOT served — [`ServeAdmission`]
//! is `#[must_use]` and its refusal arm carries a named
//! [`ServeRefusal`], mirroring the [`ApplyOutcome`] choke-point pattern
//! (CIRISEdge#425). There is no arm that refuses silently and no arm a
//! caller can drop on the floor.
//!
//! **But fail-closed is armed, not unconditional.** Both halves are gated
//! on whether a [`ScopeAddressTable`] is installed
//! ([`BlobScopeRouter::is_scope_native`]). A deployment with no table —
//! which per `scope_addressing`'s module docs is EVERY production
//! deployment until the MLS exporter label is specified upstream —
//! behaves exactly as it did before this module existed:
//! [`BlobRoute::Federation`] on send, [`ServeAdmission::Admit`] on serve.
//! Scope-native addressing is strictly additive. Refusing every blob on a
//! node that has no way to derive an address would not be fail-closed, it
//! would be fail-broken.
//!
//! [`SwarmScheduler::fetch_blob`]: super::SwarmScheduler::fetch_blob
//! [`ApplyOutcome`]: crate::replication::summary::ApplyOutcome

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::cohort_scope::CohortScope;
use crate::scope_addressing::{InboundAddress, MemberAddress, ScopeAddressTable};

/// v18 — has the unarmed-gate staging WARN fired this process?
static BLOB_SCOPE_GATE_UNARMED_WARNED: AtomicBool = AtomicBool::new(false);

/// v18 — say ONCE (per process) that the blob serve gate is riding the staged
/// default-open state, so "staged open" is never mistaken for "armed and
/// passing". The default itself is INTENTIONAL and must not flip — production
/// rides it; arming is an OPERATOR OPT-IN (install the MLS
/// [`ScopeAddressTable`] via `EdgeBuilder::scope_native_addressing`; the
/// CIRISVerify#259 `ScopePrivacyDeriver` is shipped, nothing upstream pends).
fn warn_blob_scope_gate_unarmed() {
    if !BLOB_SCOPE_GATE_UNARMED_WARNED.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            "blob serve scope gate UNARMED — scope-native addressing is not \
             installed, so this node rides the pre-#499 staged state: every \
             arrival is treated as the federation address and every blob request \
             is admitted without a scope check. This is the deliberate default; \
             arming is an OPERATOR OPT-IN — install the MLS ScopeAddressTable via \
             EdgeBuilder::scope_native_addressing (the CIRISVerify#259 \
             ScopePrivacyDeriver is shipped). Warned once per process."
        );
    }
}

// ─── What "this blob's scope" means to the addressing layer ─────────

/// The scope a blob's CONTENT lives in, in the form the addressing layer
/// needs it: the cohort scope plus the opaque MLS group id whose
/// `exporter_secret` derives that group's member addresses.
///
/// Two fields rather than one because [`CohortScope`] alone cannot
/// address anything. `Family` names a *kind* of scope; it does not say
/// WHICH family, and a node may hold several. The group id is what the
/// [`ScopeAddressTable`] is keyed by. Edge does **not** interpret
/// `group_id` — it is the MLS group's identifier as the scope-privacy
/// layer names it, carried through opaquely.
///
/// Obtained from [`BlobChunkSource::chunk_scope`](super::BlobChunkSource::chunk_scope),
/// i.e. from the persist-backed consumer that owns content classification.
/// Edge never infers a blob's scope; `None` from that call is the
/// undeterminable case and is refused, not guessed.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ContentScope {
    /// Public / federation-scoped content. Rides the node's federation
    /// address exactly as it did pre-#499. This is NOT a scope-derived
    /// route and deliberately has no group: `Public` content is reachable
    /// by construction, and deriving a private address for it would be a
    /// contradiction (see [`ScopeRouteRefusal::PublicIsNotScoped`]).
    Federation,
    /// Content bound to a scoped MLS group. Addresses for this content's
    /// flows are derived from that group's `exporter_secret`.
    Group {
        /// The cohort scope. `Public` here is refused at routing time —
        /// public content must be declared [`ContentScope::Federation`].
        scope: CohortScope,
        /// The opaque MLS group id. Edge does not interpret it.
        group_id: String,
    },
}

impl ContentScope {
    /// The cohort scope this content declares, for the #48-A predicate.
    #[must_use]
    pub fn cohort_scope(&self) -> &CohortScope {
        match self {
            Self::Federation => &CohortScope::Public,
            Self::Group { scope, .. } => scope,
        }
    }

    /// The MLS group id, or `None` for federation-scoped content.
    #[must_use]
    pub fn group_id(&self) -> Option<&str> {
        match self {
            Self::Federation => None,
            Self::Group { group_id, .. } => Some(group_id),
        }
    }
}

// ─── SEND: the resolved-recipient funnel ────────────────────────────

/// Where a blob request's bytes are addressed. Private to the crate: the
/// only way a caller learns the route is through [`BlobRecipient`], and
/// the only way to build one of those is to have resolved it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum BlobRoute {
    /// The node's federation address, reached by `key_id` through the
    /// ordinary `Transport::send` path. Byte-identical to pre-#499.
    Federation,
    /// A scope-derived per-member address.
    Scoped(MemberAddress),
}

/// Proof that a holder's address for a blob's scope HAS BEEN RESOLVED —
/// the key the blob send path requires.
///
/// Constructible ONLY via [`BlobScopeRouter::route`], so possessing one
/// is proof that the content's scope was determined and an address was
/// derived for it (or that the content is federation-scoped and the
/// federation address is correct). Holding a raw `&str` peer id grants no
/// such right: issuing a scoped fetch to it is unrepresentable without
/// first routing.
///
/// This is the blob plane's [`ResolvedRecipient`], and it is a separate
/// type on purpose — that one is the *consent* projection's authorization
/// (may I send to this peer at all), this one is the *addressing*
/// resolution (which of this peer's addresses is correct for this
/// content). Folding them would make one type mean two checks, and a
/// caller that satisfied one would silently appear to have satisfied the
/// other.
///
/// [`ResolvedRecipient`]: crate::replication::resolved_state::ResolvedRecipient
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlobRecipient {
    peer_key_id: String,
    route: BlobRoute,
}

impl BlobRecipient {
    /// The holder this authorization addresses.
    #[must_use]
    pub fn peer_key_id(&self) -> &str {
        &self.peer_key_id
    }

    /// The scope-derived address, or `None` for a federation route.
    ///
    /// Returns a [`MemberAddress`], which has no public byte constructor:
    /// a caller cannot fabricate one and cannot turn arbitrary bytes into
    /// one. The bytes are readable (`as_bytes`) because the transport has
    /// to hand them to a Reticulum `Destination`; they are not writable.
    #[must_use]
    pub fn scoped_address(&self) -> Option<&MemberAddress> {
        match &self.route {
            BlobRoute::Federation => None,
            BlobRoute::Scoped(addr) => Some(addr),
        }
    }

    /// `true` iff this recipient is addressed at a scope-derived address
    /// rather than the federation address.
    #[must_use]
    pub fn is_scoped(&self) -> bool {
        matches!(self.route, BlobRoute::Scoped(_))
    }
}

/// Why a blob request could not be routed. Every variant is a REFUSAL,
/// never a fallback: there is deliberately no arm that shrugs and uses
/// the federation address, because that is precisely the context collapse
/// this module exists to remove.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeRouteRefusal {
    /// The content's scope could not be determined on a node that IS
    /// scope-native (a [`ScopeAddressTable`] is installed). Refused rather
    /// than defaulted: "unclassified means public" is the single most
    /// expensive default this stack could adopt, and it is not edge's to
    /// choose — `chunk_scope` is the consumer's declaration and its `None`
    /// means *unknown*, not *public*.
    #[error(
        "blob scope routing: content scope is UNDETERMINABLE and this node is \
         scope-native — refusing to fall back to the federation address \
         (CIRISEdge#499). Wire BlobChunkSource::chunk_scope to report the blob's \
         scope; a None answer is never read as Public."
    )]
    ScopeUndeterminable,
    /// The content is group-scoped but no [`ScopeAddressTable`] is
    /// installed, so no address can be derived. Fail-closed: sending a
    /// scoped blob over the federation address is the defect.
    #[error(
        "blob scope routing: content is scoped to '{scope_kind}' group '{group_id}' \
         but NO scope address table is installed — no derived address exists, and \
         the federation address is not an acceptable substitute (CIRISEdge#499)"
    )]
    NoAddressTable {
        /// [`CohortScope::kind_token`] of the content's scope.
        scope_kind: &'static str,
        /// The MLS group id the content is bound to.
        group_id: String,
    },
    /// A table is installed but this holder has no derived address in the
    /// content's group — it is not a member at any live epoch, or it was
    /// excluded at a rotation seal. Either way we cannot address it for
    /// this content, and must not address it for this content.
    #[error(
        "blob scope routing: holder '{peer_key_id}' has NO derived address in \
         '{scope_kind}' group '{group_id}' (not a member at any live epoch, or \
         excluded at a rotation seal) — this holder cannot be asked for this \
         blob (CIRISEdge#499)"
    )]
    HolderNotInGroup {
        /// The holder we could not address.
        peer_key_id: String,
        /// [`CohortScope::kind_token`] of the content's scope.
        scope_kind: &'static str,
        /// The MLS group id the content is bound to.
        group_id: String,
    },
    /// The content declared [`ContentScope::Group`] with a `Public`
    /// cohort scope. Refused for exactly the reason
    /// `ReticulumTransport::register_scoped_destination` refuses to
    /// register a `Public` scoped destination: a derived per-member
    /// address is not a discovery address, and pairing "public" with a
    /// private derived address is a contradiction, not a configuration.
    /// Public content is [`ContentScope::Federation`].
    #[error(
        "blob scope routing: content declared group '{group_id}' at Public scope — \
         a derived per-member address is not a discovery address; public content \
         must be declared ContentScope::Federation (CIRISEdge#499)"
    )]
    PublicIsNotScoped {
        /// The group id the caller paired with `Public`.
        group_id: String,
    },
}

impl ScopeRouteRefusal {
    /// Stable, low-cardinality tag for log throttling and metric detail.
    /// Never contains a peer id or a group id — those ride the bounded
    /// record, not the label (unbounded label cardinality explodes
    /// downstream metric storage).
    #[must_use]
    pub const fn reason_tag(&self) -> &'static str {
        match self {
            Self::ScopeUndeterminable => "blob_scope_undeterminable",
            Self::NoAddressTable { .. } => "blob_no_address_table",
            Self::HolderNotInGroup { .. } => "blob_holder_not_in_group",
            Self::PublicIsNotScoped { .. } => "blob_public_is_not_scoped",
        }
    }
}

/// Resolves a blob's scope to the address its bytes must move over.
///
/// Sits **above** the transport by construction: it holds only the
/// address table (a pure lookup structure) and produces a
/// [`BlobRecipient`]. It cannot send, so it cannot be the place a send
/// decision leaks into the transport.
///
/// Every method is synchronous and takes no lock across anything — the
/// table's own methods are synchronous by design (CIRISEdge#217: a guard
/// held across an `.await` on a transport path is what produced the real
/// hangs), and this type adds no state of its own.
#[derive(Clone, Default)]
pub struct BlobScopeRouter {
    table: Option<Arc<ScopeAddressTable>>,
}

impl BlobScopeRouter {
    /// A router over an installed table. `None` — the production state
    /// until the MLS exporter label is specified upstream — yields a
    /// router that routes everything to the federation address, i.e.
    /// exactly pre-#499 behaviour.
    #[must_use]
    pub fn new(table: Option<Arc<ScopeAddressTable>>) -> Self {
        Self { table }
    }

    /// `true` iff a [`ScopeAddressTable`] is installed, i.e. iff this node
    /// can derive scoped addresses at all.
    ///
    /// This is THE arming condition for both halves of the gate. It is a
    /// deployment fact, not a policy knob: a node with no table has no
    /// scope-derived address to send from, to send to, or to be reached
    /// on, so a scope gate over it could only ever refuse everything.
    #[must_use]
    pub fn is_scope_native(&self) -> bool {
        self.table.is_some()
    }

    /// Resolve `peer_key_id` to the address this content's bytes must
    /// move over.
    ///
    /// `content` is the blob's declared scope, or `None` when the
    /// consumer could not determine it.
    ///
    /// # Errors
    ///
    /// Every arm of [`ScopeRouteRefusal`]. There is no arm that silently
    /// degrades to the federation address for scoped content.
    pub fn route(
        &self,
        content: Option<&ContentScope>,
        peer_key_id: &str,
    ) -> Result<BlobRecipient, ScopeRouteRefusal> {
        let federation = || BlobRecipient {
            peer_key_id: peer_key_id.to_owned(),
            route: BlobRoute::Federation,
        };

        let Some(content) = content else {
            // Undeterminable scope. On a node that cannot derive addresses
            // at all there is nothing to refuse INTO — refusing here would
            // break every existing deployment's blob plane without moving
            // a single byte off the federation address (there is no other
            // address). On a scope-native node it is a hard refusal.
            return if self.is_scope_native() {
                Err(ScopeRouteRefusal::ScopeUndeterminable)
            } else {
                Ok(federation())
            };
        };

        let (scope, group_id) = match content {
            // Public content rides the federation address — byte-identical
            // to pre-#499, on scope-native nodes and legacy nodes alike.
            ContentScope::Federation => return Ok(federation()),
            ContentScope::Group { scope, group_id } => (scope, group_id),
        };

        if matches!(scope, CohortScope::Public) {
            return Err(ScopeRouteRefusal::PublicIsNotScoped {
                group_id: group_id.clone(),
            });
        }

        let Some(table) = self.table.as_ref() else {
            return Err(ScopeRouteRefusal::NoAddressTable {
                scope_kind: scope.kind_token(),
                group_id: group_id.clone(),
            });
        };

        // The one derivation-adjacent call in this module, and it is a
        // LOOKUP, not a derivation: `send_address` never calls the deriver
        // (that is the invariant `scope_addressing`'s
        // `lookup_never_calls_the_deriver` test pins). Address derivation
        // is CIRISVerify#259's; edge reproduces its bytes, never its math.
        match table.send_address(scope, group_id, peer_key_id) {
            Some(address) => Ok(BlobRecipient {
                peer_key_id: peer_key_id.to_owned(),
                route: BlobRoute::Scoped(address),
            }),
            None => Err(ScopeRouteRefusal::HolderNotInGroup {
                peer_key_id: peer_key_id.to_owned(),
                scope_kind: scope.kind_token(),
                group_id: group_id.clone(),
            }),
        }
    }
}

// ─── SERVE: admission ahead of the parse ────────────────────────────

/// Why a blob chunk was not served. Each variant is ONE code branch, per
/// the CIRISEdge#433 rule that a refusal reason is the BRANCH and never a
/// disjunction — folding "we could not tell what this blob is" into "you
/// reached us on the wrong address" would send an operator to look in the
/// wrong place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeRefusal {
    /// The responder could not determine the blob's scope, so it cannot
    /// know whether this requester is entitled to it. Fail-closed.
    ScopeUndeterminable,
    /// The blob's scope does not admit the scope the request ARRIVED on.
    /// The canonical case: family-scoped content requested over the
    /// federation address — the requester proved nothing about family
    /// membership by reaching a public endpoint.
    ArrivalScopeInsufficient {
        /// [`CohortScope::kind_token`] of the content's scope.
        content_kind: &'static str,
        /// [`CohortScope::kind_token`] of the scope the request arrived on.
        arrival_kind: &'static str,
    },
    /// The arrival scope matched, but the request arrived on an address
    /// derived from a DIFFERENT group's `exporter_secret`.
    ///
    /// Its own branch because the scope predicate genuinely cannot see
    /// this: `Family` vs `Family` is a match to
    /// [`CohortScope::allows_recipient_scope`], and yet possession of one
    /// family's group secret proves nothing whatsoever about another
    /// family's. Serving across that boundary would answer on authority
    /// the requester never demonstrated.
    GroupMismatch {
        /// [`CohortScope::kind_token`] of the content's scope.
        content_kind: &'static str,
    },
}

impl ServeRefusal {
    /// Stable, low-cardinality tag for log throttling and metric detail.
    /// Carries no group id, peer id or blob hash — those ride the bounded
    /// record.
    #[must_use]
    pub const fn reason_tag(&self) -> &'static str {
        match self {
            Self::ScopeUndeterminable => "blob_serve_scope_undeterminable",
            Self::ArrivalScopeInsufficient { .. } => "blob_serve_arrival_scope_insufficient",
            Self::GroupMismatch { .. } => "blob_serve_group_mismatch",
        }
    }

    /// The withhold-ledger reason for this branch (CIRISEdge#433).
    #[must_use]
    pub const fn withhold_reason(&self) -> crate::observability::WithholdReason {
        match self {
            Self::ScopeUndeterminable => {
                crate::observability::WithholdReason::BlobScopeUndeterminable
            }
            Self::ArrivalScopeInsufficient { .. } => {
                crate::observability::WithholdReason::BlobArrivalScopeInsufficient
            }
            Self::GroupMismatch { .. } => {
                crate::observability::WithholdReason::BlobArrivalGroupMismatch
            }
        }
    }
}

impl std::fmt::Display for ServeRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScopeUndeterminable => f.write_str(
                "blob scope could not be determined, so entitlement cannot be \
                 evaluated — refusing (CIRISEdge#499)",
            ),
            Self::ArrivalScopeInsufficient {
                content_kind,
                arrival_kind,
            } => write!(
                f,
                "blob is scoped '{content_kind}' but the request arrived on a \
                 '{arrival_kind}' address — reaching that address proves no \
                 '{content_kind}' group-secret possession (CIRISEdge#499)"
            ),
            Self::GroupMismatch { content_kind } => write!(
                f,
                "request arrived on a '{content_kind}'-scoped address derived from a \
                 DIFFERENT group's exporter_secret — possession of one group's secret \
                 proves nothing about another's (CIRISEdge#499)"
            ),
        }
    }
}

/// Whether an inbound blob-chunk request may be answered.
///
/// `#[must_use]` with a payload-carrying refusal arm, mirroring
/// [`ApplyOutcome`](crate::replication::summary::ApplyOutcome)
/// (CIRISEdge#425): the responder cannot drop this on the floor, and a
/// refusal always arrives with a named reason to book and log. A bare
/// `bool` would have made "refused" and "refused for a reason nobody can
/// see" the same value — the exact silent-refusal class #423–#429 spent
/// four cuts removing.
#[must_use = "a serve admission carries a refusal reason the responder must book and log — do not drop it"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServeAdmission {
    /// Answer the request.
    Admit,
    /// Do not answer; book and log this reason, then reply with a typed
    /// miss (`MissReason::PolicyDenied`).
    Refuse(ServeRefusal),
}

impl ServeAdmission {
    /// `true` iff the request may be answered.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        matches!(self, Self::Admit)
    }
}

/// The serve decision: may a peer that reached us on `arrival` be handed
/// a chunk of content scoped `content`?
///
/// # The rule, and whose rule it is
///
/// The predicate is [`CohortScope::allows_recipient_scope`] — edge's
/// EXISTING CIRISEdge#48-A recipient-determination rule, unchanged. What
/// #499 changes is only the *provenance of the recipient scope input*:
///
/// - **Before**: the recipient's scope was a directory-recorded claim.
/// - **Now**: it is the scope of the address the request physically
///   arrived on. `Some(arrival)` exists only because a destination hash
///   matched the [`ScopeAddressTable`]'s reverse index, and those hashes
///   are derived from the group's MLS `exporter_secret` — so arrival is
///   proof of group-secret possession, binding `(group_id, epoch)` per
///   RFC 9420 §8.5.
///
/// A request that arrived on the federation address (`arrival == None`)
/// is treated as `CohortScope::Public`, which is not a downgrade or an
/// assumption — it is the literal truth about what reaching a public
/// discovery address demonstrates, namely nothing beyond reachability.
///
/// Group identity is checked SEPARATELY from scope because the #48-A
/// predicate structurally cannot see it (see
/// [`ServeRefusal::GroupMismatch`]).
///
/// # Arming
///
/// `scope_native == false` ⇒ [`ServeAdmission::Admit`] unconditionally.
/// See the module docs: a node with no address table has no scope-derived
/// address for anyone to arrive on, so every request would arrive as
/// `None` and a gate would refuse all non-public content on every
/// existing deployment. Additive, not disruptive.
///
/// v18 — the UNARMED state is no longer silent: the first consultation
/// emits one process-lifetime WARN naming the staged state (see
/// [`warn_blob_scope_gate_unarmed`]). The default itself is INTENTIONAL
/// and unchanged — production rides it, and
/// `the_gate_is_disarmed_when_no_table_is_installed` pins it.
pub fn admit_blob_serve(
    scope_native: bool,
    arrival: Option<&InboundAddress>,
    content: Option<&ContentScope>,
) -> ServeAdmission {
    if !scope_native {
        warn_blob_scope_gate_unarmed();
        return ServeAdmission::Admit;
    }

    let Some(content) = content else {
        return ServeAdmission::Refuse(ServeRefusal::ScopeUndeterminable);
    };

    // What the requester actually PROVED by the address it reached.
    // `None` — the federation address — proves reachability and nothing
    // else, which is exactly `Public`.
    let arrival_scope = arrival.map_or(&CohortScope::Public, |a| a.group().scope());
    let content_scope = content.cohort_scope();

    if !content_scope.allows_recipient_scope(arrival_scope) {
        return ServeAdmission::Refuse(ServeRefusal::ArrivalScopeInsufficient {
            content_kind: content_scope.kind_token(),
            arrival_kind: arrival_scope.kind_token(),
        });
    }

    // Scope matched. If the content names a group, the arrival must name
    // the SAME group: the exporter_secret that derived the arrival address
    // belongs to exactly one group, and possession of it says nothing
    // about any other. `Federation` content names no group and needs no
    // such check — `(Public, _) => true` already admitted it above.
    if let Some(group_id) = content.group_id() {
        let arrival_group = arrival.map(|a| a.group().group_id());
        if arrival_group != Some(group_id) {
            return ServeAdmission::Refuse(ServeRefusal::GroupMismatch {
                content_kind: content_scope.kind_token(),
            });
        }
    }

    ServeAdmission::Admit
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_addressing::StubDeriver;

    const ALICE: &str = "ed25519:alice";
    const BOB: &str = "ed25519:bob";
    const MEMBERS: [&str; 2] = [ALICE, BOB];

    fn cohort(id: &str) -> CohortScope {
        CohortScope::Cohort {
            cohort_id: id.to_owned(),
        }
    }

    /// A table with one family group `fam-1` and one community group
    /// `com-1`, each holding alice + bob.
    fn table() -> Arc<ScopeAddressTable> {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &MEMBERS)
            .expect("family install");
        t.install_group(&cohort("neighbourhood"), "com-1", 1, &[0xB2; 32], &MEMBERS)
            .expect("community install");
        Arc::new(t)
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

    /// Resolve the `InboundAddress` a peer would arrive on for a group.
    fn arrival_for(t: &ScopeAddressTable, scope: &CohortScope, group: &str) -> InboundAddress {
        let addr = t
            .send_address(scope, group, ALICE)
            .expect("alice has an address");
        t.accepts_inbound(addr.as_bytes())
            .expect("her own address is accepted inbound")
    }

    // ── SEND: routing ────────────────────────────────────────────────

    #[test]
    fn scoped_content_routes_to_the_derived_address_not_the_federation_one() {
        let t = table();
        let router = BlobScopeRouter::new(Some(Arc::clone(&t)));

        let recipient = router
            .route(Some(&family_content()), BOB)
            .expect("bob is a member of fam-1");

        assert!(
            recipient.is_scoped(),
            "a family-scoped blob must NOT be requested at the federation address",
        );
        assert_eq!(recipient.peer_key_id(), BOB);
        assert_eq!(
            recipient.scoped_address().map(MemberAddress::as_bytes),
            t.send_address(&CohortScope::Family, "fam-1", BOB)
                .as_ref()
                .map(MemberAddress::as_bytes),
            "the routed address must be exactly the table's derived bytes — no \
             edge-side transformation",
        );
    }

    #[test]
    fn two_scopes_route_the_same_holder_to_unrelated_addresses() {
        // The whole point of the cut: one peer, two contexts, two
        // addresses — so an observer cannot correlate the family flow and
        // the community flow to one endpoint.
        let t = table();
        let router = BlobScopeRouter::new(Some(t));

        let fam = router.route(Some(&family_content()), BOB).expect("family");
        let com = router
            .route(Some(&community_content()), BOB)
            .expect("community");

        assert_ne!(
            fam.scoped_address().map(MemberAddress::as_bytes),
            com.scoped_address().map(MemberAddress::as_bytes),
            "same holder, two scopes, one address = the context collapse #499 removes",
        );
    }

    #[test]
    fn federation_content_keeps_the_unscoped_route_on_a_scope_native_node() {
        let router = BlobScopeRouter::new(Some(table()));
        let r = router
            .route(Some(&ContentScope::Federation), BOB)
            .expect("public content always routes");
        assert!(!r.is_scoped());
        assert!(r.scoped_address().is_none());
    }

    #[test]
    fn a_node_with_no_table_behaves_exactly_as_before() {
        // The no-regression case. Every input that a legacy deployment can
        // actually produce must yield the federation route.
        let router = BlobScopeRouter::default();
        assert!(!router.is_scope_native());

        for content in [None, Some(&ContentScope::Federation)] {
            let r = router.route(content, BOB).expect("legacy route");
            assert!(
                !r.is_scoped() && r.scoped_address().is_none(),
                "a deployment with no installed address table must be byte-identical \
                 to pre-#499",
            );
        }
    }

    #[test]
    fn scoped_content_on_a_node_with_no_table_is_refused_not_downgraded() {
        let router = BlobScopeRouter::default();
        let err = router
            .route(Some(&family_content()), BOB)
            .expect_err("no table, no derived address");
        assert_eq!(
            err,
            ScopeRouteRefusal::NoAddressTable {
                scope_kind: "family",
                group_id: "fam-1".to_owned(),
            },
            "the one thing that must NEVER happen is a silent fall back to the \
             federation address",
        );
    }

    #[test]
    fn undeterminable_scope_is_refused_on_a_scope_native_node() {
        let router = BlobScopeRouter::new(Some(table()));
        assert_eq!(
            router.route(None, BOB).expect_err("unknown scope"),
            ScopeRouteRefusal::ScopeUndeterminable,
        );
        // ...and the legitimate route still works, so the refusal is not
        // "refuse everything" wearing a reason.
        assert!(router.route(Some(&family_content()), BOB).is_ok());
    }

    #[test]
    fn a_non_member_holder_is_refused() {
        let router = BlobScopeRouter::new(Some(table()));
        let err = router
            .route(Some(&family_content()), "ed25519:mallory")
            .expect_err("mallory is not in fam-1");
        assert_eq!(
            err,
            ScopeRouteRefusal::HolderNotInGroup {
                peer_key_id: "ed25519:mallory".to_owned(),
                scope_kind: "family",
                group_id: "fam-1".to_owned(),
            },
        );
        assert!(
            router.route(Some(&family_content()), BOB).is_ok(),
            "a member is still routable — the refusal is holder-specific",
        );
    }

    #[test]
    fn a_group_declared_at_public_scope_is_refused() {
        // Mirrors `register_scoped_destination` refusing a Public scoped
        // destination: a derived per-member address is not a discovery
        // address.
        let router = BlobScopeRouter::new(Some(table()));
        let err = router
            .route(
                Some(&ContentScope::Group {
                    scope: CohortScope::Public,
                    group_id: "fam-1".to_owned(),
                }),
                BOB,
            )
            .expect_err("public + group is a contradiction");
        assert_eq!(
            err,
            ScopeRouteRefusal::PublicIsNotScoped {
                group_id: "fam-1".to_owned()
            },
        );
    }

    #[test]
    fn a_sealed_out_holder_stops_being_routable_at_the_seal() {
        let t = table();
        let router = BlobScopeRouter::new(Some(Arc::clone(&t)));
        assert!(router.route(Some(&family_content()), BOB).is_ok());

        t.remove_member(&CohortScope::Family, "fam-1", BOB);
        assert!(
            matches!(
                router.route(Some(&family_content()), BOB),
                Err(ScopeRouteRefusal::HolderNotInGroup { .. })
            ),
            "a removed member must be refused, never silently federation-routed",
        );
        assert!(
            router.route(Some(&family_content()), ALICE).is_ok(),
            "removing bob must not deafen alice",
        );
    }

    #[test]
    fn reason_tags_are_distinct_and_low_cardinality() {
        let tags = [
            ScopeRouteRefusal::ScopeUndeterminable.reason_tag(),
            ScopeRouteRefusal::NoAddressTable {
                scope_kind: "family",
                group_id: "g".into(),
            }
            .reason_tag(),
            ScopeRouteRefusal::HolderNotInGroup {
                peer_key_id: "p".into(),
                scope_kind: "family",
                group_id: "g".into(),
            }
            .reason_tag(),
            ScopeRouteRefusal::PublicIsNotScoped {
                group_id: "g".into(),
            }
            .reason_tag(),
        ];
        let uniq: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(uniq.len(), tags.len(), "one tag per branch");
        for t in tags {
            assert!(
                !t.contains("ed25519") && !t.contains("fam-1"),
                "a tag must never carry an id — it is a metric label",
            );
        }
    }

    // ── SERVE: admission ─────────────────────────────────────────────

    #[test]
    fn a_scoped_blob_is_served_to_a_peer_arriving_on_the_matching_address() {
        let t = table();
        let arrival = arrival_for(&t, &CohortScope::Family, "fam-1");
        assert_eq!(
            admit_blob_serve(true, Some(&arrival), Some(&family_content())),
            ServeAdmission::Admit,
        );
    }

    #[test]
    fn a_scoped_blob_is_not_served_to_a_peer_arriving_on_the_federation_address() {
        // THE headline refusal. `None` arrival == the federation address.
        let admission = admit_blob_serve(true, None, Some(&family_content()));
        assert_eq!(
            admission,
            ServeAdmission::Refuse(ServeRefusal::ArrivalScopeInsufficient {
                content_kind: "family",
                arrival_kind: "public",
            }),
        );
        assert!(!admission.is_admitted());

        // The trap this repo has been bitten by twice: a refusal test that
        // passes by refusing everything. Assert a LEGITIMATE serve still
        // succeeds under the identical gate.
        let t = table();
        let arrival = arrival_for(&t, &CohortScope::Family, "fam-1");
        assert!(
            admit_blob_serve(true, Some(&arrival), Some(&family_content())).is_admitted(),
            "the gate must still admit the legitimate fetch",
        );
        assert!(
            admit_blob_serve(true, None, Some(&ContentScope::Federation)).is_admitted(),
            "and must still admit public content on the federation address",
        );
    }

    #[test]
    fn public_content_is_served_on_every_arrival() {
        // The no-regression case, restated at the gate: `(Public, _) => true`.
        let t = table();
        let fam = arrival_for(&t, &CohortScope::Family, "fam-1");
        let com = arrival_for(&t, &cohort("neighbourhood"), "com-1");
        for arrival in [None, Some(&fam), Some(&com)] {
            assert_eq!(
                admit_blob_serve(true, arrival, Some(&ContentScope::Federation)),
                ServeAdmission::Admit,
            );
        }
    }

    #[test]
    fn undeterminable_scope_is_never_served_on_a_scope_native_node() {
        let t = table();
        let arrival = arrival_for(&t, &CohortScope::Family, "fam-1");
        for a in [None, Some(&arrival)] {
            assert_eq!(
                admit_blob_serve(true, a, None),
                ServeAdmission::Refuse(ServeRefusal::ScopeUndeterminable),
                "an unknown scope is refused even to a proven group member — we \
                 cannot know it is THEIR content",
            );
        }
        // ...and a determinable blob still serves.
        assert!(admit_blob_serve(true, Some(&arrival), Some(&family_content())).is_admitted());
    }

    #[test]
    fn a_different_groups_address_does_not_unlock_same_scope_content() {
        // `allows_recipient_scope` sees Family vs Family and says yes; the
        // group check is what stops one family reading another's blob.
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&CohortScope::Family, "fam-1", 1, &[0xA1; 32], &MEMBERS)
            .expect("fam-1");
        t.install_group(&CohortScope::Family, "fam-2", 1, &[0xC3; 32], &MEMBERS)
            .expect("fam-2");

        let other_family = arrival_for(&t, &CohortScope::Family, "fam-2");
        assert_eq!(
            admit_blob_serve(true, Some(&other_family), Some(&family_content())),
            ServeAdmission::Refuse(ServeRefusal::GroupMismatch {
                content_kind: "family"
            }),
            "possession of fam-2's exporter_secret proves nothing about fam-1",
        );

        let own_family = arrival_for(&t, &CohortScope::Family, "fam-1");
        assert!(
            admit_blob_serve(true, Some(&own_family), Some(&family_content())).is_admitted(),
            "the legitimate member is still served",
        );
    }

    #[test]
    fn a_community_address_does_not_unlock_family_content() {
        let t = table();
        let com = arrival_for(&t, &cohort("neighbourhood"), "com-1");
        assert_eq!(
            admit_blob_serve(true, Some(&com), Some(&family_content())),
            ServeAdmission::Refuse(ServeRefusal::ArrivalScopeInsufficient {
                content_kind: "family",
                arrival_kind: "cohort",
            }),
        );
    }

    #[test]
    fn a_different_cohort_id_does_not_unlock_community_content() {
        let t = ScopeAddressTable::new(Arc::new(StubDeriver));
        t.install_group(&cohort("neighbourhood"), "com-1", 1, &[0xB2; 32], &MEMBERS)
            .expect("com-1");
        t.install_group(&cohort("book-club"), "com-2", 1, &[0xD4; 32], &MEMBERS)
            .expect("com-2");

        let other = arrival_for(&t, &cohort("book-club"), "com-2");
        assert_eq!(
            admit_blob_serve(true, Some(&other), Some(&community_content())),
            ServeAdmission::Refuse(ServeRefusal::ArrivalScopeInsufficient {
                content_kind: "cohort",
                arrival_kind: "cohort",
            }),
            "CohortScope::allows_recipient_scope compares cohort_id — a different \
             community is refused at the scope predicate, before the group check",
        );

        let own = arrival_for(&t, &cohort("neighbourhood"), "com-1");
        assert!(admit_blob_serve(true, Some(&own), Some(&community_content())).is_admitted());
    }

    /// v18 PIN — "no table ⇒ default-open" is INTENTIONAL, not an oversight.
    /// Production rides this staged state: arming is an operator OPT-IN
    /// (install the table via `EdgeBuilder::scope_native_addressing`), and a
    /// future "fix" that flips this default fail-closed would refuse every
    /// non-public blob on every existing deployment (a legacy node cannot
    /// produce a non-`None` arrival). If you are here to flip it: that is the
    /// arming EVENT, done by installing the table — not by editing this gate.
    #[test]
    fn the_gate_is_disarmed_when_no_table_is_installed() {
        // The no-regression case at the gate. A legacy node cannot produce
        // a non-`None` arrival, so every request would otherwise be
        // refused for all non-public content.
        for content in [
            None,
            Some(&family_content()),
            Some(&ContentScope::Federation),
        ] {
            assert_eq!(
                admit_blob_serve(false, None, content),
                ServeAdmission::Admit,
                "a deployment with no address table must serve exactly as pre-#499 \
                 — the INTENTIONAL staged default; do not flip it here (arming = \
                 installing the ScopeAddressTable, an operator opt-in)",
            );
        }
    }

    #[test]
    fn serve_refusal_reason_tags_are_distinct() {
        let tags = [
            ServeRefusal::ScopeUndeterminable.reason_tag(),
            ServeRefusal::ArrivalScopeInsufficient {
                content_kind: "family",
                arrival_kind: "public",
            }
            .reason_tag(),
            ServeRefusal::GroupMismatch {
                content_kind: "family",
            }
            .reason_tag(),
        ];
        let uniq: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(uniq.len(), tags.len(), "one tag per branch (CIRISEdge#433)");
    }

    #[test]
    fn every_serve_refusal_books_its_own_withhold_reason() {
        // #433: the reason is the BRANCH, not a disjunction.
        let reasons = [
            ServeRefusal::ScopeUndeterminable.withhold_reason(),
            ServeRefusal::ArrivalScopeInsufficient {
                content_kind: "family",
                arrival_kind: "public",
            }
            .withhold_reason(),
            ServeRefusal::GroupMismatch {
                content_kind: "family",
            }
            .withhold_reason(),
        ];
        let uniq: std::collections::HashSet<_> = reasons.iter().collect();
        assert_eq!(uniq.len(), reasons.len());
    }
}
