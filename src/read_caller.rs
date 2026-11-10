//! CIRISEdge#971 (persist CIRISPersist#1235) — **who each store read is made
//! for.**
//!
//! persist counts every door read (`observe::snapshot().reads`) and, since
//! v61.2, credits each one to the caller scope in force on the task that made
//! it (`snapshot().callers`). Without a scope edge's reads all land under one
//! unattributed bucket, which is why the canonical's ~330 `attestation_query`
//! a second could be traced to the advertise only by subtraction. Each
//! [`Site`] here names one edge call site; [`scoped`] runs a future under it.
//!
//! Scopes nest and the innermost wins, so a gate's own read inside the
//! advertise is credited to the gate, and the advertise's label keeps only
//! what no inner site claims. A task a scoped future spawns does not inherit
//! the scope (persist's rule); none of these sites spawns one.
//!
//! The labels are fixed, follow persist's grammar (`[a-z][a-z0-9_.:-]*`, at
//! most 48 bytes, `edge.` prefixed), and number [`Site::ALL`]'s length,
//! inside persist's [`MAX_CALLER_LABELS`](ciris_persist::observe::MAX_CALLER_LABELS)
//! of 32 shared with the host. A label persist refuses (it cannot, given the
//! grammar test below) runs its future unscoped: attribution is telemetry,
//! never a reason to change what a read does.

use std::future::Future;
use std::sync::OnceLock;

use ciris_persist::observe::{caller_scope, Caller};

/// One edge call site that reads the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Site {
    /// The advertise's required read (`required_rows`).
    AdvertiseRequired,
    /// The required read's group rows (`required_group_rows`).
    AdvertiseGroups,
    /// An advertise page of the serve cursor (`attestation_page`).
    AdvertiseHistory,
    /// The CC 5.2 unasked-offer check (`moves_unasked`).
    AdvertiseUnasked,
    /// The advertise's per-row gates not claimed by a narrower site
    /// (`offer_rows`).
    AdvertiseGate,
    /// The author-quarantine gate.
    GateQuarantine,
    /// The producer's recipient-capability gate.
    GateCapability,
    /// The first-contact consent-grant check's `owner_of(peer)`.
    GateOwnerOfPeer,
    /// The direct-fetch twin's gates (`serve_fetch_gated`).
    FetchGate,
    /// The subject-Pull serve check (`pull_ref_is_serveable`).
    PullServeable,
    /// The subject-Pull listing (`subject_holdings_inner`).
    SubjectPull,
    /// A key-plane listing's per-subject read.
    KeyPlane,
    /// The shared serve-cursor feed (`store_feed`).
    Feed,
    /// The announce-gated identity-plane advertise.
    IdentityPlane,
    /// The holdings drain of persist's content-hash index.
    Holdings,
    /// The consent send-set read.
    SendSet,
    /// The owner-binding and announce-reach reads.
    OwnerBinding,
    /// The apply choke (`dispatch_apply`).
    Apply,
    /// The transport's peer attribution.
    TransportAttribution,
    /// The first-contact handshake.
    FirstContact,
    /// The membership ceremony.
    Membership,
    /// Chat rows.
    Chat,
    /// A/V call rows.
    AvCall,
    /// The blob durability check.
    BlobDurability,
    /// The bundle serve nodes' key-record check (`bundle_bootstrap_peers_held`,
    /// at start and in the late-arrival re-check).
    BundleSeats,
    /// The transport's round-start reach check (`round_carriable`,
    /// `undialable_now`).
    RoundCarriable,
}

impl Site {
    /// Every site, in label order (the slot table's order).
    pub(crate) const ALL: [Self; 26] = [
        Self::AdvertiseRequired,
        Self::AdvertiseGroups,
        Self::AdvertiseHistory,
        Self::AdvertiseUnasked,
        Self::AdvertiseGate,
        Self::GateQuarantine,
        Self::GateCapability,
        Self::GateOwnerOfPeer,
        Self::FetchGate,
        Self::PullServeable,
        Self::SubjectPull,
        Self::KeyPlane,
        Self::Feed,
        Self::IdentityPlane,
        Self::Holdings,
        Self::SendSet,
        Self::OwnerBinding,
        Self::Apply,
        Self::TransportAttribution,
        Self::FirstContact,
        Self::Membership,
        Self::Chat,
        Self::AvCall,
        Self::BlobDurability,
        Self::BundleSeats,
        Self::RoundCarriable,
    ];

    /// The label persist counts this site's reads under.
    #[must_use]
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::AdvertiseRequired => "edge.advertise.required",
            Self::AdvertiseGroups => "edge.advertise.groups",
            Self::AdvertiseHistory => "edge.advertise.history",
            Self::AdvertiseUnasked => "edge.advertise.unasked",
            Self::AdvertiseGate => "edge.advertise.gate",
            Self::GateQuarantine => "edge.gate.quarantine",
            Self::GateCapability => "edge.gate.capability",
            Self::GateOwnerOfPeer => "edge.gate.owner_of_peer",
            Self::FetchGate => "edge.fetch.gate",
            Self::PullServeable => "edge.pull.serveable",
            Self::SubjectPull => "edge.subject_pull",
            Self::KeyPlane => "edge.key_plane",
            Self::Feed => "edge.feed",
            Self::IdentityPlane => "edge.identity_plane",
            Self::Holdings => "edge.holdings",
            Self::SendSet => "edge.send_set",
            Self::OwnerBinding => "edge.owner_binding",
            Self::Apply => "edge.apply",
            Self::TransportAttribution => "edge.transport.attribution",
            Self::FirstContact => "edge.first_contact",
            Self::Membership => "edge.membership",
            Self::Chat => "edge.chat",
            Self::AvCall => "edge.av_call",
            Self::BlobDurability => "edge.blob.durability",
            Self::BundleSeats => "edge.bundle.seats",
            Self::RoundCarriable => "edge.transport.carriable",
        }
    }

    const fn slot(self) -> usize {
        self as usize
    }
}

/// The interned callers, made once (making one takes persist's short intern
/// lock; reading under one takes none).
fn callers() -> &'static [Option<Caller>; Site::ALL.len()] {
    static CALLERS: OnceLock<[Option<Caller>; Site::ALL.len()]> = OnceLock::new();
    CALLERS.get_or_init(|| Site::ALL.map(|site| Caller::new(site.label()).ok()))
}

/// Run `fut` with every store read it makes on its task credited to `site`.
///
/// Not an `async fn`: an `async fn` keeps its argument `fut` in its state
/// beside the `caller_scope` future `fut` is moved into, so every scope
/// doubled the size of the future it wrapped, and nested scopes compounded
/// it (clippy's `large_futures` on the integrated v45 tree). Returning one
/// of the two futures directly stores `fut` once.
pub(crate) fn scoped<F: Future>(site: Site, fut: F) -> impl Future<Output = F::Output> {
    use futures::future::Either;
    match callers()[site.slot()] {
        Some(caller) => Either::Left(caller_scope(caller, fut)),
        None => Either::Right(fut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_label_is_one_persist_accepts_and_they_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        for (i, site) in Site::ALL.iter().enumerate() {
            assert_eq!(site.slot(), i, "ALL is in declaration order");
            let label = site.label();
            assert!(label.starts_with("edge."), "{label}");
            assert!(label.len() <= 48, "{label}");
            assert!(
                ciris_persist::observe::validate_caller_label(label).is_ok(),
                "{label}"
            );
            assert!(seen.insert(label), "{label} twice");
        }
        assert!(Site::ALL.len() <= ciris_persist::observe::MAX_CALLER_LABELS);
    }

    #[tokio::test]
    async fn a_scope_is_in_force_inside_and_gone_outside() {
        let inside = scoped(Site::Holdings, async {
            ciris_persist::observe::current_caller()
        })
        .await;
        assert_eq!(
            inside.map(Caller::label).as_deref(),
            Some(Site::Holdings.label())
        );
        assert!(ciris_persist::observe::current_caller().is_none());
    }
}
