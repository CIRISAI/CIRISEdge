//! CIRISEdge#805 item 8 — a direct path between two call members behind NAT
//! (leviculum v0.30 direct links, leviculum#70).
//!
//! # What a direct link is, and what it is not
//!
//! leviculum's direct link MIGRATES an existing link: two nodes whose link runs
//! through a transport node learn their reflexive addresses from a facilitator,
//! swap them as channel signals on that link, and punch. On success the link
//! moves onto a new point-to-point UDP interface; on failure nothing changes;
//! when the punched interface later dies, the link returns to the interface it
//! left.
//!
//! An A/V leg is never that link. A/V legs dial a member's DERIVED address,
//! which is announce-suppressed (CC 5.4) and so never pathed: the dial is a
//! broadcast only a directly attached neighbour answers. An A/V link is always
//! one hop and never crosses a transport node, so nothing on it can be
//! proposed. That is why two NAT'd phones cannot call each other directly today
//! (#805 item 8).
//!
//! The link that DOES cross the transport node is the members' IDENTITY-plane
//! link (federation address, pathed). Upgrading it leaves a punched interface
//! between the two nodes, which makes them one-hop neighbours; the A/V dial's
//! broadcast then goes out on that interface too, and the A/V leg is a direct
//! link from birth. The derived address is still never announced or pathed.
//!
//! # Why a configured facilitator means "propose", with no second switch
//!
//! CC 5.4.6 (CIRISConstitution#132): "Where the endpoints can bring the link
//! direct ... the link MUST be brought direct and the forwarder drops out."
//! A node with no facilitator CANNOT bring a NAT'd link direct, so the default
//! ([`DirectLinksConfig::default`]: no facilitator) is conformant. Once an
//! operator configures one, preferring the direct path is the CC's rule, not a
//! preference; there is no "prefer direct" boolean to set wrong.
//!
//! Accepting is separate and off by default ([`DirectAccept::Reject`]): see
//! [`DirectAccept::IdentifiedOnly`] for what turning it on discloses.
//!
//! # Scope of a proposal
//!
//! Proposing reveals this node's public address to the peer, so edge proposes
//! ONLY when it dials an A/V leg to a member of the call's group
//! ([`crate::transport::reticulum::ReticulumTransport::open_av_link`]) and only
//! on the identity link to that member. Nothing else proposes.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use leviculum_core::direct_link::{Failure, ProbeProtocol};
use leviculum_core::node::DirectLinkPolicy;
use leviculum_core::LinkId;

/// The most [`crate::transport::reticulum::ReticulumTransport::open_av_link`]
/// spends on a direct path before dialling the leg the way it would without
/// one: getting the identity link, the proposal, and its outcome, together.
/// Covers a facilitator probe plus leviculum's punch window.
pub const DIRECT_PATH_BUDGET: Duration = Duration::from_secs(20);

/// A proposal with no outcome after this long is treated as gone (its dial
/// was cancelled before the proposal was dispatched, or its event was lost),
/// so a peer can never be wedged `InFlight`.
pub const DIRECT_PROPOSING_STALE: Duration = Duration::from_secs(40);

/// The first retry after a proposal that timed out, failed its probe, or lost
/// its direct path: leviculum's own per-link proposal cooldown
/// (`PROPOSAL_COOLDOWN_MS`), so a retry is never refused as `CoolingDown`.
pub const DIRECT_RETRY_BASE: Duration =
    Duration::from_millis(leviculum_core::node::PROPOSAL_COOLDOWN_MS);

/// The longest a retryable failure backs off (the base doubles per attempt).
pub const DIRECT_RETRY_CAP: Duration = Duration::from_secs(30 * 60);

/// A punch that failed means a NAT that maps per destination (symmetric NAT,
/// common on cellular). It does not change between calls, so the peer is not
/// asked again for an hour; a network change shows up as a new link anyway.
pub const DIRECT_PUNCH_FAILED_BACKOFF: Duration = Duration::from_secs(60 * 60);

/// [`direct_leg_stalled`]: this many consecutive `Congested` refusals on a
/// direct A/V leg mean its path is gone, not busy.
pub const DIRECT_LEG_CONGESTED_STREAK: u32 = 8;

/// [`direct_leg_stalled`]: this long without Channel progress on a direct A/V
/// leg means its path is gone. leviculum declares the punched interface dead
/// only after 120 s of silence, and a link Stale after two keepalives (60 s on
/// edge's pin): a call cannot wait for either.
pub const DIRECT_LEG_NO_PROGRESS: Duration = Duration::from_secs(2);

/// Who this node accepts a direct-link upgrade from. Off by default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectAccept {
    /// Refuse every peer's upgrade request (leviculum's REJECT, reason POLICY).
    #[default]
    Reject,
    /// Accept from any peer whose identity is known on the link.
    ///
    /// **Disclosure:** accepting sends this node's reflexive (public) address
    /// to the requesting peer, and leviculum's policy is node-wide: ANY
    /// identified link peer that asks learns it, not only a peer this node is
    /// in a call with. An operator turns this on knowingly; configuring a
    /// facilitator never implies it.
    ///
    /// TODO(leviculum#82): a host-decided accept, so edge accepts only from a
    /// peer that shares a room with this node.
    IdentifiedOnly,
}

/// CIRISEdge#805 item 8 — direct links for this node. The default is inert:
/// no facilitator (this node cannot propose), none served, every request
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectLinksConfig {
    /// The facilitator this node probes when it proposes, as `host:port`.
    /// `None`: this node cannot bring a NAT'd link direct, and never proposes.
    /// `Some`: every A/V dial to a call member that is not already a one-hop
    /// neighbour proposes on the identity link to it (CC 5.4.6).
    pub facilitator: Option<String>,
    /// Run a facilitator on this UDP port (a reachable node: a canonical or
    /// any transport node with a public address).
    pub serve_facilitator: Option<u16>,
    /// Who this node accepts an upgrade from ([`DirectAccept`]).
    pub accept: DirectAccept,
}

impl DirectLinksConfig {
    /// Whether this node proposes at all.
    #[must_use]
    pub fn proposes(&self) -> bool {
        self.facilitator.is_some()
    }

    /// The settings handed to `ReticulumNodeBuilder::direct_link`, always,
    /// so the node never runs on a leviculum default edge did not choose.
    #[must_use]
    pub fn leviculum_settings(&self) -> leviculum_std::direct_link::DirectLinkSettings {
        leviculum_std::direct_link::DirectLinkSettings {
            policy: match self.accept {
                DirectAccept::Reject => DirectLinkPolicy::Reject,
                DirectAccept::IdentifiedOnly => DirectLinkPolicy::IdentifiedOnly,
            },
            facilitator: self.facilitator.clone(),
            protocol: ProbeProtocol::Rnsp,
            facilitator_port: self.serve_facilitator,
        }
    }
}

/// When a peer may be proposed to again, after a proposal ended without a
/// direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRetry {
    /// Not on this link: the peer refused it by policy. A new link (a network
    /// change, a restart) may ask again.
    NotOnThisLink,
    /// After this long.
    After(Duration),
}

/// The retry policy for a failed proposal, `attempts` failures in a row so far
/// (0 for the first).
#[must_use]
pub fn retry_after(failure: Failure, attempts: u32) -> DirectRetry {
    match failure {
        Failure::Rejected(_) => DirectRetry::NotOnThisLink,
        Failure::PunchFailed => DirectRetry::After(DIRECT_PUNCH_FAILED_BACKOFF),
        Failure::Timeout | Failure::ProbeFailed => {
            let factor = 1u32.checked_shl(attempts.min(16)).unwrap_or(u32::MAX);
            DirectRetry::After(
                DIRECT_RETRY_BASE
                    .saturating_mul(factor)
                    .min(DIRECT_RETRY_CAP),
            )
        }
    }
}

/// The `direct_link` metric label of a failure.
#[must_use]
pub const fn failure_label(failure: Failure) -> &'static str {
    match failure {
        Failure::Rejected(_) => crate::observability::DIRECT_LINK_FAILED_REJECTED,
        Failure::ProbeFailed => crate::observability::DIRECT_LINK_FAILED_PROBE,
        Failure::Timeout => crate::observability::DIRECT_LINK_FAILED_TIMEOUT,
        Failure::PunchFailed => crate::observability::DIRECT_LINK_FAILED_PUNCH,
    }
}

/// CIRISEdge#805 item 8 — THE liveness decision for a direct A/V leg: is its
/// path gone? `congested_streak` is the leg's consecutive `Congested`
/// refusals; `since_progress` is how long its Channel has made no progress.
///
/// One function, so the action it triggers
/// ([`crate::transport::reticulum::ReticulumTransport::fall_back_from_direct`])
/// is the one place leviculum#83 changes.
#[must_use]
pub fn direct_leg_stalled(congested_streak: u32, since_progress: Duration) -> bool {
    congested_streak >= DIRECT_LEG_CONGESTED_STREAK || since_progress >= DIRECT_LEG_NO_PROGRESS
}

/// Where a peer's direct path stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectPathState {
    /// A proposal is running on `link`.
    Proposing { link: LinkId },
    /// `link` runs over the punched `interface`.
    Direct { link: LinkId, interface: usize },
    /// The last proposal ended without a direct path.
    BackingOff,
}

/// Why a peer was not proposed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposeSkip {
    /// A proposal to this peer is already running.
    InFlight,
    /// The peer already has a direct path.
    AlreadyDirect,
    /// The last proposal failed and its backoff has not run out.
    BackingOff,
    /// The peer refused a proposal on this very link.
    RejectedOnThisLink,
}

impl ProposeSkip {
    /// Stable token for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::AlreadyDirect => "already_direct",
            Self::BackingOff => "backing_off",
            Self::RejectedOnThisLink => "rejected_on_this_link",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Entry {
    Proposing {
        link: LinkId,
        channel_limit_before: Option<usize>,
        since: Instant,
    },
    Direct {
        link: LinkId,
        interface: usize,
    },
    BackingOff {
        until: Option<Instant>,
        rejected_link: Option<LinkId>,
    },
}

#[derive(Debug, Clone, Copy)]
struct PeerDirect {
    entry: Entry,
    /// Retryable failures in a row; reset by a direct path.
    attempts: u32,
}

/// CIRISEdge#805 item 8 — the per-peer direct-path state machine and its retry
/// policy. Pure: every transition takes `now`, and nothing here touches the
/// node or a clock.
#[derive(Debug, Default)]
pub struct DirectPathTracker {
    peers: HashMap<String, PeerDirect>,
    /// The peer each tracked link belongs to (events name links).
    link_peer: HashMap<LinkId, String>,
}

impl DirectPathTracker {
    /// Whether `peer` may be proposed to on `link` now.
    ///
    /// # Errors
    /// The [`ProposeSkip`] that applies.
    pub fn admit(&self, peer: &str, link: LinkId, now: Instant) -> Result<(), ProposeSkip> {
        let Some(p) = self.peers.get(peer) else {
            return Ok(());
        };
        match p.entry {
            Entry::Proposing { since, .. }
                if now.saturating_duration_since(since) < DIRECT_PROPOSING_STALE =>
            {
                Err(ProposeSkip::InFlight)
            }
            Entry::Direct { .. } => Err(ProposeSkip::AlreadyDirect),
            Entry::BackingOff {
                rejected_link: Some(rejected),
                ..
            } if rejected == link => Err(ProposeSkip::RejectedOnThisLink),
            Entry::BackingOff {
                until: Some(until), ..
            } if until > now => Err(ProposeSkip::BackingOff),
            // A proposal gone stale, or a backoff that ran out.
            Entry::Proposing { .. } | Entry::BackingOff { .. } => Ok(()),
        }
    }

    /// A proposal to `peer` started on `link` at `now`, whose Channel carried
    /// `channel_limit_before` bytes per message.
    pub fn proposed(
        &mut self,
        peer: &str,
        link: LinkId,
        channel_limit_before: Option<usize>,
        now: Instant,
    ) {
        let attempts = self.peers.get(peer).map_or(0, |p| p.attempts);
        self.link_peer.insert(link, peer.to_owned());
        self.peers.insert(
            peer.to_owned(),
            PeerDirect {
                entry: Entry::Proposing {
                    link,
                    channel_limit_before,
                    since: now,
                },
                attempts,
            },
        );
    }

    /// leviculum refused to start the proposal (`CoolingDown`,
    /// `AlreadyUpgrading`, `ChannelBusy`, …): back off one base period.
    pub fn propose_refused(&mut self, peer: &str, link: LinkId, now: Instant) {
        self.link_peer.remove(&link);
        let attempts = self.peers.get(peer).map_or(0, |p| p.attempts);
        self.peers.insert(
            peer.to_owned(),
            PeerDirect {
                entry: Entry::BackingOff {
                    until: Some(now + DIRECT_RETRY_BASE),
                    rejected_link: None,
                },
                attempts,
            },
        );
    }

    /// `link` runs over the punched `interface`. `peer` is the attribution
    /// for a link this node did not propose on (the accepting side). Returns
    /// the peer and the Channel limit recorded when the proposal started.
    pub fn established(
        &mut self,
        link: LinkId,
        interface: usize,
        peer: Option<&str>,
    ) -> Option<(String, Option<usize>)> {
        let peer = self
            .link_peer
            .get(&link)
            .cloned()
            .or_else(|| peer.map(str::to_owned))?;
        let before = match self.peers.get(&peer).map(|p| p.entry) {
            Some(Entry::Proposing {
                link: l,
                channel_limit_before,
                ..
            }) if l == link => channel_limit_before,
            _ => None,
        };
        self.link_peer.insert(link, peer.clone());
        self.peers.insert(
            peer.clone(),
            PeerDirect {
                entry: Entry::Direct { link, interface },
                attempts: 0,
            },
        );
        Some((peer, before))
    }

    /// A proposal on `link` ended without a direct path. Returns the peer.
    pub fn failed(&mut self, link: LinkId, failure: Failure, now: Instant) -> Option<String> {
        let peer = self.link_peer.remove(&link)?;
        let attempts = self.peers.get(&peer).map_or(0, |p| p.attempts);
        let entry = match retry_after(failure, attempts) {
            DirectRetry::NotOnThisLink => Entry::BackingOff {
                until: None,
                rejected_link: Some(link),
            },
            DirectRetry::After(wait) => Entry::BackingOff {
                until: Some(now + wait),
                rejected_link: None,
            },
        };
        self.peers.insert(
            peer.clone(),
            PeerDirect {
                entry,
                attempts: attempts.saturating_add(1),
            },
        );
        Some(peer)
    }

    /// `link`'s punched interface went down; the link is back on its relayed
    /// path (or closed). The peer may be asked again after the base period.
    pub fn lost(&mut self, link: LinkId, now: Instant) -> Option<String> {
        let peer = self.link_peer.remove(&link)?;
        self.peers.insert(
            peer.clone(),
            PeerDirect {
                entry: Entry::BackingOff {
                    until: Some(now + DIRECT_RETRY_BASE),
                    rejected_link: None,
                },
                attempts: 0,
            },
        );
        Some(peer)
    }

    /// Where `peer`'s direct path stands, if it was ever proposed to.
    #[must_use]
    pub fn state(&self, peer: &str) -> Option<DirectPathState> {
        self.peers.get(peer).map(|p| match p.entry {
            Entry::Proposing { link, .. } => DirectPathState::Proposing { link },
            Entry::Direct { link, interface } => DirectPathState::Direct { link, interface },
            Entry::BackingOff { .. } => DirectPathState::BackingOff,
        })
    }

    /// Peers with a direct path now (the `direct_links_active` gauge).
    #[must_use]
    pub fn direct_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| matches!(p.entry, Entry::Direct { .. }))
            .count()
    }
}

/// What happened to a direct path, for a host (and, with CIRISEdge#805 item 5,
/// the `Call`) to react to. Broadcast by
/// [`crate::transport::reticulum::ReticulumTransport::subscribe_direct_path_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectPathEvent {
    /// A link moved onto a punched interface. leviculum lowers a link's MTU to
    /// 1400 on the move and never raises it, so `channel_limit_after` can be
    /// below `channel_limit_before` (CIRISEdge#720: a call's chunk budget is
    /// the minimum over its legs; item 5's `CallEvent::BudgetChanged` is
    /// computed from these limits).
    Established {
        peer: Option<String>,
        link_id: [u8; 16],
        interface: usize,
        proposed: bool,
        channel_limit_before: Option<usize>,
        channel_limit_after: Option<usize>,
    },
    /// A proposal ended without a direct path; the link is untouched.
    Failed {
        peer: Option<String>,
        link_id: [u8; 16],
        reason: &'static str,
        proposed: bool,
    },
    /// A punched interface went down; the link is back on its relayed path.
    Lost {
        peer: Option<String>,
        link_id: [u8; 16],
        interface: usize,
    },
}

/// What a proposal came to, for the dial waiting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectOutcome {
    Established { interface: usize },
    Failed(Failure),
    Lost,
}

/// CIRISEdge#805 item 8 — a hold on a direct path. The punched interface
/// lives exactly as long as the identity link it was punched for (leviculum
/// tears the interface down when that link closes), so while any guard is
/// held that link is exempt from the idle-pool reaper. Dropping the last
/// guard returns the link to the pool's ordinary idle rules.
#[derive(Debug)]
pub struct DirectPathGuard {
    anchors: std::sync::Arc<std::sync::Mutex<HashMap<LinkId, usize>>>,
    link: LinkId,
}

impl DirectPathGuard {
    /// The identity link the direct path was punched for.
    #[must_use]
    pub fn link_id(&self) -> [u8; 16] {
        self.link.into_bytes()
    }
}

impl Drop for DirectPathGuard {
    fn drop(&mut self) {
        let mut anchors = self
            .anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = anchors.get_mut(&self.link) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                anchors.remove(&self.link);
            }
        }
    }
}

/// What [`crate::transport::reticulum::ReticulumTransport::ensure_direct_path`]
/// came to.
#[derive(Debug)]
pub enum DirectPath {
    /// No facilitator configured: this node cannot bring a NAT'd link direct
    /// (the conformant default under CC 5.4.6).
    NotConfigured,
    /// The member is already a one-hop neighbour: there is nothing to punch.
    AlreadyNeighbour,
    /// A direct path to the member exists over the punched `interface`; it
    /// lasts while `guard` (or any other guard on it) is held.
    Direct {
        interface: usize,
        guard: DirectPathGuard,
    },
    /// No direct path now: the dial proceeds as it would without one. `reason`
    /// is a stable token (`no_link`, `backing_off`, `propose_refused`,
    /// `pending`, or a `direct_link_failed_*` label).
    Unavailable { reason: &'static str },
}

/// CIRISEdge#805 item 8 — the transport's direct-path state: the knob, the
/// tracker, the dials waiting on a proposal, the event broadcast, and the
/// anchored identity links.
#[derive(Debug)]
pub(crate) struct DirectPaths {
    pub(crate) config: DirectLinksConfig,
    tracker: std::sync::Mutex<DirectPathTracker>,
    waiters: std::sync::Mutex<HashMap<LinkId, Vec<tokio::sync::oneshot::Sender<DirectOutcome>>>>,
    events: tokio::sync::broadcast::Sender<DirectPathEvent>,
    anchors: std::sync::Arc<std::sync::Mutex<HashMap<LinkId, usize>>>,
}

impl DirectPaths {
    pub(crate) fn new(config: DirectLinksConfig) -> Self {
        Self {
            config,
            tracker: std::sync::Mutex::new(DirectPathTracker::default()),
            waiters: std::sync::Mutex::new(HashMap::new()),
            events: tokio::sync::broadcast::channel(64).0,
            anchors: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// The tracker, locked. Never held across an `.await`.
    pub(crate) fn tracker(&self) -> std::sync::MutexGuard<'_, DirectPathTracker> {
        self.tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register for `link`'s next outcome. Registered BEFORE the proposal is
    /// dispatched, so its outcome cannot precede the registration.
    pub(crate) fn wait_for(&self, link: LinkId) -> tokio::sync::oneshot::Receiver<DirectOutcome> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(link)
            .or_default()
            .push(tx);
        rx
    }

    /// Hand `outcome` to every dial waiting on `link`.
    pub(crate) fn resolve(&self, link: LinkId, outcome: DirectOutcome) {
        let waiting = self
            .waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&link)
            .unwrap_or_default();
        for tx in waiting {
            let _ = tx.send(outcome);
        }
    }

    /// Drop `link`'s waiters without an outcome (a proposal that never
    /// started).
    pub(crate) fn forget(&self, link: LinkId) {
        self.waiters
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&link);
    }

    pub(crate) fn emit(&self, event: DirectPathEvent) {
        let _ = self.events.send(event);
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DirectPathEvent> {
        self.events.subscribe()
    }

    /// A new hold on `link`'s direct path.
    pub(crate) fn anchor(&self, link: LinkId) -> DirectPathGuard {
        *self
            .anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(link)
            .or_insert(0) += 1;
        DirectPathGuard {
            anchors: std::sync::Arc::clone(&self.anchors),
            link,
        }
    }

    /// Whether `link` carries a held direct path (exempt from the idle reaper).
    pub(crate) fn is_anchored(&self, link: &LinkId) -> bool {
        self.anchors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(b: u8) -> LinkId {
        LinkId::new([b; 16])
    }

    #[test]
    fn the_default_config_is_inert() {
        let c = DirectLinksConfig::default();
        assert!(!c.proposes());
        let s = c.leviculum_settings();
        assert_eq!(s.policy, DirectLinkPolicy::Reject);
        assert!(s.facilitator.is_none());
        assert!(s.facilitator_port.is_none());
    }

    #[test]
    fn a_facilitator_does_not_imply_accepting() {
        let c = DirectLinksConfig {
            facilitator: Some("127.0.0.1:4243".to_owned()),
            ..DirectLinksConfig::default()
        };
        assert!(c.proposes());
        assert_eq!(c.leviculum_settings().policy, DirectLinkPolicy::Reject);
        let c = DirectLinksConfig {
            accept: DirectAccept::IdentifiedOnly,
            ..c
        };
        assert_eq!(
            c.leviculum_settings().policy,
            DirectLinkPolicy::IdentifiedOnly
        );
    }

    #[test]
    fn the_retry_policy_by_failure() {
        assert_eq!(
            retry_after(Failure::Rejected(1), 0),
            DirectRetry::NotOnThisLink
        );
        assert_eq!(
            retry_after(Failure::PunchFailed, 0),
            DirectRetry::After(DIRECT_PUNCH_FAILED_BACKOFF)
        );
        assert_eq!(
            retry_after(Failure::Timeout, 0),
            DirectRetry::After(DIRECT_RETRY_BASE)
        );
        assert_eq!(
            retry_after(Failure::ProbeFailed, 2),
            DirectRetry::After(DIRECT_RETRY_BASE * 4)
        );
        assert_eq!(
            retry_after(Failure::Timeout, 40),
            DirectRetry::After(DIRECT_RETRY_CAP)
        );
    }

    #[test]
    fn a_proposal_runs_once_per_peer_and_backs_off_after_a_timeout() {
        let now = Instant::now();
        let mut t = DirectPathTracker::default();
        assert_eq!(t.admit("b", link(1), now), Ok(()));
        t.proposed("b", link(1), Some(16_000), now);
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::InFlight));
        assert_eq!(
            t.failed(link(1), Failure::Timeout, now).as_deref(),
            Some("b")
        );
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::BackingOff));
        assert_eq!(t.admit("b", link(1), now + DIRECT_RETRY_BASE), Ok(()));
        // A second timeout doubles the wait.
        t.proposed("b", link(1), None, now);
        t.failed(link(1), Failure::Timeout, now);
        assert_eq!(
            t.admit("b", link(1), now + DIRECT_RETRY_BASE),
            Err(ProposeSkip::BackingOff)
        );
        assert_eq!(t.admit("b", link(1), now + DIRECT_RETRY_BASE * 2), Ok(()));
    }

    #[test]
    fn a_proposal_with_no_outcome_goes_stale() {
        let now = Instant::now();
        let mut t = DirectPathTracker::default();
        t.proposed("b", link(1), None, now);
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::InFlight));
        assert_eq!(
            t.admit("b", link(1), now + DIRECT_PROPOSING_STALE),
            Ok(()),
            "a cancelled or unanswered proposal cannot wedge the peer"
        );
    }

    #[test]
    fn a_rejection_blocks_that_link_only() {
        let now = Instant::now();
        let mut t = DirectPathTracker::default();
        t.proposed("b", link(1), None, now);
        t.failed(link(1), Failure::Rejected(1), now);
        let much_later = now + Duration::from_secs(24 * 3600);
        assert_eq!(
            t.admit("b", link(1), much_later),
            Err(ProposeSkip::RejectedOnThisLink)
        );
        assert_eq!(t.admit("b", link(2), now), Ok(()));
    }

    #[test]
    fn established_records_the_limit_before_and_lost_backs_off_once() {
        let now = Instant::now();
        let mut t = DirectPathTracker::default();
        t.proposed("b", link(1), Some(16_000), now);
        assert_eq!(
            t.established(link(1), 7, None),
            Some(("b".to_owned(), Some(16_000)))
        );
        assert_eq!(t.direct_count(), 1);
        assert_eq!(
            t.state("b"),
            Some(DirectPathState::Direct {
                link: link(1),
                interface: 7
            })
        );
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::AlreadyDirect));
        assert_eq!(t.lost(link(1), now).as_deref(), Some("b"));
        assert_eq!(t.direct_count(), 0);
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::BackingOff));
        assert_eq!(t.admit("b", link(1), now + DIRECT_RETRY_BASE), Ok(()));
    }

    #[test]
    fn the_accepting_side_tracks_a_link_it_did_not_propose_on() {
        let mut t = DirectPathTracker::default();
        assert_eq!(
            t.established(link(3), 9, None),
            None,
            "no attribution, no entry"
        );
        assert_eq!(
            t.established(link(3), 9, Some("a")),
            Some(("a".to_owned(), None))
        );
        assert_eq!(t.direct_count(), 1);
    }

    #[test]
    fn an_unknown_link_event_changes_nothing() {
        let now = Instant::now();
        let mut t = DirectPathTracker::default();
        assert_eq!(t.failed(link(9), Failure::Timeout, now), None);
        assert_eq!(t.lost(link(9), now), None);
        assert_eq!(t.direct_count(), 0);
    }

    #[test]
    fn a_direct_path_is_anchored_while_any_guard_is_held() {
        let paths = DirectPaths::new(DirectLinksConfig::default());
        let g1 = paths.anchor(link(4));
        let g2 = paths.anchor(link(4));
        assert!(paths.is_anchored(&link(4)));
        drop(g1);
        assert!(paths.is_anchored(&link(4)), "one guard still holds it");
        drop(g2);
        assert!(!paths.is_anchored(&link(4)));
    }

    #[tokio::test]
    async fn every_waiter_gets_the_outcome_and_a_forgotten_one_gets_none() {
        let paths = DirectPaths::new(DirectLinksConfig::default());
        let a = paths.wait_for(link(5));
        let b = paths.wait_for(link(5));
        paths.resolve(link(5), DirectOutcome::Established { interface: 3 });
        assert_eq!(a.await, Ok(DirectOutcome::Established { interface: 3 }));
        assert_eq!(b.await, Ok(DirectOutcome::Established { interface: 3 }));
        let c = paths.wait_for(link(6));
        paths.forget(link(6));
        assert!(c.await.is_err());
    }

    #[test]
    fn a_leg_is_stalled_by_streak_or_by_silence() {
        assert!(!direct_leg_stalled(0, Duration::ZERO));
        assert!(!direct_leg_stalled(
            DIRECT_LEG_CONGESTED_STREAK - 1,
            Duration::from_millis(1999)
        ));
        assert!(direct_leg_stalled(
            DIRECT_LEG_CONGESTED_STREAK,
            Duration::ZERO
        ));
        assert!(direct_leg_stalled(0, DIRECT_LEG_NO_PROGRESS));
    }
}
