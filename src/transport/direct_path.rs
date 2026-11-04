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
//! # Proposing is ON by default (v44), with the bundle's canonical as facilitator
//!
//! CC 5.4.6 (CIRISConstitution#132): "Where the endpoints can bring the link
//! direct ... the link MUST be brought direct and the forwarder drops out."
//! Bringing a NAT'd link direct needs a facilitator (a reflector that tells
//! this node its public address). [`DirectLinksConfig::default`] has
//! [`Proposing::On`] and no facilitator named: the host's init resolves one
//! from the baked genesis bundle's serve nodes (the canonical this node
//! bootstraps from, `CIRIS_DIRECT_LINK_FACILITATOR=bootstrap`'s meaning;
//! [`DirectLinksConfig::resolve_bundle_facilitator`]), under the same
//! CIRISEdge#661 gate as the baked dials, so a test node never probes the
//! production canonical. [`Proposing::Off`] is the operator's switch; a
//! config with proposing on and no facilitator resolved proposes nothing and
//! says so. Preferring the direct path once it can be had is the CC's rule,
//! not a preference: there is no "prefer direct" boolean to set wrong.
//!
//! **History.** Proposing was held OFF from 2026-10-31: a punch that
//! succeeded on one side only (Eric's desktop ↔ Francesco's node, both on
//! edge v43.3.0) left links dead one way until leviculum closed them. Eric's
//! conditions to turn it back on were leviculum#89 (the two-sided commit:
//! the link moves only after both sides succeed; v0.33 tightened the rule
//! to an address proven both ways) and CIRISEdge#926 (the Channel stall
//! guard: a link whose sends land nothing is closed and re-dialled, and a
//! punched one moved back to its relayed path). Both ship in v44, and
//! proposing is ON from v44 (Eric, 2026-11-04).
//!
//! Accepting is separate: by default only from a peer this node shares a room
//! with ([`DirectAccept::RoomPeers`]); [`DirectAccept::Off`] is the operator
//! override.
//!
//! # Glare (v44, leviculum#96)
//!
//! Two peers that both want a link direct propose on it within a round trip
//! of each other, and leviculum refuses a REQUEST that crosses its own
//! proposal on that link `REJECT_BUSY` before the host sees it, so both fail
//! and, with the same backoff, both retry together. Edge breaks the tie with
//! the link's direction, which both ends hold: only the link's INITIATOR
//! proposes on it; the responder yields ([`glare_verdict`]) and proposes
//! itself only after [`GLARE_WAIT`] without the initiator's proposal, on a
//! timer, so a peer that replied once still brings the link direct. Every
//! retry is jittered ±25 % ([`RETRY_JITTER`]) so a pair never stays in
//! lockstep. The in-leviculum half (a glare reason, the responder's session
//! dropped) is asked in leviculum#96.
//!
//! Only a send can yield: its proposal may ride the peer's link to this node
//! (CIRISEdge#920), and it waits on nothing. A call's dial proposes on a link
//! this node dialled (the identity lane's pool), so it is that link's initiator
//! and never yields; two members dialling each other propose on two links.
//!
//! The jitter reaches what edge schedules: a `Rejected` proposal, which
//! leviculum drops from its own retries. leviculum's background re-proposal
//! after a timeout or a failed punch runs on its fixed `RETRY_BACKOFF_MS`,
//! unjittered and past the tie-break; only a node that proposed retries, so it
//! takes a responder's [`GLARE_WAIT`] fallback for both ends to be on it.
//!
//! # Scope of a proposal
//!
//! Proposing reveals this node's public address to the peer, so edge proposes
//! only to a peer it shares a room with or that the host named a consented
//! contact (Eric 2026-10-30: "anyone who has consented to a contact request",
//! so a new contact's consent exchange collapses to direct at once), and only
//! on the identity link to it:
//!
//! - when it dials an A/V leg to a member of the call's group
//!   ([`crate::transport::reticulum::ReticulumTransport::open_av_link`]),
//!   waiting up to [`DIRECT_PATH_BUDGET`] for the outcome;
//! - after a send to a room peer or consented contact ships over a link that
//!   crosses a transport node (CIRISEdge#915), without waiting: later traffic
//!   rides the direct link once it is up.
//!
//! Nothing else proposes.

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

/// v44 — every retry is jittered by up to this fraction either way, so two
/// peers that failed together never retry in lockstep (the CI baseline's
/// glare: both proposing within 200 ms on every retry, 2 min then 4 min,
/// identical on both sides, each refusing the other `Rejected(2)`).
pub const RETRY_JITTER: f64 = 0.25;

/// v44 — how long a link's RESPONDER waits for the initiator's proposal
/// before proposing on that link itself (leviculum#96). leviculum refuses a
/// proposal that crosses its own on a link `REJECT_BUSY` before the host sees
/// it, so the tie is broken here: only the link's initiator proposes on it.
/// A responder facing a peer that never proposes (proposing off, an older
/// edge, or one that only sent before this node joined the room: #920) proposes
/// after this wait, jittered, on a timer: the send that yielded may be its last.
pub const GLARE_WAIT: Duration = Duration::from_secs(30);

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

/// Who this node accepts a direct-link upgrade from.
///
/// Accepting sends this node's reflexive (public) address to the requesting
/// peer. A direct path is the MORE private one for the call itself (no relay
/// member sees its traffic, timing or volume), so the default accepts, but
/// only from a peer this node shares a room with: the only party that learns
/// the address is someone this node is already in a call or a room with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectAccept {
    /// Accept only from a peer that shares a room with this node, or that the
    /// host named a consented contact
    /// ([`crate::transport::reticulum::ReticulumTransport::should_accept_direct`]).
    /// leviculum asks edge per request (`AskHost`, leviculum#82): it holds
    /// the request, probes nothing and reveals nothing until edge answers.
    #[default]
    RoomPeers,
    /// The operator override: refuse every peer's upgrade request
    /// (leviculum's REJECT, reason POLICY).
    Off,
    /// Accept from ANY peer whose identity is known on the link: leviculum's
    /// node-wide `IdentifiedOnly`. **Discloses this node's public address to
    /// every identified link peer that asks**, not only room peers. For tests
    /// and an explicit operator choice, never a default.
    IdentifiedOnly,
}

/// Whether this node proposes direct links at all (v44: on by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Proposing {
    /// Propose, with the configured facilitator or the bundle's canonical.
    #[default]
    On,
    /// The operator's switch: never propose, resolve no facilitator, and
    /// turn leviculum's background re-proposal off too.
    Off,
}

impl Proposing {
    /// Parse an operator's setting: `on` or `off`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "on" => Some(Self::On),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

/// CIRISEdge#805 item 8 — direct links for this node. The default proposes
/// ([`Proposing::On`]) with the facilitator the host's init resolves from
/// the genesis bundle ([`Self::resolve_bundle_facilitator`]), serves no
/// facilitator, and accepts from room peers only ([`DirectAccept::RoomPeers`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirectLinksConfig {
    /// Whether this node proposes at all (v44 default: on).
    pub proposing: Proposing,
    /// The facilitator this node probes when it proposes, as `host:port`.
    /// `None` with proposing on: unresolved; the host's init fills it from
    /// the bundle, and a config that reaches the transport unresolved
    /// proposes nothing. `Some`: every A/V dial to a call member that is not
    /// already a one-hop neighbour proposes on the identity link to it
    /// (CC 5.4.6), as does a send to a room peer over a transport node.
    pub facilitator: Option<String>,
    /// Run a facilitator on this UDP port (a reachable node: a canonical or
    /// any transport node with a public address).
    pub serve_facilitator: Option<u16>,
    /// Who this node accepts an upgrade from ([`DirectAccept`]; default room
    /// peers only).
    pub accept: DirectAccept,
}

impl DirectAccept {
    /// Parse an operator's setting: `room_peers`, `identified_only` or `off`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "room_peers" => Some(Self::RoomPeers),
            "identified_only" => Some(Self::IdentifiedOnly),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

impl DirectLinksConfig {
    /// Whether this node proposes at all: proposing on AND a facilitator to
    /// probe.
    #[must_use]
    pub fn proposes(&self) -> bool {
        self.proposing == Proposing::On && self.facilitator.is_some()
    }

    /// The facilitator the genesis bundle implies: the `ip` transport hint of
    /// the first baked serve node that carries one (falling through the list
    /// past serve nodes with no dial hint), host AND port. A canonical answers
    /// as a facilitator on UDP at its dial's own port (measured: CI run
    /// 41869107100, `108.61.242.236:4242`), so there is no second port to
    /// drift. `None` when the bundle names none.
    #[must_use]
    pub fn bundle_facilitator() -> Option<String> {
        crate::edge::baked_canonical_ip_dials()
            .into_iter()
            .map(|(_, addr)| addr.to_string())
            .next()
    }

    /// Fill an unnamed facilitator from the bundle when proposing is on and
    /// `baked_dials_allowed` (the CIRISEdge#661 gate: a node under a test
    /// trust root never touches the production canonical). `Off` resolves
    /// nothing. Logged either way.
    #[must_use]
    pub fn resolve_bundle_facilitator(mut self, baked_dials_allowed: bool) -> Self {
        match self.proposing {
            Proposing::Off => {
                self.facilitator = None;
                tracing::info!("direct links: proposing OFF by the operator's setting");
            }
            Proposing::On if self.facilitator.is_some() => {}
            Proposing::On if !baked_dials_allowed => {
                tracing::warn!(
                    "direct links: proposing on but no facilitator resolved: the baked \
                     canonical is not dialled here (CIRISEdge#661), so nothing proposes"
                );
            }
            Proposing::On => {
                self.facilitator = Self::bundle_facilitator();
                if let Some(f) = &self.facilitator {
                    tracing::info!(
                        facilitator = %f,
                        "direct links: facilitator resolved from the genesis bundle's first \
                         serve node (v44: proposing on by default)"
                    );
                } else {
                    tracing::warn!(
                        "direct links: proposing on but the genesis bundle names no serve \
                         node with a dial hint: nothing proposes"
                    );
                }
            }
        }
        self
    }

    /// The settings handed to `ReticulumNodeBuilder::direct_link`, always,
    /// so the node never runs on a leviculum default edge did not choose.
    #[must_use]
    pub fn leviculum_settings(&self) -> leviculum_std::direct_link::DirectLinkSettings {
        leviculum_std::direct_link::DirectLinkSettings {
            policy: match self.accept {
                // Asked per request, answered by `should_accept_direct`.
                DirectAccept::RoomPeers => DirectLinkPolicy::AskHost,
                DirectAccept::Off => DirectLinkPolicy::Reject,
                DirectAccept::IdentifiedOnly => DirectLinkPolicy::IdentifiedOnly,
            },
            facilitator: self.proposes().then(|| self.facilitator.clone()).flatten(),
            protocol: ProbeProtocol::Rnsp,
            facilitator_port: self.serve_facilitator,
        }
    }
}

/// When a peer may be proposed to again, after a proposal ended without a
/// direct path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRetry {
    /// After this long.
    After(Duration),
}

/// The retry policy for a failed proposal, `attempts` failures in a row so far
/// (0 for the first), with `jitter` in `[-RETRY_JITTER, RETRY_JITTER]` (clamped)
/// applied to the wait.
#[must_use]
pub fn retry_after(failure: Failure, attempts: u32, jitter: f64) -> DirectRetry {
    let DirectRetry::After(base) = retry_base(failure, attempts);
    let j = if jitter.is_finite() {
        jitter.clamp(-RETRY_JITTER, RETRY_JITTER)
    } else {
        0.0
    };
    DirectRetry::After(base.mul_f64(1.0 + j))
}

/// A jitter draw in `[-RETRY_JITTER, RETRY_JITTER]` from the OS RNG (0 if it
/// cannot be read).
#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn jitter_draw() -> f64 {
    let mut b = [0u8; 2];
    if ciris_crypto::random::fill(&mut b).is_err() {
        return 0.0;
    }
    let unit = f64::from(u16::from_le_bytes(b)) / f64::from(u16::MAX);
    2.0f64.mul_add(RETRY_JITTER * unit, -RETRY_JITTER)
}

/// v44 — who proposes on a link when both ends want it direct
/// (leviculum#96).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlareVerdict {
    /// Propose now.
    Propose,
    /// Leave it to the link's initiator; propose only after [`GLARE_WAIT`].
    Yield,
}

/// The tie-break: the link's initiator proposes; the responder yields until
/// it has waited [`GLARE_WAIT`] since `waiting_since` for the initiator's
/// proposal. Pure, so it is a unit test.
#[must_use]
pub fn glare_verdict(
    initiator: bool,
    waiting_since: Option<Instant>,
    now: Instant,
) -> GlareVerdict {
    if initiator
        || waiting_since.is_some_and(|since| now.saturating_duration_since(since) >= GLARE_WAIT)
    {
        GlareVerdict::Propose
    } else {
        GlareVerdict::Yield
    }
}

/// The unjittered retry policy.
#[must_use]
fn retry_base(failure: Failure, attempts: u32) -> DirectRetry {
    match failure {
        Failure::PunchFailed => DirectRetry::After(DIRECT_PUNCH_FAILED_BACKOFF),
        // A refusal is retried like a timeout (CIRISEdge#920). Under the
        // default `RoomPeers` a peer refuses until it shares a room with this
        // node, and room setup is exactly when the first sends to it go out:
        // pinning the refusal to the link left a pair room relayed for good.
        // The backoff doubles, so a peer that refuses by policy (`Off`) is
        // asked rarely, not never.
        Failure::Rejected(_) | Failure::Timeout | Failure::ProbeFailed => {
            let factor = 1u32.checked_shl(attempts.min(16)).unwrap_or(u32::MAX);
            DirectRetry::After(
                DIRECT_RETRY_BASE
                    .saturating_mul(factor)
                    .min(DIRECT_RETRY_CAP),
            )
        }
    }
}

/// THE accept rule for a peer's direct-link request, given whether the peer
/// shares a room with this node. One function, so the transport's
/// `should_accept_direct` and the event loop's answer cannot drift.
#[must_use]
pub const fn accepts_direct(accept: DirectAccept, shares_room: bool) -> bool {
    match accept {
        DirectAccept::RoomPeers => shares_room,
        DirectAccept::Off => false,
        DirectAccept::IdentifiedOnly => true,
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
/// retires the member's identity link off the punched interface (leviculum#83)
/// and closes the leg.
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
}

impl ProposeSkip {
    /// Stable token for logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InFlight => "in_flight",
            Self::AlreadyDirect => "already_direct",
            Self::BackingOff => "backing_off",
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
        until: Instant,
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
    /// `_link` is the link a proposal would ride; whether to propose is a
    /// property of the peer, not of one link to it.
    pub fn admit(&self, peer: &str, _link: LinkId, now: Instant) -> Result<(), ProposeSkip> {
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
            Entry::BackingOff { until } if until > now => Err(ProposeSkip::BackingOff),
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
                    until: now + DIRECT_RETRY_BASE,
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
    /// `jitter` is the retry's draw ([`jitter_draw`]; 0 in tests).
    pub fn failed(
        &mut self,
        link: LinkId,
        failure: Failure,
        now: Instant,
        jitter: f64,
    ) -> Option<String> {
        let peer = self.link_peer.remove(&link)?;
        let attempts = self.peers.get(&peer).map_or(0, |p| p.attempts);
        let DirectRetry::After(wait) = retry_after(failure, attempts, jitter);
        let entry = Entry::BackingOff { until: now + wait };
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
                    until: now + DIRECT_RETRY_BASE,
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
    /// A peer asked this node to take a link direct, and this node answered.
    /// `peer` is `None` when the link is not attributed to a known peer
    /// (always refused).
    Requested {
        peer: Option<String>,
        link_id: [u8; 16],
        accepted: bool,
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
    /// Peers (node key ids) the host named as consented contacts
    /// ([`Self::allow_contact`]): direct with them like a room peer.
    contacts: std::sync::Mutex<std::collections::HashSet<String>>,
    /// v44 — peers this node is yielding to on a link it did not initiate,
    /// since when ([`glare_verdict`]).
    yielding: std::sync::Mutex<HashMap<String, Instant>>,
}

/// Most consented contacts remembered for direct links.
pub const DIRECT_CONTACTS_MAX: usize = 4096;

impl DirectPaths {
    pub(crate) fn new(config: DirectLinksConfig) -> Self {
        Self {
            config,
            tracker: std::sync::Mutex::new(DirectPathTracker::default()),
            waiters: std::sync::Mutex::new(HashMap::new()),
            events: tokio::sync::broadcast::channel(64).0,
            anchors: std::sync::Arc::new(std::sync::Mutex::new(HashMap::new())),
            contacts: std::sync::Mutex::new(std::collections::HashSet::new()),
            yielding: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// v44 — since when this node has been yielding to `peer`'s proposal.
    pub(crate) fn yield_since(&self, peer: &str) -> Option<Instant> {
        self.yielding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(peer)
            .copied()
    }

    /// v44 — start yielding to `peer` at `now` (kept if already yielding).
    pub(crate) fn note_yield(&self, peer: &str, now: Instant) {
        self.yielding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(peer.to_owned())
            .or_insert(now);
    }

    /// v44 — stop yielding to `peer` (its proposal came, or this node's turn).
    pub(crate) fn clear_yield(&self, peer: &str) {
        self.yielding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(peer);
    }

    /// Eric 2026-10-30: a node goes direct with "anyone who has consented to a
    /// contact request", not only a room peer, so a new contact's consent
    /// exchange runs over a direct link at once. The host names each such
    /// peer by its NODE key id (on sending a request, and on accepting one).
    /// `false` when the set is full ([`DIRECT_CONTACTS_MAX`]).
    pub(crate) fn allow_contact(&self, node_key_id: &str) -> bool {
        let mut contacts = self
            .contacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if contacts.len() >= DIRECT_CONTACTS_MAX && !contacts.contains(node_key_id) {
            return false;
        }
        contacts.insert(node_key_id.to_owned());
        true
    }

    /// Forget a contact (the request was declined or withdrawn).
    pub(crate) fn forget_contact(&self, node_key_id: &str) {
        self.contacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(node_key_id);
    }

    /// Whether `peer` is a consented contact.
    pub(crate) fn is_contact(&self, peer: &str) -> bool {
        self.contacts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(peer)
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
    fn the_default_proposes_nothing_and_accepts_room_peers_only() {
        let c = DirectLinksConfig::default();
        assert!(!c.proposes());
        assert_eq!(c.accept, DirectAccept::RoomPeers);
        let s = c.leviculum_settings();
        assert_eq!(
            s.policy,
            DirectLinkPolicy::AskHost,
            "asked per request, never node-wide"
        );
        assert!(s.facilitator.is_none());
        assert!(s.facilitator_port.is_none());
    }

    #[test]
    fn every_accept_setting_parses_and_nothing_else_does() {
        for (s, want) in [
            ("room_peers", DirectAccept::RoomPeers),
            ("identified_only", DirectAccept::IdentifiedOnly),
            ("off", DirectAccept::Off),
        ] {
            assert_eq!(DirectAccept::parse(s), Some(want));
        }
        assert_eq!(DirectAccept::parse("on"), None);
        assert_eq!(DirectAccept::parse(""), None);
    }

    /// v44 — the default proposes: on, with the bundle's canonical as the
    /// facilitator once the host's init resolves it. `Off` resolves none and
    /// never proposes; an unresolved default proposes nothing. Mutation: a
    /// default of `Proposing::Off` fails this test.
    #[test]
    fn the_default_proposes_with_the_bundle_facilitator_and_off_never_does() {
        let bundle = DirectLinksConfig::bundle_facilitator()
            .expect("the baked genesis bundle names a serve node with an ip hint");
        let (_, dial) = crate::edge::baked_canonical_ip_dials()[0].clone();
        assert_eq!(
            bundle,
            dial.to_string(),
            "the facilitator is the ip hint itself, its port included"
        );
        let d = DirectLinksConfig::default();
        assert_eq!(d.proposing, Proposing::On);
        assert!(!d.proposes(), "unresolved: nothing to propose with");
        assert_eq!(d.leviculum_settings().facilitator, None);
        let on = d.clone().resolve_bundle_facilitator(true);
        assert_eq!(on.facilitator.as_deref(), Some(bundle.as_str()));
        assert!(on.proposes());
        assert_eq!(
            on.leviculum_settings().facilitator.as_deref(),
            Some(bundle.as_str())
        );
        let gated = d.resolve_bundle_facilitator(false);
        assert_eq!(gated.facilitator, None);
        assert!(!gated.proposes());
        let off = DirectLinksConfig {
            proposing: Proposing::Off,
            facilitator: Some("127.0.0.1:4242".to_owned()),
            ..DirectLinksConfig::default()
        }
        .resolve_bundle_facilitator(true);
        assert_eq!(off.facilitator, None);
        assert!(!off.proposes());
        assert_eq!(off.leviculum_settings().facilitator, None);
        let named = DirectLinksConfig {
            facilitator: Some("10.0.0.1:4242".to_owned()),
            ..DirectLinksConfig::default()
        }
        .resolve_bundle_facilitator(true);
        assert_eq!(
            named.facilitator.as_deref(),
            Some("10.0.0.1:4242"),
            "a named one stays"
        );
        assert_eq!(Proposing::parse("on"), Some(Proposing::On));
        assert_eq!(Proposing::parse("off"), Some(Proposing::Off));
        assert_eq!(Proposing::parse("yes"), None);
    }

    #[test]
    fn a_facilitator_does_not_imply_accepting() {
        let c = DirectLinksConfig {
            facilitator: Some("127.0.0.1:4243".to_owned()),
            ..DirectLinksConfig::default()
        };
        assert!(c.proposes());
        assert_eq!(c.leviculum_settings().policy, DirectLinkPolicy::AskHost);
        let off = DirectLinksConfig {
            accept: DirectAccept::Off,
            ..c.clone()
        };
        assert_eq!(off.leviculum_settings().policy, DirectLinkPolicy::Reject);
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
    fn room_peers_accepts_only_a_room_peer() {
        assert!(accepts_direct(DirectAccept::RoomPeers, true));
        assert!(!accepts_direct(DirectAccept::RoomPeers, false));
        assert!(!accepts_direct(DirectAccept::Off, true));
        assert!(accepts_direct(DirectAccept::IdentifiedOnly, false));
    }

    #[test]
    fn the_retry_policy_by_failure() {
        assert_eq!(
            retry_after(Failure::Rejected(1), 0, 0.0),
            DirectRetry::After(DIRECT_RETRY_BASE)
        );
        assert_eq!(
            retry_after(Failure::PunchFailed, 0, 0.0),
            DirectRetry::After(DIRECT_PUNCH_FAILED_BACKOFF)
        );
        assert_eq!(
            retry_after(Failure::Timeout, 0, 0.0),
            DirectRetry::After(DIRECT_RETRY_BASE)
        );
        assert_eq!(
            retry_after(Failure::ProbeFailed, 2, 0.0),
            DirectRetry::After(DIRECT_RETRY_BASE * 4)
        );
        assert_eq!(
            retry_after(Failure::Timeout, 40, 0.0),
            DirectRetry::After(DIRECT_RETRY_CAP)
        );
    }

    /// v44 — the retry is jittered ±25 % (clamped), so two peers that failed
    /// together do not retry in lockstep; the OS draw stays in range.
    #[test]
    fn the_retry_is_jittered_within_a_quarter() {
        let base = DIRECT_RETRY_BASE;
        assert_eq!(
            retry_after(Failure::Timeout, 0, 0.25),
            DirectRetry::After(base.mul_f64(1.25))
        );
        assert_eq!(
            retry_after(Failure::Timeout, 0, -0.25),
            DirectRetry::After(base.mul_f64(0.75))
        );
        assert_eq!(
            retry_after(Failure::Timeout, 0, 0.9),
            DirectRetry::After(base.mul_f64(1.25)),
            "clamped"
        );
        assert_eq!(
            retry_after(Failure::Timeout, 0, f64::NAN),
            DirectRetry::After(base)
        );
        let draws: Vec<f64> = (0..64).map(|_| jitter_draw()).collect();
        assert!(draws
            .iter()
            .all(|j| (-RETRY_JITTER..=RETRY_JITTER).contains(j)));
        assert!(
            draws.iter().any(|j| (*j - draws[0]).abs() > f64::EPSILON),
            "the draw is not a constant"
        );
    }

    /// v44 — the glare tie-break (leviculum#96): the link's initiator
    /// proposes; the responder yields until it has waited GLARE_WAIT.
    /// Mutation: a verdict that never yields fails this test.
    #[test]
    fn the_initiator_proposes_and_the_responder_yields_until_the_wait() {
        let t0 = Instant::now();
        assert_eq!(glare_verdict(true, None, t0), GlareVerdict::Propose);
        assert_eq!(glare_verdict(true, Some(t0), t0), GlareVerdict::Propose);
        assert_eq!(glare_verdict(false, None, t0), GlareVerdict::Yield);
        assert_eq!(
            glare_verdict(false, Some(t0), t0 + GLARE_WAIT / 2),
            GlareVerdict::Yield
        );
        assert_eq!(
            glare_verdict(false, Some(t0), t0 + GLARE_WAIT),
            GlareVerdict::Propose,
            "the initiator never proposed: the responder's turn"
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
            t.failed(link(1), Failure::Timeout, now, 0.0).as_deref(),
            Some("b")
        );
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::BackingOff));
        assert_eq!(t.admit("b", link(1), now + DIRECT_RETRY_BASE), Ok(()));
        // A second timeout doubles the wait.
        t.proposed("b", link(1), None, now);
        t.failed(link(1), Failure::Timeout, now, 0.0);
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
    fn a_rejection_backs_the_peer_off_and_is_asked_again_920() {
        // CIRISEdge#920: B refused while it did not yet share the room; once it
        // joins, the next send after the backoff must propose again, on any
        // link, including the one B refused.
        let now = Instant::now();
        let mut t = DirectPathTracker::default();
        t.proposed("b", link(1), None, now);
        t.failed(link(1), Failure::Rejected(1), now, 0.0);
        assert_eq!(t.admit("b", link(1), now), Err(ProposeSkip::BackingOff));
        assert_eq!(
            t.admit("b", link(2), now),
            Err(ProposeSkip::BackingOff),
            "one refusal backs the PEER off, not one link of it"
        );
        assert_eq!(t.admit("b", link(1), now + DIRECT_RETRY_BASE), Ok(()));
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
        assert_eq!(t.failed(link(9), Failure::Timeout, now, 0.0), None);
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
