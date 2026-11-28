//! v45.3 — **can this node reach a peer now, and how?** The answer the server
//! reads per peer (`Edge::peer_reach`), and the ONE decision the round-start
//! reach check (CIRISEdge#971 `undialable_now`) makes. Pure, so every state
//! is a unit test over the exact facts the transport gathers, and it builds
//! without a transport (the FFI surfaces read its types).
//!
//! The facts are gathered once, by
//! `ReticulumTransport::reach_facts`, in the order the #971 check reads them:
//! a live attributed identity-plane link, then a path to any dial candidate,
//! and the transit-pair read only when neither answers (it is a store read,
//! and a live link or a path already decides).

use serde::Serialize;

/// What [`reach_state`] makes of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachState {
    /// A live, attributed identity-plane link to it: a send rides it now.
    Live,
    /// Not live and not undialable: a dial can leave, over a path to one of
    /// its dial candidates (a pathed candidate with no pair is still dialled:
    /// E1's pre-seal route fetch) or with a transit pair authenticated to it
    /// (a seek finds the path). `has_path` and `transit_pair` say which.
    Dialable,
    /// Exactly the #971 "undialable now": no live link, no path to any dial
    /// candidate, and no transit pair. No rule reaches it until one of the
    /// three changes.
    Unreachable,
    /// No live link and no path, and the transit-pair read failed: neither
    /// dialable nor known unreachable. Also the answer with no Reticulum
    /// transport.
    Unknown,
}

impl ReachState {
    /// The wire token (`live`, `dialable`, `unreachable`, `unknown`).
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Dialable => "dialable",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }
}

/// The facts behind a [`PeerReach`], as the transport read them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReachFacts {
    /// A live, attributed identity-plane link to the peer.
    pub live_link: bool,
    /// A path to at least one of the peer's dial candidates.
    pub has_path: bool,
    /// The transit-pair read: `Some(true)` a pair is authenticated to the
    /// peer, `Some(false)` persist answered "no pair", `None` not read (a live
    /// link or a path answered first) or the read failed.
    pub transit_pair: Option<bool>,
}

impl ReachFacts {
    /// The #971 decision: no live link, no path, and persist said "no pair".
    /// A pair read that failed is not "no pair".
    #[must_use]
    pub const fn undialable(&self) -> bool {
        !self.live_link && !self.has_path && matches!(self.transit_pair, Some(false))
    }

    /// The state these facts make.
    #[must_use]
    pub const fn state(&self) -> ReachState {
        reach_state(self)
    }
}

/// The state `facts` make. [`ReachState::Unreachable`] is exactly
/// [`ReachFacts::undialable`].
#[must_use]
pub const fn reach_state(facts: &ReachFacts) -> ReachState {
    if facts.live_link {
        ReachState::Live
    } else if facts.has_path || matches!(facts.transit_pair, Some(true)) {
        ReachState::Dialable
    } else if facts.undialable() {
        ReachState::Unreachable
    } else {
        ReachState::Unknown
    }
}

/// v45.3 — what this node knows of reaching one peer now (`Edge::peer_reach`).
/// No address: hops and booleans only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerReach {
    /// The summary.
    pub state: ReachState,
    /// A live, attributed identity-plane link to the peer.
    pub live_link: bool,
    /// Milliseconds since that link last carried a frame from the peer (at
    /// one-second resolution), `None` with no live link or none heard on it.
    pub last_inbound_ms_ago: Option<u64>,
    /// A path to at least one of the peer's dial candidates.
    pub has_path: bool,
    /// The fewest hops to any of its dial candidates, when pathed.
    pub path_hops: Option<u8>,
    /// The transit-pair read ([`ReachFacts::transit_pair`]).
    pub transit_pair: Option<bool>,
    /// The live link travels a punched interface (leviculum's `direct`
    /// path state), not the relay.
    pub direct: bool,
}

impl PeerReach {
    /// [`ReachState::Unknown`] with nothing known: no Reticulum transport.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            state: ReachState::Unknown,
            live_link: false,
            last_inbound_ms_ago: None,
            has_path: false,
            path_hops: None,
            transit_pair: None,
            direct: false,
        }
    }

    /// The reach `facts` make, with the link's and the path's detail.
    #[must_use]
    pub const fn from_facts(
        facts: &ReachFacts,
        last_inbound_ms_ago: Option<u64>,
        path_hops: Option<u8>,
        direct: bool,
    ) -> Self {
        Self {
            state: facts.state(),
            live_link: facts.live_link,
            last_inbound_ms_ago,
            has_path: facts.has_path,
            path_hops,
            transit_pair: facts.transit_pair,
            direct,
        }
    }
}

/// Milliseconds since `last_inbound_secs` (unix seconds, the transport's
/// per-link stamp) at `now_secs`; `None` for an unstamped link (0).
#[must_use]
pub const fn inbound_ms_ago(last_inbound_secs: u64, now_secs: u64) -> Option<u64> {
    if last_inbound_secs == 0 {
        None
    } else {
        Some(
            now_secs
                .saturating_sub(last_inbound_secs)
                .saturating_mul(1000),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn f(live_link: bool, has_path: bool, transit_pair: Option<bool>) -> ReachFacts {
        ReachFacts {
            live_link,
            has_path,
            transit_pair,
        }
    }

    /// A live link is `Live`, whatever else holds. The transport never reads
    /// the pair then (`None`), but a read pair changes nothing.
    #[test]
    fn a_live_link_is_live() {
        for facts in [
            f(true, false, None),
            f(true, true, None),
            f(true, false, Some(false)),
        ] {
            assert_eq!(facts.state(), ReachState::Live, "{facts:?}");
            assert!(!facts.undialable());
        }
    }

    /// A path, or failing that a transit pair, is `Dialable`.
    #[test]
    fn a_path_or_a_pair_is_dialable() {
        // The transport's exact inputs: a path short-circuits the pair read.
        assert_eq!(f(false, true, None).state(), ReachState::Dialable);
        // No path, the pair read answered "a pair".
        assert_eq!(f(false, false, Some(true)).state(), ReachState::Dialable);
        assert!(!f(false, true, None).undialable());
        assert!(!f(false, false, Some(true)).undialable());
        // A path but no pair, and a pair but no path: each is still dialled,
        // so each is Dialable (not live and not undialable).
        assert_eq!(f(false, true, Some(false)).state(), ReachState::Dialable);
        assert_eq!(f(false, false, Some(true)).state(), ReachState::Dialable);
        for facts in [f(false, true, Some(false)), f(false, false, Some(true))] {
            assert!(!facts.live_link && !facts.undialable(), "{facts:?}");
        }
    }

    /// `Unreachable` is exactly the #971 undialable: all three absent, the
    /// pair read answering "no pair".
    #[test]
    fn unreachable_is_exactly_undialable() {
        let none = f(false, false, Some(false));
        assert!(none.undialable());
        assert_eq!(none.state(), ReachState::Unreachable);
        // Every other combination of the three is not.
        for live in [false, true] {
            for path in [false, true] {
                for pair in [None, Some(false), Some(true)] {
                    let facts = f(live, path, pair);
                    assert_eq!(
                        facts.state() == ReachState::Unreachable,
                        facts.undialable(),
                        "{facts:?}"
                    );
                }
            }
        }
    }

    /// A pair read that failed is not "no pair": `Unknown`, never
    /// `Unreachable` (the #971 rule: the send runs as before).
    #[test]
    fn a_failed_pair_read_is_unknown() {
        let failed = f(false, false, None);
        assert!(!failed.undialable());
        assert_eq!(failed.state(), ReachState::Unknown);
        assert_eq!(PeerReach::unknown().state, ReachState::Unknown);
    }

    /// The reach carries the facts and the detail unchanged.
    #[test]
    fn the_reach_is_the_facts_and_the_detail() {
        let r = PeerReach::from_facts(&f(true, true, None), Some(3000), Some(2), true);
        assert_eq!(
            r,
            PeerReach {
                state: ReachState::Live,
                live_link: true,
                last_inbound_ms_ago: Some(3000),
                has_path: true,
                path_hops: Some(2),
                transit_pair: None,
                direct: true,
            }
        );
        assert_eq!(
            serde_json::to_value(&r).expect("json")["state"],
            serde_json::json!("live")
        );
        for (s, t) in [
            (ReachState::Live, "live"),
            (ReachState::Dialable, "dialable"),
            (ReachState::Unreachable, "unreachable"),
            (ReachState::Unknown, "unknown"),
        ] {
            assert_eq!(s.token(), t);
            assert_eq!(serde_json::to_value(s).expect("json"), serde_json::json!(t));
        }
    }

    #[test]
    fn inbound_age_is_in_milliseconds_and_unstamped_is_none() {
        assert_eq!(inbound_ms_ago(0, 1_000), None);
        assert_eq!(inbound_ms_ago(997, 1_000), Some(3_000));
        assert_eq!(inbound_ms_ago(1_000, 1_000), Some(0));
        // A stamp ahead of the clock (a step back) reads as just now.
        assert_eq!(inbound_ms_ago(1_005, 1_000), Some(0));
    }
}
