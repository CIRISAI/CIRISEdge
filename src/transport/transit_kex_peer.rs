//! CIRISEdge#805 (CC 3.3.6.2) — resolve a PEER's transit KEX pair, the static
//! `{x25519, ml_kem_768}` a dialler runs `transit_kex::initiate` against.
//!
//! The only source is persist's per-peer resolver `transit_kex_pair_for`,
//! reached through [`RootingDirectory::transit_kex_pair_for`] (the handle
//! the transport holds; its one real implementation forwards to persist): the
//! pair from a live `Rooted` signed `transport_destination` binding, `None`
//! when there is none, when two live Rooted bindings disagree, or when the
//! pair reuses any key on the node's current occurrence. Never the raw
//! `SignedTransportDestination::transit_kex_pair` (it skips the provenance
//! and cross-row reuse checks) and never a bare announce (a routing hint is
//! not a hop key).
//!
//! `None` means the peer cannot relay (CC 3.3.6.2).
//!
//! CC rc9 (`c8f0d12`, 3.3.6.2 + E1 + 5.3.4, I1–I6) — a DIALLER may also seal
//! to a node that is not Rooted here, on a pair authenticated to that node:
//! its OWN hybrid-signed route row ([`PeerTransitResolver::resolve_authenticated`],
//! source (a), [`crate::verify::authenticated_self_signed_transit_pair`]).
//! Rooted governs what a peer is SERVED (#659), not whether two keys may
//! speak. The pairing pin (3.2 (f)) is the third source, keyed on its own
//! path. A bare announce never supplies a pair.

use std::collections::HashSet;
use std::sync::Mutex;

use ciris_persist::federation::self_at_login::TransitKexPair;

use crate::verify::RootingDirectory;

/// Which CC 3.3.6.2 source authenticated a dialled node's transit pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PairSource {
    /// (b) A live Rooted binding (persist `transit_kex_pair_for`).
    Rooted,
    /// (a) The node's own hybrid-signed route row.
    SelfSignedRow,
    /// (c) The owner's pairing payload pin (3.2 (f)).
    Pin,
    /// (a), fetched: the node's own hybrid-signed route row, asked for over
    /// the link as its first frame (CC 5.3.3.5 E1 pre-seal route fetch) and
    /// verified exactly as a held copy would be.
    RouteFetch,
}

impl PairSource {
    /// The stable token (log field and metric label).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rooted => crate::observability::LINK_SEAL_PAIR_ROOTED,
            Self::SelfSignedRow => crate::observability::LINK_SEAL_PAIR_SELF_SIGNED_ROW,
            Self::Pin => crate::observability::LINK_SEAL_PAIR_PIN,
            Self::RouteFetch => crate::observability::LINK_SEAL_PAIR_ROUTE_FETCH,
        }
    }
}

/// Per-peer transit pair resolution with a say-once log for peers that
/// cannot relay. Holds no pair: every call re-reads the directory, so a
/// re-signed or retired binding is seen on the next dial.
#[derive(Debug, Default)]
pub struct PeerTransitResolver {
    /// Peers already logged as "cannot relay" (debug, once each).
    logged_no_pair: Mutex<HashSet<String>>,
    /// Peers whose refused dial (`link_seal_refused_no_pair`) has been said
    /// at INFO since their pair last resolved ([`Self::note_no_pair_refusal`]).
    said_no_pair_refusal: Mutex<HashSet<String>>,
    /// `(peer, source)` pairs already said at INFO ([`Self::note_source`]).
    said_source: Mutex<HashSet<(String, PairSource)>>,
}

impl PeerTransitResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The transit pair to key a hop to `occurrence_key_id`, or `None` when
    /// that peer cannot relay.
    ///
    /// # Errors
    ///
    /// The directory's: a backend read error, a stored binding whose pair
    /// does not parse (a corrupted row; it passed admission), or no
    /// directory at all.
    pub async fn resolve<D: RootingDirectory + ?Sized>(
        &self,
        dir: &D,
        occurrence_key_id: &str,
    ) -> Result<Option<TransitKexPair>, String> {
        let pair = dir.transit_kex_pair_for(occurrence_key_id).await?;
        if pair.is_some() {
            self.rearm(occurrence_key_id);
        } else {
            let first = self
                .logged_no_pair
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(occurrence_key_id.to_owned());
            if first {
                // persist's `None` does not say which of its three cases
                // applied, so neither does this line.
                tracing::debug!(
                    peer = %occurrence_key_id,
                    "CIRISEdge#805: peer has no usable transit KEX pair and cannot relay \
                     (no live Rooted binding carrying one, two live Rooted bindings \
                     carrying different pairs, or the pair reuses one of its keys; \
                     persist does not say which)"
                );
            }
        }
        Ok(pair)
    }

    /// CC 3.3.6.2 (rc9, I1–I6) — the pair to seal a dial to `key_id` with,
    /// and which source authenticated it: (b) a live Rooted binding first,
    /// then (a) the node's own hybrid-signed route row
    /// ([`RootingDirectory::self_signed_transit_pair_for`]). `None` when
    /// neither supplies one.
    ///
    /// # Errors
    /// As [`Self::resolve`].
    pub async fn resolve_authenticated<D: RootingDirectory + ?Sized>(
        &self,
        dir: &D,
        key_id: &str,
    ) -> Result<Option<(TransitKexPair, PairSource)>, String> {
        if let Some(pair) = self.resolve(dir, key_id).await? {
            return Ok(Some((pair, PairSource::Rooted)));
        }
        let pair = dir.self_signed_transit_pair_for(key_id).await?;
        if pair.is_some() {
            self.rearm(key_id);
        }
        Ok(pair.map(|p| (p, PairSource::SelfSignedRow)))
    }

    /// `true` the first time `source` keyed a link to `peer` (said at INFO
    /// then, at DEBUG after).
    pub fn note_source(&self, peer: &str, source: PairSource) -> bool {
        self.said_source
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((peer.to_owned(), source))
    }

    /// A dial to `peer` was refused for want of its pair. `true` the first
    /// time since the pair last resolved: during bootstrap a peer's pair
    /// arrives only after its route does, so the refusal repeats on every
    /// round until then and is said once (INFO), its repeats at DEBUG
    /// ([`no_pair_refusal_level`]).
    pub fn note_no_pair_refusal(&self, peer: &str) -> bool {
        self.said_no_pair_refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(peer.to_owned())
    }

    /// `peer`'s pair resolved: a later loss of it is said again, at both
    /// say-once points.
    fn rearm(&self, peer: &str) {
        self.said_no_pair_refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(peer);
        self.logged_no_pair
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(peer);
    }
}

/// The level a `link_seal_refused_no_pair` dial refusal is logged at: INFO
/// the first time per peer (`first`, from
/// [`PeerTransitResolver::note_no_pair_refusal`]), DEBUG after. Never WARN:
/// a peer whose pair has not arrived yet is the normal bootstrap state, not
/// a fault.
#[must_use]
pub fn no_pair_refusal_level(first: bool) -> tracing::Level {
    if first {
        tracing::Level::INFO
    } else {
        tracing::Level::DEBUG
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_no_pair_refusal_is_said_once_per_peer_and_rearmed_when_the_pair_resolves() {
        let r = PeerTransitResolver::new();
        assert!(r.note_no_pair_refusal("bob"), "said the first time");
        for _ in 0..17 {
            assert!(!r.note_no_pair_refusal("bob"), "repeats are quiet");
        }
        assert!(r.note_no_pair_refusal("carol"), "per peer");
        r.rearm("bob");
        assert!(
            r.note_no_pair_refusal("bob"),
            "said again once the pair was had and lost"
        );
        assert_eq!(no_pair_refusal_level(true), tracing::Level::INFO);
        assert_eq!(no_pair_refusal_level(false), tracing::Level::DEBUG);
        for first in [true, false] {
            assert_ne!(
                no_pair_refusal_level(first),
                tracing::Level::WARN,
                "never WARN"
            );
        }
    }
}

#[cfg(test)]
mod authenticated_source_tests {
    use super::*;
    use crate::verify::{ProvenanceChain, RootingRejection, RootingVerdict};
    use async_trait::async_trait;

    /// A directory that answers only the two pair sources: what persist's
    /// Rooted resolver would say, and what the node's own signed row would.
    struct Sources {
        rooted: Option<TransitKexPair>,
        own_row: Option<TransitKexPair>,
    }

    fn pair(tag: u8) -> TransitKexPair {
        TransitKexPair {
            x25519: [tag; 32],
            ml_kem_768: Box::new([tag; 1184]),
        }
    }

    #[async_trait]
    impl RootingDirectory for Sources {
        async fn root_binding(&self, key_id: &str, _claimed: &str) -> RootingVerdict {
            RootingVerdict::Rejected {
                rejection: RootingRejection::UnknownKeyId {
                    key_id: key_id.to_owned(),
                },
            }
        }
        async fn provenance_chain(
            &self,
            key_id: &str,
        ) -> Result<ProvenanceChain, RootingRejection> {
            Err(RootingRejection::UnknownKeyId {
                key_id: key_id.to_owned(),
            })
        }
        async fn transit_kex_pair_for(
            &self,
            _key_id: &str,
        ) -> Result<Option<TransitKexPair>, String> {
            Ok(self.rooted.clone())
        }
        async fn self_signed_transit_pair_for(
            &self,
            _key_id: &str,
        ) -> Result<Option<TransitKexPair>, String> {
            Ok(self.own_row.clone())
        }
    }

    /// CC 3.3.6.2 (rc9 `c8f0d12`, I2) — the dial's pair comes from a source
    /// authenticated to the dialled identity, tried in order: a live Rooted
    /// binding, then the node's own hybrid-signed route row. A peer known only
    /// by a bare announce has neither and gets no pair.
    #[tokio::test]
    async fn a_rooted_binding_is_tried_before_the_nodes_own_signed_row_and_a_bare_announce_supplies_nothing(
    ) {
        let r = PeerTransitResolver::new();
        let both = Sources {
            rooted: Some(pair(1)),
            own_row: Some(pair(2)),
        };
        let (p, source) = r
            .resolve_authenticated(&both, "peer")
            .await
            .expect("read")
            .expect("a pair");
        assert_eq!((p, source), (pair(1), PairSource::Rooted), "Rooted first");

        let own_only = Sources {
            rooted: None,
            own_row: Some(pair(2)),
        };
        let (p, source) = r
            .resolve_authenticated(&own_only, "peer")
            .await
            .expect("read")
            .expect("a pair");
        assert_eq!(
            (p, source),
            (pair(2), PairSource::SelfSignedRow),
            "a node not Rooted here still keys from its own signed row"
        );

        let announce_only = Sources {
            rooted: None,
            own_row: None,
        };
        assert_eq!(
            r.resolve_authenticated(&announce_only, "peer")
                .await
                .expect("read"),
            None,
            "a bare announce never supplies a pair"
        );

        assert!(
            r.note_source("peer", PairSource::Rooted),
            "said at INFO once"
        );
        assert!(!r.note_source("peer", PairSource::Rooted), "then at DEBUG");
        assert!(
            r.note_source("peer", PairSource::SelfSignedRow),
            "per source"
        );
        assert_eq!(
            PairSource::Pin.as_str(),
            crate::observability::LINK_SEAL_PAIR_PIN
        );
    }
}
